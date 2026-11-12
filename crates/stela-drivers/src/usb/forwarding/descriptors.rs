// SPDX-License-Identifier: GPL-2.0-only
//! Strict inventory validation: a malformed physical descriptor is refused,
//! never repaired into bytes different from those a stock guest observes.
use super::*;

pub(super) struct Configuration {
    pub value: u8,
    pub interfaces: Vec<Interface>,
}
fn invalid() -> BlockError {
    BlockError::Protocol("malformed forwarding descriptor inventory")
}

pub(super) fn inventory(device: &xhci::Device) -> Result<Vec<Configuration>, BlockError> {
    if device.descriptor[0..2] != [18, crate::usb::descriptor::DEVICE_DESCRIPTOR]
        || device.descriptor[4] == 9
        || device.configurations.len() != usize::from(device.descriptor[17])
        || device.configurations.is_empty()
    {
        return Err(invalid());
    }
    let mut configurations: Vec<Configuration> = Vec::new();
    let mut total = 0usize;
    for bytes in &device.configurations {
        total = total.checked_add(bytes.len()).ok_or_else(invalid)?;
        if bytes.len() < 9
            || bytes[0..2] != [9, crate::usb::descriptor::CONFIGURATION_DESCRIPTOR]
            || usize::from(u16::from_le_bytes([bytes[2], bytes[3]])) != bytes.len()
            || bytes.len() > 4096
            || total > 65536
            || bytes[5] == 0
        {
            return Err(invalid());
        }
        let mut at = 9;
        let mut settings: Vec<(u8, u8, u8, u8)> = Vec::new();
        let mut endpoints = 0u32;
        let mut preceding_endpoint = false;
        while at < bytes.len() {
            let header = bytes.get(at..at + 2).ok_or_else(invalid)?;
            let length = usize::from(header[0]);
            if length < 2 {
                return Err(invalid());
            }
            let d = bytes.get(at..at + length).ok_or_else(invalid)?;
            match d[1] {
                crate::usb::descriptor::CONFIGURATION_DESCRIPTOR
                | crate::usb::descriptor::DEVICE_DESCRIPTOR => return Err(invalid()),
                crate::usb::descriptor::INTERFACE_DESCRIPTOR => {
                    if length < 9
                        || d[5] == 9
                        || settings.iter().any(|s| (s.0, s.1) == (d[2], d[3]))
                    {
                        return Err(invalid());
                    }
                    settings.push((d[2], d[3], d[4], 0));
                    endpoints = 0;
                }
                crate::usb::descriptor::ENDPOINT_DESCRIPTOR => {
                    if length < 7 || d[2] & 0x70 != 0 || d[2] & 15 == 0 || d[3] & 3 == 0 {
                        return Err(invalid());
                    }
                    let setting = settings.last_mut().ok_or_else(invalid)?;
                    let dci = 2 * (d[2] & 15) + u8::from(d[2] & 0x80 != 0);
                    if endpoints & (1 << dci) != 0 {
                        return Err(invalid());
                    }
                    endpoints |= 1 << dci;
                    setting.3 = setting.3.checked_add(1).ok_or_else(invalid)?;
                }
                0x30 if length != 6 || !preceding_endpoint => return Err(invalid()),
                _ => {}
            }
            preceding_endpoint = d[1] == crate::usb::descriptor::ENDPOINT_DESCRIPTOR;
            at += length;
        }
        let mut numbers: Vec<u8> = settings.iter().map(|s| s.0).collect();
        numbers.sort_unstable();
        numbers.dedup();
        if numbers.len() != usize::from(bytes[4])
            || settings.iter().any(|s| s.2 != s.3)
            || numbers
                .iter()
                .any(|n| !settings.iter().any(|s| s.0 == *n && s.1 == 0))
        {
            return Err(invalid());
        }
        let interfaces = crate::usb::descriptor::interfaces(bytes);
        if interfaces.len() != settings.len() {
            return Err(invalid());
        }
        configurations.push(Configuration {
            value: bytes[5],
            interfaces,
        });
    }
    Ok(configurations)
}

pub(super) fn active(
    configuration: &Configuration,
    settings: &[(u8, u8)],
    speed: u8,
) -> Result<Vec<Endpoint>, BlockError> {
    let mut result = Vec::new();
    let mut occupied = 0u32;
    for &(number, alternate) in settings {
        let interface = configuration
            .interfaces
            .iter()
            .find(|i| (i.number, i.alternate) == (number, alternate))
            .ok_or_else(invalid)?;
        for endpoint in &interface.endpoints {
            endpoint.validate_context(speed)?;
            if occupied & (1 << endpoint.dci()) != 0 {
                return Err(BlockError::Protocol(
                    "active composite interfaces overlap endpoints",
                ));
            }
            occupied |= 1 << endpoint.dci();
            result.push(*endpoint);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::xhci::model::device;
    use alloc::vec;
    fn composite() -> Vec<u8> {
        vec![
            9, 2, 50, 0, 2, 19, 0, 0x80, 50, 9, 4, 3, 0, 1, 0xff, 0, 0, 0, 7, 5, 0x81, 2, 0, 2, 0,
            9, 4, 7, 0, 0, 0xff, 0, 0, 0, 9, 4, 7, 2, 1, 0xff, 0, 0, 0, 7, 5, 2, 3, 64, 0, 1,
        ]
    }
    #[test]
    fn keeps_nonsequential_composite_configuration_and_alternates() {
        let mut d = device(vec![composite()]);
        d.descriptor[17] = 1;
        let inventory = inventory(&d).unwrap();
        assert_eq!(inventory[0].value, 19);
        let endpoints = active(&inventory[0], &[(3, 0), (7, 2)], xhci::HIGH_SPEED).unwrap();
        assert_eq!(
            endpoints.iter().map(|ep| ep.address).collect::<Vec<_>>(),
            vec![0x81, 2]
        );
        assert_eq!(d.configurations[0], composite());
    }
    /// A device that answers two indices with one configuration value is
    /// kept, as Linux keeps it; the value selects the first.
    #[test]
    fn keeps_two_configurations_with_one_value() {
        let mut second = composite();
        second[8] = 100;
        let mut d = device(vec![composite(), second]);
        d.descriptor[17] = 2;
        let inventory = inventory(&d).unwrap();
        assert_eq!(inventory.len(), 2);
        assert_eq!(inventory.iter().position(|c| c.value == 19), Some(0));
        assert_eq!(d.configurations[1][8], 100);
    }
    #[test]
    fn rejects_malformed_inventory_without_sanitizing_guest_bytes() {
        for (at, value) in [(2, 49), (4, 1), (5, 0), (13, 2), (20, 0), (43, 0)] {
            let mut bytes = composite();
            bytes[at] = value;
            let mut d = device(vec![bytes]);
            d.descriptor[17] = 1;
            assert!(inventory(&d).is_err(), "{at}");
        }
    }
    #[test]
    fn rejects_endpoint_overlap_only_when_both_settings_are_active() {
        let mut bytes = composite();
        bytes[45] = 0x81;
        let mut d = device(vec![bytes]);
        d.descriptor[17] = 1;
        let inventory = inventory(&d).unwrap();
        assert!(active(&inventory[0], &[(3, 0), (7, 0)], xhci::HIGH_SPEED).is_ok());
        assert!(active(&inventory[0], &[(3, 0), (7, 2)], xhci::HIGH_SPEED).is_err());
    }
}

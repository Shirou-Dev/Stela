// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (C) 2007 Intel
// Copyright (C) Zhang Yanmin (yanmin.zhang@intel.com)
// Copyright (C) Shaohua Li (shaohua.li@intel.com)
// Copyright (c) 2026 Stela contributors
//! ASPM policy through kept original bridge owners, without enumeration.
//! Link Control layout/order follows the pinned Linux PCI ASPM implementation.
use super::{BRIDGE_BUSES, PCIE_ASPM, PCIE_FLAGS, PCIE_LINK_CONTROL};
use crate::bus::pci::{
    Address, CapabilityError, ConfigSpace, Function, Layout, msi::MsiConfigSpace,
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Config(crate::bus::pci::ConfigError),
    Topology,
    Identity(Address),
    Capability(Address),
    Read {
        address: Address,
        offset: u16,
    },
    Readback {
        address: Address,
        offset: u16,
        observed: u16,
    },
}
impl From<crate::bus::pci::ConfigError> for Error {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Config(error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootBus {
    pub segment: u16,
    pub bus: u8,
}

/// Complete bridge inventory and root-bus declarations for one segment.
/// Configuration mappings and their root/resource epochs stay owned.
/// No raw ECAM window, synthetic Function, or freshly enumerated alias is used.
pub struct Topology<C: MsiConfigSpace> {
    bridges: Vec<Function<C>>,
    roots: Vec<RootBus>,
}
impl<C: MsiConfigSpace> Topology<C> {
    /// # Safety
    /// These are the original exclusively owned Functions for every
    /// bridge in the endpoint's segment, including unconfigured bridges. Roots
    /// are the complete real firmware/root-complex root buses, not guessed bus
    /// zero or inferred from absence. The native producer owns firmware/ACPI
    /// ASPM policy, bridge routing/reset/removal and all config writers for this
    /// epoch; none can race or re-enable the policy. Every C performs
    /// real native narrow writes (or belongs to an explicit independent model).
    /// Numeric topology validation below does not establish this grant.
    pub unsafe fn new(bridges: Vec<Function<C>>, roots: Vec<RootBus>) -> Self {
        Self { bridges, roots }
    }
    pub fn into_functions(self) -> Vec<Function<C>> {
        self.bridges
    }
    /// Read-only validation; call before any irreversible preparation effects.
    pub fn validate(&self, endpoint: &Function<C>) -> Result<(), Error> {
        let segment = endpoint.address.segment;
        if self.roots.is_empty()
            || self.roots.iter().any(|root| root.segment != segment)
            || self
                .roots
                .iter()
                .enumerate()
                .any(|(i, root)| self.roots[..i].contains(root))
        {
            return Err(Error::Topology);
        }
        identity(endpoint)?;
        for (index, bridge) in self.bridges.iter().enumerate() {
            if bridge.address.segment != segment
                || bridge.address == endpoint.address
                || self.bridges[..index]
                    .iter()
                    .any(|other| other.address == bridge.address)
                || bridge.class[..2] != [6, 4]
                || bridge.config.read8(0x0e)? & 0x7f != 1
            {
                return Err(Error::Topology);
            }
            identity(bridge)?;
            let Some((secondary, _)) = buses(bridge)? else {
                continue;
            };
            if self.is_root(segment, secondary) {
                return Err(Error::Topology);
            }
            for other in &self.bridges[..index] {
                let Some((other_secondary, other_subordinate)) = buses(other)? else {
                    continue;
                };
                let (_, subordinate) = buses(bridge)?.ok_or(Error::Topology)?;
                let overlap = secondary <= other_subordinate && other_secondary <= subordinate;
                let nested = (other_secondary..=other_subordinate).contains(&bridge.address.bus)
                    && secondary >= other_secondary
                    && subordinate <= other_subordinate;
                let reverse_nested = (secondary..=subordinate).contains(&other.address.bus)
                    && other_secondary >= secondary
                    && other_subordinate <= subordinate;
                if other_secondary == secondary || (overlap && !nested && !reverse_nested) {
                    return Err(Error::Topology);
                }
            }
            self.path(bridge.address.bus, segment)?;
        }
        self.path(endpoint.address.bus, segment)?;
        Ok(())
    }
    /// Read-only validation of both link controls before any reset/PM writes.
    pub fn validate_link(&self, endpoint: &Function<C>) -> Result<(), Error> {
        self.validate(endpoint)?;
        link(endpoint)?;
        if let Some(index) = self.parent(endpoint.address.bus)? {
            link(&self.bridges[index])?;
        }
        Ok(())
    }
    /// Both Link Controls and the entire topology are validated before either
    /// native word store. A refused downstream write never touches the parent.
    /// Other bits and adjacent Link Status W1C bits remain unchanged.
    pub fn disable(&mut self, endpoint: &mut Function<C>) -> Result<(), Error> {
        self.validate(endpoint)?;
        let child = link(endpoint)?;
        let parent = self.parent(endpoint.address.bus)?;
        let parent_control = parent.map(|index| link(&self.bridges[index])).transpose()?;
        clear(endpoint, child)?;
        if let Some((index, control)) = parent.zip(parent_control) {
            clear(&mut self.bridges[index], control)?;
        }
        Ok(())
    }
    fn is_root(&self, segment: u16, bus: u8) -> bool {
        self.roots.contains(&RootBus { segment, bus })
    }
    fn parent(&self, bus: u8) -> Result<Option<usize>, Error> {
        let mut parent = None;
        for (index, bridge) in self.bridges.iter().enumerate() {
            if buses(bridge)?.is_some_and(|(secondary, _)| secondary == bus)
                && parent.replace(index).is_some()
            {
                return Err(Error::Topology);
            }
        }
        Ok(parent)
    }
    fn path(&self, mut bus: u8, segment: u16) -> Result<(), Error> {
        let origin = bus;
        for _ in 0..=self.bridges.len() {
            if self.is_root(segment, bus) {
                return if self.parent(bus)?.is_none() {
                    Ok(())
                } else {
                    Err(Error::Topology)
                };
            }
            let bridge = &self.bridges[self.parent(bus)?.ok_or(Error::Topology)?];
            let (secondary, subordinate) = buses(bridge)?.ok_or(Error::Topology)?;
            if !(secondary..=subordinate).contains(&origin) {
                return Err(Error::Topology);
            }
            bus = bridge.address.bus;
        }
        Err(Error::Topology)
    }
}
fn identity<C: ConfigSpace>(function: &Function<C>) -> Result<(), Error> {
    let id = function.config.read32(0)?;
    if id != u32::from(function.vendor) | u32::from(function.device) << 16
        || function.config.read32(8)? >> 8
            != u32::from_be_bytes([0, function.class[0], function.class[1], function.class[2]])
    {
        return Err(Error::Identity(function.address));
    }
    Ok(())
}
fn read<C: ConfigSpace>(function: &Function<C>, offset: u16) -> Result<u16, Error> {
    let observed = function.config.read16(offset)?;
    if observed == u16::MAX {
        Err(Error::Read {
            address: function.address,
            offset,
        })
    } else {
        Ok(observed)
    }
}
fn buses<C: ConfigSpace>(bridge: &Function<C>) -> Result<Option<(u8, u8)>, Error> {
    let value = bridge.config.read32(BRIDGE_BUSES)?;
    if value == u32::MAX {
        return Err(Error::Read {
            address: bridge.address,
            offset: BRIDGE_BUSES,
        });
    }
    let (primary, secondary, subordinate) = (value as u8, (value >> 8) as u8, (value >> 16) as u8);
    if secondary == 0 && subordinate == 0 {
        return Ok(None);
    }
    if primary != bridge.address.bus
        || secondary == primary
        || secondary == 0
        || subordinate < secondary
    {
        return Err(Error::Topology);
    }
    Ok(Some((secondary, subordinate)))
}
fn link<C: MsiConfigSpace>(function: &Function<C>) -> Result<(u16, u16), Error> {
    let malformed = || Error::Capability(function.address);
    if read(function, 6)? & (1 << 4) == 0 {
        return Err(malformed());
    }
    let mut found = None;
    for entry in function.config.capabilities() {
        let entry = entry.map_err(|error| match error {
            CapabilityError::Config { error, .. } => Error::Config(error),
            CapabilityError::FailedRead { offset } => Error::Read {
                address: function.address,
                offset,
            },
            _ => malformed(),
        })?;
        let offset = entry.offset;
        match entry.id {
            0x10 => {
                let flags = read(function, offset + PCIE_FLAGS)?;
                let kind = (flags >> 4) & 15;
                if !matches!(flags & 15, 1 | 2)
                    || !matches!(kind, 0 | 1 | 4 | 5 | 6 | 7 | 8)
                    || found.is_some()
                {
                    return Err(malformed());
                }
                found = Some(offset + PCIE_LINK_CONTROL);
            }
            5 => {
                let flags = read(function, offset + 2)?;
                if flags & (1 << 10) != 0
                    || (flags >> 1) & 7 > 5
                    || (flags >> 4) & 7 > (flags >> 1) & 7
                {
                    return Err(malformed());
                }
            }
            _ if entry.layout == Layout::Unsupported => return Err(malformed()),
            _ => {}
        }
    }
    let offset = found.ok_or_else(malformed)?;
    Ok((offset, read(function, offset)?))
}
fn clear<C: MsiConfigSpace>(
    function: &mut Function<C>,
    (offset, before): (u16, u16),
) -> Result<(), Error> {
    let wanted = before & !PCIE_ASPM;
    if wanted != before {
        function.config.write16(offset, wanted)?;
    }
    let observed = read(function, offset)?;
    if observed != wanted {
        return Err(Error::Readback {
            address: function.address,
            offset,
            observed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;
    type Writes = Rc<RefCell<Vec<(Address, u16, u16)>>>;
    struct Config {
        words: [u32; 1024],
        address: Address,
        writes: Writes,
        failed: Option<u16>,
        refuse: bool,
    }
    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
            Ok({
                if self.failed == Some(offset) {
                    u32::MAX
                } else {
                    self.words[usize::from(offset / 4)]
                }
            })
        }
        fn write32(&mut self, _: u16, _: u32) -> Result<(), crate::bus::pci::ConfigError> {
            panic!("ASPM cannot write adjacent W1C status")
        }
        fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
            Ok({
                if self.failed == Some(offset) {
                    u16::MAX
                } else {
                    (self.words[usize::from(offset / 4)] >> ((offset & 2) * 8)) as u16
                }
            })
        }
        fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
            self.writes.borrow_mut().push((self.address, offset, value));
            if self.refuse {
                return Ok(());
            }
            let shift = (offset & 2) * 8;
            self.words[usize::from(offset / 4)] = self.words[usize::from(offset / 4)]
                & !(0xffff << shift)
                | u32::from(value) << shift;
            Ok(())
        }

        fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
            Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
        }

        fn write8(&mut self, offset: u16, value: u8) -> Result<(), crate::bus::pci::ConfigError> {
            let shift = (offset & 3) * 8;
            let word = self.read32(offset & !3)? & !(0xff << shift) | u32::from(value) << shift;
            self.write32(offset & !3, word)
        }
    }
    // SAFETY: independent narrow-access model; wider writes explicitly panic.
    unsafe impl MsiConfigSpace for Config {}
    fn address(bus: u8, device: u8) -> Address {
        Address {
            segment: 9,
            bus,
            device,
            function: 0,
        }
    }
    fn function(
        bus: u8,
        device: u8,
        bridge: Option<(u8, u8)>,
        writes: &Writes,
    ) -> Function<Config> {
        let address = address(bus, device);
        let mut words = [0; 1024];
        words[0] = 0x1234_abcd;
        words[1] = 0x0010_0400;
        words[2] = if bridge.is_some() {
            0x0604_0001
        } else {
            0x0280_0001
        };
        words[3] = u32::from(bridge.is_some()) << 16;
        words[0x34 / 4] = 0xb0;
        words[0xb0 / 4] = if bridge.is_some() {
            0x0042_0010
        } else {
            0x0002_0010
        };
        words[0xc0 / 4] = 0xa5c3_5a03;
        if let Some((secondary, subordinate)) = bridge {
            words[0x18 / 4] =
                u32::from(bus) | u32::from(secondary) << 8 | u32::from(subordinate) << 16;
        }
        Function::new(
            address,
            Config {
                words,
                address,
                writes: writes.clone(),
                failed: None,
                refuse: false,
            },
        )
        .unwrap()
    }
    fn topology(bridges: Vec<Function<Config>>, bus: u8) -> Topology<Config> {
        // SAFETY: complete explicit independent bridge/root inventory.
        unsafe { Topology::new(bridges, vec![RootBus { segment: 9, bus }]) }
    }
    #[test]
    fn original_parent_and_endpoint_have_narrow_downstream_first_effects() {
        let writes = Writes::default();
        let mut endpoint = function(8, 0, None, &writes);
        let parent = function(4, 1, Some((8, 8)), &writes);
        let mut topology = topology(vec![parent], 4);
        topology.disable(&mut endpoint).unwrap();
        assert_eq!(
            *writes.borrow(),
            vec![(address(8, 0), 0xc0, 0x5a00), (address(4, 1), 0xc0, 0x5a00)]
        );
        let bridges = topology.into_functions();
        assert_eq!(endpoint.config.read32(0xc0).unwrap(), 0xa5c3_5a00);
        assert_eq!(bridges[0].config.read32(0xc0).unwrap(), 0xa5c3_5a00);
    }
    #[test]
    fn nonzero_root_is_required_and_no_absent_parent_is_inferred() {
        let writes = Writes::default();
        let mut endpoint = function(8, 0, None, &writes);
        assert_eq!(
            topology(vec![], 4).disable(&mut endpoint),
            Err(Error::Topology)
        );
        assert!(writes.borrow().is_empty());
        topology(vec![], 8).disable(&mut endpoint).unwrap();
        assert_eq!(writes.borrow().len(), 1);
    }
    #[test]
    fn validate_every_topology_and_capability_before_first_effect() {
        for case in 0..8 {
            let writes = Writes::default();
            let mut endpoint = function(8, 0, None, &writes);
            let mut parent = function(4, 1, Some((8, 8)), &writes);
            let mut extra = Vec::new();
            match case {
                0 => parent.config.words[0x18 / 4] = 0x0808_0003,
                1 => extra.push(function(4, 2, Some((8, 8)), &writes)),
                2 => parent.config.failed = Some(0xc0),
                3 => parent.config.words[0xb0 / 4] = 0x0042_b010,
                4 => endpoint.config.words[0xb0 / 4] = 0x0002_c010,
                5 => parent.config.words[0] = u32::MAX,
                6 => extra.push(function(4, 2, Some((7, 9)), &writes)),
                7 => parent.config.words[0x18 / 4] = 0x0708_0004,
                _ => unreachable!(),
            }
            let mut bridges = vec![parent];
            bridges.extend(extra);
            assert!(
                topology(bridges, 4).disable(&mut endpoint).is_err(),
                "case {case}"
            );
            assert!(writes.borrow().is_empty(), "case {case}");
        }
    }
    #[test]
    fn refused_child_does_not_write_parent_and_refused_parent_keeps_child_disabled() {
        for child in [true, false] {
            let writes = Writes::default();
            let mut endpoint = function(8, 0, None, &writes);
            let mut parent = function(4, 1, Some((8, 8)), &writes);
            endpoint.config.refuse = child;
            parent.config.refuse = !child;
            assert!(topology(vec![parent], 4).disable(&mut endpoint).is_err());
            assert_eq!(writes.borrow().len(), if child { 1 } else { 2 });
            assert_eq!(
                endpoint.config.read16(0xc0).unwrap() & 3,
                if child { 3 } else { 0 }
            );
        }
    }
}

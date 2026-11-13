//! Devices on the I²C buses the ACPI namespace describes: HID-over-I²C
//! keyboards, touchpads and touchscreens (`PNP0C50`), attached as Linux
//! `i2c-hid-acpi` attaches them, and ELAN and Cypress touchpads, which
//! [`TouchpadInput`](crate::input::touchpad::TouchpadInput) reads as a mouse. Each device's `_CRS` names its controller,
//! an Intel LPSS function on PCI or an AMD DesignWare controller the
//! namespace lists, and the GPIO pin its interrupt is; a HID-over-I²C device
//! whose only interrupt is an APIC interrupt is polled on a timer instead.
//! Every controller and GPIO controller attaches once and is shared by the
//! devices on it.
use super::PlatformError;
use crate::bus::i2c::{
    self, Address as I2cAddress,
    timing::{self, BusSpeed, Counts, Firmware},
};
use crate::platform::acpi::{
    Value,
    resources::{Descriptor, GpioKind, Polarity, Resource, SerialKind},
};
use alloc::{string::String, vec::Vec};

/// `_HID`s of HID-over-I²C devices, as Linux `i2c_hid_acpi_match`.
pub(crate) const HID_OVER_I2C: &[&str] = &["ACPI0C50", "PNP0C50"];
/// IDs that claim HID-over-I²C compatibility but are not, as Linux
/// `i2c_hid_acpi_blacklist`.
pub(crate) const NOT_HID_OVER_I2C: &[&str] = &["CHPN0001", "IDEA5002"];
/// `_HID`s of AMD's ACPI-enumerated DesignWare controllers, as Linux
/// `dw_i2c_acpi_match`, with their `acpi_apd` input clocks.
pub(crate) const AMD_CONTROLLERS: &[(&str, u32)] = &[
    ("AMD0010", 133_000_000),
    ("AMDI0010", 150_000_000),
    ("AMDI0019", 150_000_000),
];
/// The HID-over-I²C `_DSM`, 3cdff6f7-4267-4555-ad05-b30a3d8938de, in
/// ACPI's byte order: its function 1 returns the HID descriptor register.
pub(crate) const HID_DSM: [u8; 16] = [
    0xf7, 0xf6, 0xdf, 0x3c, 0x67, 0x42, 0x55, 0x45, 0xad, 0x05, 0xb3, 0x0a, 0x3d, 0x89, 0x38, 0xde,
];
/// ELAN touchpads, as Linux `elan_acpi_id`.
pub(crate) const ELAN: &[&str] = &[
    "ELAN0000", "ELAN0100", "ELAN0600", "ELAN0601", "ELAN0602", "ELAN0603", "ELAN0604", "ELAN0605",
    "ELAN0606", "ELAN0607", "ELAN0608", "ELAN0609", "ELAN060B", "ELAN060C", "ELAN060F", "ELAN0610",
    "ELAN0611", "ELAN0612", "ELAN0615", "ELAN0616", "ELAN0617", "ELAN0618", "ELAN0619", "ELAN061A",
    "ELAN061B", "ELAN061C", "ELAN061D", "ELAN061E", "ELAN061F", "ELAN0620", "ELAN0621", "ELAN0622",
    "ELAN0623", "ELAN0624", "ELAN0625", "ELAN0626", "ELAN0627", "ELAN0628", "ELAN0629", "ELAN062A",
    "ELAN062B", "ELAN062C", "ELAN062D", "ELAN062E", "ELAN062F", "ELAN0631", "ELAN0632", "ELAN0633",
    "ELAN0634", "ELAN0635", "ELAN0636", "ELAN0637", "ELAN1000",
];
/// Cypress touchpads, as Linux `cyapa_acpi_id` lists them with their
/// generations.
pub(crate) const CYPRESS: &[(&str, Kind)] = &[
    ("CYAP0000", Kind::CypressGen3),
    ("CYAP0001", Kind::CypressGen5),
    ("CYAP0002", Kind::CypressGen6),
];

/// The I²C devices probe attaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Hid,
    Elan,
    CypressGen3,
    CypressGen5,
    CypressGen6,
}

/// Linux `i2c_hid_start_hwreset`'s wait for the reset interrupt.
pub(crate) const RESET_TIMEOUT_US: u64 = 5_000_000;

/// The GPIO pin a device's interrupt is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pin {
    /// The GPIO controller's namespace path, as `_CRS` gives it.
    pub controller: String,
    pub pin: u16,
    pub active_low: bool,
    pub debounce_us: u32,
}

/// One I²C device's connection, as its `_CRS` gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Connection {
    pub address: I2cAddress,
    pub speed: u32,
    /// The controller's namespace path, as `_CRS` gives it.
    pub controller: String,
    /// The GPIO pin whose level says the device has input, or none when its
    /// only interrupt is an APIC interrupt, which no driver here can sample:
    /// a HID-over-I²C device is then polled on its input register.
    pub interrupt: Option<Pin>,
}

/// The connection Linux `i2c_acpi_fill_info` and `i2c_acpi_get_irq` read:
/// the first I2cSerialBus and the device's interrupt. Linux takes the first
/// interrupt, an APIC interrupt before any GpioInt; the drivers here poll, so
/// they take the first GpioInt, whose level they can read, even after an
/// APIC interrupt that names the same line. A device with only an APIC
/// interrupt has no pin.
pub(crate) fn connection(descriptors: &[Descriptor]) -> Result<Connection, PlatformError> {
    let serial = descriptors
        .iter()
        .find_map(|descriptor| match &descriptor.resource {
            Resource::Serial(serial) => match serial.kind {
                SerialKind::I2c { address, ten_bit } => Some((serial, address, ten_bit)),
                SerialKind::Spi { .. } => None,
            },
            _ => None,
        });
    let Some((serial, address, ten_bit)) = serial else {
        return Err(PlatformError::Refused(
            "I2C device without an I2cSerialBus connection",
        ));
    };
    let apic = descriptors
        .iter()
        .any(|descriptor| matches!(descriptor.resource, Resource::Interrupt(_)));
    let gpio = descriptors
        .iter()
        .find_map(|descriptor| match &descriptor.resource {
            Resource::Gpio(gpio) => match gpio.kind {
                GpioKind::Interrupt { polarity, .. } => Some((gpio, polarity)),
                GpioKind::Io(_) => None,
            },
            _ => None,
        });
    let interrupt = match gpio {
        Some((gpio, polarity)) => {
            let active_low = match polarity {
                Polarity::Low => true,
                Polarity::High => false,
                Polarity::Both => {
                    return Err(PlatformError::Refused(
                        "I2C device interrupt on both edges, which has no asserted level",
                    ));
                }
            };
            let Some(&pin) = gpio.pins.first() else {
                return Err(PlatformError::Refused("GpioInt without a pin"));
            };
            Some(Pin {
                controller: gpio.source.path.clone(),
                pin,
                active_low,
                debounce_us: u32::from(gpio.debounce) * 10,
            })
        }
        None if apic => None,
        None => return Err(PlatformError::Refused("I2C device without an interrupt")),
    };
    let address = if ten_bit {
        I2cAddress::TenBit(address)
    } else {
        match u8::try_from(address) {
            Ok(address) if address < 0x80 => I2cAddress::SevenBit(address),
            _ => return Err(PlatformError::Refused("7-bit I2C address above 0x7f")),
        }
    };
    Ok(Connection {
        address,
        speed: serial.speed,
        controller: serial.source.path.clone(),
        interrupt,
    })
}

/// The HID descriptor register the `_DSM` returned, as Linux
/// `i2c_hid_acpi_get_descriptor` reads it: an integer, of which the low 16
/// bits are the register.
pub(crate) fn descriptor_register(value: Option<Value<'_>>) -> Result<u16, PlatformError> {
    match value {
        Some(Value::Integer(register)) => Ok(register as u16),
        _ => Err(PlatformError::Refused(
            "HID-over-I2C _DSM did not return the descriptor register",
        )),
    }
}

/// A DesignWare timing method's package of three integers, as Linux
/// `i2c_dw_acpi_params` reads it.
pub(crate) fn counts(value: Option<Value<'_>>) -> Option<Counts> {
    match value {
        Some(Value::Package(values)) => match values.as_slice() {
            [
                Value::Integer(high),
                Value::Integer(low),
                Value::Integer(hold),
            ] => Some(Counts {
                high: *high as u16,
                low: *low as u16,
                sda_hold: *hold as u32,
            }),
            _ => None,
        },
        _ => None,
    }
}

/// An EISA-compressed `_HID` integer as its seven-character ID, as ACPICA's
/// `acpi_ex_eisa_id_to_string`.
pub(crate) fn eisa_id(value: u64) -> String {
    let id = (value as u32).swap_bytes();
    let letter = |shift: u32| char::from(b'@' + ((id >> shift) & 0x1f) as u8);
    alloc::format!(
        "{}{}{}{:04X}",
        letter(26),
        letter(21),
        letter(16),
        id & 0xffff
    )
}

/// A device's `_HID` as a string.
pub(crate) fn hardware_id(value: Option<Value<'_>>) -> Option<String> {
    match value {
        Some(Value::String(bytes)) => String::from_utf8(bytes).ok(),
        Some(Value::Integer(id)) => Some(eisa_id(id)),
        _ => None,
    }
}

/// The PCI location `_ADR` gives a function on a root bus: the device in
/// bits 16..32 and the function in bits 0..16.
pub(crate) fn pci_location(adr: u64, segment: u16, bus: u8) -> Option<crate::bus::pci::Address> {
    let (device, function) = ((adr >> 16) & 0xffff, adr & 0xffff);
    (device < 32 && function < 8).then_some(crate::bus::pci::Address {
        segment,
        bus,
        device: device as u8,
        function: function as u8,
    })
}

/// The timing of a bus whose devices connect at `speeds`.
pub(crate) fn bus_timing(
    speeds: impl IntoIterator<Item = u32>,
    firmware: Firmware,
    board: timing::Board,
) -> i2c::Timing {
    timing::select(BusSpeed::from_connections(speeds), firmware, board)
}

pub(super) use attach::attach;

mod attach {
    use super::*;
    use crate::{
        Clock,
        bus::{
            gpio,
            i2c::{Bus, DesignWare, Operation},
            lpss,
            mmio::owned::{CacheAttribute, Mapping, Protection},
            pci::{
                Bar,
                requester::{FunctionRole, StoppedRequester},
            },
        },
        input::{
            InputDevice,
            hid_i2c::{self, InterruptError},
        },
        input::{
            cyapa, elan,
            touchpad::{self, Driver, TouchpadInput},
        },
        platform::acpi::{
            Argument, Handle, Session,
            resources::{
                DeviceResources, MemoryReservation,
                gpio::{Direction, LinePolicy, NativeController},
            },
        },
        probe::{Devices, NativeServices, ServiceError},
    };
    use alloc::{boxed::Box, format, rc::Rc};
    use core::{cell::RefCell, mem::ManuallyDrop};

    /// A DesignWare register window over an owned mapping.
    struct Window(Mapping);

    impl i2c::Registers for Window {
        fn read32(&mut self, offset: usize) -> Result<u32, i2c::IoError> {
            self.0.read32(offset).map_err(i2c::IoError::Mmio)
        }
        fn write32(&mut self, offset: usize, value: u32) -> Result<(), i2c::IoError> {
            self.0.write32(offset, value).map_err(i2c::IoError::Mmio)
        }
    }

    /// The DesignWare register file's span.
    const REGISTER_BYTES: usize = 0x100;

    /// One attached I²C controller.
    enum Controller {
        Lpss(lpss::I2c<lpss::NativeRegisters, Clock>),
        Acpi(DesignWare<Window, Clock>),
    }

    /// A controller the devices on its bus share.
    #[derive(Clone)]
    struct SharedBus(Rc<RefCell<Controller>>);

    impl Bus for SharedBus {
        fn transaction(
            &mut self,
            address: I2cAddress,
            operations: &mut [Operation<'_>],
        ) -> Result<(), i2c::Error> {
            match &mut *self.0.borrow_mut() {
                Controller::Lpss(bus) => bus.transaction(address, operations),
                Controller::Acpi(bus) => bus.transaction(address, operations),
            }
        }
    }

    /// A device's interrupt pin on a shared GPIO controller, its level read
    /// with the controller's interrupt for it masked.
    struct PinInterrupt {
        controller: Rc<RefCell<gpio::native::Device>>,
        pin: u16,
        active_low: bool,
    }

    impl hid_i2c::Interrupt for PinInterrupt {
        fn mask_and_drain(&mut self) -> Result<(), InterruptError> {
            self.controller
                .borrow_mut()
                .mask_interrupt(self.pin)
                .map_err(|_| InterruptError::Unavailable)
        }
        fn asserted(&mut self) -> Result<bool, InterruptError> {
            let level = self
                .controller
                .borrow_mut()
                .read(self.pin)
                .map_err(|error| InterruptError::Hardware(error.0))?;
            Ok(level != self.active_low)
        }
    }

    /// How often a HID-over-I²C device without a readable pin is polled:
    /// a 125 Hz report rate, as fast as common I²C touchpads report.
    const POLL_INTERVAL_US: u64 = 8_000;

    /// A device whose only interrupt is an APIC interrupt, which no driver
    /// here unmasks or samples: its input register is read on a timer.
    struct PolledInterrupt {
        clock: Clock,
        /// When the next read is due.
        due: u64,
    }

    impl hid_i2c::Interrupt for PolledInterrupt {
        /// The APIC interrupt has no route of its own here: the mount leaves
        /// it masked, and nothing it delivers is waited on.
        fn mask_and_drain(&mut self) -> Result<(), InterruptError> {
            Ok(())
        }
        fn asserted(&mut self) -> Result<bool, InterruptError> {
            let now = self.clock.now_us();
            if now < self.due {
                return Ok(false);
            }
            self.due = now.saturating_add(POLL_INTERVAL_US);
            Ok(true)
        }
        fn polled(&self) -> bool {
            true
        }
    }

    type Attached<T> = Vec<(String, T)>;

    /// What one probe attached, shared by the devices found after it.
    struct Shared {
        buses: Attached<SharedBus>,
        gpios: Attached<Rc<RefCell<gpio::native::Device>>>,
    }

    /// Attach every HID-over-I²C device and touchpad the namespace lists,
    /// each once: a device listing several IDs attaches as the first kind.
    pub(in crate::probe) fn attach(
        services: &dyn NativeServices,
        session: &Session,
        clock: Clock,
        devices: &mut Devices,
    ) {
        let mut found: Vec<(Handle<'_>, Kind)> = Vec::new();
        let kinds = HID_OVER_I2C
            .iter()
            .map(|id| (*id, Kind::Hid))
            .chain(ELAN.iter().map(|id| (*id, Kind::Elan)))
            .chain(CYPRESS.iter().copied());
        for (id, kind) in kinds {
            match session.devices(id) {
                Ok(handles) => {
                    for handle in handles {
                        if !found.iter().any(|(at, _)| *at == handle) {
                            found.push((handle, kind));
                        }
                    }
                }
                Err(error) => devices
                    .platform_failures
                    .push((format!("{id} devices"), PlatformError::Acpi(error.into()))),
            }
        }
        let mut shared = Shared {
            buses: Vec::new(),
            gpios: Vec::new(),
        };
        for (handle, kind) in found {
            let location = handle.path().unwrap_or_else(|_| String::from("I2C device"));
            match device(
                services,
                session,
                clock,
                handle,
                kind,
                &location,
                &mut shared,
                &mut devices.owners,
            ) {
                Ok(Some(input)) => devices.inputs.push(input),
                Ok(None) => {}
                Err(error) => devices.platform_failures.push((location, error)),
            }
        }
    }

    fn acpi(error: crate::platform::acpi::Error) -> PlatformError {
        PlatformError::Acpi(error.into())
    }

    fn native(error: ServiceError) -> PlatformError {
        PlatformError::Native(error)
    }

    /// Whether `handle` is one of the devices `hids` lists.
    fn listed(session: &Session, handle: Handle<'_>, hids: &[&str]) -> Result<bool, PlatformError> {
        for hid in hids {
            if session.devices(hid).map_err(acpi)?.contains(&handle) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Bring `handle` to D0 as Linux `acpi_device_set_power` does when the
    /// device is power-manageable: unless `_PSC` reports D0, turn on its
    /// `_PR0` power resources that are off, then run `_PS0`.
    fn power_on(handle: Handle<'_>) -> Result<(), PlatformError> {
        let present = |method: &str| handle.child(method).is_ok();
        if present("_PSC")
            && handle.evaluate(Some("_PSC"), &[]).map_err(acpi)? == Some(Value::Integer(0))
        {
            return Ok(());
        }
        if present("_PR0") {
            let Some(Value::Package(resources)) =
                handle.evaluate(Some("_PR0"), &[]).map_err(acpi)?
            else {
                return Err(PlatformError::Refused("_PR0 is not a package"));
            };
            for resource in resources {
                let Value::Reference(resource) = resource else {
                    return Err(PlatformError::Refused("_PR0 holds a non-reference"));
                };
                let resource = resource.handle;
                if resource.evaluate(Some("_STA"), &[]).map_err(acpi)? != Some(Value::Integer(1)) {
                    resource.evaluate(Some("_ON"), &[]).map_err(acpi)?;
                }
            }
        }
        if present("_PS0") {
            handle.evaluate(Some("_PS0"), &[]).map_err(acpi)?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the probe's services, namespace and clock, and the device it attaches"
    )]
    fn device(
        services: &dyn NativeServices,
        session: &Session,
        clock: Clock,
        handle: Handle<'_>,
        kind: Kind,
        location: &str,
        shared: &mut Shared,
        owners: &mut Vec<Box<dyn core::any::Any>>,
    ) -> Result<Option<InputDevice>, PlatformError> {
        if kind == Kind::Hid && listed(session, handle, NOT_HID_OVER_I2C)? {
            return Ok(None);
        }
        let minimum = if kind == Kind::Hid {
            let minimum = services.minimum_delay().map_err(native)?;
            minimum.check().map_err(|error| {
                PlatformError::HidI2c(hid_i2c::ErrorKind::Minimum(error).into())
            })?;
            Some(minimum)
        } else {
            None
        };
        let device = DeviceResources::inspect(handle).map_err(PlatformError::Acpi)?;
        let connection = connection(device.descriptors())?;
        let register = if kind == Kind::Hid {
            descriptor_register(
                handle
                    .evaluate(
                        Some("_DSM"),
                        &[
                            Argument::Buffer(&HID_DSM),
                            Argument::Integer(1),
                            Argument::Integer(1),
                            Argument::Package(&[]),
                        ],
                    )
                    .map_err(acpi)?,
            )?
        } else {
            0
        };
        let controller = handle.child(&connection.controller).map_err(acpi)?;
        let bus = bus(services, session, clock, controller, shared, owners)?;
        let interrupt: Box<dyn hid_i2c::Interrupt> = match &connection.interrupt {
            Some(pin) => {
                let gpio = handle.child(&pin.controller).map_err(acpi)?;
                let gpio = gpio_controller(services, gpio, shared)?;
                let mut interrupt = PinInterrupt {
                    controller: gpio,
                    pin: pin.pin,
                    active_low: pin.active_low,
                };
                interrupt
                    .controller
                    .borrow_mut()
                    .request(
                        interrupt.pin,
                        LinePolicy {
                            direction: Direction::Input,
                            debounce_us: pin.debounce_us,
                        },
                    )
                    .map_err(acpi)?;
                hid_i2c::Interrupt::mask_and_drain(&mut interrupt)
                    .map_err(|_| PlatformError::Refused("the interrupt pin could not be masked"))?;
                Box::new(interrupt)
            }
            // Only HID-over-I²C defines an empty input register, which makes
            // reading it without an interrupt safe.
            None if kind == Kind::Hid => Box::new(PolledInterrupt {
                clock,
                due: clock.now_us(),
            }),
            None => {
                return Err(PlatformError::Refused(
                    "I2C touchpad whose only interrupt is an APIC interrupt, which a polled driver cannot read",
                ));
            }
        };
        power_on(handle)?;
        let bus: Box<dyn Bus> = Box::new(bus);
        let address = connection.address;
        let touchpad = |driver| {
            Ok(Some(InputDevice::Touchpad(Box::new(TouchpadInput::new(
                driver,
                clock,
                format!("touchpad {location}"),
            )))))
        };
        let failed = PlatformError::Touchpad;
        match kind {
            Kind::Hid => {
                let attached = hid_i2c::Device::new(
                    bus,
                    interrupt,
                    clock,
                    minimum.unwrap(),
                    address,
                    register,
                    RESET_TIMEOUT_US,
                )
                .and_then(hid_i2c::Device::initialize_owned);
                let attached = match attached {
                    Ok(device) => hid_i2c::HidInput::new(device, format!("I2C-HID {location}")),
                    Err(refusal) => Err(refusal),
                };
                match attached {
                    Ok(input) => Ok(Some(InputDevice::I2cHid(Box::new(input)))),
                    Err(refusal) => {
                        let error = match refusal.error {
                            hid_i2c::RefusalCause::Transport(error) => PlatformError::HidI2c(error),
                            hid_i2c::RefusalCause::Descriptor(error) => {
                                PlatformError::HidDescriptor(error)
                            }
                        };
                        owners.push(Box::new(refusal));
                        Err(error)
                    }
                }
            }
            Kind::Elan => {
                let elan = |error| failed(touchpad::Error::Elan(error));
                let mut device =
                    elan::I2cDevice::new(bus, interrupt, clock, address).map_err(elan)?;
                device.initialize().map_err(elan)?;
                touchpad(Driver::Elan(device))
            }
            Kind::CypressGen3 => {
                let cypress = |error| failed(touchpad::Error::Cypress(error));
                let mut device =
                    cyapa::Device::new(bus, interrupt, clock, address).map_err(cypress)?;
                device.initialize().map_err(cypress)?;
                touchpad(Driver::Cypress(device))
            }
            Kind::CypressGen5 | Kind::CypressGen6 => {
                let pip = |error| failed(touchpad::Error::CypressPip(error));
                let mut device = if kind == Kind::CypressGen5 {
                    cyapa::pip::Device::new(bus, interrupt, clock, address)
                } else {
                    cyapa::pip::Device::new_gen6(bus, interrupt, clock, address)
                }
                .map_err(pip)?;
                device.initialize().map_err(pip)?;
                touchpad(Driver::CypressPip(device))
            }
        }
    }

    /// The bus `controller` drives, attached on first use.
    fn bus(
        services: &dyn NativeServices,
        session: &Session,
        clock: Clock,
        controller: Handle<'_>,
        shared: &mut Shared,
        owners: &mut Vec<Box<dyn core::any::Any>>,
    ) -> Result<SharedBus, PlatformError> {
        let path = controller.path().map_err(acpi)?;
        if let Some((_, bus)) = shared.buses.iter().find(|(at, _)| *at == path) {
            return Ok(bus.clone());
        }
        let speeds = speeds(session, controller)?;
        let firmware = Firmware {
            standard: method(controller, "SSCN")?,
            fast: method(controller, "FMCN")?,
            fast_plus: method(controller, "FPCN")?,
            high: method(controller, "HSCN")?,
        };
        let config = |board| i2c::Config {
            timing: bus_timing(speeds.iter().copied(), firmware, board),
            // Linux's adapter timeout is one second per transfer.
            timeout_us: 1_000_000,
            recovery_timeout_us: 100_000,
        };
        let hid = hardware_id(controller.evaluate(Some("_HID"), &[]).ok().flatten());
        let attached = match AMD_CONTROLLERS
            .iter()
            .find(|(id, _)| hid.as_deref() == Some(*id))
        {
            Some(&(_, clock_hz)) => {
                power_on(controller)?;
                let device = DeviceResources::inspect(controller).map_err(PlatformError::Acpi)?;
                let ordinal = device
                    .descriptors()
                    .iter()
                    .find(|descriptor| matches!(&descriptor.resource, Resource::Address(address) if address.space == crate::platform::acpi::resources::Space::Memory))
                    .map(|descriptor| descriptor.ordinal)
                    .ok_or(PlatformError::Refused("I2C controller without a memory resource"))?;
                let resource = services.acpi_memory(&device, ordinal).map_err(native)?;
                let reservation = MemoryReservation::of(&resource).ok_or(
                    PlatformError::Refused("ACPI memory outside the mount's broker"),
                )?;
                let logical = reservation.physical_span();
                let offset = (logical.start() - resource.physical_span().start()) as usize;
                if (logical.bytes() as usize) < REGISTER_BYTES {
                    return Err(PlatformError::Refused(
                        "I2C controller window under 256 bytes",
                    ));
                }
                let mapping = services
                    .authority()
                    .map_err(native)?
                    .map(
                        resource,
                        offset,
                        REGISTER_BYTES,
                        CacheAttribute::Uncached,
                        Protection::ReadWrite,
                    )
                    .map_err(|error| native(ServiceError::Mapping(error)))?;
                let mapping = ManuallyDrop::new(mapping);
                let board = timing::Board {
                    clock_hz,
                    sda_hold_ns: 0,
                    sda_fall_ns: 0,
                    scl_fall_ns: 0,
                };
                let config = config(board);
                let engine =
                    match DesignWare::new(Window(ManuallyDrop::into_inner(mapping)), clock, config)
                    {
                        Ok(engine) => engine,
                        Err(failure) => {
                            let error = failure.error;
                            owners.push(Box::new(failure));
                            return Err(PlatformError::I2c(error));
                        }
                    };
                Controller::Acpi(engine)
            }
            None => Controller::Lpss(lpss_controller(
                services, session, clock, controller, config, owners,
            )?),
        };
        let bus = SharedBus(Rc::new(RefCell::new(attached)));
        shared.buses.push((path, bus.clone()));
        Ok(bus)
    }

    /// A DesignWare timing method's counts, when the controller has it.
    fn method(controller: Handle<'_>, name: &str) -> Result<Option<Counts>, PlatformError> {
        if controller.child(name).is_err() {
            return Ok(None);
        }
        Ok(counts(controller.evaluate(Some(name), &[]).map_err(acpi)?))
    }

    /// The connection speeds of every device on `controller`'s bus, as Linux
    /// `i2c_acpi_find_bus_speed` walks the namespace for them.
    fn speeds(session: &Session, controller: Handle<'_>) -> Result<Vec<u32>, PlatformError> {
        let mut speeds = Vec::new();
        for device in session.all_devices().map_err(acpi)? {
            if device.child("_CRS").is_err() {
                continue;
            }
            let Ok(descriptors) = crate::platform::acpi::resources::evaluate(device, "_CRS") else {
                continue;
            };
            for descriptor in descriptors {
                if let Resource::Serial(serial) = descriptor.resource
                    && matches!(serial.kind, SerialKind::I2c { .. })
                    && serial
                        .source
                        .resolve(device)
                        .is_ok_and(|source| source == controller)
                {
                    speeds.push(serial.speed);
                }
            }
        }
        Ok(speeds)
    }

    /// The Intel LPSS function `controller` is the companion of.
    fn lpss_controller(
        services: &dyn NativeServices,
        session: &Session,
        clock: Clock,
        controller: Handle<'_>,
        config: impl Fn(timing::Board) -> i2c::Config,
        owners: &mut Vec<Box<dyn core::any::Any>>,
    ) -> Result<lpss::I2c<lpss::NativeRegisters, Clock>, PlatformError> {
        let integer = |handle: Handle<'_>, name: &str| -> Result<Option<u64>, PlatformError> {
            if handle.child(name).is_err() {
                return Ok(None);
            }
            match handle.evaluate(Some(name), &[]).map_err(acpi)? {
                Some(Value::Integer(value)) => Ok(Some(value)),
                _ => Err(PlatformError::Refused(
                    "ACPI integer object is not an integer",
                )),
            }
        };
        let adr = integer(controller, "_ADR")?.ok_or(PlatformError::Refused(
            "I2C controller is neither on PCI nor an AMD controller",
        ))?;
        let path = controller.path().map_err(acpi)?;
        let parent =
            path.rsplit_once('.')
                .map(|(parent, _)| parent)
                .ok_or(PlatformError::Refused(
                    "I2C controller at the namespace root",
                ))?;
        let parent = session.handle(parent).map_err(acpi)?;
        if !listed(session, parent, &["PNP0A08", "PNP0A03"])? {
            return Err(PlatformError::Refused("I2C controller behind a PCI bridge"));
        }
        let bus = integer(parent, "_BBN")?.unwrap_or(0) as u8;
        let segment = integer(parent, "_SEG")?.unwrap_or(0) as u16;
        let address = pci_location(adr, segment, bus)
            .ok_or(PlatformError::Refused("I2C controller _ADR out of range"))?;
        // The LPSS host runs its transfers by PIO and never sets Bus Master,
        // which the claim keeps sealed off.
        let requester =
            crate::probe::services::claim_unmastered(services, address).map_err(native)?;
        let mut function = ManuallyDrop::new(requester.into_function());
        let identity = lpss::Identity {
            vendor: function.vendor,
            device: function.device,
            subsystem_vendor: 0,
            subsystem_device: 0,
        };
        let inspected = (|| {
            let profile = lpss::Profile::select(identity).map_err(PlatformError::Lpss)?;
            let bars = function.bars().map_err(PlatformError::Config)?;
            Ok((profile, bars))
        })();
        let (profile, bars) = match inspected {
            Ok(observed) => observed,
            Err(error) => {
                owners.push(Box::new(function));
                return Err(error);
            }
        };
        // SAFETY: the claim keeps this function's Bus Master sealed off, and
        // sizing its BARs with decode off left it stopped.
        let requester = match unsafe {
            StoppedRequester::from_stopped_pci(
                ManuallyDrop::into_inner(function),
                FunctionRole::Physical,
            )
        } {
            Ok(requester) => ManuallyDrop::new(requester),
            Err((error, function)) => {
                owners.push(Box::new(ManuallyDrop::new(function)));
                return Err(native(ServiceError::Claim(error)));
            }
        };
        let mapped = match bars[0] {
            Some(bar @ Bar::Memory { .. }) => services.map_bar(address, bar).map_err(native),
            _ => Err(native(ServiceError::Refused("missing memory BAR"))),
        };
        let mapping = match mapped {
            Ok(mapping) => ManuallyDrop::new(mapping),
            Err(error) => {
                owners.push(Box::new(requester));
                return Err(error);
            }
        };
        let board = timing::Board {
            clock_hz: profile.input_clock_hz(),
            sda_hold_ns: profile.source_sda_hold_ns(),
            sda_fall_ns: profile.source_sda_fall_ns().unwrap_or(0),
            scl_fall_ns: profile.source_scl_fall_ns().unwrap_or(0),
        };
        let config = config(board);
        // SAFETY: the mount claimed the stopped function and mapped its BAR0
        // uncached; the counts come from the controller's firmware methods or
        // Linux's computation from this profile's input clock and board times.
        match unsafe {
            lpss::I2c::attach_native(
                ManuallyDrop::into_inner(requester),
                ManuallyDrop::into_inner(mapping),
                clock,
                config,
            )
        } {
            Ok(controller) => Ok(controller),
            Err(failure) => {
                let error = failure.error;
                owners.push(Box::new(failure));
                Err(PlatformError::LpssAttach(error))
            }
        }
    }

    /// The GPIO controller at `handle`, attached on first use.
    fn gpio_controller(
        services: &dyn NativeServices,
        handle: Handle<'_>,
        shared: &mut Shared,
    ) -> Result<Rc<RefCell<gpio::native::Device>>, PlatformError> {
        let path = handle.path().map_err(acpi)?;
        if let Some((_, gpio)) = shared.gpios.iter().find(|(at, _)| *at == path) {
            return Ok(gpio.clone());
        }
        let hid = hardware_id(handle.evaluate(Some("_HID"), &[]).map_err(acpi)?)
            .ok_or(PlatformError::Refused("GPIO controller without a _HID"))?;
        let device = DeviceResources::inspect(handle).map_err(PlatformError::Acpi)?;
        let authority = services.authority().map_err(native)?;
        let reserve = |device: &DeviceResources<'_>, ordinal: usize| {
            let resource = services
                .acpi_memory(device, ordinal)
                .map_err(|_| crate::platform::acpi::resources::Error::Unassigned)?;
            MemoryReservation::of(&resource)
                .ok_or(crate::platform::acpi::resources::Error::Unassigned)
        };
        let gpio = gpio::native::Device::attach_with(&device, &hid, &reserve, &authority)
            .map_err(PlatformError::Gpio)?;
        let gpio = Rc::new(RefCell::new(gpio));
        shared.gpios.push((path, gpio.clone()));
        Ok(gpio)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::acpi::resources::{Gpio, Serial, Source, Trigger};

    fn descriptor(resource: Resource) -> Descriptor {
        Descriptor {
            ordinal: 0,
            offset: 0,
            bytes: Vec::new(),
            resource,
        }
    }

    fn serial(address: u16, ten_bit: bool) -> Resource {
        Resource::Serial(Serial {
            consumer: true,
            controller_initiated: false,
            shared: false,
            speed: 400_000,
            kind: SerialKind::I2c { address, ten_bit },
            source: Source {
                index: 0,
                path: String::from("\\_SB.PCI0.I2C1"),
            },
            vendor: Vec::new(),
        })
    }

    fn gpio_interrupt(polarity: Polarity) -> Resource {
        Resource::Gpio(Gpio {
            consumer: true,
            kind: GpioKind::Interrupt {
                trigger: Trigger::Level,
                polarity,
            },
            shared: false,
            wake: false,
            pull: 0,
            drive_strength: 0,
            debounce: 5,
            pins: alloc::vec![0x37],
            source: Source {
                index: 0,
                path: String::from("\\_SB.GPI0"),
            },
            vendor: Vec::new(),
        })
    }

    #[test]
    fn a_connection_is_the_first_serial_bus_and_gpio_interrupt() {
        let descriptors = [
            descriptor(serial(0x15, false)),
            descriptor(serial(0x2c, false)),
            descriptor(gpio_interrupt(Polarity::Low)),
        ];
        assert_eq!(
            connection(&descriptors).unwrap(),
            Connection {
                address: I2cAddress::SevenBit(0x15),
                speed: 400_000,
                controller: String::from("\\_SB.PCI0.I2C1"),
                interrupt: Some(Pin {
                    controller: String::from("\\_SB.GPI0"),
                    pin: 0x37,
                    active_low: true,
                    debounce_us: 50,
                }),
            }
        );
        let ten_bit = [
            descriptor(serial(0x2c5, true)),
            descriptor(gpio_interrupt(Polarity::High)),
        ];
        let found = connection(&ten_bit).unwrap();
        assert_eq!(found.address, I2cAddress::TenBit(0x2c5));
        assert!(!found.interrupt.unwrap().active_low);
    }

    fn apic_interrupt() -> Resource {
        Resource::Interrupt(crate::platform::acpi::resources::Interrupt {
            consumer: true,
            trigger: Trigger::Level,
            polarity: Polarity::Low,
            shared: false,
            wake: false,
            pins: alloc::vec![0x33],
            source: None,
        })
    }

    #[test]
    fn a_connection_needs_an_interrupt_and_a_gpio_one_needs_a_level() {
        for descriptors in [
            alloc::vec![descriptor(serial(0x15, false))],
            alloc::vec![
                descriptor(serial(0x15, false)),
                descriptor(gpio_interrupt(Polarity::Both))
            ],
            alloc::vec![descriptor(gpio_interrupt(Polarity::Low))],
            alloc::vec![
                descriptor(serial(0x80, false)),
                descriptor(gpio_interrupt(Polarity::Low))
            ],
        ] {
            assert!(matches!(
                connection(&descriptors),
                Err(PlatformError::Refused(_))
            ));
        }
    }

    #[test]
    fn an_apic_interrupt_listed_first_gives_way_to_the_gpio_pin() {
        let descriptors = [
            descriptor(serial(0x2c, false)),
            descriptor(apic_interrupt()),
            descriptor(gpio_interrupt(Polarity::Low)),
        ];
        let found = connection(&descriptors).unwrap();
        assert_eq!(
            found.interrupt,
            Some(Pin {
                controller: String::from("\\_SB.GPI0"),
                pin: 0x37,
                active_low: true,
                debounce_us: 50,
            })
        );
    }

    #[test]
    fn a_device_with_only_an_apic_interrupt_has_no_pin() {
        let descriptors = [
            descriptor(serial(0x2c, false)),
            descriptor(apic_interrupt()),
        ];
        let found = connection(&descriptors).unwrap();
        assert_eq!(found.address, I2cAddress::SevenBit(0x2c));
        assert_eq!(found.interrupt, None);
    }

    #[test]
    fn the_descriptor_register_is_the_dsm_integer() {
        assert_eq!(
            descriptor_register(Some(Value::Integer(0x20))).unwrap(),
            0x20
        );
        assert!(descriptor_register(Some(Value::Buffer(alloc::vec![0x20]))).is_err());
        assert!(descriptor_register(None).is_err());
    }

    #[test]
    fn timing_methods_are_packages_of_three_integers() {
        let package = |values: Vec<Value<'static>>| Some(Value::Package(values));
        assert_eq!(
            counts(package(alloc::vec![
                Value::Integer(0x1b0),
                Value::Integer(0x1fb),
                Value::Integer(0x1e)
            ])),
            Some(Counts {
                high: 0x1b0,
                low: 0x1fb,
                sda_hold: 0x1e
            })
        );
        assert_eq!(
            counts(package(alloc::vec![Value::Integer(1), Value::Integer(2)])),
            None
        );
        assert_eq!(counts(Some(Value::Integer(1))), None);
    }

    #[test]
    fn eisa_ids_decode_as_acpica_does() {
        // EisaId("PNP0C50") and EisaId("PNP0A08").
        assert_eq!(eisa_id(0x500c_d041), "PNP0C50");
        assert_eq!(eisa_id(0x080a_d041), "PNP0A08");
        assert_eq!(
            hardware_id(Some(Value::String(b"INT34C5".to_vec()))).as_deref(),
            Some("INT34C5")
        );
    }

    #[test]
    fn adr_gives_the_device_and_function() {
        let address = pci_location(0x0015_0001, 0, 0).unwrap();
        assert_eq!((address.device, address.function), (0x15, 1));
        assert!(pci_location(0x0020_0000, 0, 0).is_none());
        assert!(pci_location(0x0015_0008, 0, 0).is_none());
    }
}

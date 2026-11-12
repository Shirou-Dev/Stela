// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Shared Intel legacy RSA and TLV RSA/ECDSA/LMS initializer over real USB or PCIe
//! command transports, adapted from Linux btintel.c/btusb.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See NOTICE.
//!
//! Supported: the exact USB IDs in identity.rs, platform 0x37 and legacy
//! variants 0x0b/0x0c/0x11–0x14 with secure boot and per-fragment completions.
//! TLV variants 0x17/0x18/0x19/0x1b–0x22 use combined RSA/ECDSA SFI headers and
//! the identified secure boot engine. SFI command streams must be complete,
//! aligned and contain explicit boot parameters. TLV 0x11–0x14 re-read the legacy
//! version instead of guessing a legacy filename from TLV fields. DSBR-dependent
//! uploads keep explicit captured/default platform input and real command
//! acceptance. Variants 0x1e–0x22 boot IML then select the operational
//! image from its FW_ID. Variants 0x20–0x22 additionally accept the source
//! hybrid header and secure engines LMS or ECDSA+LMS. ROM patching and running-image
//! upgrades remain unsupported. Each operational SFI/DDC pair must be present
//! before its upload; initial IML has only its exact SFI requirement.
//! For Uploaded evidence, enabled controller secure ROM authenticates signatures;
//! no host trust-store proof is claimed. Real secure-send/boot events and matching
//! operational identity/version/OTP address are required for that upload report.
//! Already-operational firmware is observed through identity/address checks and
//! reported as RunningUnknown, with no invented image provenance/authentication.
//! PCIe accepts source-listed TLV variants 1e–22 and the same bounded firmware
//! formats as USB. Its wrapper keeps
//! original RFH/completion/padding metadata and requires the real OP D0 handshake.
//! Reports do not establish physical/radio/profile validation.
//!
//! Reset is never given a synthetic Command Complete. A disconnect fails closed;
//! controller re-enumeration/rebind requires future generic USB lifecycle work.
//! No automatic hard-reset/retry loop is attempted over a stale USB slot.
mod firmware;
mod identity;
mod platform;
mod report;
mod stages;
mod tlv;
pub use identity::{BootParameters, Identity};
pub use platform::{DsbrCapture, DsbrCaptureObservation, DsbrInput, DsbrReport, PlatformInputs};
pub use report::{OwnedFirmwareEvidence, OwnedReport};
pub use tlv::{InheritedField, TlvIdentity};

use super::hci::{self as command, Response};
use crate::firmware::{Image, Provider, Requirement};
#[cfg(test)]
use crate::usb::bluetooth::{Hci, Io, State};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::fmt;

/// Physical bus identity remains distinct from the controller's live HCI TLVs.
/// PCIe attachments never invent USB descriptors or USB firmware target labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportIdentity {
    Usb((u16, u16, u16)),
    Pcie(super::intel_pcie::Identity),
}
impl TransportIdentity {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn usb(self) -> Result<(u16, u16, u16)> {
        match self {
            Self::Usb(identity) => Ok(identity),
            Self::Pcie(_) => Err(Error::Unsupported("legacy USB identity on PCIe transport")),
        }
    }
    fn usb_ids(self) -> Option<(u16, u16)> {
        match self {
            Self::Usb((vendor, product, _)) => Some((vendor, product)),
            Self::Pcie(_) => None,
        }
    }
    fn hardware_label(self) -> alloc::string::String {
        match self {
            Self::Usb((vendor, product, revision)) => {
                alloc::format!("usb:{vendor:04x}:{product:04x}:{revision:04x}")
            }
            Self::Pcie(i) => alloc::format!(
                "pci:{:04x}:{:04x}:{:04x}:{:04x}",
                i.vendor,
                i.device,
                i.subsystem_vendor,
                i.subsystem_device
            ),
        }
    }
}

/// An exclusively owned, real HCI command/event transport or independent model.
/// Submission acknowledges physical delivery only. Event polling must return
/// original complete HCI event bytes; no method may inject command completion.
/// Bus-specific wrappers keep any DMA/RFH metadata outside this command engine.
pub trait CommandIo {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn identity(&self) -> Result<TransportIdentity>;
    fn now_us(&self) -> u64;
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn submit_command(&mut self, bytes: &[u8]) -> Result<()>;
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn events(&mut self) -> Result<Vec<Vec<u8>>>;
    /// Correlate HCI image identity with any independent bus boot-stage evidence.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn validate_identity(&self, _identity: &ControllerIdentity) -> Result<()> {
        Ok(())
    }
    /// USB changes identified bulk framing after real endpoint cancellation;
    /// PCIe uses the same four-byte type/framing throughout the download.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn intel_mode(&mut self, bootloader: bool) -> Result<()>;
    /// PCIe verifies the post-boot D0 handshake; USB has no such MMIO.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn finish_boot(&mut self) -> Result<()>;
    /// Close or quarantine the owner and keep any cleanup failure.
    fn fail(&mut self, cause: Error) -> Error;
}

pub(crate) const SECURE_SEND: u16 = 0xfc09;
const READ_VERSION: u16 = 0xfc05;
const READ_BOOT_PARAMS: u16 = 0xfc0d;
const INTEL_RESET: u16 = 0xfc01;
const WRITE_DDC: u16 = 0xfc8b;
const SET_DSBR: u16 = 0xfc0a;
const READ_BD_ADDR: u16 = 0x1009;
const COMMAND_US: u64 = 10_000_000;
const VENDOR_US: u64 = 5_000_000;
const UPLOAD_US: u64 = 120_000_000;
const FRAGMENT_BYTES: usize = 252;

type Result<T> = core::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Transport(crate::usb::bluetooth::Error),
    PcieTransport(super::intel_pcie::Error),
    Resource(crate::firmware::Error),
    Unsupported(&'static str),
    FirmwareFormat(&'static str),
    Protocol(&'static str),
    Controller {
        opcode: u16,
        status: u8,
    },
    Timeout(&'static str),
    /// A later stage failed after completed boots. No ready report is
    /// returned; keep completed observations and the latest parsed identity,
    /// including a rejected later boot rather than substituting the prior IML.
    Stages {
        cause: Box<Error>,
        completed: Vec<StageObservation>,
        pending: Box<ControllerIdentity>,
    },
    /// A boot produced this parsed identity, but validation rejected it.
    /// This observation is never counted among successfully completed stages.
    RejectedBoot {
        cause: Box<Error>,
        observation: Box<StageObservation>,
    },
    Cleanup {
        cause: Box<Error>,
        cleanup: crate::usb::bluetooth::Error,
    },
    PcieCleanup {
        cause: Box<Error>,
        cleanup: Box<super::intel_pcie::Error>,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Intel Bluetooth {self:?}")
    }
}
impl core::error::Error for Error {}
impl From<crate::usb::bluetooth::Error> for Error {
    fn from(e: crate::usb::bluetooth::Error) -> Self {
        Self::Transport(e)
    }
}
impl From<crate::firmware::Error> for Error {
    fn from(e: crate::firmware::Error) -> Self {
        Self::Resource(e)
    }
}
impl From<super::intel_pcie::Error> for Error {
    fn from(error: super::intel_pcie::Error) -> Self {
        Self::PcieTransport(error)
    }
}

/// Observed controller identity. Legacy and TLV wire schemas stay distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControllerIdentity {
    Legacy(Identity),
    Tlv(TlvIdentity),
}
impl ControllerIdentity {
    pub fn is_operational(&self) -> bool {
        match self {
            Self::Legacy(i) => i.firmware_variant == 0x23,
            Self::Tlv(i) => i.image_type == 3,
        }
    }
    pub fn build(&self) -> Option<[u8; 3]> {
        match self {
            Self::Legacy(i) => Some(i.build),
            Self::Tlv(i) => i.build,
        }
    }
    fn same_hardware(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Legacy(a), Self::Legacy(b)) => a.same_hardware(b),
            (Self::Tlv(a), Self::Tlv(b)) => a.same_hardware(b),
            _ => false,
        }
    }
    fn parameters(&self) -> &'static [u8] {
        match self {
            Self::Legacy(_) => &[],
            Self::Tlv(_) => &[0xff],
        }
    }
}
/// Uploaded evidence keeps exact Catalog inputs and real secure-ROM/boot
/// observations. A version/address response from preexisting running firmware
/// supplies no image hash, source provenance or authentication proof.
#[derive(Debug)]
pub enum FirmwareEvidence<'a> {
    Uploaded {
        firmware: Image<'a>,
        configuration: Image<'a>,
    },
    MultiStage {
        firmware: Vec<Image<'a>>,
        configuration: Image<'a>,
    },
    RunningUnknown,
}
// Keep the established Intel receipt path compatible.
pub use crate::usb::bluetooth::FirmwareReceipt;
/// One real secure-send/reset/boot transition, in upload order. Raw observed
/// identities remain separate from explicitly inherited bootloader inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageObservation {
    pub before: ControllerIdentity,
    pub after: ControllerIdentity,
    pub firmware: FirmwareReceipt,
    pub boot_notification: [u8; 6],
    pub inherited: Vec<InheritedField>,
    /// DSBR command accepted after this boot, before any following upload.
    pub dsbr: DsbrReport,
    /// Used when attachment began at an already observed, complete IML.
    pub dsbr_before: DsbrReport,
}
#[derive(Debug)]
pub struct Report<'a> {
    pub before: ControllerIdentity,
    pub after: ControllerIdentity,
    pub evidence: FirmwareEvidence<'a>,
    pub boot_notification: Option<[u8; 6]>,
    pub address: [u8; 6],
    pub dsbr: DsbrReport,
    pub stages: Vec<StageObservation>,
}

/// Share the exact USB candidate table with the native consumer. Matching USB
/// descriptors still requires independent live silicon/firmware validation.
pub(crate) fn is_candidate(device: &crate::usb::xhci::Device) -> bool {
    Identity::usb(device).is_ok()
}
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub(crate) fn usb_identity(device: &crate::usb::xhci::Device) -> Result<TransportIdentity> {
    Ok(TransportIdentity::Usb(Identity::usb(device)?))
}

/// Initialize one exclusively owned raw controller. Any failure after physical
/// identity selection closes/quarantines its transport. Success leaves
/// ordinary command/event traffic open; keep this device-specific report.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub fn initialize<'a, B: CommandIo>(hci: &mut B, provider: &'a dyn Provider) -> Result<Report<'a>> {
    initialize_with_platform(hci, provider, PlatformInputs::default())
}

/// Supply an observed pre-EBS platform capture. Default initialize explicitly
/// records Unavailable; it never impersonates an absent/present UEFI variable.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub fn initialize_with_platform<'a, B: CommandIo>(
    hci: &mut B,
    provider: &'a dyn Provider,
    platform: PlatformInputs,
) -> Result<Report<'a>> {
    hci.identity()?;
    match Engine::new(hci, platform.dsbr).run(provider) {
        Ok(report) => Ok(report),
        Err(cause) => Err(hci.fail(cause)),
    }
}

struct Engine<'a, B: CommandIo> {
    hci: &'a mut B,
    events: VecDeque<Vec<u8>>,
    secure: bool,
    boot: Option<[u8; 6]>,
    allow_secure: bool,
    allow_boot: bool,
    dsbr: DsbrInput,
    /// HCI commands the controller will take now (one after reset).
    credits: u8,
}
impl<'a, B: CommandIo> Engine<'a, B> {
    fn new(hci: &'a mut B, dsbr: DsbrInput) -> Self {
        Self {
            hci,
            events: VecDeque::new(),
            secure: false,
            boot: None,
            allow_secure: false,
            allow_boot: false,
            dsbr,
            credits: 1,
        }
    }
    fn now(&self) -> u64 {
        self.hci.now_us()
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn submit(&mut self, opcode: u16, parameters: &[u8]) -> Result<()> {
        let packet = command::packet(opcode, parameters).map_err(Error::Protocol)?;
        self.hci.submit_command(&packet)?;
        Ok(())
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn pump(&mut self) -> Result<()> {
        for event in self.hci.events()? {
            if event[0] != 0xff {
                self.events.push_back(event);
                continue;
            }
            match event.get(2).copied() {
                Some(6) if self.allow_secure && event.len() == 7 && !self.secure => {
                    // Linux `btintel_secure_send_result` reads the result
                    // byte alone; the opcode and status that follow it are
                    // not checked, and controllers differ in them.
                    if event[3] != 0 {
                        return Err(Error::Protocol(
                            "controller rejected secure image/signature",
                        ));
                    }
                    self.secure = true;
                }
                Some(2) if self.allow_boot && event.len() == 9 && self.boot.is_none() => {
                    let boot: [u8; 6] = event[3..].try_into().unwrap();
                    if boot[0] != 0 || boot[1] == 0 || boot[5] != 0 {
                        return Err(Error::Protocol("invalid Intel boot notification"));
                    }
                    self.boot = Some(boot);
                }
                _ => return Err(Error::Protocol("unexpected/malformed Intel vendor event")),
            }
        }
        if self.events.len() > 16 {
            return Err(Error::Protocol("excess initialization events"));
        }
        Ok(())
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn command(&mut self, opcode: u16, parameters: &[u8]) -> Result<Vec<u8>> {
        if !self.events.is_empty() {
            return Err(Error::Protocol("stale command response"));
        }
        let deadline = self.now().saturating_add(COMMAND_US);
        let mut sent = false;
        loop {
            if !sent && self.credits > 0 {
                self.submit(opcode, parameters)?;
                self.credits -= 1;
                sent = true;
            }
            self.pump()?;
            while let Some(event) = self.events.pop_front() {
                match command::response(&event, opcode).map_err(Error::Protocol)? {
                    Response::Credits(credits) => self.credits = credits,
                    Response::Complete { .. } | Response::Status { .. } if !sent => {
                        return Err(Error::Protocol("command event before its command"));
                    }
                    Response::Complete { credits, returned } => {
                        self.credits = credits;
                        if returned[0] != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status: returned[0],
                            });
                        }
                        return Ok(returned.to_vec());
                    }
                    Response::Status { credits, status } => {
                        self.credits = credits;
                        if status != 0 {
                            return Err(Error::Controller { opcode, status });
                        }
                    }
                    Response::Other => {
                        return Err(Error::Protocol("unexpected/malformed command event"));
                    }
                }
            }
            if self.now() >= deadline {
                return Err(Error::Timeout(if sent {
                    "command completion"
                } else {
                    "HCI command credits"
                }));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn vendor(&mut self, boot: bool) -> Result<()> {
        let deadline = self.now().saturating_add(VENDOR_US);
        loop {
            if if boot {
                self.boot.is_some()
            } else {
                self.secure
            } {
                return Ok(());
            }
            self.pump()?;
            if !self.events.is_empty() {
                return Err(Error::Protocol(
                    "unexpected completion while awaiting vendor notification",
                ));
            }
            if self.now() >= deadline {
                return Err(Error::Timeout(if boot {
                    "boot notification; rebind may be required"
                } else {
                    "secure result"
                }));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn identity(&mut self, parameters: &[u8]) -> Result<ControllerIdentity> {
        let payload = self.command(READ_VERSION, parameters)?;
        let bus = self.hci.identity()?;
        let identity = if payload.len() == 10 && payload[1] == 0x37 {
            ControllerIdentity::Legacy(Identity::parse_usb(bus.usb()?, &payload)?)
        } else if let Some(variant) = TlvIdentity::legacy_fallback(&payload)? {
            let usb = bus.usb()?;
            let payload = self.command(READ_VERSION, &[])?;
            let identity = Identity::parse_usb(usb, &payload)?;
            if identity.hardware_variant != variant {
                return Err(Error::Protocol("legacy/TLV hardware variant mismatch"));
            }
            ControllerIdentity::Legacy(identity)
        } else {
            ControllerIdentity::Tlv(TlvIdentity::parse_transport(bus, &payload)?)
        };
        self.hci.validate_identity(&identity)?;
        Ok(identity)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn address(&mut self) -> Result<[u8; 6]> {
        let payload = self.command(READ_BD_ADDR, &[])?;
        if payload.len() != 7 {
            return Err(Error::Protocol("Read BD_ADDR length"));
        }
        let address = payload[1..].try_into().unwrap();
        identity::valid_address(address)?;
        Ok(address)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn observe_running<'p>(&mut self, before: ControllerIdentity) -> Result<Report<'p>> {
        let address = self.address()?;
        let after = self.identity(before.parameters())?;
        if before != after || !self.events.is_empty() {
            return Err(Error::Protocol("running firmware identity changed"));
        }
        Ok(Report {
            before,
            after,
            evidence: FirmwareEvidence::RunningUnknown,
            boot_notification: None,
            address,
            dsbr: DsbrReport::new(self.dsbr),
            stages: Vec::new(),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;

//! Original phase-specific configuration ownership; no naked native attach.
use super::{Address, ConfigError, ConfigSpace, EcamWindow, msi::MsiConfigSpace};
use crate::bus::mmio::owned::{Error as MappingError, Mapping, MappingView};
mod envelope;
use envelope::Envelope;
pub use envelope::{ConfigParts, PreparedConfig};
pub mod grant;
mod observed;
pub use observed::ObservedConfig;
mod region;
use grant::{DriverGrant, PrepublicationGrant};
pub struct OwnedConfig {
    storage: Envelope<DriverGrant>,
}
pub struct UnpublishedConfig {
    storage: Envelope<PrepublicationGrant>,
}
pub struct ConfigRetention {
    view: MappingView,
    custody: alloc::boxed::Box<dyn grant::ConfigEpoch>,
}
impl ConfigRetention {
    /// Refuse an original mapping that was dropped, quarantined or retired.
    pub fn check_live(&self) -> Result<(), MappingError> {
        self.custody.check()?;
        self.view.check_current()
    }

    /// Retain another view of this same original mapping in its checked
    /// context. This supplies no second writer or new reset/root permission.
    pub fn retain_epoch(&self) -> Result<Self, MappingError> {
        self.check_live()?;
        Ok(Self {
            custody: self.custody.retain()?,
            view: self.view.clone(),
        })
    }

    /// Compare this actual original configuration allocation/epoch, never
    /// equal BDFs, resource numbers or merely a shared mapping platform.
    pub fn same_allocation(&self, other: &Self) -> Result<bool, MappingError> {
        if !self.custody.same_epoch(other.custody.as_ref())? {
            return Ok(false);
        }
        self.view.shares_mapping(&other.view)
    }

    /// Compare actual installed mapping-platform provenance only. This
    /// establishes no endpoint/BAR, I/O, writer, stop or completion permission.
    pub fn shares_authority(&self, mapping: &Mapping) -> Result<bool, MappingError> {
        self.custody.check()?;
        mapping.shares_authority(&self.view)
    }
    /// Compare kept permissions, never caller-supplied numeric IDs.
    pub fn matches_mapping(&self, mapping: &Mapping) -> Result<bool, MappingError> {
        self.custody.check()?;
        mapping.shares_mapping(&self.view)
    }
}

impl OwnedConfig {
    /// Retain only actual endpoint metadata-denial storage before publication.
    /// It exposes no I/O, source/config backedge or completion/release proof.
    pub fn admission_close(&self) -> Result<super::assignment::AdmissionClose, MappingError> {
        self.storage.region().admission_close()
    }
    pub fn seal_bus_master(&mut self) -> Result<(), ConfigError> {
        self.storage.region_mut().seal_bus_master()
    }
    pub fn seal_bus_routing(&mut self) -> Result<(), ConfigError> {
        self.storage.region_mut().seal_bus_routing()
    }
    /// # Safety
    /// Actual owning driver stop/reset, no old restart, current root/config
    /// binding and required payload completion have all been acknowledged.
    /// Native source still validates real requester/engine admission separately.
    pub unsafe fn release_bus_master_seal(&mut self) {
        // SAFETY: caller holds actual original admission/retirement receipts.
        unsafe { self.storage.region_mut().release_bus_master_seal() }
    }
    /// # Safety
    /// Complete original descendant cohort is contained/retired, new roots
    /// blocked, leaf seals enforced and actual bridge assignment remains frozen.
    pub unsafe fn release_bus_forwarding_seal(&mut self) -> Result<(), ConfigError> {
        // SAFETY: actual whole-source retirement proof, never endpoint stop.
        unsafe { self.storage.region_mut().release_bus_forwarding_seal() }
    }

    /// Assert or release Secondary Bus Reset on this routing-sealed bridge,
    /// the sealed Bridge Control word otherwise unchanged.
    ///
    /// # Safety
    /// The caller owns every function below the bridge, each stopped or
    /// contained, restores or keeps refusing each after the reset, and
    /// releases the reset it asserted.
    pub unsafe fn set_secondary_bus_reset(&mut self, asserted: bool) -> Result<(), ConfigError> {
        // SAFETY: forwarded.
        unsafe { self.storage.region_mut().set_secondary_bus_reset(asserted) }
    }

    pub fn prepare(grant: DriverGrant) -> PreparedConfig<DriverGrant> {
        envelope::prepare(grant)
    }

    pub fn address(&self) -> Address {
        self.storage.region().address()
    }
    pub fn window(&self) -> EcamWindow {
        self.storage.region().window()
    }
    pub fn matches_binding(
        &self,
        binding: &super::requester::RequesterBinding,
    ) -> Result<bool, MappingError> {
        self.storage.region().matches_binding(binding)
    }
    pub fn matches_retention(&self, retained: &ConfigRetention) -> Result<bool, MappingError> {
        self.storage.region().matches_retention(retained)
    }
    pub fn retain_epoch(&self) -> Result<ConfigRetention, MappingError> {
        self.storage.region().retain_epoch()
    }
    pub fn into_parts(self) -> ConfigParts<DriverGrant> {
        ConfigParts(self.storage)
    }
    /// # Safety
    /// Every actual config/device/raw pointer/DMA/IRQ/callback user has ended;
    /// caller owns complete original retirement, no new access may start.
    /// Failure keeps SAME owner and no actual grant/assignment release follows.
    pub unsafe fn retire(&mut self) -> Result<(), MappingError> {
        // SAFETY: caller supplies this exact original mapping retirement.
        unsafe { self.storage.retire() }
    }
    pub fn try_read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.storage.region().try_read8(offset)
    }
    pub fn try_write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.storage.region_mut().try_write8(offset, value)
    }
    pub fn try_read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.storage.region().try_read16(offset)
    }
    pub fn try_write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.storage.region_mut().try_write16(offset, value)
    }
    pub fn try_read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.storage.region().try_read32(offset)
    }
    pub fn try_write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.storage.region_mut().try_write32(offset, value)
    }
}
#[cfg(test)]
impl OwnedConfig {
    fn attach_test(
        grant: DriverGrant,
        mapping: Mapping,
    ) -> Result<Self, (ConfigError, DriverGrant, Mapping)> {
        Self::prepare(grant)
            .attach(mapping)
            .map_err(|(error, parts)| {
                let (grant, mapping) = parts.into_test_parts();
                (error, grant, mapping)
            })
    }
}
impl ConfigSpace for OwnedConfig {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.try_read8(offset)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.try_write8(offset, value)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.try_read16(offset)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.try_write16(offset, value)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.try_read32(offset)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.try_write32(offset, value)
    }
}
impl UnpublishedConfig {
    /// Withdraw this temporary map and keep the same prepublication slot,
    /// resource, admission projection and operation state. A later attach
    /// maps that original resource again.
    ///
    /// # Safety
    /// All access through this map, including raw and posted-write users,
    /// has stopped and cannot restart. The same source retains exclusive
    /// custody and the same physical decode throughout the withdrawal.
    pub unsafe fn park(
        self,
    ) -> Result<PreparedConfig<PrepublicationGrant>, (MappingError, ConfigParts<PrepublicationGrant>)>
    {
        // SAFETY: the caller keeps the source and has ended this map's users.
        unsafe { envelope::park(self) }
    }

    /// Transfer the exact configuration into its driver phase. The mapping,
    /// operation state, command and routing seals survive. Refusal closes
    /// admission and keeps the original owning envelope.
    ///
    /// # Safety
    /// The sole original producer has joined every prepublication user.
    /// The source callback must consume the actual completed root/unit and
    /// source retirement and topology promotion for this physical slot.
    /// It may update policy while preserving the original mapping, epoch,
    /// assignment and all hardware obligations.
    pub unsafe fn promote<P: grant::PrepublicationCustody + grant::DriverCustody>(
        self,
        qualify: impl FnOnce(&mut P) -> Result<(), MappingError>,
    ) -> Result<OwnedConfig, (MappingError, ConfigParts<PrepublicationGrant>)> {
        envelope::promote(self, qualify)
    }

    pub fn seal_bus_master(&mut self) -> Result<(), ConfigError> {
        self.storage.region_mut().seal_bus_master()
    }
    pub fn seal_bus_routing(&mut self) -> Result<(), ConfigError> {
        self.storage.region_mut().seal_bus_routing()
    }

    pub fn prepare(grant: PrepublicationGrant) -> PreparedConfig<PrepublicationGrant> {
        envelope::prepare(grant)
    }

    pub fn address(&self) -> Address {
        self.storage.region().address()
    }
    pub fn window(&self) -> EcamWindow {
        self.storage.region().window()
    }
    pub fn matches_binding(
        &self,
        binding: &super::requester::RequesterBinding,
    ) -> Result<bool, MappingError> {
        self.storage.region().matches_binding(binding)
    }
    pub fn matches_retention(&self, retained: &ConfigRetention) -> Result<bool, MappingError> {
        self.storage.region().matches_retention(retained)
    }
    pub fn retain_epoch(&self) -> Result<ConfigRetention, MappingError> {
        self.storage.region().retain_epoch()
    }
    pub fn into_parts(self) -> ConfigParts<PrepublicationGrant> {
        ConfigParts(self.storage)
    }
    /// # Safety
    /// Every actual config/device/raw pointer/DMA/IRQ/callback user has ended;
    /// caller owns complete original retirement, no new access may start.
    /// Failure keeps SAME owner and no actual grant/assignment release follows.
    pub unsafe fn retire(&mut self) -> Result<(), MappingError> {
        // SAFETY: caller supplies this exact original mapping retirement.
        unsafe { self.storage.retire() }
    }
    pub fn try_read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.storage.region().try_read8(offset)
    }
    pub fn try_write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.storage.region_mut().try_write8(offset, value)
    }
    pub fn try_read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.storage.region().try_read16(offset)
    }
    pub fn try_write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.storage.region_mut().try_write16(offset, value)
    }
    pub fn try_read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.storage.region().try_read32(offset)
    }
    pub fn try_write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.storage.region_mut().try_write32(offset, value)
    }
}
impl super::requester::containment::MasterSeal for UnpublishedConfig {
    fn seal_bus_master(&mut self) -> Result<(), ConfigError> {
        self.storage.region_mut().seal_bus_master()
    }
    fn seal_hardwired_bus_master(&mut self, disabled: u16) -> Result<(), ConfigError> {
        if super::requester::containment::hardwired_master(self, disabled)? {
            self.storage.region_mut().seal_hardwired_bus_master()
        } else {
            self.storage.region_mut().seal_bus_master()
        }
    }
}
impl ConfigSpace for UnpublishedConfig {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.try_read8(offset)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.try_write8(offset, value)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.try_read16(offset)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.try_write16(offset, value)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.try_read32(offset)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.try_write32(offset, value)
    }
}
// SAFETY: actual final DriverGrant owns exclusive exact-width config access
// and source-owned operation/phase permissions. No unpublished IRQ admission.
unsafe impl MsiConfigSpace for OwnedConfig {}
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod transport_tests;

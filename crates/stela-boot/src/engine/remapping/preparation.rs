//! The retained original VT-d/AMD root used during vendor cold preparation.
use super::*;
use alloc::boxed::Box;
use stela_drivers::bus::pci::{owned::OwnedConfig, requester::preparation::Root};

struct VtdRoot {
    address: Address,
    unit: Arc<Unit<MmioRegisters>>,
    blocked: BlockedRequester<MmioRegisters>,
    _lines: native_mmio::InitialPciLines,
}

enum BridgeRoot {
    Intel(BlockedRequester<MmioRegisters>),
    Amd(amd::ColdRoot),
    /// No remapping hardware exists to hold a context for the port.
    Unremapped,
}

impl BridgeRoot {
    fn check(&self) -> Result<(), DmaError> {
        match self {
            Self::Intel(blocked) => blocked.check(),
            Self::Amd(blocked) => blocked.check(),
            Self::Unremapped => Ok(()),
        }
    }
}

// SAFETY: constructed only from the requester's selected original taken unit,
// under the mount's frozen routing epoch. The unit keeps its mapped registers,
// initial DMA backing and uncertain table resources. Engine/IRQ/work stop is
// the receipt producer's independent obligation; neither method infers it.
unsafe impl Root for VtdRoot {
    fn drain(&self) -> Result<(), DmaError> {
        self.blocked.drain()
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> Result<Box<dyn stela_drivers::bus::pci::requester::preparation::AttachmentBackend>, DmaError>
    {
        if binding.address() != self.address {
            return Err(DmaError::IommuUnavailable);
        }
        // SAFETY: the consuming current-epoch driver receipt supplies stop,
        // exclusion and the completed original root drain; binding is the
        // paired original configuration and this same retained unit.
        let claim = unsafe { RequesterClaim::from_binding(binding) }
            .map_err(|_| DmaError::MappingFailed)?;
        // SAFETY: same consumed receipt and original root/configuration epoch.
        let domain = unsafe { self.unit.attach_requester(claim, self.blocked.aliases()) }
            .map_err(|_| DmaError::MappingFailed)?;
        Ok(Box::new(VtdAttachment {
            address: self.address,
            domain,
        }))
    }
}

struct VtdAttachment {
    address: Address,
    domain: crate::native_dma::vtd::BoundRequester<MmioRegisters>,
}
// SAFETY: this unique control owns the same actual domain and immutable
// RID/DID/generation as the consumed original binding. Backend detach blocks
// the context and completes invalidation before returning its retained claim.
// Old Arc references check that generation and cannot reach a replacement.
// The local owner closes admission and retains the whole claim on Drop;
// the shared projection has no configuration callback or local actor edge.
unsafe impl stela_drivers::bus::pci::requester::preparation::AttachmentBackend for VtdAttachment {
    fn irq_owner(
        &mut self,
        _requester: &stela_drivers::bus::pci::requester::RequesterId,
        _config: Option<&stela_drivers::bus::pci::owned::ConfigRetention>,
    ) -> Result<Option<Box<dyn stela_drivers::bus::irq::posted_msi::RouteOwner>>, DmaError> {
        // Explicit component prerequisite. The separate native producer delta
        // consumes the actual original all-unit mode/root owner and actual
        // source pairing; no numeric/BDF observer or empty success replaces it.
        Ok(None)
    }

    fn domain(&self) -> Arc<dyn DmaDomain> {
        self.domain.domain()
    }
    unsafe fn detach(
        &mut self,
    ) -> Result<(), stela_drivers::bus::pci::requester::preparation::DetachError> {
        // SAFETY: caller supplies current-epoch quiescence and payload/IRQ/work
        // drains with original owners kept. Backend refuses live mappings
        // before context effects.
        // This metadata-only preflight precedes every hardware effect. Actual
        // detach failures below are all uncertain, regardless of error variant.
        if self
            .domain
            .has_live_mappings()
            .map_err(stela_drivers::bus::pci::requester::preparation::DetachError::Unexposed)?
        {
            return Err(
                stela_drivers::bus::pci::requester::preparation::DetachError::Unexposed(
                    DmaError::MappingFailed,
                ),
            );
        }
        // SAFETY: caller retains the quiesced current epoch and joined IRQ/work;
        // the preflight above ruled out live payload mappings before detach.
        let claim = unsafe { self.domain.detach() }.map_err(|error| {
            output::arguments(format_args!(
                "HOST IOMMU VT-d detach {} refused: {error:?}\n",
                self.address
            ));
            DmaError::MappingFailed
        })?;
        drop(claim);
        Ok(())
    }
}

impl Remappers {
    /// # Safety
    /// The original AMD units and the parked PCI fabric exclude all other
    /// configuration and topology writers. No bridge in `scope` has resumed
    /// forwarding; one outside it did so only after its own recheck.
    pub(super) unsafe fn recheck_amd_stopped(
        &self,
        pci: &native_mmio::ContainedPci<'_>,
        scope: native_mmio::PciScope,
    ) -> Result<(), native_mmio::ContainmentError> {
        // SAFETY: kept unit configuration reads match the original addresses
        // and the caller keeps the rest of the stopped fabric exclusive.
        unsafe {
            pci.recheck_stopped_scoped(scope, |address, offset, width| {
                self.amd
                    .iter()
                    .find_map(|unit| unit.read_original_config(address, offset, width))
            })
        }
    }

    fn initial_bridge(
        &self,
        source: &native_mmio::Source,
        address: Address,
        lines: &native_mmio::InitialPciLines,
        amd: bool,
    ) -> Result<BridgeRoot, DmaError> {
        if self.unremapped {
            return Ok(BridgeRoot::Unremapped);
        }
        let rid = requester(address);
        if amd {
            let taken = self
                .amd(address.segment, rid)
                .map_err(|_| DmaError::IommuUnavailable)?
                .ok_or(DmaError::IommuUnavailable)?;
            return taken
                .preparation(address, lines.clone())
                .map(BridgeRoot::Amd);
        }
        let taken = self
            .vtd(address.segment, rid)
            .map_err(|_| DmaError::IommuUnavailable)?
            .ok_or(DmaError::IommuUnavailable)?;
        let blocked = self
            .initial_requester(source, taken, rid, &[])?
            .ok_or(DmaError::DrainUnavailable)?;
        if blocked.requester() != rid {
            return Err(DmaError::IommuUnavailable);
        }
        Ok(BridgeRoot::Intel(blocked))
    }

    pub(in crate::engine) fn forward_pci_bridges(&self, pci: &native_mmio::ContainedPci<'_>) {
        let Some(lines) = &self.initial_lines else {
            return;
        };
        let source = pci.source();
        let bridges = match pci.bridges() {
            Ok(bridges) if bridges.is_empty() => return,
            Ok(bridges) => bridges,
            Err(error) => {
                output::arguments(format_args!(
                    "HOST PCI bridge inventory unavailable: {error:?}\n"
                ));
                return;
            }
        };
        let amd = self
            .amd_fabric
            .is_some_and(|original| core::ptr::eq(original, source));
        // Upstream bridges come first, so each bridge's own bus is rechecked
        // just before it forwards, while the bridges on that bus are still
        // closed. A function that changed withholds only the bridge above it
        // and the bridges below that one.
        for address in bridges {
            let scope = native_mmio::PciScope::Bridge(address);
            // SAFETY: this startup step precedes every driver and competing
            // PCI writer. The same complete blocked remappers and line owners
            // are kept, and no bridge in this scope forwards yet. A unit kept
            // in any mode holds its own function's configuration page, which
            // the whole-space view cannot map beside it.
            let stopped = unsafe {
                if self.amd.is_empty() {
                    pci.recheck_stopped(scope)
                } else {
                    self.recheck_amd_stopped(pci, scope)
                }
            };
            if let Err(error) = stopped {
                output::arguments(format_args!(
                    "HOST PCI bridge {address} forwarding withheld: {error}\n"
                ));
                continue;
            }
            let blocked = match self.initial_bridge(source, address, lines, amd) {
                Ok(blocked) => blocked,
                Err(error) => {
                    output::arguments(format_args!(
                        "HOST PCI bridge {address} blocked context unavailable: {error:?}\n"
                    ));
                    continue;
                }
            };
            // SAFETY: exact firmware-selected blocked RID, the original kept
            // line paths, checked stopped leaves and frozen topology. Other
            // reopened ports retain their own original blocked contexts.
            match unsafe { source.forward_cold_bridge(address, lines, move || blocked.check()) } {
                Ok(()) => output::arguments(format_args!(
                    "HOST PCI bridge {address} forwarding restored with routing sealed\n"
                )),
                Err(error) => output::arguments(format_args!(
                    "HOST PCI bridge forwarding withheld: {error}\n"
                )),
            }
        }
    }

    /// A requester's cold configuration on a platform that describes no
    /// remapping hardware, with the contained interrupt paths it keeps. None
    /// when an IOMMU is described, whose own preparation then applies.
    pub(in crate::engine) fn unremapped_preparation(
        &self,
        source: &native_mmio::Source,
        address: Address,
    ) -> Option<Result<(OwnedConfig, native_mmio::InitialPciLines), PreparationError>> {
        if !self.unremapped {
            return None;
        }
        Some((|| {
            let lines = self
                .initial_lines
                .as_ref()
                .ok_or(PreparationError::Interrupt(MappingError::Unavailable))?;
            lines.check(source).map_err(PreparationError::Interrupt)?;
            // SAFETY: with no remapping hardware the complete remapping
            // fabric is empty and no root can block or translate this RID.
            // The parked master seal holds, and the kept line paths and
            // source exclude every other configuration and topology writer.
            let config = unsafe { source.promote_cold_config(address, lines, || Ok(())) }
                .map_err(PreparationError::Configuration)?;
            Ok((config, lines.clone()))
        })())
    }

    pub(in crate::engine) fn preparation(
        &self,
        source: &native_mmio::Source,
        address: Address,
    ) -> Result<(OwnedConfig, Box<dyn Root>), PreparationError> {
        let rid = requester(address);
        if let Some(taken) = self
            .amd(address.segment, rid)
            .map_err(|_| DmaError::IommuUnavailable)?
        {
            if !self
                .amd_fabric
                .is_some_and(|original| core::ptr::eq(original, source))
            {
                return Err(PreparationError::AmdConfiguration);
            }
            let lines = self
                .initial_lines
                .as_ref()
                .ok_or(PreparationError::Interrupt(MappingError::Unavailable))?;
            lines.check(source).map_err(PreparationError::Interrupt)?;
            // The unit attaches the IVRS aliases with the requester and
            // refuses a requester whose alias another one shares; an alias
            // the IVRS does not name would reach no domain of this one.
            let aliases = source
                .requester_aliases(address)
                .map_err(PreparationError::Configuration)?;
            if !taken.arrives_under(rid, &aliases) {
                return Err(PreparationError::Configuration(
                    native_mmio::ContainmentError::bridge_alias(address),
                ));
            }
            let root = taken.preparation(address, lines.clone())?;
            // SAFETY: the complete original AMD fabric is blocked, the
            // selected unit owns this exact entry and gives its domain each
            // alias, and the kept line/source owners exclude prior
            // configuration and topology writers.
            let config = unsafe { source.promote_cold_config(address, lines, || root.check()) }
                .map_err(PreparationError::Configuration)?;
            return Ok((config, Box::new(root)));
        }
        let taken = self
            .vtd(address.segment, rid)
            .map_err(|_| DmaError::IommuUnavailable)?
            .filter(|taken| taken.unit.allows(rid))
            .ok_or(DmaError::DrainUnavailable)?;
        let lines = self
            .initial_lines
            .as_ref()
            .ok_or(PreparationError::Interrupt(MappingError::Unavailable))?;
        lines.check(source).map_err(PreparationError::Interrupt)?;
        let aliases = self
            .vtd_aliases(source, address, taken)
            .map_err(PreparationError::Configuration)?;
        // The claim keeps each alias blocked for this requester alone: a
        // function sharing one cannot claim it and stays parked.
        let blocked = self
            .initial_requester(source, taken, rid, &aliases)?
            .ok_or(DmaError::DrainUnavailable)?;
        // SAFETY: this root is selected from the same fully contained fabric
        // and this slot's exact firmware route, and its claim holds each
        // alias for the requester's domain. Legacy probing is read-only
        // while this fabric is active, and AML's ECAM writers are excluded.
        let config = unsafe {
            source.promote_cold_config(address, lines, || {
                if blocked.requester() != rid {
                    return Err(DmaError::IommuUnavailable);
                }
                blocked.check()
            })
        }
        .map_err(PreparationError::Configuration)?;
        let root = Box::new(VtdRoot {
            address,
            unit: taken.unit.clone(),
            blocked,
            _lines: lines.clone(),
        });
        Ok((config, root))
    }
}

//! Cold requester preparation keeps the original configuration and DMA root
//! until a driver-owned quiescence receipt permits private-domain attachment.
use super::*;
use crate::bus::dma::mapping::{DmaDomain, DmaError};
use alloc::{boxed::Box, sync::Arc};
mod attachment;
pub use attachment::{
    Attachment, CancelFailure, DetachedRequester, PinReleaseFailure, RetainActionFailure,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachError {
    /// Audited refusal before hardware publication or binding release.
    Unexposed(DmaError),
    /// Hardware/ownership transition may have begun; retain and do not retry.
    Uncertain(DmaError),
}
impl From<DmaError> for DetachError {
    fn from(error: DmaError) -> Self {
        Self::Uncertain(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Claim(ClaimError),
    Dma(DmaError),
    ForeignOwner,
}
/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Claim(error) => error.fmt(f),
            Self::Dma(error) => error.fmt(f),
            Self::ForeignOwner => f.write_str("another owner changed its configuration"),
        }
    }
}

/// Unique control of one attached requester, beside its shareable DMA domain.
///
/// # Safety
/// The domain is bound to this exact original configuration/root generation.
/// `detach` refuses live mappings, checks its original epoch, blocks the actual
/// requester/alias DTEs and completes required invalidation before releasing
/// configuration retention. Old domain references refuse all later map/unmap/
/// sync operations and cannot reach a replacement generation. Failure/unwind
/// and Drop without acknowledged detach retain uncertain roots, bindings,
/// reservations and pins. Every method observes the owner's execution context.
pub unsafe trait AttachmentBackend {
    fn domain(&self) -> Arc<dyn DmaDomain>;
    /// Construct an unused grant from this exact original root/configuration.
    /// The borrowed identity comes from this same concrete Attachment; use it
    /// with the backend's actual retained original config/root, never a lookup.
    /// No route or endpoint is programmed here. None explicitly reports missing
    /// notification admission; it is not successful empty completion.
    fn irq_owner(
        &mut self,
        _requester: &crate::bus::pci::requester::RequesterId,
        _config: Option<&crate::bus::pci::owned::ConfigRetention>,
    ) -> Result<Option<Box<dyn crate::bus::irq::posted_msi::RouteOwner>>, DmaError> {
        Ok(None)
    }
    /// # Safety
    /// This exact original requester is stopped and cannot resume. Payload,
    /// bypass and former callback/work users are drained. Every old action has
    /// joined while its original stable CPU/root/format notification ownership
    /// remains retained; late ordinary fixed/edge packets may notify only a
    /// current valid status-checking handler. This is not all-issued completion
    /// or permission to change that CPU/root/format. Strong root ledgers and
    /// their tombstones are never reclaimed by endpoint detach.
    /// Paired configuration/BAR/root owners stay kept through detach and subsequent
    /// retirement. Remaining mapped leases cause refusal before hardware
    /// retirement; they must be quiescently unmapped for success. No reset/reassignment
    /// changes that epoch. This is not a stop or drain request to the driver.
    unsafe fn detach(&mut self) -> Result<(), DetachError>;
}

/// The original root path, before the requester gets its private domain.
///
/// # Safety
/// This is the original function's kept translation/configuration/routing
/// epoch. `drain` acknowledges earlier translated payload writes through that
/// path; a CPU fence, Bus Master clear or bare command fetch cannot suffice.
/// Bypass/peer traffic must be independently excluded or drained by its owner.
/// `bind` uses the same original root, function and epoch, meets DmaDomain's
/// complete contract and keeps the original root/resources alive. Failure or
/// unwind retains uncertain hardware tables, domain reservations and pins.
/// Dropping an exposed root must retain uncertain hardware resources.
/// Each operation admits only the root's allowed process/processor context.
/// No callback may reset/reassign the requester or reenter its preparation.
pub unsafe trait Root {
    fn drain(&self) -> Result<(), DmaError>;
    /// # Safety
    /// The original paired requester is currently quiescent, this root's
    /// drain completed, and its configuration/reset/routing epoch cannot change
    /// before attachment finishes. The original owners remain kept throughout.
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> Result<Box<dyn AttachmentBackend>, DmaError>;
}

struct Resources {
    function: Function<OwnedConfig>,
    retained: ConfigRetention,
    address: Address,
    identity: (u16, u16, [u8; 3]),
    root: Box<dyn Root>,
}

/// Dropping preparation cannot establish device stop or root completion.
/// Keep the whole graph on early exit, error or unwind until boot ends.
struct Owner(Option<Box<Resources>>);
impl Drop for Owner {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
impl Owner {
    fn resources(&mut self) -> &mut Resources {
        self.0.as_deref_mut().expect("owned cold requester")
    }
    fn completed(mut self) -> Resources {
        *self.0.take().expect("owned cold requester")
    }
}

/// Original configuration and root ownership, without a stopped/DMA grant.
/// The driver may perform its cold vendor stop/reset through `function_mut`.
pub struct PreparingRequester {
    owner: Owner,
}

/// A non-cloneable acknowledgement containing the same original owner.
/// It exposes no configuration writer, so reset cannot occur between receipt
/// issuance and consuming finalization through a safe preparation accessor.
pub struct QuiescenceReceipt {
    owner: Owner,
}

/// Rejected construction returns the same original owners without granting
/// device quiescence or permission to retire their resources.
pub struct Rejected {
    pub error: ClaimError,
    pub function: Function<OwnedConfig>,
    pub root: Box<dyn Root>,
}

/// Failure keeps the original configuration/root, even if dropped.
pub struct Failure {
    pub error: Error,
    _owner: Owner,
}

/// A stopped original requester with its newly attached domain.
pub struct BoundRequester {
    pub requester: StoppedRequester,
    pub attachment: Attachment,
}

impl PreparingRequester {
    /// # Safety
    /// `role` comes from the complete PF/VF inventory, never local capability
    /// absence. `function` is the exclusively owned physical function, independently
    /// admitted for coherent WB DMA. `root` is its original root path. Prior
    /// firmware/configuration/IRQ delivery and worker owners are excluded and
    /// kept; no Stela submission/IRQ/work user exists yet. This grants no
    /// endpoint engine stop, posted-payload drain or new DMA domain.
    pub unsafe fn new(
        function: Function<OwnedConfig>,
        role: FunctionRole,
        root: Box<dyn Root>,
    ) -> Result<Self, Rejected> {
        if role != FunctionRole::Physical {
            return Err(Rejected {
                error: ClaimError::UnsupportedRole(role),
                function,
                root,
            });
        }
        // Keep the original graph before the first configuration callback.
        // Explicit refusal returns it; an unwind cannot drop its old root.
        let mut pending = core::mem::ManuallyDrop::new((function, root));
        let address = pending.0.address;
        let retained = (|| {
            let config = pending.0.config();
            if address != config.address() {
                return Err(ClaimError::IdentityChanged);
            }
            config.seal_bus_master().map_err(ClaimError::Config)?;
            config.retain_epoch().map_err(ClaimError::Mapping)
        })();
        let retained = match retained {
            Ok(retained) => retained,
            Err(error) => {
                let (function, root) = core::mem::ManuallyDrop::into_inner(pending);
                return Err(Rejected {
                    error,
                    function,
                    root,
                });
            }
        };
        let identity = (pending.0.vendor, pending.0.device, pending.0.class);
        // Allocate the complete retained stage before ending the unwind guard.
        let mut resources = Box::new_uninit();
        let (function, root) = core::mem::ManuallyDrop::into_inner(pending);
        resources.write(Resources {
            function,
            retained,
            address,
            identity,
            root,
        });
        // SAFETY: the exact resource record was initialized above.
        let resources = unsafe { resources.assume_init() };
        Ok(Self {
            owner: Owner(Some(resources)),
        })
    }

    pub fn function_mut(&mut self) -> &mut Function<OwnedConfig> {
        &mut self.owner.resources().function
    }

    /// Keep this original function for a driver that never sets Bus Master,
    /// such as an SMBus or I2C host. Its seal stays set for the owner's life,
    /// so the function issues no memory request, MSI included, and needs
    /// neither an engine stop nor a new domain. The original root is never
    /// drained or bound; it and the epoch retention stay kept until boot ends.
    pub fn into_unmastered(self) -> Function<OwnedConfig> {
        let Resources {
            function,
            retained,
            root,
            ..
        } = self.owner.completed();
        core::mem::forget(retained);
        core::mem::forget(root);
        function
    }

    /// # Safety
    /// The owning driver has acknowledged engine stop/reset and submission
    /// exclusion for this original function, with no possibility of restart.
    /// All firmware, IRQ delivery and worker users are retired; bypass/peer
    /// traffic is independently excluded or drained. Keep BARs and all old
    /// DMA backing alongside this receipt until finalization or quarantine.
    /// This does not grant posted-payload completion: finalization asks the
    /// original root for that acknowledgement before binding a new domain.
    pub unsafe fn acknowledge_quiescence(self) -> QuiescenceReceipt {
        QuiescenceReceipt { owner: self.owner }
    }
}

impl QuiescenceReceipt {
    pub fn finalize(mut self) -> Result<BoundRequester, Failure> {
        let result = (|| {
            let resources = self.owner.resources();
            let function = &mut resources.function;
            if function.address != resources.address
                || (function.vendor, function.device, function.class) != resources.identity
                || function.config().address() != resources.address
                || !function
                    .config()
                    .matches_retention(&resources.retained)
                    .map_err(|error| Error::Claim(ClaimError::Mapping(error)))?
            {
                return Err(Error::ForeignOwner);
            }
            resources.root.drain().map_err(Error::Dma)?;
            validate_stopped(function).map_err(Error::Claim)?;
            let retained = function
                .config()
                .retain_epoch()
                .map_err(|error| Error::Claim(ClaimError::Mapping(error)))?;
            let irq_retained = function
                .config()
                .retain_epoch()
                .map_err(|error| Error::Claim(ClaimError::Mapping(error)))?;
            // Keep the returned affine backend before any later context check.
            let mut backend = core::mem::ManuallyDrop::new(
                // SAFETY: the consumed driver receipt excludes new producers;
                // the original configuration seal still matches, its root drain
                // completed, and all owners stay in this attempt until success.
                unsafe {
                    resources.root.bind(RequesterBinding {
                        address: resources.address,
                        retention: retained,
                    })
                }
                .map_err(Error::Dma)?,
            );
            irq_retained
                .check_live()
                .map_err(|error| Error::Claim(ClaimError::Mapping(error)))?;
            // SAFETY: the same consumed binding/root produced this backend;
            // the original configuration's context/epoch was checked again.
            let attachment = unsafe {
                Attachment::new(core::mem::ManuallyDrop::take(&mut backend), irq_retained)
            };
            if !attachment
                .matches_config(function.config())
                .map_err(Error::Dma)?
            {
                return Err(Error::ForeignOwner);
            }
            validate_stopped(function).map_err(Error::Claim)?;
            // SAFETY: the original driver stop, original-root completion and
            // new current binding were all acknowledged. Release only this
            // endpoint's software seal, without enabling bus mastering.
            unsafe { function.config().release_bus_master_seal() };
            Ok(attachment)
        })();
        match result {
            Ok(attachment) => {
                let resources = self.owner.completed();
                Ok(BoundRequester {
                    requester: StoppedRequester {
                        function: resources.function,
                        address: resources.address,
                        dma_bound: true,
                    },
                    attachment,
                })
            }
            Err(error) => Err(Failure {
                error,
                _owner: self.owner,
            }),
        }
    }
}

#[cfg(test)]
mod tests;

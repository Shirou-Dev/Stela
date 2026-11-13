//! Function-local GPU reset while the original configuration and DMA root stay owned.
use alloc::{boxed::Box, rc::Rc};
use core::mem::ManuallyDrop;
use stela_driver_base::{
    block::BlockError,
    bus::pci::{
        CapabilityError, ConfigSpace, Function, ResetMethod, capability,
        power::{self, Timer},
        requester::{
            self, ClaimError,
            preparation::{self, BoundRequester, PreparingRequester},
        },
    },
};

const NVIDIA: u16 = 0x10de;
const DISPLAY: u8 = 3;
const EXPRESS: u8 = 0x10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewError {
    Context,
    Busy,
    Root,
    Cache,
    Retired,
    RegisterReadback,
    ForeignSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Clock(power::Error),
    Identity,
    Claim(ClaimError),
    Capability(CapabilityError),
    /// No function-local reset, and DMA is not translated.
    ResetUnavailable,
    Views(ViewError),
    Reset(BlockError),
    Preparation(preparation::Error),
}

/// The original CPU framebuffer/register writers and their translation owners.
///
/// # Safety
/// This is a real retained root/view owner for the same native bootstrap. It
/// confirms the supplied function against its retained original configuration
/// owner before acknowledging any seal; a BDF/label comparison is insufficient.
/// It excludes firmware, other CPUs and source/work users that could restore an
/// old GPU view. `seal` joins executing CPU writers and makes old framebuffer
/// status/fatal/reclaim/fallback paths unavailable until a new owned framebuffer
/// epoch is installed. It drains their CPU WC stores and completes a safe
/// uncached read from this exact GPU after the fence, so CPU posted writes to
/// this function precede its reset. A CPU fence alone is not that PCI ordering.
/// All original mappings, backing, code and root owners remain held through
/// reset/bind/failure; Drop never reopens old views or reclaims uncertain data.
/// This supplies no DMA drain, no private domain and no new framebuffer grant.
/// Timing and operations are admitted only on the original process/CPU context.
pub unsafe trait Views<C: ConfigSpace>: 'static {
    fn seal(&mut self, function: &mut Function<C>) -> Result<(), ViewError>;
}

/// An original requester/root, or an explicitly unsafe diagnostic peer.
///
/// # Safety
/// The function is the original exclusive physical configuration/reset epoch,
/// already gated for BME/MSI/INTx, with old hardware backing kept. The platform
/// excludes competing firmware/configuration/reset and software producers.
/// `finalize` consumes the same current-epoch stop receipt, drains the ORIGINAL
/// remapper payload path and only then attaches a private domain once. Failure,
/// panic and abandoned Drop retain all uncertain roots/configuration/backing.
/// No new allocation, IRQ route or DMA submission occurs before finalization.
pub unsafe trait Preparation: 'static {
    type Config: ConfigSpace;
    type Bound: 'static;
    type Failure;
    fn function_mut(&mut self) -> &mut Function<Self::Config>;
    /// # Safety
    /// A function-local reset (FLR or D3hot soft reset) and readiness/
    /// containment revalidation completed with CPU views sealed and all old
    /// owners still kept, or the function has no such reset and the private
    /// domain translates its every request, so engines firmware left running
    /// reach only that domain. Nothing can rearm the function before the
    /// original root drain and private bind.
    unsafe fn finalize(self) -> Result<Self::Bound, (preparation::Error, Self::Failure)>;
}

// SAFETY: PreparingRequester keeps the original config seal and original Root;
// its consumed receipt validates and drains that same path before binding once.
unsafe impl Preparation for PreparingRequester {
    type Config = stela_driver_base::bus::pci::owned::OwnedConfig;
    type Bound = BoundRequester;
    type Failure = preparation::Failure;
    fn function_mut(&mut self) -> &mut Function<Self::Config> {
        self.function_mut()
    }
    unsafe fn finalize(self) -> Result<Self::Bound, (preparation::Error, Self::Failure)> {
        // SAFETY: Cold reset the function, or found it has no reset and its
        // DMA translated, and sealed the original CPU views.
        unsafe { self.acknowledge_quiescence() }
            .finalize()
            .map_err(|failure| (failure.error, failure))
    }
}

pub struct Inputs<P: Preparation, V: Views<P::Config>> {
    pub requester: P,
    pub views: V,
    pub timer: Rc<dyn Timer>,
}

struct Pending<P, V> {
    requester: Option<P>,
    views: V,
    timer: Rc<dyn Timer>,
    translated: bool,
}

/// A single consumed cold attempt. Abandonment retains the actual inputs.
pub struct Cold<P: Preparation, V: Views<P::Config>> {
    kept: ManuallyDrop<Box<Pending<P, V>>>,
}

#[must_use]
pub struct Failure<P: Preparation, V: Views<P::Config>> {
    pub error: Error,
    _kept: Cold<P, V>,
    _binding: Option<ManuallyDrop<P::Failure>>,
}

/// Private-domain attachment and the still-retained original view/root owners.
/// Unfinished Drop retains both, even after a successful binding.
pub struct Ready<B, V> {
    bound: ManuallyDrop<B>,
    views: ManuallyDrop<V>,
    reset: Option<ResetMethod>,
}
impl<B, V> Ready<B, V> {
    /// The reset the function had, or None when it started in the state
    /// firmware left, as Linux starts it.
    pub fn reset(&self) -> Option<ResetMethod> {
        self.reset
    }
    /// # Safety
    /// Transfer both owners into the same native function lifetime before any
    /// probe/DMA/IRQ effect. Keep the original view/root guard through endpoint
    /// retirement. This is not authorization to reopen firmware framebuffer
    /// views or release a bound requester without its independent DMA/IRQ proof.
    pub unsafe fn into_parts(self) -> (B, V) {
        (
            ManuallyDrop::into_inner(self.bound),
            ManuallyDrop::into_inner(self.views),
        )
    }
}

fn preflight<C: ConfigSpace>(
    function: &mut Function<C>,
    timer: &dyn Timer,
    translated: bool,
) -> Result<Option<ResetMethod>, Error> {
    timer.check().map_err(Error::Clock)?;
    if function.vendor != NVIDIA || function.class[0] != DISPLAY {
        return Err(Error::Identity);
    }
    requester::validate_stopped(function).map_err(Error::Claim)?;
    let mut express = None;
    for entry in capability::capabilities(function.config()) {
        let entry = entry.map_err(Error::Capability)?;
        if entry.id == EXPRESS && express.replace(entry.offset).is_some() {
            return Err(Error::Identity);
        }
    }
    // Linux `pci_reset_function` falls back from FLR to a D3hot soft reset.
    // nouveau itself never resets: it starts what firmware left. Without
    // translation, an engine firmware left running could write recycled
    // RAM once bus mastering is on, so then a reset stays required.
    let reset = function.reset_method().map_err(Error::Reset)?;
    if reset.is_none() && !translated {
        return Err(Error::ResetUnavailable);
    }
    Ok(reset)
}

/// Read-only early qualification before native BAR probing/mapping. Success
/// grants no stop, root drain, view seal or private-domain authority; Cold
/// repeats the same checks immediately before its consumed reset attempt.
/// `translated`: whether an active remapper confines the function's DMA.
pub fn check_candidate<C: ConfigSpace>(
    function: &mut Function<C>,
    timer: &dyn Timer,
    translated: bool,
) -> Result<Option<ResetMethod>, Error> {
    preflight(function, timer, translated)
}
impl<P: Preparation, V: Views<P::Config>> Cold<P, V> {
    pub fn new(inputs: Inputs<P, V>) -> Self {
        Self {
            kept: ManuallyDrop::new(Box::new(Pending {
                requester: Some(inputs.requester),
                views: inputs.views,
                timer: inputs.timer,
                translated: false,
            })),
        }
    }

    /// Let a function with no function-local reset start in the state
    /// firmware left, without one.
    ///
    /// # Safety
    /// The private domain the requester binds translates its every request,
    /// so DMA from engines firmware left running reaches only that domain.
    pub unsafe fn translated(mut self) -> Self {
        self.kept.translated = true;
        self
    }

    pub fn quiesce_and_bind(mut self) -> Result<Ready<P::Bound, V>, Failure<P, V>> {
        let attempt = &mut **self.kept;
        let requester = attempt.requester.as_mut().expect("original cold requester");
        let result = (|| {
            let reset = preflight(
                requester.function_mut(),
                attempt.timer.as_ref(),
                attempt.translated,
            )?;
            attempt
                .views
                .seal(requester.function_mut())
                .map_err(Error::Views)?;
            let function = requester.function_mut();
            if reset.is_some()
                && function
                    .reset(attempt.timer.as_ref())
                    .map_err(Error::Reset)?
                    != reset
            {
                return Err(Error::ResetUnavailable);
            }
            requester::validate_stopped(function).map_err(Error::Claim)?;
            Ok(reset)
        })();
        let reset = match result {
            Ok(reset) => reset,
            Err(error) => {
                return Err(Failure {
                    error,
                    _kept: self,
                    _binding: None,
                });
            }
        };

        let requester = attempt.requester.take().expect("original cold requester");
        // SAFETY: this exact function completed its reset, or has none and its
        // DMA is translated, and stopped revalidation.
        // The original CPU views remain parked through the root drain and bind.
        match unsafe { requester.finalize() } {
            Ok(bound) => {
                let bound = ManuallyDrop::new(bound);
                // SAFETY: finalization acknowledged the original binding; take
                // this consumed envelope once, and transfer its exact views.
                let inputs = unsafe { ManuallyDrop::take(&mut self.kept) };
                Ok(Ready {
                    bound,
                    views: ManuallyDrop::new(inputs.views),
                    reset,
                })
            }
            Err((error, failure)) => Err(Failure {
                error: Error::Preparation(error),
                _kept: self,
                _binding: Some(ManuallyDrop::new(failure)),
            }),
        }
    }
}

#[cfg(test)]
mod tests;

//! The drivers' shared timing owner, and the minimum-delay models the
//! adapter tests run under.
#[cfg(test)]
use crate::bus::pci::power::Timer;
#[cfg(test)]
use crate::{Clock, block::BlockError};
#[cfg(test)]
use alloc::rc::Rc;
pub(crate) use stela_driver_base::timing::Timing;
#[cfg(test)]
pub(crate) fn model(nominal: Clock) -> Timing {
    use core::cell::Cell;
    struct ModelMinimum {
        elapsed: Cell<u64>,
    }
    // SAFETY: explicit isolated virtual-time model, never native timing permission.
    unsafe impl Timer for ModelMinimum {
        fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
            Ok(())
        }
        fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
            let next = self
                .elapsed
                .get()
                .checked_add(us)
                .ok_or(crate::bus::pci::power::Error::Clock)?;
            self.elapsed.set(next);
            Ok(())
        }
    }
    Timing::checked(
        nominal,
        Rc::new(ModelMinimum {
            elapsed: Cell::new(0),
        }),
    )
    .expect("isolated timing model")
}

/// [`model`], with the virtual microseconds its minimum delays waited.
#[cfg(test)]
pub(crate) fn counted_model(nominal: Clock) -> (Timing, Rc<core::cell::Cell<u64>>) {
    use core::cell::Cell;
    struct ModelMinimum {
        elapsed: Rc<Cell<u64>>,
    }
    // SAFETY: explicit isolated virtual-time model, never native timing permission.
    unsafe impl Timer for ModelMinimum {
        fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
            Ok(())
        }
        fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
            let next = self
                .elapsed
                .get()
                .checked_add(us)
                .ok_or(crate::bus::pci::power::Error::Clock)?;
            self.elapsed.set(next);
            Ok(())
        }
    }
    let elapsed = Rc::new(Cell::new(0));
    let timing = Timing::checked(
        nominal,
        Rc::new(ModelMinimum {
            elapsed: elapsed.clone(),
        }),
    )
    .expect("isolated timing model");
    (timing, elapsed)
}

#[cfg(test)]
pub(crate) struct RefusedMinimum {
    _nominal: Clock,
}
#[cfg(test)]
pub(crate) fn refused_model(nominal: Clock) -> RefusedMinimum {
    RefusedMinimum { _nominal: nominal }
}
// SAFETY: this private model never grants any successful hardware wait.
#[cfg(test)]
unsafe impl Timer for RefusedMinimum {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        Err(crate::bus::pci::power::Error::Clock)
    }
    fn wait_us(&self, _: u64) -> Result<(), crate::bus::pci::power::Error> {
        Err(crate::bus::pci::power::Error::Clock)
    }
}

#[cfg(test)]
pub(crate) fn controlled_model(nominal: Clock) -> (Timing, Rc<core::cell::Cell<bool>>) {
    use core::cell::Cell;
    struct ModelMinimum {
        failed: Rc<Cell<bool>>,
        elapsed: Cell<u64>,
    }
    // SAFETY: isolated virtual-time peer only; no native minimum is granted.
    unsafe impl Timer for ModelMinimum {
        fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
            if self.failed.get() {
                Err(crate::bus::pci::power::Error::Clock)
            } else {
                Ok(())
            }
        }
        fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
            self.check()?;
            self.elapsed.set(self.elapsed.get() + us);
            Ok(())
        }
    }
    let failed = Rc::new(Cell::new(false));
    let timing = Timing::checked(
        nominal,
        Rc::new(ModelMinimum {
            failed: failed.clone(),
            elapsed: Cell::new(0),
        }),
    )
    .unwrap();
    (timing, failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    struct Peer {
        failed: Cell<bool>,
        checks: Cell<usize>,
        elapsed: Cell<u64>,
    }
    // SAFETY: explicit isolated virtual-time peer; no physical permission is created.
    unsafe impl Timer for Peer {
        fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
            self.checks.set(self.checks.get() + 1);
            if self.failed.get() {
                Err(crate::bus::pci::power::Error::Clock)
            } else {
                Ok(())
            }
        }
        fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
            self.check()?;
            self.elapsed.set(self.elapsed.get() + us);
            Ok(())
        }
    }
    #[test]
    fn same_retained_minimum_provider_controls_waits_independently_of_nominal_rate() {
        let peer = Rc::new(Peer {
            failed: Cell::new(false),
            checks: Cell::new(0),
            elapsed: Cell::new(0),
        });
        let weak = Rc::downgrade(&peer);
        let timing = Timing::checked(
            Clock {
                ticks_per_microsecond: 0,
            },
            peer.clone(),
        )
        .unwrap();
        assert_eq!(timing.nominal().ticks_per_microsecond, 0);
        timing.delay(37).unwrap();
        assert_eq!(peer.elapsed.get(), 37);
        peer.failed.set(true);
        assert_eq!(
            timing.delay(19),
            Err(BlockError::PciPower(crate::bus::pci::power::Error::Clock))
        );
        assert_eq!(peer.elapsed.get(), 37);
        let kept = timing.clone();
        drop(timing);
        drop(peer);
        assert_eq!(weak.strong_count(), 1);
        assert!(kept.delay(1).is_err());
        drop(kept);
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn unavailable_minimum_refuses_construction_before_any_wait() {
        let peer = Rc::new(Peer {
            failed: Cell::new(true),
            checks: Cell::new(0),
            elapsed: Cell::new(0),
        });
        let result = Timing::checked(
            Clock {
                ticks_per_microsecond: 3000,
            },
            peer.clone(),
        );
        assert!(matches!(
            result,
            Err(BlockError::PciPower(crate::bus::pci::power::Error::Clock))
        ));
        assert_eq!(peer.checks.get(), 1);
        assert_eq!(peer.elapsed.get(), 0);
    }
}

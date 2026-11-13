//! AMD IOMMU register access and command-queue operation.
use super::*;

impl<P: ColdPlatform, C: UnitConfig> Engine<P, C> {
    pub(super) fn read(&self, offset: usize) -> Result<u64, Error> {
        self.resources
            .inspection
            .native_read(offset)
            .map_err(Error::Register)
    }
    pub(super) fn write(&self, offset: usize, value: u64) -> Result<(), Error> {
        self.resources
            .inspection
            .native_write(offset, value)
            .map_err(Error::Register)
    }
    /// Clear what the firmware left in a unit it stopped. Firmware that set
    /// the unit up and turned it off again, or only wrote its IVHD flags
    /// into the control register, leaves table and ring addresses, pointers
    /// and status bits behind. Linux's `early_enable_iommus` turns every
    /// unit off and writes all of these anew; so does this, and
    /// [`Self::check_cold`] then reads them back. A unit that translates or
    /// runs its rings is left as found, and refused there.
    pub(super) fn reset_stopped(&self) -> Result<(), Error> {
        let control = self.read(CONTROL)?;
        let status = self.read(STATUS)?;
        if control & (IOMMU_ENABLE | EVENT_ENABLE | COMMAND_ENABLE) != 0 {
            return Err(Error::NotCold {
                register: CONTROL,
                value: control,
            });
        }
        if status & RUNNING != 0 {
            return Err(Error::NotCold {
                register: STATUS,
                value: status,
            });
        }
        for offset in [
            CONTROL,
            DEVICE_TABLE,
            COMMAND_BASE,
            EVENT_BASE,
            EXCLUSION_BASE,
            EXCLUSION_LIMIT,
            COMMAND_HEAD,
            COMMAND_TAIL,
            EVENT_HEAD,
            EVENT_TAIL,
        ] {
            if self.read(offset)? != 0 {
                self.write(offset, 0)?;
            }
        }
        // Its event and wait bits are cleared by writing them.
        if status != 0 {
            self.write(STATUS, status)?;
        }
        Ok(())
    }
    pub(super) fn check_cold(&self) -> Result<(), Error> {
        for register in [
            CONTROL,
            STATUS,
            DEVICE_TABLE,
            COMMAND_BASE,
            EVENT_BASE,
            EXCLUSION_BASE,
            EXCLUSION_LIMIT,
            COMMAND_HEAD,
            COMMAND_TAIL,
            EVENT_HEAD,
            EVENT_TAIL,
        ] {
            let value = self.read(register)?;
            if value != 0 {
                return Err(Error::NotCold { register, value });
            }
        }
        if self.hardware_errors {
            // A hardware error the firmware saw is kept as evidence.
            let value = self.read(HARDWARE_EVENT_STATUS)?;
            if value != 0 {
                return Err(Error::NotCold {
                    register: HARDWARE_EVENT_STATUS,
                    value,
                });
            }
        }
        Ok(())
    }
    pub(super) fn initialize(&self, table: u64) -> Result<(), Error> {
        self.poisoned.set(true);
        self.table_base.set(table);
        self.write(DEVICE_TABLE, table)?;
        self.write(COMMAND_BASE, self.resources.command.physical | RING_LENGTH)?;
        self.write(EVENT_BASE, self.resources.event.physical | RING_LENGTH)?;
        self.write(COMMAND_HEAD, 0)?;
        self.write(COMMAND_TAIL, 0)?;
        self.write(EVENT_HEAD, 0)?;
        self.write(EVENT_TAIL, 0)?;
        self.write(CONTROL, self.control)?;
        let deadline = self.resources.platform.clock().deadline(self.wait_us);
        loop {
            self.resources.platform.relax();
            if self.read(CONTROL)? != self.control {
                return Err(Error::Fault);
            }
            if self.read(STATUS)? == RUNNING {
                break;
            }
            if deadline.passed() {
                return Err(Error::Timeout);
            }
        }
        self.poisoned.set(false);
        self.execute(&[Command::invalidate_all()])
    }
    fn healthy_registers(&self) -> Result<(), Error> {
        // An event is a fault even if its memory record has not reached RAM.
        // Preserve ring/status evidence rather than clear and retry. No PPR/GA/
        // completion IRQ or interrupt mode is enabled in this polled profile.
        if self.read(CONTROL)? != self.control
            || self.read(STATUS)? != RUNNING
            || self.read(DEVICE_TABLE)? != self.table_base.get()
            || self.read(EVENT_HEAD)? != 0
            || self.read(EVENT_TAIL)? != 0
            || self.read(COMMAND_BASE)? != self.resources.command.physical | RING_LENGTH
            || self.read(EVENT_BASE)? != self.resources.event.physical | RING_LENGTH
            || (self.hardware_errors && self.read(HARDWARE_EVENT_STATUS)? != 0)
        {
            return Err(Error::Fault);
        }
        Ok(())
    }
    pub(super) fn health(&self) -> Result<(), Error> {
        if self.poisoned.get() || self.retired.get() {
            return Err(Error::Poisoned);
        }
        if let Err(error) = self.healthy_registers() {
            self.poisoned.set(true);
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn execute(&self, commands: &[Command]) -> Result<(), Error> {
        if commands.is_empty() || commands.len() > 2 {
            return Err(Error::Profile);
        }
        let _guard = self.resources.platform.enter().map_err(Error::Dma)?;
        self.health()?;
        let mut queue = self.queue.try_borrow_mut().map_err(|_| Error::Busy)?;
        let head = self.read(COMMAND_HEAD)?;
        let tail = self.read(COMMAND_TAIL)?;
        // One serialized synchronous batch: exact previous consumer head must
        // reach the last acknowledged tail before any ring slot can be reused.
        if head != queue.tail as u64 || tail != queue.tail as u64 {
            self.poisoned.set(true);
            return Err(Error::Fault);
        }
        let sequence = queue.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        let completion = Command::completion(
            PhysicalAddress::new(
                self.resources.completion.physical,
                self.resources.platform.physical_bits(),
            )
            .map_err(|_| Error::Profile)?,
            sequence,
            false,
        )
        .map_err(|_| Error::Profile)?;
        // Poison before the first shared RAM mutation/callback, including unwind.
        self.poisoned.set(true);
        let mut next = queue.tail;
        for command in commands.iter().copied().chain(core::iter::once(completion)) {
            self.resources.command.command(next, command)?;
            next = (next + COMMAND_BYTES) % RING_BYTES;
        }
        self.resources.command.publish(&self.resources.platform)?;
        queue.sequence = sequence;
        queue.tail = next;
        self.write(COMMAND_TAIL, next as u64)?;
        let deadline = self.resources.platform.clock().deadline(self.wait_us);
        loop {
            self.resources.platform.relax();
            self.healthy_registers()?;
            // Exact sequence, not >=, rules out foreign/future writeback. This
            // queue never wraps its sequence or has two batches outstanding.
            let observed = self.resources.completion.sequence()?;
            let head = self.read(COMMAND_HEAD)?;
            if head >= RING_BYTES as u64 || !head.is_multiple_of(COMMAND_BYTES as u64) {
                return Err(Error::Fault);
            }
            if observed == sequence && head == next as u64 {
                drop(_guard);
                self.poisoned.set(false);
                return Ok(());
            }
            if observed > sequence {
                return Err(Error::Fault);
            }
            if deadline.passed() {
                return Err(Error::Timeout);
            }
        }
    }
}

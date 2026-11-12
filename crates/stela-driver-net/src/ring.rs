//! The polled descriptor rings the PCI Ethernet drivers share: sixteen-byte
//! descriptors, 256 unless a driver asks otherwise, with one 2 KiB DMA buffer
//! each, the next descriptor the driver fills and, for transmit, the oldest
//! one the controller still owns.
use crate::{
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
};
use core::sync::atomic::{Ordering, fence};

/// Linux e1000e's and igb's default ring length (`E1000_DEFAULT_RXD`,
/// `IGB_DEFAULT_RXD`): a polled host drains less often than an interrupt
/// handler, and a short ring drops frames that arrive meanwhile.
pub(crate) const DESCRIPTORS: usize = 256;
pub(crate) const DESCRIPTOR: usize = 16;
pub(crate) const BUFFER: usize = 2048;
const PAGE: usize = 4096;
/// Receive descriptors handed back per tail write, as Linux's
/// `E1000_RX_BUFFER_WRITE`: the tail is an MMIO write a hypervisor traps.
pub(crate) const RECEIVE_BATCH: usize = 16;

/// Write a frame to a CPU-owned transmit buffer and clear any transmitted padding.
pub(crate) fn write_transmit_frame(buffer: &mut [u8], frame: &[u8], length: usize) {
    let (payload, padding) = buffer[..length].split_at_mut(frame.len());
    payload.copy_from_slice(frame);
    if !padding.is_empty() {
        padding.fill(0);
    }
}

pub(crate) struct Ring {
    pub(crate) descriptors: DmaBuffer,
    buffers: DmaBuffer,
    /// Descriptors in the ring.
    pub(crate) count: usize,
    /// The next descriptor the driver fills or reads.
    pub(crate) next: usize,
    /// The oldest transmit descriptor the controller has not written back.
    pub(crate) clean: usize,
    /// Receive descriptors handed back since the tail last moved, and the
    /// last of them.
    unposted: usize,
    offered: usize,
}

impl Ring {
    pub(crate) fn new(dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Self::with(dma, DESCRIPTORS)
    }

    /// A ring of `count` descriptors, a multiple of eight so its length
    /// stays a multiple of 128 bytes.
    pub(crate) fn with(dma: &mut dyn DmaAllocator, count: usize) -> Result<Self, BlockError> {
        if count == 0 || !count.is_multiple_of(8) {
            return Err(BlockError::Unsupported("Ethernet ring length"));
        }
        let descriptors = dma.allocate(count * DESCRIPTOR, PAGE)?;
        let buffers = dma.allocate(count * BUFFER, PAGE)?;
        let fits = |buffer: &DmaBuffer, bytes: usize| {
            buffer.len() == bytes
                && buffer.bus_address().is_multiple_of(PAGE as u64)
                && buffer.bus_address().checked_add(bytes as u64).is_some()
        };
        if !fits(&descriptors, count * DESCRIPTOR) || !fits(&buffers, count * BUFFER) {
            return Err(BlockError::Unsupported(
                "Ethernet ring outside its DMA allocation",
            ));
        }
        Ok(Self {
            descriptors,
            buffers,
            count,
            next: 0,
            clean: 0,
            unposted: 0,
            offered: 0,
        })
    }

    /// The descriptors' bus address and length in bytes, for the
    /// controller's base and length registers.
    pub(crate) fn base(&self) -> u64 {
        self.descriptors.bus_address()
    }

    pub(crate) fn bytes(&self) -> u32 {
        (self.count * DESCRIPTOR) as u32
    }

    /// Point a controller's base and length registers at the descriptors.
    pub(crate) fn program(
        &self,
        write: impl Fn(usize, u32),
        low: usize,
        high: usize,
        length: usize,
    ) {
        write(length, self.bytes());
        write(high, (self.base() >> 32) as u32);
        write(low, self.base() as u32);
    }

    pub(crate) fn address(&self, index: usize) -> u64 {
        self.buffers.bus_address() + (index * BUFFER) as u64
    }

    pub(crate) fn buffer(&mut self, index: usize) -> &mut [u8] {
        &mut self.buffers.bytes_mut()[index * BUFFER..(index + 1) * BUFFER]
    }

    /// Step to the next descriptor, returning the current one.
    pub(crate) fn advance(&mut self) -> usize {
        let index = self.next;
        self.next = (index + 1) % self.count;
        index
    }

    /// Whether transmit descriptors are still with the controller.
    pub(crate) fn pending(&self) -> bool {
        self.clean != self.next
    }

    /// Retire the transmit descriptors `done` reports written back, and say
    /// whether one is free. Head equal to tail means empty, so one
    /// descriptor always stays unused.
    pub(crate) fn reclaim(&mut self, done: impl Fn(&DmaBuffer, usize) -> bool) -> bool {
        while self.pending() && done(&self.descriptors, self.clean * DESCRIPTOR) {
            fence(Ordering::Acquire);
            self.clean = (self.clean + 1) % self.count;
        }
        (self.next + 1) % self.count != self.clean
    }

    /// Whether a descriptor is free once those the controller handed back
    /// are taken; nothing waits for more.
    pub(crate) fn free(&mut self, done: impl Fn(&DmaBuffer, usize) -> bool) -> bool {
        self.reclaim(&done)
    }

    /// Receive descriptor `index` went back to the controller: the tail to
    /// write, once per [`RECEIVE_BATCH`] of them.
    pub(crate) fn offered(&mut self, index: usize) -> Option<u32> {
        self.offered = index;
        self.unposted += 1;
        (self.unposted >= RECEIVE_BATCH).then(|| self.post())
    }

    /// The tail covering every receive descriptor handed back, when one
    /// has not been published: the ring ran dry, so the controller gets
    /// them all.
    pub(crate) fn idle(&mut self) -> Option<u32> {
        (self.unposted != 0).then(|| self.post())
    }

    fn post(&mut self) -> u32 {
        self.unposted = 0;
        self.offered as u32
    }

    /// Forget every descriptor, once the controller's queue is stopped and
    /// its head and tail are back at zero.
    pub(crate) fn reset(&mut self) {
        self.descriptors.bytes_mut().fill(0);
        self.next = 0;
        self.clean = 0;
        self.unposted = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmit_copy_replaces_payload_and_clears_only_the_wire_padding() {
        let mut buffer = [0x5a; BUFFER];
        let frame = [0x36; crate::MAX_FRAME];
        write_transmit_frame(&mut buffer, &frame, frame.len());
        assert_eq!(&buffer[..frame.len()], &frame);
        assert!(buffer[frame.len()..].iter().all(|&byte| byte == 0x5a));

        let short = [0x7b; crate::HEADER];
        write_transmit_frame(&mut buffer, &short, crate::MIN_FRAME);
        assert_eq!(&buffer[..short.len()], &short);
        assert!(
            buffer[short.len()..crate::MIN_FRAME]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert_eq!(
            &buffer[crate::MIN_FRAME..frame.len()],
            &frame[crate::MIN_FRAME..]
        );
    }
}

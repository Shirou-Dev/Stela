// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! Requester-domain rings; packet ownership follows completions.
use super::*;
use crate::bus::dma::{
    mapping::{Direction, DmaMapping, DomainKind},
    memory::{CacheAttribute, CpuMapping},
};
pub(super) const TX: usize = 512;
#[cfg(test)]
pub(super) const RX: usize = 2048;
pub(super) const BUFFER: usize = 4096;
pub(super) const RX_BYTES: usize = 1536;
const TX_RING: usize = 0;
const RX_RING: usize = 1;
const RETURNS: usize = 2;
const STATUS: usize = 3;
const TX_DATA: usize = 4;
const RX_DATA: usize = 5;
const TX_DESCRIPTOR_BYTES: usize = 16;
const RX_DESCRIPTOR_BYTES: usize = 32;
const TX_END_COALESCE: u32 = 0x0084;
const RX_END: u32 = 4;
const RX_STANDARD: u32 = 0x0001_0000;
const RX_INVALID_RING_FLAGS: u32 = 0x0820;
const RX_ERROR: u32 = 0x0400;
/// RXD_FLAG_VLAN: the MAC stripped a VLAN tag into the descriptor.
const RX_FLAG_VLAN: u32 = 0x0040;
const RX_ERRORS: u32 = 0x01ff_0000;
struct Buffer {
    cpu: CpuMapping,
    mapping: DmaMapping,
}
impl Buffer {
    /// Pages the device reaches at addresses up to `limit`. Without a
    /// remapper the device address is the physical one, so the pages
    /// themselves must lie below it.
    fn new(
        pages: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        limit: u64,
    ) -> Result<Self, Error> {
        let pins = match limit.checked_add(1) {
            Some(end) if domain.kind() == DomainKind::Passthrough => {
                pages.allocate_below(bytes, 4096, CacheAttribute::WriteBack, end)?
            }
            _ => pages.allocate(bytes, 4096, CacheAttribute::WriteBack)?,
        };
        let cpu = pins.cpu_mapping(CacheAttribute::WriteBack)?;
        let mapping = DmaMapping::map(domain, pins, Direction::Bidirectional, limit)?;
        Ok(Self { cpu, mapping })
    }
    fn put(&self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let address = self.cpu.address(offset, bytes.len())?;
        for (i, byte) in bytes.iter().enumerate() {
            // SAFETY: only unpublished/completed ranges may call put.
            unsafe { address.as_ptr().add(i).write_volatile(*byte) };
        }
        Ok(())
    }
    fn word(&self, offset: usize, value: u32) -> Result<(), Error> {
        self.put(offset, &value.to_le_bytes())
    }
    fn address(&self, offset: usize) -> Result<u64, Error> {
        self.mapping
            .address()?
            .checked_add(offset as u64)
            .ok_or(Error::Bounds)
    }
    fn zero(&self, bytes: usize) -> Result<(), Error> {
        for offset in (0..bytes).step_by(4) {
            self.word(offset, 0)?;
        }
        self.mapping.sync_for_device(0..bytes)?;
        Ok(())
    }
}
pub(super) struct Memory {
    buffers: Vec<Buffer>,
    active_rx: Vec<bool>,
    geometry: super::super::geometry::Geometry,
}
impl Memory {
    pub(super) fn new(
        pages: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        geometry: super::super::geometry::Geometry,
        ring_limit: u64,
    ) -> Result<Self, (Error, Self)> {
        let mut value = Self {
            buffers: Vec::new(),
            active_rx: Vec::new(),
            geometry,
        };
        let result = (|| {
            value
                .active_rx
                .try_reserve_exact(geometry.rx)
                .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
            value.active_rx.resize(geometry.rx, false);
            value
                .buffers
                .try_reserve_exact(6)
                .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
            // Rings and status block are tg3's coherent memory; packet
            // buffers are its streaming mappings.
            for (bytes, limit) in [
                (TX * TX_DESCRIPTOR_BYTES, ring_limit),
                (geometry.rx * RX_DESCRIPTOR_BYTES, ring_limit),
                (geometry.returns * RX_DESCRIPTOR_BYTES, ring_limit),
                (4096, ring_limit),
                (TX * BUFFER, u64::MAX),
                (geometry.rx * BUFFER, u64::MAX),
            ] {
                value
                    .buffers
                    .push(Buffer::new(pages, domain.clone(), bytes, limit)?);
            }
            value.prepare()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(value),
            Err(error) => Err((error, value)),
        }
    }
    fn prepare(&mut self) -> Result<(), Error> {
        self.active_rx.fill(false);
        self.buffers[TX_RING].zero(TX * TX_DESCRIPTOR_BYTES)?;
        self.buffers[RX_RING].zero(self.geometry.rx * RX_DESCRIPTOR_BYTES)?;
        self.buffers[RETURNS].zero(self.geometry.returns * RX_DESCRIPTOR_BYTES)?;
        self.buffers[STATUS].zero(4096)?;
        // Domain coherent observation, before hardware publication.
        self.buffers[STATUS].mapping.read_coherent_u32(16)?;
        self.buffers[RETURNS].mapping.read_coherent_u32(28)?;
        for i in 0..self.geometry.rx - 1 {
            self.offer(i)?;
        }
        Ok(())
    }
    /// # Safety
    /// Every engine is stopped, BME clear and this original domain's posted
    /// writes drained; no IRQ/workers can touch the queue RAM.
    pub(super) unsafe fn reset_after_drain(&mut self) -> Result<(), Error> {
        for buffer in &self.buffers {
            // SAFETY: caller holds the stopped/drained queue epoch.
            unsafe {
                buffer.mapping.sync_for_cpu(0..buffer.mapping.bytes())?;
            }
        }
        self.prepare()
    }
    pub(super) fn addresses(&self) -> Result<[u64; 4], Error> {
        Ok([
            self.buffers[TX_RING].address(0)?,
            self.buffers[RX_RING].address(0)?,
            self.buffers[RETURNS].address(0)?,
            self.buffers[STATUS].address(0)?,
        ])
    }
    pub(super) fn status(&self) -> Result<(u32, usize, usize), Error> {
        let flags = self.buffers[STATUS].mapping.read_coherent_u32(0)?;
        let indices = self.buffers[STATUS].mapping.read_coherent_u32(16)?;
        Ok((flags, (indices >> 16) as usize, (indices & 0xffff) as usize))
    }
    pub(super) fn tx(&self, index: usize, frame: &[u8]) -> Result<(), Error> {
        let length = frame.len().max(MIN_FRAME);
        let data = index * BUFFER;
        self.buffers[TX_DATA].put(data, frame)?;
        if length > frame.len() {
            self.buffers[TX_DATA]
                .put(data + frame.len(), &[0; MIN_FRAME][..length - frame.len()])?;
        }
        self.buffers[TX_DATA]
            .mapping
            .sync_for_device(data..data + length)?;
        let address = self.buffers[TX_DATA].address(data)?;
        let at = index * TX_DESCRIPTOR_BYTES;
        // tg3_tx_buffer_desc is two HI/LO words, never an LE u64 store.
        self.buffers[TX_RING].word(at, (address >> 32) as u32)?;
        self.buffers[TX_RING].word(at + 4, address as u32)?;
        self.buffers[TX_RING].word(at + 8, ((length as u32) << 16) | TX_END_COALESCE)?; // END|COAL_NOW, CRC added.
        self.buffers[TX_RING].word(at + 12, 0)?;
        self.buffers[TX_RING]
            .mapping
            .sync_for_device(at..at + TX_DESCRIPTOR_BYTES)?;
        Ok(())
    }
    pub(super) fn complete_tx(&self, index: usize) -> Result<(), Error> {
        // SAFETY: status TX consumer has passed this submitted BD.
        unsafe {
            self.buffers[TX_DATA]
                .mapping
                .sync_for_cpu(index * BUFFER..(index + 1) * BUFFER)?;
        }
        Ok(())
    }
    /// Takes return descriptor `index`: its packet slot, and whether a good
    /// frame was copied into `frame` (left unchanged otherwise). With
    /// `restore_tag`, a VLAN tag the MAC stripped is put back, as tg3_rx
    /// hands it on with the frame.
    pub(super) fn receive(
        &mut self,
        index: usize,
        frame: &mut Vec<u8>,
        restore_tag: bool,
    ) -> Result<(usize, bool), Error> {
        let at = index * RX_DESCRIPTOR_BYTES;
        // Producer publication orders all BD words before status. The host
        // mailbox prevents reuse; coherent reads do not invalidate a live line.
        let length = (self.buffers[RETURNS].mapping.read_coherent_u32(at + 8)? & 0xffff) as usize;
        let kind = self.buffers[RETURNS].mapping.read_coherent_u32(at + 12)?;
        let error = self.buffers[RETURNS].mapping.read_coherent_u32(at + 20)?;
        let opaque = self.buffers[RETURNS].mapping.read_coherent_u32(at + 28)?;
        let slot = (opaque & 0xffff) as usize;
        if opaque & !0xffff != RX_STANDARD
            || slot >= self.geometry.rx
            || !self.active_rx[slot]
            || kind & RX_INVALID_RING_FLAGS != 0
        {
            return Err(Error::RingCorrupt);
        }
        // SAFETY: this return BD transfers that exact active packet page;
        // it is not reoffered until the caller has copied/dropped the packet.
        unsafe {
            self.buffers[RX_DATA]
                .mapping
                .sync_for_cpu(slot * BUFFER..(slot + 1) * BUFFER)?;
        }
        self.active_rx[slot] = false;
        let tag = (restore_tag && kind & RX_FLAG_VLAN != 0).then_some(error as u16);
        let restored = if tag.is_some() { 4 } else { 0 };
        // A damaged frame in a slot this driver offered is dropped and its
        // slot reoffered, as `tg3_rx` does; only a return naming no offered
        // slot means the ring itself is corrupt.
        if error & RX_ERRORS != 0
            || kind & (RX_ERROR | RX_END) != RX_END
            || !(4..=RX_BYTES).contains(&length)
            || !(HEADER..=MAX_FRAME).contains(&(length - 4 + restored))
        {
            return Ok((slot, false));
        }
        let length = length - 4; // device includes the Ethernet FCS.
        let source = self.buffers[RX_DATA].cpu.address(slot * BUFFER, length)?;
        frame
            .try_reserve((length + restored).saturating_sub(frame.len()))
            .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
        frame.clear();
        for i in 0..length {
            if i == 12
                && let Some(tag) = tag
            {
                frame.extend_from_slice(&[0x81, 0x00]);
                frame.extend_from_slice(&tag.to_be_bytes());
            }
            // SAFETY: completed and bounds checked RX page.
            frame.push(unsafe { source.as_ptr().add(i).read_volatile() });
        }
        Ok((slot, true))
    }
    pub(super) fn offer(&mut self, slot: usize) -> Result<(), Error> {
        if slot >= self.geometry.rx || self.active_rx[slot] {
            return Err(Error::RingCorrupt);
        }
        let data = slot * BUFFER;
        self.buffers[RX_DATA]
            .mapping
            .sync_for_device(data..data + BUFFER)?;
        let address = self.buffers[RX_DATA].address(data)?;
        let at = slot * RX_DESCRIPTOR_BYTES;
        self.buffers[RX_RING].word(at, (address >> 32) as u32)?;
        self.buffers[RX_RING].word(at + 4, address as u32)?;
        self.buffers[RX_RING].word(at + 8, RX_BYTES as u32)?;
        self.buffers[RX_RING].word(at + 12, RX_END)?;
        self.buffers[RX_RING].word(at + 16, 0)?;
        self.buffers[RX_RING].word(at + 20, 0)?;
        self.buffers[RX_RING].word(at + 24, 0)?;
        self.buffers[RX_RING].word(at + 28, RX_STANDARD | slot as u32)?;
        self.buffers[RX_RING]
            .mapping
            .sync_for_device(at..at + RX_DESCRIPTOR_BYTES)?;
        self.active_rx[slot] = true;
        Ok(())
    }
    pub(super) fn retire(&mut self) -> Result<(), Error> {
        for buffer in &mut self.buffers {
            if buffer.mapping.address().is_ok() {
                // SAFETY: Packet::stop acknowledged real engines, BME clear
                // and this original domain's posted payload drain; no IRQs.
                unsafe {
                    buffer.mapping.unmap()?;
                }
            }
        }
        Ok(())
    }
}

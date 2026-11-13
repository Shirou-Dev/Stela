//! Requester translation, firmware admission and lifecycle through a synchronous peer.
extern crate std;
mod drain;
mod model;
use super::*;
use crate::bus::dma::{amd::ivrs::Ivrs, pages::PageRange};
use crate::bus::pci::ConfigSpace;
use alloc::vec;
use model::*;

#[test]
fn requester_mapping_lifecycle() {
    let (mut unit, peer) = model::unit();
    assert_eq!(
        peer.walk(0x20, 4096),
        None,
        "prime actual blocked DTE cache before attach"
    );
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    assert_eq!(
        // SAFETY: The kept OwnedConfig is this requester's fixture function. The
        // closure changes only its command word; identity/BAR state and payload traffic remain unchanged.
        unsafe {
            requester.with_function(|function| {
                function.config().write16(4, 4).unwrap();
                function.config().read16(4).unwrap()
            })
        }
        .unwrap(),
        4,
        "owning driver configures original retained function after attach"
    );
    for (direction, read, write) in [
        (Direction::ToDevice, true, false),
        (Direction::FromDevice, false, true),
        (Direction::Bidirectional, true, true),
    ] {
        let pages = peer.pages(8192);
        let physical = pages.physical_pages().to_vec();
        let mapping = requester
            .map(pages.into(), direction, u32::MAX as u64)
            .unwrap();
        for (index, pa) in physical.into_iter().enumerate() {
            assert_eq!(
                peer.walk(0x20, mapping.address() + (index * 4096) as u64),
                Some((pa, read, write))
            );
        }
        // SAFETY: The peer has no concurrent CPU or device payload writer. Live bindings
        // keep their page pins; foreign/stale tokens are checked before accessing those bindings.
        unsafe { requester.sync(&mapping, 0..mapping.bytes(), false) }.unwrap();
        // SAFETY: The peer has no concurrent CPU or device payload writer. Live bindings
        // keep their page pins; foreign/stale tokens are checked before accessing those bindings.
        unsafe { requester.sync(&mapping, 0..mapping.bytes(), true) }.unwrap();
        assert_eq!(peer.syncs(), 2);
        peer.clear_syncs();
        // SAFETY: No modeled requester or CPU accesses the payload during removal.
        // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
        unsafe { requester.unmap(&mapping) }.unwrap();
        assert_eq!(peer.walk(0x20, mapping.address()), None);
        let before = peer.commands();
        // SAFETY: No modeled requester or CPU accesses the payload during removal.
        // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
        assert_eq!(unsafe { requester.unmap(&mapping) }, Err(Error::Mapping));
        assert_eq!(peer.commands(), before);
    }
    // Real repeated physical-page aliases remain in exact submitted order.
    let pages = peer.pages(8192);
    let first = pages.physical_pages()[0];
    let second = pages.physical_pages()[1];
    let sequence = DmaPages::from_ranges(vec![
        PageRange::new(pages.clone(), 4096..8192).unwrap(),
        PageRange::new(pages.clone(), 0..4096).unwrap(),
        PageRange::new(pages, 4096..8192).unwrap(),
    ])
    .unwrap();
    let mapping = requester
        .map(sequence, Direction::Bidirectional, u32::MAX as u64)
        .unwrap();
    for (index, pa) in [second, first, second].into_iter().enumerate() {
        assert_eq!(
            peer.walk(0x20, mapping.address() + (index * 4096) as u64),
            Some((pa, true, true))
        );
    }
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    assert_eq!(unsafe { requester.detach() }, Err(Error::Busy));
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    unsafe { requester.unmap(&mapping) }.unwrap();
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    unsafe { requester.detach() }.unwrap();
    assert_eq!(peer.walk(0x20, 4096), None);
    let before = peer.commands();
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    assert_eq!(unsafe { requester.detach() }, Err(Error::Poisoned));
    assert_eq!(peer.commands(), before);
    drop(requester);
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    unsafe { unit.retire() }.unwrap();
    let before = peer.registers();
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    assert_eq!(unsafe { unit.retire() }, Err(Error::Poisoned));
    assert!(matches!(
        // SAFETY: The function comes from this peer's owned PCI fixture. No requester
        // submits DMA or work, and the unit keeps the matching configuration/root epoch.
        unsafe { unit.attach(function(0x21)) },
        Err(Error::Poisoned)
    ));
    assert_eq!(peer.registers(), before);
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn foreign_and_stale_mapping_tokens() {
    let (mut unit, peer) = model::unit();
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut first = unsafe { unit.attach(function(0x20)) }.unwrap();
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut second = unsafe { unit.attach(function(0x21)) }.unwrap();
    let mapping = first
        .map(
            peer.pages(4096).into(),
            Direction::ToDevice,
            u32::MAX as u64,
        )
        .unwrap();
    let before = peer.image();
    let entries = peer.enters();
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    assert_eq!(unsafe { second.unmap(&mapping) }, Err(Error::Mapping));
    assert_eq!(
        // SAFETY: The peer has no concurrent CPU or device payload writer. Live bindings
        // keep their page pins; foreign/stale tokens are checked before accessing those bindings.
        unsafe { second.sync(&mapping, 0..4096, false) },
        Err(Error::Mapping)
    );
    assert_eq!(
        peer.enters(),
        entries,
        "private-owner rejection precedes context/MMIO"
    );
    assert_eq!(peer.image(), before);
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    unsafe { first.unmap(&mapping) }.unwrap();
    let replacement = first
        .map(
            peer.pages(4096).into(),
            Direction::FromDevice,
            u32::MAX as u64,
        )
        .unwrap();
    assert_eq!(
        mapping.address(),
        replacement.address(),
        "acknowledged aperture reuse"
    );
    let before = peer.image();
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    assert_eq!(unsafe { first.unmap(&mapping) }, Err(Error::Mapping));
    assert_eq!(
        // SAFETY: The peer has no concurrent CPU or device payload writer. Live bindings
        // keep their page pins; foreign/stale tokens are checked before accessing those bindings.
        unsafe { first.sync(&mapping, 0..4096, true) },
        Err(Error::Mapping)
    );
    assert_eq!(peer.image(), before);
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    unsafe { first.unmap(&replacement) }.unwrap();
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    unsafe { first.detach() }.unwrap();
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    unsafe { second.detach() }.unwrap();
    drop((first, second));
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn queue_wrap_and_completion_store() {
    let (mut unit, peer) = model::unit();
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    // More than512 commands wraps the real ring multiple times. The
    // peer decodes ring RAM and writes the PA named by every completion entry.
    for _ in 0..300 {
        let mapping = requester
            .map(
                peer.pages(4096).into(),
                Direction::Bidirectional,
                u32::MAX as u64,
            )
            .unwrap();
        // SAFETY: No modeled requester or CPU accesses the payload during removal.
        // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
        unsafe { requester.unmap(&mapping) }.unwrap();
    }
    assert!(peer.commands().len() > 1024);
    peer.mode(Mode::StoreBeforeHead);
    let mapping = requester
        .map(
            peer.pages(4096).into(),
            Direction::ToDevice,
            u32::MAX as u64,
        )
        .unwrap();
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    unsafe { requester.unmap(&mapping) }.unwrap();
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    unsafe { requester.detach() }.unwrap();
    drop(requester);
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);

    for mode in [
        Mode::HeadOnly,
        Mode::OldStore,
        Mode::FutureStore,
        Mode::BadHead,
        Mode::Halt,
        Mode::Event,
        Mode::Overflow,
        Mode::HardwareError,
        Mode::AlterBase,
    ] {
        let (mut unit, peer) = model::unit();
        // SAFETY: The function comes from this peer's owned PCI fixture. No requester
        // submits DMA or work, and the unit keeps the matching configuration/root epoch.
        let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
        peer.mode(mode);
        assert!(
            requester
                .map(
                    peer.pages(4096).into(),
                    Direction::FromDevice,
                    u32::MAX as u64
                )
                .is_err()
        );
        assert!(unit.check_health().is_err());
        // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
        // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
        assert_eq!(unsafe { requester.detach() }, Err(Error::Poisoned));
        let commands = peer.commands();
        assert!(
            requester
                .map(
                    peer.pages(4096).into(),
                    Direction::ToDevice,
                    u32::MAX as u64
                )
                .is_err()
        );
        assert_eq!(peer.commands(), commands);
        let retained = peer.live_ram();
        assert!(retained >= 6);
        drop(requester);
        drop(unit);
        assert_eq!(
            peer.live_ram(),
            retained,
            "uncertain unit/tree/payload pins are quarantined"
        );
        assert_ne!(
            peer.register(CONTROL) & IOMMU_ENABLE,
            0,
            "fault must not enable bypass"
        );
    }
}

#[test]
fn failed_unmap_keeps_payload() {
    let (mut unit, peer) = model::unit();
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    let mapping = requester
        .map(
            peer.pages(4096).into(),
            Direction::Bidirectional,
            u32::MAX as u64,
        )
        .unwrap();
    peer.mode(Mode::HeadOnly);
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    assert!(unsafe { requester.unmap(&mapping) }.is_err());
    assert_eq!(
        peer.walk(0x20, mapping.address()),
        None,
        "actual leaf was cleared before uncertain completion"
    );
    let retained = peer.live_ram();
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    assert_eq!(unsafe { requester.unmap(&mapping) }, Err(Error::Poisoned));
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    assert_eq!(unsafe { unit.retire() }, Err(Error::Busy));
    drop(requester);
    drop(unit);
    assert_eq!(peer.live_ram(), retained);
}

#[test]
fn cold_preflight_refusals() {
    for mutation in [0, 1, 2, 3, 4, 5] {
        let (inspection, platform, peer, mut bytes) = inputs();
        match mutation {
            0 => peer.set(CONTROL, IOMMU_ENABLE),
            1 => peer.set(STATUS, COMMAND_RUNNING),
            2 => bytes[88] = 0x42, // Alias entry requires original group owner.
            3 => bytes[91] = 0x10, // System-management bypass policy refused.
            4 => bytes[24] = 1,    // Even unrelated OEM bytes must match discovery.
            _ => peer.set(HARDWARE_EVENT_STATUS, 1),
        }
        checksum(&mut bytes);
        let ivrs = Ivrs::parse(&bytes, 8);
        if let Ok(ivrs) = ivrs {
            // SAFETY: inputs constructs this isolated register/RAM peer and matching IVRS
            // inspection. No firmware or requester runs concurrently; the peer keeps every backing allocation.
            assert!(unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.is_err());
            assert_eq!(peer.register(DEVICE_TABLE), 0);
            assert_eq!(peer.register(COMMAND_BASE), 0);
            assert_eq!(peer.register(EVENT_BASE), 0);
            assert_eq!(peer.live_ram(), 0);
        }
    }
}

/// Firmware that set the unit up and stopped it again leaves addresses,
/// pointers and its IVHD flag bits behind; the unit is reset and taken, as
/// Linux takes it.
#[test]
fn a_stopped_unit_with_firmware_leftovers_comes_up() {
    let (inspection, platform, peer, bytes) = inputs();
    peer.set(CONTROL, 1 << 8 | 1 << 9 | COHERENT);
    peer.set(DEVICE_TABLE, 0x7654_3000 | 0x1ff);
    peer.set(COMMAND_BASE, 0x7654_5000 | RING_LENGTH);
    peer.set(EVENT_BASE, 0x7654_7000 | RING_LENGTH);
    peer.set(EXCLUSION_BASE, 0x7000_0000);
    peer.set(EXCLUSION_LIMIT, 0x7000_f000);
    peer.set(COMMAND_HEAD, 0x40);
    peer.set(COMMAND_TAIL, 0x40);
    peer.set(EVENT_TAIL, 0x20);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    // SAFETY: as in `cold_preflight_refusals`: an isolated register and RAM
    // peer with its matching IVRS, and nothing running beside it.
    let unit = unsafe { Unit::cold(inspection, &ivrs, platform, limits()) };
    assert!(unit.is_ok(), "{:?}", unit.err());
    assert_eq!(peer.register(STATUS), RUNNING);
    assert_eq!(peer.register(EXCLUSION_BASE), 0);
    assert_eq!(peer.register(EXCLUSION_LIMIT), 0);
    assert_ne!(peer.register(DEVICE_TABLE), 0x7654_3000 | 0x1ff);
}

fn unit_with_entries(entries: &[u8]) -> (Unit<Platform>, Peer) {
    let (inspection, platform, peer, bytes) = inputs_with_entries(entries);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    (
        // SAFETY: inputs constructs this isolated register/RAM peer and matching IVRS
        // inspection. No firmware or requester runs concurrently; the peer keeps every backing allocation.
        unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap(),
        peer,
    )
}

#[test]
fn alias_domain_ownership() {
    let (mut unit, peer) = unit_with_entries(&[0x42, 0x20, 0, 0, 0, 0x21, 0, 0]);
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    let pages = peer.pages(4096);
    let physical = pages.physical_pages()[0];
    let mapping = requester
        .map(pages.into(), Direction::ToDevice, u32::MAX as u64)
        .unwrap();
    for rid in [0x20, 0x21] {
        assert_eq!(
            peer.walk(rid, mapping.address()),
            Some((physical, true, false))
        );
    }
    // SAFETY: No modeled requester or CPU accesses the payload during removal.
    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
    unsafe { requester.unmap(&mapping) }.unwrap();
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    unsafe { requester.detach() }.unwrap();
    assert_eq!(peer.walk(0x21, mapping.address()), None);
    // Two sources under one alias: neither gets a domain of its own.
    let (mut unit, _) = unit_with_entries(&[
        0x42, 0x20, 0, 0, 0, 0x30, 0, 0, 0x42, 0x28, 0, 0, 0, 0x30, 0, 0,
    ]);
    assert!(matches!(
        // SAFETY: The function comes from this peer's owned PCI fixture. No requester
        // submits DMA or work, and the unit keeps the matching configuration/root epoch.
        unsafe { unit.attach(function(0x20)) },
        Err(Error::Requester)
    ));
}

#[test]
fn an_alias_cannot_take_an_independently_routed_requester() {
    let (mut unit, peer) = unit_with_entries(&[0x42, 0x20, 0, 0, 0, 0x21, 0, 0, 2, 0x21, 0, 0]);
    let before = peer.commands();
    assert!(matches!(
        // SAFETY: isolated stopped model; the conflicting RID is firmware-declared.
        unsafe { unit.attach(function(0x20)) },
        Err(Error::Requester)
    ));
    assert_eq!(peer.commands(), before);
    // SAFETY: the refused request published no private tables and there are no users.
    unsafe { unit.retire() }.unwrap();
}

#[test]
fn an_alias_cannot_take_another_observed_pci_function() {
    let (mut unit, peer) = unit_with_entries(&[0x42, 0x20, 0, 0, 0, 0x21, 0, 0]);
    let pages = peer.pages(4096);
    // SAFETY: both physical functions were independently observed. The
    // stopped model owns the complete window and its payload.
    unsafe { unit.window(&[0x20, 0x21], vec![pages.into()]) }.unwrap();
    let before = peer.commands();
    assert!(matches!(
        // SAFETY: no request is live and the modeled requester stays stopped.
        unsafe { unit.attach(function(0x20)) },
        Err(Error::Requester)
    ));
    assert_eq!(peer.commands(), before);
    // SAFETY: no active requester remains.
    unsafe { unit.retire() }.unwrap();
}

#[test]
fn an_arrival_cannot_join_an_existing_private_alias() {
    let (mut unit, peer) = unit_with_entries(&[0x42, 0x20, 0, 0, 0, 0x21, 0, 0]);
    // SAFETY: no live traffic, and no other device owns the alias in this model.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    let before = peer.commands();
    assert_eq!(unit.admit_requester(0x21), Err(Error::Requester));
    assert_eq!(peer.commands(), before);
    // SAFETY: the attached model requester has no outstanding users or mappings.
    unsafe { requester.detach() }.unwrap();
    drop(requester);
    assert!(matches!(
        // SAFETY: the model has no live requests; the newly observed function
        // is still a distinct owner of the alias ID.
        unsafe { unit.attach(function(0x20)) },
        Err(Error::Requester)
    ));
    // SAFETY: both original physical functions are stopped.
    unsafe { unit.retire() }.unwrap();
}

#[test]
fn device_settings_override_order() {
    // SysMgt=01 and Lint1Pass on every requester, then plain settings for
    // 0x20; an IOAPIC special entry names only an interrupt source.
    let (unit, _) = unit_with_entries(&[
        1, 0, 0, 0x90, 2, 0x20, 0, 0, 0x48, 0, 0, 0xd7, 0x21, 0xa0, 0, 1,
    ]);
    let other = unit.table.borrow().snapshot(0x28).unwrap();
    assert_eq!(other[1] >> 40 & 3, 1);
    assert_ne!(other[0] & 1 << 62, 0, "AMD erratum 63 write permission");
    assert_ne!(other[2] & 1 << 63, 0);
    let plain = unit.table.borrow().snapshot(0x20).unwrap();
    assert_eq!(plain, [1, 0, 0, 0]);
}

#[test]
fn device_setting_bits() {
    // INITPass, EIntPass, NMIPass, Lint0Pass, Lint1Pass and SysMgt=10, one
    // requester each.
    let (unit, _) = unit_with_entries(&[
        2, 0x20, 0, 0x01, 2, 0x21, 0, 0x02, 2, 0x22, 0, 0x04, 2, 0x23, 0, 0x40, 2, 0x24, 0, 0x80,
        2, 0x25, 0, 0x20,
    ]);
    let table = unit.table.borrow();
    for (rid, bit) in [(0x20, 56), (0x21, 57), (0x22, 58), (0x23, 62), (0x24, 63)] {
        let words = table.snapshot(rid).unwrap();
        assert_eq!(words[2], 1 << bit, "requester {rid:#x}");
        assert_eq!(words[1], 0);
    }
    let words = table.snapshot(0x25).unwrap();
    assert_eq!(words[1] >> 40 & 3, 2);
    assert_eq!(words[0] & 1 << 62, 0);
    assert_eq!(words[2], 0);
}

#[test]
fn alias_range_window() {
    // 0x20..=0x22 DMA as 0x30.
    let (mut unit, peer) = unit_with_entries(&[0x43, 0x20, 0, 0, 0, 0x30, 0, 0, 4, 0x22, 0, 0]);
    let pages = peer.pages(4096);
    let physical = pages.physical_pages()[0];
    // SAFETY: These pinned pages and IVRS-selected RIDs belong to the same peer.
    // No requester issues payload traffic while the unit publishes the window and alias entries.
    unsafe { unit.window(&[0x20, 0x21, 0x22], vec![pages.into()]) }.unwrap();
    for rid in [0x20, 0x21, 0x22, 0x30] {
        assert_eq!(peer.walk(rid, physical), Some((physical, true, true)));
    }
    assert!(matches!(
        // SAFETY: The function comes from this peer's owned PCI fixture. No requester
        // submits DMA or work, and the unit keeps the matching configuration/root epoch.
        unsafe { unit.attach(function(0x21)) },
        Err(Error::Requester)
    ));
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    unsafe { unit.retire() }.unwrap();
}

#[test]
fn window_handoff_on_attach() {
    let (mut unit, peer) = model::unit();
    let pages = peer.pages(8192);
    let physical = pages.physical_pages()[0];
    // SAFETY: These pinned pages and IVRS-selected RIDs belong to the same peer.
    // No requester issues payload traffic while the unit publishes the window and alias entries.
    unsafe { unit.window(&[0x20, 0x21], vec![pages.into()]) }.unwrap();
    for rid in [0x20, 0x21] {
        assert_eq!(peer.walk(rid, physical), Some((physical, true, true)));
        assert_eq!(
            peer.walk(rid, physical + 4096),
            Some((physical + 4096, true, true))
        );
        assert_eq!(peer.walk(rid, physical + 8192), None);
    }
    assert_eq!(peer.walk(0x22, physical), None);
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut own = unsafe { unit.attach(function(0x20)) }.unwrap();
    assert_eq!(peer.walk(0x20, physical), None);
    assert_eq!(peer.walk(0x21, physical), Some((physical, true, true)));
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    unsafe { own.detach() }.unwrap();
    drop(own);
    assert_eq!(peer.walk(0x20, physical), None);
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    // Retirement releases every pin, the window's included.
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn requester_coverage_and_exclusivity() {
    let (inspection, platform, peer, bytes) = inputs_with_entries(&[2, 0x20, 0, 0]);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    // SAFETY: inputs constructs this isolated register/RAM peer and matching IVRS
    // inspection. No firmware or requester runs concurrently; the peer keeps every backing allocation.
    let mut unit = unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap();
    let before = peer.image();
    assert!(matches!(
        // SAFETY: The function comes from this peer's owned PCI fixture. No requester
        // submits DMA or work, and the unit keeps the matching configuration/root epoch.
        unsafe { unit.attach(function(0x21)) },
        Err(Error::Requester)
    ));
    assert_eq!(peer.image(), before);
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut owner = unsafe { unit.attach(function(0x20)) }.unwrap();
    let before = peer.image();
    assert!(matches!(
        // SAFETY: The function comes from this peer's owned PCI fixture. No requester
        // submits DMA or work, and the unit keeps the matching configuration/root epoch.
        unsafe { unit.attach(function(0x20)) },
        Err(Error::Busy)
    ));
    assert_eq!(peer.image(), before);
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    unsafe { owner.detach() }.unwrap();
    drop(owner);
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn completion_timeout_quarantines_unit() {
    let (inspection, platform, peer, bytes) = inputs();
    peer.mode(Mode::HeadOnly);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    assert!(matches!(
        // SAFETY: inputs constructs this isolated register/RAM peer and matching IVRS
        // inspection. No firmware or requester runs concurrently; the peer keeps every backing allocation.
        unsafe { Unit::cold(inspection, &ivrs, platform, limits()) },
        Err(Error::Timeout)
    ));
    assert_eq!(
        peer.live_ram(),
        4,
        "table plus all three actual command/event/store targets retained"
    );
    // Turned off again: left on, its table would block every device
    // behind it, the boot's own disks included. Its memory stays held.
    assert_eq!(peer.register(CONTROL), 0);

    let (mut unit, peer) = model::unit();
    peer.mode(Mode::OldStore);
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    assert_eq!(unsafe { unit.retire() }, Err(Error::Timeout));
    let retained = peer.live_ram();
    assert_eq!(retained, 4);
    let commands = peer.commands();
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    assert_eq!(unsafe { unit.retire() }, Err(Error::Poisoned));
    assert_eq!(peer.commands(), commands);
    drop(unit);
    assert_eq!(peer.live_ram(), retained);
    assert_ne!(peer.register(CONTROL) & IOMMU_ENABLE, 0);
}

#[test]
fn guard_unwind_quarantines_resources() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    for remove in [false, true] {
        let (mut unit, peer) = model::unit();
        // SAFETY: The function comes from this peer's owned PCI fixture. No requester
        // submits DMA or work, and the unit keeps the matching configuration/root epoch.
        let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
        let mapping = if remove {
            Some(
                requester
                    .map(
                        peer.pages(4096).into(),
                        Direction::Bidirectional,
                        u32::MAX as u64,
                    )
                    .unwrap(),
            )
        } else {
            None
        };
        let pages: DmaPages = peer.pages(4096).into();
        let payload = mapping
            .as_ref()
            .map(|mapping| peer.walk(0x20, mapping.address()).unwrap().0)
            .unwrap_or(pages.physical_pages()[0]);
        peer.fail_outer_guard();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                if let Some(mapping) = &mapping {
                    // SAFETY: No modeled requester or CPU accesses the payload during removal.
                    // The binding keeps its page pins until acknowledged invalidation, or quarantine on failure.
                    unsafe { requester.unmap(mapping) }.unwrap();
                } else {
                    requester
                        .map(pages.clone(), Direction::FromDevice, u32::MAX as u64)
                        .unwrap();
                }
            }))
            .is_err()
        );
        drop(pages);
        assert!(
            peer.retains(payload),
            "exact original payload PA remains pinned after caught teardown unwind"
        );
        // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
        // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
        assert_eq!(unsafe { requester.detach() }, Err(Error::Poisoned));
        let retained = peer.live_ram();
        drop(requester);
        drop(unit);
        assert_eq!(peer.live_ram(), retained);
        assert!(
            peer.retains(payload),
            "unmapped tree has no binding; requester Drop must retain its exact payload pin"
        );
    }
    let (mut unit, peer) = model::unit();
    peer.fail_outer_guard();
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    assert!(catch_unwind(AssertUnwindSafe(|| unsafe { unit.retire() })).is_err());
    let retained = peer.live_ram();
    assert_eq!(retained, 4);
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    assert_eq!(unsafe { unit.retire() }, Err(Error::Poisoned));
    drop(unit);
    assert_eq!(peer.live_ram(), retained);
}

#[test]
fn failed_dte_attach_keeps_requester() {
    let (mut unit, peer) = model::unit();
    let (function, counters) = function_with_counters(0x20);
    let references = Rc::strong_count(&unit.engine);
    peer.mode(Mode::HeadOnly);
    assert!(matches!(
        // SAFETY: The function comes from this peer's owned PCI fixture. No requester
        // submits DMA or work, and the unit keeps the matching configuration/root epoch.
        unsafe { unit.attach(function) },
        Err(Error::DeviceTable(DeviceTableError::Invalidation(
            DmaError::InvalidationFailed
        )))
    ));
    assert!(unit.active.borrow().contains(&0x20));
    assert!(unit.table.borrow().is_poisoned());
    assert_eq!(
        Rc::strong_count(&unit.engine),
        references + 1,
        "quarantined real page tree retains its hardware/requester owner"
    );
    let dte = unit.table.borrow().snapshot(0x20).unwrap();
    assert_eq!(
        dte[0] & 3,
        3,
        "actual translated DTE reached RAM before uncertain completion"
    );
    let root = dte[0] & 0x000f_ffff_ffff_f000;
    assert!(peer.retains(root));
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    assert_eq!(unsafe { unit.retire() }, Err(Error::Busy));
    let retained = peer.live_ram();
    drop(unit);
    assert_eq!(peer.live_ram(), retained);
    assert!(peer.retains(root));
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn ivinfo_profile_admission() {
    let ordinary = 1u32 | (48 << 8) | (48 << 15);
    for (info, features) in [
        (ordinary | (1 << 23), 1 << 6), // Reserved IVinfo upper byte.
        (1 | (31 << 8) | (48 << 15), 1 << 6),
        (1 | (48 << 8) | (29 << 15), 1 << 6),
        (ordinary, 0),                    // No invalidate-all support.
        (ordinary, (1 << 6) | (3 << 10)), // Reserved HATS.
        (ordinary, (1 << 6) | (1 << 63)), // SNP changes completion ownership.
    ] {
        let (inspection, platform, peer, bytes) = inputs_profile(&[1, 0, 0, 0], info, features);
        let ivrs = Ivrs::parse(&bytes, 8).unwrap();
        assert!(matches!(
            // SAFETY: inputs constructs this isolated register/RAM peer and matching IVRS
            // inspection. No firmware or requester runs concurrently; the peer keeps every backing allocation.
            unsafe { Unit::cold(inspection, &ivrs, platform, limits()) },
            Err(Error::Profile)
        ));
        assert_eq!(peer.register(DEVICE_TABLE), 0);
        assert_eq!(peer.live_ram(), 0);
    }
    // GVAsize occupies [7:5], not reserved upper bits. It grants no guest
    // translation in this host-only subset and must not shift the PA/VA fields.
    let (inspection, platform, peer, bytes) =
        inputs_profile(&[1, 0, 0, 0], ordinary | (2 << 5), 1 << 6);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    // SAFETY: inputs constructs this isolated register/RAM peer and matching IVRS
    // inspection. No firmware or requester runs concurrently; the peer keeps every backing allocation.
    let mut unit = unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap();
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn hardware_width_bounds_payload() {
    let info = 1u32 | (48 << 8) | (48 << 15);
    for miscellaneous in [
        0,
        (31 << 8) | (48 << 15),
        (48 << 8) | (31 << 15),
        (48 << 8) | (48 << 15) | (1 << 23),
    ] {
        let (inspection, platform, peer, bytes) =
            inputs_hardware(&[1, 0, 0, 0], info, 1 << 6, miscellaneous);
        let ivrs = Ivrs::parse(&bytes, 8).unwrap();
        assert!(matches!(
            // SAFETY: inputs constructs this isolated register/RAM peer and matching IVRS
            // inspection. No firmware or requester runs concurrently; the peer keeps every backing allocation.
            unsafe { Unit::cold(inspection, &ivrs, platform, limits()) },
            Err(Error::Profile)
        ));
        assert_eq!(peer.register(DEVICE_TABLE), 0);
        assert_eq!(peer.live_ram(), 0);
    }
    let (inspection, platform, peer, bytes) =
        inputs_hardware(&[1, 0, 0, 0], info, 1 << 6, (40 << 8) | (32 << 15));
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    // SAFETY: inputs constructs this isolated register/RAM peer and matching IVRS
    // inspection. No firmware or requester runs concurrently; the peer keeps every backing allocation.
    let mut unit = unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap();
    assert_eq!(
        unit.physical_bits, 40,
        "actual unit width bounds wider firmware and native CPU"
    );
    // SAFETY: The function comes from this peer's owned PCI fixture. No requester
    // submits DMA or work, and the unit keeps the matching configuration/root epoch.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    peer.next_physical(1 << 40);
    let pages = peer.pages(4096);
    let before = peer.image();
    let commands = peer.commands();
    assert!(
        requester
            .map(pages.clone().into(), Direction::ToDevice, u32::MAX as u64)
            .is_err()
    );
    assert_eq!(peer.image(), before);
    assert_eq!(peer.commands(), commands);
    drop(pages);
    // SAFETY: The synchronous requester has no DMA, IRQ or deferred work in flight.
    // Its bindings keep payload pins until unmap; failed detach leaves the owner intact.
    unsafe { requester.detach() }.unwrap();
    drop(requester);
    // SAFETY: The peer has no external producers or concurrent register access.
    // Unit quiescence/ownership checks run while its RAM remains held; failures preserve those pins.
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn detached_binding_releases_configuration_while_old_requester_and_tree_clones_remain() {
    use crate::bus::pci::requester::{FunctionRole, StoppedRequester};
    let (mut unit, peer) = model::unit();
    let mut function = model::function(0x20);
    function.config().write16(4, 0x400).unwrap();
    // SAFETY: complete synchronous physical fixture; all engines/IRQ/work are absent.
    let stopped = unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) }
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    let (stopped, binding) = stopped
        .into_dma_binding()
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    // SAFETY: same owned stopped fixture and original completed root; no real DMA exists.
    let mut requester = unsafe { unit.attach_binding(binding) }.unwrap();
    let mut configuration = stopped.into_function().into_config();
    // SAFETY: isolated RAM fixture; active binding must refuse before any retirement.
    let retired = unsafe { configuration.retire() };
    assert_eq!(retired, Err(crate::bus::mmio::owned::Error::Busy));
    // SAFETY: no mapping, DMA/IRQ/work producer or bypass exists in this fixture.
    unsafe { requester.detach() }.unwrap();
    // SAFETY: actual modeled DTE block/invalidation completed; all shared owner
    // clones must have released the same configuration binding cell.
    unsafe { crate::bus::pci::owned::test_support::retire_owned(configuration) }.unwrap();

    let mut replacement = model::function(0x20);
    replacement.config().write16(4, 0x400).unwrap();
    // SAFETY: new complete synchronous fixture epoch, independently stopped.
    let stopped =
        unsafe { StoppedRequester::from_stopped_pci(replacement, FunctionRole::Physical) }
            .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    let (stopped, binding) = stopped
        .into_dma_binding()
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    // SAFETY: previous DTE/domain was explicitly detached; this is the new original owner.
    let mut replacement = unsafe { unit.attach_binding(binding) }.unwrap();
    let before = peer.commands();
    assert!(matches!(
        requester.map(peer.pages(4096).into(), Direction::Bidirectional, u64::MAX),
        Err(Error::Poisoned)
    ));
    assert_eq!(
        peer.commands(),
        before,
        "stale owner cannot touch a replacement generation"
    );
    // SAFETY: replacement fixture has no maps or engine/IRQ/work producers.
    unsafe { replacement.detach() }.unwrap();
    let configuration = stopped.into_function().into_config();
    // SAFETY: exact replacement detached before configuration retirement.
    unsafe { crate::bus::pci::owned::test_support::retire_owned(configuration) }.unwrap();
}

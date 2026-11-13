use super::*;
use alloc::{vec, vec::Vec};

fn put16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn checksum(raw: &mut [u8]) {
    raw[9] = 0;
    raw[9] = 0u8.wrapping_sub(raw.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
}
fn table(blocks: &[&[u8]]) -> Vec<u8> {
    let mut raw = vec![0; TABLE_HEADER];
    raw[..4].copy_from_slice(b"IVRS");
    raw[8] = 2;
    for block in blocks {
        raw.extend_from_slice(block);
    }
    let length = u32::try_from(raw.len()).unwrap();
    raw[4..8].copy_from_slice(&length.to_le_bytes());
    checksum(&mut raw);
    raw
}
fn hardware(kind: u8, segment: u16, device_id: u16, entries: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; if kind == 0x10 { IVHD_SHORT } else { IVHD_LONG }];
    raw[0] = kind;
    raw[1] = 0x15;
    put16(&mut raw, 4, device_id);
    put16(&mut raw, 6, 0x40);
    put64(&mut raw, 8, 0xfed90000);
    put16(&mut raw, 16, segment);
    put16(&mut raw, 18, 0x1203);
    raw.extend_from_slice(entries);
    let length = u16::try_from(raw.len()).unwrap();
    put16(&mut raw, 2, length);
    raw
}
fn entry(kind: u8, device_id: u16, flags: u8, extra: Option<u32>) -> Vec<u8> {
    let mut raw = vec![kind, 0, 0, flags];
    put16(&mut raw, 1, device_id);
    if let Some(extra) = extra {
        raw.extend_from_slice(&extra.to_le_bytes());
    }
    raw
}
fn fail(raw: &[u8], kind: ErrorKind) {
    assert_eq!(Ivrs::parse(raw, usize::MAX).unwrap_err().kind, kind);
}

#[test]
fn admission_budget_counts_every_version_and_keeps_zero_unit_tables_valid() {
    let empty = table(&[]);
    assert_eq!(Ivrs::parse(&empty, 0).unwrap().units().len(), 0);
    let mut memory = vec![0; IVMD_HEADER];
    memory[0] = 0x20;
    put16(&mut memory, 2, IVMD_HEADER as u16);
    let memory_only = table(&[&memory]);
    let parsed = Ivrs::parse(&memory_only, 0).unwrap();
    assert_eq!(parsed.units().len(), 0);
    assert_eq!(parsed.memory_definitions().count(), 1);

    let low = hardware(0x10, 7, 0x8123, &[]);
    let high = hardware(0x40, 7, 0x8123, &[]);
    let raw = table(&[&low, &memory, &high]);
    let unchanged = raw.clone();
    for (budget, offset) in [
        (0, TABLE_HEADER),
        (1, TABLE_HEADER + low.len() + memory.len()),
    ] {
        assert_eq!(
            Ivrs::parse(&raw, budget).unwrap_err(),
            error(offset, ErrorKind::ResourceLimit)
        );
    }
    let parsed = Ivrs::parse(&raw, 2).unwrap();
    assert_eq!(parsed.units().len(), 1);
    assert_eq!(
        parsed.units().next().unwrap().version(),
        HardwareVersion::Type40
    );
    assert_eq!(parsed.hardware_blocks().count(), 2);
    assert_eq!(raw, unchanged);
}

#[test]
fn every_version_permutation_selects_the_same_unit_and_checks_hidden_versions() {
    let versions = [
        hardware(0x10, 0xffff, 0xffff, &[]),
        hardware(0x11, 0xffff, 0xffff, &[]),
        hardware(0x40, 0xffff, 0xffff, &[]),
    ];
    for permutation in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let blocks = permutation.map(|index| versions[index].as_slice());
        let raw = table(&blocks);
        let parsed = Ivrs::parse(&raw, 3).unwrap();
        let selected = parsed.units().next().unwrap();
        assert_eq!(selected.version(), HardwareVersion::Type40);
        assert_eq!(selected.raw(), versions[2]);
        // Full original block order remains independent of cached selection.
        for (block, expected) in parsed.hardware_blocks().zip(blocks) {
            assert_eq!(block.raw(), expected);
        }
        for version in 0..3 {
            let mut duplicate = blocks.to_vec();
            duplicate.push(&versions[version]);
            fail(&table(&duplicate), ErrorKind::DuplicateVersion);
            let mut changed = versions[version].clone();
            changed[8] ^= 0x10;
            let mut inconsistent = blocks.to_vec();
            inconsistent[permutation
                .iter()
                .position(|&index| index == version)
                .unwrap()] = &changed;
            fail(&table(&inconsistent), ErrorKind::UnitIdentity);
        }
    }
}

#[test]
fn large_interleaved_index_preserves_selected_table_order_and_original_bytes() {
    const UNITS: u16 = 2048;
    let mut blocks = Vec::new();
    // Firmware order disagrees with both identity and version
    // sort order; the final cache must follow the selected record's offset.
    for id in (0..UNITS).rev() {
        blocks.push(hardware(0x11, id % 7, id, &[]));
    }
    for id in 0..UNITS {
        blocks.push(hardware(0x40, id % 7, id, &[]));
    }
    for id in (0..UNITS).rev() {
        blocks.push(hardware(0x10, id % 7, id, &[]));
    }
    let raw = table(&blocks.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let original = raw.clone();
    let parsed = Ivrs::parse(&raw, usize::from(UNITS) * 3).unwrap();
    assert_eq!(parsed.hardware_blocks().count(), usize::from(UNITS) * 3);
    for _ in 0..3 {
        assert_eq!(parsed.units().len(), usize::from(UNITS));
        for (id, unit) in parsed.units().enumerate() {
            assert_eq!(unit.id().device_id, id as u16);
            assert_eq!(unit.id().segment, id as u16 % 7);
            assert_eq!(unit.version(), HardwareVersion::Type40);
            assert_eq!(unit.raw().as_ptr(), raw[unit.offset()..].as_ptr());
        }
    }
    assert_eq!(raw, original);
}

#[test]
fn complete_table_and_every_block_are_checked_before_success() {
    let good = table(&[&hardware(0x10, 0, 8, &[])]);
    for end in 0..TABLE_HEADER {
        fail(&good[..end], ErrorKind::Truncated);
    }
    fail(&good[..good.len() - 1], ErrorKind::TableLength);
    let mut extra = good.clone();
    extra.push(0);
    fail(&extra, ErrorKind::TableLength);
    for version in [0x10, 0x11, 0x40] {
        let entries = [
            entry(2, 0x1234, 0, None),
            entry(0x42, 0x5678, 0, Some(0xabcd00)),
        ]
        .concat();
        let complete = table(&[&hardware(version, 0, 8, &entries)]);
        // Rebind the outer length/checksum so every incomplete block and
        // entry prefix reaches the inner bounds checks.
        for end in TABLE_HEADER + 1..complete.len() {
            let mut prefix = complete[..end].to_vec();
            prefix[4..8].copy_from_slice(&(end as u32).to_le_bytes());
            checksum(&mut prefix);
            fail(&prefix, ErrorKind::Truncated);
        }
    }
    let mut raw = good.clone();
    raw[0] = b'X';
    fail(&raw, ErrorKind::Signature);
    let mut raw = good.clone();
    raw[36] ^= 1;
    fail(&raw, ErrorKind::Checksum);
    for (version, header) in [(0x10, IVHD_SHORT), (0x11, IVHD_LONG), (0x40, IVHD_LONG)] {
        for length in 0..header {
            let mut block = hardware(version, 0, 8, &[]);
            put16(&mut block, 2, length as u16);
            fail(&table(&[&block]), ErrorKind::BlockLength);
        }
    }
    let mut oversized = hardware(0x11, 0, 8, &[]);
    put16(&mut oversized, 2, 41);
    fail(&table(&[&oversized]), ErrorKind::Truncated);
    let mut short = hardware(0x40, 0, 8, &[]);
    short.truncate(IVHD_LONG - 1);
    put16(&mut short, 2, (IVHD_LONG - 1) as u16);
    fail(&table(&[&short]), ErrorKind::BlockLength);
    fail(&table(&[&[0x23, 0, 3, 0]]), ErrorKind::BlockLength);
    fail(&table(&[&[0, 0, 0]]), ErrorKind::Truncated);
    // A valid first unit does not hide malformed bytes in a later block.
    fail(
        &table(&[&hardware(0x10, 0, 8, &[]), &[0x23, 0, 9, 0]]),
        ErrorKind::Truncated,
    );
}

#[test]
fn unknown_blocks_are_stepped_over_by_length_and_reported_once() {
    let unit = hardware(0x10, 0, 8, &[]);
    let unknown = [0x23, 0, 8, 0, 1, 2, 3, 4];
    let raw = table(&[&unknown, &unit, &unknown, &[0x30, 0, 4, 0]]);
    let parsed = Ivrs::parse(&raw, usize::MAX).unwrap();
    assert_eq!(
        parsed.skipped(),
        [Skipped::Block(0x23), Skipped::Block(0x30)]
    );
    assert_eq!(parsed.units().count(), 1);
    assert_eq!(parsed.blocks().count(), 1);
    assert!(
        Ivrs::parse(&table(&[&unit]), usize::MAX)
            .unwrap()
            .skipped()
            .is_empty()
    );
}

#[test]
fn unit_versions_are_grouped_by_full_identity_without_order_assumptions() {
    let first = hardware(0x10, 0x1234, 0xabcd, &[]);
    let mut middle = hardware(0x11, 0x1234, 0xabcd, &[]);
    middle[1] = 0x36;
    put16(&mut middle, 18, 0x2345);
    put64(&mut middle, 24, 0x1122334455667788);
    let mut high = hardware(0x40, 0x1234, 0xabcd, &[]);
    put64(&mut high, 24, 0x8877665544332211);
    put64(&mut high, 32, 0xaabbccddeeff0011);
    high[20..24].copy_from_slice(&0x56781234u32.to_le_bytes());
    let other_segment = hardware(0x10, 0x1235, 0xabcd, &[]);
    let other_device = hardware(0x11, 0x1234, 0xabce, &[]);
    let mut raw = table(&[&high, &other_segment, &middle, &other_device, &first]);
    raw[36..40].copy_from_slice(&0x12345678u32.to_le_bytes());
    checksum(&mut raw);
    let parsed = Ivrs::parse(&raw, usize::MAX).unwrap();
    assert_eq!(parsed.raw().as_ptr(), raw.as_ptr());
    assert_eq!((parsed.info(), parsed.revision()), (0x12345678, 2));
    assert_eq!(parsed.hardware_blocks().count(), 5);
    let units: Vec<_> = parsed.units().collect();
    assert_eq!(units.len(), 3);
    assert_eq!(
        units[0].id(),
        RequesterId {
            segment: 0x1234,
            device_id: 0xabcd
        }
    );
    assert_eq!(units[0].version(), HardwareVersion::Type40);
    assert_eq!(
        units[0].extended_features(),
        Some((0x8877665544332211, 0xaabbccddeeff0011))
    );
    assert_eq!(units[0].feature_or_attributes(), 0x56781234);
    assert_eq!(units[1].version(), HardwareVersion::Type10);
    assert_eq!(units[1].extended_features(), None);
    let preserved = parsed
        .hardware_blocks()
        .find(|unit| unit.version() == HardwareVersion::Type11 && unit.id().device_id == 0xabcd)
        .unwrap();
    assert_eq!((preserved.flags(), preserved.info()), (0x36, 0x2345));
    fail(&table(&[&first, &first]), ErrorKind::DuplicateVersion);
    let mut inconsistent = middle.clone();
    inconsistent[8] ^= 1;
    fail(&table(&[&first, &inconsistent]), ErrorKind::UnitIdentity);
    // Even a lower, unselected version must have valid entry grammar.
    let broken_low = hardware(0x10, 0x1234, 0xabcd, &[0x80]);
    fail(
        &table(&[&high, &broken_low]),
        ErrorKind::UnsupportedEntry(0x80),
    );
}

#[test]
fn multiple_capabilities_on_one_function_select_versions_independently() {
    let mut blocks = Vec::new();
    for (capability, base, versions) in [
        (0x40, 0xfed80000, &[0x10, 0x11, 0x40][..]),
        (0x80, 0xfedc0000, &[0x10, 0x11][..]),
    ] {
        for &version in versions {
            let mut block = hardware(version, 7, 0x8123, &[]);
            put16(&mut block, 6, capability);
            put64(&mut block, 8, base);
            // Both units may have the same deprecated HT UnitID (zero).
            put16(&mut block, 18, 0);
            blocks.push(block);
        }
    }
    // Every permutation of the five descriptions, with different maximum
    // versions per capability. Expected selection follows original bytes.
    for mut permutation in 0..120 {
        let mut remaining = vec![0, 1, 2, 3, 4];
        let mut order = Vec::new();
        while !remaining.is_empty() {
            let index = permutation % remaining.len();
            permutation /= remaining.len();
            order.push(remaining.remove(index));
        }
        let ordered: Vec<_> = order
            .iter()
            .map(|&index| blocks[index].as_slice())
            .collect();
        let raw = table(&ordered);
        let original = raw.clone();
        let parsed = Ivrs::parse(&raw, 5).unwrap();
        let selected: Vec<_> = parsed.units().collect();
        assert_eq!(selected.len(), 2);
        let expected: Vec<_> = order
            .iter()
            .copied()
            .filter(|&index| index == 2 || index == 4)
            .collect();
        for (unit, index) in selected.iter().zip(expected) {
            assert_eq!(unit.raw(), blocks[index]);
            assert_eq!(unit.raw().as_ptr(), raw[unit.offset()..].as_ptr());
        }
        assert_eq!(selected[0].id(), selected[1].id());
        assert_ne!(
            selected[0].capability_offset(),
            selected[1].capability_offset()
        );
        for (unit, block) in parsed.hardware_blocks().zip(&ordered) {
            assert_eq!(unit.raw(), *block);
        }
        assert_eq!(raw, original);
        // The instance key does not hide duplicate or inconsistent lower
        // descriptions behind a different capability's higher version.
        for block in &blocks {
            let mut duplicate = ordered.clone();
            duplicate.push(block);
            fail(&table(&duplicate), ErrorKind::DuplicateVersion);
        }
        for index in 0..blocks.len() {
            let mut changed = blocks[index].clone();
            changed[8] ^= 0x10;
            let inconsistent: Vec<_> = order
                .iter()
                .map(|&current| {
                    if current == index {
                        changed.as_slice()
                    } else {
                        blocks[current].as_slice()
                    }
                })
                .collect();
            fail(&table(&inconsistent), ErrorKind::UnitIdentity);
        }
    }
    // Shared nonzero HT UnitID is also metadata, not an instance key.
    for block in &mut blocks {
        put16(block, 18, 0x1f00);
    }
    let raw = table(&blocks.iter().map(Vec::as_slice).collect::<Vec<_>>());
    assert_eq!(Ivrs::parse(&raw, 5).unwrap().units().len(), 2);
}

#[test]
fn entries_preserve_alias_extended_special_and_range_data() {
    let mut entries = Vec::new();
    entries.extend(entry(0, 0, 0, None));
    entries.extend(entry(0x40, 0, 0, Some(0)));
    entries.extend(entry(0x41, 0, 0, Some(0)));
    entries.extend(entry(1, 0, 0xa5, None));
    entries.extend(entry(2, 0xf123, 0x12, None));
    entries.extend(entry(0x42, 0xe123, 0x34, Some(0x00abcd00)));
    entries.extend(entry(0x46, 0xd123, 0x56, Some(0x80001234)));
    for (kind, extra) in [
        (3, None),
        (0x43, Some(0x00bcde00)),
        (0x47, Some(0x87654321)),
    ] {
        entries.extend(entry(kind, 0xc000, 0x78, extra));
        entries.extend(entry(4, 0xcfff, 0x99, None));
    }
    entries.extend(entry(0x48, 0, 0x9a, Some(0x01fabc07)));
    let raw = table(&[&hardware(0x11, 0x4567, 8, &entries)]);
    let unit = Ivrs::parse(&raw, usize::MAX)
        .unwrap()
        .units()
        .next()
        .unwrap();
    let decoded: Vec<_> = unit.entries().collect();
    let rid = |device_id| RequesterId {
        segment: 0x4567,
        device_id,
    };
    assert_eq!(decoded.len(), 14);
    assert_eq!(decoded[0].kind, DeviceKind::Padding);
    assert_eq!(decoded[0].raw().len(), 4);
    assert_eq!(decoded[1].kind, DeviceKind::Padding);
    assert_eq!(decoded[1].raw().len(), 8);
    assert_eq!(decoded[2].kind, DeviceKind::NotUsed);
    assert_eq!(decoded[3].kind, DeviceKind::All);
    assert_eq!(decoded[3].flags(), 0xa5);
    assert_eq!(decoded[4].kind, DeviceKind::Select(rid(0xf123)));
    assert_eq!(
        decoded[5].kind,
        DeviceKind::Alias {
            requester: rid(0xe123),
            target: rid(0xabcd)
        }
    );
    assert_eq!(
        decoded[6].kind,
        DeviceKind::Extended {
            requester: rid(0xd123),
            data: 0x80001234
        }
    );
    assert_eq!(
        decoded[9].kind,
        DeviceKind::RangeStart {
            first: rid(0xc000),
            policy: RangePolicy::Alias(rid(0xbcde))
        }
    );
    assert_eq!(decoded[9].flags(), 0x78);
    assert_eq!(
        decoded[11].kind,
        DeviceKind::RangeStart {
            first: rid(0xc000),
            policy: RangePolicy::Extended(0x87654321)
        }
    );
    assert_eq!(decoded[12].kind, DeviceKind::RangeEnd(rid(0xcfff)));
    assert_eq!(decoded[12].flags(), 0x99);
    assert_eq!(
        decoded[13].kind,
        DeviceKind::Special {
            header_id: 0,
            requester: rid(0xfabc),
            handle: 7,
            variety: 1
        }
    );
    assert_eq!(decoded[13].flags(), 0x9a);
    assert_eq!(decoded[5].raw(), &entries[28..36]);
}

#[test]
fn malformed_ranges_and_unsupported_or_truncated_entries_are_rejected() {
    let start = entry(3, 0x8000, 0, None);
    let end = entry(4, 0x8fff, 0, None);
    for entries in [
        end.clone(),
        start.clone(),
        [start.clone(), start.clone(), end.clone()].concat(),
        [start.clone(), entry(2, 0x8001, 0, None), end.clone()].concat(),
        [start.clone(), entry(4, 0x7fff, 0, None)].concat(),
    ] {
        fail(
            &table(&[&hardware(0x10, 0, 8, &entries)]),
            ErrorKind::DeviceRange,
        );
    }
    for kind in [0x03, 0x43, 0x47] {
        let first = entry(kind, 0x8000, 0, (kind != 0x03).then_some(0x12345678));
        fail(
            &table(&[&hardware(0x11, 0, 8, &first)]),
            ErrorKind::DeviceRange,
        );
        let interleaved = [first, entry(0, 0, 0, None), end.clone()].concat();
        fail(
            &table(&[&hardware(0x11, 0, 8, &interleaved)]),
            ErrorKind::DeviceRange,
        );
    }
    // Unknown fixed-length entries are stepped over; an unknown
    // variable-length entry has no length to step over.
    for kind in [0x05, 0x44, 0x80, 0xff] {
        let bytes = vec![kind; if kind < 0x40 { 4 } else { 8 }];
        let select = entry(2, 0x1234, 0, None);
        let raw = table(&[&hardware(
            0x40,
            0,
            8,
            &[&bytes[..], &select, &bytes].concat(),
        )]);
        if kind < 0x80 {
            let parsed = Ivrs::parse(&raw, usize::MAX).unwrap();
            assert_eq!(parsed.skipped(), [Skipped::Entry(kind)]);
            let kinds: Vec<_> = parsed
                .units()
                .next()
                .unwrap()
                .entries()
                .map(|entry| entry.kind)
                .collect();
            assert_eq!(
                kinds,
                [DeviceKind::Select(RequesterId {
                    segment: 0,
                    device_id: 0x1234
                })]
            );
        } else {
            fail(&raw, ErrorKind::UnsupportedEntry(kind));
        }
    }
    for entry in [
        entry(2, 0x1234, 0, None),
        entry(0x42, 0x1234, 0, Some(0x567800)),
    ] {
        for length in 1..entry.len() {
            fail(
                &table(&[&hardware(0x10, 0, 8, &entry[..length])]),
                ErrorKind::Truncated,
            );
        }
    }
}

#[test]
fn hid_has_exact_variable_length_bounds_in_any_block_type_without_uid_conversion() {
    let mut hid = entry(0xf0, 0xabcd, 0x96, None);
    hid.extend_from_slice(b"AMDI0040");
    hid.extend_from_slice(b"COMPAT00");
    hid.extend_from_slice(&[2, 3, b'a', 0, b'b']);
    let raw = table(&[&hardware(0x40, 0x1234, 8, &hid)]);
    let entry = Ivrs::parse(&raw, usize::MAX)
        .unwrap()
        .units()
        .next()
        .unwrap()
        .entries()
        .next()
        .unwrap();
    assert_eq!(
        entry.kind,
        DeviceKind::Hid {
            requester: RequesterId {
                segment: 0x1234,
                device_id: 0xabcd
            },
            hid: b"AMDI0040",
            cid: b"COMPAT00",
            uid_format: 2,
            uid: b"a\0b",
        }
    );
    assert_eq!(entry.flags(), 0x96);
    assert_eq!(entry.raw(), hid);
    // Linux reads a HID entry in any IVHD type.
    for version in [0x10, 0x11] {
        let raw = table(&[&hardware(version, 0, 8, &hid)]);
        let parsed = Ivrs::parse(&raw, usize::MAX).unwrap();
        assert!(parsed.skipped().is_empty());
        let unit = parsed.units().next().unwrap();
        assert!(matches!(
            unit.entries().next().unwrap().kind,
            DeviceKind::Hid { .. }
        ));
    }
    for length in 1..hid.len() {
        fail(
            &table(&[&hardware(0x40, 0, 8, &hid[..length])]),
            ErrorKind::Truncated,
        );
    }
    hid[21] = 0;
    hid.truncate(HID_PREFIX);
    assert!(Ivrs::parse(&table(&[&hardware(0x40, 0, 8, &hid)]), usize::MAX).is_ok());
}

#[test]
fn global_memory_scope_ignores_reserved_ids_and_neighboring_segments() {
    for segment in [0, 0xffff] {
        let before = hardware(0x10, segment, 8, &[]);
        let after = hardware(0x10, segment ^ 0xffff, 8, &[]);
        for (device, auxiliary, reserved_segment) in
            [(0, 0, 0), (0xffff, 0, 0x1234), (0xaffe, 0x8123, 0xfedc)]
        {
            for flags in [0, 0x0f] {
                let mut global = vec![0; IVMD_HEADER];
                global[0] = 0x20;
                global[1] = flags;
                put16(&mut global, 2, IVMD_HEADER as u16);
                put16(&mut global, 4, device);
                put16(&mut global, 6, auxiliary);
                put16(&mut global, 8, reserved_segment);
                global[10..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
                put64(&mut global, 16, 0x12345);
                put64(&mut global, 24, 0x1000);
                for descriptions in [
                    [global.as_slice(), before.as_slice(), after.as_slice()],
                    [before.as_slice(), global.as_slice(), after.as_slice()],
                    [before.as_slice(), after.as_slice(), global.as_slice()],
                ] {
                    let raw = table(&descriptions);
                    let original = raw.clone();
                    let parsed = Ivrs::parse(&raw, 2).unwrap();
                    assert_eq!(parsed.units().len(), 2);
                    let mut definitions = parsed.memory_definitions();
                    let memory = definitions.next().unwrap();
                    assert!(definitions.next().is_none());
                    assert_eq!(memory.segment(), None);
                    assert_eq!(memory.scope(), MemoryScope::AllDevices);
                    assert_eq!(
                        (memory.device_id(), memory.auxiliary()),
                        (device, auxiliary)
                    );
                    assert_eq!(memory.raw(), global);
                    assert_eq!(memory.raw().as_ptr(), raw[memory.offset()..].as_ptr());
                    // Preserve context for later live-policy admission;
                    // neither neighboring segment narrows raw type-20 scope.
                    let mut offset = TABLE_HEADER;
                    for (block, expected) in parsed.blocks().zip(descriptions) {
                        let (bytes, actual_offset) = match block {
                            Block::Hardware(unit) => (unit.raw(), unit.offset()),
                            Block::Memory(item) => (item.raw(), item.offset()),
                        };
                        assert_eq!((bytes, actual_offset), (expected, offset));
                        offset += expected.len();
                    }
                    assert_eq!(raw, original);
                }
            }
        }
    }
}

#[test]
fn memory_policy_keeps_type_specific_scope_flags_and_unrounded_addresses() {
    let mut blocks = Vec::new();
    for kind in [0x20, 0x21, 0x22] {
        let mut block = vec![0; IVMD_HEADER];
        block[0] = kind;
        block[1] = 0x0f;
        put16(&mut block, 2, IVMD_HEADER as u16);
        put16(&mut block, 4, 0x8123);
        put16(&mut block, 6, 0xaffe);
        put16(&mut block, 8, 0xfedc);
        put64(&mut block, 16, 0x12345);
        put64(&mut block, 24, 0x23456);
        blocks.push(block);
    }
    let raw = table(&blocks.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let memory: Vec<_> = Ivrs::parse(&raw, usize::MAX)
        .unwrap()
        .memory_definitions()
        .collect();
    assert_eq!(memory.len(), 3);
    for (index, item) in memory.iter().enumerate() {
        assert_eq!(
            (
                item.flags(),
                item.segment(),
                item.start(),
                item.length(),
                item.end()
            ),
            (
                0x0f,
                (index != 0).then_some(0xfedc),
                0x12345,
                0x23456,
                0x3579b
            )
        );
    }
    assert_eq!(memory[0].scope(), MemoryScope::AllDevices);
    assert_eq!(
        memory[1].scope(),
        MemoryScope::Device(RequesterId {
            segment: 0xfedc,
            device_id: 0x8123
        })
    );
    let mut extended = blocks[0].clone();
    extended.extend_from_slice(&[0x91, 0x82]);
    put16(&mut extended, 2, (IVMD_HEADER + 2) as u16);
    let extension_table = table(&[&extended]);
    assert_eq!(
        Ivrs::parse(&extension_table, usize::MAX)
            .unwrap()
            .memory_definitions()
            .next()
            .unwrap()
            .raw(),
        extended
    );
    let complete = table(&[&blocks[0]]);
    for end in TABLE_HEADER + 1..complete.len() {
        let mut prefix = complete[..end].to_vec();
        prefix[4..8].copy_from_slice(&(end as u32).to_le_bytes());
        checksum(&mut prefix);
        fail(&prefix, ErrorKind::Truncated);
    }
    assert_eq!(
        memory[2].scope(),
        MemoryScope::Range {
            first: RequesterId {
                segment: 0xfedc,
                device_id: 0x8123
            },
            last: RequesterId {
                segment: 0xfedc,
                device_id: 0xaffe
            },
        }
    );
    let mut bad = blocks[2].clone();
    put16(&mut bad, 6, 0x8122);
    fail(&table(&[&bad]), ErrorKind::DeviceRange);
    let mut bad = blocks[1].clone();
    put64(&mut bad, 16, u64::MAX);
    fail(&table(&[&bad]), ErrorKind::AddressOverflow);
    for length in BLOCK_HEADER..IVMD_HEADER {
        let mut bad = blocks[0][..length].to_vec();
        put16(&mut bad, 2, length as u16);
        fail(&table(&[&bad]), ErrorKind::BlockLength);
    }
}

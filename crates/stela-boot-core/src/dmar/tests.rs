//! DMAR firmware metadata and admission parser controls.
use super::*;
use alloc::{vec, vec::Vec};
fn seal(mut table: Vec<u8>) -> Vec<u8> {
    let bytes = table.len() as u32;
    table[4..8].copy_from_slice(&bytes.to_le_bytes());
    table[9] = 0;
    table[9] = 0u8.wrapping_sub(table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    table
}
fn fixture() -> Vec<u8> {
    let mut table = vec![0; 64];
    table[..4].copy_from_slice(b"DMAR");
    table[36] = 47;
    table[50..52].copy_from_slice(&16u16.to_le_bytes());
    table[52] = 1;
    table[56..64].copy_from_slice(&0xfed90000u64.to_le_bytes());
    seal(table)
}
fn scoped(paths: &[[u8; 8]]) -> Vec<u8> {
    let mut table = fixture();
    table[52] = 0;
    for scope in paths {
        table.extend(scope);
    }
    let length = (table.len() - HEADER) as u16;
    table[50..52].copy_from_slice(&length.to_le_bytes());
    seal(table)
}
#[test]
fn parses_units_reserved_regions_and_bridge_paths() {
    let mut table = fixture();
    // A second unit with an endpoint behind a bridge and a bridge scope.
    let mut unit = vec![0, 0, 0, 0, 0, 0, 0, 0];
    unit.extend(0xfed91000u64.to_le_bytes());
    unit.extend([1, 10, 0, 0, 0, 0, 0x1c, 0, 0, 0]);
    unit.extend([2, 8, 0, 0, 0, 0, 0x1d, 0]);
    unit.extend([3, 8, 0, 0, 2, 0xf0, 0x1f, 0]);
    let length = unit.len() as u16;
    unit[2..4].copy_from_slice(&length.to_le_bytes());
    table.extend(unit);
    let mut rmrr = vec![1, 0, 32, 0, 0, 0, 0, 0];
    rmrr.extend(0x7d000000u64.to_le_bytes());
    rmrr.extend(0x7d01ffffu64.to_le_bytes());
    rmrr.extend([1, 8, 0, 0, 0, 0, 0x14, 0]);
    table.extend(rmrr);
    table.extend([3, 0, 4, 0]);
    let parsed = parse(&seal(table)).unwrap();
    assert_eq!(parsed.physical_bits, 48);
    assert_eq!(parsed.units.len(), 2);
    assert!(parsed.units[0].include_all);
    assert_eq!(
        parsed.units[1].scopes,
        [
            Scope {
                bridge: false,
                bus: 0,
                path: vec![(0x1c, 0), (0, 0)]
            },
            Scope {
                bridge: true,
                bus: 0,
                path: vec![(0x1d, 0)]
            }
        ]
    );
    assert_eq!(
        parsed.units[1].sources,
        [SourceScope {
            kind: SourceKind::IoApic,
            flags: 0,
            reserved: 0,
            enumeration_id: 2,
            bus: 0xf0,
            path: vec![(0x1f, 0)],
        }]
    );
    assert_eq!(parsed.additional_structures, [3]);
    assert_eq!(parsed.reserved[0].limit, 0x7d01ffff);
    assert_eq!(parsed.reserved[0].scopes[0].path, [(0x14, 0)]);
    assert!(parsed.skipped.is_empty());
    let mut unaligned = fixture();
    unaligned.extend([1, 0, 24, 0, 0, 0, 0, 0]);
    unaligned.extend(0x1800u64.to_le_bytes());
    unaligned.extend(0x1900u64.to_le_bytes());
    let parsed = parse(&seal(unaligned)).unwrap();
    assert_eq!(
        (parsed.reserved[0].base, parsed.reserved[0].limit),
        (0x1000, 0x1fff)
    );
    assert_eq!(parsed.skipped, [Skipped::UnalignedRegion]);
    assert!(parsed.complete());
}

#[test]
fn source_inventory_preserves_ids_paths_flags_and_unknown_requirements() {
    let mut table = scoped(&[
        [1, 8, 0, 0, 0, 0, 2, 0],
        [3, 8, 0, 0, 9, 0x20, 0x1f, 0],
        [4, 8, 0, 0, 3, 0x42, 0x1e, 7],
        [5, 8, 0, 0, 5, 0x45, 0x1d, 6],
        [0x7f, 8, 0x80, 0x40, 7, 0x80, 0x1c, 5],
    ]);
    table[37] = 7;
    table.extend([0x7f, 0, 4, 0]);
    let parsed = parse(&seal(table)).unwrap();
    assert_eq!(parsed.flags, 7);
    assert_eq!(parsed.units[0].scopes.len(), 1);
    let sources = &parsed.units[0].sources;
    assert_eq!(sources.len(), 4);
    assert_eq!(
        sources.iter().map(|s| s.kind).collect::<Vec<_>>(),
        [
            SourceKind::IoApic,
            SourceKind::Hpet,
            SourceKind::Namespace,
            SourceKind::Reserved(0x7f)
        ]
    );
    assert_eq!(
        sources.iter().map(|s| s.enumeration_id).collect::<Vec<_>>(),
        [9, 3, 5, 7]
    );
    assert_eq!((sources[1].bus, &sources[1].path), (0x42, &vec![(0x1e, 7)]));
    assert_eq!((sources[2].bus, &sources[2].path), (0x45, &vec![(0x1d, 6)]));
    assert_eq!((sources[3].flags, sources[3].reserved), (0x80, 0x40));
    assert_eq!(parsed.additional_structures, [0x7f]);
}

#[test]
fn unusable_scopes_are_dropped_and_mark_the_table_incomplete() {
    for scope in [
        [3, 6, 0, 0, 1, 0, 0, 0],
        [4, 8, 0, 0, 1, 0, 32, 0],
        [5, 8, 0, 0, 1, 0, 0, 8],
        [1, 8, 0, 0, 0, 0, 32, 0],
    ] {
        let mut table = scoped(&[[1, 8, 0, 0, 0, 0, 2, 0]]);
        let bytes = usize::from(scope[1]);
        table.extend(&scope[..bytes]);
        let length = (table.len() - HEADER) as u16;
        table[50..52].copy_from_slice(&length.to_le_bytes());
        let parsed = parse(&seal(table)).unwrap();
        assert_eq!(parsed.units[0].scopes.len(), 1, "{scope:?}");
        assert!(parsed.units[0].sources.is_empty());
        assert_eq!(parsed.skipped, [Skipped::UnusableScope]);
        assert!(!parsed.complete());
    }
    // A scope too short to step over still fails the structure.
    for bytes in [0, 5] {
        let mut table = scoped(&[[1, 8, 0, 0, 0, 0, 2, 0]]);
        table[65] = bytes;
        assert_eq!(parse(&seal(table)), Err(DmarError::InvalidStructure));
    }
}

#[test]
fn reserved_scope_bytes_odd_lengths_and_long_source_paths_are_passed_over() {
    for scope in [
        [1, 8, 1, 0, 0, 0, 0, 0],
        [2, 8, 0, 1, 0, 0, 0, 0],
        [1, 8, 0, 0, 1, 0, 0, 0],
    ] {
        let parsed = parse(&scoped(&[scope])).unwrap();
        assert_eq!(parsed.units[0].scopes[0].path, [(0, 0)]);
        assert_eq!(parsed.skipped, [Skipped::ReservedBits]);
        assert!(parsed.complete());
    }
    // An HPET or namespace path through a bridge, as Linux walks it.
    for kind in [4, 5] {
        let mut table = scoped(&[[kind, 8, 0, 0, 1, 0, 0x1c, 0]]);
        table.extend([1, 0]);
        table[65] = 10;
        table[50..52].copy_from_slice(&26u16.to_le_bytes());
        let parsed = parse(&seal(table)).unwrap();
        assert_eq!(parsed.units[0].sources[0].path, [(0x1c, 0), (1, 0)]);
        assert!(parsed.skipped.is_empty());
    }
    // An odd length: the trailing byte is ignored.
    let mut table = scoped(&[[1, 8, 0, 0, 0, 0, 2, 0]]);
    table.push(0x55);
    table[65] = 9;
    table[50..52].copy_from_slice(&25u16.to_le_bytes());
    let parsed = parse(&seal(table)).unwrap();
    assert_eq!(parsed.units[0].scopes[0].path, [(2, 0)]);
    assert_eq!(parsed.skipped, [Skipped::OddScopeLength]);
    // Source flags stay recorded for the policy to refuse.
    let parsed = parse(&scoped(&[[3, 8, 1, 2, 9, 0, 0x1f, 0]])).unwrap();
    let source = &parsed.units[0].sources[0];
    assert_eq!((source.flags, source.reserved), (1, 2));
}

#[test]
fn reserved_header_unit_and_region_bits_are_ignored_once() {
    for (offset, value) in [(37, 0x80), (38, 1), (47, 1), (52, 2), (53, 0x10)] {
        let mut table = fixture();
        table[offset] = value;
        let parsed = parse(&seal(table)).unwrap();
        assert_eq!(parsed.skipped, [Skipped::ReservedBits], "byte {offset}");
        assert_eq!(parsed.units[0].bytes, 4096);
        assert!(parsed.complete());
    }
    // Include-all covers its listed requesters anyway.
    let mut table = scoped(&[[1, 8, 0, 0, 0, 0, 1, 0]]);
    table[52] = 1;
    let parsed = parse(&seal(table)).unwrap();
    assert!(parsed.units[0].include_all && parsed.units[0].scopes.is_empty());
    assert_eq!(parsed.skipped, [Skipped::IncludeAllScopes]);
    for offset in [4, 5] {
        let mut table = fixture();
        let mut rmrr = vec![1, 0, 24, 0, 0, 0, 0, 0];
        rmrr.extend(0x1000u64.to_le_bytes());
        rmrr.extend(0x1fffu64.to_le_bytes());
        rmrr[offset] = 1;
        table.extend(rmrr.clone());
        table.extend(rmrr);
        let parsed = parse(&seal(table)).unwrap();
        assert_eq!(parsed.reserved.len(), 2);
        assert_eq!(parsed.skipped, [Skipped::ReservedBits]);
    }
    let mut table = fixture();
    table[53] = 1;
    table[56..64].copy_from_slice(&0xfed91000u64.to_le_bytes());
    assert_eq!(
        parse(&seal(table.clone())),
        Err(DmarError::InvalidStructure)
    );
    table[56..64].copy_from_slice(&0xfed92000u64.to_le_bytes());
    assert_eq!(parse(&seal(table)).unwrap().units[0].bytes, 8192);
    let mut table = scoped(&[[3, 8, 0, 0, 9, 0, 0x1c, 0]]);
    table.extend([0, 0]);
    table[65] = 10;
    table[50..52].copy_from_slice(&26u16.to_le_bytes());
    assert_eq!(
        parse(&seal(table)).unwrap().units[0].sources[0].path,
        [(0x1c, 0), (0, 0)]
    );
    // A structure too short to step over still fails the table.
    let mut table = fixture();
    table.extend([1, 0, 0, 0]);
    assert_eq!(parse(&seal(table)), Err(DmarError::InvalidStructure));
}

#[test]
fn reserved_ranges_past_the_host_width_are_dropped() {
    for (bits, limit, valid) in [
        (48, u64::MAX, false),
        (64, u64::MAX, false),
        (48, (1u64 << 48) + 4095, false),
        (48, (1u64 << 48) - 1, true),
    ] {
        let mut table = fixture();
        table[36] = bits - 1;
        table.extend([1, 0, 32, 0, 0, 0, 0, 0]);
        table.extend((limit & !4095).to_le_bytes());
        table.extend(limit.to_le_bytes());
        table.extend([1, 8, 0, 0, 0, 0, 0x14, 0]);
        let parsed = parse(&seal(table)).unwrap();
        if valid {
            assert_eq!(parsed.reserved[0].limit, limit);
            assert!(parsed.complete());
        } else {
            assert!(parsed.reserved.is_empty());
            assert_eq!(parsed.skipped, [Skipped::UnusableRegion]);
            assert!(!parsed.complete());
        }
    }
}

#[test]
fn requires_live_endpoint_coverage_and_valid_direct_paths() {
    let one = [1, 8, 0, 0, 0, 0, 1, 0];
    let two = [1, 8, 0, 0, 0, 0, 2, 0];
    let ioapic = [3, 8, 0, 0, 0, 255, 31, 0];
    let complete = scoped(&[two, one, ioapic]);
    assert!(single_flat_owner(&complete, 0, &[8, 16]).is_ok());
    assert_eq!(
        single_flat_owner(&scoped(&[one]), 0, &[8, 16]),
        Err(DmarError::MissingRequester(16))
    );
    assert_eq!(
        single_flat_owner(&scoped(&[one, one]), 0, &[8]),
        Err(DmarError::DuplicateRequester(8))
    );
    assert_eq!(
        single_flat_owner(&scoped(&[one, two]), 0, &[8]),
        Err(DmarError::UnlistedRequester(16))
    );
    assert_eq!(
        single_flat_owner(&complete, 0, &[8, 8]),
        Err(DmarError::DuplicateRequester(8))
    );
    assert_eq!(
        single_flat_owner(&complete, 0, &[0x108]),
        Err(DmarError::UnsupportedRouting)
    );
    let mut bridge = one;
    bridge[0] = 2;
    assert_eq!(
        single_flat_owner(&scoped(&[bridge]), 0, &[8]),
        Err(DmarError::UnsupportedScope(2))
    );
    for (index, value) in [(1, 7), (2, 1), (4, 1), (6, 32), (7, 8)] {
        let mut malformed = one;
        malformed[index] = value;
        assert_eq!(
            single_flat_owner(&scoped(&[malformed]), 0, &[8]),
            Err(DmarError::InvalidStructure)
        );
    }
    let mut multihop = scoped(&[one]);
    multihop[65] = 10;
    multihop.extend([2, 0]);
    multihop[50..52].copy_from_slice(&26u16.to_le_bytes());
    assert_eq!(
        single_flat_owner(&seal(multihop), 0, &[8]),
        Err(DmarError::UnsupportedRouting)
    );
}
#[test]
fn single_flat_owner_accepts_only_one_complete_unit() {
    let table = fixture();
    assert_eq!(
        single_flat_owner(&table, 0, &[8, 16]),
        Ok(HardwareUnit {
            base: 0xfed90000,
            bytes: 4096,
            segment: 0,
            physical_bits: 48
        })
    );
    assert_eq!(
        single_flat_owner(&table, 1, &[8, 16]),
        Err(DmarError::UnsupportedRouting)
    );
    let mut rmrr = table.clone();
    rmrr.extend([1, 0, 4, 0]);
    assert_eq!(
        single_flat_owner(&seal(rmrr), 0, &[8, 16]),
        Err(DmarError::UnsupportedStructure(1))
    );
    let mut multiple = table.clone();
    multiple.extend_from_slice(&table[48..]);
    assert_eq!(
        single_flat_owner(&seal(multiple), 0, &[8, 16]),
        Err(DmarError::MultipleUnits)
    );
    let mut partial = table.clone();
    partial[52] = 0;
    assert_eq!(
        single_flat_owner(&seal(partial), 0, &[8, 16]),
        Err(DmarError::MissingRequester(8))
    );
    for length in [0u16, 3, 15, 17, u16::MAX] {
        let mut broken = table.clone();
        broken[50..52].copy_from_slice(&length.to_le_bytes());
        assert!(single_flat_owner(&seal(broken), 0, &[8, 16]).is_err());
    }
    let mut bad_width = table.clone();
    bad_width[36] = 255;
    assert_eq!(
        single_flat_owner(&seal(bad_width), 0, &[8, 16]),
        Err(DmarError::UnsupportedWidth)
    );
    let mut unaligned = table;
    unaligned[56] = 1;
    assert_eq!(
        single_flat_owner(&seal(unaligned), 0, &[8, 16]),
        Err(DmarError::InvalidStructure)
    );
}

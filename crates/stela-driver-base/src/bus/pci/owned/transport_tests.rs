//! Actual isolated RAM count/effect controls. No native permission is minted.
use super::{grant::DriverGrant, test_support, *};
use crate::bus::mmio::owned::{CacheAttribute, PhysicalSpan, Protection, ResourceKind};
use crate::bus::pci::{ConfigEffect, ConfigFailure};
use alloc::boxed::Box;
use core::sync::atomic::Ordering;

fn mapped() -> (
    test_support::FixtureCustody,
    Mapping,
    alloc::sync::Arc<test_support::Counters>,
) {
    let address = Address {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
    };
    let window = EcamWindow {
        segment: 0,
        start_bus: 0,
        end_bus: 0,
        base: 0x8000_0000,
    };
    test_support::mapped(
        address,
        window,
        PhysicalSpan::new(window.base, 4096).unwrap(),
        0,
        4096,
        CacheAttribute::Uncached,
        Protection::ReadWrite,
    )
}

#[test]
fn parking_withdraws_the_map_and_preserves_the_source_seal_on_reattach() {
    let address = test_support::ADDRESS;
    let span = PhysicalSpan::new(test_support::physical(address), 4096).unwrap();
    let (source, authority, counters) = test_support::unmapped(
        address,
        test_support::window(address),
        span,
        CacheAttribute::Uncached,
    );
    let retained = source.retention();
    let map = |prepared: &PreparedConfig<grant::PrepublicationGrant>| {
        authority
            .map(
                prepared.configuration_resource().clone(),
                0,
                4096,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .unwrap()
    };
    let prepared = UnpublishedConfig::prepare(source.into_prepublication());
    let mapping = map(&prepared);
    let mut config = prepared
        .attach(mapping)
        .unwrap_or_else(|_| panic!("attach"));
    config.seal_bus_master().unwrap();
    // SAFETY: this isolated model has one source and no other map users.
    let prepared = unsafe { config.park() }.unwrap_or_else(|_| panic!("park"));
    assert_eq!(retained.uses(), 0);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    let mapping = map(&prepared);
    let config = prepared
        .attach(mapping)
        .unwrap_or_else(|_| panic!("reattach"));
    // SAFETY: the same fixture owns the original resource and completed all
    // old accesses. The source's own checked model transition runs here.
    let mut config = unsafe { config.promote(test_support::FixtureCustody::finish_promotion) }
        .unwrap_or_else(|_| panic!("promotion"));
    assert_eq!(
        config.try_write16(4, 4),
        Err(ConfigError::before_effect(ConfigFailure::BusMasterSealed))
    );
    assert_eq!(retained.uses(), 1);
    drop(retained);
    // SAFETY: all synchronous isolated access ended.
    unsafe { test_support::retire_owned(config) }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 2);
}

#[test]
fn parked_bridge_retains_the_original_route_through_promotion() {
    let address = test_support::ADDRESS;
    let span = PhysicalSpan::new(test_support::physical(address), 4096).unwrap();
    let (source, authority, counters) = test_support::unmapped(
        address,
        test_support::window(address),
        span,
        CacheAttribute::Uncached,
    );
    let retained = source.retention();
    let base = source.fixture_base().as_ptr();
    // SAFETY: this is a private model page, kept through every access below.
    let at = |offset| unsafe { base.add(usize::from(offset)) };
    let read = |offset, width| {
        // SAFETY: these naturally aligned fields are inside that same page.
        Ok(unsafe {
            match width {
                1 => u32::from(at(offset).read_volatile()),
                2 => u32::from(at(offset).cast::<u16>().read_volatile()),
                4 => at(offset).cast::<u32>().read_volatile(),
                _ => unreachable!("configuration field width"),
            }
        })
    };
    // SAFETY: set the Type 1 header in the original model before attachment.
    unsafe { at(0x0e).write_volatile(1) };
    let attach = |prepared: PreparedConfig<grant::PrepublicationGrant>| {
        let mapping = authority
            .map(
                prepared.configuration_resource().clone(),
                0,
                4096,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .unwrap();
        prepared
            .attach(mapping)
            .unwrap_or_else(|_| panic!("attach"))
    };
    let mut config = attach(UnpublishedConfig::prepare(source.into_prepublication()));
    // A bridge holding Secondary Bus Reset is refused with the bit named,
    // and the reset is left as found.
    // SAFETY: model firmware leaving the reset asserted.
    unsafe { at(0x3e).cast::<u16>().write_volatile(1 << 6 | 1 << 1) };
    assert_eq!(
        config.seal_bus_routing(),
        Err(ConfigError::before_effect(ConfigFailure::Readback {
            offset: 0x3e,
            width: 2,
            expected: 1 << 1,
            observed: 1 << 6 | 1 << 1,
        }))
    );
    assert_eq!(read(0x3e, 2), Ok(1 << 6 | 1 << 1));
    // SAFETY: restore the model.
    unsafe { at(0x3e).cast::<u16>().write_volatile(0) };
    config.seal_bus_routing().unwrap();
    // SAFETY: the original map has no escaping users.
    let prepared = unsafe { config.park() }.unwrap_or_else(|_| panic!("park"));
    // SAFETY: emulate hardware updates to the two status fields in the model.
    unsafe {
        at(0x1e).cast::<u16>().write_volatile(1 << 13);
        at(0x3e).cast::<u16>().write_volatile(1 << 10);
    }
    assert_eq!(prepared.check_bridge_routing(read), Ok(()));

    // SAFETY: model an out-of-band change to the bridge memory window.
    unsafe { at(0x20).cast::<u32>().write_volatile(0x1000) };
    let changed = Err(ConfigError::before_effect(ConfigFailure::Readback {
        offset: 0x20,
        width: 4,
        expected: 0,
        observed: 0x1000,
    }));
    assert_eq!(prepared.check_bridge_routing(read), changed);
    let mut config = attach(prepared);
    assert_eq!(config.seal_bus_routing(), changed);
    // SAFETY: restore the model before starting the independent promotion check.
    unsafe { at(0x20).cast::<u32>().write_volatile(0) };
    assert_eq!(config.seal_bus_routing(), Ok(()));
    // SAFETY: isolated model with no escaped mapping. Only the source callback
    // models the window drifting after the initial promotion check.
    let (error, mut original) = unsafe {
        config.promote(|source: &mut test_support::FixtureCustody| {
            source.finish_promotion()?;
            at(0x20).cast::<u32>().write_volatile(0x1000);
            Ok(())
        })
    }
    .err()
    .expect("changed route must refuse promotion");
    assert_eq!(error, MappingError::InvalidPlatformReply);
    assert_eq!(retained.uses(), 1);
    assert!(retained.check_admission().is_err());
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    // SAFETY: all synchronous test reads and writes ended.
    unsafe { original.retire() }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 2);
}

#[test]
fn promotion_keeps_the_original_mapping_and_command_seal() {
    let (source, mapping, counters) = mapped();
    let retention = source.retention();
    let mut config = UnpublishedConfig::prepare(source.into_prepublication())
        .attach(mapping)
        .unwrap_or_else(|_| panic!("original prepublication mapping refused"));
    assert_eq!(
        config.try_write16(4, 4),
        Err(ConfigError::before_effect(
            ConfigFailure::UnqualifiedControl
        ))
    );
    config.seal_bus_master().unwrap();
    // SAFETY: this synchronous RAM fixture has no native effects or old
    // users. The original model controller checks its single kept mapping.
    let mut config = unsafe { config.promote(test_support::FixtureCustody::finish_promotion) }
        .unwrap_or_else(|_| panic!("original isolated fixture refused promotion"));
    assert_eq!(retention.uses(), 1);
    assert_eq!(counters.maps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(
        config.try_write16(4, 4),
        Err(ConfigError::before_effect(ConfigFailure::BusMasterSealed))
    );
    config.try_write16(4, 2).unwrap();
    assert_eq!(config.try_read16(4), Ok(2));
    drop(retention);
    // SAFETY: all actual model users are joined.
    unsafe { test_support::retire_config(config, &counters) }.unwrap();
}

#[test]
fn refused_promotion_closes_the_same_kept_owner() {
    let (source, mapping, counters) = mapped();
    let retention = source.retention();
    let config = UnpublishedConfig::prepare(source.into_prepublication())
        .attach(mapping)
        .unwrap_or_else(|_| panic!("original prepublication mapping refused"));
    // SAFETY: the isolated controller keeps its original allocation. The
    // callback reports that the required qualification could not complete.
    let (error, mut original) = unsafe {
        config.promote(|_: &mut test_support::FixtureCustody| Err(MappingError::Unavailable))
    }
    .err()
    .expect("source refused promotion");
    assert_eq!(error, MappingError::Unavailable);
    assert_eq!(retention.uses(), 1);
    assert!(retention.check_admission().is_err());
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    // SAFETY: this failed model callback exposed no hardware/raw user.
    unsafe { original.retire() }.unwrap();
    assert_eq!(retention.uses(), 0);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
}

#[test]
fn retained_prepublication_view_blocks_the_source_callback() {
    let (source, mapping, counters) = mapped();
    let config = UnpublishedConfig::prepare(source.into_prepublication())
        .attach(mapping)
        .unwrap_or_else(|_| panic!("original prepublication mapping refused"));
    let view = config.retain_epoch().unwrap();
    // SAFETY: the model has no raw users. The transport must refuse while
    // the existing view still pins the prepublication mapping.
    let (error, mut original) = unsafe {
        config.promote(|_: &mut test_support::FixtureCustody| {
            panic!("source callback ran with a retained prepublication view")
        })
    }
    .err()
    .expect("old view must refuse promotion");
    assert_eq!(error, MappingError::Busy);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    drop(view);
    // SAFETY: the sole actual model view has ended.
    unsafe { original.retire() }.unwrap();
}

#[test]
fn promotion_rechecks_admission_after_the_source_callback() {
    let (source, mapping, counters) = mapped();
    let config = UnpublishedConfig::prepare(source.into_prepublication())
        .attach(mapping)
        .unwrap_or_else(|_| panic!("original prepublication mapping refused"));
    // SAFETY: this isolated fixture has no old native or raw access. Model
    // the original close racing the callback's successful phase decision.
    let (error, mut original) = unsafe {
        config.promote(|source: &mut test_support::FixtureCustody| {
            source.finish_promotion()?;
            assert!(source.close().is_err());
            Ok(())
        })
    }
    .err()
    .expect("closed original slot must refuse promotion");
    assert_eq!(
        error,
        MappingError::Assignment(crate::bus::pci::assignment::Error::Closed)
    );
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    // SAFETY: the isolated allocation has no additional users.
    unsafe { original.retire() }.unwrap();
}

#[test]
fn promotion_callback_unwind_keeps_the_original_live_count_closed() {
    extern crate std;

    let (source, mapping, counters) = mapped();
    let retention = source.retention();
    let config = UnpublishedConfig::prepare(source.into_prepublication())
        .attach(mapping)
        .unwrap_or_else(|_| panic!("original prepublication mapping refused"));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: the model has no raw/native users, but qualification
        // unwinds and must leave the whole original graph parked.
        unsafe { config.promote(|_: &mut test_support::FixtureCustody| panic!("source unwind")) }
    }));
    assert!(result.is_err());
    assert!(retention.check_admission().is_err());
    assert_eq!(retention.uses(), 1);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
}

#[test]
fn counted_transport_survives_extraction_without_generic_bme_or_pointer_escape() {
    let (source, mapping, counters) = mapped();
    let retention = source.retention();
    let mut config = match OwnedConfig::attach_test(source.into_grant(), mapping) {
        Ok(config) => Box::new(config),
        Err(_) => panic!("actual RAM attachment refused"),
    };
    assert_eq!(retention.uses(), 1);
    config.try_write8(0x40, 0xab).unwrap();
    config.try_write16(0x42, 0xcdef).unwrap();
    config.try_write32(0x44, 0x89ab_cdef).unwrap();
    assert_eq!(config.try_read8(0x40).unwrap(), 0xab);
    assert_eq!(config.try_read16(0x42).unwrap(), 0xcdef);
    assert_eq!(config.try_read32(0x44).unwrap(), 0x89ab_cdef);
    assert_eq!(retention.uses(), 1);
    config.seal_bus_master().unwrap();
    let (grant, mapping) = (*config).into_parts().into_test_parts();
    assert_eq!(mapping.kind(), Ok(ResourceKind::Configuration));
    assert_eq!(
        mapping.address(0, 4096),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(
        mapping.write32(4, 4),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(
        mapping.read32(0x44),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(retention.uses(), 1);
    let mut config = match OwnedConfig::attach_test(grant, mapping) {
        Ok(config) => config,
        Err((error, _, _)) => panic!("original RAM attachment refused: {error:?}"),
    };
    assert_eq!(config.try_read32(0x44).unwrap(), 0x89ab_cdef);
    assert!(matches!(
        config.try_write16(4, 4),
        Err(ConfigError {
            reason: ConfigFailure::BusMasterSealed,
            ..
        })
    ));
    drop(retention);
    // SAFETY: every synchronous isolated fixture raw/callback tail has ended.
    unsafe { test_support::retire_config(config, &counters) }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
}
#[test]
fn equal_geometry_register_mapping_cannot_be_used_as_configuration() {
    let (source, original, counters) = mapped();
    let (bar, registers) = test_support::bar_fixture(original.physical_span().unwrap(), 4096);
    let (error, grant, registers) = match OwnedConfig::attach_test(source.into_grant(), registers) {
        Ok(_) => panic!("register mapping accepted as configuration"),
        Err(refusal) => refusal,
    };
    assert_eq!(
        error,
        ConfigError::before_effect(ConfigFailure::Mapping(
            MappingError::ConfigurationOperationRequired,
        ))
    );
    assert_eq!(registers.kind(), Ok(ResourceKind::Registers));
    assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
    // SAFETY: only attachment metadata was inspected. Both original
    // fixtures have stopped all users and are retired with their own owners.
    unsafe {
        bar.retire(registers).unwrap();
        test_support::retire(grant, original, &counters).unwrap();
    }
}

#[test]
fn real_poststore_failure_keeps_prefix_count_and_generic_veto() {
    let (source, mapping, counters) = mapped();
    let retention = source.retention();
    let mut parked: Box<(Option<DriverGrant>, Option<Mapping>)> = Box::new((None, None));
    let mut config = match OwnedConfig::attach_test(source.into_grant(), mapping) {
        Ok(config) => Box::new(config),
        Err(_) => panic!("actual RAM attachment refused"),
    };
    counters.fail_after_word.store(0x40 + 1, Ordering::Relaxed);
    counters
        .fail_after_value
        .store(0x89ab_cdef, Ordering::Relaxed);
    let error = config.try_write32(0x40, 0x89ab_cdef).unwrap_err();
    assert_eq!(
        error.effect,
        ConfigEffect::WriteMayHaveApplied {
            offset: 0x40,
            width: 4
        }
    );
    assert_eq!(retention.uses(), 2);
    let mut parts = (*config).into_parts();
    // SAFETY: all synchronous callers have returned. The retained internal
    // operation still has an uncertain effect and must veto unmap.
    assert_eq!(unsafe { parts.retire() }, Err(MappingError::Busy));
    let (grant, mapping) = parts.into_test_parts();
    parked.0 = Some(grant);
    parked.1 = Some(mapping);
    let contexts = counters.contexts.load(Ordering::Relaxed);
    assert_eq!(
        parked.1.as_ref().unwrap().address(0, 4),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(
        parked.1.as_ref().unwrap().write32(4, 4),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(counters.contexts.load(Ordering::Relaxed), contexts);
    assert_eq!(retention.uses(), 2);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    // Keep the SAME boxed grant State/operation/effect/map. Removing a fault
    // flag is not native/model postvalidation or hardware completion proof.
    core::mem::forget(parked);
    core::mem::forget(retention);
}

/// The owner's hard-wired seal over a Bus Master bit that reads clear
/// makes no write and seals it as clear: no later write may set it.
#[test]
fn a_hardwired_seal_of_a_clear_bus_master_seals_it_as_clear() {
    use crate::bus::pci::requester::containment::MasterSeal;
    let address = test_support::ADDRESS;
    let span = PhysicalSpan::new(test_support::physical(address), 4096).unwrap();
    let (source, authority, _counters) = test_support::unmapped(
        address,
        test_support::window(address),
        span,
        CacheAttribute::Uncached,
    );
    let prepared = UnpublishedConfig::prepare(source.into_prepublication());
    let mapping = authority
        .map(
            prepared.configuration_resource().clone(),
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let mut config = prepared
        .attach(mapping)
        .unwrap_or_else(|_| panic!("attach"));
    config.seal_hardwired_bus_master(0x0402).unwrap();
    assert_eq!(config.try_read16(4), Ok(0));
    assert_eq!(
        config.try_write16(4, 0x0006),
        Err(ConfigError::before_effect(ConfigFailure::BusMasterSealed))
    );
    // SAFETY: this isolated model has one source and no other map users.
    let prepared = unsafe { config.park() }.unwrap_or_else(|_| panic!("park"));
    let mapping = authority
        .map(
            prepared.configuration_resource().clone(),
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let config = prepared
        .attach(mapping)
        .unwrap_or_else(|_| panic!("reattach"));
    // SAFETY: the same fixture owns the original resource and completed all
    // old accesses. The source's own checked model transition runs here.
    let config = unsafe { config.promote(test_support::FixtureCustody::finish_promotion) }
        .unwrap_or_else(|_| panic!("promotion"));
    // SAFETY: all synchronous isolated access ended.
    unsafe { test_support::retire_owned(config) }.unwrap();
}

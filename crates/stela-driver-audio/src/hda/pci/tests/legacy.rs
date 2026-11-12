// SPDX-License-Identifier: GPL-2.0-only
//! legacy behavior tests.
use super::*;
use crate::bus::pci::regs;

#[test]
fn legacy_profile_admission() {
    for device in [
        0x2668, 0x269a, 0x27d8, 0x284b, 0x293e, 0x293f, 0x3a3e, 0x3a6e,
    ] {
        assert_eq!(
            identity(INTEL, device, CLASS).unwrap().corb_reset,
            CorbReset::Handshake
        );
    }
    for (vendor, device, class) in [
        (INTEL, 0xa828, CLASS),
        (INTEL, 0xe428, CLASS),
        (INTEL, 0x0a0c, CLASS),
        (INTEL, 0xffff, CLASS),
        (AMD, 0x15e2, CLASS),
        (INTEL, 0x2668, [4, 1, 0]),
    ] {
        assert_eq!(
            identity(vendor, device, class),
            Err(AttachError::UnsupportedController)
        );
    }
}

#[test]
fn d3hot_restores_bars_after_delay() {
    let (mut function, timer, bar) = fixture(3);
    let prepared = prepare_model(&mut function, &timer, bar).unwrap();
    assert_eq!(prepared.bar_range(), 0xfebf_0000..0xfebf_4000);
    assert_eq!(prepared.config().corb_reset, CorbReset::Handshake);
    assert_eq!(prepared.config().dma_address_bits, 64);
    let config = function.config();
    assert_eq!(timer.now_us(), 10_000);
    assert_eq!(config.words[4], 0xfebf_0000);
    assert_eq!(config.words[5], 0x1234_0000);
    assert_eq!(config.words[17], 0x5ac3_a5f0);
    assert_eq!(config.get16(0x54), PM_PME_STATUS);
    assert_eq!(config.get16(regs::STATUS), 0xf910);
    assert_eq!(config.get16(regs::COMMAND) & 0x406, 0x406);
    assert_eq!(config.get16(0x62) & 1, 0);
    assert_eq!(config.get16(0x72) & 0x8000, 0);
    assert_eq!(
        config
            .writes
            .iter()
            .filter(|(_, width, _, _)| *width == 4)
            .count(),
        6
    );
    assert_eq!(
        config
            .writes
            .iter()
            .filter(|(off, _, _, _)| *off == TCSEL)
            .count(),
        1
    );
}

#[test]
fn d2_and_no_soft_reset_preserve_bars() {
    for (state, delay_us) in [(2, 200), (3 | PM_NO_SOFT_RESET, 10_000), (0, 0)] {
        let (mut function, timer, bar) = fixture(state);
        prepare_model(&mut function, &timer, bar).unwrap();
        assert_eq!(timer.now_us(), delay_us);
        assert!(
            !function
                .config()
                .writes
                .iter()
                .any(|(_, width, _, _)| *width == 4)
        );
    }
}

#[test]
fn absent_pm_preserves_wide_bar() {
    let (mut function, timer, _) = fixture(0);
    function.config().words[13] = 0x60; // No PM capability.
    function.config().words[4] = 0x0000_0004;
    function.config().words[5] = 1;
    let bar = Bar::Memory {
        address: 1 << 32,
        size: 0x4000,
        prefetchable: false,
        wide: true,
    };
    assert_eq!(
        prepare_model(&mut function, &timer, bar)
            .unwrap()
            .bar_range(),
        (1 << 32)..(1 << 32) + 0x4000
    );
    assert!(
        !function
            .config()
            .writes
            .iter()
            .any(|(offset, _, _, _)| *offset == 0x54)
    );
}

#[test]
fn unknown_ownership_rejected() {
    for ownership in [Ownership::Unknown, Ownership::Dsp] {
        let (mut function, timer, bar) = fixture(0);
        assert_eq!(
            // SAFETY: function is a local PCI model with no firmware or other
            // hardware owner. Unknown/DSP ownership is rejected before mutation.
            unsafe { prepare(&mut function, bar, &timer, ownership) }.unwrap_err(),
            AttachError::Ownership
        );
        assert!(function.config().writes.is_empty());
    }
}

#[test]
fn malformed_capabilities_rejected() {
    for change in [0, 1, 2, 3, 4, 5] {
        let (mut function, timer, bar) = fixture(0);
        match change {
            0 => function.config().words[13] = 0x51,
            1 => function.config().words[28] |= 0x50 << 8, // Loop.
            2 => function.config().words[28] = 1,          // Second PM.
            3 => function.config().words[20] &= !(7 << 16), // PMv0.
            _ => function.config().words[4] += 0x4000,     // Stale supplied BAR.
        }
        assert!(prepare_model(&mut function, &timer, bar).is_err());
        assert!(function.config().writes.is_empty());
    }
    for bar in [
        Bar::Io {
            port: 0x1000,
            size: 0x1000,
        },
        Bar::Memory {
            address: 0xfebf_0000,
            size: 0x400,
            prefetchable: false,
            wide: false,
        },
        Bar::Memory {
            address: 0xfebf_0000,
            size: 0x4000,
            prefetchable: true,
            wide: false,
        },
        Bar::Memory {
            address: 0xfebf_0000,
            size: 0x4000,
            prefetchable: false,
            wide: true,
        },
    ] {
        let (mut function, timer, _) = fixture(0);
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::InvalidBar
        );
        assert!(function.config().writes.is_empty());
    }
}

#[test]
fn overlapping_controls_rejected() {
    for variant in 0..5 {
        let (mut function, timer, bar) = fixture(0);
        match variant {
            // PM50's PMCSR becomes an aliased MSI54 header/control pair.
            0 => {
                function.config().words[20] = 0x0003_5401;
                function.config().words[21] = 5;
            }
            // Even an unknown header must not occupy the vendor TCSEL byte.
            1 => {
                function.config().words[13] = 0x44;
                function.config().words[17] = 0xfe;
            }
            // 32-bit MSI with masks occupies 0x60..0x74, overlapping MSI-X70.
            2 => function.config().words[24] |= u32::from(MSI_VECTOR_MASK) << 16,
            // 64-bit MSI with masks occupies 0x60..0x78, also overlapping70.
            3 => function.config().words[24] |= u32::from(MSI_VECTOR_MASK | MSI_ADDRESS_64) << 16,
            // A known PM body cannot cover a previously encountered unknown header.
            _ => {
                function.config().words[13] = 0x54;
                function.config().words[21] = 0x50fe;
                function.config().words[20] = 0x0003_0001;
            }
        }
        let refused = prepare_model(&mut function, &timer, bar).unwrap_err();
        assert_eq!(
            refused,
            match variant {
                0 => AttachError::PciCapability(crate::bus::pci::CapabilityError::Overlap {
                    offset: 0x54
                }),
                2 | 3 => AttachError::PciCapability(crate::bus::pci::CapabilityError::Overlap {
                    offset: 0x70
                }),
                4 => AttachError::PciCapability(crate::bus::pci::CapabilityError::Overlap {
                    offset: 0x50
                }),
                _ => AttachError::InvalidCapabilities(CapabilityRefusal::ControlOverlap {
                    control: TCSEL,
                    offset: 0x44,
                    id: 0xfe,
                }),
            }
        );
        assert!(function.config().writes.is_empty());
    }
}

#[test]
fn msi_layout_bounds() {
    for flags in [
        0,
        MSI_ADDRESS_64,
        MSI_VECTOR_MASK,
        MSI_ADDRESS_64 | MSI_VECTOR_MASK,
    ] {
        let (mut function, timer, bar) = fixture(0);
        function.config().words[24] = (u32::from(flags | 1) << 16) | 5; // MSI ends list.
        prepare_model(&mut function, &timer, bar).unwrap();
    }
}

#[test]
fn final_enable_failure_keeps_the_published_prefix_without_cleanup() {
    let (mut function, timer, bar) = fixture(0);
    function.config().fail_after_enable = true;
    assert_eq!(
        prepare_model(&mut function, &timer, bar).unwrap_err(),
        AttachError::ConfigurationRejected
    );
    let config = function.config();
    assert!(
        config
            .writes
            .iter()
            .any(|(off, _, value, _)| *off == regs::COMMAND
                && *value & u32::from(regs::COMMAND_MASTER) != 0)
    );
    let (offset, width, value, _) = config.writes.last().unwrap();
    assert_eq!((*offset, *width), (regs::COMMAND, 2));
    assert_eq!(
        *value & u32::from(regs::COMMAND_MASTER | regs::COMMAND_MEMORY),
        u32::from(regs::COMMAND_MASTER | regs::COMMAND_MEMORY),
    );
    assert_eq!(
        config
            .writes
            .iter()
            .filter(|(off, _, _, _)| *off == regs::COMMAND)
            .count(),
        2
    );
}

#[test]
fn live_identity_preflight() {
    let (mut function, timer, bar) = fixture(0);
    function.config().words[0] = 0x27d8_8086; // Still supported, but a different function.
    assert_eq!(
        prepare_model(&mut function, &timer, bar).unwrap_err(),
        AttachError::IdentityChanged
    );
    assert!(function.config().writes.is_empty());
}

#[test]
fn rejected_decode_stops_preparation() {
    let (mut function, timer, bar) = fixture(3);
    function.config().reject_command = true;
    assert_eq!(
        prepare_model(&mut function, &timer, bar).unwrap_err(),
        AttachError::ConfigurationRejected
    );
    assert!(
        function
            .config()
            .writes
            .iter()
            .all(|(offset, width, _, _)| *offset == regs::COMMAND && *width == 2)
    );
    assert_eq!(timer.now_us(), 0);
}

#[test]
fn rejected_controls_disable_mastering() {
    for failure in 0..3 {
        let (mut function, timer, bar) = fixture(3);
        match failure {
            0 => function.config().reject_power = true,
            1 => function.config().reject_vendor_control = true,
            _ => {
                function
                    .config()
                    .set16(regs::COMMAND, regs::COMMAND_INTX_DISABLE);
                function.config().reject_command = true;
            }
        }
        let result = prepare_model(&mut function, &timer, bar).unwrap_err();
        assert_eq!(
            result,
            if failure == 0 {
                AttachError::PowerTransition
            } else {
                AttachError::ConfigurationRejected
            }
        );
        assert_eq!(
            function.config().get16(regs::COMMAND) & (regs::COMMAND_MASTER | regs::COMMAND_MEMORY),
            0
        );
    }
}

#[test]
fn ati_amd_snoop_preserves_neighbor_bits() {
    for (vendor, device, bits) in [
        (ATI, 0x437b, 32),
        (ATI, 0x4383, 32),
        (AMD, 0x780d, 40),
        (AMD, 0x157a, 40),
    ] {
        let (mut function, timer, bar) = fixture(3);
        set_identity(&mut function, vendor, device);
        function.config().words[16] = 0x5aa5_1234; //0x42snoop=a5, adjacent43=5a.
        let prepared = prepare_model(&mut function, &timer, bar).unwrap();
        assert_eq!(prepared.identity().dma_address_bits, bits);
        assert_eq!(prepared.config().dma_address_bits, bits);
        assert_eq!(prepared.config().corb_reset, CorbReset::Handshake);
        let config = function.config();
        assert_eq!(config.words[16], 0x5aa2_1234);
        assert_eq!(config.words[17], 0x5ac3_a5f7); // IntelTCSEL untouched.
        assert!(
            !config
                .writes
                .iter()
                .any(|(offset, _, _, _)| *offset == TCSEL)
        );
        assert!(
            config
                .writes
                .iter()
                .any(|(offset, width, _, time)| *offset == ATI_SNOOP_CONTROL
                    && *width == 1
                    && *time >= 10_000)
        );
    }
}

#[test]
fn nvidia_coherence_and_dma_policy() {
    let (mut function, timer, bar) = fixture(3);
    set_identity(&mut function, NVIDIA, 0x22e9);
    // 4ch output and 4dh input coherence clear, 4eh low nibble clear, 4fh
    // a neighbor that must survive.
    function.config().words[19] = 0x5af0_fefe;
    let prepared = prepare_model(&mut function, &timer, bar).unwrap();
    assert_eq!(prepared.identity().dma_address_bits, 40);
    assert_eq!(prepared.config().corb_reset, CorbReset::SelfClearing);
    let config = function.config();
    assert_eq!(config.words[19], 0x5aff_ffff);
    assert!(
        !config
            .writes
            .iter()
            .any(|(offset, _, _, _)| matches!(*offset, TCSEL | ATI_SNOOP_CONTROL))
    );
}

/// An RTX 50's audio function has PM at 0x40 and a 64-bit MSI at 0x48, whose
/// address occupies the 0x4c..0x4e coherence bytes of the chipset functions.
/// It is started, and nothing is written into the MSI capability.
#[test]
fn nvidia_controls_inside_an_msi_body_are_left_out() {
    let (mut function, timer, bar) = fixture(3);
    set_identity(&mut function, NVIDIA, 0x22e9);
    let config = function.config();
    config.words[13] = 0x40;
    config.words[16] = 0x0003_4801;
    config.words[17] = 3;
    config.words[18] = (u32::from(MSI_ADDRESS_64) << 16) | 0x0005;
    config.words[20] = 0;
    config.words[24] = 0;
    config.words[28] = 0;
    prepare_model(&mut function, &timer, bar).unwrap();
    assert!(
        !function
            .config()
            .writes
            .iter()
            .any(|(offset, bytes, _, _)| *bytes == 1 || (0x4c..0x56).contains(offset))
    );
}

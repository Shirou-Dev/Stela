//! UEFI PCI_IO resource observations. Decoding yields DATA, never native
//! mapping, configuration, reset or controller permission.
//! UEFI2.11 tables14.10/14.11 use this QWORD layout and HOST-to-PCI offset.
//! EDK2 reference: tianocore/edk2@4dfdca63a93497203f197ec98ba20e2327e4afe4,
//! MdeModulePkg/Bus/Pci/PciBusDxe/PciIo.c::PciIoGetBarAttributes. Range
//! observation is checked Start+Length; raw maximum is held separately.
use core::ops::Range;
pub const QWORD_BYTES: usize = 46;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    Length,
    Tag,
    ResourceType,
    Flags,
    Granularity,
    Range,
    Translation,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BarRegion {
    pub resource_type: u8,
    pub general_flags: u8,
    pub specific_flags: u8,
    pub granularity: u64,
    /// Raw maximum observation. UEFI table14.10 calls this the ending
    /// address; EDK2 PciIoGetBarAttributes exports BAR.Alignment here instead.
    /// Preserve it without turning either interpretation into native permission.
    pub observed_maximum: u64,
    pub host: Range<u64>,
    pub translation: u64,
    pub pci: Range<u64>,
}

/// The firmware framebuffer's observed Type 0 PCI BAR. The copied words
/// allow a later native observer to refuse a changed function or BAR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferBar {
    index: u8,
    identity: u32,
    class_revision: u32,
    layout: u32,
    low: u32,
    high: Option<u32>,
}

impl FramebufferBar {
    pub fn observe<'a>(
        header: &[u8; 64],
        regions: impl IntoIterator<Item = (u8, &'a BarRegion)>,
        screen: Range<u64>,
    ) -> Option<Self> {
        let word = |offset| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
        let identity = word(0);
        if matches!(identity as u16, 0 | 1 | u16::MAX)
            || header[0x0e] & 0x7f != 0
            || header[0x0b] != 3
            || screen.start >= screen.end
        {
            return None;
        }
        let mut lows = [None; 6];
        let mut index = 0;
        while index < lows.len() {
            let low = word(0x10 + index * 4);
            let width = low & 7;
            let high = (width == 4 && index + 1 < lows.len()).then(|| word(0x14 + index * 4));
            if width == 0 || high.is_some() {
                lows[index] = Some((low, high));
            }
            index += if high.is_some() { 2 } else { 1 };
        }
        let mut found = None;
        for (index, region) in regions {
            let Some((low, high)) = lows.get(usize::from(index)).copied().flatten() else {
                continue;
            };
            let base = u64::from(low & !15) | u64::from(high.unwrap_or_default()) << 32;
            if region.resource_type == 0
                && region.host == region.pci
                && region.granularity == if high.is_some() { 64 } else { 32 }
                && region.host.start == base
                && base != 0
                && base <= screen.start
                && screen.end <= region.host.end
            {
                if found.is_some() {
                    return None;
                }
                found = Some(Self {
                    index,
                    identity,
                    class_revision: word(8),
                    layout: word(0x0c),
                    low,
                    high,
                });
            }
        }
        found
    }

    pub fn index(self) -> u8 {
        self.index
    }

    /// The original identity, class/revision, and BAR words to compare.
    pub fn words(self) -> impl Iterator<Item = (u16, u32)> {
        let offset = 0x10 + u16::from(self.index) * 4;
        [
            (0, self.identity),
            (8, self.class_revision),
            (0x0c, self.layout),
            (offset, self.low),
        ]
        .into_iter()
        .chain(self.high.map(|word| (offset + 4, word)))
    }
}

/// UEFI device path node type and subtype of a PCI node (Hardware, PCI;
/// UEFI 2.11 section 10.3.2.1).
pub const PCI_NODE: (u8, u8) = (1, 1);

/// Whether a device path of `nodes` (type, subtype; end nodes excluded)
/// names a PCI function: firmware's PCI_IO handle for its longest prefix
/// took every node through the last PCI node, leaving `unconsumed` nodes
/// below that function, as for a GOP on a child output handle. A leftover
/// PCI node means the handle found is only a bridge above the function.
pub fn names_pci_function(nodes: impl IntoIterator<Item = (u8, u8)>, unconsumed: usize) -> bool {
    let (mut count, mut through) = (0, None);
    for node in nodes {
        count += 1;
        if node == PCI_NODE {
            through = Some(count);
        }
    }
    through.is_some_and(|through| count - through == unconsumed)
}

/// The only item, or `None` when there are none or several: two display
/// functions whose BARs both hold the screen leave its owner unknown.
pub fn sole<T>(items: impl IntoIterator<Item = T>) -> Option<T> {
    let mut items = items.into_iter();
    let first = items.next()?;
    items.next().is_none().then_some(first)
}

fn qword(bytes: &[u8; QWORD_BYTES], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}
pub fn decode_qword(bytes: &[u8; QWORD_BYTES]) -> Result<BarRegion, DescriptorError> {
    if bytes[0] != 0x8a {
        return Err(DescriptorError::Tag);
    }
    if u16::from_le_bytes([bytes[1], bytes[2]]) != 43 {
        return Err(DescriptorError::Length);
    }
    if bytes[3] > 2 {
        return Err(DescriptorError::ResourceType);
    }
    if bytes[4] & !15 != 0 {
        return Err(DescriptorError::Flags);
    }
    let granularity = qword(bytes, 6);
    if bytes[3] == 0 && !matches!(granularity, 32 | 64) {
        return Err(DescriptorError::Granularity);
    }
    let start = qword(bytes, 14);
    let maximum = qword(bytes, 22);
    let translation = qword(bytes, 30);
    let length = qword(bytes, 38);
    let end = start
        .checked_add(length)
        .filter(|end| *end > start)
        .ok_or(DescriptorError::Range)?;
    let pci_start = start
        .checked_add(translation)
        .ok_or(DescriptorError::Translation)?;
    let pci_end = pci_start
        .checked_add(length)
        .ok_or(DescriptorError::Translation)?;
    if bytes[3] == 0 && granularity == 32 && pci_end > 1u64 << 32 {
        return Err(DescriptorError::Range);
    }
    Ok(BarRegion {
        resource_type: bytes[3],
        general_flags: bytes[4],
        specific_flags: bytes[5],
        granularity,
        observed_maximum: maximum,
        host: start..end,
        translation,
        pci: pci_start..pci_end,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor(start: u64, length: u64, translation: u64) -> [u8; QWORD_BYTES] {
        let mut value = [0; QWORD_BYTES];
        value[..3].copy_from_slice(&[0x8a, 43, 0]);
        value[6..14].copy_from_slice(&64u64.to_le_bytes());
        value[14..22].copy_from_slice(&start.to_le_bytes());
        value[22..30].copy_from_slice(&(start + length - 1).to_le_bytes());
        value[30..38].copy_from_slice(&translation.to_le_bytes());
        value[38..46].copy_from_slice(&length.to_le_bytes());
        value
    }

    #[test]
    fn framebuffer_requires_one_matching_identity_mapped_display_bar() {
        let base = 0x1_8000_0000;
        let mut header = [0u8; 64];
        header[..4].copy_from_slice(&0x1111_1234u32.to_le_bytes());
        header[0x0b] = 3;
        header[0x18..0x1c].copy_from_slice(&0x8000_0004u32.to_le_bytes());
        header[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes());
        let region = decode_qword(&descriptor(base, 0x2000, 0)).unwrap();
        let screen = base + 0x100..base + 0x1100;
        let bar = FramebufferBar::observe(&header, [(2, &region)], screen.clone()).unwrap();
        assert_eq!(bar.index(), 2);
        assert_eq!(
            bar.words().collect::<alloc::vec::Vec<_>>(),
            [
                (0, 0x1111_1234),
                (8, 0x0300_0000),
                (0x0c, 0),
                (0x18, 0x8000_0004),
                (0x1c, 1)
            ]
        );
        assert!(FramebufferBar::observe(&header, [(3, &region)], screen.clone()).is_none());
        assert!(
            FramebufferBar::observe(&header, [(2, &region), (2, &region)], screen.clone())
                .is_none()
        );
        let translated = decode_qword(&descriptor(base, 0x2000, 0x1000)).unwrap();
        assert!(FramebufferBar::observe(&header, [(2, &translated)], screen.clone()).is_none());
        assert!(FramebufferBar::observe(&header, [(2, &region)], base..base + 0x2001).is_none());
        header[0x0e] = 1;
        assert!(FramebufferBar::observe(&header, [(2, &region)], screen.clone()).is_none());
        header[0x0e] = 0;
        header[0x0b] = 2;
        assert!(FramebufferBar::observe(&header, [(2, &region)], screen).is_none());
    }

    #[test]
    fn device_path_names_the_function_of_its_last_pci_node() {
        let root = (2, 1);
        let output = (2, 3);
        let controller = (1, 5);
        // The GOP on the function itself, or on a child output below it.
        assert!(names_pci_function([root, PCI_NODE], 0));
        assert!(names_pci_function([root, PCI_NODE, PCI_NODE, output], 1));
        assert!(names_pci_function(
            [root, PCI_NODE, controller, (4, 7), output],
            3
        ));
        // Firmware's handle is a bridge above the function, or took nodes
        // past it.
        assert!(!names_pci_function([root, PCI_NODE, PCI_NODE, output], 2));
        assert!(!names_pci_function([root, PCI_NODE, output], 0));
        // No PCI node at all, as on a console splitter's virtual handle.
        assert!(!names_pci_function([root, output], 1));
        assert!(!names_pci_function([], 0));
    }

    #[test]
    fn only_a_single_matching_function_owns_the_screen() {
        assert_eq!(sole([7]), Some(7));
        assert_eq!(sole::<u8>([]), None);
        assert_eq!(sole([7, 8]), None);
    }
    #[test]
    fn host_to_pci_translation_and_full_width_are_preserved() {
        let value = descriptor(1u64 << 32, 4096, 1u64 << 32);
        let decoded = decode_qword(&value).unwrap();
        assert_eq!(decoded.host, (1u64 << 32)..(1u64 << 32) + 4096);
        assert_eq!(decoded.pci, (2u64 << 32)..(2u64 << 32) + 4096);
        assert_eq!(decoded.translation, 1u64 << 32);
    }
    #[test]
    fn incompatible_width_overflow_and_incomplete_ranges_refuse() {
        let original = descriptor(1u64 << 32, 4096, 0);
        let mut value = original;
        value[6..14].copy_from_slice(&32u64.to_le_bytes());
        assert_eq!(decode_qword(&value), Err(DescriptorError::Range));
        value = original;
        value[30..38].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode_qword(&value), Err(DescriptorError::Translation));
        value = original;
        value[38..46].fill(0);
        assert_eq!(decode_qword(&value), Err(DescriptorError::Range));
        value = original;
        value[14..22].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode_qword(&value), Err(DescriptorError::Range));
    }
    #[test]
    fn raw_maximum_is_preserved_for_both_documented_endpoint_and_edk2_alignment() {
        let mut value = descriptor(1u64 << 32, 4096, 0);
        let ending = decode_qword(&value).unwrap();
        assert_eq!(ending.observed_maximum, ending.host.end - 1);
        value[22..30].copy_from_slice(&4095u64.to_le_bytes());
        let alignment = decode_qword(&value).unwrap();
        assert_eq!(alignment.observed_maximum, 4095);
        assert_eq!(alignment.host, ending.host);
        assert_eq!(alignment.pci, ending.pci);
    }

    #[test]
    fn descriptor_kind_lengths_and_memory_granularity_are_checked() {
        let original = descriptor(4096, 4096, 0);
        for (offset, byte, error) in [
            (0, 0x87, DescriptorError::Tag),
            (1, 42, DescriptorError::Length),
            (3, 3, DescriptorError::ResourceType),
            (4, 0x80, DescriptorError::Flags),
            (6, 0, DescriptorError::Granularity),
        ] {
            let mut value = original;
            value[offset] = byte;
            assert_eq!(decode_qword(&value), Err(error));
        }
        let mut io = original;
        io[3] = 1;
        io[6] = 0;
        assert_eq!(decode_qword(&io).unwrap().granularity, 0);
    }
}

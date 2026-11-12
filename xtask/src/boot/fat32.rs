//! A FAT32 image of a directory tree, without a partition table, written
//! directly so every host can make the boot volume of a large bundle.
//!
//! The volume's layout, boot sector and FSInfo are the shared encoder's
//! (`stela_runtime::pc::fat32::format`), as `stela` writes them. The
//! root directory takes the first clusters; every directory and file then
//! gets one contiguous chain, in tree order. Names that are not upper-case
//! 8.3 carry long-name entries.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use stela_runtime::pc::fat32::format::{
    ATTRIBUTE_VOLUME_ID as ATTR_VOLUME, BACKUP_BOOT_SECTOR, END_OF_CHAIN, FATS, Geometry,
    MEDIA_ENTRY, ROOT_CLUSTER, volume_label,
};

const SECTOR: u64 = 512;
const ENTRY: usize = 32;
/// The boot sector's volume serial number: fixed, so images repeat.
const SERIAL: u32 = 0x5354_454c;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = 0x0f;
/// 2026-01-01 00:00, in FAT's date encoding.
const DATE: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1;

enum Node {
    Directory {
        name: String,
        children: Vec<Node>,
        cluster: u32,
    },
    File {
        name: String,
        path: PathBuf,
        bytes: u64,
        cluster: u32,
    },
}

impl Node {
    fn name(&self) -> &str {
        match self {
            Node::Directory { name, .. } | Node::File { name, .. } => name,
        }
    }

    fn cluster(&self) -> u32 {
        match self {
            Node::Directory { cluster, .. } | Node::File { cluster, .. } => *cluster,
        }
    }
}

fn read_tree(path: &Path, name: String) -> Result<Node> {
    let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut children = Vec::new();
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| anyhow::anyhow!("{name:?} is not UTF-8"))?;
        children.push(if entry.file_type()?.is_dir() {
            read_tree(&entry.path(), name)?
        } else {
            Node::File {
                name,
                bytes: entry.metadata()?.len(),
                path: entry.path(),
                cluster: 0,
            }
        });
    }
    Ok(Node::Directory {
        name,
        children,
        cluster: 0,
    })
}

/// The directory entries a child takes: its long-name entries and its
/// short entry.
fn entries_for(name: &str) -> usize {
    if short_name(name).is_some() {
        1
    } else {
        name.encode_utf16().count().div_ceil(13) + 1
    }
}

fn directory_bytes(children: &[Node], root: bool) -> u64 {
    // `.` and `..`, or the root's volume label, then the end marker.
    let fixed = if root { 1 } else { 2 };
    let entries = fixed
        + children
            .iter()
            .map(|c| entries_for(c.name()))
            .sum::<usize>()
        + 1;
    (entries * ENTRY) as u64
}

/// Assign each node its first cluster, from `next`, in tree order.
fn allocate(node: &mut Node, cluster_bytes: u64, next: &mut u32, root: bool) {
    let span = |bytes: u64| bytes.div_ceil(cluster_bytes).max(1) as u32;
    match node {
        Node::Directory {
            children, cluster, ..
        } => {
            *cluster = *next;
            *next += span(directory_bytes(children, root));
            for child in children {
                allocate(child, cluster_bytes, next, false);
            }
        }
        Node::File { bytes, cluster, .. } => {
            if *bytes == 0 {
                return;
            }
            *cluster = *next;
            *next += span(*bytes);
        }
    }
}

/// The name as an 11-byte short name when it already is an upper-case 8.3
/// name, so it needs no long-name entries.
fn short_name(name: &str) -> Option<[u8; 11]> {
    let (base, extension) = name.split_once('.').unwrap_or((name, ""));
    let valid = |part: &str, max: usize| {
        part.len() <= max
            && part.bytes().all(|b| {
                b.is_ascii_uppercase() || b.is_ascii_digit() || b"_-~!#$%&'(){}^@`".contains(&b)
            })
    };
    if base.is_empty() || !valid(base, 8) || !valid(extension, 3) {
        return None;
    }
    let mut short = [b' '; 11];
    short[..base.len()].copy_from_slice(base.as_bytes());
    short[8..8 + extension.len()].copy_from_slice(extension.as_bytes());
    Some(short)
}

/// A unique `BASE~N.EXT` alias for a long name.
fn alias(name: &str, index: usize) -> [u8; 11] {
    let clean = |part: &str, max: usize| {
        part.bytes()
            .filter(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
            .map(|b| b.to_ascii_uppercase())
            .take(max)
            .collect::<Vec<_>>()
    };
    let (base, extension) = name.rsplit_once('.').unwrap_or((name, ""));
    let suffix = format!("~{}", index + 1).into_bytes();
    let mut stem = clean(base, 8 - suffix.len());
    stem.extend(suffix);
    let mut short = [b' '; 11];
    short[..stem.len()].copy_from_slice(&stem);
    let extension = clean(extension, 3);
    short[8..8 + extension.len()].copy_from_slice(&extension);
    short
}

fn checksum(short: &[u8; 11]) -> u8 {
    short
        .iter()
        .fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte))
}

fn short_entry(short: &[u8; 11], attributes: u8, cluster: u32, bytes: u32) -> [u8; ENTRY] {
    let mut entry = [0u8; ENTRY];
    entry[..11].copy_from_slice(short);
    entry[11] = attributes;
    entry[16..18].copy_from_slice(&DATE.to_le_bytes());
    entry[18..20].copy_from_slice(&DATE.to_le_bytes());
    entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    entry[24..26].copy_from_slice(&DATE.to_le_bytes());
    entry[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&bytes.to_le_bytes());
    entry
}

/// The long-name entries for `name`, last part first, as they are stored.
fn long_entries(name: &str, short: &[u8; 11]) -> Vec<[u8; ENTRY]> {
    let mut units: Vec<u16> = name.encode_utf16().collect();
    let parts = units.len().div_ceil(13);
    if !units.len().is_multiple_of(13) {
        units.push(0);
    }
    units.resize(parts * 13, 0xffff);
    let sum = checksum(short);
    (0..parts)
        .rev()
        .map(|part| {
            let mut entry = [0u8; ENTRY];
            entry[0] = (part + 1) as u8 | if part + 1 == parts { 0x40 } else { 0 };
            entry[11] = ATTR_LONG_NAME;
            entry[13] = sum;
            let chunk = &units[part * 13..][..13];
            for (index, unit) in chunk.iter().enumerate() {
                let at = match index {
                    0..5 => 1 + 2 * index,
                    5..11 => 14 + 2 * (index - 5),
                    _ => 28 + 2 * (index - 11),
                };
                entry[at..at + 2].copy_from_slice(&unit.to_le_bytes());
            }
            entry
        })
        .collect()
}

/// Write `image`, `bytes` long, a FAT32 volume labelled `label` holding
/// `volume`'s tree.
pub fn write(volume: &Path, image: &Path, bytes: u64, label: &str) -> Result<()> {
    let geometry = Geometry::new(bytes / SECTOR, SECTOR as u32)?;
    let label = volume_label(label)?;
    let mut root = read_tree(volume, String::new())?;
    let mut next = ROOT_CLUSTER;
    allocate(&mut root, geometry.cluster_bytes(), &mut next, true);
    let used = u64::from(next) - 2;
    ensure!(
        used <= geometry.clusters,
        "{} needs {used} clusters; the volume has {}",
        volume.display(),
        geometry.clusters
    );

    let mut file = File::create(image).with_context(|| format!("create {}", image.display()))?;
    file.set_len(geometry.sectors * SECTOR)?;

    let mut fat = vec![0u32; geometry.clusters as usize + 2];
    fat[0] = MEDIA_ENTRY;
    fat[1] = END_OF_CHAIN;
    write_node(&mut file, &geometry, &mut fat, &root, 0, true, &label)?;
    let fat_bytes: Vec<u8> = fat.iter().flat_map(|entry| entry.to_le_bytes()).collect();
    for copy in 0..FATS {
        file.seek(SeekFrom::Start(geometry.fat_sector(copy) * SECTOR))?;
        file.write_all(&fat_bytes)?;
    }

    let boot = geometry.boot_sector(0, &label, SERIAL)?;
    let info = geometry.fsinfo(u32::try_from(geometry.clusters - used)?, next);
    for base in [0, BACKUP_BOOT_SECTOR] {
        file.seek(SeekFrom::Start(base * SECTOR))?;
        file.write_all(&boot)?;
        file.write_all(&info)?;
    }
    file.sync_all()?;
    Ok(())
}

/// Chain `count` clusters from `first` in the FAT.
fn chain(fat: &mut [u32], first: u32, count: u64) {
    for index in 0..count as u32 {
        let cluster = first + index;
        fat[cluster as usize] = if u64::from(index) + 1 == count {
            END_OF_CHAIN
        } else {
            cluster + 1
        };
    }
}

fn write_node(
    file: &mut File,
    geometry: &Geometry,
    fat: &mut [u32],
    node: &Node,
    parent: u32,
    root: bool,
    label: &[u8; 11],
) -> Result<()> {
    let cluster_bytes = geometry.cluster_bytes();
    match node {
        Node::File {
            path,
            bytes,
            cluster,
            ..
        } => {
            if *bytes == 0 {
                return Ok(());
            }
            chain(fat, *cluster, bytes.div_ceil(cluster_bytes));
            file.seek(SeekFrom::Start(geometry.cluster_offset(*cluster)))?;
            let copied = std::io::copy(&mut File::open(path)?, file)?;
            ensure!(copied == *bytes, "{} changed while copied", path.display());
        }
        Node::Directory {
            children, cluster, ..
        } => {
            let length = directory_bytes(children, root);
            chain(fat, *cluster, length.div_ceil(cluster_bytes).max(1));
            let mut entries = Vec::new();
            if root {
                entries.push(short_entry(label, ATTR_VOLUME, 0, 0));
            } else {
                entries.push(short_entry(b".          ", ATTR_DIRECTORY, *cluster, 0));
                entries.push(short_entry(b"..         ", ATTR_DIRECTORY, parent, 0));
            }
            let mut aliases = 0;
            for child in children {
                let (attributes, size) = match child {
                    Node::Directory { .. } => (ATTR_DIRECTORY, 0),
                    Node::File { bytes, .. } => (
                        ATTR_ARCHIVE,
                        u32::try_from(*bytes).context("a FAT32 file holds under 4 GiB")?,
                    ),
                };
                let short = match short_name(child.name()) {
                    Some(short) => short,
                    None => {
                        let short = alias(child.name(), aliases);
                        aliases += 1;
                        entries.extend(long_entries(child.name(), &short));
                        short
                    }
                };
                entries.push(short_entry(&short, attributes, child.cluster(), size));
            }
            file.seek(SeekFrom::Start(geometry.cluster_offset(*cluster)))?;
            file.write_all(&entries.concat())?;
            let own = if root { 0 } else { *cluster };
            for child in children {
                write_node(file, geometry, fat, child, own, false, label)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_short_only_when_already_upper_case_8_3() {
        assert_eq!(short_name("BOOTX64.EFI"), Some(*b"BOOTX64 EFI"));
        assert_eq!(short_name("EFI"), Some(*b"EFI        "));
        assert_eq!(short_name("kernelcache.img"), None);
        assert_eq!(short_name("USB-C_HPM,34-P2_P-AP.bin"), None);
        assert_eq!(&alias("USB-C_HPM,34-P2_P-AP.bin", 0), b"USB-C_~1BIN");
        assert_eq!(entries_for("kernelcache.img"), 3);
    }

    #[test]
    fn long_names_split_into_terminated_padded_parts() {
        let short = alias("kernelcache.img", 0);
        let entries = long_entries("kernelcache.img", &short);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0][0], 0x42);
        assert_eq!(entries[1][0], 0x01);
        // "kernelcache.i" fills the first part; "mg", then a terminator
        // and padding, the second.
        assert_eq!(&entries[0][1..7], &[b'm', 0, b'g', 0, 0, 0]);
        assert_eq!(&entries[0][7..9], &[0xff, 0xff]);
        assert!(entries.iter().all(|e| e[13] == checksum(&short)));
    }

    #[test]
    fn fat32_chains_files_after_directories() {
        let work = std::env::temp_dir().join(format!("stela-fat32-{}", std::process::id()));
        let tree = work.join("tree");
        fs::create_dir_all(tree.join("EFI/BOOT")).unwrap();
        fs::create_dir_all(tree.join("EFI/stela/bundle")).unwrap();
        let kernel: Vec<u8> = (0..300_000u32).map(|i| (i * 31 % 251) as u8).collect();
        fs::write(tree.join("EFI/stela/bundle/kernelcache.img"), &kernel).unwrap();
        fs::write(tree.join("EFI/BOOT/BOOTX64.EFI"), b"boot").unwrap();
        fs::write(
            tree.join("EFI/stela/bundle/USB-C_HPM,34-P2_P-AP.bin"),
            b"hpm",
        )
        .unwrap();
        fs::write(tree.join("EFI/stela/empty.cfg"), b"").unwrap();
        let image = work.join("volume.img");
        write(&tree, &image, 520 << 20, "STELA").unwrap();
        let bytes = fs::read(&image).unwrap();
        assert_eq!(&bytes[510..512], &[0x55, 0xaa]);
        assert_eq!(&bytes[6 * 512..6 * 512 + 90], &bytes[..90]);
        let geometry = Geometry::new((520 << 20) / SECTOR, SECTOR as u32).unwrap();
        // The root opens with the label, then EFI's short entry.
        let root = geometry.cluster_offset(2) as usize;
        assert_eq!(&bytes[root..root + 11], b"STELA      ");
        assert_eq!(&bytes[root + 32..root + 43], b"EFI        ");
        // The kernel's bytes lie in one run of clusters.
        let found = bytes
            .windows(64)
            .position(|window| window == &kernel[..64])
            .unwrap();
        assert_eq!(&bytes[found..found + kernel.len()], &kernel[..]);
        fs::remove_dir_all(work).unwrap();
    }

    #[test]
    fn geometry_keeps_fat32_cluster_counts() {
        for bytes in [520u64 << 20, 2300 << 20, 30 << 30] {
            let geometry = Geometry::new(bytes / SECTOR, SECTOR as u32).unwrap();
            assert!(geometry.clusters >= 65_525, "{bytes}");
            assert!(geometry.cluster_sectors <= 64);
            assert!((geometry.clusters + 2) * 4 <= geometry.fat_sectors * SECTOR);
        }
    }
}

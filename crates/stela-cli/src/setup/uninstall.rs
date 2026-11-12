//! `stela uninstall`: remove everything the setup record names.
use super::{
    CHOICES_PATH, Environment, RECORD, bundle, locate_esp,
    record::{Record, read_any_record},
    translations, wifi,
};
use crate::efi;
use anyhow::{Context, Result, ensure};
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};
use stela_loader::host_firmware;

pub(super) fn uninstall(
    environment: &Environment<'_>,
    usb: &Path,
    dry_run: bool,
) -> Result<String> {
    let esp = locate_esp(environment.host, usb)?;
    let record: Option<Record> = esp
        .join(RECORD)
        .is_file()
        .then(|| read_any_record(environment.host, &esp, usb))
        .transpose()?;
    let mut text = String::new();
    let mut removals: Vec<PathBuf> = Vec::new();
    if let Some(record) = &record {
        let directories: Vec<PathBuf> = record
            .payload_directory
            .iter()
            .cloned()
            .chain([record.bundle_directory.clone()])
            .chain(record.build_directories())
            .collect();
        for directory in directories {
            ensure!(
                directory.starts_with(&record.volume)
                    && directory.parent().is_some_and(|p| {
                        p.ends_with(bundle::BOOT_DIRECTORY) || p.ends_with("EFI/stela/images")
                    }),
                "the setup record names an unexpected directory {}",
                directory.display()
            );
            if directory.exists() && !removals.contains(&directory) {
                removals.push(directory);
            }
        }
        for medium in &record.media {
            let directory = medium.removable_directory()?;
            if directory.exists() {
                removals.push(directory);
            }
        }
        if let Some(store) = &record.translations {
            let directory = translations::checked_directory(store)?;
            if directory.is_dir() {
                removals.push(directory);
            }
        }
        // The firmware bundle setup, repair and update keep on the volume.
        let firmware = record.volume.join(host_firmware::bundle::DIRECTORY);
        if firmware.is_dir() {
            removals.push(firmware);
        }
    } else {
        writeln!(
            text,
            "No setup record on {}; removing only Stela's boot loader and files.",
            esp.display()
        )?;
    }
    writeln!(text, "Stela uninstall from {}:", esp.display())?;
    for directory in &removals {
        writeln!(text, "  remove   {}", directory.display())?;
    }
    for file in efi::INSTALLED
        .iter()
        .chain([&CHOICES_PATH, &wifi::KEY_PATH])
    {
        if esp.join(file).is_file() {
            writeln!(text, "  remove   {}", esp.join(file).display())?;
        }
    }
    for install in record.iter().flat_map(|r| r.installs.iter()) {
        writeln!(
            text,
            "  keep     install \"{}\": macOS, its NVRAM and SEP state stay on {}{}; delete them \
             with a disk utility when no longer wanted",
            install.name,
            install.disk.partitions(),
            install
                .ecid
                .map(|ecid| format!(" (ECID {ecid}, which a new setup reuses with --ecid)"))
                .unwrap_or_default()
        )?;
    }
    if dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    for directory in &removals {
        fs::remove_dir_all(directory)
            .with_context(|| format!("cannot remove {}", directory.display()))?;
    }
    for file in [CHOICES_PATH, wifi::KEY_PATH] {
        if esp.join(file).is_file() {
            fs::remove_file(esp.join(file))?;
        }
    }
    if let Some(record) = &record {
        for directory in &record.created_directories {
            if fs::read_dir(directory).is_ok_and(|mut entries| entries.next().is_none()) {
                fs::remove_dir(directory)?;
            }
        }
        fs::remove_file(esp.join(RECORD))?;
    }
    efi::uninstall(&esp, record.is_some())?;
    text.push_str("Done.\n");
    Ok(text)
}

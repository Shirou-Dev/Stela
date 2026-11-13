//! A run's storage: the boot volume it writes and every disk QEMU attaches.
use super::{
    PayloadMode, Run, SYNTHETIC_SLICE_BYTES, UsbDiskModel, VVFAT_BYTES, copy_bundle,
    directory_bytes, disks, fat_image, option_path, preboot::Preboot, usb_serial,
};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as Process,
};
use stela_cli::efi;

/// Where a run keeps what it boots and what it records.
pub(super) struct Paths {
    pub(super) output: PathBuf,
    /// The boot volume, as a directory.
    pub(super) volume: PathBuf,
    /// `\EFI\stela\source.bin`: the system-mode guest image, when the run
    /// has one.
    pub(super) source: PathBuf,
    /// The guest's UART log.
    pub(super) serial: PathBuf,
}

impl Paths {
    pub(super) fn new(output: PathBuf) -> Self {
        let volume = output.join("volume");
        Self {
            source: volume.join("EFI/stela/source.bin"),
            serial: output.join("serial.txt"),
            volume,
            output,
        }
    }
}

/// `--storage-check`'s disks, made in the output directory, each named in
/// `options`.
pub(super) fn check_disks(
    arguments: &Run,
    paths: &Paths,
    options: &mut String,
) -> Result<Vec<disks::Disk>> {
    let disks = match arguments.storage_check {
        true => {
            fs::create_dir_all(&paths.output)?;
            disks::create(&paths.output)?
        }
        false => Vec::new(),
    };
    options.extend(disks.iter().map(disks::Disk::option));
    Ok(disks)
}

/// Check the USB disks, and name each `--usb-storage-disk` in `options`.
pub(super) fn usb_options(arguments: &Run, options: &mut String) -> Result<()> {
    for path in &arguments.usb_disk {
        ensure!(path.is_file(), "USB disk is not a file: {}", path.display());
    }
    ensure!(
        arguments.usb_storage_disk.len() <= 6,
        "the guest's native hub carries at most six USB disks"
    );
    for (index, path) in arguments.usb_storage_disk.iter().enumerate() {
        ensure!(
            path.is_file(),
            "USB storage disk is not a file: {}",
            path.display()
        );
        options.push_str(&format!(" --usb-storage {}", usb_serial(index)));
    }
    Ok(())
}

/// `--payload`: a synthetic IPSW split onto the volume, and `options` with
/// the install mode that reads it.
pub(super) fn payload(arguments: &Run, paths: &Paths, options: String) -> Result<String> {
    let Some(mode) = arguments.payload else {
        return Ok(options);
    };
    let ipsw = paths.output.join("synthetic.ipsw");
    fs::create_dir_all(&paths.output)?;
    efi::synthetic_ipsw(&ipsw)?;
    efi::write_payload(&efi::PayloadOptions {
        image: &ipsw,
        model: efi::SYNTHETIC_MODEL,
        root: &paths.volume,
        layout: match mode {
            PayloadMode::VerifyArchive => efi::PayloadLayout::Archive,
            PayloadMode::Verify => efi::PayloadLayout::Split,
        },
        slice_bytes: SYNTHETIC_SLICE_BYTES,
        fetch_keys: false,
    })?;
    Ok(format!(
        "{options} --install-build {} --install-mode verify",
        efi::SYNTHETIC_BUILD
    ))
}

/// EFI loader, guest source bytes and boot options written to a volume.
pub(super) struct VolumeContents<'a> {
    pub(super) image: &'a Path,
    pub(super) bytes: Vec<u8>,
    pub(super) options: &'a str,
}

/// Write the boot volume: the application, `source.bin`, `stela.cfg` and
/// what the run adds, or only the output directory for a `--usb-image`.
/// Returns the FAT32 image of a volume too large for QEMU's directory one.
pub(super) fn write_volume(
    arguments: &Run,
    paths: &Paths,
    contents: VolumeContents<'_>,
) -> Result<Option<PathBuf>> {
    let VolumeContents {
        image,
        bytes,
        options,
    } = contents;
    let volume = &paths.volume;
    if arguments.usb_image.is_some() {
        fs::create_dir_all(&paths.output)?;
    } else {
        fs::create_dir_all(volume.join("EFI/BOOT"))?;
        fs::create_dir_all(volume.join("EFI/stela"))?;
        fs::copy(image, volume.join("EFI/BOOT/BOOTX64.EFI"))?;
        if !bytes.is_empty() {
            fs::write(&paths.source, bytes)?;
        }
        fs::write(volume.join("EFI/stela/stela.cfg"), options)?;
        if let Some(directory) = &arguments.host_firmware {
            let package =
                stela_loader::host_firmware::Package::read_for_mount(directory, &fs::read(image)?)?;
            package.publish(&volume.join(stela_loader::host_firmware::DIRECTORY))?;
        }
        if let Some(bundle) = &arguments.bundle {
            copy_bundle(bundle, &volume.join("EFI/stela/bundle"))?;
        }
        if let Some(manifest) = &arguments.restore_manifest {
            fs::copy(manifest, volume.join("EFI/stela/payload.json"))
                .with_context(|| format!("restore manifest {}", manifest.display()))?;
            // The block hashes the manifest names go beside it, so the
            // restore host needs no scan of the payload.
            let parsed = stela_formats::payload::PayloadManifest::parse(&fs::read(manifest)?)
                .map_err(|error| anyhow::anyhow!("{}: {error}", manifest.display()))?;
            if let Some(blocks) = &parsed.block_hashes {
                let from = manifest.with_file_name(&blocks.file);
                fs::copy(&from, volume.join("EFI/stela").join(&blocks.file))
                    .with_context(|| format!("block hashes {}", from.display()))?;
            }
        }
    }
    // QEMU's directory volume is FAT16 and holds 516 MB; larger volumes,
    // such as a restore bundle with its ramdisk, go into a FAT32 image.
    Ok(match &arguments.usb_image {
        None if !arguments.directory_volume && directory_bytes(volume)? > VVFAT_BYTES => {
            Some(fat_image(volume, &paths.output)?)
        }
        _ => None,
    })
}

/// Boot-volume image selection and checkpoint format.
pub(super) struct VolumeOptions<'a> {
    pub(super) fat: Option<&'a Path>,
    pub(super) format: &'a str,
}

/// The boot volume's drive: the USB image, the FAT32 image or the
/// directory itself, on a virtio disk unless the USB carries it.
pub(super) fn attach_volume(
    arguments: &Run,
    paths: &Paths,
    options: VolumeOptions<'_>,
    command: &mut Process,
) {
    let VolumeOptions { fat, format } = options;
    // A USB's setup writes the boot log.
    let access = if arguments.usb_image.is_some() {
        "readonly=off,file=fat:rw:"
    } else {
        "readonly=on,file=fat:"
    };
    command.arg("-drive").arg(match &arguments.usb_image {
        Some(usb) => format!(
            "if=none,id=volume,format={format},snapshot={},file={}",
            if arguments.usb_writable { "off" } else { "on" },
            option_path(usb)
        ),
        None => match fat {
            Some(image) => format!(
                "if=none,id=volume,format=raw,readonly=on,file={}",
                option_path(image)
            ),
            None => format!(
                "if=none,id=volume,format=raw,{access}{}",
                option_path(&paths.volume)
            ),
        },
    });
    if arguments.usb_image.is_none() {
        command.args(["-device", "virtio-blk-pci,drive=volume"]);
    }
}

/// Diagnostic disks and optional Preboot image attached to a run.
pub(super) struct DiskImages<'a> {
    pub(super) disks: &'a [disks::Disk],
    pub(super) preboot: Option<&'a Preboot>,
}

/// `--storage-check`'s disks and the Preboot disk.
pub(super) fn attach_disks(images: DiskImages<'_>, command: &mut Process) {
    let DiskImages { disks, preboot } = images;
    for (index, disk) in disks.iter().enumerate() {
        disk.attach(index, command);
    }
    if let Some(preboot) = preboot {
        preboot.attach(command);
    }
}

/// The `--usb-image` stick on the host's USB controller, as the boot disk.
pub(super) fn attach_usb_boot(arguments: &Run, command: &mut Process) {
    if arguments.usb_image.is_some() {
        command.arg("-device").arg(format!(
            "usb-storage,drive=volume,serial={},bus=host-usb.0,bootindex=0",
            arguments.usb_serial
        ));
    }
}

/// `--usb-disk`s on the host's USB controller, and the NVMe disks
/// `--usb-storage-disk` names.
pub(super) fn attach_usb_disks(arguments: &Run, command: &mut Process) {
    for (index, path) in arguments.usb_disk.iter().enumerate() {
        command.arg("-drive").arg(format!(
            "if=none,id=usbdisk{index},format=raw,file={}",
            option_path(path)
        ));
        match arguments.usb_disk_model.unwrap_or(UsbDiskModel::Bot) {
            UsbDiskModel::Bot => {
                command.arg("-device").arg(format!(
                    "usb-storage,drive=usbdisk{index},serial=STELAUSBDISK{index},bus=host-usb.0"
                ));
            }
            UsbDiskModel::Uas | UsbDiskModel::UasUsb2 => {
                command.arg("-device").arg(format!(
                    "usb-uas,id=host-uas{index},serial=STELAUSBDISK{index},bus=host-usb.0"
                ));
                command.arg("-device").arg(format!(
                    "scsi-hd,drive=usbdisk{index},bus=host-uas{index}.0,scsi-id=0,lun=0"
                ));
            }
        }
    }
    for (index, path) in arguments.usb_storage_disk.iter().enumerate() {
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=usb{index},format=raw,file={}",
                option_path(path)
            ))
            .arg("-device")
            .arg(format!(
                "nvme,drive=usb{index},serial={}",
                usb_serial(index)
            ));
    }
}

/// `--storage-disk`s, each an NVMe disk with its serial.
pub(super) fn attach_storage_disks(
    attached: &[(PathBuf, String)],
    mdts: Option<u8>,
    command: &mut Process,
) {
    let mdts = mdts
        .map(|value| format!(",mdts={value}"))
        .unwrap_or_default();
    for (index, (path, serial)) in attached.iter().enumerate() {
        // Let Write Zeroes with unmap release image-file extents.
        let discard = if path.is_file() { ",discard=unmap" } else { "" };
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=ans{index},format=raw,file={}{discard}",
                option_path(path)
            ))
            .arg("-device")
            .arg(format!("nvme,drive=ans{index},serial={serial}{mdts}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(path: PathBuf) -> Vec<String> {
        let mut command = Process::new("qemu-system-x86_64");
        attach_storage_disks(&[(path, "TEST".into())], None, &mut command);
        command
            .get_args()
            .map(|argument| argument.to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn image_files_allow_unmap_and_keep_escaped_paths() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("raw,image.img");
        fs::write(&path, [0xa5; 16]).unwrap();
        assert_eq!(
            drive(path.clone()),
            [
                "-drive".to_owned(),
                format!(
                    "if=none,id=ans0,format=raw,file={},discard=unmap",
                    option_path(&path)
                ),
                "-device".to_owned(),
                "nvme,drive=ans0,serial=TEST".to_owned(),
            ]
        );
        assert_eq!(fs::read(path).unwrap(), [0xa5; 16]);
    }

    #[test]
    fn explicit_mdts_applies_to_each_storage_controller() {
        let directory = tempfile::tempdir().unwrap();
        let attached = [
            (directory.path().join("first"), "FIRST".into()),
            (directory.path().join("second"), "SECOND".into()),
        ];
        for mdts in [1, 7, 9] {
            let mut command = Process::new("qemu-system-x86_64");
            attach_storage_disks(&attached, Some(mdts), &mut command);
            let controllers: Vec<_> = command
                .get_args()
                .filter_map(|argument| argument.to_str())
                .filter(|argument| argument.starts_with("nvme,"))
                .collect();
            assert_eq!(
                controllers,
                [
                    format!("nvme,drive=ans0,serial=FIRST,mdts={mdts}"),
                    format!("nvme,drive=ans1,serial=SECOND,mdts={mdts}"),
                ]
            );
        }
    }

    #[test]
    fn non_files_keep_the_default_discard_policy() {
        let directory = tempfile::tempdir().unwrap();
        for path in [
            directory.path().to_owned(),
            directory.path().join("missing"),
        ] {
            assert!(
                !drive(path)
                    .iter()
                    .any(|argument| argument.contains("discard="))
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_use_the_backing_file_type() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("image");
        fs::write(&image, []).unwrap();
        for (name, target, unmap) in [
            ("regular", image.as_path(), true),
            ("device", Path::new("/dev/null"), false),
        ] {
            let path = directory.path().join(name);
            symlink(target, &path).unwrap();
            assert_eq!(
                drive(path)
                    .iter()
                    .any(|argument| argument.contains(",discard=unmap")),
                unmap,
            );
        }
    }
}

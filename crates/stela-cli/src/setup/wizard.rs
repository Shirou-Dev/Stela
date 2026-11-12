//! A small Clack-style front end to the same setup command used by scripts.
use super::{
    InstallImage, Request, firmware,
    host::{self, Disk, Host, Removal},
    record::{self, Record},
    wifi,
};
use crate::{progress::Phase, restore};
use anyhow::{Context, Result, ensure};
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
};

mod catalog;
mod choices;
mod menu;
mod theme;

// Advertised USB capacity classes; preparation also checks exact image sizes.
const NETWORK_MIN: u64 = 7 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Usb {
    id: String,
    name: String,
    bytes: u64,
    removal: Removal,
    serial: Option<String>,
}

impl Usb {
    pub(super) fn from_disk(disk: &Disk, host: &dyn Host) -> Self {
        Self {
            id: disk.identifier.clone(),
            name: disk.name.clone(),
            bytes: disk.bytes,
            removal: disk.removal,
            serial: host.serial(&disk.identifier).ok().flatten(),
        }
    }

    pub(super) fn verify(&self, host: &dyn Host) -> Result<()> {
        let disk = host
            .disks()?
            .into_iter()
            .find(|d| d.identifier == self.id)
            .context("the selected USB was disconnected; run setup again")?;
        ensure!(
            disk.erasable() && *self == Self::from_disk(&disk, host),
            "the selected USB changed; run setup again and choose it again"
        );
        Ok(())
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(&self.id)
    }

    fn size(&self) -> String {
        host::size_text(self.bytes)
    }

    fn description(&self) -> String {
        format!("{} · {} · {}", self.name, self.size(), self.id)
    }

    /// Its model or size, typed back to erase a disk other than a USB, or
    /// any disk when setup cannot tell which one this computer runs from.
    fn typed_back(&self) -> Result<String> {
        cliclack::log::warning(format!(
            "{} ({}, {}) {}.",
            self.name,
            self.size(),
            self.id,
            self.removal.why_typed()
        ))?;
        let (name, bytes) = (self.name.clone(), self.bytes);
        let expected = format!("Type {} or {}", self.name, self.size());
        Ok(cliclack::input("Type its model or size to erase it")
            .placeholder(&format!("{} or {}", self.name, self.size()))
            .validate(move |typed: &String| {
                if host::names_disk(&name, bytes, typed) {
                    Ok(())
                } else {
                    Err(expected.clone())
                }
            })
            .interact()?)
    }

    /// The name and size people recognize, for the erase warning.
    fn short(&self) -> String {
        format!("{} ({})", self.name, self.size())
    }
}

#[derive(serde::Deserialize)]
struct LocalImage {
    #[serde(rename = "ProductVersion")]
    product_version: String,
    #[serde(rename = "ProductBuildVersion")]
    product_build: String,
    #[serde(rename = "SupportedProductTypes")]
    supported_models: Vec<String>,
}

fn local_image(path: &Path) -> Result<LocalImage> {
    // Read only metadata into the wizard, rather than keeping every board's
    // component map. Preparation validates the selected identity before erase.
    let bytes = restore::archive::read_member(path, "BuildManifest.plist", 64 * 1024 * 1024)?;
    Ok(plist::from_reader(std::io::Cursor::new(bytes))?)
}

/// `false` is cancellation. No disk is written by this function.
pub(super) fn configure(command: &mut Request, host: &dyn Host) -> Result<bool> {
    ensure!(
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "interactive setup needs a terminal; scripts pass --usb, and --ipsw for a local image"
    );
    match configure_inner(command, host) {
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::Interrupted) =>
        {
            cliclack::outro_cancel("Setup cancelled. Your USB was not changed.")?;
            Ok(false)
        }
        result => result,
    }
}

/// The EFI partition of `usb` and the interrupted first setup it holds,
/// which the same choices again resume (`create::plan`). The partition is
/// mounted to look, as setup mounts it anyway.
pub(super) fn interrupted(host: &dyn Host, usb: &Disk) -> Option<(PathBuf, Record)> {
    let partition = usb.partitions.iter().find(|p| p.content == "EFI")?;
    let esp = match &partition.mount {
        Some(mount) => mount.clone(),
        None => host.mount(&partition.identifier).ok()?,
    };
    let record = record::interrupted(host, &esp, &esp)?;
    Some((esp, record))
}

/// Make `command` the interrupted setup `record` describes, on its EFI
/// partition `esp`, so it resumes instead of erasing the USB again. A local
/// IPSW given on the command line stays; otherwise setup downloads the
/// recorded build.
pub(super) fn resume(command: &mut Request, esp: PathBuf, record: &Record) {
    command.usb = esp;
    command.build = record.build.clone();
    command.model = Some(record.model.clone());
    // The installer the stopped setup was making: a full one goes on from
    // the pieces already on the USB (`stela setup` run again does the same).
    command.install_image = Some(record.install_kind());
    if command.ipsw.is_none() {
        command.fetch = true;
    }
    command.install = record.installs.first().map(|install| install.name.clone());
    command.wifi = record.wifi.as_ref().map(|network| network.ssid.clone());
    command.wifi_country = record
        .wifi
        .as_ref()
        .and_then(|network| network.country.clone());
    command.ipv4 = record
        .addresses
        .ipv4
        .map(|ipv4| stela_boot_core::options::StaticIpv4 {
            address: ipv4.address,
            prefix: ipv4.prefix,
        });
    command.ipv4_gateway = record.addresses.ipv4.and_then(|ipv4| ipv4.gateway);
    command.dns = (!record.addresses.dns.is_empty()).then(|| record.addresses.dns.clone());
    command.usb4_approve = record.usb4_approved.clone();
    command.profile = record.profile;
}

fn configure_inner(command: &mut Request, host: &dyn Host) -> Result<bool> {
    cliclack::set_theme(theme::Stela);
    crate::progress::follow(theme::rail());
    cliclack::intro(
        theme::accent()
            .bold()
            .apply_to("Stela · Create a macOS installer"),
    )?;
    let disks = host.disks()?;
    let choices: Vec<_> = disks
        .iter()
        .filter(|d| d.erasable())
        .map(|d| Usb::from_disk(d, host))
        .collect();
    ensure!(
        !choices.is_empty(),
        "no removable USB found. Connect a USB and run setup again."
    );
    let mut images = None;
    let mut names = catalog::cached_names();
    let mut first = true;
    // `--build`, or the newest supported build.
    let mut preferred_build = Some(command.build.clone());
    loop {
        let rows: Vec<_> = choices
            .iter()
            .enumerate()
            .map(|(i, usb)| menu::Item {
                value: i,
                label: usb.description(),
                hint: if usb.bytes == 0 {
                    "Capacity unavailable".into()
                } else if usb.bytes < NETWORK_MIN {
                    "Too small · Requires an 8 GB or larger USB".into()
                } else if usb.bytes < super::FULL_MIN {
                    "Online installer only · Offline needs 32 GB or more".into()
                } else {
                    "Offline or Online installer".into()
                },
                enabled: usb.bytes >= NETWORK_MIN,
            })
            .collect();
        if !rows.iter().any(|row| row.enabled) {
            cliclack::note(
                "USBs found",
                rows.iter()
                    .map(|row| format!("{} · {}", row.label, row.hint))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )?;
            anyhow::bail!("no USB of 8 GB or more found; connect one and run setup again");
        }
        let initial = choices
            .iter()
            .position(|usb| usb.path() == command.usb)
            .unwrap_or(0);
        let usb = &choices[menu::select("1. Choose a USB", &rows, initial)?];
        command.usb = usb.path();
        // A setup this USB holds that stopped part way is finished, not
        // erased and begun again.
        let disk = disks.iter().find(|d| d.identifier == usb.id);
        if let Some((esp, record)) = disk.and_then(|disk| interrupted(host, disk)) {
            cliclack::log::info(format!(
                "This USB holds a setup that was interrupted: {}",
                record.resume_summary()
            ))?;
            let choice = cliclack::select("Resume it or start over?")
                .item(
                    0,
                    "Resume it",
                    "Keeps what it wrote, checks each piece and finishes the rest",
                )
                .item(1, "Start over", "Erases the USB")
                .initial_value(0)
                .interact()?;
            if choice == 0 {
                resume(command, esp, &record);
                if command.wifi.is_some() {
                    cliclack::log::warning("The passphrase is stored in plaintext on the USB.")?;
                    let ssid = command.wifi.clone().unwrap_or_default();
                    command.wifi_passphrase = Some(wifi::ask_passphrase(&ssid)?);
                }
                return Ok(true);
            }
        }
        // A local IPSW named on the command line supplies the boot files,
        // and macOS too when it holds the whole image.
        let prefilled = first && command.ipsw.is_some();
        first = false;
        // macOS's size, for the Offline choice, and whether the image holds
        // all of it.
        let (image_bytes, whole);
        let (version, models) = if prefilled {
            let path = command.ipsw.clone().unwrap();
            let progress = Phase::spinner("Reading IPSW metadata");
            let manifest =
                local_image(&path).with_context(|| format!("reading {}", path.display()))?;
            progress.finish();
            stela_formats::builds::find(&manifest.product_build)
                .with_context(|| path.display().to_string())?;
            command.ipsw = Some(path);
            command.fetch = false;
            command.build = manifest.product_build.clone();
            preferred_build = Some(command.build.clone());
            let ipsw = command.ipsw.as_deref().unwrap();
            whole = crate::restore::payload::holds_system_image(ipsw)?;
            image_bytes = std::fs::metadata(ipsw).ok().map(|meta| meta.len());
            cliclack::log::info(format!(
                "macOS {} ({}) · local IPSW{}",
                manifest.product_version,
                manifest.product_build,
                if stela_formats::builds::tested(&manifest.product_build) {
                    ""
                } else {
                    " · not tested yet"
                }
            ))?;
            (manifest.product_version, manifest.supported_models)
        } else {
            if images.is_none() {
                let progress = Phase::spinner("Loading available macOS versions");
                images = Some(catalog::load()?);
                if let Ok(fresh) = catalog::model_names() {
                    names = fresh;
                }
                progress.finish();
            }
            let entries = images.as_ref().unwrap();
            let image =
                &entries[choices::release(entries, preferred_build.as_deref().unwrap_or(""))?];
            command.build = image.build.clone();
            preferred_build = Some(command.build.clone());
            command.ipsw = None;
            command.fetch = true;
            whole = true;
            image_bytes = download_size(image);
            (image.version.clone(), image.models.clone())
        };
        ensure!(
            !models.is_empty(),
            "this image lists no compatible Mac models"
        );
        let mut models = models;
        models.sort();
        models.dedup();
        command.model = Some(choices::model(&models, &names, command.model.as_deref())?);
        let (rows, initial) = installer_rows(usb.bytes, whole, image_bytes, command.install_image);
        let install_image = INSTALLERS[menu::select("4. Installer", &rows, initial)?];
        command.install_image = Some(install_image);
        // Only the Online installer's install needs the internet, and so a
        // way to it.
        let online = install_image == InstallImage::Network;
        let network = if online {
            choose_wifi(command)?;
            super::addresses::choose(command)?;
            format!(
                "{}{}",
                match &command.wifi {
                    Some(ssid) => format!("Wi-Fi      {ssid}\n"),
                    None => "Wi-Fi      None (Ethernet)\n".into(),
                },
                super::addresses::review(command)
            )
        } else {
            (command.wifi, command.wifi_passphrase) = (None, None);
            (command.ipv4, command.ipv4_gateway, command.dns) = (None, None, None);
            String::new()
        };
        cliclack::note(
            if online { "7. Review" } else { "5. Review" },
            format!(
                "USB        {}\nInstaller  {}\nmacOS      {version} ({})\nMac        {}\n{network}{}",
                usb.serial.as_ref().map_or_else(
                    || usb.description(),
                    |serial| format!("{} · serial {serial}", usb.description())
                ),
                match online {
                    false => "Offline · the install needs no internet",
                    true => "Online · the install downloads macOS",
                },
                command.build,
                names
                    .get(command.model())
                    .map_or(command.model(), String::as_str),
                // Only a scripted --profile turns it on.
                if command.profile {
                    "Profiling  On\n"
                } else {
                    ""
                },
            ),
        )?;
        for note in firmware::host_notes(host)? {
            cliclack::log::info(note)?;
        }
        cliclack::log::info(super::create::SIGNING_NOTE)?;
        cliclack::log::warning(format!("Everything on {} will be erased.", usb.short()))?;
        match cliclack::select("Create the installer?")
            .item(
                0,
                "Create installer",
                format!("Erase {} and write the installer", usb.short()),
            )
            .item(1, "Edit choices", "")
            .item(2, "Cancel", "")
            .initial_value(0)
            .interact()?
        {
            0 => {
                if matches!(usb.removal, Removal::Typed | Removal::Unsure) {
                    command.confirm_disk = Some(usb.typed_back()?);
                }
                usb.verify(host)?;
                command.confirmed = true;
                return Ok(true);
            }
            1 => continue,
            _ => {
                cliclack::outro_cancel("Setup cancelled. Your USB was not changed.")?;
                return Ok(false);
            }
        }
    }
}

/// The installer step's choices, by their menu values.
const INSTALLERS: [InstallImage; 2] = [InstallImage::Full, InstallImage::Network];

/// The installer step on a USB of `usb_bytes`, for an image of
/// `image_bytes` that holds all of macOS (`whole`) or only its startup
/// files: Offline, shown unavailable with its reason where it cannot be
/// made, and Online; and the one preselected, `chosen` before or else
/// Offline where it can be made.
fn installer_rows(
    usb_bytes: u64,
    whole: bool,
    image_bytes: Option<u64>,
    chosen: Option<InstallImage>,
) -> (Vec<menu::Item>, usize) {
    let unavailable = super::offline_unavailable(usb_bytes, whole);
    let offline = match &unavailable {
        Some(reason) => {
            let mut hint = reason.clone();
            hint[..1].make_ascii_uppercase();
            hint
        }
        None => format!(
            "macOS is copied to the USB now{}. The install needs no internet.",
            image_bytes.map_or_else(String::new, |bytes| format!(
                " (about {:.0} GB)",
                bytes as f64 / 1e9
            ))
        ),
    };
    let rows = vec![
        menu::Item {
            value: 0,
            label: InstallImage::Full.name().into(),
            hint: offline,
            enabled: unavailable.is_none(),
        },
        menu::Item {
            value: 1,
            label: InstallImage::Network.name().into(),
            hint: "Small and quick to make. The install downloads macOS, so the PC needs \
                   internet."
                .into(),
            enabled: true,
        },
    ];
    let initial = match (chosen, unavailable) {
        (Some(InstallImage::Network), _) | (_, Some(_)) => 1,
        _ => 0,
    };
    (rows, initial)
}

/// The size of the catalog's macOS image, from Apple's server; nothing
/// when the server does not say.
fn download_size(image: &restore::Image) -> Option<u64> {
    let progress = Phase::spinner("Checking the size of macOS");
    let size = restore::open_image(image).ok().map(|remote| remote.size());
    progress.finish();
    size
}

/// An Online installer's Wi-Fi: a network this computer sees or knows, one
/// typed in, or none.
fn choose_wifi(command: &mut Request) -> Result<()> {
    let progress = Phase::spinner("Looking for Wi-Fi networks");
    let networks = wifi::host_networks();
    progress.finish();
    const ETHERNET: usize = usize::MAX;
    const TYPED: usize = usize::MAX - 1;
    let mut select = cliclack::select("5. Wi-Fi during installation").item(
        ETHERNET,
        "No Wi-Fi",
        "Connect the PC to Ethernet during installation",
    );
    for (index, ssid) in networks.iter().enumerate() {
        select = select.item(index, ssid, "");
    }
    let initial = command
        .wifi
        .as_ref()
        .and_then(|ssid| networks.iter().position(|known| known == ssid))
        .unwrap_or(if command.wifi.is_some() {
            TYPED
        } else {
            ETHERNET
        });
    let choice = select
        .item(TYPED, "Another network", "Type its name")
        .initial_value(initial)
        .interact()?;
    let ssid = match choice {
        ETHERNET => {
            (command.wifi, command.wifi_passphrase) = (None, None);
            return Ok(());
        }
        TYPED => cliclack::input("Network name")
            .default_input(command.wifi.as_deref().unwrap_or_default())
            .validate(|name: &String| wifi::ssid(name).map(|_| ()))
            .interact()?,
        index => networks[index].clone(),
    };
    cliclack::log::warning("The passphrase is stored in plaintext on the USB.")?;
    command.wifi_passphrase = Some(wifi::ask_passphrase(&ssid)?);
    command.wifi = Some(ssid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_manifest_checks_version_and_model() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("local.ipsw");
        crate::efi::synthetic_ipsw(&path)?;
        let manifest = local_image(&path)?;
        assert_eq!(manifest.product_build, restore::payload::SYNTHETIC_BUILD);
        assert!(
            manifest
                .supported_models
                .contains(&restore::payload::SYNTHETIC_MODEL.into())
        );
        assert!(local_image(&dir.path().join("missing.ipsw")).is_err());
        Ok(())
    }

    fn shown(rows: &[menu::Item]) -> Vec<(String, String, bool)> {
        rows.iter()
            .map(|row| (row.label.clone(), row.hint.clone(), row.enabled))
            .collect()
    }

    const ONLINE: &str =
        "Small and quick to make. The install downloads macOS, so the PC needs internet.";

    #[test]
    fn a_large_usb_offers_both_installers_with_offline_first() {
        let (rows, initial) = installer_rows(64_000_000_000, true, Some(17_800_000_000), None);
        assert_eq!(
            shown(&rows),
            [
                (
                    "Offline".into(),
                    "macOS is copied to the USB now (about 18 GB). The install needs no internet."
                        .into(),
                    true
                ),
                ("Online".into(), ONLINE.into(), true),
            ]
        );
        assert_eq!(INSTALLERS[initial], InstallImage::Full);
        // Edit choices comes back to Online once it was chosen.
        let (_, initial) = installer_rows(64_000_000_000, true, None, Some(InstallImage::Network));
        assert_eq!(INSTALLERS[initial], InstallImage::Network);
        let (rows, _) = installer_rows(64_000_000_000, true, None, None);
        assert_eq!(
            rows[0].hint,
            "macOS is copied to the USB now. The install needs no internet."
        );
    }

    #[test]
    fn a_small_usb_shows_offline_unavailable_with_its_reason() {
        let (rows, initial) = installer_rows(16_000_000_000, true, Some(17_800_000_000), None);
        assert_eq!(
            shown(&rows),
            [
                (
                    "Offline".into(),
                    "Needs a USB of 32 GB or more (this one is 16.0 GB)".into(),
                    false
                ),
                ("Online".into(), ONLINE.into(), true),
            ]
        );
        assert_eq!(INSTALLERS[initial], InstallImage::Network);
        // An earlier Offline choice cannot be preselected there.
        let (_, initial) = installer_rows(16_000_000_000, true, None, Some(InstallImage::Full));
        assert_eq!(INSTALLERS[initial], InstallImage::Network);
    }

    #[test]
    fn a_local_ipsw_without_all_of_macos_shows_offline_unavailable() {
        let (rows, initial) = installer_rows(64_000_000_000, false, Some(1_000_000_000), None);
        assert!(!rows[0].enabled);
        assert_eq!(
            rows[0].hint,
            "Needs an IPSW file with all of macOS; this one has only its startup files"
        );
        assert_eq!(INSTALLERS[initial], InstallImage::Network);
    }
}

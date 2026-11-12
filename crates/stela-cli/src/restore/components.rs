//! Which BuildManifest identities and components a build and profile need:
//! the one definition `stela-dev boot prepare`, the restore inventory and
//! `stela` share.
//!
//! A profile is a Mac the engine presents, by its `Ap,ProductType`. The
//! profile registry ([`BOARDS`], the 26A434 IPSW's boards) gives its
//! `ApChipID`, `ApBoardID` and `DeviceClass`, and the BuildManifest
//! identities with exactly those values
//! are the profile's. An identity's purpose is its own `Info.RestoreBehavior`:
//! `Update` restores keep data; `Erase` with a `RestoreRamDisk` erases;
//! `Erase` without one is the installed system's set. Components are named by
//! their BuildManifest keys, never by archive member names, and a missing one
//! is refused with the build and the profile.
use super::manifest::{Component, Identity, RestoreManifest};
use anyhow::{Context, Result, bail};
use std::fmt;
use stela_formats::payload::Purpose;

/// The profile registry: each board's `Ap,ProductType`, `ApChipID`,
/// `ApBoardID` and `DeviceClass`.
pub const BOARDS: [(&str, u32, u32, &str); 59] = [
    ("Mac14,8", 0x6022, 0x08, "j180dap"),
    ("Macmini9,1", 0x8103, 0x22, "j274ap"),
    ("MacBookPro17,1", 0x8103, 0x24, "j293ap"),
    ("MacBookAir10,1", 0x8103, 0x26, "j313ap"),
    ("MacBookPro18,4", 0x6001, 0x08, "j314cap"),
    ("MacBookPro18,3", 0x6000, 0x08, "j314sap"),
    ("MacBookPro18,2", 0x6001, 0x0a, "j316cap"),
    ("MacBookPro18,1", 0x6000, 0x0a, "j316sap"),
    ("Mac13,1", 0x6001, 0x04, "j375cap"),
    ("Mac13,2", 0x6002, 0x0c, "j375dap"),
    ("Mac14,2", 0x8112, 0x28, "j413ap"),
    ("Mac14,5", 0x6021, 0x04, "j414cap"),
    ("Mac14,9", 0x6020, 0x04, "j414sap"),
    ("Mac14,15", 0x8112, 0x2e, "j415ap"),
    ("Mac14,6", 0x6021, 0x06, "j416cap"),
    ("Mac14,10", 0x6020, 0x06, "j416sap"),
    ("Mac15,4", 0x8122, 0x28, "j433ap"),
    ("Mac15,5", 0x8122, 0x2a, "j434ap"),
    ("iMac21,1", 0x8103, 0x28, "j456ap"),
    ("iMac21,2", 0x8103, 0x2a, "j457ap"),
    ("Mac14,3", 0x8112, 0x24, "j473ap"),
    ("Mac14,12", 0x6020, 0x02, "j474sap"),
    ("Mac14,13", 0x6021, 0x0a, "j475cap"),
    ("Mac14,14", 0x6022, 0x0a, "j475dap"),
    ("Mac14,7", 0x8112, 0x2a, "j493ap"),
    ("Mac15,3", 0x8122, 0x22, "j504ap"),
    ("Mac15,8", 0x6031, 0x44, "j514cap"),
    ("Mac15,10", 0x6034, 0x44, "j514map"),
    ("Mac15,6", 0x6030, 0x04, "j514sap"),
    ("Mac15,9", 0x6031, 0x46, "j516cap"),
    ("Mac15,11", 0x6034, 0x46, "j516map"),
    ("Mac15,7", 0x6030, 0x06, "j516sap"),
    ("Mac16,9", 0x6041, 0x02, "j575cap"),
    ("Mac15,14", 0x6032, 0x44, "j575dap"),
    ("Mac16,1", 0x8132, 0x22, "j604ap"),
    ("Mac15,12", 0x8122, 0x30, "j613ap"),
    ("Mac16,6", 0x6041, 0x04, "j614cap"),
    ("Mac16,8", 0x6040, 0x04, "j614sap"),
    ("Mac15,13", 0x8122, 0x32, "j615ap"),
    ("Mac16,5", 0x6041, 0x06, "j616cap"),
    ("Mac16,7", 0x6040, 0x06, "j616sap"),
    ("Mac16,2", 0x8132, 0x24, "j623ap"),
    ("Mac16,3", 0x8132, 0x26, "j624ap"),
    ("Mac17,5", 0x8140, 0x64, "j700ap"),
    ("Mac17,2", 0x8142, 0x22, "j704ap"),
    ("Mac16,12", 0x8132, 0x2c, "j713ap"),
    ("Mac17,7", 0x6050, 0x0a, "j714cap"),
    ("Mac17,9", 0x6050, 0x08, "j714sap"),
    ("Mac16,13", 0x8132, 0x2e, "j715ap"),
    ("Mac17,6", 0x6050, 0x0e, "j716cap"),
    ("Mac17,8", 0x6050, 0x0c, "j716sap"),
    ("Mac16,10", 0x8132, 0x2a, "j773gap"),
    ("Mac16,11", 0x6040, 0x02, "j773sap"),
    ("Mac17,14", 0x6050, 0x10, "j775cap"),
    ("Mac17,15", 0x6050, 0x12, "j775dap"),
    ("Mac17,3", 0x8142, 0x24, "j813ap"),
    ("Mac17,4", 0x8142, 0x26, "j815ap"),
    ("Mac18,5", 0x8152, 0x24, "j873gap"),
    ("Mac17,16", 0x6050, 0x02, "j873sap"),
];

/// The component only an erase or update restore has: the ramdisk restored
/// runs from.
pub const RESTORE_RAMDISK: &str = "RestoreRamDisk";

/// Whether a component belongs only to the macOS system volume, which a
/// recovery-only erase restore (`SystemImage` false) never asks for: the
/// system image, its seal metadata and the cryptexes installed with it.
pub fn system_volume(component: &str) -> bool {
    matches!(component, "OS" | "Ap,SystemVolumeCanonicalMetadata")
        || component.starts_with("Cryptex1,")
}

/// The synthetic IPSW's profile (`payload::synthetic_ipsw`), which no Mac
/// has.
pub const SYNTHETIC: (&str, u32, u32, &str) = ("StelaTest1,1", 0xfe01, 0x01, "stelatestap");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub model: String,
    pub chip_id: u32,
    pub board_id: u32,
    pub device_class: String,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}, ApChipID {:#x}, ApBoardID {:#x})",
            self.model, self.device_class, self.chip_id, self.board_id
        )
    }
}

fn hex(value: &str) -> Option<u32> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u32::from_str_radix(digits, 16).ok()
}

impl Profile {
    /// The registry's profile of `model`.
    pub fn of(model: &str) -> Result<Self> {
        if model == SYNTHETIC.0 {
            let (model, chip_id, board_id, device_class) = SYNTHETIC;
            return Ok(Self {
                model: model.into(),
                chip_id,
                board_id,
                device_class: device_class.into(),
            });
        }
        let &(model, chip_id, board_id, device_class) = BOARDS
            .iter()
            .find(|board| board.0 == model)
            .with_context(|| format!("{model} is not in the profile registry"))?;
        Ok(Self {
            model: model.into(),
            chip_id,
            board_id,
            device_class: device_class.into(),
        })
    }

    /// Whether `identity` is this profile's.
    pub fn owns(&self, identity: &Identity) -> bool {
        identity.device_class == self.device_class
            && identity.ap_chip_id.as_deref().and_then(hex) == Some(self.chip_id)
            && identity.ap_board_id.as_deref().and_then(hex) == Some(self.board_id)
    }
}

/// What an identity is for, from its own `RestoreBehavior`.
pub fn purpose(identity: &Identity) -> Option<Purpose> {
    match identity.restore_behavior.as_deref()? {
        "Update" => Some(Purpose::Update),
        "Erase" if identity.components.contains_key(RESTORE_RAMDISK) => Some(Purpose::Erase),
        "Erase" => Some(Purpose::Installed),
        _ => None,
    }
}

fn purpose_name(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::Erase => "erase restore",
        Purpose::Update => "update restore",
        Purpose::Installed => "installed system",
    }
}

/// The profile's identities in `manifest`, in manifest order.
pub fn identities<'a>(manifest: &'a RestoreManifest, profile: &Profile) -> Vec<&'a Identity> {
    manifest
        .identities
        .iter()
        .filter(|identity| profile.owns(identity))
        .collect()
}

/// The profile's one identity for `purpose`.
pub fn identity<'a>(
    manifest: &'a RestoreManifest,
    profile: &Profile,
    purpose: Purpose,
) -> Result<&'a Identity> {
    let mut matching = identities(manifest, profile)
        .into_iter()
        .filter(|identity| self::purpose(identity) == Some(purpose));
    match (matching.next(), matching.next()) {
        (Some(identity), None) => Ok(identity),
        (None, _) => bail!(
            "macOS {} has no {} identity for {profile}",
            manifest.product_build,
            purpose_name(purpose)
        ),
        (Some(_), Some(_)) => bail!(
            "macOS {} has several {} identities for {profile}",
            manifest.product_build,
            purpose_name(purpose)
        ),
    }
}

/// The profile's identity named by its `Info.Variant`.
pub fn variant<'a>(
    manifest: &'a RestoreManifest,
    profile: &Profile,
    variant: &str,
) -> Result<&'a Identity> {
    let owned = identities(manifest, profile);
    owned
        .iter()
        .find(|identity| identity.variant == variant)
        .copied()
        .with_context(|| {
            let variants: Vec<&str> = owned.iter().map(|i| i.variant.as_str()).collect();
            format!(
                "macOS {} has no {variant:?} identity for {profile}; it has {variants:?}",
                manifest.product_build
            )
        })
}

/// Component `name` of `identity`, or of another identity of the profile
/// when `identity` lacks it; returns the identity that has it.
pub fn component<'a>(
    manifest: &'a RestoreManifest,
    profile: &Profile,
    identity: &'a Identity,
    name: &str,
) -> Result<(&'a Identity, &'a Component)> {
    std::iter::once(identity)
        .chain(identities(manifest, profile))
        .find_map(|owner| owner.components.get(name).map(|c| (owner, c)))
        .with_context(|| {
            format!(
                "macOS {} lists no {name} component for {profile}",
                manifest.product_build
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restore::manifest::inspect;

    fn manifest() -> RestoreManifest {
        let identity =
            |chip: &str, board: &str, class: &str, variant: &str, behavior: &str, ramdisk: bool| {
                let ramdisk = if ramdisk {
                    "<key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key>\
                 <string>ramdisk.dmg</string></dict></dict>"
                } else {
                    ""
                };
                format!(
                    "<dict><key>ApChipID</key><string>{chip}</string><key>ApBoardID</key>\
                 <string>{board}</string><key>Info</key><dict><key>DeviceClass</key>\
                 <string>{class}</string><key>Variant</key><string>{variant}</string>\
                 <key>RestoreBehavior</key><string>{behavior}</string></dict>\
                 <key>Manifest</key><dict><key>KernelCache</key><dict><key>Info</key><dict>\
                 <key>Path</key><string>kernel</string></dict></dict>{ramdisk}</dict></dict>"
                )
            };
        let identities = [
            identity(
                "0x8112",
                "0x28",
                "j413ap",
                "Customer Erase Install (IPSW)",
                "Erase",
                true,
            ),
            identity(
                "0x8112",
                "0x24",
                "j473ap",
                "Customer Erase Install (IPSW)",
                "Erase",
                true,
            ),
            identity(
                "0x8112",
                "0x24",
                "j473ap",
                "Customer Upgrade Install (IPSW)",
                "Update",
                true,
            ),
            identity("0x8112", "0x24", "j473ap", "macOS Customer", "Erase", false),
        ]
        .concat();
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>\
             <key>ProductVersion</key><string>27.0.1</string><key>ProductBuildVersion</key>\
             <string>26A434</string><key>SupportedProductTypes</key><array/>\
             <key>BuildIdentities</key><array>{identities}</array></dict></plist>"
        );
        inspect(plist.as_bytes(), None).unwrap()
    }

    #[test]
    fn profiles_come_from_the_registry() {
        let profile = Profile::of("Mac14,3").unwrap();
        assert_eq!(
            (
                profile.chip_id,
                profile.board_id,
                profile.device_class.as_str()
            ),
            (0x8112, 0x24, "j473ap")
        );
        assert_eq!(Profile::of("Mac14,2").unwrap().device_class, "j413ap");
        let error = Profile::of("Mac99,1").unwrap_err().to_string();
        assert!(error.contains("not in the profile registry"), "{error}");
        assert_eq!(Profile::of(SYNTHETIC.0).unwrap().board_id, SYNTHETIC.2);
    }

    /// Every registry board is a selectable profile: its model resolves once
    /// and its ApChipID has a SoC row.
    #[test]
    fn every_registry_board_resolves_to_a_soc_row() {
        use stela_soc_data::board;
        for (model, chip_id, ..) in BOARDS {
            assert_eq!(BOARDS.iter().filter(|board| board.0 == model).count(), 1);
            assert_eq!(Profile::of(model).unwrap().chip_id, chip_id);
            assert!(board::chip(chip_id).is_some(), "{model}");
        }
    }

    #[test]
    fn identities_are_chosen_by_board_and_restore_behavior() {
        let manifest = manifest();
        let profile = Profile::of("Mac14,3").unwrap();
        assert_eq!(identities(&manifest, &profile).len(), 3);
        let erase = identity(&manifest, &profile, Purpose::Erase).unwrap();
        assert_eq!(erase.index, 1);
        assert_eq!(
            identity(&manifest, &profile, Purpose::Update)
                .unwrap()
                .index,
            2
        );
        assert_eq!(
            identity(&manifest, &profile, Purpose::Installed)
                .unwrap()
                .index,
            3
        );
        assert_eq!(
            variant(&manifest, &profile, "macOS Customer")
                .unwrap()
                .index,
            3
        );
        let (owner, ramdisk) = component(&manifest, &profile, erase, RESTORE_RAMDISK).unwrap();
        assert_eq!((owner.index, ramdisk.path.as_str()), (1, "ramdisk.dmg"));
        let installed = identity(&manifest, &profile, Purpose::Installed).unwrap();
        // The installed set lacks the ramdisk; another identity has it.
        assert_eq!(
            component(&manifest, &profile, installed, RESTORE_RAMDISK)
                .unwrap()
                .0
                .index,
            1
        );
        let error = component(&manifest, &profile, erase, "SEP")
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "macOS 26A434 lists no SEP component for Mac14,3 (j473ap, ApChipID 0x8112, \
             ApBoardID 0x24)"
        );
        let other = Profile::of("Mac14,9").unwrap();
        let error = identity(&manifest, &other, Purpose::Erase)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("macOS 26A434 has no erase restore identity for Mac14,9"));
        assert!(variant(&manifest, &profile, "Missing").is_err());
    }
}

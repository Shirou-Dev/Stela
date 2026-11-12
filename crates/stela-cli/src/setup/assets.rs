//! The `stela.efi` this `stela` installs: the boot image `cargo xtask dist`
//! embeds in it (see `build.rs`).
use anyhow::Result;
use std::path::PathBuf;

#[cfg(stela_boot_image)]
const IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/stela.efi"));

/// The embedded image, written where setup reads its inputs from.
#[cfg(stela_boot_image)]
pub(super) fn resolve() -> Result<PathBuf> {
    let directory = std::env::temp_dir().join("Stela");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("stela.efi");
    crate::efi::write_atomic(&path, IMAGE, false)?;
    Ok(path)
}

#[cfg(not(stela_boot_image))]
pub(super) fn resolve() -> Result<PathBuf> {
    anyhow::bail!(
        "this stela was built without its boot image: build it with `cargo xtask dist`, which \
         embeds it"
    )
}

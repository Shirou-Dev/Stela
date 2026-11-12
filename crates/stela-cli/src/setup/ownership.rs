//! Stela's cache stays its user's under `sudo`. Every Unix setup that
//! writes a disk runs as root through `sudo`, and creates its downloads as
//! root; in the invoking user's own cache (macOS keeps `HOME` under
//! `sudo`), that user could then neither remove them nor go on with them
//! without `sudo`. A run as root hands back to that user what it finds
//! there when it starts and what it created when it ends ([`Handback`]),
//! and a run without root that finds root's files in its cache says how to
//! give them back.
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// The user `sudo` runs this process for: `SUDO_UID` and `SUDO_GID` when
/// the process is root (`euid` 0) and they name another user.
fn invoker(euid: u32, uid: Option<&str>, gid: Option<&str>) -> Option<(u32, u32)> {
    let uid: u32 = uid?.parse().ok()?;
    let gid: u32 = gid?.parse().ok()?;
    (euid == 0 && uid != 0).then_some((uid, gid))
}

/// Whom root's entries in a cache go to, when the cache's nearest existing
/// directory belongs to `owner`: the invoking user, when the cache is in
/// their home. Root's own cache, such as the one `sudo` gives a run on
/// Linux, stays root's.
fn heir(invoker: Option<(u32, u32)>, owner: u32) -> Option<(u32, u32)> {
    invoker.filter(|&(uid, _)| uid == owner)
}

/// The directory a run creates `cache` from: its outermost ancestor that
/// does not exist yet, so the directories created above the cache are
/// handed back too, or the cache itself.
fn created_from(cache: &Path, exists: impl Fn(&Path) -> bool) -> PathBuf {
    let mut from = cache;
    while let Some(parent) = from
        .parent()
        .filter(|p| !p.as_os_str().is_empty() && !exists(p))
    {
        from = parent;
    }
    from.to_path_buf()
}

/// What a run without root says about a cache that holds root's files.
fn foreign_text(cache: &Path) -> String {
    format!(
        "{} holds files that a setup run with sudo left owned by root, so this run cannot \
         change them. Give them back with: sudo chown -R \"$(id -un)\" \"{}\"",
        cache.display(),
        cache.display()
    )
}

/// Hands a cache back to the user `sudo` runs this process for when the
/// run starts and when it ends, on success and on error.
pub(super) struct Handback {
    caches: Vec<(PathBuf, (u32, u32))>,
}

impl Handback {
    /// As root through `sudo`: hand back what earlier runs left in
    /// `caches`, and at the end what this one created. Without root: say
    /// how to give back the root's files a cache holds.
    pub(super) fn start(caches: &[PathBuf]) -> Self {
        // SAFETY: reads this process's credentials; no pointer arguments.
        let euid = unsafe { libc::geteuid() };
        let var = |name| std::env::var(name).ok();
        let invoker = invoker(euid, var("SUDO_UID").as_deref(), var("SUDO_GID").as_deref());
        let mut kept = Vec::new();
        for cache in caches {
            let from = created_from(cache, |path| path.exists());
            let Some(owner) = from
                .ancestors()
                .find_map(|path| std::fs::symlink_metadata(path).ok())
                .map(|meta| meta.uid())
            else {
                continue;
            };
            if euid != 0 {
                if owner == euid && walk(cache, |meta| meta.uid() != euid) {
                    eprintln!("note: {}", foreign_text(cache));
                }
            } else if let Some(heir) = heir(invoker, owner) {
                hand_back(&from, heir);
                kept.push((from, heir));
            }
        }
        Self { caches: kept }
    }
}

impl Drop for Handback {
    fn drop(&mut self) {
        for (from, heir) in &self.caches {
            hand_back(from, *heir);
        }
    }
}

/// Under `sudo`, give the file this run saved at `path` (a boot log or a
/// report) to the user who ran it, when it is in a folder of theirs.
pub(crate) fn hand_to_invoker(path: &Path) {
    // SAFETY: reads this process's credentials; no pointer arguments.
    let euid = unsafe { libc::geteuid() };
    let var = |name| std::env::var(name).ok();
    let invoker = invoker(euid, var("SUDO_UID").as_deref(), var("SUDO_GID").as_deref());
    let folder = std::path::absolute(path)
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .and_then(|folder| std::fs::metadata(folder).ok());
    if let Some(heir) = folder.and_then(|meta| heir(invoker, meta.uid())) {
        hand_back(path, heir);
    }
}

/// Visit `root` and everything below it without following links, until
/// `stop` returns true for an entry: whether it did.
fn walk(root: &Path, mut stop: impl FnMut(&std::fs::Metadata) -> bool) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if stop(&meta) {
            return true;
        }
        if meta.is_dir()
            && let Ok(entries) = std::fs::read_dir(&path)
        {
            stack.extend(entries.flatten().map(|entry| entry.path()));
        }
    }
    false
}

/// Give root's entries under `root` (itself included) to `heir`. Best
/// effort: an entry it cannot change is named by the next run without
/// root.
fn hand_back(root: &Path, (uid, gid): (u32, u32)) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.uid() == 0 {
            let _ = std::os::unix::fs::lchown(&path, Some(uid), Some(gid));
        }
        if meta.is_dir()
            && let Ok(entries) = std::fs::read_dir(&path)
        {
            stack.extend(entries.flatten().map(|entry| entry.path()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_root_run_through_sudo_for_another_user_has_an_invoker() {
        assert_eq!(invoker(0, Some("1000"), Some("1001")), Some((1000, 1001)));
        assert_eq!(invoker(1000, Some("1000"), Some("1000")), None);
        assert_eq!(invoker(0, Some("0"), Some("0")), None);
        assert_eq!(invoker(0, None, Some("1000")), None);
        assert_eq!(invoker(0, Some("x"), Some("1000")), None);
    }

    #[test]
    fn a_cache_goes_back_only_to_the_user_whose_home_holds_it() {
        let user = Some((1000, 1000));
        assert_eq!(heir(user, 1000), user);
        // Root's own cache, and another user's.
        assert_eq!(heir(user, 0), None);
        assert_eq!(heir(user, 1002), None);
        assert_eq!(heir(None, 1000), None);
    }

    #[test]
    fn the_directories_created_above_the_cache_are_handed_back_too() {
        let cache = Path::new("/home/u/.cache/stela");
        let existing = |paths: &'static [&'static str]| {
            move |path: &Path| paths.iter().any(|p| Path::new(p) == path)
        };
        assert_eq!(
            created_from(cache, existing(&["/", "/home", "/home/u"])),
            Path::new("/home/u/.cache")
        );
        assert_eq!(
            created_from(
                cache,
                existing(&["/", "/home", "/home/u", "/home/u/.cache"])
            ),
            cache
        );
        assert_eq!(
            created_from(Path::new("stela-cache"), existing(&[])),
            Path::new("stela-cache")
        );
    }

    #[test]
    fn a_run_without_root_names_the_command_that_gives_the_files_back() {
        let text = foreign_text(Path::new("/home/u/.cache/stela"));
        assert!(
            text.ends_with("sudo chown -R \"$(id -un)\" \"/home/u/.cache/stela\""),
            "{text}"
        );
        // This user's own files are never foreign to it.
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("images")).unwrap();
        std::fs::write(temp.path().join("images/a.ipsw"), b"x").unwrap();
        let me = std::fs::metadata(temp.path()).unwrap().uid();
        assert!(!walk(temp.path(), |meta| meta.uid() != me));
    }
}

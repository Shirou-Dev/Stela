//! The Stela version a stick was made or last updated with, which its record
//! keeps (`Record::release`) so messages can say older or newer. Records
//! written before 0.4 name none: such a stick is older than any stela that
//! reads this. `update::version_id` stays the stela.efi integrity hash.
use super::{Environment, Record};
use anyhow::Result;
use std::cmp::Ordering;

/// This stela's version.
pub(super) const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// `a` against `b`, by their numeric dot-separated parts; a pre-release
/// suffix (`0.4.0-rc.1`) is left out.
pub(super) fn compare(a: &str, b: &str) -> Ordering {
    let parts = |version: &str| -> Vec<u64> {
        version
            .split(['-', '+'])
            .next()
            .unwrap_or_default()
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .collect()
    };
    let (a, b) = (parts(a), parts(b));
    let length = a.len().max(b.len());
    let pad = |mut v: Vec<u64>| {
        v.resize(length, 0);
        v
    };
    pad(a).cmp(&pad(b))
}

/// The version of a stick made by a newer stela than this one.
pub(super) fn newer(record: &Record) -> Option<String> {
    record
        .release
        .clone()
        .filter(|version| compare(version, CURRENT) == Ordering::Greater)
}

/// Before this older stela changes `record`'s stick (`doing`, such as "put
/// the older Stela on it"): ask on a terminal, accept with `--yes`, and
/// refuse otherwise, changing nothing.
pub(super) fn allow_older(
    environment: &Environment<'_>,
    record: &Record,
    yes: bool,
    doing: &str,
) -> Result<()> {
    let Some(theirs) = newer(record) else {
        return Ok(());
    };
    super::consent(
        environment,
        yes,
        &format!(
            "This stick has Stela {theirs}, newer than this stela ({CURRENT}). {}?",
            capitalized(doing)
        ),
        &format!(
            "this stick has Stela {theirs}, newer than this stela ({CURRENT}): use stela \
             {theirs} or newer"
        ),
    )
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// `stela status`'s line for `record`'s Stela version.
pub(super) fn describe(record: &Record) -> String {
    match &record.release {
        Some(version) => match compare(version, CURRENT) {
            Ordering::Equal => format!("Stela {version}"),
            Ordering::Less => format!("Stela {version}; this stela is {CURRENT}"),
            Ordering::Greater => format!("Stela {version}, newer than this stela ({CURRENT})"),
        },
        None => format!("Stela 0.3 or older; this stela is {CURRENT}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_their_numbers() {
        assert_eq!(compare("0.3.0", "0.4.0"), Ordering::Less);
        assert_eq!(compare("0.10.0", "0.9.9"), Ordering::Greater);
        assert_eq!(compare("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare("0.4.0-rc.1", "0.4.0"), Ordering::Equal);
    }
}

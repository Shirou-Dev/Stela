//! The complete macOS release/model catalog; image bytes still come from Apple.
use super::{Image, apple_url};
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeMap, io::Read, time::Duration};

const URL: &str = "https://api.ipsw.me/v3/firmwares.json/condensed";

#[derive(Deserialize)]
struct Catalog {
    devices: BTreeMap<String, Device>,
}

#[derive(Deserialize)]
struct Device {
    name: String,
    firmwares: Vec<Firmware>,
}

#[derive(Deserialize)]
struct Firmware {
    version: String,
    buildid: String,
    url: String,
    sha1sum: Option<String>,
    #[serde(default)]
    signed: bool,
}

pub(super) struct Releases {
    pub images: Vec<Image>,
}

pub(super) fn load() -> Result<Releases> {
    // One condensed request contains every model and historical release.
    // Avoid one request per model, or downloading any IPSW to discover versions.
    // A connection may take a slow resolver, or a fallback from IPv6 to
    // IPv4, beyond a few seconds.
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("stela/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = crate::net::send("loading the list of macOS releases (api.ipsw.me)", || {
        client.get(URL)
    })?
    .error_for_status()?;
    let mut bytes = Vec::new();
    response
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        "IPSW.me catalog exceeds 32 MiB"
    );
    parse(&bytes)
}

fn parse(bytes: &[u8]) -> Result<Releases> {
    let catalog: Catalog = serde_json::from_slice(bytes).map_err(|error| {
        // A network that wants a sign-in first answers with its own page.
        let page = bytes.trim_ascii_start().starts_with(b"<");
        anyhow::anyhow!(
            "the list of macOS releases from api.ipsw.me cannot be read ({error}){}",
            if page {
                "; the network answered with a web page instead, as one that wants a sign-in \
                 first does: sign in to the network and run setup again"
            } else {
                ""
            }
        )
    })?;
    let mut images: BTreeMap<(String, String), Image> = BTreeMap::new();
    for (model, device) in catalog.devices {
        if !model.starts_with("Mac") && !model.starts_with("iMac") {
            continue;
        }
        if device.name.to_ascii_lowercase().contains("virtual") {
            continue;
        }
        for firmware in device.firmwares {
            if !firmware.signed {
                continue;
            }
            ensure!(
                apple_url(&reqwest::Url::parse(&firmware.url)?),
                "IPSW.me supplied an image outside Apple's HTTPS servers"
            );
            let sha1 = firmware
                .sha1sum
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_lowercase());
            ensure!(
                sha1.as_ref()
                    .is_none_or(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())),
                "IPSW.me supplied an invalid image digest"
            );
            let image = images
                .entry((firmware.buildid.clone(), firmware.url.clone()))
                .or_insert(Image {
                    version: firmware.version.clone(),
                    build: firmware.buildid,
                    models: Vec::new(),
                    url: firmware.url,
                    sha1: sha1.clone(),
                });
            ensure!(
                image.version == firmware.version && image.sha1 == sha1,
                "conflicting IPSW.me image metadata"
            );
            image.models.push(model.clone());
        }
    }
    ensure!(!images.is_empty(), "IPSW.me lists no macOS images");
    for image in images.values_mut() {
        image.models.sort();
        image.models.dedup();
    }
    Ok(Releases {
        images: images.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(url: &str) -> Vec<u8> {
        let firmware = serde_json::json!({"version":"11.0.1", "buildid":"20B29", "url":url, "sha1sum":"a".repeat(40), "signed":true});
        serde_json::to_vec(&serde_json::json!({"devices": {
            "Macmini9,1": {"name":"Mac mini (M1)", "firmwares":[firmware.clone()]},
            "MacBookAir10,1": {"name":"MacBook Air (M1)", "firmwares":[firmware.clone()]},
            "VirtualMac2,1": {"name":"VirtualMac", "firmwares":[firmware.clone()]},
            "iPhone1,1": {"name":"iPhone", "firmwares":[firmware]}
        }}))
        .unwrap()
    }

    #[test]
    fn signed_historical_versions_keep_their_physical_models() -> Result<()> {
        let images = parse(&fixture("https://updates.cdn-apple.com/old.ipsw"))?.images;
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].version, "11.0.1");
        assert_eq!(images[0].models, ["MacBookAir10,1", "Macmini9,1"]);
        Ok(())
    }

    #[test]
    fn a_web_page_instead_of_the_list_is_named() {
        let error = parse(b"\n<html><body>Sign in</body></html>")
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("answered with a web page"), "{error}");
        let error = parse(b"{\"devices\": 1}").err().unwrap().to_string();
        assert!(!error.contains("web page"), "{error}");
    }

    #[test]
    fn unsigned_releases_are_excluded() -> Result<()> {
        let mut catalog: serde_json::Value =
            serde_json::from_slice(&fixture("https://updates.cdn-apple.com/old.ipsw"))?;
        catalog["devices"]["Macmini9,1"]["firmwares"][0]["signed"] = false.into();
        let images = parse(&serde_json::to_vec(&catalog)?)?.images;
        assert_eq!(images[0].models, ["MacBookAir10,1"]);
        Ok(())
    }

    #[test]
    fn historical_metadata_never_authorizes_third_party_image_downloads() {
        for url in [
            "https://mirror.example.test/old.ipsw",
            "http://updates.cdn-apple.com/old.ipsw",
            "https://updates.cdn-apple.com.example.test/old.ipsw",
        ] {
            assert!(parse(&fixture(url)).is_err(), "{url}");
        }
    }
}

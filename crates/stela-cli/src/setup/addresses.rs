//! The mount network's addresses set by hand (`--ipv4`, `--gateway`,
//! `--dns`). Without them `stela.efi` takes DHCP's and IPv6
//! autoconfiguration's.
use super::{Request, ui::Ui};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use stela_boot_core::options::{self, StaticIpv4, System};

/// The addresses a setup's record keeps; empty when automatic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Addresses {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ipv4: Option<Ipv4>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) dns: Vec<IpAddr>,
}

/// A static IPv4 address, its prefix length and its default router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Ipv4 {
    pub(super) address: Ipv4Addr,
    pub(super) prefix: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) gateway: Option<Ipv4Addr>,
}

impl Ipv4 {
    /// `ipv4` with `gateway`, which must be another address of its subnet.
    pub(super) fn new(ipv4: StaticIpv4, gateway: Option<Ipv4Addr>) -> Result<Self> {
        if let Some(gateway) = gateway {
            ensure!(
                ipv4.neighbors(gateway),
                "--ipv4-gateway {gateway} is not another address of {ipv4}'s subnet"
            );
        }
        Ok(Self {
            address: ipv4.address,
            prefix: ipv4.prefix,
            gateway,
        })
    }
}

impl Addresses {
    pub(super) fn is_automatic(&self) -> bool {
        self.ipv4.is_none() && self.dns.is_empty()
    }

    /// The addresses `request` sets on a new setup.
    pub(super) fn requested(request: &Request) -> Result<Self> {
        Ok(Self {
            ipv4: request
                .ipv4
                .map(|ipv4| Ipv4::new(ipv4, request.ipv4_gateway))
                .transpose()?,
            dns: request.dns.clone().unwrap_or_default(),
        })
    }

    /// Write them into the option line `system`.
    pub(super) fn apply(&self, system: &mut System) {
        system.ipv4 = self.ipv4.map(|ipv4| StaticIpv4 {
            address: ipv4.address,
            prefix: ipv4.prefix,
        });
        system.ipv4_gateway = self.ipv4.and_then(|ipv4| ipv4.gateway);
        system.dns = self.dns.clone();
    }

    /// The report lines that describe them; none when automatic.
    pub(super) fn describe(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(ipv4) = self.ipv4 {
            lines.push(format!(
                "{:<14} {}/{}{}, not from DHCP",
                "IPv4",
                ipv4.address,
                ipv4.prefix,
                ipv4.gateway
                    .map(|gateway| format!(" via {gateway}"))
                    .unwrap_or_default()
            ));
        }
        if !self.dns.is_empty() {
            lines.push(format!("{:<14} {}", "DNS", servers_text(&self.dns)));
        }
        lines
    }
}

fn servers_text(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `--ipv4`'s value.
pub(super) fn ipv4(word: &str) -> Result<StaticIpv4, String> {
    StaticIpv4::parse(word)
        .ok_or_else(|| "an IPv4 host address and prefix length, such as 192.168.1.20/24".into())
}

/// `--dns`'s value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Servers(pub(super) Vec<IpAddr>);

pub(super) fn servers(word: &str) -> Result<Servers, String> {
    options::dns_servers(word).map(Servers).ok_or_else(|| {
        format!(
            "1 to {} distinct server addresses separated by commas, such as 1.1.1.1,9.9.9.9",
            options::MAX_DNS_SERVERS
        )
    })
}

/// The network addresses step: automatic, or a static IPv4 address with
/// its router and DNS servers.
pub(super) fn choose(ui: &dyn Ui, request: &mut Request) -> Result<()> {
    let rows = super::ui::rows(&[
        ("Automatic", "DHCP and IPv6 autoconfiguration"),
        ("Static IPv4", "Type the address, router and DNS servers"),
    ]);
    let manual = ui.select(
        "Network addresses",
        &rows,
        usize::from(request.ipv4.is_some()),
    )? == 1;
    if !manual {
        (request.ipv4, request.ipv4_gateway, request.dns) = (None, None, None);
        return Ok(());
    }
    let typed = ui.input(
        "IPv4 address and prefix length",
        "192.168.1.20/24",
        &request
            .ipv4
            .map(|ipv4| ipv4.to_string())
            .unwrap_or_default(),
        Box::new(|word: &str| ipv4(word).map(|_| ())),
    )?;
    let address = ipv4(&typed).map_err(anyhow::Error::msg)?;
    let typed = ui.input(
        "Router",
        "192.168.1.1",
        &request
            .ipv4_gateway
            .map(|gateway| gateway.to_string())
            .unwrap_or_default(),
        Box::new(move |word: &str| match word.parse::<Ipv4Addr>() {
            Ok(gateway) if address.neighbors(gateway) => Ok(()),
            _ => Err(format!("another IPv4 address of {address}'s subnet")),
        }),
    )?;
    let gateway: Ipv4Addr = typed.parse()?;
    let typed = ui.input(
        "DNS servers",
        "1.1.1.1,9.9.9.9",
        &request
            .dns
            .as_deref()
            .map(servers_text_plain)
            .unwrap_or_default(),
        Box::new(|word: &str| servers(word).map(|_| ())),
    )?;
    request.ipv4 = Some(address);
    request.ipv4_gateway = Some(gateway);
    request.dns = Some(servers(&typed).map_err(anyhow::Error::msg)?.0);
    Ok(())
}

/// Servers as they are typed: comma-separated.
fn servers_text_plain(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// The addresses a request sets, in a few words for Review.
pub(super) fn summary(request: &Request) -> String {
    match request.ipv4 {
        Some(ipv4) => format!(
            "address {ipv4}{}{}",
            request
                .ipv4_gateway
                .map(|gateway| format!(" via {gateway}"))
                .unwrap_or_default(),
            request
                .dns
                .as_deref()
                .map(|dns| format!(", DNS {}", servers_text(dns)))
                .unwrap_or_default()
        ),
        None => "automatic addresses".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateways_stay_in_their_subnet_and_lines_describe_the_choice() {
        let ipv4 = StaticIpv4::parse("192.168.1.20/24").unwrap();
        assert!(Ipv4::new(ipv4, Some(Ipv4Addr::new(192, 168, 2, 1))).is_err());
        let addresses = Addresses {
            ipv4: Some(Ipv4::new(ipv4, Some(Ipv4Addr::new(192, 168, 1, 1))).unwrap()),
            dns: servers("1.1.1.1,9.9.9.9").unwrap().0,
        };
        assert_eq!(
            addresses.describe(),
            [
                "IPv4           192.168.1.20/24 via 192.168.1.1, not from DHCP",
                "DNS            1.1.1.1, 9.9.9.9"
            ]
        );
        let mut system = System::default();
        addresses.apply(&mut system);
        assert_eq!(
            system.to_string(),
            "--system --ipv4 192.168.1.20/24 --ipv4-gateway 192.168.1.1 --dns 1.1.1.1,9.9.9.9"
        );
        assert!(Addresses::default().is_automatic());
        assert!(servers("1.1.1.1,1.1.1.1").is_err());
    }
}

//! DHCPv4/SLAAC admission, DAD and router-advertised DNS on one interface.
use super::*;
#[derive(Debug, Clone)]
pub struct Automatic {
    pub addresses: Vec<IpCidr>,
    pub dns: Vec<IpAddress>,
}

pub(super) fn link_local(mac: [u8; 6]) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes[..2].copy_from_slice(&[0xfe, 0x80]);
    bytes[8..].copy_from_slice(&[
        mac[0] ^ 2,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]);
    Ipv6Addr::from(bytes)
}
impl<L: Link, C: Clock> Stack<L, C> {
    pub(super) fn update_dns(&mut self) -> Result<(), NetError> {
        let servers = match &self.fixed_dns {
            Some(servers) => servers.clone(),
            None => {
                let mut servers: Vec<IpAddress> = self
                    .config
                    .iter()
                    .flat_map(|config| config.dns.iter().copied().map(IpAddress::Ipv4))
                    .collect();
                let now = self.now()?;
                for server in self.phy.rdnss.servers(now) {
                    let address = IpAddress::Ipv6(server);
                    if !servers.contains(&address) {
                        servers.push(address);
                    }
                }
                servers
            }
        };
        if servers != self.dns_servers {
            self.sockets
                .get_mut::<dns::Socket>(self.dns)
                .update_servers(&servers);
            self.dns_servers = servers;
        }
        Ok(())
    }
    pub(super) fn ipv6_ready(&self) -> bool {
        self.iface.routes().get_default_ipv6_route().is_some()
            && self.iface.ip_addrs().iter().any(|cidr| match cidr {
                IpCidr::Ipv6(cidr) => {
                    !cidr.address().is_unicast_link_local()
                        && self.phy.approved_ipv6.contains(&cidr.address())
                }
                _ => false,
            })
    }
    pub(super) fn address_usable(&self, address: IpAddress) -> bool {
        match address {
            IpAddress::Ipv4(_) => self.config.is_some(),
            IpAddress::Ipv6(address) => {
                if address.is_unicast_link_local() {
                    self.phy.approved_ipv6.contains(&self.phy.local_ipv6)
                } else {
                    self.ipv6_ready()
                }
            }
        }
    }
    pub(super) fn probe_ipv6(&mut self) -> Result<(), NetError> {
        // Prefix withdrawal/expiry must also retire admission. Otherwise a
        // later reuse of the address could bypass its new DAD interval.
        self.phy.approved_ipv6.retain(|address| {
            self.iface
                .ip_addrs()
                .iter()
                .any(|cidr| matches!(cidr, IpCidr::Ipv6(cidr) if cidr.address() == *address))
        });
        let now = self.now()?;
        let mut completed = Vec::new();
        self.phy.probes.retain(|probe| {
            if !self
                .iface
                .ip_addrs()
                .iter()
                .any(|cidr| matches!(cidr, IpCidr::Ipv6(cidr) if cidr.address() == probe.address))
            {
                return false;
            }
            if probe.duplicate || now >= probe.until {
                completed.push((probe.address, probe.duplicate));
                false
            } else {
                true
            }
        });
        for (address, duplicate) in completed {
            if duplicate {
                if self.conflicts.len() >= 64 {
                    return Err(NetError::Invalid("IPv6 conflict inventory capacity"));
                }
                self.conflicts.push(address);
            } else {
                self.phy.approved_ipv6.push(address);
            }
        }
        let candidates: Vec<_> = self
            .iface
            .ip_addrs()
            .iter()
            .filter_map(|cidr| match cidr {
                IpCidr::Ipv6(cidr)
                    if !self.phy.approved_ipv6.contains(&cidr.address())
                        && !self.conflicts.contains(&cidr.address())
                        && !self
                            .phy
                            .probes
                            .iter()
                            .any(|probe| probe.address == cidr.address()) =>
                {
                    Some(cidr.address())
                }
                _ => None,
            })
            .collect();
        for address in candidates {
            if address != self.phy.local_ipv6
                && !self.phy.approved_ipv6.contains(&self.phy.local_ipv6)
            {
                continue;
            }
            self.probe_nonce = self.probe_nonce.wrapping_add(1);
            let mut nonce = [0; 6];
            nonce.copy_from_slice(&self.probe_nonce.to_le_bytes()[..6]);
            self.phy
                .link
                .transmit(&dad::solicitation(self.phy.link.mac().0, address, nonce))?;
            // DAD is asynchronous: every normal poll still services DHCP,
            // DNS/TCP, router lifetimes and unrelated received frames.
            let until = self.now()?.saturating_add(1_000_000);
            self.phy.probes.push(dad::Probe {
                address,
                nonce,
                // Link admission/queue contention may have consumed time before
                // publication. Keep the full DAD interval after transmit returns.
                until,
                duplicate: false,
            });
        }
        // Updating even an unchanged address list flushes smoltcp's ARP/ND
        // cache. Change it only for a rejected global candidate; a
        // normal poll must not disrupt unrelated established TCP connections.
        let remove = self.iface.ip_addrs().iter().any(|cidr| {
            matches!(cidr, IpCidr::Ipv6(cidr) if cidr.address() != self.phy.local_ipv6 && self.conflicts.contains(&cidr.address()))
        });
        if remove {
            self.iface.update_ip_addrs(|addresses| {
                addresses.retain(|cidr| match cidr {
                    IpCidr::Ipv6(cidr) => {
                        cidr.address() == self.phy.local_ipv6
                            || !self.conflicts.contains(&cidr.address())
                    }
                    _ => true,
                })
            });
        }
        Ok(())
    }
    /// Configure DHCPv4 and IPv6 SLAAC together. IPv6 is admitted after DAD
    /// and a router advertisement; DNS also accepts RFC8106 RDNSS lifetimes.
    /// Stateful DHCPv6 is not implemented.
    pub fn automatic(&mut self) -> Result<Automatic, NetError> {
        self.automatic_waiting(|_| {})
    }

    /// [`Self::automatic`], telling `waiting` each whole second it has
    /// waited for the link's carrier so far.
    pub fn automatic_waiting(
        &mut self,
        mut waiting: impl FnMut(u64),
    ) -> Result<Automatic, NetError> {
        self.await_carrier(&mut waiting)?;
        let deadline = self.now()?.saturating_add(DHCP_WAIT_US);
        loop {
            self.poll()?;
            if self.config.is_some() || self.ipv6_ready() {
                return Ok(Automatic {
                    addresses: self
                        .iface
                        .ip_addrs()
                        .iter()
                        .filter(|cidr| match cidr {
                            IpCidr::Ipv4(_) => true,
                            IpCidr::Ipv6(cidr) => self.phy.approved_ipv6.contains(&cidr.address()),
                        })
                        .copied()
                        .collect(),
                    dns: self.dns_servers.clone(),
                });
            }
            if self.now()? >= deadline {
                if let Some(address) = self.conflicts.first() {
                    return Err(NetError::DuplicateAddress(*address));
                }
                return Err(NetError::Dhcp(
                    "no DHCPv4 lease or usable IPv6 router advertisement within 60 seconds; stateful DHCPv6 is unsupported",
                ));
            }
            self.wait_until(deadline)?;
        }
    }
}
pub(super) fn authority(host: &str) -> Result<(&str, u16), NetError> {
    if let Some(rest) = host.strip_prefix('[') {
        let (address, suffix) = rest
            .split_once(']')
            .ok_or(NetError::Invalid("IPv6 authority"))?;
        address
            .parse::<Ipv6Addr>()
            .map_err(|_| NetError::Invalid("IPv6 authority"))?;
        let port = if suffix.is_empty() {
            80
        } else {
            suffix
                .strip_prefix(':')
                .ok_or(NetError::Invalid("IPv6 port"))?
                .parse()
                .map_err(|_| NetError::Invalid("HTTP port"))?
        };
        return Ok((address, port));
    }
    if host.parse::<Ipv6Addr>().is_ok() {
        return Ok((host, 80));
    }
    match host.rsplit_once(':') {
        Some((name, port)) => Ok((
            name,
            port.parse().map_err(|_| NetError::Invalid("HTTP port"))?,
        )),
        None => Ok((host, 80)),
    }
}
#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    #[test]
    fn ipv6_permissions_keep_address_and_port_separate() {
        assert_eq!(
            authority("[2001:db8::1]:8080").unwrap(),
            ("2001:db8::1", 8080)
        );
        assert_eq!(authority("2001:db8::1").unwrap(), ("2001:db8::1", 80));
        assert_eq!(authority("host:8080").unwrap(), ("host", 8080));
        for host in ["[::1", "[::1]x", "[::1]:oops"] {
            assert!(authority(host).is_err());
        }
    }
    struct ClockStep(core::cell::Cell<u64>);
    impl Clock for ClockStep {
        fn now_us(&self) -> Result<u64, ClockError> {
            let now = self.0.get() + 10_000;
            self.0.set(now);
            Ok(now)
        }
    }
    struct Router {
        frames: VecDeque<Vec<u8>>,
        probes: usize,
    }
    impl Link for Router {
        fn mac(&self) -> stela_drivers::net::Mac {
            stela_drivers::net::Mac([2, 0, 0, 0, 0, 2])
        }
        fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
            if frame.len() >= 62 && frame[12..14] == [0x86, 0xdd] && frame[20] == 58 {
                if frame[54] == 135 {
                    self.probes += 1;
                }
                if frame[54] == 133 {
                    self.frames.push_back(advertisement());
                }
            }
            Ok(())
        }
        fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
            Ok(self.frames.pop_front())
        }
    }
    pub(crate) fn advertisement() -> Vec<u8> {
        let source: Ipv6Addr = "fe80::1".parse().unwrap();
        let destination: Ipv6Addr = "ff02::1".parse().unwrap();
        let prefix: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let dns: Ipv6Addr = "2001:db8:1234::53".parse().unwrap();
        let mut frame = vec![0; 14 + 40 + 72];
        frame[..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[12..14].copy_from_slice(&[0x86, 0xdd]);
        let ip = &mut frame[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&72u16.to_be_bytes());
        ip[6] = 58;
        ip[7] = 255;
        ip[8..24].copy_from_slice(&source.octets());
        ip[24..40].copy_from_slice(&destination.octets());
        let icmp = &mut ip[40..];
        icmp[0] = 134;
        icmp[4] = 64;
        icmp[6..8].copy_from_slice(&600u16.to_be_bytes());
        let pi = &mut icmp[16..48];
        pi[0] = 3;
        pi[1] = 4;
        pi[2] = 64;
        pi[3] = 0xc0;
        pi[4..8].copy_from_slice(&600u32.to_be_bytes());
        pi[8..12].copy_from_slice(&300u32.to_be_bytes());
        pi[16..32].copy_from_slice(&prefix.octets());
        let dns_option = &mut icmp[48..72];
        dns_option[0] = 25;
        dns_option[1] = 3;
        dns_option[4..8].copy_from_slice(&600u32.to_be_bytes());
        dns_option[8..24].copy_from_slice(&dns.octets());
        let sum = rdnss::checksum(source, destination, icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        frame
    }
    #[test]
    fn dad_wait_starts_after_the_solicitation_is_transmitted() {
        use alloc::rc::Rc;
        use core::cell::Cell;
        struct LogicalClock(Rc<Cell<u64>>);
        impl Clock for LogicalClock {
            fn now_us(&self) -> Result<u64, ClockError> {
                Ok(self.0.get())
            }
        }
        struct DelayedLink {
            now: Rc<Cell<u64>>,
            transmissions: usize,
        }
        impl Link for DelayedLink {
            fn mac(&self) -> stela_drivers::net::Mac {
                stela_drivers::net::Mac([2, 0, 0, 0, 0, 2])
            }
            fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
                assert_eq!(frame[54], 135);
                self.transmissions += 1;
                // A real link may wait for its root/queue owner before the
                // solicitation is published, consuming the earlier deadline.
                self.now.set(self.now.get() + 2_000_000);
                Ok(())
            }
            fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
                Ok(None)
            }
        }
        let now = Rc::new(Cell::new(0));
        let mut stack = Stack::new(
            DelayedLink {
                now: now.clone(),
                transmissions: 0,
            },
            LogicalClock(now.clone()),
            7,
        )
        .unwrap();
        stack.probe_ipv6().unwrap();
        assert_eq!(now.get(), 2_000_000);
        stack.probe_ipv6().unwrap();
        assert!(stack.phy.approved_ipv6.is_empty());
        now.set(2_999_999);
        stack.probe_ipv6().unwrap();
        assert!(stack.phy.approved_ipv6.is_empty());
        now.set(3_000_000);
        stack.probe_ipv6().unwrap();
        assert_eq!(stack.phy.approved_ipv6, [stack.phy.local_ipv6]);
        assert_eq!(stack.phy.link.transmissions, 1);
    }
    /// A link whose carrier comes up at `up_us` on a clock that advances
    /// 10 ms per reading, and that may take `wait_us` to bring it up.
    struct LateCarrier {
        now: alloc::rc::Rc<core::cell::Cell<u64>>,
        up_us: u64,
        wait_us: u64,
    }
    impl Link for LateCarrier {
        fn mac(&self) -> stela_drivers::net::Mac {
            stela_drivers::net::Mac([2, 0, 0, 0, 0, 2])
        }
        fn carrier(&mut self) -> bool {
            self.now.get() >= self.up_us
        }
        fn carrier_wait_us(&self) -> u64 {
            self.wait_us
        }
        fn transmit(&mut self, _: &[u8]) -> Result<(), LinkError> {
            Ok(())
        }
        fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
            Ok(None)
        }
    }
    struct SharedStep(alloc::rc::Rc<core::cell::Cell<u64>>);
    impl Clock for SharedStep {
        fn now_us(&self) -> Result<u64, ClockError> {
            let now = self.0.get() + 10_000;
            self.0.set(now);
            Ok(now)
        }
    }
    fn late_carrier(up_us: u64, wait_us: u64) -> (Result<(), NetError>, Vec<u64>, u64) {
        let now = alloc::rc::Rc::new(core::cell::Cell::new(0));
        let link = LateCarrier {
            now: now.clone(),
            up_us,
            wait_us,
        };
        let mut stack = Stack::new(link, SharedStep(now.clone()), 7).unwrap();
        let start = now.get();
        let mut seconds = Vec::new();
        let result = stack.await_carrier(&mut |second| seconds.push(second));
        (result, seconds, now.get() - start)
    }
    #[test]
    fn a_wired_link_gets_ten_seconds_for_carrier_and_is_taken_when_it_comes() {
        // A 10GBASE-T link up after 7 s is used at once, each second told.
        let (result, seconds, elapsed) =
            late_carrier(7_000_000, stela_drivers::net::WIRED_CARRIER_WAIT_US);
        assert_eq!(result, Ok(()));
        assert_eq!(seconds, [1, 2, 3, 4, 5, 6]);
        assert!(elapsed < 7_000_000, "{elapsed}");
        // No cable: no carrier after the link's whole wait, never sooner.
        let (result, seconds, elapsed) = late_carrier(u64::MAX, 10_000_000);
        assert_eq!(result, Err(NetError::NoCarrier));
        assert_eq!(seconds.last(), Some(&9));
        assert!((10_000_000..10_100_000).contains(&elapsed), "{elapsed}");
        // A link that says it needs longer (Wi-Fi) is waited for longer.
        let (result, _, elapsed) = late_carrier(30_000_000, 45_000_000);
        assert_eq!(result, Ok(()));
        assert!((29_000_000..30_000_000).contains(&elapsed), "{elapsed}");
    }
    /// A link with carrier whose device is gone: every receive fails.
    struct Gone(alloc::rc::Rc<core::cell::Cell<u32>>);
    impl Link for Gone {
        fn mac(&self) -> stela_drivers::net::Mac {
            stela_drivers::net::Mac([2, 0, 0, 0, 0, 3])
        }
        fn transmit(&mut self, _: &[u8]) -> Result<(), LinkError> {
            Ok(())
        }
        fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
            self.0.set(self.0.get() + 1);
            Err(LinkError::Adapter("device removed".into()))
        }
    }
    #[test]
    fn a_receive_error_means_the_device_is_gone_and_ends_the_setup_at_once() {
        let receives = alloc::rc::Rc::new(core::cell::Cell::new(0));
        let now = alloc::rc::Rc::new(core::cell::Cell::new(0));
        let mut stack = Stack::new(Gone(receives.clone()), SharedStep(now.clone()), 7).unwrap();
        let result = stack.automatic();
        assert_eq!(
            result.map(|_| ()),
            Err(NetError::Link("device removed".into()))
        );
        // One receive, not a dead link polled to the DHCP deadline.
        assert_eq!(receives.get(), 1);
        assert!(now.get() < 1_000_000, "{}", now.get());
    }
    #[test]
    fn addresses_and_servers_set_by_hand_replace_dhcp_and_advertised_dns() {
        let router = Router {
            frames: VecDeque::new(),
            probes: 0,
        };
        let mut stack = Stack::new(router, ClockStep(core::cell::Cell::new(0)), 7).unwrap();
        let address = core::net::Ipv4Addr::new(192, 168, 1, 20);
        stack
            .set_ipv4(address, 24, Some(core::net::Ipv4Addr::new(192, 168, 1, 1)))
            .unwrap();
        stack.set_dns(&["9.9.9.9".parse().unwrap()]).unwrap();
        let configuration = stack.automatic().unwrap();
        assert!(
            configuration
                .addresses
                .contains(&IpCidr::Ipv4(Ipv4Cidr::new(address, 24)))
        );
        // The router's advertised RDNSS server does not displace the fixed one.
        for _ in 0..200 {
            stack.poll().unwrap();
        }
        assert_eq!(
            stack.dns_servers,
            [IpAddress::Ipv4(core::net::Ipv4Addr::new(9, 9, 9, 9))]
        );
    }
    #[test]
    fn ipv6_only_link_uses_real_router_advertisement_and_dad() {
        let router = Router {
            frames: VecDeque::new(),
            probes: 0,
        };
        let mut stack = Stack::new(router, ClockStep(core::cell::Cell::new(0)), 7).unwrap();
        let configuration = stack.automatic().unwrap();
        assert!(stack.config().is_none());
        assert!(configuration.addresses.iter().any(|address|matches!(address,IpCidr::Ipv6(cidr) if !cidr.address().is_unicast_link_local())));
        assert!(
            configuration
                .dns
                .contains(&IpAddress::Ipv6("2001:db8:1234::53".parse().unwrap()))
        );
        assert!(stack.phy.link.probes >= 2);
    }
}

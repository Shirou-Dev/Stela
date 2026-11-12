// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//! The software connection manager for USB4 hosts whose firmware runs none:
//! Linux tb.c over the routers, paths and tunnels of its submodules.
//!
//! Linux writes this as a sequence of blocking configuration accesses under
//! one lock, and so does this: an `async` task, polled by its owner, for which
//! every access is a suspension point. The task owns the domain, so a plug
//! event waits its turn behind the job in progress.
//!
//! Tunnels: USB3 for every router that can have one, DisplayPort between free
//! adapters, and PCIe where [`Platform::admit_pcie`] allows it. CL states,
//! asymmetric links, DisplayPort bandwidth allocation mode, redrive mode and
//! host-to-host links are not implemented and are reported once.
use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::{
    fmt,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Poll,
};

mod bus;
mod legacy;
mod path;
mod regs;
mod router;
mod tmu;
mod tunnel;

pub use bus::Transport;
pub use tunnel::Protocol;

use super::{channel, config::PlugEvent, drom};
use crate::stepped::{poll_once, yield_now};
use bus::Incoming;
use path::Adapter;
use regs::*;
use router::{Kind, Router, beneath, depth, downstream, parent, port_at};
use tunnel::{Bandwidth, Tunnel};

/// How often a DisplayPort tunnel's DPRX negotiation is looked at.
const DPRX_POLL_MS: u64 = 50;

/// Why an operation on the domain did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The control path itself failed: the connection manager stops.
    Channel(channel::Error),
    /// No reply through all attempts.
    Timeout,
    /// An adapter with no configuration space.
    NotImplemented,
    /// The lane is locked.
    Locked,
    /// Nothing is connected on a port the request had to cross.
    NotConnected,
    /// The router refused with this error code.
    Controller(u8),
    /// A reply of the wrong shape.
    Reply,
    /// The router has no such operation.
    Unsupported,
    /// The domain has no such router or adapter, or is too deep.
    Topology,
    TooDeep,
    /// The DROM cannot be understood.
    Drom(drom::Error),
    /// A Thunderbolt 3 router, which this connection manager does not enumerate.
    Legacy,
    NoHopId,
    NoCredits,
    NoBandwidth,
    Busy,
}

impl Error {
    /// The router behind this request went away.
    fn gone(self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::NotConnected | Self::NotImplemented
        )
    }
}

impl From<channel::Error> for Error {
    fn from(error: channel::Error) -> Self {
        Self::Channel(error)
    }
}

/// A router's unique identity, as `/sys/bus/thunderbolt` shows it.
pub use stela_contracts::uuid::Uuid;

/// Why a router's PCIe tunnel was or was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// DMA remapping keeps the device from memory it was not given.
    Isolated,
    /// The boot configuration names this router.
    Listed,
    /// Neither.
    Refused,
}

/// What the connection manager needs of its host.
pub trait Platform {
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64;
    fn report(&mut self, report: Report);
    /// Whether a device router's PCIe tunnel may be set up, which lets it DMA.
    fn admit_pcie(&self, uuid: Uuid) -> Admission;
}

/// Something the connection manager did or could not do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Report {
    Ready,
    RouterAdded {
        route: u64,
        name: Option<String>,
        vendor: u16,
        device: u16,
        generation: u8,
        version: u8,
        uuid: Uuid,
        speed: u32,
        width: u32,
    },
    RouterRemoved {
        route: u64,
    },
    TunnelUp {
        protocol: Protocol,
        source: Adapter,
        destination: Adapter,
    },
    TunnelDown {
        protocol: Protocol,
        source: Adapter,
        destination: Adapter,
    },
    Admission {
        route: u64,
        uuid: Uuid,
        admission: Admission,
    },
    /// A host on the far end of a link, or a router of another kind.
    Unsupported {
        route: u64,
        what: &'static str,
    },
    Failed {
        route: u64,
        what: &'static str,
        error: Error,
    },
    Stopped {
        error: Error,
    },
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => f.write_str("connection manager running"),
            Self::RouterAdded {
                route,
                name,
                vendor,
                device,
                generation,
                version,
                uuid,
                speed,
                width,
            } => {
                write!(f, "router {route:#x} added: ")?;
                if let Some(name) = name {
                    write!(f, "{name} ")?;
                }
                write!(f, "{vendor:04x}:{device:04x} ")?;
                if *version != 0 {
                    write!(f, "USB4 v{version}")?;
                } else {
                    write!(f, "Thunderbolt {generation}")?;
                }
                write!(f, " {uuid}, {speed} Gb/s x{width}")
            }
            Self::RouterRemoved { route } => write!(f, "router {route:#x} removed"),
            Self::TunnelUp {
                protocol,
                source,
                destination,
            } => write!(
                f,
                "{protocol:?} tunnel up {:#x}:{} to {:#x}:{}",
                source.0, source.1, destination.0, destination.1
            ),
            Self::TunnelDown {
                protocol,
                source,
                destination,
            } => write!(
                f,
                "{protocol:?} tunnel down {:#x}:{} to {:#x}:{}",
                source.0, source.1, destination.0, destination.1
            ),
            Self::Admission {
                route,
                uuid,
                admission: Admission::Refused,
            } => write!(
                f,
                "router {route:#x} ({uuid}) gets no PCIe tunnel: no DMA isolation and not \
                 listed by --usb4-approve"
            ),
            Self::Admission {
                route,
                uuid,
                admission,
            } => write!(
                f,
                "router {route:#x} ({uuid}) PCIe tunnel admitted: {admission:?}"
            ),
            Self::Unsupported { route, what } => {
                write!(f, "router {route:#x}: {what} is not supported")
            }
            Self::Failed { route, what, error } => {
                write!(f, "router {route:#x}: {what} failed: {error:?}")
            }
            Self::Stopped { error } => write!(f, "connection manager stopped: {error:?}"),
        }
    }
}

/// The domain: `struct tb` and `struct tb_cm`.
struct Cm {
    transport: Box<dyn Transport + Send>,
    platform: Box<dyn Platform + Send>,
    routers: BTreeMap<u64, Router>,
    tunnels: Vec<Tunnel>,
    /// `tcm->dp_resources`: DP adapters that can take a tunnel, best first.
    dp_resources: Vec<Adapter>,
    incoming: VecDeque<Incoming>,
    next_dprx_poll: u64,
    status: Arc<Status>,
    /// What has already been reported as missing.
    host_links_reported: bool,
    legacy_reported: bool,
}

/// What the task shows its owner between polls.
#[derive(Default)]
struct Status {
    /// Nothing is in progress: see [`Manager::idle`].
    idle: AtomicBool,
    /// See [`Manager::pcie_tunnels`].
    pcie_tunnels: AtomicUsize,
}

/// A running connection manager.
pub struct Manager {
    task: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    status: Arc<Status>,
}

impl Manager {
    /// Take over the domain behind the started `transport`.
    pub fn new(transport: Box<dyn Transport + Send>, platform: Box<dyn Platform + Send>) -> Self {
        let status = Arc::new(Status::default());
        let cm = Cm {
            transport,
            platform,
            routers: BTreeMap::new(),
            tunnels: Vec::new(),
            dp_resources: Vec::new(),
            incoming: VecDeque::new(),
            next_dprx_poll: 0,
            status: status.clone(),
            host_links_reported: false,
            legacy_reported: false,
        };
        Self {
            task: Some(Box::pin(cm.run())),
            status,
        }
    }

    /// Whether it only waits for the routers to say something, and needs
    /// polling just often enough to hear them.
    pub fn idle(&self) -> bool {
        self.status.idle.load(Ordering::Relaxed)
    }

    /// The PCIe tunnels up now, each of which a PCIe downstream port's link
    /// comes up over.
    pub fn pcie_tunnels(&self) -> usize {
        self.status.pcie_tunnels.load(Ordering::Relaxed)
    }

    /// Run the connection manager until it waits for the hardware or a clock.
    /// False once it has stopped.
    pub fn poll(&mut self) -> bool {
        let Some(task) = &mut self.task else {
            return false;
        };
        if let Poll::Ready(()) = poll_once(task.as_mut()) {
            self.task = None;
            return false;
        }
        true
    }
}

impl Cm {
    async fn run(mut self) {
        let error = match self.start().await {
            Ok(()) => {
                self.platform.report(Report::Ready);
                self.serve().await
            }
            Err(error) => error,
        };
        self.platform.report(Report::Stopped { error });
    }

    /// Bring up the host router and clear what boot firmware left, which
    /// plugs everything still connected in again: `tb_start` with a reset.
    async fn start(&mut self) -> Result<(), Error> {
        self.add_router(0).await?;
        let result = self.enable_host_tmu().await;
        self.note(0, "host router time synchronization", result)?;
        self.reset_host().await?;
        self.add_dp_resources(0).await
    }

    /// Report a failure the domain can go on without. A dead control path
    /// is the exception.
    fn note(
        &mut self,
        route: u64,
        what: &'static str,
        result: Result<(), Error>,
    ) -> Result<(), Error> {
        match result {
            Err(error @ Error::Channel(_)) => Err(error),
            Err(error) => {
                self.platform.report(Report::Failed { route, what, error });
                Ok(())
            }
            Ok(()) => Ok(()),
        }
    }

    /// Handle what the routers send, until the control path dies.
    async fn serve(&mut self) -> Error {
        loop {
            let served = async {
                self.pump()?;
                while let Some(incoming) = self.incoming.pop_front() {
                    if let Incoming::Plug(event) = incoming {
                        let result = self.plug(event).await;
                        self.note(event.route.raw(), "hotplug", result)?;
                    }
                }
                self.poll_dprx().await
            }
            .await;
            if let Err(error) = served {
                return error;
            }
            self.status.idle.store(true, Ordering::Relaxed);
            yield_now().await;
            self.status.idle.store(false, Ordering::Relaxed);
        }
    }

    /// `tb_handle_hotplug`.
    async fn plug(&mut self, event: PlugEvent) -> Result<(), Error> {
        let route = event.route.raw();
        let Some(router) = self.routers.get(&route) else {
            return Ok(());
        };
        if event.port > router.max_port() || event.port == 0 || event.port == router.upstream {
            return Ok(());
        }
        let port = router.port(event.port)?;
        let (kind, remote) = (port.kind, port.remote);
        match (event.unplug, remote) {
            (true, Some((child, _))) => {
                self.unplug_router(route, event.port, child).await?;
                self.tunnel_dp().await
            }
            (true, None) if kind.is_dp() => self.dp_resource_unavailable((route, event.port)).await,
            (false, None) if kind == Kind::Lane => self.scan_port(route, event.port).await,
            (false, None) if kind.is_dp() => self.dp_resource_available((route, event.port)).await,
            _ => Ok(()),
        }
    }

    /// `route`'s `port` lost the router `child` and everything behind it.
    async fn unplug_router(&mut self, route: u64, port: u8, child: u64) -> Result<(), Error> {
        for router in self.routers.values_mut() {
            router.unplugged |= beneath(router.route, child);
        }
        let mut index = 0;
        while index < self.tunnels.len() {
            let invalid = self.tunnels[index].paths.iter().any(|path| {
                path.hops.iter().any(|hop| {
                    self.routers
                        .get(&hop.route)
                        .is_none_or(|router| router.unplugged)
                })
            });
            if invalid {
                self.remove_tunnel(index).await?;
            } else {
                index += 1;
            }
        }
        self.dp_resources
            .retain(|adapter| !beneath(adapter.0, child));
        // Deepest first, as the links came up the other way round.
        let mut gone: Vec<u64> = self
            .routers
            .keys()
            .copied()
            .filter(|route| beneath(*route, child))
            .collect();
        gone.sort_by_key(|route| core::cmp::Reverse(depth(*route)));
        for route in gone {
            self.routers.remove(&route);
            self.platform.report(Report::RouterRemoved { route });
        }
        let result = self.unconfigure_link(route, port).await;
        self.note(route, "unconfiguring the link", result)?;
        let dual = self.adapter(route, port)?.dual;
        self.adapter_mut(route, port)?.remote = None;
        if let Some(dual) = dual {
            self.adapter_mut(route, dual)?.remote = None;
        }
        Ok(())
    }

    /// [`Self::scan_port`], boxed for its recursion.
    fn scan_below(
        &mut self,
        route: u64,
        number: u8,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(self.scan_port(route, number))
    }

    /// Enumerate what is behind `port`: `tb_scan_port`.
    async fn scan_port(&mut self, route: u64, number: u8) -> Result<(), Error> {
        let router = self.router(route)?;
        if number == router.upstream {
            return Ok(());
        }
        let port = router.port(number)?;
        let (kind, disabled, lane, remote) = (port.kind, port.disabled, port.lane, port.remote);
        if disabled {
            return Ok(());
        }
        if kind == Kind::DpOut
            && self.dp_hot_plugged(route, number).await?
            && !self.adapter_enabled((route, number)).await?
        {
            return self.dp_resource_available((route, number)).await;
        }
        if kind != Kind::Lane || lane != 0 || remote.is_some() {
            return Ok(());
        }
        if !self.wait_for_port(route, number).await? {
            return Ok(());
        }
        let child = downstream(route, number);
        match self.add_router(child).await {
            Ok(()) => {}
            Err(Error::Legacy) => {
                if !core::mem::replace(&mut self.legacy_reported, true) {
                    self.platform.report(Report::Unsupported {
                        route: child,
                        what: "a router without plug events",
                    });
                }
                return Ok(());
            }
            // `tb_scan_xdomain`: a link with no router of this domain on it.
            Err(Error::Timeout | Error::Controller(_) | Error::TooDeep) => {
                if !core::mem::replace(&mut self.host_links_reported, true) {
                    self.platform.report(Report::Unsupported {
                        route: child,
                        what: "a link to another host",
                    });
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        self.configure_link(child).await?;
        let result = self.enable_tmu(child).await;
        self.note(child, "time synchronization", result)?;
        self.configuration_valid(child).await?;
        let router = self.router(child)?;
        self.platform.report(Report::RouterAdded {
            route: child,
            name: router.name.clone(),
            vendor: router.vendor(),
            device: router.device(),
            generation: router.generation(),
            version: router.usb4_version(),
            uuid: Uuid::from_le_words(router.uuid()),
            speed: router.link_speed,
            width: router.link_width,
        });
        let result = self.tunnel_usb3(child).await;
        self.note(child, "USB3 tunnel", result)?;
        let result = self.tunnel_pcie(child).await;
        self.note(child, "PCIe tunnel", result)?;
        self.add_dp_resources(child).await?;
        // Linux's `tb_scan_switch`.
        for number in 1..=self.router(child)?.max_port() {
            self.scan_below(child, number).await?;
        }
        Ok(())
    }

    /// The tunnel carrying `protocol` from `source`.
    fn find_tunnel(&self, protocol: Protocol, source: Adapter) -> Option<usize> {
        self.tunnels
            .iter()
            .position(|tunnel| tunnel.protocol == protocol && tunnel.source == source)
    }

    /// The USB3 tunnel from the host router towards the router farther down
    /// `source`..`destination`: `tb_find_first_usb3_tunnel`.
    fn first_usb3_tunnel(&self, source: Adapter, destination: Adapter) -> Option<usize> {
        let route = if depth(source.0) < depth(destination.0) {
            destination.0
        } else {
            source.0
        };
        if route == 0 {
            return None;
        }
        let down = self
            .routers
            .get(&0)?
            .mapped(port_at(route, 0), Kind::Usb3Down)?;
        self.find_tunnel(Protocol::Usb3, (0, down))
    }

    /// `tb_maximum_bandwidth`, without the asymmetric headroom this domain
    /// never uses, less a 10% guard band.
    async fn maximum_bandwidth(&mut self, adapter: Adapter) -> Result<Bandwidth, Error> {
        let router = self.router(adapter.0)?;
        let upstream = adapter.1 == router.upstream;
        let (speed, width) = if upstream {
            (router.link_speed, router.link_width)
        } else {
            (
                self.link_speed(adapter.0, adapter.1).await?,
                self.link_width(adapter.0, adapter.1).await?,
            )
        };
        let (transmit, receive) = match width {
            WIDTH_ASYM_TX => (3, 1),
            WIDTH_ASYM_RX => (1, 3),
            width => (width, width),
        };
        let (up, down) = if upstream {
            (speed * transmit * 1000, speed * receive * 1000)
        } else {
            (speed * receive * 1000, speed * transmit * 1000)
        };
        Ok(Bandwidth {
            up: up - up / 10,
            down: down - down / 10,
        })
    }

    /// `tb_available_bandwidth`.
    async fn available_bandwidth(
        &mut self,
        source: Adapter,
        destination: Adapter,
    ) -> Result<Bandwidth, Error> {
        let mut available = Bandwidth {
            up: 120_000,
            down: 120_000,
        };
        for (route, input, output) in self.walk(source, destination)? {
            for number in [input, output] {
                if self.adapter(route, number)?.kind != Kind::Lane {
                    continue;
                }
                let adapter = (route, number);
                let maximum = self.maximum_bandwidth(adapter).await?;
                let bulk = self.consumed_bulk(source, destination, adapter).await?;
                let display = self.consumed_dp(source, destination, adapter).await?;
                let up = bulk.up + display.up;
                let down = bulk.down + display.down;
                available.up = available.up.min(maximum.up.saturating_sub(up));
                available.down = available.down.min(maximum.down.saturating_sub(down));
            }
        }
        Ok(available)
    }

    /// `tb_consumed_usb3_pcie_bandwidth`.
    async fn consumed_bulk(
        &mut self,
        source: Adapter,
        destination: Adapter,
        adapter: Adapter,
    ) -> Result<Bandwidth, Error> {
        let from_usb3 = self.adapter(source.0, source.1)?.kind == Kind::Usb3Down;
        let to_usb3 = self.adapter(destination.0, destination.1)?.kind == Kind::Usb3Up;
        let mut consumed = match self.first_usb3_tunnel(source, destination) {
            Some(index) if !from_usb3 && !to_usb3 => self.usb3_tunnel_consumed(index).await?,
            _ => Bandwidth::default(),
        };
        let speed = self.link_speed(adapter.0, adapter.1).await?;
        let router = self.router(adapter.0)?;
        let port = router.port(adapter.1)?;
        let pcie = port.remote.is_some_and(|(remote, _)| {
            let (near, far) = if adapter.1 == router.upstream {
                (Kind::PcieUp, Kind::PcieDown)
            } else {
                (Kind::PcieDown, Kind::PcieUp)
            };
            router.find(near).is_some()
                && self
                    .routers
                    .get(&remote)
                    .is_some_and(|router| router.find(far).is_some())
        });
        let reserved = tunnel::reserved_pcie(speed, pcie);
        consumed.up += reserved.up;
        consumed.down += reserved.down;
        Ok(consumed)
    }

    /// `tb_consumed_dp_bandwidth`.
    async fn consumed_dp(
        &mut self,
        source: Adapter,
        destination: Adapter,
        adapter: Adapter,
    ) -> Result<Bandwidth, Error> {
        let mut consumed = Bandwidth::default();
        for index in 0..self.tunnels.len() {
            let tunnel = &self.tunnels[index];
            if tunnel.protocol != Protocol::DisplayPort
                || !tunnel.on_port(adapter)
                || (tunnel.source == source && tunnel.destination == destination)
            {
                continue;
            }
            let bandwidth = self.dp_consumed(index).await?;
            consumed.up += bandwidth.up;
            consumed.down += bandwidth.down;
        }
        Ok(consumed)
    }

    /// `tb_release_unused_usb3_bandwidth`.
    async fn release_unused_usb3(
        &mut self,
        source: Adapter,
        destination: Adapter,
    ) -> Result<(), Error> {
        match self.first_usb3_tunnel(source, destination) {
            Some(index) => self.usb3_release_unused(index).await,
            None => Ok(()),
        }
    }

    /// `tb_reclaim_usb3_bandwidth`.
    async fn reclaim_usb3(&mut self, source: Adapter, destination: Adapter) -> Result<(), Error> {
        let Some(index) = self.first_usb3_tunnel(source, destination) else {
            return Ok(());
        };
        let tunnel = &self.tunnels[index];
        let (from, to) = (tunnel.source, tunnel.destination);
        let available = self.available_bandwidth(from, to).await?;
        self.usb3_reclaim(index, available).await
    }

    /// `tb_tunnel_usb3`.
    async fn tunnel_usb3(&mut self, route: u64) -> Result<(), Error> {
        let router = self.router(route)?;
        let (Some(up), true) = (router.find(Kind::Usb3Up), router.link_usb4) else {
            return Ok(());
        };
        let up = (route, up.number);
        let above = parent(route);
        let lane = port_at(route, depth(route) - 1);
        let Some(down) = self.router(above)?.mapped(lane, Kind::Usb3Down) else {
            return Ok(());
        };
        let down = (above, down);
        if self.adapter_enabled(down).await? {
            return Ok(());
        }
        if above != 0 {
            // The chain above has to be complete first.
            let Some(parent_up) = self
                .router(above)?
                .find(Kind::Usb3Up)
                .map(|port| port.number)
            else {
                return Ok(());
            };
            if !self.adapter_enabled((above, parent_up)).await? {
                return Ok(());
            }
            self.release_unused_usb3(down, up).await?;
        }
        let started = async {
            let available = self.available_bandwidth(down, up).await?;
            self.start_usb3(up, down, available).await
        }
        .await;
        if above != 0 {
            let result = self.reclaim_usb3(down, up).await;
            self.note(route, "reclaiming USB3 bandwidth", result)?;
        }
        started?;
        self.report_up(Protocol::Usb3, down, up);
        Ok(())
    }

    fn report_up(&mut self, protocol: Protocol, source: Adapter, destination: Adapter) {
        if protocol == Protocol::Pcie {
            self.status.pcie_tunnels.fetch_add(1, Ordering::Relaxed);
        }
        self.platform.report(Report::TunnelUp {
            protocol,
            source,
            destination,
        });
    }

    /// `tb_find_pcie_down`.
    async fn pcie_down(&mut self, route: u64, lane: u8) -> Result<Option<u8>, Error> {
        let router = self.router(route)?;
        if let Some(down) = router
            .mapped(lane, Kind::PcieDown)
            .filter(|_| router.is_usb4())
            && !self.adapter_enabled((route, down)).await?
        {
            return Ok(Some(down));
        }
        let candidates: Vec<u8> = self
            .router(route)?
            .ports
            .iter()
            .filter(|port| port.kind == Kind::PcieDown && port.cap_adapter.is_some())
            .map(|port| port.number)
            .collect();
        for down in candidates {
            if !self.adapter_enabled((route, down)).await? {
                return Ok(Some(down));
            }
        }
        Ok(None)
    }

    /// Authorize the router, if its parent is, and tunnel PCIe to it: what
    /// Linux does when user space approves a device.
    async fn tunnel_pcie(&mut self, route: u64) -> Result<(), Error> {
        let router = self.router(route)?;
        let Some(up) = router.find(Kind::PcieUp) else {
            return Ok(());
        };
        let up = (route, up.number);
        let uuid = Uuid::from_le_words(router.uuid());
        let above = parent(route);
        if !self.router(above)?.authorized {
            return Ok(());
        }
        let admission = self.platform.admit_pcie(uuid);
        self.platform.report(Report::Admission {
            route,
            uuid,
            admission,
        });
        if admission == Admission::Refused {
            return Ok(());
        }
        self.router_mut(route)?.authorized = true;
        let Some(down) = self
            .pcie_down(above, port_at(route, depth(route) - 1))
            .await?
        else {
            return Ok(());
        };
        let down = (above, down);
        self.start_pcie(up, down).await?;
        self.report_up(Protocol::Pcie, down, up);
        let result = self.connect_xhci(route).await;
        self.note(route, "connecting the internal xHCI", result)
    }

    /// `tb_add_dp_resources`: a device router's DP IN goes first, so that an
    /// external GPU is used before the host's.
    async fn add_dp_resources(&mut self, route: u64) -> Result<(), Error> {
        let inputs: Vec<u8> = self
            .router(route)?
            .ports
            .iter()
            .filter(|port| port.kind == Kind::DpIn)
            .map(|port| port.number)
            .collect();
        for number in inputs {
            if self.dp_resource_free((route, number)).await? {
                if route == 0 {
                    self.dp_resources.push((route, number));
                } else {
                    self.dp_resources.insert(0, (route, number));
                }
            }
        }
        Ok(())
    }

    async fn dp_resource_operation(&mut self, input: Adapter, opcode: u16) -> Result<(), Error> {
        if !self.router(input.0)?.is_usb4() {
            return self
                .lc_set_sink(input, opcode == OP_ALLOC_DP_RESOURCE)
                .await;
        }
        let mut metadata = u32::from(input.1);
        match self
            .router_operation(input.0, opcode, &mut metadata, &mut [])
            .await
        {
            Ok(0) | Err(Error::Unsupported) => Ok(()),
            Ok(_) => Err(Error::Busy),
            Err(error) => Err(error),
        }
    }

    /// `tb_dp_resource_available`.
    /// `tb_switch_query_dp_resource`.
    async fn dp_resource_free(&mut self, input: Adapter) -> Result<bool, Error> {
        if !self.router(input.0)?.is_usb4() {
            return self.lc_sink_free(input).await;
        }
        let mut metadata = u32::from(input.1);
        let status = self
            .router_operation(input.0, OP_QUERY_DP_RESOURCE, &mut metadata, &mut [])
            .await;
        Ok(matches!(status, Ok(0) | Err(Error::Unsupported)))
    }

    async fn dp_resource_available(&mut self, adapter: Adapter) -> Result<(), Error> {
        if self.adapter_enabled(adapter).await? || self.dp_resources.contains(&adapter) {
            return Ok(());
        }
        self.dp_resources.push(adapter);
        self.tunnel_dp().await
    }

    /// `tb_dp_resource_unavailable`.
    async fn dp_resource_unavailable(&mut self, adapter: Adapter) -> Result<(), Error> {
        let found = self.tunnels.iter().position(|tunnel| {
            tunnel.protocol == Protocol::DisplayPort
                && (tunnel.source == adapter || tunnel.destination == adapter)
        });
        if let Some(index) = found {
            self.remove_tunnel(index).await?;
        }
        self.dp_resources.retain(|resource| *resource != adapter);
        self.tunnel_dp().await
    }

    /// `tb_find_dp_out`.
    async fn find_dp_out(&mut self, input: Adapter) -> Result<Option<Adapter>, Error> {
        let host_port = (input.0 != 0).then(|| port_at(input.0, 0));
        for index in 0..self.dp_resources.len() {
            let output = self.dp_resources[index];
            if self.adapter(output.0, output.1)?.kind != Kind::DpOut
                || self.adapter_enabled(output).await?
                || output.0 == input.0
            {
                continue;
            }
            // Keep a tunnel beneath one host router port.
            if host_port.is_some_and(|port| output.0 != 0 && port_at(output.0, 0) != port) {
                continue;
            }
            return Ok(Some(output));
        }
        Ok(None)
    }

    /// Pair inactive DP IN and OUT adapters: `tb_tunnel_dp`.
    async fn tunnel_dp(&mut self) -> Result<(), Error> {
        for index in 0..self.dp_resources.len() {
            let Some(&input) = self.dp_resources.get(index) else {
                break;
            };
            if self.adapter(input.0, input.1)?.kind != Kind::DpIn
                || self.adapter_enabled(input).await?
            {
                continue;
            }
            if let Some(output) = self.find_dp_out(input).await? {
                let result = self.tunnel_one_dp(input, output).await;
                self.note(input.0, "DisplayPort tunnel", result)?;
            }
        }
        Ok(())
    }

    /// `tb_tunnel_one_dp`. Links that are not bonded take the first stream
    /// on their second lane.
    async fn tunnel_one_dp(&mut self, input: Adapter, output: Adapter) -> Result<(), Error> {
        let any = self
            .tunnels
            .iter()
            .any(|tunnel| tunnel.protocol == Protocol::DisplayPort);
        let link = u8::from(!any);
        self.dp_resource_operation(input, OP_ALLOC_DP_RESOURCE)
            .await?;
        let started = async {
            self.release_unused_usb3(input, output).await?;
            let available = self.available_bandwidth(input, output).await?;
            self.start_dp(input, output, link, available).await
        }
        .await;
        if let Err(error) = started {
            if matches!(error, Error::Channel(_)) {
                return Err(error);
            }
            self.reclaim_usb3(input, output).await.ok();
            self.dp_resource_operation(input, OP_DEALLOC_DP_RESOURCE)
                .await
                .ok();
            return Err(error);
        }
        Ok(())
    }

    /// Finish DisplayPort tunnels whose DPRX negotiation ended: Linux's
    /// `tb_dp_dprx_work`. One that never does leaves its DP IN unused until
    /// it plugs in again.
    async fn poll_dprx(&mut self) -> Result<(), Error> {
        let now = self.platform.now_ms();
        if now < self.next_dprx_poll {
            return Ok(());
        }
        self.next_dprx_poll = now + DPRX_POLL_MS;
        for index in (0..self.tunnels.len()).rev() {
            let Some(deadline) = self.tunnels[index].dprx else {
                continue;
            };
            let input = self.tunnels[index].source;
            let output = self.tunnels[index].destination;
            match self.dprx_done(input).await {
                Ok(true) => {
                    self.tunnels[index].dprx = None;
                    self.report_up(Protocol::DisplayPort, input, output);
                    let result = self.reclaim_usb3(input, output).await;
                    self.note(input.0, "reclaiming USB3 bandwidth", result)?;
                }
                Ok(false) if self.platform.now_ms() < deadline => {}
                Ok(false) => {
                    self.platform.report(Report::Failed {
                        route: input.0,
                        what: "DPRX negotiation",
                        error: Error::Timeout,
                    });
                    self.dp_resource_unavailable(input).await?;
                    return Ok(());
                }
                Err(error @ Error::Channel(_)) => return Err(error),
                // A hotplug event removes it.
                Err(_) => {}
            }
        }
        Ok(())
    }

    /// `tb_deactivate_and_free_tunnel`.
    async fn remove_tunnel(&mut self, index: usize) -> Result<(), Error> {
        let mut tunnel = self.tunnels.remove(index);
        let result = self.deactivate_tunnel(&mut tunnel).await;
        self.free_tunnel(&tunnel);
        let (protocol, source, destination) = (tunnel.protocol, tunnel.source, tunnel.destination);
        self.note(source.0, "stopping a tunnel", result)?;
        if protocol == Protocol::Pcie {
            self.status.pcie_tunnels.fetch_sub(1, Ordering::Relaxed);
        }
        self.platform.report(Report::TunnelDown {
            protocol,
            source,
            destination,
        });
        if protocol == Protocol::DisplayPort
            && self
                .routers
                .get(&source.0)
                .is_some_and(|router| !router.unplugged)
        {
            let result = self
                .dp_resource_operation(source, OP_DEALLOC_DP_RESOURCE)
                .await;
            self.note(source.0, "releasing a DP resource", result)?;
        }
        if protocol != Protocol::Pcie {
            let present = |adapter: Adapter| {
                self.routers
                    .get(&adapter.0)
                    .is_some_and(|router| !router.unplugged)
            };
            if present(source) && present(destination) {
                let result = self.reclaim_usb3(source, destination).await;
                self.note(source.0, "reclaiming USB3 bandwidth", result)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod fabric;
#[cfg(test)]
mod tests;

// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Configuration access as tb.c sees it through ctl.c: one request at a time,
//! retried on timeout, with plug events and notifications queued for the
//! connection manager's own loop. Each `.await` hands the host back its CPU.
use super::{Cm, Error, regs::*};
use crate::bus::thunderbolt::{
    channel::{self, Channel, Event},
    config::{Address, NotificationError, PlugEvent, Reply, Route, Space},
    ring::{self, Registers},
};
use crate::stepped::yield_now;
use alloc::vec::Vec;

/// Linux's `TB_TIMEOUT`, per attempt.
const REQUEST_MS: u64 = 100;
/// Linux's `TB_CTL_RETRIES`.
const ATTEMPTS: usize = 4;
/// `ERROR_INVALID_CONFIG_SPACE`, `ERROR_LOCK`, `ERROR_PORT_NOT_CONNECTED`.
const INVALID_CONFIG_SPACE: u8 = 2;
const LOCK: u8 = 15;
const PORT_NOT_CONNECTED: u8 = 0;

/// The control path the connection manager drives.
pub trait Transport {
    fn read(
        &mut self,
        route: Route,
        address: Address,
        now: u64,
        deadline: u64,
    ) -> Result<u64, channel::Error>;
    fn write(
        &mut self,
        route: Route,
        address: Address,
        data: &[u32],
        now: u64,
        deadline: u64,
    ) -> Result<u64, channel::Error>;
    fn poll(&mut self, now: u64) -> Result<Option<Event>, channel::Error>;
}

impl<R: Registers> Transport for Channel<R> {
    fn read(
        &mut self,
        route: Route,
        address: Address,
        now: u64,
        deadline: u64,
    ) -> Result<u64, channel::Error> {
        Channel::read(self, route, address, now, deadline)
    }
    fn write(
        &mut self,
        route: Route,
        address: Address,
        data: &[u32],
        now: u64,
        deadline: u64,
    ) -> Result<u64, channel::Error> {
        Channel::write(self, route, address, data, now, deadline)
    }
    fn poll(&mut self, now: u64) -> Result<Option<Event>, channel::Error> {
        Channel::poll(self, now)
    }
}

/// An asynchronous message from a router, in arrival order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Incoming {
    Plug(PlugEvent),
    Notification(NotificationError),
}

fn address(port: u8, space: Space, offset: u16, words: u8) -> Address {
    Address {
        port,
        space,
        offset,
        words,
    }
}

impl Cm {
    /// Move what has arrived out of the transport, without a request of ours
    /// outstanding.
    pub(super) fn pump(&mut self) -> Result<(), Error> {
        while let Some(event) = self.transport.poll(self.platform.now_ms())? {
            self.dispatch(event);
        }
        Ok(())
    }

    /// Queue an asynchronous `event`; a completion is one nobody awaits.
    fn dispatch(&mut self, event: Event) {
        match event {
            Event::Plug(plug) => self.incoming.push_back(Incoming::Plug(plug)),
            Event::Notification(notice) => self.incoming.push_back(Incoming::Notification(notice)),
            Event::Discarded(_) | Event::Completed { .. } | Event::TimedOut { .. } => {}
        }
    }

    /// One request, as `tb_cfg_read`/`tb_cfg_write`: retried while it times
    /// out, answered by the router or by the first one that could not pass it on.
    async fn exchange(
        &mut self,
        route: u64,
        request: Address,
        data: Option<&[u32]>,
    ) -> Result<(u8, Vec<u32>), Error> {
        let route = Route::new(route).map_err(|_| Error::Topology)?;
        for _ in 0..ATTEMPTS {
            let id = loop {
                let now = self.platform.now_ms();
                let deadline = now + REQUEST_MS;
                let issued = match data {
                    Some(data) => self.transport.write(route, request, data, now, deadline),
                    None => self.transport.read(route, request, now, deadline),
                };
                match issued {
                    Ok(id) => break id,
                    Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => {
                        self.pump()?;
                        yield_now().await;
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            loop {
                match self.transport.poll(self.platform.now_ms())? {
                    Some(Event::Completed {
                        request: done,
                        reply,
                    }) if done == id => {
                        return match reply {
                            Reply::Configuration {
                                upstream_port,
                                data,
                            } => Ok((upstream_port, data)),
                            Reply::ControllerError { code, .. } => Err(match code {
                                INVALID_CONFIG_SPACE if request.space == Space::Port => {
                                    Error::NotImplemented
                                }
                                LOCK => Error::Locked,
                                PORT_NOT_CONNECTED => Error::NotConnected,
                                code => Error::Controller(code),
                            }),
                            Reply::Reset => Err(Error::Reply),
                        };
                    }
                    Some(Event::TimedOut { request: done }) if done == id => break,
                    Some(event) => self.dispatch(event),
                    None => yield_now().await,
                }
            }
        }
        Err(Error::Timeout)
    }

    pub(super) async fn read(
        &mut self,
        route: u64,
        port: u8,
        space: Space,
        offset: u16,
        words: u8,
    ) -> Result<Vec<u32>, Error> {
        let (_, data) = self
            .exchange(route, address(port, space, offset, words), None)
            .await?;
        if data.len() == usize::from(words) {
            Ok(data)
        } else {
            Err(Error::Reply)
        }
    }

    pub(super) async fn write(
        &mut self,
        route: u64,
        port: u8,
        space: Space,
        offset: u16,
        data: &[u32],
    ) -> Result<(), Error> {
        let words = u8::try_from(data.len()).map_err(|_| Error::Reply)?;
        self.exchange(route, address(port, space, offset, words), Some(data))
            .await
            .map(|_| ())
    }

    /// The router's upstream port, which only a reply's header tells before
    /// it is enumerated: `tb_cfg_get_upstream_port`.
    pub(super) async fn upstream_port(&mut self, route: u64) -> Result<u8, Error> {
        self.exchange(route, address(0, Space::Router, 0, 1), None)
            .await
            .map(|(upstream, _)| upstream)
    }

    pub(super) async fn router_read(&mut self, route: u64, offset: u16) -> Result<u32, Error> {
        Ok(self.read(route, 0, Space::Router, offset, 1).await?[0])
    }
    pub(super) async fn router_write(
        &mut self,
        route: u64,
        offset: u16,
        value: u32,
    ) -> Result<(), Error> {
        self.write(route, 0, Space::Router, offset, &[value]).await
    }
    pub(super) async fn port_read(
        &mut self,
        route: u64,
        port: u8,
        offset: u16,
    ) -> Result<u32, Error> {
        Ok(self.read(route, port, Space::Port, offset, 1).await?[0])
    }
    pub(super) async fn port_write(
        &mut self,
        route: u64,
        port: u8,
        offset: u16,
        value: u32,
    ) -> Result<(), Error> {
        self.write(route, port, Space::Port, offset, &[value]).await
    }
    /// Read `offset`, clear `mask`, set `value` and write it back.
    pub(super) async fn port_modify(
        &mut self,
        route: u64,
        port: u8,
        offset: u16,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        let word = self.port_read(route, port, offset).await?;
        self.port_write(route, port, offset, (word & !mask) | value)
            .await
    }
    pub(super) async fn router_modify(
        &mut self,
        route: u64,
        offset: u16,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        let word = self.router_read(route, offset).await?;
        self.router_write(route, offset, (word & !mask) | value)
            .await
    }

    /// Wait until `read` of the router's `offset` shows `value` under `mask`:
    /// `tb_switch_wait_for_bit`.
    pub(super) async fn router_wait(
        &mut self,
        route: u64,
        offset: u16,
        mask: u32,
        value: u32,
        timeout: u64,
    ) -> Result<(), Error> {
        let deadline = self.platform.now_ms() + timeout;
        loop {
            if self.router_read(route, offset).await? & mask == value {
                return Ok(());
            }
            if self.platform.now_ms() >= deadline {
                return Err(Error::Timeout);
            }
        }
    }

    /// Wait until the adapter's `offset` shows `value` under `mask`.
    pub(super) async fn port_wait(
        &mut self,
        route: u64,
        port: u8,
        offset: u16,
        mask: u32,
        value: u32,
        timeout: u64,
    ) -> Result<(), Error> {
        let deadline = self.platform.now_ms() + timeout;
        loop {
            if self.port_read(route, port, offset).await? & mask == value {
                return Ok(());
            }
            if self.platform.now_ms() >= deadline {
                return Err(Error::Timeout);
            }
        }
    }

    pub(super) async fn sleep(&mut self, milliseconds: u64) -> Result<(), Error> {
        let deadline = self.platform.now_ms() + milliseconds;
        while self.platform.now_ms() < deadline {
            self.pump()?;
            yield_now().await;
        }
        Ok(())
    }

    /// Run a router operation: `usb4_native_switch_op`. The status it ended
    /// with, or [`Error::Unsupported`] when the router has no such operation.
    pub(super) async fn router_operation(
        &mut self,
        route: u64,
        opcode: u16,
        metadata: &mut u32,
        data: &mut [u32],
    ) -> Result<u8, Error> {
        self.router_write(route, ROUTER_CS_25, *metadata).await?;
        self.router_write(route, ROUTER_CS_26, u32::from(opcode) | ROUTER_CS_26_OV)
            .await?;
        self.router_wait(route, ROUTER_CS_26, ROUTER_CS_26_OV, 0, 500)
            .await?;
        let word = self.router_read(route, ROUTER_CS_26).await?;
        if word & ROUTER_CS_26_ONS != 0 {
            return Err(Error::Unsupported);
        }
        *metadata = self.router_read(route, ROUTER_CS_25).await?;
        if !data.is_empty() {
            let words = u8::try_from(data.len()).map_err(|_| Error::Reply)?;
            let read = self
                .read(route, 0, Space::Router, ROUTER_CS_9, words)
                .await?;
            data.copy_from_slice(&read);
        }
        Ok(((word & ROUTER_CS_26_STATUS_MASK) >> ROUTER_CS_26_STATUS_SHIFT) as u8)
    }
}

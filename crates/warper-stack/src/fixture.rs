// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled active TCP peer, never used by production modules.

use crate::device::{BYTE_CAPACITY, PacketDevice};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpCidr},
};
use std::{net::SocketAddr, time::Duration};

pub(crate) struct Peer {
    pub(crate) device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    socket: SocketHandle,
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
}
impl Peer {
    pub(crate) fn new(ipv6: bool, port: u16) -> Self {
        let source: SocketAddr = if ipv6 {
            format!("[2001:db8::2]:{port}")
        } else {
            format!("192.0.2.2:{port}")
        }
        .parse()
        .unwrap();
        let destination: SocketAddr = if ipv6 {
            "[2001:db8::9]:443"
        } else {
            "192.0.2.9:443"
        }
        .parse()
        .unwrap();
        let mut device = PacketDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 117;
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(source.ip().into(), if ipv6 { 64 } else { 24 }))
                .unwrap()
        });
        let mut sockets = SocketSet::new(Vec::new());
        let mut tcp = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
            tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
        );
        tcp.connect(interface.context(), destination, source)
            .unwrap();
        let socket = sockets.add(tcp);
        Self {
            device,
            interface,
            sockets,
            socket,
            source,
            destination,
        }
    }
    pub(crate) fn poll(&mut self, now: Duration) {
        self.interface.poll(
            Instant::from_millis(now.as_millis() as i64),
            &mut self.device,
            &mut self.sockets,
        );
    }
    pub(crate) fn tcp(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(self.socket)
    }
    pub(crate) fn syn(&mut self) -> Vec<u8> {
        self.poll(Duration::ZERO);
        self.device.outgoing.pop_front().unwrap()
    }
}

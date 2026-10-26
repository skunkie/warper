// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded raw-IP device and active sockets for controlled experimental peers.

use std::{collections::VecDeque, io, net::IpAddr};

use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::{tcp, udp},
    time::Instant,
    wire::{HardwareAddress, IpCidr},
};

pub const MTU: usize = 1280;
pub const PACKET_CAPACITY: usize = 64;
pub const BYTE_CAPACITY: usize = 8192;

pub struct PacketDevice {
    incoming: VecDeque<Vec<u8>>,
    pub outgoing: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Default for PacketDevice {
    fn default() -> Self {
        Self {
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            mtu: MTU,
        }
    }
}

impl PacketDevice {
    pub fn with_mtu(mtu: usize) -> io::Result<Self> {
        if !(MTU..=1500).contains(&mtu) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            mtu,
            ..Self::default()
        })
    }

    pub fn inject(&mut self, packet: Vec<u8>) -> io::Result<()> {
        if packet.len() > self.mtu || self.incoming.len() >= PACKET_CAPACITY {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.incoming.push_back(packet);
        Ok(())
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = RxPacket;
    type TxToken<'a> = TxPacket<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outgoing.len() >= PACKET_CAPACITY {
            return None;
        }
        self.incoming
            .pop_front()
            .map(|packet| (RxPacket(packet), TxPacket(&mut self.outgoing, self.mtu)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        (self.outgoing.len() < PACKET_CAPACITY).then_some(TxPacket(&mut self.outgoing, self.mtu))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

pub struct RxPacket(Vec<u8>);

impl phy::RxToken for RxPacket {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, operation: F) -> R {
        operation(&self.0)
    }
}

pub struct TxPacket<'a>(&'a mut VecDeque<Vec<u8>>, usize);

impl phy::TxToken for TxPacket<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, operation: F) -> R {
        // Device contract: smoltcp must respect the advertised IP MTU.
        assert!(length <= self.1, "stack exceeded advertised MTU");
        let mut packet = vec![0; length];
        let result = operation(&mut packet);
        self.0.push_back(packet);
        result
    }
}

pub struct Peer {
    pub device: PacketDevice,
    pub interface: Interface,
    pub sockets: SocketSet<'static>,
    pub tcp: SocketHandle,
    pub udp: SocketHandle,
}

impl Peer {
    pub fn new(address: IpAddr, port: u16) -> anyhow::Result<Self> {
        Self::with_mtu(address, port, MTU)
    }

    pub fn with_mtu(address: IpAddr, port: u16, mtu: usize) -> anyhow::Result<Self> {
        let mut device = PacketDevice::with_mtu(mtu)?;
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = u64::from(port);
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        let prefix = if address.is_ipv4() { 24 } else { 64 };
        interface.update_ip_addrs(|addresses| {
            // One address fits smoltcp's fixed address table.
            addresses
                .push(IpCidr::new(address.into(), prefix))
                .expect("one peer address");
        });
        let mut sockets = SocketSet::new(Vec::new());
        let tcp = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
            tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
        ));
        let mut udp_socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; BYTE_CAPACITY]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; BYTE_CAPACITY]),
        );
        udp_socket.bind((address, port))?;
        let udp = sockets.add(udp_socket);
        Ok(Self {
            device,
            interface,
            sockets,
            tcp,
            udp,
        })
    }

    pub fn poll(&mut self, elapsed_ms: i64) {
        self.interface.poll(
            Instant::from_millis(elapsed_ms),
            &mut self.device,
            &mut self.sockets,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_refuses_oversized_packets_and_full_queue() {
        let mut device = PacketDevice::default();
        assert_eq!(
            device.inject(vec![0; MTU + 1]).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
        for _ in 0..PACKET_CAPACITY {
            device.inject(vec![0; MTU]).unwrap();
        }
        assert_eq!(
            device.inject(vec![0; MTU]).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
    }

    #[test]
    fn egress_applies_backpressure_at_capacity() {
        let mut device = PacketDevice::default();
        for _ in 0..PACKET_CAPACITY {
            phy::TxToken::consume(
                device.transmit(Instant::from_millis(0)).unwrap(),
                MTU,
                |_| (),
            );
        }
        assert!(device.transmit(Instant::from_millis(0)).is_none());
        device.outgoing.pop_front();
        assert!(device.transmit(Instant::from_millis(0)).is_some());
    }

    #[test]
    fn controlled_mtu_bounds_are_validated_and_enforced_before_allocation() {
        for mtu in [0, MTU - 1, 1501, usize::MAX] {
            assert!(
                matches!(PacketDevice::with_mtu(mtu), Err(error) if error.kind()==io::ErrorKind::InvalidInput)
            );
        }
        let mut device = PacketDevice::with_mtu(1500).unwrap();
        assert_eq!(device.capabilities().max_transmission_unit, 1500);
        device.inject(vec![0; 1500]).unwrap();
        assert_eq!(
            device.inject(vec![0; 1501]).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
    }
}

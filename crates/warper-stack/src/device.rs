// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded plain-IP packet queues for the host adapter.

use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use std::{collections::VecDeque, io};

pub const MTU: usize = 1280;
pub(crate) const PACKET_CAPACITY: usize = 64;
pub(crate) const BYTE_CAPACITY: usize = 8192;

pub(crate) struct PacketDevice {
    pub(crate) incoming: VecDeque<Vec<u8>>,
    pub(crate) outgoing: VecDeque<Vec<u8>>,
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

pub(crate) struct RxPacket(Vec<u8>);

impl phy::RxToken for RxPacket {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, operation: F) -> R {
        operation(&self.0)
    }
}

pub(crate) struct TxPacket<'a>(&'a mut VecDeque<Vec<u8>>, usize);

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

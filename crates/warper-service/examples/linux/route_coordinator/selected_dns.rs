// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled real SOCKS5 peer for DNS and the first discovered TCP flow.

use super::{Failure, ipv4, request};
use std::{num::NonZeroU32, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};
use warper_backends::socks5::Socks5;
use warper_core::{
    BackendId,
    dns::{Name, Policy, Rule},
};
use warper_service::{
    dns::{Admission, Limits, Packet, TcpTransport},
    linux::{context::Context, egress},
};

pub(super) struct Peer {
    pub transport: Arc<TcpTransport>,
    pub domains: Arc<Policy>,
    pub backend: Arc<Socks5>,
    stop: watch::Sender<bool>,
    task: JoinHandle<Result<(usize, usize, usize), Failure>>,
}
impl Peer {
    pub async fn new(
        context: Arc<Context>,
        excluded: NonZeroU32,
        owner: &watch::Sender<bool>,
    ) -> Result<Self, Failure> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = listener.local_addr()?;
        let connector = egress::Preparation::new(context, &[endpoint], excluded, 2)?
            .prepare(request(owner))
            .await?;
        let backend = Arc::new(Socks5::new(
            BackendId(7),
            endpoint,
            None,
            2,
            Arc::new(connector),
        )?);
        let transport = Arc::new(TcpTransport::new(
            backend.clone(),
            "192.0.2.53:53".parse()?,
            Limits::new(512, 8)?,
            Admission::new(1)?,
        )?);
        let domains = Arc::new(Policy::new(&[Rule::new("example.test", BackendId(7))?], 1)?);
        let (stop, mut cancellation) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut dns = 0;
            let mut tcp = 0;
            let mut transferred = 0;
            loop {
                let (mut stream, _) = tokio::select! {biased;
                    _=cancellation.wait_for(|stopped|*stopped)=>break,
                    accepted=listener.accept()=>accepted?,
                };
                let (is_dns, bytes) =
                    timeout(Duration::from_secs(2), exchange(&mut stream)).await??;
                transferred += bytes;
                if is_dns {
                    dns += 1;
                } else {
                    tcp += 1;
                }
                if dns + tcp > 43 {
                    return Err("selected fixture exceeded its connection budget".into());
                }
            }
            Ok((dns, tcp, transferred))
        });
        Ok(Self {
            transport,
            domains,
            backend,
            stop,
            task,
        })
    }
    pub async fn close(self) -> Result<(usize, usize, usize), Failure> {
        self.stop.send_replace(true);
        self.task.await?
    }
}

async fn exchange(stream: &mut TcpStream) -> Result<(bool, usize), Failure> {
    let mut transferred = 25; // Greeting, method selection, CONNECT and reply.
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 1, 0] {
        return Err("selected fixture received invalid SOCKS methods".into());
    }
    stream.write_all(&[5, 0]).await?;
    let mut connect = [0; 10];
    stream.read_exact(&mut connect).await?;
    if connect[..4] != [5, 1, 0, 1] {
        return Err("selected fixture received invalid SOCKS CONNECT".into());
    }
    let dns = connect[4..] == [192, 0, 2, 53, 0, 53];
    let mut expected = ipv4(70).octets().to_vec();
    expected.extend_from_slice(&8443_u16.to_be_bytes());
    if !dns && connect[4..] != expected {
        return Err("selected fixture received an unexpected destination".into());
    }
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
    if dns {
        let size = usize::from(stream.read_u16().await?);
        if !(12..=512).contains(&size) {
            return Err("selected DNS query exceeds fixture admission".into());
        }
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).await?;
        let query = Packet::request(&bytes, Limits::new(512, 8)?)?;
        if query.question().name != Name::from_ascii("managed.example.test")?
            || query.question().record_type != 1
        {
            return Err("selected DNS query lost domain or type".into());
        }
        bytes[2..4].copy_from_slice(&[0x81, 0x80]);
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 203, 0, 113, 70]);
        let reply = Packet::response(&bytes, &query, Limits::new(512, 8)?)?.encode()?;
        transferred += size + reply.len() + 4;
        stream.write_u16(reply.len() as u16).await?;
        stream.write_all(&reply).await?;
    } else {
        transferred += 32;
        let mut bytes = [0; 16];
        stream.read_exact(&mut bytes).await?;
        if bytes != *b"coordinated flow" {
            return Err("selected SOCKS TCP payload differs".into());
        }
        stream.write_all(&bytes).await?;
    }
    if stream.read(&mut [0]).await? != 0 {
        return Err("selected SOCKS stream did not close after its operation".into());
    }
    stream.shutdown().await?;
    Ok((dns, transferred))
}

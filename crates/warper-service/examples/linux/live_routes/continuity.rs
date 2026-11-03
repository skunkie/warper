// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Keep the same real protected TCP/UDP sockets across native capture updates.

use super::super::{CombinedFailure, physical::protected_udp_connector, protected_connector};
use super::Failure;
use std::{future::poll_fn, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::JoinHandle,
    time::{Instant, timeout},
};
use warper_core::transport::{Request, datagram::DatagramIo};
use warper_service::linux::{
    context::Context,
    egress::{Stream, udp::Datagram},
};

pub(super) struct Peers {
    tcp: Stream,
    udp: Datagram,
    peer: JoinHandle<Result<(), Failure>>,
}
impl Peers {
    pub(super) async fn start(context: Arc<Context>, capture: u32) -> Result<Self, Failure> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = listener.local_addr()?;
        let socket = UdpSocket::bind(endpoint).await?;
        let tcp = protected_connector(context.clone(), vec![endpoint], capture, 1).await?;
        let udp = protected_udp_connector(context, vec![endpoint], capture).await?;
        let (owner, _) = watch::channel(false);
        let request = || Request {
            deadline: Instant::now() + Duration::from_secs(2),
            cancellation: owner.subscribe(),
        };
        let peer = tokio::spawn(async move {
            let tcp = async {
                let (mut stream, _) = listener.accept().await?;
                for index in 0..21 {
                    let mut bytes = [0; 16];
                    stream.read_exact(&mut bytes).await?;
                    if bytes != sample(index) {
                        return Err("continuity TCP payload differs".into());
                    }
                    stream.write_all(&bytes).await?;
                }
                let mut after = [0; 1];
                if stream.read(&mut after).await? != 0 {
                    return Err("continuity TCP FIN differs".into());
                }
                stream.shutdown().await?;
                Ok::<_, Failure>(())
            };
            let udp = async {
                let mut source = None;
                for index in 0..21 {
                    let mut bytes = [0; 17];
                    let (length, address) = socket.recv_from(&mut bytes).await?;
                    if length != 16
                        || bytes[..16] != sample(index)
                        || source.is_some_and(|source| source != address)
                    {
                        return Err("continuity UDP datagram or source differs".into());
                    }
                    source = Some(address);
                    if socket.send_to(&bytes[..length], address).await? != length {
                        return Err("continuity UDP send was partial".into());
                    }
                }
                Ok::<_, Failure>(())
            };
            tokio::try_join!(tcp, udp)?;
            Ok(())
        });
        let connected = async {
            let tcp = tcp.connect(endpoint, request()).await?;
            let udp = udp.connect(endpoint, request()).await?;
            Ok::<_, Failure>((tcp, udp))
        }
        .await;
        match connected {
            Ok((tcp, udp)) => Ok(Self { tcp, udp, peer }),
            Err(primary) => {
                peer.abort();
                match peer.await {
                    Err(error) if error.is_cancelled() => Err(primary),
                    Err(error) => Err(Box::new(CombinedFailure {
                        primary,
                        cleanup: vec![Box::new(error) as Failure],
                    })),
                    Ok(Err(error)) => Err(Box::new(CombinedFailure {
                        primary,
                        cleanup: vec![error],
                    })),
                    Ok(Ok(())) => Err(primary),
                }
            }
        }
    }

    pub(super) async fn exchange(&mut self, index: u8) -> Result<(), Failure> {
        timeout(Duration::from_secs(2), async {
            let bytes = sample(index);
            self.tcp.write_all(&bytes).await?;
            let mut response = [0; 16];
            self.tcp.read_exact(&mut response).await?;
            if response != bytes {
                return Err("protected continuity TCP reply differs".into());
            }
            poll_fn(|context| self.udp.poll_send(context, &bytes)).await?;
            let received = poll_fn(|context| self.udp.poll_recv(context, &mut response)).await?;
            if received.length != bytes.len() || received.truncated || response != bytes {
                return Err("protected continuity UDP reply differs".into());
            }
            Ok::<_, Failure>(())
        })
        .await?
    }

    pub(super) async fn finish(mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        match timeout(Duration::from_secs(1), self.tcp.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(Box::new(error) as Failure),
            Err(error) => errors.push(Box::new(error) as Failure),
        }
        drop(self.tcp);
        drop(self.udp);
        match timeout(Duration::from_secs(1), &mut self.peer).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => errors.push(error),
            Ok(Err(error)) => errors.push(Box::new(error) as Failure),
            Err(error) => {
                errors.push(Box::new(error) as Failure);
                self.peer.abort();
                if let Err(error) = self.peer.await
                    && !error.is_cancelled()
                {
                    errors.push(Box::new(error) as Failure);
                }
            }
        }
        errors
    }
}

fn sample(index: u8) -> [u8; 16] {
    let mut bytes = *b"route-continuity";
    bytes[0] = index;
    bytes
}

// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled in-process IP/TCP baseline; no TUN or physical-network claim.

#[cfg(target_os = "linux")]
#[path = "../src/device.rs"]
mod device;
#[cfg(target_os = "linux")]
#[path = "../src/fixture.rs"]
mod fixture;

#[cfg(target_os = "linux")]
mod linux {
    use crate::fixture::Peer;
    use std::{
        fs, io,
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        task::JoinSet,
    };
    use warper_core::{
        BackendId,
        routing::{Entry, Policy},
    };
    use warper_stack::{
        Seed,
        host::Limits,
        runtime::{Error, Runtime},
    };

    type Failure = Box<dyn std::error::Error + Send + Sync>;
    const ITERATIONS: usize = 100;
    const CONCURRENCY: usize = 4;
    const PAYLOAD: usize = 65536;

    pub async fn run() -> Result<(), Failure> {
        let before = rss("VmRSS:")?;
        let cpu_before = cpu()?;
        let started = Instant::now();
        let (mut latency, emitted, drops) =
            tokio::time::timeout(Duration::from_secs(30), workload()).await??;
        let elapsed = started.elapsed().as_micros();
        let cpu = cpu()?
            .checked_sub(cpu_before)
            .ok_or("CPU counter regressed")?;
        latency.sort_unstable();
        let percentile = |p: usize| latency[(latency.len() * p).div_ceil(100) - 1];
        println!(
            "{{\"iterations\":{ITERATIONS},\"concurrency\":{CONCURRENCY},\"payload_bytes\":{PAYLOAD},\"latency_us\":{{\"p50\":{},\"p95\":{},\"p99\":{}}},\"elapsed_us\":{elapsed},\"cpu_ticks\":{cpu},\"rss_before_kib\":{before},\"peak_rss_kib\":{},\"app_bytes_sent\":{},\"app_bytes_received\":{},\"emitted_ip_packets\":{emitted},\"ingress_queue_drops\":{drops},\"failures\":0}}",
            percentile(50),
            percentile(95),
            percentile(99),
            rss("VmHWM:")?,
            ITERATIONS * PAYLOAD,
            ITERATIONS * PAYLOAD
        );
        Ok(())
    }

    async fn workload() -> Result<(Vec<u128>, u64, u64), Failure> {
        let payload: Arc<[u8]> = (0..PAYLOAD)
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>()
            .into();
        let mut latencies = Vec::with_capacity(ITERATIONS);
        let mut emitted = 0;
        let mut drops = 0;
        for _ in 0..ITERATIONS / CONCURRENCY {
            let batch_started = Instant::now();
            let mut peers: Vec<_> = (0..CONCURRENCY)
                .map(|n| Peer::new(false, 50000 + n as u16))
                .collect();
            let policy = Arc::new(Policy::new(
                &[Entry {
                    network: peers[0].destination.ip(),
                    prefix_len: 32,
                    backend: BackendId(70000),
                }],
                1,
            )?);
            let (runtime, mut channels) = Runtime::new(
                Limits {
                    flows: CONCURRENCY,
                    accepted: CONCURRENCY,
                    ..Limits::default()
                },
                policy,
                64,
                Seed::generate()?,
            )?;
            let owner = tokio::spawn(runtime.run());
            let mut tasks = JoinSet::new();
            let mut accepted = 0;
            let mut sent = [0; CONCURRENCY];
            let mut received = [0; CONCURRENCY];
            let mut closed = [false; CONCURRENCY];
            let mut finished = [false; CONCURRENCY];
            for peer in &mut peers {
                channels.ingress.try_inject(&peer.syn())?;
            }
            while finished.iter().any(|done| !*done) {
                if batch_started.elapsed() > Duration::from_secs(5) {
                    return Err("controlled packet exchange expired".into());
                }
                while let Ok(flow) = channels.tcp.try_recv() {
                    let index = usize::from(
                        flow.metadata
                            .source
                            .port()
                            .checked_sub(50000)
                            .ok_or("unexpected source")?,
                    );
                    let peer = peers.get(index).ok_or("unexpected peer")?;
                    if flow.metadata.source != peer.source
                        || flow.metadata.destination != peer.destination
                        || flow.metadata.backend != BackendId(70000)
                    {
                        return Err("original metadata differs".into());
                    }
                    accepted += 1;
                    let payload = payload.clone();
                    tasks.spawn(async move {
                        let mut stream = flow.into_core().stream;
                        let mut sample = Vec::with_capacity(PAYLOAD + 1);
                        (&mut stream)
                            .take((PAYLOAD + 1) as u64)
                            .read_to_end(&mut sample)
                            .await?;
                        if sample.as_slice() != payload.as_ref() {
                            return Err(io::Error::other("request bytes differ"));
                        }
                        stream.write_all(&payload).await?;
                        stream.shutdown().await
                    });
                }
                for (index, peer) in peers.iter_mut().enumerate() {
                    let socket = peer.tcp();
                    if socket.can_send() && sent[index] < PAYLOAD {
                        sent[index] += socket.send_slice(&payload[sent[index]..])?;
                    }
                    if sent[index] == PAYLOAD && !closed[index] {
                        socket.close();
                        closed[index] = true;
                    }
                    if socket.can_recv() {
                        socket
                            .recv(|bytes| {
                                let end = received[index] + bytes.len();
                                let valid = payload
                                    .get(received[index]..end)
                                    .is_some_and(|expected| expected == bytes);
                                received[index] = end;
                                (bytes.len(), valid)
                            })
                            .map_err(|_| "controlled receive failed")?
                            .then_some(())
                            .ok_or("response bytes differ")?;
                    }
                    if received[index] == PAYLOAD && !socket.may_recv() && !finished[index] {
                        finished[index] = true;
                        latencies.push(batch_started.elapsed().as_micros());
                    }
                    peer.poll(batch_started.elapsed());
                    while let Some(packet) = peer.device.outgoing.pop_front() {
                        match channels.ingress.try_inject(&packet) {
                            Ok(()) => {}
                            Err(Error::QueueFull) => drops += 1,
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                tokio::select! {
                    packet=channels.packets.recv()=>{
                        let packet=packet.ok_or("packet owner stopped unexpectedly")?;
                        if packet.len()<40 {return Err("truncated emitted packet".into());}
                        let port=u16::from_be_bytes([packet[22],packet[23]]);
                        let index=usize::from(port.checked_sub(50000).ok_or("unexpected output tuple")?);
                        peers.get_mut(index).ok_or("unexpected output peer")?.device.inject(packet)?;
                    },
                    ()=tokio::time::sleep(Duration::from_millis(1))=>{},
                }
            }
            while let Some(result) = tasks.join_next().await {
                result??;
            }
            // Every final ACK has entered the bounded owner queue. Give that
            // owner a scheduling turn before requesting its terminal report.
            tokio::time::sleep(Duration::from_millis(1)).await;
            channels
                .shutdown
                .send(())
                .map_err(|_| "shutdown owner lost")?;
            let report = owner.await??;
            if accepted != CONCURRENCY
                || report.tcp.finished != CONCURRENCY as u64
                || report.retained_streams != 0
                || report.rejected_packets != 0
            {
                return Err("controlled lifecycle counters differ".into());
            }
            emitted += report.emitted_packets;
            if channels.packets.recv().await.is_some() {
                return Err("late packet after shutdown".into());
            }
        }
        Ok((latencies, emitted, drops))
    }

    fn cpu() -> Result<u64, Failure> {
        let sample = fs::read_to_string("/proc/self/stat")?;
        let (_, fields) = sample.rsplit_once(')').ok_or("invalid CPU counters")?;
        let fields: Vec<_> = fields.split_whitespace().collect();
        Ok(fields.get(11).ok_or("missing user CPU")?.parse::<u64>()?
            + fields.get(12).ok_or("missing system CPU")?.parse::<u64>()?)
    }
    fn rss(key: &str) -> Result<u64, Failure> {
        let sample = fs::read_to_string("/proc/self/status")?;
        Ok(sample
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or("missing memory counter")?
            .split_whitespace()
            .next()
            .ok_or("invalid memory counter")?
            .parse()?)
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run().await
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedIntegration: workload counters require Linux");
    std::process::ExitCode::FAILURE
}

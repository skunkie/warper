// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled loopback baseline, not a TUN/physical-network performance claim.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs, io,
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::watch,
        task::JoinSet,
    };
    use warper_backends::socks5::Socks5;
    use warper_core::{
        BackendId,
        transport::{Backend, EndpointConnector, Error, OpenTcp, Request, TcpStream as BoxedTcp},
    };

    type Failure = Box<dyn std::error::Error + Send + Sync>;
    const ITERATIONS: usize = 100;
    const CONCURRENCY: usize = 4;
    const PAYLOAD: usize = 65536;

    struct LoopbackConnector;
    impl EndpointConnector for LoopbackConnector {
        fn connect_tcp(&self, endpoint: SocketAddr, request: Request) -> OpenTcp<'_> {
            Box::pin(request.run(async move {
                if !endpoint.ip().is_loopback() {
                    return Err(Error::UnsupportedCapability);
                }
                let stream = TcpStream::connect(endpoint)
                    .await
                    .map_err(|e| Error::Io(e.kind()))?;
                Ok(Box::new(stream) as BoxedTcp)
            }))
        }
    }

    pub async fn run() -> Result<(), Failure> {
        let rss_before = status("VmRSS:")?;
        let cpu_before = cpu_ticks()?;
        let drops_before = drops()?;
        let started = Instant::now();
        let latency = tokio::time::timeout(Duration::from_secs(30), workload()).await??;
        let elapsed = started.elapsed().as_micros();
        let cpu = cpu_ticks()?
            .checked_sub(cpu_before)
            .ok_or("CPU counter regressed")?;
        let drops_after = drops()?;
        let rx_drops = drops_after
            .0
            .checked_sub(drops_before.0)
            .ok_or("drop counter regressed")?;
        let tx_drops = drops_after
            .1
            .checked_sub(drops_before.1)
            .ok_or("drop counter regressed")?;
        let mut latency = latency;
        latency.sort_unstable();
        let percentile = |percent: usize| latency[(latency.len() * percent).div_ceil(100) - 1];
        println!(
            "{{\"iterations\":{ITERATIONS},\"concurrency\":{CONCURRENCY},\"payload_bytes\":{PAYLOAD},\"latency_us\":{{\"p50\":{},\"p95\":{},\"p99\":{}}},\"elapsed_us\":{elapsed},\"cpu_ticks\":{cpu},\"rss_before_kib\":{rss_before},\"peak_rss_kib\":{},\"app_bytes_sent\":{},\"app_bytes_received\":{},\"failures\":0,\"loopback_rx_drop_delta\":{rx_drops},\"loopback_tx_drop_delta\":{tx_drops}}}",
            percentile(50),
            percentile(95),
            percentile(99),
            status("VmHWM:")?,
            ITERATIONS * PAYLOAD,
            ITERATIONS * PAYLOAD
        );
        Ok(())
    }

    async fn workload() -> Result<Vec<u128>, Failure> {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = target.local_addr()?;
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = proxy.local_addr()?;
        let target_task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            for _ in 0..ITERATIONS {
                let (mut socket, _) = target.accept().await?;
                tasks.spawn(async move {
                    let (mut reader, mut writer) = socket.split();
                    tokio::io::copy(&mut reader, &mut writer).await?;
                    writer.shutdown().await?;
                    Ok::<_, io::Error>(())
                });
            }
            while let Some(result) = tasks.join_next().await {
                result??;
            }
            Ok::<_, Failure>(())
        });
        let proxy_task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            for _ in 0..ITERATIONS {
                let (mut socket, _) = proxy.accept().await?;
                tasks.spawn(async move {
                    let mut hello = [0; 3];
                    socket.read_exact(&mut hello).await?;
                    if hello != [5, 1, 0] {
                        return Err(io::Error::other("invalid synthetic greeting"));
                    }
                    socket.write_all(&[5, 0]).await?;
                    let mut header = [0; 8];
                    socket.read_exact(&mut header).await?;
                    if header != [5, 1, 0, 1, 127, 0, 0, 1]
                        || socket.read_u16().await? != destination.port()
                    {
                        return Err(io::Error::other("unexpected synthetic destination"));
                    }
                    let mut upstream = TcpStream::connect(destination).await?;
                    socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    let counts = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
                    if counts != (PAYLOAD as u64, PAYLOAD as u64) {
                        return Err(io::Error::other("synthetic byte count mismatch"));
                    }
                    Ok::<_, io::Error>(())
                });
            }
            while let Some(result) = tasks.join_next().await {
                result??;
            }
            Ok::<_, Failure>(())
        });
        let backend = Arc::new(Socks5::new(
            BackendId(1),
            endpoint,
            None,
            CONCURRENCY,
            Arc::new(LoopbackConnector),
        )?);
        let mut latencies = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS / CONCURRENCY {
            let mut tasks = JoinSet::new();
            for _ in 0..CONCURRENCY {
                let backend = backend.clone();
                tasks.spawn(async move {
                    let started = Instant::now();
                    let (_owner, cancellation) = watch::channel(false);
                    let request = Request {
                        deadline: tokio::time::Instant::now() + Duration::from_secs(5),
                        cancellation,
                    };
                    let mut stream = backend.open_tcp(destination, request).await?;
                    let payload = vec![b'w'; PAYLOAD];
                    stream.write_all(&payload).await?;
                    stream.shutdown().await?;
                    let mut actual = Vec::with_capacity(PAYLOAD + 1);
                    stream
                        .take((PAYLOAD + 1) as u64)
                        .read_to_end(&mut actual)
                        .await?;
                    if actual != payload {
                        return Err("synthetic payload mismatch".into());
                    }
                    Ok::<_, Failure>(started.elapsed().as_micros())
                });
            }
            while let Some(result) = tasks.join_next().await {
                latencies.push(result??);
            }
        }
        target_task.await??;
        proxy_task.await??;
        Ok(latencies)
    }

    fn cpu_ticks() -> Result<u64, Failure> {
        let sample = fs::read_to_string("/proc/self/stat")?;
        let (_, fields) = sample.rsplit_once(')').ok_or("invalid proc stat")?;
        let fields: Vec<_> = fields.split_whitespace().collect();
        Ok(fields.get(11).ok_or("missing user CPU")?.parse::<u64>()?
            + fields.get(12).ok_or("missing system CPU")?.parse::<u64>()?)
    }
    fn status(key: &str) -> Result<u64, Failure> {
        let sample = fs::read_to_string("/proc/self/status")?;
        let line = sample
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or("missing memory metric")?;
        Ok(line
            .split_whitespace()
            .next()
            .ok_or("missing memory value")?
            .parse()?)
    }
    fn drops() -> Result<(u64, u64), Failure> {
        let sample = fs::read_to_string("/proc/net/dev")?;
        let line = sample
            .lines()
            .find_map(|line| line.trim().strip_prefix("lo:"))
            .ok_or("missing loopback interface")?;
        let fields: Vec<_> = line.split_whitespace().collect();
        Ok((
            fields.get(3).ok_or("missing RX drop counter")?.parse()?,
            fields.get(11).ok_or("missing TX drop counter")?.parse()?,
        ))
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedCapability: Linux process counters are required for this workload");
    std::process::ExitCode::FAILURE
}

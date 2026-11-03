// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled bound TCP/UDP API experiments and production protected transport regressions.

use super::{Failure, ip, isolated, join_native, preserve, protected_connector};
use std::{
    future::poll_fn,
    io,
    io::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpSocket, UdpSocket},
};
use tun_rs::DeviceBuilder;
use warper_core::transport::Request;
use warper_core::transport::datagram::DatagramIo;
use warper_service::linux::{link_lookup, route_lookup};

const NAMESPACE: &str = "warper-peer";
const EGRESS: &str = "warper-egress";
const PEER: &str = "warper-peer";
const CAPTURE: &str = "warper-capture";
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const DESTINATION: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const PORT: u16 = 40123;
const SAMPLE: &[u8] = b"controlled-tcp";
const UDP_SAMPLES: [&[u8]; 2] = [b"first-udp", b"second-udp-with-other-length"];

pub(super) async fn exercise(
    context: Arc<warper_service::linux::context::Context>,
    mount: &str,
    net: &str,
) -> Result<(), Failure> {
    let mut namespace_created = false;
    let mut link_created = false;
    let result = async {
        ip(&["netns", "add", NAMESPACE])?;
        namespace_created = true;
        ip(&["link", "add", EGRESS, "type", "veth", "peer", "name", PEER])?;
        link_created = true;
        ip(&["link", "set", PEER, "netns", NAMESPACE])?;
        ip(&["address", "add", "192.0.2.1/30", "dev", EGRESS])?;
        ip(&["link", "set", EGRESS, "up"])?;
        ip(&[
            "-n",
            NAMESPACE,
            "address",
            "add",
            "192.0.2.2/30",
            "dev",
            PEER,
        ])?;
        ip(&["-n", NAMESPACE, "link", "set", PEER, "up"])?;
        ip(&["-n", NAMESPACE, "link", "set", "lo", "up"])?;
        exchange(context, mount, net).await
    }
    .await;
    let mut cleanup = Vec::new();
    if link_created && let Err(error) = ip(&["link", "del", EGRESS]) {
        cleanup.push(error);
    }
    if namespace_created && let Err(error) = ip(&["netns", "del", NAMESPACE]) {
        cleanup.push(error);
    }
    preserve(result, cleanup)
}

async fn exchange(
    context: Arc<warper_service::linux::context::Context>,
    mount: &str,
    net: &str,
) -> Result<(), Failure> {
    let endpoint = SocketAddrV4::new(DESTINATION, PORT);
    let (request_owner, _) = tokio::sync::watch::channel(false);
    let request = || Request {
        deadline: tokio::time::Instant::now() + Duration::from_secs(2),
        cancellation: request_owner.subscribe(),
    };
    let initial = route_lookup::lookup(
        route_lookup::Query {
            protocol: route_lookup::Protocol::Tcp,
            destination: endpoint,
            source: None,
            interface: None,
        },
        request(),
    )
    .await?;
    let egress = link_lookup::lookup(link_lookup::Query::Name(EGRESS), request()).await?;
    if initial.interface != egress.index
        || initial.source != SOURCE
        || initial.kind != route_lookup::Kind::Unicast
    {
        return Err("controlled TCP initial egress differs".into());
    }
    let socket = TcpSocket::new_v4()?;
    socket.bind_device(Some(EGRESS.as_bytes()))?;
    socket.bind(SocketAddrV4::new(SOURCE, 0).into())?;
    if socket.device()?.as_deref() != Some(EGRESS.as_bytes()) {
        return Err("controlled TCP device binding readback differs".into());
    }
    let SocketAddr::V4(source) = socket.local_addr()? else {
        return Err("controlled TCP bound family differs".into());
    };
    if source.ip() != &SOURCE || source.port() == 0 {
        return Err("controlled TCP source binding differs".into());
    }
    let udp_initial = route_lookup::lookup(
        route_lookup::Query {
            protocol: route_lookup::Protocol::Udp,
            destination: endpoint,
            source: None,
            interface: None,
        },
        request(),
    )
    .await?;
    if udp_initial != initial {
        return Err("controlled UDP initial path differs".into());
    }
    // Binding allocates a local port but emits no datagram. Constrain the device
    // and verify the UDP tuple before connecting or sending anything.
    let udp = UdpSocket::bind(SocketAddrV4::new(SOURCE, 0)).await?;
    udp.bind_device(Some(EGRESS.as_bytes()))?;
    let SocketAddr::V4(udp_source) = udp.local_addr()? else {
        return Err("controlled UDP bound family differs".into());
    };
    if udp_source.ip() != &SOURCE
        || udp_source.port() == 0
        || udp.device()?.as_deref() != Some(EGRESS.as_bytes())
    {
        return Err("controlled UDP source/device readback differs".into());
    }
    let capture = DeviceBuilder::new().mtu(1280).enable(true).build_sync()?;
    capture.set_name(CAPTURE)?;
    capture.set_nonblocking(true)?;
    let connector = protected_connector(
        context.clone(),
        vec![endpoint.into()],
        capture.if_index()?,
        1,
    )
    .await?;
    let udp_connector = protected_udp_connector(context, endpoint, capture.if_index()?).await?;
    ip(&[
        "route",
        "add",
        "192.0.2.2/32",
        "dev",
        CAPTURE,
        "src",
        "192.0.2.1",
    ])?;
    let intercepted = route_lookup::lookup(
        route_lookup::Query {
            protocol: route_lookup::Protocol::Tcp,
            destination: endpoint,
            source: Some(source),
            interface: None,
        },
        request(),
    )
    .await?;
    if intercepted.interface.get() != capture.if_index()? {
        return Err("controlled competing route did not select the TUN".into());
    }
    let protected = route_lookup::lookup(
        route_lookup::Query {
            protocol: route_lookup::Protocol::Tcp,
            destination: endpoint,
            source: Some(source),
            interface: Some(egress.index),
        },
        request(),
    )
    .await?;
    if protected != initial {
        return Err("bound TCP tuple route no longer uses its original egress".into());
    }
    let udp_query = route_lookup::Query {
        protocol: route_lookup::Protocol::Udp,
        destination: endpoint,
        source: Some(udp_source),
        interface: None,
    };
    if route_lookup::lookup(udp_query, request())
        .await?
        .interface
        .get()
        != capture.if_index()?
    {
        return Err("controlled competing UDP route did not select the TUN".into());
    }
    if route_lookup::lookup(
        route_lookup::Query {
            interface: Some(egress.index),
            ..udp_query
        },
        request(),
    )
    .await?
        != udp_initial
    {
        return Err("bound UDP tuple route no longer uses its original egress".into());
    }

    let mut child = Command::new("ip")
        .args(["netns", "exec", NAMESPACE])
        .arg(std::env::current_exe()?)
        .args(["--physical-peer", mount, net])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let result: Result<(), Failure> = async {
        let pipe = child
            .stdout
            .take()
            .ok_or("controlled TCP readiness pipe missing")?;
        let mut ready = tokio::net::unix::pipe::Receiver::from_owned_fd(pipe.into())?;
        let mut marker = [0; 6];
        tokio::time::timeout(Duration::from_secs(2), ready.read_exact(&mut marker)).await??;
        if &marker != b"READY\n" {
            return Err("controlled TCP readiness marker differs".into());
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            udp.connect(SocketAddr::V4(endpoint)).await?;
            if udp.local_addr()? != SocketAddr::V4(udp_source)
                || udp.peer_addr()? != SocketAddr::V4(endpoint)
            {
                return Err("controlled UDP actual tuple differs".into());
            }
            for sample in UDP_SAMPLES {
                if udp.send(sample).await? != sample.len() {
                    return Err("controlled UDP send lost its datagram boundary".into());
                }
                let mut response = [0; 64];
                let length = udp.recv(&mut response).await?;
                let mut expected = udp_source.port().to_be_bytes().to_vec();
                expected.extend_from_slice(sample);
                if response[..length] != expected {
                    return Err("controlled UDP source/boundary response differs".into());
                }
            }
            Ok::<_, Failure>(())
        })
        .await??;
        drop(udp);
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = socket.connect(endpoint.into()).await?;
            if stream.local_addr()? != SocketAddr::V4(source)
                || stream.peer_addr()? != SocketAddr::V4(endpoint)
            {
                return Err("controlled TCP actual tuple differs".into());
            }
            stream.write_all(SAMPLE).await?;
            stream.shutdown().await?;
            let mut response = Vec::with_capacity(12);
            (&mut stream).take(12).read_to_end(&mut response).await?;
            let mut expected = source.port().to_be_bytes().to_vec();
            expected.extend_from_slice(b"after-fin");
            if response != expected {
                return Err("controlled TCP source/FIN response differs".into());
            }
            Ok::<_, Failure>(())
        })
        .await??;
        let mut udp_reader = protected_udp_exchange(&udp_connector, endpoint, &request_owner).await?;
        if let Err(error) = protected_exchange(&connector, endpoint, &request_owner).await {
            let cleanup = cancel_reader(udp_reader).await;
            return preserve(Err(error), cleanup);
        }
        let (datagram, result) = match tokio::time::timeout(Duration::from_secs(1), &mut udp_reader).await {
            Ok(joined) => joined?,
            Err(_) => {
                let cleanup = cancel_reader(udp_reader).await;
                return preserve(Err("network change did not wake protected UDP reader".into()), cleanup);
            }
        };
        let error = result.err().ok_or("idle UDP receive did not fail on path change")?;
        if error.kind() != io::ErrorKind::NetworkUnreachable || error.get_ref().and_then(|error| error.downcast_ref::<warper_service::linux::egress::PathInvalidated>()).is_none() {
            return Err("UDP path invalidation lost its typed cause".into());
        }
        if !matches!(udp_connector.connect(endpoint.into(), request()).await, Err(warper_service::linux::egress::Error::ResourceLimit)) {
            return Err("invalidated UDP object released ownership before drop".into());
        }
        drop(datagram);
        if !matches!(udp_connector.connect(endpoint.into(), request()).await, Err(warper_service::linux::egress::Error::PathMismatch)) {
            return Err("changed UDP path selected an implicit replacement".into());
        }
        println!("PASS production protected UDP under capture, truncation, zero datagrams, retained admission and independently woken idle invalidation without fallback");
        let mut buffer = [0; 1281];
        for _ in 0..32 {
            match capture.recv(&mut buffer) {
                Ok(length) if length > 0 && buffer[0] >> 4 != 4 => {}
                Ok(_) => {
                    return Err("bound transport traffic entered the competing capture TUN".into());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        Err("controlled TCP packet observation limit exceeded".into())
    }
    .await;
    let failed = result.is_err();
    let jobs = warper_service::native::Workers::new(1)?;
    let mut joining = jobs.try_reserve()?.start(move || -> Result<(), Failure> {
        if failed && child.try_wait()?.is_none() {
            child.kill()?;
        }
        let status = child.wait()?;
        if !failed && !status.success() {
            return Err("controlled TCP peer failed".into());
        }
        Ok(())
    });
    let joined = join_native(&mut joining, &request_owner).await?;
    drop(capture);
    let cleanup = joined.err().into_iter().collect();
    preserve(result, cleanup)?;
    println!(
        "PASS source/device-bound TCP and UDP tuples bypass a competing TUN /32, preserve FIN/datagram boundaries and join their isolated peer"
    );
    Ok(())
}

async fn protected_udp_connector(
    context: Arc<warper_service::linux::context::Context>,
    endpoint: SocketAddrV4,
    excluded: u32,
) -> Result<warper_service::linux::egress::udp::Connector, Failure> {
    let jobs = warper_service::native::Workers::new(1)?;
    let excluded = std::num::NonZeroU32::new(excluded).ok_or("capture index missing")?;
    let (owner, _) = tokio::sync::watch::channel(false);
    let mut task = jobs.try_reserve()?.start(move || {
        warper_service::linux::egress::udp::Preparation::new(
            context,
            &[endpoint.into()],
            excluded,
            1,
        )
    });
    let preparation = join_native(&mut task, &owner).await??;
    Ok(preparation
        .prepare(Request {
            deadline: tokio::time::Instant::now() + Duration::from_secs(2),
            cancellation: owner.subscribe(),
        })
        .await?)
}

type UdpReader =
    tokio::task::JoinHandle<(warper_service::linux::egress::udp::Datagram, io::Result<()>)>;

async fn protected_udp_exchange(
    connector: &warper_service::linux::egress::udp::Connector,
    endpoint: SocketAddrV4,
    owner: &tokio::sync::watch::Sender<bool>,
) -> Result<UdpReader, Failure> {
    let request = || Request {
        deadline: tokio::time::Instant::now() + Duration::from_secs(2),
        cancellation: owner.subscribe(),
    };
    if !matches!(
        connector
            .connect("[2001:db8::2]:53".parse()?, request())
            .await,
        Err(warper_service::linux::egress::Error::UnsupportedPath)
    ) {
        return Err("protected UDP accepted an unsupported family".into());
    }
    if !matches!(
        connector
            .connect(SocketAddrV4::new(DESTINATION, PORT + 1).into(), request())
            .await,
        Err(warper_service::linux::egress::Error::InvalidInput)
    ) {
        return Err("protected UDP accepted an unprepared endpoint".into());
    }
    let mut expired = request();
    expired.deadline = tokio::time::Instant::now();
    if !matches!(
        connector.connect(endpoint.into(), expired).await,
        Err(warper_service::linux::egress::Error::Deadline)
    ) {
        return Err("protected UDP ignored an expired setup deadline".into());
    }
    let mut datagram = connector.connect(endpoint.into(), request()).await?;
    if datagram.endpoint() != endpoint {
        return Err("protected UDP endpoint differs".into());
    }
    if !matches!(
        connector.connect(endpoint.into(), request()).await,
        Err(warper_service::linux::egress::Error::ResourceLimit)
    ) {
        return Err("live UDP association released its admission".into());
    }
    let source = datagram.source();
    tokio::time::timeout(Duration::from_secs(2), async {
        for (index, sample) in UDP_SAMPLES.into_iter().enumerate() {
            poll_fn(|context| datagram.poll_send(context, sample)).await?;
            let mut bytes = [0; 64];
            let capacity = if index == 0 { 1 } else { bytes.len() };
            let received = poll_fn(|context| datagram.poll_recv(context, &mut bytes[..capacity])).await?;
            let mut expected = source.port().to_be_bytes().to_vec();
            expected.extend_from_slice(sample);
            if received.length != expected.len().min(capacity) || received.truncated != (index == 0)
                || bytes[..received.length] != expected[..received.length] {
                return Err("protected UDP truncation/boundary differs".into());
            }
        }
        let drops_before = egress_drops()?;
        let started = tokio::time::Instant::now();
        let cpu_before = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let mut latencies = Vec::with_capacity(200);
        let mut bytes_transferred = 0;
        for _ in 0..100 {
            for sample in UDP_SAMPLES {
                let before = tokio::time::Instant::now();
                poll_fn(|context| datagram.poll_send(context, sample)).await?;
                let mut bytes = [0; 64];
                let received = poll_fn(|context| datagram.poll_recv(context, &mut bytes)).await?;
                let mut expected = source.port().to_be_bytes().to_vec();
                expected.extend_from_slice(sample);
                if received.truncated || bytes[..received.length] != expected {
                    return Err("protected UDP workload response differs".into());
                }
                bytes_transferred += sample.len() + received.length;
                latencies.push(before.elapsed().as_nanos());
            }
        }
        let elapsed = started.elapsed();
        let drops_after = egress_drops()?;
        let cpu_after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let cpu_ns = (i128::from(cpu_after.tv_sec) - i128::from(cpu_before.tv_sec)) * 1_000_000_000
            + i128::from(cpu_after.tv_nsec) - i128::from(cpu_before.tv_nsec);
        latencies.sort_unstable();
        let status = std::fs::read_to_string("/proc/self/status")?;
        let peak = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("UDP workload peak RSS missing")?;
        let rx_drops = drops_after.0.checked_sub(drops_before.0).ok_or("UDP receive drop counter reset")?;
        let tx_drops = drops_after.1.checked_sub(drops_before.1).ok_or("UDP transmit drop counter reset")?;
        println!("UDP workload datagrams=200 bytes={bytes_transferred} elapsed_ns={} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} rx_drops={rx_drops} tx_drops={tx_drops} {peak}; probe process CPU/cumulative peak RSS, peer process excluded, private egress counters", elapsed.as_nanos(), latencies[99], latencies[189], latencies[197]);
        let oversized = vec![0; 65508];
        if !matches!(poll_fn(|context| datagram.poll_send(context, &oversized)).await, Err(error) if error.kind() == io::ErrorKind::InvalidInput) {
            return Err("oversized IPv4 UDP payload was accepted".into());
        }
        poll_fn(|context| datagram.poll_send(context, &[])).await?;
        let mut bytes = [0; 64];
        let received = poll_fn(|context| datagram.poll_recv(context, &mut bytes)).await?;
        if received.length != 0 || received.truncated {
            return Err("protected zero UDP datagram differs".into());
        }
        Ok::<_, Failure>(())
    }).await??;
    drop(datagram);
    let mut datagram = connector.connect(endpoint.into(), request()).await?;
    let (parked, ready) = tokio::sync::oneshot::channel();
    let reader = tokio::spawn(async move {
        let mut bytes = [0; 1];
        let mut parked = Some(parked);
        let result = poll_fn(|context| {
            let result = datagram.poll_recv(context, &mut bytes);
            if result.is_pending()
                && let Some(parked) = parked.take()
                && parked.send(()).is_err()
            {
                return std::task::Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
            }
            result
        })
        .await
        .map(|_| ());
        (datagram, result)
    });
    if !matches!(
        tokio::time::timeout(Duration::from_secs(1), ready).await,
        Ok(Ok(()))
    ) {
        let cleanup = cancel_reader(reader).await;
        let primary: Failure = "protected UDP reader did not park".into();
        return Err(if cleanup.is_empty() {
            primary
        } else {
            Box::new(super::CombinedFailure { primary, cleanup })
        });
    }
    Ok(reader)
}

fn egress_drops() -> Result<(u64, u64), Failure> {
    let counters = std::fs::read_to_string("/proc/net/dev")?;
    let line = counters
        .lines()
        .find_map(|line| {
            let (name, values) = line.split_once(':')?;
            (name.trim() == EGRESS).then_some(values)
        })
        .ok_or("UDP fixture egress counters missing")?;
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 16 {
        return Err("UDP fixture egress counters malformed".into());
    }
    Ok((fields[3].parse()?, fields[11].parse()?))
}

async fn protected_exchange(
    connector: &warper_service::linux::egress::Connector,
    endpoint: SocketAddrV4,
    owner: &tokio::sync::watch::Sender<bool>,
) -> Result<(), Failure> {
    use warper_service::linux::egress::{Error as EgressError, PathInvalidated};
    let request = || Request {
        deadline: tokio::time::Instant::now() + Duration::from_secs(2),
        cancellation: owner.subscribe(),
    };
    let mut stream = connector.connect(endpoint.into(), request()).await?;
    let source = stream.source();
    if stream.endpoint() != endpoint {
        return Err("protected stream endpoint differs".into());
    }
    stream.write_all(SAMPLE).await?;
    stream.shutdown().await?;
    if !matches!(
        connector.connect(endpoint.into(), request()).await,
        Err(EgressError::ResourceLimit)
    ) {
        return Err("TCP half-close released protected stream admission".into());
    }
    let mut response = Vec::with_capacity(12);
    tokio::time::timeout(
        Duration::from_secs(2),
        (&mut stream).take(12).read_to_end(&mut response),
    )
    .await??;
    let mut expected = source.port().to_be_bytes().to_vec();
    expected.extend_from_slice(b"after-fin");
    if response != expected {
        return Err("protected stream source/FIN response differs".into());
    }
    drop(stream);
    let mut stream = connector.connect(endpoint.into(), request()).await?;
    let (parked, ready) = tokio::sync::oneshot::channel();
    let mut reader = tokio::spawn(async move {
        let mut byte = [0; 1];
        let mut buffer = ReadBuf::new(&mut byte);
        let mut parked = Some(parked);
        let result = poll_fn(|context| {
            let result = Pin::new(&mut stream).poll_read(context, &mut buffer);
            if result.is_pending()
                && let Some(parked) = parked.take()
                && parked.send(()).is_err()
            {
                return std::task::Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
            }
            result
        })
        .await;
        (stream, result)
    });
    if !matches!(
        tokio::time::timeout(Duration::from_secs(1), ready).await,
        Ok(Ok(()))
    ) {
        let cleanup = cancel_reader(reader).await;
        return preserve(Err("protected idle reader did not park".into()), cleanup);
    }
    if let Err(primary) = ip(&["link", "set", EGRESS, "mtu", "1400"]) {
        let cleanup = cancel_reader(reader).await;
        return preserve(Err(primary), cleanup);
    }
    // The timeout observes a separate task; it cannot poll or wake that task's
    // read future. Completion therefore needs the network-monitor waker.
    let (stream, result) = match tokio::time::timeout(Duration::from_secs(1), &mut reader).await {
        Ok(joined) => joined?,
        Err(_) => {
            let cleanup = cancel_reader(reader).await;
            return preserve(
                Err("network change did not wake the protected idle reader".into()),
                cleanup,
            );
        }
    };
    let error = result
        .err()
        .ok_or("idle stream did not fail on path change")?;
    if error.kind() != io::ErrorKind::NetworkUnreachable
        || error
            .get_ref()
            .and_then(|error| error.downcast_ref::<PathInvalidated>())
            .is_none()
    {
        return Err("path invalidation lost its typed native failure".into());
    }
    drop(stream);
    if !matches!(
        connector.connect(endpoint.into(), request()).await,
        Err(EgressError::PathMismatch)
    ) {
        return Err("changed egress selected a replacement path implicitly".into());
    }
    println!(
        "PASS production protected TCP under capture, retained half-close admission and idle change invalidation without path fallback"
    );
    Ok(())
}

async fn cancel_reader<T>(reader: tokio::task::JoinHandle<(T, io::Result<()>)>) -> Vec<Failure> {
    reader.abort();
    match reader.await {
        Err(error) if error.is_cancelled() => Vec::new(),
        Err(error) => vec![Box::new(error)],
        Ok((_stream, Err(error))) => vec![Box::new(error)],
        Ok((_stream, Ok(()))) => Vec::new(),
    }
}

pub(super) async fn peer(mount: &str, net: &str) -> Result<(), Failure> {
    isolated(mount, net)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = TcpListener::bind((DESTINATION, PORT)).await?;
        let udp = UdpSocket::bind((DESTINATION, PORT)).await?;
        io::stdout().write_all(b"READY\n")?;
        io::stdout().flush()?;
        // The client interleaves TCP checks with UDP workload phases. Poll
        // both listeners so neither protocol waits for the other to finish.
        let udp_flow = async {
            for sample in UDP_SAMPLES.into_iter().cycle().take(204) {
                let mut data = [0; 64];
                let (length, source) = udp.recv_from(&mut data).await?;
                if source.ip() != SOURCE || data[..length] != *sample {
                    return Err("controlled UDP peer source/boundary differs".into());
                }
                let mut response = source.port().to_be_bytes().to_vec();
                response.extend_from_slice(sample);
                if udp.send_to(&response, source).await? != response.len() {
                    return Err("controlled UDP peer response boundary differs".into());
                }
            }
            let mut empty = [0; 1];
            let (length, source) = udp.recv_from(&mut empty).await?;
            if length != 0 || source.ip() != SOURCE || udp.send_to(&[], source).await? != 0 {
                return Err("controlled zero-length UDP datagram differs".into());
            }
            Ok::<_, Failure>(())
        };
        let tcp_flow = async {
            for _ in 0..2 {
                let (mut stream, source) = server.accept().await?;
                if source.ip() != SOURCE {
                    return Err("controlled TCP peer source differs".into());
                }
                let mut request = Vec::with_capacity(SAMPLE.len() + 1);
                (&mut stream)
                    .take(SAMPLE.len() as u64 + 1)
                    .read_to_end(&mut request)
                    .await?;
                if request != SAMPLE {
                    return Err("controlled TCP peer request differs".into());
                }
                stream.write_all(&source.port().to_be_bytes()).await?;
                stream.write_all(b"after-fin").await?;
                stream.shutdown().await?;
            }
            let (mut stream, _) = server.accept().await?;
            let mut request = Vec::with_capacity(1);
            (&mut stream).take(1).read_to_end(&mut request).await?;
            if !request.is_empty() {
                return Err("invalidated idle stream emitted application payload".into());
            }
            Ok::<_, Failure>(())
        };
        tokio::try_join!(udp_flow, tcp_flow)?;
        Ok::<_, Failure>(())
    })
    .await?
}

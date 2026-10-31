// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled bound-TCP API experiment, not a production physical-path lease.

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
    net::{TcpListener, TcpSocket},
};
use tun_rs::DeviceBuilder;
use warper_core::transport::Request;
use warper_service::linux::{link_lookup, route_lookup};

const NAMESPACE: &str = "warper-peer";
const EGRESS: &str = "warper-egress";
const PEER: &str = "warper-peer";
const CAPTURE: &str = "warper-capture";
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const DESTINATION: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const PORT: u16 = 40123;
const SAMPLE: &[u8] = b"controlled-tcp";

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
    let capture = DeviceBuilder::new().mtu(1280).enable(true).build_sync()?;
    capture.set_name(CAPTURE)?;
    capture.set_nonblocking(true)?;
    let connector =
        protected_connector(context, vec![endpoint.into()], capture.if_index()?, 1).await?;
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
        protected_exchange(&connector, endpoint, &request_owner).await?;
        let mut buffer = [0; 1281];
        for _ in 0..32 {
            match capture.recv(&mut buffer) {
                Ok(length) if length > 0 && buffer[0] >> 4 != 4 => {}
                Ok(_) => return Err("bound TCP traffic entered the competing capture TUN".into()),
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
        "PASS source/device-bound TCP tuple bypasses a competing TUN /32, preserves FIN and joins its isolated peer"
    );
    Ok(())
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

async fn cancel_reader(
    reader: tokio::task::JoinHandle<(warper_service::linux::egress::Stream, io::Result<()>)>,
) -> Vec<Failure> {
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
        io::stdout().write_all(b"READY\n")?;
        io::stdout().flush()?;
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
    })
    .await?
}

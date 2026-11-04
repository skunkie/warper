// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real coordinator transactions, reply gating and retained native ownership.

use super::{Failure, capture_change, ip, join_native, owned_packet_port, preserve};
use std::{
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{Instant, timeout},
};
use warper_config::schema::RoutingMode;
use warper_control::runtime::{
    RuntimeLease,
    journal::{Error as StorageError, NetworkJournal},
};
use warper_core::{
    BackendId,
    dns::{Name, lease},
    routing::{Policy, SelectionError},
    transport::{Error as TransportError, Request},
};
use warper_service::{
    dns::{Limits as PacketLimits, Packet, routes::Controller},
    linux::{
        context::Context,
        dns_routes::{Completion, Error, Limits, Manager},
        packet::Pump,
        tun,
    },
    native::Workers,
};
use warper_stack::{
    Seed,
    host::Limits as HostLimits,
    runtime::{Runtime, udp_dns},
};

pub(super) async fn exercise(
    context: Arc<Context>,
    lease: Arc<RuntimeLease>,
) -> Result<(), Failure> {
    // A single blocking thread lets the fixture deterministically queue a real
    // native operation behind a bounded gate, without a production test hook.
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()?
            .block_on(run(context, lease))
    })
    .await?
}

async fn run(context: Arc<Context>, lease: Arc<RuntimeLease>) -> Result<(), Failure> {
    let (owner, port) = owned_packet_port(context).await?;
    let mut native = Some(owner);
    let tun_name = native
        .as_ref()
        .and_then(tun::Owner::name)
        .ok_or("coordinator TUN name unavailable")?
        .to_owned();
    let port = Arc::new(port);
    let controller = Arc::new(Controller::new(
        Arc::new(Policy::new(&[], 8)?),
        lease::Limits {
            lease_entries: 8,
            route_entries: 8,
            response_entries: 4,
            flow_entries: 4,
            addresses_per_response: 4,
            bytes: 128 * 1024,
        },
        Instant::now(),
    )?);
    let (runtime, mut channels) = Runtime::with_udp_dns(
        HostLimits::default(),
        controller.selector(),
        8,
        Seed::generate()?,
        udp_dns::Config {
            endpoint: "203.0.113.53:53".parse()?,
            requests: 2,
        },
    )?;
    let mut dns = channels
        .udp_dns
        .take()
        .ok_or("virtual DNS endpoint unavailable")?;
    let workers = Arc::new(Workers::new(1)?);
    let limit = Limits {
        addresses_per_response: 4,
        bytes: 64 * 1024,
    };
    let exclusions = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(ipv4(72)),
        IpAddr::V4(ipv4(53)),
    ];
    if !matches!(
        Manager::new(
            controller.clone(),
            channels.publication.clone(),
            &mut native,
            workers.clone(),
            Limits { bytes: 1, ..limit },
            &exclusions
        ),
        Err(Error::ResourceLimit)
    ) || native.is_none()
    {
        return Err("coordinator allocation failure lost native ownership".into());
    }
    let other = Arc::new(Controller::new(
        Arc::new(Policy::new(&[], 1)?),
        lease::Limits {
            lease_entries: 1,
            route_entries: 1,
            response_entries: 1,
            flow_entries: 1,
            addresses_per_response: 1,
            bytes: 128 * 1024,
        },
        Instant::now(),
    )?);
    if !matches!(
        Manager::new(
            other,
            channels.publication.clone(),
            &mut native,
            workers.clone(),
            limit,
            &exclusions
        ),
        Err(Error::InvalidState)
    ) || native.is_none()
    {
        return Err("coordinator accepted another selector or lost the original owner".into());
    }
    let mut manager = Manager::new(
        controller.clone(),
        channels.publication.clone(),
        &mut native,
        workers.clone(),
        limit,
        &exclusions,
    )?;
    let reserved = manager.reserved_bytes();
    let mut pump = Pump::new(
        port.clone(),
        channels.ingress.clone(),
        channels.packets,
        Duration::from_secs(2),
    )?;
    let (stop, cancellation) = watch::channel(false);
    let (service_owner, _) = watch::channel(false);
    let mut gate = Gate::default();
    let mut watcher = None;
    let watcher_stop = Arc::new(AtomicBool::new(false));
    let mut latency = Vec::with_capacity(20);
    let mut saw_intent = false;
    // Fixture-owned DNS capture only. Production route publication still
    // requires both DNS transports and daemon lifecycle integration.
    ip(&[
        "route",
        "add",
        "203.0.113.53/32",
        "dev",
        &tun_name,
        "metric",
        "3",
    ])?;
    ip(&[
        "route",
        "add",
        "203.0.113.75/32",
        "dev",
        "lo",
        "metric",
        "4",
    ])?;
    let foreign_before = ip(&["-j", "route", "show", "exact", "203.0.113.75/32"])?;
    let packets = tokio::spawn(async move {
        let result = pump.run(cancellation).await;
        (pump, result)
    });
    let host = tokio::spawn(runtime.run());
    let started = Instant::now();
    let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let outcome = async {
        let response = reserve(&controller, &[ipv4(71), ipv4(72)])?;
        if manager.begin_commit(response, request(&service_owner)) != Err(Error::ExcludedEndpoint) {
            return Err("coordinator did not reject the entire excluded answer".into());
        }
        if !ip(&["route", "show", "exact", "203.0.113.71/32"])?.is_empty() {
            return Err("whole-response preflight allowed a partial native mutation".into());
        }
        sweep(&mut manager, &service_owner).await?;
        if controller.stats()?.routes != 0 {
            return Err("rejected answer leaked address ownership".into());
        }
        let response = reserve(&controller, &[ipv4(71), Ipv4Addr::UNSPECIFIED])?;
        if manager.begin_commit(response, request(&service_owner)) != Err(Error::InvalidAddress) {
            return Err("coordinator accepted an unsupported capture address".into());
        }
        sweep(&mut manager, &service_owner).await?;
        if controller.stats()?.routes != 0 {
            return Err("unsupported answer leaked unpublished address ownership".into());
        }

        let response = reserve(&controller, &[ipv4(70)])?;
        let route = controller.response_route(&response, 0)?;
        manager.begin_commit(response, request(&service_owner))?;
        let ready = gate.start();
        ready.await?;
        let (observer, cancellation) = watch::channel(false);
        let polled = {
            let mut observation = std::pin::pin!(manager.wait(Request {
                deadline: Instant::now() + Duration::from_secs(10),
                cancellation: cancellation.clone()
            }));
            poll_fn(|context| Poll::Ready(observation.as_mut().poll(context))).await
        };
        if !matches!(polled, Poll::Pending)
            || !matches!(
                workers.try_reserve(),
                Err(warper_service::native::Error::Busy)
            )
        {
            return Err("fixture did not retain the queued native operation".into());
        }
        observer.send_replace(true);
        if !matches!(
            manager
                .wait(Request {
                    deadline: Instant::now() + Duration::from_secs(10),
                    cancellation
                })
                .await,
            Err(Error::WaitCancelled)
        ) || !manager.has_pending()
            || !matches!(manager.release(), Err(Error::Busy))
            || controller.stats()?.responses != 1
            || !matches!(
                controller.selector().select_flow(ipv4(70).into()),
                Err(SelectionError::Unready)
            )
        {
            return Err(
                "cancelled observation discarded work or exposed an uncommitted answer".into(),
            );
        }
        gate.release().await?;
        let response = match manager.wait(request(&service_owner)).await? {
            Completion::Committed(response) => response,
            Completion::Retired => return Err("commit returned retirement".into()),
        };
        if controller.route_info(route)?.publication != lease::Publication::Committed {
            return Err("coordinator exposed a response before committed publication".into());
        }
        dns_reply(&controller, response).await?;
        udp_dns_reply(&mut dns).await?;
        timeout(Duration::from_secs(2), async {
            let (mut application, mut accepted) = tokio::try_join!(
                async { Ok::<_, Failure>(TcpStream::connect((ipv4(70), 8443)).await?) },
                async {
                    channels
                        .tcp
                        .recv()
                        .await
                        .ok_or_else(|| "coordinated acceptance stopped".into())
                }
            )?;
            if accepted.metadata.backend != BackendId(7)
                || accepted.metadata.destination.ip() != ipv4(70)
            {
                return Err("coordinated flow lost its original selection".into());
            }
            let client = async {
                application.write_all(b"coordinated flow").await?;
                let mut response = [0; 16];
                application.read_exact(&mut response).await?;
                if response != *b"coordinated flow" {
                    return Err("coordinated TCP reply differs".into());
                }
                Ok::<_, Failure>(())
            };
            let server = async {
                let mut bytes = [0; 16];
                accepted.stream.read_exact(&mut bytes).await?;
                if bytes != *b"coordinated flow" {
                    return Err("coordinated TCP request differs".into());
                }
                accepted.stream.write_all(&bytes).await?;
                Ok::<_, Failure>(())
            };
            tokio::try_join!(client, server)?;
            application.shutdown().await?;
            let mut byte = [0];
            if accepted.stream.read(&mut byte).await? != 0 {
                return Err("coordinated TCP FIN differs".into());
            }
            accepted.stream.shutdown().await?;
            if application.read(&mut byte).await? != 0 {
                return Err("coordinated kernel FIN differs".into());
            }
            Ok::<_, Failure>(())
        })
        .await??;
        wait_flows(&controller, &channels.publication).await?;
        tokio::time::sleep_until(
            controller
                .next_expiry()?
                .ok_or("completed reply has no grace expiry")?,
        )
        .await;

        let ready = gate.start();
        ready.await?;
        let (operation, cancellation) = watch::channel(false);
        if !manager.begin_next_retirement(Request {
            deadline: Instant::now() + Duration::from_secs(10),
            cancellation,
        })? {
            return Err("expired coordinated route was not selected for retirement".into());
        }
        operation.send_replace(true);
        gate.release().await?;
        if !matches!(
            manager.wait(request(&service_owner)).await,
            Err(Error::Native(tun::Error::Capture(tun::NativeFailure {
                delivery: tun::NativeDelivery::NotSent,
                cause: tun::NativeCause::Cancelled
            })))
        ) || manager.failure().is_some()
            || manager.deferred_retirement() != Some(route)
        {
            return Err(
                "definitively unmutated retirement was lost or treated as replayable uncertainty"
                    .into(),
            );
        }
        sweep(&mut manager, &service_owner).await?;

        for index in 0..20 {
            let response = reserve(&controller, &[ipv4(80 + index)])?;
            let before = Instant::now();
            manager.begin_commit(response, request(&service_owner))?;
            match manager.wait(request(&service_owner)).await? {
                Completion::Committed(mut response) => controller.cancel(&mut response)?,
                Completion::Retired => return Err("wrong managed completion".into()),
            }
            sweep(&mut manager, &service_owner).await?;
            latency.push(before.elapsed().as_nanos());
            if controller.stats()?.routes != 0 || manager.reserved_bytes() != reserved {
                return Err("managed rollback grew or leaked route metadata".into());
            }
        }
        let response = reserve(&controller, &[ipv4(74), ipv4(75)])?;
        manager.begin_commit(response, request(&service_owner))?;
        if !matches!(
            manager.wait(request(&service_owner)).await,
            Err(Error::Native(tun::Error::Conflict))
        ) || manager.failure().is_some()
            || controller.is_closed()?
        {
            return Err("a pre-mutation candidate conflict invalidated unrelated routing".into());
        }
        sweep(&mut manager, &service_owner).await?;
        if foreign_before != ip(&["-j", "route", "show", "exact", "203.0.113.75/32"])? {
            return Err("managed rollback changed a foreign key".into());
        }

        // Observe protected committed intent, then cancel through the real
        // operation's cancellation path. No production pause hook is needed.
        for index in 0..32 {
            let response = reserve(&controller, &[ipv4(170 + index)])?;
            let (cancel, cancellation) = watch::channel(false);
            manager.begin_commit(
                response,
                Request {
                    deadline: Instant::now() + Duration::from_secs(10),
                    cancellation,
                },
            )?;
            let (ready, started) = oneshot::channel();
            watcher_stop.store(false, Ordering::Release);
            let stopped = watcher_stop.clone();
            let lease = lease.clone();
            watcher = Some(std::thread::spawn(move || -> Result<bool, Failure> {
                ready
                    .send(())
                    .map_err(|_| "intent observer owner stopped")?;
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while !stopped.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    // A journal handle fences its first observed revision.
                    // This read-only fixture samples successive committed
                    // revisions, so each sample needs a fresh handle. A rename
                    // racing that sample is inconclusive, never mutation proof.
                    let journal = NetworkJournal::open(&lease)?;
                    match journal.read(&lease) {
                        Ok(Some(snapshot))
                            if snapshot.payload().get(96) == Some(&(tun::Stage::Routing as u8)) =>
                        {
                            cancel.send_replace(true);
                            return Ok(true);
                        }
                        Ok(_)
                        | Err(
                            StorageError::Conflict
                            | StorageError::RecoveryRequired
                            | StorageError::UnsafeState,
                        ) => {}
                        Err(error) => return Err(error.into()),
                    }
                    std::thread::sleep(Duration::from_micros(50));
                }
                Ok(false)
            }));
            started.await?;
            let result = manager.wait(request(&service_owner)).await;
            watcher_stop.store(true, Ordering::Release);
            let observed = finish_watcher(&mut watcher)?;
            if manager.failure().is_some() {
                if !observed || result.is_ok() || !controller.is_closed()? || manager.has_pending()
                {
                    return Err("post-intent failure was not closed and joined".into());
                }
                saw_intent = true;
                break;
            }
            match result {
                Ok(Completion::Committed(mut response)) => controller.cancel(&mut response)?,
                Err(
                    Error::RequestCancelled
                    | Error::Native(tun::Error::Capture(tun::NativeFailure {
                        delivery: tun::NativeDelivery::NotSent,
                        ..
                    })),
                ) => {}
                result => {
                    return Err(format!("unexpected intent observation result: {result:?}").into());
                }
            }
            sweep(&mut manager, &service_owner).await?;
        }
        if !saw_intent {
            return Err("fixture did not exercise post-intent native cancellation".into());
        }
        Ok::<_, Failure>(())
    }
    .await;
    let elapsed = started.elapsed().as_nanos();
    let after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let cpu_ns = (i128::from(after.tv_sec) - i128::from(cpu.tv_sec)) * 1_000_000_000
        + i128::from(after.tv_nsec)
        - i128::from(cpu.tv_nsec);
    let mut cleanup = Vec::new();
    if let Err(error) = gate.release().await {
        cleanup.push(error);
    }
    watcher_stop.store(true, Ordering::Release);
    if let Err(error) = finish_watcher(&mut watcher) {
        cleanup.push(error);
    }
    if let Err(error) = controller.close() {
        cleanup.push(Box::new(error) as Failure);
    }
    if manager.has_pending() {
        match manager.wait(request(&service_owner)).await {
            Ok(Completion::Committed(mut response)) => {
                if let Err(error) = controller.cancel(&mut response) {
                    cleanup.push(Box::new(error) as Failure);
                }
            }
            Ok(Completion::Retired) => {}
            Err(error) => cleanup.push(Box::new(error) as Failure),
        }
    }
    let deferred = manager.deferred_retirement();
    match manager.release() {
        Ok(owner) => native = Some(owner),
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    match channels.admission.quiesce() {
        Ok(mut receipt) => {
            if let Err(error) = receipt.wait(request(&service_owner)).await {
                cleanup.push(Box::new(error) as Failure);
            }
        }
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    if let Err(error) = wait_flows(&controller, &channels.publication).await {
        cleanup.push(error);
    }
    if let Err(error) = controller.finish_drain() {
        cleanup.push(Box::new(error) as Failure);
    }
    let withdrawn = match capture_change(&mut native, |owner, request| {
        owner.withdraw_capture(request)
    })
    .await
    {
        Ok(()) => true,
        Err(error) => {
            cleanup.push(error);
            false
        }
    };
    if withdrawn {
        let retired = (|| -> Result<(), Failure> {
            if let Some(route) = deferred {
                controller.finish_retirement(route)?;
            }
            while let Some(route) = controller.retirement_candidate()? {
                controller.begin_retirement(route)?;
                controller.finish_retirement(route)?;
            }
            Ok(())
        })();
        if let Err(error) = retired {
            cleanup.push(error);
        }
    }
    if let Err(error) = ip(&[
        "route",
        "del",
        "203.0.113.53/32",
        "dev",
        &tun_name,
        "metric",
        "3",
    ]) {
        cleanup.push(error);
    }
    stop.send_replace(true);
    let mut stopped_pump = None;
    let mut report = None;
    match packets.await {
        Ok((pump, result)) => {
            stopped_pump = Some(pump);
            match result {
                Ok(value) => report = Some(value),
                Err(error) => cleanup.push(Box::new(error) as Failure),
            }
        }
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    if channels.shutdown.send(()).is_err() {
        cleanup.push("managed runtime shutdown owner lost".into());
    }
    match host.await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => cleanup.push(Box::new(error) as Failure),
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    drop(stopped_pump);
    drop(port);
    if let Some(mut owner) = native {
        let closed = async {
            let jobs = Workers::new(1)?;
            let (join_owner, _) = watch::channel(false);
            let mut task = jobs.try_reserve()?.start(move || owner.close());
            join_native(&mut task, &join_owner).await??;
            Ok::<_, Failure>(())
        }
        .await;
        if let Err(error) = closed {
            cleanup.push(error);
        }
    }
    match ip(&["-j", "route", "show", "exact", "203.0.113.75/32"]) {
        Ok(after) if after == foreign_before => {}
        Ok(_) => cleanup.push("coordinator cleanup changed a foreign route".into()),
        Err(error) => cleanup.push(error),
    }
    if let Err(error) = ip(&[
        "route",
        "del",
        "203.0.113.75/32",
        "dev",
        "lo",
        "metric",
        "4",
    ]) {
        cleanup.push(error);
    }
    preserve(outcome, cleanup)?;
    let report = report.ok_or("coordinator packet report missing")?;
    if report.ingress_drops != 0
        || report.discarded_output != 0
        || report.lost_delivery_receipts != 0
        || dns.retained_requests() != 0
    {
        return Err("managed flow dropped packet ownership".into());
    }
    latency.sort_unstable();
    let memory = std::fs::read_to_string("/proc/self/status")?;
    let peak = memory
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or("coordinator RSS unavailable")?;
    println!(
        "route_coordinator cycles=20 app_bytes=32 udp_dns_requests=20 observer_cancellations=1 deferred_retirements=1 post_intent_failure={saw_intent} reserved_bytes={reserved} elapsed_ns={elapsed} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} ingress_drops={} discarded_output={} {peak}",
        latency[9], latency[18], latency[19], report.ingress_drops, report.discarded_output
    );
    println!(
        "PASS native coordinator retains cancelled waits, commits before zero-TTL framed output and TUN TCP, verifies virtual UDP negative reply receipts, preserves foreign state and closes post-intent failure with joined cleanup"
    );
    Ok(())
}

fn ipv4(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, last)
}

async fn udp_dns_reply(endpoint: &mut udp_dns::Endpoint) -> Result<(), Failure> {
    timeout(Duration::from_secs(2), async {
        let limits = PacketLimits::new(udp_dns::MAX_PAYLOAD, 8)?;
        let mut query_bytes = vec![0, 17, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query_bytes.extend_from_slice(Name::from_ascii("managed.example.test")?.wire());
        query_bytes.extend_from_slice(&[0, 1, 0, 1]);
        let client = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        client.connect(endpoint.local_addr()).await?;
        if client.send(&[]).await?!=0 {return Err("empty UDP send changed its boundary".into());}
        let empty=endpoint.requests.recv().await.ok_or("empty virtual UDP input lost")?;
        if !empty.payload().is_empty() {return Err("empty UDP input gained payload".into());}
        let (owner,_)=watch::channel(false);
        let mut operation=request(&owner); operation.deadline=Instant::now()+Duration::from_secs(2);
        let mut delivery=empty.respond(&[],operation)?;
        delivery.wait(request(&owner)).await?;
        if client.recv(&mut [0]).await?!=0 || endpoint.retained_requests()!=0 {return Err("empty UDP output changed its boundary or retained admission".into());}
        let mut latencies = Vec::with_capacity(20);
        let mut transferred = 0;
        let started = Instant::now();
        let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        for id in 0_u16..20 {
            let before = Instant::now();
            let mut bytes = query_bytes.clone();
            bytes[..2].copy_from_slice(&id.to_be_bytes());
            if id%2!=0 {
                // Alternate normal and maximum-size DNS packets with an EDNS
                // Padding option. No IP fragmentation is needed at this MTU.
                let padding=udp_dns::MAX_PAYLOAD-bytes.len()-15;
                bytes[11]=1;
                bytes.extend_from_slice(&[0,0,41,4,208,0,0,0,0]);
                bytes.extend_from_slice(&((padding+4) as u16).to_be_bytes());
                bytes.extend_from_slice(&12_u16.to_be_bytes());
                bytes.extend_from_slice(&(padding as u16).to_be_bytes());
                bytes.resize(udp_dns::MAX_PAYLOAD,0);
            }
            let query = Packet::request(&bytes, limits)?;
            if client.send(&bytes).await? != bytes.len() {
                return Err("native DNS query write was incomplete".into());
            }
            transferred += bytes.len();
            let datagram = endpoint.requests.recv().await.ok_or("virtual DNS receiver stopped")?;
            let received = Packet::request(datagram.payload(), limits)?;
            if received.id() != query.id() || received.question() != query.question()
                || datagram.destination() != endpoint.local_addr()
            { return Err("virtual DNS query lost original correlation".into()); }
            // SERVFAIL exposes no address. Positive UDP route/output ownership
            // remains a separate production listener integration gate.
            bytes[2..4].copy_from_slice(&[0x81, 0x82]);
            let wire = Packet::response(&bytes, &query, limits)?.encode()?;
            let (owner, _) = watch::channel(false);
            let mut operation = request(&owner);
            operation.deadline = Instant::now() + Duration::from_secs(2);
            let mut delivery = datagram.respond(&wire, operation)?;
            delivery.wait(request(&owner)).await?;
            let mut reply = [0; udp_dns::MAX_PAYLOAD+1];
            let length = client.recv(&mut reply).await?;
            if reply[..length] != wire { return Err("virtual DNS reply differs after native delivery".into()); }
            Packet::response(&reply[..length], &query, limits)?;
            transferred += length;
            if endpoint.retained_requests() != 0 { return Err("native DNS receipt leaked admission".into()); }
            latencies.push(before.elapsed().as_nanos());
        }
        let elapsed = started.elapsed().as_nanos();
        let after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let cpu_ns = (i128::from(after.tv_sec)-i128::from(cpu.tv_sec))*1_000_000_000
            +i128::from(after.tv_nsec)-i128::from(cpu.tv_nsec);
        latencies.sort_unstable();
        let memory = std::fs::read_to_string("/proc/self/status")?;
        let peak = memory.lines().find(|line|line.starts_with("VmHWM:")).ok_or("virtual DNS RSS unavailable")?;
        println!("virtual_udp_dns requests=20 empty_round_trips=1 datagrams=42 dns_payload_bytes={transferred} elapsed_ns={elapsed} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} {peak}; one connected kernel UDP socket, alternating normal/1232-byte fixture SERVFAIL, no backend resolution",latencies[9],latencies[18],latencies[19]);
        Ok::<_, Failure>(())
    }).await?
}

fn request(owner: &watch::Sender<bool>) -> Request {
    Request {
        deadline: Instant::now() + Duration::from_secs(10),
        cancellation: owner.subscribe(),
    }
}
fn reserve(controller: &Controller, addresses: &[Ipv4Addr]) -> Result<lease::Response, Failure> {
    let contributions: Vec<_> = addresses
        .iter()
        .map(|address| lease::Contribution {
            address: (*address).into(),
            expires_at: Duration::ZERO,
        })
        .collect();
    Ok(controller.reserve(
        RoutingMode::Dynamic,
        lease::QuestionKey {
            backend: BackendId(7),
            name: Name::from_ascii("managed.example.test")?,
            record_type: 1,
            class: 1,
        },
        &contributions,
        Instant::now() + Duration::from_secs(10),
    )?)
}
async fn sweep(manager: &mut Manager, owner: &watch::Sender<bool>) -> Result<(), Failure> {
    while manager.begin_next_retirement(request(owner))? {
        if !matches!(manager.wait(request(owner)).await?, Completion::Retired) {
            return Err("maintenance returned a commit".into());
        }
    }
    Ok(())
}
async fn wait_flows(
    controller: &Controller,
    publication: &warper_stack::runtime::Publication,
) -> Result<(), Failure> {
    timeout(Duration::from_secs(2), async {
        loop {
            controller.advance()?;
            if publication.retained_flows() == 0 && controller.stats()?.flows == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, Failure>(())
    })
    .await?
}
async fn dns_reply(controller: &Controller, response: lease::Response) -> Result<(), Failure> {
    let limits = PacketLimits::new(512, 8)?;
    let mut bytes = vec![0, 17, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(Name::from_ascii("managed.example.test")?.wire());
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    let query = Packet::request(&bytes, limits)?;
    bytes[2..4].copy_from_slice(&[0x81, 0x80]);
    bytes[7] = 1;
    bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 203, 0, 113, 70]);
    let wire = Packet::response(&bytes, &query, limits)?.encode()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let endpoint = listener.local_addr()?;
    let (mut client, (mut server, _)) = timeout(Duration::from_secs(2), async {
        tokio::try_join!(TcpStream::connect(endpoint), listener.accept())
    })
    .await??;
    let mut output = controller.begin_output(response)?;
    let (owner, cancellation) = watch::channel(false);
    Request {
        deadline: Instant::now() + Duration::from_secs(2),
        cancellation,
    }
    .run(async {
        server
            .write_all(&(wire.len() as u16).to_be_bytes())
            .await
            .map_err(|error| TransportError::Io(error.kind()))?;
        server
            .write_all(&wire)
            .await
            .map_err(|error| TransportError::Io(error.kind()))
    })
    .await?;
    controller.complete_output(&mut output, Duration::from_secs(1))?;
    let length = client.read_u16().await?;
    let mut received = vec![0; usize::from(length)];
    client.read_exact(&mut received).await?;
    Packet::response(&received, &query, limits)?;
    if received != wire
        || u32::from_be_bytes(received[received.len() - 10..received.len() - 6].try_into()?) != 0
    {
        return Err("coordinated zero-TTL frame differs".into());
    }
    drop(owner);
    server.shutdown().await?;
    client.shutdown().await?;
    Ok(())
}
fn finish_watcher(
    watcher: &mut Option<std::thread::JoinHandle<Result<bool, Failure>>>,
) -> Result<bool, Failure> {
    match watcher.take() {
        None => Ok(false),
        Some(watcher) => watcher.join().map_err(|_| "intent observer panicked")?,
    }
}
#[derive(Default)]
struct Gate {
    release: Option<mpsc::SyncSender<()>>,
    task: Option<JoinHandle<Result<(), Failure>>>,
}
impl Gate {
    fn start(&mut self) -> oneshot::Receiver<()> {
        let (release, blocked) = mpsc::sync_channel(1);
        let (started, ready) = oneshot::channel();
        self.release = Some(release);
        self.task = Some(tokio::task::spawn_blocking(move || {
            started
                .send(())
                .map_err(|_| "blocking gate observer stopped")?;
            blocked.recv_timeout(Duration::from_secs(5))?;
            Ok(())
        }));
        ready
    }
    async fn release(&mut self) -> Result<(), Failure> {
        let mut errors = Vec::new();
        if let Some(release) = self.release.take()
            && release.send(()).is_err()
        {
            errors.push("blocking gate ended before release".into());
        }
        if let Some(task) = self.task.take() {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(error),
                Err(error) => errors.push(Box::new(error) as Failure),
            }
        }
        preserve(Ok(()), errors)
    }
}

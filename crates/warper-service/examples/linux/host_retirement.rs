// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Individual native retirement with an unrelated real TUN TCP flow retained.

use super::{Failure, capture_change, ip, join_native, owned_packet_port, preserve};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::{Instant, timeout},
};
use warper_config::schema::RoutingMode;
use warper_core::{
    BackendId,
    dns::{Name, lease},
    routing::{Entry, Policy, SelectionError},
    transport::Request,
};
use warper_service::{
    dns::routes::Controller,
    linux::{context::Context, packet::Pump, tun},
    native::Workers,
};
use warper_stack::{
    Seed,
    host::{AcceptedFlow, Limits},
    runtime::{Publication, Runtime},
};

const ACTIVE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 40);
const RETIRED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 41);
const STATIC: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);

pub(super) async fn exercise(context: Arc<Context>) -> Result<(), Failure> {
    let (native, port) = owned_packet_port(context).await?;
    let mut native = Some(native);
    let port = Arc::new(port);
    let controller = Controller::new(
        Arc::new(Policy::new(
            &[Entry {
                network: STATIC.into(),
                prefix_len: 32,
                backend: BackendId(70003),
            }],
            8,
        )?),
        lease::Limits {
            lease_entries: 8,
            route_entries: 8,
            response_entries: 2,
            flow_entries: 2,
            addresses_per_response: 2,
            bytes: 128 * 1024,
        },
        Instant::now(),
    )?;
    let (runtime, mut channels) = Runtime::with_selector(
        Limits {
            setup_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(5),
            max_age: Duration::from_secs(60),
            ..Default::default()
        },
        controller.selector(),
        8,
        Seed::generate()?,
    )?;
    let mut pump = Pump::new(
        port.clone(),
        channels.ingress.clone(),
        channels.packets,
        Duration::from_secs(2),
    )?;
    let (packet_owner, cancellation) = watch::channel(false);
    let packets = tokio::spawn(async move {
        let result = pump.run(cancellation).await;
        (pump, result)
    });
    let host = tokio::spawn(runtime.run());
    let mut routes = Vec::with_capacity(2);
    let mut latency = Vec::with_capacity(20);
    let started = Instant::now();
    let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let outcome = async {
        let (mut response, active) = reserve(&controller, ACTIVE, BackendId(70000))?;
        routes.push(active);
        let publication = channels.publication.clone();
        capture_change(&mut native, move |native, request| {
            native.publish_host(publication, ACTIVE, BackendId(70000), request)
        })
        .await?;
        controller.confirm_publication(active)?;
        let (mut application, mut accepted) = timeout(Duration::from_secs(2), async {
            tokio::try_join!(
                async { Ok::<_, Failure>(TcpStream::connect((ACTIVE, 8443)).await?) },
                async {
                    channels
                        .tcp
                        .recv()
                        .await
                        .ok_or_else(|| "retirement fixture acceptance stopped".into())
                }
            )
        })
        .await??;
        if accepted.metadata.destination.ip() != ACTIVE
            || accepted.metadata.destination.port() != 8443
            || accepted.metadata.backend != BackendId(70000)
        {
            return Err("retirement fixture lost original TCP selection".into());
        }
        controller.cancel(&mut response)?;
        if controller.begin_retirement(active)
            != Err(warper_service::dns::routes::Error::Ledger(
                lease::Error::Referenced,
            ))
        {
            return Err("active TCP reference did not block retirement".into());
        }
        let publication = channels.publication.clone();
        let blocked = capture_change(&mut native, move |native, request| {
            native.withdraw_host(publication, ACTIVE, BackendId(70000), request)
        })
        .await;
        if !matches!(
            blocked
                .as_ref()
                .err()
                .and_then(|error| error.downcast_ref::<tun::Error>()),
            Some(tun::Error::CaptureHostActive)
        ) {
            return Err("native withdrawal ignored an active address owner".into());
        }
        // Another allocated selector cannot vouch for this runtime's live
        // address owner, even if it reports the same backend as retiring.
        let other = Controller::new(
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
        )?;
        let (mut other_response, other_route) = reserve(&other, ACTIVE, BackendId(70000))?;
        other.cancel(&mut other_response)?;
        other.begin_retirement(other_route)?;
        let (other_runtime, other_channels) =
            Runtime::with_selector(Limits::default(), other.selector(), 1, Seed::generate()?)?;
        let publication = other_channels.publication;
        let rejected = capture_change(&mut native, move |native, request| {
            native.withdraw_host(publication, ACTIVE, BackendId(70000), request)
        })
        .await;
        drop(other_runtime);
        if !matches!(
            rejected
                .as_ref()
                .err()
                .and_then(|error| error.downcast_ref::<tun::Error>()),
            Some(tun::Error::Conflict)
        ) {
            return Err("another runtime authorized retirement of the original TCP flow".into());
        }
        for index in 0..20 {
            let backend = BackendId(70001 + u64::from(index % 2));
            let (mut response, route) = reserve(&controller, RETIRED, backend)?;
            routes.push(route);
            let publication = channels.publication.clone();
            capture_change(&mut native, move |native, request| {
                native.publish_host(publication, RETIRED, backend, request)
            })
            .await?;
            controller.confirm_publication(route)?;
            controller.cancel(&mut response)?;
            controller.begin_retirement(route)?;
            if controller.route_info(active)?.flows != 1
                || channels.publication.retained_flows() != 1
                || channels.publication.is_quiescent()
            {
                return Err("unrelated TUN TCP flow stopped before individual withdrawal".into());
            }
            let before = Instant::now();
            let publication = channels.publication.clone();
            capture_change(&mut native, move |native, request| {
                native.withdraw_host(publication, RETIRED, backend, request)
            })
            .await?;
            latency.push(before.elapsed().as_nanos());
            if index == 0 {
                let publication = channels.publication.clone();
                capture_change(&mut native, move |native, request| {
                    native.withdraw_host(publication, RETIRED, backend, request)
                })
                .await?;
            }
            if controller.selector().lookup(RETIRED.into()) != Ok(backend) {
                return Err("native deletion released the mapping before ledger retirement".into());
            }
            controller.finish_retirement(route)?;
            routes.pop();
            if controller.selector().lookup(RETIRED.into()) != Err(SelectionError::Unselected) {
                return Err("retired dynamic address retained a selectable owner".into());
            }
            exchange(&mut application, &mut accepted, index).await?;
        }
        timeout(Duration::from_secs(2), async {
            application.shutdown().await?;
            let mut byte = [0];
            if accepted.stream.read(&mut byte).await? != 0 {
                return Err("captured TCP FIN differs".into());
            }
            accepted.stream.shutdown().await?;
            if application.read(&mut byte).await? != 0 {
                return Err("kernel TCP FIN differs".into());
            }
            Ok::<_, Failure>(())
        })
        .await??;
        drop(accepted);
        drop(application);
        wait_drained(&controller, &channels.publication).await?;
        controller.begin_retirement(active)?;
        let publication = channels.publication.clone();
        capture_change(&mut native, move |native, request| {
            native.withdraw_host(publication, ACTIVE, BackendId(70000), request)
        })
        .await?;
        let publication = channels.publication.clone();
        capture_change(&mut native, move |native, request| {
            native.withdraw_host(publication, ACTIVE, BackendId(70000), request)
        })
        .await?;
        if native
            .as_ref()
            .is_none_or(|native| native.stage() != tun::Stage::Enabled)
        {
            return Err("last dynamic route did not clear the native batch".into());
        }
        controller.finish_retirement(active)?;
        routes.pop();

        let (mut response, route) = reserve(&controller, STATIC, BackendId(70003))?;
        routes.push(route);
        let publication = channels.publication.clone();
        capture_change(&mut native, move |native, request| {
            native.publish_host(publication, STATIC, BackendId(70003), request)
        })
        .await?;
        controller.confirm_publication(route)?;
        controller.cancel(&mut response)?;
        controller.begin_retirement(route)?;
        let before = ip(&["-j", "route", "show", "exact", "203.0.113.42/32"])?;
        let publication = channels.publication.clone();
        capture_change(&mut native, move |native, request| {
            native.withdraw_host(publication, STATIC, BackendId(70003), request)
        })
        .await?;
        if before != ip(&["-j", "route", "show", "exact", "203.0.113.42/32"])? {
            return Err("individual DNS retirement removed immutable static coverage".into());
        }
        controller.finish_retirement(route)?;
        routes.pop();
        if controller.selector().select_flow(STATIC.into())?.backend() != BackendId(70003) {
            return Err("retired DNS metadata lost static selection".into());
        }

        let (mut response, route) = reserve(&controller, STATIC, BackendId(70003))?;
        routes.push(route);
        controller.cancel(&mut response)?;
        controller.begin_retirement(route)?;
        let jobs = Workers::new(1)?;
        let cancellation = packet_owner.subscribe();
        let mut inspection = jobs.try_reserve()?.start(move || {
            warper_service::linux::route_inventory::inspect(Request {
                deadline: Instant::now() + Duration::from_secs(2),
                cancellation,
            })
        });
        let inventory = join_native(&mut inspection, &packet_owner).await??;
        let metric = inventory
            .entries()
            .iter()
            .find(|entry| {
                entry.network == STATIC && entry.prefix_len == 32 && entry.table.get() == 254
            })
            .and_then(|entry| entry.metric)
            .ok_or("native capture metric missing")?
            .to_string();
        let name = native
            .as_ref()
            .and_then(|owner| owner.name())
            .ok_or("native TUN name missing")?
            .to_owned();
        ip(&[
            "route",
            "replace",
            "203.0.113.42/32",
            "dev",
            &name,
            "proto",
            "boot",
            "metric",
            &metric,
        ])?;
        let changed = ip(&["-j", "route", "show", "exact", "203.0.113.42/32"])?;
        let publication = channels.publication.clone();
        let rejected = capture_change(&mut native, move |native, request| {
            native.withdraw_host(publication, STATIC, BackendId(70003), request)
        })
        .await;
        let preserved = changed == ip(&["-j", "route", "show", "exact", "203.0.113.42/32"])?;
        // Restore only the private fixture's own deliberate mutation so the
        // independent whole-batch cleanup can verify the original owned key.
        ip(&[
            "route",
            "replace",
            "203.0.113.42/32",
            "dev",
            &name,
            "proto",
            "static",
            "metric",
            &metric,
        ])?;
        if !preserved
            || !matches!(
                rejected
                    .as_ref()
                    .err()
                    .and_then(|error| error.downcast_ref::<tun::Error>()),
                Some(tun::Error::Conflict | tun::Error::CaptureChanged(_))
            )
        {
            return Err("individual retirement changed an ambiguous foreign key".into());
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
    if let Err(error) = controller.close() {
        cleanup.push(Box::new(error) as Failure);
    }
    match channels.admission.quiesce() {
        Ok(mut receipt) => {
            if let Err(error) = receipt
                .wait(Request {
                    deadline: Instant::now() + Duration::from_secs(2),
                    cancellation: packet_owner.subscribe(),
                })
                .await
            {
                cleanup.push(Box::new(error) as Failure);
            }
        }
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    if let Err(error) = wait_drained(&controller, &channels.publication).await {
        cleanup.push(error);
    }
    if let Err(error) = controller.finish_drain() {
        cleanup.push(Box::new(error) as Failure);
    }
    let withdrawn = match capture_change(&mut native, |native, request| {
        native.withdraw_capture(request)
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
        for route in routes {
            let retired = (|| {
                if controller.route_info(route)?.publication != lease::Publication::Retiring {
                    controller.begin_retirement(route)?;
                }
                controller.finish_retirement(route)
            })();
            if let Err(error) = retired {
                cleanup.push(Box::new(error) as Failure);
            }
        }
    }
    packet_owner.send_replace(true);
    let mut stopped_pump = None;
    let mut packet_report = None;
    match packets.await {
        Ok((pump, result)) => {
            stopped_pump = Some(pump);
            match result {
                Ok(report) => packet_report = Some(report),
                Err(error) => cleanup.push(Box::new(error) as Failure),
            }
        }
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    if channels.shutdown.send(()).is_err() {
        cleanup.push("retirement runtime shutdown owner lost".into());
    }
    match host.await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => cleanup.push(Box::new(error) as Failure),
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    drop(stopped_pump);
    drop(port);
    if let Some(mut native) = native {
        let closed = async {
            let jobs = Workers::new(1)?;
            let (join_owner, _) = watch::channel(false);
            let mut task = jobs.try_reserve()?.start(move || native.close());
            join_native(&mut task, &join_owner).await??;
            Ok::<_, Failure>(())
        }
        .await;
        if let Err(error) = closed {
            cleanup.push(error);
        }
    }
    preserve(outcome, cleanup)?;
    let report = packet_report.ok_or("retirement packet report missing")?;
    if report.ingress_drops != 0 || report.discarded_output != 0 {
        return Err("retirement workload dropped packet ownership".into());
    }
    latency.sort_unstable();
    let memory = std::fs::read_to_string("/proc/self/status")?;
    let peak = memory
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or("retirement RSS unavailable")?;
    println!(
        "host_retirement iterations=20 concurrency=1 app_bytes=1280 elapsed_ns={elapsed} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} ingress_drops={} discarded_output={} captured_bytes={} sent_bytes={} {peak}",
        latency[9],
        latency[18],
        latency[19],
        report.ingress_drops,
        report.discarded_output,
        report.captured_bytes,
        report.sent_bytes
    );
    println!(
        "PASS individual host retirement and backend reassignment preserve a real unrelated TUN TCP flow, static coverage, changed keys and joined cleanup"
    );
    Ok(())
}

fn reserve(
    controller: &Controller,
    address: Ipv4Addr,
    backend: BackendId,
) -> Result<(lease::Response, lease::Route), Failure> {
    let response = controller.reserve(
        RoutingMode::Mixed,
        lease::QuestionKey {
            backend,
            name: Name::from_ascii("retire.example.test")?,
            record_type: 1,
            class: 1,
        },
        &[lease::Contribution {
            address: address.into(),
            expires_at: Duration::ZERO,
        }],
        Instant::now() + Duration::from_secs(10),
    )?;
    let route = controller.response_route(&response, 0)?;
    Ok((response, route))
}

async fn exchange(
    application: &mut TcpStream,
    accepted: &mut AcceptedFlow,
    index: u8,
) -> Result<(), Failure> {
    timeout(Duration::from_secs(2), async {
        let bytes = [index; 32];
        let client = async {
            application.write_all(&bytes).await?;
            let mut reply = [0; 32];
            application.read_exact(&mut reply).await?;
            if reply != bytes {
                return Err("retained kernel TCP reply differs".into());
            }
            Ok::<_, Failure>(())
        };
        let server = async {
            let mut request = [0; 32];
            accepted.stream.read_exact(&mut request).await?;
            if request != bytes {
                return Err("retained TUN TCP request differs".into());
            }
            accepted.stream.write_all(&request).await?;
            Ok::<_, Failure>(())
        };
        tokio::try_join!(client, server)?;
        Ok(())
    })
    .await?
}

async fn wait_drained(controller: &Controller, publication: &Publication) -> Result<(), Failure> {
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

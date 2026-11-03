// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real incremental native publication in the disposable acceptance namespace.

use super::{Failure, capture_change, ip, join_native, owned_packet_port, preserve};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{sync::watch, time::Instant};
use warper_config::schema::RoutingMode;
use warper_core::{
    BackendId,
    dns::{Name, lease},
    routing::{Policy, SelectionError},
    transport::Request,
};
use warper_service::{
    dns::routes::Controller,
    linux::{context::Context, tun},
    native::Workers,
};
use warper_stack::{Seed, runtime::Runtime};

pub(super) async fn exercise(context: Arc<Context>) -> Result<(), Failure> {
    let (native, port) = owned_packet_port(context).await?;
    let mut native = Some(native);
    let controller = Controller::new(
        Arc::new(Policy::new(&[], 32)?),
        lease::Limits {
            lease_entries: 32,
            route_entries: 32,
            response_entries: 1,
            flow_entries: 2,
            addresses_per_response: 1,
            bytes: 128 * 1024,
        },
        Instant::now(),
    )?;
    let (runtime, channels) = Runtime::with_selector(
        warper_stack::host::Limits {
            flows: 2,
            accepted: 2,
            ..Default::default()
        },
        controller.selector(),
        2,
        Seed::generate()?,
    )?;
    let (owner, _) = watch::channel(false);
    let backend = BackendId(70000);
    let question = lease::QuestionKey {
        backend,
        name: Name::from_ascii("native-route.example.test")?,
        record_type: 1,
        class: 1,
    };
    let reserve = |address: Ipv4Addr| {
        controller.reserve(
            RoutingMode::Dynamic,
            question,
            &[lease::Contribution {
                address: address.into(),
                expires_at: Duration::ZERO,
            }],
            Instant::now() + Duration::from_secs(10),
        )
    };
    let mut routes = Vec::with_capacity(20);
    let mut latencies = Vec::with_capacity(20);
    ip(&["route", "add", "203.0.113.250/32", "dev", "lo"])?;
    let foreign_before = ip(&["-j", "route", "show", "exact", "203.0.113.250/32"])?;
    let runtime_task = tokio::spawn(runtime.run());
    let started = Instant::now();
    let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let outcome = async {
        let address = Ipv4Addr::new(203, 0, 113, 250);
        let mut response = reserve(address)?;
        let publication = channels.publication.clone();
        let conflict = capture_change(&mut native, move |native, request| {
            native.publish_host(publication, address, backend, request)
        })
        .await;
        if !matches!(
            conflict
                .as_ref()
                .err()
                .and_then(|error| error.downcast_ref::<tun::Error>()),
            Some(tun::Error::Conflict)
        ) || native
            .as_ref()
            .is_none_or(|native| native.stage() != tun::Stage::Enabled)
            || foreign_before != ip(&["-j", "route", "show", "exact", "203.0.113.250/32"])?
        {
            return Err("incremental publication changed a foreign route".into());
        }
        controller.cancel(&mut response)?;
        let foreign = controller
            .retirement_candidate()?
            .ok_or("conflict reservation not released")?;
        controller.begin_retirement(foreign)?;
        controller.finish_retirement(foreign)?;
        for index in 0..20 {
            let address = Ipv4Addr::new(203, 0, 113, 10 + index);
            let mut response = reserve(address)?;
            let route = controller.response_route(&response, 0)?;
            if !matches!(
                controller.selector().select_flow(address.into()),
                Err(SelectionError::Unready)
            ) {
                return Err("uncommitted native route accepted a flow".into());
            }
            let publication = channels.publication.clone();
            let rejected = capture_change(&mut native, move |native, request| {
                native.publish_host(publication, address, BackendId(70001), request)
            })
            .await;
            if !matches!(
                rejected
                    .as_ref()
                    .err()
                    .and_then(|error| error.downcast_ref::<tun::Error>()),
                Some(tun::Error::InvalidCapturePolicy)
            ) {
                return Err("native publication ignored the selected backend".into());
            }
            let before = Instant::now();
            let publication = channels.publication.clone();
            capture_change(&mut native, move |native, request| {
                native.publish_host(publication, address, backend, request)
            })
            .await?;
            latencies.push(before.elapsed().as_nanos());
            // Metadata commitment follows the joined native ACK and durable
            // snapshot; this fixture does not emit a DNS answer.
            controller.confirm_publication(route)?;
            controller.handoff(&mut response, Duration::from_secs(60))?;
            let pin = controller.selector().select_flow(address.into())?;
            if pin.backend() != backend || controller.route_info(route)?.flows != 1 {
                return Err("native route lost its selected flow ownership".into());
            }
            drop(pin);
            let publication = channels.publication.clone();
            capture_change(&mut native, move |native, request| {
                native.publish_host(publication, address, backend, request)
            })
            .await?;
            routes.push(route);
        }
        if controller.stats()?.routes != 20 {
            return Err("native route union differs from reserved ownership".into());
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
                    cancellation: owner.subscribe(),
                })
                .await
            {
                cleanup.push(Box::new(error) as Failure);
            }
        }
        Err(error) => cleanup.push(Box::new(error) as Failure),
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
            if let Err(error) = controller
                .begin_retirement(route)
                .and_then(|()| controller.finish_retirement(route))
            {
                cleanup.push(Box::new(error) as Failure);
            }
        }
    }
    if channels.shutdown.send(()).is_err() {
        cleanup.push("live route runtime shutdown owner lost".into());
    }
    match runtime_task.await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => cleanup.push(Box::new(error) as Failure),
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    drop(port);
    if let Some(mut native) = native {
        let closed = async {
            let workers = Workers::new(1)?;
            let mut task = workers.try_reserve()?.start(move || native.close());
            join_native(&mut task, &owner).await??;
            Ok::<_, Failure>(())
        }
        .await;
        if let Err(error) = closed {
            cleanup.push(error);
        }
    }
    match ip(&["-j", "route", "show", "exact", "203.0.113.250/32"]) {
        Ok(after) if after == foreign_before => {}
        Ok(_) => cleanup.push("native cleanup changed the foreign route".into()),
        Err(error) => cleanup.push(error),
    }
    if let Err(error) = ip(&["route", "del", "203.0.113.250/32", "dev", "lo"]) {
        cleanup.push(error);
    }
    preserve(outcome, cleanup)?;
    latencies.sort_unstable();
    let memory = std::fs::read_to_string("/proc/self/status")?;
    let peak = memory
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or("native route RSS unavailable")?;
    println!(
        "live_capture routes=20 concurrency=1 elapsed_ns={elapsed} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 {peak}",
        latencies[9], latencies[18], latencies[19]
    );
    println!(
        "PASS live DNS mapping precedes native host ACK, repeated publication preserves ownership, and joined withdrawal preserves a foreign route"
    );
    Ok(())
}

// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Actual service supervisor in the disposable native acceptance namespace.

use super::{
    application,
    configuration_installation::encoded,
    fixture::{Failure, ip, join_native, preserve},
    peers,
};
use std::{os::unix::net::UnixStream, sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    time::{Instant, timeout},
};
use warper_control::runtime::{RuntimeLease, journal::NetworkJournal};
use warper_service::{
    linux::{
        configuration::{ConfigurationLease, Configurations, Error as ConfigurationError},
        context::Context,
        network::{self, Network, State},
    },
    native::Workers,
};

const NAME: &str = "warper-super";
const SAMPLE: &str = "tunnel: {ip: 198.18.0.1, name: warper-super}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]\ntimeouts: {connect_ms: 3000, shutdown_ms: 4000}";

async fn native<F, T>(work: F) -> Result<T, Failure>
where
    F: FnOnce() -> Result<T, Failure> + Send + 'static,
    T: Send + 'static,
{
    let workers = Workers::new(1)?;
    let (owner, _) = watch::channel(false);
    let mut job = workers.try_reserve()?.start(work);
    join_native(&mut job, &owner).await?
}
async fn approved(
    context: Arc<Context>,
    sample: String,
) -> Result<(Configurations, ConfigurationLease), Failure> {
    native(move || {
        let mut manager = Configurations::open(context)?;
        let generation = manager.status()?.generation;
        let (peer, _client) = UnixStream::pair()?;
        manager.install(&peer, generation, encoded(&sample)?.expose())?;
        let lease = manager.lease()?.ok_or("approved fixture lease missing")?;
        Ok((manager, lease))
    })
    .await
}
async fn journal(runtime: Arc<RuntimeLease>) -> Result<Option<(u64, Vec<u8>)>, Failure> {
    native(move || {
        Ok(NetworkJournal::open(&runtime)?
            .read(&runtime)?
            .map(|snapshot| (snapshot.revision(), snapshot.payload().to_vec())))
    })
    .await
}
fn absent() -> Result<(), Failure> {
    if nix::net::if_::if_nameindex()?
        .iter()
        .any(|interface| interface.name().to_bytes() == NAME.as_bytes())
    {
        return Err("supervisor left its owned TUN interface".into());
    }
    Ok(())
}

pub(super) async fn exercise(
    context: Arc<Context>,
    runtime: Arc<RuntimeLease>,
) -> Result<(), Failure> {
    precanceled(context.clone(), runtime.clone()).await?;
    rollback(context.clone()).await?;
    traffic(context).await?;
    println!(
        "PASS service network supervisor startup, actual kernel TCP/FIN, retained approval, explicit shutdown and failed-start rollback"
    );
    Ok(())
}
async fn precanceled(context: Arc<Context>, runtime: Arc<RuntimeLease>) -> Result<(), Failure> {
    let (manager, lease) = approved(context, SAMPLE.to_owned()).await?;
    let before = journal(runtime.clone()).await?;
    let mut network = Network::new(lease)?;
    let (_owner, cancellation) = watch::channel(true);
    let (state, observed) = watch::channel(State::Starting);
    let failure = match network.run(cancellation, &state).await {
        Err(failure) => failure,
        Ok(_) => return Err("precanceled startup unexpectedly succeeded".into()),
    };
    if failure.primary != Some(network::Error::Cancelled)
        || !failure.report.retired
        || *observed.borrow() != State::Disconnected
    {
        return Err("precanceled supervisor state or retirement differs".into());
    }
    if journal(runtime).await? != before {
        return Err("precanceled startup mutated the journal".into());
    }
    absent()?;
    drop(network);
    drop(manager);
    Ok(())
}
async fn rollback(context: Arc<Context>) -> Result<(), Failure> {
    let sample = SAMPLE.replace("127.0.0.1:1080", "198.18.0.2:1080");
    let (manager, lease) = approved(context, sample).await?;
    let before = ip(&["-j", "route", "show", "table", "all"])?;
    let mut network = Network::new(lease)?;
    let (_owner, cancellation) = watch::channel(false);
    let (state, observed) = watch::channel(State::Starting);
    let result = network.run(cancellation, &state).await;
    let failure = match result {
        Err(failure) => failure,
        Ok(_) => return Err("unroutable backend unexpectedly became connected".into()),
    };
    if !matches!(failure.primary, Some(network::Error::Egress(_)))
        || !failure.report.retired
        || *observed.borrow() != State::Disconnected
    {
        return Err(format!("supervisor failed-start rollback differs: {failure:?}").into());
    }
    absent()?;
    if before != ip(&["-j", "route", "show", "table", "all"])? {
        return Err("supervisor failed start changed foreign routes".into());
    }
    drop(network);
    drop(manager);
    Ok(())
}
async fn traffic(context: Arc<Context>) -> Result<(), Failure> {
    let (manager, lease) = approved(context, SAMPLE.to_owned()).await?;
    let mut network = Network::new(lease)?;
    let mut peers = peers().await?;
    let (stop, cancellation) = watch::channel(false);
    let (state, mut observed) = watch::channel(State::Starting);
    let state_owner = state.clone();
    let mut task = tokio::spawn(async move {
        let result = network.run(cancellation, &state_owner).await;
        (network, result)
    });
    let mut early = None;
    let mut manager = Some(manager);
    let started = Instant::now();
    let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let outcome=async {
        tokio::select! { biased;
            result=&mut task=>{early=Some(result);return Err("supervisor stopped before Connected".into());},
            ready=timeout(Duration::from_secs(5),observed.wait_for(|state|*state==State::Connected))=>{drop(ready??);},
        }
        let retained=manager.take().ok_or("configuration manager missing")?;
        manager=Some(native(move || {
            let mut manager=retained;
            let (admin,_client)=UnixStream::pair()?;
            let generation=manager.status()?.generation;
            if manager.install(&admin,generation,b"invalid")!=Err(ConfigurationError::Busy) {
                return Err("live supervisor did not fence managed installation".into());
            }
            Ok(manager)
        }).await?);
        timeout(Duration::from_secs(5),application()).await??;
        // Completing the application/observer is not an explicit service stop.
        if *observed.borrow()!=State::Connected || task.is_finished() {return Err("application exit stopped service networking".into());}
        Ok::<_,Failure>(())
    }.await;
    stop.send_replace(true);
    // The disposable outer harness independently bounds and reaps this process.
    // Keep the actual owner until its run and any retained cleanup are joined.
    let joined = match early {
        Some(result) => result,
        None => task.await,
    };
    let mut cleanup = Vec::new();
    let mut completed = None;
    match joined {
        Ok((mut network, result)) => {
            let retired = match result {
                Ok(report) => {
                    let retired = report.retired;
                    completed = Some(report);
                    retired
                }
                Err(error) => {
                    let retired = error.report.retired;
                    cleanup.push(Box::new(error) as Failure);
                    retired
                }
            };
            if !retired && let Err(error) = network.cleanup().await {
                cleanup.push(Box::new(error) as Failure);
            }
            drop(network);
        }
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    if outcome.is_err() {
        peers.abort_all();
    }
    while !peers.is_empty() {
        match timeout(Duration::from_secs(1), peers.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) => {
                cleanup.push(error);
                peers.abort_all();
            }
            Ok(Some(Err(error))) if error.is_cancelled() => {}
            Ok(Some(Err(error))) => {
                cleanup.push(Box::new(error) as Failure);
                peers.abort_all();
            }
            Ok(None) => break,
            Err(error) => {
                cleanup.push(Box::new(error) as Failure);
                peers.abort_all();
            }
        }
    }
    preserve(outcome, cleanup)?;
    let report = completed.ok_or("supervisor report missing")?;
    if !report.retired
        || *observed.borrow() != State::Disconnected
        || report.relays.as_ref().is_none_or(|relays| {
            relays.finished != 1
                || relays.failed != 0
                || relays.transferred.sent != 65536
                || relays.transferred.received != 16393
        })
        || report
            .runtime
            .as_ref()
            .is_none_or(|runtime| runtime.retained_streams != 0)
        || report
            .packets
            .as_ref()
            .is_none_or(|packets| packets.captured_packets == 0 || packets.sent_packets == 0)
    {
        return Err(format!("supervisor traffic report differs: {report:?}").into());
    }
    absent()?;
    if let Some(manager) = manager {
        native(move || {
            let mut manager = manager;
            let (admin, _client) = UnixStream::pair()?;
            let generation = manager.status()?.generation;
            manager.install(&admin, generation, encoded(SAMPLE)?.expose())?;
            Ok(())
        })
        .await?;
    } else {
        return Err("supervisor fixture lost its configuration manager".into());
    }
    let after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let cpu_ns = (i128::from(after.tv_sec) - i128::from(cpu.tv_sec)) * 1_000_000_000
        + i128::from(after.tv_nsec)
        - i128::from(cpu.tv_nsec);
    let status = std::fs::read_to_string("/proc/self/status")?;
    let peak = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or("supervisor peak RSS missing")?;
    println!(
        "supervised_network scope=lifecycle_and_reapproval flows=1 request_bytes=65536 response_bytes=16393 elapsed_ns={} cpu_ns={cpu_ns} kernel_drops=unmeasured process_peak_{peak} report={report:?}",
        started.elapsed().as_nanos()
    );
    Ok(())
}

// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real crash/absence reconciliation in a fresh disposable harness invocation.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        io::{self, Write},
        os::unix::{fs::OpenOptionsExt, process::ExitStatusExt},
        process::{Command, Stdio},
        sync::Arc,
        time::Duration,
    };
    use tokio::io::AsyncReadExt;
    use tun_rs::DeviceBuilder;
    use warper_control::runtime::{
        RuntimeLease,
        connection::ConnectionStore,
        journal::{Error as JournalError, NetworkJournal},
    };
    use warper_core::{
        BackendId,
        routing::{Entry, Policy},
        transport::Request,
    };
    use warper_service::{
        linux::{
            context::Context,
            tun::{Error as TunError, Owner, RecoveryOutcome, Stage, recover_abandoned},
        },
        native::Workers,
    };
    use warper_stack::{Seed, host::Limits, runtime::Runtime};

    mod fixture;
    pub(crate) use fixture::root;
    use fixture::{Failure, ip, isolated, join_native, preserve};
    const NAME: &str = "warper-recover";
    const PREFIX: &str = "198.18.0.2/32";

    fn capture() -> Result<(Arc<Context>, Arc<RuntimeLease>), Failure> {
        let lease = Arc::new(RuntimeLease::acquire()?);
        let store = ConnectionStore::open(&lease)?;
        let context = Arc::new(Context::capture(lease.clone(), &store)?);
        Ok((context, lease))
    }
    fn request(owner: &tokio::sync::watch::Sender<bool>) -> Request {
        Request {
            deadline: tokio::time::Instant::now() + Duration::from_secs(3),
            cancellation: owner.subscribe(),
        }
    }

    pub async fn peer(mount: &str, net: &str, stage: &str) -> Result<(), Failure> {
        isolated(mount, net)?;
        let expected = match stage {
            "prepared" => Stage::Prepared,
            "allocated" => Stage::Allocated,
            "enabled" => Stage::Enabled,
            "captured" => Stage::Captured,
            _ => return Err("unknown controlled crash stage".into()),
        };
        let jobs = Workers::new(1)?;
        let (observer, _) = tokio::sync::watch::channel(false);
        let operation = request(&observer);
        let mut preparing = jobs.try_reserve()?.start(move || -> Result<_, Failure> {
            let (context, lease) = capture()?;
            let mut owner = Owner::prepare(context.clone(), Some(NAME), 1280)?;
            if expected != Stage::Prepared {
                owner.allocate()?;
                owner.apply_name()?;
            }
            if matches!(expected, Stage::Enabled | Stage::Captured) {
                owner.assign_ipv4("198.18.0.1".parse()?, operation.clone())?;
                owner.enable(operation)?;
            }
            let port = if expected == Stage::Captured {
                Some(owner.packet_port()?)
            } else {
                None
            };
            Ok((context, lease, owner, port))
        });
        let (context, _lease, owner, port) = join_native(&mut preparing, &observer).await??;
        let mut runtime_owner = None;
        let mut channels_owner = None;
        let mut owner = Some(owner);
        // The parent kills the real owner. An expired fixture is a failure;
        // any normally returning runtime is retained and joined below.
        let outcome = async {
            if expected == Stage::Captured {
                let policy = Arc::new(Policy::new(
                    &[Entry {
                        network: "198.18.0.2".parse()?,
                        prefix_len: 32,
                        backend: BackendId(1),
                    }],
                    1,
                )?);
                let (runtime, channels) =
                    Runtime::new(Limits::default(), policy, 64, Seed::generate()?)?;
                runtime_owner = Some(tokio::spawn(runtime.run()));
                let publication = channels.publication.clone();
                channels_owner = Some(channels);
                let operation = request(&observer);
                let reservation = jobs.try_reserve()?;
                let mut retained = owner.take().ok_or("crash owner missing")?;
                let mut publishing = reservation.start(move || {
                    let result = retained.publish_capture(publication, operation);
                    (retained, result)
                });
                let (retained, result) = join_native(&mut publishing, &observer).await?;
                owner = Some(retained);
                result?;
            }
            let checked_context = context.clone();
            let operation = request(&observer);
            let mut checking = jobs.try_reserve()?.start(move || -> Result<(), Failure> {
                if recover_abandoned(&checked_context, operation) != Err(TunError::OwnerAlive) {
                    return Err("live crash owner could retire its own journal".into());
                }
                io::stdout().write_all(b"READY\n")?;
                io::stdout().flush()?;
                Ok(())
            });
            join_native(&mut checking, &observer).await??;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Err::<(), Failure>("controlled crash peer expired without SIGKILL".into())
        }
        .await;
        let mut cleanup = Vec::new();
        if let Some(channels) = channels_owner
            && channels.shutdown.send(()).is_err()
        {
            cleanup.push("crash peer shutdown owner lost".into());
        }
        if let Some(task) = runtime_owner {
            match task.await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => cleanup.push(Box::new(error) as Failure),
                Err(error) => cleanup.push(Box::new(error) as Failure),
            }
        }
        drop(port);
        drop(owner);
        preserve(outcome, cleanup)
    }

    async fn crash(stage: &str, mount: &str, net: &str) -> Result<(), Failure> {
        let jobs = Workers::new(1)?;
        let (observer, _) = tokio::sync::watch::channel(false);
        let args = [mount.to_owned(), net.to_owned(), stage.to_owned()];
        let mut spawning = jobs.try_reserve()?.start(move || -> Result<_, Failure> {
            Ok(Command::new(std::env::current_exe()?)
                .args(["--crash-owner", &args[0], &args[1], &args[2]])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?)
        });
        let mut child = join_native(&mut spawning, &observer).await??;
        let ready = async {
            let pipe = child
                .stdout
                .take()
                .ok_or("crash owner readiness pipe missing")?;
            let mut input = tokio::net::unix::pipe::Receiver::from_owned_fd(pipe.into())?;
            let mut marker = [0; 6];
            tokio::time::timeout(Duration::from_secs(2), input.read_exact(&mut marker)).await??;
            if &marker != b"READY\n" {
                return Err("crash owner readiness marker differs".into());
            }
            Ok::<_, Failure>(())
        }
        .await;
        let mut reaping = jobs.try_reserve()?.start(move || {
            let kill = child.kill().map_err(|error| Box::new(error) as Failure);
            let waited = child
                .wait()
                .map_err(|error| Box::new(error) as Failure)
                .and_then(|status| {
                    if status.signal() == Some(9) {
                        Ok(())
                    } else {
                        Err("crash owner did not exit under SIGKILL".into())
                    }
                });
            preserve(waited, kill.err().into_iter().collect())
        });
        let reaped = join_native(&mut reaping, &observer).await?;
        preserve(ready, reaped.err().into_iter().collect())
    }

    fn reconcile(stage: &str, observer: tokio::sync::watch::Sender<bool>) -> Result<(), Failure> {
        let (context, lease) = capture()?;
        let mut journal = NetworkJournal::open(&lease)?;
        let original = journal.read(&lease)?.ok_or("crash journal missing")?;
        let original_payload = original.payload().to_vec();
        let mut revision = original.revision();
        if original_payload.get(96).copied()
            != Some(match stage {
                "prepared" => Stage::Prepared,
                "allocated" => Stage::Named,
                "enabled" => Stage::Enabled,
                "captured" => Stage::Captured,
                _ => return Err("unknown crash stage".into()),
            } as u8)
        {
            return Err("crash intent stage differs".into());
        }
        let expired = Request {
            deadline: tokio::time::Instant::now(),
            cancellation: observer.subscribe(),
        };
        if !matches!(
            recover_abandoned(&context, expired),
            Err(TunError::RecoveryWait(_))
        ) {
            return Err("expired recovery changed journal ownership".into());
        }
        let (cancelled_owner, cancellation) = tokio::sync::watch::channel(true);
        let cancelled = Request {
            deadline: tokio::time::Instant::now() + Duration::from_secs(3),
            cancellation,
        };
        if !matches!(
            recover_abandoned(&context, cancelled),
            Err(TunError::RecoveryWait(_))
        ) {
            return Err("cancelled recovery changed journal ownership".into());
        }
        drop(cancelled_owner);
        if stage != "prepared" {
            let foreign = DeviceBuilder::new().mtu(1400).enable(false).build_sync()?;
            let name = foreign.name()?;
            let index = foreign.if_index()?;
            let mut forged = original_payload.clone();
            forged[116..132].fill(0);
            forged[116..116 + name.len()].copy_from_slice(name.as_bytes());
            forged[132..136].copy_from_slice(&index.to_be_bytes());
            revision = journal.replace(&lease, revision, &forged)?.revision();
            let result = recover_abandoned(&context, request(&observer));
            let after = journal
                .read(&lease)?
                .ok_or("foreign conflict removed the journal")?;
            if result != Err(TunError::CleanupUncertain)
                || after.revision() != revision
                || after.payload() != forged
                || foreign.if_index()? != index
                || foreign.name()? != name
                || foreign.mtu()? != 1400
                || foreign.is_running()?
            {
                return Err("recovery adopted or changed a foreign interface claim".into());
            }
            revision = journal
                .replace(&lease, revision, &original_payload)?
                .revision();
            drop(foreign);
        }
        if stage == "captured" {
            let metric = u32::from_be_bytes(original_payload[144..148].try_into()?).to_string();
            ip(&[
                "route", "add", PREFIX, "dev", "lo", "proto", "static", "metric", &metric,
            ])?;
            let result = (|| -> Result<(), Failure> {
                let before = ip(&["-j", "route", "show", PREFIX])?;
                if recover_abandoned(&context, request(&observer)) != Err(TunError::Conflict)
                    || before != ip(&["-j", "route", "show", PREFIX])?
                {
                    return Err("recovery changed a surviving foreign route key".into());
                }
                Ok(())
            })();
            let cleanup = ip(&[
                "route", "del", PREFIX, "dev", "lo", "proto", "static", "metric", &metric,
            ])
            .err()
            .into_iter()
            .collect();
            preserve(result, cleanup)?;
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open("/var/lib/warper/network.pending")?
            .write_all(b"partial")?;
        if recover_abandoned(&context, request(&observer))
            != Err(TunError::Storage(JournalError::RecoveryRequired))
        {
            return Err("pending intent did not block abandoned recovery".into());
        }
        let token = journal
            .inspect_pending(&lease)?
            .ok_or("pending recovery fixture missing")?;
        journal.discard_pending(&lease, token)?;
        if recover_abandoned(&context, request(&observer))? != RecoveryOutcome::Retired
            || recover_abandoned(&context, request(&observer))? != RecoveryOutcome::AlreadyRetired
        {
            return Err("abandoned retirement is not idempotent".into());
        }
        // Recovery intentionally changes the observed generation. Reopen rather
        // than bypassing the original journal object's stale-observation guard.
        let retired_journal = NetworkJournal::open(&lease)?;
        let retired = retired_journal
            .read(&lease)?
            .ok_or("retired record missing")?;
        if retired.revision() != revision + 1
            || retired.payload().get(96).copied() != Some(Stage::Retired as u8)
        {
            return Err("abandoned retirement revision/stage differs".into());
        }
        let started = std::time::Instant::now();
        let cpu_before = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let mut latencies = Vec::with_capacity(20);
        for _ in 0..20 {
            let before = std::time::Instant::now();
            if recover_abandoned(&context, request(&observer))? != RecoveryOutcome::AlreadyRetired {
                return Err("repeated retirement changed ownership".into());
            }
            latencies.push(before.elapsed().as_nanos());
        }
        let elapsed = started.elapsed().as_nanos();
        let cpu_after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let cpu = (i128::from(cpu_after.tv_sec) - i128::from(cpu_before.tv_sec)) * 1_000_000_000
            + i128::from(cpu_after.tv_nsec)
            - i128::from(cpu_before.tv_nsec);
        latencies.sort_unstable();
        let memory = fs::read_to_string("/proc/self/status")?;
        let peak = memory
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .ok_or("recovery workload RSS missing")?;
        println!(
            "retired_observation stage={stage} iterations=20 concurrency=1 elapsed_ns={elapsed} cpu_ns={cpu} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 {peak}",
            latencies[9], latencies[18], latencies[19]
        );
        let mut fresh = Owner::prepare(context.clone(), Some(NAME), 1280)?;
        fresh.allocate()?;
        fresh.close()?;
        // Model a previous-boot record against a currently live foreign index.
        // Boot history must never authorize adopting or deleting that object.
        let foreign = DeviceBuilder::new().mtu(1400).enable(false).build_sync()?;
        let name = foreign.name()?;
        let index = foreign.if_index()?;
        let mut boot_journal = NetworkJournal::open(&lease)?;
        let current = boot_journal
            .read(&lease)?
            .ok_or("boot fixture record missing")?;
        let mut prior = current.payload().to_vec();
        prior[16] ^= 1;
        prior[17] |= 1;
        prior[96] = Stage::Allocated as u8;
        prior[116..132].fill(0);
        prior[116..116 + name.len()].copy_from_slice(name.as_bytes());
        prior[132..136].copy_from_slice(&index.to_be_bytes());
        boot_journal.replace(&lease, current.revision(), &prior)?;
        if recover_abandoned(&context, request(&observer))? != RecoveryOutcome::Retired
            || foreign.if_index()? != index
            || foreign.name()? != name
            || foreign.mtu()? != 1400
            || foreign.is_running()?
        {
            return Err("previous boot recovery touched a current foreign interface".into());
        }
        drop(foreign);
        Ok(())
    }

    pub async fn exercise(mount: &str, net: &str) -> Result<(), Failure> {
        isolated(mount, net)?;
        let jobs = Workers::new(1)?;
        let (observer, _) = tokio::sync::watch::channel(false);
        let operation = request(&observer);
        let mut empty = jobs.try_reserve()?.start(move || -> Result<(), Failure> {
            let (context, _lease) = capture()?;
            if recover_abandoned(&context, operation)? != RecoveryOutcome::NoRecord {
                return Err("fresh recovery invented prior ownership".into());
            }
            Ok(())
        });
        join_native(&mut empty, &observer).await??;
        for stage in ["prepared", "allocated", "enabled", "captured"] {
            crash(stage, mount, net).await?;
            let jobs = Workers::new(1)?;
            let (observer, _) = tokio::sync::watch::channel(false);
            let observing = observer.clone();
            let mut recovery = jobs
                .try_reserve()?
                .start(move || reconcile(stage, observing));
            join_native(&mut recovery, &observer).await??;
            println!(
                "PASS {stage} SIGKILL recovery preserves foreign claims and pending intent, retires only absent ownership and allocates a fresh TUN"
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "--require-initial-root" => linux::root(),
        [mode, mount, net] if mode == "--exercise" => linux::exercise(mount, net).await,
        [mode, mount, net, stage] if mode == "--crash-owner" => {
            linux::peer(mount, net, stage).await
        }
        _ => Err("use the disposable namespace acceptance harness".into()),
    }
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedIntegration: native recovery probe requires Linux");
    std::process::ExitCode::FAILURE
}

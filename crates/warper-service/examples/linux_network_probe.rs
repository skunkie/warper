// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Disposable native API experiment, not a journaled production Linux driver.
//! Must run through control_acceptance.py with private mount/net/state/devices.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs, io,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        os::unix::fs::PermissionsExt,
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinSet,
    };
    use tun_rs::DeviceBuilder;
    use warper_config::schema::{Config, Platform};
    #[cfg(test)]
    use warper_core::transport::{EndpointConnector, Error, OpenTcp, TcpStream as BoxedTcp};
    use warper_core::{
        configuration::paths::{Account, Paths},
        transport::Request,
    };
    use warper_service::preflight::{Networking, Plan};
    use warper_stack::{Seed, host::MTU};

    mod fixture;
    pub(crate) use fixture::root;
    use fixture::{CombinedFailure, Failure, ip, isolated, join_native, preserve};
    mod configuration_installation;
    mod controller_dispatch;
    mod physical;
    mod process_owner;
    mod supervised_network;

    pub fn configuration_peer() -> Result<(), Failure> {
        configuration_installation::peer()
    }

    const NAME: &str = "warper-probe";
    const DESTINATION: &str = "198.18.0.2:443";
    const PAYLOAD: usize = 65536;

    async fn inspect_link(
        name: &str,
    ) -> Result<warper_service::linux::link_lookup::Observation, Failure> {
        let (_owner, cancellation) = tokio::sync::watch::channel(false);
        Ok(warper_service::linux::link_lookup::lookup(
            warper_service::linux::link_lookup::Query::Name(name),
            Request {
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                cancellation,
            },
        )
        .await?)
    }
    #[cfg(test)]
    struct LocalConnector(SocketAddr);
    #[cfg(test)]
    impl EndpointConnector for LocalConnector {
        fn connect_tcp(&self, endpoint: SocketAddr, request: Request) -> OpenTcp<'_> {
            Box::pin(request.run(async move {
                if endpoint != self.0 || !endpoint.ip().is_loopback() {
                    return Err(Error::UnsupportedCapability);
                }
                Ok(Box::new(
                    TcpStream::connect(endpoint)
                        .await
                        .map_err(|e| Error::Io(e.kind()))?,
                ) as BoxedTcp)
            }))
        }
    }
    fn index_exists(index: u32) -> Result<bool, Failure> {
        use rustix::net::{
            AddressFamily, SocketFlags, SocketType, netdevice::index_to_name_inlined, socket_with,
        };
        let socket = socket_with(
            AddressFamily::INET,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        match index_to_name_inlined(socket, index) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NODEV | rustix::io::Errno::NXIO) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn native_context() -> Result<
        (
            warper_service::linux::context::Context,
            Arc<warper_control::runtime::RuntimeLease>,
        ),
        Failure,
    > {
        use warper_control::runtime::{RuntimeLease, connection::ConnectionStore};
        use warper_service::linux::context::{
            Classification, Context, ProcessState, RecordedOwner,
        };
        let lease = Arc::new(RuntimeLease::acquire()?);
        let retained_lease = Arc::downgrade(&lease);
        let connection = ConnectionStore::open(&lease)?;
        let context = Arc::new(Context::capture(lease.clone(), &connection)?);
        let recorded = RecordedOwner::decode(&context.recorded_owner().encode())?;
        if context.classify(&recorded) != Classification::Current {
            return Err("native owner component did not round trip".into());
        }
        let reopened = ConnectionStore::open(&lease)?;
        let other = Context::capture(lease.clone(), &reopened)?;
        if other.classify(&recorded) != Classification::PreviousInstance {
            return Err("previous native instance became current".into());
        }
        if context.owner_process(&recorded)? != ProcessState::Alive
            || other.owner_process(&recorded)? != ProcessState::Alive
        {
            return Err("live native owner was misclassified as absent".into());
        }
        let mut changed = recorded.encode();
        changed[83] ^= 1;
        let changed = RecordedOwner::decode(&changed)?;
        if context.owner_process(&changed)
            != Err(warper_service::linux::context::Error::ContextChanged)
            || other.owner_process(&changed)? != ProcessState::Reused
        {
            return Err("recorded process identity bypassed native instance fencing".into());
        }
        let mut prior_boot = recorded.encode();
        prior_boot[8] ^= 1;
        prior_boot[9] |= 1;
        if context.owner_process(&RecordedOwner::decode(&prior_boot)?)?
            != ProcessState::PreviousBoot
        {
            return Err("previous boot record was interpreted as a current process".into());
        }
        drop(other);
        drop(reopened);
        drop(connection);
        drop(lease);
        let worker_context = context.clone();
        let worker = std::thread::spawn(move || -> Result<(), Failure> {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
            if worker_context.revalidate()
                != Err(warper_service::linux::context::Error::ContextChanged)
            {
                return Err("changed thread network namespace retained native context".into());
            }
            Ok(())
        });
        worker
            .join()
            .map_err(|_| "native context worker panicked")??;
        context.revalidate()?;
        if !matches!(
            RuntimeLease::acquire(),
            Err(warper_control::runtime::Error::AlreadyRunning)
        ) {
            return Err("native context released runtime ownership early".into());
        }
        let configuration_runtime = retained_lease
            .upgrade()
            .ok_or("configuration fixture lost runtime ownership")?;
        configuration_installation::exercise(context.clone(), &configuration_runtime)?;
        drop(configuration_runtime);
        let context = Arc::try_unwrap(context)
            .map_err(|_| "native context worker retained ownership after join")?;
        println!(
            "PASS native boot/process/namespace context, prior-instance fencing and joined foreign-thread rejection"
        );
        let lease = retained_lease
            .upgrade()
            .ok_or("native context lost runtime ownership")?;
        Ok((context, lease))
    }
    async fn journaled_tun_lifecycle(
        context: Arc<warper_service::linux::context::Context>,
        foreign: &tun_rs::SyncDevice,
    ) -> Result<(), Failure> {
        use warper_service::linux::tun::{Error as TunError, NameOutcome, Owner, Stage};
        let original = foreign.name()?;
        let before = inspect_link(&original).await?;
        let mut owner = Owner::prepare(context.clone(), Some("warper-journal"), MTU as u16)?;
        if owner.stage() != Stage::Prepared {
            return Err("TUN intent was not prepared".into());
        }
        owner.allocate()?;
        if owner.stage() != Stage::Allocated || owner.index() == Some(before.index.get()) {
            return Err("journaled TUN allocation differs".into());
        }
        foreign.set_name("warper-journal")?;
        let collision = owner.apply_name();
        foreign.set_name(&original)?;
        if collision != Err(TunError::Conflict) {
            return Err("journaled TUN rename did not preserve a raced foreign name".into());
        }
        owner.close()?;
        owner.close()?;
        if owner.stage() != Stage::Retired || inspect_link(&original).await? != before {
            return Err("journaled TUN rollback changed foreign identity".into());
        }
        drop(owner);
        let mut owner = Owner::prepare(context.clone(), Some("warper-journal"), MTU as u16)?;
        owner.allocate()?;
        if owner.apply_name()? != NameOutcome::Renamed
            || owner.apply_name()? != NameOutcome::AlreadyApplied
        {
            return Err("journaled TUN rename/idempotency differs".into());
        }
        let observed = inspect_link("warper-journal").await?;
        if Some(observed.index.get()) != owner.index()
            || observed.mtu.get() != MTU as u32
            || observed.flags & nix::libc::IFF_UP as u32 != 0
        {
            return Err("journaled TUN was not the intended down interface".into());
        }
        owner.close()?;
        owner.close()?;
        drop(owner);
        let mut owner = Owner::prepare(context.clone(), None, MTU as u16)?;
        owner.allocate()?;
        if owner.apply_name()? != NameOutcome::OsSelected {
            return Err("OS-selected TUN name was not preserved".into());
        }
        owner.close()?;
        if inspect_link(&original).await? != before {
            return Err("journaled TUN retirement changed foreign metadata".into());
        }
        drop(owner);
        journaled_address(context.clone(), foreign).await?;
        let started = tokio::time::Instant::now();
        let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let workers = warper_service::native::Workers::new(1)?;
        let (cancellation_owner, cancellation) = tokio::sync::watch::channel(false);
        let mut task = workers
            .try_reserve()?
            .start(move || -> Result<Vec<u128>, Failure> {
                let mut latencies = Vec::with_capacity(20);
                for _ in 0..20 {
                    let before = tokio::time::Instant::now();
                    let mut owner = Owner::prepare(context.clone(), None, MTU as u16)?;
                    let result = (|| -> Result<(), Failure> {
                        owner.allocate()?;
                        let request = || Request {
                            deadline: tokio::time::Instant::now() + Duration::from_secs(5),
                            cancellation: cancellation.clone(),
                        };
                        owner.assign_ipv4(Ipv4Addr::new(198, 18, 0, 11), request())?;
                        owner.enable(request())?;
                        Ok(())
                    })();
                    let cleanup = owner.close();
                    match (result, cleanup) {
                        (Err(primary), Err(cleanup)) => {
                            return Err(format!("{primary}; cleanup: {cleanup}").into());
                        }
                        (Err(primary), Ok(())) => return Err(primary),
                        (Ok(()), Err(cleanup)) => return Err(cleanup.into()),
                        (Ok(()), Ok(())) => {}
                    }
                    latencies.push(before.elapsed().as_nanos());
                }
                Ok(latencies)
            });
        let mut latencies = join_native(&mut task, &cancellation_owner).await??;
        let elapsed = started.elapsed().as_nanos();
        let after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let cpu_ns = (i128::from(after.tv_sec) - i128::from(cpu.tv_sec)) * 1_000_000_000
            + i128::from(after.tv_nsec)
            - i128::from(cpu.tv_nsec);
        latencies.sort_unstable();
        let memory = fs::read_to_string("/proc/self/status")?;
        let peak = memory
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .ok_or("native workload peak RSS unavailable")?;
        println!(
            "journaled_tun mode=address_activation iterations=20 concurrency=1 elapsed_ns={elapsed} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 {peak}",
            latencies[9], latencies[18], latencies[19]
        );
        println!(
            "PASS journaled fresh TUN creation, raced rename rollback, naming idempotency and verified retirement"
        );
        Ok(())
    }
    async fn journaled_address(
        context: Arc<warper_service::linux::context::Context>,
        foreign: &tun_rs::SyncDevice,
    ) -> Result<(), Failure> {
        use warper_service::{
            linux::tun::{Error as TunError, Owner, Stage},
            native::Workers,
        };
        let foreign_name = foreign.name()?;
        let duplicate = "198.18.0.10/32";
        ip(&["address", "add", duplicate, "dev", &foreign_name])?;
        let before = ip(&["-j", "address", "show", "dev", &foreign_name])?;
        let workers = Workers::new(1)?;
        let (cancellation_owner, cancellation) = tokio::sync::watch::channel(false);
        let mut task = workers
            .try_reserve()?
            .start(move || -> Result<(), Failure> {
                let mut owner = Owner::prepare(context, Some("warper-address"), MTU as u16)?;
                let applied = (|| -> Result<(), Failure> {
                    owner.allocate()?;
                    owner.apply_name()?;
                    let request = || Request {
                        deadline: tokio::time::Instant::now() + Duration::from_secs(5),
                        cancellation: cancellation.clone(),
                    };
                    if owner.assign_ipv4(Ipv4Addr::new(198, 18, 0, 10), request())
                        != Err(TunError::Conflict)
                        || owner.stage() != Stage::Named
                    {
                        return Err("foreign address was not rejected before mutation".into());
                    }
                    if owner.enable(request()) != Err(TunError::InvalidState) {
                        return Err("activation accepted missing address ownership".into());
                    }
                    let address = Ipv4Addr::new(198, 18, 0, 9);
                    owner.assign_ipv4(address, request())?;
                    owner.assign_ipv4(address, request())?;
                    if owner.stage() != Stage::Addressed {
                        return Err("address ownership was not committed".into());
                    }
                    owner.enable(request())?;
                    owner.assign_ipv4(address, request())?;
                    owner.enable(request())?;
                    if owner.stage() != Stage::Enabled {
                        return Err("activation ownership was not committed".into());
                    }
                    let link =
                        String::from_utf8(ip(&["-o", "link", "show", "dev", "warper-address"])?)?;
                    if !link.split(['<', '>', ',']).any(|field| field == "UP") {
                        return Err("activation did not set the isolated kernel UP flag".into());
                    }
                    let observed = String::from_utf8(ip(&[
                        "-o",
                        "-4",
                        "address",
                        "show",
                        "dev",
                        "warper-address",
                    ])?)?;
                    let fields: Vec<_> = observed.split_whitespace().collect();
                    if observed.lines().count() != 1
                        || !fields
                            .windows(2)
                            .any(|pair| pair == ["inet", "198.18.0.9/32"])
                        || !fields.contains(&"noprefixroute")
                    {
                        return Err(
                            "committed address differs from isolated kernel observation".into()
                        );
                    }
                    if !ip(&[
                        "-4",
                        "route",
                        "show",
                        "table",
                        "main",
                        "dev",
                        "warper-address",
                    ])?
                    .is_empty()
                    {
                        return Err("address assignment published a connected prefix route".into());
                    }
                    Ok(())
                })();
                let cleanup = owner.close();
                match (applied, cleanup) {
                    (Err(primary), Err(cleanup)) => {
                        Err(format!("{primary}; cleanup: {cleanup}").into())
                    }
                    (Err(primary), Ok(())) => Err(primary),
                    (Ok(()), Err(cleanup)) => Err(cleanup.into()),
                    (Ok(()), Ok(())) => Ok(()),
                }
            });
        let result = join_native(&mut task, &cancellation_owner).await?;
        let after = ip(&["-j", "address", "show", "dev", &foreign_name])?;
        ip(&["address", "del", duplicate, "dev", &foreign_name])?;
        result?;
        if before != after {
            return Err("owned address cleanup changed a foreign address".into());
        }
        println!(
            "PASS journaled IPv4 /32 and UP ACK/readback, idempotency, foreign conflict and joined rollback"
        );
        Ok(())
    }
    async fn protected_connector(
        context: Arc<warper_service::linux::context::Context>,
        endpoints: Vec<SocketAddr>,
        excluded: u32,
        limit: usize,
    ) -> Result<warper_service::linux::egress::Connector, Failure> {
        let jobs = warper_service::native::Workers::new(1)?;
        let excluded = std::num::NonZeroU32::new(excluded).ok_or("capture index missing")?;
        let (owner, _) = tokio::sync::watch::channel(false);
        let mut task = jobs.try_reserve()?.start(move || {
            warper_service::linux::egress::Preparation::new(context, &endpoints, excluded, limit)
        });
        let preparation = join_native(&mut task, &owner).await??;
        Ok(preparation
            .prepare(Request {
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                cancellation: owner.subscribe(),
            })
            .await?)
    }
    async fn owned_packet_port(
        context: Arc<warper_service::linux::context::Context>,
    ) -> Result<
        (
            warper_service::linux::tun::Owner,
            warper_service::linux::tun::PacketPort,
        ),
        Failure,
    > {
        use warper_service::linux::tun::{Error as TunError, Owner, PacketPort, Stage};
        let jobs = warper_service::native::Workers::new(1)?;
        let (join_owner, cancellation) = tokio::sync::watch::channel(false);
        let mut task=jobs.try_reserve()?.start(move || -> Result<(Owner, PacketPort), Failure> {
            let mut owner=Owner::prepare(context,Some(NAME),MTU as u16)?;
            let result=(|| -> Result<PacketPort, Failure> {
                owner.allocate()?;
                owner.apply_name()?;
                if !matches!(owner.packet_port(),Err(TunError::InvalidState)) {
                    return Err("packet port escaped before committed activation".into());
                }
                let request=||Request {deadline:tokio::time::Instant::now()+Duration::from_secs(5), cancellation:cancellation.clone()};
                owner.assign_ipv4(Ipv4Addr::new(198,18,0,1),request())?;
                owner.enable(request())?;
                let port=owner.packet_port()?;
                if !matches!(owner.packet_port(),Err(TunError::InvalidState))
                    || !matches!(owner.close(),Err(failure) if failure.primary==TunError::PacketPortActive)
                    || owner.stage()!=Stage::Enabled {
                    return Err("live packet port failed to preserve its native owner".into());
                }
                Ok(port)
            })();
            match result {
                Ok(port)=>Ok((owner,port)),
                Err(primary)=>match owner.close() {
                    Ok(())=>Err(primary),
                    Err(cleanup)=>Err(Box::new(CombinedFailure{primary,cleanup:vec![Box::new(cleanup)]})),
                },
            }
        });
        join_native(&mut task, &join_owner).await?
    }
    async fn peers() -> Result<JoinSet<Result<(), Failure>>, Failure> {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = target.local_addr()?;
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 1080)).await?;
        let mut workers = JoinSet::new();
        workers.spawn(async move {
            let (mut stream, _) = target.accept().await?;
            stream.write_all(&vec![b'g'; 16384]).await?;
            let mut actual = Vec::with_capacity(PAYLOAD + 1);
            (&mut stream)
                .take((PAYLOAD + 1) as u64)
                .read_to_end(&mut actual)
                .await?;
            let expected: Vec<_> = (0..PAYLOAD).map(|n| (n % 251) as u8).collect();
            if actual != expected {
                return Err("controlled target request differs".into());
            }
            stream.write_all(b"after-fin").await?;
            stream.shutdown().await?;
            Ok(())
        });
        workers.spawn(async move {
            let (mut stream, _) = proxy.accept().await?;
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).await?;
            if hello != [5, 1, 0] {
                return Err("controlled SOCKS greeting differs".into());
            }
            stream.write_all(&[5, 0]).await?;
            let mut connect = [0; 10];
            stream.read_exact(&mut connect).await?;
            if connect != [5, 1, 0, 1, 198, 18, 0, 2, 1, 187] {
                return Err("captured original destination differs".into());
            }
            // This controlled proxy maps the invented destination to a private
            // loopback target. It verifies CONNECT before making that fixture hop.
            let mut upstream = TcpStream::connect(destination).await?;
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            if tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?
                != (PAYLOAD as u64, 16384 + 9)
            {
                return Err("controlled proxy byte counts differ".into());
            }
            Ok(())
        });
        Ok(workers)
    }
    async fn application() -> Result<(), Failure> {
        let stream = TcpStream::connect(DESTINATION).await?;
        let (mut read, mut write) = stream.into_split();
        let payload: Vec<_> = (0..PAYLOAD).map(|n| (n % 251) as u8).collect();
        let mut greeting = vec![0; 16384];
        let (sent, received) =
            tokio::join!(write.write_all(&payload), read.read_exact(&mut greeting));
        sent?;
        received?;
        if greeting != vec![b'g'; 16384] {
            return Err("controlled application greeting differs".into());
        }
        write.shutdown().await?;
        let mut after = Vec::with_capacity(10);
        read.take(10).read_to_end(&mut after).await?;
        if after != b"after-fin" {
            return Err("controlled application response after FIN differs".into());
        }
        Ok(())
    }
    fn plan() -> Result<Plan, Failure> {
        plan_for("198.18.0.2/32")
    }
    fn plan_for(prefixes: &str) -> Result<Plan, Failure> {
        let endpoint: SocketAddr = "127.0.0.1:1080".parse()?;
        let account = Account {
            uid: 1000,
            name: "fixture".into(),
            home: "/nonexistent".into(),
        };
        let paths = Paths::new(&account, std::path::Path::new("/"), Some("/fixture.yaml"))?;
        let source = format!(
            "tunnel: {{ip: 198.18.0.1, name: {NAME}}}\nprotocols: [{{socks5: {{host: '{endpoint}', ips: [{prefixes}]}}}}]\n"
        );
        let config = Config::parse(source.as_bytes(), &paths, Platform::Linux)?;
        Ok(Plan::prepare(&config, Platform::Linux)?)
    }
    async fn capture_change(
        owner: &mut Option<warper_service::linux::tun::Owner>,
        work: impl FnOnce(
            &mut warper_service::linux::tun::Owner,
            Request,
        ) -> Result<(), warper_service::linux::tun::Error>
        + Send
        + 'static,
    ) -> Result<(), Failure> {
        let jobs = warper_service::native::Workers::new(1)?;
        let reservation = jobs.try_reserve()?;
        let mut native = owner.take().ok_or("capture fixture owner missing")?;
        let (join_owner, cancellation) = tokio::sync::watch::channel(false);
        let mut task = reservation.start(move || {
            let result = work(
                &mut native,
                Request {
                    deadline: tokio::time::Instant::now() + Duration::from_secs(3),
                    cancellation,
                },
            );
            (native, result)
        });
        let (native, result) = join_native(&mut task, &join_owner).await?;
        *owner = Some(native);
        Ok(result?)
    }
    async fn journaled_capture(
        context: Arc<warper_service::linux::context::Context>,
    ) -> Result<(), Failure> {
        use warper_service::linux::tun::Error as TunError;
        let (native, port) = owned_packet_port(context.clone()).await?;
        let mut native = Some(native);
        let plan = plan_for("198.18.0.2/32, 203.0.113.2/32, 203.0.113.0/24")?;
        let index = native
            .as_ref()
            .and_then(|owner| owner.index())
            .ok_or("capture fixture index missing")?;
        let connector = protected_connector(
            context,
            plan.endpoints().map(|(_, endpoint)| endpoint).collect(),
            index,
            plan.flow_capacity(),
        )
        .await?;
        let Networking {
            runtime,
            channels,
            relays,
            ..
        } = plan.instantiate(Seed::generate()?, Arc::new(connector))?;
        let host = tokio::spawn(runtime.run());
        let (owner, _) = tokio::sync::watch::channel(false);
        let mut restore_metric = None;
        let outcome = async {
            let publication = channels.publication.clone();
            capture_change(&mut native, move |native, request| {
                native.publish_capture(publication, request)
            })
            .await?;
            let publication = channels.publication.clone();
            capture_change(&mut native, move |native, request| {
                native.publish_capture(publication, request)?;
                if !matches!(native.close(), Err(error) if error.primary == TunError::CaptureActive)
                {
                    return Err(TunError::InvalidState);
                }
                Ok(())
            })
            .await?;
            let blocked = capture_change(&mut native, |native, request| {
                native.withdraw_capture(request)
            })
            .await;
            if !matches!(
                blocked
                    .as_ref()
                    .err()
                    .and_then(|error| error.downcast_ref::<TunError>()),
                Some(TunError::CaptureFlowsActive)
            ) {
                return Err("capture retirement ignored admission quiescence".into());
            }
            let mut receipt = channels.admission.quiesce()?;
            receipt
                .wait(Request {
                    deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                    cancellation: owner.subscribe(),
                })
                .await?;
            let jobs = warper_service::native::Workers::new(1)?;
            let cancellation = owner.subscribe();
            let mut inspection = jobs.try_reserve()?.start(move || {
                warper_service::linux::route_inventory::inspect(Request {
                    deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                    cancellation,
                })
            });
            let inventory = join_native(&mut inspection, &owner).await??;
            let route = inventory
                .entries()
                .iter()
                .find(|entry| {
                    entry.network == Ipv4Addr::new(198, 18, 0, 2)
                        && entry.prefix_len == 32
                        && entry
                            .interface
                            .is_some_and(|interface| interface.get() == index)
                })
                .ok_or("journaled capture route missing")?;
            let metric = route
                .metric
                .ok_or("journaled capture metric missing")?
                .to_string();
            ip(&[
                "route",
                "replace",
                "198.18.0.2/32",
                "dev",
                "lo",
                "proto",
                "static",
                "metric",
                &metric,
            ])?;
            restore_metric = Some(metric.clone());
            let before = ip(&["-j", "route", "show", "198.18.0.2/32"])?;
            let blocked = capture_change(&mut native, |native, request| {
                native.withdraw_capture(request)
            })
            .await;
            if !matches!(
                blocked
                    .as_ref()
                    .err()
                    .and_then(|error| error.downcast_ref::<TunError>()),
                Some(TunError::Conflict)
            ) || before != ip(&["-j", "route", "show", "198.18.0.2/32"])?
            {
                return Err("capture retirement changed foreign route metadata".into());
            }
            Ok(())
        }
        .await;
        let mut cleanup = Vec::new();
        if let Some(metric) = restore_metric
            && let Err(error) = ip(&[
                "route",
                "replace",
                "198.18.0.2/32",
                "dev",
                NAME,
                "proto",
                "static",
                "metric",
                &metric,
            ])
        {
            cleanup.push(error);
        }
        // Always retain/join quiescence and native cleanup before withdrawing
        // the actual runtime mapping; this fixture has no application flows.
        let quiescence = async {
            let mut receipt = channels.admission.quiesce()?;
            receipt
                .wait(Request {
                    deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                    cancellation: owner.subscribe(),
                })
                .await?;
            Ok::<_, Failure>(())
        }
        .await;
        if let Err(error) = quiescence {
            cleanup.push(error);
        }
        if native.as_ref().is_some_and(|native| {
            matches!(
                native.stage(),
                warper_service::linux::tun::Stage::Routing
                    | warper_service::linux::tun::Stage::Captured
                    | warper_service::linux::tun::Stage::RoutesRetiring
            )
        }) && let Err(error) = capture_change(&mut native, |native, request| {
            native.withdraw_capture(request)
        })
        .await
        {
            cleanup.push(error);
        }
        if native
            .as_ref()
            .is_some_and(|native| native.stage() == warper_service::linux::tun::Stage::Enabled)
            && let Err(error) = capture_change(&mut native, |native, request| {
                native.withdraw_capture(request)
            })
            .await
        {
            cleanup.push(error);
        }
        let report = relays.shutdown().await;
        if report.finished != 0 || report.shutdown_error.is_some() {
            cleanup.push("empty capture fixture relay shutdown differs".into());
        }
        if channels.shutdown.send(()).is_err() {
            cleanup.push("capture runtime shutdown owner lost".into());
        }
        match host.await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => cleanup.push(Box::new(error) as Failure),
            Err(error) => cleanup.push(Box::new(error) as Failure),
        }
        drop(port);
        if let Some(mut native) = native {
            let jobs = warper_service::native::Workers::new(1)?;
            let mut closing = jobs.try_reserve()?.start(move || native.close());
            if let Err(error) = join_native(&mut closing, &owner).await? {
                cleanup.push(Box::new(error) as Failure);
            }
        }
        preserve(outcome, cleanup)?;
        println!(
            "PASS journaled capture ACK/readback, repeated publication, quiescence fence, changed-route preservation and joined retirement"
        );
        Ok(())
    }
    async fn measure_captures(
        context: Arc<warper_service::linux::context::Context>,
    ) -> Result<(), Failure> {
        let started = tokio::time::Instant::now();
        let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let mut latencies = Vec::with_capacity(20);
        for _ in 0..20 {
            let before = tokio::time::Instant::now();
            journaled_capture(context.clone()).await?;
            latencies.push(before.elapsed().as_nanos());
        }
        let elapsed = started.elapsed().as_nanos();
        let after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let cpu = (i128::from(after.tv_sec) - i128::from(cpu.tv_sec)) * 1_000_000_000
            + i128::from(after.tv_nsec)
            - i128::from(cpu.tv_nsec);
        latencies.sort_unstable();
        let memory = fs::read_to_string("/proc/self/status")?;
        let peak = memory
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .ok_or("capture workload RSS missing")?;
        println!(
            "journaled_capture iterations=20 prefixes=3 concurrency=1 elapsed_ns={elapsed} cpu_ns={cpu} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 kernel_drops=unmeasured {peak}",
            latencies[9], latencies[18], latencies[19]
        );
        Ok(())
    }
    async fn inspect_rules() -> Result<warper_service::linux::rule_inventory::Inventory, Failure> {
        let jobs = warper_service::native::Workers::new(1)?;
        let (owner, cancellation) = tokio::sync::watch::channel(false);
        let mut task = jobs.try_reserve()?.start(move || {
            warper_service::linux::rule_inventory::inspect(Request {
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                cancellation,
            })
        });
        Ok(join_native(&mut task, &owner).await??)
    }
    async fn reject_custom_rules() -> Result<(), Failure> {
        // The private fixture starts with exactly three rules, so this priority
        // is not foreign state. Delete only after our successful addition.
        ip(&["rule", "add", "priority", "1000", "table", "main"])?;
        let result = async {
            let before = ip(&["-j", "rule", "show"])?;
            let rules = inspect_rules().await?;
            if rules.is_default_layout() || rules.rules() != 4 {
                return Err("custom native IPv4 rule layout was admitted".into());
            }
            if before != ip(&["-j", "rule", "show"])? {
                return Err("rule inspection mutated custom fixture state".into());
            }
            Ok(())
        }
        .await;
        let cleanup = ip(&["rule", "del", "priority", "1000", "table", "main"])
            .err()
            .into_iter()
            .collect();
        preserve(result, cleanup)?;
        if !inspect_rules().await?.is_default_layout() {
            return Err("private fixture rule restoration differs".into());
        }
        println!(
            "PASS custom IPv4 rules are rejected and preserved; fixture cleanup restores the default layout"
        );
        Ok(())
    }
    async fn inspect_capture_route() -> Result<(), Failure> {
        let interface = inspect_link(NAME).await?.index;
        let jobs = warper_service::native::Workers::new(1)?;
        let (owner, cancellation) = tokio::sync::watch::channel(false);
        let mut task = jobs.try_reserve()?.start(move || -> Result<_, Failure> {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            let routes = warper_service::linux::route_inventory::inspect(Request {
                deadline,
                cancellation: cancellation.clone(),
            })?;
            let rules = warper_service::linux::rule_inventory::inspect(Request {
                deadline,
                cancellation,
            })?;
            Ok((routes, rules))
        });
        let (inventory, rules) = join_native(&mut task, &owner).await??;
        if !rules.is_default_layout() {
            return Err("private fixture IPv4 rule layout differs".into());
        }
        println!("PASS complete bounded IPv4 rules retain the ordinary local/main/default layout");
        let matches = inventory
            .entries()
            .iter()
            .filter(|entry| {
                entry.network == Ipv4Addr::new(198, 18, 0, 2)
                    && entry.prefix_len == 32
                    && entry.table.get() == 254
            })
            .collect::<Vec<_>>();
        if matches.len() != 1
            || matches[0].interface != Some(interface)
            || matches[0].scope != 253
            || matches[0].kind != 1
            || !matches[0].exact
        {
            return Err("native capture route inventory differs".into());
        }
        println!(
            "PASS complete bounded IPv4 inventory preserves exact fixture capture route metadata"
        );
        Ok(())
    }
    async fn exchange(
        tun: Arc<warper_service::linux::tun::PacketPort>,
        networking: Networking,
        native: &mut Option<warper_service::linux::tun::Owner>,
    ) -> Result<(), Failure> {
        let Networking {
            runtime,
            mut channels,
            mut relays,
            ..
        } = networking;
        let mut pump = warper_service::linux::packet::Pump::new(
            tun.clone(),
            channels.ingress.clone(),
            channels.packets,
            Duration::from_secs(2),
        )?;
        let (pump_stop, pump_cancellation) = tokio::sync::watch::channel(false);
        let mut pump_task = tokio::spawn(async move {
            let result = pump.run(pump_cancellation).await;
            (pump, result)
        });
        let mut stopped_pump = None;
        let mut pump_joined = false;
        let owner = tokio::spawn(runtime.run());
        let app = application();
        tokio::pin!(app);
        let rejected = async {
            let error =
                tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(DESTINATION))
                    .await?
                    .err()
                    .ok_or("quiescence accepted a new kernel TCP connection")?;
            if !matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
            ) {
                return Err(Box::new(error) as Failure);
            }
            Ok::<_, Failure>(())
        };
        tokio::pin!(rejected);
        let mut application_done = false;
        let mut rejection_done = false;
        let started = tokio::time::Instant::now();
        let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let (packet_owner, _) = tokio::sync::watch::channel(false);
        let request = || Request {
            deadline: started + Duration::from_secs(8),
            cancellation: packet_owner.subscribe(),
        };
        let mut joined = 0;
        // Retain/join native publication outside the cancellable packet loop.
        // The real runtime owner already exists before any capture route.
        let publication = channels.publication.clone();
        let capture = capture_change(native, move |native, request| {
            native.publish_capture(publication, request)
        })
        .await;
        let outcome = async {
            capture?;
            inspect_capture_route().await?;
            loop {
                let changes = native
                    .as_mut()
                    .ok_or("packet fixture capture owner missing")?
                    .capture_changes()?;
                tokio::select! {
                    result=&mut app,if !application_done=>{
                        result?;
                        let mut receipt=channels.admission.quiesce()?;
                        receipt.wait(request()).await?;
                        application_done=true;
                    },
                    result=&mut rejected,if application_done && !rejection_done=>{
                        result?;
                        rejection_done=true;
                        println!("PASS live quiescent mapping resets new kernel TCP without accepting another flow");
                    },
                    reason=changes.wait(request())=>return Err(format!("capture invalidated during controlled traffic: {reason:?}").into()),
                    ()=tokio::time::sleep(Duration::from_millis(1)),if rejection_done && joined==1=>{
                        if channels.publication.retained_flows()!=0 {continue;}
                        break;
                    },
                    result=&mut pump_task=>{
                        pump_joined=true;
                        match result {
                            Ok((pump,result))=>{
                                stopped_pump=Some(pump);
                                return match result {
                                    Err(error)=>Err(Box::new(error) as Failure),
                                    Ok(_)=>Err("packet pump stopped before native withdrawal".into()),
                                };
                            },
                            Err(error)=>return Err(Box::new(error) as Failure),
                        }
                    },
                    flow=channels.tcp.recv()=>{
                        let flow=flow.ok_or("host acceptance owner stopped")?;
                        if flow.metadata.source.ip()!="198.18.0.1".parse::<std::net::IpAddr>()? || flow.metadata.destination!=DESTINATION.parse::<SocketAddr>()? {return Err("kernel application tuple differs".into());}
                        let mut receipt=channels.admission.quiesce()?;
                        receipt.wait(request()).await?;
                        if channels.publication.retained_flows()==0 {return Err("accepted flow lost its lifetime reservation".into());}
                        let blocked=capture_change(native,|native,request|native.withdraw_capture(request)).await;
                        if !matches!(blocked.as_ref().err().and_then(|error|error.downcast_ref::<warper_service::linux::tun::Error>()),Some(warper_service::linux::tun::Error::CaptureFlowsActive)) {
                            return Err("capture withdrawal ignored a quiescent accepted flow".into());
                        }
                        relays.admit(flow.into_core())?;
                    },
                    completion=relays.next(),if relays.retained()>0=>{
                        let completion=completion?.ok_or("relay completion owner stopped")?;
                        if completion.outcome.is_err() || completion.transferred.sent!=PAYLOAD as u64 || completion.transferred.received!=16384+9 {return Err(format!("TUN relay outcome differs: {:?}, sent={}, received={}", completion.outcome, completion.transferred.sent, completion.transferred.received).into());}joined+=1;
                    },
                }
            }
            Ok::<_, Failure>(())
        };
        let result = tokio::time::timeout(Duration::from_secs(8), outcome)
            .await
            .map_err(|error| Box::new(error) as Failure)
            .and_then(|result| result);
        let mut cleanup = Vec::new();
        if result.is_ok() {
            // Native cleanup is joined while the quiescent policy still exists.
            if let Err(error) =
                capture_change(native, |native, request| native.withdraw_capture(request)).await
            {
                cleanup.push(error);
            } else if !channels.publication.is_published() {
                cleanup.push("capture retired after the runtime mapping disappeared".into());
            } else {
                println!(
                    "PASS journaled capture drains accepted flows and retires before runtime shutdown"
                );
            }
        }
        pump_stop.send_replace(true);
        let packet_report = if pump_joined {
            None
        } else {
            match pump_task.await {
                Ok((pump, result)) => {
                    stopped_pump = Some(pump);
                    match result {
                        Ok(report) => Some(report),
                        Err(error) => {
                            cleanup.push(Box::new(error) as Failure);
                            None
                        }
                    }
                }
                Err(error) => {
                    cleanup.push(Box::new(error) as Failure);
                    None
                }
            }
        };
        let relay_report = relays.shutdown().await;
        if channels.shutdown.send(()).is_err() {
            cleanup.push("host shutdown owner lost".into());
        }
        let host_report = match owner.await {
            Ok(Ok(report)) => Some(report),
            Ok(Err(error)) => {
                cleanup.push(Box::new(error) as Failure);
                None
            }
            Err(error) => {
                cleanup.push(Box::new(error) as Failure);
                None
            }
        };
        drop(stopped_pump);
        if relay_report.first_flow_failure.is_some()
            || relay_report.first_worker_failure.is_some()
            || relay_report.shutdown_error.is_some()
        {
            cleanup.push("relay shutdown reported a failure".into());
        }
        preserve(result, cleanup)?;
        let host_report = host_report.ok_or("host runtime report missing")?;
        let packet_report = packet_report.ok_or("packet pump report missing")?;
        let input = packet_report.captured_packets;
        let output = packet_report.sent_packets;
        if joined != 1
            || relay_report.finished != 1
            || relay_report.failed != 0
            || host_report.tcp.accepted != 1
            || host_report.retained_streams != 0
            || input == 0
            || output == 0
        {
            return Err("native TUN worker counters differ".into());
        }
        let elapsed = started.elapsed().as_nanos();
        let after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let cpu_ns = (i128::from(after.tv_sec) - i128::from(cpu.tv_sec)) * 1_000_000_000
            + i128::from(after.tv_nsec)
            - i128::from(cpu.tv_nsec);
        let memory = fs::read_to_string("/proc/self/status")?;
        let peak = memory
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .ok_or("packet workload RSS missing")?;
        println!(
            "owned_packet_pump flows=1 mtu=1280 request_bytes={PAYLOAD} response_bytes=16393 captured={input} returned={output} elapsed_ns={elapsed} cpu_ns={cpu_ns} ingress_drops={} discarded_output={} write_wait_buckets={:?} kernel_drops=unmeasured {peak}",
            packet_report.ingress_drops, packet_report.discarded_output, packet_report.write_waits,
        );
        println!(
            "PASS actual kernel TCP/TUN to production host/SOCKS5/relay adapters; {input} captured and {output} returned packets; exact 64 KiB, duplex and response after FIN"
        );
        Ok(())
    }
    pub async fn exercise(mount: &str, net: &str) -> Result<(), Failure> {
        isolated(mount, net)?;
        let jobs = warper_service::native::Workers::new(1)?;
        let (bootstrap_owner, _) = tokio::sync::watch::channel(false);
        let mut bootstrap = jobs.try_reserve()?.start(native_context);
        let (context, runtime_lease) = join_native(&mut bootstrap, &bootstrap_owner).await??;
        let context = Arc::new(context);
        // Complete deliberate rule changes before preparing protected paths.
        // Restoring visible rules does not promise unchanged kernel lookup state.
        reject_custom_rules().await?;
        physical::exercise(context.clone(), mount, net).await?;
        // Read-only production query in the fixture's private network namespace.
        // This observes a route; it does not authorize the loopback connector.
        let (query_owner, cancellation) = tokio::sync::watch::channel(false);
        let mut changes = warper_service::linux::change_monitor::Monitor::subscribe()?;
        let observed = warper_service::linux::route_lookup::lookup(
            warper_service::linux::route_lookup::Query {
                destination: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080),
                source: None,
                interface: None,
            },
            Request {
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                cancellation,
            },
        )
        .await?;
        if observed.source != Ipv4Addr::LOCALHOST
            || observed.kind != warper_service::linux::route_lookup::Kind::Local
            || observed.gateway.is_some()
        {
            return Err("private loopback route observation differs".into());
        }
        println!("PASS bounded native route query in private network namespace");
        if changes.check_pending().is_err() {
            return Err("private network changed during route query".into());
        }
        let interrupted = tokio::time::timeout(
            Duration::from_millis(1),
            changes.wait(Request {
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                cancellation: query_owner.subscribe(),
            }),
        )
        .await;
        if interrupted.is_ok()
            || changes.invalidation().is_some()
            || changes.check_pending().is_err()
        {
            return Err("dropped pending wait changed private subscription".into());
        }
        let plan = plan()?;
        // A retained TUN occupies the first generated name. The candidate
        // must create another device and preserve this independent owner.
        let foreign = DeviceBuilder::new().mtu(1400).enable(false).build_sync()?;
        let reason = changes
            .wait(Request {
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                cancellation: query_owner.subscribe(),
            })
            .await;
        if reason != warper_service::linux::change_monitor::Invalidation::NetworkChanged
            || changes.check_pending() != Err(reason)
        {
            return Err("private TUN change did not invalidate native monitor".into());
        }
        println!("PASS native link change permanently invalidates bounded monitor");
        let foreign_name = foreign.name()?;
        let result=async {
            journaled_tun_lifecycle(context.clone(),&foreign).await?;
            measure_captures(context.clone()).await?;
            let foreign_identity=inspect_link(&foreign_name).await?;
            if foreign_identity.kind!=warper_service::linux::link_lookup::Kind::Tun
                || foreign_identity.mtu.get()!=1400 {return Err("foreign fixture TUN inspection differs".into());}
            let before=ip(&["-j","link","show","dev",&foreign_name])?;
            let native=DeviceBuilder::new().mtu(MTU as u16).enable(false).build_sync()?;
            let fresh=native.name()?;
            if !matches!(native.set_name(&foreign_name),Err(error) if error.kind()==io::ErrorKind::AlreadyExists)
                || before!=ip(&["-j","link","show","dev",&foreign_name])? {return Err("TUN rename collision changed foreign interface".into());}
            native.set_name(NAME)?;
            if fresh==foreign_name || native.mtu()?!=MTU as u16 {return Err("fresh TUN identity/MTU differs".into());}
            let owned=inspect_link(NAME).await?;
            if owned.kind!=warper_service::linux::link_lookup::Kind::Tun
                || owned.mtu.get()!=MTU as u32 || owned.index==foreign_identity.index
                || inspect_link(&foreign_name).await?!=foreign_identity {return Err("native TUN identity inspection differs".into());}
            println!("PASS native TUN name/index/MTU inspection and foreign identity preservation");
            drop(native);
            let (native_owner, port)=owned_packet_port(context.clone()).await?;
            let index=native_owner.index().ok_or("packet owner index missing")?;
            let mut native_owner=Some(native_owner);
            let endpoints=plan.endpoints().map(|(_,endpoint)|endpoint).collect();
            let connector=protected_connector(context.clone(),endpoints,index,plan.flow_capacity()).await?;
            let networking=plan.instantiate(Seed::generate()?,Arc::new(connector))?;
            let tun=Arc::new(port);
            let mut workers=peers().await?;
            let outcome=exchange(tun.clone(),networking,&mut native_owner).await;
            if outcome.is_err() {workers.abort_all();}
            let mut cleanup=Vec::new();
            let deadline=tokio::time::Instant::now()+Duration::from_secs(1);
            while !workers.is_empty() {
                match tokio::time::timeout_at(deadline,workers.join_next()).await {
                    Ok(Some(Ok(Ok(()))))=>{},
                    Ok(Some(Ok(Err(error))))=>{cleanup.push(error);workers.abort_all();},
                    Ok(Some(Err(error))) if !error.is_cancelled()=>{cleanup.push(Box::new(error) as Failure);workers.abort_all();},
                    Ok(Some(Err(_)))=>{},
                    Ok(None)=>break,
                    Err(error)=>{
                        cleanup.push(Box::new(error) as Failure);workers.abort_all();
                        while let Some(result)=workers.join_next().await {
                            match result {Ok(Ok(()))=>{},Ok(Err(error))=>cleanup.push(error),Err(error) if !error.is_cancelled()=>cleanup.push(Box::new(error) as Failure),Err(_)=>{}}
                        }
                    },
                }
            }
            drop(tun);
            let jobs=warper_service::native::Workers::new(1)?;
            let (join_owner,_)=tokio::sync::watch::channel(false);
            if let Some(mut native_owner)=native_owner {
                let mut closing=jobs.try_reserve()?.start(move||native_owner.close());
                if let Err(error)=join_native(&mut closing,&join_owner).await? {cleanup.push(Box::new(error) as Failure);}
            } else {
                cleanup.push("packet fixture native owner lost".into());
            }
            let absent=nix::net::if_::if_nameindex()?.iter().all(|interface|interface.name().to_bytes()!=NAME.as_bytes());
            if !absent || before!=ip(&["-j","link","show","dev",&foreign_name])? {cleanup.push("native TUN cleanup or foreign preservation failed".into());}
            preserve(outcome,cleanup)?;
            println!("PASS journaled TUN packet port, collision preservation, explicit retirement and joined peers");
            supervised_network::exercise(context.clone(),runtime_lease.clone()).await?;
            controller_dispatch::exercise(runtime_lease.clone()).await?;
            Ok(())
        }.await;
        drop(foreign);
        let mut cleanup = match nix::net::if_::if_nameindex() {
            Ok(interfaces)
                if interfaces
                    .iter()
                    .any(|interface| interface.name().to_bytes() == foreign_name.as_bytes()) =>
            {
                vec!["controlled foreign TUN did not retire".into()]
            }
            Ok(_) => Vec::new(),
            Err(error) => vec![Box::new(error) as Failure],
        };
        let storage_recovery = (|| -> Result<(), Failure> {
            use warper_control::runtime::journal::{Error as JournalError, NetworkJournal};
            use warper_service::linux::tun::{Error as TunError, Owner};
            let mut owner = Owner::prepare(context.clone(), Some("warper-failure"), MTU as u16)?;
            owner.allocate()?;
            let index = owner.index().ok_or("faulted TUN lacked an index")?;
            fs::write("/var/lib/warper/network.pending", b"partial")?;
            fs::set_permissions(
                "/var/lib/warper/network.pending",
                fs::Permissions::from_mode(0o600),
            )?;
            if owner.apply_name() != Err(TunError::Storage(JournalError::RecoveryRequired)) {
                return Err("pending storage did not block native rename".into());
            }
            if !matches!(owner.close(),Err(failure) if failure.primary==TunError::Storage(JournalError::RecoveryRequired))
                || index_exists(index)?
            {
                return Err(
                    "TUN cleanup did not preserve storage failure and close its descriptor".into(),
                );
            }
            let mut journal = NetworkJournal::open(&runtime_lease)?;
            let token = journal
                .inspect_pending(&runtime_lease)?
                .ok_or("missing injected pending state")?;
            journal.discard_pending(&runtime_lease, token)?;
            owner.close()?;
            println!(
                "PASS native TUN cleanup surfaces storage failure and finishes only after explicit pending recovery"
            );
            Ok(())
        })();
        if let Err(error) = storage_recovery {
            cleanup.push(error);
        }
        let abandoned: Result<_, Failure> = async {
            use warper_service::linux::tun::{Error as TunError, Owner};
            let (owner, port) = owned_packet_port(context.clone()).await?;
            let index = owner.index().ok_or("abandoned TUN lacked an index")?;
            drop(owner);
            if !index_exists(index)?
                || !matches!(
                    Owner::prepare(context.clone(), None, MTU as u16),
                    Err(TunError::RecoveryRequired)
                )
            {
                return Err(
                    "live packet port lost native ownership or conservative recovery".into(),
                );
            }
            Ok((index, port))
        }
        .await;
        let pending_port = match abandoned {
            Ok(port) => Some(port),
            Err(error) => {
                cleanup.push(error);
                None
            }
        };
        if let Err(error) = context.revalidate() {
            cleanup.push(Box::new(error) as Failure);
        }
        drop(context);
        drop(runtime_lease);
        if let Some((index, port)) = pending_port {
            if !matches!(
                warper_control::runtime::RuntimeLease::acquire(),
                Err(warper_control::runtime::Error::AlreadyRunning)
            ) {
                cleanup.push("surviving packet port released runtime ownership".into());
            }
            drop(port);
            match index_exists(index) {
                Ok(false) => {}
                Ok(true) => cleanup.push("last packet port failed to retire its TUN".into()),
                Err(error) => cleanup.push(error),
            }
            println!(
                "PASS surviving packet port retains device/runtime ownership and conservative recovery until last drop"
            );
        }
        if let Err(error) = warper_control::runtime::RuntimeLease::acquire() {
            cleanup.push(Box::new(error) as Failure);
        }
        preserve(result, cleanup)?;
        process_owner::exercise(mount, net).await
    }
    pub async fn context_peer(mount: &str, net: &str) -> Result<(), Failure> {
        process_owner::peer(mount, net).await
    }
    pub async fn physical_peer(mount: &str, net: &str) -> Result<(), Failure> {
        physical::peer(mount, net).await
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn cleanup_diagnostics_preserve_the_primary_and_secondary_failures() {
            let error = preserve(
                Err("initial probe failure".into()),
                vec!["cleanup failure".into()],
            )
            .unwrap_err();
            let combined = error.downcast_ref::<fixture::CombinedFailure>().unwrap();
            assert_eq!(combined.primary.to_string(), "initial probe failure");
            assert_eq!(combined.cleanup[0].to_string(), "cleanup failure");
            assert_eq!(
                error.to_string(),
                "initial probe failure; 1 cleanup failure(s)"
            );
            assert_eq!(
                preserve(Ok(()), vec!["cleanup only".into()])
                    .unwrap_err()
                    .to_string(),
                "cleanup only"
            );
        }
        #[test]
        fn controlled_plan_is_valid_before_any_native_tun_operation() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let Networking {
                    runtime,
                    channels,
                    relays,
                    ..
                } = {
                    let plan = plan().unwrap();
                    let endpoint = plan.endpoints().next().unwrap().1;
                    plan.instantiate(
                        Seed::generate().unwrap(),
                        Arc::new(LocalConnector(endpoint)),
                    )
                    .unwrap()
                };
                channels.shutdown.send(()).unwrap();
                assert_eq!(runtime.run().await.unwrap().admitted_packets, 0);
                assert_eq!(relays.shutdown().await.admitted, 0);
            });
        }
    }
}
#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "--require-initial-root" => linux::root(),
        [mode] if mode == "--configuration-peer" => {
            tokio::task::spawn_blocking(linux::configuration_peer).await?
        }
        [mode, mount, net] if mode == "--exercise" => linux::exercise(mount, net).await,
        [mode, mount, net] if mode == "--physical-peer" => linux::physical_peer(mount, net).await,
        [mode, mount, net] if mode == "--context-peer" => linux::context_peer(mount, net).await,
        _ => Err("use the disposable namespace acceptance harness".into()),
    }
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedIntegration: native TUN probe requires Linux");
    std::process::ExitCode::FAILURE
}

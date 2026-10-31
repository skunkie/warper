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
        os::unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::UnixStream as NativeStream,
        },
        process::Command,
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinSet,
    };
    use tun_rs::{AsyncDevice, DeviceBuilder};
    use warper_config::schema::{Config, Platform};
    use warper_control::{namespace, unix};
    use warper_core::{
        configuration::paths::{Account, Paths},
        transport::{EndpointConnector, Error, OpenTcp, Request, TcpStream as BoxedTcp},
    };
    use warper_service::preflight::{Networking, Plan};
    use warper_stack::{Seed, host::MTU};

    type Failure = Box<dyn std::error::Error + Send + Sync>;
    const NAME: &str = "warper-probe";
    const DESTINATION: &str = "198.18.0.2:443";
    const PAYLOAD: usize = 65536;

    pub fn root() -> Result<(), Failure> {
        namespace::require_initial_user_namespace()?;
        let (a, _b) = NativeStream::pair()?;
        unix::authenticate_service(&a)?;
        Ok(())
    }
    fn isolated(mount: &str, net: &str) -> Result<(), Failure> {
        root()?;
        for (kind, anchor) in [("mnt", mount), ("net", net)] {
            let fd: u32 = anchor.parse()?;
            let path = format!("/proc/self/fd/{fd}");
            let label = fs::read_link(&path)?;
            let label = label.to_str().ok_or("invalid fixture namespace label")?;
            let file = fs::File::open(&path)?;
            if rustix::fs::fstatfs(&file)?.f_type as u64 != 0x6e736673
                || !label.starts_with(&format!("{kind}:["))
                || !label.ends_with(']')
            {
                return Err("fixture requires inherited namespace handles".into());
            }
            let old = file.metadata()?;
            let current = fs::metadata(format!("/proc/thread-self/ns/{kind}"))?;
            if old.dev() == current.dev() && old.ino() == current.ino() {
                return Err("fixture requires private mount/network namespaces".into());
            }
        }
        let device = fs::symlink_metadata("/dev/net/tun")?;
        if !device.file_type().is_char_device()
            || device.uid() != 0
            || rustix::fs::major(device.rdev()) != 10
            || rustix::fs::minor(device.rdev()) != 200
        {
            return Err("fixture requires a real protected TUN character device".into());
        }
        Ok(())
    }
    fn ip(args: &[&str]) -> Result<Vec<u8>, Failure> {
        let output = Command::new("timeout")
            .args(["--kill-after=1s", "2s", "ip"])
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err("controlled ip operation failed".into());
        }
        Ok(output.stdout)
    }
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
    struct LocalConnector(SocketAddr);
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
        use warper_service::linux::context::{Classification, Context, RecordedOwner};
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
        let mut latencies = Vec::with_capacity(20);
        for _ in 0..20 {
            let before = tokio::time::Instant::now();
            let mut owner = Owner::prepare(context.clone(), None, MTU as u16)?;
            owner.allocate()?;
            owner.close()?;
            latencies.push(before.elapsed().as_nanos());
        }
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
            "journaled_tun iterations=20 concurrency=1 elapsed_ns={elapsed} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 {peak}",
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
                    let address = Ipv4Addr::new(198, 18, 0, 9);
                    owner.assign_ipv4(address, request())?;
                    owner.assign_ipv4(address, request())?;
                    if owner.stage() != Stage::Addressed {
                        return Err("address ownership was not committed".into());
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
        // Retain and join even if the shorter mutation deadline has expired.
        let result = loop {
            match task
                .wait(Request {
                    deadline: tokio::time::Instant::now() + Duration::from_secs(10),
                    cancellation: cancellation_owner.subscribe(),
                })
                .await
            {
                Err(warper_service::native::Error::Deadline) => continue,
                result => break result?,
            }
        };
        let after = ip(&["-j", "address", "show", "dev", &foreign_name])?;
        ip(&["address", "del", duplicate, "dev", &foreign_name])?;
        result?;
        if before != after {
            return Err("owned address cleanup changed a foreign address".into());
        }
        println!(
            "PASS journaled IPv4 /32 address ACK/readback, idempotency, foreign conflict and joined rollback"
        );
        Ok(())
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
    fn networking() -> Result<Networking, Failure> {
        let endpoint = "127.0.0.1:1080".parse()?;
        let account = Account {
            uid: 1000,
            name: "fixture".into(),
            home: "/nonexistent".into(),
        };
        let paths = Paths::new(&account, std::path::Path::new("/"), Some("/fixture.yaml"))?;
        let source = format!(
            "tunnel: {{ip: 198.18.0.1, name: {NAME}}}\nprotocols: [{{socks5: {{host: '{endpoint}', ips: [198.18.0.2/32]}}}}]\n"
        );
        let config = Config::parse(source.as_bytes(), &paths, Platform::Linux)?;
        Ok(Plan::prepare(&config, Platform::Linux)?
            .instantiate(Seed::generate()?, Arc::new(LocalConnector(endpoint)))?)
    }
    #[derive(Debug)]
    struct CombinedFailure {
        primary: Failure,
        cleanup: Vec<Failure>,
    }
    impl std::fmt::Display for CombinedFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}; {} cleanup failure(s)",
                self.primary,
                self.cleanup.len()
            )
        }
    }
    impl std::error::Error for CombinedFailure {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&*self.primary)
        }
    }
    fn preserve(primary: Result<(), Failure>, mut cleanup: Vec<Failure>) -> Result<(), Failure> {
        let primary = match primary {
            Err(error) => error,
            Ok(()) if cleanup.is_empty() => return Ok(()),
            Ok(()) => cleanup.remove(0),
        };
        if cleanup.is_empty() {
            Err(primary)
        } else {
            Err(Box::new(CombinedFailure { primary, cleanup }))
        }
    }
    async fn exchange(tun: Arc<AsyncDevice>, networking: Networking) -> Result<(), Failure> {
        let Networking {
            runtime,
            mut channels,
            mut relays,
            ..
        } = networking;
        let owner = tokio::spawn(runtime.run());
        let app = application();
        tokio::pin!(app);
        let mut buffer = [0; MTU + 1];
        let mut input = 0u64;
        let mut output = 0u64;
        let mut joined = 0;
        let outcome = async {
            // The internal policy/handler and retained runtime owner exist
            // before the fixture publishes its acknowledged kernel route.
            ip(&["route", "add", "198.18.0.2/32", "dev", NAME])?;
            loop {
                tokio::select! {
                    result=&mut app=>{result?;break;},
                    packet=tun.recv(&mut buffer)=>{
                        let length=packet?;
                        if length==0 || length>MTU {return Err("TUN packet exceeds declared bounds".into());}
                        channels.ingress.try_inject(&buffer[..length])?;input+=1;
                    },
                    packet=channels.packets.recv()=>{
                        let packet=packet.ok_or("host packet owner stopped")?;
                        if tun.send(&packet).await?!=packet.len() {return Err("TUN short write".into());}output+=1;
                    },
                    flow=channels.tcp.recv()=>{
                        let flow=flow.ok_or("host acceptance owner stopped")?;
                        if flow.metadata.source.ip()!="198.18.0.1".parse::<std::net::IpAddr>()? || flow.metadata.destination!=DESTINATION.parse::<SocketAddr>()? {return Err("kernel application tuple differs".into());}
                        relays.admit(flow.into_core())?;
                    },
                    completion=relays.next(),if relays.retained()>0=>{
                        let completion=completion?.ok_or("relay completion owner stopped")?;
                        if completion.outcome.is_err() || completion.transferred.sent!=PAYLOAD as u64 || completion.transferred.received!=16384+9 {return Err("TUN relay outcome differs".into());}joined+=1;
                    },
                }
            }
            if joined == 0 {
                let completion = tokio::time::timeout(Duration::from_secs(1), relays.next())
                    .await??
                    .ok_or("missing final relay completion")?;
                if completion.outcome.is_err()
                    || completion.transferred.sent != PAYLOAD as u64
                    || completion.transferred.received != 16384 + 9
                {
                    return Err("final relay failed".into());
                }
                joined += 1;
            }
            Ok::<_, Failure>(())
        };
        let result = tokio::time::timeout(Duration::from_secs(8), outcome)
            .await
            .map_err(|error| Box::new(error) as Failure)
            .and_then(|result| result);
        let relay_report = relays.shutdown().await;
        let mut cleanup = Vec::new();
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
        if relay_report.first_flow_failure.is_some()
            || relay_report.first_worker_failure.is_some()
            || relay_report.shutdown_error.is_some()
        {
            cleanup.push("relay shutdown reported a failure".into());
        }
        preserve(result, cleanup)?;
        let host_report = host_report.ok_or("host runtime report missing")?;
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
        println!(
            "PASS actual kernel TCP/TUN to production host/SOCKS5/relay adapters; {input} captured and {output} returned packets; exact 64 KiB, duplex and response after FIN"
        );
        Ok(())
    }
    pub async fn exercise(mount: &str, net: &str) -> Result<(), Failure> {
        isolated(mount, net)?;
        let (context, runtime_lease) = native_context()?;
        let context = Arc::new(context);
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
        let networking = networking()?;
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
            let tun=Arc::new(AsyncDevice::new(native)?);
            ip(&["address","add","198.18.0.1/32","dev",NAME])?;
            tun.enabled(true)?;
            let mut workers=peers().await?;
            let outcome=exchange(tun.clone(),networking).await;
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
            let absent=nix::net::if_::if_nameindex()?.iter().all(|interface|interface.name().to_bytes()!=NAME.as_bytes());
            if !absent || before!=ip(&["-j","link","show","dev",&foreign_name])? {cleanup.push("native TUN cleanup or foreign preservation failed".into());}
            preserve(outcome,cleanup)?;
            println!("PASS fresh unnamed TUN, collision preservation, last-owner cleanup and joined peers");
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
        let abandoned = (|| -> Result<(), Failure> {
            use warper_service::linux::tun::{Error as TunError, Owner};
            let mut owner = Owner::prepare(context.clone(), None, MTU as u16)?;
            owner.allocate()?;
            let index = owner.index().ok_or("abandoned TUN lacked an index")?;
            drop(owner);
            if index_exists(index)?
                || !matches!(
                    Owner::prepare(context.clone(), None, MTU as u16),
                    Err(TunError::RecoveryRequired)
                )
            {
                return Err("dropped TUN did not close conservatively behind recovery".into());
            }
            println!(
                "PASS dropped TUN closes only its descriptor and preserves explicit journal recovery"
            );
            Ok(())
        })();
        if let Err(error) = abandoned {
            cleanup.push(error);
        }
        if let Err(error) = context.revalidate() {
            cleanup.push(Box::new(error) as Failure);
        }
        drop(context);
        drop(runtime_lease);
        if let Err(error) = warper_control::runtime::RuntimeLease::acquire() {
            cleanup.push(Box::new(error) as Failure);
        }
        preserve(result, cleanup)
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
            let combined = error.downcast_ref::<CombinedFailure>().unwrap();
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
                } = networking().unwrap();
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
        [mode, mount, net] if mode == "--exercise" => linux::exercise(mount, net).await,
        _ => Err("use the disposable namespace acceptance harness".into()),
    }
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedIntegration: native TUN probe requires Linux");
    std::process::ExitCode::FAILURE
}

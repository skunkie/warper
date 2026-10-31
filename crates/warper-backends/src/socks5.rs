// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! SOCKS5 TCP CONNECT, without route discovery, DNS or direct fallback.

use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use warper_core::{
    BackendId,
    transport::{
        Backend, Capabilities, EndpointConnector, Error, OpenTcp, Rejection, Request, TcpStream,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    InvalidEndpoint,
    InvalidLimit,
    InvalidCredentials,
}
impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEndpoint => "InvalidConfig: invalid SOCKS5 endpoint",
            Self::InvalidLimit => "InvalidConfig: invalid SOCKS5 stream limit",
            Self::InvalidCredentials => {
                "InvalidConfig: SOCKS5 credentials must contain 1..255 bytes each"
            }
        })
    }
}
impl std::error::Error for ConfigurationError {}

pub struct Credentials {
    user: Vec<u8>,
    password: Vec<u8>,
}
impl Credentials {
    pub fn new(user: Vec<u8>, password: Vec<u8>) -> Result<Self, ConfigurationError> {
        if !(1..=255).contains(&user.len()) || !(1..=255).contains(&password.len()) {
            return Err(ConfigurationError::InvalidCredentials);
        }
        Ok(Self { user, password })
    }
}
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

pub struct Socks5 {
    id: BackendId,
    endpoint: SocketAddr,
    credentials: Option<Credentials>,
    connector: Arc<dyn EndpointConnector>,
    permits: Arc<Semaphore>,
}
impl Socks5 {
    pub fn new(
        id: BackendId,
        endpoint: SocketAddr,
        credentials: Option<Credentials>,
        max_streams: usize,
        connector: Arc<dyn EndpointConnector>,
    ) -> Result<Self, ConfigurationError> {
        if endpoint.port() == 0 {
            return Err(ConfigurationError::InvalidEndpoint);
        }
        if max_streams == 0 || max_streams > Semaphore::MAX_PERMITS {
            return Err(ConfigurationError::InvalidLimit);
        }
        Ok(Self {
            id,
            endpoint,
            credentials,
            connector,
            permits: Arc::new(Semaphore::new(max_streams)),
        })
    }

    async fn open(&self, destination: SocketAddr, request: Request) -> Result<TcpStream, Error> {
        if destination.port() == 0 {
            return Err(Error::InvalidDestination);
        }
        if let SocketAddr::V6(address) = destination
            && (address.scope_id() != 0 || address.flowinfo() != 0)
        {
            return Err(Error::UnsupportedCapability);
        }
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        let mut stream = self.connector.connect_tcp(self.endpoint, request).await?;
        negotiate(&mut stream, self.credentials.as_ref(), destination).await?;
        Ok(Box::new(PermittedStream {
            stream,
            _permit: permit,
        }))
    }
}
impl Backend for Socks5 {
    fn id(&self) -> BackendId {
        self.id
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            ipv4: true,
            ipv6: true,
            tcp: true,
            udp: false,
        }
    }
    fn open_tcp(&self, destination: SocketAddr, request: Request) -> OpenTcp<'_> {
        let connector_request = request.clone();
        Box::pin(request.run(self.open(destination, connector_request)))
    }
}
impl fmt::Debug for Socks5 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Socks5(<redacted>)")
    }
}

struct PermittedStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}
impl AsyncRead for PermittedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for PermittedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn negotiate(
    stream: &mut TcpStream,
    credentials: Option<&Credentials>,
    destination: SocketAddr,
) -> Result<(), Error> {
    let method = if credentials.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await.map_err(io_error)?;
    let mut selected = [0; 2];
    stream.read_exact(&mut selected).await.map_err(io_error)?;
    if selected[0] != 5 {
        return Err(Error::Protocol);
    }
    if selected[1] != method {
        return Err(Error::Authentication);
    }
    if let Some(credentials) = credentials {
        let mut auth = Vec::with_capacity(513);
        auth.extend_from_slice(&[1, credentials.user.len() as u8]);
        auth.extend_from_slice(&credentials.user);
        auth.push(credentials.password.len() as u8);
        auth.extend_from_slice(&credentials.password);
        stream.write_all(&auth).await.map_err(io_error)?;
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.map_err(io_error)?;
        if reply != [1, 0] {
            return Err(Error::Authentication);
        }
    }
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[5, 1, 0]);
    match destination.ip() {
        IpAddr::V4(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&destination.port().to_be_bytes());
    stream.write_all(&request).await.map_err(io_error)?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await.map_err(io_error)?;
    if reply[0] != 5 || reply[2] != 0 {
        return Err(Error::Protocol);
    }
    if reply[1] != 0 {
        return Err(rejected(reply[1]));
    }
    let length = match reply[3] {
        1 => 6,
        4 => 18,
        3 => {
            let size = stream.read_u8().await.map_err(io_error)?;
            if size == 0 {
                return Err(Error::Protocol);
            }
            usize::from(size) + 2
        }
        _ => return Err(Error::Protocol),
    };
    let mut bound = [0; 257];
    stream
        .read_exact(&mut bound[..length])
        .await
        .map_err(io_error)?;
    Ok(())
}
fn rejected(value: u8) -> Error {
    Error::Rejected(match value {
        1 => Rejection::General,
        2 => Rejection::PolicyDenied,
        3 => Rejection::NetworkUnreachable,
        4 => Rejection::HostUnreachable,
        5 => Rejection::ConnectionRefused,
        6 => Rejection::TtlExpired,
        7 => Rejection::CommandUnsupported,
        8 => Rejection::AddressUnsupported,
        _ => return Error::Protocol,
    })
}
fn io_error(error: io::Error) -> Error {
    Error::Io(error.kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{io::DuplexStream, sync::watch, time::Instant};

    const V4_REQUEST: [u8; 10] = [5, 1, 0, 1, 198, 51, 100, 9, 1, 187];
    const SUCCESS: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

    fn request() -> (watch::Sender<bool>, Request) {
        let (owner, cancellation) = watch::channel(false);
        (
            owner,
            Request {
                deadline: Instant::now() + Duration::from_secs(1),
                cancellation,
            },
        )
    }
    fn destination() -> SocketAddr {
        "198.51.100.9:443".parse().unwrap()
    }

    async fn exchange_reply(reply: Vec<u8>) -> Result<Vec<u8>, Error> {
        let (client, mut peer) = tokio::io::duplex(64);
        let mut client: TcpStream = Box::new(client);
        let (_owner, request) = request();
        let (actual, ()) = tokio::join!(
            request.run(async {
                negotiate(&mut client, None, destination()).await?;
                let mut remaining = Vec::new();
                client
                    .take(64)
                    .read_to_end(&mut remaining)
                    .await
                    .map_err(io_error)?;
                Ok(remaining)
            }),
            async {
                let mut hello = [0; 3];
                peer.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello, [5, 1, 0]);
                peer.write_all(&[5, 0]).await.unwrap();
                let mut target = [0; 10];
                peer.read_exact(&mut target).await.unwrap();
                assert_eq!(target, V4_REQUEST);
                peer.write_all(&reply).await.unwrap();
                drop(peer);
            }
        );
        actual
    }

    #[tokio::test(start_paused = true)]
    async fn every_bound_address_shape_is_consumed_without_consuming_application_data() {
        let mut ipv4 = SUCCESS.to_vec();
        ipv4.extend_from_slice(b"after-reply");
        let mut ipv6 = vec![5, 0, 0, 4];
        ipv6.extend_from_slice(&[0; 18]);
        ipv6.extend_from_slice(b"after-reply");
        let mut domain = vec![5, 0, 0, 3, 255];
        domain.extend_from_slice(&[b'x'; 255]);
        domain.extend_from_slice(&[0, 0]);
        domain.extend_from_slice(b"after-reply");
        for reply in [ipv4, ipv6, domain] {
            assert_eq!(exchange_reply(reply).await.unwrap(), b"after-reply");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn server_rejections_and_malformed_replies_are_typed_without_fallback() {
        struct Case {
            id: &'static str,
            reply: Vec<u8>,
            expected: Error,
        }
        let cases = [
            Case {
                id: "general",
                reply: vec![5, 1, 0, 1],
                expected: Error::Rejected(Rejection::General),
            },
            Case {
                id: "policy",
                reply: vec![5, 2, 0, 1],
                expected: Error::Rejected(Rejection::PolicyDenied),
            },
            Case {
                id: "network",
                reply: vec![5, 3, 0, 1],
                expected: Error::Rejected(Rejection::NetworkUnreachable),
            },
            Case {
                id: "host",
                reply: vec![5, 4, 0, 1],
                expected: Error::Rejected(Rejection::HostUnreachable),
            },
            Case {
                id: "refused",
                reply: vec![5, 5, 0, 1],
                expected: Error::Rejected(Rejection::ConnectionRefused),
            },
            Case {
                id: "ttl",
                reply: vec![5, 6, 0, 1],
                expected: Error::Rejected(Rejection::TtlExpired),
            },
            Case {
                id: "command",
                reply: vec![5, 7, 0, 1],
                expected: Error::Rejected(Rejection::CommandUnsupported),
            },
            Case {
                id: "family",
                reply: vec![5, 8, 0, 1],
                expected: Error::Rejected(Rejection::AddressUnsupported),
            },
            Case {
                id: "unknown rejection",
                reply: vec![5, 9, 0, 1],
                expected: Error::Protocol,
            },
            Case {
                id: "version",
                reply: vec![4, 0, 0, 1],
                expected: Error::Protocol,
            },
            Case {
                id: "reserved",
                reply: vec![5, 0, 1, 1],
                expected: Error::Protocol,
            },
            Case {
                id: "address tag",
                reply: vec![5, 0, 0, 2],
                expected: Error::Protocol,
            },
            Case {
                id: "empty domain",
                reply: vec![5, 0, 0, 3, 0],
                expected: Error::Protocol,
            },
            Case {
                id: "truncated bound",
                reply: vec![5, 0, 0, 1, 0],
                expected: Error::Io(io::ErrorKind::UnexpectedEof),
            },
        ];
        for case in cases {
            assert_eq!(
                exchange_reply(case.reply).await,
                Err(case.expected),
                "{}",
                case.id
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn credentials_use_byte_lengths_and_ipv6_preserves_the_original_destination() {
        let credentials = Credentials::new(
            "тестовая".as_bytes().to_vec(),
            b"invented-password".to_vec(),
        )
        .unwrap();
        let (client, mut peer) = tokio::io::duplex(64);
        let mut client: TcpStream = Box::new(client);
        let (_owner, request) = request();
        let (actual, ()) = tokio::join!(
            request.run(negotiate(
                &mut client,
                Some(&credentials),
                "[2001:db8::9]:8443".parse().unwrap()
            )),
            async {
                let mut hello = [0; 3];
                peer.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello, [5, 1, 2]);
                peer.write_all(&[5, 2]).await.unwrap();
                assert_eq!(peer.read_u8().await.unwrap(), 1);
                let user_len = peer.read_u8().await.unwrap();
                assert_eq!(usize::from(user_len), "тестовая".len());
                let mut user = vec![0; usize::from(user_len)];
                peer.read_exact(&mut user).await.unwrap();
                assert_eq!(user, "тестовая".as_bytes());
                let password_len = peer.read_u8().await.unwrap();
                let mut password = vec![0; usize::from(password_len)];
                peer.read_exact(&mut password).await.unwrap();
                assert_eq!(password, b"invented-password");
                peer.write_all(&[1, 0]).await.unwrap();
                let mut target = [0; 22];
                peer.read_exact(&mut target).await.unwrap();
                assert_eq!(
                    target,
                    [
                        5, 1, 0, 4, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0x20,
                        0xfb
                    ]
                );
                peer.write_all(&SUCCESS).await.unwrap();
            }
        );
        actual.unwrap();
        assert_eq!(format!("{credentials:?}"), "Credentials(<redacted>)");
    }

    #[tokio::test(start_paused = true)]
    async fn method_downgrade_and_authentication_failure_close_without_connect_or_payload() {
        struct Case {
            id: &'static str,
            authenticated: bool,
            auth_reply: [u8; 2],
            selection: [u8; 2],
            expected: Error,
        }
        let cases = [
            Case {
                id: "bad version",
                authenticated: false,
                auth_reply: [1, 0],
                selection: [4, 0],
                expected: Error::Protocol,
            },
            Case {
                id: "no acceptable method",
                authenticated: false,
                auth_reply: [1, 0],
                selection: [5, 255],
                expected: Error::Authentication,
            },
            Case {
                id: "unoffered authentication",
                authenticated: false,
                auth_reply: [1, 0],
                selection: [5, 2],
                expected: Error::Authentication,
            },
            Case {
                id: "downgrade",
                authenticated: true,
                auth_reply: [1, 0],
                selection: [5, 0],
                expected: Error::Authentication,
            },
            Case {
                id: "bad auth version",
                authenticated: true,
                auth_reply: [2, 0],
                selection: [5, 2],
                expected: Error::Authentication,
            },
            Case {
                id: "auth rejected",
                authenticated: true,
                auth_reply: [1, 1],
                selection: [5, 2],
                expected: Error::Authentication,
            },
        ];
        for case in cases {
            let credentials = case.authenticated.then(|| {
                Credentials::new(b"sample-user".to_vec(), b"sample-password".to_vec()).unwrap()
            });
            let (client, mut peer) = tokio::io::duplex(64);
            let (_owner, request) = request();
            let (actual, ()) = tokio::join!(
                request.run(async {
                    let mut client: TcpStream = Box::new(client);
                    negotiate(&mut client, credentials.as_ref(), destination()).await
                }),
                async {
                    let mut hello = [0; 3];
                    peer.read_exact(&mut hello).await.unwrap();
                    assert_eq!(hello, [5, 1, if case.authenticated { 2 } else { 0 }]);
                    peer.write_all(&case.selection).await.unwrap();
                    if case.authenticated && case.selection == [5, 2] {
                        let mut auth = [0; 29];
                        peer.read_exact(&mut auth).await.unwrap();
                        assert_eq!(&auth[..2], &[1, 11]);
                        assert_eq!(&auth[2..13], b"sample-user");
                        assert_eq!(auth[13], 15);
                        assert_eq!(&auth[14..], b"sample-password");
                        peer.write_all(&case.auth_reply).await.unwrap();
                    }
                    let mut remaining = Vec::new();
                    peer.take(1).read_to_end(&mut remaining).await.unwrap();
                    assert!(remaining.is_empty(), "{}", case.id);
                }
            );
            assert_eq!(actual, Err(case.expected), "{}", case.id);
        }
    }

    struct MockConnector {
        endpoint: SocketAddr,
        stream: Mutex<Option<DuplexStream>>,
        calls: AtomicUsize,
    }
    impl EndpointConnector for MockConnector {
        fn connect_tcp(&self, endpoint: SocketAddr, _request: Request) -> OpenTcp<'_> {
            assert_eq!(endpoint, self.endpoint);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                self.stream
                    .lock()
                    .unwrap()
                    .take()
                    .map(|stream| Box::new(stream) as TcpStream)
                    .ok_or(Error::Io(io::ErrorKind::ConnectionRefused))
            })
        }
    }
    fn backend(stream: DuplexStream) -> (Socks5, Arc<MockConnector>) {
        let connector = Arc::new(MockConnector {
            endpoint: "192.0.2.10:1080".parse().unwrap(),
            stream: Mutex::new(Some(stream)),
            calls: AtomicUsize::new(0),
        });
        (
            Socks5::new(BackendId(7), connector.endpoint, None, 1, connector.clone()).unwrap(),
            connector,
        )
    }
    async fn successful_peer(mut peer: DuplexStream) {
        let mut hello = [0; 3];
        peer.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 1, 0]);
        peer.write_all(&[5, 0]).await.unwrap();
        let mut target = [0; 10];
        peer.read_exact(&mut target).await.unwrap();
        assert_eq!(target, V4_REQUEST);
        peer.write_all(&SUCCESS).await.unwrap();
        let mut remaining = Vec::new();
        peer.take(1).read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_admission_is_retained_through_half_close_and_released_on_drop() {
        let (client, peer) = tokio::io::duplex(64);
        let (backend, connector) = backend(client);
        let (_owner, request) = request();
        let ((), ()) = tokio::join!(
            async {
                let mut stream = backend
                    .open_tcp(destination(), request.clone())
                    .await
                    .unwrap();
                assert!(matches!(
                    backend.open_tcp(destination(), request.clone()).await,
                    Err(Error::ResourceLimit)
                ));
                stream.shutdown().await.unwrap();
                assert_eq!(backend.permits.available_permits(), 0);
                drop(stream);
                assert_eq!(backend.permits.available_permits(), 1);
                assert!(matches!(
                    backend.open_tcp(destination(), request).await,
                    Err(Error::Io(io::ErrorKind::ConnectionRefused))
                ));
                assert_eq!(connector.calls.load(Ordering::SeqCst), 2);
            },
            successful_peer(peer)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_setup_times_out_closes_the_owned_stream_and_releases_admission() {
        let (client, mut peer) = tokio::io::duplex(64);
        let (backend, connector) = backend(client);
        let (_owner, request) = request();
        let (actual, ()) = tokio::join!(backend.open_tcp(destination(), request), async {
            let mut hello = [0; 3];
            peer.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 1, 0]);
            let mut data = Vec::new();
            peer.read_to_end(&mut data).await.unwrap();
            assert!(data.is_empty());
        });
        assert!(matches!(actual, Err(Error::Timeout)));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.permits.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_during_negotiation_releases_the_only_permit_without_redial() {
        let (client, mut peer) = tokio::io::duplex(64);
        let (backend, connector) = backend(client);
        let (owner, request) = request();
        let (actual, ()) = tokio::join!(backend.open_tcp(destination(), request), async {
            let mut hello = [0; 3];
            peer.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 1, 0]);
            owner.send(true).unwrap();
            let mut remaining = Vec::new();
            peer.read_to_end(&mut remaining).await.unwrap();
            assert!(remaining.is_empty());
        });
        assert!(matches!(actual, Err(Error::Cancelled)));
        assert_eq!(backend.permits.available_permits(), 1);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_targets_cancelled_requests_and_invalid_configuration_never_dial() {
        let (client, _peer) = tokio::io::duplex(64);
        let (backend, connector) = backend(client);
        let (_owner, request) = request();
        assert!(matches!(
            backend
                .open_tcp("198.51.100.9:0".parse().unwrap(), request.clone())
                .await,
            Err(Error::InvalidDestination)
        ));
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            443,
            0,
            1,
        ));
        assert!(matches!(
            backend.open_tcp(scoped, request.clone()).await,
            Err(Error::UnsupportedCapability)
        ));
        let expired = Request {
            deadline: Instant::now(),
            cancellation: request.cancellation.clone(),
        };
        assert!(matches!(
            backend.open_tcp(destination(), expired).await,
            Err(Error::Timeout)
        ));
        let (cancel, cancellation) = watch::channel(true);
        assert!(matches!(
            backend
                .open_tcp(
                    destination(),
                    Request {
                        deadline: request.deadline,
                        cancellation
                    }
                )
                .await,
            Err(Error::Cancelled)
        ));
        drop(cancel);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            Socks5::new(
                BackendId(1),
                "192.0.2.10:0".parse().unwrap(),
                None,
                1,
                connector.clone()
            ),
            Err(ConfigurationError::InvalidEndpoint)
        ));
        for limit in [0, usize::MAX] {
            assert!(matches!(
                Socks5::new(
                    BackendId(1),
                    connector.endpoint,
                    None,
                    limit,
                    connector.clone()
                ),
                Err(ConfigurationError::InvalidLimit)
            ));
        }
    }

    #[test]
    fn credential_boundaries_and_backend_capabilities_are_explicit() {
        assert!(Credentials::new(vec![1; 255], vec![2; 255]).is_ok());
        for (user, password) in [
            (vec![], vec![1]),
            (vec![1], vec![]),
            (vec![1; 256], vec![2]),
            (vec![1], vec![2; 256]),
        ] {
            assert!(matches!(
                Credentials::new(user, password),
                Err(ConfigurationError::InvalidCredentials)
            ));
        }
        let (client, _peer) = tokio::io::duplex(1);
        let (backend, _connector) = backend(client);
        assert_eq!(backend.id(), BackendId(7));
        assert_eq!(
            backend.capabilities(),
            Capabilities {
                ipv4: true,
                ipv6: true,
                tcp: true,
                udp: false
            }
        );
        assert_eq!(format!("{backend:?}"), "Socks5(<redacted>)");
    }
}

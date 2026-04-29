use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use etherparse::PacketBuilder;
use log::{debug, error, trace, warn};
use parking_lot::Mutex;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::config::{WireGuardClientConfig, WireGuardIpVersion};
use crate::resolver::{Resolver, resolve_addresses};
use crate::socket_util::new_udp_socket;

const MAX_PACKET: usize = 65_536;
const TCP_SEND_BUFFER_SIZE: usize = 256 * 1024;
const TCP_RECV_BUFFER_SIZE: usize = 256 * 1024;
const TCP_READ_CHUNK: usize = 16 * 1024;
const EPHEMERAL_START: u16 = 49_152;
const EPHEMERAL_RANGE: u16 = 16_384;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const OUTBOUND_QUEUE_CAPACITY: usize = 4096;
const ROUTE_QUEUE_CAPACITY: usize = 1024;
const DNS_CACHE_CAPACITY: usize = 1024;
const DNS_CACHE_MAX_TTL: Duration = Duration::from_secs(300);
const DNS_CACHE_MIN_TTL: Duration = Duration::from_secs(5);

type Packet = Bytes;

#[derive(Clone)]
pub struct WireGuardSocketConnector {
    runtime: Arc<WireGuardRuntime>,
    bind_interface: Option<String>,
}

impl std::fmt::Debug for WireGuardSocketConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardSocketConnector")
            .field("server", &self.runtime.config.server)
            .field("port", &self.runtime.config.port)
            .field("bind_interface", &self.bind_interface)
            .finish()
    }
}

impl WireGuardSocketConnector {
    pub fn new(config: WireGuardClientConfig, bind_interface: Option<String>) -> Self {
        Self {
            runtime: Arc::new(WireGuardRuntime {
                config,
                bind_interface: bind_interface.clone(),
                inner: OnceCell::new(),
            }),
            bind_interface,
        }
    }

    pub async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let inner = self.runtime.inner(resolver).await?;
        let targets = inner.resolve_target(resolver, address).await?;

        let mut last_err = None;
        for target in targets {
            match inner.connect_tcp(target).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(err) => {
                    debug!("WireGuard TCP connect to {} failed: {}", target, err);
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| io::Error::other("no WireGuard target address succeeded")))
    }

    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let inner = self.runtime.inner(resolver).await?;
        if !inner.config.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WireGuard UDP is disabled by config",
            ));
        }

        let targets = inner.resolve_target(resolver, &target).await?;
        let target = targets.into_iter().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no usable WireGuard UDP target address",
            )
        })?;

        Ok(Box::new(inner.connect_udp(target)?))
    }

    pub fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    pub fn supports_udp(&self) -> bool {
        self.runtime.config.udp
    }
}

struct WireGuardRuntime {
    config: WireGuardClientConfig,
    bind_interface: Option<String>,
    inner: OnceCell<Arc<WireGuardInner>>,
}

impl std::fmt::Debug for WireGuardRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardRuntime")
            .field("server", &self.config.server)
            .field("port", &self.config.port)
            .finish()
    }
}

impl Drop for WireGuardRuntime {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.get() {
            inner.shutdown_background_tasks();
        }
    }
}

impl WireGuardRuntime {
    async fn inner(&self, resolver: &Arc<dyn Resolver>) -> io::Result<Arc<WireGuardInner>> {
        self.inner
            .get_or_try_init(|| async {
                WireGuardInner::new(
                    self.config.clone(),
                    self.bind_interface.clone(),
                    resolver.clone(),
                )
                .await
            })
            .await
            .cloned()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RouteKey {
    ip: IpAddr,
    port: u16,
}

#[derive(Debug, Clone, Copy)]
struct AllowedIp {
    network: u128,
    mask: u128,
    is_ipv6: bool,
}

impl AllowedIp {
    fn contains(&self, ip: IpAddr) -> bool {
        let is_ipv6 = matches!(ip, IpAddr::V6(_));
        self.is_ipv6 == is_ipv6 && (ip_to_u128(ip) & self.mask) == self.network
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsCacheKey {
    hostname: String,
    qtype: u16,
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: StdInstant,
}

struct WireGuardInner {
    config: WireGuardClientConfig,
    endpoint: SocketAddr,
    peer: AsyncMutex<Box<Tunn>>,
    udp: Arc<UdpSocket>,
    outbound_tx: mpsc::Sender<Packet>,
    tcp_routes: Mutex<HashMap<RouteKey, mpsc::Sender<Packet>>>,
    udp_routes: Mutex<HashMap<RouteKey, mpsc::Sender<Packet>>>,
    allowed_ips: Vec<AllowedIp>,
    dns_cache: Mutex<HashMap<DnsCacheKey, DnsCacheEntry>>,
    next_port: AtomicU16,
    shutdown_token: CancellationToken,
}

impl std::fmt::Debug for WireGuardInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardInner")
            .field("endpoint", &self.endpoint)
            .field("ip", &self.config.ip)
            .field("ipv6", &self.config.ipv6)
            .finish()
    }
}

enum TunnAction {
    Network(Packet),
    Tunnel(Packet),
}

impl WireGuardInner {
    async fn new(
        config: WireGuardClientConfig,
        bind_interface: Option<String>,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<Arc<Self>> {
        let endpoint = resolve_endpoint(&config, &resolver).await?;
        let udp = Arc::new(new_udp_socket(endpoint.is_ipv6(), bind_interface)?);
        let private_key = StaticSecret::from(decode_wireguard_key("private-key", &config.private_key)?);
        let public_key = PublicKey::from(decode_wireguard_key("public-key", &config.public_key)?);
        let allowed_ips = parse_allowed_ips(&config.allowed_ips)?;
        let pre_shared_key = config
            .pre_shared_key
            .as_deref()
            .map(|key| decode_wireguard_key("pre-shared-key", key))
            .transpose()?;
        let peer = Box::new(Tunn::new(
            private_key,
            public_key,
            pre_shared_key,
            Some(25),
            rand::random::<u32>() >> 8,
            None,
        )
        .map_err(|err| io::Error::other(format!("failed to initialize WireGuard tunnel: {err}")))?);

        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        let inner = Arc::new(Self {
            config,
            endpoint,
            peer: AsyncMutex::new(peer),
            udp,
            outbound_tx,
            tcp_routes: Mutex::new(HashMap::new()),
            udp_routes: Mutex::new(HashMap::new()),
            allowed_ips,
            dns_cache: Mutex::new(HashMap::new()),
            next_port: AtomicU16::new(rand::random::<u16>()),
            shutdown_token: CancellationToken::new(),
        });

        inner.start_background_tasks(outbound_rx);
        inner.initiate_handshake().await;
        Ok(inner)
    }

    fn start_background_tasks(self: &Arc<Self>, outbound_rx: mpsc::Receiver<Packet>) {
        let _ = tokio::spawn(Self::outbound_loop(self.clone(), outbound_rx));
        let _ = tokio::spawn(Self::inbound_loop(self.clone()));
        let _ = tokio::spawn(Self::timer_loop(self.clone()));
    }

    fn shutdown_background_tasks(&self) {
        self.shutdown_token.cancel();
    }

    async fn outbound_loop(inner: Arc<Self>, mut outbound_rx: mpsc::Receiver<Packet>) {
        let shutdown_token = inner.shutdown_token.clone();
        let mut send_buf = vec![0u8; MAX_PACKET];
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => break,
                packet = outbound_rx.recv() => {
                    let Some(packet) = packet else {
                        break;
                    };
                    if let Err(err) = inner.send_ip_packet_with_buffer(&packet, &mut send_buf).await {
                        debug!("WireGuard send IP packet failed: {}", err);
                    }
                }
            }
        }
    }

    async fn inbound_loop(inner: Arc<Self>) {
        let shutdown_token = inner.shutdown_token.clone();
        let mut recv_buf = vec![0u8; MAX_PACKET];
        loop {
            let size = match tokio::select! {
                _ = shutdown_token.cancelled() => break,
                result = inner.udp.recv_from(&mut recv_buf) => result,
            } {
                Ok((size, _addr)) => size,
                Err(err) => {
                    error!("WireGuard UDP recv failed: {}", err);
                    tokio::select! {
                        _ = shutdown_token.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                    continue;
                }
            };

            let actions = inner.decapsulate_network_packet(&recv_buf[..size]).await;
            for action in actions {
                match action {
                    TunnAction::Network(packet) => {
                        if let Err(err) = inner.udp.send_to(&packet, inner.endpoint).await {
                            debug!("WireGuard response packet send failed: {}", err);
                        }
                    }
                    TunnAction::Tunnel(packet) => inner.dispatch_ip_packet(packet),
                }
            }
        }
    }

    async fn timer_loop(inner: Arc<Self>) {
        let shutdown_token = inner.shutdown_token.clone();
        let mut send_buf = vec![0u8; MAX_PACKET];
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
            let action = {
                let mut peer = inner.peer.lock().await;
                match peer.update_timers(&mut send_buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        Some(Ok(Bytes::copy_from_slice(packet)))
                    }
                    TunnResult::Err(WireGuardError::ConnectionExpired) => None,
                    TunnResult::Err(err) => {
                        debug!("WireGuard timer update failed: {:?}", err);
                        Some(Err(()))
                    }
                    TunnResult::Done => Some(Err(())),
                    other => {
                        trace!("WireGuard timer produced unexpected state: {:?}", other);
                        Some(Err(()))
                    }
                }
            };

            match action {
                Some(Ok(packet)) => {
                    if let Err(err) = inner.udp.send_to(&packet, inner.endpoint).await {
                        debug!("WireGuard timer packet send failed: {}", err);
                    }
                }
                None => inner.initiate_handshake().await,
                Some(Err(())) => {}
            }
        }
    }

    async fn initiate_handshake(&self) {
        let mut send_buf = vec![0u8; MAX_PACKET];
        let packet = {
            let mut peer = self.peer.lock().await;
            match peer.format_handshake_initiation(&mut send_buf, false) {
                TunnResult::WriteToNetwork(packet) => Some(Bytes::copy_from_slice(packet)),
                TunnResult::Done => None,
                TunnResult::Err(err) => {
                    debug!("WireGuard handshake initiation failed: {:?}", err);
                    None
                }
                other => {
                    trace!("WireGuard handshake produced unexpected state: {:?}", other);
                    None
                }
            }
        };

        if let Some(packet) = packet
            && let Err(err) = self.udp.send_to(&packet, self.endpoint).await
        {
            debug!("WireGuard handshake send failed: {}", err);
        }
    }

    async fn send_ip_packet_with_buffer(
        &self,
        packet: &[u8],
        send_buf: &mut Vec<u8>,
    ) -> io::Result<()> {
        let required_len = MAX_PACKET.max(packet.len() + 64);
        if send_buf.len() < required_len {
            send_buf.resize(required_len, 0);
        }
        let network_packet = {
            let mut peer = self.peer.lock().await;
            match peer.encapsulate(packet, send_buf.as_mut_slice()) {
                TunnResult::WriteToNetwork(packet) => Some(Bytes::copy_from_slice(packet)),
                TunnResult::Done => None,
                TunnResult::Err(err) => {
                    return Err(io::Error::other(format!(
                        "WireGuard encapsulate failed: {err:?}"
                    )));
                }
                other => {
                    return Err(io::Error::other(format!(
                        "unexpected WireGuard encapsulate state: {other:?}"
                    )));
                }
            }
        };

        if let Some(network_packet) = network_packet {
            self.udp.send_to(&network_packet, self.endpoint).await?;
        }
        Ok(())
    }

    async fn decapsulate_network_packet(&self, packet: &[u8]) -> Vec<TunnAction> {
        let mut actions = Vec::new();
        let mut first = true;
        let mut send_buf = vec![0u8; MAX_PACKET];

        loop {
            let input = if first { packet } else { &[] };
            first = false;
            let result = {
                let mut peer = self.peer.lock().await;
                peer.decapsulate(None, input, &mut send_buf)
            };

            match result {
                TunnResult::WriteToNetwork(packet) => {
                    actions.push(TunnAction::Network(Bytes::copy_from_slice(packet)));
                    continue;
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    actions.push(TunnAction::Tunnel(Bytes::copy_from_slice(packet)));
                }
                TunnResult::Done => {}
                TunnResult::Err(err) => {
                    trace!("WireGuard decapsulate failed: {:?}", err);
                }
            }
            break;
        }

        actions
    }

    async fn resolve_target(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: &ResolvedLocation,
    ) -> io::Result<Vec<SocketAddr>> {
        if let Some(addr) = target.resolved_addr() {
            return self.filter_usable_addresses(vec![addr]);
        }

        if let Some(addr) = target.location().to_socket_addr_nonblocking() {
            return self.filter_usable_addresses(vec![addr]);
        }

        if self.config.remote_dns_resolve {
            let Address::Hostname(hostname) = target.address() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "WireGuard target address is neither resolved nor a hostname",
                ));
            };
            return self.resolve_remote_hostname(hostname, target.location().port()).await;
        }

        let addrs = resolve_addresses(resolver, target.location()).await?;
        self.filter_usable_addresses(addrs)
    }

    fn filter_usable_addresses(&self, mut addrs: Vec<SocketAddr>) -> io::Result<Vec<SocketAddr>> {
        addrs.retain(|addr| self.can_use_remote_ip(addr.ip()));
        addrs.sort_by_key(|addr| {
            if addr.is_ipv6() == self.config.ip_version.prefer_ipv6() {
                0
            } else {
                1
            }
        });

        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no resolved address is usable with this WireGuard ip-version/local IP config",
            ));
        }

        Ok(addrs)
    }

    fn can_use_remote_ip(&self, ip: IpAddr) -> bool {
        let allowed_by_family = match ip {
            IpAddr::V4(_) => self.config.ip_version.allow_ipv4(),
            IpAddr::V6(_) => self.config.ip_version.allow_ipv6() && self.config.ipv6.is_some(),
        };
        allowed_by_family && self.allowed_ips.iter().any(|allowed_ip| allowed_ip.contains(ip))
    }

    fn local_ip_for_remote(&self, remote_ip: IpAddr) -> io::Result<IpAddr> {
        match remote_ip {
            IpAddr::V4(_) if self.config.ip_version.allow_ipv4() => Ok(IpAddr::V4(self.config.ip)),
            IpAddr::V6(_) if self.config.ip_version.allow_ipv6() => self
                .config
                .ipv6
                .map(IpAddr::V6)
                .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "WireGuard ipv6 is not configured")),
            IpAddr::V4(_) => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "WireGuard ip-version forbids IPv4 targets",
            )),
            IpAddr::V6(_) => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "WireGuard ip-version forbids IPv6 targets",
            )),
        }
    }

    async fn connect_tcp(self: &Arc<Self>, target: SocketAddr) -> io::Result<WireGuardTcpStream> {
        let source_ip = self.local_ip_for_remote(target.ip())?;
        let (source, route, inbound_rx) = self.register_tcp_route(source_ip)?;
        let (client_side, worker_side) = tokio::io::duplex(TCP_SEND_BUFFER_SIZE);
        let (established_tx, established_rx) = oneshot::channel();

        tokio::spawn(run_tcp_connection(
            self.clone(),
            route,
            source,
            target,
            inbound_rx,
            worker_side,
            established_tx,
        ));

        match established_rx.await {
            Ok(Ok(())) => Ok(WireGuardTcpStream { inner: client_side }),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "WireGuard TCP worker exited before connect completed",
            )),
        }
    }

    fn connect_udp(self: &Arc<Self>, target: SocketAddr) -> io::Result<WireGuardUdpStream> {
        let source_ip = self.local_ip_for_remote(target.ip())?;
        let (source, route, inbound_rx) = self.register_udp_route(source_ip)?;
        Ok(WireGuardUdpStream {
            inner: self.clone(),
            route,
            source,
            target,
            inbound_rx,
            closed: false,
        })
    }

    fn register_tcp_route(
        &self,
        source_ip: IpAddr,
    ) -> io::Result<(SocketAddr, RouteKey, mpsc::Receiver<Packet>)> {
        self.register_route(source_ip, &self.tcp_routes)
    }

    fn register_udp_route(
        &self,
        source_ip: IpAddr,
    ) -> io::Result<(SocketAddr, RouteKey, mpsc::Receiver<Packet>)> {
        self.register_route(source_ip, &self.udp_routes)
    }

    fn register_route(
        &self,
        source_ip: IpAddr,
        routes: &Mutex<HashMap<RouteKey, mpsc::Sender<Packet>>>,
    ) -> io::Result<(SocketAddr, RouteKey, mpsc::Receiver<Packet>)> {
        for _ in 0..EPHEMERAL_RANGE {
            let port = EPHEMERAL_START
                + (self.next_port.fetch_add(1, Ordering::Relaxed) % EPHEMERAL_RANGE);
            let route = RouteKey {
                ip: source_ip,
                port,
            };
            let (tx, rx) = mpsc::channel(ROUTE_QUEUE_CAPACITY);

            let mut routes = routes.lock();
            if let std::collections::hash_map::Entry::Vacant(entry) = routes.entry(route) {
                entry.insert(tx);
                return Ok((SocketAddr::new(source_ip, port), route, rx));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no WireGuard ephemeral ports available",
        ))
    }

    fn remove_tcp_route(&self, route: RouteKey) {
        self.tcp_routes.lock().remove(&route);
    }

    fn remove_udp_route(&self, route: RouteKey) {
        self.udp_routes.lock().remove(&route);
    }

    fn dispatch_ip_packet(&self, packet: Packet) {
        match parse_transport_route(&packet) {
            Some((IpProtocol::Tcp, route)) => {
                if let Some(tx) = self.tcp_routes.lock().get(&route).cloned() {
                    if tx.try_send(packet).is_err() {
                        warn!("WireGuard TCP route queue full for {:?}", route);
                    }
                }
            }
            Some((IpProtocol::Udp, route)) => {
                if let Some(tx) = self.udp_routes.lock().get(&route).cloned()
                    && let Some((payload, _, _)) = parse_udp_packet(&packet)
                {
                    if tx.try_send(payload).is_err() {
                        warn!("WireGuard UDP route queue full for {:?}", route);
                    }
                }
            }
            _ => trace!("WireGuard received unhandled IP packet"),
        }
    }

    async fn resolve_remote_hostname(&self, hostname: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let qtypes = dns_query_order(self.config.ip_version);
        let mut resolved = Vec::new();
        let mut last_err = None;

        for qtype in qtypes {
            for dns in &self.config.dns {
                match self.query_dns(*dns, hostname, qtype).await {
                    Ok(addrs) if !addrs.is_empty() => {
                        resolved.extend(addrs.into_iter().map(|addr| SocketAddr::new(addr, port)));
                        break;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        debug!("WireGuard remote DNS query via {} failed: {}", dns, err);
                        last_err = Some(err);
                    }
                }
            }
        }

        self.filter_usable_addresses(resolved).or_else(|err| {
            if let Some(last_err) = last_err {
                Err(last_err)
            } else {
                Err(err)
            }
        })
    }

    async fn query_dns(&self, dns_ip: IpAddr, hostname: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
        let cache_key = DnsCacheKey {
            hostname: hostname.trim_end_matches('.').to_ascii_lowercase(),
            qtype,
        };
        if let Some(addrs) = self.get_dns_cache(&cache_key) {
            return Ok(addrs);
        }

        let source_ip = self.local_ip_for_remote(dns_ip)?;
        let dns_addr = SocketAddr::new(dns_ip, 53);
        let (source, route, mut inbound_rx) = self.register_udp_route(source_ip)?;
        let query_id = rand::random::<u16>();
        let query = build_dns_query(query_id, hostname, qtype)?;
        let packet = build_udp_packet(&query, source, dns_addr)?;

        let result = async {
            self.outbound_tx
                .send(packet)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard outbound channel closed"))?;
            loop {
                let response = inbound_rx.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "WireGuard DNS route closed")
                })?;
                if let Some(response) = parse_dns_response(query_id, qtype, &response) {
                    return Ok(response);
                }
            }
        };

        let result = tokio::time::timeout(DNS_TIMEOUT, result)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WireGuard remote DNS query timed out"))
            .and_then(|result| result);
        self.remove_udp_route(route);
        result.map(|response| {
            self.insert_dns_cache(cache_key, &response);
            response.addrs
        })
    }

    fn get_dns_cache(&self, key: &DnsCacheKey) -> Option<Vec<IpAddr>> {
        let now = StdInstant::now();
        let mut cache = self.dns_cache.lock();
        if let Some(entry) = cache.get(key) {
            if entry.expires_at > now {
                return Some(entry.addrs.clone());
            }
        }
        cache.remove(key);
        None
    }

    fn insert_dns_cache(&self, key: DnsCacheKey, response: &DnsResponse) {
        if response.addrs.is_empty() || response.ttl.is_zero() {
            return;
        }
        let ttl = response.ttl.min(DNS_CACHE_MAX_TTL).max(DNS_CACHE_MIN_TTL);
        let mut cache = self.dns_cache.lock();
        if cache.len() >= DNS_CACHE_CAPACITY {
            let now = StdInstant::now();
            cache.retain(|_, entry| entry.expires_at > now);
            if cache.len() >= DNS_CACHE_CAPACITY
                && let Some(key) = cache.keys().next().cloned()
            {
                cache.remove(&key);
            }
        }
        cache.insert(
            key,
            DnsCacheEntry {
                addrs: response.addrs.clone(),
                expires_at: StdInstant::now() + ttl,
            },
        );
    }
}

pub struct WireGuardTcpStream {
    inner: DuplexStream,
}

impl AsyncRead for WireGuardTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for WireGuardTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for WireGuardTcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for WireGuardTcpStream {}

pub struct WireGuardUdpStream {
    inner: Arc<WireGuardInner>,
    route: RouteKey,
    source: SocketAddr,
    target: SocketAddr,
    inbound_rx: mpsc::Receiver<Packet>,
    closed: bool,
}

impl Drop for WireGuardUdpStream {
    fn drop(&mut self) {
        if !self.closed {
            self.inner.remove_udp_route(self.route);
            self.closed = true;
        }
    }
}

impl AsyncReadMessage for WireGuardUdpStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inbound_rx).poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let len = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..len]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "WireGuard UDP route closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteMessage for WireGuardUdpStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        match build_udp_packet(buf, self.source, self.target) {
            Ok(packet) => {
                if let Err(err) = self.inner.outbound_tx.try_send(packet) {
                    match err {
                        mpsc::error::TrySendError::Full(_) => {
                            warn!("WireGuard outbound queue full while sending UDP packet");
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "WireGuard outbound queue full",
                            )));
                        }
                        mpsc::error::TrySendError::Closed(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "WireGuard outbound channel closed",
                            )));
                        }
                    }
                }
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl AsyncFlushMessage for WireGuardUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for WireGuardUdpStream {
    fn poll_shutdown_message(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.inner.remove_udp_route(self.route);
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for WireGuardUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for WireGuardUdpStream {}

async fn run_tcp_connection(
    inner: Arc<WireGuardInner>,
    route: RouteKey,
    source: SocketAddr,
    target: SocketAddr,
    mut inbound_rx: mpsc::Receiver<Packet>,
    mut stream: DuplexStream,
    established_tx: oneshot::Sender<io::Result<()>>,
) {
    let result = run_tcp_connection_inner(
        &inner,
        source,
        target,
        &mut inbound_rx,
        &mut stream,
        established_tx,
    )
    .await;

    if let Err(err) = result {
        debug!("WireGuard TCP worker {} -> {} exited: {}", source, target, err);
    }
    inner.remove_tcp_route(route);
    let _ = stream.shutdown().await;
}

async fn run_tcp_connection_inner(
    inner: &Arc<WireGuardInner>,
    source: SocketAddr,
    target: SocketAddr,
    inbound_rx: &mut mpsc::Receiver<Packet>,
    stream: &mut DuplexStream,
    established_tx: oneshot::Sender<io::Result<()>>,
) -> io::Result<()> {
    let mut established_tx = Some(established_tx);
    let mut device = ChannelDevice::new(inner.config.mtu as usize, inner.outbound_tx.clone());
    let mut iface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        SmolInstant::now(),
    );
    let local_ip = IpAddress::from(source.ip());
    iface.update_ip_addrs(|ip_addrs| {
        let _ = ip_addrs.push(IpCidr::new(local_ip, ip_prefix_len(local_ip)));
    });

    let mut sockets = SocketSet::new(vec![]);
    let socket_handle = new_tcp_socket(&mut sockets);
    {
        let socket = sockets.get_mut::<tcp::Socket>(socket_handle);
        socket
            .connect(
                iface.context(),
                (IpAddress::from(target.ip()), target.port()),
                (IpAddress::from(source.ip()), source.port()),
            )
            .map_err(|err| io::Error::other(format!("smoltcp TCP connect failed: {err}")))?;
    }

    let mut pending_to_remote: VecDeque<Bytes> = VecDeque::new();
    let mut app_read_buf = vec![0u8; TCP_READ_CHUNK];
    let mut app_eof = false;

    loop {
        while let Ok(packet) = inbound_rx.try_recv() {
            device.push_packet(packet);
        }

        let timestamp = SmolInstant::now();
        let _ = iface.poll(timestamp, &mut device, &mut sockets);

        let state = sockets.get::<tcp::Socket>(socket_handle).state();
        if state == tcp::State::Established {
            notify_established(&mut established_tx, Ok(()));
        } else if matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
            notify_established(
                &mut established_tx,
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "WireGuard TCP connection closed before establishment",
                )),
            );
            return Ok(());
        }

        {
            let socket = sockets.get_mut::<tcp::Socket>(socket_handle);
            while socket.can_send() {
                let Some(front) = pending_to_remote.pop_front() else {
                    break;
                };
                let sent = socket
                    .send_slice(&front)
                    .map_err(|err| io::Error::other(format!("smoltcp TCP send failed: {err}")))?;
                if sent < front.len() {
                    pending_to_remote.push_front(front.slice(sent..));
                    break;
                }
            }

            if app_eof && pending_to_remote.is_empty() && socket.may_send() {
                socket.close();
            }
        }

        let mut chunks = Vec::new();
        {
            let socket = sockets.get_mut::<tcp::Socket>(socket_handle);
            while socket.can_recv() {
                let chunk = socket
                    .recv(|buffer| {
                        let len = buffer.len().min(TCP_READ_CHUNK);
                        (len, Bytes::copy_from_slice(&buffer[..len]))
                    })
                    .map_err(|err| io::Error::other(format!("smoltcp TCP recv failed: {err}")))?;
                if chunk.is_empty() {
                    break;
                }
                chunks.push(chunk);
            }
        }

        for chunk in chunks {
            stream.write_all(&chunk).await?;
        }

        let socket = sockets.get::<tcp::Socket>(socket_handle);
        if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
            || (app_eof && pending_to_remote.is_empty() && !socket.may_recv())
        {
            notify_established(&mut established_tx, Ok(()));
            return Ok(());
        }

        let sleep_duration = iface
            .poll_delay(SmolInstant::now(), &sockets)
            .map(|delay| Duration::from_millis(delay.total_millis().min(50) as u64))
            .unwrap_or_else(|| Duration::from_millis(50));

        tokio::select! {
            packet = inbound_rx.recv() => {
                match packet {
                    Some(packet) => device.push_packet(packet),
                    None => return Ok(()),
                }
            }
            read_result = stream.read(&mut app_read_buf), if !app_eof && pending_to_remote.len() < 128 => {
                let n = read_result?;
                if n == 0 {
                    app_eof = true;
                } else {
                    pending_to_remote.push_back(Bytes::copy_from_slice(&app_read_buf[..n]));
                }
            }
            _ = tokio::time::sleep(sleep_duration) => {}
        }
    }
}

fn notify_established(
    established_tx: &mut Option<oneshot::Sender<io::Result<()>>>,
    result: io::Result<()>,
) {
    if let Some(tx) = established_tx.take() {
        let _ = tx.send(result);
    }
}

fn new_tcp_socket(sockets: &mut SocketSet<'static>) -> SocketHandle {
    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_RECV_BUFFER_SIZE]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_SEND_BUFFER_SIZE]);
    let mut socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
    socket.set_nagle_enabled(false);
    sockets.add(socket)
}

struct ChannelDevice {
    inbound: VecDeque<Packet>,
    outbound_tx: mpsc::Sender<Packet>,
    mtu: usize,
}

impl ChannelDevice {
    fn new(mtu: usize, outbound_tx: mpsc::Sender<Packet>) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound_tx,
            mtu,
        }
    }

    fn push_packet(&mut self, packet: Packet) {
        self.inbound.push_back(packet);
    }
}

impl Device for ChannelDevice {
    type RxToken<'a>
        = ChannelRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = ChannelTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let outbound_permit = self.outbound_tx.clone().try_reserve_owned().ok()?;
        self.inbound.pop_front().map(|packet| {
            (
                ChannelRxToken { packet },
                ChannelTxToken { outbound_permit },
            )
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        self.outbound_tx
            .clone()
            .try_reserve_owned()
            .ok()
            .map(|outbound_permit| ChannelTxToken { outbound_permit })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv6 = smoltcp::phy::Checksum::Tx;
        caps
    }
}

struct ChannelRxToken {
    packet: Packet,
}

impl RxToken for ChannelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

struct ChannelTxToken {
    outbound_permit: mpsc::OwnedPermit<Packet>,
}

impl TxToken for ChannelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.outbound_permit.send(Bytes::from(packet));
        result
    }
}

async fn resolve_endpoint(
    config: &WireGuardClientConfig,
    resolver: &Arc<dyn Resolver>,
) -> io::Result<SocketAddr> {
    let address = Address::from(&config.server)?;
    let location = NetLocation::new(address, config.port);
    let mut addrs = resolve_addresses(resolver, &location).await?;
    sort_by_ip_version(&mut addrs, config.ip_version);
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "WireGuard server did not resolve"))
}

fn sort_by_ip_version(addrs: &mut [SocketAddr], ip_version: WireGuardIpVersion) {
    addrs.sort_by_key(|addr| {
        if addr.is_ipv6() == ip_version.prefer_ipv6() {
            0
        } else {
            1
        }
    });
}

fn decode_wireguard_key(field: &str, value: &str) -> io::Result<[u8; 32]> {
    let bytes = STANDARD.decode(value.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("WireGuard {field} is not valid base64: {err}"),
        )
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("WireGuard {field} must decode to 32 bytes, got {}", bytes.len()),
        )
    })
}

fn parse_allowed_ips(values: &[String]) -> io::Result<Vec<AllowedIp>> {
    values
        .iter()
        .map(|value| {
            let (addr, prefix) = value.split_once('/').ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("WireGuard allowed-ips entry '{value}' must be CIDR notation"),
                )
            })?;
            let addr: IpAddr = addr.parse().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("WireGuard allowed-ips entry '{value}' has invalid address: {err}"),
                )
            })?;
            let prefix: u8 = prefix.parse().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("WireGuard allowed-ips entry '{value}' has invalid prefix: {err}"),
                )
            })?;
            let max_prefix = if matches!(addr, IpAddr::V6(_)) { 128 } else { 32 };
            if prefix > max_prefix {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "WireGuard allowed-ips entry '{value}' has prefix {prefix}, maximum is {max_prefix}"
                    ),
                ));
            }
            let mask = prefix_mask(prefix, max_prefix);
            Ok(AllowedIp {
                network: ip_to_u128(addr) & mask,
                mask,
                is_ipv6: matches!(addr, IpAddr::V6(_)),
            })
        })
        .collect()
}

fn prefix_mask(prefix: u8, bits: u8) -> u128 {
    if prefix == 0 {
        0
    } else if bits == 32 {
        (u32::MAX << (32 - prefix)) as u128
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(addr) => u32::from(addr) as u128,
        IpAddr::V6(addr) => u128::from(addr),
    }
}

fn parse_transport_route(packet: &[u8]) -> Option<(IpProtocol, RouteKey)> {
    match packet.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            let octets = ip.dst_addr().octets();
            let route_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            ));
            match ip.next_header() {
                IpProtocol::Tcp => {
                    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
                    Some((
                        IpProtocol::Tcp,
                        RouteKey {
                            ip: route_ip,
                            port: tcp.dst_port(),
                        },
                    ))
                }
                IpProtocol::Udp => {
                    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
                    Some((
                        IpProtocol::Udp,
                        RouteKey {
                            ip: route_ip,
                            port: udp.dst_port(),
                        },
                    ))
                }
                _ => None,
            }
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            let route_ip = IpAddr::V6(std::net::Ipv6Addr::from(ip.dst_addr().octets()));
            match ip.next_header() {
                IpProtocol::Tcp => {
                    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
                    Some((
                        IpProtocol::Tcp,
                        RouteKey {
                            ip: route_ip,
                            port: tcp.dst_port(),
                        },
                    ))
                }
                IpProtocol::Udp => {
                    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
                    Some((
                        IpProtocol::Udp,
                        RouteKey {
                            ip: route_ip,
                            port: udp.dst_port(),
                        },
                    ))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_udp_packet(packet: &[u8]) -> Option<(Packet, SocketAddr, SocketAddr)> {
    match packet.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some((
                Bytes::copy_from_slice(udp.payload()),
                SocketAddr::new(smoltcp_ipv4_to_std(ip.src_addr()), udp.src_port()),
                SocketAddr::new(smoltcp_ipv4_to_std(ip.dst_addr()), udp.dst_port()),
            ))
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some((
                Bytes::copy_from_slice(udp.payload()),
                SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(ip.src_addr().octets())),
                    udp.src_port(),
                ),
                SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(ip.dst_addr().octets())),
                    udp.dst_port(),
                ),
            ))
        }
        _ => None,
    }
}

fn smoltcp_ipv4_to_std(addr: smoltcp::wire::Ipv4Address) -> IpAddr {
    let octets = addr.octets();
    IpAddr::V4(std::net::Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    ))
}

fn build_udp_packet(payload: &[u8], src_addr: SocketAddr, dst_addr: SocketAddr) -> io::Result<Packet> {
    let builder = match (src_addr, dst_addr) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 20)
                .udp(src.port(), dst.port())
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 20)
                .udp(src.port(), dst.port())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WireGuard UDP source and destination IP versions differ",
            ));
        }
    };

    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut packet, payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(Bytes::from(packet))
}

fn ip_prefix_len(addr: IpAddress) -> u8 {
    match addr {
        IpAddress::Ipv4(_) => 32,
        IpAddress::Ipv6(_) => 128,
    }
}

fn dns_query_order(ip_version: WireGuardIpVersion) -> Vec<u16> {
    match ip_version {
        WireGuardIpVersion::Ipv4Only => vec![1],
        WireGuardIpVersion::Ipv6Only => vec![28],
        WireGuardIpVersion::Ipv4Prefer => vec![1, 28],
        WireGuardIpVersion::Ipv6Prefer => vec![28, 1],
    }
}

fn build_dns_query(id: u16, hostname: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    for label in hostname.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DNS label in hostname '{hostname}'"),
            ));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

struct DnsResponse {
    addrs: Vec<IpAddr>,
    ttl: Duration,
}

fn parse_dns_response(id: u16, qtype: u16, packet: &[u8]) -> Option<DnsResponse> {
    if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != id {
        return None;
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qdcount {
        pos = skip_dns_name(packet, pos)?;
        pos = pos.checked_add(4)?;
        if pos > packet.len() {
            return None;
        }
    }

    let mut addrs = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for _ in 0..ancount {
        pos = skip_dns_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return None;
        }
        let answer_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let answer_class = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > packet.len() {
            return None;
        }

        if answer_class == 1 && answer_type == qtype {
            match (answer_type, rdlen) {
                (1, 4) => {
                    min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
                    addrs.push(IpAddr::V4(
                        [packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3]].into(),
                    ));
                }
                (28, 16) => {
                    min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[pos..pos + 16]);
                    addrs.push(IpAddr::V6(octets.into()));
                }
                _ => {}
            }
        }
        pos += rdlen;
    }

    Some(DnsResponse {
        addrs,
        ttl: Duration::from_secs(min_ttl.unwrap_or(0) as u64),
    })
}

fn skip_dns_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)?;
        if len & 0xc0 == 0xc0 {
            packet.get(pos + 1)?;
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos = pos.checked_add(1 + len as usize)?;
        if pos > packet.len() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_allowed_ips_ipv4_cidr() {
        let allowed = parse_allowed_ips(&["10.0.0.0/8".to_string()]).unwrap();

        assert!(allowed[0].contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!allowed[0].contains(IpAddr::V4(Ipv4Addr::new(11, 1, 2, 3))));
        assert!(!allowed[0].contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_allowed_ips_rejects_invalid_prefix() {
        let err = parse_allowed_ips(&["192.0.2.1/33".to_string()])
            .unwrap_err()
            .to_string();

        assert!(err.contains("prefix 33"), "unexpected error: {err}");
    }

    #[test]
    fn test_sort_by_ip_version_preference() {
        let mut addrs = vec![
            "192.0.2.1:443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
        ];

        sort_by_ip_version(&mut addrs, WireGuardIpVersion::Ipv6Prefer);
        assert!(addrs[0].is_ipv6());

        sort_by_ip_version(&mut addrs, WireGuardIpVersion::Ipv4Prefer);
        assert!(addrs[0].is_ipv4());
    }

    #[test]
    fn test_build_and_parse_ipv4_udp_packet() {
        let src = "10.8.0.2:49152".parse::<SocketAddr>().unwrap();
        let dst = "1.1.1.1:53".parse::<SocketAddr>().unwrap();
        let payload = b"hello";

        let packet = build_udp_packet(payload, src, dst).unwrap();
        let (parsed_payload, parsed_src, parsed_dst) = parse_udp_packet(&packet).unwrap();

        assert_eq!(parsed_payload.as_ref(), payload);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn test_build_and_parse_ipv6_udp_packet() {
        let src = "[2001:db8::2]:49152".parse::<SocketAddr>().unwrap();
        let dst = "[2001:4860:4860::8888]:53"
            .parse::<SocketAddr>()
            .unwrap();
        let payload = b"hello";

        let packet = build_udp_packet(payload, src, dst).unwrap();
        let (parsed_payload, parsed_src, parsed_dst) = parse_udp_packet(&packet).unwrap();

        assert_eq!(parsed_payload.as_ref(), payload);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn test_build_udp_packet_rejects_mixed_ip_versions() {
        let src = "10.8.0.2:49152".parse::<SocketAddr>().unwrap();
        let dst = "[2001:4860:4860::8888]:53"
            .parse::<SocketAddr>()
            .unwrap();

        assert!(build_udp_packet(b"hello", src, dst).is_err());
    }

    #[test]
    fn test_parse_dns_response_a_record() {
        let response = dns_response_with_answer(0x1234, 1, 300, &[93, 184, 216, 34]);
        let parsed = parse_dns_response(0x1234, 1, &response).unwrap();

        assert_eq!(parsed.addrs, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(parsed.ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_parse_dns_response_aaaa_record() {
        let addr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0, 0, 0, 0x25c8);
        let response = dns_response_with_answer(0x1234, 28, 120, &addr.octets());
        let parsed = parse_dns_response(0x1234, 28, &response).unwrap();

        assert_eq!(parsed.addrs, vec![IpAddr::V6(addr)]);
        assert_eq!(parsed.ttl, Duration::from_secs(120));
    }

    #[test]
    fn test_parse_dns_response_ignores_wrong_id() {
        let response = dns_response_with_answer(0x1234, 1, 300, &[93, 184, 216, 34]);

        assert!(parse_dns_response(0x4321, 1, &response).is_none());
    }

    fn dns_response_with_answer(id: u16, qtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x8180u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(rdata);
        packet
    }
}

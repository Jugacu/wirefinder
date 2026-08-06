//! The WireGuard boundary, in two layers.
//!
//! [`Wireguard`] is the HIGH-level intent the daemon speaks ("switch to this
//! server", "disconnect"). The daemon is tested against an in-memory fake of it
//! (see `daemon::tests`).
//!
//! [`WgOps`] is the LOW-level seam underneath: exactly the `defguard` operations
//! wirefinder performs, one method each. [`KernelWireguard`] implements the
//! high-level trait by orchestrating a `WgOps`, so the *ordering* of kernel
//! operations during a switch — the thing that makes switching leak-safe — is unit
//! tested against a recording fake, with no root, kernel, or network. The only
//! genuinely untestable code is [`KernelWgOps`], a set of one-line delegations to
//! `defguard`.
//!
//! ## Leak-safety (why the switch is shaped the way it is)
//!
//! For a full-tunnel (`AllowedIPs = 0.0.0.0/0`), defguard installs a kill switch as
//! a pair of persistent `ip rule`s (a main-table `suppress_prefixlen 0` rule + an
//! fwmark rule). Those rules are created by `configure_peer_routing` and torn down
//! ONLY by `remove_interface`. `configure_interface` does not touch them. So a
//! switch that reconfigures the LIVE interface in place — never calling
//! `remove_interface`, and preserving the device fwmark — keeps the kill switch up
//! the whole time: during the brief reconfigure window, traffic is DROPPED
//! (fail-closed), not leaked. `remove_interface` is therefore confined to
//! `disconnect`, the one moment the user actually wants the tunnel gone.
//!
//! ## Split routes (why `configure_peer_routing` isn't enough)
//!
//! When defguard sees a default route in the AllowedIPs it installs the kill switch
//! and adds NO kernel route for the peer's *other* prefixes. That leaves any prefix
//! the host already has a more specific route for unreachable through the tunnel —
//! see [`split_route_prefixes`]. `switch` therefore follows routing with
//! [`WgOps::sync_split_routes`], which owns those routes the way wg-quick does.

use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

use defguard_wireguard_rs::host::Host;
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::{
    InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi, peer::Peer,
};

use crate::config::ServerConfig;

/// The single tunnel interface wirefinder manages. Fixed so onboarding never has
/// to ask the user to name an interface.
pub const INTERFACE_NAME: &str = "wirefinder";

/// A snapshot of live interface state, expressed in protocol-neutral terms so the
/// daemon never has to import WireGuard types to read status.
pub struct LiveInterface {
    pub name: String,
    /// OUR public key currently on the interface, derived from the live private key.
    /// This is what identifies *which* configured tunnel is active — uniquely, even
    /// when two tunnels share a peer (server) public key. `None` if the kernel
    /// didn't return a private key.
    pub public_key: Option<String>,
    pub listen_port: u16,
    pub peers: Vec<LivePeer>,
}

pub struct LivePeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// The high-level operations the daemon performs against WireGuard. Each method is
/// one complete intent, so the daemon owns *policy* (when to do what) while the
/// implementation owns *mechanism* (the kernel call sequence).
pub trait Wireguard {
    /// Tear the interface down entirely. This also clears any DNS the tunnel set
    /// and removes the kill-switch routing rules — restoring normal connectivity.
    fn disconnect(&self) -> Result<(), String>;

    /// Bring up `server`'s tunnel (its key, addresses, port) and make its peer the
    /// sole active one, applying routes and DNS. Reconfigures the live interface in
    /// place when already up (leak-safe — see the module docs). Returns the endpoint
    /// address the peer was configured with, so the caller can refresh its cached
    /// copy with every successful connection.
    fn switch(&self, server: &ServerConfig) -> Result<SocketAddr, String>;

    /// Read live interface state, or `Err` if the interface is down/unreadable.
    fn status(&self) -> Result<LiveInterface, String>;
}

/// The exact `defguard` operations wirefinder uses, behind a trait so the call
/// sequence and the data threaded between calls (notably the fwmark) can be
/// asserted in tests without root. All take `&self`: the real implementation
/// constructs a fresh `WGApi` per call.
pub trait WgOps {
    fn create_interface(&self) -> Result<(), String>;
    fn remove_interface(&self) -> Result<(), String>;
    fn configure_interface(&self, cfg: &InterfaceConfiguration) -> Result<(), String>;
    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), String>;
    /// Make `prefixes` — and only `prefixes` — the interface's explicit routes,
    /// replacing the ones installed for the previously active server. Fills the gap
    /// `configure_peer_routing` leaves (see [`split_route_prefixes`]).
    fn sync_split_routes(&self, prefixes: &[IpAddrMask]) -> Result<(), String>;
    fn configure_dns(&self, dns: &[IpAddr], search_domains: &[&str]) -> Result<(), String>;
    /// Restore the system resolver by removing the tunnel's resolvconf entry.
    /// defguard's `configure_dns(&[])` is a no-op and its `clear_dns` is private,
    /// so this is implemented directly (see [`reset_resolvconf`]).
    fn reset_dns(&self) -> Result<(), String>;
    fn read_interface_data(&self) -> Result<Host, String>;
}

// ── Pure validation / conversion (no kernel access — unit-tested directly) ──────

/// Validate everything about a tunnel we can check without the kernel: our private
/// key and the peer's public key parse, the endpoint resolves, and the addresses,
/// allowed-IPs, and DNS are well-formed. Run when a client adds a server so bad
/// input fails at configuration time, not at connect time. Returns the resolved
/// endpoint address so the caller can cache it for DNS-free switching later.
pub fn validate_server(server: &ServerConfig) -> Result<SocketAddr, String> {
    Key::from_str(server.private_key.trim())
        .map_err(|e| format!("server '{}': bad private_key: {e}", server.name))?;
    let peer = build_peer(server)?;
    parse_dns(server)?;
    parse_addresses(server)?;
    peer.endpoint.ok_or_else(|| {
        format!(
            "server '{}': endpoint resolved to no addresses",
            server.name
        )
    })
}

/// How long a hostname lookup may block. getaddrinfo has no timeout of its own and
/// can stall for a long time when every resolver query is dropped — exactly the
/// state a never-handshaked full tunnel's kill switch leaves the system in. The
/// daemon is single-threaded, so an unbounded lookup would wedge every client.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve `host:port` to its first socket address. An IP-literal endpoint parses
/// directly (no resolver involved); a hostname gets one getaddrinfo on a throwaway
/// thread, abandoned at [`RESOLVE_TIMEOUT`].
fn resolve_endpoint(server: &ServerConfig) -> Result<SocketAddr, String> {
    let endpoint = server.endpoint.trim().to_string();
    if let Ok(addr) = SocketAddr::from_str(&endpoint) {
        return Ok(addr);
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(
            endpoint
                .to_socket_addrs()
                .map(|mut addrs| addrs.next())
                .map_err(|e| e.to_string()),
        );
    });
    let name = &server.name;
    match rx.recv_timeout(RESOLVE_TIMEOUT) {
        Ok(Ok(Some(addr))) => Ok(addr),
        Ok(Ok(None)) => Err(format!(
            "server '{name}': endpoint resolved to no addresses"
        )),
        Ok(Err(e)) => Err(format!("server '{name}': cannot resolve endpoint: {e}")),
        Err(_) => Err(format!("server '{name}': endpoint resolution timed out")),
    }
}

/// Prefer a fresh resolution, else the address cached at add/edit time. Pure, so
/// the fallback rule is unit-tested without touching a resolver.
fn or_cached(
    fresh: Result<SocketAddr, String>,
    cached: Option<&str>,
) -> Result<SocketAddr, String> {
    fresh.or_else(|e| cached.and_then(|c| SocketAddr::from_str(c).ok()).ok_or(e))
}

/// The endpoint address to configure: fresh when DNS answers, cached when it
/// doesn't. The fallback is what lets a switch AWAY from a black-holed tunnel
/// (kill switch up, resolver dead) still find its new server.
fn endpoint_addr(server: &ServerConfig) -> Result<SocketAddr, String> {
    or_cached(
        resolve_endpoint(server),
        server.resolved_endpoint.as_deref(),
    )
}

/// Parse the tunnel's address(es) into `IpAddrMask`es, requiring at least one.
fn parse_addresses(server: &ServerConfig) -> Result<Vec<IpAddrMask>, String> {
    if server.addresses.is_empty() {
        return Err(format!(
            "server '{}': at least one address required",
            server.name
        ));
    }
    server
        .addresses
        .iter()
        .map(|a| {
            IpAddrMask::from_str(a.trim())
                .map_err(|e| format!("server '{}': bad address '{a}': {e}", server.name))
        })
        .collect()
}

/// Build the full interface configuration for a (re)configure, entirely from the
/// tunnel: its private key, address(es), port, and MTU. `fwmark` is preserved across
/// a live reconfigure (`Some`) or left for routing to assign on a cold bring-up
/// (`None`). `peers` is the post-switch peer set (the one server we're switching to).
fn build_interface_config(
    server: &ServerConfig,
    peers: Vec<Peer>,
    fwmark: Option<u32>,
) -> Result<InterfaceConfiguration, String> {
    // Parsed for its validating side effect — surfaces a bad key early.
    let _ = Key::from_str(server.private_key.trim())
        .map_err(|e| format!("server '{}': bad private_key: {e}", server.name))?;

    Ok(InterfaceConfiguration {
        name: INTERFACE_NAME.to_string(),
        prvkey: server.private_key.trim().to_string(),
        addresses: parse_addresses(server)?,
        port: server.listen_port,
        peers,
        mtu: server.mtu,
        fwmark,
    })
}

fn build_peer(server: &ServerConfig) -> Result<Peer, String> {
    let key = Key::from_str(server.public_key.trim())
        .map_err(|e| format!("server '{}': bad public_key: {e}", server.name))?;
    let mut peer = Peer::new(key);
    peer.endpoint = Some(endpoint_addr(server)?);

    for ip in &server.allowed_ips {
        let mask = IpAddrMask::from_str(ip.trim())
            .map_err(|e| format!("server '{}': bad allowed_ip '{ip}': {e}", server.name))?;
        peer.allowed_ips.push(mask);
    }

    peer.persistent_keepalive_interval = server.keepalive;
    peer.preshared_key = server
        .preshared_key
        .as_ref()
        .map(|s| {
            Key::from_str(s.trim())
                .map_err(|e| format!("server '{}': bad preshared_key: {e}", server.name))
        })
        .transpose()?;

    Ok(peer)
}

/// The peer's AllowedIPs that need a kernel route of their own: every prefix that
/// isn't a default route.
///
/// defguard's Linux `add_peer_routing` adds routes for the individual AllowedIPs ONLY
/// when the peer has no default route; the moment it finds `0.0.0.0/0` it installs the
/// fwmark kill switch instead and drops the rest on the floor, assuming the default
/// route covers them. It doesn't. The kill switch's main-table rule is
/// `suppress_prefixlength 0`, which suppresses only the *default* route — so any more
/// specific route the host already has still wins. A peer offering `192.168.1.0/24`
/// alongside `0.0.0.0/0` is therefore reached over the LOCAL link whenever the host's
/// own LAN is also `192.168.1.0/24` (the common case for a home-router peer): the
/// tunnel is up, the traffic just never enters it.
///
/// wg-quick has no such gap — it routes every non-default AllowedIP out of the
/// interface explicitly. Those routes land in the main table with metric 0, beating a
/// LAN route from DHCP (metric 100/600). This mirrors that.
fn split_route_prefixes(peer: &Peer) -> Vec<IpAddrMask> {
    peer.allowed_ips
        .iter()
        // `is_unspecified` (not `cidr == 0`) is exactly how defguard decides a prefix
        // is a default route, so this keeps precisely what it skipped.
        .filter(|ip| !ip.address.is_unspecified())
        .map(network_prefix)
        .collect()
}

/// `prefix` with its host bits cleared. WireGuard tolerates an AllowedIP written as
/// `192.168.1.5/24` (the kernel masks it for crypto routing) but `ip route` rejects it,
/// and the kernel reports routes back masked — so canonicalising here is what keeps
/// such a config working AND keeps [`stale_routes`] comparing like with like.
fn network_prefix(prefix: &IpAddrMask) -> IpAddrMask {
    let address = match (prefix.address, prefix.mask()) {
        (IpAddr::V4(a), IpAddr::V4(m)) => Ipv4Addr::from(u32::from(a) & u32::from(m)).into(),
        (IpAddr::V6(a), IpAddr::V6(m)) => Ipv6Addr::from(u128::from(a) & u128::from(m)).into(),
        // `mask()` always returns the address's own family; unreachable in practice.
        _ => prefix.address,
    };
    IpAddrMask::new(address, prefix.cidr)
}

/// Parse the configured DNS strings into `IpAddr`s. Collecting an iterator of
/// `Result` into a `Result<Vec<_>, _>` short-circuits on the first bad entry.
fn parse_dns(server: &ServerConfig) -> Result<Vec<IpAddr>, String> {
    server
        .dns
        .iter()
        .map(|s| {
            IpAddr::from_str(s.trim())
                .map_err(|e| format!("server '{}': bad dns '{s}': {e}", server.name))
        })
        .collect()
}

// ── The real, kernel-backed implementation ─────────────────────────────────────

/// Orchestrates a [`WgOps`] backend into the high-level [`Wireguard`] intents.
/// Generic over the backend so tests can assert the kernel call sequence; the
/// default backend is the real [`KernelWgOps`], so `main.rs` is unaffected.
pub struct KernelWireguard<O: WgOps = KernelWgOps> {
    ops: O,
}

impl Default for KernelWireguard<KernelWgOps> {
    fn default() -> Self {
        Self {
            ops: KernelWgOps {
                ifname: INTERFACE_NAME.to_string(),
            },
        }
    }
}

impl<O: WgOps> KernelWireguard<O> {
    #[cfg(test)]
    fn with_ops(ops: O) -> Self {
        Self { ops }
    }

    /// Cold bring-up. Create the interface if it is absent; if it already exists —
    /// a stale interface from a crashed run, or (rarely) a live interface whose
    /// `read_interface_data` transiently errored — reconfigure it IN PLACE rather
    /// than removing it. We deliberately never call `remove_interface` here, so
    /// that operation stays confined to `disconnect` and a switch can never tear
    /// down the kill switch. `configure_interface` overwrites any stale address,
    /// peers, and fwmark, and the `configure_peer_routing` that follows re-asserts
    /// the routing — so reconfiguring in place fully heals a stale interface.
    ///
    /// NOTE: on a genuinely cold connect, until `configure_peer_routing` runs the
    /// kill switch is not yet installed — the disconnected→connected transition has
    /// an inherent exposure window that only an always-on firewall kill switch
    /// (out of scope) would close.
    fn bring_up_with(&self, cfg: &InterfaceConfiguration) -> Result<(), String> {
        // Best-effort: Ok when absent (the common cold case), Err (ignored) when it
        // already exists. A real failure to create an absent interface still
        // surfaces — `configure_interface` below will fail on the missing device.
        let _ = self.ops.create_interface();
        self.ops.configure_interface(cfg)?;
        Ok(())
    }

    /// Apply the new server's DNS, or reset to the system resolver if it has none —
    /// so a switch never inherits the previous server's resolver. Resetting is
    /// best-effort: a failure to clear a (possibly absent) entry must not fail an
    /// otherwise-successful switch.
    fn apply_dns(&self, dns: &[IpAddr]) -> Result<(), String> {
        if dns.is_empty() {
            if let Err(e) = self.ops.reset_dns() {
                eprintln!("wirefinderd: dns reset failed: {e}");
            }
            Ok(())
        } else {
            // Empty search_domains makes these servers exclusive (preferred for all
            // domains) — the right default for a full-tunnel connection.
            self.ops.configure_dns(dns, &[])
        }
    }
}

impl<O: WgOps> Wireguard for KernelWireguard<O> {
    fn disconnect(&self) -> Result<(), String> {
        // The ONE place remove_interface is allowed: it tears down the kill-switch
        // rules and DNS on purpose, because the user asked to disconnect entirely.
        self.ops.remove_interface()
    }

    fn switch(&self, server: &ServerConfig) -> Result<SocketAddr, String> {
        // Parse FIRST — fail before touching the tunnel.
        let peer = build_peer(server)?;
        let split = split_route_prefixes(&peer);
        let dns = parse_dns(server)?;
        parse_addresses(server)?;
        let endpoint = peer.endpoint.ok_or_else(|| {
            format!(
                "server '{}': endpoint resolved to no addresses",
                server.name
            )
        })?;

        match self.ops.read_interface_data() {
            Ok(host) => {
                // Warm: reconfigure the live interface in place. configure_interface
                // flushes the old address, sets this tunnel's address + key, replaces
                // all peers with just this server, and rewrites the PRESERVED fwmark.
                // It never touches the kill-switch ip rules, so the window is
                // fail-closed.
                let cfg = build_interface_config(server, vec![peer.clone()], host.fwmark)?;
                self.ops.configure_interface(&cfg)?;
            }
            Err(_) => {
                // Cold: interface is down; bring it up fresh (routing will assign a
                // fwmark, so pass None).
                let cfg = build_interface_config(server, vec![peer.clone()], None)?;
                self.bring_up_with(&cfg)?;
            }
        }

        // (Re)assert the custom-table default route for the new peer. Must follow
        // configure_interface; the persistent ip rules mean the gap is fail-closed.
        self.ops.configure_peer_routing(&[peer])?;
        // Then this server's non-default prefixes, which the call above skips. Also
        // where the PREVIOUS server's prefixes are retired — a stale one would send
        // its traffic into a tunnel whose crypto routing no longer accepts it.
        self.ops.sync_split_routes(&split)?;
        self.apply_dns(&dns)?;
        Ok(endpoint)
    }

    fn status(&self) -> Result<LiveInterface, String> {
        let host = self.ops.read_interface_data()?;
        Ok(LiveInterface {
            name: INTERFACE_NAME.to_string(),
            // Derive our public key from the live private key (root-only) so the
            // daemon can tell which configured tunnel is the active one.
            public_key: host
                .private_key
                .as_ref()
                .map(|k| k.public_key().to_string()),
            listen_port: host.listen_port,
            peers: host
                .peers
                .values()
                .map(|p| LivePeer {
                    public_key: p.public_key.to_string(),
                    endpoint: p.endpoint.map(|ep| ep.to_string()),
                    allowed_ips: p.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
                    last_handshake: p.last_handshake,
                    rx_bytes: p.rx_bytes,
                    tx_bytes: p.tx_bytes,
                })
                .collect(),
        })
    }
}

/// The real backend: each method constructs a fresh `WGApi<Kernel>` and delegates.
/// This is the one part of the daemon that genuinely needs root and a live kernel,
/// kept to thin one-liners so everything above it is testable.
pub struct KernelWgOps {
    ifname: String,
}

impl KernelWgOps {
    fn api(&self) -> Result<WGApi<Kernel>, String> {
        WGApi::<Kernel>::new(self.ifname.clone()).map_err(|e| e.to_string())
    }
}

impl WgOps for KernelWgOps {
    fn create_interface(&self) -> Result<(), String> {
        let mut api = self.api()?;
        api.create_interface().map_err(|e| e.to_string())
    }
    fn remove_interface(&self) -> Result<(), String> {
        self.api()?.remove_interface().map_err(|e| e.to_string())
    }
    fn configure_interface(&self, cfg: &InterfaceConfiguration) -> Result<(), String> {
        self.api()?
            .configure_interface(cfg)
            .map_err(|e| e.to_string())
    }
    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), String> {
        self.api()?
            .configure_peer_routing(peers)
            .map_err(|e| e.to_string())
    }
    fn sync_split_routes(&self, prefixes: &[IpAddrMask]) -> Result<(), String> {
        sync_split_routes_via_ip(&self.ifname, prefixes)
    }
    fn configure_dns(&self, dns: &[IpAddr], search_domains: &[&str]) -> Result<(), String> {
        self.api()?
            .configure_dns(dns, search_domains)
            .map_err(|e| e.to_string())
    }
    fn reset_dns(&self) -> Result<(), String> {
        reset_resolvconf(&self.ifname)
    }
    fn read_interface_data(&self) -> Result<Host, String> {
        self.api()?.read_interface_data().map_err(|e| e.to_string())
    }
}

/// The `proto` we tag our own routes with. It marks exactly the routes wirefinder
/// installed, so reading them back — and deleting the ones a switch retires — can
/// never touch the kernel's on-link route for the tunnel address (`proto kernel`) or
/// defguard's default route (a different table entirely).
const ROUTE_PROTO: &str = "static";

/// Make `prefixes` the interface's explicit main-table routes, retiring ours from the
/// last switch. Implemented by shelling out to `ip` — defguard's netlink route helpers
/// are crate-private, and `iproute2` is the same tool wg-quick uses for this.
///
/// Installs BEFORE pruning, so a prefix that BOTH the old and new server carry is never
/// momentarily route-less: for that instant it would fall back to the main table and go
/// out the local link, and leaking where we could have not leaked is the thing this
/// module's ordering exists to avoid. An add is a hard error — a prefix the user asked
/// for and silently didn't get is the bug this whole path fixes. A delete is
/// best-effort and logged: it can only fail on a route that is already gone.
fn sync_split_routes_via_ip(ifname: &str, prefixes: &[IpAddrMask]) -> Result<(), String> {
    for prefix in prefixes {
        ip_route("replace", prefix, ifname)?;
    }
    for stale in stale_routes(&installed_split_routes(ifname), prefixes) {
        if let Err(e) = ip_route("del", &stale, ifname) {
            eprintln!("wirefinderd: stale route {stale} not removed: {e}");
        }
    }
    Ok(())
}

/// One `ip route <action> <prefix> dev <ifname>` against the main table, tagged as
/// ours. No metric, so an added route lands at 0 and wins over a DHCP LAN route —
/// which is what makes an overlapping prefix (the peer's LAN numbered like ours)
/// reachable through the tunnel at all.
fn ip_route(action: &str, prefix: &IpAddrMask, ifname: &str) -> Result<(), String> {
    let dest = prefix.to_string();
    let status = Command::new("ip")
        .args([
            "route",
            action,
            &dest,
            "dev",
            ifname,
            "table",
            "main",
            "proto",
            ROUTE_PROTO,
        ])
        .status()
        .map_err(|e| format!("ip route {action} {dest}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip route {action} {dest} dev {ifname} exited with {status}"
        ))
    }
}

/// The routes we own on `ifname`, read back from the kernel. Scoped to `proto static`,
/// so it can only ever return routes wirefinder installed. Best-effort by design: an
/// `ip` too old for `-j` (pre-4.15), or a missing interface, yields nothing parseable
/// and degrades to pruning nothing rather than to deleting something else.
fn installed_split_routes(ifname: &str) -> Vec<IpAddrMask> {
    ["-4", "-6"]
        .iter()
        .flat_map(|family| {
            let out = Command::new("ip")
                .args([
                    family,
                    "-j",
                    "route",
                    "show",
                    "table",
                    "main",
                    "dev",
                    ifname,
                    "proto",
                    ROUTE_PROTO,
                ])
                .output();
            let stdout = match out {
                Ok(o) if o.status.success() => o.stdout,
                _ => Vec::new(),
            };
            parse_ip_route_prefixes(&String::from_utf8_lossy(&stdout))
        })
        .collect()
}

/// Pull the destinations out of `ip -j route show` output. `dst` is a CIDR, a bare
/// address for a host route, or the literal `"default"` — the first two parse (bare
/// addresses as /32 or /128, matching the kernel), and a default route is never ours.
/// Pure, so it is unit-tested against real `ip` output without invoking `ip`.
fn parse_ip_route_prefixes(json: &str) -> Vec<IpAddrMask> {
    #[derive(serde::Deserialize)]
    struct Entry {
        dst: Option<String>,
    }
    serde_json::from_str::<Vec<Entry>>(json)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| IpAddrMask::from_str(e.dst?.trim()).ok())
        .collect()
}

/// Which of the routes we own are no longer wanted. Pure. Both sides are network
/// prefixes ([`network_prefix`]) — the kernel reports them masked, so canonicalising
/// what we install is what makes this comparison meaningful.
fn stale_routes(installed: &[IpAddrMask], wanted: &[IpAddrMask]) -> Vec<IpAddrMask> {
    installed
        .iter()
        .filter(|p| !wanted.contains(p))
        .cloned()
        .collect()
}

/// Remove the tunnel's resolvconf entry, restoring the system resolver. A faithful
/// equivalent of defguard's private `clear_dns`: `resolvconf -d <ifname> -f`, where
/// `<ifname>` matches the name defguard registers under (see [`resolvconf_ifname`]).
fn reset_resolvconf(base_ifname: &str) -> Result<(), String> {
    let ifname = resolvconf_ifname(base_ifname);
    let status = Command::new("resolvconf")
        .args(["-d", &ifname, "-f"])
        .status()
        .map_err(|e| format!("resolvconf: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("resolvconf -d {ifname} exited with {status}"))
    }
}

/// Mirror defguard's `construct_resolvconf_ifname`: openresolv (a real binary, with
/// an interface-order file) registers DNS under `<prefix>.<ifname>`; everything else
/// (e.g. a resolvectl symlink) uses the bare name. We must use the same name we'd be
/// deleting, or the stale entry would linger.
fn resolvconf_ifname(base: &str) -> String {
    const ORDER_PATH: &str = "/etc/resolvconf/interface-order";
    if !Path::new(ORDER_PATH).exists() {
        return base.to_string();
    }
    match which("resolvconf") {
        // A symlink (to resolvectl) → systemd-resolved path → no prefix.
        Some(p)
            if std::fs::symlink_metadata(&p)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(true) =>
        {
            return base.to_string();
        }
        None => return base.to_string(),
        Some(_) => {} // a real binary → read the interface-order file below
    }
    match std::fs::read_to_string(ORDER_PATH) {
        Ok(content) => match interface_order_prefix(&content) {
            Some(prefix) => format!("{prefix}.{base}"),
            None => base.to_string(),
        },
        Err(_) => base.to_string(),
    }
}

/// Extract the highest-priority interface prefix from a resolvconf
/// `interface-order` file: the first line of the form `<prefix>*` where `<prefix>`
/// is non-empty `[A-Za-z0-9-]`. Pure, so it is unit-tested directly. Mirrors the
/// regex `^([A-Za-z0-9-]+)\*$` in defguard's `construct_resolvconf_ifname`.
fn interface_order_prefix(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let prefix = line.trim().strip_suffix('*')?;
        let valid = !prefix.is_empty()
            && prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        valid.then(|| prefix.to_string())
    })
}

/// Locate a command on `PATH` (a tiny `which`), used only by [`resolvconf_ifname`].
fn which(cmd: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(cmd))
        .find(|p| p.exists())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    fn valid_server() -> ServerConfig {
        ServerConfig {
            name: "edge".into(),
            private_key: keys::generate_private_key(),
            // A real, parseable base64 key.
            public_key: "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=".into(),
            // Numeric endpoint so the test never depends on DNS resolution.
            endpoint: "198.51.100.10:51820".into(),
            resolved_endpoint: None,
            addresses: vec!["10.0.0.2/24".into()],
            allowed_ips: vec!["0.0.0.0/0".into()],
            listen_port: 51820,
            mtu: None,
            keepalive: Some(25),
            preshared_key: None,
            dns: vec![],
        }
    }

    // ── pure validation ────────────────────────────────────────────────────────

    #[test]
    fn valid_server_passes_validation() {
        assert!(validate_server(&valid_server()).is_ok());
    }

    #[test]
    fn bad_public_key_is_rejected() {
        let mut s = valid_server();
        s.public_key = "not-base64!!".into();
        assert!(validate_server(&s).unwrap_err().contains("public_key"));
    }

    #[test]
    fn bad_server_address_is_rejected() {
        let mut s = valid_server();
        s.addresses = vec!["not-a-cidr".into()];
        assert!(validate_server(&s).unwrap_err().contains("address"));
    }

    #[test]
    fn empty_addresses_are_rejected() {
        let mut s = valid_server();
        s.addresses = vec![];
        assert!(
            validate_server(&s)
                .unwrap_err()
                .contains("at least one address")
        );
    }

    #[test]
    fn bad_private_key_is_rejected() {
        let mut s = valid_server();
        s.private_key = "garbage".into();
        assert!(validate_server(&s).unwrap_err().contains("private_key"));
    }

    #[test]
    fn bad_allowed_ip_is_rejected() {
        let mut s = valid_server();
        s.allowed_ips = vec!["not-a-cidr".into()];
        assert!(validate_server(&s).unwrap_err().contains("allowed_ip"));
    }

    #[test]
    fn bad_dns_is_rejected() {
        let mut s = valid_server();
        s.dns = vec!["999.999.999.999".into()];
        assert!(validate_server(&s).unwrap_err().contains("dns"));
    }

    #[test]
    fn bad_preshared_key_is_rejected() {
        let mut s = valid_server();
        s.preshared_key = Some("nope".into());
        assert!(validate_server(&s).unwrap_err().contains("preshared_key"));
    }

    // ── endpoint resolution ──────────────────────────────────────────────────────

    #[test]
    fn validate_returns_the_resolved_endpoint_for_caching() {
        let addr = validate_server(&valid_server()).unwrap();
        assert_eq!(addr.to_string(), "198.51.100.10:51820");
    }

    #[test]
    fn an_ip_literal_endpoint_never_touches_the_resolver() {
        // IPv4 and bracketed IPv6 literals parse directly.
        let mut s = valid_server();
        s.endpoint = "[2001:db8::1]:51820".into();
        assert_eq!(
            resolve_endpoint(&s).unwrap().to_string(),
            "[2001:db8::1]:51820"
        );
    }

    #[test]
    fn a_failed_resolution_falls_back_to_the_cached_address() {
        let fresh = Err("temporary failure in name resolution".to_string());
        let addr = or_cached(fresh, Some("198.51.100.10:51820")).unwrap();
        assert_eq!(addr.to_string(), "198.51.100.10:51820");
    }

    #[test]
    fn a_failed_resolution_with_no_usable_cache_keeps_the_original_error() {
        let err = "temporary failure in name resolution".to_string();
        assert_eq!(or_cached(Err(err.clone()), None).unwrap_err(), err);
        // A corrupt cached value must not mask the real error either.
        assert_eq!(
            or_cached(Err(err.clone()), Some("not-an-addr")).unwrap_err(),
            err
        );
    }

    #[test]
    fn a_fresh_resolution_wins_over_the_cache() {
        let fresh = Ok(SocketAddr::from_str("203.0.113.7:51820").unwrap());
        let addr = or_cached(fresh, Some("198.51.100.10:51820")).unwrap();
        assert_eq!(addr.to_string(), "203.0.113.7:51820");
    }

    // ── leak-safe switch ordering (recording fake, no root) ──────────────────────

    /// One recorded kernel operation. We capture only the load-bearing fields.
    #[derive(Debug, PartialEq)]
    enum WgCall {
        CreateInterface,
        RemoveInterface,
        ConfigureInterface {
            prvkey: String,
            addresses: Vec<String>,
            port: u16,
            mtu: Option<u32>,
            peer_keys: Vec<String>,
            fwmark: Option<u32>,
        },
        ConfigurePeerRouting {
            peer_keys: Vec<String>,
        },
        SyncSplitRoutes {
            prefixes: Vec<String>,
        },
        ConfigureDns {
            servers: Vec<String>,
        },
        ResetDns,
        ReadInterfaceData,
    }

    /// Records every op and replays scripted `read_interface_data` results.
    struct RecordingWg {
        calls: RefCell<Vec<WgCall>>,
        reads: RefCell<VecDeque<Result<Host, String>>>,
        reset_dns_err: std::cell::Cell<bool>,
    }

    impl RecordingWg {
        fn new(reads: Vec<Result<Host, String>>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                reads: RefCell::new(reads.into()),
                reset_dns_err: std::cell::Cell::new(false),
            }
        }
        fn calls(&self) -> Vec<WgCall> {
            std::mem::take(&mut self.calls.borrow_mut())
        }
    }

    impl WgOps for RecordingWg {
        fn create_interface(&self) -> Result<(), String> {
            self.calls.borrow_mut().push(WgCall::CreateInterface);
            Ok(())
        }
        fn remove_interface(&self) -> Result<(), String> {
            self.calls.borrow_mut().push(WgCall::RemoveInterface);
            Ok(())
        }
        fn configure_interface(&self, cfg: &InterfaceConfiguration) -> Result<(), String> {
            self.calls.borrow_mut().push(WgCall::ConfigureInterface {
                prvkey: cfg.prvkey.clone(),
                addresses: cfg.addresses.iter().map(|a| a.to_string()).collect(),
                port: cfg.port,
                mtu: cfg.mtu,
                peer_keys: cfg.peers.iter().map(|p| p.public_key.to_string()).collect(),
                fwmark: cfg.fwmark,
            });
            Ok(())
        }
        fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), String> {
            self.calls.borrow_mut().push(WgCall::ConfigurePeerRouting {
                peer_keys: peers.iter().map(|p| p.public_key.to_string()).collect(),
            });
            Ok(())
        }
        fn sync_split_routes(&self, prefixes: &[IpAddrMask]) -> Result<(), String> {
            self.calls.borrow_mut().push(WgCall::SyncSplitRoutes {
                prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
            });
            Ok(())
        }
        fn configure_dns(&self, dns: &[IpAddr], _search: &[&str]) -> Result<(), String> {
            self.calls.borrow_mut().push(WgCall::ConfigureDns {
                servers: dns.iter().map(|d| d.to_string()).collect(),
            });
            Ok(())
        }
        fn reset_dns(&self) -> Result<(), String> {
            self.calls.borrow_mut().push(WgCall::ResetDns);
            if self.reset_dns_err.get() {
                Err("resolvconf -d failed".into())
            } else {
                Ok(())
            }
        }
        fn read_interface_data(&self) -> Result<Host, String> {
            self.calls.borrow_mut().push(WgCall::ReadInterfaceData);
            self.reads
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err("no scripted read".into()))
        }
    }

    /// A live `Host` carrying a fwmark and one peer, to script the warm path.
    fn live_host(fwmark: Option<u32>, peer_key: &str) -> Host {
        let key = Key::from_str(peer_key).unwrap();
        let mut host = Host::new(51820, Key::generate());
        host.fwmark = fwmark;
        host.peers.insert(key.clone(), Peer::new(key));
        host
    }

    /// Run a switch against scripted reads and return the recorded call log.
    fn run_switch(reads: Vec<Result<Host, String>>, server: &ServerConfig) -> Vec<WgCall> {
        let wg = KernelWireguard::with_ops(RecordingWg::new(reads));
        wg.switch(server).unwrap();
        wg.ops.calls()
    }

    fn index_of(calls: &[WgCall], pred: impl Fn(&WgCall) -> bool) -> Option<usize> {
        calls.iter().position(pred)
    }

    #[test]
    fn warm_switch_never_removes_or_recreates_the_interface() {
        let server = valid_server();
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        assert!(!calls.contains(&WgCall::RemoveInterface), "{calls:?}");
        assert!(!calls.contains(&WgCall::CreateInterface), "{calls:?}");
    }

    #[test]
    fn warm_switch_preserves_the_fwmark_read_from_the_device() {
        let server = valid_server();
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        let cfg = calls
            .iter()
            .find(|c| matches!(c, WgCall::ConfigureInterface { .. }))
            .expect("a ConfigureInterface");
        match cfg {
            WgCall::ConfigureInterface { fwmark, .. } => {
                assert_eq!(
                    *fwmark,
                    Some(51820),
                    "fwmark from read must be threaded back"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn warm_switch_reads_then_configures_then_routes() {
        let server = valid_server();
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        let read = index_of(&calls, |c| matches!(c, WgCall::ReadInterfaceData)).unwrap();
        let conf = index_of(&calls, |c| matches!(c, WgCall::ConfigureInterface { .. })).unwrap();
        let route = index_of(&calls, |c| matches!(c, WgCall::ConfigurePeerRouting { .. })).unwrap();
        assert!(read < conf && conf < route, "order was {calls:?}");
    }

    #[test]
    fn warm_switch_sets_exactly_the_servers_address_and_peer() {
        let server = valid_server();
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        match calls
            .iter()
            .find(|c| matches!(c, WgCall::ConfigureInterface { .. }))
            .unwrap()
        {
            WgCall::ConfigureInterface {
                addresses,
                peer_keys,
                ..
            } => {
                assert_eq!(addresses, &vec!["10.0.0.2/24".to_string()]);
                assert_eq!(peer_keys, &vec![server.public_key.clone()]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn switch_threads_all_addresses_for_a_dual_stack_tunnel() {
        let mut server = valid_server();
        server.addresses = vec!["10.0.0.2/32".into(), "fd00::2/128".into()];
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        match calls
            .iter()
            .find(|c| matches!(c, WgCall::ConfigureInterface { .. }))
            .unwrap()
        {
            WgCall::ConfigureInterface { addresses, .. } => {
                assert_eq!(
                    addresses,
                    &vec!["10.0.0.2/32".to_string(), "fd00::2/128".to_string()]
                );
            }
            _ => unreachable!(),
        }
    }

    /// The crux of the per-tunnel refactor: the interface is configured with THIS
    /// tunnel's own private key, port, and MTU — not a shared global identity.
    #[test]
    fn switch_uses_the_tunnels_own_key_port_and_mtu() {
        let mut server = valid_server();
        server.listen_port = 12345;
        server.mtu = Some(1380);
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        match calls
            .iter()
            .find(|c| matches!(c, WgCall::ConfigureInterface { .. }))
            .unwrap()
        {
            WgCall::ConfigureInterface {
                prvkey, port, mtu, ..
            } => {
                assert_eq!(prvkey, &server.private_key);
                assert_eq!(*port, 12345);
                assert_eq!(*mtu, Some(1380));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn cold_switch_creates_then_configures_then_routes_with_no_fwmark() {
        let server = valid_server();
        let calls = run_switch(vec![Err("interface down".into())], &server);
        // Order: Create → Configure → Routing. Crucially NO RemoveInterface —
        // a switch must never tear the interface (and its kill switch) down.
        assert!(!calls.contains(&WgCall::RemoveInterface), "{calls:?}");
        let cr = index_of(&calls, |c| matches!(c, WgCall::CreateInterface)).unwrap();
        let conf = index_of(&calls, |c| matches!(c, WgCall::ConfigureInterface { .. })).unwrap();
        let route = index_of(&calls, |c| matches!(c, WgCall::ConfigurePeerRouting { .. })).unwrap();
        assert!(cr < conf && conf < route, "order was {calls:?}");
        match calls
            .iter()
            .find(|c| matches!(c, WgCall::ConfigureInterface { .. }))
            .unwrap()
        {
            WgCall::ConfigureInterface { fwmark, .. } => assert_eq!(*fwmark, None),
            _ => unreachable!(),
        }
    }

    #[test]
    fn switch_with_dns_configures_the_resolver_after_routing() {
        let mut server = valid_server();
        server.dns = vec!["10.0.0.1".into()];
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        let route = index_of(&calls, |c| matches!(c, WgCall::ConfigurePeerRouting { .. })).unwrap();
        let dns = index_of(&calls, |c| matches!(c, WgCall::ConfigureDns { .. })).unwrap();
        assert!(route < dns, "DNS must be set after routing: {calls:?}");
        assert!(!calls.contains(&WgCall::ResetDns));
    }

    #[test]
    fn switch_to_a_server_without_dns_resets_the_resolver() {
        let server = valid_server(); // dns is empty
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        assert!(calls.contains(&WgCall::ResetDns), "{calls:?}");
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, WgCall::ConfigureDns { .. }))
        );
    }

    /// The address handed back by a switch is the one the peer was configured
    /// with — it's what the daemon writes into the endpoint cache.
    #[test]
    fn switch_returns_the_endpoint_it_configured() {
        let wg = KernelWireguard::with_ops(RecordingWg::new(vec![Err("interface down".into())]));
        let addr = wg.switch(&valid_server()).unwrap();
        assert_eq!(addr.to_string(), "198.51.100.10:51820");
    }

    #[test]
    fn a_switch_whose_input_is_invalid_touches_no_kernel_ops() {
        let mut server = valid_server();
        server.public_key = "not-a-key".into();
        let wg = KernelWireguard::with_ops(RecordingWg::new(vec![]));
        assert!(wg.switch(&server).is_err());
        assert!(wg.ops.calls().is_empty(), "parse-before-touch violated");
    }

    /// `remove_interface` must be confined to `disconnect` — a switch never removes
    /// the interface (that would drop the kill switch). This pins the invariant from
    /// the only legitimate caller's side: disconnect does exactly one thing.
    #[test]
    fn disconnect_removes_the_interface_and_nothing_else() {
        let wg = KernelWireguard::with_ops(RecordingWg::new(vec![]));
        wg.disconnect().unwrap();
        assert_eq!(wg.ops.calls(), vec![WgCall::RemoveInterface]);
    }

    /// Clearing DNS is best-effort: a failure to remove a (possibly absent)
    /// resolvconf entry must not fail an otherwise-successful switch.
    #[test]
    fn a_failed_dns_reset_does_not_fail_the_switch() {
        let server = valid_server(); // no DNS → switch takes the reset path
        let wg = KernelWireguard::with_ops(RecordingWg::new(vec![Ok(live_host(
            Some(51820),
            "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
        ))]));
        wg.ops.reset_dns_err.set(true);
        assert!(
            wg.switch(&server).is_ok(),
            "reset_dns failure must not fail the switch"
        );
        assert!(wg.ops.calls().contains(&WgCall::ResetDns));
    }

    // ── split routes ─────────────────────────────────────────────────────────────

    #[test]
    fn split_route_prefixes_keeps_only_the_non_default_prefixes() {
        let mut server = valid_server();
        server.allowed_ips = vec![
            "192.168.1.0/24".into(),
            "0.0.0.0/0".into(),
            "::/0".into(),
            "fd00:beef::/48".into(),
        ];
        let prefixes = split_route_prefixes(&build_peer(&server).unwrap());
        assert_eq!(
            prefixes.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            vec!["192.168.1.0/24", "fd00:beef::/48"]
        );
    }

    /// The regression this path exists for: a home-router peer that offers its LAN
    /// alongside a full tunnel. defguard routes only the default route, so without an
    /// explicit route for `192.168.1.0/24` the host's own identically-numbered LAN
    /// route wins and that traffic never enters the tunnel.
    #[test]
    fn switch_routes_a_peers_lan_prefix_explicitly() {
        let mut server = valid_server();
        server.allowed_ips = vec!["192.168.1.0/24".into(), "0.0.0.0/0".into(), "::/0".into()];
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        assert!(
            calls.contains(&WgCall::SyncSplitRoutes {
                prefixes: vec!["192.168.1.0/24".to_string()],
            }),
            "{calls:?}"
        );
        // After peer routing: that call is what assigns the fwmark and installs the
        // rules these routes coexist with.
        let route = index_of(&calls, |c| matches!(c, WgCall::ConfigurePeerRouting { .. })).unwrap();
        let split = index_of(&calls, |c| matches!(c, WgCall::SyncSplitRoutes { .. })).unwrap();
        assert!(route < split, "order was {calls:?}");
    }

    /// A plain full tunnel has no prefixes of its own, but the sync must still run:
    /// it is what retires the routes the PREVIOUS server left on the interface.
    #[test]
    fn switch_to_a_plain_full_tunnel_still_syncs_an_empty_route_set() {
        let server = valid_server(); // allowed_ips = 0.0.0.0/0
        let calls = run_switch(
            vec![Ok(live_host(
                Some(51820),
                "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=",
            ))],
            &server,
        );
        assert!(
            calls.contains(&WgCall::SyncSplitRoutes { prefixes: vec![] }),
            "{calls:?}"
        );
    }

    /// A config written with host bits set still has to produce a route `ip route`
    /// accepts — and one that compares equal to what the kernel reports back.
    #[test]
    fn split_route_prefixes_are_canonical_network_addresses() {
        let mut server = valid_server();
        server.allowed_ips = vec![
            "192.168.1.5/24".into(),
            "10.1.2.3/8".into(),
            "fd00:beef::1/48".into(),
            "0.0.0.0/0".into(),
        ];
        let prefixes = split_route_prefixes(&build_peer(&server).unwrap());
        assert_eq!(
            prefixes.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            vec!["192.168.1.0/24", "10.0.0.0/8", "fd00:beef::/48"]
        );
        // A host route and a /0 are already canonical.
        let host = IpAddrMask::from_str("10.5.5.5/32").unwrap();
        assert_eq!(network_prefix(&host).to_string(), "10.5.5.5/32");
    }

    /// Real `ip -j route show table main dev wirefinder proto static` output, plus the
    /// two forms that must be tolerated: a bare host address, and `"default"`.
    #[test]
    fn ip_route_json_yields_the_prefixes_it_lists() {
        let json = r#"[{"dst":"192.168.1.0/24","protocol":"static","scope":"link","flags":[]},
                       {"dst":"10.5.5.5","protocol":"static","scope":"link","flags":[]},
                       {"dst":"default","protocol":"static","flags":[]}]"#;
        assert_eq!(
            parse_ip_route_prefixes(json)
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
            // "default" is not ours to delete, so it is not reported.
            vec!["192.168.1.0/24", "10.5.5.5/32"]
        );
    }

    /// Anything unparseable (an `ip` with no `-j`, an absent interface, empty output)
    /// must prune NOTHING rather than guess.
    #[test]
    fn unparseable_ip_output_yields_no_prefixes() {
        for junk in ["", "Cannot find device \"wirefinder\"", "[]", "not json"] {
            assert!(parse_ip_route_prefixes(junk).is_empty(), "{junk:?}");
        }
    }

    #[test]
    fn stale_routes_are_the_ones_the_new_server_does_not_want() {
        let p = |s: &str| IpAddrMask::from_str(s).unwrap();
        let installed = vec![p("192.168.1.0/24"), p("10.8.0.0/16"), p("fd00::/48")];
        let wanted = vec![p("192.168.1.0/24"), p("172.16.0.0/12")];
        assert_eq!(
            stale_routes(&installed, &wanted)
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>(),
            // The shared prefix is kept (never deleted, so never briefly route-less);
            // a wanted prefix that isn't installed yet is not a deletion.
            vec!["10.8.0.0/16", "fd00::/48"]
        );
        assert!(stale_routes(&[], &wanted).is_empty());
        assert_eq!(stale_routes(&installed, &[]).len(), 3);
    }

    // ── resolvconf interface-name parsing (pure) ─────────────────────────────────

    #[test]
    fn interface_order_prefix_picks_the_first_valid_entry() {
        let content = "# comment\nwg*\neth*\n";
        // The leading comment isn't `<prefix>*`; the first real entry wins.
        assert_eq!(interface_order_prefix(content).as_deref(), Some("wg"));
    }

    #[test]
    fn interface_order_prefix_handles_dashes_and_skips_malformed_lines() {
        assert_eq!(
            interface_order_prefix("not-a-pattern\nmy-vpn*\n").as_deref(),
            Some("my-vpn")
        );
        assert_eq!(interface_order_prefix("").as_deref(), None);
        assert_eq!(interface_order_prefix("*\n").as_deref(), None); // empty prefix
        assert_eq!(interface_order_prefix("eth0\nwlan0\n").as_deref(), None); // no '*'
    }
}

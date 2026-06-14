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

use std::env;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::SystemTime;

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
    /// place when already up (leak-safe — see the module docs).
    fn switch(&self, server: &ServerConfig) -> Result<(), String>;

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
/// input fails at configuration time, not at connect time.
pub fn validate_server(server: &ServerConfig) -> Result<(), String> {
    Key::from_str(server.private_key.trim())
        .map_err(|e| format!("server '{}': bad private_key: {e}", server.name))?;
    build_peer(server)?;
    parse_dns(server)?;
    parse_addresses(server)?;
    Ok(())
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

    let endpoint = server
        .endpoint
        .to_socket_addrs()
        .map_err(|e| format!("server '{}': cannot resolve endpoint: {e}", server.name))?
        .next()
        .ok_or_else(|| {
            format!(
                "server '{}': endpoint resolved to no addresses",
                server.name
            )
        })?;
    peer.endpoint = Some(endpoint);

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

    fn switch(&self, server: &ServerConfig) -> Result<(), String> {
        // Parse FIRST — fail before touching the tunnel.
        let peer = build_peer(server)?;
        let dns = parse_dns(server)?;
        parse_addresses(server)?;

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
        self.apply_dns(&dns)?;
        Ok(())
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

//! The daemon's brain: it owns the persisted config and the runtime connection
//! state, and maps each [`Request`] to a [`Response`]. All policy lives here; all
//! kernel mechanism lives behind the [`Wireguard`] trait, so this whole module is
//! exercised by unit tests against an in-memory fake backend.

use std::time::{Duration, Instant, SystemTime};

use wirefinder_proto::{
    ConnState, InterfaceStatus, PeerStatus, Request, Response, ServerDetail, ServerInfo, ServerSpec,
};

use crate::config::{Config, ServerConfig, Store};
use crate::keys;
use crate::wgconf;
use crate::wireguard::{self, LivePeer, Wireguard};

/// How long after initiating a connection we report a not-yet-handshaked peer as
/// `Connecting` (rather than `Never`) while it tries to reach the server.
const CONNECTING_WINDOW: Duration = Duration::from_secs(15);

/// A handshake older than this is considered `Stale` rather than `Alive`.
const STALE_AFTER: Duration = Duration::from_secs(180);

/// Derive the synthesized connection state from a peer's handshake age and whether
/// we just initiated a connection. Pure, so the state machine is tested directly.
fn derive_state(handshake_age_secs: Option<u64>, connecting: bool) -> ConnState {
    match handshake_age_secs {
        Some(age) if age < STALE_AFTER.as_secs() => ConnState::Alive,
        Some(_) => ConnState::Stale,
        None if connecting => ConnState::Connecting,
        None => ConnState::Never,
    }
}

/// Seconds since a peer's last handshake, or `None` if it never handshook.
fn handshake_age(peer: &LivePeer) -> Option<u64> {
    match peer.last_handshake {
        None => None,
        Some(t) if t == SystemTime::UNIX_EPOCH => None,
        Some(t) => Some(
            SystemTime::now()
                .duration_since(t)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ),
    }
}

/// The daemon. Single-threaded: the accept loop is the only caller of `handle`, so
/// the mutable state needs no lock.
pub struct Daemon<W: Wireguard> {
    store: Store,
    cfg: Config,
    wg: W,
    /// When the most recent connect/switch was initiated; drives the `Connecting`
    /// window. `None` means idle (disconnected, or never connected this run).
    last_connect: Option<Instant>,
}

impl<W: Wireguard> Daemon<W> {
    /// Build a daemon, loading any persisted config from `store`.
    pub fn load(store: Store, wg: W) -> Result<Self, String> {
        let cfg = store.load()?;
        Ok(Self {
            store,
            cfg,
            wg,
            last_connect: None,
        })
    }

    /// The number of configured servers — used for the startup log line.
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.cfg.servers.len()
    }

    // --- connection-window intent ---

    fn mark_connecting(&mut self) {
        self.last_connect = Some(Instant::now());
    }

    fn clear_connecting(&mut self) {
        self.last_connect = None;
    }

    fn is_connecting(&self) -> bool {
        self.last_connect
            .is_some_and(|t| t.elapsed() < CONNECTING_WINDOW)
    }

    // --- request handlers ---

    fn persist(&self) -> Result<(), String> {
        self.store.save(&self.cfg)
    }

    /// The single funnel for adding a tunnel, shared by `AddServer` and
    /// `ImportServer`. Resolves the private key (generates one if none supplied),
    /// validates, upserts (replace-by-name), and persists.
    fn add_server(&mut self, spec: ServerSpec) -> Result<(), String> {
        if spec.name.trim().is_empty() {
            return Err("server name must not be empty".into());
        }
        let private_key = spec
            .private_key
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .unwrap_or_else(crate::keys::generate_private_key);

        let server = ServerConfig {
            name: spec.name.trim().to_string(),
            private_key,
            public_key: spec.public_key,
            endpoint: spec.endpoint,
            addresses: spec.addresses,
            allowed_ips: spec.allowed_ips,
            listen_port: spec.listen_port.unwrap_or(0),
            mtu: spec.mtu,
            keepalive: spec.keepalive,
            preshared_key: spec.preshared_key,
            dns: spec.dns,
        };
        // Reject malformed input (keys, addresses, peer) before we persist anything.
        wireguard::validate_server(&server)?;
        self.cfg.upsert_server(server);
        self.persist()
    }

    /// Import a wg-quick `.conf`: parse it into a spec (its `[Interface] PrivateKey`
    /// simply becomes this tunnel's key) and add it through the same path.
    fn import_server(&mut self, name: String, conf: &str) -> Result<(), String> {
        let parsed = wgconf::parse(conf)?;
        self.add_server(ServerSpec {
            name,
            private_key: Some(parsed.private_key),
            public_key: parsed.public_key,
            endpoint: parsed.endpoint,
            addresses: parsed.addresses,
            allowed_ips: parsed.allowed_ips,
            listen_port: parsed.listen_port,
            mtu: parsed.mtu,
            keepalive: parsed.keepalive,
            preshared_key: parsed.preshared_key,
            dns: parsed.dns,
        })
    }

    fn remove_server(&mut self, name: &str) -> Result<(), String> {
        if !self.cfg.remove_server(name) {
            return Err(format!("unknown server '{name}'"));
        }
        self.persist()
    }

    /// The editable detail for one server, to pre-fill an edit form. Secret-free.
    fn get_server(&self, name: &str) -> Result<ServerDetail, String> {
        self.cfg
            .find_server(name)
            .map(ServerConfig::detail)
            .ok_or_else(|| format!("unknown server '{name}'"))
    }

    /// Edit an existing tunnel in place. The name is the identity (it cannot change);
    /// the server must already exist and must not be the active tunnel. Secrets are
    /// preserved unless explicitly resupplied — `None` keeps the stored value, so the
    /// UI (which never sees the private key) can edit other fields without rotating
    /// it. Validates and persists, like [`add_server`](Self::add_server).
    fn edit_server(&mut self, spec: ServerSpec) -> Result<(), String> {
        let name = spec.name.trim().to_string();
        if name.is_empty() {
            return Err("server name must not be empty".into());
        }

        // Edit never creates: the server must already exist. Clone the stored config
        // (and its secrets) out before we mutate — mirrors how `SwitchServer` clones
        // before acting, and sidesteps borrowing `self.cfg` across the mutation.
        let existing = self
            .cfg
            .find_server(&name)
            .ok_or_else(|| format!("unknown server '{name}'"))?
            .clone();

        // Refuse to edit the live tunnel: a reconfigure-in-place could change the key
        // or addresses of the connection the user is currently relying on.
        let derived = keys::public_key(&existing.private_key)?;
        if self.active_public_key().as_deref() == Some(derived.as_str()) {
            return Err(format!(
                "server '{name}' is the active tunnel; disconnect or switch away before editing"
            ));
        }

        // `None` (or an empty string, as in `add_server`) preserves the stored secret;
        // a non-empty value replaces it.
        let private_key = spec
            .private_key
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .unwrap_or(existing.private_key);
        let preshared_key = match spec.preshared_key.map(|k| k.trim().to_string()) {
            Some(k) if !k.is_empty() => Some(k),
            _ => existing.preshared_key,
        };

        let server = ServerConfig {
            name,
            private_key,
            public_key: spec.public_key,
            endpoint: spec.endpoint,
            addresses: spec.addresses,
            allowed_ips: spec.allowed_ips,
            listen_port: spec.listen_port.unwrap_or(0),
            mtu: spec.mtu,
            keepalive: spec.keepalive,
            preshared_key,
            dns: spec.dns,
        };
        // Reject malformed input before we persist anything.
        wireguard::validate_server(&server)?;
        self.cfg.upsert_server(server); // replace-by-name; existence enforced above
        self.persist()
    }

    /// OUR public key currently on the live interface, or `None` if the interface is
    /// down/unreadable. This uniquely identifies the active tunnel. Note `list_servers`
    /// deliberately inlines this same logic so it can share a single status snapshot
    /// across the `active` flag and the derived `state`, rather than reading twice.
    fn active_public_key(&self) -> Option<String> {
        self.wg.status().ok().and_then(|live| live.public_key)
    }

    /// The configured servers, each flagged with whether it is the active tunnel and,
    /// for the active one, its live connection state. A tunnel is active when OUR
    /// public key currently on the interface matches its own derived public key —
    /// which is unique per tunnel, so two tunnels that share a peer (server) public
    /// key are still told apart. The active tunnel's `state` is derived from the same
    /// live snapshot, using the same rule as [`read_status`](Self::read_status), so a
    /// client renders the two consistently. Best-effort: if the interface is
    /// down/unreadable, nothing is active.
    fn list_servers(&self) -> Vec<ServerInfo> {
        // Read the interface once so `active` and `state` come from one snapshot.
        let live = self.wg.status().ok();
        let active_key = live.as_ref().and_then(|l| l.public_key.clone());
        let connecting = self.is_connecting();

        self.cfg
            .servers
            .iter()
            .filter_map(|s| {
                let mut info = s.info(false).ok()?;
                info.active = active_key.as_deref() == Some(info.public_key.as_str());
                if info.active {
                    // The active tunnel's sole peer is its server; derive its state
                    // exactly as `read_status` does (handshake age + connecting window).
                    let age = live
                        .as_ref()
                        .and_then(|l| l.peers.iter().find(|p| p.public_key == s.public_key))
                        .and_then(handshake_age);
                    info.state = Some(derive_state(age, connecting));
                }
                Some(info)
            })
            .collect()
    }

    fn read_status(&self) -> Result<InterfaceStatus, String> {
        let live = self.wg.status()?;
        let connecting = self.is_connecting();
        Ok(InterfaceStatus {
            name: live.name,
            listen_port: live.listen_port,
            peers: live
                .peers
                .iter()
                .map(|p| {
                    let age = handshake_age(p);
                    PeerStatus {
                        public_key: p.public_key.clone(),
                        endpoint: p.endpoint.clone(),
                        allowed_ips: p.allowed_ips.clone(),
                        state: derive_state(age, connecting),
                        handshake_age_secs: age,
                        rx_bytes: p.rx_bytes,
                        tx_bytes: p.tx_bytes,
                    }
                })
                .collect(),
        })
    }

    /// Map one request to a response, applying any connection-state transition.
    /// All transitions live here, so the state machine reads in one place.
    pub fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::Status => match self.read_status() {
                Ok(status) => Response::Status(status),
                // No interface = disconnected, not an error.
                Err(_) => Response::Disconnected,
            },

            Request::ListServers => Response::Servers(self.list_servers()),

            Request::GetServer { name } => match self.get_server(&name) {
                Ok(detail) => Response::ServerDetail(detail),
                Err(e) => Response::Error(e),
            },

            Request::AddServer { server } => match self.add_server(server) {
                Ok(()) => Response::Servers(self.list_servers()),
                Err(e) => Response::Error(e),
            },

            Request::EditServer { server } => match self.edit_server(server) {
                Ok(()) => Response::Servers(self.list_servers()),
                Err(e) => Response::Error(e),
            },

            Request::ImportServer { name, conf } => match self.import_server(name, &conf) {
                Ok(()) => Response::Servers(self.list_servers()),
                Err(e) => Response::Error(e),
            },

            Request::RemoveServer { name } => match self.remove_server(&name) {
                Ok(()) => Response::Servers(self.list_servers()),
                Err(e) => Response::Error(e),
            },

            Request::SwitchServer { name } => {
                let server = match self.cfg.find_server(&name) {
                    Some(s) => s.clone(),
                    None => return Response::Error(format!("unknown server '{name}'")),
                };
                match self.wg.switch(&server) {
                    Ok(()) => {
                        self.mark_connecting(); // open the connecting window
                        Response::Switched { name }
                    }
                    Err(e) => Response::Error(e),
                }
            }

            Request::Disconnect => match self.wg.disconnect() {
                Ok(()) => {
                    self.clear_connecting();
                    Response::Disconnected
                }
                Err(e) => Response::Error(e),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use crate::wireguard::LiveInterface;
    use std::cell::RefCell;
    use std::time::UNIX_EPOCH;

    /// An in-memory WireGuard backend. Records calls and lets each test dictate
    /// what `status()` returns, so the daemon's policy can be tested with no root,
    /// no kernel, and no network.
    #[derive(Default)]
    struct FakeWireguard {
        calls: RefCell<Vec<String>>,
        /// Public keys of peers currently "on the interface". `None` = interface
        /// down (status returns Err).
        live_peers: RefCell<Option<Vec<FakePeer>>>,
        /// The addresses of the most recently switched-to tunnel — so tests can
        /// assert the daemon passes each tunnel's OWN config to the backend.
        last_switch_addresses: RefCell<Vec<String>>,
        /// OUR public key of the active tunnel (derived from its private key on
        /// switch), mirroring what the real interface reports. `None` = down.
        live_pubkey: RefCell<Option<String>>,
        /// If set, the next mutating op returns this error.
        fail_with: RefCell<Option<String>>,
    }

    #[derive(Clone)]
    struct FakePeer {
        public_key: String,
        last_handshake: Option<SystemTime>,
    }

    impl FakeWireguard {
        fn record(&self, what: &str) {
            self.calls.borrow_mut().push(what.to_string());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
        fn set_live(&self, peers: Vec<FakePeer>) {
            *self.live_peers.borrow_mut() = Some(peers);
        }
        fn check_fail(&self) -> Result<(), String> {
            if let Some(e) = self.fail_with.borrow_mut().take() {
                return Err(e);
            }
            Ok(())
        }
    }

    impl Wireguard for FakeWireguard {
        fn disconnect(&self) -> Result<(), String> {
            self.record("disconnect");
            self.check_fail()?;
            *self.live_peers.borrow_mut() = None;
            *self.live_pubkey.borrow_mut() = None;
            Ok(())
        }
        fn switch(&self, server: &ServerConfig) -> Result<(), String> {
            self.record(&format!("switch:{}", server.name));
            *self.last_switch_addresses.borrow_mut() = server.addresses.clone();
            self.check_fail()?;
            // Mimic the kernel: the switched tunnel's OWN key lands on the interface,
            // and its server becomes the sole peer (no handshake yet).
            *self.live_pubkey.borrow_mut() = Some(keys::public_key(&server.private_key).unwrap());
            self.set_live(vec![FakePeer {
                public_key: server.public_key.clone(),
                last_handshake: None,
            }]);
            Ok(())
        }
        fn status(&self) -> Result<LiveInterface, String> {
            let peers = self
                .live_peers
                .borrow()
                .clone()
                .ok_or_else(|| "interface down".to_string())?;
            Ok(LiveInterface {
                name: "wg0".into(),
                public_key: self.live_pubkey.borrow().clone(),
                listen_port: 51820,
                peers: peers
                    .into_iter()
                    .map(|p| LivePeer {
                        public_key: p.public_key,
                        endpoint: Some("198.51.100.10:51820".into()),
                        allowed_ips: vec!["0.0.0.0/0".into()],
                        last_handshake: p.last_handshake,
                        rx_bytes: 100,
                        tx_bytes: 200,
                    })
                    .collect(),
            })
        }
    }

    /// A client-facing add spec, with `private_key: None` so the daemon generates a
    /// fresh keypair (the common path). The peer public key is a real base64 key.
    fn server(name: &str) -> ServerSpec {
        ServerSpec {
            name: name.into(),
            private_key: None,
            public_key: "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=".into(),
            endpoint: "198.51.100.10:51820".into(),
            addresses: vec!["10.0.0.2/24".into()],
            allowed_ips: vec!["0.0.0.0/0".into()],
            listen_port: None,
            mtu: None,
            keepalive: Some(25),
            preshared_key: None,
            dns: vec![],
        }
    }

    /// The peer public key a freshly-`server()`'d entry will report on the interface.
    const PEER_KEY: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    /// A daemon writing to a throwaway temp state file, backed by the fake.
    fn fresh_daemon() -> (tempfile::TempDir, Daemon<FakeWireguard>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("state.json"));
        let daemon = Daemon::load(store, FakeWireguard::default()).unwrap();
        (dir, daemon)
    }

    /// A daemon with one server configured — onboarding is just "add a server".
    fn onboarded() -> (tempfile::TempDir, Daemon<FakeWireguard>) {
        let (dir, mut d) = fresh_daemon();
        d.handle(Request::AddServer {
            server: server("nexus"),
        });
        (dir, d)
    }

    fn servers(d: &mut Daemon<FakeWireguard>) -> Vec<ServerInfo> {
        let Response::Servers(list) = d.handle(Request::ListServers) else {
            panic!("expected Servers");
        };
        list
    }

    #[test]
    fn a_fresh_daemon_has_no_servers() {
        let (_dir, mut d) = fresh_daemon();
        assert!(servers(&mut d).is_empty());
    }

    #[test]
    fn switching_when_no_server_exists_is_an_unknown_server_error() {
        let (_dir, mut d) = fresh_daemon();
        let Response::Error(e) = d.handle(Request::SwitchServer {
            name: "nexus".into(),
        }) else {
            panic!("expected Error");
        };
        assert!(e.contains("unknown server"), "{e}");
    }

    #[test]
    fn add_server_generates_a_key_and_exposes_only_the_derived_public_one() {
        let (_dir, mut d) = fresh_daemon();
        d.handle(Request::AddServer {
            server: server("nexus"),
        });

        let stored_private = d.cfg.servers[0].private_key.clone();
        let derived = keys::public_key(&stored_private).expect("a real key was generated");

        let info = servers(&mut d)
            .into_iter()
            .find(|s| s.name == "nexus")
            .unwrap();
        // The list exposes OUR derived public key, never the private one.
        assert_eq!(info.public_key, derived);
        assert_ne!(info.public_key, stored_private);
    }

    #[test]
    fn add_server_adopts_a_supplied_private_key() {
        let (_dir, mut d) = fresh_daemon();
        let provided = keys::generate_private_key();
        let mut spec = server("nexus");
        spec.private_key = Some(provided.clone());
        d.handle(Request::AddServer { server: spec });
        assert_eq!(d.cfg.servers[0].private_key, provided);
    }

    #[test]
    fn add_server_rejects_a_bad_address() {
        let (_dir, mut d) = onboarded();
        let mut bad = server("broken");
        bad.addresses = vec!["not-a-cidr".into()];
        let Response::Error(e) = d.handle(Request::AddServer { server: bad }) else {
            panic!("expected Error");
        };
        assert!(e.contains("address"), "{e}");
        assert_eq!(d.cfg.servers.len(), 1, "only the good 'nexus' remains");
    }

    #[test]
    fn add_server_rejects_a_bad_peer_key() {
        let (_dir, mut d) = onboarded();
        let mut bad = server("broken");
        bad.public_key = "not-a-key".into();
        let Response::Error(e) = d.handle(Request::AddServer { server: bad }) else {
            panic!("expected Error");
        };
        assert!(e.contains("public_key"), "{e}");
        assert_eq!(d.cfg.servers.len(), 1);
    }

    #[test]
    fn add_server_rejects_a_bad_supplied_private_key() {
        let (_dir, mut d) = fresh_daemon();
        let mut bad = server("broken");
        bad.private_key = Some("not-a-key".into());
        let Response::Error(e) = d.handle(Request::AddServer { server: bad }) else {
            panic!("expected Error");
        };
        assert!(e.contains("private_key"), "{e}");
        assert!(d.cfg.servers.is_empty(), "nothing should be persisted");
    }

    #[test]
    fn add_server_rejects_empty_name() {
        let (_dir, mut d) = onboarded();
        let Response::Error(e) = d.handle(Request::AddServer { server: server("") }) else {
            panic!("expected Error");
        };
        assert!(e.contains("name"), "{e}");
    }

    #[test]
    fn remove_unknown_server_errors() {
        let (_dir, mut d) = onboarded();
        let Response::Error(e) = d.handle(Request::RemoveServer {
            name: "ghost".into(),
        }) else {
            panic!("expected Error");
        };
        assert!(e.contains("unknown server"), "{e}");
    }

    #[test]
    fn add_and_remove_servers_round_trip_through_the_list() {
        let (_dir, mut d) = onboarded();
        d.handle(Request::AddServer {
            server: server("edge"),
        });
        let names: Vec<_> = servers(&mut d).into_iter().map(|s| s.name).collect();
        assert!(names.contains(&"nexus".to_string()) && names.contains(&"edge".to_string()));

        d.handle(Request::RemoveServer {
            name: "edge".into(),
        });
        let list = servers(&mut d);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "nexus");
    }

    #[test]
    fn switching_marks_the_server_active_and_reports_connecting() {
        let (_dir, mut d) = onboarded();
        let Response::Switched { name } = d.handle(Request::SwitchServer {
            name: "nexus".into(),
        }) else {
            panic!("expected Switched");
        };
        assert_eq!(name, "nexus");
        assert!(d.wg.calls().contains(&"switch:nexus".to_string()));

        let listed = servers(&mut d);
        let nexus = listed.iter().find(|s| s.name == "nexus").unwrap();
        assert!(nexus.active);
        // The server list and the status view derive the SAME state: with no handshake
        // yet, inside the window, the active server reads as Connecting in both places.
        assert_eq!(nexus.state, Some(ConnState::Connecting));

        let Response::Status(status) = d.handle(Request::Status) else {
            panic!("expected Status");
        };
        assert_eq!(status.peers[0].state, ConnState::Connecting);
    }

    #[test]
    fn the_active_server_lists_alive_once_a_handshake_lands() {
        let (_dir, mut d) = onboarded();
        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });
        d.wg.set_live(vec![FakePeer {
            public_key: PEER_KEY.into(),
            last_handshake: Some(SystemTime::now()),
        }]);
        // The list-derived state agrees with the status-derived state: both Alive.
        let listed = servers(&mut d);
        let nexus = listed.iter().find(|s| s.name == "nexus").unwrap();
        assert!(nexus.active);
        assert_eq!(nexus.state, Some(ConnState::Alive));
    }

    #[test]
    fn an_inactive_server_lists_no_state() {
        let (_dir, mut d) = onboarded(); // "nexus", never switched to
        let nexus = servers(&mut d)
            .into_iter()
            .find(|s| s.name == "nexus")
            .unwrap();
        assert!(!nexus.active);
        assert_eq!(nexus.state, None);
    }

    #[test]
    fn disconnect_brings_the_interface_down() {
        let (_dir, mut d) = onboarded();
        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });
        assert!(matches!(d.handle(Request::Status), Response::Status(_)));

        let resp = d.handle(Request::Disconnect);
        assert!(matches!(resp, Response::Disconnected));
        assert!(matches!(d.handle(Request::Status), Response::Disconnected));
    }

    #[test]
    fn servers_survive_a_daemon_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        {
            let mut d = Daemon::load(Store::new(path.clone()), FakeWireguard::default()).unwrap();
            d.handle(Request::AddServer {
                server: server("nexus"),
            });
        }
        // A brand-new daemon over the same file sees the persisted server.
        let mut d2 = Daemon::load(Store::new(path), FakeWireguard::default()).unwrap();
        let list = servers(&mut d2);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "nexus");
    }

    #[test]
    fn state_derivation_covers_every_case() {
        assert_eq!(derive_state(Some(5), false), ConnState::Alive);
        assert_eq!(derive_state(Some(5), true), ConnState::Alive); // handshake wins
        assert_eq!(derive_state(Some(9_999), false), ConnState::Stale);
        assert_eq!(derive_state(None, true), ConnState::Connecting);
        assert_eq!(derive_state(None, false), ConnState::Never);
    }

    #[test]
    fn a_recent_handshake_reads_as_alive() {
        let (_dir, mut d) = onboarded();
        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });
        d.wg.set_live(vec![FakePeer {
            public_key: PEER_KEY.into(),
            last_handshake: Some(SystemTime::now()),
        }]);
        let Response::Status(status) = d.handle(Request::Status) else {
            panic!("expected Status");
        };
        assert_eq!(status.peers[0].state, ConnState::Alive);
    }

    #[test]
    fn epoch_handshake_is_treated_as_never_handshaked() {
        let (_dir, mut d) = onboarded();
        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });
        // Close the connecting window so we isolate the epoch→Never handshake logic
        // (a switch opens the window, which would otherwise read as Connecting).
        d.last_connect = None;
        d.wg.set_live(vec![FakePeer {
            public_key: PEER_KEY.into(),
            last_handshake: Some(UNIX_EPOCH),
        }]);
        let Response::Status(status) = d.handle(Request::Status) else {
            panic!("expected Status");
        };
        assert_eq!(status.peers[0].state, ConnState::Never);
    }

    #[test]
    fn a_failed_switch_surfaces_the_backend_error() {
        let (_dir, mut d) = onboarded();
        *d.wg.fail_with.borrow_mut() = Some("kernel exploded".into());
        let Response::Error(e) = d.handle(Request::SwitchServer {
            name: "nexus".into(),
        }) else {
            panic!("expected Error");
        };
        assert!(e.contains("kernel exploded"), "{e}");
    }

    /// The product's core promise: switching servers moves the single active flag.
    /// Each tunnel has its OWN key (generated) and address.
    #[test]
    fn switching_between_two_servers_moves_the_active_flag() {
        let (_dir, mut d) = onboarded(); // "nexus" at 10.0.0.2/24
        let mut edge = server("edge");
        edge.public_key = "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=".into();
        edge.addresses = vec!["192.168.50.5/24".into()]; // a different per-server address
        d.handle(Request::AddServer { server: edge });

        // The two tunnels have distinct generated keys.
        let pubkeys: Vec<_> = servers(&mut d).into_iter().map(|s| s.public_key).collect();
        assert_ne!(pubkeys[0], pubkeys[1], "each tunnel has its own keypair");

        let active = |d: &mut Daemon<FakeWireguard>, name: &str| {
            servers(d)
                .into_iter()
                .find(|s| s.name == name)
                .unwrap()
                .active
        };

        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });
        assert!(active(&mut d, "nexus"));
        assert!(!active(&mut d, "edge"));
        // The daemon passed nexus's OWN address to the backend.
        assert_eq!(
            *d.wg.last_switch_addresses.borrow(),
            vec!["10.0.0.2/24".to_string()]
        );

        d.handle(Request::SwitchServer {
            name: "edge".into(),
        });
        assert!(
            !active(&mut d, "nexus"),
            "old server must deactivate on switch"
        );
        assert!(active(&mut d, "edge"));
        // ...and edge's distinct address on the next switch.
        assert_eq!(
            *d.wg.last_switch_addresses.borrow(),
            vec!["192.168.50.5/24".to_string()]
        );
    }

    /// Two tunnels to the SAME server (identical peer public key) but with distinct
    /// client identities must be told apart by their own key — only the connected
    /// one shows active. (Regression: we used to match on the peer key alone.)
    #[test]
    fn two_tunnels_to_the_same_server_are_told_apart() {
        let (_dir, mut d) = fresh_daemon();
        // `server()` gives both the same peer public key; their generated client
        // keypairs differ.
        d.handle(Request::AddServer {
            server: server("nexus-a"),
        });
        d.handle(Request::AddServer {
            server: server("nexus-b"),
        });
        assert_eq!(
            d.cfg.servers[0].public_key, d.cfg.servers[1].public_key,
            "same peer"
        );

        d.handle(Request::SwitchServer {
            name: "nexus-a".into(),
        });
        let list = servers(&mut d);
        assert!(list.iter().find(|s| s.name == "nexus-a").unwrap().active);
        assert!(
            !list.iter().find(|s| s.name == "nexus-b").unwrap().active,
            "the other tunnel to the same server must NOT show active"
        );
    }

    /// The trust boundary, asserted on the wire: a known tunnel private key must not
    /// appear in the JSON of ANY client-facing response, across the request surface.
    #[test]
    fn the_private_key_never_appears_in_any_client_facing_response() {
        let (_dir, mut d) = fresh_daemon();
        let secret = keys::generate_private_key();
        let psk = keys::generate_private_key();
        let mut spec = server("nexus");
        spec.private_key = Some(secret.clone());
        spec.preshared_key = Some(psk.clone());
        d.handle(Request::AddServer {
            server: spec.clone(),
        });
        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });

        let requests = [
            Request::ListServers,
            Request::Status,
            Request::AddServer {
                server: spec.clone(),
            },
            Request::EditServer { server: spec },
            Request::GetServer {
                name: "nexus".into(),
            },
        ];
        for req in requests {
            let json = serde_json::to_string(&d.handle(req)).unwrap();
            assert!(
                !json.contains(&secret),
                "private key leaked in response: {json}"
            );
            assert!(
                !json.contains(&psk),
                "preshared key leaked in response: {json}"
            );
        }
    }

    #[test]
    fn the_connecting_window_expires_to_never() {
        let (_dir, mut d) = onboarded();
        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });
        assert!(d.is_connecting(), "window opens on switch");

        // Force the window to have opened just past its expiry.
        d.last_connect = Instant::now().checked_sub(CONNECTING_WINDOW + Duration::from_secs(1));
        assert!(!d.is_connecting());

        let Response::Status(status) = d.handle(Request::Status) else {
            panic!("expected Status");
        };
        assert_eq!(status.peers[0].state, ConnState::Never);
    }

    // ── edit / get ───────────────────────────────────────────────────────────────

    fn detail(d: &mut Daemon<FakeWireguard>, name: &str) -> ServerDetail {
        let Response::ServerDetail(det) = d.handle(Request::GetServer { name: name.into() }) else {
            panic!("expected ServerDetail");
        };
        det
    }

    /// An edit that supplies no private key must keep the stored one — editing other
    /// fields must never rotate the keypair (the UI can't resupply the secret).
    #[test]
    fn edit_preserves_the_private_key_when_none_is_supplied() {
        let (_dir, mut d) = fresh_daemon();
        let secret = keys::generate_private_key();
        let mut spec = server("nexus");
        spec.private_key = Some(secret.clone());
        d.handle(Request::AddServer { server: spec });

        let mut edit = server("nexus");
        edit.private_key = None;
        edit.endpoint = "198.51.100.20:51820".into();
        let Response::Servers(_) = d.handle(Request::EditServer { server: edit }) else {
            panic!("expected Servers");
        };

        assert_eq!(d.cfg.servers[0].private_key, secret, "key preserved");
        assert_eq!(d.cfg.servers[0].endpoint, "198.51.100.20:51820");
    }

    #[test]
    fn edit_adopts_a_supplied_private_key() {
        let (_dir, mut d) = onboarded();
        let replacement = keys::generate_private_key();
        let mut edit = server("nexus");
        edit.private_key = Some(replacement.clone());
        d.handle(Request::EditServer { server: edit });
        assert_eq!(d.cfg.servers[0].private_key, replacement);
    }

    #[test]
    fn edit_preserves_the_preshared_key_when_none_is_supplied() {
        let (_dir, mut d) = fresh_daemon();
        let psk = keys::generate_private_key();
        let mut spec = server("nexus");
        spec.preshared_key = Some(psk.clone());
        d.handle(Request::AddServer { server: spec });

        let mut edit = server("nexus");
        edit.preshared_key = None;
        d.handle(Request::EditServer { server: edit });
        assert_eq!(d.cfg.servers[0].preshared_key, Some(psk), "PSK preserved");
    }

    #[test]
    fn edit_adopts_a_supplied_preshared_key() {
        let (_dir, mut d) = onboarded();
        let psk = keys::generate_private_key();
        let mut edit = server("nexus");
        edit.preshared_key = Some(psk.clone());
        d.handle(Request::EditServer { server: edit });
        assert_eq!(d.cfg.servers[0].preshared_key, Some(psk));
    }

    #[test]
    fn edit_of_an_unknown_server_errors_and_persists_nothing() {
        let (_dir, mut d) = fresh_daemon();
        let Response::Error(e) = d.handle(Request::EditServer {
            server: server("ghost"),
        }) else {
            panic!("expected Error");
        };
        assert!(e.contains("unknown server"), "{e}");
        assert!(d.cfg.servers.is_empty());
    }

    #[test]
    fn edit_of_the_active_tunnel_is_rejected() {
        let (_dir, mut d) = onboarded();
        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });
        let mut edit = server("nexus");
        edit.endpoint = "new.example.com:51820".into();
        let Response::Error(e) = d.handle(Request::EditServer { server: edit }) else {
            panic!("expected Error");
        };
        assert!(e.contains("active tunnel"), "{e}");
        assert_eq!(
            d.cfg.servers[0].endpoint, "198.51.100.10:51820",
            "rejected edit must not persist"
        );
    }

    /// The active check must key off the EDITED server, not "is anything connected".
    /// Editing a different (inactive) server while one is active must succeed.
    #[test]
    fn edit_of_a_non_active_tunnel_while_another_is_active_succeeds() {
        let (_dir, mut d) = onboarded(); // "nexus"
        let mut edge = server("edge");
        edge.public_key = "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=".into();
        edge.addresses = vec!["192.168.50.5/24".into()];
        d.handle(Request::AddServer { server: edge });
        d.handle(Request::SwitchServer {
            name: "nexus".into(),
        });

        let mut edit = server("edge");
        edit.public_key = "XhbwkaURz3Tcc2A7TmV89aB+cHOJayNRiSH2My/r1Bk=".into();
        edit.addresses = vec!["192.168.50.5/24".into()];
        edit.endpoint = "198.51.100.30:51820".into();
        let Response::Servers(_) = d.handle(Request::EditServer { server: edit }) else {
            panic!("expected Servers");
        };
        let edged = d.cfg.servers.iter().find(|s| s.name == "edge").unwrap();
        assert_eq!(edged.endpoint, "198.51.100.30:51820");
    }

    #[test]
    fn edit_rejects_a_bad_address_and_persists_nothing() {
        let (_dir, mut d) = onboarded();
        let mut edit = server("nexus");
        edit.addresses = vec!["not-a-cidr".into()];
        let Response::Error(e) = d.handle(Request::EditServer { server: edit }) else {
            panic!("expected Error");
        };
        assert!(e.contains("address"), "{e}");
        assert_eq!(
            d.cfg.servers[0].addresses,
            vec!["10.0.0.2/24".to_string()],
            "rejected edit must not persist"
        );
    }

    #[test]
    fn get_server_returns_detail_for_a_known_server() {
        let (_dir, mut d) = onboarded();
        let det = detail(&mut d, "nexus");
        assert_eq!(det.name, "nexus");
        // The peer public key the server was added with — not our derived key.
        assert_eq!(det.public_key, PEER_KEY);
        assert_eq!(det.endpoint, "198.51.100.10:51820");
        assert_eq!(det.keepalive, Some(25));
        assert!(!det.has_preshared_key);
    }

    #[test]
    fn get_server_reports_a_stored_preshared_key_as_a_flag() {
        let (_dir, mut d) = fresh_daemon();
        let mut spec = server("nexus");
        spec.preshared_key = Some(keys::generate_private_key());
        d.handle(Request::AddServer { server: spec });
        assert!(detail(&mut d, "nexus").has_preshared_key);
    }

    #[test]
    fn get_server_unknown_errors() {
        let (_dir, mut d) = onboarded();
        let Response::Error(e) = d.handle(Request::GetServer {
            name: "ghost".into(),
        }) else {
            panic!("expected Error");
        };
        assert!(e.contains("unknown server"), "{e}");
    }

    // ── import ───────────────────────────────────────────────────────────────────

    fn valid_conf() -> String {
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.0.0.2/24\n\
             [Peer]\nPublicKey = {PEER_KEY}\nEndpoint = 198.51.100.10:51820\nAllowedIPs = 0.0.0.0/0\n",
            keys::generate_private_key()
        )
    }

    #[test]
    fn import_adds_a_server_with_a_derived_public_key() {
        let (_dir, mut d) = fresh_daemon();
        let Response::Servers(list) = d.handle(Request::ImportServer {
            name: "home".into(),
            conf: valid_conf(),
        }) else {
            panic!("expected Servers");
        };
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "home");
        // The derived public key matches the stored private key from the .conf.
        assert_eq!(
            list[0].public_key,
            keys::public_key(&d.cfg.servers[0].private_key).unwrap()
        );
    }

    #[test]
    fn import_of_malformed_conf_errors_and_persists_nothing() {
        let (_dir, mut d) = fresh_daemon();
        let Response::Error(e) = d.handle(Request::ImportServer {
            name: "home".into(),
            conf: "not a config".into(),
        }) else {
            panic!("expected Error");
        };
        assert!(!e.is_empty(), "a parse error is surfaced");
        assert!(d.cfg.servers.is_empty());
    }

    #[test]
    fn import_with_a_bad_key_surfaces_validate_server() {
        let (_dir, mut d) = fresh_daemon();
        // Structurally valid, but PrivateKey isn't base64 → caught by validate_server.
        let conf = "[Interface]\nPrivateKey = not-a-key\nAddress = 10.0.0.2/24\n\
                    [Peer]\nPublicKey = p\nEndpoint = h:51820\nAllowedIPs = 0.0.0.0/0\n";
        let Response::Error(e) = d.handle(Request::ImportServer {
            name: "home".into(),
            conf: conf.into(),
        }) else {
            panic!("expected Error");
        };
        assert!(e.contains("private_key"), "{e}");
        assert!(d.cfg.servers.is_empty());
    }

    #[test]
    fn an_imported_private_key_never_appears_in_a_response() {
        let (_dir, mut d) = fresh_daemon();
        let secret = keys::generate_private_key();
        let conf = format!(
            "[Interface]\nPrivateKey = {secret}\nAddress = 10.0.0.2/24\n\
             [Peer]\nPublicKey = {PEER_KEY}\nEndpoint = 198.51.100.10:51820\nAllowedIPs = 0.0.0.0/0\n"
        );
        let resp = d.handle(Request::ImportServer {
            name: "home".into(),
            conf,
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains(&secret),
            "imported private key leaked: {json}"
        );
    }

    #[test]
    fn import_of_a_multi_peer_conf_is_rejected_end_to_end() {
        let (_dir, mut d) = fresh_daemon();
        let conf = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.0.0.2/24\n\
             [Peer]\nPublicKey = {PEER_KEY}\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n\
             [Peer]\nPublicKey = {PEER_KEY}\nEndpoint = h:2\nAllowedIPs = 0.0.0.0/0\n",
            keys::generate_private_key()
        );
        let Response::Error(e) = d.handle(Request::ImportServer {
            name: "home".into(),
            conf,
        }) else {
            panic!("expected Error");
        };
        assert!(e.contains("one peer"), "{e}");
        assert!(d.cfg.servers.is_empty());
    }

    #[test]
    fn a_dual_stack_tunnels_addresses_are_passed_to_the_backend_in_full() {
        let (_dir, mut d) = fresh_daemon();
        let mut spec = server("ds");
        spec.addresses = vec!["10.0.0.2/32".into(), "fd00::2/128".into()];
        d.handle(Request::AddServer { server: spec });
        d.handle(Request::SwitchServer { name: "ds".into() });
        assert_eq!(
            *d.wg.last_switch_addresses.borrow(),
            vec!["10.0.0.2/32".to_string(), "fd00::2/128".to_string()]
        );
    }
}

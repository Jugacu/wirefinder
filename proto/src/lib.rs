//! The wirefinder IPC protocol: the types shared by the daemon and its clients.
//!
//! These deliberately do NOT reuse the WireGuard crate's types — the wire format
//! is a contract with frontends, not a window into daemon internals. The crate is
//! intentionally dependency-light (serde only) so every client can depend on it.
//!
//! ## The model
//!
//! A "server" is a COMPLETE, self-contained WireGuard tunnel: its own private key,
//! address(es), listen port, MTU, and DNS, plus the peer it connects to. This
//! mirrors a wg-quick `.conf` file (one `[Interface]` + one `[Peer]`), which is how
//! providers and self-hosters hand out configs. wirefinder switches between these
//! tunnels exclusively (one active at a time).
//!
//! ## Trust boundary
//!
//! The daemon is the sole owner of cryptographic material. A tunnel's PRIVATE key is
//! either generated daemon-side or supplied once (in a [`ServerSpec`] or an imported
//! `.conf`) and then persisted daemon-side — it NEVER appears in any response.
//! Clients only ever learn the corresponding PUBLIC key (in [`ServerInfo`], so the
//! user can register it with a self-hosted server).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Where the daemon listens. A client connects here to speak the protocol below.
///
/// This lives under `/run` (root-owned, not the world-writable `/tmp`) inside a
/// dedicated `0750 root:wirefinder` directory. The directory's restricted
/// traversal is what makes the bind race-free: even for the instant between
/// `bind()` and setting the socket's mode, no one outside the `wirefinder` group
/// can reach the path.
pub const SOCKET_PATH: &str = "/run/wirefinder/wirefinderd.sock";

/// Send one request to the daemon and read one response.
/// Connect, write a line, read a line — the whole transport, in one place.
pub fn request(req: &Request) -> Result<Response, String> {
    let stream = UnixStream::connect(SOCKET_PATH).map_err(|e| e.to_string())?;
    // Don't let a wedged daemon hang a client (or the GUI's poll loop) forever.
    let timeout = Some(Duration::from_secs(10));
    stream
        .set_read_timeout(timeout)
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(timeout)
        .map_err(|e| e.to_string())?;

    let mut writer = &stream;
    serde_json::to_writer(&mut writer, req).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| e.to_string())
}

/// A command or query a client may send the daemon. One line of JSON per request.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Request {
    // --- queries ---
    /// Live tunnel status, or `Disconnected` if the interface is down.
    Status,
    /// The configured servers, each flagged with whether it is currently active.
    /// An empty list means the daemon is reachable but un-onboarded.
    ListServers,
    /// Full editable detail for one server, to pre-fill an edit form. Carries every
    /// field a client may change EXCEPT secrets: the private key is never exposed,
    /// and a stored preshared key is reduced to a `has_preshared_key` flag. Errors
    /// if the named server is unknown. Returns [`Response::ServerDetail`].
    GetServer { name: String },

    // --- configuration ---
    /// Add (or replace, by name) a tunnel. With `private_key: None` the daemon
    /// generates a fresh keypair for it; otherwise it adopts the supplied key.
    /// Returns the updated server list (each entry carries its derived public key).
    AddServer { server: ServerSpec },
    /// Edit an EXISTING tunnel in place. `server.name` identifies it and is the one
    /// field that cannot change (it is the identity/upsert key). Secrets are
    /// preserved unless explicitly resupplied: `private_key: None` keeps the stored
    /// key (the UI cannot resupply it), and `preshared_key: None` keeps the stored
    /// preshared key. A stored preshared key can thus be replaced but not cleared
    /// through an edit. Editing the currently-active tunnel is rejected. Returns the
    /// updated server list.
    EditServer { server: ServerSpec },
    /// Import a standard wg-quick `.conf`: `name` labels the resulting tunnel (the
    /// file has none) and `conf` is the file's full text. The daemon parses it,
    /// adds the tunnel, and returns the updated list. Like `AddServer`, any private
    /// key in the config is persisted daemon-side and never echoed back.
    ImportServer { name: String, conf: String },
    /// Forget a server by name. Returns the updated server list.
    RemoveServer { name: String },

    // --- tunnel control ---
    /// Make `name` the sole active server, bringing its tunnel up if needed. This
    /// is the only way to connect — the interface identity comes from the chosen
    /// tunnel.
    SwitchServer { name: String },
    /// Tear the interface down entirely.
    Disconnect,
}

/// The daemon's reply. Exactly one line of JSON per response.
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Status(InterfaceStatus),
    /// The interface is not up. Returned by `Status` when there's no tunnel, and
    /// as the ack for `Disconnect`. Distinct from `Error` (daemon trouble) and from
    /// the transport failing entirely (daemon unreachable).
    Disconnected,
    /// The configured servers. Returned by `ListServers`, `AddServer`,
    /// `ImportServer`, `RemoveServer`, and `EditServer`.
    Servers(Vec<ServerInfo>),
    /// One server's editable detail, secret-free. Returned by `GetServer`.
    ServerDetail(ServerDetail),
    Switched {
        name: String,
    },
    Error(String),
}

/// A complete tunnel definition sent by a client to add a server. Carries the
/// cryptographic material the daemon needs; `private_key: None` asks the daemon to
/// generate one. Never appears in a [`Response`] — secrets flow one way.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    pub name: String,
    /// Our tunnel private key (base64). `None` → the daemon generates one.
    #[serde(default)]
    pub private_key: Option<String>,
    /// The server's (peer's) WireGuard public key (base64).
    pub public_key: String,
    /// `host:port`, e.g. `vpn.example.com:51820`.
    pub endpoint: String,
    /// The tunnel address(es) this server assigns to your device, e.g.
    /// `["10.0.0.2/24"]` or dual-stack `["10.0.0.2/32", "fd00::2/128"]`.
    pub addresses: Vec<String>,
    /// Traffic to route into the tunnel, e.g. `["0.0.0.0/0"]` for a full tunnel.
    pub allowed_ips: Vec<String>,
    /// Listen port. `None` → kernel-assigned (the norm for clients).
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Interface MTU. `None` → kernel default.
    #[serde(default)]
    pub mtu: Option<u32>,
    /// Persistent keepalive in seconds; recommended behind NAT. `None` = off.
    #[serde(default)]
    pub keepalive: Option<u16>,
    /// Optional pre-shared key (base64) for an extra symmetric layer.
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// DNS resolvers to route through the tunnel while this server is active.
    /// Empty = use the system resolver. Mirrors wg-quick's `DNS =`.
    #[serde(default)]
    pub dns: Vec<String>,
}

/// What clients may know about a configured server. The private key is absent; the
/// `public_key` here is OURS (derived from the tunnel's private key) so the user can
/// register it on a self-hosted server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub name: String,
    pub endpoint: String,
    /// This tunnel's address(es).
    pub addresses: Vec<String>,
    /// Our public key for this tunnel (safe to expose).
    pub public_key: String,
    /// Whether this is the SELECTED tunnel: its identity is currently loaded on the
    /// live interface. This says nothing about handshake health — see `state`.
    pub active: bool,
    /// The active tunnel's live connection state, derived the same way as a peer's
    /// `state` in [`InterfaceStatus`] (so a client renders it consistently with the
    /// status view). `None` for inactive tunnels, which have no live connection.
    #[serde(default)]
    pub state: Option<ConnState>,
}

/// The editable view of a configured server, used to pre-fill an edit form. Like
/// [`ServerInfo`] it crosses the daemon → client boundary, so it carries NO secrets:
/// the tunnel private key never appears, and a stored preshared key is reduced to a
/// boolean hint. Unlike `ServerInfo` it carries the full set of *editable* fields
/// (the peer's public key, allowed-IPs, DNS, MTU, keepalive, listen port) so the form
/// starts from the real stored values. `name` is shown read-only — it is the identity.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerDetail {
    pub name: String,
    /// The server's (peer's) WireGuard public key (base64).
    pub public_key: String,
    /// `host:port`, e.g. `vpn.example.com:51820`.
    pub endpoint: String,
    /// The tunnel address(es) this server assigns to your device.
    pub addresses: Vec<String>,
    /// Traffic routed into the tunnel.
    pub allowed_ips: Vec<String>,
    /// Listen port; `None`/absent means kernel-assigned.
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Interface MTU; `None` = kernel default.
    #[serde(default)]
    pub mtu: Option<u32>,
    /// Persistent keepalive in seconds; `None` = off.
    #[serde(default)]
    pub keepalive: Option<u16>,
    /// Whether a preshared key is stored. The key itself is never sent; this only
    /// lets the form show "a preshared key is set" without revealing it.
    pub has_preshared_key: bool,
    /// DNS resolvers routed through the tunnel while this server is active.
    #[serde(default)]
    pub dns: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct InterfaceStatus {
    pub name: String,
    pub listen_port: u16,
    pub peers: Vec<PeerStatus>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PeerStatus {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub state: ConnState,
    pub handshake_age_secs: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Daemon-derived connection state. WireGuard has no such concept —
/// inventing it is the daemon's job (see Mullvad's tunnel state machine).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Alive,
    /// Peer configured and a connect was recently initiated, but no handshake
    /// has landed yet. Daemon-synthesized, like the others.
    Connecting,
    Stale,
    Never,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire format IS the contract between daemon and clients. This pins the
    /// exact JSON for representative requests, so an accidental rename or shape
    /// change breaks the build instead of breaking clients silently.
    #[test]
    fn requests_serialize_to_expected_json() {
        let cases = [
            (
                Request::SwitchServer {
                    name: "nexus".into(),
                },
                r#"{"SwitchServer":{"name":"nexus"}}"#,
            ),
            (
                Request::RemoveServer {
                    name: "decoy".into(),
                },
                r#"{"RemoveServer":{"name":"decoy"}}"#,
            ),
            (
                Request::ImportServer {
                    name: "home".into(),
                    conf: "[Interface]".into(),
                },
                r#"{"ImportServer":{"name":"home","conf":"[Interface]"}}"#,
            ),
            (
                Request::GetServer {
                    name: "nexus".into(),
                },
                r#"{"GetServer":{"name":"nexus"}}"#,
            ),
        ];
        for (req, expected) in cases {
            assert_eq!(serde_json::to_string(&req).unwrap(), expected);
        }
    }

    /// A minimal `ServerSpec` (only the required fields) deserializes, with the
    /// optional fields defaulting — this is what the GUI sends for "generate a key".
    #[test]
    fn server_spec_optional_fields_default() {
        let json = r#"{
            "name": "edge",
            "public_key": "abc",
            "endpoint": "vpn.example.com:51820",
            "addresses": ["10.0.0.2/24"],
            "allowed_ips": ["0.0.0.0/0"]
        }"#;
        let spec: ServerSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.addresses, vec!["10.0.0.2/24"]);
        assert_eq!(spec.private_key, None);
        assert_eq!(spec.listen_port, None);
        assert_eq!(spec.mtu, None);
        assert_eq!(spec.keepalive, None);
        assert!(spec.dns.is_empty());
    }

    /// `addresses` is required: a payload omitting it must fail to deserialize.
    #[test]
    fn server_spec_requires_addresses() {
        let json = r#"{
            "name": "edge",
            "public_key": "abc",
            "endpoint": "vpn.example.com:51820",
            "allowed_ips": ["0.0.0.0/0"]
        }"#;
        assert!(serde_json::from_str::<ServerSpec>(json).is_err());
    }

    #[test]
    fn add_server_round_trips() {
        let req = Request::AddServer {
            server: ServerSpec {
                name: "edge".into(),
                private_key: None,
                public_key: "abc".into(),
                endpoint: "vpn.example.com:51820".into(),
                addresses: vec!["10.0.0.2/24".into()],
                allowed_ips: vec!["0.0.0.0/0".into()],
                listen_port: None,
                mtu: None,
                keepalive: Some(25),
                preshared_key: None,
                dns: vec![],
            },
        };
        let wire = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&wire).unwrap(), req);
    }

    /// `EditServer` carries a full `ServerSpec`, same as `AddServer`; pin that it
    /// survives a round-trip so the edit contract can't drift silently.
    #[test]
    fn edit_server_round_trips() {
        let req = Request::EditServer {
            server: ServerSpec {
                name: "edge".into(),
                private_key: None,
                public_key: "abc".into(),
                endpoint: "vpn.example.com:51820".into(),
                addresses: vec!["10.0.0.2/24".into()],
                allowed_ips: vec!["0.0.0.0/0".into()],
                listen_port: None,
                mtu: None,
                keepalive: Some(25),
                preshared_key: None,
                dns: vec![],
            },
        };
        let wire = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&wire).unwrap(), req);
    }

    /// `ServerDetail` crosses the daemon → client boundary, so its JSON must never
    /// carry a secret field. It reports only `has_preshared_key`, never the key.
    #[test]
    fn server_detail_has_no_secret_field_names() {
        let detail = ServerDetail {
            name: "edge".into(),
            public_key: "abc".into(),
            endpoint: "vpn.example.com:51820".into(),
            addresses: vec!["10.0.0.2/24".into()],
            allowed_ips: vec!["0.0.0.0/0".into()],
            listen_port: None,
            mtu: None,
            keepalive: Some(25),
            has_preshared_key: true,
            dns: vec![],
        };
        let json = serde_json::to_string(&detail).unwrap();
        assert!(!json.contains("private_key"), "{json}");
        assert!(!json.contains("\"preshared_key\""), "{json}");
        assert!(json.contains("has_preshared_key"), "{json}");
    }

    /// Every response variant must survive a serialize → deserialize round-trip
    /// unchanged. Guards the half of the contract that flows daemon → client.
    #[test]
    fn responses_round_trip() {
        let cases = [
            Response::Disconnected,
            Response::Servers(vec![ServerInfo {
                name: "nexus".into(),
                endpoint: "vpn.example.com:51820".into(),
                addresses: vec!["10.0.0.2/24".into()],
                public_key: "pubkey".into(),
                active: true,
                state: Some(ConnState::Alive),
            }]),
            Response::Switched {
                name: "nexus".into(),
            },
            Response::ServerDetail(ServerDetail {
                name: "nexus".into(),
                public_key: "peerkey".into(),
                endpoint: "vpn.example.com:51820".into(),
                addresses: vec!["10.0.0.2/24".into()],
                allowed_ips: vec!["0.0.0.0/0".into()],
                listen_port: None,
                mtu: None,
                keepalive: Some(25),
                has_preshared_key: false,
                dns: vec![],
            }),
            Response::Error("boom".into()),
        ];
        for resp in cases {
            let wire = serde_json::to_string(&resp).unwrap();
            let back: Response = serde_json::from_str(&wire).unwrap();
            // Compare via their JSON, since Response isn't PartialEq.
            assert_eq!(serde_json::to_string(&back).unwrap(), wire);
        }
    }
}

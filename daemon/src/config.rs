//! Persistent daemon state: the set of known tunnels ("servers"), each a complete,
//! self-contained WireGuard config (its own private key, addresses, port, MTU, DNS,
//! and peer).
//!
//! The daemon OWNS this file. There is no admin-edited config file — clients build
//! the state up over IPC, and the daemon persists every mutation. Because each
//! server holds a private key the file is written atomically with mode 0600 (owner
//! read/write only).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wirefinder_proto::{ServerDetail, ServerInfo};

use crate::keys;

/// Default on-disk location of the persisted state. Overridable via the
/// `WIREFINDER_STATE` environment variable (used by dev runs and tests).
const DEFAULT_STATE_PATH: &str = "/var/lib/wirefinder/state.json";

/// Resolve the state-file path from the environment, falling back to the default.
#[must_use]
pub fn default_state_path() -> PathBuf {
    std::env::var_os("WIREFINDER_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_PATH))
}

/// The whole persisted state. Starts empty on first run; onboarding fills it in.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct Config {
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}

impl Config {
    /// Look up a server by name.
    pub fn find_server(&self, name: &str) -> Option<&ServerConfig> {
        self.servers.iter().find(|s| s.name == name)
    }

    /// Add a server, replacing any existing one with the same name (so the GUI's
    /// "edit" is just a re-add). Returns whether an existing entry was replaced.
    pub fn upsert_server(&mut self, server: ServerConfig) -> bool {
        if let Some(slot) = self.servers.iter_mut().find(|s| s.name == server.name) {
            *slot = server;
            true
        } else {
            self.servers.push(server);
            false
        }
    }

    /// Remove a server by name. Returns whether anything was removed.
    pub fn remove_server(&mut self, name: &str) -> bool {
        let before = self.servers.len();
        self.servers.retain(|s| s.name != name);
        self.servers.len() != before
    }
}

/// A complete tunnel: a full WireGuard config (its own interface identity + the one
/// peer it connects to). Holds the PRIVATE key, so it is only ever serialized to the
/// root-owned 0600 state file — never sent to a client. This is the daemon's stored
/// form; clients send a [`wirefinder_proto::ServerSpec`] (private key optional) which
/// the daemon resolves into this.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub name: String,
    /// OUR tunnel private key (base64). Persisted; never echoed to a client.
    pub private_key: String,
    /// The server's (peer's) public key (base64).
    pub public_key: String,
    /// `host:port`, e.g. `vpn.example.com:51820`.
    pub endpoint: String,
    /// This tunnel's address(es), e.g. `["10.0.0.2/24"]` (possibly dual-stack).
    pub addresses: Vec<String>,
    /// Traffic to route into the tunnel, e.g. `["0.0.0.0/0"]` for a full tunnel.
    pub allowed_ips: Vec<String>,
    /// Listen port; `0` = kernel-assigned.
    pub listen_port: u16,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub keepalive: Option<u16>,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
}

impl ServerConfig {
    /// The client-facing view: identity + our DERIVED public key + active flag.
    /// Never the private key.
    pub fn info(&self, active: bool) -> Result<ServerInfo, String> {
        Ok(ServerInfo {
            name: self.name.clone(),
            endpoint: self.endpoint.clone(),
            addresses: self.addresses.clone(),
            public_key: keys::public_key(&self.private_key)?,
            active,
            // The active tunnel's live state is filled in by `Daemon::list_servers`,
            // which has the live interface in hand; a bare `info()` reports none.
            state: None,
        })
    }

    /// The client-facing EDIT view: every editable field, but no secrets. Unlike
    /// [`info`](Self::info) this exposes the stored PEER public key (not our derived
    /// one) and never touches the private key, so it cannot fail. A stored preshared
    /// key becomes a boolean hint; its value is never sent.
    pub fn detail(&self) -> ServerDetail {
        ServerDetail {
            name: self.name.clone(),
            public_key: self.public_key.clone(),
            endpoint: self.endpoint.clone(),
            addresses: self.addresses.clone(),
            allowed_ips: self.allowed_ips.clone(),
            // Stored `0` means kernel-assigned; present that as "unset" to the form.
            listen_port: (self.listen_port != 0).then_some(self.listen_port),
            mtu: self.mtu,
            keepalive: self.keepalive,
            has_preshared_key: self.preshared_key.is_some(),
            dns: self.dns.clone(),
        }
    }
}

/// Owns the state-file path and reads/writes [`Config`] through it. Injecting a
/// `Store` (rather than hard-coding the path) is what makes persistence testable.
pub struct Store {
    path: PathBuf,
}

impl Store {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load the persisted config. A missing file is not an error — it means a
    /// fresh, un-onboarded install, so we return the empty default.
    pub fn load(&self) -> Result<Config, String> {
        match fs::read_to_string(&self.path) {
            Ok(text) => {
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", self.path.display()))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", self.path.display())),
        }
    }

    /// Persist the config atomically: write a sibling temp file with mode 0600,
    /// flush it, then rename over the target. A crash mid-write can never leave a
    /// truncated state file — the reader sees either the old file or the new one.
    pub fn save(&self, cfg: &Config) -> Result<(), String> {
        if let Some(dir) = self.path.parent()
            && !dir.as_os_str().is_empty()
        {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }

        let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("json.tmp");

        write_private(&tmp, json.as_bytes()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        fs::rename(&tmp, &self.path)
            .map_err(|e| format!("{} -> {}: {e}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

/// Write `bytes` to `path`, creating it 0600 and fsync'ing before close.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file: File = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample_server(name: &str) -> ServerConfig {
        ServerConfig {
            name: name.into(),
            private_key: keys::generate_private_key(),
            public_key: "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=".into(),
            endpoint: "vpn.example.com:51820".into(),
            addresses: vec!["10.0.0.2/24".into()],
            allowed_ips: vec!["0.0.0.0/0".into()],
            listen_port: 51820,
            mtu: None,
            keepalive: Some(25),
            preshared_key: None,
            dns: vec!["10.0.0.1".into()],
        }
    }

    fn tmp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("nested/state.json"));
        (dir, store)
    }

    #[test]
    fn missing_file_loads_as_empty_default() {
        let (_dir, store) = tmp_store();
        let cfg = store.load().unwrap();
        assert_eq!(cfg, Config::default());
        assert!(cfg.servers.is_empty());
    }

    #[test]
    fn save_then_load_round_trips_and_creates_parent_dirs() {
        let (_dir, store) = tmp_store();
        let mut cfg = Config::default();
        cfg.upsert_server(sample_server("nexus"));

        store.save(&cfg).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn the_stored_private_key_is_in_the_file_but_the_file_is_0600() {
        let (_dir, store) = tmp_store();
        let mut cfg = Config::default();
        let server = sample_server("nexus");
        let secret = server.private_key.clone();
        cfg.upsert_server(server);
        store.save(&cfg).unwrap();

        let text = fs::read_to_string(&store.path).unwrap();
        assert!(text.contains(&secret), "private key is persisted...");
        let mode = fs::metadata(&store.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "...but only the owner can read it");
    }

    #[test]
    fn saved_state_file_is_owner_only_0600() {
        let (_dir, store) = tmp_store();
        store.save(&Config::default()).unwrap();
        let mode = fs::metadata(&store.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "state holds the private key");
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp_file() {
        let (_dir, store) = tmp_store();
        store.save(&Config::default()).unwrap();
        let tmp = store.path.with_extension("json.tmp");
        assert!(!tmp.exists(), "temp file must be renamed away");
    }

    #[test]
    fn upsert_replaces_by_name_rather_than_duplicating() {
        let mut cfg = Config::default();
        assert!(!cfg.upsert_server(sample_server("nexus")));
        let mut edited = sample_server("nexus");
        edited.endpoint = "new.example.com:51820".into();
        assert!(cfg.upsert_server(edited), "same name replaces");
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].endpoint, "new.example.com:51820");
    }

    #[test]
    fn remove_server_reports_whether_it_existed() {
        let mut cfg = Config::default();
        cfg.upsert_server(sample_server("nexus"));
        assert!(cfg.remove_server("nexus"));
        assert!(!cfg.remove_server("nexus"));
        assert!(cfg.servers.is_empty());
    }

    #[test]
    fn info_exposes_the_derived_public_key_never_the_private_one() {
        let server = sample_server("nexus");
        let info = server.info(true).unwrap();
        assert_eq!(
            info.public_key,
            keys::public_key(&server.private_key).unwrap()
        );
        assert_ne!(info.public_key, server.private_key);
        assert!(info.active);
        assert_eq!(info.addresses, server.addresses);
    }

    #[test]
    fn detail_omits_secrets_and_exposes_editable_fields() {
        let mut server = sample_server("nexus");
        server.preshared_key = Some(keys::generate_private_key());
        let detail = server.detail();

        // The detail exposes the stored PEER key, NOT our derived public key.
        assert_eq!(detail.public_key, server.public_key);
        assert_eq!(detail.endpoint, server.endpoint);
        assert_eq!(detail.addresses, server.addresses);
        assert_eq!(detail.allowed_ips, server.allowed_ips);
        assert_eq!(detail.dns, server.dns);
        assert_eq!(detail.keepalive, server.keepalive);
        // A stored preshared key is reduced to a boolean — never its value.
        assert!(detail.has_preshared_key);
        let json = serde_json::to_string(&detail).unwrap();
        assert!(
            !json.contains(server.preshared_key.as_deref().unwrap()),
            "preshared key leaked: {json}"
        );
        assert!(!json.contains(&server.private_key), "private key leaked");
    }

    #[test]
    fn detail_maps_kernel_assigned_port_to_none() {
        let mut server = sample_server("nexus");
        server.listen_port = 0; // kernel-assigned
        assert_eq!(server.detail().listen_port, None);
        server.listen_port = 51820;
        assert_eq!(server.detail().listen_port, Some(51820));
    }
}

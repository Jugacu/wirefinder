import { invoke } from "@tauri-apps/api/core";

// These mirror the Rust types in `wirefinder-proto`. serde serializes a unit enum
// variant as just its name string, hence the string-literal union for ConnState.
export type ConnState = "Alive" | "Connecting" | "Stale" | "Never";

/** A complete tunnel definition sent to add a server. `private_key: null` asks the
 *  daemon to generate one. Mirrors `wirefinder_proto::ServerSpec`. */
export interface ServerSpec {
  name: string;
  private_key: string | null;
  public_key: string; // the server's (peer's) public key
  endpoint: string;
  addresses: string[];
  allowed_ips: string[];
  listen_port: number | null;
  mtu: number | null;
  keepalive: number | null;
  preshared_key: string | null;
  dns: string[];
}

/** The safe list view: identity + our derived public key, never the private key. */
export interface ServerInfo {
  name: string;
  endpoint: string;
  addresses: string[];
  public_key: string; // OURS, derived — safe to show/copy
  active: boolean; // the SELECTED tunnel (identity loaded on the interface)
  // The active tunnel's live connection state, derived daemon-side like a peer's
  // `state`, so the server block renders consistently with the hero. null = inactive.
  state: ConnState | null;
}

/** The editable view of a stored tunnel: every field in `ServerSpec` except the
 *  secrets. The private key is never returned; `has_preshared_key` only reports
 *  whether one is stored (the value is never sent). Mirrors
 *  `wirefinder_proto::ServerDetail`. */
export interface ServerDetail {
  name: string;
  public_key: string; // the server's (peer's) public key
  endpoint: string;
  addresses: string[];
  allowed_ips: string[];
  listen_port: number | null;
  mtu: number | null;
  keepalive: number | null;
  has_preshared_key: boolean;
  dns: string[];
}

export interface PeerStatus {
  public_key: string;
  endpoint: string | null; // Rust Option<String> → null when absent
  allowed_ips: string[];
  state: ConnState;
  handshake_age_secs: number | null;
  rx_bytes: number;
  tx_bytes: number;
}

export interface InterfaceStatus {
  name: string;
  listen_port: number;
  peers: PeerStatus[];
}

// --- configuration ---
export const addServer = (server: ServerSpec) => invoke<ServerInfo[]>("add_server", { server });

/** Fetch the editable detail for one server (no secrets) to seed the edit form. */
export const getServer = (name: string) => invoke<ServerDetail>("get_server", { name });

/** Save edits to an existing server (identified by `server.name`). A null
 *  `private_key`/`preshared_key` means "keep the stored value". The daemon rejects
 *  editing the active tunnel. */
export const editServer = (server: ServerSpec) => invoke<ServerInfo[]>("edit_server", { server });

/** Import a wg-quick `.conf` (full text). The daemon parses, validates, and stores. */
export const importServer = (name: string, conf: string) =>
  invoke<ServerInfo[]>("import_server", { name, conf });

export const removeServer = (name: string) => invoke<ServerInfo[]>("remove_server", { name });

// --- status / control ---
export const listServers = () => invoke<ServerInfo[]>("list_servers");
// null when the daemon is reachable but the tunnel is down (disconnected).
export const getStatus = () => invoke<InterfaceStatus | null>("status");
export const switchServer = (name: string) => invoke<string>("switch_server", { name });
export const disconnect = () => invoke<void>("disconnect");

// --- tray ---
/** Push the connection summary to the tray (native tooltip on macOS/Windows,
 *  the menu header on Linux). */
export const setTraySummary = (summary: string) => invoke<void>("set_tray_summary", { summary });

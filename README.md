# wirefinder

A WireGuard endpoint switcher for Linux: a privileged daemon that owns the tunnel
interface, a desktop GUI that walks you through setup, and a CLI for everything the
GUI can do.

There is **no config file to edit**. Each "server" is a complete WireGuard tunnel —
its own private key, address, DNS, and peer — mirroring a wg-quick `.conf`. On first
launch you **import a `.conf`** (what providers like Mullvad/Proton hand out) or add
a self-hosted one by hand, in which case the daemon generates the keypair and shows
you the public key to register. You add servers on demand; the daemon persists
everything itself.

## Architecture

```
┌─────────────┐         Unix socket          ┌──────────────────────┐
│  GUI (Tauri)│  ───  /run/wirefinder/  ───▶  │  wirefinderd (root)  │
│  CLI        │       wirefinderd.sock        │  owns wg0, the keys, │
└─────────────┘   one JSON request/response   │  and /var/lib state  │
                                              └──────────────────────┘
```

Four crates plus the GUI, in a Cargo workspace (`Cargo.toml`):

| Path        | What it is                                                                 |
|-------------|----------------------------------------------------------------------------|
| `proto/`    | The IPC contract: `Request`/`Response` + shared types. serde-only, no deps. |
| `daemon/`   | `wirefinderd` — the privileged daemon. Split into focused modules (below).  |
| `cli/`      | `wirefinder` — the unprivileged client. Speaks only the protocol.           |
| `ui/`       | The Tauri + React desktop GUI (its own build; excluded from the workspace). |
| `install/`  | systemd unit, desktop launcher, maintainer scripts.                         |
| `release/`  | Packaging helper (`cargo deb`).                                             |

### Daemon modules (`daemon/src/`)

- **`keys`** — WireGuard key generation/derivation (wraps the crypto crate).
- **`config`** — the persisted state (`/var/lib/wirefinder/state.json`, written
  atomically at `0600` since every server holds a private key) and its accessors.
- **`wgconf`** — a small, tested wg-quick `.conf` parser (no INI dependency).
- **`wireguard`** — the kernel boundary. All netlink I/O lives behind the
  `Wireguard` trait; `KernelWireguard` is the real implementation. Pure
  validation/parsing helpers sit alongside it.
- **`daemon`** — the state machine: maps each request to a response and owns the
  connection-state policy. Generic over `Wireguard`, so it is unit-tested against
  an in-memory fake — no root, no kernel, no network.
- **`server`** — the Unix-socket transport (framing, accept loop, locked-down
  socket permissions, per-connection timeouts and request size cap).
- **`main`** — wiring + signal-handled teardown.

### The trust boundary

The daemon is the sole owner of cryptographic material. Each tunnel's **private key
is generated daemon-side (or imported once) and never appears in any response** —
clients only ever learn the derived public key. All keys live in the same `0600`
state file. The control socket lives in a `0750 root:wirefinder` directory and is
itself `0660 root:wirefinder`; group membership is how the unprivileged GUI is
allowed to talk to a root daemon.

## Development

```sh
# Build + test everything (no root needed — the kernel is mocked in tests).
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Run the daemon (needs root for CAP_NET_ADMIN). For a throwaway state file:
sudo WIREFINDER_STATE=/tmp/wf-state.json target/debug/wirefinderd

# CLI against the running daemon:
target/debug/wirefinder import ./mullvad-nyc.conf                          # import a wg-quick config
target/debug/wirefinder add home <server_pubkey> vpn.example.com:51820 10.0.0.2/24  # generates a key
target/debug/wirefinder servers
target/debug/wirefinder switch home

# GUI dev:
cd ui && pnpm install && pnpm tauri dev
```

## Packaging

`cd release && ./package.sh` builds the daemon, CLI, and GUI and produces a single
`.deb` (`cargo deb -p wirefinderd`). The package installs and starts the daemon
right away — no config step — and the GUI handles the rest.

> **Pre-release note:** the `state.json` format is not yet stable. This version moved
> the private key/address from a shared interface onto each server, so a state file
> from an earlier build won't load — delete `/var/lib/wirefinder/state.json` (and any
> dev `WIREFINDER_STATE` file) and re-onboard.

//! wirefinderd — the privileged daemon. Owns all WireGuard access and serves
//! status and control to unprivileged clients over a Unix domain socket.
//!
//! There is no admin-edited config file: the daemon starts with whatever state it
//! has persisted (empty on first run) and is configured entirely over IPC. Each
//! "server" is a complete tunnel with its own private key (generated daemon-side or
//! imported from a wg-quick `.conf`); those keys never leave this process — see
//! [`mod config`], [`mod keys`], and [`mod wgconf`].

mod config;
mod daemon;
mod keys;
mod server;
mod wgconf;
mod wireguard;

use std::fs;

use wirefinder_proto::SOCKET_PATH;

use crate::config::Store;
use crate::daemon::Daemon;
use crate::wireguard::{KernelWireguard, Wireguard};

fn main() -> std::io::Result<()> {
    let store = Store::new(config::default_state_path());
    let mut daemon = match Daemon::load(store, KernelWireguard::default()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("wirefinderd: state: {e}");
            std::process::exit(1);
        }
    };

    install_signal_handler();

    eprintln!(
        "wirefinderd: ready — {} server(s) configured",
        daemon.server_count()
    );

    let listener = server::bind()?;
    server::serve(&listener, &mut daemon);
    Ok(())
}

/// On SIGINT/SIGTERM, tear the tunnel down and remove the socket before exiting.
/// The handler runs on its own thread and can't borrow the `Daemon`, so it builds
/// a fresh kernel backend (which only needs the fixed interface name) to bring the
/// interface down. `systemctl stop` sends SIGTERM, so this doubles as the clean
/// shutdown path.
fn install_signal_handler() {
    ctrlc::set_handler(move || {
        eprintln!("\nwirefinderd: signal received, tearing down");
        if let Err(e) = KernelWireguard::default().disconnect() {
            eprintln!("wirefinderd: teardown failed: {e}");
        }
        let _ = fs::remove_file(SOCKET_PATH);
        std::process::exit(0);
    })
    .expect("failed to install signal handler");
}

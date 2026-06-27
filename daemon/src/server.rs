//! The Unix-socket server: framing and the accept loop. Pure transport — every
//! decision lives in [`Daemon::handle`]. One request line in, one response line
//! out, one connection at a time (the daemon is deliberately single-threaded).

use std::fs::{self, DirBuilder};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use wirefinder_proto::{Request, Response, SOCKET_PATH};

use crate::daemon::Daemon;
use crate::wireguard::Wireguard;

/// Cap a single request line. A control request is tiny (a key, an address); this
/// stops a buggy or hostile client from streaming gigabytes with no newline and
/// exhausting the root daemon's memory.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Per-connection I/O timeout. The daemon handles one client at a time, so a
/// client that connects and then stalls would otherwise wedge every other client
/// (including the GUI's poll loop) forever. This bounds that.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Bind the listener at [`SOCKET_PATH`].
pub fn bind() -> std::io::Result<UnixListener> {
    bind_at(Path::new(SOCKET_PATH))
}

/// Bind the control socket at `path`, replacing any stale socket, and lock it down
/// so only the owning user (or the `wirefinder` group, under systemd) can talk to
/// it. The socket accepts WRITE commands, so its containing directory is the real
/// gate: it is *created* `0750` (atomically, via `DirBuilder::mode`, so it is never
/// world-traversable for even an instant) and that restricted traversal is what
/// keeps the socket unreachable during the brief window between `bind()` and the
/// `chmod` below. Split out from [`bind`] so the permission logic is unit-testable
/// against a temp path without root.
fn bind_at(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        // recursive(true) is a no-op when the dir already exists (e.g. systemd's
        // RuntimeDirectory); the explicit set_permissions then enforces 0750 on
        // a pre-existing directory regardless of how it was created.
        DirBuilder::new().recursive(true).mode(0o750).create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o750))?;
        chown_to_invoking_user(dir)?;
    }

    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    chown_to_invoking_user(path)?;
    Ok(listener)
}

/// Dev convenience: when launched via `sudo`, hand `path` to the invoking user so
/// their (unprivileged) GUI can reach it. Under systemd there is no `SUDO_UID`, so
/// this is skipped and the unit's `Group=wirefinder` grants access instead.
fn chown_to_invoking_user(path: &Path) -> std::io::Result<()> {
    if let (Some(uid), Some(gid)) = (
        std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok()),
        std::env::var("SUDO_GID").ok().and_then(|v| v.parse().ok()),
    ) {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// Serve requests forever. Each accepted connection is handled to completion
/// before the next — fine for a single-user control socket, given the per-client
/// timeout above keeps one stalled client from blocking the rest.
pub fn serve<W: Wireguard>(listener: &UnixListener, daemon: &mut Daemon<W>) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle_client(s, daemon) {
                    eprintln!("wirefinderd: client error: {e}");
                }
            }
            Err(e) => eprintln!("wirefinderd: accept error: {e}"),
        }
    }
}

/// Read one request line, dispatch it, write one response line back. Framing only.
fn handle_client<W: Wireguard>(stream: UnixStream, daemon: &mut Daemon<W>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut reader = BufReader::new((&stream).take(MAX_REQUEST_BYTES));
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let response = dispatch(&line, daemon);

    let mut writer = &stream;
    serde_json::to_writer(&mut writer, &response)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Parse one request line and dispatch it, turning a parse failure into a tidy
/// `Error` response rather than dropping the connection. Pure (no socket), so the
/// malformed-input path is unit-testable.
fn dispatch<W: Wireguard>(line: &str, daemon: &mut Daemon<W>) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(req) => daemon.handle(req),
        Err(e) => Response::Error(format!("bad request: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, Store};
    use crate::wireguard::{LiveInterface, Wireguard};

    /// A no-op backend: the dispatch tests only care about request parsing.
    struct NullWg;
    impl Wireguard for NullWg {
        fn disconnect(&self) -> Result<(), String> {
            Ok(())
        }
        fn switch(&self, _: &ServerConfig) -> Result<(), String> {
            Ok(())
        }
        fn status(&self) -> Result<LiveInterface, String> {
            Err("down".into())
        }
    }

    fn daemon() -> (tempfile::TempDir, Daemon<NullWg>) {
        let dir = tempfile::tempdir().unwrap();
        let d = Daemon::load(Store::new(dir.path().join("state.json")), NullWg).unwrap();
        (dir, d)
    }

    #[test]
    fn malformed_request_becomes_a_tidy_error_not_a_dropped_connection() {
        let (_dir, mut d) = daemon();
        let resp = dispatch("this is not json\n", &mut d);
        match resp {
            Response::Error(e) => assert!(e.starts_with("bad request:"), "{e}"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_request_line_is_dispatched() {
        let (_dir, mut d) = daemon();
        let resp = dispatch("{\"ListServers\":{}}\n", &mut d);
        assert!(matches!(resp, Response::Servers(_)));
    }

    /// The control socket accepts privileged write commands, so its directory must
    /// be 0750 (group-only traversal) and the socket itself 0660. This pins the
    /// security-critical permission logic that protects a root daemon's socket.
    #[test]
    fn bind_locks_down_the_socket_directory_and_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("run/wirefinderd.sock");
        let listener = bind_at(&path).unwrap();
        drop(listener);

        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        let sock_mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            dir_mode & 0o777,
            0o750,
            "directory traversal must be group-only"
        );
        assert_eq!(
            sock_mode & 0o777,
            0o660,
            "socket must not be world-accessible"
        );
    }

    /// Binding over a stale socket from a previous run must succeed, not fail.
    #[test]
    fn bind_replaces_a_stale_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("wirefinderd.sock");
        drop(bind_at(&path).unwrap());
        // Second bind over the leftover socket file should still work.
        assert!(bind_at(&path).is_ok());
    }
}

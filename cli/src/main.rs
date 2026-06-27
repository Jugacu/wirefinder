//! wirefinder — the unprivileged client. Knows nothing about WireGuard: it speaks
//! only the IPC protocol and renders what the daemon says. The desktop GUI is the
//! primary way to onboard, but every operation is available here too.

use std::path::Path;
use std::process::exit;

use wirefinder_proto::{
    ConnState, PeerStatus, Request, Response, ServerDetail, ServerInfo, ServerSpec, request,
};

fn humanize(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = "B";
    for next in ["KiB", "MiB", "GiB"] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

fn print_peer(p: &PeerStatus) {
    let age = p.handshake_age_secs.unwrap_or(0);
    let status = match p.state {
        ConnState::Alive => format!("ALIVE ✓, {age}s ago"),
        ConnState::Connecting => "connecting…".to_string(),
        ConnState::Stale => format!("STALE, {age}s ago"),
        ConnState::Never => "never connected".to_string(),
    };

    println!("peer      {}…", &p.public_key[..12.min(p.public_key.len())]);
    println!("endpoint  {}", p.endpoint.as_deref().unwrap_or("-"));
    println!("allowed   {}", p.allowed_ips.join(", "));
    println!("handshake {status}");
    println!(
        "traffic   ↓ {}  ↑ {}",
        humanize(p.rx_bytes),
        humanize(p.tx_bytes)
    );
    println!();
}

fn print_servers(servers: &[ServerInfo], filter: Option<&str>) {
    if servers.is_empty() {
        match filter {
            // An active filter that matched nothing is a different story from an
            // un-onboarded daemon — don't tell the user to add a server.
            Some(q) => println!("no servers match {q:?}"),
            None => println!("no servers configured — add one with `wirefinder add …` or `import`"),
        }
        return;
    }
    println!("servers:");
    for s in servers {
        let marker = if s.active { "●" } else { " " };
        println!("{marker} {:<12} {}", s.name, s.endpoint);
        println!("    address  {}", s.addresses.join(", "));
        println!("    pubkey   {}", s.public_key);
    }
}

/// The editable detail of one server. Secret-free: the private key is never sent and
/// a stored preshared key shows only as "(set)".
fn print_detail(d: &ServerDetail) {
    println!("{}", d.name);
    println!("    peer pubkey  {}", d.public_key);
    println!("    endpoint     {}", d.endpoint);
    println!("    addresses    {}", d.addresses.join(", "));
    println!("    allowed ips  {}", d.allowed_ips.join(", "));
    if let Some(port) = d.listen_port {
        println!("    listen port  {port}");
    }
    if let Some(mtu) = d.mtu {
        println!("    mtu          {mtu}");
    }
    if let Some(ka) = d.keepalive {
        println!("    keepalive    {ka}s");
    }
    if !d.dns.is_empty() {
        println!("    dns          {}", d.dns.join(", "));
    }
    if d.has_preshared_key {
        println!("    preshared    (set)");
    }
}

fn print_usage() {
    println!("usage:");
    println!("  wirefinder add <name> <pubkey> <endpoint> <address> [allowed_ips]");
    println!("                                                  add a server (generates a key)");
    println!("  wirefinder import <file.conf> [name]            import a wg-quick config");
    println!("  wirefinder remove <name>                        forget a server");
    println!(
        "  wirefinder servers [query]                      list servers (optionally filtered)"
    );
    println!("  wirefinder get <name>                           show a server's editable detail");
    println!("  wirefinder switch <name>                        connect to a server");
    println!("  wirefinder disconnect                           tear the tunnel down");
    println!("  wirefinder info                                 live tunnel status");
}

/// Parse argv into a request. Returns `None` for usage errors (caller exits 2).
/// `import` is handled separately in `main` since it reads a file.
fn parse_request(args: &[String]) -> Option<Request> {
    match args {
        [cmd] if cmd == "info" => Some(Request::Status),
        [cmd] if cmd == "servers" => Some(Request::ListServers { query: None }),
        [cmd, query] if cmd == "servers" => Some(Request::ListServers {
            query: Some(query.clone()),
        }),
        [cmd] if cmd == "disconnect" => Some(Request::Disconnect),
        [cmd, name] if cmd == "switch" => Some(Request::SwitchServer { name: name.clone() }),
        [cmd, name] if cmd == "remove" => Some(Request::RemoveServer { name: name.clone() }),
        [cmd, name] if cmd == "get" => Some(Request::GetServer { name: name.clone() }),
        [cmd, name, public_key, endpoint, address, rest @ ..] if cmd == "add" => {
            // allowed_ips: optional comma-separated trailing arg; default to a full,
            // dual-stack tunnel so IPv6 doesn't leak outside the tunnel on a
            // dual-stack host. Listing only one family is respected as intent.
            let allowed_ips = match rest {
                [csv] => csv.split(',').map(|s| s.trim().to_string()).collect(),
                _ => vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            };
            Some(Request::AddServer {
                server: ServerSpec {
                    name: name.clone(),
                    private_key: None, // daemon generates a fresh keypair
                    public_key: public_key.clone(),
                    endpoint: endpoint.clone(),
                    addresses: vec![address.clone()],
                    allowed_ips,
                    listen_port: None,
                    mtu: None,
                    keepalive: Some(25),
                    preshared_key: None,
                    dns: vec![],
                },
            })
        }
        _ => None,
    }
}

/// Build an `ImportServer` request by reading the `.conf` file. `name` defaults to
/// the file stem (e.g. `mullvad-nyc.conf` → `mullvad-nyc`).
fn import_request(file: &str, name: Option<&str>) -> Result<Request, String> {
    let conf = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let name = name.map(String::from).unwrap_or_else(|| file_stem(file));
    Ok(Request::ImportServer { name, conf })
}

fn file_stem(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("imported")
        .to_string()
}

fn render(response: Response, filter: Option<&str>) {
    match response {
        Response::Status(s) => {
            println!("interface {}  port {}\n", s.name, s.listen_port);
            for peer in &s.peers {
                print_peer(peer);
            }
        }
        Response::Servers(servers) => print_servers(&servers, filter),
        Response::ServerDetail(d) => print_detail(&d),
        Response::Switched { name } => println!("switched to {name}"),
        Response::Disconnected => println!("disconnected — interface is down"),
        Response::Error(e) => {
            eprintln!("daemon error: {e}");
            exit(1);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // `import` reads a file, so it can't go through the pure `parse_request`.
    let req = match args.as_slice() {
        [cmd, file] if cmd == "import" => import_request(file, None),
        [cmd, file, name] if cmd == "import" => import_request(file, Some(name)),
        _ => parse_request(&args).ok_or_else(String::new),
    };

    let req = match req {
        Ok(req) => req,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}");
            } else {
                print_usage();
            }
            exit(2);
        }
    };

    // The list filter (if any) shapes the "empty" message, so carry it into render.
    let filter = match &req {
        Request::ListServers { query } => query.clone(),
        _ => None,
    };
    render(request(&req)?, filter.as_deref());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_simple_commands() {
        assert_eq!(parse_request(&argv(&["info"])), Some(Request::Status));
        assert_eq!(
            parse_request(&argv(&["servers"])),
            Some(Request::ListServers { query: None })
        );
        assert_eq!(
            parse_request(&argv(&["servers", "nyc"])),
            Some(Request::ListServers {
                query: Some("nyc".into())
            })
        );
        assert_eq!(
            parse_request(&argv(&["disconnect"])),
            Some(Request::Disconnect)
        );
        assert_eq!(
            parse_request(&argv(&["switch", "nexus"])),
            Some(Request::SwitchServer {
                name: "nexus".into()
            })
        );
        assert_eq!(
            parse_request(&argv(&["remove", "decoy"])),
            Some(Request::RemoveServer {
                name: "decoy".into()
            })
        );
    }

    #[test]
    fn removed_commands_are_no_longer_recognized() {
        // The bare `connect`, the old `setup`, and `configure` are all gone.
        assert_eq!(parse_request(&argv(&["connect"])), None);
        assert_eq!(parse_request(&argv(&["setup"])), None);
        assert_eq!(parse_request(&argv(&["configure", "51820"])), None);
    }

    #[test]
    fn add_generates_a_key_takes_an_address_and_splits_allowed_ips() {
        let Request::AddServer { server } =
            parse_request(&argv(&["add", "edge", "PUBKEY", "h:51820", "10.0.0.2/24"])).unwrap()
        else {
            panic!("expected AddServer");
        };
        assert_eq!(server.private_key, None, "the daemon generates the key");
        assert_eq!(server.addresses, vec!["10.0.0.2/24"]);
        // Default is a full, dual-stack tunnel so IPv6 doesn't leak.
        assert_eq!(server.allowed_ips, vec!["0.0.0.0/0", "::/0"]);

        let Request::AddServer { server } = parse_request(&argv(&[
            "add",
            "edge",
            "PUBKEY",
            "h:51820",
            "10.0.0.2/24",
            "10.0.0.0/24,192.168.1.0/24",
        ]))
        .unwrap() else {
            panic!("expected AddServer");
        };
        assert_eq!(server.allowed_ips, vec!["10.0.0.0/24", "192.168.1.0/24"]);
    }

    #[test]
    fn unknown_and_malformed_commands_are_rejected() {
        assert_eq!(parse_request(&argv(&["bogus"])), None);
        assert_eq!(parse_request(&argv(&["switch"])), None);
        // `add` without the required address is incomplete.
        assert_eq!(
            parse_request(&argv(&["add", "edge", "PUBKEY", "h:51820"])),
            None
        );
    }

    #[test]
    fn import_reads_a_file_and_defaults_the_name_to_the_stem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mullvad-nyc.conf");
        std::fs::write(&path, "[Interface]\n").unwrap();
        let p = path.to_str().unwrap();

        let Request::ImportServer { name, conf } = import_request(p, None).unwrap() else {
            panic!("expected ImportServer");
        };
        assert_eq!(name, "mullvad-nyc");
        assert_eq!(conf, "[Interface]\n");

        // An explicit name overrides the stem.
        let Request::ImportServer { name, .. } = import_request(p, Some("work")).unwrap() else {
            panic!("expected ImportServer");
        };
        assert_eq!(name, "work");
    }

    #[test]
    fn import_of_a_missing_file_errors() {
        assert!(import_request("/no/such/file.conf", None).is_err());
    }
}

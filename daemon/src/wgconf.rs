//! A small, dependency-free parser for wg-quick `.conf` files — the standard
//! artifact providers (Mullvad, Proton) and self-hosters hand out: one `[Interface]`
//! block (our identity) plus one `[Peer]` block (the server we connect to).
//!
//! This parser is deliberately STRUCTURAL only: it produces trimmed strings and
//! defers all cryptographic/network validation (keys parse, endpoint resolves,
//! CIDRs well-formed) to [`crate::wireguard::validate_server`], so an imported
//! config and a hand-added one go through the exact same validation path.

/// The lossless parse of a wg-quick `.conf`: the `[Interface]` fields plus the one
/// `[Peer]`. `name` is not part of a `.conf` — it is supplied by the import request.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedConfig {
    pub private_key: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u32>,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub preshared_key: Option<String>,
    pub keepalive: Option<u16>,
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Interface,
    Peer,
}

#[derive(Default)]
struct Iface {
    private_key: Option<String>,
    addresses: Vec<String>,
    dns: Vec<String>,
    listen_port: Option<u16>,
    mtu: Option<u32>,
}

#[derive(Default)]
struct PeerAcc {
    public_key: Option<String>,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    preshared_key: Option<String>,
    keepalive: Option<u16>,
}

/// Split a comma-separated value into trimmed, non-empty parts.
fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Set a scalar field, rejecting a duplicate within its section.
fn set_scalar(
    slot: &mut Option<String>,
    key: &str,
    value: &str,
    line: usize,
) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("line {line}: duplicate '{key}'"));
    }
    *slot = Some(value.to_string());
    Ok(())
}

fn parse_num<T: std::str::FromStr>(key: &str, value: &str, line: usize) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("line {line}: '{key}' must be a number, got '{value}'"))
}

/// Parse a wg-quick `.conf`. Returns the structural parse or a human-readable error
/// naming the problem (lowercase, no trailing period, matching the daemon's style).
pub fn parse(text: &str) -> Result<ParsedConfig, String> {
    let mut iface: Option<Iface> = None;
    let mut peers: Vec<PeerAcc> = Vec::new();
    let mut section: Option<Section> = None;

    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        // Strip a trailing CR (CRLF files) and any inline comment, then trim. Like
        // wg-quick / `wg`, only `#` starts a comment (not `;`); no parsed value
        // (base64 keys, host:port, CIDRs) ever legitimately contains `#`.
        let no_cr = raw.strip_suffix('\r').unwrap_or(raw);
        let content = match no_cr.find('#') {
            Some(idx) => &no_cr[..idx],
            None => no_cr,
        };
        let content = content.trim();
        if content.is_empty() {
            continue;
        }

        // Section header?
        if let Some(inner) = content.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let inner = inner.trim();
            if inner.eq_ignore_ascii_case("interface") {
                if iface.is_some() {
                    return Err("multiple [Interface] sections".into());
                }
                iface = Some(Iface::default());
                section = Some(Section::Interface);
            } else if inner.eq_ignore_ascii_case("peer") {
                peers.push(PeerAcc::default());
                section = Some(Section::Peer);
            } else {
                return Err(format!("unknown section '[{inner}]'"));
            }
            continue;
        }

        // key = value
        let Some((key, value)) = content.split_once('=') else {
            return Err(format!(
                "line {line}: expected 'key = value', got '{content}'"
            ));
        };
        let key = key.trim();
        let value = value.trim();
        let key_lc = key.to_ascii_lowercase();

        match section {
            None => return Err(format!("line {line}: '{key}' appears before any section")),
            Some(Section::Interface) => {
                let iface = iface.as_mut().expect("interface section started");
                match key_lc.as_str() {
                    "privatekey" => set_scalar(&mut iface.private_key, key, value, line)?,
                    "address" => iface.addresses.extend(csv(value)),
                    "dns" => iface.dns.extend(csv(value)),
                    "listenport" => iface.listen_port = Some(parse_num(key, value, line)?),
                    "mtu" => iface.mtu = Some(parse_num(key, value, line)?),
                    // Unknown [Interface] keys (Table, PreUp, SaveConfig, …) are ignored.
                    _ => {}
                }
            }
            Some(Section::Peer) => {
                let peer = peers.last_mut().expect("peer section started");
                match key_lc.as_str() {
                    "publickey" => set_scalar(&mut peer.public_key, key, value, line)?,
                    "endpoint" => set_scalar(&mut peer.endpoint, key, value, line)?,
                    "allowedips" => peer.allowed_ips.extend(csv(value)),
                    "presharedkey" => set_scalar(&mut peer.preshared_key, key, value, line)?,
                    "persistentkeepalive" => peer.keepalive = Some(parse_num(key, value, line)?),
                    _ => {}
                }
            }
        }
    }

    let iface = iface.ok_or("missing [Interface] section")?;
    if peers.is_empty() {
        return Err("missing [Peer] section".into());
    }
    if peers.len() > 1 {
        return Err(format!(
            "wirefinder supports one peer per config, found {}",
            peers.len()
        ));
    }
    let peer = peers.into_iter().next().expect("exactly one peer");

    let private_key = iface.private_key.ok_or("[Interface]: missing PrivateKey")?;
    if iface.addresses.is_empty() {
        return Err("[Interface]: missing Address".into());
    }
    let public_key = peer.public_key.ok_or("[Peer]: missing PublicKey")?;
    let endpoint = peer.endpoint.ok_or("[Peer]: missing Endpoint")?;
    // A VPN import with no AllowedIPs is almost always meant as a full tunnel; mirror
    // the CLI `add` default rather than producing a route-less tunnel.
    let allowed_ips = if peer.allowed_ips.is_empty() {
        vec!["0.0.0.0/0".to_string()]
    } else {
        peer.allowed_ips
    };

    Ok(ParsedConfig {
        private_key,
        addresses: iface.addresses,
        dns: iface.dns,
        listen_port: iface.listen_port,
        mtu: iface.mtu,
        public_key,
        endpoint,
        allowed_ips,
        preshared_key: peer.preshared_key,
        keepalive: peer.keepalive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "\
[Interface]
PrivateKey = aGVsbG8=
Address = 10.64.0.2/32, fc00:bbbb::2/128
DNS = 10.64.0.1, 1.1.1.1
ListenPort = 51820
MTU = 1380

[Peer]
PublicKey = c2VydmVy
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
PresharedKey = cHNr
PersistentKeepalive = 25
";

    #[test]
    fn parses_a_full_mullvad_style_config() {
        let c = parse(FULL).unwrap();
        assert_eq!(c.private_key, "aGVsbG8=");
        assert_eq!(c.addresses, vec!["10.64.0.2/32", "fc00:bbbb::2/128"]);
        assert_eq!(c.dns, vec!["10.64.0.1", "1.1.1.1"]);
        assert_eq!(c.listen_port, Some(51820));
        assert_eq!(c.mtu, Some(1380));
        assert_eq!(c.public_key, "c2VydmVy");
        assert_eq!(c.endpoint, "1.2.3.4:51820");
        assert_eq!(c.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(c.preshared_key.as_deref(), Some("cHNr"));
        assert_eq!(c.keepalive, Some(25));
    }

    #[test]
    fn parses_a_minimal_client_config() {
        let c = parse(
            "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/24\n\
             [Peer]\nPublicKey = p\nEndpoint = h:51820\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        assert_eq!(c.dns, Vec::<String>::new());
        assert_eq!(c.listen_port, None);
        assert_eq!(c.mtu, None);
        assert_eq!(c.keepalive, None);
        assert_eq!(c.preshared_key, None);
    }

    #[test]
    fn comments_blank_lines_and_crlf_are_handled() {
        let c = parse(
            "# a header comment\r\n\r\n[Interface]\r\nPrivateKey = k\r\n\
             Address = 10.0.0.2/24 # trailing\r\n\r\n[Peer]\r\nPublicKey = p\r\n\
             Endpoint = h:51820\r\nAllowedIPs = 0.0.0.0/0\r\n",
        )
        .unwrap();
        assert_eq!(c.private_key, "k");
        assert_eq!(c.addresses, vec!["10.0.0.2/24"]);
        assert_eq!(c.endpoint, "h:51820");
    }

    #[test]
    fn semicolon_is_not_a_comment_delimiter() {
        // wg-quick only treats `#` as a comment; a `;` stays part of the value
        // (and would then fail crypto validation downstream, not be silently cut).
        let c = parse(
            "[Interface]\nPrivateKey = k;x\nAddress = 10.0.0.2/24\n\
             [Peer]\nPublicKey = p\nEndpoint = h:51820\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        assert_eq!(c.private_key, "k;x");
    }

    #[test]
    fn sections_and_keys_are_case_insensitive() {
        let c = parse(
            "[interface]\nprivatekey = k\nADDRESS = 10.0.0.2/24\n\
             [PEER]\nPublicKey = p\nendPoint = h:51820\nallowedips = 0.0.0.0/0\n",
        )
        .unwrap();
        assert_eq!(c.private_key, "k");
        assert_eq!(c.endpoint, "h:51820");
    }

    #[test]
    fn whitespace_and_ragged_comma_lists_are_trimmed() {
        let c = parse(
            "[Interface]\nPrivateKey   =   k\nAddress = 10.0.0.2/24 ,10.0.0.3/24\n\
             [Peer]\nPublicKey=p\nEndpoint=h:51820\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        assert_eq!(c.addresses, vec!["10.0.0.2/24", "10.0.0.3/24"]);
    }

    #[test]
    fn list_keys_accumulate_across_repeats() {
        let c = parse(
            "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/24\n\
             [Peer]\nPublicKey = p\nEndpoint = h:51820\n\
             AllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/0\n",
        )
        .unwrap();
        assert_eq!(c.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let c = parse(
            "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/24\nTable = off\nPostUp = true\n\
             [Peer]\nPublicKey = p\nEndpoint = h:51820\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        assert_eq!(c.private_key, "k");
    }

    #[test]
    fn missing_allowed_ips_defaults_to_full_tunnel() {
        let c = parse(
            "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/24\n\
             [Peer]\nPublicKey = p\nEndpoint = h:51820\n",
        )
        .unwrap();
        assert_eq!(c.allowed_ips, vec!["0.0.0.0/0"]);
    }

    fn err(text: &str) -> String {
        parse(text).unwrap_err()
    }

    #[test]
    fn structural_errors_are_named() {
        assert!(err("").contains("missing [Interface]"));
        assert!(err("[Peer]\nPublicKey = p\nEndpoint = h:1\n").contains("missing [Interface]"));
        assert!(err("[Interface]\nPrivateKey = k\nAddress = a\n").contains("missing [Peer]"));
        assert!(
            err("[Interface]\nAddress = a\n[Peer]\nPublicKey = p\nEndpoint = h:1\n")
                .contains("missing PrivateKey")
        );
        assert!(
            err("[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nEndpoint = h:1\n")
                .contains("missing Address")
        );
        assert!(
            err("[Interface]\nPrivateKey = k\nAddress = a\n[Peer]\nEndpoint = h:1\n")
                .contains("missing PublicKey")
        );
        assert!(
            err("[Interface]\nPrivateKey = k\nAddress = a\n[Peer]\nPublicKey = p\n")
                .contains("missing Endpoint")
        );
    }

    #[test]
    fn multiple_peers_are_rejected() {
        let text = "[Interface]\nPrivateKey = k\nAddress = a\n\
                    [Peer]\nPublicKey = p1\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n\
                    [Peer]\nPublicKey = p2\nEndpoint = h:2\nAllowedIPs = 0.0.0.0/0\n";
        assert!(err(text).contains("one peer per config"));
    }

    #[test]
    fn multiple_interfaces_are_rejected() {
        assert!(err("[Interface]\nPrivateKey = k\n[Interface]\n").contains("multiple [Interface]"));
    }

    #[test]
    fn unknown_section_is_rejected() {
        assert!(err("[Bogus]\nx = y\n").contains("unknown section"));
    }

    #[test]
    fn key_value_before_a_section_is_rejected() {
        assert!(err("PrivateKey = k\n").contains("before any section"));
    }

    #[test]
    fn a_line_without_equals_is_rejected() {
        assert!(err("[Interface]\nPrivateKey foo\n").contains("expected 'key = value'"));
    }

    #[test]
    fn non_numeric_port_is_rejected() {
        let text = "[Interface]\nPrivateKey = k\nAddress = a\nListenPort = abc\n\
                    [Peer]\nPublicKey = p\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n";
        assert!(err(text).contains("must be a number"));
    }

    #[test]
    fn duplicate_scalar_key_is_rejected() {
        let text = "[Interface]\nPrivateKey = k\nPrivateKey = k2\nAddress = a\n\
                    [Peer]\nPublicKey = p\nEndpoint = h:1\n";
        assert!(err(text).contains("duplicate 'PrivateKey'"));
    }

    #[test]
    fn junk_input_errors_without_panicking() {
        assert!(parse("hello world").is_err());
        assert!(parse("\0\0\0").is_err());
    }
}

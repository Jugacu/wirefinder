//! WireGuard key helpers. Thin wrappers over the crypto crate so the rest of the
//! daemon talks in `String`s (base64) and never touches `Key` directly.

use std::str::FromStr;

use defguard_wireguard_rs::key::Key;

/// Generate a fresh WireGuard private key, base64-encoded.
#[must_use]
pub fn generate_private_key() -> String {
    Key::generate().to_string()
}

/// Derive the base64 public key from a base64 (or base16) private key. Also the
/// canonical "is this a valid key" check — it parses the input as a side effect.
pub fn public_key(private_key: &str) -> Result<String, String> {
    let key = Key::from_str(private_key.trim()).map_err(|e| format!("invalid private key: {e}"))?;
    Ok(key.public_key().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_yields_a_derivable_public_key() {
        let priv_key = generate_private_key();
        let pub_key = public_key(&priv_key).expect("derive public key");
        // Distinct keys, and the derivation is stable.
        assert_ne!(priv_key, pub_key);
        assert_eq!(public_key(&priv_key).unwrap(), pub_key);
    }

    #[test]
    fn generated_keys_are_unique() {
        assert_ne!(generate_private_key(), generate_private_key());
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let key = generate_private_key();
        let padded = format!("  {key}\n");
        assert!(public_key(&padded).is_ok());
    }

    #[test]
    fn garbage_is_rejected_with_a_named_error() {
        let err = public_key("not-a-key").unwrap_err();
        assert!(err.contains("private key"), "error names the field: {err}");
    }
}

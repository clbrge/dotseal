//! Dotseal core: per-value AES-256-GCM sealing for dotenv files.
//!
//! See `FORMAT.md` at the repository root for the envelope format, AAD
//! construction, and cross-language compatibility guarantees. See `CLI.md`
//! for the binary's stability contract.
//!
//! The two primary entry points are [`seal_value`] (encrypt) and
//! [`decrypt_value`] (decrypt). [`parse_env`] / [`decrypt_env`] handle
//! whole dotenv files. [`Plaintext`] wraps decrypt outputs in a
//! zeroize-on-drop string.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use indexmap::IndexMap;
use rand_core::{OsRng, RngCore};
use std::fmt;
use zeroize::Zeroizing;

/// Plaintext output type. The underlying `String` is zeroed on drop so that
/// the recovered secret does not linger in heap memory after the caller is
/// done with it. Loaders in non-Rust languages cannot offer the same guarantee
/// — see `FORMAT.md` for the documented divergence.
pub type Plaintext = Zeroizing<String>;

/// Envelope version emitted by [`seal_value`] and accepted by
/// [`decrypt_value`]. Bumping this constant is a coordinated breaking
/// change — see the Versioning section in `FORMAT.md`.
pub const VERSION: &str = "v1";

/// Scope name used by the CLI when no `-s/--scope` flag is given.
pub const DEFAULT_SCOPE: &str = "default";

/// Nonce length, in bytes, for AES-256-GCM in the v1 envelope.
pub const NONCE_LEN: usize = 12;

/// Master key length, in bytes.
pub const KEY_LEN: usize = 32;

/// Result alias parameterised over [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    ParseHexKey {
        source: std::num::ParseIntError,
    },
    ParseBase64Key {
        source: base64::DecodeError,
    },
    DecodedKeyLength {
        expected: usize,
        actual: usize,
    },
    KeyLength {
        expected: usize,
        actual: usize,
    },
    NonceLength {
        expected: usize,
        actual: usize,
    },
    EncryptFailed,
    UnsupportedEncryptedValue {
        name: String,
    },
    DecodeEncryptedValue {
        name: String,
        source: base64::DecodeError,
    },
    EncryptedValueTooShort {
        name: String,
    },
    DecryptFailed {
        name: String,
    },
    PlaintextNotUtf8 {
        name: String,
        source: std::string::FromUtf8Error,
    },
    InvalidEnvName {
        name: String,
    },
    InvalidScope {
        scope: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ParseHexKey { source } => write!(f, "parse hex key: {source}"),
            Error::ParseBase64Key { source } => write!(f, "parse base64url key: {source}"),
            Error::DecodedKeyLength { expected, .. } => {
                write!(f, "master key must decode to {expected} bytes")
            }
            Error::KeyLength { expected, .. } => write!(f, "master key must be {expected} bytes"),
            Error::NonceLength { expected, .. } => write!(f, "nonce must be {expected} bytes"),
            Error::EncryptFailed => f.write_str("encrypt failed"),
            Error::UnsupportedEncryptedValue { name } => {
                write!(f, "unsupported encrypted value for {name:?}")
            }
            Error::DecodeEncryptedValue { name, source } => {
                write!(f, "decode encrypted value for {name:?}: {source}")
            }
            Error::EncryptedValueTooShort { name } => {
                write!(f, "encrypted value for {name:?} is too short")
            }
            Error::DecryptFailed { name } => write!(f, "decrypt failed for {name:?}"),
            Error::PlaintextNotUtf8 { name, source } => {
                write!(f, "plaintext for {name:?} is not utf8: {source}")
            }
            Error::InvalidEnvName { name } => write!(f, "invalid env name: {name:?}"),
            Error::InvalidScope { scope } => write!(f, "invalid scope: {scope:?}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ParseHexKey { source } => Some(source),
            Error::ParseBase64Key { source } => Some(source),
            Error::DecodeEncryptedValue { source, .. } => Some(source),
            Error::PlaintextNotUtf8 { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Returns `true` if `value` carries the dotseal `enc:` prefix. This is a
/// cheap-and-cheerful classifier — actual decryption is what authenticates
/// the value.
pub fn is_encrypted_value(value: &str) -> bool {
    value.starts_with("enc:")
}

/// Generate a fresh 32-byte master key from the OS RNG. The returned `Vec<u8>`
/// is unprotected — wrap it in your zeroizing container of choice if it will
/// live longer than a single statement.
pub fn generate_key() -> Vec<u8> {
    let mut key = vec![0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encode a 32-byte master key as base64url **without padding**. Pair with
/// [`parse_key`] for round-tripping.
pub fn encode_key(key: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

/// Parse a master key. Accepts either base64url (with or without `=`
/// padding) or 64-character hex. Anything else is rejected.
pub fn parse_key(raw: &str) -> Result<Vec<u8>> {
    let raw = raw.trim();
    if raw.len() == KEY_LEN * 2 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = Vec::with_capacity(KEY_LEN);
        for i in (0..raw.len()).step_by(2) {
            let byte = u8::from_str_radix(&raw[i..i + 2], 16)
                .map_err(|source| Error::ParseHexKey { source })?;
            out.push(byte);
        }
        return Ok(out);
    }

    let key = decode_base64url(raw).map_err(|source| Error::ParseBase64Key { source })?;
    if key.len() != KEY_LEN {
        return Err(Error::DecodedKeyLength {
            expected: KEY_LEN,
            actual: key.len(),
        });
    }
    Ok(key)
}

/// Seal a plaintext into a `enc:v1:<base64url>` envelope using a fresh
/// 96-bit random nonce.
///
/// The ciphertext is bound to the `(scope, name)` tuple via AAD — moving
/// the result to a different `name` or `scope` makes it un-decryptable.
/// `scope` and `name` MUST validate per [`validate_scope`] / [`validate_name`];
/// anything else returns [`Error::InvalidScope`] / [`Error::InvalidEnvName`].
pub fn seal_value(plaintext: &str, key: &[u8], scope: &str, name: &str) -> Result<String> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    seal_value_with_nonce(plaintext, key, scope, name, &nonce_bytes)
}

/// As [`seal_value`] but with a caller-supplied nonce. Used for deterministic
/// test vectors. **Production callers MUST use [`seal_value`] instead** —
/// AES-GCM nonce reuse is catastrophic and there is no in-band detection.
pub fn seal_value_with_nonce(
    plaintext: &str,
    key: &[u8],
    scope: &str,
    name: &str,
    nonce_bytes: &[u8],
) -> Result<String> {
    validate_scope(scope)?;
    validate_name(name)?;
    if key.len() != KEY_LEN {
        return Err(Error::KeyLength {
            expected: KEY_LEN,
            actual: key.len(),
        });
    }
    if nonce_bytes.len() != NONCE_LEN {
        return Err(Error::NonceLength {
            expected: NONCE_LEN,
            actual: nonce_bytes.len(),
        });
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let aad = aad(scope, name);
    let ciphertext = cipher
        .encrypt(nonce, Payload {
            msg: plaintext.as_bytes(),
            aad: aad.as_bytes(),
        })
        .map_err(|_| Error::EncryptFailed)?;

    let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    Ok(format!("enc:{VERSION}:{}", URL_SAFE_NO_PAD.encode(payload)))
}

/// Decrypt a `enc:v1:<base64url>` envelope. Returns a [`Plaintext`] which
/// zero-fills its allocation on drop.
///
/// Plaintext is required to be valid UTF-8 (see `FORMAT.md`); non-UTF-8
/// authenticated payloads return [`Error::PlaintextNotUtf8`].
///
/// Values that don't carry the `enc:` prefix are returned unchanged (the
/// "passthrough plain values" pattern, used by [`decrypt_env`]).
///
/// `scope` and `name` are loosened relative to the seal-side regex — only
/// `\n` and `\r` are rejected. This is what makes
/// [`decryptTree`-style](https://github.com/clbrge/dotseal#decrypttree) dotted
/// paths work.
pub fn decrypt_value(
    value: &str,
    key: &[u8],
    scope: &str,
    name: &str,
) -> Result<Plaintext> {
    if !is_encrypted_value(value) {
        return Ok(Zeroizing::new(value.to_string()));
    }
    validate_scope(scope)?;
    validate_name(name)?;

    let mut parts = value.splitn(3, ':');
    let marker = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    let payload = parts.next().unwrap_or_default();

    if marker != "enc" || version != VERSION {
        return Err(Error::UnsupportedEncryptedValue {
            name: name.to_string(),
        });
    }

    let bytes = decode_base64url(payload).map_err(|source| Error::DecodeEncryptedValue {
        name: name.to_string(),
        source,
    })?;
    if bytes.len() <= NONCE_LEN {
        return Err(Error::EncryptedValueTooShort {
            name: name.to_string(),
        });
    }

    let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let aad = aad(scope, name);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), Payload {
            msg: ciphertext,
            aad: aad.as_bytes(),
        })
        .map_err(|_| Error::DecryptFailed {
            name: name.to_string(),
        })?;

    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|source| Error::PlaintextNotUtf8 {
            name: name.to_string(),
            source,
        })
}

/// Decrypt every encrypted entry in an env map produced by [`parse_env`].
/// Plaintext values pass through unchanged. Iteration order matches `env`
/// (file order if `env` came from `parse_env`).
pub fn decrypt_env(
    env: &IndexMap<String, String>,
    key: &[u8],
    scope: &str,
) -> Result<IndexMap<String, Plaintext>> {
    let mut out = IndexMap::with_capacity(env.len());
    for (name, value) in env {
        out.insert(name.clone(), decrypt_value(value, key, scope, name)?);
    }
    Ok(out)
}

/// Parse a dotenv-formatted string into `(name, value)` pairs.
///
/// Iteration order matches the order of definitions in `content`. When the
/// same name appears multiple times, the last definition wins and keeps the
/// position of the first occurrence (standard `IndexMap` insert behavior).
pub fn parse_env(content: &str) -> IndexMap<String, String> {
    let content = content.strip_prefix('\u{FEFF}').unwrap_or(content);
    content
        .lines()
        .filter_map(|line| {
            let name = env_line_name(line)?;
            let idx = line.find('=')?;
            Some((name, parse_env_value(&line[idx + 1..])))
        })
        .collect()
}

/// Parse the right-hand side of a single dotenv line (`KEY=...`) into a
/// value string. The behavior is documented in `FORMAT.md` § Dotenv parsing
/// and is part of the public commitment — changing it is a breaking change.
///
/// Highlights:
/// - Leading whitespace is trimmed.
/// - `"..."` is honored with backslash escapes (`\n`, `\r`, `\t`, `\"`, `\\`).
/// - `'...'` is taken literally.
/// - Otherwise unquoted: terminated by the first `#` at value-start or
///   preceded by space/tab; trailing whitespace is stripped.
pub fn parse_env_value(raw: &str) -> String {
    let trimmed_start = raw.trim_start();

    if let Some(rest) = trimmed_start.strip_prefix('"') {
        if let Some(end) = find_double_quote_end(rest) {
            return unescape_double_quoted(&rest[..end]);
        }
    } else if let Some(rest) = trimmed_start.strip_prefix('\'') {
        if let Some(end) = rest.find('\'') {
            return rest[..end].to_string();
        }
    }

    strip_inline_comment(trimmed_start).trim_end().to_string()
}

fn strip_inline_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return &value[..i];
        }
        i += 1;
    }
    value
}

fn find_double_quote_end(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Reject `name`s that don't match the env-name regex
/// (`[A-Za-z_][A-Za-z0-9_]*`). Intended for seal-side input validation.
pub fn validate_name(name: &str) -> Result<()> {
    if is_valid_name(name) {
        Ok(())
    } else {
        Err(Error::InvalidEnvName {
            name: name.to_string(),
        })
    }
}

/// Pure predicate version of [`validate_name`]. Cheap to call from filter
/// chains.
pub fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Reject `scope`s that don't match the seal-side regex
/// (`[A-Za-z0-9_.-]+`). The decrypt side uses a looser
/// no-`\n`/`\r` rule — see [`decrypt_value`].
pub fn validate_scope(scope: &str) -> Result<()> {
    if !scope.is_empty()
        && scope
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        Ok(())
    } else {
        Err(Error::InvalidScope {
            scope: scope.to_string(),
        })
    }
}

/// Extract the variable name from a single dotenv line. Returns `None` for
/// blank, comment, or malformed lines.
///
/// Strips an optional UTF-8 BOM, leading whitespace, and an optional
/// `export` keyword followed by space or tab (matching `parse_env`). The
/// returned name is validated with [`is_valid_name`].
pub fn env_line_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start_matches(|c: char| c == '\u{FEFF}' || c.is_whitespace());
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let rest = strip_export_prefix(trimmed).unwrap_or(trimmed);
    let idx = rest.find('=')?;
    let name = rest[..idx].trim();
    if is_valid_name(name) {
        Some(name.to_string())
    } else {
        None
    }
}

fn strip_export_prefix(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("export")?;
    let mut chars = rest.chars();
    let first = chars.next()?;
    if first == ' ' || first == '\t' {
        let trimmed_count = first.len_utf8()
            + rest[first.len_utf8()..]
                .chars()
                .take_while(|c| *c == ' ' || *c == '\t')
                .map(|c| c.len_utf8())
                .sum::<usize>();
        Some(&rest[trimmed_count..])
    } else {
        None
    }
}

/// Construct the AAD payload that binds a sealed value to a `(scope, name)`
/// tuple. The byte sequence is documented in `FORMAT.md` § Algorithm. The
/// trailing `\n` after `name=<NAME>` is part of the contract — every loader
/// reproduces it byte-for-byte.
///
/// Callers MUST validate `scope` and `name` against the AAD-injection
/// charset (no `\n`, no `\r`) before calling this; `seal_value_with_nonce`
/// and `decrypt_value` already do.
fn aad(scope: &str, name: &str) -> String {
    format!("dotseal:{VERSION}\nscope={scope}\nname={name}\n")
}

fn decode_base64url(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    if value.contains('=') {
        URL_SAFE.decode(value)
    } else {
        URL_SAFE_NO_PAD.decode(value)
    }
}

fn unescape_double_quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_binds_name_and_scope() {
        let key = [7u8; KEY_LEN];
        let sealed = seal_value("secret", &key, "production", "API_KEY").unwrap();
        assert_eq!(
            &**decrypt_value(&sealed, &key, "production", "API_KEY").unwrap(),
            "secret"
        );
        assert!(decrypt_value(&sealed, &key, "development", "API_KEY").is_err());
        assert!(decrypt_value(&sealed, &key, "production", "OTHER_KEY").is_err());
    }

    #[test]
    fn public_errors_are_typed() {
        match validate_scope("prod\nname=ADMIN").unwrap_err() {
            Error::InvalidScope { scope } => {
                assert_eq!(scope, "prod\nname=ADMIN");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn seal_rejects_invalid_scope_and_name() {
        let key = [7u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];

        assert!(seal_value_with_nonce(
            "secret",
            &key,
            "prod\nname=ADMIN",
            "API_KEY",
            &nonce,
        )
        .is_err());
        assert!(seal_value_with_nonce(
            "secret",
            &key,
            "production",
            "ADMIN\nname=API_KEY",
            &nonce,
        )
        .is_err());
    }

    #[test]
    fn decrypt_rejects_invalid_expected_scope_and_name() {
        let key = [7u8; KEY_LEN];
        let sealed = seal_value("secret", &key, "production", "API_KEY").unwrap();

        assert!(decrypt_value(&sealed, &key, "prod\nname=ADMIN", "API_KEY").is_err());
        assert!(decrypt_value(&sealed, &key, "production", "ADMIN\nname=API_KEY").is_err());
    }

    #[test]
    fn decrypt_rejects_authenticated_invalid_utf8_plaintext() {
        let key: Vec<u8> = (0..32).collect();
        let sealed = "enc:v1:aGlqa2xtbm9wcXJz0R30E2YLXTiKpdMVm3jkrejLYw";

        let err = decrypt_value(sealed, &key, "production", "BINARY_VALUE").unwrap_err();
        assert!(err.to_string().contains("not utf8"));
    }

    #[test]
    fn key_parser_accepts_base64url_and_hex() {
        let key = [3u8; KEY_LEN];
        let encoded = encode_key(&key);
        assert_eq!(parse_key(&encoded).unwrap(), key);
        assert_eq!(parse_key(&(encoded + "=")).unwrap(), key);
        assert_eq!(parse_key(&"03".repeat(KEY_LEN)).unwrap(), key);
    }

    #[test]
    fn decrypt_accepts_padded_base64url_payload() {
        let key: Vec<u8> = (0..32).collect();
        let sealed = "enc:v1:ICEiIyQlJicoKSoroV_FAgnsN3h7EDerj53e0Qpsr2lTDYsfbYmoIQ==";

        assert_eq!(
            &**decrypt_value(sealed, &key, "production", "API_SUPER_KEY").unwrap(),
            "secret-value"
        );
    }

    #[test]
    fn decrypt_rejects_mutations_and_downgrades() {
        let key: Vec<u8> = (0..32).collect();
        let nonce: Vec<u8> = (32..44).collect();
        let sealed = seal_value_with_nonce(
            "secret-value",
            &key,
            "production",
            "API_SUPER_KEY",
            &nonce,
        )
        .unwrap();

        assert!(decrypt_value("enc:v1:ICEi", &key, "production", "API_SUPER_KEY").is_err());
        assert!(decrypt_value(
            &sealed.replacen("enc:v1:", "enc:v0:", 1),
            &key,
            "production",
            "API_SUPER_KEY",
        )
        .is_err());
        assert!(decrypt_value(&sealed, &key, "development", "API_SUPER_KEY").is_err());
        assert!(decrypt_value(&sealed, &key, "production", "OTHER_KEY").is_err());

        let payload = payload_bytes(&sealed);
        for len in 0..payload.len() {
            let truncated = replace_payload(&sealed, &payload[..len]);
            assert!(
                decrypt_value(&truncated, &key, "production", "API_SUPER_KEY").is_err(),
                "accepted truncated payload length {len}",
            );
        }

        for index in 0..payload.len() {
            let mut mutated = payload.clone();
            mutated[index] ^= 0x01;
            let mutated = replace_payload(&sealed, &mutated);
            assert!(
                decrypt_value(&mutated, &key, "production", "API_SUPER_KEY").is_err(),
                "accepted bit flip at payload byte {index}",
            );
        }
    }

    #[test]
    fn parses_and_decrypts_env() {
        let key = [4u8; KEY_LEN];
        let sealed = seal_value("secret", &key, "production", "API_KEY").unwrap();
        let env = parse_env(&format!("API_KEY={sealed}\nPLAIN=value\n"));
        let decrypted = decrypt_env(&env, &key, "production").unwrap();
        assert_eq!(&***decrypted.get("API_KEY").unwrap(), "secret");
        assert_eq!(&***decrypted.get("PLAIN").unwrap(), "value");
    }

    #[test]
    fn roundtrip_edge_plaintexts() {
        let key: Vec<u8> = (0..32).collect();
        let long = "0123456789abcdef".repeat(64);
        let cases = [
            ("production", "EMPTY_VALUE", ""),
            ("production", "UNICODE_VALUE", "héllo 🌍 Привет こんにちは"),
            ("default", "DEFAULT_SECRET", "default-secret"),
            ("production", "LONG_VALUE", long.as_str()),
            ("production", "MULTILINE_VALUE", "line one\nline two\nline three"),
        ];

        for (index, (scope, name, plaintext)) in cases.into_iter().enumerate() {
            let nonce: Vec<u8> = ((index * NONCE_LEN)..((index + 1) * NONCE_LEN))
                .map(|value| value as u8)
                .collect();
            let sealed = seal_value_with_nonce(plaintext, &key, scope, name, &nonce).unwrap();
            assert_eq!(
                &**decrypt_value(&sealed, &key, scope, name).unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn parses_dotenv_quoted_values() {
        let env = parse_env(
            "PLAIN= value \nDOUBLE=\" hello world \"\nSINGLE=' keep spaces '\nESCAPED=\"line\\nnext\\t\\\"q\\\"\"\n",
        );
        assert_eq!(env.get("PLAIN").unwrap(), "value");
        assert_eq!(env.get("DOUBLE").unwrap(), " hello world ");
        assert_eq!(env.get("SINGLE").unwrap(), " keep spaces ");
        assert_eq!(env.get("ESCAPED").unwrap(), "line\nnext\t\"q\"");
    }

    #[test]
    fn parse_env_preserves_file_order() {
        let env = parse_env("ZEBRA=z\nALPHA=a\nMIDDLE=m\n");
        let names: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(names, ["ZEBRA", "ALPHA", "MIDDLE"]);
    }

    #[test]
    fn parse_env_dedup_keeps_last_value_at_first_position() {
        let env = parse_env("FIRST=1\nDUP=a\nSECOND=2\nDUP=b\n");
        let names: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(names, ["FIRST", "DUP", "SECOND"]);
        assert_eq!(env.get("DUP").unwrap(), "b");
    }

    #[test]
    fn parse_env_strips_utf8_bom() {
        let env = parse_env("\u{FEFF}FIRST=lost\nSECOND=kept\n");
        assert_eq!(env.get("FIRST").unwrap(), "lost");
        assert_eq!(env.get("SECOND").unwrap(), "kept");
    }

    #[test]
    fn parse_env_accepts_tab_after_export() {
        let env = parse_env("export\tTABBED=val\nNORMAL=ok\nexport   PADDED=padded\n");
        assert_eq!(env.get("TABBED").unwrap(), "val");
        assert_eq!(env.get("NORMAL").unwrap(), "ok");
        assert_eq!(env.get("PADDED").unwrap(), "padded");
    }

    #[test]
    fn parse_env_value_strips_inline_comments() {
        let env = parse_env(
            "PLAIN=value # trailing\nNOSPACE=foo#bar\nLEADING=  spaced   # tail\nEMPTYISH=#all comment\n",
        );
        assert_eq!(env.get("PLAIN").unwrap(), "value");
        assert_eq!(env.get("NOSPACE").unwrap(), "foo#bar");
        assert_eq!(env.get("LEADING").unwrap(), "spaced");
        assert_eq!(env.get("EMPTYISH").unwrap(), "");
    }

    #[test]
    fn parse_env_value_keeps_hash_inside_quotes() {
        let env = parse_env(
            "DOUBLE=\"with # inside\" # tail\nSINGLE='also # literal' # tail\nESCAPED=\"line\\nx#y\"\n",
        );
        assert_eq!(env.get("DOUBLE").unwrap(), "with # inside");
        assert_eq!(env.get("SINGLE").unwrap(), "also # literal");
        assert_eq!(env.get("ESCAPED").unwrap(), "line\nx#y");
    }

    #[test]
    fn parses_dotenv_edge_cases() {
        let env = parse_env(
            "\r\n# comment\r\nA=1\r\nexport B=\"two words\"\r\nC=left=right\r\nSPACED = value \r\nSINGLE=' a=b '\r\n",
        );

        assert_eq!(env.get("A").unwrap(), "1");
        assert_eq!(env.get("B").unwrap(), "two words");
        assert_eq!(env.get("C").unwrap(), "left=right");
        assert_eq!(env.get("SPACED").unwrap(), "value");
        assert_eq!(env.get("SINGLE").unwrap(), " a=b ");
        assert!(!env.contains_key("# comment"));
    }

    #[test]
    fn deterministic_vector_matches_shared_vector() {
        let key: Vec<u8> = (0..32).collect();
        let nonce: Vec<u8> = (32..44).collect();
        let sealed = seal_value_with_nonce(
            "secret-value",
            &key,
            "production",
            "API_SUPER_KEY",
            &nonce,
        )
        .unwrap();
        assert_eq!(
            sealed,
            "enc:v1:ICEiIyQlJicoKSoroV_FAgnsN3h7EDerj53e0Qpsr2lTDYsfbYmoIQ"
        );
    }

    fn payload_bytes(sealed: &str) -> Vec<u8> {
        let payload = sealed.rsplit_once(':').unwrap().1;
        decode_base64url(payload).unwrap()
    }

    fn replace_payload(sealed: &str, payload: &[u8]) -> String {
        let prefix = sealed.rsplit_once(':').unwrap().0;
        format!("{prefix}:{}", URL_SAFE_NO_PAD.encode(payload))
    }
}

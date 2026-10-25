//! The authorization server behind `ferry mcp serve --http` (ADR 0031, "Authorization server").
//!
//! Pure state and rules, no HTTP: dynamic client registration with a redirect allow-list,
//! single-use pairing codes, authorization codes with PKCE S256, opaque tokens kept as
//! hashes, rotating refresh tokens with reuse detection. Everything that depends on time
//! takes `now` (unix seconds) so tests can move the clock. State lives in machine-local
//! files under the state directory and is never synced.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The hosted claude.ai callback. Anything else must be a loopback address.
pub const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
/// Registrations kept at once (placeholder per ADR 0031).
pub const MAX_CLIENTS: usize = 50;
/// A registration nobody used expires after this long.
pub const UNUSED_CLIENT_SECS: i64 = 3600;
pub const ACCESS_SECS: i64 = 15 * 60;
pub const GRANT_SECS: i64 = 90 * 24 * 3600;
pub const CODE_SECS: i64 = 60;
pub const PAIRING_SECS: i64 = 10 * 60;
/// Wrong pairing codes tolerated in a window before `/authorize` locks.
pub const LOCKOUT_FAILURES: usize = 5;
pub const LOCKOUT_SECS: i64 = 600;

pub const SCOPE_READ: &str = "ferry:read";
pub const SCOPE_WRITE: &str = "ferry:write";

/// An OAuth error: the `error` code and a human sentence.
#[derive(Debug, Clone)]
pub struct OAuthError {
    pub code: &'static str,
    pub description: String,
}

pub fn oauth_error(code: &'static str, description: impl Into<String>) -> OAuthError {
    OAuthError {
        code,
        description: description.into(),
    }
}

#[must_use]
pub fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn sha_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
    hex::encode(buf)
}

/// Compare two secrets without stopping at the first difference.
#[must_use]
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Base64url without padding.
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// The S256 challenge for a verifier.
#[must_use]
pub fn s256(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}

fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// A redirect URI this server will ever send a code to: the hosted claude.ai callback, or
/// a loopback address over http (Claude Code picks any port). No fragments, no userinfo.
#[must_use]
pub fn allowed_redirect(uri: &str) -> bool {
    if uri == CLAUDE_CALLBACK {
        return true;
    }
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    if url.scheme() != "http"
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

// ---------------------------------------------------------------------------------------
// Pairing codes: minted by `ferry mcp pair`, read by the server. A separate small file so
// the CLI and the running server never write the same one.

#[derive(Serialize, Deserialize, Default)]
struct Pairing {
    /// `(sha256 of the code, expiry)`.
    codes: Vec<(String, i64)>,
}

fn pairing_path(dir: &Path) -> PathBuf {
    dir.join("pairing.json")
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn read_pairing(dir: &Path) -> Pairing {
    std::fs::read_to_string(pairing_path(dir))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Mint a single-use pairing code valid for ten minutes. Only its hash is stored.
pub fn mint_pairing_code(dir: &Path, now: i64) -> Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut raw = [0u8; 10];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut raw);
    let letters: String = raw
        .iter()
        .map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char)
        .collect();
    let code = format!("{}-{}", &letters[..5], &letters[5..]);
    let mut pairing = read_pairing(dir);
    pairing.codes.retain(|(_, expires)| *expires > now);
    pairing.codes.push((sha_hex(&code), now + PAIRING_SECS));
    write_private(&pairing_path(dir), &serde_json::to_vec(&pairing)?)?;
    Ok(code)
}

/// Spend a pairing code: true once, if it is known and unexpired.
pub fn consume_pairing_code(dir: &Path, entered: &str, now: i64) -> bool {
    let entered = entered.trim().to_ascii_uppercase();
    let hash = sha_hex(&entered);
    let mut pairing = read_pairing(dir);
    let before = pairing.codes.len();
    let mut found = false;
    pairing.codes.retain(|(stored, expires)| {
        if *expires <= now {
            return false;
        }
        if !found && ct_eq(stored, &hash) {
            found = true;
            return false;
        }
        true
    });
    if (found || pairing.codes.len() != before)
        && let Ok(bytes) = serde_json::to_vec(&pairing)
    {
        let _ = write_private(&pairing_path(dir), &bytes);
    }
    found
}

// ---------------------------------------------------------------------------------------
// The store

#[derive(Serialize, Deserialize, Clone)]
struct Client {
    redirect_uris: Vec<String>,
    name: String,
    created: i64,
    used: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct Grant {
    client_id: String,
    agent: String,
    audience: String,
    scope: String,
    expires: i64,
    revoked: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct Access {
    grant: String,
    expires: i64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Refresh {
    grant: String,
    expires: i64,
    used: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct Data {
    clients: BTreeMap<String, Client>,
    grants: BTreeMap<String, Grant>,
    /// Keyed by the SHA-256 of the token. The tokens themselves are never stored.
    access: BTreeMap<String, Access>,
    refresh: BTreeMap<String, Refresh>,
}

struct AuthCode {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    audience: String,
    scope: String,
    agent: String,
    expires: i64,
}

/// What `/authorize` has validated and the pairing code has unlocked.
pub struct CodeRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub challenge: &'a str,
    pub audience: &'a str,
    pub scope: &'a str,
    pub agent: &'a str,
}

pub struct Store {
    path: Option<PathBuf>,
    data: Data,
    codes: HashMap<String, AuthCode>,
    /// Spent authorization codes and the grant they made, so a replay revokes it.
    spent: HashMap<String, String>,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        let path = dir.join("oauth.json");
        let data = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("{} is not valid", path.display()))?,
            Err(_) => Data::default(),
        };
        Ok(Self {
            path: Some(path),
            data,
            codes: HashMap::new(),
            spent: HashMap::new(),
        })
    }

    fn persist(&self) {
        if let Some(path) = &self.path
            && let Ok(bytes) = serde_json::to_vec(&self.data)
            && let Err(err) = write_private(path, &bytes)
        {
            eprintln!("mcp: could not save {}: {err:#}", path.display());
        }
    }

    fn prune(&mut self, now: i64) {
        self.data
            .clients
            .retain(|_, c| c.used || c.created + UNUSED_CLIENT_SECS > now);
        self.data.access.retain(|_, a| a.expires > now);
        self.data.refresh.retain(|_, r| r.expires > now);
        self.data.grants.retain(|_, g| g.expires > now);
        self.codes.retain(|_, c| c.expires > now);
    }

    /// Dynamic client registration (RFC 7591), fenced: public clients only, redirect URIs
    /// on the allow-list, capped, unused ones expire.
    pub fn register(&mut self, body: &Value, now: i64) -> Result<Value, OAuthError> {
        self.prune(now);
        let uris: Vec<String> = body
            .get("redirect_uris")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if uris.is_empty() || uris.len() > 5 {
            return Err(oauth_error(
                "invalid_redirect_uri",
                "redirect_uris must list one to five URIs",
            ));
        }
        if let Some(bad) = uris.iter().find(|u| !allowed_redirect(u)) {
            return Err(oauth_error(
                "invalid_redirect_uri",
                format!(
                    "{} is not allowed: only {CLAUDE_CALLBACK} and loopback addresses are",
                    bad.chars().take(80).collect::<String>()
                ),
            ));
        }
        if let Some(method) = body
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            && method != "none"
        {
            return Err(oauth_error(
                "invalid_client_metadata",
                "only public clients (token_endpoint_auth_method none) are supported",
            ));
        }
        if self.data.clients.len() >= MAX_CLIENTS {
            return Err(oauth_error(
                "invalid_client_metadata",
                "too many registrations; try again later",
            ));
        }
        let name: String = body
            .get("client_name")
            .and_then(Value::as_str)
            .unwrap_or("an app")
            .chars()
            .filter(|c| !c.is_control())
            .take(60)
            .collect();
        let id = format!("fmcp_c_{}", random_hex(16));
        self.data.clients.insert(
            id.clone(),
            Client {
                redirect_uris: uris.clone(),
                name: name.clone(),
                created: now,
                used: false,
            },
        );
        self.persist();
        Ok(json!({
            "client_id": id,
            "client_name": name,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_id_issued_at": now,
        }))
    }

    #[must_use]
    pub fn client_name(&self, client_id: &str) -> Option<String> {
        self.data.clients.get(client_id).map(|c| c.name.clone())
    }

    /// Is `redirect_uri` exactly one this client registered?
    #[must_use]
    pub fn redirect_ok(&self, client_id: &str, redirect_uri: &str) -> bool {
        self.data
            .clients
            .get(client_id)
            .is_some_and(|c| c.redirect_uris.iter().any(|u| u == redirect_uri))
    }

    /// A one-minute authorization code, kept in memory only.
    pub fn issue_code(&mut self, request: &CodeRequest<'_>, now: i64) -> String {
        self.prune(now);
        let code = format!("fmcp_code_{}", random_hex(32));
        self.codes.insert(
            sha_hex(&code),
            AuthCode {
                client_id: request.client_id.into(),
                redirect_uri: request.redirect_uri.into(),
                challenge: request.challenge.into(),
                audience: request.audience.into(),
                scope: request.scope.into(),
                agent: request.agent.into(),
                expires: now + CODE_SECS,
            },
        );
        code
    }

    fn mint(&mut self, grant_id: &str, now: i64) -> Value {
        let access = format!("fmcp_at_{}", random_hex(32));
        let refresh = format!("fmcp_rt_{}", random_hex(32));
        let grant = self.data.grants.get(grant_id).cloned();
        let expires = grant.as_ref().map_or(now, |g| g.expires);
        self.data.access.insert(
            sha_hex(&access),
            Access {
                grant: grant_id.into(),
                expires: (now + ACCESS_SECS).min(expires),
            },
        );
        self.data.refresh.insert(
            sha_hex(&refresh),
            Refresh {
                grant: grant_id.into(),
                expires,
                used: false,
            },
        );
        self.persist();
        json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_SECS,
            "refresh_token": refresh,
            "scope": grant.map(|g| g.scope).unwrap_or_default(),
        })
    }

    fn revoke(&mut self, grant_id: &str) {
        if let Some(grant) = self.data.grants.get_mut(grant_id) {
            grant.revoked = true;
        }
        self.data.access.retain(|_, a| a.grant != grant_id);
        self.data.refresh.retain(|_, r| r.grant != grant_id);
        self.persist();
    }

    /// `grant_type=authorization_code`.
    pub fn exchange_code(
        &mut self,
        form: &HashMap<String, String>,
        audience: &str,
        now: i64,
    ) -> Result<Value, OAuthError> {
        self.prune(now);
        let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
        let hash = sha_hex(get("code"));
        if let Some(grant) = self.spent.get(&hash).cloned() {
            // A replayed code: whatever it made is revoked.
            self.revoke(&grant);
            return Err(oauth_error(
                "invalid_grant",
                "authorization code already used",
            ));
        }
        let Some(code) = self.codes.remove(&hash) else {
            return Err(oauth_error("invalid_grant", "unknown or expired code"));
        };
        if code.client_id != get("client_id") || code.redirect_uri != get("redirect_uri") {
            return Err(oauth_error(
                "invalid_grant",
                "client or redirect_uri mismatch",
            ));
        }
        let verifier = get("code_verifier");
        if !valid_verifier(verifier) || !ct_eq(&s256(verifier), &code.challenge) {
            return Err(oauth_error("invalid_grant", "PKCE verification failed"));
        }
        check_resource(form, audience, &code.audience)?;
        let grant_id = format!("g_{}", random_hex(12));
        self.data.grants.insert(
            grant_id.clone(),
            Grant {
                client_id: code.client_id.clone(),
                agent: code.agent,
                audience: code.audience,
                scope: code.scope,
                expires: now + GRANT_SECS,
                revoked: false,
            },
        );
        if let Some(client) = self.data.clients.get_mut(&code.client_id) {
            client.used = true;
        }
        self.spent.insert(hash, grant_id.clone());
        Ok(self.mint(&grant_id, now))
    }

    /// `grant_type=refresh_token`: rotates; a spent token presented again revokes the grant.
    pub fn refresh(
        &mut self,
        form: &HashMap<String, String>,
        audience: &str,
        now: i64,
    ) -> Result<Value, OAuthError> {
        self.prune(now);
        let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
        let dead = || oauth_error("invalid_grant", "refresh token is not valid");
        let hash = sha_hex(get("refresh_token"));
        let Some(token) = self.data.refresh.get(&hash).cloned() else {
            return Err(dead());
        };
        let grant = self.data.grants.get(&token.grant).cloned();
        let Some(grant) = grant.filter(|g| !g.revoked) else {
            return Err(dead());
        };
        if token.used {
            self.revoke(&token.grant);
            return Err(dead());
        }
        if grant.client_id != get("client_id") {
            return Err(dead());
        }
        check_resource(form, audience, &grant.audience)?;
        if let Some(entry) = self.data.refresh.get_mut(&hash) {
            entry.used = true;
        }
        Ok(self.mint(&token.grant, now))
    }

    /// Is `token` a live access token for this audience and this agent?
    #[must_use]
    pub fn verify_access(&self, token: &str, audience: &str, agent: &str, now: i64) -> bool {
        let Some(access) = self.data.access.get(&sha_hex(token)) else {
            return false;
        };
        let Some(grant) = self.data.grants.get(&access.grant) else {
            return false;
        };
        access.expires > now
            && grant.expires > now
            && !grant.revoked
            && grant.audience == audience
            && grant.agent == agent
    }
}

/// RFC 8707: a `resource` that is sent must be the canonical MCP URL, and the grant's
/// audience must still be it.
fn check_resource(
    form: &HashMap<String, String>,
    audience: &str,
    granted: &str,
) -> Result<(), OAuthError> {
    if granted != audience {
        return Err(oauth_error(
            "invalid_target",
            "the grant is for another resource",
        ));
    }
    match form.get("resource") {
        Some(resource) if resource != audience => Err(oauth_error(
            "invalid_target",
            format!("resource must be {audience}"),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUD: &str = "https://mcp.example.com/mcp";

    fn store() -> Store {
        Store {
            path: None,
            data: Data::default(),
            codes: HashMap::new(),
            spent: HashMap::new(),
        }
    }

    fn client(store: &mut Store, now: i64) -> String {
        store
            .register(&json!({ "redirect_uris": [CLAUDE_CALLBACK] }), now)
            .unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn form(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn tokens(store: &mut Store, client: &str, now: i64) -> Value {
        let code = store.issue_code(
            &CodeRequest {
                client_id: client,
                redirect_uri: CLAUDE_CALLBACK,
                challenge: &s256(VERIFIER),
                audience: AUD,
                scope: SCOPE_READ,
                agent: "claude-ai",
            },
            now,
        );
        store
            .exchange_code(
                &form(&[
                    ("code", &code),
                    ("client_id", client),
                    ("redirect_uri", CLAUDE_CALLBACK),
                    ("code_verifier", VERIFIER),
                ]),
                AUD,
                now,
            )
            .unwrap()
    }

    #[test]
    fn s256_matches_the_rfc_7636_example() {
        assert_eq!(
            s256(VERIFIER),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn redirects_are_allow_listed() {
        assert!(allowed_redirect(CLAUDE_CALLBACK));
        assert!(allowed_redirect("http://127.0.0.1:53211/callback"));
        assert!(allowed_redirect("http://localhost:8080/cb"));
        assert!(allowed_redirect("http://[::1]:9/cb"));
        assert!(!allowed_redirect("https://evil.example/cb"));
        assert!(!allowed_redirect(
            "https://claude.ai/api/mcp/auth_callback/x"
        ));
        assert!(!allowed_redirect("http://claude.ai/api/mcp/auth_callback"));
        assert!(!allowed_redirect("http://127.0.0.1.evil.example/cb"));
        assert!(!allowed_redirect("http://user@127.0.0.1/cb"));
    }

    #[test]
    fn registration_is_capped_and_unused_ones_expire() {
        let mut s = store();
        for _ in 0..MAX_CLIENTS {
            client(&mut s, 0);
        }
        assert!(
            s.register(&json!({ "redirect_uris": [CLAUDE_CALLBACK] }), 10)
                .is_err()
        );
        // An hour later the unused ones are gone.
        assert!(
            s.register(
                &json!({ "redirect_uris": [CLAUDE_CALLBACK] }),
                UNUSED_CLIENT_SECS + 1
            )
            .is_ok()
        );
        let bad = s.register(&json!({ "redirect_uris": ["https://evil.example/cb"] }), 0);
        assert_eq!(bad.unwrap_err().code, "invalid_redirect_uri");
    }

    #[test]
    fn a_code_works_once_and_a_replay_revokes_the_grant() {
        let mut s = store();
        let c = client(&mut s, 0);
        let code = s.issue_code(
            &CodeRequest {
                client_id: &c,
                redirect_uri: CLAUDE_CALLBACK,
                challenge: &s256(VERIFIER),
                audience: AUD,
                scope: SCOPE_READ,
                agent: "a",
            },
            0,
        );
        let f = form(&[
            ("code", &code),
            ("client_id", &c),
            ("redirect_uri", CLAUDE_CALLBACK),
            ("code_verifier", VERIFIER),
        ]);
        let first = s.exchange_code(&f, AUD, 1).unwrap();
        let access = first["access_token"].as_str().unwrap().to_string();
        assert!(s.verify_access(&access, AUD, "a", 2));
        assert_eq!(
            s.exchange_code(&f, AUD, 3).unwrap_err().code,
            "invalid_grant"
        );
        assert!(!s.verify_access(&access, AUD, "a", 4));
    }

    #[test]
    fn pkce_and_audience_are_enforced() {
        let mut s = store();
        let c = client(&mut s, 0);
        let issue = |s: &mut Store| {
            s.issue_code(
                &CodeRequest {
                    client_id: &c,
                    redirect_uri: CLAUDE_CALLBACK,
                    challenge: &s256(VERIFIER),
                    audience: AUD,
                    scope: SCOPE_READ,
                    agent: "a",
                },
                0,
            )
        };
        let code = issue(&mut s);
        let wrong = form(&[
            ("code", &code),
            ("client_id", &c),
            ("redirect_uri", CLAUDE_CALLBACK),
            ("code_verifier", "x".repeat(50).as_str()),
        ]);
        assert_eq!(
            s.exchange_code(&wrong, AUD, 1).unwrap_err().code,
            "invalid_grant"
        );
        let code = issue(&mut s);
        let other = form(&[
            ("code", &code),
            ("client_id", &c),
            ("redirect_uri", CLAUDE_CALLBACK),
            ("code_verifier", VERIFIER),
            ("resource", "https://other.example/mcp"),
        ]);
        assert_eq!(
            s.exchange_code(&other, AUD, 1).unwrap_err().code,
            "invalid_target"
        );
        // A token minted for one audience does not pass for another.
        let t = tokens(&mut s, &c, 0);
        let access = t["access_token"].as_str().unwrap();
        assert!(s.verify_access(access, AUD, "claude-ai", 1));
        assert!(!s.verify_access(access, "https://other.example/mcp", "claude-ai", 1));
        assert!(!s.verify_access(access, AUD, "someone-else", 1));
    }

    #[test]
    fn refresh_rotates_and_reuse_revokes() {
        let mut s = store();
        let c = client(&mut s, 0);
        let t1 = tokens(&mut s, &c, 0);
        let r1 = t1["refresh_token"].as_str().unwrap().to_string();
        let t2 = s
            .refresh(&form(&[("refresh_token", &r1), ("client_id", &c)]), AUD, 5)
            .unwrap();
        let (r2, a2) = (
            t2["refresh_token"].as_str().unwrap().to_string(),
            t2["access_token"].as_str().unwrap().to_string(),
        );
        assert_ne!(r1, r2);
        assert!(s.verify_access(&a2, AUD, "claude-ai", 6));
        // The old refresh token again: the whole grant dies, including the new tokens.
        let again = s.refresh(&form(&[("refresh_token", &r1), ("client_id", &c)]), AUD, 7);
        assert_eq!(again.unwrap_err().code, "invalid_grant");
        assert!(!s.verify_access(&a2, AUD, "claude-ai", 8));
        let dead = s.refresh(&form(&[("refresh_token", &r2), ("client_id", &c)]), AUD, 9);
        assert_eq!(dead.unwrap_err().code, "invalid_grant");
    }

    #[test]
    fn access_tokens_expire_and_grants_end_at_ninety_days() {
        let mut s = store();
        let c = client(&mut s, 0);
        let t = tokens(&mut s, &c, 0);
        let access = t["access_token"].as_str().unwrap();
        assert!(s.verify_access(access, AUD, "claude-ai", ACCESS_SECS - 1));
        assert!(!s.verify_access(access, AUD, "claude-ai", ACCESS_SECS + 1));
        let r = t["refresh_token"].as_str().unwrap();
        let late = s.refresh(
            &form(&[("refresh_token", r), ("client_id", &c)]),
            AUD,
            GRANT_SECS + 1,
        );
        assert_eq!(late.unwrap_err().code, "invalid_grant");
    }

    #[test]
    fn pairing_codes_are_single_use_and_expire() {
        let dir = tempfile::tempdir().unwrap();
        let code = mint_pairing_code(dir.path(), 0).unwrap();
        assert!(
            !std::fs::read_to_string(pairing_path(dir.path()))
                .unwrap()
                .contains(&code)
        );
        assert!(!consume_pairing_code(dir.path(), "WRONG-CODE1", 1));
        assert!(consume_pairing_code(dir.path(), &code.to_lowercase(), 1));
        assert!(!consume_pairing_code(dir.path(), &code, 2));
        let late = mint_pairing_code(dir.path(), 0).unwrap();
        assert!(!consume_pairing_code(dir.path(), &late, PAIRING_SECS + 1));
    }

    #[test]
    fn tokens_are_stored_only_as_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let c = client(&mut s, 0);
        let t = tokens(&mut s, &c, 0);
        let on_disk = std::fs::read_to_string(dir.path().join("oauth.json")).unwrap();
        for key in ["access_token", "refresh_token"] {
            assert!(!on_disk.contains(t[key].as_str().unwrap()));
        }
        // And they survive a restart.
        let reopened = Store::open(dir.path()).unwrap();
        assert!(reopened.verify_access(t["access_token"].as_str().unwrap(), AUD, "claude-ai", 1));
    }
}

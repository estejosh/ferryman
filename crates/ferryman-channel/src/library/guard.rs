//! Secrets never go in the library.
//!
//! The library is read by every agent on every machine and by models, so a secret written
//! into it is a secret handed to the fleet. What it keeps instead is a *pointer*:
//! "NVIDIA key: Custodly, name nvidiaapi". This module is the guard on that rule. It is run
//! on every fact before it is signed, again when a fact is read back (so a line a hostile
//! writer put straight into a file is never shown, indexed or sent to a model), and on the
//! rows of the generated views.
//!
//! It is a shape check, in the spirit of gitleaks: known token prefixes, private-key
//! blocks, JSON web tokens, bot tokens, credentials inside URLs, `key=`/`token=`/
//! `password=` assignments whose value is not a pointer, and long high-entropy words. It
//! errs towards refusing, and what it refuses is told to store a pointer instead. It
//! never echoes the text it refused.

/// What a refused text looked like. Never the text itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    PrivateKeyBlock,
    KnownToken,
    Jwt,
    BotToken,
    UrlCredentials,
    Assignment,
    Password,
    HighEntropy,
}

impl Shape {
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::PrivateKeyBlock => "a private key block",
            Self::KnownToken => "an access token",
            Self::Jwt => "a signed web token",
            Self::BotToken => "a bot token",
            Self::UrlCredentials => "a web address with a password in it",
            Self::Assignment => "a key, token or secret with its value",
            Self::Password => "a password",
            Self::HighEntropy => "a long random-looking string",
        }
    }
}

/// Token prefixes that are a credential on their own, with the least total length of a
/// real one (so a word that merely starts the same way is left alone).
const PREFIXES: &[(&str, usize)] = &[
    ("ghp_", 40),
    ("gho_", 40),
    ("ghu_", 40),
    ("ghs_", 40),
    ("ghr_", 40),
    ("github_pat_", 40),
    ("glpat-", 26),
    ("sk-", 24),
    ("sk_live_", 24),
    ("sk_test_", 24),
    ("rk_live_", 24),
    ("xoxb-", 20),
    ("xoxp-", 20),
    ("xoxa-", 20),
    ("xoxr-", 20),
    ("xoxs-", 20),
    ("nvapi-", 30),
    ("hf_", 34),
    ("npm_", 40),
    ("SG.", 30),
    ("dop_v1_", 40),
    ("shpat_", 30),
    ("lin_api_", 30),
    ("tskey-", 20),
    ("ya29.", 30),
    ("gsk_", 30),
    ("r8_", 30),
    ("pplx-", 30),
    ("AIza", 39),
];

/// Names whose assignment is checked.
const TRIGGERS: &[&str] = &[
    "key",
    "token",
    "secret",
    "passw",
    "pwd",
    "credential",
    "auth",
    "bearer",
    "passphrase",
];

/// Values that point at where a secret lives rather than being one.
const POINTERS: &[&str] = &[
    "custodly",
    "vault",
    "keychain",
    "1password",
    "bitwarden",
    "n/a",
    "none",
    "unknown",
    "tbd",
    "redacted",
    "stored",
    "see",
    "name",
    "env",
    "set",
    "unset",
    "secrets",
    "ferryman",
    "channel",
    "sealed",
    "required",
    "optional",
    "yes",
    "no",
];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=' | '.' | '~')
}

/// Shannon entropy of `word` in bits per character.
fn entropy(word: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut total = 0f64;
    for c in word.chars() {
        *counts.entry(c).or_insert(0f64) += 1.0;
        total += 1.0;
    }
    if total == 0.0 {
        return 0.0;
    }
    counts
        .values()
        .map(|count| {
            let p = count / total;
            -p * p.log2()
        })
        .sum()
}

fn classes(word: &str) -> (bool, bool, bool) {
    (
        word.chars().any(|c| c.is_ascii_lowercase()),
        word.chars().any(|c| c.is_ascii_uppercase()),
        word.chars().any(|c| c.is_ascii_digit()),
    )
}

fn is_hex(word: &str) -> bool {
    !word.is_empty() && word.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// A private key block: a PEM header whose label says PRIVATE.
fn has_private_key_block(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    let mut from = 0;
    while let Some(at) = upper[from..].find("-----BEGIN") {
        let start = from + at;
        let end = (start + 80).min(upper.len());
        if upper.get(start..end).is_some_and(|w| w.contains("PRIVATE")) {
            return true;
        }
        from = start + "-----BEGIN".len();
    }
    false
}

fn has_prefixed_token(word: &str) -> bool {
    if word.len() >= 20
        && (word.starts_with("AKIA") || word.starts_with("ASIA"))
        && word
            .chars()
            .take(20)
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return true;
    }
    PREFIXES
        .iter()
        .any(|(prefix, least)| word.starts_with(prefix) && word.len() >= *least)
}

fn is_jwt(word: &str) -> bool {
    let parts: Vec<&str> = word.split('.').collect();
    parts.len() == 3 && word.starts_with("eyJ") && parts.iter().all(|part| part.len() >= 8)
}

/// `123456789:AAH...` - a Telegram bot token: digits, a colon, then a long run.
fn has_bot_token(text: &str) -> bool {
    for (at, _) in text.match_indices(':') {
        let digits = text[..at]
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .count();
        let after = text[at + 1..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            .count();
        if digits >= 6 && after >= 30 {
            return true;
        }
    }
    false
}

/// `scheme://user:password@host`.
fn has_url_credentials(text: &str) -> bool {
    for (at, _) in text.match_indices("://") {
        let authority: &str = text[at + 3..]
            .split(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#'))
            .next()
            .unwrap_or_default();
        if let Some((userinfo, _)) = authority.rsplit_once('@')
            && let Some((_, password)) = userinfo.split_once(':')
            && !password.is_empty()
        {
            return true;
        }
    }
    false
}

fn is_pointer(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    let lowered = lowered.trim_matches(|c: char| !c.is_alphanumeric() && c != '/');
    POINTERS.contains(&lowered)
        || value.starts_with(['$', '<', '{', '%', '*', '['])
        || value
            .chars()
            .all(|c| matches!(c, '*' | 'x' | 'X' | '.' | '#'))
}

/// Whether `value` (what follows `name=`) is a secret rather than a pointer or a word.
fn secret_value(name: &str, value: &str) -> Option<Shape> {
    let value = value.trim_matches(|c: char| matches!(c, '.' | ',' | ';' | ')' | '(' | '"' | '\''));
    if value.is_empty() || is_pointer(value) {
        return None;
    }
    let passwordish = name.contains("passw") || name.contains("pwd") || name.contains("phrase");
    if passwordish && value.chars().count() >= 4 {
        return Some(Shape::Password);
    }
    let (lower, upper, digit) = classes(value);
    let len = value.chars().count();
    if len >= 12 && digit && (lower || upper) && !value.contains(char::is_whitespace) {
        return Some(Shape::Assignment);
    }
    if len >= 16 && entropy(value) >= 3.8 {
        return Some(Shape::Assignment);
    }
    None
}

/// The name before a separator at `end`: the run of name characters, past any quote or
/// space, lower-cased.
fn name_before(text: &str, mut end: usize) -> String {
    while let Some(previous) = text[..end].chars().next_back() {
        if previous.is_whitespace() || matches!(previous, '"' | '\'' | '`') {
            end -= previous.len_utf8();
        } else {
            break;
        }
    }
    let start = text[..end]
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .last()
        .map_or(end, |(index, _)| index);
    text[start..end].to_ascii_lowercase()
}

/// `name = value`, `name: value`, `"name": "value"`, for the names in [`TRIGGERS`].
fn has_secret_assignment(text: &str) -> Option<Shape> {
    for (at, c) in text.char_indices() {
        if c != '=' && c != ':' {
            continue;
        }
        let name = name_before(text, at);
        if name.is_empty() || !TRIGGERS.iter().any(|trigger| name.contains(trigger)) {
            continue;
        }
        let rest = text[at + 1..].trim_start_matches(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '=' | '>')
        });
        let value: &str = rest
            .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | ';' | '&'))
            .next()
            .unwrap_or_default();
        // `key: value` in prose often names a place; only a value that is itself a secret
        // counts.
        if let Some(shape) = secret_value(&name, value) {
            return Some(shape);
        }
    }
    None
}

fn is_random_looking(word: &str) -> bool {
    let len = word.chars().count();
    if len < 24 || is_hex(word) {
        return false;
    }
    let (lower, upper, digit) = classes(word);
    let kinds = usize::from(lower) + usize::from(upper) + usize::from(digit);
    let h = entropy(word);
    (lower && upper && digit && h >= 3.9) || (len >= 40 && kinds >= 3 && h >= 4.3)
}

/// Whether `text` looks like it holds a secret, and what kind.
#[must_use]
pub fn scan(text: &str) -> Option<Shape> {
    if has_private_key_block(text) {
        return Some(Shape::PrivateKeyBlock);
    }
    if has_url_credentials(text) {
        return Some(Shape::UrlCredentials);
    }
    if has_bot_token(text) {
        return Some(Shape::BotToken);
    }
    for word in text.split(|c: char| !is_token_char(c)) {
        let word = word.trim_matches(|c: char| matches!(c, '.' | '-' | '_' | '/' | '~'));
        if word.len() < 8 {
            continue;
        }
        if has_prefixed_token(word) {
            return Some(Shape::KnownToken);
        }
        if is_jwt(word) {
            return Some(Shape::Jwt);
        }
        if is_random_looking(word) {
            return Some(Shape::HighEntropy);
        }
    }
    let lowered = text.to_ascii_lowercase();
    if let Some(at) = lowered.find("bearer ") {
        let value = lowered[at + 7..]
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if value.len() >= 16 && !is_pointer(value) {
            return Some(Shape::KnownToken);
        }
    }
    has_secret_assignment(text)
}

/// Refuse `text` if it looks like a secret. `label` names the field, for the message.
///
/// # Errors
/// What the text looked like and what to store instead. The text is never repeated.
pub fn check(label: &str, text: &str) -> Result<(), String> {
    match scan(text) {
        None => Ok(()),
        Some(shape) => Err(format!(
            "the {label} looks like {}. The library never holds a secret: store a pointer \
             instead, such as \"NVIDIA key: Custodly, name nvidiaapi\"",
            shape.describe()
        )),
    }
}

/// Whether anything in `fields` looks like a secret.
#[must_use]
pub fn any_secret(fields: &[&str]) -> bool {
    fields.iter().any(|field| scan(field).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const UPPER_DIGIT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const URL_SAFE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    const BASE64: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

    fn random(len: usize, alphabet: &[u8]) -> String {
        let mut rng = rand::rng();
        (0..len)
            .map(|_| {
                let mut byte = [0u8; 1];
                rng.fill_bytes(&mut byte);
                alphabet[usize::from(byte[0]) % alphabet.len()] as char
            })
            .collect()
    }

    /// Every shape, built at run time so no key-shaped literal sits in the source.
    fn shapes() -> Vec<(&'static str, String)> {
        let header = random(20, URL_SAFE);
        let claims = random(40, URL_SAFE);
        let signature = random(43, URL_SAFE);
        vec![
            ("github", format!("my token is ghp_{}", random(36, ALNUM))),
            (
                "github fine grained",
                format!("github_pat_{}", random(82, ALNUM)),
            ),
            ("openai style", format!("use sk-{} here", random(48, ALNUM))),
            (
                "anthropic style",
                format!("sk-ant-api03-{}", random(86, URL_SAFE)),
            ),
            ("aws", format!("AKIA{}", random(16, UPPER_DIGIT))),
            ("google", format!("AIza{}", random(35, URL_SAFE))),
            ("nvidia", format!("nvapi-{}", random(64, URL_SAFE))),
            (
                "slack",
                format!("xoxb-{}-{}", random(12, b"0123456789"), random(24, ALNUM)),
            ),
            ("huggingface", format!("hf_{}", random(34, ALNUM))),
            ("jwt", format!("eyJ{header}.eyJ{claims}.{signature}")),
            (
                "telegram",
                format!("{}:{}", random(9, b"0123456789"), random(35, URL_SAFE)),
            ),
            (
                "pem",
                format!(
                    "{} {} KEY-----\n{}\n-----END",
                    "-----BEGIN",
                    "OPENSSH PRIVATE",
                    random(60, ALNUM)
                ),
            ),
            (
                "rsa pem",
                format!("-----BEGIN {} KEY-----", String::from("RSA PRIVATE")),
            ),
            (
                "url password",
                format!("postgres://admin:{}@db.example.com/prod", random(14, ALNUM)),
            ),
            (
                "api key assignment",
                format!("api_key={}", random(32, ALNUM)),
            ),
            (
                "token json",
                format!("{{\"token\": \"{}\"}}", random(30, ALNUM)),
            ),
            (
                "env line",
                format!("NVIDIA_API_KEY={}", random(40, URL_SAFE)),
            ),
            ("password", "the db password: hunter2x".to_string()),
            ("password equals", "pwd=letmein99".to_string()),
            (
                "bearer",
                format!("Authorization: Bearer {}", random(40, URL_SAFE)),
            ),
            ("bare random", format!("it is {}", random(44, BASE64))),
        ]
    }

    #[test]
    fn every_secret_shape_is_refused_whatever_the_random_bytes() {
        for round in 0..25 {
            for (name, text) in shapes() {
                assert!(
                    scan(&text).is_some(),
                    "round {round}: {name} was not refused ({} chars)",
                    text.len()
                );
                let message = check("text", &text).unwrap_err();
                assert!(message.contains("pointer"), "{name}");
                // The refusal never repeats what it refused.
                let probe: String = text.chars().skip(text.len() / 2).take(12).collect();
                assert!(!message.contains(&probe), "{name} leaked into the message");
            }
        }
    }

    #[test]
    fn pointers_ids_hashes_and_prose_are_not_refused() {
        let sha1 = "a".repeat(40);
        let sha256: String = (0..64)
            .map(|i| char::from(b"0123456789abcdef"[i % 16]))
            .collect();
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        for text in [
            "NVIDIA key: Custodly, name nvidiaapi",
            "The GitHub token lives in Custodly under the name ghapp-ferryman.",
            "password: stored in Custodly",
            "api key is in the vault",
            "secret name: nvidiaapi (sealed in the ferryman channel for beastly)",
            "beastly runs Windows with WSL and an RTX 3090; grouchly is Ubuntu, always on.",
            "bullship is at focus until 2026-11-04; self-improve is on.",
            "token budget: 4000 per task",
            "the commit is deadbeef",
            "see crates/ferryman-channel/src/library/store.rs for the chain",
            "https://github.com/estejosh/ferryman/blob/HEAD/docs/LIBRARIAN.md",
            "key: value",
            "AWS access keys are rotated monthly",
            "set FERRYMAN_FOCUS_HOME to name another home project",
            "ssh key passphrase: see Custodly",
            "f-0a1b2c3d4e and m-9f8e7d6c5b are ids",
            "version 0.5.26 shipped on 2026-10-01",
        ] {
            assert!(scan(text).is_none(), "wrongly refused: {text}");
        }
        assert!(scan(&sha1).is_none(), "a git hash is not a secret");
        assert!(scan(&sha256).is_none(), "a sha256 is not a secret");
        assert!(scan(uuid).is_none(), "a bare uuid is not a secret");
        assert!(
            scan(&format!("the public key is {sha256}")).is_none(),
            "a public key in hex is not a secret"
        );
    }

    #[test]
    fn a_secret_inside_a_longer_sentence_is_still_found() {
        let token = format!("ghp_{}", random(36, ALNUM));
        let text = format!(
            "Deploys work again. Note for later: the old token was {token}, remove it please."
        );
        assert_eq!(scan(&text), Some(Shape::KnownToken));
        assert!(any_secret(&["fine", &text]));
        assert!(!any_secret(&["fine", "also fine"]));
    }
}

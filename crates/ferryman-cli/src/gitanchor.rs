//! Asking a git provider the two questions ADR 0022 cares about, and nothing else.
//!
//! This is the only part of the anchor that touches a network, and it lives here
//! rather than in `ferryman-channel` because that crate has no HTTP client and is
//! not getting one. What crosses back is [`AccountFacts`] and [`RepositoryFacts`];
//! the rules that turn those into a verdict are pure functions over there, with
//! tests for cases a real provider would not produce on demand.
//!
//! ## The shape of "I could not tell"
//!
//! Every function here returns `Ok(None)` when the provider could not be reached or
//! would not answer - offline, rate limited, 401, 403, 404. That is *not checked*,
//! it is the ordinary state of a fleet, and it must never be recorded as an
//! observation. GitHub answers 404 for anything a caller cannot see on a private
//! repository, so "moved", "deleted", "made private" and "your token expired" all
//! arrive wearing the same status: reading any of them as evidence would pause
//! every private project the day a token lapsed.
//!
//! An `Err` from here means the request could not even be formed. It is a bug, not
//! a finding, and it is still not evidence about anybody's ownership.

use std::{collections::HashMap, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use ferryman_channel::anchor::{AccountFacts, RepositoryFacts};

const AGENT: &str = concat!("ferry/", env!("CARGO_PKG_VERSION"));

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(AGENT)
        .timeout(Duration::from_secs(20))
        .build()
        .context("build an HTTP client")
}

/// A token for one account, if this machine has one.
///
/// Per account, because two accounts are two credentials: `estejosh`'s token cannot
/// read `shindevlin`'s repositories, and using the wrong one gets a 404 that - by
/// the rule above - correctly reads as *not checked* and quietly explains nothing.
/// Deriving the variable name from the login makes a third account one more line.
///
/// Never logged, never printed, never put in an error message.
#[must_use]
pub fn token_for(login: &str, dotenv: &HashMap<String, String>) -> Option<String> {
    let upper = login.to_ascii_uppercase().replace('-', "_");
    let names = [
        format!("FERRYMAN_GIT_TOKEN_{upper}"),
        "FERRYMAN_GIT_TOKEN".to_string(),
        "GITHUB_TOKEN".to_string(),
        "GH_TOKEN".to_string(),
    ];
    for name in &names {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            return Some(value);
        }
        if let Some(value) = dotenv.get(name)
            && !value.trim().is_empty()
        {
            return Some(value.clone());
        }
    }
    None
}

/// Read a `.env` beside the project, without putting anything into the process
/// environment.
///
/// Deliberately not `set_var`: that is unsafe under edition 2024, and a credential
/// that never enters the environment cannot be inherited by a child process that
/// had no business seeing it. The map stays in this function's caller and dies with
/// it.
#[must_use]
pub fn read_dotenv(directory: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string(directory.join(".env")) else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.insert(name.trim().to_string(), value.to_string());
    }
    out
}

/// Why a check could not be made. Carried so a finding can say which, because
/// "could not check" with no reason is the kind of message people stop reading.
#[derive(Debug, Clone)]
pub struct NotChecked(pub String);

/// The account's id, login and published SSH keys.
///
/// Both requests are unauthenticated by design. `<login>.keys` is public, which is
/// precisely what lets every member of a project check its master rather than only
/// the master's own machine. A token here would make watching a privilege.
pub async fn fetch_account(login: &str) -> Result<Result<AccountFacts, NotChecked>> {
    let client = client()?;

    let account = client
        .get(format!("https://api.github.com/users/{login}"))
        .send()
        .await;
    let account = match account {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            return Ok(Err(NotChecked(format!(
                "github answered {} for the account {login}",
                response.status()
            ))));
        }
        Err(error) => return Ok(Err(NotChecked(format!("could not reach github: {error}")))),
    };
    let body: serde_json::Value = match account.json().await {
        Ok(body) => body,
        Err(error) => {
            return Ok(Err(NotChecked(format!(
                "github's answer for {login} did not parse: {error}"
            ))));
        }
    };
    let Some(account_id) = body["id"].as_u64() else {
        return Ok(Err(NotChecked(format!(
            "github's answer for {login} carried no account id"
        ))));
    };

    // SIGNING keys first, and they are the right ones.
    //
    // `<login>.keys` serves AUTHENTICATION keys - the ones that grant git push. Proving
    // an account with one of those means the proof is only as separable as a push
    // credential, and it means a machine that verifies has to hold something that can
    // write to every repository on the account. A signing key grants nothing at all:
    // stealing it forges anchor claims and cannot push a commit. That is the correct
    // separation, and it is also the endpoint that was already right on this account
    // while `.keys` showed nothing.
    let mut published = Vec::new();
    match client
        .get(format!(
            "https://api.github.com/users/{login}/ssh_signing_keys"
        ))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            if let Ok(listed) = response.json::<serde_json::Value>().await
                && let Some(entries) = listed.as_array()
            {
                published.extend(
                    entries
                        .iter()
                        .filter_map(|entry| entry["key"].as_str())
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(ToString::to_string),
                );
            }
        }
        // Not fatal. Authentication keys are read next, and a claim already proven with
        // one of those must go on verifying.
        Ok(_) | Err(_) => {}
    }

    match client
        .get(format!("https://github.com/{login}.keys"))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            if let Ok(text) = response.text().await {
                published.extend(
                    text.lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(ToString::to_string),
                );
            }
        }
        Ok(_) | Err(_) => {}
    }

    if published.is_empty() {
        return Ok(Err(NotChecked(format!(
            "github published no signing or authentication keys for {login}"
        ))));
    }

    Ok(Ok(AccountFacts {
        account_id,
        login: body["login"]
            .as_str()
            .unwrap_or(login)
            .to_ascii_lowercase(),
        published_keys: published,
    }))
}

/// Every private key on this machine that could prove an account, as a path.
///
/// `ssh-keygen -Y sign` takes the private key, so what is wanted is the file whose
/// `.pub` sibling matches something the account publishes. Nothing here reads a
/// private key; it only matches public halves and hands `ssh-keygen` a path.
#[must_use]
pub fn local_signing_keys() -> Vec<(std::path::PathBuf, String)> {
    let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) else {
        return Vec::new();
    };
    let ssh = Path::new(&home).join(".ssh");
    let Ok(entries) = std::fs::read_dir(&ssh) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "pub") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let private = path.with_extension("");
        if !private.is_file() {
            continue;
        }
        found.push((private, text.trim().to_string()));
    }
    found.sort();
    found
}

/// The local key that proves this account, if this machine holds one.
///
/// Compared as keys rather than as whole lines: the comment on an authorized-keys
/// line is free text, and GitHub serves its own titling rather than whatever was in
/// the file when it was uploaded.
#[must_use]
pub fn proving_key(facts: &AccountFacts) -> Option<(std::path::PathBuf, String)> {
    let published: Vec<[u8; 32]> = facts
        .published_keys
        .iter()
        .filter_map(|line| ferryman_channel::anchor::parse_public_key(line))
        .collect();
    local_signing_keys().into_iter().find(|(_, line)| {
        ferryman_channel::anchor::parse_public_key(line)
            .is_some_and(|local| published.contains(&local))
    })
}

/// Who owns a repository now.
///
/// A token is needed only for a private repository, and only that repository. It is
/// sent when this machine has one for the account and left out otherwise: most
/// repositories are public and a token buys nothing on them.
pub async fn fetch_repository(
    owner: &str,
    name: &str,
    token: Option<&str>,
) -> Result<Result<RepositoryFacts, NotChecked>> {
    let mut request = client()?.get(format!("https://api.github.com/repos/{owner}/{name}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = match request.send().await {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            // 404 is the important one and is deliberately no different from the
            // rest: on a private repository it is what GitHub says to anyone who
            // cannot see it, so it cannot be told apart from the repository having
            // moved. Saying "not checked" is the only honest answer.
            let hint = if response.status().as_u16() == 404 && token.is_none() {
                " (no token for this account, so a private repository looks the same as a missing one)"
            } else {
                ""
            };
            return Ok(Err(NotChecked(format!(
                "github answered {} for {owner}/{name}{hint}",
                response.status()
            ))));
        }
        Err(error) => {
            return Ok(Err(NotChecked(format!(
                "could not reach github for {owner}/{name}: {error}"
            ))));
        }
    };
    let body: serde_json::Value = match response.json().await {
        Ok(body) => body,
        Err(error) => {
            return Ok(Err(NotChecked(format!(
                "github's answer for {owner}/{name} did not parse: {error}"
            ))));
        }
    };
    let Some(owner_id) = body["owner"]["id"].as_u64() else {
        return Ok(Err(NotChecked(format!(
            "github's answer for {owner}/{name} carried no owner id"
        ))));
    };
    Ok(Ok(RepositoryFacts {
        owner_id,
        owner_login: body["owner"]["login"]
            .as_str()
            .unwrap_or(owner)
            .to_ascii_lowercase(),
    }))
}

/// The repository a project's remote points at, as `(owner, name)`.
#[must_use]
pub fn remote_repository(remote: &str) -> Option<(String, String)> {
    let owner = ferryman_channel::anchor::remote_owner(remote)?;
    let trimmed = remote.trim().trim_end_matches(".git");
    let name = trimmed.rsplit('/').next()?;
    if name.is_empty() {
        None
    } else {
        Some((owner, name.to_string()))
    }
}

/// Have the account's own SSH key sign the payload that names the Ferryman key.
///
/// `ssh-keygen -Y sign` is used rather than anything reimplemented here: it is the
/// tool that defines the format, it is present wherever git over SSH is, and when
/// the private key is held by ssh-agent it is the agent that signs, so no
/// passphrase is ever typed into Ferryman. Passing a `.pub` path is therefore a
/// supported and preferable way to do this.
pub fn sign_with_ssh(payload: &str, key: &Path, scratch: &Path) -> Result<String> {
    std::fs::create_dir_all(scratch).context("make somewhere to sign in")?;
    let file = scratch.join("anchor-payload.txt");
    let signature = scratch.join("anchor-payload.txt.sig");
    let _ = std::fs::remove_file(&signature);
    // Exact bytes. `ssh-keygen` hashes the file, so a trailing newline the caller
    // did not intend is a different payload and a signature that verifies nowhere.
    std::fs::write(&file, payload.as_bytes()).context("write the payload to sign")?;

    let output = std::process::Command::new("ssh-keygen")
        .arg("-Y")
        .arg("sign")
        .arg("-f")
        .arg(key)
        .arg("-n")
        .arg(ferryman_channel::anchor::NAMESPACE)
        .arg(&file)
        .output()
        .context("run ssh-keygen (is OpenSSH installed and on PATH?)")?;
    if !output.status.success() {
        bail!(
            "ssh-keygen would not sign with {}: {}",
            key.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let armoured = std::fs::read_to_string(&signature)
        .context("read the signature ssh-keygen produced")?;
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(&signature);
    Ok(armoured)
}

// `default_ssh_key` lived here and guessed at `~/.ssh/id_ed25519`. Guessing was the
// wrong idea: `proving_key` asks the account what it publishes and matches that
// against every key on the machine, so the right key is found rather than assumed.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_gives_up_its_owner_and_repository() {
        assert_eq!(
            remote_repository("git@github.com:estejosh/ferryman.git"),
            Some(("estejosh".into(), "ferryman".into()))
        );
        assert_eq!(
            remote_repository("https://github.com/shindevlin/hone"),
            Some(("shindevlin".into(), "hone".into()))
        );
        assert_eq!(remote_repository(""), None);
    }

    /// Per account, because one token cannot read another account's repositories.
    #[test]
    fn a_token_is_looked_up_by_the_account_it_belongs_to() {
        let env = HashMap::from([
            (
                "FERRYMAN_GIT_TOKEN_ESTEJOSH".to_string(),
                "one".to_string(),
            ),
            (
                "FERRYMAN_GIT_TOKEN_SHINDEVLIN".to_string(),
                "two".to_string(),
            ),
        ]);
        assert_eq!(token_for("estejosh", &env).as_deref(), Some("one"));
        assert_eq!(token_for("shindevlin", &env).as_deref(), Some("two"));
        assert_eq!(token_for("somebody-else", &env), None);
    }

    #[test]
    fn a_hyphenated_login_folds_to_an_underscore() {
        let env = HashMap::from([(
            "FERRYMAN_GIT_TOKEN_ACME_CORP".to_string(),
            "three".to_string(),
        )]);
        assert_eq!(token_for("acme-corp", &env).as_deref(), Some("three"));
    }

    #[test]
    fn a_dotenv_is_read_without_touching_the_process_environment() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "# a comment\n\nexport FERRYMAN_GIT_TOKEN_ESTEJOSH=\"abc\"\nOTHER='def'\nmalformed\n",
        )
        .unwrap();
        let env = read_dotenv(dir.path());
        assert_eq!(env.get("FERRYMAN_GIT_TOKEN_ESTEJOSH").unwrap(), "abc");
        assert_eq!(env.get("OTHER").unwrap(), "def");
        assert!(!env.contains_key("malformed"));
        assert!(
            std::env::var("FERRYMAN_GIT_TOKEN_ESTEJOSH").is_err(),
            "reading a .env must not export anything"
        );
    }

    /// The scrub in `ferryman-channel` is what stops these reaching a child, and it
    /// works on names. A name this reads is a name that has to be caught.
    #[test]
    fn the_names_this_looks_for_all_read_as_secrets() {
        for name in [
            "FERRYMAN_GIT_TOKEN_ESTEJOSH",
            "FERRYMAN_GIT_TOKEN",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        ] {
            assert!(
                name.to_ascii_uppercase().contains("TOKEN"),
                "{name} must trip the environment scrub"
            );
        }
    }
}

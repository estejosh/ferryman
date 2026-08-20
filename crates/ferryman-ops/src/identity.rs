//! Which agent this machine is acting as.
//!
//! # Why this is its own module
//!
//! There used to be two copies of this logic, one in the CLI and one in `enable`, and
//! both were wrong in the same way: they read the `HOSTNAME` and `COMPUTERNAME`
//! environment variables and fell back to the literal string `"agent"` when neither was
//! set.
//!
//! `HOSTNAME` is a *shell* variable on Linux, not an exported one. It is absent from
//! every non-interactive process - which is every process an agent runs in. So the
//! documented default, "this machine's name", silently became `agent` on the machines
//! that matter most. The first outside user hit it within an hour.
//!
//! That is not a cosmetic default. The roster is keyed by filename, so two machines that
//! both take the fallback write `agents/agent.json` with *different public keys* into one
//! synced folder, and sync order decides which key survives. A system whose whole value
//! is signed provenance cannot have an identity that collides by default.
//!
//! Hence: ask the operating system for the hostname, and if that fails, **fail**. An
//! invented name that collides is worse than an error naming the flag that fixes it.

use anyhow::{Context, Result, bail};
use std::path::Path;

use crate::agent::AgentConfig;

/// This machine's name, lowercased and made path-safe.
///
/// Checked in this order because each step is more specific than the next: an operator
/// who set `FERRYMAN_AGENT` means it, and anyone else means their machine.
pub fn machine_name() -> Result<String> {
    let host = hostname::get()
        .context("ask the operating system for this machine's name")?
        .to_string_lossy()
        .into_owned();
    let forced = std::env::var("FERRYMAN_AGENT").ok();
    choose(forced.as_deref(), &host)
}

/// The decision, separated from where the two inputs came from.
///
/// Kept pure so the behaviour that broke - what happens when the environment says
/// nothing - can be tested without a test mutating the process environment, which under
/// Rust 2024 needs `unsafe` and which this crate forbids for good reason.
fn choose(forced: Option<&str>, host: &str) -> Result<String> {
    if let Some(forced) = forced.filter(|v| !v.trim().is_empty()) {
        let name = slug(forced);
        if name.is_empty() {
            bail!("FERRYMAN_AGENT is set to '{forced}', which has no usable characters")
        }
        return Ok(name);
    }
    // A hostname can be an FQDN; only the first label names the machine.
    let name = slug(host.split('.').next().unwrap_or(host));
    if name.is_empty() {
        bail!(
            "this machine's name ('{host}') has no characters usable in a path; \
             pass --agent to choose one"
        )
    }
    Ok(name)
}

/// The agent a command should act as.
///
/// The configured name is consulted *before* the hostname, which is the half of this the
/// CLI was missing entirely: `ferry channel work` never read `agent.toml`, so on a
/// correctly configured machine it announced "nothing for agent right now" while work sat
/// waiting. Every command that acts on behalf of an agent now resolves it the same way.
pub fn resolve(explicit: Option<String>, attachment: &Path) -> Result<String> {
    if let Some(name) = explicit {
        let slugged = slug(&name);
        if slugged.is_empty() {
            bail!("--agent '{name}' has no characters usable in a path")
        }
        return Ok(slugged);
    }
    if let Ok(config) = AgentConfig::load(attachment) {
        let configured = slug(&config.agent);
        if !configured.is_empty() {
            return Ok(configured);
        }
    }
    machine_name()
}

/// The name an unattended worker takes: `ichabod-<machine>-<engine>`.
///
/// # Three actors, not two
///
/// The operator is a person: they say what they want, and they sign with a key sealed
/// under their password because they are present to type it.
///
/// `fang` is an agent - an engine on that machine, with a human in the conversation.
/// It writes the orders, not the operator; what the operator supplied was intent. It is
/// not the person, and it is not unattended either.
///
/// `ichabod-fang-deepseek` is the same machine's agent running alone, on a schedule,
/// at three in the morning. Same hardware, same engine, nobody watching.
///
/// The middle one is easy to collapse into either neighbour and both collapses are wrong.
/// Called a person, it inherits an identity that cannot be signed with unattended. Called
/// the same as the unattended worker, a signature stops being able to say whether anyone
/// was there - and "was a human in the loop for this" is a question a ledger has to be
/// able to answer. So: `ichabod` marks the one that ran alone, and `fang` keeps its
/// key and its rosters, meaning what it already meant.
///
/// Supervision is the axis, not humanity. Both are machine identities with machine keys;
/// only the operator's is sealed. It is the same distinction [`crate::governor::presence`]
/// already acts on - a headless worker holds off when someone is at the keyboard - said
/// in the one place it can also be signed.
///
/// # Why the engine is in the name, and what that costs
///
/// It is there because two headless workers on one box are told apart by what they run,
/// and a name that cannot tell them apart is a name that needs a suffix invented later.
///
/// The cost is real and worth saying once: a worker that changes engine changes name, and
/// a changed name is a new identity to every roster. Its ledger history stays under the
/// old one. That is honest - it *was* a different worker - but it is not free, and nothing
/// should rewrite the old attributions to pretend otherwise.
///
/// # The short form is not this
///
/// `ichabodgd` is what a person says. It is never what gets signed, written to a roster,
/// or passed to `--agent`: a name that varies by context is a different identity every
/// time it varies, which is exactly what the roster's name-to-key pinning exists to catch.
/// Only the full form is ever written down, and only this function writes it.
#[must_use]
pub fn headless_name(machine: &str, engine: &str) -> String {
    let machine = slug(machine);
    let engine = slug(engine);
    match (machine.is_empty(), engine.is_empty()) {
        (true, true) => "ichabod".to_string(),
        (false, true) => format!("ichabod-{machine}"),
        (true, false) => format!("ichabod-{engine}"),
        (false, false) => format!("ichabod-{machine}-{engine}"),
    }
}

/// What to call the engine in a headless worker's name, given the CLI it runs.
///
/// A guess, and a deliberately shallow one: `ferryman-cline` is a runner, not a model, and
/// what it drives is a choice made elsewhere. So the default names the runner honestly
/// rather than inventing a model it might not be pointed at - and `--engine` is there for
/// the operator to say what is actually running, which is usually what they want in the
/// name.
#[must_use]
pub fn engine_label(command: &str) -> String {
    let command = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let command = command.strip_suffix(".exe").unwrap_or(command);
    slug(command.strip_prefix("ferryman-").unwrap_or(command))
}

/// Make an arbitrary name usable as a path component.
///
/// A project directory can be called anything at all, and an unattended caller has no
/// way to fix a rejected name. Mapping it is better than failing on it - but the result
/// is still checked by `is_safe_component`, so this loosens nothing.
pub fn slug(value: &str) -> String {
    let mapped: String = value
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    mapped.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unattended_worker_is_named_for_its_machine_and_engine() {
        assert_eq!(headless_name("fang", "deepseek"), "ichabod-fang-deepseek");
        assert_eq!(headless_name("wisp", "claude"), "ichabod-wisp-claude");
    }

    #[test]
    fn the_generated_name_is_always_a_usable_path_component() {
        // It becomes a key filename, a roster filename and a lock filename. A name that
        // is not path-safe fails at the first of those, after the others were written.
        let name = headless_name("Wisp WSL", "DeepSeek v4/pro");
        assert!(ferryman_channel::is_safe_component(&name), "{name}");
        assert_eq!(name, ferryman_channel::canonical_agent_name(&name));
    }

    #[test]
    fn a_missing_part_does_not_produce_a_name_with_a_hole_in_it() {
        // "ichabod--deepseek" and "ichabod-fang-" are different identities to a
        // roster than the ones intended, and neither reads as anything.
        assert_eq!(headless_name("", "deepseek"), "ichabod-deepseek");
        assert_eq!(headless_name("fang", ""), "ichabod-fang");
        assert_eq!(headless_name("", ""), "ichabod");
    }

    #[test]
    fn the_engine_label_names_the_runner_not_a_model_it_guesses_at() {
        // ferryman-cline drives whatever it is pointed at. Naming it "deepseek" here
        // would be inventing a fact; --engine is where the operator states it.
        assert_eq!(engine_label("ferryman-cline"), "cline");
        assert_eq!(engine_label("claude"), "claude");
        assert_eq!(engine_label("/usr/local/bin/claude"), "claude");
        assert_eq!(engine_label("C:\\bin\\claude.exe"), "claude");
    }

    #[test]
    fn one_machine_can_run_two_engines_without_them_being_one_identity() {
        // The reason the engine is in the name at all.
        assert_ne!(
            headless_name("fang", "deepseek"),
            headless_name("fang", "claude")
        );
    }

    #[test]
    fn slug_maps_rather_than_rejects() {
        assert_eq!(slug("Wisp"), "wisp");
        assert_eq!(slug("  My Box!  "), "my-box");
        assert_eq!(slug("a_b-c"), "a_b-c");
        assert_eq!(slug("---"), "");
    }

    #[test]
    fn with_no_environment_the_hostname_is_used_not_the_word_agent() {
        // The exact bug: nothing in the environment, so the old code returned "agent"
        // and two machines collided in the roster.
        assert_eq!(choose(None, "Fang").unwrap(), "fang");
        assert_eq!(choose(Some(""), "Wisp").unwrap(), "wisp");
        assert_eq!(choose(None, "wisp.lan.example").unwrap(), "wisp");
    }

    #[test]
    fn an_unusable_hostname_fails_instead_of_inventing_one() {
        let err = choose(None, "---").unwrap_err().to_string();
        assert!(
            err.contains("--agent"),
            "the error must name the way out: {err}"
        );
    }

    #[test]
    fn the_real_machine_resolves() {
        let name = machine_name().expect("the OS knows this machine's name");
        assert!(!name.is_empty());
    }

    #[test]
    fn an_explicit_name_wins_and_is_slugged() {
        let dir = std::env::temp_dir().join("ferryman-identity-explicit");
        assert_eq!(
            resolve(Some("Fang".into()), &dir).unwrap(),
            "fang",
            "--agent should be taken as given, once path-safe"
        );
    }

    #[test]
    fn the_configured_agent_is_read_before_the_hostname() {
        // The bug this exists to prevent: `channel work` resolved to the hostname (or
        // worse) while agent.toml sat two directories up saying who this agent is.
        let dir = std::env::temp_dir().join("ferryman-identity-configured");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            AgentConfig::path(&dir),
            AgentConfig::render(
                "fang",
                "worker",
                "claude",
                &["-p".to_string(), "{prompt}".to_string()],
                crate::agent::ReviewMode::Confirm,
                None,
                false,
            ),
        )
        .unwrap();

        assert_eq!(resolve(None, &dir).unwrap(), "fang");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! `ferry engines policy`: see, recommend, accept and set the engine policy - which
//! engines do a project's background work, in what order, never which, and on which
//! machines. See [`ferryman_channel::policy`].
//!
//! Setting it takes the master's signature, exactly as `ferry improve on` does, and the
//! signed file travels with the channel to every machine.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use chrono::Utc;
use ferryman_channel::policy::{self, NeverScope, Policy, Role};
use serde_json::{Value, json};

use super::{
    ImproveProject, improve_project, mastered_signer, mastered_targets, signing_identity_in,
};

#[derive(clap::Subcommand, Clone)]
pub(crate) enum PolicyCommand {
    /// The policy in force for a project, who signed it, and how it falls on the fleet
    /// now: each role's engines in order, and every blocked engine with the reason.
    Show {
        #[command(flatten)]
        which: ImproveProject,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// What auto would choose from the engines the fleet published - local and free
    /// first, subscriptions never - with one reason per choice. Nothing is signed.
    Recommend {
        #[command(flatten)]
        which: ImproveProject,
        #[arg(long)]
        json: bool,
    },
    /// Sign the recommendation as the project's policy. `--all`: every project you are
    /// master of, each recommended from its own channel.
    Accept {
        #[command(flatten)]
        which: ImproveProject,
    },
    /// Change the policy, signed as the project's master. Only what you name changes.
    ///
    /// Without `--role`, `--prefer` sets the order for every role (plan, build, review,
    /// chore). A selector is an engine name (`nemotron`), a model glob
    /// (`nvidia/nemotron*`), a paid class (`paid:free-tier`) or a host
    /// (`host:deepseek.com`). `--where any` lets any worker run it again.
    ///
    ///   ferry engines policy set --improve nemotron --review deepseek --never claude --where grouchly --all
    Set {
        #[command(flatten)]
        which: ImproveProject,
        /// The simple choice: what improves (plans and builds) first.
        #[arg(long, value_name = "SELECTOR")]
        improve: Option<String>,
        /// The simple choice: what reviews first - the first of the two keys every
        /// improvement needs before it can go live.
        #[arg(long, value_name = "SELECTOR")]
        review: Option<String>,
        /// plan, build, review or chore; repeat for several. Default: all four.
        #[arg(long = "role", value_name = "ROLE")]
        roles: Vec<String>,
        /// Most preferred first; repeat. Replaces the role's list.
        #[arg(long = "prefer", value_name = "SELECTOR")]
        prefer: Vec<String>,
        /// Never for background work; repeat. Replaces the never list.
        #[arg(long = "never", value_name = "SELECTOR")]
        never: Vec<String>,
        /// Agents or machines that may run self-improve; repeat. Replaces the list.
        #[arg(long = "where", value_name = "AGENT_OR_MACHINE")]
        machines: Vec<String>,
        /// Dollars a week the fleet may spend on each role named by `--role`.
        #[arg(long, value_name = "USD")]
        cap_usd: Option<f64>,
        /// Keep subscriptions out of background work (the default), or allow them.
        #[arg(long, value_name = "true|false")]
        protect_subscriptions: Option<bool>,
        /// `background` (the default): never leaves a person's own orders alone.
        /// `all`: it applies to them too.
        #[arg(long, value_name = "background|all")]
        never_applies_to: Option<String>,
    },
    /// Go back to auto, signed.
    Clear {
        #[command(flatten)]
        which: ImproveProject,
    },
}

/// Every project `which` means, as (id, channel, attachment).
fn projects(which: &ImproveProject) -> Result<Vec<(String, PathBuf, PathBuf)>> {
    if which.all {
        mastered_targets(None, None)
    } else {
        Ok(vec![improve_project(which)?])
    }
}

/// What the fleet published into this channel, and who is online in it.
fn fleet(channel: &Path) -> Vec<policy::Candidate> {
    ferryman_channel::route_for(channel)
        .map(|route| policy::fleet(&route, Utc::now()))
        .unwrap_or_default()
}

/// The recommendation for the project in `channel`.
pub(crate) fn recommendation(channel: &Path) -> policy::Recommendation {
    match ferryman_channel::route_for(channel) {
        Ok(route) => policy::recommend_for(&route, Utc::now()),
        Err(_) => policy::recommend(&[], &[]),
    }
}

pub(crate) async fn command(command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Show { which, json } => show(&which, json),
        PolicyCommand::Recommend { which, json } => {
            recommend(&which, json)?;
            if !json {
                suggest_omniroute(&which).await;
            }
            Ok(())
        }
        PolicyCommand::Accept { which } => sign_each(&which, "accepted", |_, channel, _| {
            Ok(Some(recommendation(channel).policy))
        }),
        PolicyCommand::Set {
            which,
            improve,
            review,
            roles,
            prefer,
            never,
            machines,
            cap_usd,
            protect_subscriptions,
            never_applies_to,
        } => {
            let roles: Vec<Role> = if roles.is_empty() {
                Role::ALL.to_vec()
            } else {
                roles
                    .iter()
                    .map(|role| Role::parse(role))
                    .collect::<Result<_>>()?
            };
            let scope = never_applies_to
                .as_deref()
                .map(|scope| match scope.trim().to_ascii_lowercase().as_str() {
                    "background" => Ok(NeverScope::Background),
                    "all" => Ok(NeverScope::All),
                    other => bail!("--never-applies-to is background or all, not '{other}'"),
                })
                .transpose()?;
            if improve.is_none()
                && review.is_none()
                && prefer.is_empty()
                && never.is_empty()
                && machines.is_empty()
                && cap_usd.is_none()
                && protect_subscriptions.is_none()
                && scope.is_none()
            {
                bail!(
                    "nothing to set: name --improve, --review, --prefer, --never, --where, \
                     --cap-usd, --protect-subscriptions or --never-applies-to"
                );
            }
            sign_each(&which, "set", |_, _, mut current| {
                if let Some(selector) = &improve {
                    current.set_improvement_engine(selector);
                }
                if let Some(selector) = &review {
                    current.set_review_engine(selector);
                }
                for role in &roles {
                    if !prefer.is_empty() {
                        current
                            .prefer
                            .insert(role.as_str().to_string(), prefer.clone());
                    }
                    if let Some(cap) = cap_usd {
                        current.caps_usd.insert(role.as_str().to_string(), cap);
                    }
                }
                if !never.is_empty() {
                    current.never.clone_from(&never);
                }
                if !machines.is_empty() {
                    current.machines = if machines.iter().any(|m| m.eq_ignore_ascii_case("any")) {
                        Vec::new()
                    } else {
                        machines.clone()
                    };
                }
                if let Some(protect) = protect_subscriptions {
                    current.protect_subscriptions = protect;
                }
                if let Some(scope) = scope {
                    current.never_applies_to = scope;
                }
                Ok(Some(current))
            })
        }
        PolicyCommand::Clear { which } => {
            sign_each(&which, "cleared - back to auto", |_, _, _| Ok(None))
        }
    }
}

/// Sign `change` of each project's current policy as its master. `None` is auto.
fn sign_each(
    which: &ImproveProject,
    verb: &str,
    change: impl Fn(&str, &Path, Policy) -> Result<Option<Policy>>,
) -> Result<()> {
    let mut me: Option<String> = None;
    let mut changed = 0;
    for (project, channel, attachment) in projects(which)? {
        let signer = if which.all {
            mastered_signer(&channel, &attachment, me.as_deref())
        } else {
            match ferryman_channel::ferry::master_of(&channel)? {
                Some(master) => {
                    signing_identity_in(&attachment, &master).map(|identity| (master, identity))
                }
                None => bail!(
                    "{project} has no master, and only its master sets the engine policy.\n\
                     \n\
                     Claim every project that has none:  ferry root master"
                ),
            }
        };
        let (master, identity) = match signer {
            Ok(signer) => signer,
            Err(error) if which.all => {
                println!("  {project}: skipped - {error:#}");
                continue;
            }
            Err(error) => return Err(error),
        };
        me.get_or_insert(master.clone());
        let current = policy::setting(&channel, &project)
            .and_then(|setting| setting.policy)
            .unwrap_or_default();
        let next = change(&project, &channel, current)?;
        match policy::set_policy(&channel, &project, next, &identity) {
            Ok(true) => {
                changed += 1;
                println!("  {project}: engine policy {verb}, signed by {master}");
            }
            Ok(false) => println!("  {project}: already so"),
            Err(error) if which.all => println!("  {project}: skipped - {error:#}"),
            Err(error) => return Err(error),
        }
    }
    println!(
        "engine policy {verb} in {changed} project(s); every machine that syncs a channel \
         follows it"
    );
    Ok(())
}

fn show(which: &ImproveProject, as_json: bool) -> Result<()> {
    let mut out: Vec<Value> = Vec::new();
    for (project, channel, _) in all_or_one(which)? {
        let (policy, setting) = policy::effective(&channel, &project);
        let engines = fleet(&channel);
        if as_json {
            out.push(json!({
                "project": project,
                "auto": setting.as_ref().is_none_or(|s| s.policy.is_none()),
                "set_by": setting.as_ref().map(policy::PolicySetting::set_by),
                "set_at": setting.as_ref().map(|s| s.set_at),
                "policy": policy,
                "effective": policy::view(&policy, &engines),
            }));
            continue;
        }
        println!("{project}: {}", source(setting.as_ref()));
        for line in policy.describe() {
            println!("  {line}");
        }
        if engines.is_empty() {
            println!("  no worker has published its engines here yet");
        } else {
            println!("  now, over the engines the fleet published:");
            for line in policy::summary(&policy, &engines) {
                println!("    {line}");
            }
        }
    }
    if as_json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    Ok(())
}

/// Who set the policy in force, as a person reads it.
pub(crate) fn source(setting: Option<&policy::PolicySetting>) -> String {
    match setting {
        Some(setting) if setting.policy.is_some() => format!(
            "policy signed by {}, {} UTC",
            setting.set_by(),
            setting.set_at.format("%Y-%m-%d %H:%M")
        ),
        Some(setting) => format!("auto, chosen by {}", setting.set_by()),
        None => "auto (no policy signed; subscriptions protected)".to_string(),
    }
}

/// `--all` means every project in the ferry root here, for reading; otherwise one.
fn all_or_one(which: &ImproveProject) -> Result<Vec<(String, PathBuf, PathBuf)>> {
    projects(which)
}

fn recommend(which: &ImproveProject, as_json: bool) -> Result<()> {
    let mut out: Vec<Value> = Vec::new();
    for (project, channel, _) in all_or_one(which)? {
        let proposal = recommendation(&channel);
        if as_json {
            out.push(json!({
                "project": project,
                "policy": proposal.policy,
                "reasons": proposal.reasons,
            }));
            continue;
        }
        println!("{project}: recommended");
        for line in proposal.policy.describe() {
            println!("  {line}");
        }
        println!("  why:");
        for reason in &proposal.reasons {
            println!("    - {reason}");
        }
        println!("  accept it: ferry engines policy accept {project}");
    }
    if as_json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    Ok(())
}

/// When OmniRoute answers on this machine and no engine in the fleet goes through it,
/// say so, with the agent.toml lines that add it.
async fn suggest_omniroute(which: &ImproveProject) {
    let Some(catalog) = ferryman_ops::omniroute::detect().await else {
        return;
    };
    let used = projects(which).is_ok_and(|all| {
        all.iter()
            .any(|(_, channel, _)| fleet(channel).iter().any(|engine| !engine.route.is_empty()))
    });
    if !used {
        println!("\n{}", ferryman_ops::omniroute::suggestion(&catalog));
    }
}

/// After `ferry improve on`: for the projects just switched on that have no policy of
/// their own, show what auto would choose and offer to sign it. At a terminal the
/// master is asked once; anywhere else the command to accept it is printed.
pub(crate) fn offer(signed: &[(String, PathBuf, ferryman_channel::AgentIdentity)]) {
    let without: Vec<&(String, PathBuf, ferryman_channel::AgentIdentity)> = signed
        .iter()
        .filter(|(project, channel, _)| !policy::is_set(channel, project))
        .collect();
    if without.is_empty() {
        return;
    }
    println!(
        "\n{} project(s) have no engine policy. Self-improve runs on auto until one is set: \
         local and free engines first, subscriptions never.",
        without.len()
    );
    for (project, channel, _) in &without {
        let proposal = recommendation(channel);
        println!("{project}, recommended:");
        for line in proposal.policy.describe() {
            println!("  {line}");
        }
        for reason in proposal.reasons.iter().take(8) {
            println!("  - {reason}");
        }
    }
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if !interactive {
        println!(
            "accept it with: ferry engines policy accept{}",
            if without.len() > 1 { " --all" } else { "" }
        );
        return;
    }
    print!("Sign the recommended engine policy now? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        println!("left on auto; 'ferry engines policy accept' signs it later");
        return;
    }
    for (project, channel, identity) in without {
        match policy::set_policy(
            channel,
            project,
            Some(recommendation(channel).policy),
            identity,
        ) {
            Ok(_) => println!("  {project}: engine policy accepted"),
            Err(error) => println!("  {project}: not signed - {error:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: PolicyCommand,
    }

    #[test]
    fn the_simple_choice_parses() {
        let cli = Cli::try_parse_from([
            "policy",
            "set",
            "--improve",
            "nemotron",
            "--review",
            "deepseek",
            "--never",
            "claude",
            "--where",
            "grouchly",
            "--all",
        ])
        .unwrap();
        let PolicyCommand::Set {
            improve, review, ..
        } = cli.command
        else {
            panic!("not set")
        };
        assert_eq!(improve.as_deref(), Some("nemotron"));
        assert_eq!(review.as_deref(), Some("deepseek"));
    }

    /// Josh's own policy, as the docs give it, parses into what it says.
    #[test]
    fn the_documented_set_command_parses() {
        let cli = Cli::try_parse_from([
            "policy", "set", "--prefer", "nemotron", "--prefer", "deepseek", "--never", "claude",
            "--where", "grouchly", "--all",
        ])
        .unwrap();
        let PolicyCommand::Set {
            which,
            roles,
            prefer,
            never,
            machines,
            ..
        } = cli.command
        else {
            panic!("not set")
        };
        assert!(which.all);
        assert!(roles.is_empty(), "every role");
        assert_eq!(prefer, ["nemotron", "deepseek"]);
        assert_eq!(never, ["claude"]);
        assert_eq!(machines, ["grouchly"]);
        assert!(
            Cli::try_parse_from(["policy", "set", "--role", "build", "--cap-usd", "2.5"]).is_ok()
        );
        assert!(Cli::try_parse_from(["policy", "accept", "--all"]).is_ok());
        assert!(Cli::try_parse_from(["policy", "recommend", "ferryman", "--json"]).is_ok());
    }

    #[test]
    fn the_source_line_says_who_set_it_or_that_it_is_auto() {
        assert!(source(None).starts_with("auto"));
    }
}

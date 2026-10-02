//! `ferry engines policy`: see, recommend, accept and set the engine policy - which
//! engines do a project's background work, in what order, never which, and on which
//! machines. See [`ferryman_channel::policy`].
//!
//! Setting it takes the master's signature, exactly as `ferry improve on` does, and the
//! signed file travels with the channel to every machine.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use chrono::Utc;
use ferryman_channel::policy::{self, Effort, NeverScope, Policy, Role, TeamOptions};
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
    /// The team preset - plan on high, build on medium, swarm the cheap work - proposed
    /// from the engines the fleet published, with one reason per choice. Nothing is
    /// signed unless you add `--accept`.
    ///
    /// A large judge plans and reviews at high effort; mid-size engines build at medium,
    /// three at once; the smallest do chores at low effort, four at once; the adversary
    /// is a large judge of another model family than the top builder. Subscriptions stay
    /// out of background work unless you name the role in `--allow-subscriptions-for`, and
    /// then only an engine with a `weekly_requests` cap is used.
    ///
    ///   ferry engines policy team myproject --allow-subscriptions-for build,chore --width build=4
    ///   ferry engines policy team --all --accept
    Team {
        #[command(flatten)]
        which: ImproveProject,
        /// Roles whose background work may use a capped subscription: plan, build,
        /// review, chore or adversary, comma-separated.
        #[arg(long, value_name = "ROLES", value_delimiter = ',')]
        allow_subscriptions_for: Vec<String>,
        /// Orders at once for a role, instead of the preset's: `build=3`; repeat.
        #[arg(long, value_name = "ROLE=N")]
        width: Vec<String>,
        /// Effort for a role, instead of the preset's: `build=medium` (low, medium or
        /// high); repeat.
        #[arg(long, value_name = "ROLE=LEVEL")]
        effort: Vec<String>,
        /// Sign the proposal as the project's policy.
        #[arg(long)]
        accept: bool,
        #[arg(long)]
        json: bool,
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
        /// plan, build, review, chore or adversary; repeat for several. Default: the first
        /// four (the adversary is chosen on its own).
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
        /// `none` (the default): you merge every approved improvement. `low-risk`: fm
        /// merges docs-, tests- and dependency-bump-only improvements on its own, and only
        /// after both keys - the review engine's and yours.
        #[arg(long, value_name = "none|low-risk", value_parser = policy::AutoMerge::parse)]
        auto_merge: Option<policy::AutoMerge>,
        /// What the adversary's findings do: `off`, `advisory` (the default: shown beside
        /// the review keys, never in the way) or `blocking` (a Block stops the contract
        /// lock and the engine key until you sign an override). Which engine challenges is
        /// `--role adversary --prefer <engine>`.
        ///
        ///   ferry engines policy set --role adversary --prefer deepseek --adversary blocking
        #[arg(long, value_name = "off|advisory|blocking", value_parser = policy::AdversaryMode::parse)]
        adversary: Option<policy::AdversaryMode>,
        /// How hard a role thinks: `build=medium`, `plan=high`, `chore=low`; repeat. The
        /// engine's `{effort}` argument, `effort_args` or reasoning field gets it.
        #[arg(long, value_name = "ROLE=LEVEL")]
        effort: Vec<String>,
        /// The most orders of a role claimed at once across the fleet: `build=3`; repeat.
        /// `build=none` removes the cap.
        #[arg(long, value_name = "ROLE=N")]
        width: Vec<String>,
        /// Roles whose background work may use a subscription - only one with a
        /// `weekly_requests` cap, comma-separated; `none` clears the list.
        ///
        ///   ferry engines policy set --allow-subscriptions-for build,chore
        #[arg(long, value_name = "ROLES", value_delimiter = ',')]
        allow_subscriptions_for: Vec<String>,
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

/// The team preset for the project in `channel`.
pub(crate) fn team_proposal(channel: &Path, options: &TeamOptions) -> policy::Recommendation {
    match ferryman_channel::route_for(channel) {
        Ok(route) => policy::team_for(&route, Utc::now(), options),
        Err(_) => policy::team(&[], &[], options),
    }
}

/// `--allow-subscriptions-for build,chore`: the roles, or `Some([])` for `none`. `None`
/// when the flag is absent.
fn parse_roles(flag: &str, values: &[String]) -> Result<Option<Vec<Role>>> {
    if values.is_empty() {
        return Ok(None);
    }
    let mut roles: Vec<Role> = Vec::new();
    for value in values {
        let value = value.trim();
        if value.eq_ignore_ascii_case("none") {
            continue;
        }
        let role = Role::parse(value).map_err(|error| anyhow::anyhow!("{flag}: {error}"))?;
        if !roles.contains(&role) {
            roles.push(role);
        }
    }
    roles.sort();
    Ok(Some(roles))
}

/// `build=medium`, `plan=high`: role and value, split once at `=`.
fn pairs<'a>(flag: &str, values: &'a [String]) -> Result<Vec<(Role, &'a str)>> {
    values
        .iter()
        .map(|value| {
            let (role, setting) = value
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("{flag} wants ROLE=VALUE, not '{value}'"))?;
            let role =
                Role::parse(role.trim()).map_err(|error| anyhow::anyhow!("{flag}: {error}"))?;
            Ok((role, setting.trim()))
        })
        .collect()
}

fn parse_efforts(values: &[String]) -> Result<BTreeMap<Role, Effort>> {
    pairs("--effort", values)?
        .into_iter()
        .map(|(role, level)| {
            Effort::parse(level)
                .map(|effort| (role, effort))
                .map_err(|error| anyhow::anyhow!("--effort {}: {error}", role.as_str()))
        })
        .collect()
}

/// `build=3` is a cap; `build=none` is `None`, no cap.
fn parse_widths(values: &[String]) -> Result<BTreeMap<Role, Option<u8>>> {
    pairs("--width", values)?
        .into_iter()
        .map(|(role, width)| {
            if matches!(width.to_ascii_lowercase().as_str(), "none" | "unlimited") {
                return Ok((role, None));
            }
            match width.parse::<u8>() {
                Ok(0) => bail!(
                    "--width {}=0 would stop the role; use a number from 1, or none for no cap",
                    role.as_str()
                ),
                Ok(width) => Ok((role, Some(width))),
                Err(_) => bail!(
                    "--width {} wants a number from 1 to 255, or none, not '{width}'",
                    role.as_str()
                ),
            }
        })
        .collect()
}

/// What `ferry engines policy team` was asked for, as [`TeamOptions`].
fn team_options(
    subscription_roles: &[String],
    width: &[String],
    effort: &[String],
) -> Result<TeamOptions> {
    let mut widths = BTreeMap::new();
    for (role, width) in parse_widths(width)? {
        match width {
            Some(width) => widths.insert(role, width),
            None => bail!(
                "--width {}=none: the team preset always caps a role; set it afterwards with \
                 `ferry engines policy set --width {}=none`",
                role.as_str(),
                role.as_str()
            ),
        };
    }
    Ok(TeamOptions {
        subscription_roles: parse_roles("--allow-subscriptions-for", subscription_roles)?
            .unwrap_or_default(),
        width: widths,
        effort: parse_efforts(effort)?,
    })
}

/// The options as the flags that make them, to print under a proposal.
fn options_flags(options: &TeamOptions) -> String {
    let mut flags = String::new();
    if !options.subscription_roles.is_empty() {
        flags.push_str(&format!(
            " --allow-subscriptions-for {}",
            options
                .subscription_roles
                .iter()
                .map(|role| role.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    for (role, width) in &options.width {
        flags.push_str(&format!(" --width {}={width}", role.as_str()));
    }
    for (role, effort) in &options.effort {
        flags.push_str(&format!(" --effort {}={}", role.as_str(), effort.as_str()));
    }
    flags
}

/// The options for one project: the roles opened to a capped subscription are the ones the
/// policy in force has, unless the person named some (`--allow-subscriptions-for`).
fn keeping_roles(
    options: &TeamOptions,
    explicit: bool,
    channel: &Path,
    project: &str,
) -> TeamOptions {
    let mut options = options.clone();
    if !explicit {
        options.subscription_roles = policy::effective(channel, project).0.subscription_roles;
    }
    options
}

/// The team preset for one project as it would be signed: laid over the policy in force,
/// so the master's `never`, caps, auto-merge, adversary mode and `where` stay.
fn team_signed(
    channel: &Path,
    project: &str,
    options: &TeamOptions,
    explicit: bool,
) -> policy::Recommendation {
    let options = keeping_roles(options, explicit, channel, project);
    let mut proposal = team_proposal(channel, &options);
    let in_force = policy::effective(channel, project).0;
    proposal.policy = policy::apply_team(&in_force, &proposal.policy);
    proposal
}

/// `ferry engines policy team`: show the proposal for each project; with `accept`, sign it.
fn team(
    which: &ImproveProject,
    options: &TeamOptions,
    explicit: bool,
    accept: bool,
    as_json: bool,
) -> Result<()> {
    if accept && as_json {
        bail!(
            "--accept and --json do not combine: read the proposal, then accept it without --json"
        );
    }
    let mut out: Vec<Value> = Vec::new();
    for (project, channel, _) in projects(which)? {
        let proposal = team_signed(&channel, &project, options, explicit);
        let warnings = policy::subscription_warnings(&proposal.policy, &fleet(&channel));
        if as_json {
            out.push(json!({
                "project": project,
                "policy": proposal.policy,
                "reasons": proposal.reasons,
                "warnings": warnings,
            }));
            continue;
        }
        println!(
            "{project}: team preset{}",
            if accept { "" } else { " (proposal)" }
        );
        for line in proposal.policy.describe() {
            println!("  {line}");
        }
        println!("  why:");
        for reason in &proposal.reasons {
            println!("    - {reason}");
        }
        for warning in &warnings {
            println!("  warning: {warning}");
        }
        if !accept {
            println!(
                "  accept it: ferry engines policy team {project} --accept{}",
                options_flags(options)
            );
        }
    }
    if as_json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    if accept {
        let options = options.clone();
        sign_each(
            which,
            "set to the team preset",
            move |project, channel, _| {
                Ok(Some(
                    team_signed(channel, project, &options, explicit).policy,
                ))
            },
        )?;
    }
    Ok(())
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
        PolicyCommand::Accept { which } => {
            sign_each(&which, "accepted", |_, channel, current| {
                // Laid over the policy in force: accepting engine preferences keeps the
                // master's `never`, caps, auto-merge and adversary mode.
                Ok(Some(policy::apply_recommendation(
                    &current,
                    &recommendation(channel).policy,
                )))
            })
        }
        PolicyCommand::Team {
            which,
            allow_subscriptions_for,
            width,
            effort,
            accept,
            json,
        } => {
            let options = team_options(&allow_subscriptions_for, &width, &effort)?;
            team(
                &which,
                &options,
                !allow_subscriptions_for.is_empty(),
                accept,
                json,
            )
        }
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
            auto_merge,
            adversary,
            effort,
            width,
            allow_subscriptions_for,
        } => {
            let efforts = parse_efforts(&effort)?;
            let widths = parse_widths(&width)?;
            let subscription_roles =
                parse_roles("--allow-subscriptions-for", &allow_subscriptions_for)?;
            // The adversary is never a default: `--prefer deepseek` with no `--role` sets
            // the four roles that build and judge, and leaves who challenges them alone.
            let roles: Vec<Role> = if roles.is_empty() {
                Role::BUILDING.to_vec()
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
                && auto_merge.is_none()
                && adversary.is_none()
                && efforts.is_empty()
                && widths.is_empty()
                && subscription_roles.is_none()
            {
                bail!(
                    "nothing to set: name --improve, --review, --prefer, --never, --where, \
                     --cap-usd, --protect-subscriptions, --never-applies-to, --auto-merge, \
                     --adversary, --effort, --width or --allow-subscriptions-for"
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
                if let Some(mode) = auto_merge {
                    current.auto_merge = mode;
                }
                if let Some(mode) = adversary {
                    current.adversary = mode;
                }
                current.effort.extend(efforts.clone());
                for (role, width) in &widths {
                    match width {
                        Some(width) => current.width.insert(*role, *width),
                        None => current.width.remove(role),
                    };
                }
                if let Some(roles) = &subscription_roles {
                    current.subscription_roles.clone_from(roles);
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
                "warnings": policy::subscription_warnings(&policy, &engines),
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
            println!("  effort, width and size class per role:");
            for line in policy::role_lines(&policy, &engines) {
                println!("    {line}");
            }
            for warning in policy::subscription_warnings(&policy, &engines) {
                println!("  warning: {warning}");
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
            "--auto-merge",
            "low-risk",
            "--all",
        ])
        .unwrap();
        let PolicyCommand::Set {
            improve,
            review,
            auto_merge,
            ..
        } = cli.command
        else {
            panic!("not set")
        };
        assert_eq!(improve.as_deref(), Some("nemotron"));
        assert_eq!(review.as_deref(), Some("deepseek"));
        assert_eq!(auto_merge, Some(policy::AutoMerge::LowRisk));
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

    #[test]
    fn the_adversary_role_and_mode_parse_and_the_default_roles_leave_it_out() {
        let cli = Cli::try_parse_from([
            "policy",
            "set",
            "--role",
            "adversary",
            "--prefer",
            "deepseek",
            "--adversary",
            "blocking",
        ])
        .unwrap();
        let PolicyCommand::Set {
            roles,
            prefer,
            adversary,
            ..
        } = cli.command
        else {
            panic!("not set")
        };
        assert_eq!(roles, ["adversary"]);
        assert_eq!(prefer, ["deepseek"]);
        assert_eq!(adversary, Some(policy::AdversaryMode::Blocking));
        assert!(Role::parse(&roles[0]).is_ok());
        for mode in ["off", "advisory", "blocking"] {
            assert!(
                Cli::try_parse_from(["policy", "set", "--adversary", mode]).is_ok(),
                "{mode}"
            );
        }
        assert!(Cli::try_parse_from(["policy", "set", "--adversary", "sometimes"]).is_err());
        // Without --role the building roles are set; who challenges is its own choice.
        assert!(!Role::BUILDING.contains(&Role::Adversary));
    }

    #[test]
    fn the_team_command_and_the_effort_flags_parse() {
        let cli = Cli::try_parse_from([
            "policy",
            "team",
            "ferryman",
            "--allow-subscriptions-for",
            "build,chore",
            "--width",
            "build=4",
            "--effort",
            "plan=high",
            "--accept",
        ])
        .unwrap();
        let PolicyCommand::Team {
            allow_subscriptions_for,
            width,
            effort,
            accept,
            json,
            ..
        } = cli.command
        else {
            panic!("not team")
        };
        assert!(accept && !json);
        assert_eq!(allow_subscriptions_for, ["build", "chore"]);
        let options = team_options(&allow_subscriptions_for, &width, &effort).unwrap();
        assert_eq!(options.subscription_roles, [Role::Build, Role::Chore]);
        assert_eq!(options.width, BTreeMap::from([(Role::Build, 4)]));
        assert_eq!(options.effort, BTreeMap::from([(Role::Plan, Effort::High)]));
        assert_eq!(
            options_flags(&options),
            " --allow-subscriptions-for build,chore --width build=4 --effort plan=high"
        );
        assert!(Cli::try_parse_from(["policy", "team", "--all"]).is_ok());
        assert!(Cli::try_parse_from(["policy", "team", "--json"]).is_ok());

        let cli = Cli::try_parse_from([
            "policy",
            "set",
            "--effort",
            "build=medium",
            "--width",
            "chore=4",
            "--allow-subscriptions-for",
            "none",
        ])
        .unwrap();
        let PolicyCommand::Set {
            effort,
            width,
            allow_subscriptions_for,
            ..
        } = cli.command
        else {
            panic!("not set")
        };
        assert_eq!(
            parse_efforts(&effort).unwrap(),
            BTreeMap::from([(Role::Build, Effort::Medium)])
        );
        assert_eq!(
            parse_widths(&width).unwrap(),
            BTreeMap::from([(Role::Chore, Some(4))])
        );
        assert_eq!(
            parse_roles("--allow-subscriptions-for", &allow_subscriptions_for).unwrap(),
            Some(Vec::new()),
            "none clears the list"
        );
        assert_eq!(
            parse_roles("--x", &[]).unwrap(),
            None,
            "absent changes nothing"
        );
    }

    #[test]
    fn nonsense_effort_and_width_are_refused_with_a_reason() {
        let one = |value: &str| vec![value.to_string()];
        assert!(parse_efforts(&one("build")).is_err(), "no =");
        assert!(parse_efforts(&one("builder=low")).is_err(), "no such role");
        assert!(
            parse_efforts(&one("build=extreme")).is_err(),
            "no such level"
        );
        assert!(parse_widths(&one("build=0")).is_err(), "0 stops the role");
        assert!(parse_widths(&one("build=300")).is_err(), "over a byte");
        assert!(parse_widths(&one("build=many")).is_err());
        assert_eq!(
            parse_widths(&one("build=none")).unwrap(),
            BTreeMap::from([(Role::Build, None)])
        );
        assert!(
            team_options(&[], &one("build=none"), &[]).is_err(),
            "the preset always caps"
        );
        assert!(parse_roles("--x", &one("builder")).is_err());
    }
}

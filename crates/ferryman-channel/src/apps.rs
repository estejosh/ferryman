//! Connected apps: one agent identity per cloud app that logs in to `ferry mcp serve --http`
//! (ADR 0031, "Identity, permissions, revocation").
//!
//! An app is never the machine's own agent. When the owner lets one in, it gets a name
//! (`claude-ai-<owner>`, `chatgpt-<owner>`), a key of its own, a roster entry and a level the
//! project's master signs: Worker by default, Member when the owner says so, never
//! Orchestrator and never the master. The key sits in a keystore under the server's state
//! directory and nowhere else, so deleting it ends the identity.
//!
//! Everything here is machine-local state plus the existing master-signed path
//! ([`crate::access::set_level`], [`crate::master::revoke_member`]). The one rule that holds it
//! together: **an app is approved only when a master-signed grant for its key exists**. A
//! machine without the master's key cannot approve; it leaves the app's signed request in
//! `apps/<id>.json`, and the app turns approved when the master signs the grant somewhere
//! else and it syncs here ([`settle`]).
//!
//! The server owns the usage sidecars; the CLI and the dashboard own the records. Neither
//! writes the other's files, so a running server and `ferry mcp apps` never race.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::access::{self, Level};
use crate::{
    AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, canonical_agent_name,
    is_safe_component,
};

/// A request nobody approved is dropped after this long.
pub const PENDING_SECS: i64 = 10 * 60;
/// Requests waiting for the owner at once.
pub const MAX_PENDING: usize = 20;
/// A pending request that was never decided is pruned (with its key) after this long.
const STALE_SECS: i64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Logged in with a pairing code; the owner has not decided.
    Pending,
    /// A master-signed grant exists for its key.
    Approved,
    Denied,
    Revoked,
}

impl State {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
        }
    }
}

/// One app, from first request to revocation. The record holds only the public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct App {
    pub id: String,
    pub agent: String,
    pub public_key: String,
    pub client_name: String,
    /// Where the app's login returns to (the host only): what the owner is shown.
    pub redirect_host: String,
    pub owner: String,
    /// What the owner offers at approval; Worker unless they choose otherwise.
    pub requested: Level,
    /// Highest level the master has signed for it, once approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<Level>,
    pub state: State,
    pub created: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided: Option<i64>,
    /// Projects where a verified master grant for this key exists.
    #[serde(default)]
    pub projects: Vec<String>,
    /// The app's own signature over the request: proof the key is the one it asked with.
    pub signature: String,
}

/// What the server counts, kept apart so only the server writes it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Usage {
    pub last_used: i64,
    pub calls: u64,
}

fn apps_dir(state: &Path) -> PathBuf {
    state.join("apps")
}

fn record_path(state: &Path, id: &str) -> PathBuf {
    apps_dir(state).join(format!("{id}.json"))
}

fn usage_path(state: &Path, id: &str) -> PathBuf {
    apps_dir(state).join(format!("{id}.use.json"))
}

/// Where `ferry mcp serve --http` keeps its tokens, pairing codes and apps on this machine.
/// The CLI, the server and the dashboard all look here.
#[must_use]
pub fn default_state_dir() -> Option<PathBuf> {
    crate::licensing::machine_state_dir().map(|dir| dir.join("mcp-http"))
}

/// The keystore of connected apps. Nothing else keeps keys here.
#[must_use]
pub fn keys_dir(state: &Path) -> PathBuf {
    state.join("keys")
}

/// The key of an approved or pending app, if this machine still holds it.
#[must_use]
pub fn load_key(state: &Path, agent: &str) -> Option<AgentIdentity> {
    AgentIdentity::load_existing(agent, &keys_dir(state))
        .ok()
        .flatten()
}

fn request_payload(app: &App) -> String {
    format!(
        "ferryman-app-request-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        app.id,
        app.agent,
        app.public_key,
        app.requested.as_str(),
        app.client_name,
        app.redirect_host,
        app.owner,
    )
}

fn verify_request(app: &App) -> bool {
    let roster = [AgentRoute {
        name: app.agent.clone(),
        role: "app".into(),
        capabilities: Vec::new(),
        public_key: Some(app.public_key.clone()),
        encryption_key: None,
    }];
    crate::check_signature(
        Some(&app.agent),
        Some(&app.signature),
        &request_payload(app),
        &roster,
    ) == SignatureCheck::Valid
}

fn save(state: &Path, app: &App) -> Result<()> {
    crate::atomic_json(&record_path(state, &app.id), app)
}

/// Every record, oldest first. Unreadable files are skipped.
#[must_use]
pub fn list(state: &Path) -> Vec<App> {
    let mut apps: Vec<App> = fs::read_dir(apps_dir(state))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            if !name.ends_with(".json") || name.ends_with(".use.json") {
                return None;
            }
            serde_json::from_slice(&fs::read(&path).ok()?).ok()
        })
        .collect();
    apps.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
    apps
}

#[must_use]
pub fn usage(state: &Path, id: &str) -> Usage {
    fs::read(usage_path(state, id))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Count one call by `agent`. Server only.
pub fn record_use(state: &Path, agent: &str, now: i64) {
    let name = canonical_agent_name(agent);
    if let Some(app) = list(state).into_iter().find(|a| a.agent == name) {
        let mut seen = usage(state, &app.id);
        seen.last_used = now;
        seen.calls += 1;
        let _ = crate::atomic_json(&usage_path(state, &app.id), &seen);
    }
}

/// The record named by `id` or by a prefix of it that names exactly one.
///
/// # Errors
/// No such app, or the prefix fits several.
pub fn find(state: &Path, id: &str) -> Result<App> {
    let id = id.trim();
    let mut hits: Vec<App> = list(state)
        .into_iter()
        .filter(|a| !id.is_empty() && (a.id == id || a.id.starts_with(id) || a.agent == id))
        .collect();
    if let Some(exact) = hits.iter().position(|a| a.id == id || a.agent == id) {
        return Ok(hits.swap_remove(exact));
    }
    match hits.len() {
        1 => Ok(hits.remove(0)),
        0 => bail!("no connected app '{id}' (ferry mcp apps list)"),
        _ => bail!("'{id}' fits several apps; give more of the id"),
    }
}

/// The app whose identity is `agent`.
#[must_use]
pub fn by_agent(state: &Path, agent: &str) -> Option<App> {
    let name = canonical_agent_name(agent);
    list(state).into_iter().find(|a| a.agent == name)
}

/// Agents whose apps were revoked, so the server can end their tokens.
#[must_use]
pub fn revoked_agents(state: &Path) -> Vec<String> {
    list(state)
        .into_iter()
        .filter(|a| a.state == State::Revoked)
        .map(|a| a.agent)
        .collect()
}

/// Is `agent` an app the owner has approved and not revoked?
#[must_use]
pub fn is_live(state: &Path, agent: &str) -> bool {
    by_agent(state, agent).is_some_and(|a| a.state == State::Approved)
}

fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').chars().take(20).collect()
}

/// The first half of an app's name, from the host its login returns to or, for a loopback
/// client such as Claude Code, from what it calls itself.
#[must_use]
pub fn vendor(client_name: &str, redirect_host: &str) -> String {
    let host = redirect_host.to_ascii_lowercase();
    if host == "claude.ai" || host.ends_with(".claude.ai") {
        return "claude-ai".into();
    }
    if host.contains("chatgpt") || host.contains("openai") {
        return "chatgpt".into();
    }
    let named = slug(client_name);
    if named.is_empty() {
        "app".into()
    } else {
        named
    }
}

/// The routes with each roster read again from disk: a route loaded a while ago does not
/// know the keys published since, and the master is verified against the roster.
#[must_use]
pub fn refreshed(routes: &[ProjectRoute]) -> Vec<ProjectRoute> {
    routes
        .iter()
        .map(|route| {
            let mut route = route.clone();
            if let Ok(agents) = crate::read_agent_roster(&route.communications) {
                route.agents = agents;
            }
            route
        })
        .collect()
}

/// The owner's name: the master of the first live project that has one.
#[must_use]
pub fn owner_of(routes: &[ProjectRoute]) -> String {
    refreshed(routes)
        .iter()
        .find_map(|route| crate::master::read_master(route).ok().flatten())
        .map(|declaration| slug(&declaration.master))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "owner".into())
}

/// Every live, non-archived project in the ferry root whose checkout and channel can be
/// read here.
#[must_use]
pub fn live_routes() -> Vec<ProjectRoute> {
    let Some(root) = crate::ferry::find_root() else {
        return Vec::new();
    };
    root.read()
        .projects
        .iter()
        .filter(|entry| !entry.is_archived())
        .filter_map(|entry| entry.route(&root).ok().map(|(route, _)| route))
        .collect()
}

/// The master's key for `route`, when this machine holds it as a key file. A sealed
/// operator identity is not opened here: whoever is at a terminal or a dashboard brings it.
#[must_use]
pub fn master_key_here(route: &ProjectRoute) -> Option<AgentIdentity> {
    let route = &refreshed(std::slice::from_ref(route))[0];
    let master = crate::master::read_master(route).ok().flatten()?;
    AgentIdentity::load_existing(&master.master, &route.attachment)
        .ok()
        .flatten()
}

fn taken(state: &Path, routes: &[ProjectRoute], name: &str) -> bool {
    list(state).iter().any(|a| a.agent == name)
        || routes.iter().any(|route| {
            crate::read_agent_roster(&route.communications)
                .unwrap_or_default()
                .iter()
                .any(|a| canonical_agent_name(&a.name) == name)
        })
}

/// What a login asks for.
pub struct Request<'a> {
    pub client_name: &'a str,
    pub redirect_host: &'a str,
}

/// Start a connection: a new name, a new key and a signed pending request. Nothing is
/// granted and nothing is written to any channel.
///
/// # Errors
/// Too many requests waiting, or the keystore cannot be written.
pub fn request(
    state: &Path,
    routes: &[ProjectRoute],
    asked: &Request<'_>,
    now: i64,
) -> Result<App> {
    for app in list(state) {
        if app.state == State::Pending && app.created + STALE_SECS <= now {
            let _ = AgentIdentity::remove_key(&app.agent, &keys_dir(state));
            let _ = fs::remove_file(record_path(state, &app.id));
        }
    }
    if list(state)
        .iter()
        .filter(|a| a.state == State::Pending)
        .count()
        >= MAX_PENDING
    {
        bail!("too many apps are waiting for approval; decide them first (ferry mcp apps list)");
    }
    let client_name: String = asked
        .client_name
        .chars()
        .filter(|c| !c.is_control())
        .take(60)
        .collect();
    let base = format!(
        "{}-{}",
        vendor(&client_name, asked.redirect_host),
        owner_of(routes)
    );
    let mut agent = base.clone();
    for n in 2.. {
        if !taken(state, routes, &agent) {
            break;
        }
        agent = format!("{base}-{n}");
    }
    if !is_safe_component(&agent) {
        bail!("cannot name an app '{agent}'");
    }
    let identity = AgentIdentity::create_in(&agent, &keys_dir(state))?;
    let mut app = App {
        id: format!("app-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
        agent,
        public_key: identity.public_key_hex(),
        client_name,
        redirect_host: asked.redirect_host.chars().take(80).collect(),
        owner: owner_of(routes),
        requested: Level::Worker,
        level: None,
        state: State::Pending,
        created: now,
        decided: None,
        projects: Vec::new(),
        signature: String::new(),
    };
    app.signature = identity.sign_bytes(request_payload(&app).as_bytes());
    save(state, &app)?;
    Ok(app)
}

/// Take in a signed request made on another machine (the one running the server), so the
/// master key here can approve it.
///
/// # Errors
/// The file is not a request, its signature does not verify against its own key, or it was
/// already imported.
pub fn import(state: &Path, file: &Path) -> Result<App> {
    let app: App =
        serde_json::from_slice(&fs::read(file).with_context(|| file.display().to_string())?)
            .context("not a connected-app request")?;
    if app.state != State::Pending
        || !is_safe_component(&app.id)
        || !is_safe_component(&app.agent)
        || app.requested == Level::Orchestrator
        || !verify_request(&app)
    {
        bail!(
            "{} is not a valid pending request from an app",
            file.display()
        );
    }
    if record_path(state, &app.id).exists() {
        bail!("{} is already here", app.id);
    }
    save(state, &app)?;
    Ok(app)
}

/// Where a request's record lives, for handing to the machine that holds the master key.
#[must_use]
pub fn request_file(state: &Path, id: &str) -> PathBuf {
    record_path(state, id)
}

/// Publish the app's public key under its name, refusing to replace a different key:
/// first key wins, as for every agent.
fn register(route: &ProjectRoute, app: &App) -> Result<()> {
    let name = canonical_agent_name(&app.agent);
    let roster = crate::read_agent_roster(&route.communications)?;
    if let Some(known) = roster
        .iter()
        .find(|a| canonical_agent_name(&a.name) == name)
        .and_then(|a| a.public_key.clone())
        .filter(|key| !key.is_empty())
    {
        if known == app.public_key {
            return Ok(());
        }
        bail!(
            "'{name}' is already published in {} with a different key",
            route.project_id
        );
    }
    crate::register_agent(
        route,
        &AgentRoute {
            name,
            role: "app".into(),
            capabilities: Vec::new(),
            public_key: Some(app.public_key.clone()),
            encryption_key: None,
        },
    )?;
    Ok(())
}

/// The projects where a verified master grant (Worker or Member) names this app's key.
fn granted(routes: &[ProjectRoute], app: &App) -> Vec<(String, Level)> {
    let name = canonical_agent_name(&app.agent);
    routes
        .iter()
        .filter_map(|route| {
            let keyed = crate::read_agent_roster(&route.communications)
                .ok()?
                .iter()
                .any(|a| {
                    canonical_agent_name(&a.name) == name
                        && a.public_key.as_deref() == Some(app.public_key.as_str())
                });
            let level = access::grants(&route.communications, &route.project_id)
                .get(&name)?
                .level;
            (keyed && level != Level::Orchestrator).then(|| (route.project_id.clone(), level))
        })
        .collect()
}

/// Turn a pending app into an approved one if a master-signed grant for its key has
/// arrived in any project. Returns whether it is approved now. A revoked or denied app
/// stays that way whatever the channel says.
///
/// # Errors
/// The record cannot be saved.
pub fn settle(state: &Path, app: &mut App, routes: &[ProjectRoute], now: i64) -> Result<bool> {
    if !matches!(app.state, State::Pending | State::Approved) {
        return Ok(false);
    }
    let seats = granted(routes, app);
    if seats.is_empty() {
        return Ok(app.state == State::Approved);
    }
    app.state = State::Approved;
    app.level = seats.iter().map(|(_, level)| *level).max();
    app.projects = seats.into_iter().map(|(project, _)| project).collect();
    app.decided.get_or_insert(now);
    save(state, app)?;
    Ok(true)
}

/// What deciding an app did, project by project.
#[derive(Debug, Default)]
pub struct Report {
    /// Projects where the master's grant now stands.
    pub signed: Vec<String>,
    /// Projects left alone, and why: no master key here, no master, a refusal.
    pub skipped: Vec<(String, String)>,
}

/// Approve `app` at `level` (Worker or Member) in the live projects where `signer` can
/// produce the master's key, or only in `only` when given. The roster entry and the grant
/// are the existing master-signed ones. When no project could be signed here the request
/// stays pending: its signed record is the thing to carry to the master.
///
/// # Errors
/// The app is not waiting, the level is Orchestrator, or the record cannot be saved.
pub fn approve(
    state: &Path,
    app: &mut App,
    level: Level,
    only: &[String],
    routes: &[ProjectRoute],
    signer: &dyn Fn(&ProjectRoute) -> Option<AgentIdentity>,
    now: i64,
) -> Result<Report> {
    if level == Level::Orchestrator {
        bail!("an app is a Worker or a Member, never an Orchestrator");
    }
    if !matches!(app.state, State::Pending | State::Approved) {
        bail!(
            "{} is {}; connect it again to start over",
            app.id,
            app.state.as_str()
        );
    }
    if !verify_request(app) {
        bail!("{}'s request does not verify against its key", app.id);
    }
    let routes = &refreshed(routes);
    let mut report = Report::default();
    for route in routes
        .iter()
        .filter(|r| only.is_empty() || only.contains(&r.project_id))
    {
        let project = route.project_id.clone();
        let Some(master) = crate::master::read_master(route).ok().flatten() else {
            report.skipped.push((project, "no master".into()));
            continue;
        };
        let Some(identity) = signer(route) else {
            report.skipped.push((
                project,
                format!("the master key ({}) is not on this machine", master.master),
            ));
            continue;
        };
        let signed = register(route, app)
            .and_then(|()| access::set_level(route, &identity, &app.agent, level).map(|_| ()));
        match signed {
            Ok(()) => report.signed.push(project),
            Err(error) => report.skipped.push((project, format!("{error:#}"))),
        }
    }
    app.requested = level;
    settle(state, app, routes, now)?;
    Ok(report)
}

/// Refuse a waiting app: its key is deleted and nothing was ever granted.
///
/// # Errors
/// The app is not waiting, or the record cannot be saved.
pub fn deny(state: &Path, app: &mut App, now: i64) -> Result<()> {
    if app.state != State::Pending {
        bail!("{} is {}, not waiting", app.id, app.state.as_str());
    }
    app.state = State::Denied;
    app.decided = Some(now);
    save(state, app)?;
    AgentIdentity::remove_key(&app.agent, &keys_dir(state))?;
    Ok(())
}

/// What revoking an app did.
#[derive(Debug, Default)]
pub struct Revoked {
    /// The key was on this machine and is gone.
    pub key_deleted: bool,
    /// Projects where the master signed the end of the grant.
    pub signed: Vec<String>,
    /// Projects where it could not be signed here, and why. The app is dead here regardless:
    /// no token is accepted and its key is gone.
    pub skipped: Vec<(String, String)>,
}

/// End an app. In this order, so the part that needs no master comes first: mark it
/// revoked (the server stops honouring its tokens at once), delete its key, then, where
/// `signer` has the master key, sign it down to Worker and sign the revocation.
///
/// # Errors
/// The record cannot be saved or the key cannot be deleted.
pub fn revoke(
    state: &Path,
    app: &mut App,
    routes: &[ProjectRoute],
    signer: &dyn Fn(&ProjectRoute) -> Option<AgentIdentity>,
    now: i64,
) -> Result<Revoked> {
    let routes = &refreshed(routes);
    let mut report = Revoked::default();
    let was_granted = !granted(routes, app).is_empty() || app.state == State::Approved;
    app.state = State::Revoked;
    app.decided = Some(now);
    save(state, app)?;
    report.key_deleted = AgentIdentity::remove_key(&app.agent, &keys_dir(state))?;
    if !was_granted {
        return Ok(report);
    }
    let name = canonical_agent_name(&app.agent);
    for route in routes {
        let on_roster = crate::read_agent_roster(&route.communications)
            .unwrap_or_default()
            .iter()
            .any(|a| {
                canonical_agent_name(&a.name) == name
                    && a.public_key.as_deref() == Some(app.public_key.as_str())
            });
        if !on_roster {
            continue;
        }
        let project = route.project_id.clone();
        let Some(identity) = signer(route) else {
            report
                .skipped
                .push((project, "the master key is not on this machine".into()));
            continue;
        };
        let held = access::grants(&route.communications, &route.project_id)
            .get(&name)
            .map(|g| g.level);
        let done = (|| -> Result<()> {
            if held != Some(Level::Worker) {
                access::set_level(route, &identity, &name, Level::Worker)?;
            }
            crate::master::revoke_member(route, &identity, &name, "connected app revoked")?;
            Ok(())
        })();
        match done {
            Ok(()) => report.signed.push(project),
            Err(error) => report.skipped.push((project, format!("{error:#}"))),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fleet {
        _dir: tempfile::TempDir,
        state: PathBuf,
        routes: Vec<ProjectRoute>,
    }

    /// Two projects, both mastered by `josh`, whose key sits in each attachment.
    fn fleet() -> Fleet {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("machine"));
        let mut routes = Vec::new();
        for project in ["alpha", "beta"] {
            let workspace = dir.path().join(project).join("workspace");
            let attachment = workspace.join(".ferryman");
            let communications = attachment.join("ferryman");
            fs::create_dir_all(&communications).unwrap();
            let mut route = ProjectRoute {
                project_id: project.into(),
                workspace,
                attachment: attachment.clone(),
                communications: communications.clone(),
                shared_remote: format!("{project}-ferryman"),
                git_remote: String::new(),
                git_visibility: String::new(),
                agents: Vec::new(),
            };
            let josh = AgentIdentity::load_or_create("josh", &attachment).unwrap();
            crate::register_agent(
                &route,
                &AgentRoute {
                    name: "josh".into(),
                    role: "operator".into(),
                    capabilities: Vec::new(),
                    public_key: Some(josh.public_key_hex()),
                    encryption_key: None,
                },
            )
            .unwrap();
            route.agents = crate::read_agent_roster(&communications).unwrap();
            crate::master::initialize_master(&route, &josh, "josh").unwrap();
            routes.push(route);
        }
        let state = dir.path().join("mcp-state");
        Fleet {
            _dir: dir,
            state,
            routes,
        }
    }

    fn master(route: &ProjectRoute) -> Option<AgentIdentity> {
        AgentIdentity::load_existing("josh", &route.attachment)
            .ok()
            .flatten()
    }

    fn no_master(_: &ProjectRoute) -> Option<AgentIdentity> {
        None
    }

    fn ask(fleet: &Fleet) -> App {
        request(
            &fleet.state,
            &fleet.routes,
            &Request {
                client_name: "Claude",
                redirect_host: "claude.ai",
            },
            100,
        )
        .unwrap()
    }

    #[test]
    fn an_app_gets_its_own_named_key_kept_in_the_app_keystore_only() {
        let fleet = fleet();
        let app = ask(&fleet);
        assert_eq!(app.agent, "claude-ai-josh");
        assert_eq!((app.state, app.requested), (State::Pending, Level::Worker));
        assert!(verify_request(&app));
        let key = load_key(&fleet.state, &app.agent).unwrap();
        assert_eq!(key.public_key_hex(), app.public_key);
        // Not an agent of the machine: no attachment and no machine keystore has it.
        for route in &fleet.routes {
            assert!(
                AgentIdentity::load_existing(&app.agent, &route.attachment)
                    .unwrap()
                    .is_none()
            );
        }
        let machine = crate::licensing::machine_state_dir().unwrap();
        assert!(
            AgentIdentity::load_existing(&app.agent, &machine)
                .unwrap()
                .is_none()
        );
        // Nothing was written to any channel.
        for route in &fleet.routes {
            assert!(
                !crate::read_agent_roster(&route.communications)
                    .unwrap()
                    .iter()
                    .any(|a| a.name == app.agent)
            );
        }
        // A second login is a second identity, not the same one.
        assert_eq!(ask(&fleet).agent, "claude-ai-josh-2");
        let chat = request(
            &fleet.state,
            &fleet.routes,
            &Request {
                client_name: "ChatGPT",
                redirect_host: "chatgpt.com",
            },
            100,
        )
        .unwrap();
        assert_eq!(chat.agent, "chatgpt-josh");
    }

    #[test]
    fn approval_signs_a_worker_grant_by_default_and_never_an_orchestrator() {
        let fleet = fleet();
        let mut app = ask(&fleet);
        assert!(
            approve(
                &fleet.state,
                &mut app,
                Level::Orchestrator,
                &[],
                &fleet.routes,
                &master,
                200
            )
            .is_err()
        );
        assert_eq!(app.state, State::Pending);
        let report = approve(
            &fleet.state,
            &mut app,
            Level::Worker,
            &[],
            &fleet.routes,
            &master,
            200,
        )
        .unwrap();
        assert_eq!(report.signed, ["alpha", "beta"]);
        assert_eq!(
            (app.state, app.level),
            (State::Approved, Some(Level::Worker))
        );
        for route in &fleet.routes {
            assert_eq!(
                access::level_of(&route.communications, &route.project_id, &app.agent),
                Level::Worker
            );
            let grant = &access::grants(&route.communications, &route.project_id)[&app.agent];
            assert_eq!(grant.signed_by, "josh");
        }
        assert!(is_live(&fleet.state, &app.agent));
        // Member is an explicit choice, and can be limited to one project.
        let mut member = ask(&fleet);
        let only = ["beta".to_string()];
        let report = approve(
            &fleet.state,
            &mut member,
            Level::Member,
            &only,
            &fleet.routes,
            &master,
            300,
        )
        .unwrap();
        assert_eq!(report.signed, ["beta"]);
        assert_eq!(member.projects, ["beta"]);
        assert_eq!(member.level, Some(Level::Member));
        let alpha = &fleet.routes[0];
        assert!(!access::grants(&alpha.communications, "alpha").contains_key(&member.agent));
    }

    #[test]
    fn without_the_master_key_the_signed_request_waits_and_a_later_grant_approves_it() {
        let fleet = fleet();
        let mut app = ask(&fleet);
        let report = approve(
            &fleet.state,
            &mut app,
            Level::Worker,
            &[],
            &fleet.routes,
            &no_master,
            200,
        )
        .unwrap();
        assert!(report.signed.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .all(|(_, why)| why.contains("master key") && why.contains("not on this machine"))
        );
        assert_eq!(app.state, State::Pending);
        // Nothing reached the channels, and the request is a signed file.
        assert!(!is_live(&fleet.state, &app.agent));
        let file = request_file(&fleet.state, &app.id);
        // The machine with the master key takes the request in and approves it.
        let elsewhere = tempfile::tempdir().unwrap();
        let mut taken = import(elsewhere.path(), &file).unwrap();
        assert_eq!(taken.public_key, app.public_key);
        approve(
            elsewhere.path(),
            &mut taken,
            Level::Worker,
            &[],
            &fleet.routes,
            &master,
            400,
        )
        .unwrap();
        // Back on the first machine the grant has synced: settling approves it, no master key needed.
        assert!(settle(&fleet.state, &mut app, &fleet.routes, 500).unwrap());
        assert_eq!(app.state, State::Approved);
        // A request whose signature or key was altered is refused.
        let mut forged: App = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        forged.id = "app-forged000000".into();
        forged.public_key = "00".repeat(32);
        let forged_file = elsewhere.path().join("forged.json");
        fs::write(&forged_file, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(import(elsewhere.path(), &forged_file).is_err());
    }

    #[test]
    fn revoke_ends_the_key_and_signs_the_grant_down_with_a_revocation() {
        let fleet = fleet();
        let mut app = ask(&fleet);
        approve(
            &fleet.state,
            &mut app,
            Level::Member,
            &[],
            &fleet.routes,
            &master,
            200,
        )
        .unwrap();
        let report = revoke(&fleet.state, &mut app, &fleet.routes, &master, 300).unwrap();
        assert!(report.key_deleted);
        assert_eq!(report.signed, ["alpha", "beta"]);
        assert!(load_key(&fleet.state, &app.agent).is_none());
        assert_eq!(app.state, State::Revoked);
        assert!(!is_live(&fleet.state, &app.agent));
        assert_eq!(revoked_agents(&fleet.state), [app.agent.clone()]);
        for route in &fleet.routes {
            assert_eq!(
                access::level_of(&route.communications, &route.project_id, &app.agent),
                Level::Worker
            );
            assert!(crate::master::is_revoked(route, &app.agent).unwrap());
        }
        // A revoked app cannot be approved again, and settling does not revive it.
        assert!(
            approve(
                &fleet.state,
                &mut app,
                Level::Worker,
                &[],
                &fleet.routes,
                &master,
                400
            )
            .is_err()
        );
        assert!(!settle(&fleet.state, &mut app, &fleet.routes, 400).unwrap());
        // Without the master key the local kill still happens and the rest is reported.
        let mut other = ask(&fleet);
        approve(
            &fleet.state,
            &mut other,
            Level::Worker,
            &[],
            &fleet.routes,
            &master,
            500,
        )
        .unwrap();
        let report = revoke(&fleet.state, &mut other, &fleet.routes, &no_master, 600).unwrap();
        assert!(report.key_deleted && report.signed.is_empty() && report.skipped.len() == 2);
        assert!(load_key(&fleet.state, &other.agent).is_none());
    }

    #[test]
    fn denying_deletes_the_key_and_stale_requests_are_pruned() {
        let fleet = fleet();
        let mut app = ask(&fleet);
        deny(&fleet.state, &mut app, 150).unwrap();
        assert!(load_key(&fleet.state, &app.agent).is_none());
        assert!(deny(&fleet.state, &mut app, 160).is_err());
        let stale = ask(&fleet);
        let later = request(
            &fleet.state,
            &fleet.routes,
            &Request {
                client_name: "Claude",
                redirect_host: "claude.ai",
            },
            100 + STALE_SECS + 1,
        )
        .unwrap();
        assert!(find(&fleet.state, &stale.id).is_err());
        // The pruned request's key went with it: its name is free again, with a new key.
        assert_eq!(later.agent, stale.agent);
        assert_ne!(later.public_key, stale.public_key);
        assert_eq!(
            load_key(&fleet.state, &later.agent)
                .unwrap()
                .public_key_hex(),
            later.public_key
        );
        assert!(find(&fleet.state, &later.id).is_ok());
        // Ids can be given whole, as a long enough prefix, or as the agent name.
        assert_eq!(find(&fleet.state, &later.id[..10]).unwrap().id, later.id);
        assert_eq!(find(&fleet.state, &later.agent).unwrap().id, later.id);
    }

    #[test]
    fn usage_is_counted_apart_from_the_record() {
        let fleet = fleet();
        let app = ask(&fleet);
        record_use(&fleet.state, &app.agent, 700);
        record_use(&fleet.state, &app.agent, 710);
        assert_eq!(
            usage(&fleet.state, &app.id),
            Usage {
                last_used: 710,
                calls: 2
            }
        );
        assert_eq!(list(&fleet.state).len(), 1);
    }
}

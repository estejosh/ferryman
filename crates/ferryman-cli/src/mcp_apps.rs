//! `ferry mcp apps`: decide the apps that log in to `ferry mcp serve --http` (ADR 0031).
//!
//! The rules live in [`ferryman_channel::apps`]; this is the terminal around them. Every
//! function returns the lines to print, so the words can be tested.

use std::path::Path;

use anyhow::{Result, bail};
use ferryman_channel::AgentIdentity;
use ferryman_channel::ProjectRoute;
use ferryman_channel::access::Level;
use ferryman_channel::apps::{self, App, State};

/// The master's key for a project, from a key file here or from the operator the person at
/// this terminal unlocks (once, for the whole run).
fn signer(route: &ProjectRoute) -> Option<AgentIdentity> {
    let master = ferryman_channel::master::read_master(route)
        .ok()
        .flatten()?;
    crate::signing_identity_in(&route.attachment, &master.master).ok()
}

/// Unlock the operator who is master of the first project that has one on this machine, so
/// signing in several projects asks for a password once.
fn unlock_master(routes: &[ProjectRoute]) {
    for route in routes {
        if let Some(master) = ferryman_channel::master::read_master(route).ok().flatten()
            && crate::hold_operator(&route.attachment, &master.master).unwrap_or(false)
        {
            return;
        }
    }
}

fn ago(now: i64, then: i64) -> String {
    let secs = (now - then).max(0);
    match secs {
        0..=59 => "just now".into(),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

/// The apps, one line each. Waiting apps whose grant has since synced here are settled first.
pub fn list(state: &Path, routes: &[ProjectRoute], now: i64) -> Vec<String> {
    let mut apps_now = apps::list(state);
    for app in &mut apps_now {
        if app.state == State::Pending {
            let _ = apps::settle(state, app, routes, now);
        }
    }
    if apps_now.is_empty() {
        return vec![
            "no apps have connected yet. Run `ferry mcp pair` and give the code to the app".into(),
        ];
    }
    let mut lines = vec![format!(
        "{:<17} {:<24} {:<8} {:<9} {:<14} {:<10} {:>5}  FROM",
        "ID", "AGENT", "LEVEL", "STATE", "PROJECTS", "LAST USED", "CALLS"
    )];
    for app in apps_now {
        let used = apps::usage(state, &app.id);
        let level = app.level.unwrap_or(app.requested);
        let projects = if app.projects.is_empty() {
            "-".to_string()
        } else {
            app.projects.join(",")
        };
        lines.push(format!(
            "{:<17} {:<24} {:<8} {:<9} {:<14} {:<10} {:>5}  {} ({})",
            app.id,
            app.agent,
            level.as_str(),
            app.state.as_str(),
            projects,
            if used.calls == 0 {
                "never".to_string()
            } else {
                ago(now, used.last_used)
            },
            used.calls,
            app.client_name,
            app.redirect_host,
        ));
    }
    lines
}

/// Approve a waiting app at `level` in the live projects where the master key is here (or
/// only in `only`). With `request`, first take in a signed request made on the machine that
/// runs the server.
pub fn approve(
    state: &Path,
    id: Option<&str>,
    request: Option<&Path>,
    level: &str,
    only: &[String],
    routes: &[ProjectRoute],
    now: i64,
) -> Result<Vec<String>> {
    let level = Level::parse(level)?;
    let mut app = match (request, id) {
        (Some(file), _) => apps::import(state, file)?,
        (None, Some(id)) => apps::find(state, id)?,
        (None, None) => bail!("name the app (ferry mcp apps list), or give --request <file>"),
    };
    for project in only {
        if !routes.iter().any(|r| r.project_id == *project) {
            bail!("no live project '{project}' here");
        }
    }
    unlock_master(routes);
    let report = apps::approve(state, &mut app, level, only, routes, &signer, now)?;
    let mut lines = Vec::new();
    if app.state == State::Approved {
        lines.push(format!(
            "approved {} ({}) as {} in: {}",
            app.agent,
            app.id,
            app.level.unwrap_or(level).as_str(),
            app.projects.join(", ")
        ));
        lines.push("the app's browser continues by itself".into());
    } else {
        lines.push(format!(
            "{} ({}) is still waiting: no grant could be signed here",
            app.agent, app.id
        ));
    }
    for (project, why) in &report.skipped {
        lines.push(format!("  {project}: {why}"));
    }
    if app.state == State::Pending {
        lines.push(format!(
            "its signed request is {}. Take it to the machine that holds the master key and run:\n  ferry mcp apps approve --request <that file> --level {}\nwhen the grant syncs back here the app continues by itself",
            apps::request_file(state, &app.id).display(),
            level.as_str(),
        ));
    }
    Ok(lines)
}

/// Refuse a waiting app.
pub fn deny(state: &Path, id: &str, now: i64) -> Result<Vec<String>> {
    let mut app = apps::find(state, id)?;
    apps::deny(state, &mut app, now)?;
    Ok(vec![format!(
        "denied {} ({}); its key is deleted",
        app.agent, app.id
    )])
}

/// End an app: every token at once, the grant, the key.
pub fn revoke(state: &Path, id: &str, routes: &[ProjectRoute], now: i64) -> Result<Vec<String>> {
    let mut app: App = apps::find(state, id)?;
    unlock_master(routes);
    let done = apps::revoke(state, &mut app, routes, &signer, now)?;
    let mut lines = vec![format!(
        "revoked {} ({}): its tokens stop at the next request{}",
        app.agent,
        app.id,
        if done.key_deleted {
            ", and its key is deleted"
        } else {
            ""
        }
    )];
    if !done.signed.is_empty() {
        lines.push(format!(
            "  signed its grant down and recorded the revocation in: {}",
            done.signed.join(", ")
        ));
    }
    for (project, why) in &done.skipped {
        lines.push(format!("  could not sign in {project}: {why}"));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferryman_channel::apps::Request;

    fn setup() -> (tempfile::TempDir, Vec<ProjectRoute>, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("machine"));
        let workspace = dir.path().join("alpha").join("workspace");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: "alpha".into(),
            workspace,
            attachment: attachment.clone(),
            communications: communications.clone(),
            shared_remote: "alpha-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        let josh = AgentIdentity::load_or_create("josh", &attachment).unwrap();
        ferryman_channel::register_agent(
            &route,
            &ferryman_channel::AgentRoute {
                name: "josh".into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(josh.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        route.agents = ferryman_channel::read_agent_roster(&communications).unwrap();
        ferryman_channel::master::initialize_master(&route, &josh, "josh").unwrap();
        let state = dir.path().join("mcp-state");
        (dir, vec![route], state)
    }

    fn ask(state: &Path, routes: &[ProjectRoute]) -> App {
        apps::request(
            state,
            routes,
            &Request {
                client_name: "Claude",
                redirect_host: "claude.ai",
            },
            1000,
        )
        .unwrap()
    }

    #[test]
    fn approve_list_and_revoke_say_what_happened() {
        let (_dir, routes, state) = setup();
        assert!(list(&state, &routes, 1000)[0].contains("no apps have connected"));
        let app = ask(&state, &routes);
        let waiting = list(&state, &routes, 1060).join("\n");
        assert!(
            waiting.contains("claude-ai-josh")
                && waiting.contains("pending")
                && waiting.contains("never")
        );

        // Member only when asked for; Orchestrator never.
        assert!(
            approve(
                &state,
                Some(&app.id),
                None,
                "orchestrator",
                &[],
                &routes,
                1100
            )
            .is_err()
        );
        assert!(
            approve(
                &state,
                Some(&app.id),
                None,
                "worker",
                &["nope".into()],
                &routes,
                1100
            )
            .is_err()
        );
        let said = approve(
            &state,
            Some(&app.id[..8]),
            None,
            "worker",
            &[],
            &routes,
            1100,
        )
        .unwrap()
        .join("\n");
        assert!(
            said.contains("approved claude-ai-josh") && said.contains("as worker in: alpha"),
            "{said}"
        );

        apps::record_use(&state, &app.agent, 1200);
        let shown = list(&state, &routes, 1260).join("\n");
        assert!(
            shown.contains("approved") && shown.contains("1m ago") && shown.contains("alpha"),
            "{shown}"
        );

        let gone = revoke(&state, &app.id, &routes, 1300).unwrap().join("\n");
        assert!(
            gone.contains("revoked claude-ai-josh") && gone.contains("key is deleted"),
            "{gone}"
        );
        assert!(gone.contains("signed its grant down"), "{gone}");
        assert!(list(&state, &routes, 1400).join("\n").contains("revoked"));
        assert!(apps::load_key(&state, &app.agent).is_none());
    }

    #[test]
    fn with_no_master_key_here_it_says_so_and_leaves_the_signed_request() {
        let (_dir, routes, state) = setup();
        let app = ask(&state, &routes);
        std::fs::remove_file(routes[0].attachment.join("keys").join("josh.key")).unwrap();
        // The machine-wide copy of the key would find its way back; there is none in a test
        // machine directory once the attachment's is gone.
        let machine = ferryman_channel::licensing::machine_state_dir().unwrap();
        let _ = std::fs::remove_file(machine.join("keys").join("josh.key"));
        let said = approve(&state, Some(&app.id), None, "worker", &[], &routes, 1100)
            .unwrap()
            .join("\n");
        assert!(said.contains("still waiting"), "{said}");
        assert!(
            said.contains("master key (josh) is not on this machine"),
            "{said}"
        );
        assert!(
            said.contains(&apps::request_file(&state, &app.id).display().to_string()),
            "{said}"
        );
        assert!(said.contains("ferry mcp apps approve --request"), "{said}");
        assert_eq!(apps::find(&state, &app.id).unwrap().state, State::Pending);
    }

    #[test]
    fn deny_refuses_and_deletes_the_key() {
        let (_dir, routes, state) = setup();
        let app = ask(&state, &routes);
        assert!(deny(&state, &app.id, 1100).unwrap()[0].contains("denied claude-ai-josh"));
        assert!(apps::load_key(&state, &app.agent).is_none());
        assert!(approve(&state, Some(&app.id), None, "worker", &[], &routes, 1200).is_err());
    }
}

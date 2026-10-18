//! Finding Ferryman on this machine, and serving its dashboard from inside this process.
//!
//! # Why this does not call `ferry dashboard`
//!
//! `ferry dashboard` starts from the directory it was launched in and asks for *that*
//! project's channel. Launched from a home folder, which is where a double-clicked app or a
//! Start menu entry always starts, it answers "no Ferryman channel found" even on a machine
//! with a full fleet, because the question it asks is about the folder rather than the
//! machine.
//!
//! This asks the machine: the same `find_root` the CLI uses for everything else (an explicit
//! `FERRYMAN_ROOT`, a root the current folder sits inside, then the one this machine
//! remembers), then any project the root has filed. The dashboard needs one project to be
//! "home"; the others are reached through its own project picker and Fleet page, which read
//! the same root.

use std::{net::Ipv4Addr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use ferryman_channel::{
    ProjectRoute,
    ferry::{self, Root},
};
use ferryman_server::{
    dashboard::{self, DashboardState},
    operators::OperatorStore,
};

/// Minutes of inactivity before an operator is signed out. The CLI's default, so the app
/// is no looser than `ferry dashboard` and no tighter.
const SESSION_MINUTES: u64 = 15;

/// What looking for Ferryman found.
pub enum Found {
    /// A root with at least one project this machine can read.
    Ready(Box<ProjectRoute>, Root),
    /// No root anywhere: nothing set up on this machine.
    NoRoot,
    /// A root, but nothing filed in it that can be read yet.
    NoProjects(PathBuf),
}

/// Look for a root, then for a project in it to open on.
///
/// A project with a checkout on this machine is preferred over a channel-only one, since
/// only a checkout has the private directory a signed-in operator's key can sit beside.
/// Ties are broken by name so the choice is the same every launch.
pub fn locate() -> Found {
    let Some(root) = ferry::find_root() else {
        return Found::NoRoot;
    };
    let mut entries = root.projects();
    entries.sort_by(|a, b| {
        (a.attachment().is_none(), &a.project_id).cmp(&(b.attachment().is_none(), &b.project_id))
    });
    for entry in &entries {
        if let Ok((route, _)) = entry.route(&root) {
            return Found::Ready(Box::new(route), root);
        }
    }
    let path = root.path.clone();
    Found::NoProjects(path)
}

/// The folder `set up` makes: `~/ferry`, what `ferry root init` makes when run from home.
pub fn default_root_path() -> Result<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .context("could not find your home folder")?;
    Ok(home.join("ferry"))
}

/// Make the layout and remember it, exactly as `ferry root init` does. Safe to repeat.
pub fn create_root() -> Result<PathBuf> {
    let root = Root::create(&default_root_path()?)?;
    Ok(root.path)
}

/// A dashboard running in this process.
#[derive(Clone)]
pub struct Server {
    pub port: u16,
    /// Kept so the one-time setup token can be shown to the person at the keyboard. It is
    /// never sent over HTTP and never written to a log.
    pub state: DashboardState,
}

/// Serve the dashboard on a free loopback port.
///
/// Loopback only, and the router is the dashboard's own: the same `Host` guard against DNS
/// rebinding, the same sign-in, the same idle timeout as `ferry dashboard`. Port 0 lets the
/// OS pick, so this never collides with a `ferry dashboard` that is already running on 8788.
pub async fn serve(route: ProjectRoute, root: &Root) -> Result<Server> {
    dashboard::discover_projects_in(root.comms());
    let route = Arc::new(route);
    let operators = OperatorStore::new(&route.attachment);
    let state = DashboardState::new(
        route,
        operators,
        false,
        Duration::from_secs(SESSION_MINUTES * 60),
    );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("bind a loopback port")?;
    let port = listener.local_addr()?.port();
    let app = dashboard::router(state.clone());
    tauri::async_runtime::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            eprintln!("ferryman-desktop: the dashboard server stopped: {error}");
        }
    });
    Ok(Server { port, state })
}

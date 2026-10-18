//! Ferryman as a desktop app.
//!
//! It runs the existing dashboard server inside this process, on a loopback port, and shows
//! it in a native web view. There is no second copy of the UI: the page in the window is the
//! page `ferry dashboard` serves, from the same code, behind the same sign-in.
//!
//! What the app adds is the part that was a terminal: it finds the Ferryman folder by itself
//! (see [`boot`]), opens on the fleet, lives in the system tray, and is a single instance.
//!
//! # Security
//!
//! - The server binds `127.0.0.1` only, on a port the OS picks, and is the dashboard's own
//!   router with its `Host` guard, sign-in and idle timeout untouched.
//! - The web view may navigate only to that origin, and may not open new windows.
//! - The dashboard window has no Tauri IPC at all: no capability names it. The only window
//!   with commands is the bundled setup screen, which is local, and each command checks that
//!   it was called from there.
//! - The one-time setup token is shown in a native dialog to the person at the keyboard,
//!   where `ferry dashboard` printed it to a terminal. It is not logged and never served.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod boot;
mod tray;

use tauri::{
    AppHandle, Manager, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent,
    webview::NewWindowResponse,
};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

const MAIN: &str = "main";
const SETUP: &str = "setup";

/// Runs in the dashboard page on every load.
///
/// Two small things, both done from outside the page so `dashboard.html` is untouched:
/// the first screen after sign-in is the Fleet, since that is what this window is for, and
/// the sign-up form's "printed in the terminal" is corrected, because there is no terminal.
const PAGE_SCRIPT: &str = r#"
(function () {
  if (window.__ferrymanDesktop) return;
  window.__ferrymanDesktop = true;
  var wentToFleet = false;
  setInterval(function () {
    var label = document.getElementById("auth-setup-label");
    if (label && !label.dataset.desktop) {
      label.dataset.desktop = "1";
      label.textContent = "Setup token (shown when the app opened; tray menu > First-time setup token)";
    }
    if (!wentToFleet) {
      var button = document.querySelector('#nav-system button[data-page="fleet"]');
      if (button && button.offsetParent !== null) {
        wentToFleet = true;
        button.click();
      }
    }
  }, 250);
})();
"#;

/// Set by the first successful boot; there is exactly one dashboard server per process.
struct Running(tauri::async_runtime::Mutex<Option<boot::Server>>);

enum Outcome {
    Ready,
    NoRoot,
    NoProjects(String),
}

fn main() {
    let app = tauri::Builder::default()
        // First, so a second launch is handled before anything else in it starts.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            open_window(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(Running(tauri::async_runtime::Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![set_up_here, check_again])
        .on_window_event(|window, event| {
            // Closing the window leaves the app in the tray. Quit is in the tray menu.
            if window.label() == MAIN
                && let WindowEvent::CloseRequested { api, .. } = event
            {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            tray::build(app.handle())?;
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let first = boot_window(&handle).await;
                if matches!(first, Outcome::Ready) {
                    show_setup_token_if_new(&handle).await;
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("could not start Ferryman");

    app.run(|_, _| {});
}

/// Show the dashboard if there is one, otherwise whatever it takes to get one.
pub fn open_window(app: &AppHandle) {
    if tray::raise(app, MAIN) || tray::raise(app, SETUP) {
        return;
    }
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        boot_window(&handle).await;
    });
}

/// Find Ferryman and put the right window on screen. Starts the server on first success.
async fn boot_window(app: &AppHandle) -> Outcome {
    match boot::locate() {
        boot::Found::Ready(route, root) => {
            let running = app.state::<Running>();
            let mut slot = running.0.lock().await;
            if slot.is_none() {
                match boot::serve(*route, &root).await {
                    Ok(server) => *slot = Some(server),
                    Err(error) => {
                        eprintln!("ferryman-desktop: could not start the dashboard: {error:#}");
                        app.dialog()
                            .message(format!(
                                "Ferryman could not start its dashboard.\n\n{error:#}"
                            ))
                            .title("Ferryman")
                            .show(|_| {});
                        return Outcome::NoRoot;
                    }
                }
            }
            let port = slot.as_ref().map_or(0, |server| server.port);
            drop(slot);
            if let Err(error) = show_dashboard(app, port) {
                eprintln!("ferryman-desktop: could not open the window: {error}");
            }
            if let Some(setup) = app.get_webview_window(SETUP) {
                let _ = setup.destroy();
            }
            Outcome::Ready
        }
        boot::Found::NoRoot => {
            show_setup(app, "no_root", "");
            Outcome::NoRoot
        }
        boot::Found::NoProjects(path) => {
            let path = path.display().to_string();
            show_setup(app, "no_projects", &path);
            Outcome::NoProjects(path)
        }
    }
}

/// Whether a URL is the dashboard's own origin, and nothing else.
fn is_dashboard(url: &Url, port: u16) -> bool {
    url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && url.port() == Some(port)
}

fn show_dashboard(app: &AppHandle, port: u16) -> tauri::Result<()> {
    if tray::raise(app, MAIN) {
        return Ok(());
    }
    let url: Url = format!("http://127.0.0.1:{port}/")
        .parse()
        .expect("a loopback address is a valid URL");
    WebviewWindowBuilder::new(app, MAIN, WebviewUrl::External(url))
        .title("Ferryman")
        .inner_size(1280.0, 860.0)
        .min_inner_size(900.0, 600.0)
        .initialization_script(PAGE_SCRIPT)
        .on_navigation(move |url| is_dashboard(url, port))
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()?;
    Ok(())
}

fn show_setup(app: &AppHandle, state: &str, path: &str) {
    // Already on screen: the button that asked is waiting on this answer and redraws itself
    // from it, so replacing the window under it would only lose the reply.
    if tray::raise(app, SETUP) {
        return;
    }
    let page = format!("index.html?state={state}&path={}", percent(path));
    let built = WebviewWindowBuilder::new(app, SETUP, WebviewUrl::App(page.into()))
        .title("Ferryman")
        .inner_size(560.0, 420.0)
        .resizable(false)
        .focused(true)
        .build();
    if let Err(error) = built {
        eprintln!("ferryman-desktop: could not open the setup window: {error}");
    }
}

/// Just enough escaping for a file path in a query string.
fn percent(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn outcome_json(outcome: &Outcome) -> String {
    let (state, path) = match outcome {
        Outcome::Ready => ("ready", String::new()),
        Outcome::NoRoot => ("no_root", String::new()),
        Outcome::NoProjects(path) => ("no_projects", path.clone()),
    };
    serde_json::json!({ "state": state, "path": path }).to_string()
}

/// The setup screen's commands run only for the setup screen.
fn only_setup(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == SETUP {
        Ok(())
    } else {
        Err("not available here".into())
    }
}

#[tauri::command]
async fn set_up_here(window: WebviewWindow, app: AppHandle) -> Result<String, String> {
    only_setup(&window)?;
    boot::create_root().map_err(|error| format!("{error:#}"))?;
    Ok(outcome_json(&boot_window(&app).await))
}

#[tauri::command]
async fn check_again(window: WebviewWindow, app: AppHandle) -> Result<String, String> {
    only_setup(&window)?;
    Ok(outcome_json(&boot_window(&app).await))
}

/// On a fresh install there is no operator, and creating the first one needs a one-time
/// token. `ferry dashboard` prints it to the terminal; with no terminal, show it to the
/// person at the keyboard instead.
async fn show_setup_token_if_new(app: &AppHandle) {
    let token = {
        let running = app.state::<Running>();
        let slot = running.0.lock().await;
        slot.as_ref()
            .and_then(|server| server.state.bootstrap_token())
    };
    if let Some(token) = token {
        offer_token(app, token, true);
    }
}

/// The tray's "First-time setup token" item.
pub fn show_setup_token(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let token = {
            let running = handle.state::<Running>();
            let slot = running.0.lock().await;
            slot.as_ref()
                .and_then(|server| server.state.bootstrap_token())
        };
        match token {
            Some(token) => offer_token(&handle, token, false),
            None => {
                handle
                    .dialog()
                    .message("An operator already exists on this machine, so no setup token is needed. Sign in from the window.")
                    .title("Ferryman")
                    .show(|_| {});
            }
        }
    });
}

fn offer_token(app: &AppHandle, token: String, first_run: bool) {
    let intro = if first_run {
        "Welcome to Ferryman. To create the first operator you need this one-time setup token.\n\n"
    } else {
        "This is the one-time setup token for creating the first operator.\n\n"
    };
    let message = format!(
        "{intro}{token}\n\nPaste it into the sign-up form. It stops working as soon as one operator exists. Copying puts it on your clipboard."
    );
    let handle = app.clone();
    app.dialog()
        .message(message)
        .title("Ferryman setup token")
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Copy token".into(),
            "Close".into(),
        ))
        .show(move |copy| {
            if copy {
                let _ = handle.clipboard().write_text(token);
            }
        });
}

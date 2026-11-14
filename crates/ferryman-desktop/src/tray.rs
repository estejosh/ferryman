//! The system tray: what the governor currently says, and the one control worth having.
//!
//! This is what `ferryman-tray` does, folded in. It owns nothing and holds no state: it reads
//! the same governor the worker loop reads and writes the same pause marker `ferry pause`
//! writes, so quitting the app changes nothing about whether work happens.

use std::time::Duration;

use tauri::{
    AppHandle, Manager,
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

/// How often the status line is refreshed. Each poll is a file check and a memory reading.
const REFRESH: Duration = Duration::from_secs(2);

/// The light mark. A tray sits on a taskbar that is dark far more often than not, and the
/// navy mark on a dark taskbar looks like no icon at all.
const ICON: &[u8] = include_bytes!("../icons/tray.png");

pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Ferryman", true, None::<&str>)?;
    let status = MenuItem::with_id(app, "status", "checking...", false, None::<&str>)?;
    let pause = MenuItem::with_id(
        app,
        "pause",
        "Pause this machine's worker",
        true,
        None::<&str>,
    )?;
    let token = MenuItem::with_id(
        app,
        "token",
        "First-time setup token...",
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit Ferryman", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &open,
            &PredefinedMenuItem::separator(app)?,
            &status,
            &pause,
            &PredefinedMenuItem::separator(app)?,
            &token,
            &quit,
        ],
    )?;

    TrayIconBuilder::with_id("ferryman")
        .icon(Image::from_bytes(ICON)?)
        .tooltip("Ferryman")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => crate::open_window(app),
            "pause" => toggle_pause(),
            "token" => crate::show_setup_token(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                crate::open_window(tray.app_handle());
            }
        })
        .build(app)?;

    std::thread::spawn(move || {
        let mut shown = String::new();
        loop {
            let (line, label) = describe();
            if line != shown {
                let _ = status.set_text(&line);
                let _ = pause.set_text(label);
                shown = line;
            }
            std::thread::sleep(REFRESH);
        }
    });
    Ok(())
}

/// The status line, and what the pause item should say.
fn describe() -> (String, &'static str) {
    use ferryman_ops::governor::{self, Presence};
    if let Some(note) = governor::paused() {
        return (
            format!("Worker paused - {note}"),
            "Resume this machine's worker",
        );
    }
    let line = match governor::presence() {
        Presence::Active(idle) if idle < Duration::from_secs(300) => {
            format!("Waiting - you used this machine {}s ago", idle.as_secs())
        }
        _ => match governor::available_memory_mb() {
            Some(mb) => format!("Ready - {mb} MB free"),
            None => "Ready".to_string(),
        },
    };
    (line, "Pause this machine's worker")
}

/// Pause or resume by creating or removing the marker `ferry pause` / `ferry resume` use.
fn toggle_pause() {
    let Some(path) = ferryman_ops::governor::pause_marker() else {
        return;
    };
    if ferryman_ops::governor::paused().is_some() {
        let _ = std::fs::remove_file(&path);
    } else {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, "paused from the desktop app");
    }
}

/// Bring the dashboard window forward, wherever it is hiding.
pub fn raise(app: &AppHandle, label: &str) -> bool {
    let Some(window) = app.get_webview_window(label) else {
        return false;
    };
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
    true
}

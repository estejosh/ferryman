//! Ferryman in the system tray.
//!
//! # What this is for
//!
//! Ferryman decides, several times a minute, whether to pick up work. Until now those
//! decisions were invisible: the machine either did something or it did not, and the
//! only way to ask why was to run a command. That is the complaint the first outside
//! user made in a different form - a fleet that reports itself empty, with no way to
//! see what it thinks is true.
//!
//! So this shows the current answer, and offers the one control worth having: stop.
//!
//! # Why it owns nothing
//!
//! The tray does not run agents, does not hold state, and is not required. It reads the
//! same governor the worker loop reads and writes the same pause file `ferry pause`
//! writes. Quitting it changes nothing about whether work happens - which is the point,
//! because a tray that is load-bearing is a tray whose crash stops your fleet.
//!
//! # The icon must be the light mark
//!
//! Built with the navy mark first, and it appeared to not work at all: the process ran,
//! reported no error, and no icon was visible. It was visible - #0D132B on a dark
//! taskbar is a dark shape on a dark background, and it read as another application's
//! icon. The light mark is not a preference here, it is the difference between working
//! and appearing not to.
//!
//! Confirmed the only way worth trusting: stop the process and watch the notification
//! area reflow from fourteen icons to thirteen.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use winit::application::ApplicationHandler;
use winit::event_loop::{ControlFlow, EventLoop};

/// How often the menu is rebuilt from what the governor currently says.
///
/// Two seconds: fast enough that the answer is never stale when someone opens the menu
/// to ask, cheap enough that it is invisible - each poll is a file check and a memory
/// reading, not a process spawn.
const REFRESH: Duration = Duration::from_secs(2);

fn main() -> Result<()> {
    // GTK must be initialised before a tray icon exists on Linux, and only there.
    #[cfg(target_os = "linux")]
    gtk::init().ok();

    let event_loop = EventLoop::new().context("start the event loop")?;
    event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + REFRESH));
    let mut app = Tray::new()?;
    event_loop.run_app(&mut app).context("run the tray")?;
    Ok(())
}

struct Tray {
    icon: Option<TrayIcon>,
    status: MenuItem,
    pause: MenuItem,
    /// Rebuilt only when the text changes: replacing menu text every two seconds makes
    /// an open menu flicker and, on Windows, can close it under the cursor.
    shown: String,
    paused: bool,
}

impl Tray {
    fn new() -> Result<Self> {
        Ok(Self {
            icon: None,
            status: MenuItem::new("checking…", false, None),
            pause: MenuItem::new("Pause", true, None),
            shown: String::new(),
            paused: false,
        })
    }

    /// Build the tray once the event loop is running.
    ///
    /// Deliberately not in `new`: on macOS a tray icon created before the loop starts is
    /// not attached to the status bar, and simply never appears.
    fn build(&mut self) -> Result<()> {
        let menu = Menu::new();
        menu.append(&self.status)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&self.pause)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&MenuItem::with_id("quit", "Quit", true, None))?;

        self.icon = Some(
            TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("Ferryman")
                .with_icon(icon()?)
                .build()
                .context("create the tray icon")?,
        );
        Ok(())
    }

    /// Ask the governor what it would do, and say so.
    fn refresh(&mut self) {
        let paused = ferryman_ops::governor::paused();
        self.paused = paused.is_some();
        self.pause
            .set_text(if self.paused { "Resume" } else { "Pause" });

        let text = match paused {
            Some(note) => format!("Paused - {note}"),
            None => match ferryman_ops::governor::presence() {
                ferryman_ops::governor::Presence::Active(idle) if idle < Duration::from_secs(300) => {
                    format!("Waiting - you used this machine {}s ago", idle.as_secs())
                }
                _ => match ferryman_ops::governor::available_memory_mb() {
                    Some(mb) => format!("Ready - {mb} MB free"),
                    None => "Ready".to_string(),
                },
            },
        };
        if text != self.shown {
            self.status.set_text(&text);
            self.shown = text;
        }
    }

    fn toggle_pause(&mut self) {
        let Some(path) = ferryman_ops::governor::pause_marker() else {
            return;
        };
        if self.paused {
            let _ = std::fs::remove_file(&path);
        } else {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&path, "paused from the tray");
        }
        self.refresh();
    }
}

impl Tray {
    /// Create the tray if it does not exist, and say so loudly if that fails.
    ///
    /// This was originally `if self.build().is_ok()`, which meant a tray that failed to
    /// appear looked exactly like a tray that was working: the process ran, printed
    /// nothing, and showed no icon. Swallowing the one error that matters is worse than
    /// not handling it.
    fn ensure_built(&mut self) {
        if self.icon.is_some() {
            return;
        }
        match self.build() {
            Ok(()) => self.refresh(),
            Err(error) => eprintln!("ferryman-tray: could not create the tray icon: {error:#}"),
        }
    }
}

impl ApplicationHandler for Tray {
    fn resumed(&mut self, _: &winit::event_loop::ActiveEventLoop) {
        self.ensure_built();
    }

    fn window_event(
        &mut self,
        _: &winit::event_loop::ActiveEventLoop,
        _: winit::window::WindowId,
        _: winit::event::WindowEvent,
    ) {
    }

    fn new_events(&mut self, loop_: &winit::event_loop::ActiveEventLoop, _: winit::event::StartCause) {
        // Also here, not only in `resumed`: whether `resumed` fires on a desktop platform
        // for an application that never opens a window is not something to bet the whole
        // feature on, and this handler runs regardless.
        self.ensure_built();
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id.0 == "quit" {
                loop_.exit();
                return;
            }
            if event.id == self.pause.id().clone() {
                self.toggle_pause();
            }
        }
        self.refresh();
        loop_.set_control_flow(ControlFlow::WaitUntil(Instant::now() + REFRESH));
    }
}

/// The tray glyph.
///
/// The 32px mark, because that is the size the brand's own rules say the full wheel
/// survives at; below it the handles come off and a different file is used. Embedded in
/// the binary rather than read from disk, so the tray cannot start up without its icon.
fn icon() -> Result<tray_icon::Icon> {
    // The off-white mark, not the navy one. A tray sits on the taskbar, taskbars are
    // dark far more often than not, and #0D132B on a dark taskbar is a dark smudge on a
    // dark background. The brand ships both for exactly this reason.
    const PNG: &[u8] = include_bytes!("../../../assets/brand/png/ferryman-32-dark.png");
    let image = image::load_from_memory(PNG)
        .context("decode the embedded tray icon")?
        .into_rgba8();
    let (width, height) = image.dimensions();
    tray_icon::Icon::from_rgba(image.into_raw(), width, height).context("build the tray icon")
}

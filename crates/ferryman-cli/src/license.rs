//! `ferry license` - what this deployment counts as, and telling the Licensor.
//!
//! The check-in is the part users are entitled to be suspicious of, so it is built to
//! be checkable rather than trusted:
//!
//! - `--dry-run` prints the exact bytes and sends nothing.
//! - The payload type has no field for content, so no amount of misuse can put a task,
//!   a prompt or a file name into it.
//! - A failure to send is ignored. Licensing never blocks work, and a Licensor whose
//!   endpoint is down must not take a customer's fleet with it.

use anyhow::{Context, Result};
use ferryman_channel::ProjectRoute;
use ferryman_channel::licensing::{self, DeviceKind, DeviceRecord};
use std::time::Duration;

/// Where check-ins go. Unset means the build does not report at all.
fn endpoint() -> Option<String> {
    std::env::var("FERRYMAN_CHECKIN_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && value != "off")
}

/// Count this deployment and say where it stands.
pub fn status(route: &ProjectRoute, as_json: bool) -> Result<()> {
    let devices = licensing::read_devices(route)?;
    let counted = licensing::count(&devices);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "seats": counted.seats,
                "computers": counted.computers,
                "mobile_devices": counted.mobile_devices,
                "agents": "unlimited",
                "over_limit": counted.over_limit(),
                "exceeded": counted.exceeded(),
                "registered_emails": licensing::registered_emails(&devices),
                "free_tier": {
                    "seats": licensing::FREE_SEATS,
                    "computers": licensing::FREE_COMPUTERS,
                    "mobile_devices": licensing::FREE_MOBILE_DEVICES,
                },
            }))?
        );
        return Ok(());
    }
    println!("  seats           {}", counted.seats);
    println!("  computers       {}", counted.computers);
    println!("  phones/tablets  {}", counted.mobile_devices);
    println!("  agents          unlimited, and never counted");
    if devices.is_empty() {
        println!("\nNothing registered yet. Run 'ferry enable --email you@example.com'.");
        return Ok(());
    }
    if counted.over_limit() {
        print!("{}", licensing::over_limit_notice(&counted));
    } else {
        println!("\nWithin the free tier.");
    }
    Ok(())
}

/// Register or update this machine's record.
pub fn register(route: &ProjectRoute, email: &str, kind: DeviceKind) -> Result<()> {
    let id = licensing::device_id(&route.attachment)?;
    let record = DeviceRecord {
        id: id.clone(),
        kind,
        operator_email: email.trim().to_string(),
        registered_at: chrono::Utc::now(),
    };
    let path = licensing::register_device(route, &record)?;
    println!("registered this {} as {}", kind.as_str(), email.trim());
    println!("  {}", path.display());
    warn_if_over(route)?;
    Ok(())
}

/// Print the over-limit notice if the fleet is beyond the free tier.
///
/// Called from the setup and the loops rather than only from `license status`, because
/// a notice nobody runs the command to see is not a notice.
pub fn warn_if_over(route: &ProjectRoute) -> Result<()> {
    let devices = licensing::read_devices(route)?;
    let counted = licensing::count(&devices);
    if counted.over_limit() {
        eprint!("{}", licensing::over_limit_notice(&counted));
    }
    Ok(())
}

/// Send the check-in, or show exactly what would be sent.
pub async fn check_in(route: &ProjectRoute, dry_run: bool) -> Result<()> {
    let Some(payload) = licensing::check_in(route, env!("CARGO_PKG_VERSION"))? else {
        println!("nothing registered yet, so there is nothing to report");
        return Ok(());
    };
    let body = serde_json::to_string_pretty(&payload)?;
    if dry_run {
        println!("{body}");
        println!("\n-- dry run: nothing was sent --");
        match endpoint() {
            Some(url) => println!("would POST the above to {url}"),
            None => println!("no check-in URL is set, so this build reports nothing"),
        }
        return Ok(());
    }
    let Some(url) = endpoint() else {
        println!("no check-in URL is set; nothing sent");
        return Ok(());
    };
    // Short timeout, and a failure is not an error: the alternative is a fleet that
    // stalls because someone else's web server is down.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build the HTTP client")?;
    match client.post(&url).json(&payload).send().await {
        Ok(response) if response.status().is_success() => println!("checked in"),
        Ok(response) => eprintln!("check-in refused by {url}: {}", response.status()),
        Err(error) => eprintln!("check-in could not be delivered (ignored): {error}"),
    }
    Ok(())
}

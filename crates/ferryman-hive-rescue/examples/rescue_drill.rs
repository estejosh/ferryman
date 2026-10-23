//! A self-contained harness for the rescue drill (docs/testing/rescue-drill.md): two real
//! machines, a throwaway channel of their own, and the real lane and rescue code.
//!
//! It touches nothing of the live fleet: its own iroh key, roster, channel and state live
//! under `--dir`, it joins no real channel, and it is a separate executable so a firewall
//! rule can be scoped to it alone.
//!
//! ```text
//! rescue_drill init  --dir D --name N --primary-relay URL      # makes D/export/
//!   (copy each machine's export/ to the other's D/peer/)
//! rescue_drill run   --dir D --name N --master M --role master|peer --primary-relay URL
//!                    --primary-pin HEX --rescue-relay URL --hive URL [--serve-hive ADDR]
//!                    [--cut-minutes 2] [--expires-minutes 15] [--poll-minutes 1]
//! rescue_drill probe-hive --node URL --account NAME            # read-only, real node
//! ```
//!
//! Every line it prints starts with a UTC timestamp to the millisecond, for the drill's
//! timings. The Hive posting key is the reference implementation's test key unless
//! `HIVE_RESCUE_POSTING_KEY` says otherwise; against the mock node it is never checked.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use ferryman_channel::secrets::EncryptionIdentity;
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};
use ferryman_hive_rescue::config::{Credentials, RescueConfig};
use ferryman_hive_rescue::mock::MockHive;
use ferryman_hive_rescue::rescuer::{FleetView, Rescuer, ViewFn};
use ferryman_hive_rescue::rpc::HiveClient;
use ferryman_hive_rescue::tx::{CustomJson, PostingKey};
use ferryman_iroh::config::FleetRelayEntry;
use ferryman_iroh::{IrohConfig, Lane, endpoint_hex};
use serde::{Deserialize, Serialize};

const TEST_WIF: &str = "5K2r4ZRQ9HUu1Y1Sfon55LSe5jLwKiwcB7wAEi61cHKDjZ3LrGY";

fn arg(name: &str) -> Option<String> {
    let flag = format!("--{name}");
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| *a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn need(name: &str) -> Result<String> {
    arg(name).with_context(|| format!("--{name} is required"))
}

fn log(text: impl AsRef<str>) {
    println!(
        "{} {}",
        Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        text.as_ref()
    );
}

#[derive(Serialize, Deserialize)]
struct Identity {
    sign_seed: String,
    enc_seed: String,
    iroh_key: String,
}

#[derive(Serialize, Deserialize)]
struct Me {
    name: String,
    sign_pub: String,
    enc_pub: String,
    endpoint_id: String,
}

fn seed32(text: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(text)?.as_slice()).map_err(|_| anyhow::anyhow!("not 32 bytes"))
}

fn load_identity(dir: &Path) -> Result<Identity> {
    let path = dir.join("identity.json");
    if let Ok(bytes) = std::fs::read(&path) {
        return Ok(serde_json::from_slice(&bytes)?);
    }
    std::fs::create_dir_all(dir)?;
    let rand_hex = || {
        let mut b = [0_u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut b);
        hex::encode(b)
    };
    let id = Identity {
        sign_seed: rand_hex(),
        enc_seed: rand_hex(),
        iroh_key: rand_hex(),
    };
    std::fs::write(&path, serde_json::to_vec_pretty(&id)?)?;
    Ok(id)
}

fn route(dir: &Path) -> Result<ProjectRoute> {
    let workspace = dir.join("chan").join("drill");
    let attachment = workspace.join(".ferryman");
    let communications = attachment.join("ferryman");
    std::fs::create_dir_all(&communications)?;
    Ok(ProjectRoute {
        project_id: "drill".into(),
        workspace,
        attachment,
        communications,
        shared_remote: String::new(),
        git_remote: String::new(),
        git_visibility: "private".into(),
        agents: Vec::new(),
    })
}

fn agent_route(me: &Me) -> AgentRoute {
    AgentRoute {
        name: me.name.clone(),
        role: "worker".into(),
        capabilities: Vec::new(),
        public_key: Some(me.sign_pub.clone()),
        encryption_key: Some(me.enc_pub.clone()),
    }
}

fn init(dir: &Path) -> Result<()> {
    let name = need("name")?;
    let primary = need("primary-relay")?;
    let id = load_identity(dir)?;
    let signer = AgentIdentity::from_seed(&name, seed32(&id.sign_seed)?);
    let enc = EncryptionIdentity::from_seed(&name, seed32(&id.enc_seed)?);
    let key = iroh::SecretKey::from_bytes(&seed32(&id.iroh_key)?);
    let me = Me {
        name: name.clone(),
        sign_pub: signer.public_key_hex(),
        enc_pub: enc.public_key_hex(),
        endpoint_id: endpoint_hex(&key.public()),
    };
    let route = route(dir)?;
    ferryman_channel::register_agent(&route, &agent_route(&me))?;
    ferryman_channel::transports::publish(&route, &signer, &me.endpoint_id, Some(&primary))?;
    let export = dir.join("export");
    std::fs::create_dir_all(&export)?;
    std::fs::write(export.join("me.json"), serde_json::to_vec_pretty(&me)?)?;
    std::fs::copy(
        route.communications.join("transports").join(format!(
            "{}.json",
            ferryman_channel::canonical_agent_name(&name)
        )),
        export.join("transports.json"),
    )?;
    log(format!("init ok: {name} endpoint {}", me.endpoint_id));
    log(format!(
        "copy {} to the other machine's <dir>/peer/",
        export.display()
    ));
    Ok(())
}

async fn run(dir: PathBuf) -> Result<()> {
    let name = need("name")?;
    let master = need("master")?;
    let role = need("role")?;
    let primary = need("primary-relay")?;
    let pin = need("primary-pin")?;
    let rescue_relay = need("rescue-relay")?;
    let hive_url = need("hive")?;
    let num = |n: &str, d: u64| arg(n).and_then(|v| v.parse().ok()).unwrap_or(d);

    let id = load_identity(&dir)?;
    let signer = AgentIdentity::from_seed(&name, seed32(&id.sign_seed)?);
    let enc = EncryptionIdentity::from_seed(&name, seed32(&id.enc_seed)?);
    let key = iroh::SecretKey::from_bytes(&seed32(&id.iroh_key)?);
    let me: Me = serde_json::from_slice(&std::fs::read(dir.join("export/me.json"))?)?;
    let peer: Me = serde_json::from_slice(
        &std::fs::read(dir.join("peer/me.json"))
            .context("copy the other machine's export/ to <dir>/peer/ first")?,
    )?;
    let route = route(&dir)?;
    ferryman_channel::register_agent(&route, &agent_route(&me))?;
    ferryman_channel::register_agent(&route, &agent_route(&peer))?;
    let transports = route.communications.join("transports");
    std::fs::create_dir_all(&transports)?;
    std::fs::copy(
        dir.join("peer/transports.json"),
        transports.join(format!(
            "{}.json",
            ferryman_channel::canonical_agent_name(&peer.name)
        )),
    )?;

    if let Some(addr) = arg("serve-hive") {
        let mock = MockHive::start(&addr).await?;
        let wif = std::env::var("HIVE_RESCUE_POSTING_KEY").unwrap_or_else(|_| TEST_WIF.into());
        mock.authorize_key("drillfleet", &PostingKey::from_wif(&wif)?);
        log(format!("mock Hive node serving on {}", mock.url()));
        std::mem::forget(mock);
    }

    // `--primary-pin none` means the primary relay has a public certificate (no pin).
    let pin_line = if pin == "none" {
        String::new()
    } else {
        format!("relay_cert_sha256 = \"{pin}\"\n")
    };
    let toml = format!("[iroh]\nenabled = true\nrelay_url = \"{primary}\"\n{pin_line}");
    let mut cfg = IrohConfig::parse(&toml, Some(&dir));
    for note in &cfg.notes {
        log(format!("config note: {note}"));
    }
    cfg.rescue_relays.push(FleetRelayEntry {
        url: rescue_relay.clone(),
        pin: None,
    });
    let (endpoint, _fallback, shared) = ferryman_iroh::lane::bind_shared(&cfg, key).await?;
    log(format!(
        "endpoint {} bound; primary relay {primary}; rescue relay {rescue_relay}",
        endpoint_hex(&endpoint.id())
    ));
    let status_file = dir.join("iroh-status.json");
    let lane = Lane::new(
        endpoint,
        vec![route.clone()],
        Some(primary.clone()),
        Some(status_file),
    );
    lane.configure_relays(true, None);
    tokio::spawn(Arc::clone(&lane).run(Duration::from_secs(10)));

    let roster = vec![agent_route(&me), agent_route(&peer)];
    let master_name = ferryman_channel::canonical_agent_name(&master);
    let view: ViewFn = Arc::new(move || FleetView {
        roster: roster.clone(),
        master: Some(master_name.clone()),
        ..FleetView::default()
    });
    let rescue_cfg = RescueConfig {
        enabled: true,
        account: "drillfleet".into(),
        nodes: vec![hive_url.clone()],
        cut_off_minutes: num("cut-minutes", 2),
        poll_minutes: num("poll-minutes", 1),
        expires_minutes: num("expires-minutes", 15),
        repost_minutes: 0,
        rescue_relay: Some(rescue_relay),
        ..RescueConfig::default()
    };
    let wif = std::env::var("HIVE_RESCUE_POSTING_KEY").unwrap_or_else(|_| TEST_WIF.into());
    let creds = Credentials {
        account: "drillfleet".into(),
        poster: None,
        key: (role == "master")
            .then(|| PostingKey::from_wif(&wif))
            .transpose()?,
    };
    let rescuer = Arc::new(Rescuer::with_client(
        rescue_cfg,
        creds,
        HiveClient::new(vec![hive_url]).with_min_ok(1),
        view,
        dir.clone(),
        signer,
        enc,
    ));
    rescuer.attach(lane.endpoint(), shared)?;
    tokio::spawn(Arc::clone(&rescuer).run(Arc::clone(&lane), Duration::from_secs(5)));
    log(format!("running as {name} ({role}); master is {master}"));

    // Watch, and say what changes.
    let comms = route.communications.clone();
    let mut last = String::new();
    let (mut last_seq, mut last_post, mut last_files, mut tick) = (0_u64, 0_u64, 0_usize, 0_u64);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        tick += 1;
        let status = lane.status();
        let peer_status = status.peers.values().next();
        let line = format!(
            "relay_connected={} peer_ok={} path={} failing_since={} cut_off={}",
            status.relay_connected,
            peer_status.is_some_and(|p| p.last_error.is_none() && p.last_sync.is_some()),
            peer_status
                .and_then(|p| p.path.clone())
                .unwrap_or_else(|| "-".into()),
            peer_status
                .and_then(|p| p.failing_since)
                .map_or("-".into(), |t| t.format("%H:%M:%S").to_string()),
            ferryman_hive_rescue::cut_off_since(&status)
                .map_or("-".into(), |t| t.format("%H:%M:%S").to_string()),
        );
        if line != last {
            log(format!("STATE {line}"));
            last = line;
        }
        let state = rescuer.snapshot();
        if state.posted.seq != last_post {
            last_post = state.posted.seq;
            log(format!(
                "EVENT posted record seq {} ({:?}) tx {}",
                state.posted.seq,
                state.posted.kind,
                state.posted.tx_id.clone().unwrap_or_default()
            ));
        }
        if let Some(rec) = &state.latest_master
            && rec.body.seq != last_seq
        {
            last_seq = rec.body.seq;
            log(format!(
                "EVENT accepted master record seq {} issued {} -> endpoint {}",
                rec.body.seq,
                rec.body.issued,
                &rec.body.at.id[..12]
            ));
        }
        if role == "master" && tick % 20 == 0 {
            let file = comms
                .join("msgs")
                .join(format!("m-{}.json", Utc::now().timestamp()));
            std::fs::create_dir_all(file.parent().unwrap())?;
            std::fs::write(
                &file,
                format!("{{\"from\":\"{name}\",\"at\":\"{}\"}}", Utc::now()),
            )?;
        }
        let files = std::fs::read_dir(comms.join("msgs")).map_or(0, std::iter::Iterator::count);
        if files != last_files {
            last_files = files;
            log(format!("EVENT channel files in msgs/: {files}"));
        }
    }
}

async fn probe(node: &str, account: &str) -> Result<()> {
    let client = HiveClient::new(vec![node.to_owned()]).with_min_ok(1);
    let read = client.read_history(account, "ferryman-rescue", 100).await;
    log(format!(
        "{node}: answered={:?} failed={:?} ops_with_our_id={}",
        read.answered,
        read.failed,
        read.ops.len()
    ));
    if read.answered.is_empty() {
        bail!("the node did not answer a get_account_history");
    }
    let tx = client
        .build(CustomJson {
            required_auths: Vec::new(),
            required_posting_auths: vec![account.to_owned()],
            id: "ferryman-rescue".into(),
            json: "{}".into(),
        })
        .await?;
    log(format!(
        "head reference ok: ref_block_num {} prefix {} expiration {}",
        tx.ref_block_num, tx.ref_block_prefix, tx.expiration
    ));
    log("read-only: nothing was signed or broadcast");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("init") => init(Path::new(&need("dir")?)),
        Some("run") => run(PathBuf::from(need("dir")?)).await,
        Some("probe-hive") => probe(&need("node")?, &need("account")?).await,
        _ => bail!("rescue_drill init | run | probe-hive (see the file's header)"),
    }
}

//! `ferry rescue hive`: the Hive rescue channel (ADR 0027), opt-in.
//!
//! The commands are always in the binary so `--help` is the same everywhere; without
//! `--features hive-rescue` they say how to get it.

#[derive(clap::Subcommand, Clone)]
pub(crate) enum HiveCommand {
    /// Config, credentials, whether this machine is cut off, and the last records.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Post a record now. `--dry-run` prints the record, the sealed operation and the
    /// transaction without broadcasting anything.
    Post {
        #[arg(long)]
        dry_run: bool,
        /// Post as the designated backup (a pointer to this machine) rather than master.
        #[arg(long)]
        backup: bool,
    },
    /// Scan the fleet account's recent Hive history and report every record that opens and
    /// verifies (and why the others do not). Changes nothing.
    Read,
    /// Run a stand-in Hive API node, for a drill before the fleet has an account.
    Mock {
        #[arg(long, default_value = "127.0.0.1:8091")]
        listen: String,
    },
}

#[cfg(not(feature = "hive-rescue"))]
pub(crate) async fn run(_command: HiveCommand) -> anyhow::Result<()> {
    anyhow::bail!(
        "this build has no Hive rescue channel; rebuild with `--features hive-rescue` \
         (see docs/adr/0027-phones-on-the-lane.md)"
    )
}

#[cfg(feature = "hive-rescue")]
pub(crate) use enabled::{run, start_in_worker, with_rescue_trust};

#[cfg(feature = "hive-rescue")]
mod enabled {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use chrono::Utc;
    use ferryman_channel::AgentIdentity;
    use ferryman_channel::ferry::Root;
    use ferryman_channel::secrets::EncryptionIdentity;
    use ferryman_hive_rescue::rescuer::{self, Verdict};
    use ferryman_hive_rescue::{Credentials, Kind, LaneInfo, RescueConfig, Rescuer};
    use ferryman_iroh::IrohConfig;
    use ferryman_iroh::config::FleetRelayEntry;
    use ferryman_ops::Progress;

    use super::HiveCommand;

    /// Add the relays the rescue channel may name to the lane's TLS trust (not to its relay
    /// plan): the configured rescue relay and the one in the newest cached master record.
    pub(crate) fn with_rescue_trust(mut config: IrohConfig, root: &Root) -> IrohConfig {
        let Ok(cfg) = RescueConfig::load(&root.path) else {
            return config;
        };
        if !cfg.enabled {
            return config;
        }
        let mut urls: Vec<(String, Option<String>)> = Vec::new();
        if let Some(url) = &cfg.rescue_relay {
            urls.push((url.clone(), cfg.rescue_relay_cert_sha256.clone()));
        }
        if let Ok(dir) = ferryman_iroh::machine_dir() {
            let state = ferryman_hive_rescue::state::State::load(&dir);
            if let Some(relay) = state.latest_master.and_then(|r| r.body.rescue_relay) {
                urls.push((relay.url, relay.cert_sha256));
            }
        }
        for (url, pin) in urls {
            let pin = pin
                .and_then(|text| hex::decode(text).ok())
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());
            if !config.rescue_relays.iter().any(|e| e.url == url) {
                config.rescue_relays.push(FleetRelayEntry { url, pin });
            }
        }
        config
    }

    /// Start the rescuer beside the lane, when `[hive_rescue]` is on. Never fatal.
    pub(crate) fn start_in_worker(
        lane: &Arc<ferryman_iroh::Lane>,
        shared_map: Option<iroh::RelayMap>,
        identity: &AgentIdentity,
        report: &impl Progress,
    ) {
        let Some(root) = ferryman_channel::ferry::find_root() else {
            return;
        };
        let cfg = match RescueConfig::load(&root.path) {
            Ok(cfg) if cfg.enabled => cfg,
            Ok(_) => return,
            Err(error) => {
                report.warn(&format!("hive rescue not started: {error:#}"));
                return;
            }
        };
        match build(&root, cfg, identity) {
            Ok(rescuer) => {
                let rescuer = Arc::new(rescuer);
                if let Err(error) = rescuer.attach(lane.endpoint(), shared_map) {
                    report.warn(&format!("hive rescue not started: {error:#}"));
                    return;
                }
                let role = if rescuer.config().backup {
                    "backup poster"
                } else {
                    "reader (and master poster, if this machine is the master)"
                };
                report.info(&format!(
                    "hive rescue channel on: {role}; posts only after {} minutes cut off",
                    rescuer.config().cut_off_minutes
                ));
                tokio::spawn(rescuer.run(Arc::clone(lane), Duration::from_secs(30)));
            }
            Err(error) => report.warn(&format!("hive rescue not started: {error:#}")),
        }
    }

    fn build(root: &Root, cfg: RescueConfig, identity: &AgentIdentity) -> Result<Rescuer> {
        let machine = ferryman_iroh::machine_dir()?;
        let creds = Credentials::load(&cfg)?;
        let cwd = std::env::current_dir().context("read the current directory")?;
        let home = ferryman_channel::route_for(&cwd)?;
        let enc = EncryptionIdentity::load_or_create(identity.name(), &home.attachment)?;
        // Make this machine a recipient: its X25519 key goes on its fleet roster entry.
        if ferryman_channel::fleethome::exists(root) {
            let _ = rescuer::publish_encryption_key(root, identity, &enc);
        }
        Ok(Rescuer::new(
            cfg,
            creds,
            rescuer::view_from_root(root.clone()),
            machine,
            AgentIdentity::from_seed(identity.name(), identity.seed_bytes()),
            enc,
        ))
    }

    fn lane_info_from_status(machine: &Path) -> Result<LaneInfo> {
        let key = ferryman_iroh::load_key(machine)?
            .context("no iroh key here; run `ferry lane iroh init`")?;
        let status = ferryman_iroh::lane::Status::read(&machine.join(ferryman_iroh::STATUS_FILE));
        Ok(LaneInfo {
            endpoint_id: ferryman_iroh::endpoint_hex(&key.public()),
            home_relay: status.and_then(|s| s.home_relay),
            direct: Vec::new(),
        })
    }

    pub(crate) async fn run(command: HiveCommand) -> Result<()> {
        if let HiveCommand::Mock { listen } = command {
            let mock = ferryman_hive_rescue::mock::MockHive::start(&listen).await?;
            println!(
                "mock Hive API node on {} (in memory; Ctrl-C to stop)",
                mock.url()
            );
            println!("point [hive_rescue] nodes = [\"{}\"] at it", mock.url());
            mock.forever().await;
            return Ok(());
        }
        let root = ferryman_channel::ferry::find_root().context("no ferry root here")?;
        let cfg = RescueConfig::load(&root.path)?;
        let cwd = std::env::current_dir()?;
        let (_, identity) = crate::lane::served(&root, Some(cwd))?;
        let machine = ferryman_iroh::machine_dir()?;
        let rescuer = build(&root, cfg, &identity)?;
        let now = Utc::now();
        match command {
            HiveCommand::Status { json } => status(&rescuer, &machine, json),
            HiveCommand::Post { dry_run, backup } => {
                let info = lane_info_from_status(&machine)?;
                let kind = if backup { Kind::Backup } else { Kind::Master };
                if dry_run {
                    let preview = rescuer.preview(kind, &info, now).await?;
                    println!("record (signed by {}):", preview.record.body.signer);
                    println!("{}", serde_json::to_string_pretty(&preview.record)?);
                    println!("\nsealed to: {}", preview.recipients.join(", "));
                    println!(
                        "\ncustom_json id={} under {} ({} bytes of json)",
                        preview.op.id,
                        preview.op.required_posting_auths.join(","),
                        preview.op.json.len()
                    );
                    println!("{}", preview.op.json);
                    match (&preview.tx_hex, &preview.digest_hex) {
                        (Some(tx), Some(digest)) => {
                            println!(
                                "\nunsigned transaction (serialized): {tx}\ndigest to sign: {digest}"
                            );
                        }
                        _ => println!("\n(no Hive node answered, so no transaction was built)"),
                    }
                    println!("\ndry run: nothing was broadcast");
                } else {
                    let outcome = rescuer
                        .post(kind, "posted by hand", &info, now, None)
                        .await?;
                    println!(
                        "posted {:?} record seq {} as {} via {} ({} bytes)",
                        outcome.kind,
                        outcome.record.body.seq,
                        outcome.tx_id,
                        outcome.node.unwrap_or_default(),
                        outcome.op_json_len
                    );
                }
                Ok(())
            }
            HiveCommand::Read => {
                let report = rescuer.poll(now, false).await?;
                println!(
                    "read {} operation(s) under account '{}'; nodes answered: {}; failed: {}",
                    report.scanned,
                    rescuer.credentials().account,
                    report.answered.len(),
                    report.failed.len()
                );
                for (node, why) in &report.failed {
                    println!("  {node}: {why}");
                }
                for finding in &report.records {
                    match &finding.verdict {
                        Verdict::Valid {
                            kind,
                            signer,
                            seq,
                            issued,
                            expires,
                            endpoint,
                            new,
                        } => println!(
                            "  valid  {:?} from {signer} seq {seq} issued {issued} expires {expires} -> {}{} [{}]",
                            kind,
                            &endpoint[..12.min(endpoint.len())],
                            if *new { "" } else { " (already seen)" },
                            finding.trx_id
                        ),
                        Verdict::Refused(why) => println!("  REFUSED {why} [{}]", finding.trx_id),
                        Verdict::Unreadable(why) => {
                            println!("  unreadable ({why}) [{}]", finding.trx_id)
                        }
                    }
                }
                Ok(())
            }
            HiveCommand::Mock { .. } => unreachable!("handled above"),
        }
    }

    fn status(rescuer: &Rescuer, machine: &Path, json: bool) -> Result<()> {
        let cfg = rescuer.config();
        let state = rescuer.snapshot();
        let lane = ferryman_iroh::lane::Status::read(&machine.join(ferryman_iroh::STATUS_FILE));
        let cut = lane.as_ref().and_then(rescuer::cut_off_since);
        let creds = rescuer.credentials();
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "enabled": cfg.enabled,
                    "account": creds.account,
                    "poster": creds.poster,
                    "posting_key": creds.key.is_some(),
                    "nodes": cfg.nodes,
                    "cut_off_since": cut,
                    "last_post": state.posted.at,
                    "last_post_seq": state.posted.seq,
                    "latest_master": state.latest_master.as_ref().map(|r| (r.body.seq, r.body.issued, r.body.expires)),
                    "latest_backup": state.latest_backup.as_ref().map(|r| (r.body.seq, r.body.issued, r.body.expires)),
                    "last_poll": state.last_poll,
                })
            );
            return Ok(());
        }
        println!(
            "hive rescue channel: {}",
            if cfg.enabled {
                "on"
            } else {
                "off ([hive_rescue] enabled = false)"
            }
        );
        println!(
            "  fleet account   {}",
            if creds.account.is_empty() {
                "(not set)"
            } else {
                &creds.account
            }
        );
        println!(
            "  posting key     {}",
            if creds.key.is_some() {
                "present (never shown)"
            } else {
                "none: this machine reads only"
            }
        );
        println!("  nodes           {}", cfg.nodes.join(", "));
        println!(
            "  posts after     {} minutes cut off{}",
            cfg.cut_off_minutes,
            if cfg.backup {
                format!(
                    " (backup: {} minutes and no fresh master record)",
                    cfg.backup_after_minutes
                )
            } else {
                String::new()
            }
        );
        match cut {
            Some(since) => println!("  this machine    CUT OFF since {since}"),
            None => println!("  this machine    not cut off (or no lane status yet)"),
        }
        println!(
            "  last post       {}",
            state
                .posted
                .at
                .map_or("never".into(), |t| format!("{t} seq {}", state.posted.seq))
        );
        println!(
            "  last read       {}",
            state.last_poll.map_or("never".into(), |t| t.to_string())
        );
        for (label, record) in [
            ("master", &state.latest_master),
            ("backup", &state.latest_backup),
        ] {
            if let Some(r) = record {
                println!(
                    "  {label} record    seq {} issued {} expires {} -> {}",
                    r.body.seq,
                    r.body.issued,
                    r.body.expires,
                    &r.body.at.id[..12]
                );
            }
        }
        Ok(())
    }
}

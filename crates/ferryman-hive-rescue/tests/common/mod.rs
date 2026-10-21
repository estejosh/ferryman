//! A two-machine fleet fixture: beastly (the master) and grouchly, each with a signing
//! identity and an X25519 encryption identity, both on one roster.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use ferryman_channel::secrets::EncryptionIdentity;
use ferryman_channel::{AgentIdentity, AgentRoute};
use ferryman_hive_rescue::config::{Credentials, RescueConfig};
use ferryman_hive_rescue::rescuer::{FleetView, Rescuer, ViewFn};
use ferryman_hive_rescue::rpc::HiveClient;
use ferryman_hive_rescue::tx::PostingKey;

/// A posting key from the reference implementation's vectors (never a real key).
pub const TEST_WIF: &str = "5K2r4ZRQ9HUu1Y1Sfon55LSe5jLwKiwcB7wAEi61cHKDjZ3LrGY";
pub const ACCOUNT: &str = "ferryfleet";

#[derive(Clone)]
pub struct Machine {
    pub name: String,
    pub seed: u8,
}

impl Machine {
    pub fn new(name: &str, seed: u8) -> Self {
        Self {
            name: name.into(),
            seed,
        }
    }

    pub fn signer(&self) -> AgentIdentity {
        AgentIdentity::from_seed(&self.name, [self.seed; 32])
    }

    pub fn enc(&self) -> EncryptionIdentity {
        EncryptionIdentity::from_seed(&self.name, [self.seed.wrapping_add(100); 32])
    }

    pub fn route(&self) -> AgentRoute {
        AgentRoute {
            name: self.name.clone(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(self.signer().public_key_hex()),
            encryption_key: Some(self.enc().public_key_hex()),
        }
    }
}

pub struct Fleet {
    pub beastly: Machine,
    pub grouchly: Machine,
    pub view: Arc<Mutex<FleetView>>,
}

impl Fleet {
    pub fn new() -> Self {
        let beastly = Machine::new("beastly-ferry", 11);
        let grouchly = Machine::new("grouchly-ferry", 22);
        let view = FleetView {
            roster: vec![beastly.route(), grouchly.route()],
            master: Some("beastly-ferry".into()),
            ..FleetView::default()
        };
        Self {
            beastly,
            grouchly,
            view: Arc::new(Mutex::new(view)),
        }
    }

    pub fn view_fn(&self) -> ViewFn {
        let view = Arc::clone(&self.view);
        Arc::new(move || view.lock().unwrap().clone())
    }

    pub fn rescuer(
        &self,
        who: &Machine,
        hive_url: &str,
        state_dir: &std::path::Path,
        with_key: bool,
        tweak: impl FnOnce(&mut RescueConfig),
    ) -> Rescuer {
        self.rescuer_nodes(who, &[hive_url.to_owned()], state_dir, with_key, tweak)
    }

    pub fn rescuer_nodes(
        &self,
        who: &Machine,
        nodes: &[String],
        state_dir: &std::path::Path,
        with_key: bool,
        tweak: impl FnOnce(&mut RescueConfig),
    ) -> Rescuer {
        let mut cfg = RescueConfig {
            enabled: true,
            account: ACCOUNT.into(),
            nodes: nodes.to_vec(),
            ..RescueConfig::default()
        };
        tweak(&mut cfg);
        let creds = Credentials {
            account: ACCOUNT.into(),
            poster: None,
            key: with_key.then(|| PostingKey::from_wif(TEST_WIF).unwrap()),
        };
        Rescuer::with_client(
            cfg,
            creds,
            HiveClient::new(nodes.to_vec()).with_min_ok(1),
            self.view_fn(),
            state_dir.to_path_buf(),
            who.signer(),
            who.enc(),
        )
    }
}

pub fn minutes(m: i64) -> chrono::Duration {
    chrono::Duration::minutes(m)
}

pub fn at(base: DateTime<Utc>, m: i64) -> DateTime<Utc> {
    base + minutes(m)
}

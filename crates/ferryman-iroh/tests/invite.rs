//! The iroh invite handshake, end to end: two endpoints in one process, connected
//! directly (no relay), with real signed channel files and a real v2 invite.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use chrono::{Duration, Utc};
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};
use ferryman_iroh::invite::{self, InviteEndpoint, Join};
use ferryman_iroh::{ALPN, INVITE_ALPN, Lane, endpoint_hex};
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

fn route(base: &Path, project: &str) -> ProjectRoute {
    let workspace = base.join(project);
    let attachment = workspace.join(".ferryman");
    let communications = attachment.join("ferryman");
    fs::create_dir_all(&communications).unwrap();
    ProjectRoute {
        project_id: project.into(),
        workspace,
        attachment,
        communications,
        shared_remote: String::new(),
        git_remote: String::new(),
        git_visibility: "private".into(),
        agents: Vec::new(),
    }
}

fn enrol(route: &ProjectRoute, identity: &AgentIdentity, role: &str) {
    ferryman_channel::register_agent(
        route,
        &AgentRoute {
            name: identity.name().into(),
            role: role.into(),
            capabilities: vec!["messages.receive".to_string()],
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        },
    )
    .unwrap();
}

async fn endpoint(key: SecretKey, lookup: &MemoryLookup, alpn: Vec<Vec<u8>>) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(alpn)
        .relay_mode(RelayMode::Disabled)
        .address_lookup(lookup.clone())
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

fn addr(endpoint: &Endpoint) -> EndpointAddr {
    let mut addr = EndpointAddr::new(endpoint.id());
    for socket in endpoint.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

fn transports_record(
    identity: &AgentIdentity,
    project: &str,
    endpoint_id: &str,
) -> ferryman_channel::transports::Transports {
    let mut t = ferryman_channel::transports::Transports {
        version: ferryman_channel::transports::VERSION,
        project_id: project.into(),
        agent: identity.name().into(),
        endpoint_id: endpoint_id.into(),
        relay_url: None,
        at: Utc::now(),
        signed_by: identity.name().into(),
        signature: String::new(),
    };
    t.signature = identity.sign_bytes(ferryman_channel::transports::payload(&t).as_bytes());
    t
}

/// An inviter channel with a master, a lane agent on the roster with a transports record,
/// and a named v2 invite for `david` / `david-agent`.
struct Inviter {
    _dir: tempfile::TempDir,
    route: ProjectRoute,
    lane_agent: AgentIdentity,
    invite: ferryman_channel::invite::Invite,
    code: ferryman_channel::invite::InviteCode,
}

fn inviter(project: &str) -> Inviter {
    let dir = tempfile::tempdir().unwrap();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-invite-tests-{}", std::process::id())),
    );
    let mut route = route(dir.path(), project);
    let master = AgentIdentity::from_seed("ada", [7u8; 32]);
    let lane_agent = AgentIdentity::from_seed("fang", [1u8; 32]);
    enrol(&route, &master, "operator");
    enrol(&route, &lane_agent, "worker");
    ferryman_channel::master::initialize_master(&route, &master, "ada").unwrap();
    let lane_endpoint_id = "aa".repeat(32);
    ferryman_channel::transports::publish(&route, &lane_agent, &lane_endpoint_id, None).unwrap();
    route.agents = ferryman_channel::read_agent_roster(&route.communications).unwrap();

    let (invite, code_text) = ferryman_channel::invite::create(
        &route,
        &master,
        Some("david"),
        Some("david-agent"),
        vec!["reader".to_string()],
        Duration::days(7),
        &ferryman_channel::invite::Transport::Iroh(ferryman_channel::invite::InviteEndpoint {
            id: "bb".repeat(32),
            relay: None,
            pin: None,
        }),
    )
    .unwrap();
    let code = ferryman_channel::invite::decode_code(&code_text).unwrap();
    Inviter {
        _dir: dir,
        route,
        lane_agent,
        invite,
        code,
    }
}

/// A newcomer agent whose Join would be valid against `inviter`.
fn valid_join(inviter: &Inviter, newcomer: &AgentIdentity, newcomer_endpoint: &str) -> Join {
    let transports = transports_record(newcomer, &inviter.route.project_id, newcomer_endpoint);
    invite::build_join(&inviter.code, newcomer, transports)
}

#[tokio::test]
async fn named_invite_happy_path_then_a_lane_round_moves_files_both_ways() {
    let inv = inviter("demo");
    let lookup = MemoryLookup::new();
    let inviter_invite_key = SecretKey::generate();
    let inviter_lane_key = SecretKey::generate();
    let newcomer_key = SecretKey::generate();

    let invite_end = endpoint(
        inviter_invite_key.clone(),
        &lookup,
        vec![INVITE_ALPN.to_vec()],
    )
    .await;
    let inviter_lane_end = endpoint(inviter_lane_key.clone(), &lookup, vec![ALPN.to_vec()]).await;
    let newcomer_end = endpoint(newcomer_key.clone(), &lookup, vec![ALPN.to_vec()]).await;
    lookup.add_endpoint_info(addr(&invite_end));
    lookup.add_endpoint_info(addr(&inviter_lane_end));
    lookup.add_endpoint_info(addr(&newcomer_end));

    // The inviter's lane republishes its real lane endpoint id (not the one in `inviter`).
    ferryman_channel::transports::publish(
        &inv.route,
        &inv.lane_agent,
        &endpoint_hex(&inviter_lane_key.public()),
        None,
    )
    .unwrap();

    // The newcomer's channel copy, and its own agent key + transports record.
    let newcomer_route = route(inv._dir.path(), "demo");
    let newcomer = AgentIdentity::from_seed("david-agent", [3u8; 32]);
    ferryman_channel::register_agent_public_key(
        &newcomer_route,
        &AgentRoute {
            name: "david-agent".into(),
            role: "worker".into(),
            capabilities: vec!["messages.receive".to_string()],
            public_key: None,
            encryption_key: None,
        },
        &newcomer.public_key_hex(),
    )
    .unwrap();
    ferryman_channel::transports::publish(
        &newcomer_route,
        &newcomer,
        &endpoint_hex(&newcomer_key.public()),
        None,
    )
    .unwrap();
    let join = valid_join(&inv, &newcomer, &endpoint_hex(&newcomer_key.public()));

    let invite_ep = InviteEndpoint::new(invite_end, vec![inv.route.clone()], inv.lane_agent);
    tokio::spawn(Arc::clone(&invite_ep).serve());

    let welcome = invite::join(&newcomer_end, &addr(invite_ep.endpoint()), &join, None)
        .await
        .unwrap();

    invite::verify_welcome(&welcome.files, "demo").unwrap();
    invite::write_welcome(&newcomer_route, &welcome.files).unwrap();
    let accept = ferryman_channel::invite::build_acceptance(
        &newcomer,
        &inv.code,
        &endpoint_hex(&newcomer_key.public()),
        "david",
        Some("david-agent"),
    );
    invite::send_accept(
        &newcomer_end,
        &addr(invite_ep.endpoint()),
        invite::Accept {
            acceptance: accept,
            operator_entry: None,
        },
    )
    .await
    .unwrap();

    // The invite is now bound and the acceptance recorded.
    assert!(
        ferryman_channel::invite::read_acceptance(&inv.route, &inv.invite.id)
            .unwrap()
            .is_some()
    );

    // Both sides hold each other's roster + transports, so one lane round moves files.
    let a = Lane::new(inviter_lane_end, vec![inv.route.clone()], None, None);
    let b = Lane::new(newcomer_end, vec![newcomer_route.clone()], None, None);
    tokio::spawn(Arc::clone(&a).serve());
    tokio::spawn(Arc::clone(&b).serve());
    fs::create_dir_all(inv.route.communications.join("tasks/t-1")).unwrap();
    fs::write(
        inv.route.communications.join("tasks/t-1/order.json"),
        "{\"from\":\"inviter\"}",
    )
    .unwrap();
    fs::create_dir_all(newcomer_route.communications.join("handins/david-agent")).unwrap();
    fs::write(
        newcomer_route
            .communications
            .join("handins/david-agent/out.json"),
        "{\"from\":\"newcomer\"}",
    )
    .unwrap();

    a.round().await;

    assert!(
        newcomer_route
            .communications
            .join("tasks/t-1/order.json")
            .is_file(),
        "the task file did not move inviter -> newcomer"
    );
    assert!(
        inv.route
            .communications
            .join("handins/david-agent/out.json")
            .is_file(),
        "the hand-in did not move newcomer -> inviter"
    );
}

#[test]
fn a_wrong_nonce_is_refused_and_five_burn_the_invite() {
    let inv = inviter("burn");
    let newcomer = AgentIdentity::from_seed("david-agent", [3u8; 32]);
    let mut join = valid_join(&inv, &newcomer, &"11".repeat(32));
    join.nonce = "00000000000000000000000000000000".into();
    join.signature = newcomer.sign_bytes(invite::join_payload(&join).as_bytes());

    assert!(invite::verify_join(&inv.route, &join, Utc::now()).is_err());
    for _ in 0..5 {
        invite::record_failure(&inv.route, &inv.invite.id).unwrap();
    }
    let burned = ferryman_channel::invite::read(&inv.route, &inv.invite.id)
        .unwrap()
        .unwrap();
    assert!(!ferryman_channel::invite::is_open(&burned, Utc::now()));
}

#[test]
fn an_expired_and_a_granted_invite_are_refused() {
    let inv = inviter("refuse");
    let newcomer = AgentIdentity::from_seed("david-agent", [3u8; 32]);
    let join = valid_join(&inv, &newcomer, &"22".repeat(32));
    assert!(invite::verify_join(&inv.route, &join, Utc::now()).is_ok());

    // Expired (burned) -> refused.
    ferryman_channel::invite::burn(&inv.route, &inv.invite.id).unwrap();
    assert!(invite::verify_join(&inv.route, &join, Utc::now()).is_err());

    // Granted -> refused even while it is within its window.
    let inv2 = inviter("granted");
    let join2 = valid_join(&inv2, &newcomer, &"33".repeat(32));
    ferryman_channel::invite::mark_granted(&inv2.route, &inv2.invite.id).unwrap();
    assert!(invite::verify_join(&inv2.route, &join2, Utc::now()).is_err());
}

#[test]
fn a_tampered_welcome_is_refused_before_anything_is_written() {
    let inv = inviter("tamper");
    let newcomer = AgentIdentity::from_seed("david-agent", [3u8; 32]);
    let endpoint = "44".repeat(32);
    let join = valid_join(&inv, &newcomer, &endpoint);
    assert!(invite::verify_join(&inv.route, &join, Utc::now()).is_ok());
    let files = invite::welcome_files(&inv.route, &inv.invite, "fang").unwrap();
    assert!(invite::verify_welcome(&files, "tamper").is_ok());

    // Tamper the master declaration (bad signature) -> refused.
    let mut bad = files.clone();
    let mut master: serde_json::Value = serde_json::from_slice(&bad["master.json"]).unwrap();
    master["signature"] = serde_json::Value::String("00".repeat(64));
    bad.insert("master.json".into(), serde_json::to_vec(&master).unwrap());
    assert!(invite::verify_welcome(&bad, "tamper").is_err());
}

#[test]
fn welcome_writer_rejects_traversal_and_unlisted_files_before_writing() {
    let inv = inviter("welcome-paths");
    let newcomer_route = route(inv._dir.path(), "welcome-paths-new");
    let files = invite::welcome_files(&inv.route, &inv.invite, "fang").unwrap();
    let mut traversal = files.clone();
    traversal.insert("../x.json".into(), b"nope".to_vec());
    assert!(invite::write_welcome(&newcomer_route, &traversal).is_err());
    assert!(
        !newcomer_route
            .communications
            .parent()
            .unwrap()
            .join("x.json")
            .exists()
    );

    let mut extra = files;
    extra.insert("secrets.json".into(), b"nope".to_vec());
    assert!(invite::write_welcome(&newcomer_route, &extra).is_err());
    assert!(!newcomer_route.communications.join("secrets.json").exists());
}

#[test]
fn a_generic_invite_joins_as_guest_then_accepts_from_a_new_operator() {
    let dir = tempfile::tempdir().unwrap();
    let mut route = route(dir.path(), "generic");
    let master = AgentIdentity::from_seed("ada", [7u8; 32]);
    let lane_agent = AgentIdentity::from_seed("fang", [1u8; 32]);
    enrol(&route, &master, "operator");
    enrol(&route, &lane_agent, "worker");
    ferryman_channel::master::initialize_master(&route, &master, "ada").unwrap();
    ferryman_channel::transports::publish(&route, &lane_agent, &"aa".repeat(32), None).unwrap();
    route.agents = ferryman_channel::read_agent_roster(&route.communications).unwrap();

    let (invite, code_text) = ferryman_channel::invite::create(
        &route,
        &master,
        None,
        None,
        vec!["reader".to_string()],
        Duration::days(7),
        &ferryman_channel::invite::Transport::Iroh(ferryman_channel::invite::InviteEndpoint {
            id: "bb".repeat(32),
            relay: None,
            pin: None,
        }),
    )
    .unwrap();
    let code = ferryman_channel::invite::decode_code(&code_text).unwrap();
    // The guest placeholder is accepted for a generic invite.
    let guest = AgentIdentity::from_seed(&format!("guest-{}", invite.id), [4u8; 32]);
    let join = invite::build_join(
        &code,
        &guest,
        transports_record(&guest, "generic", &"cc".repeat(32)),
    );
    assert!(invite::verify_join(&route, &join, Utc::now()).is_ok());

    // A real name that is free is accepted too.
    let named = AgentIdentity::from_seed("someone", [5u8; 32]);
    let join2 = invite::build_join(
        &code,
        &named,
        transports_record(&named, "generic", &"dd".repeat(32)),
    );
    assert!(invite::verify_join(&route, &join2, Utc::now()).is_ok());
}

#[tokio::test]
async fn the_invite_endpoint_refuses_channel_sync_and_the_lane_refuses_invite() {
    let lookup = MemoryLookup::new();
    let invite_end = endpoint(SecretKey::generate(), &lookup, vec![INVITE_ALPN.to_vec()]).await;
    let lane_end = endpoint(SecretKey::generate(), &lookup, vec![ALPN.to_vec()]).await;
    lookup.add_endpoint_info(addr(&invite_end));
    lookup.add_endpoint_info(addr(&lane_end));
    let dialer = endpoint(SecretKey::generate(), &lookup, vec![]).await;
    // Drain accepted connections so the ALPN handshake reaches a verdict.
    for ep in [invite_end.clone(), lane_end.clone()] {
        tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let _ = incoming.await;
            }
        });
    }

    // The invite endpoint does not speak channel-sync.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dialer.connect(addr(&invite_end), ALPN)
        )
        .await
        .map(|r| r.is_err())
        .unwrap_or(true),
        "the invite endpoint must refuse ferryman/channel-sync/1"
    );
    // The lane does not speak the invite protocol.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dialer.connect(addr(&lane_end), INVITE_ALPN)
        )
        .await
        .map(|r| r.is_err())
        .unwrap_or(true),
        "the lane must refuse ferryman/invite/1"
    );
}

#[tokio::test]
async fn endpoint_nonce_failures_burn_and_binding_is_first_key_wins() {
    let inv = inviter("endpoint-security");
    let lookup = MemoryLookup::new();
    let invite_end = endpoint(SecretKey::generate(), &lookup, vec![INVITE_ALPN.to_vec()]).await;
    let newcomer_end = endpoint(SecretKey::generate(), &lookup, vec![]).await;
    lookup.add_endpoint_info(addr(&invite_end));
    lookup.add_endpoint_info(addr(&newcomer_end));
    let service = InviteEndpoint::new(
        invite_end.clone(),
        vec![inv.route.clone()],
        AgentIdentity::from_seed("fang", [1u8; 32]),
    );
    tokio::spawn(Arc::clone(&service).serve());
    let newcomer = AgentIdentity::from_seed("david-agent", [3u8; 32]);
    let mut wrong = valid_join(&inv, &newcomer, &endpoint_hex(&newcomer_end.id()));
    wrong.nonce = "00".repeat(16);
    wrong.signature = newcomer.sign_bytes(invite::join_payload(&wrong).as_bytes());
    for _ in 0..5 {
        assert!(
            invite::join(&newcomer_end, &addr(&invite_end), &wrong, None)
                .await
                .is_err()
        );
    }
    let valid = valid_join(&inv, &newcomer, &endpoint_hex(&newcomer_end.id()));
    assert!(
        invite::join(&newcomer_end, &addr(&invite_end), &valid, None)
            .await
            .is_err()
    );

    let inv = inviter("first-key");
    let lookup = MemoryLookup::new();
    let invite_end = endpoint(SecretKey::generate(), &lookup, vec![INVITE_ALPN.to_vec()]).await;
    let first_end = endpoint(SecretKey::generate(), &lookup, vec![]).await;
    let second_end = endpoint(SecretKey::generate(), &lookup, vec![]).await;
    for ep in [&invite_end, &first_end, &second_end] {
        lookup.add_endpoint_info(addr(ep));
    }
    let service = InviteEndpoint::new(
        invite_end.clone(),
        vec![inv.route.clone()],
        AgentIdentity::from_seed("fang", [1u8; 32]),
    );
    tokio::spawn(Arc::clone(&service).serve());
    let first = AgentIdentity::from_seed("david-agent", [3u8; 32]);
    let first_join = valid_join(&inv, &first, &endpoint_hex(&first_end.id()));
    invite::join(&first_end, &addr(&invite_end), &first_join, None)
        .await
        .unwrap();
    let second = AgentIdentity::from_seed("david-agent", [4u8; 32]);
    let second_join = valid_join(&inv, &second, &endpoint_hex(&second_end.id()));
    let refused = invite::join(&second_end, &addr(&invite_end), &second_join, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("invite already used"));
    invite::join(&first_end, &addr(&invite_end), &first_join, None)
        .await
        .unwrap();
}

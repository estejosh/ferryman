//! A channel another lane carries is not Syncthing's to vouch for.

use ferryman_channel::{Health, ProjectRoute, SharedHealthProbe, SyncthingProbe};

fn route() -> ProjectRoute {
    ProjectRoute {
        project_id: "iroh-only".into(),
        workspace: "w".into(),
        attachment: "a".into(),
        communications: "c".into(),
        shared_remote: "iroh-only-ferryman".into(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    }
}

#[test]
fn a_channel_the_iroh_lane_carries_is_healthy_without_asking_syncthing() {
    // An address nothing listens on: if it were asked, the answer would be Unavailable.
    let mut asked = SyncthingProbe {
        api_base: "http://127.0.0.1:1".into(),
        api_key: "key".into(),
        carried_by: None,
    };
    assert_eq!(
        asked.health(&route()).unwrap_or(Health::Unavailable),
        Health::Unavailable
    );

    let mut carried = SyncthingProbe {
        carried_by: Some("iroh".into()),
        ..asked
    };
    let started = std::time::Instant::now();
    assert_eq!(carried.health(&route()).unwrap(), Health::Healthy);
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
}

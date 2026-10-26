//! The v2 accept path must not touch Syncthing anywhere: a `ferry2.` join is over the
//! iroh invite endpoint, and this test fails if the code starts calling Syncthing.

#[test]
fn the_v2_accept_path_never_calls_syncthing() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
        .expect("read main.rs");
    // The two v2 accept functions sit between accept_invite_v2 and ensure_iroh_enabled.
    let start = source
        .find("async fn accept_invite_v2(")
        .expect("accept_invite_v2");
    let end = source
        .find("fn ensure_iroh_enabled(")
        .expect("ensure_iroh_enabled");
    let body = &source[start..end];
    assert!(
        !body.contains("ferryman_ops::syncthing"),
        "the v2 accept path must not call anything in ferryman_ops::syncthing"
    );
    assert!(
        !body.contains("syncthing::start"),
        "the v2 accept path must not start Syncthing"
    );
    assert!(
        !body.contains("syncthing_add_device"),
        "the v2 accept path must not trust a Syncthing device"
    );
}

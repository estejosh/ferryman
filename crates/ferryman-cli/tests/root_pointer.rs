//! The machine's `ferry-root` pointer must never be rewritten by a root created in a
//! scratch directory. That is the bug that left the real pointer naming a deleted
//! `...\Temp\.tmp*` folder whenever a test ran `Root::create` against the real state dir.

use ferryman_channel::ferry::Root;
use std::path::PathBuf;

/// A machine-state directory that is NOT under the OS temporary directory, so
/// `remember_root` sees it as durable. It lives beside the test binary, never in the
/// operator's real home.
fn durable_state_dir() -> PathBuf {
    let mut dir = std::env::current_exe().expect("the test binary's path");
    dir.pop();
    dir.push(format!(
        "ferryman-root-pointer-state-{}",
        std::process::id()
    ));
    dir
}

#[test]
fn creating_a_root_in_a_temp_dir_does_not_rewrite_the_machine_pointer() {
    let durable = durable_state_dir();
    std::fs::create_dir_all(&durable).unwrap();
    let pointer = durable.join("ferry-root");
    std::fs::write(&pointer, "the real root").unwrap();

    // FERRYMAN_STATE_DIR is deliberately NOT set: the machine state is this durable dir.
    ferryman_channel::licensing::use_machine_state_dir(durable.clone());

    let scratch = tempfile::tempdir().unwrap();
    let root = Root::create(&scratch.path().join("ferry")).unwrap();
    assert!(root.path.is_dir());

    assert_eq!(
        std::fs::read_to_string(&pointer).unwrap(),
        "the real root",
        "Root::create in a temp dir must not rewrite the machine's root pointer"
    );

    let _ = std::fs::remove_dir_all(&durable);
}

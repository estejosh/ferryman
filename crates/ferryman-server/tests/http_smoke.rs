//! Black-box smoke tests: bind the real server on an ephemeral port and drive
//! it over a TCP socket, exactly as a client would. No internals, no mocks.

use ferryman_core::SqliteStore;
use ferryman_server::{AppState, app};
use std::net::SocketAddr;

/// Start the real server on an ephemeral loopback port. The returned `TempDir`
/// keeps the database and workspace alive for the lifetime of the test.
async fn spawn_server() -> (SocketAddr, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("bridge.db")).expect("open store");
    let state = AppState::new(store, dir.path().join("artifacts"))
        .with_workspace_root(dir.path().join("projects"))
        .with_memory_root(dir.path().join("memory"))
        .with_admin_token("test-admin-token".to_string());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app(state)).await;
    });
    (addr, dir)
}

#[tokio::test]
async fn healthz_answers_over_the_socket() {
    let (addr, _dir) = spawn_server().await;
    let body = reqwest::get(format!("http://{addr}/healthz"))
        .await
        .expect("request")
        .error_for_status()
        .expect("2xx")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn projects_are_admin_gated_over_the_socket() {
    let (addr, _dir) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Without the admin token, creation is refused.
    let unauthorized = client
        .post(format!("{base}/v1/projects"))
        .json(&serde_json::json!({"id": "demo", "name": "Demo", "token": "demo-token-12345"}))
        .send()
        .await
        .expect("request");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

    // With the admin token, creation succeeds and the project is listed back.
    let created = client
        .post(format!("{base}/v1/projects"))
        .header("authorization", "Bearer test-admin-token")
        .json(&serde_json::json!({"id": "demo", "name": "Demo", "token": "demo-token-12345"}))
        .send()
        .await
        .expect("request");
    assert_eq!(
        created.status(),
        reqwest::StatusCode::CREATED,
        "body: {}",
        created.text().await.unwrap_or_default()
    );

    let listed = client
        .get(format!("{base}/v1/projects"))
        .header("authorization", "Bearer test-admin-token")
        .send()
        .await
        .expect("request")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    let ids: Vec<&str> = listed["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|project| project["id"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert!(ids.contains(&"demo"), "listed ids: {ids:?}");
}

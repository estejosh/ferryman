//! Read-only web dashboard over the channel: tasks, ledger, and engine stats
//! in one pane.

use std::sync::Arc;

use anyhow::Error;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::Html,
    routing::get,
};
use ferryman_channel::{ProjectRoute, TaskState};
use serde_json::{Value, json};

/// A `Router` that serves the dashboard. The caller supplies the route to
/// observe; this module never binds a listener or mutates the channel.
pub fn router(route: Arc<ProjectRoute>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/tasks", get(tasks))
        .route("/api/stats", get(stats))
        .with_state(route)
}

type DashboardError = (StatusCode, String);

fn internal(error: Error) -> DashboardError {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

/// GET /api/tasks
///
/// One object per task: its id, derived state, current holder, and how many
/// results have been submitted.
async fn tasks(
    State(route): State<Arc<ProjectRoute>>,
) -> Result<Json<Vec<Value>>, DashboardError> {
    let tasks = ferryman_channel::list_tasks(&route).map_err(internal)?;
    let items = tasks
        .iter()
        .map(|task| {
            json!({
                "id": task.order.id,
                "state": state_value(&task.state()),
                "holder": task.holder(),
                "result_count": task.results.len(),
            })
        })
        .collect();
    Ok(Json(items))
}

/// GET /api/stats
async fn stats(
    State(route): State<Arc<ProjectRoute>>,
) -> Result<Json<Vec<Value>>, DashboardError> {
    let stats = ferryman_channel::learning::engine_stats(&route).map_err(internal)?;
    let items = stats
        .iter()
        .map(|stat| {
            json!({
                "engine": stat.engine,
                "total": stat.total,
                "accepted": stat.accepted,
                "rate": stat.rate(),
            })
        })
        .collect();
    Ok(Json(items))
}

/// GET /
///
/// A minimal HTML page with the same task and stat data as the JSON endpoints.
async fn index(State(route): State<Arc<ProjectRoute>>) -> Result<Html<String>, DashboardError> {
    let tasks = ferryman_channel::list_tasks(&route).map_err(internal)?;
    let stats = ferryman_channel::learning::engine_stats(&route).map_err(internal)?;

    let mut task_rows = String::new();
    for task in &tasks {
        task_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&task.order.id),
            escape_html(&state_text(&task.state())),
            escape_html(task.holder().unwrap_or("\u{2014}")),
            task.results.len(),
        ));
    }
    if tasks.is_empty() {
        task_rows.push_str("<tr><td colspan=\"4\">No tasks yet</td></tr>");
    }

    let mut stat_rows = String::new();
    for stat in &stats {
        stat_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1}%</td></tr>",
            escape_html(&stat.engine),
            stat.total,
            stat.accepted,
            stat.rate() * 100.0,
        ));
    }
    if stats.is_empty() {
        stat_rows.push_str("<tr><td colspan=\"4\">No learning data yet</td></tr>");
    }

    let html = format!(
        "<!doctype html>\
         <html lang=\"en\">\
         <head><meta charset=\"utf-8\"><title>Ferryman dashboard</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}\
         table{{border-collapse:collapse;margin-bottom:2rem;min-width:40rem}}\
         th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}}\
         th{{background:#f5f5f5}}\
         </style></head>\
         <body>\
         <h1>Ferryman dashboard</h1>\
         <h2>Tasks</h2><table><thead><tr><th>ID</th><th>State</th><th>Holder</th><th>Results</th></tr></thead>\
         <tbody>{task_rows}</tbody></table>\
         <h2>Engine stats</h2><table><thead><tr><th>Engine</th><th>Total</th><th>Accepted</th><th>Rate</th></tr></thead>\
         <tbody>{stat_rows}</tbody></table>\
         </body></html>"
    );
    Ok(Html(html))
}

/// JSON representation of a task state. The shape is intentionally flat and
/// strings are used for state names so the dashboard stays stable as the
/// channel's internal types evolve.
fn state_value(state: &TaskState) -> Value {
    match state {
        TaskState::Open => json!("open"),
        TaskState::Claimed { by } => json!({ "status": "claimed", "by": by }),
        TaskState::AwaitingReview { by, revision } => {
            json!({ "status": "awaiting_review", "by": by, "revision": revision })
        }
        TaskState::ChangesRequested { revision } => {
            json!({ "status": "changes_requested", "revision": revision })
        }
        TaskState::Accepted => json!("accepted"),
        TaskState::Done => json!("done"),
    }
}

fn state_text(state: &TaskState) -> String {
    match state {
        TaskState::Open => "open".to_string(),
        TaskState::Claimed { by } => format!("claimed by {by}"),
        TaskState::AwaitingReview { by, revision } => {
            format!("awaiting review by {by} (revision {revision})")
        }
        TaskState::ChangesRequested { revision } => format!("changes requested (revision {revision})"),
        TaskState::Accepted => "accepted".to_string(),
        TaskState::Done => "done".to_string(),
    }
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use chrono::Utc;
    use ferryman_channel::Order;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn order(id: &str) -> Order {
        Order {
            id: id.to_string(),
            project_id: "ferryman".to_string(),
            issued_by: "orchestrator".to_string(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "test": true }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
        }
    }

    #[tokio::test]
    async fn api_tasks_lists_channel_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        ferryman_channel::issue_order(&route, &order("task-1")).unwrap();
        ferryman_channel::claim_order(&route, "task-1", "alice").unwrap();

        let response = router(Arc::new(route))
            .oneshot(
                Request::builder()
                    .uri("/api/tasks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let tasks: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["id"], "task-1");
        assert_eq!(tasks[0]["holder"], "alice");
        assert_eq!(tasks[0]["result_count"], 0);
        assert_eq!(tasks[0]["state"]["status"], "claimed");
        assert_eq!(tasks[0]["state"]["by"], "alice");
    }
}


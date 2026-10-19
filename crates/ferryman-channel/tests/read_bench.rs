//! How long one idle poll of a big channel takes.
//!
//! `cargo test -p ferryman-channel --release --test read_bench -- --ignored --nocapture`
//!
//! A synthetic channel of 1,500 finished tasks (an order, a claim, a result and a review
//! each: 6,000 signed files). The worker reads all of it on every poll; this times that
//! read cold and then warm, the way the poll repeats it.

use std::path::Path;
use std::time::Instant;

use chrono::Utc;
use ferryman_channel::{
    AgentIdentity, AgentRoute, Order, ProjectRoute, Review, SignatureCheck, TaskResult, list_tasks,
    work_for,
};
use serde_json::json;

fn route(dir: &Path, wisp: &AgentIdentity, boss: &AgentIdentity) -> ProjectRoute {
    let workspace = dir.join("workspace");
    let attachment = workspace.join(".ferryman");
    let communications = attachment.join("ferryman");
    std::fs::create_dir_all(communications.join("tasks")).unwrap();
    let agent = |identity: &AgentIdentity, role: &str| AgentRoute {
        name: identity.name().to_string(),
        role: role.to_string(),
        capabilities: Vec::new(),
        public_key: Some(identity.public_key_hex()),
        encryption_key: None,
    };
    ProjectRoute {
        project_id: "bench".into(),
        workspace,
        attachment,
        communications,
        shared_remote: "bench-ferryman".into(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: vec![agent(wisp, "worker"), agent(boss, "operator")],
    }
}

fn write(path: &Path, value: &impl serde::Serialize) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn fill(route: &ProjectRoute, wisp: &AgentIdentity, boss: &AgentIdentity, tasks: usize) {
    for n in 0..tasks {
        let id = format!("t-{n:05}");
        let dir = route.communications.join("tasks").join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        let mut order = Order {
            id: id.clone(),
            project_id: route.project_id.clone(),
            issued_by: "boss".into(),
            assigned_to: Some("wisp".into()),
            created_at: Utc::now(),
            payload: json!({ "task": "write the report", "n": n }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
            priority: None,
        };
        boss.sign_order(&mut order);
        write(&dir.join("order.json"), &order);
        write(
            &dir.join("claim.wisp.json"),
            &json!({ "order_id": id, "agent": "wisp", "claimed_at": Utc::now() }),
        );
        let mut result = TaskResult {
            order_id: id.clone(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "done" }),
            signed_by: None,
            signature: None,
        };
        wisp.sign_result(&mut result);
        write(&dir.join("result.wisp.001.json"), &result);
        let mut review = Review {
            order_id: id,
            revision: 1,
            reviewer: "boss".into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        boss.sign_review(&mut review);
        write(&dir.join("review.001.json"), &review);
    }
}

#[test]
#[ignore = "a timing, not a check: run it with --ignored --nocapture"]
fn an_idle_poll_of_six_thousand_files() {
    let dir = tempfile::tempdir().unwrap();
    let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
    let boss = AgentIdentity::from_seed("boss", [9; 32]);
    let route = route(dir.path(), &wisp, &boss);
    let size: usize = std::env::var("BENCH_TASKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_500);
    fill(&route, &wisp, &boss, size);
    // Files this young are not trusted by the cache; a worker's channel has long settled.
    std::thread::sleep(std::time::Duration::from_secs(3));

    let polls = 10;
    let mut times = Vec::new();
    for _ in 0..polls {
        let started = Instant::now();
        // The two reads a pass makes of the whole channel, and what it does with them.
        let tasks = list_tasks(&route).unwrap();
        let valid = tasks
            .iter()
            .filter(|task| {
                ferryman_channel::verify_order_in(&route, &task.order) == SignatureCheck::Valid
            })
            .count();
        let waiting = work_for(&route, "wisp").unwrap().len();
        assert_eq!(tasks.len(), size);
        assert_eq!(valid, size);
        assert_eq!(waiting, 0);
        times.push(started.elapsed());
    }
    let ms = |d: &std::time::Duration| d.as_secs_f64() * 1000.0;
    println!(
        "idle poll over {size} tasks / {} files: first {:.0} ms, then {:?} ms",
        size * 4,
        ms(&times[0]),
        times[1..].iter().map(|t| ms(t).round()).collect::<Vec<_>>()
    );
    let warm: f64 = times[1..].iter().map(ms).sum::<f64>() / (polls - 1) as f64;
    println!(
        "warm average {warm:.0} ms per poll (one poll every 10 s => {:.1}% of a core)",
        warm / 100.0
    );
}

#[test]
#[ignore = "a timing, not a check"]
fn where_a_poll_spends_its_time() {
    let dir = tempfile::tempdir().unwrap();
    let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
    let boss = AgentIdentity::from_seed("boss", [9; 32]);
    let route = route(dir.path(), &wisp, &boss);
    fill(&route, &wisp, &boss, 20);
    let time = |label: &str, f: &dyn Fn()| {
        let started = Instant::now();
        for _ in 0..50 {
            f();
        }
        println!(
            "{label}: {:.2} ms per call",
            started.elapsed().as_secs_f64() * 20.0
        );
    };
    let c = &route.communications;
    time("read_agent_roster", &|| {
        let _ = ferryman_channel::read_agent_roster(c);
    });
    time("access::refused_authors", &|| {
        let _ = ferryman_channel::access::refused_authors(c, "bench");
    });
    time("access::overlay_dirs", &|| {
        let _ = ferryman_channel::access::overlay_dirs(c, "bench");
    });
    time("read_task", &|| {
        let _ = ferryman_channel::read_task(&route, "t-00003");
    });
    let task = ferryman_channel::read_task(&route, "t-00003").unwrap();
    time("verify_order_in", &|| {
        let _ = ferryman_channel::verify_order_in(&route, &task.order);
    });
    time("review_authority", &|| {
        let _ = ferryman_channel::review_authority(&route, &task.reviews[0]);
    });
}

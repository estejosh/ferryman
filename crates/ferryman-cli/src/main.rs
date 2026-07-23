#![forbid(unsafe_code)]
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Parser, Clone)]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    endpoint: String,
    #[arg(long, env = "FERRYMAN_TOKEN")]
    token: String,
    #[arg(long, env = "FERRYMAN_MEMORY_TOKEN")]
    memory_token: Option<String>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand, Clone)]
enum Command {
    Init {
        #[arg(default_value = "orchestrator.toml")]
        path: PathBuf,
    },
    Projects {
        #[command(subcommand)]
        command: Projects,
    },
    Jobs {
        #[command(subcommand)]
        command: Jobs,
    },
    Workers {
        #[command(subcommand)]
        command: Workers,
    },
    Agents {
        #[command(subcommand)]
        command: Agents,
    },
    Memory {
        #[command(subcommand)]
        command: Memory,
    },
    Artifacts {
        #[command(subcommand)]
        command: Artifacts,
    },
    Consents {
        #[command(subcommand)]
        command: Consents,
    },
    Continuity {
        #[command(subcommand)]
        command: Continuity,
    },
}
#[derive(Subcommand, Clone)]
enum Projects {
    /// Create a project. FERRYMAN_TOKEN must be the admin token when the server runs with --production.
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        token: String,
    },
}

#[derive(Subcommand, Clone)]
enum Jobs {
    Submit {
        #[arg(long)]
        project: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        requires_approval: bool,
        #[arg(long, default_value_t = 3)]
        max_attempts: u32,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Get {
        #[arg(long)]
        project: String,
        job: String,
    },
    Approve {
        #[arg(long)]
        project: String,
        job: String,
    },
    Reject {
        #[arg(long)]
        project: String,
        job: String,
    },
    Tail {
        #[arg(long)]
        project: String,
        job: String,
    },
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
}
#[derive(Subcommand, Clone)]
enum Workers {
    Register {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "mock")]
        capability: String,
    },
}
#[derive(Subcommand, Clone)]
enum Agents {
    Create {
        #[arg(long)]
        project: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        description: String,
        #[arg(long, default_value = "temporal")]
        persistence: String,
    },
    List {
        #[arg(long)]
        project: String,
    },
}
#[derive(Subcommand, Clone)]
enum Memory {
    Add {
        #[arg(long)]
        project: String,
        #[arg(long)]
        category: String,
        #[arg(long)]
        content: String,
        #[arg(long, default_value = "operator")]
        source: String,
    },
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        limit: Option<u32>,
    },
}
#[derive(Subcommand, Clone)]
enum Artifacts {
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        job: String,
    },
    Download {
        #[arg(long)]
        project: String,
        artifact: String,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand, Clone)]
enum Consents {
    List {
        #[arg(long)]
        project: String,
    },
    Approve {
        #[arg(long)]
        project: String,
        consent: String,
        #[arg(long, default_value = "local-operator")]
        approver: String,
    },
    Reject {
        #[arg(long)]
        project: String,
        consent: String,
        #[arg(long, default_value = "local-operator")]
        approver: String,
    },
}
#[derive(Subcommand, Clone)]
enum Continuity {
    Pack {
        #[arg(long)]
        project: String,
    },
    Recover {
        #[arg(long)]
        project: String,
        pack_hash: String,
    },
    Drill {
        #[arg(long)]
        project: String,
    },
    /// Create the consent that authorizes one exact encrypted pack to private Git.
    GitConsent {
        #[arg(long)]
        project: String,
        pack_hash: String,
    },
    /// Deliver one consent-approved encrypted pack to the configured private Git branch.
    DeliverGit {
        #[arg(long)]
        project: String,
        pack_hash: String,
        #[arg(long)]
        consent: String,
    },
    Timeline {
        #[arg(long)]
        project: String,
        #[arg(long)]
        after: Option<i64>,
        #[arg(long)]
        category: Option<String>,
    },
    Simulate {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "{}")]
        policy: String,
        #[arg(long, default_value_t = 0)]
        artifact_bytes: u64,
        #[arg(long)]
        outbound: bool,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.clone() {
        Command::Init { path } => {
            std::fs::write(
                &path,
                "# Keep tokens in FERRYMAN_TOKEN, not this file\nendpoint = \"http://127.0.0.1:8787\"\nproject = \"demo\"\n",
            )?;
            println!("wrote {}", path.display());
        }
        Command::Jobs { command } => jobs(&cli, command).await?,
        Command::Projects { command } => match command {
            Projects::Create { id, name, token } => {
                call(
                    &cli,
                    "POST",
                    "/v1/projects".to_string(),
                    Some(json!({"id":id,"name":name,"token":token})),
                )
                .await?
            }
        },
        Command::Workers { command } => match command {
            Workers::Register {
                project,
                capability,
            } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/workers"),
                    Some(json!({"capabilities":[capability]})),
                )
                .await?
            }
        },
        Command::Agents { command } => {
            match command {
                Agents::Create {
                    project,
                    role,
                    description,
                    persistence,
                } => call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/agents"),
                    Some(json!({"role":role,"description":description,"persistence":persistence})),
                )
                .await?,
                Agents::List { project } => {
                    call(&cli, "GET", format!("/v1/projects/{project}/agents"), None).await?
                }
            }
        }
        Command::Memory { command } => match command {
            Memory::Add {
                project,
                category,
                content,
                source,
            } => {
                call_memory(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/memory"),
                    Some(json!({"category":category,"content":content,"source":source})),
                )
                .await?
            }
            Memory::List { project, limit } => {
                let suffix = limit
                    .map(|value| format!("?limit={value}"))
                    .unwrap_or_default();
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/memory{suffix}"),
                    None,
                )
                .await?
            }
        },
        Command::Artifacts { command } => match command {
            Artifacts::List { project, job } => {
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/jobs/{job}/artifacts"),
                    None,
                )
                .await?
            }
            Artifacts::Download {
                project,
                artifact,
                output,
            } => download_artifact(&cli, &project, &artifact, &output).await?,
        },
        Command::Consents { command } => match command {
            Consents::List { project } => {
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/consents"),
                    None,
                )
                .await?
            }
            Consents::Approve {
                project,
                consent,
                approver,
            } => {
                call_approver(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/consents/{consent}/approve"),
                    &approver,
                )
                .await?
            }
            Consents::Reject {
                project,
                consent,
                approver,
            } => {
                call_approver(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/consents/{consent}/reject"),
                    &approver,
                )
                .await?
            }
        },
        Command::Continuity { command } => match command {
            Continuity::Pack { project } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/continuity-packs"),
                    None,
                )
                .await?
            }
            Continuity::Recover { project, pack_hash } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/continuity-packs/{pack_hash}/recover"),
                    None,
                )
                .await?
            }
            Continuity::Drill { project } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/recovery-drill"),
                    None,
                )
                .await?
            }
            Continuity::GitConsent { project, pack_hash } => {
                call(
                    &cli,
                    "POST",
                    format!(
                        "/v1/projects/{project}/continuity-packs/{pack_hash}/delivery-consents"
                    ),
                    Some(json!({"target":"private_git"})),
                )
                .await?
            }
            Continuity::DeliverGit {
                project,
                pack_hash,
                consent,
            } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/continuity-packs/{pack_hash}/deliver"),
                    Some(json!({"consent_id":consent})),
                )
                .await?
            }
            Continuity::Timeline {
                project,
                after,
                category,
            } => {
                let mut query = Vec::new();
                if let Some(after) = after {
                    query.push(format!("after={after}"));
                }
                if let Some(category) = category {
                    query.push(format!("category={category}"));
                }
                let suffix = if query.is_empty() {
                    String::new()
                } else {
                    format!("?{}", query.join("&"))
                };
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/timeline{suffix}"),
                    None,
                )
                .await?
            }
            Continuity::Simulate {
                project,
                policy,
                artifact_bytes,
                outbound,
            } => {
                let policy: Value =
                    serde_json::from_str(&policy).context("--policy must be JSON")?;
                call(&cli, "POST", format!("/v1/projects/{project}/policy/simulate"), Some(json!({"policy":policy,"artifact_bytes":artifact_bytes,"outbound":outbound}))).await?
            }
        },
    };
    Ok(())
}
async fn jobs(cli: &Cli, command: Jobs) -> Result<()> {
    match command {
        Jobs::Submit {
            project,
            input,
            requires_approval,
            max_attempts,
            idempotency_key,
        } => {
            let input: Value = serde_json::from_str(&input).context("--input must be JSON")?;
            call(cli,"POST",format!("/v1/projects/{project}/jobs"),Some(json!({"input":input,"requires_approval":requires_approval,"max_attempts":max_attempts,"idempotency_key":idempotency_key}))).await?
        }
        Jobs::Get { project, job } => {
            call(
                cli,
                "GET",
                format!("/v1/projects/{project}/jobs/{job}"),
                None,
            )
            .await?
        }
        Jobs::Approve { project, job } => {
            call(
                cli,
                "POST",
                format!("/v1/projects/{project}/jobs/{job}/approve"),
                None,
            )
            .await?
        }
        Jobs::Reject { project, job } => {
            call(
                cli,
                "POST",
                format!("/v1/projects/{project}/jobs/{job}/cancel"),
                None,
            )
            .await?
        }
        Jobs::List {
            project,
            status,
            limit,
            cursor,
        } => {
            let mut query = Vec::new();
            if let Some(status) = status {
                query.push(format!("status={status}"));
            }
            if let Some(limit) = limit {
                query.push(format!("limit={limit}"));
            }
            if let Some(cursor) = cursor {
                query.push(format!("cursor={cursor}"));
            }
            let suffix = if query.is_empty() {
                String::new()
            } else {
                format!("?{}", query.join("&"))
            };
            call(
                cli,
                "GET",
                format!("/v1/projects/{project}/jobs{suffix}"),
                None,
            )
            .await?
        }
        Jobs::Tail { project, job } => tail_events(cli, &project, &job).await?,
    };
    Ok(())
}
async fn tail_events(cli: &Cli, project: &str, job: &str) -> Result<()> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/projects/{project}/jobs/{job}/events",
            cli.endpoint
        ))
        .bearer_auth(&cli.token)
        .send()
        .await?
        .error_for_status()?;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        print!("{}", String::from_utf8_lossy(&chunk?));
    }
    Ok(())
}
async fn download_artifact(
    cli: &Cli,
    project: &str,
    artifact: &str,
    output: &PathBuf,
) -> Result<()> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/projects/{project}/artifacts/{artifact}/content",
            cli.endpoint
        ))
        .bearer_auth(&cli.token)
        .send()
        .await?
        .error_for_status()?;
    let bytes = response.bytes().await?;
    std::fs::write(output, bytes)?;
    println!("wrote {}", output.display());
    Ok(())
}
async fn call(cli: &Cli, method: &str, path: String, body: Option<Value>) -> Result<()> {
    let client = reqwest::Client::new();
    let mut request = client
        .request(method.parse()?, format!("{}{}", cli.endpoint, path))
        .bearer_auth(&cli.token);
    if let Some(body) = body {
        request = request.json(&body)
    };
    let response = request.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("bridge returned {status}: {text}")
    };
    println!("{text}");
    Ok(())
}
async fn call_memory(cli: &Cli, method: &str, path: String, body: Option<Value>) -> Result<()> {
    let client = reqwest::Client::new();
    let mut request = client
        .request(method.parse()?, format!("{}{}", cli.endpoint, path))
        .bearer_auth(&cli.token);
    if let Some(token) = &cli.memory_token {
        request = request.header("x-ferryman-memory-token", token);
    };
    if let Some(body) = body {
        request = request.json(&body)
    };
    let response = request.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("bridge returned {status}: {text}")
    };
    println!("{text}");
    Ok(())
}
async fn call_approver(cli: &Cli, method: &str, path: String, approver: &str) -> Result<()> {
    let response = reqwest::Client::new()
        .request(method.parse()?, format!("{}{}", cli.endpoint, path))
        .bearer_auth(&cli.token)
        .header("x-ferryman-approver", approver)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("bridge returned {status}: {text}")
    };
    println!("{text}");
    Ok(())
}

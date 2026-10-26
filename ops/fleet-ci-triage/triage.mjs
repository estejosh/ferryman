#!/usr/bin/env node
// Fleet CI triage — detection + reporting only.
//
// Runs daily from .github/workflows/fleet-ci-triage.yml in estejosh/ferryman.
// For each repo in repos.json:
//   1. Skip it if Actions is disabled there (nothing to triage).
//   2. Look at the most recent run of each workflow. If a workflow's latest
//      run failed and we haven't seen that exact (workflow, commit, conclusion)
//      combination before, it's NEW.
//   3. For each NEW failure, file a tracking issue (labeled ci-triage) in the
//      target repo with the run link and a ready-to-run command to actually
//      attempt a fix — see fix-one.mjs / fleet-ci-fix.yml. This script never
//      writes code or opens a PR itself.
//   4. Record what's been seen so known/pre-existing failures are never
//      re-reported, and write a dated report.
//
// A failure triaging one repo is logged and does not stop the others.

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = "ops/fleet-ci-triage";
const REPOS_FILE = path.join(ROOT, "repos.json");
const STATE_DIR = path.join(ROOT, "state");
const REPORTS_DIR = path.join(ROOT, "reports");

const FLEET_TOKEN = process.env.FLEET_GH_TOKEN;
if (!FLEET_TOKEN) {
  console.error(
    "FLEET_GH_TOKEN is not set. Add it as a secret on estejosh/ferryman: a PAT " +
      "(classic or fine-grained) with repo scope covering every repo listed in " +
      "repos.json, across both the estejosh and shindevlin accounts.",
  );
  process.exit(1);
}

function sh(cmd) {
  return execSync(cmd, { encoding: "utf8", env: { ...process.env, GH_TOKEN: FLEET_TOKEN } });
}

function ghApi(args) {
  const out = sh(`gh api ${args}`);
  return out.trim() ? JSON.parse(out) : null;
}

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function firstLine(e) {
  return String(e.message || e).split("\n")[0];
}

fs.mkdirSync(STATE_DIR, { recursive: true });
fs.mkdirSync(REPORTS_DIR, { recursive: true });

const { repos } = loadJson(REPOS_FILE, { repos: [] });
const today = new Date().toISOString().slice(0, 10);
const report = [`# Fleet CI triage — ${today}`, ""];

for (const repoFull of repos) {
  const [owner, repo] = repoFull.split("/");
  const stateFile = path.join(STATE_DIR, `${owner}__${repo}.json`);
  const seen = loadJson(stateFile, {});
  report.push(`## ${repoFull}`);

  let actionsEnabled = true;
  try {
    const perm = ghApi(`repos/${repoFull}/actions/permissions`);
    actionsEnabled = !!perm?.enabled;
  } catch (e) {
    report.push(`- could not read Actions settings (${firstLine(e)}) — skipped`);
    continue;
  }
  if (!actionsEnabled) {
    report.push("- Actions disabled on this repo — skipped");
    continue;
  }

  let runs;
  try {
    const page = ghApi(`repos/${repoFull}/actions/runs?per_page=20`);
    runs = page?.workflow_runs ?? [];
  } catch (e) {
    report.push(`- could not list workflow runs (${firstLine(e)}) — skipped`);
    continue;
  }

  const latestByWorkflow = new Map();
  for (const run of runs) {
    if (!latestByWorkflow.has(run.name)) latestByWorkflow.set(run.name, run);
  }

  const newFailures = [];
  for (const [wfName, run] of latestByWorkflow) {
    if (wfName === "Fleet CI Triage") continue; // never triage ourselves
    if (run.status !== "completed") continue;
    if (run.conclusion !== "failure" && run.conclusion !== "timed_out") continue;
    const sig = `${wfName}:${run.head_sha}:${run.conclusion}`;
    if (seen[sig]) continue; // already reported
    newFailures.push({ wfName, run, sig });
  }

  if (newFailures.length === 0) {
    report.push("- no new failures");
    continue;
  }

  for (const { wfName, run, sig } of newFailures) {
    report.push(`- **NEW failure**: \`${wfName}\` on ${run.head_sha.slice(0, 7)} — ${run.html_url}`);
    seen[sig] = { firstSeen: today, runUrl: run.html_url };
    try {
      fileTrackingIssue(repoFull, wfName, run);
      report.push("  - filed a ci-triage tracking issue");
    } catch (e) {
      report.push(`  - could not file tracking issue (${firstLine(e)})`);
    }
  }

  fs.writeFileSync(stateFile, JSON.stringify(seen, null, 2) + "\n");
}

fs.writeFileSync(path.join(REPORTS_DIR, `${today}.md`), report.join("\n") + "\n");
console.log(report.join("\n"));

function fileTrackingIssue(repoFull, wfName, run) {
  const title = `ci-triage: ${wfName} failing on ${run.head_sha.slice(0, 7)}`;
  const existing = ghApi(
    `search/issues?q=${encodeURIComponent(`repo:${repoFull} "${title}" in:title state:open`)}`,
  );
  if (existing?.total_count > 0) return;
  const body = [
    `Workflow **${wfName}** failed.`,
    "",
    `Run: ${run.html_url}`,
    `Commit: ${run.head_sha}`,
    "",
    "To have Claude look at this and open a fix PR if it's safe, run:",
    "",
    "```",
    `gh workflow run fleet-ci-fix.yml --repo estejosh/ferryman \\`,
    `  -f target_repo=${repoFull} -f run_id=${run.id}`,
    "```",
    "",
    "(That workflow only ever runs when someone dispatches it by hand — never on a schedule.)",
    "",
    "_Filed automatically by fleet-ci-triage. Close it once handled — it won't be re-opened for this commit._",
  ].join("\n");
  sh(
    `gh issue create --repo ${repoFull} --title ${JSON.stringify(title)} --body ${JSON.stringify(body)} --label ci-triage`,
  );
}

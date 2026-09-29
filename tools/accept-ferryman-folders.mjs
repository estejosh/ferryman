#!/usr/bin/env node
import { mkdir, readdir } from "node:fs/promises";

const key = (await new Response(process.stdin).text()).trim();
const api = "http://127.0.0.1:33471";
const root = "/mnt/nvme-storage/repos/ferryman-comms";
const ids = [
  "bullship-bridge-ferryman", "comm-channel-ferryman", "hone-bridge-ferryman",
  "lobster-nexus-ferryman", "lobster-ops-ferryman", "natv-bridge-codex-ferryman",
  "natv-bridge-ferryman", "pc-agent-bridge-ferryman", "pc-secrets-ferryman", "sem-ferryman",
];
const headers = { "X-API-Key": key, "Content-Type": "application/json" };

const current = await fetch(`${api}/rest/config/folders`, { headers }).then((r) => r.json());
const template = current.find((folder) => folder.id === "ferryman-ferryman");
if (!template) throw new Error("Ferryman folder template is missing");

for (const id of ids) {
  const path = `${root}/${id}/.ferryman/ferryman`;
  let entries = [];
  try { entries = await readdir(path); } catch (error) { if (error.code !== "ENOENT") throw error; }
  if (entries.length) {
    console.log(`${id}\tSKIPPED non-empty`);
    continue;
  }
  if (current.some((folder) => folder.id === id)) {
    console.log(`${id}\tSKIPPED already configured`);
    continue;
  }
  await mkdir(path, { recursive: true });
  const folder = structuredClone(template);
  folder.id = id;
  folder.label = id.replaceAll("-", " ");
  folder.path = path;
  const response = await fetch(`${api}/rest/config/folders`, {
    method: "POST", headers, body: JSON.stringify(folder),
  });
  if (!response.ok) {
    console.log(`${id}\tFAILED HTTP ${response.status}`);
    continue;
  }
  console.log(`${id}\tACCEPTED`);
}

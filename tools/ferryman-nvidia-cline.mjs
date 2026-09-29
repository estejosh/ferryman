#!/usr/bin/env node
import { spawn } from "node:child_process";
import { Agent } from "/mnt/nvme-storage/cline/worker/node_modules/@cline/sdk/dist/index.js";

const [requestedModel, ...promptParts] = process.argv.slice(2);
const prompt = promptParts.join(" ").trim();
const primary = requestedModel || "nvidia/nemotron-3-super-120b-a12b";
const fallback = "nvidia/nemotron-3-ultra-550b-a55b";
const baseUrl = "https://integrate.api.nvidia.com/v1";

if (!prompt) {
  console.error("ferryman-nvidia-cline: prompt required");
  process.exit(2);
}

async function runSdk(model) {
  const transcript = [];
  const agent = new Agent({
    providerId: "openai-native",
    modelId: model,
    apiKey: process.env.NVIDIA_API_KEY || "",
    baseUrl,
    maxIterations: 50,
  });
  agent.subscribe((event) => {
    if (event.type === "assistant-text-delta" && event.text) transcript.push(event.text);
  });
  const result = await agent.run(prompt);
  return result.outputText || transcript.join("");
}

function runDeepSeek() {
  return new Promise((resolve, reject) => {
    const child = spawn("cline", [
      "--auto-approve", "true", "--json", "--provider", "deepseek",
      "--model", "deepseek-flash", prompt,
    ], { stdio: ["ignore", "pipe", "inherit"] });
    let out = "";
    child.stdout.on("data", (chunk) => { out += chunk; });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve(out) : reject(new Error(`DeepSeek fallback exit ${code}`)));
  });
}

try {
  process.stdout.write(await runSdk(primary));
} catch (primaryError) {
  try {
    process.stderr.write(`NVIDIA primary failed; trying fallback model ${fallback}\n`);
    process.stdout.write(await runSdk(fallback));
  } catch (fallbackError) {
    process.stderr.write("NVIDIA models failed; trying configured DeepSeek fallback\n");
    process.stdout.write(await runDeepSeek());
  }
}

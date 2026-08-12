#!/usr/bin/env node
// Hands straight over to the real binary.
//
// spawnSync with stdio inherit rather than exec, so an interactive command behaves the
// same through npm as it does when run directly, and the exit code survives - a wrapper
// that swallows a non-zero exit would break every script that checks one.

const path = require("node:path");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");

const binary = path.join(__dirname, process.platform === "win32" ? "ferry.exe" : "ferry");

if (!fs.existsSync(binary)) {
  console.error(
    "ferryman: the binary is missing - the postinstall step did not finish.\n" +
      "Reinstall with:  npm install -g ferryman-cli\n" +
      "Or download it:  https://github.com/estejosh/ferryman/releases",
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`ferryman: could not run ${binary}: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);

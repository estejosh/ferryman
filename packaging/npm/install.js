#!/usr/bin/env node
// Fetches the ferry binary for this platform from the GitHub release matching this
// package's version.
//
// npm is used purely as a delivery mechanism - the same trick esbuild and biome use to
// ship Rust and Go binaries to people who have node but no compiler. Nothing here is
// written in JavaScript except the download.
//
// Two rules this file exists to honour:
//
//   1. The checksum is verified, always. This downloads an executable and puts it on
//      your PATH; taking it on faith because the URL looked right is how supply-chain
//      incidents start. A mismatch aborts and leaves nothing behind.
//   2. A failure explains itself. The most common one is an unsupported platform, and
//      "postinstall failed with code 1" tells you nothing you can act on.

const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");

const VERSION = require("./package.json").version;
const REPO = "estejosh/ferryman";

// Rust target triples, keyed by what node calls the platform.
const TARGETS = {
  "linux-x64": "x86_64-unknown-linux-gnu",
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "win32-x64": "x86_64-pc-windows-msvc",
};

function fail(message, detail) {
  console.error(`\nferryman: ${message}\n`);
  if (detail) console.error(`${detail}\n`);
  console.error(`Install it directly instead:`);
  console.error(`  https://github.com/${REPO}/releases/tag/v${VERSION}\n`);
  process.exit(1);
}

function get(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "ferryman-npm" } }, (response) => {
        // GitHub redirects release assets to a CDN, so following them is required
        // rather than optional.
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          if (redirectsLeft === 0) return reject(new Error("too many redirects"));
          response.resume();
          return resolve(get(response.headers.location, redirectsLeft - 1));
        }
        if (response.statusCode !== 200) {
          response.resume();
          return reject(new Error(`HTTP ${response.statusCode} for ${url}`));
        }
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks)));
      })
      .on("error", reject);
  });
}

async function main() {
  const key = `${process.platform}-${process.arch}`;
  const target = TARGETS[key];
  if (!target) {
    fail(
      `no prebuilt binary for ${key}`,
      `Supported: ${Object.keys(TARGETS).join(", ")}.\n` +
        `On another platform, build from source:\n` +
        `  cargo install --git https://github.com/${REPO} ferryman-cli`,
    );
  }

  const isWindows = process.platform === "win32";
  const archive = isWindows ? `ferry-${target}.zip` : `ferry-${target}.tar.gz`;
  const base = `https://github.com/${REPO}/releases/download/v${VERSION}`;

  console.log(`ferryman: fetching ${archive}`);
  let payload, checksumFile;
  try {
    [payload, checksumFile] = await Promise.all([
      get(`${base}/${archive}`),
      get(`${base}/${archive}.sha256`),
    ]);
  } catch (error) {
    fail(`could not download the binary`, String(error.message || error));
  }

  const expected = checksumFile.toString("utf8").trim().split(/\s+/)[0].toLowerCase();
  const actual = crypto.createHash("sha256").update(payload).digest("hex");
  if (expected !== actual) {
    // Deliberately fatal and deliberately loud. Nothing is written to disk.
    fail(
      `checksum mismatch - refusing to install`,
      `expected ${expected}\ngot      ${actual}\n\n` +
        `Do not work around this. Report it: https://github.com/${REPO}/issues`,
    );
  }

  const binDir = path.join(__dirname, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const archivePath = path.join(binDir, archive);
  fs.writeFileSync(archivePath, payload);

  try {
    if (isWindows) {
      execFileSync("powershell", [
        "-NoProfile", "-Command",
        `Expand-Archive -Force -LiteralPath '${archivePath}' -DestinationPath '${binDir}'`,
      ]);
    } else {
      // tar is present on every supported unix; shelling out beats bundling a tar
      // implementation for one call.
      execFileSync("tar", ["-xzf", archivePath, "-C", binDir]);
    }
  } catch (error) {
    fail(`could not unpack ${archive}`, String(error.message || error));
  }

  const unpacked = path.join(binDir, `ferry-${target}`, isWindows ? "ferry.exe" : "ferry");
  const destination = path.join(binDir, isWindows ? "ferry.exe" : "ferry");
  if (!fs.existsSync(unpacked)) fail(`the archive did not contain ferry`);
  fs.renameSync(unpacked, destination);
  if (!isWindows) fs.chmodSync(destination, 0o755);

  fs.rmSync(archivePath, { force: true });
  fs.rmSync(path.join(binDir, `ferry-${target}`), { recursive: true, force: true });

  console.log(`ferryman: installed ferry ${VERSION}`);
  console.log(`  next: cd your-project && ferry enable --email you@example.com`);
}

main().catch((error) => fail("install failed", String(error.stack || error)));

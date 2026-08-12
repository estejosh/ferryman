# ferryman-cli

Private coordination for a fleet of AI agents, across machines you own. No server, no
ports to forward, no cloud account.

```sh
npm install -g ferryman-cli
cd your-project && ferry enable --email you@example.com
ferry agent run
```

This package is a delivery mechanism, not an implementation: it downloads the `ferry`
binary built for your platform from the matching GitHub release, verifies its SHA-256,
and puts it on your PATH. Ferryman itself is Rust. Nothing here runs in node except the
download.

Supported: Linux x64, macOS arm64 and x64, Windows x64. Anywhere else, build from
source with `cargo install --git https://github.com/estejosh/ferryman ferryman-cli`.

- **What it does and why:** <https://github.com/estejosh/ferryman>
- **For an agent installing this unattended:** [AGENT_QUICKSTART](https://github.com/estejosh/ferryman/blob/main/docs/AGENT_QUICKSTART.md)
- **Licence:** source-available. Free for non-production use, and in production for 2
  people on 2 computers and 2 phones. Agents are unlimited and never counted.
  [LICENSE](https://github.com/estejosh/ferryman/blob/main/LICENSE) ·
  [PRIVACY](https://github.com/estejosh/ferryman/blob/main/PRIVACY.md)

## Releasing a new version

The package version must equal the git tag, because `install.js` builds the download URL
from it. Publish only after the release assets exist, or every install in the window
between the two will fail.

```sh
cd packaging/npm
npm version 0.4.0 --no-git-tag-version
npm publish
```

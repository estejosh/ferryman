# Opt-in Bridge updates

There are two deliberately separate update paths.

1. **Bridge software:** the operator explicitly fast-forwards a clean Bridge checkout from its already configured `origin`. The updater never creates or changes remotes.
2. **Project compatibility records:** each private project independently declares `[updates] opt_in = true` in `bridge-project.toml`. A system-wide apply records the selected Bridge release in `.ferryman/bridge-update-state.json`; it never changes project files, makes Git commits, adds remotes, or publishes anything.

```powershell
# Inventory eligible projects. This is read-only.
cargo run -p ferryman-cli --bin ferryman-updater -- check --projects-root ./.data/projects

# Explicitly record an approved release for opted-in projects only.
cargo run -p ferryman-cli --bin ferryman-updater -- --projects-root ./.data/projects apply --release 0.1.0

# Update the Bridge installation itself only when its checkout is clean and origin is already set.
cargo run -p ferryman-cli --bin ferryman-updater -- update-bridge --checkout X:\ferryman
```

The update command uses `git fetch` and a fast-forward-only merge; conflicts, dirty trees, missing origins, and non-fast-forward histories fail closed. New bridge releases should update `bridge-release.toml` with compatibility information before users opt in.

# Two-machine recovery with private Git

This is the first working cross-device recovery target. It uses a separate,
private repository (`estejosh/orchestrator-bridge-recovery`) and stores only
encrypted `.obpack` files plus authenticated manifests. It never receives a
project workspace, raw artifact, prompt, token, or recovery key.

On the **first** Windows machine, create its recovery key and then make a
one-time encrypted pairing file:

```powershell
./scripts/start-local.ps1
./scripts/pair-recovery-key.ps1 -Mode Export
```

Copy `bridge-recovery-pairing.obkey` to the second trusted machine with a USB
drive or another private transfer method. Give the pairing passphrase through a
different channel. The pairing file alone cannot open any pack.

On the **second** Windows machine:

1. Install Git and sign in once with `gh auth login` (or configure Git Credential Manager for the private recovery repository).
2. Clone the Bridge software repository.
3. Run `./scripts/pair-recovery-key.ps1 -Mode Import -Path <copied pairing file>` before starting the Bridge.
4. Run `./scripts/start-local.ps1`. It finds the paired key in Windows Credential Manager without printing it.

Delete the pairing file from the USB and both machines after import. Do not put
the recovery key, pairing passphrase, or pairing file in Git or Drive.

To send a pack, make it, then approve its exact delivery manifest. The commands
print IDs and hashes as JSON; copy the values shown in angle brackets:

```powershell
# 1. Make the encrypted continuity pack and copy its bundle_sha256 value.
cargo run -p orchestrator-cli -- --token <project-token> continuity pack --project <project>

# 2. Create the private-Git delivery consent for that exact hash, then copy its id.
cargo run -p orchestrator-cli -- --token <project-token> continuity git-consent --project <project> <bundle-sha256>

# 3. Explicitly approve it, then send it.
cargo run -p orchestrator-cli -- --token <project-token> consents approve --project <project> <consent-id> --approver Josh
cargo run -p orchestrator-cli -- --token <project-token> continuity deliver-git --project <project> <bundle-sha256> --consent <consent-id>
```

The Bridge clones the recovery repository, commits `packs/<hash>.obpack` and
`packs/<hash>.manifest.json` to `bridge/recovery`, pushes, downloads the same
blob again, and verifies its SHA-256 hash.

Drive and MEGA remain optional secondary targets. They should be enabled only
after their device-authorized credentials and hash-verification paths are set
up; private Git is enough to begin the two-machine pilot.

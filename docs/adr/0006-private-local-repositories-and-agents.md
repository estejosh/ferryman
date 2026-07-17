# ADR 0006: Private local repositories and project-role agent identities

Every project owns a local Git repository under the configured workspace root. The bridge initializes it with `main`, writes `.orchestrator/REPOSITORY.md`, never configures a remote, and refuses a workspace that already has one. This means the bridge cannot make a project public; a remote publishing adapter, if ever added, must separately prove the target is private and be explicitly approved.

On a different device, the same project ID maps to the same slugged folder name and gets a new local Git repository. Agent names are derived as `<project-slug>-<role-slug>` and their lifecycle/purpose is carried in `.orchestrator/agents/*.md`.

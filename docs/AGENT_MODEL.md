# Agent model

## Names are derived, never generic

An agent is named from its project ID and its assigned role:

```text
<project-slug>-<role-slug>
```

For example, the `Saturday 80s` project's `Visual QA` role becomes `saturday-80s-visual-qa`. The bridge derives this name; callers provide a role and a description, not an arbitrary agent label.

## Durable profile file

Every agent has a Markdown profile in the project's private local repository:

```text
<workspace>/<project-slug>/.ferryman/agents/<project-slug>-<role-slug>.md
```

It describes the project, role, lifecycle, purpose, and the instructions a later orchestrator needs to use it. The database stores the profile path for discovery, but the Markdown file is the portable handoff when a project moves to another device.

## Lifecycle

- **temporal**: made for a bounded job/workflow; it may be retired when the work completes.
- **permanent**: retained as reusable project infrastructure; future orchestrators should inspect and reuse the profile when the role fits.

Workers remain execution targets. An agent is a project role and operational identity; a later workflow layer can bind one or more workers to an agent without changing this naming rule.

<!-- TRELLIS:START -->
# Trellis Instructions

These instructions are for AI assistants working in this project.

This project is managed by Trellis. The working knowledge you need lives under `.trellis/`:

- `.trellis/workflow.md` — development phases, when to create tasks, skill routing
- `.trellis/spec/` — package- and layer-scoped coding guidelines (read before writing code in a given layer)
- `.trellis/workspace/` — per-developer journals and session traces
- `.trellis/tasks/` — active and archived tasks (PRDs, research, jsonl context)

If a Trellis command is available on your platform (e.g. `/trellis:finish-work`, `/trellis:continue`), prefer it over manual steps. Not every platform exposes every command.

If you're using Codex or another agent-capable tool, additional project-scoped helpers may live in:
- `.agents/skills/` — reusable Trellis skills
- `.codex/agents/` — optional custom subagents

Managed by Trellis. Edits outside this block are preserved; edits inside may be overwritten by a future `trellis update`.

<!-- TRELLIS:END -->

## Python invocation on this machine

Run Trellis scripts as `py -3 ./.trellis/scripts/<script>.py`, not `python ...`.

Under Git Bash, `python` resolves to the Microsoft Store app-execution stub in
`AppData\Local\Microsoft\WindowsApps\` and exits 49 with no output; only PowerShell
resolves it to a working shim. `py -3` works in PowerShell, Git Bash, and cmd.exe.
The `.claude/` hooks are already wired with `py -3` for the same reason.

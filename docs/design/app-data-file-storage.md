# App Data File Storage

## Scope

DiskClean persists small UI state under the Tauri app data directory for the desktop app:

- `logs/app.jsonl`: recent application log entries shown in the Log Center.
- `config/rule-subscription.json`: the latest valid rule subscription URL, raw content, and last check time.

This is not a database and does not store scan indexes, cleanup decisions, or file-change metadata.

## Ownership

The Tauri backend owns file paths and validation in `apps/desktop/src-tauri/src/app_storage.rs`.

The React frontend owns when entries are created and when the subscription is refreshed. Frontend state is mirrored to the backend through explicit IPC commands.

## Schemas

`logs/app.jsonl` stores one JSON object per line:

```json
{"id":"operation-...","kind":"operation","time":"2026-05-14T00:00:00.000Z","title":"应用启动","message":"DiskClean 已加载。","detail":"optional"}
```

Only `scan`, `cleanup`, and `operation` log kinds are accepted. The file keeps at most 500 entries.

`config/rule-subscription.json` stores:

```json
{
  "url": "https://example.com/rules.yaml",
  "content": "version: 1\nrules:\n...",
  "checkedAt": "2026-05-14T00:00:00.000Z"
}
```

The backend validates the URL with the same subscription URL policy and enforces the existing 2 MB rule content limit.

## Migration

The frontend still reads legacy `localStorage` values once when the file cache is empty, then writes them through the backend file commands. New writes use app data files as the primary path.

There is no database migration. Future schema changes should create a new file version or add backward-compatible optional fields.

## Backup And Recovery

Both files are disposable:

- If `logs/app.jsonl` is missing or partially malformed, invalid lines are skipped and the app continues.
- If `config/rule-subscription.json` is missing or invalid, subscription rules are disabled until the user loads a subscription again.

Users can back up the app data directory to preserve logs and subscription settings.

## Cleanup Safety

Persisted state must never be the sole reason to delete a file. Rule subscription content is recompiled through the existing rule compiler before it can participate in scans. Cleanup execution still depends on current filesystem validation, risk levels, blocked-path policy, and explicit user selection.

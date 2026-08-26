# Full-Scan Inventory Storage

## Scope

DiskClean full scans create a temporary local inventory so the backend can account for every accessible filesystem entry while the frontend reads only bounded directory, search, and largest-file pages. This inventory is analysis state, not cleanup authority.

## Ownership

- `cleaner-core` owns inventory entries, coverage, aggregation, and the sink/query contracts.
- `apps/desktop/src-tauri/src/inventory_repository.rs` owns SQLite paths, schema, batching, query cursors, and lifecycle cleanup.
- React owns only the current scan session identifier and bounded query pages.

## Storage and schema

Each complete scan uses one SQLite file under the Tauri cache directory:

```text
scan-inventory/<scan-session-uuid>.sqlite3
```

The repository stores a versioned scan session, parent-linked inventory entries, post-order directory aggregates, and structured coverage gaps. It stores `parent + name` instead of duplicating absolute paths for every row. Query paths are reconstructed only for explicit local UI requests.

The SQLite dependency is bundled with the application so repository behavior does not depend on a separately installed database runtime. Writes use bounded transactions; page size, busy timeout, and result limits are fixed by the backend.

## Migration

Inventory is disposable and never migrated. On schema-version mismatch the file is closed, deleted, and rebuilt by a new full scan. Persistent user configuration and rule-library generations do not reference inventory row identifiers.

## Lifecycle and recovery

- Starting a new full scan closes and removes the previous session.
- Normal application shutdown closes and removes the active session.
- Application startup removes crash leftovers under `scan-inventory/` before accepting queries.
- If the repository becomes corrupt or reaches a resource limit, coverage becomes `partial`; completed candidate safety data remains conservative and the user is asked to rescan.
- Inventory files are excluded from logs, diagnostics, rule exports, AI requests, and cloud/subscription flows.

## Privacy

Inventory contains local file and directory names. It remains on the machine in the current user's application cache, inherits restrictive application-directory permissions, and has the shortest practical lifetime. Log and error messages include session IDs, counts, durations, and error categories—not entry names or full paths.

## Cleanup safety

Inventory never makes a path selectable and never proves that a path is unchanged. Cleanup receives only validated `CleanupCandidate` values, then reopens the current filesystem object and reapplies blocked-path, runtime-state, delete-strategy, metadata-staleness, and user-confirmation checks. Missing or stale inventory only degrades analysis browsing.

## NTFS enumerator

On Windows NTFS volumes with sufficient privilege, full inventory prefers direct `$MFT` parsing (`backend: ntfs-mft`) so logical and allocated sizes come from `$DATA` attributes. `FSCTL_ENUM_USN_DATA` is not used for complete sizing (USN records have no size). When MFT open/parse fails, coverage records `accessDenied` / `backendFallback` and the scan continues with `FileIdExtdDirectoryInfo` / metadata directory walk.

Progress:

- Reading `$MFT` records is phase `indexing` (`on_visited` per in-use record).
- Emitting reconstructed paths is phase `walking`: `on_progress_reset` then `on_visited` + `on_location` per link, so the file count moves with the current path.
- Inventory disposition is path-string only. It must not `read_dir` ancestors while emitting millions of rows.

Parser invariants:

- Fragmented `$MFT` `$DATA` must concatenate **all** unnamed non-resident extents (not only LowestVcn == 0).
- Base FILE records that set `ATTRIBUTE_LIST` must merge sizes/names/reparse from extension records (`base_record != 0`); dropping extensions undercounts large files.
- If `$MFT` itself only exposes `$DATA` via `ATTRIBUTE_LIST` extensions, open may fail closed and fall back (explicit gap), rather than silently truncating the stream.
- Inventory rows and temporary session storage never authorize cleanup; candidates still pass classifiers and execution-time revalidation.

## Backup and rollback

Inventory is excluded from backup guidance because it is reproducible and privacy-sensitive. Feature rollback deletes the cache directory and disables inventory query IPC; no migration or user-data restoration is required.

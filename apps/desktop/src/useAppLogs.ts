import { useCallback, useEffect, useRef, useState } from "react";
import { readAppLogs, writeAppLogs } from "./api";
import type { AppLogEntry, AppLogKind } from "./types";

/**
 * Log state used to live in `App` together with the scan lifecycle, so every
 * appended entry re-rendered the whole workbench. Logs are append-only and
 * unrelated to scanning, so they own their own hook and persistence.
 */

const LOG_STORAGE_KEY = "diskclean.logs.v1";
const MAX_LOG_ENTRIES = 200;
const LOG_RETENTION_DAYS = 7;

export interface AppLogsApi {
  logs: AppLogEntry[];
  appendLog: (kind: AppLogKind, title: string, message: string, detail?: string) => void;
  replaceLogs: (entries: AppLogEntry[]) => void;
}

export function useAppLogs(): AppLogsApi {
  const [logs, setLogs] = useState<AppLogEntry[]>(() => readStoredLogs());
  const hydrated = useRef(false);

  const appendLog = useCallback(
    (kind: AppLogKind, title: string, message: string, detail?: string) => {
      setLogs((currentLogs) => pruneLogEntries([createLogEntry(kind, title, message, detail), ...currentLogs]));
    },
    []
  );

  const replaceLogs = useCallback((entries: AppLogEntry[]) => {
    setLogs(pruneLogEntries(entries));
  }, []);

  // The Rust side owns the durable copy; localStorage is only a fast first paint.
  useEffect(() => {
    if (hydrated.current) {
      return;
    }

    hydrated.current = true;
    let disposed = false;

    void readAppLogs()
      .then((persistedLogs) => {
        if (disposed || persistedLogs.length === 0) {
          return;
        }

        setLogs((currentLogs) => mergeLogEntries(persistedLogs, currentLogs));
      })
      .catch(() => {
        // A missing or unreadable log file is not worth surfacing; the in-memory
        // log still works and will be rewritten on the next append.
      });

    return () => {
      disposed = true;
    };
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(logs));
    } catch {
      // Quota or private-mode failures must not break the app.
    }

    void writeAppLogs(logs).catch(() => {});
  }, [logs]);

  return { logs, appendLog, replaceLogs };
}

export function createLogEntry(
  kind: AppLogKind,
  title: string,
  message: string,
  detail?: string
): AppLogEntry {
  return {
    id: `${kind}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    kind,
    time: new Date().toISOString(),
    title,
    message,
    detail
  };
}

export function pruneLogEntries(entries: AppLogEntry[]): AppLogEntry[] {
  const cutoff = Date.now() - LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;

  return entries
    .filter((entry) => {
      const time = Date.parse(entry.time);

      return Number.isNaN(time) || time >= cutoff;
    })
    .slice(0, MAX_LOG_ENTRIES);
}

export function mergeLogEntries(
  primaryLogs: AppLogEntry[],
  secondaryLogs: AppLogEntry[]
): AppLogEntry[] {
  const seen = new Set<string>();
  const merged: AppLogEntry[] = [];

  for (const entry of [...primaryLogs, ...secondaryLogs]) {
    if (seen.has(entry.id)) {
      continue;
    }

    seen.add(entry.id);
    merged.push(entry);
  }

  merged.sort((left, right) => Date.parse(right.time) - Date.parse(left.time));

  return pruneLogEntries(merged);
}

function readStoredLogs(): AppLogEntry[] {
  try {
    const raw = window.localStorage.getItem(LOG_STORAGE_KEY);

    if (!raw) {
      return [];
    }

    const parsed: unknown = JSON.parse(raw);

    return Array.isArray(parsed) ? pruneLogEntries(parsed.filter(isStoredLogEntry)) : [];
  } catch {
    return [];
  }
}

function isStoredLogEntry(value: unknown): value is AppLogEntry {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const entry = value as Partial<AppLogEntry>;

  return (
    typeof entry.id === "string" &&
    typeof entry.time === "string" &&
    typeof entry.title === "string" &&
    typeof entry.message === "string" &&
    isLogKind(entry.kind)
  );
}

function isLogKind(value: unknown): value is AppLogKind {
  return value === "scan" || value === "cleanup" || value === "operation";
}
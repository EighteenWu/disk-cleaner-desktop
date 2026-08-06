import type {
  CleanupProgress,
  CleanupReport,
  ScanMode,
  ScanPhase,
  ScanProgress,
  ScanSnapshot
} from "./types";

/**
 * One state machine owns the whole scan -> review -> cleanup lifecycle.
 *
 * Before this module the same lifecycle was spread across `scanStatus`,
 * `scanLive`, `scanProgress`, `scanStartedAt`, `scanElapsedMs`, `cleanupStatus`,
 * `cleanupProgress`, `cleanupStartedAt`, `cleanupElapsedMs` and a
 * `scanRunActive` ref. Each render recombined them with nested ternaries, and
 * "is a scan running" had to be re-derived at every call site.
 *
 * The important product rule encoded here: scan statistics survive completion.
 * `stats` is only reset when a new run starts, so the status bar keeps showing
 * how many files were scanned after the run finishes.
 */

export type SessionPhase =
  | "loading"
  | "idle"
  | "scanning"
  | "scanPaused"
  | "scanFailed"
  | "reviewing"
  | "cleaning"
  | "cleanupPaused"
  | "cleanupCanceling"
  | "cleanupDone"
  | "cleanupFailed";

export interface ScanStats {
  phase: ScanPhase;
  scannedFiles: number;
  candidateCount: number;
  reclaimableBytes: number;
  currentPath: string;
  currentVolume: string;
  percent: number | null;
  /** Wall clock of the run; frozen once the run settles. */
  elapsedMs: number;
  /** Non-null only while a run is in flight, so the ticker can advance. */
  startedAt: number | null;
  /** True once a run has produced numbers worth showing. */
  hasRun: boolean;
}

export interface CleanupStats {
  processedCount: number;
  totalCount: number;
  percent: number;
  currentPath: string;
  elapsedMs: number;
  startedAt: number | null;
}

export interface SessionState {
  phase: SessionPhase;
  mode: ScanMode;
  /**
   * Mode of the scan that actually finished, not the mode currently selected in
   * the toolbar. The startup snapshot is synthetic, so `snapshot !== null` alone
   * cannot tell whether a real full-disk run has happened.
   */
  completedScanMode: ScanMode | null;
  snapshot: ScanSnapshot | null;
  scan: ScanStats;
  cleanup: CleanupStats;
  report: CleanupReport | null;
  /** Machine-readable reason for the latest failure, for i18n at render time. */
  error: string | null;
}

export type SessionEvent =
  | { type: "snapshotLoaded"; snapshot: ScanSnapshot }
  | { type: "modeChanged"; mode: ScanMode }
  | { type: "scanStarted"; at: number }
  | { type: "scanProgress"; progress: ScanProgress }
  | { type: "scanPaused" }
  | { type: "scanResumed" }
  | { type: "scanSucceeded"; snapshot: ScanSnapshot; at: number }
  | { type: "scanFailed"; error: string; at: number }
  | { type: "snapshotReplaced"; snapshot: ScanSnapshot }
  | { type: "cleanupStarted"; totalCount: number; at: number }
  | { type: "cleanupProgress"; progress: CleanupProgress }
  | { type: "cleanupPaused" }
  | { type: "cleanupResumed" }
  | { type: "cleanupCanceling" }
  | { type: "cleanupSettled"; report: CleanupReport; snapshot: ScanSnapshot; at: number }
  | { type: "cleanupFailed"; error: string; at: number }
  | { type: "tick"; at: number };

export const EMPTY_SCAN_STATS: ScanStats = {
  phase: "preparing",
  scannedFiles: 0,
  candidateCount: 0,
  reclaimableBytes: 0,
  currentPath: "",
  currentVolume: "",
  percent: null,
  elapsedMs: 0,
  startedAt: null,
  hasRun: false
};

export const EMPTY_CLEANUP_STATS: CleanupStats = {
  processedCount: 0,
  totalCount: 0,
  percent: 0,
  currentPath: "",
  elapsedMs: 0,
  startedAt: null
};

export const INITIAL_SESSION: SessionState = {
  phase: "loading",
  mode: "quick",
  completedScanMode: null,
  snapshot: null,
  scan: EMPTY_SCAN_STATS,
  cleanup: EMPTY_CLEANUP_STATS,
  report: null,
  error: null
};

const SCAN_BUSY_PHASES: ReadonlySet<SessionPhase> = new Set<SessionPhase>(["scanning", "scanPaused"]);

const CLEANUP_BUSY_PHASES: ReadonlySet<SessionPhase> = new Set<SessionPhase>([
  "cleaning",
  "cleanupPaused",
  "cleanupCanceling"
]);

export function sessionReducer(state: SessionState, event: SessionEvent): SessionState {
  switch (event.type) {
    case "snapshotLoaded":
      return {
        ...state,
        phase: state.phase === "loading" ? "idle" : state.phase,
        snapshot: event.snapshot
      };

    case "modeChanged":
      return { ...state, mode: event.mode };

    case "scanStarted":
      return {
        ...state,
        phase: "scanning",
        report: null,
        error: null,
        // A new run invalidates the previous result, including its mode.
        completedScanMode: null,
        scan: { ...EMPTY_SCAN_STATS, startedAt: event.at, hasRun: true },
        cleanup: EMPTY_CLEANUP_STATS
      };

    case "scanProgress": {
      if (!isScanBusy(state)) {
        return state;
      }

      return {
        ...state,
        scan: {
          ...state.scan,
          phase: event.progress.phase,
          scannedFiles: event.progress.scannedFiles,
          candidateCount: event.progress.candidateCount,
          reclaimableBytes: event.progress.reclaimableBytes,
          currentPath: event.progress.currentPath,
          currentVolume: event.progress.currentVolume,
          percent: normalizePercent(event.progress.percent),
          hasRun: true
        }
      };
    }

    case "scanPaused":
      return state.phase === "scanning" ? { ...state, phase: "scanPaused" } : state;

    case "scanResumed":
      return state.phase === "scanPaused" ? { ...state, phase: "scanning" } : state;

    case "scanSucceeded":
      return {
        ...state,
        phase: "reviewing",
        snapshot: event.snapshot,
        completedScanMode: state.mode,
        error: null,
        scan: {
          ...state.scan,
          phase: "complete",
          // Trust the finished snapshot over the last progress event; the tail
          // of a run can be summarised after the final tick was emitted.
          candidateCount: event.snapshot.summary.candidateCount,
          reclaimableBytes: event.snapshot.summary.estimatedReclaimBytes,
          currentPath: "",
          percent: 100,
          elapsedMs: elapsedSince(state.scan.startedAt, event.at, state.scan.elapsedMs),
          startedAt: null,
          hasRun: true
        }
      };

    case "scanFailed":
      return {
        ...state,
        phase: "scanFailed",
        error: event.error,
        scan: {
          ...state.scan,
          currentPath: "",
          elapsedMs: elapsedSince(state.scan.startedAt, event.at, state.scan.elapsedMs),
          startedAt: null
        }
      };

    case "snapshotReplaced":
      return { ...state, snapshot: event.snapshot };

    case "cleanupStarted":
      return {
        ...state,
        phase: "cleaning",
        error: null,
        report: null,
        cleanup: { ...EMPTY_CLEANUP_STATS, totalCount: event.totalCount, startedAt: event.at }
      };

    case "cleanupProgress": {
      if (!isCleanupBusy(state)) {
        return state;
      }

      return {
        ...state,
        cleanup: {
          ...state.cleanup,
          processedCount: event.progress.processedCount,
          totalCount: event.progress.totalCount || state.cleanup.totalCount,
          percent: clampPercent(event.progress.percent),
          currentPath: event.progress.currentPath
        }
      };
    }

    case "cleanupPaused":
      return state.phase === "cleaning" ? { ...state, phase: "cleanupPaused" } : state;

    case "cleanupResumed":
      return state.phase === "cleanupPaused" ? { ...state, phase: "cleaning" } : state;

    case "cleanupCanceling":
      return isCleanupBusy(state) ? { ...state, phase: "cleanupCanceling" } : state;

    case "cleanupSettled":
      return {
        ...state,
        phase: "cleanupDone",
        snapshot: event.snapshot,
        report: event.report,
        error: null,
        cleanup: {
          ...state.cleanup,
          percent: 100,
          currentPath: "",
          elapsedMs: elapsedSince(state.cleanup.startedAt, event.at, state.cleanup.elapsedMs),
          startedAt: null
        }
      };

    case "cleanupFailed":
      return {
        ...state,
        phase: "cleanupFailed",
        error: event.error,
        cleanup: {
          ...state.cleanup,
          currentPath: "",
          elapsedMs: elapsedSince(state.cleanup.startedAt, event.at, state.cleanup.elapsedMs),
          startedAt: null
        }
      };

    case "tick": {
      if (state.scan.startedAt !== null) {
        return { ...state, scan: { ...state.scan, elapsedMs: event.at - state.scan.startedAt } };
      }

      if (state.cleanup.startedAt !== null) {
        return {
          ...state,
          cleanup: { ...state.cleanup, elapsedMs: event.at - state.cleanup.startedAt }
        };
      }

      return state;
    }

    default:
      return state;
  }
}

export function isScanBusy(state: SessionState): boolean {
  return SCAN_BUSY_PHASES.has(state.phase);
}

export function isCleanupBusy(state: SessionState): boolean {
  return CLEANUP_BUSY_PHASES.has(state.phase);
}

export function isBusy(state: SessionState): boolean {
  return isScanBusy(state) || isCleanupBusy(state);
}

/**
 * Scan numbers stay visible after a run settles, which is what makes the status
 * bar keep its "scanned N files" readout instead of blanking on completion.
 */
export function scanStatsVisible(state: SessionState): boolean {
  return state.scan.hasRun;
}

/**
 * AI rule drafting is only meaningful once a full-disk run has produced a real
 * candidate set: a quick scan only visits well-known roots, and the synthetic
 * startup snapshot has no candidates at all.
 */
export function aiRuleGenerationReady(state: SessionState): boolean {
  return state.completedScanMode === "full" && state.snapshot !== null && !isBusy(state);
}

export const SCAN_PATH_MAX_LENGTH = 52;

export function scanPercentOrNull(progress: ScanProgress): number | null {
  const { percent } = progress;

  return percent === null || !Number.isFinite(percent) ? null : clampScanPercent(percent);
}

export function isDeterminateScanProgress(progress: ScanProgress): boolean {
  return scanPercentOrNull(progress) !== null;
}

export function clampScanPercent(percent: number): number {
  return Math.min(100, Math.max(0, Math.round(percent)));
}

export function formatScanCount(value: number, language: string): string {
  return Math.max(0, Math.trunc(value)).toLocaleString(language);
}

export function truncatePathMiddle(path: string, maxLength = SCAN_PATH_MAX_LENGTH): string {
  if (maxLength <= 1 || path.length <= maxLength) {
    return path;
  }

  const tailLength = Math.ceil((maxLength - 1) / 2);
  const headLength = maxLength - 1 - tailLength;

  return `${path.slice(0, headLength)}…${path.slice(path.length - tailLength)}`;
}

export function formatDuration(milliseconds: number): string {
  const totalSeconds = Math.max(0, Math.round(milliseconds / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

export type PrimaryAction = "scan" | "pause" | "resume" | "rescan";

export function primaryAction(state: SessionState): PrimaryAction {
  switch (state.phase) {
    case "scanning":
      return "pause";
    case "scanPaused":
      return "resume";
    case "reviewing":
    case "cleanupDone":
    case "cleanupFailed":
    case "scanFailed":
      return "rescan";
    default:
      return "scan";
  }
}

function elapsedSince(startedAt: number | null, now: number, fallback: number): number {
  if (startedAt === null) {
    return fallback;
  }

  return Math.max(0, now - startedAt);
}

function normalizePercent(percent: number | null): number | null {
  if (percent === null || !Number.isFinite(percent)) {
    return null;
  }

  return clampPercent(percent);
}

function clampPercent(percent: number): number {
  if (!Number.isFinite(percent)) {
    return 0;
  }

  return Math.min(100, Math.max(0, Math.round(percent)));
}
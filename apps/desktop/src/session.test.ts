import { describe, expect, it } from "vitest";

import {
  EMPTY_SCAN_STATS,
  INITIAL_SESSION,
  isBusy,
  isCleanupBusy,
  isScanBusy,
  primaryAction,
  scanHeadlineBytes,
  scanStatsVisible,
  sessionReducer,
  type SessionEvent,
  type SessionState
} from "./session";
import type { CleanupProgress, CleanupReport, ScanProgress, ScanSnapshot } from "./types";

function snapshot(overrides: Partial<ScanSnapshot["summary"]> = {}): ScanSnapshot {
  return {
    volumes: [],
    candidates: [],
    selectedCandidateId: "",
    summary: {
      estimatedReclaimBytes: 4096,
      candidateCount: 7,
      lockedCount: 0,
      progressPercent: 100,
      selectedCount: 3,
      selectedBytes: 2048,
      ...overrides
    },
    scanBackend: "usn",
    warnings: [],
    scanSessionId: null,
    coverage: {
      status: "complete",
      visitedEntries: 0,
      indexedEntries: 0,
      logicalBytes: 0,
      allocatedBytes: 0,
      volumes: [],
      gaps: []
    },
    spaceSummary: []
  };
}

function scanProgress(overrides: Partial<ScanProgress> = {}): ScanProgress {
  return {
    phase: "walking",
    scannedFiles: 1200,
    candidateCount: 5,
    reclaimableBytes: 1024,
    scannedBytes: 0,
    currentPath: "C:\\Windows\\Temp",
    currentVolume: "C",
    totalFiles: 2400,
    percent: 50,
    ...overrides
  };
}

function cleanupProgress(overrides: Partial<CleanupProgress> = {}): CleanupProgress {
  return {
    processedCount: 2,
    totalCount: 8,
    percent: 25,
    currentId: "chrome-cache",
    currentPath: "C:\\cache",
    status: "cleaning",
    ...overrides
  };
}

function report(): CleanupReport {
  return {
    requestedCount: 3,
    cleanedCount: 3,
    skippedLockedCount: 0,
    failedCount: 0,
    cancelled: false,
    reclaimedBytes: 2048,
    cleanedIds: ["a", "b", "c"],
    skippedIds: [],
    failedIds: [],
    deleteStrategy: "moveToRecycleBin",
    warnings: [],
    itemResults: []
  };
}

function reduceAll(state: SessionState, events: SessionEvent[]): SessionState {
  return events.reduce(sessionReducer, state);
}

const READY: SessionState = sessionReducer(INITIAL_SESSION, {
  type: "snapshotLoaded",
  snapshot: snapshot()
});

describe("session lifecycle", () => {
  it("moves from loading to idle once the first snapshot arrives", () => {
    expect(INITIAL_SESSION.phase).toBe("loading");
    expect(READY.phase).toBe("idle");
    expect(READY.snapshot).not.toBeNull();
  });

  it("walks the happy path idle -> scanning -> reviewing -> cleaning -> done", () => {
    const scanning = sessionReducer(READY, { type: "scanStarted", at: 1_000 });
    expect(scanning.phase).toBe("scanning");

    const reviewing = sessionReducer(scanning, {
      type: "scanSucceeded",
      snapshot: snapshot(),
      at: 3_000
    });
    expect(reviewing.phase).toBe("reviewing");

    const cleaning = sessionReducer(reviewing, {
      type: "cleanupStarted",
      totalCount: 8,
      at: 4_000
    });
    expect(cleaning.phase).toBe("cleaning");

    const done = sessionReducer(cleaning, {
      type: "cleanupSettled",
      report: report(),
      snapshot: snapshot({ candidateCount: 4 }),
      at: 6_000
    });
    expect(done.phase).toBe("cleanupDone");
    expect(done.report?.cleanedCount).toBe(3);
  });

  it("keeps scan statistics after the run settles", () => {
    const settled = reduceAll(READY, [
      { type: "scanStarted", at: 1_000 },
      { type: "scanProgress", progress: scanProgress({ scannedFiles: 98_765 }) },
      { type: "scanSucceeded", snapshot: snapshot(), at: 5_000 }
    ]);

    expect(settled.phase).toBe("reviewing");
    expect(settled.scan.scannedFiles).toBe(98_765);
    expect(scanStatsVisible(settled)).toBe(true);
    expect(settled.scan.elapsedMs).toBe(4_000);
  });

  it("keeps scan statistics after a failure", () => {
    const failed = reduceAll(READY, [
      { type: "scanStarted", at: 1_000 },
      { type: "scanProgress", progress: scanProgress({ scannedFiles: 4_321 }) },
      { type: "scanFailed", error: "boom", at: 2_500 }
    ]);

    expect(failed.phase).toBe("scanFailed");
    expect(failed.scan.scannedFiles).toBe(4_321);
    expect(scanStatsVisible(failed)).toBe(true);
    expect(failed.error).toBe("boom");
  });

  it("resets counters only when a new run starts", () => {
    const rescanned = reduceAll(READY, [
      { type: "scanStarted", at: 1_000 },
      { type: "scanProgress", progress: scanProgress({ scannedFiles: 500 }) },
      { type: "scanSucceeded", snapshot: snapshot(), at: 2_000 },
      { type: "scanStarted", at: 9_000 }
    ]);

    expect(rescanned.scan.scannedFiles).toBe(0);
    expect(rescanned.scan.startedAt).toBe(9_000);
    expect(rescanned.report).toBeNull();
  });

  it("trusts the finished snapshot for final candidate totals", () => {
    const settled = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanProgress", progress: scanProgress({ candidateCount: 2 }) },
      { type: "scanSucceeded", snapshot: snapshot({ candidateCount: 11 }), at: 100 }
    ]);

    expect(settled.scan.candidateCount).toBe(11);
    expect(settled.scan.percent).toBe(100);
  });

  it("copies live scanned bytes from progress events", () => {
    const scanning = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanProgress", progress: scanProgress({ scannedBytes: 12_345, reclaimableBytes: 4096 }) }
    ]);

    expect(scanning.scan.scannedBytes).toBe(12_345);
    expect(scanHeadlineBytes(scanning.scan)).toBe(12_345);
  });

  it("uses coverage allocated bytes as the finished scan total", () => {
    const finished = snapshot();
    finished.coverage = {
      ...finished.coverage,
      allocatedBytes: 50 * 1024 * 1024 * 1024,
      logicalBytes: 48 * 1024 * 1024 * 1024
    };

    const settled = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanProgress", progress: scanProgress({ reclaimableBytes: 4096 }) },
      { type: "scanSucceeded", snapshot: finished, at: 100 }
    ]);

    expect(settled.scan.reclaimableBytes).toBe(4096);
    expect(settled.scan.scannedBytes).toBe(50 * 1024 * 1024 * 1024);
    expect(scanHeadlineBytes(settled.scan)).toBe(50 * 1024 * 1024 * 1024);
  });
});

describe("pause and resume", () => {
  it("toggles scan pause only from the matching phase", () => {
    const scanning = sessionReducer(READY, { type: "scanStarted", at: 0 });
    const paused = sessionReducer(scanning, { type: "scanPaused" });
    expect(paused.phase).toBe("scanPaused");

    const resumed = sessionReducer(paused, { type: "scanResumed" });
    expect(resumed.phase).toBe("scanning");

    expect(sessionReducer(READY, { type: "scanPaused" })).toBe(READY);
    expect(sessionReducer(READY, { type: "scanResumed" })).toBe(READY);
  });

  it("toggles cleanup pause and cancel only while cleanup is busy", () => {
    const cleaning = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanSucceeded", snapshot: snapshot(), at: 10 },
      { type: "cleanupStarted", totalCount: 4, at: 20 }
    ]);

    expect(sessionReducer(cleaning, { type: "cleanupPaused" }).phase).toBe("cleanupPaused");
    expect(sessionReducer(cleaning, { type: "cleanupCanceling" }).phase).toBe("cleanupCanceling");
    expect(sessionReducer(READY, { type: "cleanupCanceling" })).toBe(READY);
  });

  it("still records progress while paused", () => {
    const paused = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanPaused" },
      { type: "scanProgress", progress: scanProgress({ scannedFiles: 42 }) }
    ]);

    expect(paused.scan.scannedFiles).toBe(42);
  });
});

describe("stale event guards", () => {
  it("ignores scan progress that arrives after the run settled", () => {
    const settled = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanProgress", progress: scanProgress({ scannedFiles: 900 }) },
      { type: "scanSucceeded", snapshot: snapshot(), at: 100 }
    ]);

    const late = sessionReducer(settled, {
      type: "scanProgress",
      progress: scanProgress({ scannedFiles: 1, currentPath: "stale" })
    });

    expect(late).toBe(settled);
    expect(late.scan.scannedFiles).toBe(900);
  });

  it("ignores cleanup progress outside a cleanup run", () => {
    const late = sessionReducer(READY, { type: "cleanupProgress", progress: cleanupProgress() });
    expect(late).toBe(READY);
  });

  it("keeps the last known total when a progress event reports zero", () => {
    const cleaning = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanSucceeded", snapshot: snapshot(), at: 10 },
      { type: "cleanupStarted", totalCount: 9, at: 20 },
      { type: "cleanupProgress", progress: cleanupProgress({ totalCount: 0 }) }
    ]);

    expect(cleaning.cleanup.totalCount).toBe(9);
  });
});

describe("percent normalization", () => {
  it("clamps out-of-range scan percents and keeps null for indeterminate runs", () => {
    const scanning = sessionReducer(READY, { type: "scanStarted", at: 0 });

    expect(sessionReducer(scanning, {
      type: "scanProgress",
      progress: scanProgress({ percent: 240 })
    }).scan.percent).toBe(100);

    expect(sessionReducer(scanning, {
      type: "scanProgress",
      progress: scanProgress({ percent: -8 })
    }).scan.percent).toBe(0);

    expect(sessionReducer(scanning, {
      type: "scanProgress",
      progress: scanProgress({ percent: null })
    }).scan.percent).toBeNull();

    expect(sessionReducer(scanning, {
      type: "scanProgress",
      progress: scanProgress({ percent: Number.NaN })
    }).scan.percent).toBeNull();
  });

  it("clamps cleanup percents into range", () => {
    const cleaning = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanSucceeded", snapshot: snapshot(), at: 10 },
      { type: "cleanupStarted", totalCount: 4, at: 20 }
    ]);

    expect(sessionReducer(cleaning, {
      type: "cleanupProgress",
      progress: cleanupProgress({ percent: 500 })
    }).cleanup.percent).toBe(100);
  });
});

describe("elapsed ticker", () => {
  it("advances the active scan clock", () => {
    const ticked = reduceAll(READY, [
      { type: "scanStarted", at: 1_000 },
      { type: "tick", at: 4_500 }
    ]);

    expect(ticked.scan.elapsedMs).toBe(3_500);
  });

  it("advances the active cleanup clock", () => {
    const ticked = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanSucceeded", snapshot: snapshot(), at: 10 },
      { type: "cleanupStarted", totalCount: 4, at: 1_000 },
      { type: "tick", at: 2_250 }
    ]);

    expect(ticked.cleanup.elapsedMs).toBe(1_250);
  });

  it("does nothing when no run is active", () => {
    expect(sessionReducer(READY, { type: "tick", at: 5_000 })).toBe(READY);
  });

  it("freezes the clock once a run settles", () => {
    const settled = reduceAll(READY, [
      { type: "scanStarted", at: 1_000 },
      { type: "scanSucceeded", snapshot: snapshot(), at: 3_000 },
      { type: "tick", at: 99_000 }
    ]);

    expect(settled.scan.elapsedMs).toBe(2_000);
  });
});

describe("derived flags", () => {
  it("reports busy states for scan and cleanup separately", () => {
    const scanning = sessionReducer(READY, { type: "scanStarted", at: 0 });
    expect(isScanBusy(scanning)).toBe(true);
    expect(isCleanupBusy(scanning)).toBe(false);
    expect(isBusy(scanning)).toBe(true);

    const cleaning = reduceAll(scanning, [
      { type: "scanSucceeded", snapshot: snapshot(), at: 10 },
      { type: "cleanupStarted", totalCount: 2, at: 20 }
    ]);
    expect(isScanBusy(cleaning)).toBe(false);
    expect(isCleanupBusy(cleaning)).toBe(true);
    expect(isBusy(cleaning)).toBe(true);

    expect(isBusy(READY)).toBe(false);
  });

  it("hides scan statistics before the first run", () => {
    expect(scanStatsVisible(READY)).toBe(false);
    expect(READY.scan).toEqual(EMPTY_SCAN_STATS);
  });

  it("maps each phase to the right primary action", () => {
    const scanning = sessionReducer(READY, { type: "scanStarted", at: 0 });
    const paused = sessionReducer(scanning, { type: "scanPaused" });
    const reviewing = sessionReducer(scanning, {
      type: "scanSucceeded",
      snapshot: snapshot(),
      at: 10
    });
    const failed = sessionReducer(scanning, { type: "scanFailed", error: "x", at: 10 });

    expect(primaryAction(INITIAL_SESSION)).toBe("scan");
    expect(primaryAction(READY)).toBe("scan");
    expect(primaryAction(scanning)).toBe("pause");
    expect(primaryAction(paused)).toBe("resume");
    expect(primaryAction(reviewing)).toBe("rescan");
    expect(primaryAction(failed)).toBe("rescan");
  });
});

describe("snapshot updates outside a run", () => {
  it("replaces the snapshot without touching the phase", () => {
    const reviewing = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanSucceeded", snapshot: snapshot(), at: 10 }
    ]);

    const replaced = sessionReducer(reviewing, {
      type: "snapshotReplaced",
      snapshot: snapshot({ candidateCount: 99 })
    });

    expect(replaced.phase).toBe("reviewing");
    expect(replaced.snapshot?.summary.candidateCount).toBe(99);
    expect(replaced.scan.candidateCount).toBe(reviewing.scan.candidateCount);
  });

  it("does not regress the phase when a later snapshot load arrives", () => {
    const reviewing = reduceAll(READY, [
      { type: "scanStarted", at: 0 },
      { type: "scanSucceeded", snapshot: snapshot(), at: 10 }
    ]);

    const reloaded = sessionReducer(reviewing, { type: "snapshotLoaded", snapshot: snapshot() });
    expect(reloaded.phase).toBe("reviewing");
  });
});

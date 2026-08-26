import { describe, expect, it } from "vitest";
import {
  clampScanPercent,
  formatScanCount,
  isDeterminateScanProgress,
  scanPercentOrNull,
  truncatePathMiddle
} from "./session";
import { localizedScanPhase } from "./i18n";
import type { LanguageCode } from "./i18n";
import type { ScanPhase, ScanProgress } from "./types";

function progress(overrides: Partial<ScanProgress> = {}): ScanProgress {
  return {
    phase: "walking",
    scannedFiles: 0,
    candidateCount: 0,
    reclaimableBytes: 0,
    scannedBytes: 0,
    currentPath: "",
    currentVolume: "C:",
    totalFiles: null,
    percent: null,
    ...overrides
  };
}

describe("determinate vs indeterminate decision", () => {
  it("treats a null percent as indeterminate", () => {
    expect(scanPercentOrNull(progress({ percent: null }))).toBeNull();
    expect(isDeterminateScanProgress(progress({ percent: null }))).toBe(false);
  });

  it("treats a real percent as determinate", () => {
    expect(scanPercentOrNull(progress({ percent: 42 }))).toBe(42);
    expect(isDeterminateScanProgress(progress({ percent: 42 }))).toBe(true);
  });

  it("treats zero percent as determinate rather than falsy-indeterminate", () => {
    expect(scanPercentOrNull(progress({ percent: 0 }))).toBe(0);
    expect(isDeterminateScanProgress(progress({ percent: 0 }))).toBe(true);
  });

  it("rejects non-finite percents as indeterminate", () => {
    expect(scanPercentOrNull(progress({ percent: Number.NaN }))).toBeNull();
    expect(scanPercentOrNull(progress({ percent: Number.POSITIVE_INFINITY }))).toBeNull();
  });

  it("clamps and rounds out-of-range percents", () => {
    expect(clampScanPercent(-10)).toBe(0);
    expect(clampScanPercent(140)).toBe(100);
    expect(clampScanPercent(41.6)).toBe(42);
    expect(scanPercentOrNull(progress({ percent: 130 }))).toBe(100);
  });
});

describe("scanned file count formatting", () => {
  it("groups thousands for the headline count", () => {
    expect(formatScanCount(421339, "en-US")).toBe("421,339");
  });

  it("formats small and zero counts without separators", () => {
    expect(formatScanCount(0, "en-US")).toBe("0");
    expect(formatScanCount(999, "en-US")).toBe("999");
  });

  it("normalizes negative and fractional counts", () => {
    expect(formatScanCount(-5, "en-US")).toBe("0");
    expect(formatScanCount(1234.9, "en-US")).toBe("1,234");
  });

  it("is locale aware", () => {
    expect(formatScanCount(421339, "de-DE")).toBe("421.339");
  });
});

describe("middle-ellipsis path truncation", () => {
  it("leaves short paths untouched", () => {
    expect(truncatePathMiddle("C:\\Windows\\Temp", 52)).toBe("C:\\Windows\\Temp");
  });

  it("keeps the informative tail of a long path", () => {
    const path = "C:\\Users\\dkon\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\data_2";
    const truncated = truncatePathMiddle(path, 40);

    expect(truncated).toHaveLength(40);
    expect(truncated).toContain("…");
    expect(truncated.startsWith("C:\\Users")).toBe(true);
    expect(truncated.endsWith("data_2")).toBe(true);
  });

  it("never exceeds the requested budget", () => {
    const path = "D:\\".concat("segment\\".repeat(40), "final.log");

    expect(truncatePathMiddle(path, 52).length).toBeLessThanOrEqual(52);
    expect(truncatePathMiddle(path, 10).length).toBeLessThanOrEqual(10);
  });

  it("handles an empty path", () => {
    expect(truncatePathMiddle("", 52)).toBe("");
  });
});

describe("phase label localization", () => {
  const phases: ScanPhase[] = ["preparing", "indexing", "walking", "analyzing", "complete"];
  const languages: LanguageCode[] = ["zh-CN", "en-US", "ja-JP", "fr-FR", "de-DE"];

  it("resolves every phase in every language", () => {
    for (const language of languages) {
      for (const phase of phases) {
        const label = localizedScanPhase(language, phase);

        expect(label).not.toBe(`scan.phase.${phase}`);
        expect(label.trim()).not.toBe("");
      }
    }
  });

  it("uses distinct labels per phase", () => {
    const labels = phases.map((phase) => localizedScanPhase("en-US", phase));

    expect(new Set(labels).size).toBe(phases.length);
  });

  it("names the rule-matching phase instead of a vague analyzing label", () => {
    expect(localizedScanPhase("zh-CN", "analyzing")).toBe("匹配规则");
    expect(localizedScanPhase("en-US", "analyzing")).toBe("Matching rules");
  });
});

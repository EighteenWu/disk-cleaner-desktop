import { describe, expect, it } from "vitest";
import {
  applyCleanupIntensity,
  DEFAULT_RULE_INTENSITY,
  filterRulesForIntensity,
  isRuleIntensity,
  readStoredRuleIntensity,
  storeRuleIntensity
} from "./ruleIntensity";
import type { CleanupCandidate, CompiledCleanupRule, RuleLevel, RiskLevel, SourceKind } from "./types";

function candidate(
  id: string,
  riskLevel: RiskLevel,
  overrides: Partial<CleanupCandidate> = {}
): CleanupCandidate {
  return {
    id,
    parentId: null,
    displayName: id,
    path: `C:\\${id}`,
    volumeId: "C",
    objectType: "directory",
    category: "cache",
    sizeBytes: 1024,
    childrenCount: 0,
    riskLevel,
    defaultSelected: riskLevel === "safeRecommended",
    selected: false,
    deleteStrategy: "moveToRecycleBin",
    reason: "test",
    confidence: 90,
    source: { label: id, kind: "windows" as SourceKind, confidence: 90, evidence: "test" },
    cleanupPolicy: { ruleId: id, method: "contents", keepDays: 0, excludePatterns: [] },
    ...overrides
  };
}

function rule(id: string, level: RuleLevel): CompiledCleanupRule {
  return {
    id,
    name: id,
    app: "App",
    category: "cache",
    level,
    riskLevel:
      level === "recommended"
        ? "safeRecommended"
        : level === "cautious"
          ? "cautiousRecommended"
          : "reviewRequired",
    defaultSelected: level === "recommended",
    requiresDefaultConfirmation: false,
    paths: [`%TEMP%\\${id}`],
    clean: "contents",
    keepDays: 3,
    close: [],
    exclude: [],
    mandatoryExclude: [],
    note: "test",
    source: "user",
    warnings: []
  };
}

describe("filterRulesForIntensity", () => {
  const rules = [
    rule("a.rec", "recommended"),
    rule("b.caut", "cautious"),
    rule("c.rev", "reviewRequired")
  ];

  it("keeps only recommended rules for light", () => {
    expect(filterRulesForIntensity(rules, "light").map((item) => item.id)).toEqual(["a.rec"]);
  });

  it("keeps recommended and cautious rules for medium", () => {
    expect(filterRulesForIntensity(rules, "medium").map((item) => item.id)).toEqual([
      "a.rec",
      "b.caut"
    ]);
  });

  it("keeps every approved rule for heavy", () => {
    expect(filterRulesForIntensity(rules, "heavy").map((item) => item.id)).toEqual([
      "a.rec",
      "b.caut",
      "c.rev"
    ]);
  });

  it("returns an empty list unchanged", () => {
    expect(filterRulesForIntensity([], "heavy")).toEqual([]);
    expect(filterRulesForIntensity([], "light")).toEqual([]);
  });
});

describe("rule intensity preference", () => {
  it("accepts only light, medium, and heavy", () => {
    expect(isRuleIntensity("light")).toBe(true);
    expect(isRuleIntensity("medium")).toBe(true);
    expect(isRuleIntensity("heavy")).toBe(true);
    expect(isRuleIntensity("Light")).toBe(false);
    expect(isRuleIntensity("all")).toBe(false);
    expect(isRuleIntensity(null)).toBe(false);
  });

  it("defaults to medium when storage is missing or invalid", () => {
    expect(DEFAULT_RULE_INTENSITY).toBe("medium");
    expect(readStoredRuleIntensity()).toBe("medium");
    expect(() => storeRuleIntensity("light")).not.toThrow();
  });
});

describe("applyCleanupIntensity", () => {
  const items = [
    candidate("temp", "safeRecommended"),
    candidate("recycle", "safeRecommended", {
      category: "回收站",
      path: "C:\\$Recycle.Bin",
      defaultSelected: false,
      selected: true
    }),
    candidate("wechat", "cautiousRecommended", { selected: true }),
    candidate("npm", "reviewRequired", { selected: true })
  ];

  it("keeps only simple items for light and checks recommended defaults", () => {
    const next = applyCleanupIntensity(items, "light");
    expect(next.map((item) => item.id)).toEqual(["temp", "recycle"]);
    expect(next.find((item) => item.id === "temp")?.selected).toBe(true);
    expect(next.find((item) => item.id === "recycle")?.selected).toBe(false);
  });

  it("auto-checks cautious items for medium", () => {
    const next = applyCleanupIntensity(items, "medium");
    expect(next.map((item) => item.id)).toEqual(["temp", "recycle", "wechat"]);
    expect(next.find((item) => item.id === "temp")?.selected).toBe(true);
    expect(next.find((item) => item.id === "wechat")?.selected).toBe(true);
    expect(next.find((item) => item.id === "recycle")?.selected).toBe(false);
  });

  it("auto-checks review items for heavy", () => {
    const next = applyCleanupIntensity(items, "heavy");
    expect(next.map((item) => item.id)).toEqual(["temp", "recycle", "wechat", "npm"]);
    expect(next.find((item) => item.id === "npm")?.selected).toBe(true);
    expect(next.find((item) => item.id === "wechat")?.selected).toBe(true);
    expect(next.find((item) => item.id === "recycle")?.selected).toBe(false);
  });
});

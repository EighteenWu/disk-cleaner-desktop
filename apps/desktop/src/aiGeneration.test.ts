import { describe, expect, it } from "vitest";

import {
  aiGeneratedRulesFromCompiled,
  aiGenerationRequest,
  aiGenerationRequestPreview,
  appendPlanDelta,
  canApproveAiPlan,
  canonicalPlanUserMessage,
  clampRevisionInstruction,
  liveAiRuleYaml,
  planMessagesForRequest,
  previousRulesFromLiveAiLibrary,
  resolvePlanUserContent,
  shouldWarnReplaceAiRecord,
  MAX_PLAN_MESSAGES,
  MAX_REVISION_INSTRUCTION_CHARS
} from "./aiGeneration";
import type {
  ActiveRuleSnapshot,
  AiChatMessage,
  AiGeneratedRuleSet,
  CompiledCleanupRule,
  RedactedScanSummary,
  RuleRecord
} from "./types";

const summary: RedactedScanSummary = {
  schemaVersion: 3,
  redactionVersion: 3,
  scanMode: "mft",
  buckets: [
    {
      sourceKind: "browser",
      riskLevel: "safeRecommended",
      category: "cache",
      candidateCount: 1,
      totalBytes: 4096,
      sizeBand: "under10mb",
      samples: [
        {
          path: "C:\\Users\\alice\\AppData\\Local\\Temp\\cache",
          displayName: "cache",
          sizeBytes: 4096
        }
      ]
    }
  ],
  riskSignals: ["coverage-partial"],
  omittedCount: 0,
  truncated: false,
  summaryHash: "fixture-hash"
};

const previousRules: AiGeneratedRuleSet = {
  schemaVersion: 1,
  rules: [
    {
      id: "cache.temp",
      tier: "light",
      name: "Temp cache",
      app: "Windows",
      category: "cache",
      paths: ["%TEMP%\\AppCache"],
      clean: "contents",
      keepDays: 7,
      exclude: ["*.lock"],
      note: "cache",
      evidence: ["aggregate"],
      cautions: ["review"]
    }
  ]
};

describe("AI generation request", () => {
  it("defaults to allTiers without a target tier", () => {
    const request = aiGenerationRequest(summary);

    expect(request.generationMode).toBe("allTiers");
    expect(request.targetTier).toBeNull();
    expect(request.revision).toBeUndefined();
    expect(request.summary.schemaVersion).toBe(3);
    expect(request.summary.buckets[0]?.samples[0]?.path).toContain("AppData");
    expect(request.summary.buckets[0]?.samples[0]).not.toHaveProperty("reason");
    expect(request.summary.buckets[0]?.samples[0]).not.toHaveProperty("evidence");
    const preview = JSON.parse(aiGenerationRequestPreview(request));
    expect(preview).toEqual(request);
    expect(preview.summary.buckets[0].samples[0].path).toBe(
      summary.buckets[0].samples[0].path
    );
    expect(JSON.stringify(preview)).not.toContain("browser cache");
  });

  it("builds a singleTier request with the selected tier", () => {
    const request = aiGenerationRequest(summary, "singleTier", "heavy");

    expect(request.generationMode).toBe("singleTier");
    expect(request.targetTier).toBe("heavy");
  });

  it("rejects singleTier without a target tier", () => {
    expect(() => aiGenerationRequest(summary, "singleTier", null)).toThrow(
      /singleTier generation requires a target tier/
    );
  });

  it("includes revision decisions without changing the summary contract", () => {
    const request = aiGenerationRequest(summary, "allTiers", null, {
      previousRules,
      droppedIds: ["old.rule"],
      tierChanges: [{ id: "cache.temp", tier: "medium" }],
      rewriteIds: ["cache.temp"],
      instruction: "只要缓存"
    });

    expect(request.revision?.droppedIds).toEqual(["old.rule"]);
    expect(request.revision?.instruction).toBe("只要缓存");
    expect(request.summary.summaryHash).toBe(summary.summaryHash);
    const preview = aiGenerationRequestPreview(request);
    expect(preview).toContain("droppedIds");
    expect(preview).toContain("只要缓存");
    expect(preview).not.toMatch(/Authorization|sk-/i);
  });

  it("clamps revision instructions to the shared character cap", () => {
    expect(clampRevisionInstruction("x".repeat(MAX_REVISION_INSTRUCTION_CHARS + 8))).toHaveLength(
      MAX_REVISION_INSTRUCTION_CHARS
    );
  });

  it("includes planText without stuffing it into the 200-char instruction field", () => {
    const planText = "轻度：缓存。中度：日志。重度：空。";
    const request = aiGenerationRequest(summary, "allTiers", null, null, planText);

    expect(request.planText).toBe(planText);
    expect(request.revision).toBeUndefined();
    expect(request.generationMode).toBe("allTiers");
  });
});

describe("AI plan chat helpers", () => {
  const translate = (key: string) =>
    key === "rule.aiChatCanonical"
      ? "From this scan, list recommended, confirm, and do-not-touch directories with size, path, note, and impact."
      : key;

  it("sends a canonical user message when the composer is empty", () => {
    expect(resolvePlanUserContent("", translate)).toBe(canonicalPlanUserMessage(translate));
    expect(resolvePlanUserContent(" 只要缓存 ", translate)).toBe("只要缓存");
    expect(canonicalPlanUserMessage(translate)).toMatch(/大小|路径|size|path|说明|影响/i);
  });

  it("does not require a prepared preview payload to build plan messages", () => {
    const messages: AiChatMessage[] = [
      { id: "u1", role: "user", content: canonicalPlanUserMessage(translate), status: "complete" }
    ];
    const outbound = planMessagesForRequest(messages);
    expect(outbound).toEqual([
      { role: "user", content: canonicalPlanUserMessage(translate) }
    ]);
    expect(JSON.stringify(outbound)).not.toContain("summaryHash");
  });

  it("enables approve only after a completed assistant reply", () => {
    const streaming: AiChatMessage[] = [
      { id: "u1", role: "user", content: "scope", status: "complete" },
      { id: "a1", role: "assistant", content: "轻", status: "streaming" }
    ];
    expect(canApproveAiPlan(streaming, false)).toBe(false);
    expect(
      canApproveAiPlan(
        [
          streaming[0],
          { id: "a1", role: "assistant", content: "轻度：缓存\n中度：空\n重度：空", status: "complete" }
        ],
        false
      )
    ).toBe(true);
    expect(
      canApproveAiPlan(
        [
          streaming[0],
          { id: "a1", role: "assistant", content: "轻度：缓存", status: "complete" }
        ],
        true
      )
    ).toBe(false);
  });

  it("warns when a live AI record would be replaced and ignores tombstones", () => {
    const live = { origin: "aiGenerated", state: "approved", updatedAt: "2", id: "a" } as RuleRecord;
    const deleted = { origin: "aiGenerated", state: "deleted", updatedAt: "9", id: "d" } as RuleRecord;
    expect(shouldWarnReplaceAiRecord([deleted])).toBe(false);
    expect(shouldWarnReplaceAiRecord([deleted, live])).toBe(true);
  });

  it("appends plan deltas without exposing probe text", () => {
    expect(appendPlanDelta("轻", "度：缓存")).toBe("轻度：缓存");
    expect(appendPlanDelta("轻", undefined)).toBe("轻");
    expect(MAX_PLAN_MESSAGES).toBe(8);
  });

  it("rebuilds previousRules from a live approved AI record", () => {
    const compiled: CompiledCleanupRule = {
      id: "cache.temp",
      name: "Temp cache",
      app: "Windows",
      category: "cache",
      level: "recommended",
      riskLevel: "safeRecommended",
      defaultSelected: false,
      requiresDefaultConfirmation: false,
      paths: ["%TEMP%\\AppCache"],
      clean: "contents",
      keepDays: 7,
      close: [],
      exclude: ["*.lock"],
      mandatoryExclude: [],
      note: "cache",
      source: "user",
      warnings: []
    };
    const live = {
      origin: "aiGenerated",
      state: "approved",
      updatedAt: "2",
      id: "a",
      activeRevisionId: "rev",
      lastApprovedRevisionId: "rev",
      pendingRevisionId: null,
      revisions: [{ id: "rev", content: "version: 1\nrules: []" }]
    } as RuleRecord;
    const deleted = {
      origin: "aiGenerated",
      state: "deleted",
      updatedAt: "9",
      id: "d",
      revisions: [{ id: "old", content: "gone" }]
    } as RuleRecord;
    const active: ActiveRuleSnapshot = {
      libraryGeneration: 1,
      rules: [compiled],
      entries: [{ recordId: "a", revisionId: "rev", contentHash: "h", ruleIds: ["cache.temp"] }],
      blockingIssues: []
    };

    expect(previousRulesFromLiveAiLibrary([deleted], active)).toBeNull();
    expect(liveAiRuleYaml([deleted, live])).toContain("version: 1");
    const rebuilt = previousRulesFromLiveAiLibrary([deleted, live], active);
    expect(rebuilt?.rules).toEqual([
      {
        id: "cache.temp",
        tier: "light",
        name: "Temp cache",
        app: "Windows",
        category: "cache",
        paths: ["%TEMP%\\AppCache"],
        clean: "contents",
        keepDays: 7,
        exclude: ["*.lock"],
        note: "cache",
        evidence: ["aggregate"],
        cautions: ["review"]
      }
    ]);
    expect(aiGeneratedRulesFromCompiled([{ ...compiled, keepDays: 400 }])).toBeNull();
    expect(aiGeneratedRulesFromCompiled([{ ...compiled, id: "not a rule" }])).toBeNull();
  });
});

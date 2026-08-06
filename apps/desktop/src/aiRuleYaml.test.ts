import { describe, expect, it } from "vitest";

import { AI_RULE_TIERS, aiDraftProvenance, aiRulesToYaml, tierRules } from "./aiRuleYaml";
import type { AiGeneratedRule, AiGeneratedRuleSet, AiRuleTier } from "./types";

function rule(id: string, tier: AiRuleTier, overrides: Partial<AiGeneratedRule> = {}): AiGeneratedRule {
  return {
    id,
    tier,
    name: id,
    app: "Fixture",
    category: "cache",
    paths: ["%TEMP%\\fixture"],
    clean: "contents",
    keepDays: 7,
    exclude: ["*.lock"],
    note: "fixture note",
    evidence: ["aggregate"],
    cautions: [],
    ...overrides
  };
}

function ruleSet(rules: AiGeneratedRule[]): AiGeneratedRuleSet {
  return { schemaVersion: 1, rules };
}

describe("aiRuleYaml", () => {
  it("groups candidates by tier in a stable order", () => {
    const set = ruleSet([rule("a", "heavy"), rule("b", "light"), rule("c", "light")]);

    expect(AI_RULE_TIERS).toEqual(["light", "medium", "heavy"]);
    expect(tierRules(set, "light").map((item) => item.id)).toEqual(["b", "c"]);
    expect(tierRules(set, "medium")).toEqual([]);
    expect(tierRules(set, "heavy").map((item) => item.id)).toEqual(["a"]);
  });

  it("maps tiers onto rule levels and quotes scalars", () => {
    const yaml = aiRulesToYaml(
      ruleSet([rule("light.one", "light"), rule("medium.one", "medium"), rule("heavy.one", "heavy")])
    );

    expect(yaml).toContain('level: "推荐清理"');
    expect(yaml).toContain('level: "谨慎清理"');
    expect(yaml).toContain('level: "需要确认"');
    // Backslashes in Windows path templates must survive as YAML strings.
    expect(yaml).toContain('- "%TEMP%\\\\fixture"');
    expect(yaml.endsWith("\n")).toBe(true);
  });

  it("never marks generated rules as selected by default", () => {
    const yaml = aiRulesToYaml(ruleSet([rule("light.one", "light")]));

    expect(yaml).toContain("default: false");
    expect(yaml).not.toContain("default: true");
  });

  it("keeps a provider trail on the draft provenance", () => {
    const provenance = aiDraftProvenance({
      providerProfileId: "profile-1",
      model: "claude-opus-5",
      scanSummaryHash: "hash-1",
      generatedAt: "2026-07-28T00:00:00.000Z"
    });

    expect(provenance).toEqual({
      sourceLabel: "aiGenerated",
      providerProfileId: "profile-1",
      model: "claude-opus-5",
      scanSummaryHash: "hash-1",
      sourceUrl: null,
      generatedAt: "2026-07-28T00:00:00.000Z",
      aiDraftId: null,
      aiDraftRevision: null
    });
  });
});

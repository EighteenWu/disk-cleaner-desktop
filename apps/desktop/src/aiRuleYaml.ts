import type { AiGeneratedRule, AiGeneratedRuleSet, AiRuleTier, RuleProvenance } from "./types";

/**
 * AI output is a one-shot proposal: it is serialised to YAML exactly once when
 * saved as a draft, and from then on the library revision is the source of
 * truth. Nothing parses YAML back into this shape, so the flow stays one-way
 * (proposal -> YAML -> revision) and later edits happen on the YAML itself.
 */

const TIER_LEVEL: Record<AiRuleTier, string> = {
  light: "推荐清理",
  medium: "谨慎清理",
  heavy: "需要确认"
};

export const AI_RULE_TIERS: readonly AiRuleTier[] = ["light", "medium", "heavy"];

export function tierRules(ruleSet: AiGeneratedRuleSet, tier: AiRuleTier): AiGeneratedRule[] {
  return ruleSet.rules.filter((rule) => rule.tier === tier);
}

export function aiRulesToYaml(ruleSet: AiGeneratedRuleSet): string {
  const lines = ["version: 1", "name: AI generated cleanup rules", "publisher: local-ai", "rules:"];
  for (const rule of ruleSet.rules) {
    lines.push(
      `  - id: ${yamlScalar(rule.id)}`,
      `    name: ${yamlScalar(rule.name)}`,
      `    app: ${yamlScalar(rule.app)}`,
      `    category: ${yamlScalar(rule.category)}`,
      `    level: ${yamlScalar(TIER_LEVEL[rule.tier])}`,
      "    default: false",
      "    paths:"
    );
    for (const path of rule.paths) {
      lines.push(`      - ${yamlScalar(path)}`);
    }
    lines.push(`    clean: ${rule.clean}`, `    keep_days: ${rule.keepDays}`, "    exclude:");
    for (const exclude of rule.exclude) {
      lines.push(`      - ${yamlScalar(exclude)}`);
    }
    lines.push(`    note: ${yamlScalar(rule.note)}`);
  }
  return `${lines.join("\n")}\n`;
}

export function aiDraftProvenance(options: {
  providerProfileId: string;
  model: string | null;
  scanSummaryHash: string;
  generatedAt?: string;
}): RuleProvenance {
  return {
    sourceLabel: "aiGenerated",
    providerProfileId: options.providerProfileId,
    model: options.model,
    scanSummaryHash: options.scanSummaryHash,
    sourceUrl: null,
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    aiDraftId: null,
    aiDraftRevision: null
  };
}

function yamlScalar(value: string): string {
  return JSON.stringify(value);
}

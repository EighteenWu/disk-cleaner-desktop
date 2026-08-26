import type {
  ActiveRuleSnapshot,
  AiChatMessage,
  AiGeneratedRule,
  AiGeneratedRuleSet,
  AiGenerationMode,
  AiGenerationRevision,
  AiProviderGenerationRequest,
  AiProviderPlanMessage,
  AiRuleTier,
  CompiledCleanupRule,
  RedactedScanSummary,
  RuleLevel,
  RuleRecord
} from "./types";

export const MAX_REVISION_INSTRUCTION_CHARS = 200;
export const MAX_PLAN_MESSAGES = 8;
export const MAX_PLAN_MESSAGE_CHARS = 2000;
export const MAX_PLAN_TEXT_CHARS = 16384;

export function aiGenerationRequest(
  summary: RedactedScanSummary,
  generationMode: AiGenerationMode = "allTiers",
  targetTier: AiRuleTier | null = null,
  revision: AiGenerationRevision | null = null,
  planText: string | null = null
): AiProviderGenerationRequest {
  const request: AiProviderGenerationRequest =
    generationMode === "allTiers"
      ? { summary, generationMode, targetTier: null }
      : targetTier
        ? { summary, generationMode, targetTier }
        : (() => {
            throw new Error("singleTier generation requires a target tier");
          })();
  if (revision) {
    request.revision = revision;
  }
  if (planText) {
    request.planText = [...planText].slice(0, MAX_PLAN_TEXT_CHARS).join("");
  }
  return request;
}

export function canonicalPlanUserMessage(
  translate: (key: string, values?: Record<string, string | number>) => string
): string {
  return translate("rule.aiChatCanonical");
}

export function resolvePlanUserContent(
  input: string,
  translate: (key: string, values?: Record<string, string | number>) => string
): string {
  const trimmed = input.trim();
  return trimmed.length === 0 ? canonicalPlanUserMessage(translate) : trimmed;
}

export function planMessagesForRequest(messages: AiChatMessage[]): AiProviderPlanMessage[] {
  return messages
    .filter(
      (message) =>
        message.role === "user" || (message.role === "assistant" && message.status === "complete")
    )
    .map((message) => ({
      role: message.role,
      content: [...message.content].slice(0, MAX_PLAN_MESSAGE_CHARS).join("")
    }))
    .slice(-MAX_PLAN_MESSAGES);
}

export function canApproveAiPlan(messages: AiChatMessage[], busy: boolean): boolean {
  if (busy) return false;
  const last = [...messages].reverse().find((message) => message.role === "assistant");
  return last?.status === "complete" && last.content.trim().length > 0;
}

export function latestLiveAiRecord(records: RuleRecord[] | undefined): RuleRecord | undefined {
  return records
    ?.filter((record) => record.origin === "aiGenerated" && record.state !== "deleted")
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt) || right.id.localeCompare(left.id))[0];
}

export function shouldWarnReplaceAiRecord(records: RuleRecord[] | undefined): boolean {
  return latestLiveAiRecord(records) != null;
}

const LEVEL_TO_TIER: Record<RuleLevel, AiRuleTier> = {
  recommended: "light",
  cautious: "medium",
  reviewRequired: "heavy"
};

export function liveAiRuleYaml(records: RuleRecord[] | undefined): string | null {
  const live = latestLiveAiRecord(records);
  if (!live) return null;
  const headId = live.activeRevisionId ?? live.lastApprovedRevisionId ?? live.pendingRevisionId;
  return live.revisions.find((revision) => revision.id === headId)?.content ?? null;
}

export function aiGeneratedRulesFromCompiled(
  rules: CompiledCleanupRule[]
): AiGeneratedRuleSet | null {
  if (rules.length === 0 || rules.length > 96) return null;
  const mapped: AiGeneratedRule[] = [];
  const ids = new Set<string>();
  for (const rule of rules) {
    if (
      !/^[A-Za-z0-9._-]{1,128}$/.test(rule.id) ||
      ids.has(rule.id) ||
      rule.paths.length === 0 ||
      rule.keepDays > 365 ||
      !rule.name.trim()
    ) {
      return null;
    }
    ids.add(rule.id);
    mapped.push({
      id: rule.id,
      tier: LEVEL_TO_TIER[rule.level],
      name: rule.name,
      app: rule.app.trim() || "App",
      category: rule.category.trim() || "other",
      paths: rule.paths,
      clean: rule.clean,
      keepDays: rule.keepDays,
      exclude: rule.exclude,
      note: rule.note.trim() || "previous",
      evidence: ["aggregate"],
      cautions: ["review"]
    });
  }
  return { schemaVersion: 1, rules: mapped };
}

export function previousRulesFromLiveAiLibrary(
  records: RuleRecord[] | undefined,
  active: ActiveRuleSnapshot | null | undefined
): AiGeneratedRuleSet | null {
  const live = latestLiveAiRecord(records);
  if (!live || !active) return null;
  const entry = active.entries.find((item) => item.recordId === live.id);
  if (!entry) return null;
  return aiGeneratedRulesFromCompiled(
    active.rules.filter((rule) => entry.ruleIds.includes(rule.id))
  );
}

export function appendPlanDelta(content: string, delta: string | undefined): string {
  return delta ? `${content}${delta}` : content;
}

export function aiGenerationRequestPreview(request: AiProviderGenerationRequest): string {
  return JSON.stringify(request, null, 2);
}

export function clampRevisionInstruction(value: string): string {
  return [...value].slice(0, MAX_REVISION_INSTRUCTION_CHARS).join("");
}

import { isCleanupSelectable, setCandidateSelection } from "./state";
import type { CleanupCandidate, CompiledCleanupRule, RuleIntensity } from "./types";

export const RULE_INTENSITIES = ["light", "medium", "heavy"] as const;
export const DEFAULT_RULE_INTENSITY: RuleIntensity = "medium";
export const INTENSITY_STORAGE_KEY = "diskclean.scanIntensity.v1";

export function isRuleIntensity(value: unknown): value is RuleIntensity {
  return value === "light" || value === "medium" || value === "heavy";
}

export function filterRulesForIntensity(
  rules: readonly CompiledCleanupRule[],
  intensity: RuleIntensity
): CompiledCleanupRule[] {
  switch (intensity) {
    case "light":
      return rules.filter((rule) => rule.level === "recommended");
    case "medium":
      return rules.filter((rule) => rule.level === "recommended" || rule.level === "cautious");
    case "heavy":
      return rules.slice();
  }
}

export function readStoredRuleIntensity(): RuleIntensity {
  try {
    const stored = window.localStorage.getItem(INTENSITY_STORAGE_KEY);
    return isRuleIntensity(stored) ? stored : DEFAULT_RULE_INTENSITY;
  } catch {
    return DEFAULT_RULE_INTENSITY;
  }
}

export function storeRuleIntensity(intensity: RuleIntensity) {
  try {
    window.localStorage.setItem(INTENSITY_STORAGE_KEY, intensity);
  } catch {
    // Storage can be unavailable; the in-memory value still applies.
  }
}

export function candidateCleanupTier(candidate: CleanupCandidate): RuleIntensity {
  const path = candidate.path.toLowerCase();
  if (candidate.category === "回收站" || path.includes("$recycle.bin")) {
    return "light";
  }
  switch (candidate.riskLevel) {
    case "safeRecommended":
      return "light";
    case "cautiousRecommended":
      return "medium";
    case "reviewRequired":
    case "blocked":
      return "heavy";
  }
}

export function candidateMatchesIntensity(
  candidate: CleanupCandidate,
  intensity: RuleIntensity
): boolean {
  const tier = candidateCleanupTier(candidate);
  switch (intensity) {
    case "light":
      return tier === "light";
    case "medium":
      return tier === "light" || tier === "medium";
    case "heavy":
      return true;
  }
}

export function applyCleanupIntensity(
  candidates: readonly CleanupCandidate[],
  intensity: RuleIntensity
): CleanupCandidate[] {
  const visible = candidates.filter((candidate) =>
    candidateMatchesIntensity(candidate, intensity)
  );
  const selectedIds: string[] = [];
  const otherIds: string[] = [];

  for (const candidate of visible) {
    if (isCleanupSelectable(candidate) && !isRecycleBinCandidate(candidate)) {
      selectedIds.push(candidate.id);
    } else {
      otherIds.push(candidate.id);
    }
  }

  return setCandidateSelection(
    setCandidateSelection(visible, otherIds, false),
    selectedIds,
    true
  );
}

function isRecycleBinCandidate(candidate: CleanupCandidate): boolean {
  return (
    candidate.category === "回收站" || candidate.path.toLowerCase().includes("$recycle.bin")
  );
}

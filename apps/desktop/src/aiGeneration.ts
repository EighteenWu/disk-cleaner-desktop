import type {
  AiGenerationMode,
  AiProviderGenerationRequest,
  AiRuleTier,
  RedactedScanSummary
} from "./types";

export function aiGenerationRequest(
  summary: RedactedScanSummary,
  generationMode: AiGenerationMode = "allTiers",
  targetTier: AiRuleTier | null = null
): AiProviderGenerationRequest {
  if (generationMode === "allTiers") {
    return { summary, generationMode, targetTier: null };
  }
  if (!targetTier) {
    throw new Error("singleTier generation requires a target tier");
  }
  return { summary, generationMode, targetTier };
}

export function aiGenerationRequestPreview(request: AiProviderGenerationRequest): string {
  return JSON.stringify(request, null, 2);
}

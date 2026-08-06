import type { AiProviderGenerationRequest, AiRuleTier, RedactedScanSummary } from "./types";

export function aiGenerationRequest(
  summary: RedactedScanSummary,
  targetTier: AiRuleTier
): AiProviderGenerationRequest {
  return { summary, targetTier };
}

export function aiGenerationRequestPreview(request: AiProviderGenerationRequest): string {
  return JSON.stringify(request, null, 2);
}

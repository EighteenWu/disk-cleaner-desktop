import { describe, expect, it } from "vitest";

import { aiGenerationRequest, aiGenerationRequestPreview } from "./aiGeneration";
import type { RedactedScanSummary } from "./types";

const summary: RedactedScanSummary = {
  schemaVersion: 1,
  redactionVersion: 1,
  scanMode: "mft",
  buckets: [],
  riskSignals: [],
  omittedCount: 0,
  truncated: false,
  summaryHash: "fixture-hash"
};

describe("AI generation request", () => {
  it("defaults to allTiers without a target tier", () => {
    const request = aiGenerationRequest(summary);

    expect(request.generationMode).toBe("allTiers");
    expect(request.targetTier).toBeNull();
    expect(JSON.parse(aiGenerationRequestPreview(request))).toEqual(request);
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
});

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
  it("renders the exact business payload that is sent", () => {
    const request = aiGenerationRequest(summary, "heavy");

    expect(JSON.parse(aiGenerationRequestPreview(request))).toEqual(request);
    expect(request.targetTier).toBe("heavy");
  });
});

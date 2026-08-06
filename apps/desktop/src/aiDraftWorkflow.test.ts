import { describe, expect, it } from "vitest";

import { aiDraftApprovalReady, aiDraftValidationReady } from "./aiDraftWorkflow";
import type { AiRuleDraft } from "./types";

function draft(overrides: Partial<AiRuleDraft> = {}): AiRuleDraft {
  return {
    schemaVersion: 1,
    redactionVersion: 1,
    id: "draft-1",
    revision: 2,
    validationRevision: 2,
    summaryHash: "0123456789abcdef".repeat(4),
    targetTier: "light",
    providerProfileId: "00000000-0000-4000-8000-000000000001",
    model: "fixture-model",
    generatedAt: "2026-07-30T00:00:00Z",
    rules: { schemaVersion: 1, rules: [] },
    compilation: {
      rules: [],
      report: { valid: true, ruleCount: 0, errors: [], warnings: [] }
    },
    ...overrides
  };
}

describe("AI draft workflow gates", () => {
  it("makes current validation stale as soon as the editor changes", () => {
    const current = draft();

    expect(aiDraftApprovalReady(current, false)).toBe(true);
    expect(aiDraftValidationReady(current, true)).toBe(false);
    expect(aiDraftApprovalReady(current, true)).toBe(false);
  });

  it("rejects stale or invalid approval", () => {
    expect(aiDraftApprovalReady(draft({ validationRevision: 1 }), false)).toBe(false);
    expect(
      aiDraftApprovalReady(
        draft({
          compilation: {
            rules: [],
            report: {
              valid: false,
              ruleCount: 0,
              errors: [{ ruleId: null, field: "paths", message: "invalid" }],
              warnings: []
            }
          }
        }),
        false
      )
    ).toBe(false);
  });
});

import { describe, expect, it } from "vitest";

import {
  AI_RULE_IMPORT_MUTATION,
  libraryTableActions,
  visibleRuleLibraryRecords
} from "./useRuleSources";
import type { RuleRecord } from "./types";

function record(overrides: Partial<RuleRecord>): RuleRecord {
  return {
    id: "r1",
    displayName: "AI",
    origin: "aiGenerated",
    state: "approved",
    activeRevisionId: "rev1",
    pendingRevisionId: null,
    lastApprovedRevisionId: "rev1",
    createdAt: "1",
    updatedAt: "1",
    deletedAt: null,
    revisions: [],
    events: [],
    ...overrides
  };
}

describe("rule library table projection", () => {
  it("hides tombstones and does not offer restore or rollback", () => {
    const approved = record({ id: "a", state: "approved" });
    const disabled = record({ id: "b", state: "disabled" });
    const deleted = record({ id: "c", state: "deleted", deletedAt: "9" });

    expect(visibleRuleLibraryRecords([approved, disabled, deleted]).map((item) => item.id)).toEqual([
      "a",
      "b"
    ]);
    expect(libraryTableActions(approved)).toEqual(["edit", "disable", "delete"]);
    expect(libraryTableActions(disabled)).toEqual(["edit", "enable", "delete"]);
    expect(libraryTableActions(record({ state: "draft", pendingRevisionId: "p1" }))).toEqual([
      "edit",
      "approve",
      "delete"
    ]);
    expect(libraryTableActions(approved)).not.toContain("enable");
    expect(libraryTableActions(disabled)).not.toContain("disable");
  });

  it("imports AI rules with the upsert-and-enable mutation", () => {
    expect(AI_RULE_IMPORT_MUTATION).toBe("importAndApproveAiRule");
  });
});

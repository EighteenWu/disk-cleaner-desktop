import { describe, expect, it } from "vitest";

import {
  DEFAULT_PROVIDER_TIMEOUT_MS,
  MAX_AI_SESSION_EVENTS,
  MAX_PROVIDER_TIMEOUT_SECONDS,
  MIN_PROVIDER_TIMEOUT_SECONDS,
  providerDetectSavePlan,
  pushSessionEvent,
  shouldAutoDetectProvider
} from "./useAiRuleGeneration";
import type { AiSessionEvent } from "./types";

describe("provider timeout defaults", () => {
  it("uses a thinking-model-friendly overall cap instead of 45s", () => {
    expect(DEFAULT_PROVIDER_TIMEOUT_MS).toBe(180_000);
    expect(MIN_PROVIDER_TIMEOUT_SECONDS).toBe(15);
    expect(MAX_PROVIDER_TIMEOUT_SECONDS).toBe(600);
  });
});

describe("provider auto-detect guards", () => {
  it("does not auto-network when the key field is empty", () => {
    expect(shouldAutoDetectProvider("")).toBe(false);
    expect(shouldAutoDetectProvider("  ")).toBe(false);
    expect(shouldAutoDetectProvider("sk-live")).toBe(true);
  });

  it("does not save a new profile or credential after a failed probe", () => {
    expect(providerDetectSavePlan(false, "sk-new")).toEqual({
      saveProfile: false,
      saveCredential: false
    });
  });
});

describe("AI session panel ring buffer", () => {
  it("prepends events and caps at the dialog memory limit", () => {
    let events: AiSessionEvent[] = [];
    for (let index = 0; index < MAX_AI_SESSION_EVENTS + 3; index += 1) {
      events = pushSessionEvent(events, {
        at: `2026-08-06T00:00:${String(index).padStart(2, "0")}Z`,
        kind: "probe",
        model: "fixture-model",
        latencyMs: index,
        message: `event-${index}`
      });
    }

    expect(events).toHaveLength(MAX_AI_SESSION_EVENTS);
    expect(events[0]?.message).toBe(`event-${MAX_AI_SESSION_EVENTS + 2}`);
    expect(events[events.length - 1]?.message).toBe("event-3");
    expect(events.every((event) => !event.message.toLowerCase().includes("api key"))).toBe(true);
    expect(JSON.stringify(events)).not.toMatch(/C:\\\\Users|Authorization|sk-/i);
  });

  it("records generate metadata without raw paths", () => {
    const events = pushSessionEvent([], {
      kind: "generate",
      summaryHash: "a".repeat(64),
      mode: "allTiers",
      model: "fixture-model",
      latencyMs: 1200,
      ruleCount: 3,
      message: "generated"
    });

    expect(events[0]).toMatchObject({
      kind: "generate",
      mode: "allTiers",
      model: "fixture-model",
      ruleCount: 3,
      latencyMs: 1200
    });
    expect(events[0]?.summaryHash).toHaveLength(64);
  });
});

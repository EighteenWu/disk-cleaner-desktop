import { describe, expect, it } from "vitest";
import {
  clearStoredRuleSubscription,
  createStoredRuleSubscription,
  readStoredRuleSubscription,
  RULE_SUBSCRIPTION_STORAGE_KEY,
  storeRuleSubscription
} from "./ruleSubscriptionStorage";

class MemoryStorage {
  private readonly entries = new Map<string, string>();

  getItem(key: string): string | null {
    return this.entries.get(key) ?? null;
  }

  setItem(key: string, value: string) {
    this.entries.set(key, value);
  }

  removeItem(key: string) {
    this.entries.delete(key);
  }
}

describe("rule subscription storage", () => {
  it("stores and reads a valid subscription payload", () => {
    const storage = new MemoryStorage();
    const subscription = createStoredRuleSubscription(
      " https://example.com/rules.yaml ",
      "version: 1\nrules:\n  - id: sample\n",
      "2026-05-14T00:00:00.000Z"
    );

    expect(storeRuleSubscription(subscription, storage)).toBe(true);
    expect(readStoredRuleSubscription(storage)).toEqual({
      url: "https://example.com/rules.yaml",
      content: "version: 1\nrules:\n  - id: sample\n",
      checkedAt: "2026-05-14T00:00:00.000Z"
    });
  });

  it("rejects malformed stored payloads", () => {
    const storage = new MemoryStorage();
    storage.setItem(
      RULE_SUBSCRIPTION_STORAGE_KEY,
      JSON.stringify({
        url: "",
        content: "version: 1",
        checkedAt: "2026-05-14T00:00:00.000Z"
      })
    );

    expect(readStoredRuleSubscription(storage)).toBeNull();
  });

  it("rejects oversized cached content", () => {
    const storage = new MemoryStorage();
    const oversizedContent = "x".repeat(2 * 1024 * 1024 + 1);

    expect(
      storeRuleSubscription(
        createStoredRuleSubscription("https://example.com/rules.yaml", oversizedContent),
        storage
      )
    ).toBe(false);
    expect(readStoredRuleSubscription(storage)).toBeNull();
  });

  it("clears a cached subscription", () => {
    const storage = new MemoryStorage();
    const subscription = createStoredRuleSubscription("https://example.com/rules.yaml", "version: 1");

    storeRuleSubscription(subscription, storage);
    clearStoredRuleSubscription(storage);

    expect(readStoredRuleSubscription(storage)).toBeNull();
  });
});

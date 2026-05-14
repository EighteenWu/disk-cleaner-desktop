import type { StoredRuleSubscription } from "./types";

export const RULE_SUBSCRIPTION_STORAGE_KEY = "diskclean.ruleSubscription.v1";
const MAX_STORED_RULE_SUBSCRIPTION_BYTES = 2 * 1024 * 1024;

export type { StoredRuleSubscription } from "./types";

export function createStoredRuleSubscription(
  url: string,
  content: string,
  checkedAt = new Date().toISOString()
): StoredRuleSubscription {
  return {
    url: url.trim(),
    content,
    checkedAt
  };
}

export function readStoredRuleSubscription(
  storage: Pick<Storage, "getItem"> = window.localStorage
): StoredRuleSubscription | null {
  try {
    const rawSubscription = storage.getItem(RULE_SUBSCRIPTION_STORAGE_KEY);
    if (!rawSubscription) {
      return null;
    }

    const parsedSubscription = JSON.parse(rawSubscription);
    return isStoredRuleSubscription(parsedSubscription) ? parsedSubscription : null;
  } catch {
    return null;
  }
}

export function storeRuleSubscription(
  subscription: StoredRuleSubscription,
  storage: Pick<Storage, "setItem"> = window.localStorage
): boolean {
  if (!isStoredRuleSubscription(subscription)) {
    return false;
  }

  try {
    storage.setItem(RULE_SUBSCRIPTION_STORAGE_KEY, JSON.stringify(subscription));
    return true;
  } catch {
    return false;
  }
}

export function clearStoredRuleSubscription(
  storage: Pick<Storage, "removeItem"> = window.localStorage
) {
  try {
    storage.removeItem(RULE_SUBSCRIPTION_STORAGE_KEY);
  } catch {
    // Storage can be unavailable in restricted runtimes; the in-memory state still changes.
  }
}

function isStoredRuleSubscription(value: unknown): value is StoredRuleSubscription {
  if (!value || typeof value !== "object") {
    return false;
  }

  const subscription = value as Partial<StoredRuleSubscription>;

  return (
    typeof subscription.url === "string" &&
    subscription.url.trim().length > 0 &&
    typeof subscription.content === "string" &&
    subscription.content.length > 0 &&
    subscriptionByteLength(subscription.content) <= MAX_STORED_RULE_SUBSCRIPTION_BYTES &&
    typeof subscription.checkedAt === "string" &&
    subscription.checkedAt.length > 0
  );
}

function subscriptionByteLength(content: string): number {
  return new TextEncoder().encode(content).length;
}

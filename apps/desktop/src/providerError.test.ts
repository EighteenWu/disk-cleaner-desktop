import { describe, expect, it } from "vitest";

import { describeProviderError, isProviderError } from "./providerError";
import type { AiProviderError } from "./types";

const translate = (key: string, values: Record<string, string | number> = {}) =>
  Object.keys(values).length === 0
    ? key
    : `${key}(${Object.entries(values)
        .map(([name, value]) => `${name}=${value}`)
        .join(",")})`;

function providerError(overrides: Partial<AiProviderError> = {}): AiProviderError {
  return { category: "authentication", message: "HTTP 401", retryAfterSeconds: null, ...overrides };
}

describe("describeProviderError", () => {
  it("renders a structured provider rejection instead of [object Object]", () => {
    const text = describeProviderError(providerError(), translate);

    expect(text).toBe("rule.aiError.authentication: HTTP 401");
    expect(text).not.toContain("[object Object]");
  });

  it("appends the retry hint when the provider sent Retry-After", () => {
    const text = describeProviderError(
      providerError({ category: "rateLimited", message: "HTTP 429", retryAfterSeconds: 30 }),
      translate
    );

    expect(text).toBe("rule.aiError.rateLimited: HTTP 429rule.aiError.retryAfter(seconds=30)");
  });

  it("falls back for Error, string, and unknown rejections", () => {
    expect(describeProviderError(new Error("boom"), translate)).toBe("boom");
    expect(describeProviderError("plain failure", translate)).toBe("plain failure");
    expect(describeProviderError({ nope: true }, translate)).toBe("rule.aiError.provider");
  });

  it("only recognises payloads carrying a known category", () => {
    expect(isProviderError(providerError())).toBe(true);
    expect(isProviderError({ category: "unknown", message: "x" })).toBe(false);
    expect(isProviderError(null)).toBe(false);
  });
});
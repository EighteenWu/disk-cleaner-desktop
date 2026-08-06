import type { AiProviderError, AiProviderErrorCategory } from "./types";

/**
 * Provider generation, model listing, and connection tests reject with a structured
 * `ProviderError`, not a string. Tauri hands that struct to the frontend as a
 * plain object, so the usual `error instanceof Error ? ... : String(error)`
 * dance renders "[object Object]" and hides the real failure.
 */

const CATEGORY_KEY: Record<AiProviderErrorCategory, string> = {
  configuration: "rule.aiError.configuration",
  credentialMissing: "rule.aiError.credentialMissing",
  authentication: "rule.aiError.authentication",
  rateLimited: "rule.aiError.rateLimited",
  timeout: "rule.aiError.timeout",
  cancelled: "rule.aiError.cancelled",
  network: "rule.aiError.network",
  responseTooLarge: "rule.aiError.responseTooLarge",
  invalidSchema: "rule.aiError.invalidSchema",
  provider: "rule.aiError.provider"
};

export function isProviderError(value: unknown): value is AiProviderError {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<AiProviderError>;
  return (
    typeof candidate.message === "string" &&
    typeof candidate.category === "string" &&
    candidate.category in CATEGORY_KEY
  );
}

export type Translate = (key: string, values?: Record<string, string | number>) => string;

/** Turns anything a rejected provider call can throw into a readable line. */
export function describeProviderError(error: unknown, translate: Translate): string {
  if (isProviderError(error)) {
    const label = translate(CATEGORY_KEY[error.category]);
    const retry =
      error.retryAfterSeconds !== null && error.retryAfterSeconds !== undefined
        ? translate("rule.aiError.retryAfter", { seconds: error.retryAfterSeconds })
        : "";
    return `${label}: ${error.message}${retry}`;
  }
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  return translate("rule.aiError.provider");
}

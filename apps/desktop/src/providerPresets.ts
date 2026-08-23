import type { AiProviderKind, AiProviderModel } from "./types";

export const DEFAULT_PROVIDER_TIMEOUT_MS = 180_000;

export type ProviderVendorId =
  | "custom"
  | "deepseek"
  | "qwenBeijing"
  | "kimiCn"
  | "siliconflow"
  | "openai"
  | "anthropic";

export interface ProviderVendorPreset {
  id: ProviderVendorId;
  labelKey: string;
  kind: AiProviderKind;
  baseUrl: string;
  recommendedModel: string | null;
  timeoutMs: number;
}

export const PROVIDER_VENDOR_PRESETS: readonly ProviderVendorPreset[] = [
  {
    id: "custom",
    labelKey: "rule.aiVendor.custom",
    kind: "openAiCompatible",
    baseUrl: "",
    recommendedModel: null,
    timeoutMs: DEFAULT_PROVIDER_TIMEOUT_MS
  },
  {
    id: "deepseek",
    labelKey: "rule.aiVendor.deepseek",
    kind: "openAiCompatible",
    baseUrl: "https://api.deepseek.com",
    recommendedModel: "deepseek-v4-flash",
    timeoutMs: DEFAULT_PROVIDER_TIMEOUT_MS
  },
  {
    id: "qwenBeijing",
    labelKey: "rule.aiVendor.qwenBeijing",
    kind: "openAiCompatible",
    baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
    recommendedModel: "qwen-plus",
    timeoutMs: DEFAULT_PROVIDER_TIMEOUT_MS
  },
  {
    id: "kimiCn",
    labelKey: "rule.aiVendor.kimiCn",
    kind: "openAiCompatible",
    baseUrl: "https://api.moonshot.cn/v1",
    recommendedModel: "kimi-k3",
    timeoutMs: DEFAULT_PROVIDER_TIMEOUT_MS
  },
  {
    id: "siliconflow",
    labelKey: "rule.aiVendor.siliconflow",
    kind: "openAiCompatible",
    baseUrl: "https://api.siliconflow.cn/v1",
    recommendedModel: null,
    timeoutMs: DEFAULT_PROVIDER_TIMEOUT_MS
  },
  {
    id: "openai",
    labelKey: "rule.aiVendor.openai",
    kind: "openAiCompatible",
    baseUrl: "https://api.openai.com",
    recommendedModel: null,
    timeoutMs: DEFAULT_PROVIDER_TIMEOUT_MS
  },
  {
    id: "anthropic",
    labelKey: "rule.aiVendor.anthropic",
    kind: "anthropicCompatible",
    baseUrl: "https://api.anthropic.com",
    recommendedModel: null,
    timeoutMs: DEFAULT_PROVIDER_TIMEOUT_MS
  }
];

const NON_CHAT_MODEL = /embedding|tts|whisper|rerank|reranker|image|vl-|vision|moderation/i;

export function vendorPreset(id: ProviderVendorId): ProviderVendorPreset {
  return PROVIDER_VENDOR_PRESETS.find((item) => item.id === id) ?? PROVIDER_VENDOR_PRESETS[0];
}

export function inferVendorId(kind: AiProviderKind, baseUrl: string): ProviderVendorId {
  const normalized = baseUrl.trim().replace(/\/+$/, "");
  const match = PROVIDER_VENDOR_PRESETS.find(
    (preset) =>
      preset.id !== "custom" &&
      preset.kind === kind &&
      preset.baseUrl.replace(/\/+$/, "") === normalized
  );
  return match?.id ?? "custom";
}

export function pickChatModel(
  models: ReadonlyArray<Pick<AiProviderModel, "id" | "displayName">>,
  recommended: string | null | undefined
): string {
  if (models.length === 0) {
    return "";
  }
  const rec = recommended?.trim();
  if (rec && models.some((item) => item.id === rec)) {
    return rec;
  }
  const chat = models.filter((item) => {
    const haystack = `${item.id} ${item.displayName ?? ""}`;
    return !NON_CHAT_MODEL.test(haystack);
  });
  return (chat[0] ?? models[0]).id;
}

export function shouldAutoDetectProvider(apiKey: string): boolean {
  return apiKey.trim().length > 0;
}

/** Named vendor templates must not clobber an unrelated saved profile on auto-save. */
export function shouldCreateProfileForVendor(
  vendorId: ProviderVendorId,
  selected: { kind: AiProviderKind; baseUrl: string } | null | undefined
): boolean {
  if (!selected || vendorId === "custom") {
    return false;
  }
  return inferVendorId(selected.kind, selected.baseUrl) !== vendorId;
}

export function providerDetectSavePlan(probeOk: boolean, typedKey: string): {
  saveProfile: boolean;
  saveCredential: boolean;
} {
  if (!probeOk) {
    return { saveProfile: false, saveCredential: false };
  }
  return {
    saveProfile: true,
    saveCredential: typedKey.trim().length > 0
  };
}

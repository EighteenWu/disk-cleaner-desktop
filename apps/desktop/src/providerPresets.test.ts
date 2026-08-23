import { describe, expect, it } from "vitest";

import {
  inferVendorId,
  pickChatModel,
  providerDetectSavePlan,
  shouldAutoDetectProvider,
  shouldCreateProfileForVendor,
  vendorPreset
} from "./providerPresets";

const models = [
  { id: "embedding-2", displayName: "Embedding" },
  { id: "tts-1", displayName: null },
  { id: "deepseek-v4-flash", displayName: "DeepSeek V4 Flash" },
  { id: "whisper-1", displayName: "Whisper" }
];

describe("pickChatModel", () => {
  it("uses the recommended id when it is in the list", () => {
    expect(pickChatModel(models, "deepseek-v4-flash")).toBe("deepseek-v4-flash");
  });

  it("skips embedding, tts, whisper, rerank, image, vision, and moderation ids", () => {
    const catalog = [
      { id: "BAAI/bge-reranker-v2-m3", displayName: null },
      { id: "netease-youdao/bce-embedding-base_v1", displayName: null },
      { id: "fnlp/MOSS-TTSD-v0.5", displayName: null },
      { id: "openai/whisper-large-v3", displayName: null },
      { id: "Kwai-Kolors/Kolors", displayName: "image" },
      { id: "Qwen/Qwen3-VL-32B-Instruct", displayName: null },
      { id: "Pro/Qwen/Qwen2.5-VL-7B-Instruct", displayName: "vision" },
      { id: "omni-moderation-latest", displayName: null },
      { id: "Qwen/Qwen3-8B", displayName: "Qwen3 8B" }
    ];
    expect(pickChatModel(catalog, null)).toBe("Qwen/Qwen3-8B");
  });

  it("falls back to the first list item when every id is filtered", () => {
    const onlyNonChat = [
      { id: "text-embedding-3-small", displayName: null },
      { id: "tts-1", displayName: null }
    ];
    expect(pickChatModel(onlyNonChat, "missing-model")).toBe("text-embedding-3-small");
  });

  it("returns empty string for an empty catalog", () => {
    expect(pickChatModel([], "deepseek-v4-flash")).toBe("");
  });
});

describe("vendor presets", () => {
  it("matches DeepSeek by kind and base URL", () => {
    expect(inferVendorId("openAiCompatible", "https://api.deepseek.com")).toBe("deepseek");
    expect(inferVendorId("openAiCompatible", "https://api.deepseek.com/")).toBe("deepseek");
    expect(inferVendorId("openAiCompatible", "https://api.openai.com")).toBe("openai");
    expect(inferVendorId("anthropicCompatible", "https://api.anthropic.com")).toBe("anthropic");
    expect(inferVendorId("openAiCompatible", "https://relay.example/v1")).toBe("custom");
  });

  it("keeps custom base URL empty so the form does not default to OpenAI", () => {
    expect(vendorPreset("custom").baseUrl).toBe("");
    expect(vendorPreset("deepseek").recommendedModel).toBe("deepseek-v4-flash");
    expect(vendorPreset("siliconflow").recommendedModel).toBeNull();
  });
});

describe("vendor change vs saved profile", () => {
  const customProfile = {
    kind: "openAiCompatible" as const,
    baseUrl: "https://relay.example/v1"
  };

  it("starts a new profile when a named vendor does not match the selected one", () => {
    expect(shouldCreateProfileForVendor("deepseek", customProfile)).toBe(true);
    expect(
      shouldCreateProfileForVendor("qwenBeijing", {
        kind: "openAiCompatible",
        baseUrl: "https://api.deepseek.com"
      })
    ).toBe(true);
  });

  it("keeps the selected profile for custom or the same vendor", () => {
    expect(shouldCreateProfileForVendor("custom", customProfile)).toBe(false);
    expect(shouldCreateProfileForVendor("deepseek", null)).toBe(false);
    expect(
      shouldCreateProfileForVendor("deepseek", {
        kind: "openAiCompatible",
        baseUrl: "https://api.deepseek.com/"
      })
    ).toBe(false);
  });
});

describe("detect save plan", () => {
  it("auto-detects only when a key was typed", () => {
    expect(shouldAutoDetectProvider("")).toBe(false);
    expect(shouldAutoDetectProvider("   ")).toBe(false);
    expect(shouldAutoDetectProvider(" sk-test ")).toBe(true);
  });

  it("saves profile and credential only after a successful probe", () => {
    expect(providerDetectSavePlan(false, "sk-new")).toEqual({
      saveProfile: false,
      saveCredential: false
    });
    expect(providerDetectSavePlan(true, "")).toEqual({
      saveProfile: true,
      saveCredential: false
    });
    expect(providerDetectSavePlan(true, "sk-new")).toEqual({
      saveProfile: true,
      saveCredential: true
    });
  });
});

import { useCallback, useEffect, useRef, useState } from "react";
import {
  approveAiRuleDraft,
  buildAiScanSummary,
  cancelAiRuleGeneration,
  generateAiRules,
  listenAiGenerationProgress,
  listAiProviderModels,
  listAiProviderProfiles,
  probeAiProviderGeneration,
  reviseAiRuleDraft,
  saveAiProviderCredential,
  saveAiProviderProfile,
  testAiProviderConnection,
  validateAiRuleDraft
} from "./api";
import { aiGenerationRequest } from "./aiGeneration";
import { aiDraftApprovalReady, aiDraftValidationReady } from "./aiDraftWorkflow";
import { describeProviderError, describeProviderErrorOrTimeout } from "./providerError";
import {
  DEFAULT_PROVIDER_TIMEOUT_MS,
  inferVendorId,
  pickChatModel,
  providerDetectSavePlan,
  shouldAutoDetectProvider,
  shouldCreateProfileForVendor,
  vendorPreset,
  type ProviderVendorId
} from "./providerPresets";
import type { RuleSourcesState } from "./useRuleSources";
import type {
  AiGeneratedRuleSet,
  AiGenerationMode,
  AiProviderKind,
  AiProviderModel,
  AiProviderProfile,
  AiRuleDraft,
  AiRuleTier,
  AiSessionEvent,
  RedactedScanSummary,
  ScanSnapshot
} from "./types";

export { DEFAULT_PROVIDER_TIMEOUT_MS, shouldAutoDetectProvider, providerDetectSavePlan };
export type { ProviderVendorId };

const PROVIDER_DETECT_DEBOUNCE_MS = 800;
export const MIN_PROVIDER_TIMEOUT_SECONDS = 15;
export const MAX_PROVIDER_TIMEOUT_SECONDS = 600;
const LEGACY_DEFAULT_TIMEOUT_MS = 45_000;

function displayTimeoutMs(value: number): number {
  return value === LEGACY_DEFAULT_TIMEOUT_MS ? DEFAULT_PROVIDER_TIMEOUT_MS : value;
}
export const MAX_AI_SESSION_EVENTS = 10;

type Translate = (key: string, values?: Record<string, string | number>) => string;

export interface AiRuleGenerationState {
  profiles: AiProviderProfile[];
  selectedProfileId: string;
  setSelectedProfileId: (value: string) => void;
  vendorId: ProviderVendorId;
  setVendorId: (value: ProviderVendorId) => void;
  providerKind: AiProviderKind;
  setProviderKind: (value: AiProviderKind) => void;
  providerName: string;
  setProviderName: (value: string) => void;
  baseUrl: string;
  setBaseUrl: (value: string) => void;
  timeoutMs: number;
  setTimeoutMs: (value: number) => void;
  model: string;
  setModel: (value: string) => void;
  apiKey: string;
  setApiKey: (value: string) => void;
  models: AiProviderModel[];
  loadingModels: boolean;
  testingConnection: boolean;
  probingGeneration: boolean;
  summary: RedactedScanSummary | null;
  generationMode: AiGenerationMode;
  setGenerationMode: (value: AiGenerationMode) => void;
  targetTier: AiRuleTier;
  setTargetTier: (value: AiRuleTier) => void;
  draft: AiRuleDraft | null;
  draftEditor: string;
  draftEditorDirty: boolean;
  setDraftEditor: (value: string) => void;
  generating: boolean;
  message: string;
  sessionEvents: AiSessionEvent[];
  clearSessionEvents: () => void;
  loadModels: () => Promise<void>;
  testConnection: () => Promise<void>;
  probeGeneration: () => Promise<void>;
  onApiKeyBlur: () => void;
  saveProvider: () => Promise<void>;
  preparePreview: (snapshot: ScanSnapshot | null, ready: boolean) => Promise<void>;
  generate: () => Promise<void>;
  cancel: () => Promise<void>;
  applyDraftEdit: () => Promise<void>;
  validateDraft: () => Promise<void>;
  approveAndImportDraft: () => Promise<void>;
}

export function pushSessionEvent(
  events: AiSessionEvent[],
  event: Omit<AiSessionEvent, "at"> & { at?: string }
): AiSessionEvent[] {
  const next: AiSessionEvent = {
    at: event.at ?? new Date().toISOString(),
    kind: event.kind,
    summaryHash: event.summaryHash,
    mode: event.mode,
    model: event.model,
    latencyMs: event.latencyMs,
    ruleCount: event.ruleCount,
    message: event.message
  };
  return [next, ...events].slice(0, MAX_AI_SESSION_EVENTS);
}

export function useAiRuleGeneration(
  rules: RuleSourcesState,
  translate: Translate,
  onLog?: (title: string, message: string, detail?: string) => void
): AiRuleGenerationState {
  const [profiles, setProfiles] = useState<AiProviderProfile[]>([]);
  const [selectedProfileIdValue, setSelectedProfileIdValue] = useState("");
  const [vendorId, setVendorIdValue] = useState<ProviderVendorId>("custom");
  const [providerKind, setProviderKindValue] = useState<AiProviderKind>("openAiCompatible");
  const [providerName, setProviderName] = useState("");
  const [baseUrl, setBaseUrlValue] = useState("");
  const [timeoutMs, setTimeoutMsValue] = useState(DEFAULT_PROVIDER_TIMEOUT_MS);
  const [model, setModel] = useState("");
  const [apiKey, setApiKeyValue] = useState("");
  const [models, setModels] = useState<AiProviderModel[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [probingGeneration, setProbingGeneration] = useState(false);
  const detectGeneration = useRef(0);
  const lastAutoDetectKey = useRef("");
  const [summary, setSummary] = useState<RedactedScanSummary | null>(null);
  const [generationMode, setGenerationModeValue] = useState<AiGenerationMode>("allTiers");
  const [targetTierValue, setTargetTierValue] = useState<AiRuleTier>("light");
  const [draft, setDraft] = useState<AiRuleDraft | null>(null);
  const [draftEditor, setDraftEditorValue] = useState("");
  const [draftEditorDirty, setDraftEditorDirty] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState("");
  const [sessionEvents, setSessionEvents] = useState<AiSessionEvent[]>([]);
  const clearSessionEvents = useCallback(() => setSessionEvents([]), []);

  useEffect(() => {
    let disposed = false;
    void listAiProviderProfiles()
      .then((items) => {
        if (disposed) return;
        setProfiles(items);
        if (items.length > 0) {
          const profile = items[0];
          setSelectedProfileIdValue((current) => current || profile.id);
          applyProfileFields(profile);
        }
      })
      .catch((error) => {
        if (!disposed) setMessage(describeProviderError(error, translate));
      });
    return () => {
      disposed = true;
    };
  }, [translate]);

  function bumpDetect() {
    detectGeneration.current += 1;
    lastAutoDetectKey.current = "";
  }

  function setApiKey(value: string) {
    bumpDetect();
    setApiKeyValue(value);
  }

  function setBaseUrl(value: string) {
    bumpDetect();
    setBaseUrlValue(value);
  }

  function setProviderKind(value: AiProviderKind) {
    bumpDetect();
    setProviderKindValue(value);
  }

  function setTimeoutMs(value: number) {
    bumpDetect();
    setTimeoutMsValue(value);
  }

  // Auto-detect on typed key + endpoint only. Model is chosen inside detectReady.
  useEffect(() => {
    if (!shouldAutoDetectProvider(apiKey) || !baseUrl.trim()) return;
    const timer = window.setTimeout(() => {
      void detectReady("auto");
    }, PROVIDER_DETECT_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [apiKey, baseUrl, providerKind, vendorId, selectedProfileIdValue, timeoutMs]);

  function recordSession(event: Omit<AiSessionEvent, "at"> & { at?: string }) {
    setSessionEvents((current) => pushSessionEvent(current, event));
  }

  function logOperation(title: string, message: string, detail?: string) {
    onLog?.(title, message, detail);
  }

  function clearPreparedDraft() {
    setSummary(null);
    setDraft(null);
    setDraftEditorValue("");
    setDraftEditorDirty(false);
  }

  function applyProfileFields(profile: AiProviderProfile) {
    setProviderKindValue(profile.kind);
    setProviderName(profile.displayName);
    setBaseUrlValue(profile.baseUrl);
    setTimeoutMsValue(displayTimeoutMs(profile.timeoutMs));
    setModel(profile.model);
    setVendorIdValue(inferVendorId(profile.kind, profile.baseUrl));
  }

  function setSelectedProfileId(value: string) {
    bumpDetect();
    setSelectedProfileIdValue(value);
    clearPreparedDraft();
    const profile = profiles.find((item) => item.id === value);
    if (profile) applyProfileFields(profile);
  }

  function setVendorId(value: ProviderVendorId) {
    bumpDetect();
    setVendorIdValue(value);
    const selected = profiles.find((item) => item.id === selectedProfileIdValue);
    if (shouldCreateProfileForVendor(value, selected)) {
      setSelectedProfileIdValue("");
    }
    const preset = vendorPreset(value);
    if (value === "custom") {
      return;
    }
    setProviderKindValue(preset.kind);
    setProviderName(translate(preset.labelKey));
    setBaseUrlValue(preset.baseUrl);
    setTimeoutMsValue(preset.timeoutMs);
    setModel(preset.recommendedModel ?? "");
    setModels([]);
    clearPreparedDraft();
  }

  function setGenerationMode(value: AiGenerationMode) {
    setGenerationModeValue(value);
    clearPreparedDraft();
  }

  function setTargetTier(value: AiRuleTier) {
    setTargetTierValue(value);
    clearPreparedDraft();
  }

  async function loadModels() {
    setLoadingModels(true);
    try {
      const items = await listAiProviderModels({
        kind: providerKind,
        baseUrl,
        timeoutMs,
        profileId: selectedProfileIdValue || null,
        apiKey: apiKey.trim() || null
      });
      setModels(items);
      setMessage(translate("rule.aiModelsLoaded", { count: items.length }));
      if (!model && items.length > 0) {
        setModel(pickChatModel(items, vendorPreset(vendorId).recommendedModel));
      }
    } catch (error) {
      setModels([]);
      setMessage(describeProviderError(error, translate));
    } finally {
      setLoadingModels(false);
    }
  }

  async function testConnection() {
    setTestingConnection(true);
    try {
      const result = await testAiProviderConnection({
        kind: providerKind,
        baseUrl,
        timeoutMs,
        profileId: selectedProfileIdValue || null,
        apiKey: apiKey.trim() || null
      });
      setMessage(
        translate("rule.aiConnectionSucceeded", { count: result.modelCount })
      );
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    } finally {
      setTestingConnection(false);
    }
  }

  async function persistProvider(nextModel: string, typedKey: string, saveCredential: boolean) {
    const id = selectedProfileIdValue || crypto.randomUUID();
    const preset = vendorPreset(vendorId);
    const displayName = providerName.trim() || translate(preset.labelKey);
    if (!providerName.trim()) setProviderName(displayName);
    await saveAiProviderProfile({
      id,
      kind: providerKind,
      displayName,
      baseUrl,
      model: nextModel,
      timeoutMs,
      credentialPresent: false
    });
    if (saveCredential && typedKey) {
      await saveAiProviderCredential(id, typedKey);
      setApiKeyValue("");
    }
    const next = await listAiProviderProfiles();
    setProfiles(next);
    setSelectedProfileIdValue(id);
    clearPreparedDraft();
    return id;
  }

  async function detectReady(reason: "auto" | "explicit") {
    const typedKey = apiKey.trim();
    if (reason === "auto" && !shouldAutoDetectProvider(typedKey)) {
      return;
    }
    if (!typedKey && !selectedProfileIdValue) {
      if (reason === "explicit") setMessage(translate("rule.aiDetectNeedsKey"));
      return;
    }
    if (!baseUrl.trim()) {
      if (reason === "explicit") setMessage(translate("rule.aiDetectNeedsUrl"));
      return;
    }
    if (reason === "auto") {
      const autoFingerprint = `${typedKey}|${providerKind}|${baseUrl}|${selectedProfileIdValue}|${timeoutMs}`;
      if (lastAutoDetectKey.current === autoFingerprint) {
        return;
      }
      lastAutoDetectKey.current = autoFingerprint;
    }

    const generation = ++detectGeneration.current;
    setLoadingModels(true);
    setProbingGeneration(true);
    setMessage(translate("rule.aiDetecting"));
    const started = performance.now();
    const preset = vendorPreset(vendorId);
    try {
      let items: AiProviderModel[] = [];
      try {
        items = await listAiProviderModels({
          kind: providerKind,
          baseUrl,
          timeoutMs,
          profileId: selectedProfileIdValue || null,
          apiKey: typedKey || null
        });
      } catch (error) {
        if (generation !== detectGeneration.current) return;
        setModels([]);
        const text = translate("rule.aiModelsFailed", {
          detail: describeProviderError(error, translate)
        });
        setMessage(text);
        recordSession({
          kind: "error",
          model: model.trim() || undefined,
          message: text
        });
        logOperation(translate("rule.aiProbeFailedLog"), text, undefined);
        return;
      }
      if (generation !== detectGeneration.current) return;
      setModels(items);

      const recommended = preset.recommendedModel;
      const chosen =
        reason === "explicit" && model.trim()
          ? model.trim()
          : pickChatModel(items, recommended);
      if (chosen) setModel(chosen);
      if (!chosen) {
        setMessage(translate("rule.aiProbeNeedsModel"));
        return;
      }

      const result = await probeAiProviderGeneration({
        kind: providerKind,
        baseUrl,
        timeoutMs,
        model: chosen,
        profileId: selectedProfileIdValue || null,
        apiKey: typedKey || null
      });
      if (generation !== detectGeneration.current) return;
      if (!result.ok) {
        throw {
          category: "invalidSchema",
          message: translate("rule.aiError.invalidSchema"),
          retryAfterSeconds: null
        };
      }
      const plan = providerDetectSavePlan(result.ok, typedKey);
      if (plan.saveProfile) {
        await persistProvider(chosen, typedKey, plan.saveCredential);
      }
      const text = translate("rule.aiReady", { id: chosen, ms: result.latencyMs });
      setMessage(text);
      recordSession({
        kind: "probe",
        model: chosen,
        latencyMs: result.latencyMs,
        message: text
      });
      logOperation(translate("rule.aiProbeLog"), text, chosen);
    } catch (error) {
      if (generation !== detectGeneration.current) return;
      const elapsed = Math.round(performance.now() - started);
      const text = describeProviderErrorOrTimeout(
        error,
        translate,
        translate("rule.aiProbeTimeout", {
          seconds: Math.round(timeoutMs / 1000),
          ms: elapsed
        })
      );
      setMessage(text);
      recordSession({
        kind: "error",
        model: model.trim() || undefined,
        latencyMs: elapsed,
        message: text
      });
      logOperation(translate("rule.aiProbeFailedLog"), text, model.trim() || undefined);
    } finally {
      if (generation === detectGeneration.current) {
        setLoadingModels(false);
        setProbingGeneration(false);
      }
    }
  }

  async function probeGeneration() {
    await detectReady("explicit");
  }

  function onApiKeyBlur() {
    if (shouldAutoDetectProvider(apiKey)) {
      void detectReady("auto");
    }
  }

  async function saveProvider() {
    try {
      await persistProvider(model, apiKey.trim(), Boolean(apiKey.trim()));
      setMessage(translate("rule.aiProviderSaved"));
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    }
  }

  async function preparePreview(snapshot: ScanSnapshot | null, ready: boolean) {
    if (!snapshot || !selectedProfileIdValue) {
      setMessage(translate("rule.aiNeedsScanAndProvider"));
      return;
    }
    if (!ready) {
      setMessage(translate("rule.aiNeedsFullScan"));
      return;
    }
    setDraft(null);
    try {
      const nextSummary = await buildAiScanSummary(snapshot);
      setSummary(nextSummary);
      const text = translate("rule.aiPreviewReady");
      setMessage(text);
      recordSession({
        kind: "preview",
        summaryHash: nextSummary.summaryHash,
        mode: generationMode,
        model: model.trim() || undefined,
        message: text
      });
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    }
  }

  async function generate() {
    if (!summary || !selectedProfileIdValue) {
      setMessage(translate("rule.aiPrepareFirst"));
      return;
    }
    setGenerating(true);
    setDraft(null);
    const started = performance.now();
    let unlistenProgress: (() => void) | undefined;
    try {
      unlistenProgress = await listenAiGenerationProgress((progress) => {
        setMessage(
          translate("rule.aiGeneratingProgress", {
            chars: progress.outputChars,
            seconds: Math.max(1, Math.round(progress.elapsedMs / 1000))
          })
        );
      });
      const request = aiGenerationRequest(
        summary,
        generationMode,
        generationMode === "singleTier" ? targetTierValue : null
      );
      const response = await generateAiRules(selectedProfileIdValue, request);
      const elapsed = Math.round(performance.now() - started);
      setDraft(response.draft);
      setDraftEditorValue(JSON.stringify(response.draft.rules, null, 2));
      setDraftEditorDirty(false);
      const text = translate("rule.aiGenerated", { count: response.draft.rules.rules.length });
      setMessage(text);
      recordSession({
        kind: "generate",
        summaryHash: summary.summaryHash,
        mode: generationMode,
        model: response.draft.model,
        latencyMs: elapsed,
        ruleCount: response.draft.rules.rules.length,
        message: text
      });
      logOperation(
        translate("rule.aiGeneratedLog"),
        text,
        [response.draft.model, `${elapsed} ms`].filter(Boolean).join(" · ")
      );
    } catch (error) {
      const elapsed = Math.round(performance.now() - started);
      const text = describeProviderErrorOrTimeout(
        error,
        translate,
        translate("rule.aiGenerationTimeout", {
          seconds: Math.round(timeoutMs / 1000),
          elapsedSeconds: Math.max(1, Math.round(elapsed / 1000))
        })
      );
      setMessage(text);
      recordSession({
        kind: "error",
        summaryHash: summary.summaryHash,
        mode: generationMode,
        model: model.trim() || undefined,
        latencyMs: elapsed,
        message: text
      });
      logOperation(
        translate("rule.aiGenerateFailedLog"),
        text,
        [model.trim(), `${elapsed} ms`].filter(Boolean).join(" · ") || undefined
      );
    } finally {
      unlistenProgress?.();
      setGenerating(false);
    }
  }

  async function cancel() {
    try {
      await cancelAiRuleGeneration();
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    }
  }

  function setDraftEditor(value: string) {
    setDraftEditorValue(value);
    setDraftEditorDirty(true);
  }

  async function applyDraftEdit() {
    if (!draft) return;
    try {
      const nextRules = JSON.parse(draftEditor) as AiGeneratedRuleSet;
      const next = await reviseAiRuleDraft(draft, draft.revision, nextRules);
      setDraft(next);
      setDraftEditorValue(JSON.stringify(next.rules, null, 2));
      setDraftEditorDirty(false);
      setMessage(translate("rule.aiDraftRevised", { revision: next.revision }));
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    }
  }

  async function validateDraft() {
    if (!aiDraftValidationReady(draft, draftEditorDirty) || !draft) return;
    try {
      const next = await validateAiRuleDraft(draft, draft.revision, draft.summaryHash);
      setDraft(next);
      setMessage(translate("rule.aiDraftValidated", { revision: next.revision }));
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    }
  }

  async function approveAndImportDraft() {
    if (!aiDraftApprovalReady(draft, draftEditorDirty) || !draft) return;
    try {
      const envelope = await approveAiRuleDraft(draft, draft.revision, draft.summaryHash);
      await rules.importApprovedAiDraft(translate("rule.aiDraftName"), envelope);
      setMessage(translate("rule.aiDraftSavedEditable"));
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    }
  }

  return {
    profiles,
    selectedProfileId: selectedProfileIdValue,
    setSelectedProfileId,
    vendorId,
    setVendorId,
    providerKind,
    setProviderKind,
    providerName,
    setProviderName,
    baseUrl,
    setBaseUrl,
    timeoutMs,
    setTimeoutMs,
    model,
    setModel,
    apiKey,
    setApiKey,
    models,
    loadingModels,
    testingConnection,
    probingGeneration,
    summary,
    generationMode,
    setGenerationMode,
    targetTier: targetTierValue,
    setTargetTier,
    draft,
    draftEditor,
    draftEditorDirty,
    setDraftEditor,
    generating,
    message,
    sessionEvents,
    clearSessionEvents,
    loadModels,
    testConnection,
    probeGeneration,
    onApiKeyBlur,
    saveProvider,
    preparePreview,
    generate,
    cancel,
    applyDraftEdit,
    validateDraft,
    approveAndImportDraft
  };
}

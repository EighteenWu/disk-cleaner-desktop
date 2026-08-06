import { useCallback, useEffect, useState } from "react";
import {
  approveAiRuleDraft,
  buildAiScanSummary,
  cancelAiRuleGeneration,
  generateAiRules,
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

const DEFAULT_PROVIDER_TIMEOUT_MS = 45_000;
export const MAX_AI_SESSION_EVENTS = 10;

type Translate = (key: string, values?: Record<string, string | number>) => string;

export interface AiRuleGenerationState {
  profiles: AiProviderProfile[];
  selectedProfileId: string;
  setSelectedProfileId: (value: string) => void;
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
  translate: Translate
): AiRuleGenerationState {
  const [profiles, setProfiles] = useState<AiProviderProfile[]>([]);
  const [selectedProfileIdValue, setSelectedProfileIdValue] = useState("");
  const [providerKind, setProviderKind] = useState<AiProviderKind>("openAiCompatible");
  const [providerName, setProviderName] = useState("OpenAI compatible");
  const [baseUrl, setBaseUrl] = useState("https://api.openai.com");
  const [timeoutMs, setTimeoutMs] = useState(DEFAULT_PROVIDER_TIMEOUT_MS);
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [models, setModels] = useState<AiProviderModel[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [probingGeneration, setProbingGeneration] = useState(false);
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
        if (items.length > 0) setSelectedProfileIdValue((current) => current || items[0].id);
      })
      .catch((error) => {
        if (!disposed) setMessage(describeProviderError(error, translate));
      });
    return () => {
      disposed = true;
    };
  }, [translate]);

  function recordSession(event: Omit<AiSessionEvent, "at"> & { at?: string }) {
    setSessionEvents((current) => pushSessionEvent(current, event));
  }

  function clearPreparedDraft() {
    setSummary(null);
    setDraft(null);
    setDraftEditorValue("");
    setDraftEditorDirty(false);
  }

  function setSelectedProfileId(value: string) {
    setSelectedProfileIdValue(value);
    clearPreparedDraft();
    const profile = profiles.find((item) => item.id === value);
    if (profile) {
      setProviderKind(profile.kind);
      setProviderName(profile.displayName);
      setBaseUrl(profile.baseUrl);
      setTimeoutMs(profile.timeoutMs);
      setModel(profile.model);
    }
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
      if (!model && items.length > 0) setModel(items[0].id);
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

  async function probeGeneration() {
    if (!model.trim()) {
      setMessage(translate("rule.aiProbeNeedsModel"));
      return;
    }
    setProbingGeneration(true);
    const started = performance.now();
    try {
      const result = await probeAiProviderGeneration({
        kind: providerKind,
        baseUrl,
        timeoutMs,
        model: model.trim(),
        profileId: selectedProfileIdValue || null,
        apiKey: apiKey.trim() || null
      });
      const latencyMs = result.latencyMs;
      const text = translate("rule.aiProbeSucceeded", { ms: latencyMs });
      setMessage(text);
      recordSession({
        kind: "probe",
        model: model.trim(),
        latencyMs,
        message: text
      });
    } catch (error) {
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
        model: model.trim(),
        latencyMs: elapsed,
        message: text
      });
    } finally {
      setProbingGeneration(false);
    }
  }

  async function saveProvider() {
    const id = selectedProfileIdValue || crypto.randomUUID();
    try {
      await saveAiProviderProfile({
        id,
        kind: providerKind,
        displayName: providerName,
        baseUrl,
        model,
        timeoutMs,
        credentialPresent: false
      });
      if (apiKey.trim()) {
        await saveAiProviderCredential(id, apiKey.trim());
        setApiKey("");
      }
      const next = await listAiProviderProfiles();
      setProfiles(next);
      setSelectedProfileIdValue(id);
      clearPreparedDraft();
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
    try {
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
    } finally {
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
    saveProvider,
    preparePreview,
    generate,
    cancel,
    applyDraftEdit,
    validateDraft,
    approveAndImportDraft
  };
}

import { useCallback, useEffect, useRef, useState } from "react";
import {
  approveAiRuleDraft,
  buildAiScanSummary,
  cancelAiRuleGeneration,
  generateAiRulePlan,
  generateAiRules,
  listenAiGenerationProgress,
  listAiProviderModels,
  listAiProviderProfiles,
  probeAiProviderGeneration,
  saveAiProviderCredential,
  saveAiProviderProfile,
  testAiProviderConnection,
  validateAiRuleDraft
} from "./api";
import {
  aiGeneratedRulesFromCompiled,
  aiGenerationRequest,
  appendPlanDelta,
  canApproveAiPlan,
  liveAiRuleYaml,
  planMessagesForRequest,
  previousRulesFromLiveAiLibrary,
  resolvePlanUserContent,
  shouldWarnReplaceAiRecord
} from "./aiGeneration";
import { describeProviderError, describeProviderErrorOrTimeout, isProviderError } from "./providerError";
import {
  DEFAULT_PROVIDER_TIMEOUT_MS,
  inferVendorId,
  pickChatModel,
  providerDetectSavePlan,
  shouldAutoDetectProvider,
  shouldCreateProfileForVendor,
  shouldQueueProviderDetect,
  vendorPreset,
  type ProviderVendorId
} from "./providerPresets";
import type { RuleSourcesState } from "./useRuleSources";
import type {
  AiChatMessage,
  AiGeneratedRuleSet,
  AiGenerationMode,
  AiProviderKind,
  AiProviderModel,
  AiProviderProfile,
  AiSessionEvent,
  RedactedScanSummary,
  ScanSnapshot
} from "./types";

export {
  DEFAULT_PROVIDER_TIMEOUT_MS,
  shouldAutoDetectProvider,
  shouldQueueProviderDetect,
  providerDetectSavePlan
};
export type { ProviderVendorId };

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
  messages: AiChatMessage[];
  composer: string;
  setComposer: (value: string) => void;
  planning: boolean;
  generating: boolean;
  canApprove: boolean;
  replaceWarning: boolean;
  message: string;
  sessionEvents: AiSessionEvent[];
  clearSessionEvents: () => void;
  resetConversation: () => void;
  loadModels: () => Promise<void>;
  testConnection: () => Promise<void>;
  probeGeneration: () => Promise<void>;
  onApiKeyBlur: () => void;
  onApiKeyPaste: () => void;
  saveProvider: () => Promise<void>;
  sendPlan: (snapshot: ScanSnapshot | null, ready: boolean) => Promise<void>;
  approvePlan: () => Promise<void>;
  cancel: () => Promise<void>;
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
  const pasteDetectPending = useRef(false);
  const conversationEpoch = useRef(0);
  const inFlight = useRef(false);
  const [summary, setSummary] = useState<RedactedScanSummary | null>(null);
  const [messages, setMessages] = useState<AiChatMessage[]>([]);
  const [composer, setComposer] = useState("");
  const [planning, setPlanning] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [previousRules, setPreviousRules] = useState<AiGeneratedRuleSet | null>(null);
  const [message, setMessage] = useState("");
  const [sessionEvents, setSessionEvents] = useState<AiSessionEvent[]>([]);
  const clearSessionEvents = useCallback(() => setSessionEvents([]), []);
  const generationMode: AiGenerationMode = "allTiers";

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

  const setApiKey = useCallback((value: string) => {
    detectGeneration.current += 1;
    lastAutoDetectKey.current = "";
    setApiKeyValue(value);
  }, []);

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

  function recordSession(event: Omit<AiSessionEvent, "at"> & { at?: string }) {
    setSessionEvents((current) => pushSessionEvent(current, event));
  }

  function logOperation(title: string, message: string, detail?: string) {
    onLog?.(title, message, detail);
  }

  function clearPreparedDraft() {
    setSummary(null);
  }

  function resetConversation() {
    conversationEpoch.current += 1;
    setMessages([]);
    setComposer("");
    setPlanning(false);
    setGenerating(false);
    setSummary(null);
    setMessage("");
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
    if (shouldQueueProviderDetect("blur", apiKey)) {
      void detectReady("auto");
    }
  }

  function onApiKeyPaste() {
    pasteDetectPending.current = true;
  }

  // Run after React commits the pasted value. setState inside the paste event
  // would re-render the controlled input with the old "" and swallow the insert.
  useEffect(() => {
    if (!pasteDetectPending.current) return;
    pasteDetectPending.current = false;
    if (!shouldQueueProviderDetect("paste", apiKey)) return;
    void detectReady("auto");
  }, [apiKey]);

  async function saveProvider() {
    try {
      await persistProvider(model, apiKey.trim(), Boolean(apiKey.trim()));
      setMessage(translate("rule.aiProviderSaved"));
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    }
  }

  async function sendPlan(snapshot: ScanSnapshot | null, ready: boolean) {
    if (inFlight.current || planning || generating) return;
    if (!snapshot || !selectedProfileIdValue) {
      setMessage(translate("rule.aiNeedsScanAndProvider"));
      return;
    }
    if (!ready) {
      setMessage(translate("rule.aiNeedsFullScan"));
      return;
    }
    const content = resolvePlanUserContent(composer, translate);
    const userMessage: AiChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content,
      status: "complete"
    };
    const assistantMessage: AiChatMessage = {
      id: crypto.randomUUID(),
      role: "assistant",
      content: "",
      status: "streaming"
    };
    const nextMessages = [...messages, userMessage, assistantMessage];
    const epoch = conversationEpoch.current;
    inFlight.current = true;
    setComposer("");
    setMessages(nextMessages);
    setPlanning(true);
    const started = performance.now();
    let unlistenProgress: (() => void) | undefined;
    try {
      const nextSummary = await buildAiScanSummary(snapshot);
      if (epoch !== conversationEpoch.current) return;
      setSummary(nextSummary);
      unlistenProgress = await listenAiGenerationProgress((progress) => {
        if (epoch !== conversationEpoch.current) return;
        if (progress.phase === "plan" && progress.delta) {
          setMessages((current) =>
            current.map((item) =>
              item.id === assistantMessage.id && item.status === "streaming"
                ? { ...item, content: appendPlanDelta(item.content, progress.delta) }
                : item
            )
          );
        }
        setMessage(
          translate("rule.aiGeneratingProgress", {
            chars: progress.outputChars,
            seconds: Math.max(1, Math.round(progress.elapsedMs / 1000))
          })
        );
      });
      const response = await generateAiRulePlan(selectedProfileIdValue, {
        summary: nextSummary,
        messages: planMessagesForRequest([...messages, userMessage]),
        scanSessionId: snapshot.scanSessionId
      });
      if (epoch !== conversationEpoch.current) return;
      setMessages((current) =>
        current.map((item) =>
          item.id === assistantMessage.id
            ? { ...item, content: response.reply, status: "complete" }
            : item
        )
      );
      const elapsed = Math.round(performance.now() - started);
      const text = translate("rule.aiChatPlanReady");
      setMessage(text);
      recordSession({
        kind: "generate",
        summaryHash: nextSummary.summaryHash,
        mode: generationMode,
        model: response.model,
        latencyMs: elapsed,
        message: text
      });
    } catch (error) {
      if (epoch !== conversationEpoch.current) return;
      const elapsed = Math.round(performance.now() - started);
      const cancelled = isProviderError(error) && error.category === "cancelled";
      const text = cancelled
        ? translate("rule.aiChatCancelled")
        : describeProviderErrorOrTimeout(
            error,
            translate,
            translate("rule.aiGenerationTimeout", {
              seconds: Math.round(timeoutMs / 1000),
              elapsedSeconds: Math.max(1, Math.round(elapsed / 1000))
            })
          );
      setMessages((current) =>
        current.map((item) =>
          item.id === assistantMessage.id
            ? {
                ...item,
                status: cancelled ? "cancelled" : "error",
                content: item.content || text
              }
            : item
        )
      );
      setMessage(text);
      recordSession({
        kind: "error",
        summaryHash: summary?.summaryHash,
        mode: generationMode,
        model: model.trim() || undefined,
        latencyMs: elapsed,
        message: text
      });
      logOperation(translate("rule.aiGenerateFailedLog"), text, model.trim() || undefined);
    } finally {
      unlistenProgress?.();
      inFlight.current = false;
      if (epoch === conversationEpoch.current) setPlanning(false);
    }
  }

  async function approvePlan() {
    if (
      inFlight.current ||
      !canApproveAiPlan(messages, planning || generating) ||
      !summary ||
      !selectedProfileIdValue
    ) {
      return;
    }
    const planText = [...messages].reverse().find((item) => item.role === "assistant" && item.status === "complete")
      ?.content;
    if (!planText?.trim()) return;
    const epoch = conversationEpoch.current;
    inFlight.current = true;
    setGenerating(true);
    setMessage(translate("rule.aiChatApproving"));
    const started = performance.now();
    let unlistenProgress: (() => void) | undefined;
    try {
      unlistenProgress = await listenAiGenerationProgress((progress) => {
        if (epoch !== conversationEpoch.current) return;
        setMessage(
          translate("rule.aiGeneratingProgress", {
            chars: progress.outputChars,
            seconds: Math.max(1, Math.round(progress.elapsedMs / 1000))
          })
        );
      });
      const libraryRecords = rules.library?.snapshot?.records;
      let prior = previousRules ?? previousRulesFromLiveAiLibrary(libraryRecords, rules.activeLibrarySnapshot);
      if (!prior) {
        const yaml = liveAiRuleYaml(libraryRecords);
        if (yaml) {
          try {
            const compilation = await rules.validateLibraryDraft(yaml);
            prior = aiGeneratedRulesFromCompiled(compilation.rules);
          } catch {
            prior = null;
          }
        }
      }
      if (epoch !== conversationEpoch.current) return;
      const revision = prior
        ? {
            previousRules: prior,
            droppedIds: [],
            tierChanges: [],
            rewriteIds: []
          }
        : null;
      const response = await generateAiRules(
        selectedProfileIdValue,
        aiGenerationRequest(summary, "allTiers", null, revision, planText)
      );
      const validated = await validateAiRuleDraft(
        response.draft,
        response.draft.revision,
        response.draft.summaryHash
      );
      const envelope = await approveAiRuleDraft(
        validated,
        validated.revision,
        validated.summaryHash
      );
      if (epoch !== conversationEpoch.current) return;
      await rules.importAndApproveAiRule(translate("rule.aiDraftName"), envelope);
      if (epoch !== conversationEpoch.current) return;
      setPreviousRules(validated.rules);
      const elapsed = Math.round(performance.now() - started);
      const text = translate("rule.aiDraftEnabled", { count: validated.rules.rules.length });
      setMessage(text);
      recordSession({
        kind: "generate",
        summaryHash: summary.summaryHash,
        mode: generationMode,
        model: validated.model,
        latencyMs: elapsed,
        ruleCount: validated.rules.rules.length,
        message: text
      });
      logOperation(
        translate("rule.aiGeneratedLog"),
        text,
        [validated.model, `${elapsed} ms`].filter(Boolean).join(" · ")
      );
    } catch (error) {
      if (epoch !== conversationEpoch.current) return;
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
      inFlight.current = false;
      if (epoch === conversationEpoch.current) setGenerating(false);
    }
  }

  async function cancel() {
    try {
      await cancelAiRuleGeneration();
    } catch {
      // Idle cancel is expected when the dialog closes or the request already finished.
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
    messages,
    composer,
    setComposer,
    planning,
    generating,
    canApprove: canApproveAiPlan(messages, planning || generating),
    replaceWarning: shouldWarnReplaceAiRecord(rules.library?.snapshot?.records),
    message,
    sessionEvents,
    clearSessionEvents,
    resetConversation,
    loadModels,
    testConnection,
    probeGeneration,
    onApiKeyBlur,
    onApiKeyPaste,
    saveProvider,
    sendPlan,
    approvePlan,
    cancel
  };
}

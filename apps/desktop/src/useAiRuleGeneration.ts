import { useEffect, useState } from "react";
import {
  approveAiRuleDraft,
  buildAiScanSummary,
  cancelAiRuleGeneration,
  generateAiRules,
  listAiProviderModels,
  listAiProviderProfiles,
  reviseAiRuleDraft,
  saveAiProviderCredential,
  saveAiProviderProfile,
  testAiProviderConnection,
  validateAiRuleDraft
} from "./api";
import { aiGenerationRequest } from "./aiGeneration";
import { aiDraftApprovalReady, aiDraftValidationReady } from "./aiDraftWorkflow";
import { describeProviderError } from "./providerError";
import type { RuleSourcesState } from "./useRuleSources";
import type {
  AiGeneratedRuleSet,
  AiProviderKind,
  AiProviderModel,
  AiProviderProfile,
  AiRuleDraft,
  AiRuleTier,
  RedactedScanSummary,
  ScanSnapshot
} from "./types";

const DEFAULT_PROVIDER_TIMEOUT_MS = 45_000;

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
  summary: RedactedScanSummary | null;
  targetTier: AiRuleTier;
  setTargetTier: (value: AiRuleTier) => void;
  draft: AiRuleDraft | null;
  draftEditor: string;
  draftEditorDirty: boolean;
  setDraftEditor: (value: string) => void;
  generating: boolean;
  message: string;
  loadModels: () => Promise<void>;
  testConnection: () => Promise<void>;
  saveProvider: () => Promise<void>;
  preparePreview: (snapshot: ScanSnapshot | null, ready: boolean) => Promise<void>;
  generate: () => Promise<void>;
  cancel: () => Promise<void>;
  applyDraftEdit: () => Promise<void>;
  validateDraft: () => Promise<void>;
  approveAndImportDraft: () => Promise<void>;
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
  const [summary, setSummary] = useState<RedactedScanSummary | null>(null);
  const [targetTierValue, setTargetTierValue] = useState<AiRuleTier>("light");
  const [draft, setDraft] = useState<AiRuleDraft | null>(null);
  const [draftEditor, setDraftEditorValue] = useState("");
  const [draftEditorDirty, setDraftEditorDirty] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState("");

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
      setMessage(translate("rule.aiConnectionSucceeded", { count: result.modelCount }));
    } catch (error) {
      setMessage(describeProviderError(error, translate));
    } finally {
      setTestingConnection(false);
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
      setSummary(await buildAiScanSummary(snapshot));
      setMessage(translate("rule.aiPreviewReady"));
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
    try {
      const response = await generateAiRules(
        selectedProfileIdValue,
        aiGenerationRequest(summary, targetTierValue)
      );
      setDraft(response.draft);
      setDraftEditorValue(JSON.stringify(response.draft.rules, null, 2));
      setDraftEditorDirty(false);
      setMessage(translate("rule.aiGenerated", { count: response.draft.rules.rules.length }));
    } catch (error) {
      setMessage(describeProviderError(error, translate));
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
    summary,
    targetTier: targetTierValue,
    setTargetTier,
    draft,
    draftEditor,
    draftEditorDirty,
    setDraftEditor,
    generating,
    message,
    loadModels,
    testConnection,
    saveProvider,
    preparePreview,
    generate,
    cancel,
    applyDraftEdit,
    validateDraft,
    approveAndImportDraft
  };
}

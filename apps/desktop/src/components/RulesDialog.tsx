import { ChevronDown, ChevronRight, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Dialog } from "./Dialog";
import { AiRuleChatPanel } from "./AiRuleChatPanel";
import { PROVIDER_VENDOR_PRESETS } from "../providerPresets";
import {
  MAX_PROVIDER_TIMEOUT_SECONDS,
  MIN_PROVIDER_TIMEOUT_SECONDS,
  type AiRuleGenerationState
} from "../useAiRuleGeneration";
import {
  libraryTableActions,
  visibleRuleLibraryRecords,
  type RuleSourcesState
} from "../useRuleSources";
import type {
  AiProviderKind,
  RuleRecord,
  RuleValidationReport,
  ScanSnapshot
} from "../types";

/**
 * Rule configuration is layered instead of flat. The default view answers
 * "which rule sets are active" in four rows; the YAML editor and subscription
 * URL live behind an "advanced" disclosure because a first-time user has no
 * reason to hand-write cleanup rules.
 */

export interface RulesDialogProps {
  rules: RuleSourcesState;
  ai: AiRuleGenerationState;
  snapshot: ScanSnapshot | null;
  /**
   * True only after a full-disk scan has settled. A quick scan visits a handful
   * of known roots, so its summary is too thin to draft rules from.
   */
  aiGenerationReady: boolean;
  onImportStarterRules?: () => void;
  onClose: () => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function RulesDialog({
  rules,
  ai,
  snapshot,
  aiGenerationReady,
  onImportStarterRules,
  onClose,
  translate
}: RulesDialogProps) {
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [providerAdvancedOpen, setProviderAdvancedOpen] = useState(false);
  const [editingRecordId, setEditingRecordId] = useState<string | null>(null);
  const [editorContent, setEditorContent] = useState("");
  const [editorReport, setEditorReport] = useState<RuleValidationReport | null>(null);
  const {
    profiles,
    selectedProfileId,
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
    probingGeneration,
    messages,
    composer,
    setComposer,
    planning,
    generating,
    canApprove,
    replaceWarning,
    message: aiMessage,
    clearSessionEvents,
    resetConversation
  } = ai;

  function handleClose() {
    if (planning || generating) void ai.cancel();
    setApiKey("");
    clearSessionEvents();
    resetConversation();
    onClose();
  }

  function openRecordEditor(record: RuleRecord) {
    const head = record.revisions.find(
      (revision) => revision.id === (record.pendingRevisionId ?? record.activeRevisionId)
    );
    setEditingRecordId(record.id);
    setEditorContent(head?.content ?? "");
    setEditorReport(head?.validation?.report ?? null);
  }

  function closeRecordEditor() {
    setEditingRecordId(null);
    setEditorContent("");
    setEditorReport(null);
  }

  async function validateEditor() {
    const compilation = await rules.validateLibraryDraft(editorContent);
    setEditorReport(compilation.report);
  }

  async function saveRecordEditor(record: RuleRecord) {
    // Compiling first keeps an unparseable edit from becoming a revision the
    // user then has to roll back.
    const compilation = await rules.validateLibraryDraft(editorContent);
    setEditorReport(compilation.report);
    if (!compilation.report.valid) {
      return;
    }
    await rules.saveLibraryDraft(record, editorContent);
    closeRecordEditor();
  }

  const customCount = rules.customCompilation?.report.valid
    ? String(rules.customCompilation.report.ruleCount)
    : translate("rule.notEnabled");
  const subscriptionCount = rules.subscriptionCompilation?.report.valid
    ? String(rules.subscriptionCompilation.report.ruleCount)
    : translate("rule.notEnabled");
  const visibleRecords = visibleRuleLibraryRecords(rules.library?.snapshot?.records);

  return (
    <Dialog
      title={translate("dialog.rules")}
      closeLabel={translate("button.close")}
      onClose={handleClose}
      className="ruleDialog"
      footer={
        <button className="button primary" onClick={handleClose}>
          {translate("button.done")}
        </button>
      }
    >
      <dl className="ruleSummary">
        <div className="ruleSummaryRow">
          <dt>{translate("rule.libraryActiveCount")}</dt>
          <dd>{String(rules.activeRules.length)}</dd>
        </div>
        <div className="ruleSummaryRow">
          <dt>{translate("rule.custom")}</dt>
          <dd>{customCount}</dd>
        </div>
        <div className="ruleSummaryRow">
          <dt>{translate("rule.subscription")}</dt>
          <dd>{subscriptionCount}</dd>
        </div>
        <div className="ruleSummaryRow">
          <dt>{translate("rule.subscriptionRefresh")}</dt>
          <dd>
            {rules.subscriptionCompilation?.report.valid
              ? translate("rule.every12Hours")
              : translate("rule.notEnabled")}
          </dd>
        </div>
      </dl>

      {rules.activeRules.length === 0 && onImportStarterRules ? (
        <section className="ruleCommunity" aria-labelledby="rule-starter-title">
          <div className="ruleLibraryHeader">
            <div>
              <h3 id="rule-starter-title">{translate("rule.starterTitle")}</h3>
              <p>{translate("scan.emptyLibraryHint")}</p>
            </div>
          </div>
          <div className="ruleActions">
            <button
              className="button primary"
              disabled={rules.libraryMutating}
              onClick={onImportStarterRules}
            >
              {translate("rule.useStarter")}
            </button>
          </div>
        </section>
      ) : null}

      <section className="ruleCommunity" aria-labelledby="rule-community-title">
        <div className="ruleLibraryHeader">
          <div>
            <h3 id="rule-community-title">{translate("rule.communityTitle")}</h3>
            <p>
              {rules.activeRules.length === 0
                ? translate("rule.libraryEmptyHint")
                : translate("rule.communityHint")}
            </p>
          </div>
        </div>
        <div className="ruleActions">
          <button
            className="button primary"
            disabled={rules.libraryMutating}
            onClick={() => void rules.refreshSubscription("manual")}
          >
            {translate("rule.loadSubscription")}
          </button>
          <button
            className="button primary"
            disabled={
              rules.libraryMutating ||
              !rules.subscriptionCompilation?.report.valid ||
              !rules.subscriptionContent
            }
            onClick={() => void rules.enableSubscriptionPack()}
          >
            {translate("rule.subscriptionEnable")}
          </button>
        </div>
        <p className="ruleAdvancedHint">{translate("rule.winapp2Attribution")}</p>
      </section>

      <section className="ruleAi" aria-labelledby="rule-ai-title">
        <div className="ruleLibraryHeader">
          <div>
            <h3 id="rule-ai-title">{translate("rule.aiTitle")}</h3>
            <p>{translate("rule.aiPrivacyHint")}</p>
          </div>
        </div>
        <div className="ruleAiGrid">
          <label className="ruleField">
            <span className="ruleFieldLabel">{translate("rule.aiProfile")}</span>
            <select
              value={selectedProfileId}
              onChange={(event) => setSelectedProfileId(event.target.value)}
            >
              <option value="">{translate("rule.aiNewProfile")}</option>
              {profiles.map((profile) => (
                <option value={profile.id} key={profile.id}>
                  {profile.displayName} · {profile.model}
                </option>
              ))}
            </select>
          </label>
          <label className="ruleField">
            <span className="ruleFieldLabel">{translate("rule.aiVendor")}</span>
            <select
              value={vendorId}
              onChange={(event) => setVendorId(event.target.value as typeof vendorId)}
            >
              {PROVIDER_VENDOR_PRESETS.map((preset) => (
                <option value={preset.id} key={preset.id}>
                  {translate(preset.labelKey)}
                </option>
              ))}
            </select>
          </label>
          <div className="ruleField ruleFieldWide">
            <span className="ruleFieldLabel">{translate("rule.aiApiKey")}</span>
            <div className="ruleUrlRow">
              <input
                type="text"
                value={apiKey}
                autoComplete="off"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                lang="en"
                inputMode="text"
                name="diskclean-ai-api-key"
                onChange={(event) => setApiKey(event.target.value)}
                onPaste={() => ai.onApiKeyPaste()}
                onBlur={() => ai.onApiKeyBlur()}
                placeholder={translate("rule.aiKeyPlaceholder")}
              />
              <button
                type="button"
                className="button"
                disabled={loadingModels || probingGeneration}
                onClick={() => void ai.probeGeneration()}
              >
                {loadingModels || probingGeneration
                  ? translate("rule.aiDetecting")
                  : translate("rule.aiDetect")}
              </button>
            </div>
          </div>
          <label className="ruleField ruleFieldWide">
            <span className="ruleFieldLabel">{translate("rule.aiModel")}</span>
            <div className="ruleUrlRow">
              {/* The dropdown is a convenience over the text field, not a
                  replacement: gateways can omit models from /v1/models, and the
                  fetch itself can fail while the model name is still valid. */}
              <select
                value={models.some((item) => item.id === model) ? model : ""}
                aria-label={translate("rule.aiModelPick")}
                onChange={(event) => {
                  if (event.target.value) {
                    setModel(event.target.value);
                  }
                }}
              >
                <option value="">
                  {models.length === 0
                    ? translate("rule.aiModelNotLoaded")
                    : translate("rule.aiModelPick")}
                </option>
                {models.map((item) => (
                  <option value={item.id} key={item.id}>
                    {item.displayName ?? item.id}
                  </option>
                ))}
              </select>
              <button
                className="button"
                disabled={loadingModels}
                onClick={() => void ai.loadModels()}
              >
                {loadingModels ? translate("rule.aiModelLoading") : translate("rule.aiModelFetch")}
              </button>
            </div>
            <input
              value={model}
              onChange={(event) => setModel(event.target.value)}
              placeholder={translate("rule.aiModelPlaceholder")}
            />
          </label>
        </div>
        <div className="ruleAiProviderAdvanced">
          <button
            className="ruleAdvancedToggle"
            onClick={() => setProviderAdvancedOpen((open) => !open)}
            aria-expanded={providerAdvancedOpen}
          >
            {providerAdvancedOpen ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
            <span>{translate("rule.aiProviderAdvanced")}</span>
          </button>
          {providerAdvancedOpen ? (
            <div className="ruleAiGrid">
              <label className="ruleField">
                <span className="ruleFieldLabel">{translate("rule.aiProtocol")}</span>
                <select
                  value={providerKind}
                  onChange={(event) => setProviderKind(event.target.value as AiProviderKind)}
                >
                  <option value="openAiCompatible">{translate("rule.aiProtocolOpenAi")}</option>
                  <option value="anthropicCompatible">{translate("rule.aiProtocolAnthropic")}</option>
                </select>
              </label>
              <label className="ruleField">
                <span className="ruleFieldLabel">{translate("rule.aiProfileName")}</span>
                <input value={providerName} onChange={(event) => setProviderName(event.target.value)} />
              </label>
              <label className="ruleField">
                <span className="ruleFieldLabel">{translate("rule.aiBaseUrl")}</span>
                <input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} />
              </label>
              <label className="ruleField">
                <span className="ruleFieldLabel">{translate("rule.aiTimeoutSeconds")}</span>
                <input
                  type="number"
                  min={MIN_PROVIDER_TIMEOUT_SECONDS}
                  max={MAX_PROVIDER_TIMEOUT_SECONDS}
                  step={1}
                  value={timeoutMs / 1000}
                  onChange={(event) => {
                    if (Number.isFinite(event.target.valueAsNumber)) {
                      const seconds = Math.min(
                        MAX_PROVIDER_TIMEOUT_SECONDS,
                        Math.max(MIN_PROVIDER_TIMEOUT_SECONDS, Math.round(event.target.valueAsNumber))
                      );
                      setTimeoutMs(seconds * 1000);
                    }
                  }}
                />
                <p className="ruleAdvancedHint">{translate("rule.aiTimeoutHint")}</p>
              </label>
            </div>
          ) : null}
        </div>
        <div className="ruleActions">
          <button className="button" onClick={() => void ai.saveProvider()}>
            {translate("rule.aiSaveProvider")}
          </button>
        </div>
        {!aiGenerationReady ? (
          <p className="ruleAdvancedHint">{translate("rule.aiNeedsFullScan")}</p>
        ) : null}
        <AiRuleChatPanel
          messages={messages}
          composer={composer}
          setComposer={setComposer}
          planning={planning}
          generating={generating}
          canApprove={canApprove}
          replaceWarning={replaceWarning}
          message={aiMessage}
          onSend={() => void ai.sendPlan(snapshot, aiGenerationReady)}
          onCancel={() => void ai.cancel()}
          onApprove={() => void ai.approvePlan()}
          translate={translate}
        />
      </section>

      <section className="ruleLibrary" aria-labelledby="rule-library-title">
        <div className="ruleLibraryHeader">
          <div>
            <h3 id="rule-library-title">{translate("rule.library")}</h3>
            <p>
              {rules.library?.snapshot
                ? translate("rule.libraryGeneration", {
                    generation: rules.library.snapshot.generation
                  })
                : translate("rule.libraryEmpty")}
            </p>
          </div>
          <button
            className="button"
            onClick={() => void rules.reloadRuleLibrary()}
            aria-label={translate("rule.libraryRefresh")}
          >
            <RefreshCw size={14} />
            {translate("button.refresh")}
          </button>
        </div>
        {rules.library?.notice ? (
          <div
            className={`ruleReport ${
              rules.library.status === "recoveredFromBackup" ? "safe" : "danger"
            }`}
            role="status"
          >
            <p className="ruleReportHead">{rules.library.notice}</p>
          </div>
        ) : null}
        {rules.activeLibrarySnapshot?.blockingIssues.length ? (
          <ul className="ruleReport ruleReportList danger">
            {rules.activeLibrarySnapshot.blockingIssues.map((issue, index) => (
              <li key={`${issue.code}-${issue.recordId ?? index}`}>{issue.message}</li>
            ))}
          </ul>
        ) : null}
        {visibleRecords.length ? (
          <ul className="ruleLibraryList">
            {visibleRecords.map((record) => {
              const pending = record.revisions.find(
                (revision) => revision.id === record.pendingRevisionId
              );
              const active = record.revisions.find(
                (revision) => revision.id === record.activeRevisionId
              );
              const actions = libraryTableActions(record);
              return (
                <li className="ruleLibraryItem" key={record.id}>
                  <div className="ruleLibraryItemHead">
                    <strong>{record.displayName}</strong>
                    <span className={`ruleState ruleState-${record.state}`}>
                      {translate(`rule.state.${record.state}`)}
                    </span>
                  </div>
                  <p>
                    {translate(`rule.origin.${record.origin}`)} · {record.id.slice(0, 8)}
                  </p>
                  <div className="ruleLibraryRevisions">
                    {active ? (
                      <span>
                        {translate("rule.libraryActive")}: {translate("rule.libraryRevision", { revision: active.number })} · {active.contentHash.slice(7, 19)}
                      </span>
                    ) : null}
                    {pending ? (
                      <span>
                        {translate("rule.libraryPending")}: {translate("rule.libraryRevision", { revision: pending.number })} · {pending.contentHash.slice(7, 19)}
                      </span>
                    ) : null}
                  </div>
                  {editingRecordId === record.id ? (
                    <div className="ruleLibraryEditor">
                      <label className="ruleField">
                        <span className="ruleFieldLabel">{translate("rule.libraryEditTitle")}</span>
                        <textarea
                          className="ruleTextarea"
                          value={editorContent}
                          onChange={(event) => setEditorContent(event.target.value)}
                          spellCheck={false}
                        />
                      </label>
                      <div className="ruleActions">
                        <button className="button" onClick={() => closeRecordEditor()}>
                          {translate("button.cancel")}
                        </button>
                        <button className="button" onClick={() => void validateEditor()}>
                          {translate("rule.validate")}
                        </button>
                        <button
                          className="button primary"
                          disabled={rules.libraryMutating}
                          onClick={() => void saveRecordEditor(record)}
                        >
                          {translate("rule.libraryEditSave")}
                        </button>
                      </div>
                      {editorReport ? (
                        <RuleReport report={editorReport} translate={translate} />
                      ) : null}
                    </div>
                  ) : null}
                  <div className="ruleActions ruleLibraryActions">
                    {editingRecordId !== record.id && actions.includes("edit") ? (
                      <button
                        className="button"
                        disabled={rules.libraryMutating}
                        onClick={() => openRecordEditor(record)}
                      >
                        {translate("rule.libraryEdit")}
                      </button>
                    ) : null}
                    {actions.includes("approve") ? (
                      <button
                        className="button primary"
                        disabled={rules.libraryMutating}
                        onClick={() => void rules.approveLibraryRecord(record)}
                      >
                        {translate("rule.libraryApprove")}
                      </button>
                    ) : null}
                    {actions.includes("disable") ? (
                      <button
                        className="button"
                        disabled={rules.libraryMutating}
                        onClick={() => void rules.disableLibraryRecord(record)}
                      >
                        {translate("rule.libraryDisable")}
                      </button>
                    ) : null}
                    {actions.includes("enable") ? (
                      <button
                        className="button primary"
                        disabled={rules.libraryMutating}
                        onClick={() => void rules.enableLibraryRecord(record)}
                      >
                        {translate("rule.libraryEnable")}
                      </button>
                    ) : null}
                    {actions.includes("delete") ? (
                      <button
                        className="button danger"
                        disabled={rules.libraryMutating}
                        onClick={() => {
                          if (window.confirm(translate("rule.libraryDeleteConfirm"))) {
                            void rules.deleteLibraryRecord(record);
                          }
                        }}
                      >
                        {translate("rule.libraryDelete")}
                      </button>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ul>
        ) : null}
      </section>

      <section className="ruleAdvanced">
        <button
          className="ruleAdvancedToggle"
          onClick={() => setAdvancedOpen((open) => !open)}
          aria-expanded={advancedOpen}
        >
          {advancedOpen ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
          <span>{translate("rule.advanced")}</span>
        </button>
        <p className="ruleAdvancedHint">{translate("rule.advancedHint")}</p>

        {advancedOpen ? (
          <div className="ruleAdvancedBody">
            <label className="ruleField">
              <span className="ruleFieldLabel">{translate("rule.custom")}</span>
              <textarea
                className="ruleTextarea"
                value={rules.ruleYaml}
                onChange={(event) => rules.setRuleYaml(event.target.value)}
                spellCheck={false}
              />
            </label>
            <div className="ruleActions">
              <button className="button" onClick={rules.resetCustomRules}>
                {translate("rule.reset")}
              </button>
              <button className="button" onClick={() => void rules.importWinapp2()}>
                {translate("rule.importWinapp2")}
              </button>
              <button className="button primary" onClick={() => void rules.validateCustomRules()}>
                {translate("rule.validate")}
              </button>
              <button
                className="button primary"
                disabled={rules.libraryMutating}
                onClick={() =>
                  void rules.createLibraryDraft(translate("rule.custom"), rules.ruleYaml)
                }
              >
                {translate("rule.librarySaveEditor")}
              </button>
            </div>
            {rules.customCompilation ? (
              <RuleReport report={rules.customCompilation.report} translate={translate} />
            ) : null}

            <label className="ruleField">
              <span className="ruleFieldLabel">{translate("rule.subscription")}</span>
              <div className="ruleUrlRow">
                <input
                  value={rules.subscriptionUrl}
                  onChange={(event) => rules.setSubscriptionUrl(event.target.value)}
                />
                <button
                  className="button primary"
                  onClick={() => void rules.refreshSubscription("manual")}
                >
                  {translate("rule.loadSubscription")}
                </button>
                <button
                  className="button"
                  disabled={!rules.subscriptionCompilation?.report.valid || rules.libraryMutating}
                  onClick={() => void rules.saveSubscriptionDraft()}
                >
                  {translate("rule.subscriptionSaveDraft")}
                </button>
              </div>
            </label>
            {rules.subscriptionReport ? (
              <RuleReport report={rules.subscriptionReport} translate={translate} />
            ) : null}
          </div>
        ) : null}
      </section>
    </Dialog>
  );
}

function RuleReport({
  report,
  translate
}: {
  report: RuleValidationReport;
  translate: (key: string, values?: Record<string, string | number>) => string;
}) {
  return (
    <div className={`ruleReport ${report.valid ? "safe" : "danger"}`}>
      <p className="ruleReportHead">
        {report.valid
          ? translate("rule.validateOk", { count: report.ruleCount })
          : translate("rule.validateFailed", { count: report.errors.length })}
      </p>
      {report.errors.length > 0 ? (
        <ul className="ruleReportList">
          {report.errors.slice(0, 8).map((issue, index) => (
            <li key={`${issue.ruleId ?? "rule"}-${issue.field}-${index}`}>
              {issue.ruleId ? `${issue.ruleId} · ` : ""}
              {issue.field}: {issue.message}
            </li>
          ))}
        </ul>
      ) : null}
      {report.warnings.length > 0 ? (
        <ul className="ruleReportList warn">
          {report.warnings.slice(0, 5).map((issue, index) => (
            <li key={`${issue.ruleId ?? "rule"}-warn-${issue.field}-${index}`}>
              {issue.field}: {issue.message}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

import { useCallback, useEffect, useRef, useState } from "react";
import {
  clearRuleSubscriptionCache,
  compileRuleSubscriptionContent,
  getActiveRuleSnapshot,
  importWinapp2Rules,
  loadRuleLibrary,
  loadRuleSubscriptionWithContent,
  mutateRuleLibrary,
  readRuleSubscriptionCache,
  validateRulesYaml,
  writeRuleSubscriptionCache
} from "./api";
import { createStoredRuleSubscription, readStoredRuleSubscription } from "./ruleSubscriptionStorage";
import type {
  ActiveRuleSnapshot,
  ApprovedRuleEnvelope,
  CompiledCleanupRule,
  RuleCompilation,
  RuleLibraryLoadResult,
  RuleLibraryMutationAction,
  RuleOrigin,
  RuleProvenance,
  RuleRecord,
  RuleValidationReport
} from "./types";

/**
 * Approved local-library revisions are the only rules that reach a scan.
 * Custom YAML and subscription fetches stay previews until the user enables them.
 */

export const DEFAULT_RULE_SUBSCRIPTION_URL =
  "https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini";

const REFRESH_INTERVAL_MS = 12 * 60 * 60 * 1000;
const STARTUP_REFRESH_DELAY_MS = 3000;

export type RefreshReason = "manual" | "startup" | "scheduled";

export const DEFAULT_RULE_YAML = `version: 1
rules:
  - id: custom.example.cache
    name: 示例应用缓存
    app: Example App
    category: 应用缓存
    level: 推荐清理
    default: false
    paths:
      - '%LOCALAPPDATA%\\Example\\Cache'
    clean: contents
    keep_days: 7
    exclude:
      - '*.license'
    note: 示例规则，可安全删除缓存内容。
`;

export interface RuleSourcesState {
  ruleYaml: string;
  setRuleYaml: (yaml: string) => void;
  customCompilation: RuleCompilation | null;
  subscriptionUrl: string;
  setSubscriptionUrl: (url: string) => void;
  subscriptionReport: RuleValidationReport | null;
  subscriptionCompilation: RuleCompilation | null;
  subscriptionContent: string | null;
  library: RuleLibraryLoadResult | null;
  activeLibrarySnapshot: ActiveRuleSnapshot | null;
  libraryMutating: boolean;
  reloadRuleLibrary: () => Promise<void>;
  createLibraryDraft: (
    displayName: string,
    content: string,
    provenance?: RuleProvenance,
    origin?: RuleOrigin
  ) => Promise<void>;
  importApprovedAiDraft: (displayName: string, envelope: ApprovedRuleEnvelope) => Promise<void>;
  validateLibraryDraft: (content: string) => Promise<RuleCompilation>;
  saveSubscriptionDraft: () => Promise<void>;
  enableSubscriptionPack: () => Promise<void>;
  /** Replaces a record's pending content, creating a new revision to approve. */
  saveLibraryDraft: (
    record: RuleRecord,
    content: string,
    provenance?: RuleProvenance
  ) => Promise<void>;
  approveLibraryRecord: (record: RuleRecord) => Promise<void>;
  disableLibraryRecord: (record: RuleRecord) => Promise<void>;
  deleteLibraryRecord: (record: RuleRecord) => Promise<void>;
  restoreLibraryRecord: (record: RuleRecord) => Promise<void>;
  rollbackLibraryRecord: (record: RuleRecord, revisionId: string) => Promise<void>;
  /** Approved library revisions only. */
  activeRules: CompiledCleanupRule[];
  validateCustomRules: () => Promise<void>;
  importWinapp2: () => Promise<void>;
  resetCustomRules: () => void;
  refreshSubscription: (reason: RefreshReason) => Promise<void>;
}

export interface RuleSourcesCallbacks {
  onNotice: (message: string) => void;
  onLog: (title: string, message: string, detail?: string) => void;
  translate: (key: string, values?: Record<string, string | number>) => string;
}

export function useRuleSources(callbacks: RuleSourcesCallbacks): RuleSourcesState {
  const { onNotice, onLog, translate } = callbacks;
  const [ruleYaml, setRuleYaml] = useState(DEFAULT_RULE_YAML);
  const [customCompilation, setCustomCompilation] = useState<RuleCompilation | null>(null);
  const [subscriptionUrl, setSubscriptionUrl] = useState(DEFAULT_RULE_SUBSCRIPTION_URL);
  const [subscriptionReport, setSubscriptionReport] = useState<RuleValidationReport | null>(null);
  const [subscriptionCompilation, setSubscriptionCompilation] = useState<RuleCompilation | null>(null);
  const [subscriptionContent, setSubscriptionContent] = useState<string | null>(null);
  const [library, setLibrary] = useState<RuleLibraryLoadResult | null>(null);
  const [activeLibrarySnapshot, setActiveLibrarySnapshot] = useState<ActiveRuleSnapshot | null>(null);
  const [libraryMutating, setLibraryMutating] = useState(false);
  const [loadedFromCache, setLoadedFromCache] = useState(false);
  const actorId = useRef(stableBrowserUuid("diskclean.ruleLibrary.actorId"));
  const deviceId = useRef(stableBrowserUuid("diskclean.ruleLibrary.deviceId"));
  const refreshInFlight = useRef(false);
  const startupRefreshQueued = useRef(false);

  const reloadRuleLibrary = useCallback(async () => {
    const [loaded, active] = await Promise.all([loadRuleLibrary(), getActiveRuleSnapshot()]);
    setLibrary(loaded);
    setActiveLibrarySnapshot(active);
    if (loaded.notice) {
      onNotice(loaded.notice);
      onLog("本地规则库", loaded.notice);
    }
    for (const issue of active.blockingIssues) {
      onLog("本地规则库校验", issue.message, issue.code);
    }
  }, [onLog, onNotice]);

  const applyLibraryMutation = useCallback(
    async (action: RuleLibraryMutationAction, expectedHeadRevisionId: string | null) => {
      if (libraryMutating) {
        return;
      }
      setLibraryMutating(true);
      try {
        await mutateRuleLibrary({
          expectedGeneration: library?.snapshot?.generation ?? 0,
          expectedHeadRevisionId,
          mutationId: crypto.randomUUID(),
          actorId: actorId.current,
          deviceId: deviceId.current,
          timestamp: new Date().toISOString(),
          action
        });
        await reloadRuleLibrary();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        onNotice(message);
        onLog("本地规则库更新失败", message);
        throw error;
      } finally {
        setLibraryMutating(false);
      }
    },
    [library?.snapshot?.generation, libraryMutating, onLog, onNotice, reloadRuleLibrary]
  );

  const createLibraryDraft = useCallback(
    async (
      displayName: string,
      content: string,
      provenance: RuleProvenance = manualProvenance(),
      origin: RuleOrigin = "manual"
    ) => {
      await applyLibraryMutation(
        { type: "createDraft", displayName, origin, content, provenance },
        null
      );
    },
    [applyLibraryMutation]
  );

  const subscriptionProvenance = useCallback(
    (): RuleProvenance => ({
      sourceLabel: "subscription",
      providerProfileId: null,
      model: null,
      scanSummaryHash: null,
      sourceUrl: sanitizeSubscriptionUrl(subscriptionUrl),
      generatedAt: null,
      aiDraftId: null,
      aiDraftRevision: null
    }),
    [subscriptionUrl]
  );

  const saveSubscriptionDraft = useCallback(async () => {
    if (!subscriptionCompilation?.report.valid || !subscriptionContent) {
      return;
    }
    await createLibraryDraft(
      translate("rule.subscriptionPackName"),
      subscriptionContent,
      subscriptionProvenance(),
      "subscription"
    );
  }, [
    createLibraryDraft,
    subscriptionCompilation,
    subscriptionContent,
    subscriptionProvenance,
    translate
  ]);

  const enableSubscriptionPack = useCallback(async () => {
    if (!subscriptionCompilation?.report.valid || !subscriptionContent) {
      return;
    }
    await applyLibraryMutation(
      {
        type: "importAndApproveSubscription",
        displayName: translate("rule.subscriptionPackName"),
        content: subscriptionContent,
        provenance: subscriptionProvenance()
      },
      null
    );
  }, [
    applyLibraryMutation,
    subscriptionCompilation,
    subscriptionContent,
    subscriptionProvenance,
    translate
  ]);

  const importApprovedAiDraft = useCallback(
    async (displayName: string, envelope: ApprovedRuleEnvelope) => {
      await applyLibraryMutation(
        { type: "importApprovedAiDraft", displayName, envelope },
        null
      );
    },
    [applyLibraryMutation]
  );

  const validateLibraryDraft = useCallback(async (content: string) => {
    return looksLikeWinapp2(content)
      ? importWinapp2Rules(content, "subscription")
      : validateRulesYaml(content, "user");
  }, []);

  const saveLibraryDraft = useCallback(
    async (record: RuleRecord, content: string, provenance?: RuleProvenance) => {
      const head = record.revisions.find(
        (revision) => revision.id === (record.pendingRevisionId ?? record.activeRevisionId)
      );
      await applyLibraryMutation(
        {
          type: "saveDraft",
          recordId: record.id,
          content,
          // Editing keeps the record's origin trail rather than resetting it to
          // "manual", so an AI-derived rule set stays attributable after edits.
          provenance: provenance ?? head?.provenance ?? manualProvenance()
        },
        record.pendingRevisionId ?? record.activeRevisionId
      );
    },
    [applyLibraryMutation]
  );

  const approveLibraryRecord = useCallback(
    async (record: RuleRecord) => {
      const pending = record.revisions.find((revision) => revision.id === record.pendingRevisionId);
      if (!pending) {
        return;
      }
      await applyLibraryMutation(
        { type: "approve", recordId: record.id, expectedHash: pending.contentHash },
        pending.id
      );
    },
    [applyLibraryMutation]
  );

  const disableLibraryRecord = useCallback(
    async (record: RuleRecord) => {
      await applyLibraryMutation(
        { type: "disable", recordId: record.id },
        record.pendingRevisionId ?? record.activeRevisionId
      );
    },
    [applyLibraryMutation]
  );

  const deleteLibraryRecord = useCallback(
    async (record: RuleRecord) => {
      await applyLibraryMutation(
        { type: "delete", recordId: record.id },
        record.pendingRevisionId ?? record.activeRevisionId
      );
    },
    [applyLibraryMutation]
  );

  const restoreLibraryRecord = useCallback(
    async (record: RuleRecord) => {
      await applyLibraryMutation(
        { type: "restore", recordId: record.id },
        record.pendingRevisionId ?? record.activeRevisionId
      );
    },
    [applyLibraryMutation]
  );

  const rollbackLibraryRecord = useCallback(
    async (record: RuleRecord, revisionId: string) => {
      await applyLibraryMutation(
        { type: "rollback", recordId: record.id, revisionId },
        record.pendingRevisionId ?? record.activeRevisionId
      );
    },
    [applyLibraryMutation]
  );

  useEffect(() => {
    void reloadRuleLibrary().catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      onLog("本地规则库加载失败", message);
    });
  }, [onLog, reloadRuleLibrary]);

  const refreshSubscription = useCallback(
    async (reason: RefreshReason) => {
      const trimmedUrl = subscriptionUrl.trim();
      const currentValid = subscriptionCompilation?.report.valid ? subscriptionCompilation : null;

      if (!trimmedUrl) {
        if (reason === "manual") {
          await clearRuleSubscriptionCache();
          setSubscriptionCompilation(null);
          setSubscriptionContent(null);
          setSubscriptionReport(null);
          setLoadedFromCache(false);
          onNotice(translate("rule.subscriptionDisabled"));
          onLog(
            translate("rule.subscriptionDisabledLog"),
            translate("rule.subscriptionDisabledDetail")
          );
        }
        return;
      }

      if (refreshInFlight.current) {
        return;
      }

      refreshInFlight.current = true;

      if (reason === "manual") {
        onNotice(translate("rule.subscriptionLoading"));
      }

      try {
        const result = await loadRuleSubscriptionWithContent(trimmedUrl);
        setSubscriptionReport(result.compilation.report);

        if (!result.compilation.report.valid || result.content === null) {
          // A failed scheduled check must not drop rules that already work.
          if (!currentValid) {
            setSubscriptionCompilation(null);
            setSubscriptionContent(null);
          }

          const message = translate(
            reason === "manual" ? "rule.subscriptionLoadFailed" : "rule.subscriptionCheckFailed"
          );

          if (reason === "manual") {
            onNotice(message);
          }

          onLog(subscriptionLogTitle(translate, reason, false), message, trimmedUrl);
          return;
        }

        const changed = compilationChanged(currentValid, result.compilation);
        const stored = createStoredRuleSubscription(trimmedUrl, result.content);
        const saved = await writeRuleSubscriptionCache(stored);
        const count = result.compilation.report.ruleCount;
        const baseMessage =
          reason === "manual"
            ? translate("rule.subscriptionLoaded", { count })
            : changed
              ? translate("rule.subscriptionUpdated", { count })
              : translate("rule.subscriptionUnchanged", { count });
        const message = saved
          ? baseMessage
          : `${baseMessage} ${translate("rule.subscriptionCacheFailed")}`;

        setSubscriptionCompilation(result.compilation);
        setSubscriptionContent(result.content);
        setLoadedFromCache(false);
        setSubscriptionUrl(trimmedUrl);

        if (reason === "manual" || changed) {
          onNotice(message);
        }

        onLog(subscriptionLogTitle(translate, reason, true), message, trimmedUrl);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);

        if (!currentValid) {
          setSubscriptionCompilation(null);
          setSubscriptionContent(null);
        }

        setSubscriptionReport({
          valid: false,
          ruleCount: 0,
          errors: [{ ruleId: null, field: "url", message }],
          warnings: []
        });

        if (reason === "manual") {
          onNotice(translate("rule.subscriptionLoadFailedWith", { message }));
        }

        onLog(subscriptionLogTitle(translate, reason, false), message, trimmedUrl);
      } finally {
        refreshInFlight.current = false;
      }
    },
    [onLog, onNotice, subscriptionCompilation, subscriptionUrl, translate]
  );

  useEffect(() => {
    let disposed = false;

    async function restore() {
      const persisted = await readRuleSubscriptionCache();
      const cached = persisted ?? readStoredRuleSubscription();

      if (!cached) {
        return;
      }

      if (!persisted) {
        await writeRuleSubscriptionCache(cached);
      }

      const compilation = await compileRuleSubscriptionContent(cached.url, cached.content);

      if (disposed) {
        return;
      }

      setSubscriptionUrl(cached.url);
      setSubscriptionReport(compilation.report);

      if (compilation.report.valid) {
        setSubscriptionCompilation(compilation);
        setSubscriptionContent(cached.content);
        setLoadedFromCache(true);
        onLog(
          translate("rule.subscriptionRestoredLog"),
          translate("rule.subscriptionRestored", { count: compilation.report.ruleCount }),
          cached.url
        );
        return;
      }

      await clearRuleSubscriptionCache();
      setSubscriptionCompilation(null);
      setSubscriptionContent(null);
      setLoadedFromCache(false);
      onLog(
        translate("rule.subscriptionRestoreFailedLog"),
        translate("rule.subscriptionStaleDetail"),
        cached.url
      );
    }

    void restore().catch((error) => {
      if (disposed) {
        return;
      }

      const message = error instanceof Error ? error.message : String(error);
      setSubscriptionCompilation(null);
      setSubscriptionContent(null);
      setLoadedFromCache(false);
      setSubscriptionReport({
        valid: false,
        ruleCount: 0,
        errors: [{ ruleId: null, field: "content", message }],
        warnings: []
      });
      onLog(translate("rule.subscriptionRestoreFailedLog"), message);
    });

    return () => {
      disposed = true;
    };
    // Restoring the cache is a mount-time concern; re-running it on every
    // translator identity change would refetch and re-log on language switch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!subscriptionCompilation?.report.valid || subscriptionUrl.trim().length === 0) {
      return;
    }

    let startupTimerId: number | undefined;

    if (loadedFromCache && !startupRefreshQueued.current) {
      startupRefreshQueued.current = true;
      startupTimerId = window.setTimeout(() => {
        void refreshSubscription("startup");
      }, STARTUP_REFRESH_DELAY_MS);
    }

    const intervalId = window.setInterval(() => {
      void refreshSubscription("scheduled");
    }, REFRESH_INTERVAL_MS);

    return () => {
      if (startupTimerId !== undefined) {
        window.clearTimeout(startupTimerId);
      }

      window.clearInterval(intervalId);
    };
  }, [loadedFromCache, refreshSubscription, subscriptionCompilation?.report.valid, subscriptionUrl]);

  const validateCustomRules = useCallback(async () => {
    const compilation = await validateRulesYaml(ruleYaml, "user");
    setCustomCompilation(compilation);
    onNotice(
      compilation.report.valid
        ? translate("rule.validateOk", { count: compilation.report.ruleCount })
        : translate("rule.validateFailed", { count: compilation.report.errors.length })
    );
    onLog(
      translate("rule.validateLog"),
      compilation.report.valid
        ? translate("rule.validateOk", { count: compilation.report.ruleCount })
        : translate("rule.validateFailed", { count: compilation.report.errors.length })
    );
  }, [onLog, onNotice, ruleYaml, translate]);

  const importWinapp2 = useCallback(async () => {
    const compilation = await importWinapp2Rules(ruleYaml, "user");
    setCustomCompilation(compilation);
    onNotice(
      compilation.report.valid
        ? translate("rule.importOk", { count: compilation.report.ruleCount })
        : translate("rule.importFailed")
    );
    onLog(
      translate("rule.importLog"),
      compilation.report.valid
        ? translate("rule.importOk", { count: compilation.report.ruleCount })
        : translate("rule.importFailed")
    );
  }, [onLog, onNotice, ruleYaml, translate]);

  const resetCustomRules = useCallback(() => {
    setRuleYaml(DEFAULT_RULE_YAML);
    setCustomCompilation(null);
  }, []);

  // Only immutable, durably approved library revisions are allowed to reach a scan.
  // Editor and subscription compilations remain previews until explicitly saved and approved.
  const activeRules = activeLibrarySnapshot?.rules ?? [];

  return {
    ruleYaml,
    setRuleYaml,
    customCompilation,
    subscriptionUrl,
    setSubscriptionUrl,
    subscriptionReport,
    subscriptionCompilation,
    subscriptionContent,
    library,
    activeLibrarySnapshot,
    libraryMutating,
    reloadRuleLibrary,
    createLibraryDraft,
    importApprovedAiDraft,
    validateLibraryDraft,
    saveSubscriptionDraft,
    enableSubscriptionPack,
    saveLibraryDraft,
    approveLibraryRecord,
    disableLibraryRecord,
    deleteLibraryRecord,
    restoreLibraryRecord,
    rollbackLibraryRecord,
    activeRules,
    validateCustomRules,
    importWinapp2,
    resetCustomRules,
    refreshSubscription
  };
}

function sanitizeSubscriptionUrl(value: string): string | null {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.hash = "";
    for (const key of [...url.searchParams.keys()]) {
      if (/token|key|secret|signature|auth/i.test(key)) {
        url.searchParams.set(key, "REDACTED");
      }
    }
    return url.toString();
  } catch {
    return null;
  }
}

function manualProvenance(): RuleProvenance {
  return {
    sourceLabel: "manual",
    providerProfileId: null,
    model: null,
    scanSummaryHash: null,
    sourceUrl: null,
    generatedAt: null,
    aiDraftId: null,
    aiDraftRevision: null
  };
}

function stableBrowserUuid(key: string): string {
  const stored = window.localStorage.getItem(key);
  if (stored && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(stored)) {
    return stored;
  }
  const value = crypto.randomUUID();
  window.localStorage.setItem(key, value);
  return value;
}

function subscriptionLogTitle(
  translate: (key: string) => string,
  reason: RefreshReason,
  success: boolean
): string {
  if (reason === "manual") {
    return translate(success ? "rule.subscriptionLoadedLog" : "rule.subscriptionLoadFailedLog");
  }

  return translate(success ? "rule.subscriptionCheckedLog" : "rule.subscriptionCheckFailedLog");
}

function looksLikeWinapp2(content: string): boolean {
  const trimmed = content.replace(/^\uFEFF/, "");
  for (const rawLine of trimmed.split(/\r?\n/).slice(0, 32)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) {
      continue;
    }
    if (line.startsWith("version:") || line.startsWith("rules:")) {
      return false;
    }
    if ((line.startsWith("[") && line.endsWith("]")) || line.toLowerCase().startsWith("filekey")) {
      return true;
    }
  }
  return /(?:^|\n)\s*\[.+\]\s*(?:\n|$)/.test(trimmed) || /^filekey/im.test(trimmed);
}

function compilationChanged(
  current: RuleCompilation | null,
  next: RuleCompilation
): boolean {
  if (!current) {
    return true;
  }

  return (
    current.report.ruleCount !== next.report.ruleCount ||
    current.rules.map((rule) => rule.id).join("|") !== next.rules.map((rule) => rule.id).join("|")
  );
}

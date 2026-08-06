import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { isPermissionGranted, requestPermission, sendNotification } from "@tauri-apps/plugin-notification";
import { mockChildren, mockCleanupPlan, mockCleanupReport, mockSnapshot } from "./mockData";
import type {
  AdminStatus,
  ActiveRuleSnapshot,
  AutomationConfig,
  AutomationRunReport,
  AutomationSchedulerStatus,
  AiProviderGenerationRequest,
  AiProviderGenerationResponse,
  AiProviderConnectionResult,
  AiProviderModelQuery,
  AiProviderProfile,
  AiGeneratedRuleSet,
  AiRuleDraft,
  ApprovedRuleEnvelope,
  CleanupCandidate,
  CleanupPlan,
  CleanupProgress,
  CleanupReport,
  DeleteStrategy,
  AppLogEntry,
  InventoryPage,
  InventorySort,
  RuleCompilation,
  RuleLibraryLoadResult,
  RuleLibraryMutationRequest,
  RuleLibrarySnapshot,
  RuleSourceKind,
  RuleValidationReport,
  ScanProgress,
  ScanRequest,
  ScanSnapshot,
  StoredRuleSubscription
} from "./types";
import {
  clearStoredRuleSubscription,
  readStoredRuleSubscription,
  storeRuleSubscription
} from "./ruleSubscriptionStorage";

const CLEANUP_PROGRESS_EVENT = "cleanup-progress";
const SCAN_PROGRESS_EVENT = "scan-progress";
const MAX_RULE_SUBSCRIPTION_BYTES = 2 * 1024 * 1024;

export interface RuleSubscriptionLoadResult {
  content: string | null;
  compilation: RuleCompilation;
}

export async function getScanSnapshot(): Promise<ScanSnapshot> {
  try {
    return await invoke<ScanSnapshot>("get_scan_snapshot");
  } catch {
    return {
      ...mockSnapshot,
      candidates: [],
      selectedCandidateId: "",
      summary: {
        estimatedReclaimBytes: 0,
        candidateCount: 0,
        lockedCount: 0,
        progressPercent: 0,
        selectedCount: 0,
        selectedBytes: 0
      },
      scanBackend: "mock-idle",
      warnings: []
    };
  }
}

export async function getAdminStatus(): Promise<AdminStatus> {
  try {
    return await invoke<AdminStatus>("get_admin_status");
  } catch {
    return {
      isAdmin: false,
      canRestartElevated: false
    };
  }
}

export async function restartAsAdmin(): Promise<void> {
  await invoke("restart_as_admin");
}

export async function runScan(request: ScanRequest): Promise<ScanSnapshot> {
  try {
    return await invoke<ScanSnapshot>("run_scan", { request });
  } catch {
    return {
      ...mockSnapshot,
      volumes: mockSnapshot.volumes.map((volume) => ({
        ...volume,
        selected: request.volumeIds.length === 0 || request.volumeIds.includes(volume.id)
      })),
      scanBackend: request.mode === "full" ? "mock-full" : "mock-quick"
    };
  }
}

export async function pauseScan(): Promise<void> {
  if (!hasTauriRuntime()) {
    return;
  }

  await invoke("pause_scan");
}

export async function resumeScan(): Promise<void> {
  if (!hasTauriRuntime()) {
    return;
  }

  await invoke("resume_scan");
}

export async function notifyScanComplete(title: string, body: string): Promise<boolean> {
  if (!hasTauriRuntime()) {
    return false;
  }

  try {
    let permissionGranted = await isPermissionGranted();
    if (!permissionGranted) {
      const permission = await requestPermission();
      permissionGranted = permission === "granted";
    }

    if (!permissionGranted) {
      return false;
    }

    sendNotification({ title, body });
    return true;
  } catch {
    return false;
  }
}

export async function listCandidateChildren(candidate: CleanupCandidate): Promise<CleanupCandidate[]> {
  try {
    return await invoke<CleanupCandidate[]>("list_candidate_children", { candidate });
  } catch {
    return candidate.id === "chrome-cache" ? mockChildren : [];
  }
}

export async function listInventoryChildren(
  scanSessionId: string,
  parentEntryId: string | null,
  cursor: string | null = null,
  limit = 100,
  sort: InventorySort = "name"
): Promise<InventoryPage> {
  if (!hasTauriRuntime()) {
    return { items: [], nextCursor: null };
  }
  return await invoke<InventoryPage>("list_inventory_children", {
    scanSessionId,
    parentEntryId,
    cursor,
    limit,
    sort
  });
}

export async function searchInventory(
  scanSessionId: string,
  query: string,
  cursor: string | null = null,
  limit = 100
): Promise<InventoryPage> {
  if (!hasTauriRuntime()) {
    return { items: [], nextCursor: null };
  }
  return await invoke<InventoryPage>("search_inventory", {
    scanSessionId,
    query,
    cursor,
    limit
  });
}

export async function listInventoryLargest(
  scanSessionId: string,
  cursor: string | null = null,
  limit = 100
): Promise<InventoryPage> {
  if (!hasTauriRuntime()) {
    return { items: [], nextCursor: null };
  }
  return await invoke<InventoryPage>("list_inventory_largest", {
    scanSessionId,
    cursor,
    limit
  });
}

export async function closeInventorySession(scanSessionId: string): Promise<void> {
  if (!hasTauriRuntime()) {
    return;
  }
  await invoke("close_inventory_session", { scanSessionId });
}

export async function previewCleanupPlan(candidates: CleanupCandidate[], selectedIds: string[]): Promise<CleanupPlan> {
  if (selectedIds.length === 0) {
    return {
      ...mockCleanupPlan,
      selectedCount: 0,
      skippedLockedCount: 0,
      estimatedReclaimBytes: 0
    };
  }

  try {
    return await invoke<CleanupPlan>("preview_cleanup_plan", { candidates, selectedIds });
  } catch {
    const selected = candidates.filter((candidate) => selectedIds.includes(candidate.id));
    const cleanable = selected.filter(
      (candidate) => candidate.riskLevel !== "blocked" && candidate.deleteStrategy !== "skip"
    );
    const skippedLockedCount = selected.length - cleanable.length;

    return {
      ...mockCleanupPlan,
      selectedCount: cleanable.length,
      skippedLockedCount,
      estimatedReclaimBytes: cleanable.reduce((total, candidate) => total + candidate.sizeBytes, 0)
    };
  }
}

export async function executeCleanupPlan(
  candidates: CleanupCandidate[],
  selectedIds: string[],
  deleteStrategy: Exclude<DeleteStrategy, "skip">
): Promise<CleanupReport> {
  try {
    return await invoke<CleanupReport>("execute_cleanup_plan", {
      candidates,
      selectedIds,
      options: { deleteStrategy }
    });
  } catch {
    const selected = candidates.filter((candidate) => selectedIds.includes(candidate.id));
    const cleaned = selected.filter(
      (candidate) => candidate.riskLevel !== "blocked" && candidate.deleteStrategy !== "skip"
    );
    const skipped = selected.filter(
      (candidate) => candidate.riskLevel === "blocked" || candidate.deleteStrategy === "skip"
    );

    return {
      ...mockCleanupReport,
      requestedCount: selectedIds.length,
      cleanedCount: cleaned.length,
      skippedLockedCount: skipped.length,
      failedCount: 0,
      reclaimedBytes: cleaned.reduce((total, candidate) => total + candidate.sizeBytes, 0),
      cleanedIds: cleaned.map((candidate) => candidate.id),
      skippedIds: skipped.map((candidate) => candidate.id),
      failedIds: [],
      deleteStrategy,
      itemResults: [
        ...cleaned.map((candidate) => ({
          id: candidate.id,
          displayName: candidate.displayName,
          path: candidate.path,
          source: candidate.source,
          status: "cleaned" as const,
          reclaimedBytes: candidate.sizeBytes,
          reason:
            deleteStrategy === "permanentDelete"
              ? "符合清理条件，已永久删除。"
              : "符合清理条件，已移动到 Windows 回收站。"
        })),
        ...skipped.map((candidate) => ({
          id: candidate.id,
          displayName: candidate.displayName,
          path: candidate.path,
          source: candidate.source,
          status: "skipped" as const,
          reclaimedBytes: 0,
          reason: candidate.reason || "已锁定或策略为跳过，未执行清理。"
        }))
      ]
    };
  }
}

export async function pauseCleanup(): Promise<void> {
  if (!hasTauriRuntime()) {
    return;
  }

  await invoke("pause_cleanup");
}

export async function resumeCleanup(): Promise<void> {
  if (!hasTauriRuntime()) {
    return;
  }

  await invoke("resume_cleanup");
}

export async function cancelCleanup(): Promise<void> {
  if (!hasTauriRuntime()) {
    return;
  }

  await invoke("cancel_cleanup");
}

export async function listenCleanupProgress(
  handler: (progress: CleanupProgress) => void
): Promise<() => void> {
  if (!hasTauriRuntime()) {
    return () => {};
  }

  return await listen<CleanupProgress>(CLEANUP_PROGRESS_EVENT, (event) => handler(event.payload));
}

export async function listenScanProgress(
  handler: (progress: ScanProgress) => void
): Promise<() => void> {
  if (!hasTauriRuntime()) {
    return () => {};
  }

  return await listen<ScanProgress>(SCAN_PROGRESS_EVENT, (event) => handler(event.payload));
}

function hasTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function revealPath(path: string): Promise<void> {
  try {
    await invoke("reveal_path", { path });
  } catch {
    await navigator.clipboard.writeText(path);
  }
}

export async function readAppLogs(): Promise<AppLogEntry[]> {
  try {
    return await invoke<AppLogEntry[]>("read_app_logs");
  } catch {
    return [];
  }
}

export async function writeAppLogs(logs: AppLogEntry[]): Promise<boolean> {
  try {
    await invoke("write_app_logs", { logs });
    return true;
  } catch {
    return false;
  }
}

export async function readRuleSubscriptionCache(): Promise<StoredRuleSubscription | null> {
  try {
    return await invoke<StoredRuleSubscription | null>("read_rule_subscription_cache");
  } catch {
    return readStoredRuleSubscription();
  }
}

export async function writeRuleSubscriptionCache(subscription: StoredRuleSubscription): Promise<boolean> {
  try {
    await invoke("write_rule_subscription_cache", { subscription });
    clearStoredRuleSubscription();
    return true;
  } catch {
    return storeRuleSubscription(subscription);
  }
}

export async function clearRuleSubscriptionCache(): Promise<void> {
  try {
    await invoke("clear_rule_subscription_cache");
    clearStoredRuleSubscription();
  } catch {
    clearStoredRuleSubscription();
  }
}

export async function loadRuleLibrary(): Promise<RuleLibraryLoadResult> {
  return await invoke<RuleLibraryLoadResult>("load_rule_library");
}

export async function commitRuleLibrary(
  expectedGeneration: number,
  snapshot: RuleLibrarySnapshot
): Promise<RuleLibrarySnapshot> {
  return await invoke<RuleLibrarySnapshot>("commit_rule_library", {
    expectedGeneration,
    snapshot
  });
}

export async function mutateRuleLibrary(
  request: RuleLibraryMutationRequest
): Promise<RuleLibrarySnapshot> {
  return await invoke<RuleLibrarySnapshot>("mutate_rule_library", { request });
}

export async function getActiveRuleSnapshot(): Promise<ActiveRuleSnapshot> {
  return await invoke<ActiveRuleSnapshot>("get_active_rule_snapshot");
}

export async function validateRulesYaml(content: string, source: RuleSourceKind): Promise<RuleCompilation> {
  try {
    return await invoke<RuleCompilation>("validate_rules_yaml", { content, source });
  } catch (error) {
    return {
      rules: [],
      report: {
        valid: false,
        ruleCount: 0,
        errors: [
          {
            ruleId: null,
            field: "yaml",
            message: error instanceof Error ? error.message : "规则校验失败"
          }
        ],
        warnings: []
      }
    };
  }
}

export async function importWinapp2Rules(content: string, source: RuleSourceKind): Promise<RuleCompilation> {
  try {
    return await invoke<RuleCompilation>("import_winapp2_rules", { content, source });
  } catch (error) {
    return {
      rules: [],
      report: {
        valid: false,
        ruleCount: 0,
        errors: [
          {
            ruleId: null,
            field: "winapp2",
            message: error instanceof Error ? error.message : "Winapp2 导入失败"
          }
        ],
        warnings: []
      }
    };
  }
}

export async function loadRuleSubscription(url: string): Promise<RuleCompilation> {
  const result = await loadRuleSubscriptionWithContent(url);
  return result.compilation;
}

export async function loadRuleSubscriptionWithContent(url: string): Promise<RuleSubscriptionLoadResult> {
  const validation = await validateSubscriptionUrl(url);
  if (!validation.valid) {
    return {
      content: null,
      compilation: {
        rules: [],
        report: validation
      }
    };
  }

  const response = await fetch(url);
  if (!response.ok) {
    return {
      content: null,
      compilation: {
        rules: [],
        report: {
          valid: false,
          ruleCount: 0,
          errors: [
            {
              ruleId: null,
              field: "url",
              message: `订阅下载失败：HTTP ${response.status}`
            }
          ],
          warnings: []
        }
      }
    };
  }

  const content = await response.text();
  const contentReport = validateRuleSubscriptionContent(content);
  if (contentReport) {
    return {
      content: null,
      compilation: {
        rules: [],
        report: contentReport
      }
    };
  }

  return {
    content,
    compilation: await compileRuleSubscriptionContent(url, content)
  };
}

export async function compileRuleSubscriptionContent(url: string, content: string): Promise<RuleCompilation> {
  const contentReport = validateRuleSubscriptionContent(content);
  if (contentReport) {
    return {
      rules: [],
      report: contentReport
    };
  }

  return subscriptionUrlIsIni(url)
    ? importWinapp2Rules(content, "subscription")
    : validateRulesYaml(content, "subscription");
}

function subscriptionUrlIsIni(url: string): boolean {
  return url.split(/[?#]/, 1)[0].toLowerCase().endsWith(".ini");
}

function validateRuleSubscriptionContent(content: string): RuleValidationReport | null {
  if (new TextEncoder().encode(content).length <= MAX_RULE_SUBSCRIPTION_BYTES) {
    return null;
  }

  return invalidRuleReport("content", "订阅规则文件不能超过 2 MB");
}

export async function validateSubscriptionUrl(url: string): Promise<RuleValidationReport> {
  try {
    return await invoke<RuleValidationReport>("validate_subscription_url", { url });
  } catch {
    return validateSubscriptionUrlLocally(url);
  }
}

function validateSubscriptionUrlLocally(url: string): RuleValidationReport {
  const trimmed = url.trim();
  const lower = trimmed.toLowerCase();

  if (trimmed.length === 0) {
    return invalidRuleReport("url", "订阅链接不能为空");
  }

  if (/\s/.test(trimmed)) {
    return invalidRuleReport("url", "订阅链接不能包含空白字符");
  }

  if (!lower.startsWith("https://")) {
    return invalidRuleReport("url", "订阅链接只支持 https://");
  }

  const withoutScheme = trimmed.slice("https://".length);
  const host = withoutScheme.split(/[/?#]/, 1)[0];
  if (host.length === 0 || host.includes("@")) {
    return invalidRuleReport("url", "订阅链接 host 无效");
  }

  const path = withoutScheme.split(/[?#]/, 1)[0].toLowerCase();
  if (path.endsWith(".txt")) {
    return invalidRuleReport("url", "MVP 不支持 .txt 订阅，请使用 .yaml、.yml 或 .ini");
  }

  if (!path.endsWith(".yaml") && !path.endsWith(".yml") && !path.endsWith(".ini")) {
    return invalidRuleReport("url", "订阅链接必须指向 .yaml、.yml 或 .ini 文件");
  }

  return {
    valid: true,
    ruleCount: 0,
    errors: [],
    warnings: []
  };
}

function invalidRuleReport(field: string, message: string): RuleValidationReport {
  return {
    valid: false,
    ruleCount: 0,
    errors: [
      {
        ruleId: null,
        field,
        message
      }
    ],
    warnings: []
  };
}

export async function buildAiScanSummary(snapshot: ScanSnapshot): Promise<import("./types").RedactedScanSummary> {
  return await invoke<import("./types").RedactedScanSummary>("build_ai_scan_summary", { snapshot });
}

export async function listAiProviderProfiles(): Promise<AiProviderProfile[]> {
  return await invoke<AiProviderProfile[]>("list_ai_provider_profiles");
}

export async function saveAiProviderProfile(profile: AiProviderProfile): Promise<AiProviderProfile[]> {
  return await invoke<AiProviderProfile[]>("save_ai_provider_profile", { profile });
}

export async function deleteAiProviderProfile(profileId: string): Promise<AiProviderProfile[]> {
  return await invoke<AiProviderProfile[]>("delete_ai_provider_profile", { profileId });
}

export async function saveAiProviderCredential(profileId: string, secret: string): Promise<void> {
  await invoke("save_ai_provider_credential", { profileId, secret });
}

export async function deleteAiProviderCredential(profileId: string): Promise<void> {
  await invoke("delete_ai_provider_credential", { profileId });
}

export async function listAiProviderModels(
  query: AiProviderModelQuery
): Promise<import("./types").AiProviderModel[]> {
  return await invoke<import("./types").AiProviderModel[]>("list_ai_provider_models", { query });
}

export async function testAiProviderConnection(
  query: AiProviderModelQuery
): Promise<AiProviderConnectionResult> {
  return await invoke<AiProviderConnectionResult>("test_ai_provider_connection", { query });
}

export async function generateAiRules(
  profileId: string,
  request: AiProviderGenerationRequest
): Promise<AiProviderGenerationResponse> {
  return await invoke<AiProviderGenerationResponse>("generate_ai_rules", { profileId, request });
}

export async function cancelAiRuleGeneration(): Promise<void> {
  await invoke("cancel_ai_rule_generation");
}

export async function reviseAiRuleDraft(
  draft: AiRuleDraft,
  expectedRevision: number,
  rules: AiGeneratedRuleSet
): Promise<AiRuleDraft> {
  return await invoke<AiRuleDraft>("revise_ai_rule_draft", { draft, expectedRevision, rules });
}

export async function validateAiRuleDraft(
  draft: AiRuleDraft,
  expectedRevision: number,
  expectedSummaryHash: string
): Promise<AiRuleDraft> {
  return await invoke<AiRuleDraft>("validate_ai_rule_draft", {
    draft,
    expectedRevision,
    expectedSummaryHash
  });
}

export async function approveAiRuleDraft(
  draft: AiRuleDraft,
  expectedRevision: number,
  expectedSummaryHash: string
): Promise<ApprovedRuleEnvelope> {
  return await invoke<ApprovedRuleEnvelope>("approve_ai_rule_draft", {
    draft,
    expectedRevision,
    expectedSummaryHash
  });
}

export async function getAutomationConfig(): Promise<AutomationConfig> {
  return await invoke<AutomationConfig>("get_automation_config");
}

export async function saveAutomationConfig(config: AutomationConfig): Promise<AutomationConfig> {
  return await invoke<AutomationConfig>("save_automation_config", {
    expectedRevision: config.revision,
    config: { ...config, updatedAt: new Date().toISOString() }
  });
}

export async function getAutomationSchedulerStatus(): Promise<AutomationSchedulerStatus> {
  return await invoke<AutomationSchedulerStatus>("get_automation_scheduler_status");
}

export async function listAutomationReports(): Promise<AutomationRunReport[]> {
  return await invoke<AutomationRunReport[]>("list_automation_reports");
}

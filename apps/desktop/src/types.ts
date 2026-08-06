export type ObjectType = "file" | "directory" | "virtualGroup";
export type RiskLevel = "safeRecommended" | "cautiousRecommended" | "reviewRequired" | "blocked";
export type DeleteStrategy = "moveToRecycleBin" | "permanentDelete" | "skip";
export type CleanupProgressStatus =
  | "preparing"
  | "cleaning"
  | "paused"
  | "cleaned"
  | "skipped"
  | "failed"
  | "canceled"
  | "complete";
export type CleanupItemStatus = "cleaned" | "skipped" | "failed";
export type RuleSourceKind = "builtIn" | "user" | "subscription";
export type RuleLevel = "recommended" | "cautious" | "reviewRequired";
export type RuleCleanupMethod = "contents" | "files" | "recycle" | "manual";
export type SourceKind = "browser" | "windows" | "installedApp" | "storeApp" | "game" | "devTool" | "project" | "unknown";

export interface VolumeInfo {
  id: string;
  label: string;
  mountPoint: string;
  filesystem: string;
  totalBytes: number;
  availableBytes: number;
  selected: boolean;
  supportsFastIndex: boolean;
}

export interface CleanupCandidate {
  id: string;
  parentId: string | null;
  displayName: string;
  path: string;
  volumeId: string;
  objectType: ObjectType;
  category: string;
  sizeBytes: number;
  childrenCount: number;
  riskLevel: RiskLevel;
  defaultSelected: boolean;
  selected: boolean;
  deleteStrategy: DeleteStrategy;
  reason: string;
  confidence: number;
  source: SourceInfo;
  cleanupPolicy: CleanupPolicy;
}

export interface SourceInfo {
  label: string;
  kind: SourceKind;
  confidence: number;
  evidence: string;
}

export interface ScanSummary {
  estimatedReclaimBytes: number;
  candidateCount: number;
  lockedCount: number;
  progressPercent: number;
  selectedCount: number;
  selectedBytes: number;
}

export interface ScanSnapshot {
  volumes: VolumeInfo[];
  candidates: CleanupCandidate[];
  selectedCandidateId: string;
  summary: ScanSummary;
  scanBackend: string;
  warnings: string[];
  scanSessionId: string | null;
  coverage: ScanCoverage;
  spaceSummary: VolumeSpaceSummary[];
}

export type ScanCoverageStatus = "notStarted" | "complete" | "partial" | "cancelled" | "failed";
export type CoverageGapReason =
  | "accessDenied"
  | "disappeared"
  | "invalidMetadata"
  | "reparseNotFollowed"
  | "identityFallback"
  | "backendFallback"
  | "resourceLimit";
export type InventoryDisposition = "normal" | "analysisOnly" | "blocked";
export type InventoryObjectType = "file" | "directory" | "reparsePoint" | "other";
export type InventorySort = "name" | "logicalBytes" | "allocatedBytes";

export interface CoverageGap {
  volumeId: string;
  reason: CoverageGapReason;
  pathHint?: string;
  count: number;
}

export interface VolumeCoverage {
  volumeId: string;
  backend: string;
  status: ScanCoverageStatus;
  visitedEntries: number;
  indexedEntries: number;
  logicalBytes: number;
  allocatedBytes: number;
  gaps: CoverageGap[];
}

export interface ScanCoverage {
  status: ScanCoverageStatus;
  visitedEntries: number;
  indexedEntries: number;
  logicalBytes: number;
  allocatedBytes: number;
  volumes: VolumeCoverage[];
  gaps: CoverageGap[];
}

export interface VolumeSpaceSummary {
  volumeId: string;
  logicalBytes: number;
  allocatedBytes: number;
  fileCount: number;
  directoryCount: number;
  analysisOnlyCount: number;
  blockedCount: number;
}

export interface InventoryQueryItem {
  entryId: string;
  parentEntryId: string | null;
  volumeId: string;
  name: string;
  path: string;
  objectType: InventoryObjectType;
  logicalBytes: number;
  allocatedBytes: number;
  disposition: InventoryDisposition;
  allocationOwner: boolean;
  hasChildren: boolean;
}

export interface InventoryPage {
  items: InventoryQueryItem[];
  nextCursor: string | null;
}

export interface CleanupPlan {
  selectedCount: number;
  skippedLockedCount: number;
  estimatedReclaimBytes: number;
  deleteStrategy: DeleteStrategy;
  warnings: string[];
}

export interface CleanupReport {
  requestedCount: number;
  cleanedCount: number;
  skippedLockedCount: number;
  failedCount: number;
  cancelled: boolean;
  reclaimedBytes: number;
  cleanedIds: string[];
  skippedIds: string[];
  failedIds: string[];
  deleteStrategy: DeleteStrategy;
  warnings: string[];
  itemResults: CleanupReportItem[];
}

export interface CleanupReportItem {
  id: string;
  displayName: string;
  path: string;
  source: SourceInfo;
  status: CleanupItemStatus;
  reclaimedBytes: number;
  reason: string;
}

export interface CleanupProgress {
  processedCount: number;
  totalCount: number;
  percent: number;
  currentId: string;
  currentPath: string;
  status: CleanupProgressStatus;
}

export type ScanPhase = "preparing" | "indexing" | "walking" | "analyzing" | "complete";

export interface ScanProgress {
  phase: ScanPhase;
  scannedFiles: number;
  candidateCount: number;
  reclaimableBytes: number;
  currentPath: string;
  currentVolume: string;
  totalFiles: number | null;
  percent: number | null;
}

export type RiskFilter = "all" | "recommended" | "caution" | "dangerous";
export type ScanMode = "quick" | "full";
export type ScanStatus = "idle" | "scanning" | "paused" | "complete" | "failed";
export type CleanupStatus = "idle" | "running" | "paused" | "canceling" | "complete" | "cancelled" | "failed";
export type AppLogKind = "scan" | "cleanup" | "operation";
export type LogFilter = AppLogKind | "all";

export interface AdminStatus {
  isAdmin: boolean;
  canRestartElevated: boolean;
}

export interface ScanRequest {
  mode: ScanMode;
  volumeIds: string[];
  rules: CompiledCleanupRule[];
}

export interface CleanupPolicy {
  ruleId: string | null;
  method: RuleCleanupMethod;
  keepDays: number;
  excludePatterns: string[];
}

export interface AppLogEntry {
  id: string;
  kind: AppLogKind;
  time: string;
  title: string;
  message: string;
  detail?: string;
}

export interface CompiledCleanupRule {
  id: string;
  name: string;
  app: string;
  category: string;
  level: RuleLevel;
  riskLevel: RiskLevel;
  defaultSelected: boolean;
  requiresDefaultConfirmation: boolean;
  paths: string[];
  clean: RuleCleanupMethod;
  keepDays: number;
  close: string[];
  exclude: string[];
  mandatoryExclude: string[];
  note: string;
  source: RuleSourceKind;
  warnings: string[];
}

export interface RuleValidationIssue {
  ruleId: string | null;
  field: string;
  message: string;
}

export interface RuleValidationReport {
  valid: boolean;
  ruleCount: number;
  errors: RuleValidationIssue[];
  warnings: RuleValidationIssue[];
}

export interface RuleCompilation {
  rules: CompiledCleanupRule[];
  report: RuleValidationReport;
}

export interface StoredRuleSubscription {
  url: string;
  content: string;
  checkedAt: string;
}

export type AiRuleTier = "light" | "medium" | "heavy";
export type AiGenerationMode = "allTiers" | "singleTier";
export type AiRuleCleanMethod = "contents" | "files" | "recycle" | "manual";
export type AiProviderKind = "openAiCompatible" | "anthropicCompatible";
export type AiSessionEventKind = "preview" | "probe" | "generate" | "error";
export type AiProviderErrorCategory =
  | "configuration"
  | "credentialMissing"
  | "authentication"
  | "rateLimited"
  | "timeout"
  | "cancelled"
  | "network"
  | "responseTooLarge"
  | "invalidSchema"
  | "provider";

export interface RedactedScanBucket {
  sourceKind: string;
  riskLevel: string;
  category: string;
  candidateCount: number;
  totalBytes: number;
  sizeBand: string;
}

export interface RedactedScanSummary {
  schemaVersion: number;
  redactionVersion: number;
  scanMode: string;
  buckets: RedactedScanBucket[];
  riskSignals: string[];
  omittedCount: number;
  truncated: boolean;
  summaryHash: string;
}

export interface AiProviderProfile {
  id: string;
  kind: AiProviderKind;
  displayName: string;
  baseUrl: string;
  model: string;
  timeoutMs: number;
  credentialPresent: boolean;
}

export interface AiProviderModel {
  id: string;
  displayName: string | null;
}

export interface AiProviderConnectionResult {
  modelCount: number;
}

/**
 * Model discovery targets the profile form as it is being edited, because a
 * profile cannot be saved before a model is picked.
 */
export interface AiProviderModelQuery {
  kind: AiProviderKind;
  baseUrl: string;
  timeoutMs: number;
  profileId: string | null;
  apiKey: string | null;
}

export interface AiGeneratedRule {
  id: string;
  tier: AiRuleTier;
  name: string;
  app: string;
  category: string;
  paths: string[];
  clean: AiRuleCleanMethod;
  keepDays: number;
  exclude: string[];
  note: string;
  evidence: string[];
  cautions: string[];
}

export interface AiGeneratedRuleSet {
  schemaVersion: number;
  rules: AiGeneratedRule[];
}

export interface AiProviderGenerationRequest {
  summary: RedactedScanSummary;
  generationMode: AiGenerationMode;
  /** Required for `singleTier`; null for `allTiers`. */
  targetTier: AiRuleTier | null;
}

export interface AiProviderGenerationResponse {
  requestId: string | null;
  draft: AiRuleDraft;
}

export interface AiProviderGenerationProbeQuery {
  kind: AiProviderKind;
  baseUrl: string;
  timeoutMs: number;
  model: string;
  profileId: string | null;
  apiKey: string | null;
}

export interface AiProviderGenerationProbeResult {
  ok: boolean;
  latencyMs: number;
  requestId: string | null;
}

export interface AiProviderError {
  category: AiProviderErrorCategory;
  message: string;
  retryAfterSeconds: number | null;
}

export interface AiRuleDraft {
  schemaVersion: number;
  redactionVersion: number;
  id: string;
  revision: number;
  validationRevision: number | null;
  summaryHash: string;
  generationMode: AiGenerationMode;
  targetTier: AiRuleTier | null;
  providerProfileId: string;
  model: string;
  generatedAt: string;
  rules: AiGeneratedRuleSet;
  compilation: RuleCompilation | null;
}

export interface ApprovedRuleEnvelope {
  schemaVersion: number;
  redactionVersion: number;
  draftId: string;
  revision: number;
  summaryHash: string;
  generationMode: AiGenerationMode;
  targetTier: AiRuleTier | null;
  providerProfileId: string;
  model: string;
  generatedAt: string;
  rules: AiGeneratedRuleSet;
  compilation: RuleCompilation;
}

export interface AiSessionEvent {
  at: string;
  kind: AiSessionEventKind;
  summaryHash?: string;
  mode?: AiGenerationMode;
  model?: string;
  latencyMs?: number;
  ruleCount?: number;
  message: string;
}

export type RuleOrigin = "manual" | "aiGenerated" | "subscription" | "legacyMigration" | "imported";
export type RuleRecordState = "draft" | "approved" | "disabled" | "deleted";
export type RuleLibraryLoadStatus =
  | "ready"
  | "empty"
  | "recoveredFromBackup"
  | "corruptNoRecovery"
  | "unsupportedSchema";
export type RuleLibraryEventKind =
  | "createDraft"
  | "saveDraft"
  | "approve"
  | "disable"
  | "delete"
  | "restore"
  | "rollbackRequested"
  | "import";

export interface RuleProvenance {
  sourceLabel: string;
  providerProfileId: string | null;
  model: string | null;
  scanSummaryHash: string | null;
  sourceUrl: string | null;
  generatedAt: string | null;
  aiDraftId: string | null;
  aiDraftRevision: number | null;
}

export interface RevisionValidation {
  contentHash: string;
  compilerSchemaVersion: number;
  validatedAt: string;
  report: RuleValidationReport;
}

export interface RuleRevision {
  id: string;
  number: number;
  parentRevisionId: string | null;
  baseRevisionId: string | null;
  content: string;
  contentHash: string;
  provenance: RuleProvenance;
  createdAt: string;
  actorId: string;
  mutationId: string;
  validation: RevisionValidation | null;
}

export interface RuleLibraryEvent {
  id: string;
  kind: RuleLibraryEventKind;
  actorId: string;
  mutationId: string;
  occurredAt: string;
  fromState: RuleRecordState | null;
  toState: RuleRecordState;
  fromRevisionId: string | null;
  toRevisionId: string | null;
}

export interface RuleRecord {
  id: string;
  displayName: string;
  origin: RuleOrigin;
  state: RuleRecordState;
  activeRevisionId: string | null;
  pendingRevisionId: string | null;
  lastApprovedRevisionId: string | null;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
  revisions: RuleRevision[];
  events: RuleLibraryEvent[];
}

export interface RuleLibrarySnapshot {
  schemaVersion: number;
  libraryId: string;
  generation: number;
  createdAt: string;
  updatedAt: string;
  deviceId: string;
  actorId: string;
  lastMutationId: string;
  records: RuleRecord[];
}

export interface RuleLibraryLoadResult {
  status: RuleLibraryLoadStatus;
  snapshot: RuleLibrarySnapshot | null;
  notice: string | null;
}

export interface ActiveRuleEntry {
  recordId: string;
  revisionId: string;
  contentHash: string;
  ruleIds: string[];
}

export interface ActiveRuleIssue {
  recordId: string | null;
  revisionId: string | null;
  code: string;
  message: string;
}

export interface ActiveRuleSnapshot {
  libraryGeneration: number;
  rules: CompiledCleanupRule[];
  entries: ActiveRuleEntry[];
  blockingIssues: ActiveRuleIssue[];
}

export type RuleLibraryMutationAction =
  | {
      type: "createDraft";
      displayName: string;
      origin: RuleOrigin;
      content: string;
      provenance: RuleProvenance;
    }
  | {
      type: "importApprovedAiDraft";
      displayName: string;
      envelope: ApprovedRuleEnvelope;
    }
  | {
      type: "saveDraft";
      recordId: string;
      content: string;
      provenance: RuleProvenance;
    }
  | { type: "approve"; recordId: string; expectedHash: string }
  | { type: "disable"; recordId: string }
  | { type: "delete"; recordId: string }
  | { type: "restore"; recordId: string }
  | { type: "rollback"; recordId: string; revisionId: string };

export interface RuleLibraryMutationRequest {
  expectedGeneration: number;
  expectedHeadRevisionId: string | null;
  mutationId: string;
  actorId: string;
  deviceId: string;
  timestamp: string;
  action: RuleLibraryMutationAction;
}

export type AutomationMode = "scanOnly" | "scanAndCleanup";
export type AutomationCadence = "daily" | "weekly";
export type AutomationTrigger = "manual" | "startup" | "scheduled";
export type AutomationReportStatus = "started" | "completed" | "partial" | "failed";
export type AutomationOutcome =
  | "completed"
  | "scanOnly"
  | "partial"
  | "noEligibleItems"
  | "busy"
  | "timedOut"
  | "invalidConfig"
  | "invalidRuleSnapshot"
  | "failed";

export interface AutomationLimits {
  maxWorkItems: number;
  maxBytes: number;
  maxRuntimeSeconds: number;
}

export interface AutomationConfig {
  schemaVersion: number;
  configId: string;
  revision: number;
  startupEnabled: boolean;
  scheduleEnabled: boolean;
  mode: AutomationMode;
  cadence: AutomationCadence;
  localTime: string;
  weekday: number | null;
  notificationsEnabled: boolean;
  limits: AutomationLimits;
  updatedAt: string;
}

export interface AutomationSchedulerStatus {
  startupRegistered: boolean;
  scheduleRegistered: boolean;
}

export interface AutomationRunReport {
  schemaVersion: number;
  runId: string;
  status: AutomationReportStatus;
  trigger: AutomationTrigger;
  mode: AutomationMode;
  outcome: AutomationOutcome | null;
  startedAt: string;
  finishedAt: string | null;
  libraryGeneration: number | null;
  scannedCount: number;
  eligibleCount: number;
  cleanedCount: number;
  reclaimedBytes: number;
  skippedCount: number;
  capped: boolean;
  warnings: string[];
}

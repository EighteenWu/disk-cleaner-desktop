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

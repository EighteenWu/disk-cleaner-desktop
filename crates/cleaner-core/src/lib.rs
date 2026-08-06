use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    sync::{mpsc, Mutex, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime},
};
use sysinfo::Disks;

pub mod ai_rules;
pub mod automation;
pub mod inventory;
pub mod local_rule_library;
pub mod rules;

pub use ai_rules::{
    redacted_scan_summary, AiGeneratedRule, AiGeneratedRuleSet, AiGenerationMode,
    AiRuleCleanMethod, AiRuleDraft, AiRuleTier, ApprovedRuleEnvelope, RedactedScanBucket,
    RedactedScanSummary, AI_REDACTION_VERSION, AI_SUMMARY_SCHEMA_VERSION,
};

pub use automation::*;
pub use inventory::{
    CoverageGap, CoverageGapReason, DirectoryAggregate, InventoryDisposition, InventoryEntry,
    InventoryObjectType, InventoryPage, InventoryQueryItem, InventorySink, InventorySort,
    ScanCoverage, ScanCoverageStatus, VolumeCoverage, VolumeSpaceSummary,
};
pub use local_rule_library::*;

pub use rules::{
    compile_cleanup_rules_yaml, import_winapp2_ini, mandatory_rule_excludes,
    validate_rule_subscription_bytes, validate_rule_subscription_url, CompiledCleanupRule,
    RuleCleanupMethod, RuleCompilation, RuleLevel, RuleSourceKind, RuleValidationIssue,
    RuleValidationReport,
};

const MAX_QUICK_SCAN_ENTRIES: u64 = 25_000;
const MAX_QUICK_SCAN_DEPTH: usize = 10;
#[allow(dead_code)]
const MAX_FULL_SCAN_DEPTH: usize = 96;
#[allow(dead_code)]
const MAX_FULL_SCAN_ENTRIES: u64 = 2_000_000;
#[allow(dead_code)]
const MAX_USN_RECORDS: usize = 2_000_000;
const LARGE_FILE_THRESHOLD_BYTES: u64 = 512 * 1024 * 1024;
const WINDOWS_ERROR_ACCESS_DENIED: u32 = 5;
const MAX_PERMANENT_DELETE_WORKERS: usize = 8;
const MAX_SCAN_WORKERS: usize = 8;
/// Below this many roots the thread setup costs more than the overlap gains.
const MIN_PARALLEL_SCAN_ROOTS: usize = 8;

static BUILT_IN_RULES: OnceLock<Vec<CompiledCleanupRule>> = OnceLock::new();

macro_rules! scan_debug_log {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            eprintln!($($arg)*);
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = format_args!($($arg)*);
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ObjectType {
    File,
    Directory,
    VirtualGroup,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RiskLevel {
    SafeRecommended,
    CautiousRecommended,
    ReviewRequired,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeleteStrategy {
    MoveToRecycleBin,
    PermanentDelete,
    Skip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanMode {
    Quick,
    Full,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CacheDecision {
    AllowClean,
    ReviewClean,
    BlockClean,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceKind {
    Browser,
    Windows,
    InstalledApp,
    StoreApp,
    Game,
    DevTool,
    Project,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceInfo {
    pub label: String,
    pub kind: SourceKind,
    pub confidence: u8,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeInfo {
    pub id: String,
    pub label: String,
    pub mount_point: String,
    pub filesystem: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub selected: bool,
    pub supports_fast_index: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupCandidate {
    pub id: String,
    pub parent_id: Option<String>,
    pub display_name: String,
    pub path: String,
    pub volume_id: String,
    pub object_type: ObjectType,
    pub category: String,
    pub size_bytes: u64,
    pub children_count: u32,
    pub risk_level: RiskLevel,
    pub default_selected: bool,
    pub selected: bool,
    pub delete_strategy: DeleteStrategy,
    pub reason: String,
    pub confidence: u8,
    pub source: SourceInfo,
    #[serde(default)]
    pub cleanup_policy: CleanupPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupPolicy {
    pub rule_id: Option<String>,
    pub method: RuleCleanupMethod,
    pub keep_days: u16,
    pub exclude_patterns: Vec<String>,
}

impl Default for CleanupPolicy {
    fn default() -> Self {
        Self {
            rule_id: None,
            method: RuleCleanupMethod::Contents,
            keep_days: 0,
            exclude_patterns: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub estimated_reclaim_bytes: u64,
    pub candidate_count: u32,
    pub locked_count: u32,
    pub progress_percent: u8,
    pub selected_count: u32,
    pub selected_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSnapshot {
    pub volumes: Vec<VolumeInfo>,
    pub candidates: Vec<CleanupCandidate>,
    pub selected_candidate_id: String,
    pub summary: ScanSummary,
    pub scan_backend: String,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub scan_session_id: Option<String>,
    #[serde(default)]
    pub coverage: ScanCoverage,
    #[serde(default)]
    pub space_summary: Vec<VolumeSpaceSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub mode: ScanMode,
    pub volume_ids: Vec<String>,
    #[serde(default)]
    pub rules: Vec<CompiledCleanupRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupPlan {
    pub selected_count: u32,
    pub skipped_locked_count: u32,
    pub estimated_reclaim_bytes: u64,
    pub delete_strategy: DeleteStrategy,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupReport {
    pub requested_count: u32,
    pub cleaned_count: u32,
    pub skipped_locked_count: u32,
    pub failed_count: u32,
    pub cancelled: bool,
    pub reclaimed_bytes: u64,
    pub cleaned_ids: Vec<String>,
    pub skipped_ids: Vec<String>,
    pub failed_ids: Vec<String>,
    pub delete_strategy: DeleteStrategy,
    pub warnings: Vec<String>,
    pub item_results: Vec<CleanupReportItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CleanupItemStatus {
    Cleaned,
    Skipped,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupReportItem {
    pub id: String,
    pub display_name: String,
    pub path: String,
    pub source: SourceInfo,
    pub status: CleanupItemStatus,
    pub reclaimed_bytes: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupExecutionOptions {
    pub delete_strategy: DeleteStrategy,
}

impl Default for CleanupExecutionOptions {
    fn default() -> Self {
        Self {
            delete_strategy: DeleteStrategy::MoveToRecycleBin,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CleanupProgressStatus {
    Preparing,
    Cleaning,
    Paused,
    Cleaned,
    Skipped,
    Failed,
    Canceled,
    Complete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupProgress {
    pub processed_count: u32,
    pub total_count: u32,
    pub percent: u8,
    pub current_id: String,
    pub current_path: String,
    pub status: CleanupProgressStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupControlFlow {
    Continue,
    Cancel,
}

pub trait CleanupController: Clone + Send + Sync {
    fn is_paused(&self) -> bool {
        false
    }

    fn is_canceled(&self) -> bool {
        false
    }

    fn checkpoint(&self) -> CleanupControlFlow {
        CleanupControlFlow::Continue
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopCleanupController;

impl CleanupController for NoopCleanupController {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanPhase {
    Preparing,
    Indexing,
    Walking,
    Analyzing,
    Complete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub phase: ScanPhase,
    pub scanned_files: u64,
    pub candidate_count: u32,
    pub reclaimable_bytes: u64,
    pub current_path: String,
    pub current_volume: String,
    pub total_files: Option<u64>,
    pub percent: Option<u8>,
}

pub trait ScanController: Send + Sync {
    fn checkpoint(&self) {}

    fn on_phase(&self, _phase: ScanPhase) {}

    fn on_total_files(&self, _total: Option<u64>) {}

    fn on_volume(&self, _volume_id: &str) {}

    fn on_location(&self, _path: &Path) {}

    fn on_visited(&self, _count: u64) {}

    fn on_candidate(&self, _size_bytes: u64) {}
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopScanController;

impl ScanController for NoopScanController {}

const SCAN_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug)]
struct ScanProgressState {
    phase: ScanPhase,
    scanned_files: u64,
    candidate_count: u32,
    reclaimable_bytes: u64,
    current_path: String,
    current_volume: String,
    total_files: Option<u64>,
    last_emit: Option<Instant>,
}

impl ScanProgressState {
    fn snapshot(&self) -> ScanProgress {
        ScanProgress {
            phase: self.phase,
            scanned_files: self.scanned_files,
            candidate_count: self.candidate_count,
            reclaimable_bytes: self.reclaimable_bytes,
            current_path: self.current_path.clone(),
            current_volume: self.current_volume.clone(),
            total_files: self.total_files,
            // percent exists only when a real denominator was obtained (NTFS MFT
            // record estimate); the recursive walk cannot know its total up front.
            percent: self.total_files.map(|total| {
                if total == 0 {
                    0
                } else {
                    ((self.scanned_files.saturating_mul(100) / total).min(99)) as u8
                }
            }),
        }
    }
}

struct ScanProgressShared<'a> {
    state: ScanProgressState,
    sink: Box<dyn FnMut(ScanProgress) + Send + 'a>,
}

pub struct ScanProgressController<'a, C: ScanController + ?Sized> {
    inner: &'a C,
    shared: Mutex<ScanProgressShared<'a>>,
}

impl<'a, C: ScanController + ?Sized> ScanProgressController<'a, C> {
    pub fn new<P>(inner: &'a C, sink: P) -> Self
    where
        P: FnMut(ScanProgress) + Send + 'a,
    {
        Self {
            inner,
            shared: Mutex::new(ScanProgressShared {
                state: ScanProgressState {
                    phase: ScanPhase::Preparing,
                    scanned_files: 0,
                    candidate_count: 0,
                    reclaimable_bytes: 0,
                    current_path: String::new(),
                    current_volume: String::new(),
                    total_files: None,
                    last_emit: None,
                },
                sink: Box::new(sink),
            }),
        }
    }

    fn with_shared<F>(&self, apply: F)
    where
        F: FnOnce(&mut ScanProgressState) -> bool,
    {
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let forced = apply(&mut shared.state);
        let due = shared
            .state
            .last_emit
            .map(|last| last.elapsed() >= SCAN_PROGRESS_INTERVAL)
            .unwrap_or(true);

        if forced || due {
            shared.state.last_emit = Some(Instant::now());
            let progress = shared.state.snapshot();
            (shared.sink)(progress);
        }
    }

    fn begin(&self) {
        self.with_shared(|state| {
            state.phase = ScanPhase::Preparing;
            true
        });
    }

    fn finish(&self) {
        self.with_shared(|state| {
            state.phase = ScanPhase::Complete;
            state.current_path = String::new();
            true
        });
    }

    #[cfg(test)]
    fn set_total_files(&self, total: Option<u64>) {
        self.on_total_files(total);
    }
}

impl<C: ScanController + ?Sized> ScanController for ScanProgressController<'_, C> {
    fn checkpoint(&self) {
        self.inner.checkpoint();
    }

    fn on_phase(&self, phase: ScanPhase) {
        self.with_shared(|state| {
            let changed = state.phase != phase;
            state.phase = phase;
            changed
        });
    }

    fn on_total_files(&self, total: Option<u64>) {
        self.with_shared(|state| {
            state.total_files = total;
            true
        });
    }

    fn on_volume(&self, volume_id: &str) {
        self.with_shared(|state| {
            let changed = state.current_volume != volume_id;
            if changed {
                state.current_volume = volume_id.to_string();
            }
            changed
        });
    }

    fn on_location(&self, path: &Path) {
        // Called once per visited entry, so only pay for the path allocation when
        // the throttle window is already open.
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let due = shared
            .state
            .last_emit
            .map(|last| last.elapsed() >= SCAN_PROGRESS_INTERVAL)
            .unwrap_or(true);
        if !due {
            return;
        }

        shared.state.current_path = path.to_string_lossy().to_string();
        shared.state.last_emit = Some(Instant::now());
        let progress = shared.state.snapshot();
        (shared.sink)(progress);
    }

    fn on_visited(&self, count: u64) {
        self.with_shared(|state| {
            state.scanned_files = state.scanned_files.saturating_add(count);
            false
        });
    }

    fn on_candidate(&self, size_bytes: u64) {
        self.with_shared(|state| {
            state.candidate_count = state.candidate_count.saturating_add(1);
            state.reclaimable_bytes = state.reclaimable_bytes.saturating_add(size_bytes);
            false
        });
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheClassification {
    pub decision: CacheDecision,
    pub risk_level: RiskLevel,
    pub default_selected: bool,
    pub reason: &'static str,
    pub confidence: u8,
}

#[derive(Clone, Debug)]
struct ScanRoot {
    path: PathBuf,
    display_name: String,
    category: String,
    rule: Option<CompiledCleanupRule>,
}

#[derive(Clone, Debug, Default)]
struct DirectoryStats {
    size_bytes: u64,
    children_count: u32,
    truncated: bool,
}

#[derive(Default)]
struct ScanStatsCache {
    directory_stats: HashMap<String, DirectoryStats>,
    policy_directory_stats: HashMap<String, DirectoryStats>,
}

#[derive(Clone, Debug)]
struct ScanRun {
    candidates: Vec<CleanupCandidate>,
    backend: String,
    warnings: Vec<String>,
    coverage: ScanCoverage,
    space_summary: Vec<VolumeSpaceSummary>,
}

#[derive(Clone, Debug)]
struct VolumeScanRun {
    candidates: Vec<CleanupCandidate>,
    backend: String,
    warnings: Vec<String>,
    coverage: VolumeCoverage,
    space_summary: VolumeSpaceSummary,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct FullWalkContext {
    volume: VolumeInfo,
    candidates: Vec<CleanupCandidate>,
    visited_entries: u64,
    warnings: Vec<String>,
    truncated: bool,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct UsnEntry {
    parent_reference: u64,
    name: String,
    attributes: u32,
}

pub fn scan_snapshot() -> ScanSnapshot {
    scan_snapshot_with_request(ScanRequest {
        mode: ScanMode::Quick,
        volume_ids: Vec::new(),
        rules: Vec::new(),
    })
}

pub fn initial_scan_snapshot() -> ScanSnapshot {
    let volumes = detected_volumes();
    let candidates = Vec::new();

    ScanSnapshot {
        volumes,
        candidates: candidates.clone(),
        selected_candidate_id: String::new(),
        summary: summarize_with_progress(&candidates, 0),
        scan_backend: "idle".to_string(),
        warnings: Vec::new(),
        scan_session_id: None,
        coverage: ScanCoverage::default(),
        space_summary: Vec::new(),
    }
}

pub fn scan_snapshot_with_request(request: ScanRequest) -> ScanSnapshot {
    let control = NoopScanController;
    scan_snapshot_with_request_and_control(request, &control)
}

pub fn scan_snapshot_with_request_and_progress<C, P>(
    request: ScanRequest,
    control: &C,
    on_progress: P,
) -> ScanSnapshot
where
    C: ScanController + ?Sized,
    P: FnMut(ScanProgress) + Send,
{
    let reporter = ScanProgressController::new(control, on_progress);
    reporter.begin();
    let snapshot = scan_snapshot_with_request_and_control(request, &reporter);
    reporter.finish();
    snapshot
}

pub fn scan_snapshot_with_request_and_progress_and_inventory<C, P>(
    request: ScanRequest,
    session_id: &str,
    control: &C,
    sink: &mut dyn InventorySink,
    on_progress: P,
) -> ScanSnapshot
where
    C: ScanController + ?Sized,
    P: FnMut(ScanProgress) + Send,
{
    let reporter = ScanProgressController::new(control, on_progress);
    reporter.begin();
    let snapshot = scan_snapshot_with_request_and_control_and_inventory(
        request,
        &reporter,
        Some(session_id),
        sink,
    );
    reporter.finish();
    snapshot
}

pub fn scan_snapshot_with_request_and_control<C: ScanController + ?Sized>(
    request: ScanRequest,
    control: &C,
) -> ScanSnapshot {
    let mut sink = inventory::NullInventorySink;
    scan_snapshot_with_request_and_control_and_inventory(request, control, None, &mut sink)
}

fn scan_snapshot_with_request_and_control_and_inventory<C: ScanController + ?Sized>(
    request: ScanRequest,
    control: &C,
    session_id: Option<&str>,
    sink: &mut dyn InventorySink,
) -> ScanSnapshot {
    control.checkpoint();
    control.on_phase(ScanPhase::Preparing);
    let volumes = detected_volumes();
    control.checkpoint();
    let selected_volumes = apply_volume_selection(volumes, &request.volume_ids);
    let scan_run = scan_candidates_with_control(
        &selected_volumes,
        request.mode,
        &request.rules,
        control,
        session_id,
        sink,
    );
    let candidates = scan_run.candidates;
    let summary = summarize_with_progress(&candidates, 100);
    let selected_candidate_id = candidates
        .first()
        .map(|candidate| candidate.id.clone())
        .unwrap_or_default();

    ScanSnapshot {
        volumes: selected_volumes,
        candidates,
        selected_candidate_id,
        summary,
        scan_backend: scan_run.backend,
        warnings: scan_run.warnings,
        scan_session_id: session_id.map(str::to_string),
        coverage: scan_run.coverage,
        space_summary: scan_run.space_summary,
    }
}

pub fn scan_candidate_children(candidate_id: &str) -> Vec<CleanupCandidate> {
    let snapshot = scan_snapshot();
    let Some(parent) = snapshot
        .candidates
        .iter()
        .find(|candidate| candidate.id == candidate_id)
    else {
        return sample_candidate_children(candidate_id);
    };

    if parent.object_type != ObjectType::Directory {
        return Vec::new();
    }

    list_real_candidate_children(parent)
}

pub fn scan_candidate_children_for_candidate(parent: &CleanupCandidate) -> Vec<CleanupCandidate> {
    if parent.object_type != ObjectType::Directory {
        return Vec::new();
    }

    list_real_candidate_children(parent)
}

pub fn preview_current_cleanup(request: ScanRequest, selected_ids: &[String]) -> CleanupPlan {
    let snapshot = scan_snapshot_with_request(request);

    preview_cleanup_for_candidates(&snapshot.candidates, selected_ids)
}

pub fn execute_current_cleanup(request: ScanRequest, selected_ids: &[String]) -> CleanupReport {
    let snapshot = scan_snapshot_with_request(request);

    execute_cleanup_for_candidates(snapshot.candidates, selected_ids)
}

pub fn execute_cleanup_for_candidates(
    candidates: Vec<CleanupCandidate>,
    selected_ids: &[String],
) -> CleanupReport {
    execute_cleanup_for_candidates_with_options(
        candidates,
        selected_ids,
        CleanupExecutionOptions::default(),
    )
}

pub fn execute_cleanup_for_candidates_with_options(
    candidates: Vec<CleanupCandidate>,
    selected_ids: &[String],
    options: CleanupExecutionOptions,
) -> CleanupReport {
    let delete_strategy = executable_delete_strategy(options.delete_strategy);
    execute_cleanup_with_mover(
        candidates,
        selected_ids,
        delete_strategy.clone(),
        delete_executor_for_strategy(delete_strategy),
    )
}

pub fn execute_cleanup_for_candidates_with_progress<P>(
    candidates: Vec<CleanupCandidate>,
    selected_ids: &[String],
    options: CleanupExecutionOptions,
    on_progress: P,
) -> CleanupReport
where
    P: FnMut(CleanupProgress),
{
    execute_cleanup_for_candidates_with_progress_and_control(
        candidates,
        selected_ids,
        options,
        NoopCleanupController,
        on_progress,
    )
}

pub fn execute_cleanup_for_candidates_with_progress_and_control<P, C>(
    candidates: Vec<CleanupCandidate>,
    selected_ids: &[String],
    options: CleanupExecutionOptions,
    control: C,
    mut on_progress: P,
) -> CleanupReport
where
    P: FnMut(CleanupProgress),
    C: CleanupController,
{
    let delete_strategy = executable_delete_strategy(options.delete_strategy);
    execute_cleanup_with_mover_and_progress_controlled(
        candidates,
        selected_ids,
        delete_strategy.clone(),
        delete_executor_for_strategy(delete_strategy),
        control,
        &mut on_progress,
    )
}

fn execute_cleanup_with_mover<F>(
    candidates: Vec<CleanupCandidate>,
    selected_ids: &[String],
    delete_strategy: DeleteStrategy,
    mut delete_path: F,
) -> CleanupReport
where
    F: FnMut(&Path) -> Result<(), String>,
{
    let mut ignore_progress = |_progress: CleanupProgress| {};

    execute_cleanup_with_mover_and_progress_controlled(
        candidates,
        selected_ids,
        delete_strategy,
        &mut delete_path,
        NoopCleanupController,
        &mut ignore_progress,
    )
}

#[cfg(test)]
fn execute_cleanup_with_mover_and_progress<F, P>(
    candidates: Vec<CleanupCandidate>,
    selected_ids: &[String],
    delete_strategy: DeleteStrategy,
    delete_path: F,
    on_progress: &mut P,
) -> CleanupReport
where
    F: FnMut(&Path) -> Result<(), String>,
    P: FnMut(CleanupProgress),
{
    execute_cleanup_with_mover_and_progress_controlled(
        candidates,
        selected_ids,
        delete_strategy,
        delete_path,
        NoopCleanupController,
        on_progress,
    )
}

fn execute_cleanup_with_mover_and_progress_controlled<F, P, C>(
    candidates: Vec<CleanupCandidate>,
    selected_ids: &[String],
    delete_strategy: DeleteStrategy,
    mut delete_path: F,
    control: C,
    on_progress: &mut P,
) -> CleanupReport
where
    F: FnMut(&Path) -> Result<(), String>,
    P: FnMut(CleanupProgress),
    C: CleanupController,
{
    let selected_lookup = selected_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let selected_candidates = candidates
        .into_iter()
        .filter(|candidate| selected_lookup.contains(candidate.id.as_str()))
        .collect::<Vec<_>>();
    let mut cleaned_ids = Vec::new();
    let mut skipped_ids = Vec::new();
    let mut failed_ids = Vec::new();
    let mut reclaimed_bytes = 0_u64;
    let mut warnings = Vec::new();
    let mut item_results = Vec::new();
    let mut cancelled = false;
    let total_work_units = selected_candidates
        .iter()
        .map(cleanup_work_units)
        .fold(0_u32, u32::saturating_add);
    let mut progress = CleanupProgressReporter::new(total_work_units, on_progress);

    progress.emit_current("", "", CleanupProgressStatus::Preparing);

    for (candidate_index, candidate) in selected_candidates.iter().enumerate() {
        if !cleanup_control_checkpoint(&control, &mut progress) {
            cancelled = true;
            push_cancelled_cleanup_items(
                &selected_candidates[candidate_index..],
                &mut skipped_ids,
                &mut warnings,
                &mut item_results,
            );
            break;
        }

        if candidate.risk_level == RiskLevel::Blocked
            || candidate.delete_strategy == DeleteStrategy::Skip
        {
            progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
            skipped_ids.push(candidate.id.clone());
            let warning = format!(
                "{} 已锁定或策略为跳过，未执行清理。",
                candidate.display_name
            );
            item_results.push(cleanup_report_item(
                candidate,
                CleanupItemStatus::Skipped,
                0,
                &warning,
            ));
            warnings.push(warning);
            continue;
        }

        let candidate_delete_strategy =
            effective_delete_strategy_for_candidate(candidate, &delete_strategy);

        match cleanup_candidate(
            candidate,
            &candidate_delete_strategy,
            &mut delete_path,
            &mut progress,
            &control,
        ) {
            CandidateCleanupOutcome::Cleaned {
                reclaimed_bytes: bytes,
                warnings: candidate_warnings,
            } => {
                reclaimed_bytes = reclaimed_bytes.saturating_add(bytes);
                cleaned_ids.push(candidate.id.clone());
                item_results.push(cleanup_report_item(
                    candidate,
                    CleanupItemStatus::Cleaned,
                    bytes,
                    &cleaned_reason_for_strategy(&candidate_delete_strategy, &candidate_warnings),
                ));
                warnings.extend(candidate_warnings);
            }
            CandidateCleanupOutcome::Skipped { warning } => {
                skipped_ids.push(candidate.id.clone());
                item_results.push(cleanup_report_item(
                    candidate,
                    CleanupItemStatus::Skipped,
                    0,
                    &warning,
                ));
                warnings.push(warning);
            }
            CandidateCleanupOutcome::Failed { warning } => {
                failed_ids.push(candidate.id.clone());
                item_results.push(cleanup_report_item(
                    candidate,
                    CleanupItemStatus::Failed,
                    0,
                    &warning,
                ));
                warnings.push(warning);
            }
        }

        if control.is_canceled() {
            cancelled = true;
            push_cancelled_cleanup_items(
                &selected_candidates[(candidate_index + 1)..],
                &mut skipped_ids,
                &mut warnings,
                &mut item_results,
            );
            break;
        }
    }

    if cancelled {
        progress.cancel();
    } else {
        progress.complete();
    }

    let mut report_warnings = vec![
        cleanup_started_message(&delete_strategy),
        "目录候选会清理其直接子项并保留目录本身；系统保护路径和状态数据会跳过。".to_string(),
    ];

    if cancelled {
        report_warnings.push("用户已取消清理；未处理项目已跳过。".to_string());
    }

    CleanupReport {
        requested_count: selected_ids.len() as u32,
        cleaned_count: cleaned_ids.len() as u32,
        skipped_locked_count: skipped_ids.len() as u32,
        failed_count: failed_ids.len() as u32,
        cancelled,
        reclaimed_bytes,
        cleaned_ids,
        skipped_ids,
        failed_ids,
        delete_strategy: delete_strategy.clone(),
        warnings: report_warnings.into_iter().chain(warnings).collect(),
        item_results,
    }
}

fn effective_delete_strategy_for_candidate(
    candidate: &CleanupCandidate,
    requested_strategy: &DeleteStrategy,
) -> DeleteStrategy {
    if is_recycle_bin_path(&normalize_path_for_id(Path::new(&candidate.path))) {
        DeleteStrategy::PermanentDelete
    } else {
        requested_strategy.clone()
    }
}

fn cleanup_control_checkpoint<C, P>(control: &C, progress: &mut CleanupProgressReporter<P>) -> bool
where
    C: CleanupController,
    P: FnMut(CleanupProgress),
{
    if control.is_paused() {
        progress.emit_current("", "", CleanupProgressStatus::Paused);
    }

    control.checkpoint() == CleanupControlFlow::Continue
}

fn push_cancelled_cleanup_items(
    candidates: &[CleanupCandidate],
    skipped_ids: &mut Vec<String>,
    warnings: &mut Vec<String>,
    item_results: &mut Vec<CleanupReportItem>,
) {
    for candidate in candidates {
        skipped_ids.push(candidate.id.clone());
        let warning = format!("{}：用户取消清理，未处理。", candidate.display_name);
        item_results.push(cleanup_report_item(
            candidate,
            CleanupItemStatus::Skipped,
            0,
            &warning,
        ));
        warnings.push(warning);
    }
}

fn cleanup_report_item(
    candidate: &CleanupCandidate,
    status: CleanupItemStatus,
    reclaimed_bytes: u64,
    reason: &str,
) -> CleanupReportItem {
    CleanupReportItem {
        id: candidate.id.clone(),
        display_name: candidate.display_name.clone(),
        path: candidate.path.clone(),
        source: candidate.source.clone(),
        status,
        reclaimed_bytes,
        reason: reason.to_string(),
    }
}

fn executable_delete_strategy(delete_strategy: DeleteStrategy) -> DeleteStrategy {
    match delete_strategy {
        DeleteStrategy::PermanentDelete => DeleteStrategy::PermanentDelete,
        DeleteStrategy::MoveToRecycleBin | DeleteStrategy::Skip => DeleteStrategy::MoveToRecycleBin,
    }
}

fn delete_executor_for_strategy(
    delete_strategy: DeleteStrategy,
) -> fn(&Path) -> Result<(), String> {
    match delete_strategy {
        DeleteStrategy::PermanentDelete => delete_path_permanently,
        DeleteStrategy::MoveToRecycleBin | DeleteStrategy::Skip => move_path_to_recycle_bin,
    }
}

fn cleanup_started_message(delete_strategy: &DeleteStrategy) -> String {
    match delete_strategy {
        DeleteStrategy::PermanentDelete => "已执行真实清理：符合条件的对象已永久删除。".to_string(),
        DeleteStrategy::MoveToRecycleBin | DeleteStrategy::Skip => {
            "已执行真实清理：符合条件的对象已移动到 Windows 回收站。".to_string()
        }
    }
}

fn cleaned_reason_for_strategy(
    delete_strategy: &DeleteStrategy,
    candidate_warnings: &[String],
) -> String {
    if !candidate_warnings.is_empty() {
        return format!(
            "已清理可处理对象；另有 {} 条子项提示需要关注。",
            candidate_warnings.len()
        );
    }

    match delete_strategy {
        DeleteStrategy::PermanentDelete => "符合清理条件，已永久删除。".to_string(),
        DeleteStrategy::MoveToRecycleBin | DeleteStrategy::Skip => {
            "符合清理条件，已移动到 Windows 回收站。".to_string()
        }
    }
}

fn cleanup_failure_message(
    display_name: &str,
    delete_strategy: &DeleteStrategy,
    error: String,
) -> String {
    match delete_strategy {
        DeleteStrategy::PermanentDelete => format!("{display_name} 永久删除失败：{error}"),
        DeleteStrategy::MoveToRecycleBin | DeleteStrategy::Skip => {
            format!("{display_name} 移动到回收站失败：{error}")
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CandidateCleanupOutcome {
    Cleaned {
        reclaimed_bytes: u64,
        warnings: Vec<String>,
    },
    Skipped {
        warning: String,
    },
    Failed {
        warning: String,
    },
}

#[derive(Debug)]
enum DirectoryCleanupEvent {
    Started(PathBuf),
    Finished(DirectoryChildCleanupResult),
}

#[derive(Debug)]
struct DirectoryChildCleanupResult {
    path: PathBuf,
    status: CleanupProgressStatus,
    reclaimed_bytes: u64,
    warning: Option<String>,
}

struct CleanupProgressReporter<'a, P>
where
    P: FnMut(CleanupProgress),
{
    total_count: u32,
    processed_count: u32,
    on_progress: &'a mut P,
}

impl<'a, P> CleanupProgressReporter<'a, P>
where
    P: FnMut(CleanupProgress),
{
    fn new(total_count: u32, on_progress: &'a mut P) -> Self {
        Self {
            total_count,
            processed_count: 0,
            on_progress,
        }
    }

    fn emit_current(
        &mut self,
        current_id: &str,
        current_path: &str,
        status: CleanupProgressStatus,
    ) {
        (self.on_progress)(CleanupProgress {
            processed_count: self.processed_count,
            total_count: self.total_count,
            percent: cleanup_progress_percent(self.processed_count, self.total_count, status),
            current_id: current_id.to_string(),
            current_path: current_path.to_string(),
            status,
        });
    }

    fn advance_candidate(&mut self, candidate: &CleanupCandidate, status: CleanupProgressStatus) {
        self.advance(&candidate.id, &candidate.path, status);
    }

    fn start_candidate(&mut self, candidate: &CleanupCandidate) {
        self.emit_current(
            &candidate.id,
            &candidate.path,
            CleanupProgressStatus::Cleaning,
        );
    }

    fn start_path(&mut self, candidate: &CleanupCandidate, path: &Path) {
        let current_path = path.to_string_lossy();
        self.emit_current(
            &candidate.id,
            current_path.as_ref(),
            CleanupProgressStatus::Cleaning,
        );
    }

    fn advance_path(
        &mut self,
        candidate: &CleanupCandidate,
        path: &Path,
        status: CleanupProgressStatus,
    ) {
        let current_path = path.to_string_lossy();
        self.advance(&candidate.id, current_path.as_ref(), status);
    }

    fn complete(&mut self) {
        self.processed_count = self.total_count;
        self.emit_current("", "", CleanupProgressStatus::Complete);
    }

    fn cancel(&mut self) {
        self.emit_current("", "", CleanupProgressStatus::Canceled);
    }

    fn advance(&mut self, current_id: &str, current_path: &str, status: CleanupProgressStatus) {
        self.processed_count = self.processed_count.saturating_add(1);
        if self.total_count > 0 {
            self.processed_count = self.processed_count.min(self.total_count);
        }
        self.emit_current(current_id, current_path, status);
    }
}

fn cleanup_progress_percent(
    processed_count: u32,
    total_count: u32,
    status: CleanupProgressStatus,
) -> u8 {
    if status == CleanupProgressStatus::Complete {
        return 100;
    }

    if total_count == 0 {
        return 0;
    }

    if status == CleanupProgressStatus::Cleaning {
        let active_count = processed_count.saturating_add(1).min(total_count);
        return (active_count as u64 * 100)
            .div_ceil(total_count as u64)
            .min(99) as u8;
    }

    ((processed_count.min(total_count) as u64 * 100) / total_count as u64) as u8
}

fn cleanup_work_units(candidate: &CleanupCandidate) -> u32 {
    if candidate.risk_level == RiskLevel::Blocked
        || candidate.delete_strategy == DeleteStrategy::Skip
        || candidate.cleanup_policy.method == RuleCleanupMethod::Manual
    {
        return 1;
    }

    if is_recycle_bin_path(&normalize_path_for_id(Path::new(&candidate.path))) {
        return recycle_bin_cleanup_targets(Path::new(&candidate.path))
            .len()
            .max(1) as u32;
    }

    if candidate.object_type != ObjectType::Directory {
        return 1;
    }

    let entry_count = fs::read_dir(Path::new(&candidate.path))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| {
                    let path = entry.path();
                    fs::symlink_metadata(&path)
                        .map(|metadata| {
                            cleanup_policy_allows_directory_child(
                                &path,
                                &metadata,
                                &candidate.cleanup_policy,
                            )
                            .is_ok()
                        })
                        .unwrap_or(false)
                })
                .count() as u32
        })
        .unwrap_or(1);

    entry_count.max(1)
}

fn cleanup_candidate<F, P, C>(
    candidate: &CleanupCandidate,
    delete_strategy: &DeleteStrategy,
    delete_path: &mut F,
    progress: &mut CleanupProgressReporter<P>,
    control: &C,
) -> CandidateCleanupOutcome
where
    F: FnMut(&Path) -> Result<(), String>,
    P: FnMut(CleanupProgress),
    C: CleanupController,
{
    let path = PathBuf::from(&candidate.path);
    let normalized_path = normalize_path_for_id(&path);

    if candidate.cleanup_policy.method == RuleCleanupMethod::Manual {
        progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
        return CandidateCleanupOutcome::Skipped {
            warning: format!(
                "{} 使用 manual 规则，未执行自动清理。",
                candidate.display_name
            ),
        };
    }

    if is_recycle_bin_path(&normalized_path) {
        return cleanup_recycle_bin_candidate(candidate, &path, progress, control);
    }

    if let Err(warning) = validate_cleanup_target_path(&path) {
        progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
        return CandidateCleanupOutcome::Skipped {
            warning: format!("{}：{}", candidate.display_name, warning),
        };
    }

    let Ok(metadata) = fs::symlink_metadata(&path) else {
        progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
        return CandidateCleanupOutcome::Skipped {
            warning: format!("{} 已不存在，已跳过。", candidate.display_name),
        };
    };

    if is_reparse_point_or_symlink(&metadata) {
        progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
        return CandidateCleanupOutcome::Skipped {
            warning: format!(
                "{} 是链接或 reparse point，已跳过。",
                candidate.display_name
            ),
        };
    }

    if candidate.object_type == ObjectType::File {
        if let Err(warning) =
            cleanup_policy_allows_path(&path, &metadata, &candidate.cleanup_policy)
        {
            progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
            return CandidateCleanupOutcome::Skipped {
                warning: format!("{}：{}", candidate.display_name, warning),
            };
        }
    }

    match candidate.object_type {
        ObjectType::File => {
            progress.start_candidate(candidate);
            let outcome =
                cleanup_file_candidate(candidate, &path, &metadata, delete_strategy, delete_path);
            progress.advance_candidate(candidate, progress_status_for_outcome(&outcome));
            outcome
        }
        ObjectType::Directory => cleanup_directory_candidate(
            candidate,
            &path,
            delete_strategy,
            delete_path,
            progress,
            control,
        ),
        ObjectType::VirtualGroup => {
            progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
            CandidateCleanupOutcome::Skipped {
                warning: format!("{} 是虚拟分组，暂不直接清理。", candidate.display_name),
            }
        }
    }
}

fn cleanup_recycle_bin_candidate<P, C>(
    candidate: &CleanupCandidate,
    path: &Path,
    progress: &mut CleanupProgressReporter<P>,
    control: &C,
) -> CandidateCleanupOutcome
where
    P: FnMut(CleanupProgress),
    C: CleanupController,
{
    let targets = recycle_bin_cleanup_targets(path);

    if targets.is_empty() {
        progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
        return CandidateCleanupOutcome::Skipped {
            warning: format!("{} 为空或没有可安全清理的子项。", candidate.display_name),
        };
    }

    let mut cleaned_any = false;
    let mut failed_any = false;
    let mut reclaimed_bytes = 0_u64;
    let mut warnings = Vec::new();

    for target in targets {
        if !cleanup_control_checkpoint(control, progress) {
            warnings.push(format!(
                "{}：用户取消清理，剩余回收站项目未处理。",
                candidate.display_name
            ));
            break;
        }

        progress.start_path(candidate, &target);
        let result = cleanup_recycle_bin_target_path(target);

        if result.status == CleanupProgressStatus::Cleaned {
            cleaned_any = true;
            reclaimed_bytes = reclaimed_bytes.saturating_add(result.reclaimed_bytes);
        } else if result.status == CleanupProgressStatus::Failed {
            failed_any = true;
        }

        if let Some(warning) = result.warning {
            warnings.push(warning);
        }

        progress.advance_path(candidate, &result.path, result.status);
    }

    if cleaned_any {
        CandidateCleanupOutcome::Cleaned {
            reclaimed_bytes,
            warnings,
        }
    } else if control.is_canceled() {
        CandidateCleanupOutcome::Skipped {
            warning: format!("{}：用户取消清理，未处理。", candidate.display_name),
        }
    } else if failed_any {
        CandidateCleanupOutcome::Failed {
            warning: format!("{} 未能永久删除任何回收站项目。", candidate.display_name),
        }
    } else {
        CandidateCleanupOutcome::Skipped {
            warning: format!("{} 为空或没有可安全清理的子项。", candidate.display_name),
        }
    }
}

fn progress_status_for_outcome(outcome: &CandidateCleanupOutcome) -> CleanupProgressStatus {
    match outcome {
        CandidateCleanupOutcome::Cleaned { .. } => CleanupProgressStatus::Cleaned,
        CandidateCleanupOutcome::Skipped { .. } => CleanupProgressStatus::Skipped,
        CandidateCleanupOutcome::Failed { .. } => CleanupProgressStatus::Failed,
    }
}

fn cleanup_file_candidate<F>(
    candidate: &CleanupCandidate,
    path: &Path,
    metadata: &fs::Metadata,
    delete_strategy: &DeleteStrategy,
    delete_path: &mut F,
) -> CandidateCleanupOutcome
where
    F: FnMut(&Path) -> Result<(), String>,
{
    if !metadata.is_file() {
        return CandidateCleanupOutcome::Skipped {
            warning: format!("{} 的对象类型已变化，已跳过。", candidate.display_name),
        };
    }

    match delete_path(path) {
        Ok(()) => CandidateCleanupOutcome::Cleaned {
            reclaimed_bytes: metadata.len(),
            warnings: Vec::new(),
        },
        Err(error) => CandidateCleanupOutcome::Failed {
            warning: cleanup_failure_message(&candidate.display_name, delete_strategy, error),
        },
    }
}

fn cleanup_directory_candidate<F, P, C>(
    candidate: &CleanupCandidate,
    path: &Path,
    delete_strategy: &DeleteStrategy,
    delete_path: &mut F,
    progress: &mut CleanupProgressReporter<P>,
    control: &C,
) -> CandidateCleanupOutcome
where
    F: FnMut(&Path) -> Result<(), String>,
    P: FnMut(CleanupProgress),
    C: CleanupController,
{
    if matches!(delete_strategy, DeleteStrategy::PermanentDelete) {
        return cleanup_directory_candidate_permanent_parallel(candidate, path, progress, control);
    }

    let Ok(entries) = fs::read_dir(path) else {
        progress.advance_candidate(candidate, CleanupProgressStatus::Failed);
        return CandidateCleanupOutcome::Failed {
            warning: format!("{} 目录无法读取，已跳过。", candidate.display_name),
        };
    };

    let mut moved_any = false;
    let mut failed_any = false;
    let mut processed_entry = false;
    let mut reclaimed_bytes = 0_u64;
    let mut warnings = Vec::new();
    let mut cancelled = false;

    for entry in entries.flatten() {
        if !cleanup_control_checkpoint(control, progress) {
            cancelled = true;
            break;
        }

        processed_entry = true;
        let child_path = entry.path();
        progress.start_path(candidate, &child_path);

        if let Err(warning) = validate_cleanup_target_path(&child_path) {
            warnings.push(format!("{}：{}", child_path.to_string_lossy(), warning));
            progress.advance_path(candidate, &child_path, CleanupProgressStatus::Skipped);
            continue;
        }

        let Ok(metadata) = fs::symlink_metadata(&child_path) else {
            warnings.push(format!(
                "{} 已不存在，已跳过。",
                child_path.to_string_lossy()
            ));
            progress.advance_path(candidate, &child_path, CleanupProgressStatus::Skipped);
            continue;
        };

        if is_reparse_point_or_symlink(&metadata) {
            warnings.push(format!(
                "{} 是链接或 reparse point，已跳过。",
                child_path.to_string_lossy()
            ));
            progress.advance_path(candidate, &child_path, CleanupProgressStatus::Skipped);
            continue;
        }

        if let Err(warning) =
            cleanup_policy_allows_directory_child(&child_path, &metadata, &candidate.cleanup_policy)
        {
            warnings.push(format!("{}：{}", child_path.to_string_lossy(), warning));
            progress.advance_path(candidate, &child_path, CleanupProgressStatus::Skipped);
            continue;
        }

        let child_size = if metadata.is_dir() {
            scan_directory_stats(&child_path).size_bytes
        } else {
            metadata.len()
        };

        match delete_path(&child_path) {
            Ok(()) => {
                moved_any = true;
                reclaimed_bytes = reclaimed_bytes.saturating_add(child_size);
                progress.advance_path(candidate, &child_path, CleanupProgressStatus::Cleaned);
            }
            Err(error) => {
                failed_any = true;
                warnings.push(cleanup_failure_message(
                    child_path.to_string_lossy().as_ref(),
                    delete_strategy,
                    error,
                ));
                progress.advance_path(candidate, &child_path, CleanupProgressStatus::Failed);
            }
        }
    }

    if moved_any {
        if cancelled {
            warnings.push(format!(
                "{}：用户取消清理，剩余子项未处理。",
                candidate.display_name
            ));
        }

        CandidateCleanupOutcome::Cleaned {
            reclaimed_bytes,
            warnings,
        }
    } else if cancelled {
        CandidateCleanupOutcome::Skipped {
            warning: format!("{}：用户取消清理，未处理。", candidate.display_name),
        }
    } else if failed_any {
        CandidateCleanupOutcome::Failed {
            warning: match delete_strategy {
                DeleteStrategy::PermanentDelete => {
                    format!("{} 未能永久删除任何子项。", candidate.display_name)
                }
                DeleteStrategy::MoveToRecycleBin | DeleteStrategy::Skip => {
                    format!("{} 未能移动任何子项到回收站。", candidate.display_name)
                }
            },
        }
    } else {
        if !processed_entry {
            progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
        }
        CandidateCleanupOutcome::Skipped {
            warning: format!("{} 为空或没有可安全清理的子项。", candidate.display_name),
        }
    }
}

fn cleanup_directory_candidate_permanent_parallel<P, C>(
    candidate: &CleanupCandidate,
    path: &Path,
    progress: &mut CleanupProgressReporter<P>,
    control: &C,
) -> CandidateCleanupOutcome
where
    P: FnMut(CleanupProgress),
    C: CleanupController,
{
    let Ok(entries) = fs::read_dir(path) else {
        progress.advance_candidate(candidate, CleanupProgressStatus::Failed);
        return CandidateCleanupOutcome::Failed {
            warning: format!("{} 目录无法读取，已跳过。", candidate.display_name),
        };
    };

    let mut warnings = Vec::new();
    let child_paths = entries
        .flatten()
        .filter_map(|entry| {
            let child_path = entry.path();
            match fs::symlink_metadata(&child_path) {
                Ok(metadata) => {
                    match cleanup_policy_allows_directory_child(
                        &child_path,
                        &metadata,
                        &candidate.cleanup_policy,
                    ) {
                        Ok(()) => Some(child_path),
                        Err(warning) => {
                            warnings.push(format!("{}：{}", child_path.to_string_lossy(), warning));
                            None
                        }
                    }
                }
                Err(_) => Some(child_path),
            }
        })
        .collect::<Vec<_>>();

    if child_paths.is_empty() {
        progress.advance_candidate(candidate, CleanupProgressStatus::Skipped);
        return CandidateCleanupOutcome::Skipped {
            warning: format!("{} 为空或没有可安全清理的子项。", candidate.display_name),
        };
    }

    let worker_count = permanent_delete_worker_count(child_paths.len());
    let chunk_size = child_paths.len().div_ceil(worker_count);
    let (event_sender, event_receiver) = mpsc::channel::<DirectoryCleanupEvent>();
    let mut moved_any = false;
    let mut failed_any = false;
    let mut reclaimed_bytes = 0_u64;
    let cleanup_policy = candidate.cleanup_policy.clone();

    thread::scope(|scope| {
        for chunk in child_paths.chunks(chunk_size) {
            let event_sender = event_sender.clone();
            let paths = chunk.to_vec();
            let control = control.clone();
            let cleanup_policy = cleanup_policy.clone();

            scope.spawn(move || {
                for child_path in paths {
                    if control.checkpoint() == CleanupControlFlow::Cancel {
                        return;
                    }

                    if event_sender
                        .send(DirectoryCleanupEvent::Started(child_path.clone()))
                        .is_err()
                    {
                        return;
                    }

                    if control.checkpoint() == CleanupControlFlow::Cancel {
                        return;
                    }

                    if event_sender
                        .send(DirectoryCleanupEvent::Finished(
                            cleanup_permanent_child_path(child_path, &cleanup_policy),
                        ))
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }

        drop(event_sender);

        for event in event_receiver {
            match event {
                DirectoryCleanupEvent::Started(child_path) => {
                    progress.start_path(candidate, &child_path);
                }
                DirectoryCleanupEvent::Finished(result) => {
                    match result.status {
                        CleanupProgressStatus::Cleaned => {
                            moved_any = true;
                            reclaimed_bytes =
                                reclaimed_bytes.saturating_add(result.reclaimed_bytes);
                        }
                        CleanupProgressStatus::Failed => {
                            failed_any = true;
                        }
                        CleanupProgressStatus::Skipped => {}
                        CleanupProgressStatus::Preparing
                        | CleanupProgressStatus::Cleaning
                        | CleanupProgressStatus::Paused
                        | CleanupProgressStatus::Canceled
                        | CleanupProgressStatus::Complete => {}
                    }

                    if let Some(warning) = result.warning {
                        warnings.push(warning);
                    }

                    progress.advance_path(candidate, &result.path, result.status);
                }
            }
        }
    });

    if moved_any {
        if control.is_canceled() {
            warnings.push(format!(
                "{}：用户取消清理，剩余子项未处理。",
                candidate.display_name
            ));
        }

        CandidateCleanupOutcome::Cleaned {
            reclaimed_bytes,
            warnings,
        }
    } else if control.is_canceled() {
        CandidateCleanupOutcome::Skipped {
            warning: format!("{}：用户取消清理，未处理。", candidate.display_name),
        }
    } else if failed_any {
        CandidateCleanupOutcome::Failed {
            warning: format!("{} 未能永久删除任何子项。", candidate.display_name),
        }
    } else {
        CandidateCleanupOutcome::Skipped {
            warning: format!("{} 为空或没有可安全清理的子项。", candidate.display_name),
        }
    }
}

fn cleanup_permanent_child_path(
    child_path: PathBuf,
    cleanup_policy: &CleanupPolicy,
) -> DirectoryChildCleanupResult {
    if let Err(warning) = validate_cleanup_target_path(&child_path) {
        return DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Skipped,
            reclaimed_bytes: 0,
            warning: Some(format!("{}：{}", child_path.to_string_lossy(), warning)),
        };
    }

    let Ok(metadata) = fs::symlink_metadata(&child_path) else {
        return DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Skipped,
            reclaimed_bytes: 0,
            warning: Some(format!(
                "{} 已不存在，已跳过。",
                child_path.to_string_lossy()
            )),
        };
    };

    if let Err(warning) =
        cleanup_policy_allows_directory_child(&child_path, &metadata, cleanup_policy)
    {
        return DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Skipped,
            reclaimed_bytes: 0,
            warning: Some(format!("{}：{}", child_path.to_string_lossy(), warning)),
        };
    }

    if is_reparse_point_or_symlink(&metadata) {
        return DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Skipped,
            reclaimed_bytes: 0,
            warning: Some(format!(
                "{} 是链接或 reparse point，已跳过。",
                child_path.to_string_lossy()
            )),
        };
    }

    let child_size = if metadata.is_dir() {
        scan_directory_stats(&child_path).size_bytes
    } else {
        metadata.len()
    };

    match delete_path_permanently(&child_path) {
        Ok(()) => DirectoryChildCleanupResult {
            path: child_path,
            status: CleanupProgressStatus::Cleaned,
            reclaimed_bytes: child_size,
            warning: None,
        },
        Err(error) => DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Failed,
            reclaimed_bytes: 0,
            warning: Some(cleanup_failure_message(
                child_path.to_string_lossy().as_ref(),
                &DeleteStrategy::PermanentDelete,
                error,
            )),
        },
    }
}

fn recycle_bin_cleanup_targets(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut targets = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();

        if name.eq_ignore_ascii_case("desktop.ini") {
            continue;
        }

        if path.is_dir() && name.starts_with("S-") {
            if let Ok(sid_entries) = fs::read_dir(&path) {
                targets.extend(
                    sid_entries
                        .flatten()
                        .map(|sid_entry| sid_entry.path())
                        .filter(|sid_path| {
                            sid_path
                                .file_name()
                                .map(|value| {
                                    !value.to_string_lossy().eq_ignore_ascii_case("desktop.ini")
                                })
                                .unwrap_or(true)
                        }),
                );
            }
        } else {
            targets.push(path);
        }
    }

    targets
}

fn cleanup_recycle_bin_target_path(child_path: PathBuf) -> DirectoryChildCleanupResult {
    let normalized_path = normalize_path_for_id(&child_path);

    if !is_recycle_bin_path(&normalized_path) {
        return DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Skipped,
            reclaimed_bytes: 0,
            warning: Some(format!(
                "{} 不在回收站目录内，已跳过。",
                child_path.to_string_lossy()
            )),
        };
    }

    let Ok(metadata) = fs::symlink_metadata(&child_path) else {
        return DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Skipped,
            reclaimed_bytes: 0,
            warning: Some(format!(
                "{} 已不存在，已跳过。",
                child_path.to_string_lossy()
            )),
        };
    };

    if is_reparse_point_or_symlink(&metadata) {
        return DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Skipped,
            reclaimed_bytes: 0,
            warning: Some(format!(
                "{} 是链接或 reparse point，已跳过。",
                child_path.to_string_lossy()
            )),
        };
    }

    let child_size = if metadata.is_dir() {
        scan_directory_stats(&child_path).size_bytes
    } else {
        metadata.len()
    };

    match delete_path_permanently(&child_path) {
        Ok(()) => DirectoryChildCleanupResult {
            path: child_path,
            status: CleanupProgressStatus::Cleaned,
            reclaimed_bytes: child_size,
            warning: None,
        },
        Err(error) => DirectoryChildCleanupResult {
            path: child_path.clone(),
            status: CleanupProgressStatus::Failed,
            reclaimed_bytes: 0,
            warning: Some(cleanup_failure_message(
                child_path.to_string_lossy().as_ref(),
                &DeleteStrategy::PermanentDelete,
                error,
            )),
        },
    }
}

fn permanent_delete_worker_count(item_count: usize) -> usize {
    let available_parallelism = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4);

    item_count
        .max(1)
        .min(available_parallelism)
        .min(MAX_PERMANENT_DELETE_WORKERS)
}

fn evaluate_cleanup_target_path(path: &Path) -> PathGuardLevel {
    let normalized = normalize_path_for_id(path);

    if normalized.trim().is_empty() {
        return PathGuardLevel::HardDeny("路径为空");
    }

    if is_drive_root_path(&normalized) {
        return PathGuardLevel::HardDeny("不能清理盘符根目录");
    }

    if is_current_app_path(&normalized) {
        return PathGuardLevel::HardDeny("不能清理 DiskClean 当前运行目录或工作目录");
    }

    if is_application_install_path(path, &normalized) {
        return PathGuardLevel::HardDeny("不能清理应用安装目录或运行时依赖文件");
    }

    if is_store_or_installer_system_path(&normalized) {
        return PathGuardLevel::HardDeny("不能清理应用商店、安装回滚或程序数据系统目录");
    }

    if is_dependency_runtime_path(&normalized) {
        return PathGuardLevel::HardDeny("不能清理项目依赖目录或运行依赖文件");
    }

    if normalized.contains("\\program files\\")
        || normalized.contains("\\program files (x86)\\")
        || normalized.contains("\\programfiles\\")
    {
        return PathGuardLevel::HardDeny("不能清理应用安装目录");
    }

    if is_user_content_path(&normalized) {
        return PathGuardLevel::HardDeny("不能自动清理用户文档、桌面、图片、视频或音乐目录");
    }

    if is_protected_windows_path(&normalized) {
        return PathGuardLevel::HardDeny("不能清理受保护的 Windows 系统目录");
    }

    if let PathGuardLevel::HardDeny(reason) = classify_path_state_markers(&normalized) {
        return PathGuardLevel::HardDeny(reason);
    }

    // WHY: 回收站根候选项在 apply_cleanup_support_policy 里走专属确认流程，这里拦住其余绕过确认的深层路径。
    if is_recycle_bin_path(&normalized) {
        return PathGuardLevel::HardDeny(
            "回收站清空属于永久删除，必须通过回收站候选项手动确认执行",
        );
    }

    if is_dependency_store_path(&normalized) {
        return PathGuardLevel::NeedsConfirm(REASON_DEPENDENCY_STORE);
    }

    classify_path_state_markers(&normalized)
}

fn validate_cleanup_target_path(path: &Path) -> Result<(), String> {
    match evaluate_cleanup_target_path(path) {
        PathGuardLevel::HardDeny(reason) => Err(reason.to_string()),
        PathGuardLevel::NeedsConfirm(_) | PathGuardLevel::Allowed => Ok(()),
    }
}

fn apply_cleanup_support_policy(mut candidate: CleanupCandidate) -> CleanupCandidate {
    if candidate.delete_strategy == DeleteStrategy::Skip {
        candidate.default_selected = false;
        candidate.selected = false;
        return candidate;
    }

    let path = PathBuf::from(&candidate.path);
    let normalized_path = normalize_path_for_id(&path);

    if is_recycle_bin_path(&normalized_path) {
        candidate.risk_level = RiskLevel::ReviewRequired;
        candidate.default_selected = false;
        candidate.selected = false;
        candidate.delete_strategy = DeleteStrategy::PermanentDelete;
        candidate.reason = append_reason(
            candidate.reason,
            "回收站清空会永久删除其中项目，必须由用户手动勾选确认",
        );
        candidate.confidence = candidate.confidence.max(88);
        return candidate;
    }

    if candidate.category == "大文件" {
        return mark_candidate_unsupported(
            candidate,
            "大文件仅用于空间分析，当前版本不执行自动清理",
        );
    }

    match evaluate_cleanup_target_path(&path) {
        // HARD_DENY 对所有候选项生效，包括内置规则与订阅规则。
        PathGuardLevel::HardDeny(reason) => mark_candidate_unsupported(candidate, reason),
        PathGuardLevel::NeedsConfirm(reason)
            if !is_built_in_rule_id(candidate.cleanup_policy.rule_id.as_deref()) =>
        {
            mark_candidate_needs_confirmation(candidate, reason)
        }
        PathGuardLevel::NeedsConfirm(_) | PathGuardLevel::Allowed => candidate,
    }
}

fn is_built_in_rule_id(rule_id: Option<&str>) -> bool {
    let Some(rule_id) = rule_id else {
        return false;
    };

    built_in_rules()
        .iter()
        .any(|rule| rule.id == rule_id && rule.source == RuleSourceKind::BuiltIn)
}

fn mark_candidate_needs_confirmation(
    mut candidate: CleanupCandidate,
    reason: &str,
) -> CleanupCandidate {
    candidate.risk_level = RiskLevel::ReviewRequired;
    candidate.default_selected = false;
    candidate.selected = false;
    candidate.reason = append_reason(candidate.reason, reason);
    candidate
}

fn mark_candidate_unsupported(
    mut candidate: CleanupCandidate,
    unsupported_reason: &str,
) -> CleanupCandidate {
    candidate.risk_level = RiskLevel::Blocked;
    candidate.default_selected = false;
    candidate.selected = false;
    candidate.delete_strategy = DeleteStrategy::Skip;
    candidate.reason = append_reason(candidate.reason, unsupported_reason);
    candidate.confidence = candidate.confidence.max(90);
    candidate
}

fn append_reason(reason: String, addition: &str) -> String {
    if reason.contains(addition) {
        reason
    } else if reason.trim().is_empty() {
        addition.to_string()
    } else {
        format!("{reason}；{addition}")
    }
}

fn cleanup_policy_for_rule(rule: &CompiledCleanupRule) -> CleanupPolicy {
    let mut exclude_patterns = Vec::new();
    let mut seen = HashSet::new();

    for pattern in rule.exclude.iter().chain(rule.mandatory_exclude.iter()) {
        let normalized = normalize_glob_pattern(pattern);
        if seen.insert(normalized.clone()) {
            exclude_patterns.push(normalized);
        }
    }

    CleanupPolicy {
        rule_id: Some(rule.id.clone()),
        method: rule.clean.clone(),
        keep_days: rule.keep_days,
        exclude_patterns,
    }
}

fn confidence_for_rule_source(source: &RuleSourceKind) -> u8 {
    match source {
        RuleSourceKind::BuiltIn => 92,
        RuleSourceKind::User => 82,
        RuleSourceKind::Subscription => 70,
    }
}

fn source_info_for_rule(rule: &CompiledCleanupRule, path: &Path) -> SourceInfo {
    let detected = source_info_for_path(path);
    source_info(
        rule.app.clone(),
        detected.kind,
        detected
            .confidence
            .max(confidence_for_rule_source(&rule.source)),
        format!("cleanup rule {}", rule.id),
    )
}

fn rule_cleanup_reason(reason: String, cleanup_policy: &CleanupPolicy) -> String {
    if cleanup_policy.rule_id.is_none() {
        return reason;
    }

    let mut additions = Vec::new();
    if cleanup_policy.keep_days > 0 {
        additions.push(format!(
            "保留最近 {} 天内修改的对象",
            cleanup_policy.keep_days
        ));
    }
    if !cleanup_policy.exclude_patterns.is_empty() {
        additions.push("执行时会应用规则排除项和强制安全排除项".to_string());
    }
    if cleanup_policy.method == RuleCleanupMethod::Manual {
        additions.push("manual 规则仅展示，不自动清理".to_string());
    }

    additions.into_iter().fold(reason, |current, addition| {
        append_reason(current, &addition)
    })
}

fn cleanup_policy_allows_directory_child(
    path: &Path,
    metadata: &fs::Metadata,
    cleanup_policy: &CleanupPolicy,
) -> Result<(), String> {
    if cleanup_policy.method == RuleCleanupMethod::Files && metadata.is_dir() {
        return Err("规则 clean=files，仅清理直接文件，目录已跳过".to_string());
    }

    cleanup_policy_allows_path(path, metadata, cleanup_policy)
}

fn cleanup_policy_allows_path(
    path: &Path,
    metadata: &fs::Metadata,
    cleanup_policy: &CleanupPolicy,
) -> Result<(), String> {
    if cleanup_policy.method == RuleCleanupMethod::Manual {
        return Err("规则 clean=manual，仅展示，不执行自动清理".to_string());
    }

    if path_matches_exclude_patterns(path, &cleanup_policy.exclude_patterns) {
        return Err("命中规则排除项，已跳过".to_string());
    }

    if metadata.is_dir()
        && !cleanup_policy.exclude_patterns.is_empty()
        && directory_has_excluded_descendant(path, &cleanup_policy.exclude_patterns)
    {
        return Err("目录内包含规则排除项，已跳过整个目录以避免误删".to_string());
    }

    if let Some(cutoff) = keep_days_cutoff(cleanup_policy.keep_days) {
        if metadata
            .modified()
            .map(|modified| modified > cutoff)
            .unwrap_or(true)
        {
            return Err(format!(
                "最近 {} 天内修改，按规则保留",
                cleanup_policy.keep_days
            ));
        }

        if metadata.is_dir() && directory_has_recent_descendant(path, cutoff) {
            return Err(format!(
                "目录内包含最近 {} 天内修改的对象，已跳过整个目录",
                cleanup_policy.keep_days
            ));
        }
    }

    Ok(())
}

fn keep_days_cutoff(keep_days: u16) -> Option<SystemTime> {
    if keep_days == 0 {
        return None;
    }

    SystemTime::now().checked_sub(Duration::from_secs(u64::from(keep_days) * 86_400))
}

fn path_matches_exclude_patterns(path: &Path, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    let normalized_path = normalize_path_for_id(path);
    patterns
        .iter()
        .any(|pattern| path_matches_glob_pattern(pattern, &normalized_path))
}

fn path_matches_glob_pattern(pattern: &str, normalized_path: &str) -> bool {
    let normalized_pattern = normalize_glob_pattern(pattern);

    if !has_path_wildcards(&normalized_pattern) {
        return normalized_path == normalized_pattern
            || normalized_path.ends_with(&format!("\\{normalized_pattern}"))
            || normalized_path.contains(&format!("\\{normalized_pattern}\\"));
    }

    glob_matches(&normalized_pattern, normalized_path)
}

fn normalize_glob_pattern(pattern: &str) -> String {
    pattern.trim().replace('/', "\\").to_ascii_lowercase()
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut matches = vec![false; text.len() + 1];
    matches[0] = true;

    for pattern_byte in pattern {
        if *pattern_byte == b'*' {
            for index in 1..=text.len() {
                matches[index] = matches[index] || matches[index - 1];
            }
        } else {
            for index in (1..=text.len()).rev() {
                matches[index] = matches[index - 1]
                    && (*pattern_byte == b'?' || *pattern_byte == text[index - 1]);
            }
            matches[0] = false;
        }
    }

    matches[text.len()]
}

fn directory_has_excluded_descendant(root: &Path, patterns: &[String]) -> bool {
    directory_has_matching_descendant(root, |path, _metadata| {
        path_matches_exclude_patterns(path, patterns)
    })
}

fn directory_has_recent_descendant(root: &Path, cutoff: SystemTime) -> bool {
    directory_has_matching_descendant(root, |_path, metadata| {
        metadata
            .modified()
            .map(|modified| modified > cutoff)
            .unwrap_or(true)
    })
}

fn directory_has_matching_descendant<F>(root: &Path, mut matches_entry: F) -> bool
where
    F: FnMut(&Path, &fs::Metadata) -> bool,
{
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0_u64;

    while let Some(path) = stack.pop() {
        if visited >= MAX_QUICK_SCAN_ENTRIES {
            return true;
        }
        visited += 1;

        let Ok(entries) = fs::read_dir(&path) else {
            return true;
        };

        for entry in entries.flatten() {
            let child_path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&child_path) else {
                return true;
            };

            if is_reparse_point_or_symlink(&metadata) {
                continue;
            }

            if matches_entry(&child_path, &metadata) {
                return true;
            }

            if metadata.is_dir() {
                stack.push(child_path);
            }
        }
    }

    false
}

fn is_recycle_bin_path(normalized_path: &str) -> bool {
    normalized_path.contains("\\$recycle.bin")
}

fn is_supported_windows_log_cleanup_path(normalized_path: &str) -> bool {
    normalized_path.contains("\\windows\\logs\\cbs")
        || normalized_path.contains("\\windows\\logs\\dism")
        || normalized_path.contains("\\windows\\system32\\logfiles\\cloudfiles")
        || normalized_path.contains("\\windows\\system32\\logfiles\\httperr")
        || normalized_path.contains("\\windows\\minidump")
        || normalized_path.contains("\\appdata\\local\\crashdumps")
}

fn is_supported_dotnet_log_path(normalized_path: &str) -> bool {
    (normalized_path.contains("\\windows\\microsoft.net\\framework\\")
        || normalized_path.contains("\\windows\\microsoft.net\\framework64\\"))
        && normalized_path.ends_with("\\ngen.log")
}

#[derive(Clone, Debug)]
struct IndexedSource {
    label: String,
    kind: SourceKind,
    normalized_root: String,
    confidence: u8,
    evidence: String,
}

static INSTALLED_APP_SOURCES: OnceLock<Vec<IndexedSource>> = OnceLock::new();
static STEAM_APP_SOURCES: OnceLock<Vec<IndexedSource>> = OnceLock::new();

fn source_info_for_path(path: &Path) -> SourceInfo {
    let normalized_path = normalize_path_for_id(path);

    source_from_steam_path(&normalized_path)
        .or_else(|| source_from_known_path(&normalized_path))
        .or_else(|| source_from_indexed_sources(installed_app_sources(), &normalized_path))
        .or_else(|| source_from_appdata_path(path))
        .or_else(|| source_from_project_path(path))
        .unwrap_or_else(source_unknown)
}

fn installed_app_sources() -> &'static [IndexedSource] {
    INSTALLED_APP_SOURCES
        .get_or_init(registry_installed_app_sources)
        .as_slice()
}

fn steam_app_sources() -> &'static [IndexedSource] {
    STEAM_APP_SOURCES
        .get_or_init(steam_manifest_sources)
        .as_slice()
}

fn source_unknown() -> SourceInfo {
    SourceInfo {
        label: "未知来源".to_string(),
        kind: SourceKind::Unknown,
        confidence: 0,
        evidence: "no source rule matched".to_string(),
    }
}

fn source_info(
    label: impl Into<String>,
    kind: SourceKind,
    confidence: u8,
    evidence: impl Into<String>,
) -> SourceInfo {
    SourceInfo {
        label: label.into(),
        kind,
        confidence,
        evidence: evidence.into(),
    }
}

fn source_from_known_path(normalized_path: &str) -> Option<SourceInfo> {
    let known_sources: &[(&str, &str, SourceKind, u8)] = &[
        (
            "\\google\\chrome\\",
            "Google Chrome",
            SourceKind::Browser,
            96,
        ),
        (
            "\\microsoft\\edge\\",
            "Microsoft Edge",
            SourceKind::Browser,
            96,
        ),
        (
            "\\mozilla\\firefox\\",
            "Mozilla Firefox",
            SourceKind::Browser,
            96,
        ),
        (
            "\\microsoft\\windows\\inetcache",
            "Windows INetCache",
            SourceKind::Windows,
            94,
        ),
        (
            "\\microsoft\\windows\\explorer",
            "Windows Explorer",
            SourceKind::Windows,
            94,
        ),
        ("\\directx shader cache", "DirectX", SourceKind::Windows, 92),
        ("\\dxcshadercache", "DirectX", SourceKind::Windows, 92),
        ("\\d3dscache", "DirectX", SourceKind::Windows, 92),
        ("\\nvidia\\dxcache", "NVIDIA", SourceKind::InstalledApp, 92),
        ("\\nvidia\\glcache", "NVIDIA", SourceKind::InstalledApp, 92),
        ("\\npm-cache", "npm", SourceKind::DevTool, 90),
        ("\\npm\\cache", "npm", SourceKind::DevTool, 90),
        ("\\.pnpm-store", "pnpm", SourceKind::DevTool, 90),
        ("\\pnpm\\store", "pnpm", SourceKind::DevTool, 90),
        ("\\yarn\\cache", "Yarn", SourceKind::DevTool, 90),
        ("\\pip\\cache", "pip", SourceKind::DevTool, 90),
        ("\\uv\\cache", "uv", SourceKind::DevTool, 88),
        ("\\node-gyp\\cache", "node-gyp", SourceKind::DevTool, 88),
        ("\\.gradle\\caches", "Gradle", SourceKind::DevTool, 90),
        ("\\gradle\\caches", "Gradle", SourceKind::DevTool, 90),
        ("\\flutter\\bin\\cache", "Flutter", SourceKind::DevTool, 90),
        ("\\.pub-cache", "Dart Pub", SourceKind::DevTool, 90),
        ("\\pub\\cache", "Dart Pub", SourceKind::DevTool, 90),
        ("\\nuget\\packages", "NuGet", SourceKind::DevTool, 90),
        ("\\nuget\\cache", "NuGet", SourceKind::DevTool, 90),
        ("\\composer\\cache", "Composer", SourceKind::DevTool, 88),
        (
            "\\.cargo\\registry\\cache",
            "Cargo",
            SourceKind::DevTool,
            90,
        ),
        (
            "\\cursor\\user\\globalstorage",
            "Cursor",
            SourceKind::DevTool,
            90,
        ),
        (
            "\\code\\cache",
            "Visual Studio Code",
            SourceKind::DevTool,
            88,
        ),
        (
            "\\visual studio code\\",
            "Visual Studio Code",
            SourceKind::DevTool,
            88,
        ),
        ("\\camoufox\\", "Camoufox", SourceKind::Browser, 88),
        (
            "\\$winreagent\\",
            "Windows Recovery",
            SourceKind::Windows,
            92,
        ),
        (
            "\\softwaredistribution\\download",
            "Windows Update",
            SourceKind::Windows,
            94,
        ),
        (
            "\\deliveryoptimization\\",
            "Delivery Optimization",
            SourceKind::Windows,
            94,
        ),
        ("\\windows\\temp", "Windows Temp", SourceKind::Windows, 94),
        (
            "\\windows\\system32\\config\\systemprofile\\appdata\\local\\microsoft\\windows\\wer\\",
            "Windows Error Reporting",
            SourceKind::Windows,
            94,
        ),
        (
            "\\wer\\",
            "Windows Error Reporting",
            SourceKind::Windows,
            88,
        ),
        (
            "\\reportarchive",
            "Windows Error Reporting",
            SourceKind::Windows,
            88,
        ),
        (
            "\\reportqueue",
            "Windows Error Reporting",
            SourceKind::Windows,
            88,
        ),
        ("\\$recycle.bin", "Recycle Bin", SourceKind::Windows, 94),
    ];

    known_sources
        .iter()
        .find(|(needle, _, _, _)| normalized_path.contains(needle))
        .map(|(_, label, kind, confidence)| {
            source_info(*label, kind.clone(), *confidence, "built-in path rule")
        })
}

fn source_from_project_path(path: &Path) -> Option<SourceInfo> {
    path.ancestors()
        .take(9)
        .find(|ancestor| {
            looks_like_project_root(ancestor) && !is_broad_source_project_root(ancestor)
        })
        .and_then(|project_root| {
            project_root
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .filter(|name| !name.trim().is_empty())
        })
        .map(|project_name| {
            source_info(
                format!("项目：{project_name}"),
                SourceKind::Project,
                88,
                "project marker in ancestor directory",
            )
        })
}

fn is_broad_source_project_root(path: &Path) -> bool {
    let segments = source_path_segments(path);

    segments.len() == 2 && segments[0].eq_ignore_ascii_case("users")
}

fn source_from_appdata_path(path: &Path) -> Option<SourceInfo> {
    let segments = source_path_segments(path);

    for index in 0..segments.len().saturating_sub(1) {
        if segments[index].eq_ignore_ascii_case("appdata")
            && matches_source_segment(&segments[index + 1], &["local", "locallow", "roaming"])
        {
            return source_from_app_segments(&segments[(index + 2)..], "AppData path");
        }

        if segments[index].eq_ignore_ascii_case("programdata") {
            return source_from_app_segments(&segments[(index + 1)..], "ProgramData path");
        }
    }

    None
}

fn source_from_app_segments(segments: &[String], evidence: &str) -> Option<SourceInfo> {
    let first = segments.first()?.trim();

    if first.is_empty() || is_noise_app_source_segment(first) {
        return None;
    }

    let second = segments
        .get(1)
        .map(|segment| segment.trim())
        .unwrap_or_default();

    if first.eq_ignore_ascii_case("packages") && !second.is_empty() {
        return Some(source_info(
            store_package_source_label(second),
            SourceKind::StoreApp,
            76,
            evidence,
        ));
    }

    if let Some(known) = known_appdata_source_label(first, second) {
        return Some(known);
    }

    let label =
        if !second.is_empty() && is_vendor_segment(first) && !is_noise_app_source_segment(second) {
            format!(
                "{} {}",
                display_source_segment(first),
                display_source_segment(second)
            )
        } else {
            display_source_segment(first)
        };

    if label.is_empty() {
        return None;
    }

    Some(source_info(label, SourceKind::InstalledApp, 68, evidence))
}

fn known_appdata_source_label(first: &str, second: &str) -> Option<SourceInfo> {
    if first.eq_ignore_ascii_case("google") && second.eq_ignore_ascii_case("chrome") {
        return Some(source_info(
            "Google Chrome",
            SourceKind::Browser,
            92,
            "AppData vendor/app path",
        ));
    }

    if first.eq_ignore_ascii_case("microsoft") && second.eq_ignore_ascii_case("edge") {
        return Some(source_info(
            "Microsoft Edge",
            SourceKind::Browser,
            92,
            "AppData vendor/app path",
        ));
    }

    if first.eq_ignore_ascii_case("mozilla") && second.eq_ignore_ascii_case("firefox") {
        return Some(source_info(
            "Mozilla Firefox",
            SourceKind::Browser,
            92,
            "AppData vendor/app path",
        ));
    }

    let lower_first = first.to_ascii_lowercase();
    let (label, kind) = match lower_first.as_str() {
        "code" => ("Visual Studio Code", SourceKind::DevTool),
        "cursor" => ("Cursor", SourceKind::DevTool),
        "npm-cache" | "npm" => ("npm", SourceKind::DevTool),
        "pnpm" => ("pnpm", SourceKind::DevTool),
        "yarn" => ("Yarn", SourceKind::DevTool),
        "pip" => ("pip", SourceKind::DevTool),
        "nuget" => ("NuGet", SourceKind::DevTool),
        "cargo" => ("Cargo", SourceKind::DevTool),
        "docker" => ("Docker", SourceKind::DevTool),
        "steam" => ("Steam", SourceKind::Game),
        "discord" => ("Discord", SourceKind::InstalledApp),
        "telegram desktop" => ("Telegram Desktop", SourceKind::InstalledApp),
        _ => return None,
    };

    Some(source_info(label, kind, 86, "AppData app directory"))
}

fn source_from_steam_path(normalized_path: &str) -> Option<SourceInfo> {
    source_from_indexed_sources(steam_app_sources(), normalized_path).or_else(|| {
        let marker = "\\steamapps\\common\\";
        let marker_index = normalized_path.find(marker)?;
        let after_marker = &normalized_path[(marker_index + marker.len())..];
        let game_dir = after_marker.split('\\').next().unwrap_or_default();

        if game_dir.is_empty() {
            return None;
        }

        Some(source_info(
            format!("Steam: {}", display_source_segment(game_dir)),
            SourceKind::Game,
            80,
            "Steam common directory path",
        ))
    })
}

fn source_from_indexed_sources(
    sources: &[IndexedSource],
    normalized_path: &str,
) -> Option<SourceInfo> {
    sources
        .iter()
        .filter(|source| normalized_path_matches_root(normalized_path, &source.normalized_root))
        .max_by_key(|source| source.normalized_root.len())
        .map(|source| {
            source_info(
                source.label.clone(),
                source.kind.clone(),
                source.confidence,
                source.evidence.clone(),
            )
        })
}

fn registry_installed_app_sources() -> Vec<IndexedSource> {
    registry_installed_app_entries()
        .into_iter()
        .filter_map(|(label, root)| {
            normalized_source_root(&root).map(|normalized_root| IndexedSource {
                label,
                kind: SourceKind::InstalledApp,
                normalized_root,
                confidence: 90,
                evidence: "Windows uninstall registry InstallLocation".to_string(),
            })
        })
        .collect()
}

#[cfg(all(windows, not(test)))]
fn registry_installed_app_entries() -> Vec<(String, String)> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
        System::{
            Environment::ExpandEnvironmentStringsW,
            Registry::{
                RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY,
                HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ,
                REG_VALUE_TYPE,
            },
        },
    };

    struct RegistryKey(HKEY);

    impl Drop for RegistryKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn open_registry_key(root: HKEY, subkey: &str) -> Option<RegistryKey> {
        let subkey = wide_null(subkey);
        let mut key = ptr::null_mut();
        let result = unsafe { RegOpenKeyExW(root, subkey.as_ptr(), 0, KEY_READ, &mut key) };

        if result == ERROR_SUCCESS {
            Some(RegistryKey(key))
        } else {
            None
        }
    }

    fn trim_registry_string(mut value: String) -> String {
        value = value.replace('\t', " ");
        value.trim().to_string()
    }

    fn expand_registry_string(value: String, value_type: REG_VALUE_TYPE) -> String {
        if value_type != REG_EXPAND_SZ {
            return value;
        }

        let source = wide_null(&value);
        let required = unsafe { ExpandEnvironmentStringsW(source.as_ptr(), ptr::null_mut(), 0) };
        if required == 0 {
            return value;
        }

        let mut expanded = vec![0_u16; required as usize];
        let written =
            unsafe { ExpandEnvironmentStringsW(source.as_ptr(), expanded.as_mut_ptr(), required) };
        if written == 0 || written > required {
            return value;
        }

        let end = expanded
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(expanded.len());
        String::from_utf16_lossy(&expanded[..end])
    }

    fn query_registry_string(key: HKEY, name: &str) -> Option<String> {
        let name = wide_null(name);
        let mut value_type: REG_VALUE_TYPE = 0;
        let mut byte_len = 0_u32;
        let result = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut value_type,
                ptr::null_mut(),
                &mut byte_len,
            )
        };

        if result != ERROR_SUCCESS || (value_type != REG_SZ && value_type != REG_EXPAND_SZ) {
            return None;
        }

        let mut buffer = vec![0_u16; (byte_len as usize).div_ceil(2).max(1)];
        let result = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut value_type,
                buffer.as_mut_ptr() as *mut u8,
                &mut byte_len,
            )
        };

        if result != ERROR_SUCCESS || (value_type != REG_SZ && value_type != REG_EXPAND_SZ) {
            return None;
        }

        let wchar_len = (byte_len as usize / 2).min(buffer.len());
        let end = buffer[..wchar_len]
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(wchar_len);
        let value = String::from_utf16_lossy(&buffer[..end]);
        let value = trim_registry_string(expand_registry_string(value, value_type));

        (!value.is_empty()).then_some(value)
    }

    fn read_uninstall_entries(root: HKEY, subkey: &str) -> Vec<(String, String)> {
        let Some(uninstall_key) = open_registry_key(root, subkey) else {
            return Vec::new();
        };

        let mut entries = Vec::new();
        let mut index = 0_u32;
        loop {
            let mut name = vec![0_u16; 256];
            let mut name_len = name.len() as u32;
            let result = unsafe {
                RegEnumKeyExW(
                    uninstall_key.0,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };

            if result == ERROR_NO_MORE_ITEMS {
                break;
            }

            index += 1;
            if result != ERROR_SUCCESS {
                continue;
            }

            let child_name = String::from_utf16_lossy(&name[..name_len as usize]);
            let Some(child_key) = open_registry_key(uninstall_key.0, &child_name) else {
                continue;
            };
            let Some(label) = query_registry_string(child_key.0, "DisplayName") else {
                continue;
            };
            let Some(root) = query_registry_string(child_key.0, "InstallLocation") else {
                continue;
            };

            entries.push((label, root));
        }

        entries
    }

    [
        (
            HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
        (
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
    ]
    .into_iter()
    .flat_map(|(root, subkey)| read_uninstall_entries(root, subkey))
    .collect()
}

#[cfg(any(not(windows), test))]
fn registry_installed_app_entries() -> Vec<(String, String)> {
    Vec::new()
}

fn steam_manifest_sources() -> Vec<IndexedSource> {
    let mut sources = Vec::new();

    for steamapps in steamapps_roots() {
        let Ok(entries) = fs::read_dir(&steamapps) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            if !file_name.starts_with("appmanifest_") || !file_name.ends_with(".acf") {
                continue;
            }

            let Ok(contents) = fs::read_to_string(&path) else {
                continue;
            };
            let Some(name) = steam_vdf_value(&contents, "name") else {
                continue;
            };
            let Some(install_dir) = steam_vdf_value(&contents, "installdir") else {
                continue;
            };
            let game_root = steamapps.join("common").join(install_dir);
            let Some(normalized_root) = normalized_source_root(&game_root.to_string_lossy()) else {
                continue;
            };

            sources.push(IndexedSource {
                label: format!("Steam: {name}"),
                kind: SourceKind::Game,
                normalized_root,
                confidence: 96,
                evidence: path.to_string_lossy().to_string(),
            });
        }
    }

    sources
}

fn steamapps_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();

    for drive in b'C'..=b'Z' {
        let drive = drive as char;
        push_steamapps_root(
            &mut roots,
            &mut seen,
            PathBuf::from(format!("{drive}:\\Program Files (x86)\\Steam\\steamapps")),
        );
        push_steamapps_root(
            &mut roots,
            &mut seen,
            PathBuf::from(format!("{drive}:\\Program Files\\Steam\\steamapps")),
        );
        push_steamapps_root(
            &mut roots,
            &mut seen,
            PathBuf::from(format!("{drive}:\\SteamLibrary\\steamapps")),
        );
    }

    let existing_roots = roots.clone();
    for steamapps in existing_roots {
        for library in steam_library_paths_from_vdf(&steamapps) {
            push_steamapps_root(&mut roots, &mut seen, library.join("steamapps"));
        }
    }

    roots
}

fn push_steamapps_root(roots: &mut Vec<PathBuf>, seen: &mut HashSet<String>, path: PathBuf) {
    if !path.exists() || !path.is_dir() {
        return;
    }

    let key = normalize_path_for_id(&path);
    if seen.insert(key) {
        roots.push(path);
    }
}

fn steam_library_paths_from_vdf(steamapps: &Path) -> Vec<PathBuf> {
    let Ok(contents) = fs::read_to_string(steamapps.join("libraryfolders.vdf")) else {
        return Vec::new();
    };

    contents
        .lines()
        .filter_map(|line| steam_vdf_value(line, "path"))
        .map(|path| PathBuf::from(path.replace("\\\\", "\\")))
        .collect()
}

fn steam_vdf_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let values = line
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect::<Vec<_>>();

        if values.first().map(String::as_str) == Some(key) {
            values.get(1).cloned()
        } else {
            None
        }
    })
}

fn source_path_segments(path: &Path) -> Vec<String> {
    path.to_string_lossy()
        .replace('/', "\\")
        .split('\\')
        .filter_map(|segment| {
            let segment = segment.trim();
            if segment.is_empty() || segment.ends_with(':') {
                None
            } else {
                Some(segment.to_string())
            }
        })
        .collect()
}

fn matches_source_segment(segment: &str, choices: &[&str]) -> bool {
    choices
        .iter()
        .any(|choice| segment.eq_ignore_ascii_case(choice))
}

fn is_vendor_segment(segment: &str) -> bool {
    matches_source_segment(
        segment,
        &[
            "adobe",
            "apple",
            "autodesk",
            "bytedance",
            "google",
            "jetbrains",
            "microsoft",
            "mozilla",
            "nvidia",
            "tencent",
            "unity",
        ],
    )
}

fn is_noise_app_source_segment(segment: &str) -> bool {
    matches_source_segment(
        segment,
        &[
            "cache",
            "caches",
            "code cache",
            "data",
            "default",
            "log",
            "logs",
            "profile",
            "profiles",
            "temp",
            "tmp",
            "user data",
        ],
    )
}

fn display_source_segment(segment: &str) -> String {
    segment
        .replace(['_', '-'], " ")
        .split_whitespace()
        .map(|word| {
            if word.chars().any(char::is_uppercase) && word.chars().any(char::is_lowercase) {
                return word.to_string();
            }

            let mut chars = word.chars();
            match chars.next() {
                Some(first) => format!(
                    "{}{}",
                    first.to_uppercase(),
                    chars.as_str().to_ascii_lowercase()
                ),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn store_package_source_label(segment: &str) -> String {
    let package_name = segment
        .split('_')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(segment)
        .replace('.', " ");

    display_source_segment(&package_name)
}

fn normalized_source_root(root: &str) -> Option<String> {
    let trimmed = root.trim().trim_matches('"').replace('/', "\\");

    if trimmed.is_empty() || trimmed.contains('%') {
        return None;
    }

    let mut normalized = trimmed.to_ascii_lowercase();

    while normalized.len() > 3 && normalized.ends_with('\\') {
        normalized.pop();
    }

    if normalized.is_empty() || is_drive_root_path(&normalized) {
        return None;
    }

    Some(normalized)
}

fn normalized_path_matches_root(normalized_path: &str, normalized_root: &str) -> bool {
    normalized_path == normalized_root
        || normalized_path
            .strip_prefix(normalized_root)
            .map(|remaining| remaining.starts_with('\\'))
            .unwrap_or(false)
}

fn is_drive_root_path(normalized_path: &str) -> bool {
    normalized_path.len() == 3
        && normalized_path.as_bytes()[1] == b':'
        && normalized_path.as_bytes()[2] == b'\\'
}

fn is_current_app_path(normalized_path: &str) -> bool {
    let current_dir = env::current_dir()
        .ok()
        .map(|path| normalize_path_for_id(&path))
        .unwrap_or_default();
    let current_exe = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .map(|path| normalize_path_for_id(&path))
        .unwrap_or_default();

    (!current_dir.is_empty() && normalized_path.starts_with(&current_dir))
        || (!current_exe.is_empty() && normalized_path.starts_with(&current_exe))
}

fn is_application_install_path(path: &Path, normalized_path: &str) -> bool {
    if normalized_path.len() >= 11
        && normalized_path.as_bytes().get(1) == Some(&b':')
        && normalized_path.as_bytes().get(2) == Some(&b'\\')
        && normalized_path[2..].starts_with("\\windows\\")
    {
        return false;
    }

    is_application_runtime_payload_path(normalized_path) || has_application_install_ancestor(path)
}

fn is_application_runtime_payload_path(normalized_path: &str) -> bool {
    normalized_path.contains("\\resources\\app\\")
        || normalized_path.ends_with("\\resources\\app")
        || normalized_path.contains("\\resources\\app.asar")
        || normalized_path.contains("\\app.asar.unpacked\\")
        || normalized_path.ends_with("\\app.asar")
}

fn is_dependency_runtime_path(normalized_path: &str) -> bool {
    has_exact_segment(normalized_path, DEPENDENCY_RUNTIME_SEGMENTS)
        || normalized_path.contains("\\.cargo\\registry\\src\\")
}

fn is_store_or_installer_system_path(normalized_path: &str) -> bool {
    normalized_path.contains("\\windowsapps\\")
        || normalized_path.ends_with("\\windowsapps")
        || normalized_path.contains("\\wpsystem\\")
        || normalized_path.ends_with("\\wpsystem")
        || normalized_path.contains("\\config.msi\\")
        || normalized_path.ends_with("\\config.msi")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PathGuardLevel {
    Allowed,
    NeedsConfirm(&'static str),
    HardDeny(&'static str),
}

const REGENERABLE_CACHE_SEGMENTS: &[&str] =
    &["cache", "cache2", "code cache", "gpucache", "shadercache"];
const HARD_DENY_SEGMENT_MARKERS: &[&str] =
    &["token", "session", "wallet", "keychain", "credential"];
const LIVE_STATE_SEGMENTS: &[&str] = &[
    "indexeddb",
    "local storage",
    "databases",
    "blob_storage",
    "network",
];
const LIVE_STATE_SEGMENT_PREFIXES: &[&str] = &[
    "login data",
    "cookies",
    "history",
    "preferences",
    "local state",
];
const LIVE_STATE_EXTENSIONS: &[&str] = &["db", "sqlite", "sqlite3", "vscdb"];
const CONFIRM_STATE_SEGMENTS: &[&str] = &["profile", "profiles"];
const CONFIRM_STATE_SEGMENT_MARKERS: &[&str] = &["backup", "recovery", "autosave"];
const DEPENDENCY_RUNTIME_SEGMENTS: &[&str] = &["node_modules", ".venv", "site-packages", "vendor"];
const USER_CONTENT_SEGMENTS: &[&str] = &["desktop", "documents", "pictures", "videos", "music"];

const REASON_SECRET: &str = "不能清理钱包、密钥串、凭据、令牌或会话等机密数据";
const REASON_LIVE_STATE: &str = "不能清理账号、会话、数据库或应用持久化状态数据";
const REASON_CONFIRM_STATE: &str = "命中备份、恢复、自动保存或浏览器 profile 数据，需要逐项确认";
const REASON_DEPENDENCY_STORE: &str = "命中开发依赖缓存，删除后可能需要重新下载依赖，需要确认";

fn path_segments(normalized_path: &str) -> impl Iterator<Item = &str> {
    normalized_path
        .split('\\')
        .filter(|segment| !segment.is_empty())
}

fn has_exact_segment(normalized_path: &str, markers: &[&str]) -> bool {
    path_segments(normalized_path).any(|segment| markers.contains(&segment))
}

fn has_segment_prefix(normalized_path: &str, markers: &[&str]) -> bool {
    path_segments(normalized_path)
        .any(|segment| markers.iter().any(|marker| segment.starts_with(marker)))
}

fn has_segment_substring(normalized_path: &str, markers: &[&str]) -> bool {
    path_segments(normalized_path)
        .any(|segment| markers.iter().any(|marker| segment.contains(marker)))
}

fn is_regenerable_cache_path(normalized_path: &str) -> bool {
    has_exact_segment(normalized_path, REGENERABLE_CACHE_SEGMENTS)
}

fn regenerable_cache_tail(normalized_path: &str) -> Option<String> {
    let segments: Vec<&str> = normalized_path.split('\\').collect();
    segments
        .iter()
        .rposition(|segment| REGENERABLE_CACHE_SEGMENTS.contains(segment))
        .map(|index| segments[index + 1..].join("\\"))
}

pub(crate) fn classify_path_state_markers(normalized_path: &str) -> PathGuardLevel {
    // WHY: 机密与会话数据无论是否位于缓存目录都不可删除，因此排在缓存豁免之前。
    if has_segment_substring(normalized_path, HARD_DENY_SEGMENT_MARKERS) {
        return PathGuardLevel::HardDeny(REASON_SECRET);
    }

    if is_windows_explorer_cache_database(normalized_path) {
        return PathGuardLevel::Allowed;
    }

    // WHY: 缓存可重新生成，优先于状态标记，否则 Firefox Profiles\xxx\cache2 会被祖先目录名误判为持久化状态。
    // 仅豁免最后一个缓存段之前的祖先，缓存目录内部的 Cookies 等状态文件仍然拦截。
    let scope = regenerable_cache_tail(normalized_path);
    let scope = match &scope {
        Some(tail) if tail.is_empty() => return PathGuardLevel::Allowed,
        Some(tail) => tail.as_str(),
        None => normalized_path,
    };

    if has_exact_segment(scope, LIVE_STATE_SEGMENTS)
        || has_segment_prefix(scope, LIVE_STATE_SEGMENT_PREFIXES)
        || path_segments(scope).last().is_some_and(|leaf| {
            Path::new(leaf)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| LIVE_STATE_EXTENSIONS.contains(&extension))
        })
    {
        return PathGuardLevel::HardDeny(REASON_LIVE_STATE);
    }

    if has_exact_segment(scope, CONFIRM_STATE_SEGMENTS)
        || has_segment_substring(scope, CONFIRM_STATE_SEGMENT_MARKERS)
    {
        return PathGuardLevel::NeedsConfirm(REASON_CONFIRM_STATE);
    }

    PathGuardLevel::Allowed
}

fn is_persistent_state_path(normalized_path: &str) -> bool {
    matches!(
        classify_path_state_markers(normalized_path),
        PathGuardLevel::HardDeny(_)
    )
}

fn is_windows_explorer_cache_database(normalized_path: &str) -> bool {
    normalized_path.contains("\\microsoft\\windows\\explorer\\")
        && (normalized_path.contains("\\thumbcache_") || normalized_path.contains("\\iconcache_"))
        && matches!(
            Path::new(normalized_path)
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("db")
        )
}

fn has_application_install_ancestor(path: &Path) -> bool {
    path.ancestors()
        .take(10)
        .any(looks_like_application_install_root)
}

fn looks_like_application_install_root(path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };

    let mut has_executable = false;
    let mut has_runtime_marker = false;

    for entry in entries.flatten().take(160) {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();

        if name.ends_with(".exe") {
            has_executable = true;
        }

        if matches!(name.as_str(), "resources" | "locales" | "swiftshader")
            || matches!(
                name.as_str(),
                "app.asar" | "icudtl.dat" | "v8_context_snapshot.bin"
            )
            || name.ends_with(".pak")
            || name.ends_with(".dll")
        {
            has_runtime_marker = true;
        }

        if has_executable && has_runtime_marker {
            return true;
        }
    }

    false
}

fn is_user_content_path(normalized_path: &str) -> bool {
    has_exact_segment(normalized_path, USER_CONTENT_SEGMENTS)
}

fn is_protected_windows_path(normalized_path: &str) -> bool {
    if normalized_path.len() < 11
        || normalized_path.as_bytes().get(1) != Some(&b':')
        || normalized_path.as_bytes().get(2) != Some(&b'\\')
        || !normalized_path[2..].starts_with("\\windows\\")
    {
        return false;
    }

    !is_allowed_windows_cleanup_path(&normalized_path[2..])
}

fn is_allowed_windows_cleanup_path(windows_path: &str) -> bool {
    windows_path.starts_with("\\windows\\temp\\")
        || windows_path == "\\windows\\temp"
        || windows_path.starts_with("\\windows\\softwaredistribution\\download\\")
        || windows_path == "\\windows\\softwaredistribution\\download"
        || windows_path.starts_with("\\windows\\logs\\cbs\\")
        || windows_path == "\\windows\\logs\\cbs"
        || windows_path.starts_with("\\windows\\logs\\dism\\")
        || windows_path == "\\windows\\logs\\dism"
        || windows_path.starts_with("\\windows\\system32\\logfiles\\cloudfiles\\")
        || windows_path == "\\windows\\system32\\logfiles\\cloudfiles"
        || windows_path.starts_with("\\windows\\system32\\logfiles\\httperr\\")
        || windows_path == "\\windows\\system32\\logfiles\\httperr"
        || windows_path.starts_with("\\windows\\minidump\\")
        || windows_path == "\\windows\\minidump"
        || is_supported_dotnet_log_path(windows_path)
        || windows_path.starts_with(
            "\\windows\\system32\\config\\systemprofile\\appdata\\local\\microsoft\\windows\\wer\\",
        )
        || windows_path
            == "\\windows\\system32\\config\\systemprofile\\appdata\\local\\microsoft\\windows\\wer"
}

fn is_reparse_point_or_symlink(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    is_reparse_point(metadata)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn move_path_to_recycle_bin(path: &Path) -> Result<(), String> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::Shell::{
        SHFileOperationW, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT, FO_DELETE,
        SHFILEOPSTRUCTW,
    };

    let mut from = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let mut operation = SHFILEOPSTRUCTW {
        hwnd: ptr::null_mut(),
        wFunc: FO_DELETE,
        pFrom: from.as_mut_ptr(),
        pTo: ptr::null(),
        fFlags: (FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT) as u16,
        fAnyOperationsAborted: 0,
        hNameMappings: ptr::null_mut(),
        lpszProgressTitle: ptr::null(),
    };

    let result = unsafe { SHFileOperationW(&mut operation) };

    if result != 0 {
        return Err(format!("SHFileOperationW 返回错误码 {result}"));
    }

    if operation.fAnyOperationsAborted != 0 {
        return Err("操作被系统取消".to_string());
    }

    Ok(())
}

#[cfg(not(windows))]
fn move_path_to_recycle_bin(_path: &Path) -> Result<(), String> {
    Err("当前平台暂不支持移动到 Windows 回收站".to_string())
}

fn delete_path_permanently(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("读取元数据失败：{error}"))?;

    if metadata.is_dir() {
        fs::remove_dir_all(path).map_err(|error| format!("删除失败：{error}"))
    } else {
        fs::remove_file(path).map_err(|error| format!("删除失败：{error}"))
    }
}

pub fn sample_scan_snapshot() -> ScanSnapshot {
    let volumes = vec![
        VolumeInfo {
            id: "C".to_string(),
            label: "System".to_string(),
            mount_point: "C:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 476 * gib(),
            available_bytes: 142 * gib(),
            selected: true,
            supports_fast_index: true,
        },
        VolumeInfo {
            id: "D".to_string(),
            label: "Work".to_string(),
            mount_point: "D:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 1800 * gib(),
            available_bytes: 628 * gib(),
            selected: true,
            supports_fast_index: true,
        },
        VolumeInfo {
            id: "E".to_string(),
            label: "Portable".to_string(),
            mount_point: "E:\\".to_string(),
            filesystem: "exFAT".to_string(),
            total_bytes: 512 * gib(),
            available_bytes: 218 * gib(),
            selected: false,
            supports_fast_index: false,
        },
    ];

    let candidates = sample_candidates();
    let summary = summarize(&candidates);

    ScanSnapshot {
        volumes,
        candidates,
        selected_candidate_id: "chrome-cache".to_string(),
        summary,
        scan_backend: "mock".to_string(),
        warnings: Vec::new(),
        scan_session_id: None,
        coverage: ScanCoverage::default(),
        space_summary: Vec::new(),
    }
}

pub fn sample_candidate_children(candidate_id: &str) -> Vec<CleanupCandidate> {
    if candidate_id != "chrome-cache" {
        return Vec::new();
    }

    vec![
        child_candidate("chrome-cache-data", "Cache_Data", 612 * mib(), 1_203),
        child_candidate("chrome-code-cache", "Code Cache", 148 * mib(), 331),
        child_candidate("chrome-index-dir", "index-dir", 82 * mib(), 44),
    ]
}

pub fn preview_cleanup(selected_ids: &[String]) -> CleanupPlan {
    let candidates = sample_candidates();

    preview_cleanup_for_candidates(&candidates, selected_ids)
}

pub fn preview_cleanup_for_candidates(
    candidates: &[CleanupCandidate],
    selected_ids: &[String],
) -> CleanupPlan {
    let selected_lookup = selected_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let use_default_selection = selected_lookup.is_empty();
    let mut selected_count = 0_u32;
    let mut skipped_locked_count = 0_u32;
    let mut estimated_reclaim_bytes = 0_u64;

    for candidate in candidates.iter() {
        let selected = if use_default_selection {
            candidate.selected
        } else {
            selected_lookup.contains(candidate.id.as_str())
        };

        if !selected {
            continue;
        }

        if candidate.risk_level == RiskLevel::Blocked
            || candidate.delete_strategy == DeleteStrategy::Skip
        {
            skipped_locked_count += 1;
            continue;
        }

        selected_count += 1;
        estimated_reclaim_bytes += candidate.size_bytes;
    }

    CleanupPlan {
        selected_count,
        skipped_locked_count,
        estimated_reclaim_bytes,
        delete_strategy: DeleteStrategy::MoveToRecycleBin,
        warnings: vec!["清理前会重新校验对象状态，目录会展开为具体子项执行。".to_string()],
    }
}

pub fn classify_application_cache(path: &str, is_locked: bool) -> CacheClassification {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    let blocked_tokens = [
        "\\appdata\\roaming\\",
        "session",
        "token",
        "wallet",
        "config",
        "settings",
        "indexeddb",
        ".db",
    ];

    if is_locked
        || blocked_tokens
            .iter()
            .any(|token| normalized.contains(token))
    {
        return CacheClassification {
            decision: CacheDecision::BlockClean,
            risk_level: RiskLevel::Blocked,
            default_selected: false,
            reason: "配置、会话、数据库或运行中对象不可清理",
            confidence: 95,
        };
    }

    if is_known_browser_cache(&normalized) || normalized.contains("\\microsoft\\windows\\inetcache")
    {
        return CacheClassification {
            decision: CacheDecision::AllowClean,
            risk_level: RiskLevel::SafeRecommended,
            default_selected: true,
            reason: "已知浏览器缓存目录",
            confidence: 94,
        };
    }

    if is_dependency_store_path(&normalized) {
        return CacheClassification {
            decision: CacheDecision::ReviewClean,
            risk_level: RiskLevel::ReviewRequired,
            default_selected: false,
            reason: "开发依赖缓存或包管理器缓存，删除后可能需要重新下载依赖，必须确认",
            confidence: 82,
        };
    }

    if is_known_regenerable_app_cache(&normalized) {
        return CacheClassification {
            decision: CacheDecision::AllowClean,
            risk_level: RiskLevel::SafeRecommended,
            default_selected: true,
            reason: "已知可重建应用缓存，删除后应用会按需重新生成",
            confidence: 88,
        };
    }

    if normalized.contains("\\temp\\")
        || normalized.contains("crashdump")
        || normalized.contains("shadercache")
    {
        return CacheClassification {
            decision: CacheDecision::AllowClean,
            risk_level: RiskLevel::SafeRecommended,
            default_selected: true,
            reason: "临时或崩溃缓存目录",
            confidence: 88,
        };
    }

    if normalized.contains("\\$recycle.bin") {
        return CacheClassification {
            decision: CacheDecision::ReviewClean,
            risk_level: RiskLevel::CautiousRecommended,
            default_selected: false,
            reason: "回收站内容需要用户确认后清理",
            confidence: 75,
        };
    }

    CacheClassification {
        decision: CacheDecision::ReviewClean,
        risk_level: RiskLevel::ReviewRequired,
        default_selected: false,
        reason: "未知应用缓存，需要用户审查",
        confidence: 55,
    }
}

pub fn summarize(candidates: &[CleanupCandidate]) -> ScanSummary {
    summarize_with_progress(candidates, 72)
}

fn summarize_with_progress(candidates: &[CleanupCandidate], progress_percent: u8) -> ScanSummary {
    let mut selected_count = 0_u32;
    let mut selected_bytes = 0_u64;
    let mut locked_count = 0_u32;

    for candidate in candidates {
        if candidate.risk_level == RiskLevel::Blocked {
            locked_count += 1;
        }

        if candidate.selected && candidate.risk_level != RiskLevel::Blocked {
            selected_count += 1;
            selected_bytes += candidate.size_bytes;
        }
    }

    ScanSummary {
        estimated_reclaim_bytes: selected_bytes,
        candidate_count: candidates.len() as u32,
        locked_count,
        progress_percent,
        selected_count,
        selected_bytes,
    }
}

fn detected_volumes() -> Vec<VolumeInfo> {
    let disks = Disks::new_with_refreshed_list();
    let mut volumes = Vec::new();

    for disk in disks.list() {
        let mount_point = disk.mount_point().to_string_lossy().to_string();
        let filesystem = disk.file_system().to_string_lossy().to_string();
        let id = volume_id_from_mount(&mount_point);
        let label = disk.name().to_string_lossy().to_string();

        volumes.push(VolumeInfo {
            id: id.clone(),
            label: if label.is_empty() { id } else { label },
            mount_point,
            filesystem: if filesystem.is_empty() {
                "Unknown".to_string()
            } else {
                filesystem
            },
            total_bytes: disk.total_space(),
            available_bytes: disk.available_space(),
            selected: false,
            supports_fast_index: supports_fast_index(disk.file_system().to_string_lossy().as_ref()),
        });
    }

    if volumes.is_empty() {
        let mount_point = env::current_dir()
            .ok()
            .and_then(|path| {
                path.components()
                    .next()
                    .map(|component| component.as_os_str().to_owned())
            })
            .map(|component| component.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string());

        volumes.push(VolumeInfo {
            id: volume_id_from_mount(&mount_point),
            label: "Current".to_string(),
            mount_point,
            filesystem: "Unknown".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: false,
        });
    }

    mark_default_selected_volume(&mut volumes);

    volumes
}

fn mark_default_selected_volume(volumes: &mut [VolumeInfo]) {
    mark_default_selected_volume_with_id(volumes, default_selected_volume_id());
}

fn mark_default_selected_volume_with_id(volumes: &mut [VolumeInfo], default_id: Option<String>) {
    if volumes.is_empty() {
        return;
    }

    if let Some(default_id) = default_id {
        let mut matched = false;
        for volume in volumes.iter_mut() {
            volume.selected = volume.id.eq_ignore_ascii_case(&default_id);
            matched |= volume.selected;
        }
        if matched {
            return;
        }
    }

    if let Some(first) = volumes.first_mut() {
        first.selected = true;
    }
}

fn default_selected_volume_id() -> Option<String> {
    if let Ok(system_drive) = env::var("SystemDrive") {
        let id = volume_id_from_mount(&system_drive);
        if !id.is_empty() {
            return Some(id);
        }
    }

    env::var("WINDIR")
        .ok()
        .map(|path| volume_id_from_mount(&path))
}

fn apply_volume_selection(
    mut volumes: Vec<VolumeInfo>,
    requested_volume_ids: &[String],
) -> Vec<VolumeInfo> {
    if requested_volume_ids.is_empty() {
        return volumes;
    }

    let requested = requested_volume_ids
        .iter()
        .map(|id| id.to_ascii_uppercase())
        .collect::<HashSet<_>>();

    for volume in volumes.iter_mut() {
        volume.selected = requested.contains(&volume.id.to_ascii_uppercase());
    }

    volumes
}

fn scan_candidates_with_control<C: ScanController + ?Sized>(
    volumes: &[VolumeInfo],
    mode: ScanMode,
    request_rules: &[CompiledCleanupRule],
    control: &C,
    session_id: Option<&str>,
    inventory_sink: &mut dyn InventorySink,
) -> ScanRun {
    let scan_started = Instant::now();
    let rule_compile_started = Instant::now();
    let rules = scan_rules(request_rules);
    let rule_compile_ms = rule_compile_started.elapsed().as_millis();
    control.checkpoint();

    let primary_scan_started = Instant::now();
    let mut run = match mode {
        ScanMode::Quick => quick_scan_candidates_with_control(volumes, control),
        ScanMode::Full => full_scan_candidates_with_control(
            volumes,
            control,
            session_id.unwrap_or("transient"),
            inventory_sink,
        ),
    };
    let primary_scan_ms = primary_scan_started.elapsed().as_millis();
    control.checkpoint();

    let rule_scan_started = Instant::now();
    control.on_phase(ScanPhase::Analyzing);
    let mut rule_run = scan_rule_candidates_with_control(volumes, &rules, control);
    let rule_scan_ms = rule_scan_started.elapsed().as_millis();

    run.warnings.append(&mut rule_run.warnings);
    run.candidates.append(&mut rule_run.candidates);

    let dedupe_started = Instant::now();
    run.candidates = dedupe_candidates_by_path(run.candidates);
    let dedupe_ms = dedupe_started.elapsed().as_millis();

    if !rules.is_empty() {
        run.backend = format!("{} + rules", run.backend);
    }

    scan_debug_log!(
        "[scan-perf] mode={:?} rules={} compile={}ms primary={}ms rules={}ms dedupe={}ms total={}ms",
        mode,
        rules.len(),
        rule_compile_ms,
        primary_scan_ms,
        rule_scan_ms,
        dedupe_ms,
        scan_started.elapsed().as_millis()
    );

    run
}

pub fn built_in_rules() -> &'static [CompiledCleanupRule] {
    BUILT_IN_RULES.get_or_init(|| {
        compile_cleanup_rules_yaml(
            include_str!("../../../rules/default-rules.yaml"),
            RuleSourceKind::BuiltIn,
        )
        .rules
    })
}

fn scan_rules(request_rules: &[CompiledCleanupRule]) -> Vec<CompiledCleanupRule> {
    let mut rules = built_in_rules().to_vec();
    rules.extend(request_rules.iter().cloned());
    rules
}

#[cfg(test)]
fn scan_rule_candidates(volumes: &[VolumeInfo], rules: &[CompiledCleanupRule]) -> ScanRun {
    let control = NoopScanController;
    scan_rule_candidates_with_control(volumes, rules, &control)
}

fn scan_rule_candidates_with_control<C: ScanController + ?Sized>(
    volumes: &[VolumeInfo],
    rules: &[CompiledCleanupRule],
    control: &C,
) -> ScanRun {
    let selected_volumes = selected_volume_ids_from_infos(volumes);
    let mut warnings = Vec::new();
    let mut roots = Vec::new();
    let mut rule_path_keys = HashSet::new();
    let mut path_indexes = HashMap::new();
    let mut expanded_path_count = 0_usize;
    let mut skipped_unselected_count = 0_usize;
    let expand_started = Instant::now();

    for rule in rules {
        control.checkpoint();
        for path in expand_rule_paths_with_control(
            rule,
            &mut warnings,
            volumes,
            &selected_volumes,
            &mut skipped_unselected_count,
            control,
        ) {
            expanded_path_count += 1;
            let key = normalize_path_for_id(&path);
            if !selected_volumes.is_empty()
                && !selected_volumes.contains(&volume_id_for_path(&path, volumes))
            {
                skipped_unselected_count += 1;
                continue;
            }

            if !rule_path_keys.insert(format!("{}|{}", rule.id, key)) {
                continue;
            }

            let root = ScanRoot {
                path,
                display_name: rule.name.clone(),
                category: rule.category.clone(),
                rule: Some(rule.clone()),
            };

            if let Some(index) = path_indexes.get(&key).copied() {
                roots[index] = root;
            } else {
                path_indexes.insert(key, roots.len());
                roots.push(root);
            }
        }
    }
    let expand_ms = expand_started.elapsed().as_millis();

    let scan_started = Instant::now();
    let candidates = scan_roots_parallel(roots, volumes, control);
    let scan_ms = scan_started.elapsed().as_millis();

    scan_debug_log!(
        "[scan-perf] rules detail rules={} expanded_paths={} skipped_unselected={} merged_roots={} candidates={} expand={}ms scan={}ms",
        rules.len(),
        expanded_path_count,
        skipped_unselected_count,
        path_indexes.len(),
        candidates.len(),
        expand_ms,
        scan_ms
    );

    ScanRun {
        candidates,
        backend: "rules".to_string(),
        warnings,
        coverage: ScanCoverage::default(),
        space_summary: Vec::new(),
    }
}

/// Sizing a rule root means walking its whole subtree, so the work is dominated
/// by disk latency rather than CPU. Running the roots one at a time left most of
/// the queue depth unused; chunking them across scoped threads overlaps the
/// waits. Chunks are merged in order so candidate ordering stays deterministic,
/// which the frontend selection tests rely on.
fn scan_roots_parallel<C: ScanController + ?Sized>(
    roots: Vec<ScanRoot>,
    volumes: &[VolumeInfo],
    control: &C,
) -> Vec<CleanupCandidate> {
    if roots.len() < MIN_PARALLEL_SCAN_ROOTS {
        let mut stats_cache = ScanStatsCache::default();

        return roots
            .into_iter()
            .filter_map(|root| {
                control.checkpoint();
                control.on_location(&root.path);
                scan_root_candidate_with_control(root, volumes, control, &mut stats_cache)
            })
            .collect();
    }

    let worker_count = scan_worker_count(roots.len());
    let chunk_size = roots.len().div_ceil(worker_count);
    let chunks: Vec<&[ScanRoot]> = roots.chunks(chunk_size).collect();

    let chunk_results: Vec<Vec<CleanupCandidate>> = thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                scope.spawn(move || {
                    // Each worker keeps its own directory-stats cache. Sharing one
                    // behind a lock would serialize the hot path again, and the
                    // roots handed to different workers rarely overlap.
                    let mut stats_cache = ScanStatsCache::default();

                    chunk
                        .iter()
                        .filter_map(|root| {
                            control.checkpoint();
                            control.on_location(&root.path);
                            scan_root_candidate_with_control(
                                root.clone(),
                                volumes,
                                control,
                                &mut stats_cache,
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or_default())
            .collect()
    });

    chunk_results.into_iter().flatten().collect()
}

fn scan_worker_count(root_count: usize) -> usize {
    let available_parallelism = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4);

    root_count
        .max(1)
        .min(available_parallelism)
        .min(MAX_SCAN_WORKERS)
}

fn expand_rule_paths_with_control<C: ScanController + ?Sized>(
    rule: &CompiledCleanupRule,
    warnings: &mut Vec<String>,
    volumes: &[VolumeInfo],
    selected_volumes: &HashSet<String>,
    skipped_unselected_count: &mut usize,
    control: &C,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    for raw_path in &rule.paths {
        control.checkpoint();
        let Some(expanded) = expand_supported_env_vars(raw_path) else {
            warnings.push(format!(
                "{}：规则路径环境变量无法展开：{}",
                rule.id, raw_path
            ));
            continue;
        };

        if !rule_path_may_match_selected_volumes(&expanded, volumes, selected_volumes) {
            *skipped_unselected_count += 1;
            continue;
        }

        if expanded.contains("\\**\\") {
            let matches = expand_double_star_path_glob_with_control(&expanded, control);
            if matches.is_empty() {
                warnings.push(format!(
                    "{}：规则路径未匹配任何现有目录：{}",
                    rule.id, raw_path
                ));
            }
            paths.extend(matches);
        } else if has_path_wildcards(&expanded) {
            let matches = expand_simple_path_glob_with_control(&expanded, control);
            if matches.is_empty() {
                warnings.push(format!(
                    "{}：规则路径未匹配任何现有目录：{}",
                    rule.id, raw_path
                ));
            }
            paths.extend(matches);
        } else {
            paths.push(PathBuf::from(expanded));
        }
    }

    paths
}

fn rule_path_may_match_selected_volumes(
    expanded_path: &str,
    volumes: &[VolumeInfo],
    selected_volumes: &HashSet<String>,
) -> bool {
    selected_volumes.is_empty()
        || selected_volumes.contains(&volume_id_for_path(Path::new(expanded_path), volumes))
}

fn expand_supported_env_vars(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if !trimmed.starts_with('%') {
        return Some(trimmed.to_string());
    }

    let end = trimmed[1..].find('%')? + 1;
    let variable = &trimmed[..=end];
    let remainder = &trimmed[(end + 1)..];
    let value = match variable.to_ascii_lowercase().as_str() {
        "%localappdata%" => env::var("LOCALAPPDATA").ok(),
        "%locallowappdata%" => env::var("LOCALLOWAPPDATA").ok().or_else(|| {
            env::var("USERPROFILE")
                .ok()
                .map(|path| format!("{path}\\AppData\\LocalLow"))
        }),
        "%appdata%" => env::var("APPDATA").ok(),
        "%userprofile%" => env::var("USERPROFILE").ok(),
        "%documents%" => env::var("DOCUMENTS").ok().or_else(|| {
            env::var("USERPROFILE")
                .ok()
                .map(|path| format!("{path}\\Documents"))
        }),
        "%temp%" => env::var("TEMP").ok(),
        "%tmp%" => env::var("TMP").ok(),
        "%programdata%" => env::var("ProgramData").ok(),
        "%commonappdata%" => env::var("ProgramData").ok(),
        "%allusersprofile%" => env::var("ALLUSERSPROFILE").ok(),
        "%public%" => env::var("PUBLIC").ok(),
        "%systemdrive%" => env::var("SystemDrive").ok(),
        "%programfiles%" => env::var("ProgramFiles").ok(),
        "%programfiles(x86)%" => env::var("ProgramFiles(x86)").ok(),
        "%programw6432%" => env::var("ProgramW6432").ok(),
        "%commonprogramfiles%" => env::var("CommonProgramFiles").ok(),
        "%commonprogramfiles(x86)%" => env::var("CommonProgramFiles(x86)").ok(),
        "%commonprogramw6432%" => env::var("CommonProgramW6432").ok(),
        "%windir%" => env::var("WINDIR").ok(),
        "%systemroot%" => env::var("SystemRoot").ok(),
        _ => None,
    }?;

    Some(format!("{value}{remainder}"))
}

fn has_path_wildcards(path: &str) -> bool {
    path.contains('*') || path.contains('?')
}

fn expand_simple_path_glob_with_control<C: ScanController + ?Sized>(
    path: &str,
    control: &C,
) -> Vec<PathBuf> {
    let normalized = path.replace('/', "\\");
    let parts = normalized
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    if parts.is_empty() {
        return Vec::new();
    }

    let mut roots = if normalized.len() >= 3 && normalized.as_bytes()[1] == b':' {
        vec![PathBuf::from(format!("{}\\", &normalized[..2]))]
    } else {
        vec![PathBuf::new()]
    };
    let start_index = if normalized.len() >= 3 && normalized.as_bytes()[1] == b':' {
        1
    } else {
        0
    };

    for part in parts.into_iter().skip(start_index) {
        control.checkpoint();
        let mut next_roots = Vec::new();
        if has_path_wildcards(part) {
            for root in roots {
                control.checkpoint();
                let Ok(entries) = fs::read_dir(&root) else {
                    continue;
                };
                for entry in entries.flatten().take(200) {
                    control.checkpoint();
                    let name = entry.file_name().to_string_lossy().to_string();
                    if glob_matches(&part.to_ascii_lowercase(), &name.to_ascii_lowercase()) {
                        next_roots.push(entry.path());
                    }
                }
            }
        } else {
            next_roots.extend(roots.into_iter().map(|root| root.join(part)));
        }
        roots = next_roots;
    }

    roots
}

fn expand_double_star_path_glob_with_control<C: ScanController + ?Sized>(
    path: &str,
    control: &C,
) -> Vec<PathBuf> {
    let normalized = path.replace('/', "\\");
    let Some((prefix, suffix)) = normalized.split_once("\\**\\") else {
        return expand_simple_path_glob_with_control(&normalized, control);
    };

    let prefix_roots = if has_path_wildcards(prefix) {
        expand_simple_path_glob_with_control(prefix, control)
    } else {
        vec![PathBuf::from(prefix)]
    };

    let suffix = suffix.trim().trim_start_matches(['\\', '/']).to_string();
    if suffix.is_empty() {
        return prefix_roots;
    }

    let mut matches = Vec::new();
    let suffix_lower = suffix.to_ascii_lowercase();

    for root in prefix_roots
        .into_iter()
        .filter(|path| path.exists() && path.is_dir())
    {
        control.checkpoint();
        let mut stack = vec![root.clone()];
        let mut visited = 0_u64;

        while let Some(directory) = stack.pop() {
            control.checkpoint();
            if visited >= MAX_QUICK_SCAN_ENTRIES {
                break;
            }

            let Ok(entries) = fs::read_dir(&directory) else {
                continue;
            };

            for entry in entries.flatten() {
                control.checkpoint();
                if visited >= MAX_QUICK_SCAN_ENTRIES {
                    break;
                }
                visited += 1;

                let entry_path = entry.path();
                let Ok(metadata) = fs::symlink_metadata(&entry_path) else {
                    continue;
                };
                if is_reparse_point_or_symlink(&metadata) {
                    continue;
                }

                if metadata.is_dir() {
                    stack.push(entry_path.clone());
                }

                let Ok(relative) = entry_path.strip_prefix(&root) else {
                    continue;
                };
                let relative = relative.to_string_lossy().replace('/', "\\");
                if glob_matches(&suffix_lower, &relative.to_ascii_lowercase()) {
                    matches.push(entry_path);
                }
            }
        }
    }

    matches
}

fn dedupe_candidates_by_path(candidates: Vec<CleanupCandidate>) -> Vec<CleanupCandidate> {
    let mut deduped = Vec::new();
    let mut indexes = HashMap::new();

    for candidate in candidates {
        let key = normalize_path_for_id(Path::new(&candidate.path));
        if let Some(index) = indexes.get(&key).copied() {
            if should_prefer_candidate(&candidate, &deduped[index]) {
                deduped[index] = candidate;
            }
        } else {
            indexes.insert(key, deduped.len());
            deduped.push(candidate);
        }
    }

    deduped
}

fn should_prefer_candidate(candidate: &CleanupCandidate, existing: &CleanupCandidate) -> bool {
    candidate.cleanup_policy.rule_id.is_some()
        && (existing.cleanup_policy.rule_id.is_none()
            || existing.cleanup_policy.rule_id != candidate.cleanup_policy.rule_id)
}

fn quick_scan_candidates_with_control<C: ScanController + ?Sized>(
    volumes: &[VolumeInfo],
    control: &C,
) -> ScanRun {
    let selected_volumes = selected_volume_ids_from_infos(volumes);
    let mut roots = discover_scan_roots();
    roots.extend(discover_volume_quick_roots(volumes));

    let mut candidates = Vec::new();
    let mut stats_cache = ScanStatsCache::default();
    // Quick scan visits a fixed root list of unknown size, so no denominator exists.
    control.on_total_files(None);
    control.on_phase(ScanPhase::Walking);
    for root in roots {
        control.checkpoint();
        control.on_location(&root.path);
        let Some(candidate) =
            scan_root_candidate_with_control(root, volumes, control, &mut stats_cache)
        else {
            continue;
        };
        if selected_volumes.is_empty() || selected_volumes.contains(&candidate.volume_id) {
            control.on_candidate(candidate.size_bytes);
            candidates.push(candidate);
        }
    }

    ScanRun {
        candidates,
        backend: "quick-walk".to_string(),
        warnings: Vec::new(),
        coverage: ScanCoverage::default(),
        space_summary: Vec::new(),
    }
}

fn full_scan_candidates_with_control<C: ScanController + ?Sized>(
    volumes: &[VolumeInfo],
    control: &C,
    session_id: &str,
    inventory_sink: &mut dyn InventorySink,
) -> ScanRun {
    let mut all_candidates = Vec::new();
    let mut backends = Vec::new();
    let mut warnings = Vec::new();
    let mut volume_coverages = Vec::new();
    let mut space_summary = Vec::new();

    control.on_total_files(full_scan_total_files_estimate(volumes));

    for volume in volumes.iter().filter(|volume| volume.selected) {
        control.checkpoint();
        control.on_volume(&volume.id);
        let run = scan_full_volume_with_control(volume, control, session_id, inventory_sink);
        backends.push(format!("{}:{}", volume.id, run.backend));
        warnings.extend(run.warnings);
        all_candidates.extend(run.candidates);
        volume_coverages.push(run.coverage);
        space_summary.push(run.space_summary);
    }

    all_candidates.sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes));

    let coverage = combine_scan_coverage(volume_coverages);
    ScanRun {
        candidates: all_candidates,
        backend: if backends.is_empty() {
            "full-none".to_string()
        } else {
            backends.join(", ")
        },
        warnings,
        coverage,
        space_summary,
    }
}

fn scan_full_volume_with_control<C: ScanController + ?Sized>(
    volume: &VolumeInfo,
    control: &C,
    session_id: &str,
    inventory_sink: &mut dyn InventorySink,
) -> VolumeScanRun {
    control.checkpoint();
    control.on_phase(ScanPhase::Walking);
    let run = inventory::scan_volume_inventory(session_id, volume, control, inventory_sink);
    let warnings = run
        .coverage
        .gaps
        .iter()
        .filter(|gap| {
            !matches!(
                gap.reason,
                CoverageGapReason::ReparseNotFollowed | CoverageGapReason::IdentityFallback
            )
        })
        .map(|gap| {
            format!(
                "{}: 全盘 inventory 存在 {:?} 覆盖缺口（{} 项）",
                volume.id, gap.reason, gap.count
            )
        })
        .collect();
    VolumeScanRun {
        candidates: run.candidates,
        backend: run.coverage.backend.clone(),
        warnings,
        coverage: run.coverage,
        space_summary: run.summary,
    }
}

fn combine_scan_coverage(volumes: Vec<VolumeCoverage>) -> ScanCoverage {
    let status = if volumes.is_empty() {
        ScanCoverageStatus::NotStarted
    } else if volumes
        .iter()
        .any(|volume| volume.status == ScanCoverageStatus::Failed)
    {
        ScanCoverageStatus::Failed
    } else if volumes
        .iter()
        .any(|volume| volume.status == ScanCoverageStatus::Cancelled)
    {
        ScanCoverageStatus::Cancelled
    } else if volumes
        .iter()
        .any(|volume| volume.status == ScanCoverageStatus::Partial)
    {
        ScanCoverageStatus::Partial
    } else {
        ScanCoverageStatus::Complete
    };
    let gaps = volumes
        .iter()
        .flat_map(|volume| volume.gaps.iter().cloned())
        .collect();
    ScanCoverage {
        status,
        visited_entries: volumes.iter().map(|volume| volume.visited_entries).sum(),
        indexed_entries: volumes.iter().map(|volume| volume.indexed_entries).sum(),
        logical_bytes: volumes.iter().map(|volume| volume.logical_bytes).sum(),
        allocated_bytes: volumes.iter().map(|volume| volume.allocated_bytes).sum(),
        volumes,
        gaps,
    }
}

fn full_scan_total_files_estimate(volumes: &[VolumeInfo]) -> Option<u64> {
    let mut total = 0_u64;

    for volume in volumes.iter().filter(|volume| volume.selected) {
        if !supports_fast_index(&volume.filesystem) {
            return None;
        }
        total = total.saturating_add(ntfs_mft_record_estimate(volume)?);
    }

    (total > 0).then_some(total)
}

#[cfg(windows)]
fn ntfs_mft_record_estimate(volume: &VolumeInfo) -> Option<u64> {
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING,
        },
        System::{
            Ioctl::{FSCTL_GET_NTFS_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER},
            IO::DeviceIoControl,
        },
    };

    struct VolumeHandle(HANDLE);

    impl Drop for VolumeHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    let device_path = volume_device_path(volume).ok()?;
    let wide_path = device_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return None;
    }

    let _handle = VolumeHandle(handle);
    let mut data = NTFS_VOLUME_DATA_BUFFER::default();
    let mut bytes_returned = 0_u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            null_mut(),
            0,
            &mut data as *mut NTFS_VOLUME_DATA_BUFFER as *mut _,
            size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
            &mut bytes_returned,
            null_mut(),
        )
    };

    if ok == 0 || data.BytesPerFileRecordSegment == 0 || data.MftValidDataLength <= 0 {
        return None;
    }

    let records = data.MftValidDataLength as u64 / u64::from(data.BytesPerFileRecordSegment);
    Some(records)
}

#[cfg(not(windows))]
fn ntfs_mft_record_estimate(_volume: &VolumeInfo) -> Option<u64> {
    None
}

#[cfg(test)]
fn walk_full_volume(volume: &VolumeInfo) -> VolumeScanRun {
    let control = NoopScanController;
    walk_full_volume_with_control(volume, &control)
}

#[allow(dead_code)]
fn walk_full_volume_with_control<C: ScanController + ?Sized>(
    volume: &VolumeInfo,
    control: &C,
) -> VolumeScanRun {
    let root = PathBuf::from(&volume.mount_point);
    let mut context = FullWalkContext {
        volume: volume.clone(),
        candidates: Vec::new(),
        visited_entries: 0,
        warnings: Vec::new(),
        truncated: false,
    };

    let _ = walk_full_directory(&root, 0, &mut context, control);

    if context.truncated {
        context.warnings.push(format!(
            "{}: 全盘递归扫描达到 {} 项上限，结果可能不完整",
            volume.id, MAX_FULL_SCAN_ENTRIES
        ));
    }

    context
        .candidates
        .sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes));

    VolumeScanRun {
        candidates: context.candidates,
        backend: "walk".to_string(),
        warnings: context.warnings,
        coverage: VolumeCoverage::default(),
        space_summary: VolumeSpaceSummary::default(),
    }
}

#[allow(dead_code)]
fn fast_scan_fallback_warning(volume: &VolumeInfo, error: &str) -> String {
    if error.contains("访问被拒绝") || error.contains("错误码 5") {
        return format!(
            "{}: 当前没有管理员权限，无法读取 NTFS USN/MFT 快速索引，已回退到递归扫描；结果仍可用，但会更慢。详情：{}",
            volume.id, error
        );
    }

    format!(
        "{}: NTFS USN/MFT 快速扫描不可用，已回退到递归扫描；结果仍可用，但会更慢。详情：{}",
        volume.id, error
    )
}

#[allow(dead_code)]
fn walk_full_directory<C: ScanController + ?Sized>(
    path: &Path,
    depth: usize,
    context: &mut FullWalkContext,
    control: &C,
) -> DirectoryStats {
    control.checkpoint();
    let mut stats = DirectoryStats::default();

    if depth > MAX_FULL_SCAN_DEPTH {
        context.truncated = true;
        stats.truncated = true;
        return stats;
    }

    let Ok(entries) = fs::read_dir(path) else {
        if context.warnings.len() < 20 {
            context
                .warnings
                .push(format!("无法读取目录：{}", path.to_string_lossy()));
        }
        return stats;
    };

    for entry in entries.flatten() {
        control.checkpoint();
        if context.visited_entries >= MAX_FULL_SCAN_ENTRIES {
            context.truncated = true;
            stats.truncated = true;
            return stats;
        }

        context.visited_entries += 1;
        stats.children_count = stats.children_count.saturating_add(1);
        control.on_visited(1);

        let child_path = entry.path();
        control.on_location(&child_path);
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let file_type = metadata.file_type();

        if file_type.is_symlink() || should_skip_full_scan_path(&child_path) {
            continue;
        }

        if file_type.is_dir() {
            let child_stats = walk_full_directory(&child_path, depth + 1, context, control);
            stats.size_bytes = stats.size_bytes.saturating_add(child_stats.size_bytes);
            stats.children_count = stats
                .children_count
                .saturating_add(child_stats.children_count);
            stats.truncated |= child_stats.truncated;

            if let Some(candidate) =
                full_directory_candidate(&child_path, child_stats, &context.volume)
            {
                control.on_candidate(candidate.size_bytes);
                context.candidates.push(candidate);
            }
        } else if file_type.is_file() {
            let size_bytes = metadata.len();
            stats.size_bytes = stats.size_bytes.saturating_add(size_bytes);

            if let Some(candidate) = full_file_candidate(&child_path, size_bytes, &context.volume) {
                control.on_candidate(candidate.size_bytes);
                context.candidates.push(candidate);
            }
        }
    }

    stats
}

fn full_directory_candidate(
    path: &Path,
    stats: DirectoryStats,
    volume: &VolumeInfo,
) -> Option<CleanupCandidate> {
    if stats.size_bytes == 0 {
        return None;
    }

    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string());
    let normalized_name = name.to_ascii_lowercase();
    let normalized_path = normalize_path_for_id(path);

    let (category, risk_level, default_selected, reason, confidence) =
        if let Some(classification) = classify_windows_directory(&normalized_path) {
            classification
        } else if is_known_browser_cache(&normalized_path) {
            (
                "浏览器缓存",
                RiskLevel::SafeRecommended,
                true,
                "已知浏览器缓存目录，可按需重新生成",
                92,
            )
        } else if is_dependency_store_path(&normalized_path) {
            (
                "开发依赖缓存",
                RiskLevel::ReviewRequired,
                false,
                "包管理器或开发工具依赖缓存，删除后可能需要重新下载依赖",
                82,
            )
        } else if is_known_regenerable_app_cache(&normalized_path) {
            (
                "应用缓存",
                RiskLevel::SafeRecommended,
                true,
                "已知可重建应用缓存，删除后会按需重新生成",
                86,
            )
        } else if is_cache_directory_name(&normalized_name) {
            (
                "应用缓存",
                RiskLevel::CautiousRecommended,
                false,
                "全盘扫描发现的缓存目录，需要确认所属应用",
                70,
            )
        } else if is_temp_directory_name(&normalized_name) || normalized_path.contains("\\temp\\") {
            (
                "临时文件",
                RiskLevel::SafeRecommended,
                true,
                "全盘扫描发现的临时目录",
                82,
            )
        } else if is_log_directory_name(&normalized_name) {
            (
                "日志目录",
                RiskLevel::CautiousRecommended,
                false,
                "全盘扫描发现的日志目录",
                72,
            )
        } else if is_build_directory_name(&normalized_name) {
            if is_project_build_output_path(path, &normalized_path) {
                (
                    "构建产物",
                    RiskLevel::ReviewRequired,
                    false,
                    "已识别项目目录下的构建输出，清理前必须确认项目上下文",
                    68,
                )
            } else {
                (
                    "构建产物",
                    RiskLevel::Blocked,
                    false,
                    "名称类似构建输出，但不在可识别项目目录；可能是应用运行依赖，已禁止清理",
                    92,
                )
            }
        } else {
            return None;
        };

    Some(apply_cleanup_support_policy(CleanupCandidate {
        id: candidate_id_for_path(path),
        parent_id: None,
        display_name: name,
        path: path.to_string_lossy().to_string(),
        volume_id: volume.id.clone(),
        object_type: ObjectType::Directory,
        category: category.to_string(),
        size_bytes: stats.size_bytes,
        children_count: stats.children_count,
        risk_level: risk_level.clone(),
        default_selected,
        selected: default_selected && risk_level != RiskLevel::Blocked,
        delete_strategy: DeleteStrategy::MoveToRecycleBin,
        reason: if stats.truncated {
            format!("{}；目录过深或扫描达到上限，清理前必须复核", reason)
        } else {
            reason.to_string()
        },
        confidence,
        source: source_info_for_path(path),
        cleanup_policy: CleanupPolicy::default(),
    }))
}

fn full_file_candidate(
    path: &Path,
    size_bytes: u64,
    volume: &VolumeInfo,
) -> Option<CleanupCandidate> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let normalized_name = name.to_ascii_lowercase();
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    let normalized_path = normalize_path_for_id(path);
    let (category, risk_level, default_selected, reason, confidence) =
        if let Some(classification) = classify_windows_file(&normalized_path, &normalized_name) {
            classification
        } else if matches!(
            extension.as_str(),
            "tmp" | "temp" | "dmp" | "dump" | "log" | "old" | "bak"
        ) {
            (
                "可疑临时文件",
                RiskLevel::CautiousRecommended,
                false,
                "全盘扫描发现的临时、日志或备份文件",
                64,
            )
        } else if size_bytes >= LARGE_FILE_THRESHOLD_BYTES {
            (
                "大文件",
                RiskLevel::ReviewRequired,
                false,
                "大文件仅作为空间分析候选，不默认清理",
                50,
            )
        } else if normalized_name.ends_with(".crdownload") || normalized_name.ends_with(".part") {
            (
                "下载残留",
                RiskLevel::CautiousRecommended,
                false,
                "疑似未完成下载残留，需要确认下载状态",
                62,
            )
        } else {
            return None;
        };

    Some(apply_cleanup_support_policy(CleanupCandidate {
        id: candidate_id_for_path(path),
        parent_id: None,
        display_name: name,
        path: path.to_string_lossy().to_string(),
        volume_id: volume.id.clone(),
        object_type: ObjectType::File,
        category: category.to_string(),
        size_bytes,
        children_count: 0,
        risk_level: risk_level.clone(),
        default_selected,
        selected: default_selected && risk_level != RiskLevel::Blocked,
        delete_strategy: DeleteStrategy::MoveToRecycleBin,
        reason: reason.to_string(),
        confidence,
        source: source_info_for_path(path),
        cleanup_policy: CleanupPolicy::default(),
    }))
}

fn is_cache_directory_name(name: &str) -> bool {
    matches!(
        name,
        "cache" | "caches" | "code cache" | "gpucache" | "shadercache" | ".cache"
    ) || name.ends_with("-cache")
}

fn is_temp_directory_name(name: &str) -> bool {
    matches!(name, "temp" | "tmp" | "temporary files")
}

fn is_log_directory_name(name: &str) -> bool {
    matches!(name, "log" | "logs" | "crashdumps" | "crash dumps")
}

fn is_build_directory_name(name: &str) -> bool {
    matches!(
        name,
        "target" | "build" | "dist" | "out" | ".next" | ".turbo"
    )
}

fn is_project_build_output_path(path: &Path, normalized_path: &str) -> bool {
    if is_application_install_path(path, normalized_path) {
        return false;
    }

    path.ancestors()
        .skip(1)
        .take(8)
        .any(looks_like_project_root)
}

fn looks_like_project_root(path: &Path) -> bool {
    [
        ".git",
        "package.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "package-lock.json",
        "Cargo.toml",
        "pyproject.toml",
        "poetry.lock",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "settings.gradle",
        "deno.json",
        "vite.config.ts",
        "vite.config.js",
        "next.config.ts",
        "next.config.js",
    ]
    .iter()
    .any(|marker| path.join(marker).exists())
        || directory_contains_extension(path, "sln")
        || directory_contains_extension(path, "csproj")
}

fn directory_contains_extension(path: &Path, extension: &str) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };

    entries.flatten().take(80).any(|entry| {
        entry
            .path()
            .extension()
            .map(|value| value.to_string_lossy().eq_ignore_ascii_case(extension))
            .unwrap_or(false)
    })
}

fn is_known_browser_cache(normalized_path: &str) -> bool {
    ((normalized_path.contains("\\google\\chrome\\")
        || normalized_path.contains("\\microsoft\\edge\\")
        || normalized_path.contains("\\mozilla\\firefox\\"))
        && is_regenerable_cache_path(normalized_path))
        || normalized_path.contains("\\microsoft\\windows\\inetcache")
}

fn is_dependency_store_path(normalized_path: &str) -> bool {
    normalized_path.contains("\\npm-cache")
        || normalized_path.contains("\\npm\\cache")
        || normalized_path.contains("\\.pnpm-store")
        || normalized_path.contains("\\pnpm\\store")
        || normalized_path.contains("\\yarn\\cache")
        || normalized_path.contains("\\pip\\cache")
        || normalized_path.contains("\\uv\\cache")
        || normalized_path.contains("\\node-gyp\\cache")
        || normalized_path.contains("\\.gradle\\caches")
        || normalized_path.contains("\\gradle\\caches")
        || normalized_path.contains("\\pub\\cache")
        || normalized_path.contains("\\.pub-cache")
        || normalized_path.contains("\\nuget\\packages")
        || normalized_path.contains("\\nuget\\cache")
        || normalized_path.contains("\\composer\\cache")
        || normalized_path.contains("\\.cargo\\registry\\cache")
        || normalized_path.contains("\\.cache\\codex-runtimes")
        || normalized_path.contains("\\.cache\\chrome-devtools-mcp")
        || normalized_path.contains("\\.cache\\hyperframes")
}

fn is_known_regenerable_app_cache(normalized_path: &str) -> bool {
    normalized_path.contains("\\directx shader cache")
        || normalized_path.contains("\\dxcshadercache")
        || normalized_path.contains("\\nvidia\\dxcache")
        || normalized_path.contains("\\nvidia\\glcache")
}

fn should_skip_full_scan_path(path: &Path) -> bool {
    let normalized = normalize_path_for_id(path);

    normalized.contains("\\system volume information\\")
        || normalized.contains("\\$extend\\")
        || normalized.contains("\\windows\\winsxs\\")
        || normalized.contains("\\program files\\")
        || normalized.contains("\\program files (x86)\\")
        || normalized.contains("\\programfiles\\")
        || normalized.contains("\\windowsapps\\")
        || normalized.contains("\\wpsystem\\")
        || normalized.contains("\\config.msi\\")
        || is_application_runtime_payload_path(&normalized)
        || is_persistent_state_path(&normalized)
        || is_dependency_runtime_path(&normalized)
}

fn inventory_disposition_for_path(path: &Path) -> InventoryDisposition {
    if should_skip_full_scan_path(path) {
        return InventoryDisposition::Blocked;
    }

    match evaluate_cleanup_target_path(path) {
        PathGuardLevel::HardDeny(_) => InventoryDisposition::Blocked,
        PathGuardLevel::NeedsConfirm(_) => InventoryDisposition::AnalysisOnly,
        PathGuardLevel::Allowed => InventoryDisposition::Normal,
    }
}

fn format_windows_volume_open_error(device_path: &str, error: u32) -> String {
    if error == WINDOWS_ERROR_ACCESS_DENIED {
        return format!(
            "无法打开卷句柄 {device_path}：访问被拒绝（错误码 5）。读取 NTFS USN/MFT 快速索引需要以管理员身份运行"
        );
    }

    format!("无法打开卷句柄 {device_path}，错误码 {error}")
}

fn format_usn_ioctl_error(error: u32) -> String {
    if error == WINDOWS_ERROR_ACCESS_DENIED {
        return "FSCTL_ENUM_USN_DATA 访问被拒绝（错误码 5）。读取 NTFS USN/MFT 快速索引需要以管理员身份运行"
            .to_string();
    }

    format!("FSCTL_ENUM_USN_DATA 失败，错误码 {error}")
}

#[cfg(windows)]
#[allow(dead_code)]
fn scan_ntfs_usn_volume<C: ScanController + ?Sized>(
    volume: &VolumeInfo,
    control: &C,
) -> Result<Vec<CleanupCandidate>, String> {
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_HANDLE_EOF, ERROR_MORE_DATA, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_GENERIC_READ, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            Ioctl::{FSCTL_ENUM_USN_DATA, MFT_ENUM_DATA_V0, USN_RECORD_V2},
            IO::DeviceIoControl,
        },
    };

    struct VolumeHandle(HANDLE);

    impl Drop for VolumeHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    let device_path = volume_device_path(volume)?;
    let wide_path = device_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(format_windows_volume_open_error(&device_path, unsafe {
            GetLastError()
        }));
    }

    let _handle = VolumeHandle(handle);
    let mut input = MFT_ENUM_DATA_V0 {
        StartFileReferenceNumber: 0,
        LowUsn: 0,
        HighUsn: i64::MAX,
    };
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut entries = HashMap::<u64, UsnEntry>::new();

    loop {
        control.checkpoint();
        let mut bytes_returned = 0_u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_ENUM_USN_DATA,
                &input as *const MFT_ENUM_DATA_V0 as *const _,
                size_of::<MFT_ENUM_DATA_V0>() as u32,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_returned,
                null_mut(),
            )
        };

        if ok == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_HANDLE_EOF {
                break;
            }
            if error != ERROR_MORE_DATA || bytes_returned <= size_of::<i64>() as u32 {
                return Err(format_usn_ioctl_error(error));
            }
        }

        if bytes_returned <= size_of::<i64>() as u32 {
            break;
        }

        input.StartFileReferenceNumber =
            unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const u64) };

        let mut offset = size_of::<i64>();
        let returned = bytes_returned as usize;

        while offset + size_of::<u32>() <= returned {
            control.checkpoint();
            let record_length =
                unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const u32) }
                    as usize;
            if record_length == 0 || offset + record_length > returned {
                break;
            }

            let major_version =
                unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset + 4) as *const u16) };
            if major_version == 2 && record_length >= size_of::<USN_RECORD_V2>() {
                let record = unsafe {
                    std::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const USN_RECORD_V2)
                };
                let name_offset = offset + record.FileNameOffset as usize;
                let name_len = record.FileNameLength as usize / 2;
                if name_offset + name_len * 2 <= returned {
                    let name_slice = unsafe {
                        std::slice::from_raw_parts(
                            buffer.as_ptr().add(name_offset) as *const u16,
                            name_len,
                        )
                    };
                    let name = String::from_utf16_lossy(name_slice);
                    control.on_visited(1);
                    entries.insert(
                        record.FileReferenceNumber,
                        UsnEntry {
                            parent_reference: record.ParentFileReferenceNumber,
                            name,
                            attributes: record.FileAttributes,
                        },
                    );
                }
            }

            offset += record_length;

            if entries.len() >= MAX_USN_RECORDS {
                break;
            }
        }

        if entries.len() >= MAX_USN_RECORDS {
            break;
        }
    }

    if entries.is_empty() {
        return Err("USN 枚举没有返回可解析记录".to_string());
    }

    let mut candidates = Vec::new();
    let mut seen_paths = HashSet::new();
    control.on_phase(ScanPhase::Analyzing);

    for (reference, entry) in entries.iter() {
        control.checkpoint();
        let is_directory = (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        let normalized_name = entry.name.to_ascii_lowercase();
        let name_matches = if is_directory {
            is_cache_directory_name(&normalized_name)
                || is_temp_directory_name(&normalized_name)
                || is_log_directory_name(&normalized_name)
                || is_build_directory_name(&normalized_name)
        } else {
            file_name_is_cleanup_candidate(&normalized_name)
        };

        if !name_matches {
            continue;
        }

        let Some(path) = build_usn_path(&entries, *reference, &volume.mount_point) else {
            continue;
        };
        if should_skip_full_scan_path(&path) {
            continue;
        }
        if !seen_paths.insert(normalize_path_for_id(&path)) {
            continue;
        }

        control.on_location(&path);

        if is_directory {
            let stats = scan_directory_stats_with_control(&path, control);
            if let Some(candidate) = full_directory_candidate(&path, stats, volume) {
                control.on_candidate(candidate.size_bytes);
                candidates.push(candidate);
            }
        } else if let Ok(metadata) = fs::metadata(&path) {
            if let Some(candidate) = full_file_candidate(&path, metadata.len(), volume) {
                control.on_candidate(candidate.size_bytes);
                candidates.push(candidate);
            }
        }
    }

    candidates.sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes));
    Ok(candidates)
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn scan_ntfs_usn_volume<C: ScanController + ?Sized>(
    _volume: &VolumeInfo,
    _control: &C,
) -> Result<Vec<CleanupCandidate>, String> {
    Err("当前平台不支持 Windows NTFS USN 快速扫描".to_string())
}

fn volume_device_path(volume: &VolumeInfo) -> Result<String, String> {
    if volume.id.len() == 1 && volume.id.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Ok(format!("\\\\.\\{}:", volume.id.to_ascii_uppercase()));
    }

    Err(format!("不支持的卷标识：{}", volume.id))
}

#[allow(dead_code)]
fn build_usn_path(
    entries: &HashMap<u64, UsnEntry>,
    reference: u64,
    mount_point: &str,
) -> Option<PathBuf> {
    let mut components = Vec::new();
    let mut current = reference;
    let mut visited = HashSet::new();

    for _ in 0..128 {
        if !visited.insert(current) {
            return None;
        }

        let entry = entries.get(&current)?;
        if !entry.name.is_empty() && entry.name != "." {
            components.push(entry.name.clone());
        }

        if entry.parent_reference == current || !entries.contains_key(&entry.parent_reference) {
            break;
        }

        current = entry.parent_reference;
    }

    components.reverse();
    let mut path = PathBuf::from(mount_point);
    for component in components {
        path.push(component);
    }

    Some(path)
}

fn file_name_is_cleanup_candidate(name: &str) -> bool {
    name.ends_with(".tmp")
        || name.ends_with(".temp")
        || name.ends_with(".dmp")
        || name.ends_with(".dump")
        || name.ends_with(".log")
        || name.ends_with(".old")
        || name.ends_with(".bak")
        || name.ends_with(".crdownload")
        || name.ends_with(".part")
}

fn scan_root_candidate_with_control<C: ScanController + ?Sized>(
    root: ScanRoot,
    volumes: &[VolumeInfo],
    control: &C,
    stats_cache: &mut ScanStatsCache,
) -> Option<CleanupCandidate> {
    control.checkpoint();
    if !root.path.exists() {
        return None;
    }

    let metadata = fs::symlink_metadata(&root.path).ok()?;
    if is_reparse_point_or_symlink(&metadata) {
        return None;
    }

    let cleanup_policy = root
        .rule
        .as_ref()
        .map(cleanup_policy_for_rule)
        .unwrap_or_default();
    let object_type = if metadata.is_dir() {
        ObjectType::Directory
    } else if metadata.is_file() {
        ObjectType::File
    } else {
        return None;
    };
    let stats = match object_type {
        ObjectType::Directory => scan_directory_stats_for_policy_cached(
            &root.path,
            &cleanup_policy,
            control,
            stats_cache,
        ),
        ObjectType::File => {
            control.checkpoint();
            if cleanup_policy_allows_path(&root.path, &metadata, &cleanup_policy).is_ok() {
                DirectoryStats {
                    size_bytes: metadata.len(),
                    children_count: 0,
                    truncated: false,
                }
            } else {
                DirectoryStats::default()
            }
        }
        ObjectType::VirtualGroup => DirectoryStats::default(),
    };
    let path = root.path.to_string_lossy().to_string();
    let normalized_path = normalize_path_for_id(&root.path);
    let (category, risk_level, default_selected, reason, confidence, source) =
        if let Some(rule) = &root.rule {
            (
                rule.category.as_str(),
                rule.risk_level.clone(),
                rule.default_selected,
                rule.note.as_str(),
                confidence_for_rule_source(&rule.source),
                source_info_for_rule(rule, &root.path),
            )
        } else if let Some(classification) = classify_windows_directory(&normalized_path) {
            (
                classification.0,
                classification.1,
                classification.2,
                classification.3,
                classification.4,
                source_info_for_path(&root.path),
            )
        } else {
            let classification = classify_application_cache(&path, false);
            (
                root.category.as_str(),
                classification.risk_level,
                classification.default_selected,
                classification.reason,
                classification.confidence,
                source_info_for_path(&root.path),
            )
        };
    let default_selected = default_selected
        && stats.size_bytes > 0
        && cleanup_policy.method != RuleCleanupMethod::Manual;
    let reason = if stats.truncated {
        format!("{reason}；扫描达到首版上限，清理前需要重新校验")
    } else {
        reason.to_string()
    };
    let reason = rule_cleanup_reason(reason, &cleanup_policy);
    let delete_strategy =
        if risk_level == RiskLevel::Blocked || cleanup_policy.method == RuleCleanupMethod::Manual {
            DeleteStrategy::Skip
        } else {
            DeleteStrategy::MoveToRecycleBin
        };

    Some(apply_cleanup_support_policy(CleanupCandidate {
        id: candidate_id_for_scan_root(&root),
        parent_id: None,
        display_name: root.display_name,
        path: path.clone(),
        volume_id: volume_id_for_path(&root.path, volumes),
        object_type,
        category: category.to_string(),
        size_bytes: stats.size_bytes,
        children_count: stats.children_count,
        risk_level: risk_level.clone(),
        default_selected,
        selected: default_selected && risk_level != RiskLevel::Blocked,
        delete_strategy,
        reason,
        confidence,
        source,
        cleanup_policy,
    }))
}

fn discover_scan_roots() -> Vec<ScanRoot> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();

    if let Ok(temp) = env::var("TEMP") {
        push_scan_root(&mut roots, &mut seen, "用户临时目录", "临时文件", temp);
    }

    if let Ok(windir) = env::var("WINDIR") {
        let windir = PathBuf::from(windir);
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows Temp",
            "Windows 临时文件",
            windir.join("Temp"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows Update Download",
            "Windows 更新缓存",
            windir.join("SoftwareDistribution\\Download"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows Error Reports",
            "Windows 错误报告",
            windir.join("System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\WER"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows CBS Logs",
            "Windows 日志文件",
            windir.join("Logs\\CBS"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows DISM Logs",
            "Windows 日志文件",
            windir.join("Logs\\DISM"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows Cloud Files Logs",
            "Windows 日志文件",
            windir.join("System32\\LogFiles\\CloudFiles"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows HTTPERR Logs",
            "Windows 日志文件",
            windir.join("System32\\LogFiles\\HTTPERR"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows Minidump",
            "Windows 崩溃转储",
            windir.join("Minidump"),
        );
    }

    if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
        let local_app_data = PathBuf::from(local_app_data);
        push_scan_root(
            &mut roots,
            &mut seen,
            "Chrome Cache",
            "浏览器缓存",
            local_app_data.join("Google\\Chrome\\User Data\\Default\\Cache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Chrome Code Cache",
            "浏览器缓存",
            local_app_data.join("Google\\Chrome\\User Data\\Default\\Code Cache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Edge Cache",
            "浏览器缓存",
            local_app_data.join("Microsoft\\Edge\\User Data\\Default\\Cache"),
        );
        push_browser_profile_cache_roots(
            &mut roots,
            &mut seen,
            &local_app_data.join("Mozilla\\Firefox\\Profiles"),
            "Firefox Cache",
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows INetCache",
            "Windows INetCache",
            local_app_data.join("Microsoft\\Windows\\INetCache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Delivery Optimization",
            "Windows 传递优化缓存",
            local_app_data.join("Microsoft\\Windows\\DeliveryOptimization\\Cache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Thumbnail Cache",
            "缩略图缓存",
            local_app_data.join("Microsoft\\Windows\\Explorer"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "DirectX Shader Cache",
            "DirectX 着色器缓存",
            local_app_data.join("D3DSCache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows Error Reports",
            "Windows 错误报告",
            local_app_data.join("Microsoft\\Windows\\WER"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Crash Dumps",
            "崩溃日志",
            local_app_data.join("CrashDumps"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "npm Cache",
            "开发依赖缓存",
            local_app_data.join("npm-cache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "pnpm Store",
            "开发依赖缓存",
            local_app_data.join("pnpm\\store"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Yarn Cache",
            "开发依赖缓存",
            local_app_data.join("Yarn\\Cache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "pip Cache",
            "开发依赖缓存",
            local_app_data.join("pip\\Cache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "NuGet Packages",
            "开发依赖缓存",
            local_app_data.join("NuGet\\Cache"),
        );
    }

    if let Ok(program_data) = env::var("ProgramData") {
        let program_data = PathBuf::from(program_data);
        push_scan_root(
            &mut roots,
            &mut seen,
            "Delivery Optimization",
            "Windows 传递优化缓存",
            program_data.join("Microsoft\\Windows\\DeliveryOptimization\\Cache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Windows Error Reports",
            "Windows 错误报告",
            program_data.join("Microsoft\\Windows\\WER"),
        );
    }

    if let Ok(user_profile) = env::var("USERPROFILE") {
        let user_profile = PathBuf::from(user_profile);
        push_scan_root(
            &mut roots,
            &mut seen,
            "Gradle Cache",
            "开发依赖缓存",
            user_profile.join(".gradle\\caches"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Pub Cache",
            "开发依赖缓存",
            user_profile.join(".pub-cache"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "NuGet Packages",
            "开发依赖缓存",
            user_profile.join(".nuget\\packages"),
        );
        push_scan_root(
            &mut roots,
            &mut seen,
            "Cargo Registry Cache",
            "开发依赖缓存",
            user_profile.join(".cargo\\registry\\cache"),
        );
    }

    roots
}

fn push_browser_profile_cache_roots(
    roots: &mut Vec<ScanRoot>,
    seen: &mut HashSet<String>,
    profiles_root: &Path,
    display_prefix: &str,
) {
    let Ok(entries) = fs::read_dir(profiles_root) else {
        return;
    };

    for entry in entries.flatten().take(20) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let profile_name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "Profile".to_string());

        push_scan_root(
            roots,
            seen,
            &format!("{display_prefix} {profile_name}"),
            "浏览器缓存",
            path.join("cache2"),
        );
    }
}

fn discover_volume_quick_roots(volumes: &[VolumeInfo]) -> Vec<ScanRoot> {
    volumes
        .iter()
        .filter(|volume| volume.selected)
        .map(|volume| ScanRoot {
            path: PathBuf::from(&volume.mount_point).join("$Recycle.Bin"),
            display_name: format!("{}: 回收站", volume.id),
            category: "回收站".to_string(),
            rule: None,
        })
        .collect()
}

fn push_scan_root(
    roots: &mut Vec<ScanRoot>,
    seen: &mut HashSet<String>,
    display_name: &str,
    category: &str,
    path: impl Into<PathBuf>,
) {
    let path = path.into();
    let key = normalize_path_for_id(&path);

    if seen.insert(key) {
        roots.push(ScanRoot {
            path,
            display_name: display_name.to_string(),
            category: category.to_string(),
            rule: None,
        });
    }
}

fn classify_windows_directory(
    normalized_path: &str,
) -> Option<(&'static str, RiskLevel, bool, &'static str, u8)> {
    if normalized_path.contains("\\softwaredistribution\\download") {
        return Some((
            "Windows 更新缓存",
            RiskLevel::CautiousRecommended,
            true,
            "Windows 更新下载缓存，可重新下载；系统更新运行中会跳过",
            78,
        ));
    }

    if normalized_path.contains("\\deliveryoptimization\\") {
        return Some((
            "Windows 传递优化缓存",
            RiskLevel::CautiousRecommended,
            true,
            "Windows 传递优化缓存，可重新生成；不影响系统正常使用",
            74,
        ));
    }

    if normalized_path.contains("\\microsoft\\windows\\explorer") {
        return Some((
            "缩略图缓存",
            RiskLevel::SafeRecommended,
            true,
            "Windows 缩略图和图标缓存，可按需重新生成",
            86,
        ));
    }

    if normalized_path.contains("\\d3dscache")
        || normalized_path.contains("\\directx shader cache")
        || normalized_path.contains("\\dxcshadercache")
    {
        return Some((
            "DirectX 着色器缓存",
            RiskLevel::SafeRecommended,
            true,
            "DirectX 着色器缓存，可按需重新生成",
            84,
        ));
    }

    if normalized_path.contains("\\windows\\temp") {
        return Some((
            "Windows 临时文件",
            RiskLevel::SafeRecommended,
            true,
            "Windows 临时目录",
            84,
        ));
    }

    if normalized_path.contains("\\$winreagent\\") {
        return Some((
            "Windows 恢复缓存",
            RiskLevel::ReviewRequired,
            false,
            "Windows 恢复/更新临时目录，不默认清理",
            62,
        ));
    }

    if normalized_path.contains("\\wer\\")
        || normalized_path.contains("\\reportarchive")
        || normalized_path.contains("\\reportqueue")
    {
        return Some((
            "Windows 错误报告",
            RiskLevel::SafeRecommended,
            true,
            "Windows 错误报告和诊断归档，删除后不影响系统正常使用",
            72,
        ));
    }

    if normalized_path.contains("\\windows\\logs\\cbs")
        || normalized_path.contains("\\windows\\logs\\dism")
        || normalized_path.contains("\\windows\\system32\\logfiles\\cloudfiles")
        || normalized_path.contains("\\windows\\system32\\logfiles\\httperr")
    {
        return Some((
            "Windows 日志文件",
            RiskLevel::CautiousRecommended,
            false,
            "Windows 诊断日志，删除后不影响系统正常使用但会减少诊断历史",
            68,
        ));
    }

    if normalized_path.contains("\\windows\\minidump") {
        return Some((
            "Windows 崩溃转储",
            RiskLevel::CautiousRecommended,
            true,
            "Windows 小型崩溃转储，删除后不影响系统正常使用",
            72,
        ));
    }

    None
}

fn classify_windows_file(
    normalized_path: &str,
    normalized_name: &str,
) -> Option<(&'static str, RiskLevel, bool, &'static str, u8)> {
    if normalized_path.contains("\\$winreagent\\scratch\\") {
        return Some((
            "Windows 恢复缓存",
            RiskLevel::ReviewRequired,
            false,
            "Windows 恢复环境临时文件，不默认清理",
            62,
        ));
    }

    if normalized_path.contains("\\softwaredistribution\\download") {
        return Some((
            "Windows 更新缓存",
            RiskLevel::CautiousRecommended,
            true,
            "Windows 更新下载缓存文件，可重新下载",
            74,
        ));
    }

    if normalized_name.starts_with("thumbcache_")
        || normalized_name.starts_with("iconcache_")
        || normalized_path.contains("\\microsoft\\windows\\explorer\\thumbcache")
        || normalized_path.contains("\\microsoft\\windows\\explorer\\iconcache")
    {
        return Some((
            "缩略图缓存",
            RiskLevel::SafeRecommended,
            true,
            "Windows 缩略图和图标缓存文件，可按需重新生成",
            86,
        ));
    }

    if normalized_path.contains("\\d3dscache")
        || normalized_path.contains("\\directx shader cache")
        || normalized_path.contains("\\dxcshadercache")
        || normalized_path.contains("\\nvidia\\dxcache")
        || normalized_path.contains("\\nvidia\\glcache")
    {
        return Some((
            "DirectX 着色器缓存",
            RiskLevel::SafeRecommended,
            true,
            "图形着色器缓存文件，可按需重新生成",
            84,
        ));
    }

    if normalized_path.contains("\\windows\\temp\\") {
        return Some((
            "Windows 临时文件",
            RiskLevel::SafeRecommended,
            true,
            "Windows 临时文件",
            82,
        ));
    }

    if normalized_name.ends_with(".dmp") && normalized_path.contains("\\windows\\") {
        return Some((
            "Windows 崩溃转储",
            RiskLevel::CautiousRecommended,
            true,
            "Windows 崩溃转储文件，需要确认调试需求",
            70,
        ));
    }

    if (is_supported_windows_log_cleanup_path(normalized_path)
        && (normalized_name.ends_with(".log")
            || normalized_name.ends_with(".etl")
            || normalized_name.ends_with(".dmp")))
        || is_supported_dotnet_log_path(normalized_path)
    {
        return Some((
            "Windows 日志文件",
            RiskLevel::CautiousRecommended,
            false,
            "Windows 诊断日志文件，需要确认诊断留存需求",
            68,
        ));
    }

    None
}

fn scan_directory_stats(root: &Path) -> DirectoryStats {
    let control = NoopScanController;
    let mut stats_cache = ScanStatsCache::default();
    scan_directory_stats_cached(root, &control, &mut stats_cache)
}

fn scan_directory_stats_with_control<C: ScanController + ?Sized>(
    root: &Path,
    control: &C,
) -> DirectoryStats {
    let mut stats_cache = ScanStatsCache::default();
    scan_directory_stats_cached(root, control, &mut stats_cache)
}

fn scan_directory_stats_cached<C: ScanController + ?Sized>(
    root: &Path,
    control: &C,
    stats_cache: &mut ScanStatsCache,
) -> DirectoryStats {
    let key = normalize_path_for_id(root);
    if let Some(stats) = stats_cache.directory_stats.get(&key) {
        return stats.clone();
    }

    let stats = scan_directory_stats_uncached(root, control);
    stats_cache.directory_stats.insert(key, stats.clone());
    stats
}

fn scan_directory_stats_uncached<C: ScanController + ?Sized>(
    root: &Path,
    control: &C,
) -> DirectoryStats {
    let mut stats = DirectoryStats::default();
    let mut stack = vec![(root.to_path_buf(), 0_usize)];
    let mut visited = 0_u64;

    while let Some((directory, depth)) = stack.pop() {
        control.checkpoint();
        if depth > MAX_QUICK_SCAN_DEPTH {
            stats.truncated = true;
            continue;
        }

        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };

        for entry in entries.flatten() {
            control.checkpoint();
            if visited >= MAX_QUICK_SCAN_ENTRIES {
                stats.truncated = true;
                return stats;
            }

            visited += 1;
            stats.children_count = stats.children_count.saturating_add(1);
            control.on_visited(1);

            let Ok(file_type) = entry.file_type() else {
                continue;
            };

            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_file() {
                if let Ok(metadata) = entry.metadata() {
                    stats.size_bytes = stats.size_bytes.saturating_add(metadata.len());
                }
            } else if file_type.is_dir() {
                stack.push((entry.path(), depth + 1));
            }
        }
    }

    stats
}

fn scan_directory_stats_for_policy_cached<C: ScanController + ?Sized>(
    root: &Path,
    cleanup_policy: &CleanupPolicy,
    control: &C,
    stats_cache: &mut ScanStatsCache,
) -> DirectoryStats {
    if cleanup_policy.rule_id.is_none() || cleanup_policy.method == RuleCleanupMethod::Manual {
        return scan_directory_stats_cached(root, control, stats_cache);
    }

    let key = format!(
        "{}|{}",
        cleanup_policy_stats_cache_key(cleanup_policy),
        normalize_path_for_id(root)
    );
    if let Some(stats) = stats_cache.policy_directory_stats.get(&key) {
        return stats.clone();
    }

    let stats =
        scan_directory_stats_for_policy_uncached(root, cleanup_policy, control, stats_cache);
    stats_cache
        .policy_directory_stats
        .insert(key, stats.clone());
    stats
}

fn scan_directory_stats_for_policy_uncached<C: ScanController + ?Sized>(
    root: &Path,
    cleanup_policy: &CleanupPolicy,
    control: &C,
    stats_cache: &mut ScanStatsCache,
) -> DirectoryStats {
    let Ok(entries) = fs::read_dir(root) else {
        return DirectoryStats::default();
    };

    let mut stats = DirectoryStats::default();
    for (visited, entry) in entries.flatten().enumerate() {
        control.checkpoint();
        if visited as u64 >= MAX_QUICK_SCAN_ENTRIES {
            stats.truncated = true;
            return stats;
        }

        let child_path = entry.path();
        control.on_visited(1);
        let Ok(metadata) = fs::symlink_metadata(&child_path) else {
            continue;
        };

        if is_reparse_point_or_symlink(&metadata)
            || cleanup_policy_allows_directory_child(&child_path, &metadata, cleanup_policy)
                .is_err()
        {
            continue;
        }

        stats.children_count = stats.children_count.saturating_add(1);
        if metadata.is_dir() {
            let child_stats = scan_directory_stats_cached(&child_path, control, stats_cache);
            stats.size_bytes = stats.size_bytes.saturating_add(child_stats.size_bytes);
            stats.children_count = stats
                .children_count
                .saturating_add(child_stats.children_count);
            stats.truncated |= child_stats.truncated;
        } else if metadata.is_file() {
            stats.size_bytes = stats.size_bytes.saturating_add(metadata.len());
        }
    }

    stats
}

fn cleanup_policy_stats_cache_key(cleanup_policy: &CleanupPolicy) -> String {
    format!(
        "{:?}|{}|{}|{}",
        cleanup_policy.method,
        cleanup_policy.keep_days,
        cleanup_policy.rule_id.as_deref().unwrap_or_default(),
        cleanup_policy.exclude_patterns.join("\u{1f}")
    )
}

fn list_real_candidate_children(parent: &CleanupCandidate) -> Vec<CleanupCandidate> {
    let parent_path = PathBuf::from(&parent.path);
    let Ok(entries) = fs::read_dir(parent_path) else {
        return Vec::new();
    };
    let mut children = Vec::new();

    for entry in entries.flatten().take(200) {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        if file_type.is_symlink() {
            continue;
        }

        let child_path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&child_path) else {
            continue;
        };
        if cleanup_policy_allows_directory_child(&child_path, &metadata, &parent.cleanup_policy)
            .is_err()
        {
            continue;
        }

        let display_name = child_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| child_path.to_string_lossy().to_string());
        let (object_type, size_bytes, children_count) = if file_type.is_dir() {
            let stats = scan_directory_stats(&child_path);
            (
                ObjectType::Directory,
                stats.size_bytes,
                stats.children_count,
            )
        } else {
            let size_bytes = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            (ObjectType::File, size_bytes, 0)
        };

        children.push(apply_cleanup_support_policy(CleanupCandidate {
            id: candidate_id_for_path(&child_path),
            parent_id: Some(parent.id.clone()),
            display_name,
            path: child_path.to_string_lossy().to_string(),
            volume_id: parent.volume_id.clone(),
            object_type,
            category: parent.category.clone(),
            size_bytes,
            children_count,
            risk_level: parent.risk_level.clone(),
            default_selected: parent.default_selected,
            selected: parent.selected,
            delete_strategy: parent.delete_strategy.clone(),
            reason: parent.reason.clone(),
            confidence: parent.confidence,
            source: source_info_for_path(&child_path),
            cleanup_policy: parent.cleanup_policy.clone(),
        }));
    }

    children.sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes));
    children
}

fn volume_id_for_path(path: &Path, volumes: &[VolumeInfo]) -> String {
    let path_text = normalize_path_for_id(path);

    volumes
        .iter()
        .filter(|volume| path_text.starts_with(&normalize_mount_for_match(&volume.mount_point)))
        .max_by_key(|volume| volume.mount_point.len())
        .map(|volume| volume.id.clone())
        .unwrap_or_else(|| volume_id_from_mount(&path.to_string_lossy()))
}

fn selected_volume_ids_from_infos(volumes: &[VolumeInfo]) -> HashSet<String> {
    volumes
        .iter()
        .filter(|volume| volume.selected)
        .map(|volume| volume.id.clone())
        .collect()
}

fn volume_id_from_mount(mount_point: &str) -> String {
    let mut chars = mount_point.chars();
    let Some(first) = chars.next() else {
        return "Local".to_string();
    };

    if chars.next() == Some(':') {
        return first.to_ascii_uppercase().to_string();
    }

    mount_point.trim_end_matches(['\\', '/']).to_string()
}

fn supports_fast_index(filesystem: &str) -> bool {
    let normalized = filesystem.to_ascii_uppercase();

    normalized.contains("NTFS")
}

fn candidate_id_for_path(path: &Path) -> String {
    format!("real-{:016x}", stable_hash(&normalize_path_for_id(path)))
}

fn candidate_id_for_scan_root(root: &ScanRoot) -> String {
    if let Some(rule) = &root.rule {
        return format!(
            "rule-{:016x}",
            stable_hash(&format!(
                "{}|{}",
                rule.id,
                normalize_path_for_id(&root.path)
            ))
        );
    }

    candidate_id_for_path(&root.path)
}

fn normalize_path_for_id(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn normalize_mount_for_match(mount_point: &str) -> String {
    let mut normalized = mount_point.replace('/', "\\").to_ascii_lowercase();

    if !normalized.ends_with('\\') {
        normalized.push('\\');
    }

    normalized
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;

    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }

    hash
}

fn sample_candidates() -> Vec<CleanupCandidate> {
    vec![
        CleanupCandidate {
            id: "chrome-cache".to_string(),
            parent_id: None,
            display_name: "Chrome Cache".to_string(),
            path: "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"
                .to_string(),
            volume_id: "C".to_string(),
            object_type: ObjectType::Directory,
            category: "浏览器缓存".to_string(),
            size_bytes: 842 * mib(),
            children_count: 1_842,
            risk_level: RiskLevel::SafeRecommended,
            default_selected: true,
            selected: true,
            delete_strategy: DeleteStrategy::MoveToRecycleBin,
            reason: "浏览器缓存，超过 7 天".to_string(),
            confidence: 94,
            source: source_info_for_path(Path::new(
                "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache",
            )),
            cleanup_policy: CleanupPolicy::default(),
        },
        CleanupCandidate {
            id: "installer-rollback".to_string(),
            parent_id: None,
            display_name: "installer_unpack_rollback".to_string(),
            path: "C:\\Users\\979\\AppData\\Local\\Temp\\setup-cache".to_string(),
            volume_id: "C".to_string(),
            object_type: ObjectType::Directory,
            category: "安装残留".to_string(),
            size_bytes: 1_270 * mib(),
            children_count: 88,
            risk_level: RiskLevel::SafeRecommended,
            default_selected: true,
            selected: true,
            delete_strategy: DeleteStrategy::MoveToRecycleBin,
            reason: "临时安装缓存，超过 14 天".to_string(),
            confidence: 88,
            source: source_info_for_path(Path::new(
                "C:\\Users\\979\\AppData\\Local\\Temp\\setup-cache",
            )),
            cleanup_policy: CleanupPolicy::default(),
        },
        CleanupCandidate {
            id: "video-editor-cache".to_string(),
            parent_id: None,
            display_name: "video-editor-cache".to_string(),
            path: "D:\\Media\\Cache\\PreviewRender".to_string(),
            volume_id: "D".to_string(),
            object_type: ObjectType::Directory,
            category: "应用缓存".to_string(),
            size_bytes: 2_060 * mib(),
            children_count: 411,
            risk_level: RiskLevel::CautiousRecommended,
            default_selected: false,
            selected: false,
            delete_strategy: DeleteStrategy::MoveToRecycleBin,
            reason: "应用预览缓存，最近 2 天修改".to_string(),
            confidence: 68,
            source: source_info_for_path(Path::new("D:\\Media\\Cache\\PreviewRender")),
            cleanup_policy: CleanupPolicy::default(),
        },
        CleanupCandidate {
            id: "project-build-cache".to_string(),
            parent_id: None,
            display_name: "project-build-cache".to_string(),
            path: "D:\\Work\\xyzw-app\\build\\cache".to_string(),
            volume_id: "D".to_string(),
            object_type: ObjectType::Directory,
            category: "项目目录".to_string(),
            size_bytes: 618 * mib(),
            children_count: 202,
            risk_level: RiskLevel::ReviewRequired,
            default_selected: false,
            selected: false,
            delete_strategy: DeleteStrategy::MoveToRecycleBin,
            reason: "项目目录缓存，需要确认构建上下文".to_string(),
            confidence: 62,
            source: source_info_for_path(Path::new("D:\\Work\\xyzw-app\\build\\cache")),
            cleanup_policy: CleanupPolicy::default(),
        },
        CleanupCandidate {
            id: "app-session-db".to_string(),
            parent_id: None,
            display_name: "app-session.db".to_string(),
            path: "C:\\Users\\979\\AppData\\Roaming\\SomeApp\\session.db".to_string(),
            volume_id: "C".to_string(),
            object_type: ObjectType::File,
            category: "应用配置".to_string(),
            size_bytes: 128 * mib(),
            children_count: 0,
            risk_level: RiskLevel::Blocked,
            default_selected: false,
            selected: false,
            delete_strategy: DeleteStrategy::Skip,
            reason: "Roaming 配置和会话数据库不可清理".to_string(),
            confidence: 98,
            source: source_info_for_path(Path::new(
                "C:\\Users\\979\\AppData\\Roaming\\SomeApp\\session.db",
            )),
            cleanup_policy: CleanupPolicy::default(),
        },
    ]
}

fn child_candidate(
    id: &str,
    display_name: &str,
    size_bytes: u64,
    children_count: u32,
) -> CleanupCandidate {
    CleanupCandidate {
        id: id.to_string(),
        parent_id: Some("chrome-cache".to_string()),
        display_name: display_name.to_string(),
        path: format!(
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\{}",
            display_name
        ),
        volume_id: "C".to_string(),
        object_type: ObjectType::Directory,
        category: "浏览器缓存".to_string(),
        size_bytes,
        children_count,
        risk_level: RiskLevel::SafeRecommended,
        default_selected: true,
        selected: true,
        delete_strategy: DeleteStrategy::MoveToRecycleBin,
        reason: "Chrome cache child directory".to_string(),
        confidence: 92,
        source: source_info_for_path(Path::new(&format!(
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\{}",
            display_name
        ))),
        cleanup_policy: CleanupPolicy::default(),
    }
}

fn mib() -> u64 {
    1024 * 1024
}

fn gib() -> u64 {
    1024 * mib()
}

pub fn candidates_by_id(candidates: &[CleanupCandidate]) -> HashMap<&str, &CleanupCandidate> {
    candidates
        .iter()
        .map(|candidate| (candidate.id.as_str(), candidate))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cleanup_candidate(id: &str, path: &Path, object_type: ObjectType) -> CleanupCandidate {
        CleanupCandidate {
            id: id.to_string(),
            parent_id: None,
            display_name: id.to_string(),
            path: path.to_string_lossy().to_string(),
            volume_id: volume_id_from_mount(&path.to_string_lossy()),
            object_type,
            category: "测试缓存".to_string(),
            size_bytes: 0,
            children_count: 0,
            risk_level: RiskLevel::SafeRecommended,
            default_selected: true,
            selected: true,
            delete_strategy: DeleteStrategy::MoveToRecycleBin,
            reason: "test".to_string(),
            confidence: 100,
            source: source_info_for_path(path),
            cleanup_policy: CleanupPolicy::default(),
        }
    }

    fn yaml_path(path: &Path) -> String {
        path.to_string_lossy().replace('\'', "''")
    }

    fn test_volume(root: &Path) -> VolumeInfo {
        test_volume_with_id(root, "T", true)
    }

    fn test_volume_with_id(root: &Path, id: &str, selected: bool) -> VolumeInfo {
        VolumeInfo {
            id: id.to_string(),
            label: format!("Test {id}"),
            mount_point: root.to_string_lossy().to_string(),
            filesystem: "exFAT".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected,
            supports_fast_index: false,
        }
    }

    #[test]
    fn directory_children_are_available_for_directory_candidate() {
        let children = sample_candidate_children("chrome-cache");

        assert_eq!(children.len(), 3);
        assert_eq!(children[0].parent_id.as_deref(), Some("chrome-cache"));
        assert!(children
            .iter()
            .all(|child| child.object_type == ObjectType::Directory));
        assert_eq!(
            children.iter().map(|child| child.size_bytes).sum::<u64>(),
            842 * mib()
        );
    }

    #[test]
    fn scan_snapshot_detects_volumes_and_consistent_summary() {
        let snapshot = scan_snapshot();

        assert!(!snapshot.volumes.is_empty());
        assert_eq!(
            snapshot.summary.candidate_count,
            snapshot.candidates.len() as u32
        );
        assert_eq!(snapshot.summary.progress_percent, 100);
    }

    #[test]
    fn initial_snapshot_does_not_scan_candidates() {
        let snapshot = initial_scan_snapshot();

        assert!(!snapshot.volumes.is_empty());
        assert!(snapshot.candidates.is_empty());
        assert_eq!(snapshot.scan_backend, "idle");
        assert_eq!(snapshot.summary.progress_percent, 0);
    }

    #[test]
    fn supported_env_expansion_accepts_winapp2_pseudo_vars() {
        if env::var("USERPROFILE").is_ok() {
            assert!(expand_supported_env_vars("%LOCALLOWAPPDATA%\\Example").is_some());
            assert!(expand_supported_env_vars("%DOCUMENTS%\\My Games").is_some());
        }
    }

    #[test]
    fn custom_rule_scan_produces_policy_backed_candidate() {
        let root = env::temp_dir().join(format!(
            "diskclean-rule-scan-test-{}-{}",
            std::process::id(),
            stable_hash("rule-scan")
        ));
        let cache = root.join("cache");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&cache).expect("rule cache directory should be created");
        fs::write(cache.join("cache.tmp"), [1_u8; 7]).expect("cache file should be written");

        let yaml = format!(
            "\
version: 1
rules:
  - id: local.rule.cache
    name: Local Rule Cache
    app: Test App
    category: 测试缓存
    level: 推荐清理
    default: true
    paths:
      - '{}'
    clean: contents
    keep_days: 0
    note: 测试规则缓存，可重新生成。
",
            yaml_path(&cache)
        );
        let compilation = compile_cleanup_rules_yaml(&yaml, RuleSourceKind::User);
        assert!(compilation.report.valid);

        let run = scan_rule_candidates(&[test_volume(&root)], &compilation.rules);
        let candidate = run
            .candidates
            .iter()
            .find(|candidate| candidate.category == "测试缓存")
            .expect("rule candidate should be produced");

        assert_eq!(
            candidate.cleanup_policy.rule_id.as_deref(),
            Some("local.rule.cache")
        );
        assert_eq!(candidate.cleanup_policy.method, RuleCleanupMethod::Contents);
        assert_eq!(candidate.size_bytes, 7);
        assert!(candidate.default_selected);
        assert!(candidate.selected);
        assert_eq!(candidate.source.label, "Test App");

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn scan_worker_count_stays_within_bounds() {
        assert_eq!(scan_worker_count(0), 1);
        assert_eq!(scan_worker_count(1), 1);
        assert!(scan_worker_count(1_000) <= MAX_SCAN_WORKERS);
        assert!(scan_worker_count(1_000) >= 1);
    }

    #[test]
    fn parallel_root_scan_preserves_root_order() {
        let root = env::temp_dir().join(format!(
            "diskclean-parallel-order-test-{}-{}",
            std::process::id(),
            stable_hash("parallel-order")
        ));
        let _ = fs::remove_dir_all(&root);

        // More roots than MIN_PARALLEL_SCAN_ROOTS so the chunked path is used.
        let root_count = MIN_PARALLEL_SCAN_ROOTS * 3;
        let mut scan_roots = Vec::with_capacity(root_count);

        for index in 0..root_count {
            let directory = root.join(format!("cache-{index:03}"));
            fs::create_dir_all(&directory).expect("cache directory should be created");
            fs::write(directory.join("payload.tmp"), vec![7_u8; index + 1])
                .expect("payload should be written");
            scan_roots.push(ScanRoot {
                path: directory,
                display_name: format!("Cache {index:03}"),
                category: "测试缓存".to_string(),
                rule: None,
            });
        }

        let expected_paths: Vec<String> = scan_roots
            .iter()
            .map(|scan_root| normalize_path_for_id(&scan_root.path))
            .collect();
        let volumes = vec![test_volume_with_id(&root, "P", true)];
        let control = NoopScanController;
        let candidates = scan_roots_parallel(scan_roots, &volumes, &control);
        let actual_paths: Vec<String> = candidates
            .iter()
            .map(|candidate| normalize_path_for_id(Path::new(&candidate.path)))
            .collect();

        assert_eq!(actual_paths, expected_paths);

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn rule_scan_skips_paths_on_unselected_volumes_before_candidate_scan() {
        let root = env::temp_dir().join(format!(
            "diskclean-rule-volume-filter-test-{}-{}",
            std::process::id(),
            stable_hash("rule-volume-filter")
        ));
        let selected_root = root.join("selected");
        let unselected_root = root.join("unselected");
        let selected_cache = selected_root.join("cache");
        let unselected_cache = unselected_root.join("cache");
        let unselected_glob = unselected_root.join("**").join("cache");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&selected_cache).expect("selected cache directory should be created");
        fs::create_dir_all(&unselected_cache)
            .expect("unselected cache directory should be created");
        fs::write(selected_cache.join("selected.tmp"), [1_u8; 7])
            .expect("selected cache file should be written");
        fs::write(unselected_cache.join("unselected.tmp"), [2_u8; 11])
            .expect("unselected cache file should be written");

        let yaml = format!(
            "\
version: 1
rules:
  - id: selected.rule.cache
    name: Selected Rule Cache
    app: Test App
    category: 测试缓存
    level: 推荐清理
    default: true
    paths:
      - '{}'
    clean: contents
    keep_days: 0
    note: 选中盘符规则缓存，可重新生成。
  - id: unselected.rule.cache
    name: Unselected Rule Cache
    app: Test App
    category: 测试缓存
    level: 推荐清理
    default: true
    paths:
      - '{}'
    clean: contents
    keep_days: 0
    note: 未选中盘符规则缓存，不应扫描。
",
            yaml_path(&selected_cache),
            yaml_path(&unselected_glob)
        );
        let compilation = compile_cleanup_rules_yaml(&yaml, RuleSourceKind::User);
        assert!(compilation.report.valid);

        let volumes = vec![
            test_volume_with_id(&selected_root, "S", true),
            test_volume_with_id(&unselected_root, "U", false),
        ];
        let run = scan_rule_candidates(&volumes, &compilation.rules);
        let candidate_paths = run
            .candidates
            .iter()
            .map(|candidate| normalize_path_for_id(Path::new(&candidate.path)))
            .collect::<HashSet<_>>();

        assert!(candidate_paths.contains(&normalize_path_for_id(&selected_cache)));
        assert!(!candidate_paths.contains(&normalize_path_for_id(&unselected_cache)));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn rule_scan_merges_duplicate_paths_before_candidate_scan() {
        let root = env::temp_dir().join(format!(
            "diskclean-rule-merge-test-{}-{}",
            std::process::id(),
            stable_hash("rule-merge")
        ));
        let cache = root.join("cache");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&cache).expect("rule cache directory should be created");
        fs::write(cache.join("cache.tmp"), [1_u8; 7]).expect("cache file should be written");

        let yaml = format!(
            "\
version: 1
rules:
  - id: first.rule.cache
    name: First Rule Cache
    app: First App
    category: 第一规则
    level: 推荐清理
    default: true
    paths:
      - '{}'
    clean: contents
    keep_days: 0
    note: 第一条重复路径规则。
  - id: second.rule.cache
    name: Second Rule Cache
    app: Second App
    category: 第二规则
    level: 推荐清理
    default: true
    paths:
      - '{}'
    clean: contents
    keep_days: 0
    note: 第二条重复路径规则应保留。
",
            yaml_path(&cache),
            yaml_path(&cache)
        );
        let compilation = compile_cleanup_rules_yaml(&yaml, RuleSourceKind::User);
        assert!(compilation.report.valid);

        let run = scan_rule_candidates(&[test_volume(&root)], &compilation.rules);
        let normalized_cache = normalize_path_for_id(&cache);
        let matches = run
            .candidates
            .iter()
            .filter(|candidate| {
                normalize_path_for_id(Path::new(&candidate.path)) == normalized_cache
            })
            .collect::<Vec<_>>();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].cleanup_policy.rule_id.as_deref(),
            Some("second.rule.cache")
        );
        assert_eq!(matches[0].category, "第二规则");

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn rule_cleanup_skips_excluded_children() {
        let root = env::temp_dir().join(format!(
            "diskclean-rule-exclude-test-{}-{}",
            std::process::id(),
            stable_hash("rule-exclude")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test directory should be created");
        fs::write(root.join("remove.tmp"), [1_u8; 7]).expect("cleanable file should be written");
        fs::write(root.join("keep.cache"), [2_u8; 5]).expect("excluded file should be written");

        let mut candidate = test_cleanup_candidate("rule-dir", &root, ObjectType::Directory);
        candidate.cleanup_policy = CleanupPolicy {
            rule_id: Some("local.rule.exclude".to_string()),
            method: RuleCleanupMethod::Contents,
            keep_days: 0,
            exclude_patterns: vec![normalize_glob_pattern("**\\keep.cache")],
        };
        let mut moved_paths = Vec::new();

        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("rule-dir")],
            DeleteStrategy::MoveToRecycleBin,
            |path| {
                moved_paths.push(normalize_path_for_id(path));
                Ok(())
            },
        );

        assert_eq!(report.cleaned_count, 1);
        assert_eq!(report.reclaimed_bytes, 7);
        assert_eq!(
            moved_paths,
            vec![normalize_path_for_id(&root.join("remove.tmp"))]
        );
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("命中规则排除项")));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn rule_cleanup_keeps_recent_children() {
        let root = env::temp_dir().join(format!(
            "diskclean-rule-keep-days-test-{}-{}",
            std::process::id(),
            stable_hash("rule-keep-days")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test directory should be created");
        let fresh = root.join("fresh.tmp");
        fs::write(&fresh, [1_u8; 7]).expect("fresh file should be written");

        let mut candidate = test_cleanup_candidate("rule-dir", &root, ObjectType::Directory);
        candidate.cleanup_policy = CleanupPolicy {
            rule_id: Some("local.rule.keep".to_string()),
            method: RuleCleanupMethod::Contents,
            keep_days: 365,
            exclude_patterns: Vec::new(),
        };
        let mut moved_paths = Vec::new();

        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("rule-dir")],
            DeleteStrategy::MoveToRecycleBin,
            |path| {
                moved_paths.push(normalize_path_for_id(path));
                Ok(())
            },
        );

        assert_eq!(report.cleaned_count, 0);
        assert_eq!(report.skipped_locked_count, 1);
        assert!(moved_paths.is_empty());
        assert!(fresh.exists());
        assert!(report
            .item_results
            .iter()
            .any(|item| item.reason.contains("没有可安全清理的子项")));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn scan_directory_stats_counts_nested_files() {
        let root = env::temp_dir().join(format!(
            "cleandeck-scan-test-{}-{}",
            std::process::id(),
            stable_hash("nested")
        ));
        let nested = root.join("nested");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&nested).expect("test directory should be created");
        fs::write(root.join("a.tmp"), [1_u8; 7]).expect("test file should be written");
        fs::write(nested.join("b.tmp"), [2_u8; 5]).expect("nested file should be written");

        let stats = scan_directory_stats(&root);

        assert_eq!(stats.size_bytes, 12);
        assert_eq!(stats.children_count, 3);

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn scan_directory_stats_checks_scan_controller() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct CountingScanController {
            checkpoints: Arc<AtomicUsize>,
        }

        impl ScanController for CountingScanController {
            fn checkpoint(&self) {
                self.checkpoints.fetch_add(1, Ordering::SeqCst);
            }
        }

        let root = env::temp_dir().join(format!(
            "cleandeck-scan-control-test-{}-{}",
            std::process::id(),
            stable_hash("scan-control")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test directory should be created");
        fs::write(root.join("a.tmp"), [1_u8; 7]).expect("test file should be written");

        let checkpoints = Arc::new(AtomicUsize::new(0));
        let controller = CountingScanController {
            checkpoints: Arc::clone(&checkpoints),
        };
        let mut stats_cache = ScanStatsCache::default();

        let stats = scan_directory_stats_cached(&root, &controller, &mut stats_cache);

        assert_eq!(stats.size_bytes, 7);
        assert!(checkpoints.load(Ordering::SeqCst) > 0);

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    fn walk_progress_events(label: &str) -> Vec<ScanProgress> {
        let root = env::temp_dir().join(format!(
            "cleandeck-scan-progress-{}-{}",
            std::process::id(),
            stable_hash(label)
        ));
        let cache = root.join("App").join("Cache");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&cache).expect("cache directory should be created");
        for index in 0..24 {
            fs::write(cache.join(format!("cache-{index}.bin")), [7_u8; 32])
                .expect("cache file should be written");
        }

        let volume = VolumeInfo {
            id: "T".to_string(),
            label: "Test".to_string(),
            mount_point: root.to_string_lossy().to_string(),
            filesystem: "exFAT".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: false,
        };

        let events = Mutex::new(Vec::new());
        {
            let inner = NoopScanController;
            let reporter = ScanProgressController::new(&inner, |progress: ScanProgress| {
                events
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(progress);
            });
            reporter.begin();
            reporter.set_total_files(None);
            reporter.on_phase(ScanPhase::Walking);
            let _ = walk_full_volume_with_control(&volume, &reporter);
            reporter.finish();
        }

        fs::remove_dir_all(&root).expect("test directory should be removed");
        events
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn scan_progress_throttling_keeps_first_and_final_events() {
        let events = walk_progress_events("throttle");

        assert!(events.len() >= 2);
        assert_eq!(
            events.first().map(|event| event.phase),
            Some(ScanPhase::Preparing)
        );
        assert_eq!(
            events.last().map(|event| event.phase),
            Some(ScanPhase::Complete)
        );
        assert!(events.iter().any(|event| event.phase == ScanPhase::Walking));
        // Throttling must collapse per-entry emissions well below the visited count.
        assert!(events.len() < 24);
    }

    #[test]
    fn scan_progress_scanned_files_is_monotonic() {
        let events = walk_progress_events("monotonic");

        let mut previous = 0_u64;
        for event in &events {
            assert!(event.scanned_files >= previous);
            previous = event.scanned_files;
        }

        assert!(previous >= 24);
    }

    #[test]
    fn scan_progress_walk_path_reports_no_percent() {
        let events = walk_progress_events("no-percent");

        assert!(events
            .iter()
            .all(|event| event.percent.is_none() && event.total_files.is_none()));
    }

    #[test]
    fn scan_progress_reports_running_candidate_totals() {
        let events = walk_progress_events("candidates");
        let final_event = events.last().expect("final event should exist");

        assert!(final_event.candidate_count > 0);
        assert!(final_event.reclaimable_bytes > 0);
    }

    #[test]
    fn scan_progress_serializes_to_camel_case_json() {
        let progress = ScanProgress {
            phase: ScanPhase::Indexing,
            scanned_files: 421_339,
            candidate_count: 12,
            reclaimable_bytes: 4096,
            current_path: "C:\\Windows\\Temp".to_string(),
            current_volume: "C".to_string(),
            total_files: Some(1_000_000),
            percent: Some(42),
        };
        let json = serde_json::to_value(progress).expect("progress should serialize");

        assert_eq!(
            json.get("phase").and_then(|value| value.as_str()),
            Some("indexing")
        );
        assert_eq!(
            json.get("scannedFiles").and_then(|value| value.as_u64()),
            Some(421_339)
        );
        assert_eq!(
            json.get("candidateCount").and_then(|value| value.as_u64()),
            Some(12)
        );
        assert_eq!(
            json.get("reclaimableBytes")
                .and_then(|value| value.as_u64()),
            Some(4096)
        );
        assert!(json.get("currentPath").is_some());
        assert!(json.get("currentVolume").is_some());
        assert_eq!(
            json.get("totalFiles").and_then(|value| value.as_u64()),
            Some(1_000_000)
        );
        assert_eq!(
            json.get("percent").and_then(|value| value.as_u64()),
            Some(42)
        );
    }

    #[test]
    fn scan_progress_percent_uses_real_denominator_and_caps_below_complete() {
        let events = Mutex::new(Vec::new());
        {
            let inner = NoopScanController;
            let reporter = ScanProgressController::new(&inner, |progress: ScanProgress| {
                events
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(progress);
            });
            reporter.set_total_files(Some(200));
            reporter.on_visited(100);
            reporter.on_phase(ScanPhase::Analyzing);
            reporter.on_visited(500);
            reporter.on_phase(ScanPhase::Indexing);
        }

        let events = events
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let percents = events
            .iter()
            .filter_map(|event| event.percent)
            .collect::<Vec<_>>();

        assert!(percents.contains(&50));
        assert!(percents.iter().all(|percent| *percent <= 99));
    }

    #[test]
    fn scan_progress_reports_zero_percent_for_empty_denominator() {
        let events = Mutex::new(Vec::new());
        {
            let inner = NoopScanController;
            let reporter = ScanProgressController::new(&inner, |progress: ScanProgress| {
                events
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(progress);
            });
            reporter.set_total_files(Some(0));
        }

        let events = events
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        assert_eq!(events.last().and_then(|event| event.percent), Some(0));
    }

    #[test]
    fn full_walk_discovers_cache_build_and_large_file_candidates() {
        let root = env::temp_dir().join(format!(
            "cleandeck-full-walk-test-{}-{}",
            std::process::id(),
            stable_hash("full")
        ));
        let cache = root.join("App").join("Cache");
        let build = root.join("Project").join("target");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&cache).expect("cache directory should be created");
        fs::create_dir_all(&build).expect("build directory should be created");
        fs::write(cache.join("cache.bin"), [1_u8; 11]).expect("cache file should be written");
        fs::write(
            root.join("Project").join("Cargo.toml"),
            "[package]\nname='demo'\n",
        )
        .expect("project marker should be written");
        fs::write(build.join("artifact.tmp"), [2_u8; 13]).expect("build file should be written");

        let volume = VolumeInfo {
            id: "T".to_string(),
            label: "Test".to_string(),
            mount_point: root.to_string_lossy().to_string(),
            filesystem: "exFAT".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: false,
        };

        let run = walk_full_volume(&volume);
        let categories = run
            .candidates
            .iter()
            .map(|candidate| candidate.category.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(run.backend, "walk");
        assert!(categories.contains("应用缓存"));
        assert!(categories.contains("构建产物"));
        assert!(run
            .candidates
            .iter()
            .any(|candidate| candidate.path.ends_with("artifact.tmp")));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn full_walk_blocks_electron_runtime_build_output_in_custom_install_path() {
        let root = env::temp_dir().join(format!(
            "cleandeck-electron-install-test-{}-{}",
            std::process::id(),
            stable_hash("electron-install")
        ));
        let install_root = root
            .join("cantinstall")
            .join("Microsoft VS Code")
            .join("8b640eef5a");
        let out_dir = install_root.join("resources").join("app").join("out");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&out_dir).expect("runtime out directory should be created");
        fs::write(install_root.join("Code.exe"), [0_u8; 1])
            .expect("app executable marker should be written");
        fs::write(out_dir.join("main.js"), [1_u8; 11]).expect("runtime file should be written");

        let volume = VolumeInfo {
            id: "T".to_string(),
            label: "Test".to_string(),
            mount_point: root.to_string_lossy().to_string(),
            filesystem: "exFAT".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: false,
        };
        let run = walk_full_volume(&volume);

        assert!(run
            .candidates
            .iter()
            .all(
                |candidate| !normalize_path_for_id(Path::new(&candidate.path))
                    .starts_with(&normalize_path_for_id(&install_root))
            ));
        assert!(validate_cleanup_target_path(&out_dir)
            .expect_err("runtime out directory should be protected")
            .contains("应用安装目录"));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn cleanup_refuses_custom_installed_app_runtime_path() {
        let root = env::temp_dir().join(format!(
            "cleandeck-clean-electron-install-test-{}-{}",
            std::process::id(),
            stable_hash("clean-electron-install")
        ));
        let install_root = root
            .join("cantinstall")
            .join("Microsoft VS Code")
            .join("8b640eef5a");
        let out_dir = install_root.join("resources").join("app").join("out");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&out_dir).expect("runtime out directory should be created");
        fs::write(install_root.join("Code.exe"), [0_u8; 1])
            .expect("app executable marker should be written");
        fs::write(out_dir.join("main.js"), [1_u8; 11]).expect("runtime file should be written");

        let candidate = test_cleanup_candidate("vscode-out", &out_dir, ObjectType::Directory);
        let mut delete_called = false;
        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("vscode-out")],
            DeleteStrategy::MoveToRecycleBin,
            |_path| {
                delete_called = true;
                Ok(())
            },
        );

        assert_eq!(report.cleaned_count, 0);
        assert_eq!(report.skipped_locked_count, 1);
        assert!(!delete_called);
        assert!(out_dir.join("main.js").exists());
        assert!(report.item_results[0].reason.contains("应用安装目录"));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn scan_request_marks_only_requested_volumes_selected() {
        let volumes = vec![
            VolumeInfo {
                id: "C".to_string(),
                label: "System".to_string(),
                mount_point: "C:\\".to_string(),
                filesystem: "NTFS".to_string(),
                total_bytes: 0,
                available_bytes: 0,
                selected: true,
                supports_fast_index: true,
            },
            VolumeInfo {
                id: "E".to_string(),
                label: "Portable".to_string(),
                mount_point: "E:\\".to_string(),
                filesystem: "exFAT".to_string(),
                total_bytes: 0,
                available_bytes: 0,
                selected: true,
                supports_fast_index: false,
            },
        ];

        let selected = apply_volume_selection(volumes, &[String::from("E")]);

        assert!(!selected[0].selected);
        assert!(selected[1].selected);
    }

    #[test]
    fn default_selection_chooses_first_volume_when_system_drive_is_unavailable() {
        let mut volumes = vec![
            VolumeInfo {
                id: "X".to_string(),
                label: "One".to_string(),
                mount_point: "X:\\".to_string(),
                filesystem: "NTFS".to_string(),
                total_bytes: 0,
                available_bytes: 0,
                selected: false,
                supports_fast_index: true,
            },
            VolumeInfo {
                id: "Y".to_string(),
                label: "Two".to_string(),
                mount_point: "Y:\\".to_string(),
                filesystem: "exFAT".to_string(),
                total_bytes: 0,
                available_bytes: 0,
                selected: false,
                supports_fast_index: false,
            },
        ];

        mark_default_selected_volume_with_id(&mut volumes, None);

        assert!(volumes[0].selected);
        assert!(!volumes[1].selected);
    }

    #[test]
    fn ntfs_only_reports_fast_index_support() {
        assert!(supports_fast_index("NTFS"));
        assert!(!supports_fast_index("exFAT"));
        assert!(!supports_fast_index("FAT32"));
    }

    #[test]
    fn usn_access_denied_warning_explains_admin_requirement() {
        let volume = VolumeInfo {
            id: "C".to_string(),
            label: "System".to_string(),
            mount_point: "C:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: true,
        };
        let error = format_windows_volume_open_error("\\\\.\\C:", WINDOWS_ERROR_ACCESS_DENIED);
        let warning = fast_scan_fallback_warning(&volume, &error);

        assert!(warning.contains("管理员权限"));
        assert!(warning.contains("已回退到递归扫描"));
        assert!(warning.contains("结果仍可用"));
    }

    #[test]
    fn preview_cleanup_for_candidates_respects_explicit_empty_selection() {
        let candidates = sample_candidates();

        let plan = preview_cleanup_for_candidates(&candidates, &[String::from("missing")]);

        assert_eq!(plan.selected_count, 0);
        assert_eq!(plan.skipped_locked_count, 0);
        assert_eq!(plan.estimated_reclaim_bytes, 0);
    }

    #[test]
    fn cleanup_preview_counts_selected_and_skips_locked_items() {
        let selected = vec![
            "chrome-cache".to_string(),
            "app-session-db".to_string(),
            "missing-candidate".to_string(),
        ];
        let candidates = sample_candidates();
        let plan = preview_cleanup_for_candidates(&candidates, &selected);

        assert_eq!(plan.selected_count, 1);
        assert_eq!(plan.skipped_locked_count, 1);
        assert_eq!(plan.estimated_reclaim_bytes, 842 * mib());
    }

    #[test]
    fn real_cleanup_moves_file_candidates_to_recycle_bin() {
        let root = env::temp_dir().join(format!(
            "cleandeck-clean-file-test-{}-{}",
            std::process::id(),
            stable_hash("file")
        ));
        let file = root.join("cache.tmp");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test directory should be created");
        fs::write(&file, [1_u8; 7]).expect("test file should be written");

        let candidate = test_cleanup_candidate("file-cache", &file, ObjectType::File);
        let mut moved_paths = Vec::new();

        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("file-cache")],
            DeleteStrategy::MoveToRecycleBin,
            |path| {
                moved_paths.push(normalize_path_for_id(path));
                Ok(())
            },
        );

        assert_eq!(report.cleaned_count, 1);
        assert_eq!(report.failed_count, 0);
        assert_eq!(report.reclaimed_bytes, 7);
        assert_eq!(moved_paths, vec![normalize_path_for_id(&file)]);
        assert_eq!(report.item_results.len(), 1);
        assert_eq!(report.item_results[0].status, CleanupItemStatus::Cleaned);
        assert_eq!(report.item_results[0].reclaimed_bytes, 7);
        assert!(report.warnings[0].contains("真实清理"));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn real_cleanup_can_permanently_delete_file_candidates() {
        let root = env::temp_dir().join(format!(
            "cleandeck-clean-permanent-test-{}-{}",
            std::process::id(),
            stable_hash("permanent")
        ));
        let file = root.join("cache.tmp");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test directory should be created");
        fs::write(&file, [1_u8; 11]).expect("test file should be written");

        let candidate = test_cleanup_candidate("file-cache", &file, ObjectType::File);
        let report = execute_cleanup_for_candidates_with_options(
            vec![candidate],
            &[String::from("file-cache")],
            CleanupExecutionOptions {
                delete_strategy: DeleteStrategy::PermanentDelete,
            },
        );

        assert_eq!(report.cleaned_count, 1);
        assert_eq!(report.failed_count, 0);
        assert_eq!(report.reclaimed_bytes, 11);
        assert_eq!(report.delete_strategy, DeleteStrategy::PermanentDelete);
        assert!(!file.exists());
        assert!(report.item_results[0].reason.contains("永久删除"));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn real_cleanup_permanently_deletes_directory_children_with_progress() {
        let root = env::temp_dir().join(format!(
            "cleandeck-clean-parallel-permanent-test-{}-{}",
            std::process::id(),
            stable_hash("parallel-permanent")
        ));
        let nested = root.join("nested");
        let file = root.join("cache.tmp");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&nested).expect("nested test directory should be created");
        fs::write(&file, [1_u8; 7]).expect("test file should be written");
        fs::write(nested.join("b.tmp"), [2_u8; 5]).expect("nested test file should be written");

        let candidate = test_cleanup_candidate("dir-cache", &root, ObjectType::Directory);
        let mut progress_events = Vec::new();
        let report = execute_cleanup_for_candidates_with_progress(
            vec![candidate],
            &[String::from("dir-cache")],
            CleanupExecutionOptions {
                delete_strategy: DeleteStrategy::PermanentDelete,
            },
            |progress| progress_events.push(progress),
        );

        assert_eq!(report.cleaned_count, 1);
        assert_eq!(report.failed_count, 0);
        assert_eq!(report.reclaimed_bytes, 12);
        assert_eq!(report.delete_strategy, DeleteStrategy::PermanentDelete);
        assert!(root.exists());
        assert!(!file.exists());
        assert!(!nested.exists());
        assert!(progress_events
            .iter()
            .any(|event| event.status == CleanupProgressStatus::Cleaning
                && event.percent > 0
                && !event.current_path.is_empty()));
        assert!(progress_events.iter().any(|event| event.total_count == 2
            && event.processed_count == 2
            && event.percent == 100));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn real_cleanup_expands_directory_candidates_to_direct_children() {
        let root = env::temp_dir().join(format!(
            "cleandeck-clean-dir-test-{}-{}",
            std::process::id(),
            stable_hash("dir")
        ));
        let nested = root.join("nested");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&nested).expect("nested test directory should be created");
        fs::write(root.join("a.tmp"), [1_u8; 7]).expect("test file should be written");
        fs::write(nested.join("b.tmp"), [2_u8; 5]).expect("nested test file should be written");

        let candidate = test_cleanup_candidate("dir-cache", &root, ObjectType::Directory);
        let mut moved_paths = Vec::new();

        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("dir-cache")],
            DeleteStrategy::MoveToRecycleBin,
            |path| {
                moved_paths.push(normalize_path_for_id(path));
                Ok(())
            },
        );

        assert_eq!(report.cleaned_count, 1);
        assert_eq!(report.skipped_locked_count, 0);
        assert_eq!(report.failed_count, 0);
        assert_eq!(report.reclaimed_bytes, 12);
        assert_eq!(moved_paths.len(), 2);
        assert!(moved_paths.contains(&normalize_path_for_id(&root.join("a.tmp"))));
        assert!(moved_paths.contains(&normalize_path_for_id(&nested)));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn real_cleanup_reports_progress_for_actual_directory_children() {
        let root = env::temp_dir().join(format!(
            "cleandeck-clean-progress-test-{}-{}",
            std::process::id(),
            stable_hash("progress")
        ));
        let nested = root.join("nested");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&nested).expect("nested test directory should be created");
        fs::write(root.join("a.tmp"), [1_u8; 7]).expect("test file should be written");

        let candidate = test_cleanup_candidate("dir-cache", &root, ObjectType::Directory);
        let mut moved_paths = Vec::new();
        let mut progress_events = Vec::new();
        let mut on_progress = |progress: CleanupProgress| progress_events.push(progress);

        let report = execute_cleanup_with_mover_and_progress(
            vec![candidate],
            &[String::from("dir-cache")],
            DeleteStrategy::MoveToRecycleBin,
            |path| {
                moved_paths.push(normalize_path_for_id(path));
                Ok(())
            },
            &mut on_progress,
        );

        assert_eq!(report.cleaned_count, 1);
        assert_eq!(moved_paths.len(), 2);
        assert_eq!(
            progress_events.first().map(|event| event.status),
            Some(CleanupProgressStatus::Preparing)
        );
        assert_eq!(
            progress_events.last().map(|event| event.status),
            Some(CleanupProgressStatus::Complete)
        );
        assert!(progress_events
            .iter()
            .any(|event| event.total_count == 2 && event.processed_count == 1));
        assert!(progress_events
            .iter()
            .any(|event| event.status == CleanupProgressStatus::Cleaning
                && event.percent > 0
                && !event.current_path.is_empty()));
        assert!(progress_events.iter().any(|event| event.total_count == 2
            && event.processed_count == 2
            && event.percent == 100));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn real_cleanup_can_cancel_before_remaining_candidates() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        #[derive(Clone)]
        struct CancelOnSecondCheckpoint {
            calls: Arc<AtomicUsize>,
        }

        impl CleanupController for CancelOnSecondCheckpoint {
            fn is_canceled(&self) -> bool {
                self.calls.load(Ordering::SeqCst) >= 2
            }

            fn checkpoint(&self) -> CleanupControlFlow {
                if self.calls.fetch_add(1, Ordering::SeqCst) >= 1 {
                    CleanupControlFlow::Cancel
                } else {
                    CleanupControlFlow::Continue
                }
            }
        }

        let root = env::temp_dir().join(format!(
            "cleandeck-clean-cancel-test-{}-{}",
            std::process::id(),
            stable_hash("cancel")
        ));
        let first = root.join("first.tmp");
        let second = root.join("second.tmp");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test directory should be created");
        fs::write(&first, [1_u8; 7]).expect("first file should be written");
        fs::write(&second, [2_u8; 5]).expect("second file should be written");

        let mut progress_events = Vec::new();
        let report = execute_cleanup_for_candidates_with_progress_and_control(
            vec![
                test_cleanup_candidate("first", &first, ObjectType::File),
                test_cleanup_candidate("second", &second, ObjectType::File),
            ],
            &[String::from("first"), String::from("second")],
            CleanupExecutionOptions {
                delete_strategy: DeleteStrategy::PermanentDelete,
            },
            CancelOnSecondCheckpoint {
                calls: Arc::new(AtomicUsize::new(0)),
            },
            |progress| progress_events.push(progress),
        );

        assert!(report.cancelled);
        assert_eq!(report.cleaned_count, 1);
        assert_eq!(report.skipped_locked_count, 1);
        assert!(!first.exists());
        assert!(second.exists());
        assert_eq!(
            progress_events.last().map(|event| event.status),
            Some(CleanupProgressStatus::Canceled)
        );

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn recycle_bin_candidate_requires_review_and_cleans_contents_permanently() {
        let root = env::temp_dir().join(format!(
            "cleandeck-recycle-test-{}-{}",
            std::process::id(),
            stable_hash("recycle")
        ));
        let recycle_root = root.join("$Recycle.Bin");
        let sid_root = recycle_root.join("S-1-5-21-test");
        let recycled_file = sid_root.join("$R123.tmp");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&sid_root).expect("recycle SID directory should be created");
        fs::write(&recycled_file, [1_u8; 9]).expect("recycle test file should be written");

        let mut candidate = test_cleanup_candidate("recycle", &recycle_root, ObjectType::Directory);
        candidate.category = "回收站".to_string();
        candidate.size_bytes = 9;
        candidate.children_count = 1;
        candidate = apply_cleanup_support_policy(candidate);

        assert_eq!(candidate.risk_level, RiskLevel::ReviewRequired);
        assert_eq!(candidate.delete_strategy, DeleteStrategy::PermanentDelete);
        assert!(!candidate.default_selected);
        assert!(!candidate.selected);

        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("recycle")],
            DeleteStrategy::MoveToRecycleBin,
            |_path| Err("standard mover should not be used for recycle bin".to_string()),
        );

        assert_eq!(report.cleaned_count, 1);
        assert_eq!(report.reclaimed_bytes, 9);
        assert!(!recycled_file.exists());
        assert!(sid_root.exists());
        assert!(report.item_results[0].reason.contains("永久删除"));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn cleanup_refuses_dependency_and_persistent_state_paths() {
        let dependency_path = Path::new("D:\\Work\\demo\\node_modules");
        let state_path =
            Path::new("D:\\cantinstall\\Ant Browser\\data\\Default\\Local Storage\\leveldb");
        let database_path = Path::new("C:\\Users\\979\\AppData\\Local\\Cursor\\state.vscdb");

        assert!(validate_cleanup_target_path(dependency_path)
            .expect_err("node_modules should be protected")
            .contains("依赖"));
        let state_error = validate_cleanup_target_path(state_path)
            .expect_err("Local Storage should be protected");
        assert!(state_error.contains("持久化状态") || state_error.contains("应用安装目录"));
        assert!(validate_cleanup_target_path(database_path)
            .expect_err("database files should be protected")
            .contains("数据库"));
    }

    #[test]
    fn source_info_identifies_builtin_and_appdata_sources() {
        let chrome = source_info_for_path(Path::new(
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache",
        ));
        let vscode =
            source_info_for_path(Path::new("C:\\Users\\979\\AppData\\Roaming\\Code\\Cache"));
        let update = source_info_for_path(Path::new("C:\\Windows\\SoftwareDistribution\\Download"));
        let temp = source_info_for_path(Path::new(
            "C:\\Users\\979\\AppData\\Local\\Temp\\setup-cache",
        ));

        assert_eq!(chrome.label, "Google Chrome");
        assert_eq!(chrome.kind, SourceKind::Browser);
        assert_eq!(vscode.label, "Visual Studio Code");
        assert_eq!(vscode.kind, SourceKind::DevTool);
        assert_eq!(update.label, "Windows Update");
        assert_eq!(update.kind, SourceKind::Windows);
        assert_ne!(temp.kind, SourceKind::Project);
    }

    #[test]
    fn source_info_identifies_project_ancestor() {
        let root = env::temp_dir().join(format!(
            "cleandeck-source-project-test-{}-{}",
            std::process::id(),
            stable_hash("source-project")
        ));
        let project = root.join("diskclean-project");
        let cache = project.join("target").join("debug");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&cache).expect("project cache directory should be created");
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='diskclean-project'\n",
        )
        .expect("project marker should be written");

        let source = source_info_for_path(&cache);

        assert_eq!(source.kind, SourceKind::Project);
        assert!(source.label.contains("diskclean-project"));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn source_info_identifies_steam_common_path_without_manifest() {
        let source = source_info_for_path(Path::new(
            "D:\\SteamLibrary\\steamapps\\common\\Detroit Become Human\\ShaderCache",
        ));

        assert_eq!(source.kind, SourceKind::Game);
        assert_eq!(source.label, "Steam: Detroit Become Human");
    }

    #[test]
    fn cleanup_report_items_keep_backend_source() {
        let candidate = test_cleanup_candidate(
            "chrome-cache",
            Path::new("C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"),
            ObjectType::Directory,
        );
        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("chrome-cache")],
            DeleteStrategy::MoveToRecycleBin,
            |_path| Ok(()),
        );

        assert_eq!(report.item_results[0].source.label, "Google Chrome");
        assert_eq!(report.item_results[0].source.kind, SourceKind::Browser);
    }

    #[test]
    fn full_walk_skips_dependency_directories_inside_projects() {
        let root = env::temp_dir().join(format!(
            "cleandeck-node-modules-skip-test-{}-{}",
            std::process::id(),
            stable_hash("node-modules-skip")
        ));
        let project = root.join("project");
        let node_modules = project.join("node_modules");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&node_modules).expect("node_modules directory should be created");
        fs::write(project.join("package.json"), "{}").expect("project marker should be written");
        fs::write(node_modules.join("left-pad.js"), [1_u8; 11])
            .expect("dependency file should be written");

        let volume = VolumeInfo {
            id: "T".to_string(),
            label: "Test".to_string(),
            mount_point: root.to_string_lossy().to_string(),
            filesystem: "exFAT".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: false,
        };
        let run = walk_full_volume(&volume);

        assert!(run
            .candidates
            .iter()
            .all(|candidate| !candidate.path.contains("node_modules")));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn real_cleanup_blocks_system_roots_before_moving() {
        let candidate = test_cleanup_candidate(
            "system32",
            Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts"),
            ObjectType::File,
        );
        let mut move_called = false;

        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("system32")],
            DeleteStrategy::MoveToRecycleBin,
            |_path| {
                move_called = true;
                Ok(())
            },
        );

        assert_eq!(report.cleaned_count, 0);
        assert_eq!(report.skipped_locked_count, 1);
        assert_eq!(report.item_results[0].status, CleanupItemStatus::Skipped);
        assert!(report.item_results[0].reason.contains("Windows 系统目录"));
        assert!(!move_called);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("Windows 系统目录")));
    }

    #[test]
    fn real_cleanup_reports_move_failures_without_removing_from_ui() {
        let root = env::temp_dir().join(format!(
            "cleandeck-clean-fail-test-{}-{}",
            std::process::id(),
            stable_hash("fail")
        ));
        let file = root.join("cache.tmp");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test directory should be created");
        fs::write(&file, [1_u8; 7]).expect("test file should be written");

        let candidate = test_cleanup_candidate("file-cache", &file, ObjectType::File);
        let report = execute_cleanup_with_mover(
            vec![candidate],
            &[String::from("file-cache")],
            DeleteStrategy::MoveToRecycleBin,
            |_path| Err("access denied".to_string()),
        );

        assert_eq!(report.cleaned_count, 0);
        assert_eq!(report.failed_count, 1);
        assert_eq!(report.failed_ids, vec!["file-cache"]);
        assert!(report.cleaned_ids.is_empty());
        assert_eq!(report.item_results[0].status, CleanupItemStatus::Failed);
        assert!(report.item_results[0].reason.contains("access denied"));

        fs::remove_dir_all(&root).expect("test directory should be removed");
    }

    #[test]
    fn cleanup_preview_skips_blocked_candidates() {
        let selected = vec!["chrome-cache".to_string(), "app-session-db".to_string()];

        let plan = preview_cleanup(&selected);

        assert_eq!(plan.selected_count, 1);
        assert_eq!(plan.skipped_locked_count, 1);
        assert_eq!(plan.estimated_reclaim_bytes, 842 * mib());
        assert_eq!(plan.delete_strategy, DeleteStrategy::MoveToRecycleBin);
    }

    #[test]
    fn known_browser_cache_is_safe_by_default() {
        let classification = classify_application_cache(
            "C:/Users/979/AppData/Local/Google/Chrome/User Data/Default/Cache",
            false,
        );

        assert_eq!(classification.decision, CacheDecision::AllowClean);
        assert_eq!(classification.risk_level, RiskLevel::SafeRecommended);
        assert!(classification.default_selected);
    }

    #[test]
    fn dependency_store_requires_review_by_default() {
        let classification = classify_application_cache("C:/Users/979/.gradle/caches", false);

        assert_eq!(classification.decision, CacheDecision::ReviewClean);
        assert_eq!(classification.risk_level, RiskLevel::ReviewRequired);
        assert!(!classification.default_selected);
    }

    #[test]
    fn roaming_session_database_is_blocked() {
        let classification =
            classify_application_cache("C:/Users/979/AppData/Roaming/SomeApp/session.db", false);

        assert_eq!(classification.decision, CacheDecision::BlockClean);
        assert_eq!(classification.risk_level, RiskLevel::Blocked);
        assert!(!classification.default_selected);
    }

    #[test]
    fn unknown_cache_requires_review() {
        let classification = classify_application_cache("D:/Media/Cache/PreviewRender", false);

        assert_eq!(classification.decision, CacheDecision::ReviewClean);
        assert_eq!(classification.risk_level, RiskLevel::ReviewRequired);
        assert!(!classification.default_selected);
    }

    #[test]
    fn windows_temp_directory_is_safe_by_default() {
        let volume = VolumeInfo {
            id: "C".to_string(),
            label: "System".to_string(),
            mount_point: "C:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: true,
        };
        let candidate = full_directory_candidate(
            Path::new("C:\\Windows\\Temp"),
            DirectoryStats {
                size_bytes: 42,
                children_count: 2,
                truncated: false,
            },
            &volume,
        )
        .expect("Windows temp should be a cleanup candidate");

        assert_eq!(candidate.category, "Windows 临时文件");
        assert_eq!(candidate.risk_level, RiskLevel::SafeRecommended);
        assert!(candidate.default_selected);
        assert!(candidate.selected);
    }

    #[test]
    fn known_windows_logs_require_review_but_are_cleanable() {
        let volume = VolumeInfo {
            id: "C".to_string(),
            label: "System".to_string(),
            mount_point: "C:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: true,
        };
        let candidate = full_file_candidate(
            Path::new("C:\\Windows\\System32\\LogFiles\\HTTPERR\\httperr1.log"),
            128,
            &volume,
        )
        .expect("Windows log file should be visible as a candidate");

        assert_eq!(candidate.category, "Windows 日志文件");
        assert_eq!(candidate.risk_level, RiskLevel::CautiousRecommended);
        assert_eq!(candidate.delete_strategy, DeleteStrategy::MoveToRecycleBin);
        assert!(!candidate.default_selected);
        assert!(!candidate.selected);
        assert!(!candidate.reason.contains("暂不支持自动清理日志"));
    }

    #[test]
    fn generic_log_files_are_visible_but_not_selected_by_default() {
        let volume = VolumeInfo {
            id: "D".to_string(),
            label: "Data".to_string(),
            mount_point: "D:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: true,
        };
        let candidate = full_file_candidate(Path::new("D:\\App\\logs\\app.log"), 128, &volume)
            .expect("generic log file should be visible as a candidate");

        assert_eq!(candidate.category, "可疑临时文件");
        assert_eq!(candidate.risk_level, RiskLevel::CautiousRecommended);
        assert_eq!(candidate.delete_strategy, DeleteStrategy::MoveToRecycleBin);
        assert!(!candidate.default_selected);
        assert!(!candidate.selected);
        assert!(!candidate.reason.contains("暂不支持自动清理日志"));
    }

    #[test]
    fn large_files_are_analysis_only_before_cleanup() {
        let volume = VolumeInfo {
            id: "D".to_string(),
            label: "Data".to_string(),
            mount_point: "D:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: true,
        };
        let candidate = full_file_candidate(
            Path::new("D:\\Downloads\\archive.iso"),
            LARGE_FILE_THRESHOLD_BYTES,
            &volume,
        )
        .expect("large file should be visible as an analysis candidate");

        assert_eq!(candidate.category, "大文件");
        assert_eq!(candidate.risk_level, RiskLevel::Blocked);
        assert_eq!(candidate.delete_strategy, DeleteStrategy::Skip);
        assert!(!candidate.selected);
        assert!(candidate.reason.contains("仅用于空间分析"));
    }

    #[test]
    fn windows_diagnostic_directory_is_selected_by_default() {
        let volume = VolumeInfo {
            id: "C".to_string(),
            label: "System".to_string(),
            mount_point: "C:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: true,
        };
        let candidate = full_directory_candidate(
            Path::new("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive"),
            DirectoryStats {
                size_bytes: 42,
                children_count: 2,
                truncated: false,
            },
            &volume,
        )
        .expect("Windows diagnostic reports should be a cleanup candidate");

        assert_eq!(candidate.category, "Windows 错误报告");
        assert_eq!(candidate.risk_level, RiskLevel::SafeRecommended);
        assert!(candidate.default_selected);
        assert!(candidate.selected);
    }

    #[test]
    fn thumbnail_cache_file_is_safe_by_default() {
        let volume = VolumeInfo {
            id: "C".to_string(),
            label: "System".to_string(),
            mount_point: "C:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: true,
        };
        let candidate = full_file_candidate(
            Path::new(
                "C:\\Users\\979\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_256.db",
            ),
            128,
            &volume,
        )
        .expect("thumbnail cache should be a cleanup candidate");

        assert_eq!(candidate.category, "缩略图缓存");
        assert_eq!(candidate.risk_level, RiskLevel::SafeRecommended);
        assert!(candidate.default_selected);
    }

    #[test]
    fn windows_recovery_file_requires_review() {
        let volume = VolumeInfo {
            id: "C".to_string(),
            label: "System".to_string(),
            mount_point: "C:\\".to_string(),
            filesystem: "NTFS".to_string(),
            total_bytes: 0,
            available_bytes: 0,
            selected: true,
            supports_fast_index: true,
        };
        let candidate = full_file_candidate(
            Path::new("C:\\$WinREAgent\\Scratch\\update.wim"),
            128,
            &volume,
        )
        .expect("Windows recovery scratch file should be a cleanup candidate");

        assert_eq!(candidate.category, "Windows 恢复缓存");
        assert_eq!(candidate.risk_level, RiskLevel::ReviewRequired);
        assert!(!candidate.default_selected);
        assert!(!candidate.selected);
    }

    #[test]
    fn snapshot_serializes_to_camel_case_json() {
        let snapshot = sample_scan_snapshot();
        let json = serde_json::to_value(snapshot).expect("snapshot should serialize");

        assert!(json.get("selectedCandidateId").is_some());
        assert!(json
            .get("summary")
            .and_then(|summary| summary.get("estimatedReclaimBytes"))
            .is_some());
    }

    const FIREFOX_CACHE: &str =
        "C:\\Users\\979\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\ab12cd.default-release\\cache2";

    #[test]
    fn firefox_profile_cache_is_cleanable_despite_profile_segment() {
        let normalized = normalize_path_for_id(Path::new(FIREFOX_CACHE));

        assert!(!is_persistent_state_path(&normalized));
        assert!(is_known_browser_cache(&normalized));
        assert_eq!(
            evaluate_cleanup_target_path(Path::new(FIREFOX_CACHE)),
            PathGuardLevel::Allowed
        );
        assert!(validate_cleanup_target_path(Path::new(FIREFOX_CACHE)).is_ok());

        let entry = Path::new(FIREFOX_CACHE).join("entries\\3F2A1B00");
        assert!(validate_cleanup_target_path(&entry).is_ok());
    }

    #[test]
    fn profile_state_files_stay_hard_denied() {
        for path in [
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Preferences",
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies-journal",
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data-wal",
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local State",
            "C:\\Users\\979\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\IndexedDB",
        ] {
            assert!(
                matches!(
                    evaluate_cleanup_target_path(Path::new(path)),
                    PathGuardLevel::HardDeny(_)
                ),
                "{path} should be hard denied"
            );
        }
    }

    #[test]
    fn state_inside_cache_directory_stays_hard_denied() {
        let cookies = Path::new(FIREFOX_CACHE).join("Cookies");
        let wallet = Path::new(FIREFOX_CACHE).join("wallet");

        assert!(matches!(
            evaluate_cleanup_target_path(&cookies),
            PathGuardLevel::HardDeny(_)
        ));
        assert!(matches!(
            evaluate_cleanup_target_path(&wallet),
            PathGuardLevel::HardDeny(_)
        ));
    }

    #[test]
    fn user_content_directories_stay_hard_denied() {
        for path in [
            "C:\\Users\\979\\Documents\\taxes\\2025.xlsx",
            "C:\\Users\\979\\Desktop\\notes\\todo.txt",
            "C:\\Users\\979\\Pictures\\2025\\img.png",
        ] {
            assert!(
                matches!(
                    evaluate_cleanup_target_path(Path::new(path)),
                    PathGuardLevel::HardDeny(_)
                ),
                "{path} should be hard denied"
            );
        }
    }

    #[test]
    fn dependency_dirs_are_denied_but_download_caches_only_need_confirmation() {
        assert!(matches!(
            evaluate_cleanup_target_path(Path::new("D:\\Work\\demo\\node_modules\\react")),
            PathGuardLevel::HardDeny(_)
        ));

        let npm_cache = Path::new("C:\\Users\\979\\AppData\\Local\\npm-cache");
        assert!(matches!(
            evaluate_cleanup_target_path(npm_cache),
            PathGuardLevel::NeedsConfirm(_)
        ));
        assert!(validate_cleanup_target_path(npm_cache).is_ok());

        let candidate = apply_cleanup_support_policy(test_cleanup_candidate(
            "npm-cache",
            npm_cache,
            ObjectType::Directory,
        ));
        assert_eq!(candidate.risk_level, RiskLevel::ReviewRequired);
        assert_ne!(candidate.delete_strategy, DeleteStrategy::Skip);
        assert!(!candidate.selected);
    }

    #[test]
    fn hard_deny_applies_to_rule_backed_candidates() {
        let mut candidate = test_cleanup_candidate(
            "subscription-docs",
            Path::new("C:\\Users\\979\\Documents\\taxes"),
            ObjectType::Directory,
        );
        candidate.cleanup_policy = CleanupPolicy {
            rule_id: Some("subscription.docs".to_string()),
            method: RuleCleanupMethod::Contents,
            keep_days: 0,
            exclude_patterns: Vec::new(),
        };

        let candidate = apply_cleanup_support_policy(candidate);

        assert_eq!(candidate.risk_level, RiskLevel::Blocked);
        assert_eq!(candidate.delete_strategy, DeleteStrategy::Skip);
        assert!(!candidate.selected);
    }

    #[test]
    fn built_in_rules_keep_needs_confirm_exemption() {
        assert!(is_built_in_rule_id(Some("npm.cache.review")));
        assert!(!is_built_in_rule_id(Some("subscription.npm")));
        assert!(!is_built_in_rule_id(None));
    }

    #[test]
    fn subscription_rule_targeting_denied_path_is_not_cleanable() {
        let compilation = compile_cleanup_rules_yaml(
            r#"
version: 1
rules:
  - id: evil.docs
    name: 文档清理
    app: Evil
    category: 临时文件
    level: 推荐清理
    default: true
    paths:
      - "%USERPROFILE%\\Documents\\Reports"
    clean: contents
    note: 订阅规则不应获得豁免。
"#,
            RuleSourceKind::Subscription,
        );

        assert!(compilation.report.valid);
        let rule = &compilation.rules[0];
        assert_ne!(rule.risk_level, RiskLevel::SafeRecommended);
        assert!(!rule.default_selected);

        let mut candidate = test_cleanup_candidate(
            "evil",
            Path::new("C:\\Users\\979\\Documents\\Reports"),
            ObjectType::Directory,
        );
        candidate.cleanup_policy = cleanup_policy_for_rule(rule);
        let candidate = apply_cleanup_support_policy(candidate);

        assert_eq!(candidate.risk_level, RiskLevel::Blocked);
        assert_eq!(candidate.delete_strategy, DeleteStrategy::Skip);
    }
}

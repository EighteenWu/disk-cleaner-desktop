mod ai_provider;
mod app_storage;
mod automation_storage;
mod background_tasks;
mod credentials;
mod inventory_repository;
mod rule_library_repository;
mod windows_scheduler;

use ai_provider::{
    ProviderConnectionResult, ProviderError, ProviderErrorCategory, ProviderGenerationRequest,
    ProviderModel, ProviderModelQuery, ProviderPlanRequest, ProviderProfile,
};
use app_storage::{AppLogEntry, StoredRuleSubscription};
use cleaner_core::{
    build_space_digest, compile_cleanup_rules_yaml,
    execute_cleanup_for_candidates_with_progress_and_control, import_winapp2_ini,
    initial_scan_snapshot, preview_cleanup_for_candidates, redacted_scan_summary,
    scan_candidate_children_for_candidate, scan_snapshot_with_request_and_progress,
    scan_snapshot_with_request_and_progress_and_inventory, validate_rule_subscription_url,
    CleanupCandidate, CleanupControlFlow, CleanupController, CleanupExecutionOptions, CleanupPlan,
    CleanupReport, InventoryPage, InventorySort, RuleCompilation, RuleLibrarySnapshot,
    RuleSourceKind, RuleValidationReport, ScanController, ScanMode, ScanRequest, ScanSnapshot,
    SPACE_DIGEST_FETCH_LIMIT,
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    process::Command,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};

use inventory_repository::InventoryRepository;

const CLEANUP_PROGRESS_EVENT: &str = "cleanup-progress";
const SCAN_PROGRESS_EVENT: &str = "scan-progress";
const AI_GENERATION_PROGRESS_EVENT: &str = "ai-generation-progress";

#[derive(Default)]
struct RuleLibraryWriteControl(tokio::sync::Mutex<()>);

#[derive(Default)]
struct AiGenerationControl {
    active: Mutex<Option<tokio_util::sync::CancellationToken>>,
}

impl AiGenerationControl {
    fn start(&self) -> Result<tokio_util::sync::CancellationToken, String> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active.is_some() {
            return Err("已有 AI 规则生成任务正在运行。".to_string());
        }
        let token = tokio_util::sync::CancellationToken::new();
        *active = Some(token.clone());
        Ok(token)
    }

    fn finish(&self) {
        *self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    fn cancel(&self) -> Result<(), String> {
        let active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let token = active
            .as_ref()
            .ok_or_else(|| "当前没有正在运行的 AI 规则生成任务。".to_string())?;
        token.cancel();
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminStatus {
    is_admin: bool,
    can_restart_elevated: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleLibraryMutationRequest {
    expected_generation: u64,
    expected_head_revision_id: Option<uuid::Uuid>,
    mutation_id: uuid::Uuid,
    actor_id: uuid::Uuid,
    device_id: uuid::Uuid,
    timestamp: String,
    action: RuleLibraryMutationAction,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum RuleLibraryMutationAction {
    CreateDraft {
        display_name: String,
        origin: cleaner_core::RuleOrigin,
        content: String,
        provenance: cleaner_core::RuleProvenance,
    },
    ImportApprovedAiDraft {
        display_name: String,
        envelope: cleaner_core::ApprovedRuleEnvelope,
    },
    ImportAndApproveAiRule {
        display_name: String,
        envelope: cleaner_core::ApprovedRuleEnvelope,
    },
    SaveDraft {
        record_id: uuid::Uuid,
        content: String,
        provenance: cleaner_core::RuleProvenance,
    },
    Approve {
        record_id: uuid::Uuid,
        expected_hash: String,
    },
    Disable {
        record_id: uuid::Uuid,
    },
    Enable {
        record_id: uuid::Uuid,
    },
    Delete {
        record_id: uuid::Uuid,
    },
    Restore {
        record_id: uuid::Uuid,
    },
    Rollback {
        record_id: uuid::Uuid,
        revision_id: uuid::Uuid,
    },
    ImportAndApproveSubscription {
        display_name: String,
        content: String,
        provenance: cleaner_core::RuleProvenance,
    },
    ImportAndApproveStarter {
        display_name: String,
    },
}

#[derive(Clone)]
struct CleanupTaskControl {
    inner: Arc<CleanupTaskControlInner>,
}

struct CleanupTaskControlInner {
    state: Mutex<CleanupTaskControlState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct CleanupTaskControlState {
    running: bool,
    paused: bool,
    cancelled: bool,
}

impl Default for CleanupTaskControl {
    fn default() -> Self {
        Self {
            inner: Arc::new(CleanupTaskControlInner {
                state: Mutex::new(CleanupTaskControlState::default()),
                changed: Condvar::new(),
            }),
        }
    }
}

impl CleanupTaskControl {
    fn start(&self) -> Result<(), String> {
        let mut state = self.lock_state();
        if state.running {
            return Err("已有清理任务正在运行。".to_string());
        }

        state.running = true;
        state.paused = false;
        state.cancelled = false;
        self.inner.changed.notify_all();
        Ok(())
    }

    fn finish(&self) {
        let mut state = self.lock_state();
        state.running = false;
        state.paused = false;
        state.cancelled = false;
        self.inner.changed.notify_all();
    }

    fn pause(&self) -> Result<(), String> {
        let mut state = self.lock_state();
        if !state.running {
            return Err("当前没有正在运行的清理任务。".to_string());
        }

        state.paused = true;
        self.inner.changed.notify_all();
        Ok(())
    }

    fn resume(&self) -> Result<(), String> {
        let mut state = self.lock_state();
        if !state.running {
            return Err("当前没有正在运行的清理任务。".to_string());
        }

        state.paused = false;
        self.inner.changed.notify_all();
        Ok(())
    }

    fn cancel(&self) -> Result<(), String> {
        let mut state = self.lock_state();
        if !state.running {
            return Err("当前没有正在运行的清理任务。".to_string());
        }

        state.cancelled = true;
        state.paused = false;
        self.inner.changed.notify_all();
        Ok(())
    }

    fn lock_state(&self) -> MutexGuard<'_, CleanupTaskControlState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl CleanupController for CleanupTaskControl {
    fn is_paused(&self) -> bool {
        self.lock_state().paused
    }

    fn is_canceled(&self) -> bool {
        self.lock_state().cancelled
    }

    fn checkpoint(&self) -> CleanupControlFlow {
        let mut state = self.lock_state();
        while state.running && state.paused && !state.cancelled {
            state = self
                .inner
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }

        if state.cancelled {
            CleanupControlFlow::Cancel
        } else {
            CleanupControlFlow::Continue
        }
    }
}

#[derive(Clone)]
struct ScanTaskControl {
    inner: Arc<ScanTaskControlInner>,
}

struct ScanTaskControlInner {
    state: Mutex<ScanTaskControlState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct ScanTaskControlState {
    running: bool,
    paused: bool,
}

impl Default for ScanTaskControl {
    fn default() -> Self {
        Self {
            inner: Arc::new(ScanTaskControlInner {
                state: Mutex::new(ScanTaskControlState::default()),
                changed: Condvar::new(),
            }),
        }
    }
}

impl ScanTaskControl {
    fn start(&self) -> Result<(), String> {
        let mut state = self.lock_state();
        if state.running {
            return Err("已有扫描任务正在运行。".to_string());
        }

        state.running = true;
        state.paused = false;
        self.inner.changed.notify_all();
        Ok(())
    }

    fn finish(&self) {
        let mut state = self.lock_state();
        state.running = false;
        state.paused = false;
        self.inner.changed.notify_all();
    }

    fn pause(&self) -> Result<(), String> {
        let mut state = self.lock_state();
        if !state.running {
            return Err("当前没有正在运行的扫描任务。".to_string());
        }

        state.paused = true;
        self.inner.changed.notify_all();
        Ok(())
    }

    fn resume(&self) -> Result<(), String> {
        let mut state = self.lock_state();
        if !state.running {
            return Err("当前没有正在运行的扫描任务。".to_string());
        }

        state.paused = false;
        self.inner.changed.notify_all();
        Ok(())
    }

    fn lock_state(&self) -> MutexGuard<'_, ScanTaskControlState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ScanController for ScanTaskControl {
    fn checkpoint(&self) {
        let mut state = self.lock_state();
        while state.running && state.paused {
            state = self
                .inner
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

#[tauri::command]
async fn get_scan_snapshot() -> Result<ScanSnapshot, String> {
    tauri::async_runtime::spawn_blocking(initial_scan_snapshot)
        .await
        .map_err(|error| format!("scan snapshot task failed: {error}"))
}

#[tauri::command]
async fn run_scan(
    app: AppHandle,
    scan_control: State<'_, ScanTaskControl>,
    inventory_repository: State<'_, InventoryRepository>,
    request: ScanRequest,
) -> Result<ScanSnapshot, String> {
    let scan_control = scan_control.inner().clone();
    scan_control.start()?;
    let task_control = scan_control.clone();
    let repository = inventory_repository.inner().clone();
    let task_result =
        tauri::async_runtime::spawn_blocking(move || -> Result<ScanSnapshot, String> {
            if request.mode == ScanMode::Full {
                let session_id = uuid::Uuid::new_v4().to_string();
                let mut writer = repository.start_session(&session_id, &request.volume_ids)?;
                let snapshot = scan_snapshot_with_request_and_progress_and_inventory(
                    request,
                    &session_id,
                    &task_control,
                    &mut writer,
                    |progress| {
                        let _ = app.emit(SCAN_PROGRESS_EVENT, &progress);
                    },
                );
                writer.finish(snapshot.coverage.status)?;
                Ok(snapshot)
            } else {
                repository.close_active()?;
                Ok(scan_snapshot_with_request_and_progress(
                    request,
                    &task_control,
                    |progress| {
                        let _ = app.emit(SCAN_PROGRESS_EVENT, &progress);
                    },
                ))
            }
        })
        .await;

    scan_control.finish();
    task_result.map_err(|error| format!("scan task failed: {error}"))?
}

#[tauri::command]
async fn list_inventory_children(
    inventory_repository: State<'_, InventoryRepository>,
    scan_session_id: String,
    parent_entry_id: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
    sort: Option<InventorySort>,
) -> Result<InventoryPage, String> {
    let repository = inventory_repository.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        repository.list_children(
            &scan_session_id,
            parent_entry_id.as_deref(),
            cursor.as_deref(),
            limit.unwrap_or(100),
            sort.unwrap_or_default(),
        )
    })
    .await
    .map_err(|error| format!("inventory query task failed: {error}"))?
}

#[tauri::command]
async fn search_inventory(
    inventory_repository: State<'_, InventoryRepository>,
    scan_session_id: String,
    query: String,
    cursor: Option<String>,
    limit: Option<usize>,
) -> Result<InventoryPage, String> {
    let repository = inventory_repository.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        repository.search(
            &scan_session_id,
            &query,
            cursor.as_deref(),
            limit.unwrap_or(100),
        )
    })
    .await
    .map_err(|error| format!("inventory search task failed: {error}"))?
}

#[tauri::command]
async fn list_inventory_largest(
    inventory_repository: State<'_, InventoryRepository>,
    scan_session_id: String,
    cursor: Option<String>,
    limit: Option<usize>,
) -> Result<InventoryPage, String> {
    let repository = inventory_repository.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        repository.list_largest(&scan_session_id, cursor.as_deref(), limit.unwrap_or(100))
    })
    .await
    .map_err(|error| format!("inventory largest query task failed: {error}"))?
}

#[tauri::command]
fn close_inventory_session(
    inventory_repository: State<'_, InventoryRepository>,
    scan_session_id: String,
) -> Result<(), String> {
    inventory_repository.close_session(&scan_session_id)
}

#[tauri::command]
fn pause_scan(scan_control: State<'_, ScanTaskControl>) -> Result<(), String> {
    scan_control.pause()
}

#[tauri::command]
fn resume_scan(scan_control: State<'_, ScanTaskControl>) -> Result<(), String> {
    scan_control.resume()
}

#[tauri::command]
async fn list_candidate_children(
    candidate: CleanupCandidate,
) -> Result<Vec<CleanupCandidate>, String> {
    tauri::async_runtime::spawn_blocking(move || scan_candidate_children_for_candidate(&candidate))
        .await
        .map_err(|error| format!("directory listing task failed: {error}"))
}

#[tauri::command]
fn preview_cleanup_plan(
    candidates: Vec<CleanupCandidate>,
    selected_ids: Vec<String>,
) -> CleanupPlan {
    preview_cleanup_for_candidates(&candidates, &selected_ids)
}

#[tauri::command]
async fn execute_cleanup_plan(
    app: AppHandle,
    cleanup_control: State<'_, CleanupTaskControl>,
    candidates: Vec<CleanupCandidate>,
    selected_ids: Vec<String>,
    options: Option<CleanupExecutionOptions>,
) -> Result<CleanupReport, String> {
    let cleanup_control = cleanup_control.inner().clone();
    cleanup_control.start()?;
    let task_control = cleanup_control.clone();
    let task_result = tauri::async_runtime::spawn_blocking(move || {
        execute_cleanup_for_candidates_with_progress_and_control(
            candidates,
            &selected_ids,
            options.unwrap_or_default(),
            task_control,
            |progress| {
                let _ = app.emit(CLEANUP_PROGRESS_EVENT, &progress);
            },
        )
    })
    .await;

    cleanup_control.finish();
    task_result.map_err(|error| format!("cleanup task failed: {error}"))
}

#[tauri::command]
fn pause_cleanup(cleanup_control: State<'_, CleanupTaskControl>) -> Result<(), String> {
    cleanup_control.pause()
}

#[tauri::command]
fn resume_cleanup(cleanup_control: State<'_, CleanupTaskControl>) -> Result<(), String> {
    cleanup_control.resume()
}

#[tauri::command]
fn cancel_cleanup(cleanup_control: State<'_, CleanupTaskControl>) -> Result<(), String> {
    cleanup_control.cancel()
}

#[tauri::command]
fn validate_rules_yaml(content: String, source: RuleSourceKind) -> RuleCompilation {
    compile_cleanup_rules_yaml(&content, source)
}

#[tauri::command]
fn import_winapp2_rules(content: String, source: RuleSourceKind) -> RuleCompilation {
    import_winapp2_ini(&content, source)
}

#[tauri::command]
fn validate_subscription_url(url: String) -> RuleValidationReport {
    match validate_rule_subscription_url(&url) {
        Ok(()) => RuleValidationReport {
            valid: true,
            rule_count: 0,
            errors: Vec::new(),
            warnings: Vec::new(),
        },
        Err(error) => RuleValidationReport {
            valid: false,
            rule_count: 0,
            errors: vec![error],
            warnings: Vec::new(),
        },
    }
}

#[tauri::command]
fn get_admin_status() -> AdminStatus {
    AdminStatus {
        is_admin: is_running_as_admin(),
        can_restart_elevated: cfg!(windows),
    }
}

#[tauri::command]
async fn restart_as_admin(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(relaunch_current_exe_as_admin)
        .await
        .map_err(|error| format!("admin relaunch task failed: {error}"))??;

    // ShellExecuteW returns an error when the UAC prompt is cancelled, so only
    // close this non-elevated instance after the elevated process is launched.
    app.exit(0);
    Ok(())
}

#[tauri::command]
async fn reveal_path(path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || reveal_path_in_explorer(path))
        .await
        .map_err(|error| format!("reveal path task failed: {error}"))?
}

#[tauri::command]
async fn read_app_logs(app: AppHandle) -> Result<Vec<AppLogEntry>, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || app_storage::read_app_logs(&root))
        .await
        .map_err(|error| format!("read app logs task failed: {error}"))?
}

#[tauri::command]
async fn write_app_logs(app: AppHandle, logs: Vec<AppLogEntry>) -> Result<(), String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || app_storage::write_app_logs(&root, &logs))
        .await
        .map_err(|error| format!("write app logs task failed: {error}"))?
}

#[tauri::command]
async fn read_rule_subscription_cache(
    app: AppHandle,
) -> Result<Option<StoredRuleSubscription>, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || app_storage::read_rule_subscription(&root))
        .await
        .map_err(|error| format!("read rule subscription cache task failed: {error}"))?
}

#[tauri::command]
async fn write_rule_subscription_cache(
    app: AppHandle,
    subscription: StoredRuleSubscription,
) -> Result<(), String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        app_storage::write_rule_subscription(&root, &subscription)
    })
    .await
    .map_err(|error| format!("write rule subscription cache task failed: {error}"))?
}

#[tauri::command]
async fn clear_rule_subscription_cache(app: AppHandle) -> Result<(), String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || app_storage::clear_rule_subscription(&root))
        .await
        .map_err(|error| format!("clear rule subscription cache task failed: {error}"))?
}

#[tauri::command]
async fn load_rule_library(
    app: AppHandle,
) -> Result<rule_library_repository::RuleLibraryLoadResult, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || rule_library_repository::load_rule_library(&root))
        .await
        .map_err(|error| format!("load rule library task failed: {error}"))?
}

#[tauri::command]
async fn commit_rule_library(
    app: AppHandle,
    write_control: State<'_, RuleLibraryWriteControl>,
    expected_generation: u64,
    snapshot: RuleLibrarySnapshot,
) -> Result<RuleLibrarySnapshot, String> {
    let root = app_storage::app_storage_root(&app)?;
    let _guard = write_control.0.lock().await;
    tauri::async_runtime::spawn_blocking(move || {
        rule_library_repository::commit_rule_library(&root, expected_generation, &snapshot)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("commit rule library task failed: {error}"))?
}

#[tauri::command]
async fn mutate_rule_library(
    app: AppHandle,
    write_control: State<'_, RuleLibraryWriteControl>,
    request: RuleLibraryMutationRequest,
) -> Result<RuleLibrarySnapshot, String> {
    let root = app_storage::app_storage_root(&app)?;
    let _guard = write_control.0.lock().await;
    tauri::async_runtime::spawn_blocking(move || {
        let loaded = rule_library_repository::load_rule_library(&root)?;
        let current = match loaded.snapshot {
            Some(snapshot) => snapshot,
            None if matches!(
                loaded.status,
                rule_library_repository::RuleLibraryLoadStatus::Empty
            ) =>
            {
                cleaner_core::RuleLibrarySnapshot::empty(
                    request.timestamp.clone(),
                    request.device_id,
                    request.actor_id,
                )
            }
            None => return Err("规则库当前处于阻断状态，请先处理恢复问题。".to_string()),
        };
        if current.generation != request.expected_generation {
            return Err("规则库已更新，请刷新后重试。".to_string());
        }
        let context = cleaner_core::RuleMutationContext {
            expected_generation: request.expected_generation,
            expected_head_revision_id: request.expected_head_revision_id,
            mutation_id: request.mutation_id,
            actor_id: request.actor_id,
            timestamp: request.timestamp,
        };
        let next = match request.action {
            RuleLibraryMutationAction::CreateDraft {
                display_name,
                origin,
                content,
                provenance,
            } => cleaner_core::create_rule_draft(
                &current,
                display_name,
                origin,
                &content,
                provenance,
                context,
            ),
            RuleLibraryMutationAction::ImportApprovedAiDraft {
                display_name,
                envelope,
            }
            | RuleLibraryMutationAction::ImportAndApproveAiRule {
                display_name,
                envelope,
            } => {
                cleaner_core::import_and_approve_ai_rule(&current, display_name, &envelope, context)
            }
            RuleLibraryMutationAction::SaveDraft {
                record_id,
                content,
                provenance,
            } => cleaner_core::save_rule_draft(&current, record_id, &content, provenance, context),
            RuleLibraryMutationAction::Approve {
                record_id,
                expected_hash,
            } => {
                cleaner_core::approve_pending_revision(&current, record_id, &expected_hash, context)
            }
            RuleLibraryMutationAction::ImportAndApproveSubscription {
                display_name,
                content,
                provenance,
            } => cleaner_core::import_and_approve_subscription(
                &current,
                display_name,
                &content,
                provenance,
                context,
            ),
            RuleLibraryMutationAction::ImportAndApproveStarter { display_name } => {
                cleaner_core::import_and_approve_starter_rules(&current, display_name, context)
            }
            RuleLibraryMutationAction::Disable { record_id } => {
                cleaner_core::disable_rule_record(&current, record_id, context)
            }
            RuleLibraryMutationAction::Enable { record_id } => {
                cleaner_core::enable_rule_record(&current, record_id, context)
            }
            RuleLibraryMutationAction::Delete { record_id } => {
                cleaner_core::delete_rule_record(&current, record_id, context)
            }
            RuleLibraryMutationAction::Restore { record_id } => {
                cleaner_core::restore_rule_record(&current, record_id, context)
            }
            RuleLibraryMutationAction::Rollback {
                record_id,
                revision_id,
            } => cleaner_core::create_rollback_draft(&current, record_id, revision_id, context),
        }
        .map_err(|error| error.to_string())?;
        if next.generation == current.generation {
            return Ok(current);
        }
        rule_library_repository::commit_rule_library(&root, request.expected_generation, &next)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("mutate rule library task failed: {error}"))?
}

#[tauri::command]
async fn get_active_rule_snapshot(
    app: AppHandle,
) -> Result<cleaner_core::ActiveRuleSnapshot, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let loaded = rule_library_repository::load_rule_library(&root)?;
        Ok(match loaded.snapshot {
            Some(snapshot) => cleaner_core::build_active_rule_snapshot(&snapshot),
            None => cleaner_core::ActiveRuleSnapshot {
                library_generation: 0,
                rules: Vec::new(),
                entries: Vec::new(),
                blocking_issues: loaded.notice.map_or_else(Vec::new, |message| {
                    vec![cleaner_core::ActiveRuleIssue {
                        record_id: None,
                        revision_id: None,
                        code: "libraryUnavailable".into(),
                        message,
                    }]
                }),
            },
        })
    })
    .await
    .map_err(|error| format!("load active rule snapshot task failed: {error}"))?
}

#[tauri::command]
fn build_ai_scan_summary(snapshot: ScanSnapshot) -> cleaner_core::RedactedScanSummary {
    redacted_scan_summary(&snapshot)
}

#[tauri::command]
async fn list_ai_provider_profiles(app: AppHandle) -> Result<Vec<ProviderProfile>, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        ai_provider::read_profiles(&root, &credentials::WindowsCredentialStore)
    })
    .await
    .map_err(|error| format!("list AI provider profiles task failed: {error}"))?
}

#[tauri::command]
async fn save_ai_provider_profile(
    app: AppHandle,
    profile: ProviderProfile,
) -> Result<Vec<ProviderProfile>, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        ai_provider::save_profile(&root, profile, &credentials::WindowsCredentialStore)
    })
    .await
    .map_err(|error| format!("save AI provider profile task failed: {error}"))?
}

#[tauri::command]
async fn delete_ai_provider_profile(
    app: AppHandle,
    profile_id: String,
) -> Result<Vec<ProviderProfile>, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        ai_provider::delete_profile(&root, &profile_id, &credentials::WindowsCredentialStore)
    })
    .await
    .map_err(|error| format!("delete AI provider profile task failed: {error}"))?
}

#[tauri::command]
async fn save_ai_provider_credential(profile_id: String, secret: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        ai_provider::save_credential(&profile_id, secret, &credentials::WindowsCredentialStore)
    })
    .await
    .map_err(|error| format!("save AI provider credential task failed: {error}"))?
}

#[tauri::command]
async fn delete_ai_provider_credential(profile_id: String) -> Result<(), String> {
    use credentials::CredentialStore;
    tauri::async_runtime::spawn_blocking(move || {
        credentials::WindowsCredentialStore.delete(&profile_id)
    })
    .await
    .map_err(|error| format!("delete AI provider credential task failed: {error}"))?
}

#[tauri::command]
async fn list_ai_provider_models(
    query: ProviderModelQuery,
) -> Result<Vec<ProviderModel>, ProviderError> {
    ai_provider::list_models(query, &credentials::WindowsCredentialStore).await
}

#[tauri::command]
async fn test_ai_provider_connection(
    query: ProviderModelQuery,
) -> Result<ProviderConnectionResult, ProviderError> {
    ai_provider::test_connection(query, &credentials::WindowsCredentialStore).await
}

#[tauri::command]
async fn generate_ai_rules(
    app: AppHandle,
    generation_control: State<'_, AiGenerationControl>,
    profile_id: String,
    request: ProviderGenerationRequest,
) -> Result<AiDraftGenerationResponse, ProviderError> {
    let root = app_storage::app_storage_root(&app).map_err(|message| ProviderError {
        category: ProviderErrorCategory::Configuration,
        message,
        retry_after_seconds: None,
    })?;
    let profiles = ai_provider::read_profiles(&root, &credentials::WindowsCredentialStore)
        .map_err(|message| ProviderError {
            category: ProviderErrorCategory::Configuration,
            message,
            retry_after_seconds: None,
        })?;
    let profile = profiles
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| ProviderError {
            category: ProviderErrorCategory::Configuration,
            message: "未找到指定的 AI Provider 配置。".to_string(),
            retry_after_seconds: None,
        })?;
    let token = generation_control
        .start()
        .map_err(|message| ProviderError {
            category: ProviderErrorCategory::Configuration,
            message,
            retry_after_seconds: None,
        })?;
    let app_for_progress = app.clone();
    let result = tokio::select! {
        result = ai_provider::generate_rules(
            &profile,
            &request,
            &credentials::WindowsCredentialStore,
            |progress| {
                let _ = app_for_progress.emit(AI_GENERATION_PROGRESS_EVENT, &progress);
            },
        ) => result,
        _ = token.cancelled() => Err(ProviderError {
            category: ProviderErrorCategory::Cancelled,
            message: "AI 规则生成已取消。".to_string(),
            retry_after_seconds: None,
        }),
    };
    generation_control.finish();
    let response = result?;
    let (generation_mode, target_tier) =
        request.resolved_mode().map_err(|message| ProviderError {
            category: ProviderErrorCategory::Configuration,
            message,
            retry_after_seconds: None,
        })?;
    let draft = cleaner_core::AiRuleDraft::new(
        uuid::Uuid::new_v4().to_string(),
        request.summary.summary_hash,
        generation_mode,
        target_tier,
        profile.id,
        profile.model,
        chrono::Utc::now().to_rfc3339(),
        response.rules,
    )
    .map_err(|message| ProviderError {
        category: ProviderErrorCategory::InvalidSchema,
        message,
        retry_after_seconds: None,
    })?;
    Ok(AiDraftGenerationResponse {
        request_id: response.request_id,
        draft,
    })
}

#[tauri::command]
async fn generate_ai_rule_plan(
    app: AppHandle,
    generation_control: State<'_, AiGenerationControl>,
    inventory_repository: State<'_, InventoryRepository>,
    profile_id: String,
    mut request: ProviderPlanRequest,
) -> Result<ai_provider::ProviderPlanResponse, ProviderError> {
    let root = app_storage::app_storage_root(&app).map_err(|message| ProviderError {
        category: ProviderErrorCategory::Configuration,
        message,
        retry_after_seconds: None,
    })?;
    let profiles = ai_provider::read_profiles(&root, &credentials::WindowsCredentialStore)
        .map_err(|message| ProviderError {
            category: ProviderErrorCategory::Configuration,
            message,
            retry_after_seconds: None,
        })?;
    let profile = profiles
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| ProviderError {
            category: ProviderErrorCategory::Configuration,
            message: "未找到指定的 AI Provider 配置。".to_string(),
            retry_after_seconds: None,
        })?;
    if let Some(session_id) = request.scan_session_id.clone() {
        let repository = inventory_repository.inner().clone();
        request.space_digest = tauri::async_runtime::spawn_blocking(move || {
            repository
                .list_largest_directories(&session_id, SPACE_DIGEST_FETCH_LIMIT)
                .ok()
                .map(build_space_digest)
        })
        .await
        .ok()
        .flatten();
    }
    let token = generation_control
        .start()
        .map_err(|message| ProviderError {
            category: ProviderErrorCategory::Configuration,
            message,
            retry_after_seconds: None,
        })?;
    let app_for_progress = app.clone();
    let result = tokio::select! {
        result = ai_provider::generate_plan(
            &profile,
            &request,
            &credentials::WindowsCredentialStore,
            |progress| {
                let _ = app_for_progress.emit(AI_GENERATION_PROGRESS_EVENT, &progress);
            },
        ) => result,
        _ = token.cancelled() => Err(ProviderError {
            category: ProviderErrorCategory::Cancelled,
            message: "AI 规则对话已取消。".to_string(),
            retry_after_seconds: None,
        }),
    };
    generation_control.finish();
    result
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiDraftGenerationResponse {
    request_id: Option<String>,
    draft: cleaner_core::AiRuleDraft,
}

#[tauri::command]
async fn test_ai_provider_generation(
    query: ai_provider::ProviderGenerationProbeQuery,
) -> Result<ai_provider::ProviderGenerationProbeResult, ProviderError> {
    ai_provider::probe_generation(query, &credentials::WindowsCredentialStore).await
}

#[tauri::command]
fn revise_ai_rule_draft(
    mut draft: cleaner_core::AiRuleDraft,
    expected_revision: u32,
    rules: cleaner_core::AiGeneratedRuleSet,
) -> Result<cleaner_core::AiRuleDraft, String> {
    draft.validate_contract()?;
    if draft.revision != expected_revision {
        return Err("草稿版本已变化，请刷新后重试。".into());
    }
    draft.replace_rules(rules)?;
    Ok(draft)
}

#[tauri::command]
fn validate_ai_rule_draft(
    mut draft: cleaner_core::AiRuleDraft,
    expected_revision: u32,
    expected_summary_hash: String,
) -> Result<cleaner_core::AiRuleDraft, String> {
    draft.validate_contract()?;
    if draft.revision != expected_revision || draft.summary_hash != expected_summary_hash {
        return Err("草稿版本或扫描摘要已变化，请刷新后重试。".into());
    }
    draft.validate_current_revision()?;
    Ok(draft)
}

#[tauri::command]
fn approve_ai_rule_draft(
    draft: cleaner_core::AiRuleDraft,
    expected_revision: u32,
    expected_summary_hash: String,
) -> Result<cleaner_core::ApprovedRuleEnvelope, String> {
    draft.approve(expected_revision, &expected_summary_hash)
}

#[tauri::command]
fn cancel_ai_rule_generation(
    generation_control: State<'_, AiGenerationControl>,
) -> Result<(), String> {
    generation_control.cancel()
}

#[tauri::command]
async fn get_automation_config(
    app: AppHandle,
) -> Result<automation_storage::AutomationConfig, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || automation_storage::read_config(&root))
        .await
        .map_err(|error| format!("read automation config task failed: {error}"))?
}

#[tauri::command]
async fn save_automation_config(
    app: AppHandle,
    expected_revision: u64,
    config: automation_storage::AutomationConfig,
) -> Result<automation_storage::AutomationConfig, String> {
    let root = app_storage::app_storage_root(&app)?;
    let executable =
        std::env::current_exe().map_err(|error| format!("读取当前应用路径失败：{error}"))?;
    tauri::async_runtime::spawn_blocking(move || {
        let saved = automation_storage::save_config(&root, expected_revision, config)?;
        let token = uuid::Uuid::new_v4();
        let registration = automation_storage::AutomationRunnerRegistration::create(&saved, token)?;
        automation_storage::write_runner_registration(&root, &registration)?;
        if saved.startup_enabled || saved.schedule_enabled {
            windows_scheduler::reconcile_tasks(&executable, &saved, token)?;
        } else {
            windows_scheduler::remove_tasks()?;
            automation_storage::remove_runner_registration(&root)?;
        }
        Ok(saved)
    })
    .await
    .map_err(|error| format!("save automation config task failed: {error}"))?
}

#[tauri::command]
async fn get_automation_scheduler_status() -> Result<windows_scheduler::SchedulerStatus, String> {
    tauri::async_runtime::spawn_blocking(windows_scheduler::query_status)
        .await
        .map_err(|error| format!("query automation scheduler task failed: {error}"))?
}

#[tauri::command]
async fn list_automation_reports(
    app: AppHandle,
) -> Result<Vec<automation_storage::AutomationRunReport>, String> {
    let root = app_storage::app_storage_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || automation_storage::list_reports(&root))
        .await
        .map_err(|error| format!("list automation reports task failed: {error}"))?
}

pub fn run_background_cli(args: &[String]) -> Result<(), String> {
    if args.len() != 8
        || args[0] != "--background-task"
        || args[2] != "--task-id"
        || args[4] != "--config-id"
        || args[6] != "--run-token"
    {
        return Err("自动化后台参数格式无效。".into());
    }
    let mode = match args[1].as_str() {
        "scan" => cleaner_core::AutomationMode::ScanOnly,
        "cleanup" => cleaner_core::AutomationMode::ScanAndCleanup,
        _ => return Err("自动化后台模式无效。".into()),
    };
    let trigger = match args[3].as_str() {
        "startup" => cleaner_core::AutomationTrigger::Startup,
        "scheduled" => cleaner_core::AutomationTrigger::Scheduled,
        _ => return Err("自动化任务来源无效。".into()),
    };
    let config_id = args[5]
        .parse::<uuid::Uuid>()
        .map_err(|_| "自动化配置 ID 无效。".to_string())?;
    let token = args[7]
        .parse::<uuid::Uuid>()
        .map_err(|_| "自动化运行令牌无效。".to_string())?;
    let root = background_tasks::default_app_storage_root()?;
    background_tasks::run_background_task(&root, mode, trigger, config_id, token)?;
    Ok(())
}

fn reveal_path_in_explorer(path: String) -> Result<(), String> {
    let path_buf = PathBuf::from(&path);
    if !path_buf.exists() {
        return Err(format!("path does not exist: {path}"));
    }

    let mut command = Command::new("explorer.exe");
    if path_buf.is_file() {
        command.arg(format!("/select,{path}"));
    } else {
        command.arg(path);
    }

    command
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("failed to open explorer: {error}"))
}

#[cfg(windows)]
fn is_running_as_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
fn is_running_as_admin() -> bool {
    false
}

#[cfg(windows)]
fn relaunch_current_exe_as_admin() -> Result<(), String> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

    let exe = std::env::current_exe().map_err(|error| format!("current_exe failed: {error}"))?;
    let operation = OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let file = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };

    if result as isize <= 32 {
        return Err(format!("ShellExecuteW runas failed: {}", result as isize));
    }

    Ok(())
}

#[cfg(not(windows))]
fn relaunch_current_exe_as_admin() -> Result<(), String> {
    Err("当前平台不支持以 Windows 管理员方式启动".to_string())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(CleanupTaskControl::default())
        .manage(ScanTaskControl::default())
        .manage(InventoryRepository::default())
        .manage(AiGenerationControl::default())
        .manage(RuleLibraryWriteControl::default())
        .invoke_handler(tauri::generate_handler![
            get_scan_snapshot,
            run_scan,
            pause_scan,
            resume_scan,
            list_inventory_children,
            search_inventory,
            list_inventory_largest,
            close_inventory_session,
            list_candidate_children,
            preview_cleanup_plan,
            execute_cleanup_plan,
            pause_cleanup,
            resume_cleanup,
            cancel_cleanup,
            validate_rules_yaml,
            import_winapp2_rules,
            validate_subscription_url,
            get_admin_status,
            restart_as_admin,
            reveal_path,
            read_app_logs,
            write_app_logs,
            read_rule_subscription_cache,
            write_rule_subscription_cache,
            clear_rule_subscription_cache,
            load_rule_library,
            commit_rule_library,
            mutate_rule_library,
            get_active_rule_snapshot,
            build_ai_scan_summary,
            list_ai_provider_profiles,
            save_ai_provider_profile,
            delete_ai_provider_profile,
            save_ai_provider_credential,
            delete_ai_provider_credential,
            list_ai_provider_models,
            test_ai_provider_connection,
            test_ai_provider_generation,
            generate_ai_rules,
            generate_ai_rule_plan,
            cancel_ai_rule_generation,
            revise_ai_rule_draft,
            validate_ai_rule_draft,
            approve_ai_rule_draft,
            get_automation_config,
            save_automation_config,
            get_automation_scheduler_status,
            list_automation_reports
        ])
        .setup(|app| {
            let root = app
                .path()
                .app_cache_dir()
                .map_err(std::io::Error::other)?
                .join("scan-inventory");
            app.state::<InventoryRepository>()
                .initialize(root)
                .map_err(std::io::Error::other)?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build disk cleanup desktop app")
        .run(|app, event| {
            if matches!(event, RunEvent::Exit) {
                let _ = app.state::<InventoryRepository>().close_active();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    #[test]
    fn admin_status_reports_platform_restart_support() {
        let status = get_admin_status();

        assert_eq!(status.can_restart_elevated, cfg!(windows));
    }

    #[test]
    fn ai_generation_control_cancels_the_current_token() {
        let control = AiGenerationControl::default();
        let token = control.start().expect("generation should start");

        control.cancel().expect("generation should cancel");
        assert!(token.is_cancelled());
        control.finish();
        assert!(control.cancel().is_err());
    }

    #[test]
    fn scan_task_control_blocks_checkpoint_until_resume() {
        let control = ScanTaskControl::default();
        control.start().expect("scan task should start");
        control.pause().expect("scan task should pause");

        let checkpoint_control = control.clone();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            checkpoint_control.checkpoint();
            sender.send(()).expect("checkpoint result should send");
        });

        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());

        control.resume().expect("scan task should resume");
        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("checkpoint should unblock after resume");

        handle.join().expect("checkpoint thread should finish");
        control.finish();
    }
}

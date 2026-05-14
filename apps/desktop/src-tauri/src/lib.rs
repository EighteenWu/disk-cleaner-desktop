mod app_storage;

use app_storage::{AppLogEntry, StoredRuleSubscription};
use cleaner_core::{
    compile_cleanup_rules_yaml, execute_cleanup_for_candidates_with_progress_and_control,
    import_winapp2_ini, initial_scan_snapshot, preview_cleanup_for_candidates,
    scan_candidate_children_for_candidate, scan_snapshot_with_request_and_control,
    validate_rule_subscription_url, CleanupCandidate, CleanupControlFlow, CleanupController,
    CleanupExecutionOptions, CleanupPlan, CleanupReport, RuleCompilation, RuleSourceKind,
    RuleValidationReport, ScanController, ScanRequest, ScanSnapshot,
};
use serde::Serialize;
use std::{
    path::PathBuf,
    process::Command,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};
use tauri::{AppHandle, Emitter, State};

const CLEANUP_PROGRESS_EVENT: &str = "cleanup-progress";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminStatus {
    is_admin: bool,
    can_restart_elevated: bool,
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
    scan_control: State<'_, ScanTaskControl>,
    request: ScanRequest,
) -> Result<ScanSnapshot, String> {
    let scan_control = scan_control.inner().clone();
    scan_control.start()?;
    let task_control = scan_control.clone();
    let task_result = tauri::async_runtime::spawn_blocking(move || {
        scan_snapshot_with_request_and_control(request, &task_control)
    })
    .await;

    scan_control.finish();
    task_result.map_err(|error| format!("scan task failed: {error}"))
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
        .invoke_handler(tauri::generate_handler![
            get_scan_snapshot,
            run_scan,
            pause_scan,
            resume_scan,
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
            clear_rule_subscription_cache
        ])
        .run(tauri::generate_context!())
        .expect("failed to run disk cleanup desktop app");
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

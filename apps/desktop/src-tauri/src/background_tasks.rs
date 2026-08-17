use crate::{automation_storage, rule_library_repository};
use cleaner_core::{
    build_active_rule_snapshot, execute_cleanup_for_candidates_with_progress_and_control,
    initial_scan_snapshot, scan_snapshot_with_request_and_progress, select_automation_candidates,
    ActiveRuleSnapshot, AutomationMode, AutomationOutcome, AutomationTrigger, CleanupControlFlow,
    CleanupController, CleanupExecutionOptions, RuleOrigin, ScanController, ScanMode, ScanRequest,
};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub fn default_app_storage_root() -> Result<PathBuf, String> {
    let roaming =
        std::env::var_os("APPDATA").ok_or_else(|| "缺少 Windows APPDATA 环境变量。".to_string())?;
    Ok(PathBuf::from(roaming).join("com.cleandeck.desktop"))
}

pub fn run_background_task(
    root: &Path,
    requested_mode: AutomationMode,
    trigger: AutomationTrigger,
    config_id: Uuid,
    token: Uuid,
) -> Result<automation_storage::AutomationRunReport, String> {
    let _instance = SingleInstanceGuard::acquire()?;
    let config = automation_storage::read_config(root)?;
    let registration = automation_storage::read_runner_registration(root)?;
    registration.validate_runner(&config, config_id, token)?;
    if config.mode != requested_mode {
        return Err("自动化运行模式与已保存配置不一致。".into());
    }
    let started_at = chrono::Utc::now().to_rfc3339();
    let mut report =
        automation_storage::AutomationRunReport::started(trigger, requested_mode, started_at);
    automation_storage::write_report(root, &report)?;
    let result = execute(root, &config, &mut report);
    report.finished_at = Some(chrono::Utc::now().to_rfc3339());
    if let Err(error) = result {
        report.status = automation_storage::AutomationReportStatus::Failed;
        report.outcome = Some(AutomationOutcome::Failed);
        report.warnings.push(error);
    }
    automation_storage::write_report(root, &report)?;
    if config.notifications_enabled {
        notify_completion(&report);
    }
    Ok(report)
}

fn execute(
    root: &Path,
    config: &automation_storage::AutomationConfig,
    report: &mut automation_storage::AutomationRunReport,
) -> Result<(), String> {
    config.validate()?;
    let started = Instant::now();
    let loaded = rule_library_repository::load_rule_library(root)?;
    let library = loaded
        .snapshot
        .ok_or_else(|| "本地规则库为空，自动化运行已停止。".to_string())?;
    let mut active = build_active_rule_snapshot(&library);
    retain_ai_generated_rules(&library, &mut active);
    if !active.blocking_issues.is_empty() {
        report.outcome = Some(AutomationOutcome::InvalidRuleSnapshot);
        return Err("当前规则库未通过自动化完整性复检。".into());
    }
    report.library_generation = Some(active.library_generation);

    let volumes = initial_scan_snapshot().volumes;
    let volume_ids = volumes.into_iter().map(|volume| volume.id).collect();
    let request = ScanRequest {
        mode: ScanMode::Full,
        volume_ids,
        rules: active.rules.clone(),
    };
    let control = BackgroundScanControl;
    let snapshot = scan_snapshot_with_request_and_progress(request, &control, |_| {});
    report.scanned_count = snapshot.candidates.len().min(u32::MAX as usize) as u32;
    if !snapshot.warnings.is_empty() {
        report
            .warnings
            .push(format!("扫描返回 {} 条警告。", snapshot.warnings.len()));
    }
    if started.elapsed() >= Duration::from_secs(config.limits.max_runtime_seconds) {
        report.status = automation_storage::AutomationReportStatus::Partial;
        report.outcome = Some(AutomationOutcome::TimedOut);
        return Ok(());
    }

    let selection = select_automation_candidates(&active, &snapshot.candidates, &config.limits)
        .map_err(|_| "自动化候选筛选策略校验失败。".to_string())?;
    report.eligible_count = selection.selected_count;
    report.skipped_count = selection.skipped_count;
    report.capped = selection.capped;
    if config.mode == AutomationMode::ScanOnly {
        report.status = automation_storage::AutomationReportStatus::Completed;
        report.outcome = Some(AutomationOutcome::ScanOnly);
        return Ok(());
    }
    if selection.candidate_ids.is_empty() {
        report.status = automation_storage::AutomationReportStatus::Completed;
        report.outcome = Some(AutomationOutcome::NoEligibleItems);
        return Ok(());
    }

    let deadline = started + Duration::from_secs(config.limits.max_runtime_seconds);
    let cleanup = execute_cleanup_for_candidates_with_progress_and_control(
        snapshot.candidates,
        &selection.candidate_ids,
        CleanupExecutionOptions::default(),
        DeadlineCleanupControl { deadline },
        |_| {},
    );
    report.cleaned_count = cleanup.cleaned_count;
    report.reclaimed_bytes = cleanup.reclaimed_bytes;
    report.skipped_count = report
        .skipped_count
        .saturating_add(cleanup.skipped_locked_count)
        .saturating_add(cleanup.failed_count);
    let timed_out = cleanup.cancelled && Instant::now() >= deadline;
    report.status = if timed_out || selection.capped || cleanup.failed_count > 0 {
        automation_storage::AutomationReportStatus::Partial
    } else {
        automation_storage::AutomationReportStatus::Completed
    };
    report.outcome = Some(if timed_out {
        AutomationOutcome::TimedOut
    } else if selection.capped || cleanup.failed_count > 0 {
        AutomationOutcome::Partial
    } else {
        AutomationOutcome::Completed
    });
    Ok(())
}

#[cfg(windows)]
fn notify_completion(report: &automation_storage::AutomationRunReport) {
    let (body, icon) = match report.status {
        automation_storage::AutomationReportStatus::Completed => (
            format!(
                "后台任务完成：扫描 {} 项，清理 {} 项。",
                report.scanned_count, report.cleaned_count
            ),
            "Info",
        ),
        automation_storage::AutomationReportStatus::Partial => (
            format!(
                "后台任务部分完成：清理 {} 项，部分项目已跳过。",
                report.cleaned_count
            ),
            "Warning",
        ),
        automation_storage::AutomationReportStatus::Failed => (
            "后台任务失败，请在运行记录中查看详情。".to_string(),
            "Error",
        ),
        automation_storage::AutomationReportStatus::Started => return,
    };
    let body = body.replace('\'', "''");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::{icon}; $n.Visible=$true; $n.ShowBalloonTip(5000,'DiskClean','{body}',[System.Windows.Forms.ToolTipIcon]::{icon}); Start-Sleep -Seconds 6; $n.Dispose()"
    );
    let _ = std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &script,
        ])
        .spawn();
}

#[cfg(not(windows))]
fn notify_completion(_report: &automation_storage::AutomationRunReport) {}

fn retain_ai_generated_rules(
    library: &cleaner_core::RuleLibrarySnapshot,
    active: &mut ActiveRuleSnapshot,
) {
    let ai_records: HashSet<Uuid> = library
        .records
        .iter()
        .filter(|record| record.origin == RuleOrigin::AiGenerated)
        .map(|record| record.id)
        .collect();
    active
        .entries
        .retain(|entry| ai_records.contains(&entry.record_id));
    let eligible_ids: HashSet<String> = active
        .entries
        .iter()
        .flat_map(|entry| entry.rule_ids.iter().cloned())
        .collect();
    active.rules.retain(|rule| eligible_ids.contains(&rule.id));
}

struct BackgroundScanControl;
impl ScanController for BackgroundScanControl {
    fn checkpoint(&self) {}
}

#[derive(Clone)]
struct DeadlineCleanupControl {
    deadline: Instant,
}
impl CleanupController for DeadlineCleanupControl {
    fn is_paused(&self) -> bool {
        false
    }
    fn is_canceled(&self) -> bool {
        Instant::now() >= self.deadline
    }
    fn checkpoint(&self) -> CleanupControlFlow {
        if self.is_canceled() {
            CleanupControlFlow::Cancel
        } else {
            CleanupControlFlow::Continue
        }
    }
}

#[cfg(windows)]
struct SingleInstanceGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl SingleInstanceGuard {
    fn acquire() -> Result<Self, String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::{
            Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS},
            System::Threading::CreateMutexW,
        };
        let name: Vec<u16> = std::ffi::OsStr::new(r"Local\CleanDeck.Automation.Runner.v1")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(format!(
                "创建自动化单实例互斥锁失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return Err("已有自动化任务正在运行。".into());
        }
        Ok(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(not(windows))]
struct SingleInstanceGuard;
#[cfg(not(windows))]
impl SingleInstanceGuard {
    fn acquire() -> Result<Self, String> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleaner_core::{
        create_rule_draft, RuleLibrarySnapshot, RuleMutationContext, RuleProvenance,
    };

    #[test]
    fn ai_filter_excludes_manual_library_records() {
        let actor = Uuid::new_v4();
        let device = Uuid::new_v4();
        let timestamp = "2026-03-14T00:00:00Z".to_string();
        let empty = RuleLibrarySnapshot::empty(timestamp.clone(), device, actor);
        let library = create_rule_draft(
            &empty,
            "manual".into(),
            RuleOrigin::Manual,
            "rules: []",
            RuleProvenance::manual(),
            RuleMutationContext {
                expected_generation: 0,
                expected_head_revision_id: None,
                mutation_id: Uuid::new_v4(),
                actor_id: actor,
                timestamp,
            },
        )
        .expect("draft");
        let mut active = build_active_rule_snapshot(&library);
        retain_ai_generated_rules(&library, &mut active);
        assert!(active.entries.is_empty());
        assert!(active.rules.is_empty());
    }
}

use cleaner_core::{validate_rule_subscription_bytes, validate_rule_subscription_url};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

const MAX_APP_LOG_ENTRIES: usize = 200;
const LOG_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
const LOG_FILE_PATH: &[&str] = &["logs", "app.jsonl"];
const RULE_SUBSCRIPTION_FILE_PATH: &[&str] = &["config", "rule-subscription.json"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppLogEntry {
    pub id: String,
    pub kind: String,
    pub time: String,
    pub title: String,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredRuleSubscription {
    pub url: String,
    pub content: String,
    pub checked_at: String,
}

pub fn app_storage_root(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|error| format!("无法定位应用数据目录：{error}"))
}

pub fn read_app_logs(root: &Path) -> Result<Vec<AppLogEntry>, String> {
    let path = app_storage_path(root, LOG_FILE_PATH);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&path)
        .map_err(|error| format!("读取应用日志失败：{}：{error}", path.display()))?;
    let mut logs = Vec::new();

    let cutoff = retention_cutoff();

    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        if let Ok(entry) = serde_json::from_str::<AppLogEntry>(line) {
            if is_valid_log_entry(&entry) && is_within_retention(&entry.time, &cutoff) {
                logs.push(entry);
            }
        }
    }

    Ok(logs.into_iter().take(MAX_APP_LOG_ENTRIES).collect())
}

pub fn write_app_logs(root: &Path, logs: &[AppLogEntry]) -> Result<(), String> {
    let path = app_storage_path(root, LOG_FILE_PATH);
    ensure_parent_dir(&path)?;

    let cutoff = retention_cutoff();
    let mut content = String::new();
    for log in logs
        .iter()
        .filter(|log| is_valid_log_entry(log) && is_within_retention(&log.time, &cutoff))
        .take(MAX_APP_LOG_ENTRIES)
    {
        let line =
            serde_json::to_string(log).map_err(|error| format!("序列化应用日志失败：{error}"))?;
        content.push_str(&line);
        content.push('\n');
    }

    fs::write(&path, content)
        .map_err(|error| format!("写入应用日志失败：{}：{error}", path.display()))
}

pub fn read_rule_subscription(root: &Path) -> Result<Option<StoredRuleSubscription>, String> {
    let path = app_storage_path(root, RULE_SUBSCRIPTION_FILE_PATH);
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&path)
        .map_err(|error| format!("读取订阅规则缓存失败：{}：{error}", path.display()))?;
    let subscription = serde_json::from_str::<StoredRuleSubscription>(&content)
        .map_err(|error| format!("解析订阅规则缓存失败：{error}"))?;

    if is_valid_rule_subscription(&subscription) {
        Ok(Some(subscription))
    } else {
        Ok(None)
    }
}

pub fn write_rule_subscription(
    root: &Path,
    subscription: &StoredRuleSubscription,
) -> Result<(), String> {
    if !is_valid_rule_subscription(subscription) {
        return Err("订阅规则缓存无效，未写入。".to_string());
    }

    let path = app_storage_path(root, RULE_SUBSCRIPTION_FILE_PATH);
    ensure_parent_dir(&path)?;
    let content = serde_json::to_string_pretty(subscription)
        .map_err(|error| format!("序列化订阅规则缓存失败：{error}"))?;

    fs::write(&path, content)
        .map_err(|error| format!("写入订阅规则缓存失败：{}：{error}", path.display()))
}

pub fn clear_rule_subscription(root: &Path) -> Result<(), String> {
    let path = app_storage_path(root, RULE_SUBSCRIPTION_FILE_PATH);
    if !path.exists() {
        return Ok(());
    }

    fs::remove_file(&path)
        .map_err(|error| format!("删除订阅规则缓存失败：{}：{error}", path.display()))
}

fn app_storage_path(root: &Path, segments: &[&str]) -> PathBuf {
    segments
        .iter()
        .fold(root.to_path_buf(), |path, segment| path.join(segment))
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("无法定位父目录：{}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("创建应用数据目录失败：{}：{error}", parent.display()))
}

fn retention_cutoff() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    iso_timestamp(now.saturating_sub(LOG_RETENTION_SECS))
}

fn iso_timestamp(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let secs_of_day = epoch_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

// Timestamps come from JS toISOString(): always UTC, always the same
// fixed-width layout, so lexicographic ordering equals chronological ordering.
fn is_within_retention(time: &str, cutoff: &str) -> bool {
    if !is_iso_utc_timestamp(time) {
        return true;
    }
    time >= cutoff
}

fn is_iso_utc_timestamp(time: &str) -> bool {
    let bytes = time.as_bytes();
    if bytes.len() != 24 || bytes[23] != b'Z' {
        return false;
    }

    bytes.iter().enumerate().all(|(index, byte)| match index {
        4 | 7 => *byte == b'-',
        10 => *byte == b'T',
        13 | 16 => *byte == b':',
        19 => *byte == b'.',
        23 => true,
        _ => byte.is_ascii_digit(),
    })
}

fn is_valid_log_entry(entry: &AppLogEntry) -> bool {
    matches!(entry.kind.as_str(), "scan" | "cleanup" | "operation")
        && !entry.id.is_empty()
        && !entry.time.is_empty()
        && !entry.title.is_empty()
        && !entry.message.is_empty()
}

fn is_valid_rule_subscription(subscription: &StoredRuleSubscription) -> bool {
    !subscription.url.trim().is_empty()
        && !subscription.content.is_empty()
        && !subscription.checked_at.is_empty()
        && validate_rule_subscription_url(&subscription.url).is_ok()
        && validate_rule_subscription_bytes(subscription.content.as_bytes()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_logs_round_trip_as_jsonl() {
        let root = test_root("app-logs-round-trip");
        let logs = vec![
            AppLogEntry {
                id: "1".to_string(),
                kind: "operation".to_string(),
                time: iso_days_ago(1),
                title: "启动".to_string(),
                message: "应用启动".to_string(),
                detail: None,
            },
            AppLogEntry {
                id: "2".to_string(),
                kind: "scan".to_string(),
                time: iso_days_ago(2),
                title: "扫描".to_string(),
                message: "扫描完成".to_string(),
                detail: Some("后端：rules".to_string()),
            },
        ];

        write_app_logs(&root, &logs).expect("write logs");
        assert_eq!(read_app_logs(&root).expect("read logs"), logs);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_log_lines_are_ignored() {
        let root = test_root("malformed-log-lines");
        let path = app_storage_path(&root, LOG_FILE_PATH);
        ensure_parent_dir(&path).expect("create parent");
        fs::write(
            &path,
            "{\"id\":\"1\",\"kind\":\"operation\",\"time\":\"now\",\"title\":\"ok\",\"message\":\"ok\"}\nnot-json\n",
        )
        .expect("write malformed log file");

        let logs = read_app_logs(&root).expect("read logs");

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].id, "1");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn expired_logs_are_pruned_and_recent_kept() {
        let root = test_root("log-retention-window");
        let logs = vec![
            sample_log("fresh", &iso_days_ago(1)),
            sample_log("stale", &iso_days_ago(8)),
        ];

        write_app_logs(&root, &logs).expect("write logs");
        let stored = read_app_logs(&root).expect("read logs");

        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, "fresh");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn expired_logs_are_pruned_on_read() {
        let root = test_root("log-retention-on-read");
        let path = app_storage_path(&root, LOG_FILE_PATH);
        ensure_parent_dir(&path).expect("create parent");
        let mut content = String::new();
        for log in [
            sample_log("fresh", &iso_days_ago(2)),
            sample_log("stale", &iso_days_ago(30)),
        ] {
            content.push_str(&serde_json::to_string(&log).expect("serialize"));
            content.push('\n');
        }
        fs::write(&path, content).expect("write log file");

        let stored = read_app_logs(&root).expect("read logs");

        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, "fresh");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unparseable_timestamps_are_kept() {
        let root = test_root("log-retention-bad-time");
        let logs = vec![
            sample_log("garbage", "not-a-date"),
            sample_log("truncated", "2026-05-14"),
            sample_log("offset", "2026-05-14T00:00:00+02:00"),
        ];

        write_app_logs(&root, &logs).expect("write logs");
        let stored = read_app_logs(&root).expect("read logs");

        assert_eq!(stored, logs);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn entry_cap_keeps_newest_entries() {
        let root = test_root("log-retention-cap");
        let logs: Vec<AppLogEntry> = (0..MAX_APP_LOG_ENTRIES + 40)
            .map(|index| sample_log(&format!("entry-{index}"), &iso_days_ago(1)))
            .collect();

        write_app_logs(&root, &logs).expect("write logs");
        let stored = read_app_logs(&root).expect("read logs");

        assert_eq!(stored.len(), MAX_APP_LOG_ENTRIES);
        assert_eq!(stored[0].id, "entry-0");
        assert_eq!(
            stored[MAX_APP_LOG_ENTRIES - 1].id,
            format!("entry-{}", MAX_APP_LOG_ENTRIES - 1)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn iso_timestamp_handles_leap_and_year_boundaries() {
        assert_eq!(iso_timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_timestamp(1_709_164_800), "2024-02-29T00:00:00.000Z");
        assert_eq!(iso_timestamp(1_709_251_199), "2024-02-29T23:59:59.000Z");
        assert_eq!(iso_timestamp(1_709_251_200), "2024-03-01T00:00:00.000Z");
        assert_eq!(iso_timestamp(1_483_228_799), "2016-12-31T23:59:59.000Z");
        assert_eq!(iso_timestamp(1_483_228_800), "2017-01-01T00:00:00.000Z");
        assert_eq!(iso_timestamp(1_900_000_000), "2030-03-17T17:46:40.000Z");
        // 1900 was not a leap year; 2000 was.
        assert_eq!(iso_timestamp(951_782_400), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn retention_comparison_is_fail_open() {
        let cutoff = iso_days_ago(7);
        assert!(is_within_retention(&iso_days_ago(1), &cutoff));
        assert!(!is_within_retention(&iso_days_ago(9), &cutoff));
        assert!(is_within_retention("", &cutoff));
        assert!(is_within_retention("whenever", &cutoff));
    }

    #[test]
    fn rule_subscription_round_trip_and_clear() {
        let root = test_root("rule-subscription-round-trip");
        let subscription = StoredRuleSubscription {
            url: "https://example.com/rules.yaml".to_string(),
            content: "version: 1\nrules:\n  - id: sample\n".to_string(),
            checked_at: "2026-05-14T00:00:00.000Z".to_string(),
        };

        write_rule_subscription(&root, &subscription).expect("write subscription");
        assert_eq!(
            read_rule_subscription(&root).expect("read subscription"),
            Some(subscription)
        );

        clear_rule_subscription(&root).expect("clear subscription");
        assert_eq!(
            read_rule_subscription(&root).expect("read after clear"),
            None
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_rule_subscription_is_rejected() {
        let root = test_root("invalid-rule-subscription");
        let subscription = StoredRuleSubscription {
            url: "http://example.com/rules.yaml".to_string(),
            content: "version: 1".to_string(),
            checked_at: "2026-05-14T00:00:00.000Z".to_string(),
        };

        assert!(write_rule_subscription(&root, &subscription).is_err());
        assert_eq!(read_rule_subscription(&root).expect("read missing"), None);

        let _ = fs::remove_dir_all(root);
    }

    fn sample_log(id: &str, time: &str) -> AppLogEntry {
        AppLogEntry {
            id: id.to_string(),
            kind: "cleanup".to_string(),
            time: time.to_string(),
            title: "清理".to_string(),
            message: "清理完成".to_string(),
            detail: None,
        }
    }

    fn iso_days_ago(days: u64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        iso_timestamp(now - days * 86_400)
    }

    fn test_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("diskclean-{name}-{unique}"))
    }
}

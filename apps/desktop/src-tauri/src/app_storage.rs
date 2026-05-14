use cleaner_core::{validate_rule_subscription_bytes, validate_rule_subscription_url};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tauri::{AppHandle, Manager};

const MAX_APP_LOG_ENTRIES: usize = 500;
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

    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        if let Ok(entry) = serde_json::from_str::<AppLogEntry>(line) {
            if is_valid_log_entry(&entry) {
                logs.push(entry);
            }
        }
    }

    Ok(logs.into_iter().take(MAX_APP_LOG_ENTRIES).collect())
}

pub fn write_app_logs(root: &Path, logs: &[AppLogEntry]) -> Result<(), String> {
    let path = app_storage_path(root, LOG_FILE_PATH);
    ensure_parent_dir(&path)?;

    let mut content = String::new();
    for log in logs
        .iter()
        .filter(|log| is_valid_log_entry(log))
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
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn app_logs_round_trip_as_jsonl() {
        let root = test_root("app-logs-round-trip");
        let logs = vec![
            AppLogEntry {
                id: "1".to_string(),
                kind: "operation".to_string(),
                time: "2026-05-14T00:00:00.000Z".to_string(),
                title: "启动".to_string(),
                message: "应用启动".to_string(),
                detail: None,
            },
            AppLogEntry {
                id: "2".to_string(),
                kind: "scan".to_string(),
                time: "2026-05-14T00:00:01.000Z".to_string(),
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

    fn test_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("diskclean-{name}-{unique}"))
    }
}

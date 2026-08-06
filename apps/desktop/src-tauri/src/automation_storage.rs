use cleaner_core::{AutomationLimits, AutomationMode, AutomationOutcome, AutomationTrigger};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const AUTOMATION_CONFIG_SCHEMA_VERSION: u32 = 1;
const CONFIG_PATH: &[&str] = &["automation", "config-v1.json"];
const CONFIG_BACKUP_PATH: &[&str] = &["automation", "config-v1.backup.json"];
const REGISTRATION_PATH: &[&str] = &["automation", "runner-registration-v1.json"];
const REPORTS_PATH: &[&str] = &["automation", "reports"];
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_REPORT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REPORTS: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutomationCadence {
    Daily,
    Weekly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationConfig {
    pub schema_version: u32,
    pub config_id: Uuid,
    pub revision: u64,
    pub startup_enabled: bool,
    pub schedule_enabled: bool,
    pub mode: AutomationMode,
    pub cadence: AutomationCadence,
    pub local_time: String,
    pub weekday: Option<u8>,
    pub notifications_enabled: bool,
    pub limits: AutomationLimits,
    pub updated_at: String,
}

impl Default for AutomationConfig {
    fn default() -> Self {
        Self {
            schema_version: AUTOMATION_CONFIG_SCHEMA_VERSION,
            config_id: Uuid::new_v4(),
            revision: 0,
            startup_enabled: false,
            schedule_enabled: false,
            mode: AutomationMode::ScanOnly,
            cadence: AutomationCadence::Daily,
            local_time: "09:00".into(),
            weekday: None,
            notifications_enabled: true,
            limits: AutomationLimits::default(),
            updated_at: "1970-01-01T00:00:00.000Z".into(),
        }
    }
}

impl AutomationConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != AUTOMATION_CONFIG_SCHEMA_VERSION {
            return Err("unsupported automation config schema".into());
        }
        let bytes = self.local_time.as_bytes();
        if bytes.len() != 5
            || bytes[2] != b':'
            || !bytes[..2].iter().all(u8::is_ascii_digit)
            || !bytes[3..].iter().all(u8::is_ascii_digit)
        {
            return Err("自动化时间必须使用 HH:MM 格式。".into());
        }
        let hour = self.local_time[..2]
            .parse::<u8>()
            .map_err(|_| "自动化小时无效。")?;
        let minute = self.local_time[3..]
            .parse::<u8>()
            .map_err(|_| "自动化分钟无效。")?;
        if hour > 23 || minute > 59 {
            return Err("自动化时间超出范围。".into());
        }
        if self.cadence == AutomationCadence::Weekly && !matches!(self.weekday, Some(1..=7)) {
            return Err("每周任务必须选择星期。".into());
        }
        self.limits
            .validate()
            .map_err(|_| "自动化限制无效。".to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationRunnerRegistration {
    pub schema_version: u32,
    pub config_id: Uuid,
    pub config_revision: u64,
    pub config_digest: String,
    pub token_hash: String,
}

impl AutomationRunnerRegistration {
    pub fn create(config: &AutomationConfig, token: Uuid) -> Result<Self, String> {
        Ok(Self {
            schema_version: 1,
            config_id: config.config_id,
            config_revision: config.revision,
            config_digest: config_digest(config)?,
            token_hash: token_hash(token),
        })
    }

    pub fn validate_runner(
        &self,
        config: &AutomationConfig,
        config_id: Uuid,
        token: Uuid,
    ) -> Result<(), String> {
        if self.schema_version != 1
            || self.config_id != config_id
            || config.config_id != config_id
            || self.config_revision != config.revision
            || self.config_digest != config_digest(config)?
            || self.token_hash != token_hash(token)
        {
            return Err("自动化运行凭据或配置身份校验失败。".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutomationReportStatus {
    Started,
    Completed,
    Partial,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationRunReport {
    pub schema_version: u32,
    pub run_id: Uuid,
    pub status: AutomationReportStatus,
    pub trigger: AutomationTrigger,
    pub mode: AutomationMode,
    pub outcome: Option<AutomationOutcome>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub library_generation: Option<u64>,
    pub scanned_count: u32,
    pub eligible_count: u32,
    pub cleaned_count: u32,
    pub reclaimed_bytes: u64,
    pub skipped_count: u32,
    pub capped: bool,
    pub warnings: Vec<String>,
}

impl AutomationRunReport {
    pub fn started(trigger: AutomationTrigger, mode: AutomationMode, timestamp: String) -> Self {
        Self {
            schema_version: 1,
            run_id: Uuid::new_v4(),
            status: AutomationReportStatus::Started,
            trigger,
            mode,
            outcome: None,
            started_at: timestamp,
            finished_at: None,
            library_generation: None,
            scanned_count: 0,
            eligible_count: 0,
            cleaned_count: 0,
            reclaimed_bytes: 0,
            skipped_count: 0,
            capped: false,
            warnings: Vec::new(),
        }
    }
}

pub fn read_config(root: &Path) -> Result<AutomationConfig, String> {
    let path = storage_path(root, CONFIG_PATH);
    let backup = storage_path(root, CONFIG_BACKUP_PATH);
    if !path.exists() {
        return Ok(AutomationConfig::default());
    }
    match read_valid_config(&path) {
        Ok(config) => Ok(config),
        Err(primary_error) => match read_valid_config(&backup) {
            Ok(config) => {
                write_atomic_json(&path, &config, MAX_CONFIG_BYTES, Uuid::new_v4())?;
                Ok(config)
            }
            Err(backup_error) => Err(format!(
                "自动化配置及备份均未通过校验：{primary_error}; {backup_error}"
            )),
        },
    }
}

fn read_valid_config(path: &Path) -> Result<AutomationConfig, String> {
    let config: AutomationConfig = read_bounded_json(path, MAX_CONFIG_BYTES)?;
    config.validate()?;
    Ok(config)
}

pub fn save_config(
    root: &Path,
    expected_revision: u64,
    mut config: AutomationConfig,
) -> Result<AutomationConfig, String> {
    let current = read_config(root)?;
    if current.revision != expected_revision {
        return Err("自动化配置已更新，请刷新后重试。".into());
    }
    if expected_revision > 0 && config.config_id != current.config_id {
        return Err("自动化配置身份已变化，请刷新后重试。".into());
    }
    config.schema_version = AUTOMATION_CONFIG_SCHEMA_VERSION;
    config.revision = expected_revision.saturating_add(1);
    config.validate()?;
    if expected_revision > 0 {
        write_atomic_json(
            &storage_path(root, CONFIG_BACKUP_PATH),
            &current,
            MAX_CONFIG_BYTES,
            Uuid::new_v4(),
        )?;
    }
    write_atomic_json(
        &storage_path(root, CONFIG_PATH),
        &config,
        MAX_CONFIG_BYTES,
        Uuid::new_v4(),
    )?;
    read_config(root)
}

pub fn write_runner_registration(
    root: &Path,
    registration: &AutomationRunnerRegistration,
) -> Result<(), String> {
    write_atomic_json(
        &storage_path(root, REGISTRATION_PATH),
        registration,
        MAX_CONFIG_BYTES,
        Uuid::new_v4(),
    )
}

pub fn read_runner_registration(root: &Path) -> Result<AutomationRunnerRegistration, String> {
    read_bounded_json(&storage_path(root, REGISTRATION_PATH), MAX_CONFIG_BYTES)
}

pub fn remove_runner_registration(root: &Path) -> Result<(), String> {
    let path = storage_path(root, REGISTRATION_PATH);
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除自动化运行凭据失败：{error}")),
    }
}

pub fn write_report(root: &Path, report: &AutomationRunReport) -> Result<(), String> {
    let reports = storage_path(root, REPORTS_PATH);
    fs::create_dir_all(&reports).map_err(|error| format!("创建自动化报告目录失败：{error}"))?;
    let path = reports.join(format!("{}.json", report.run_id));
    write_atomic_json(&path, report, MAX_REPORT_BYTES, report.run_id)?;
    prune_reports(&reports)
}

pub fn list_reports(root: &Path) -> Result<Vec<AutomationRunReport>, String> {
    let reports = storage_path(root, REPORTS_PATH);
    if !reports.exists() {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    for entry in
        fs::read_dir(&reports).map_err(|error| format!("读取自动化报告目录失败：{error}"))?
    {
        let Ok(entry) = entry else { continue };
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if let Ok(report) =
            read_bounded_json::<AutomationRunReport>(&entry.path(), MAX_REPORT_BYTES)
        {
            output.push(report);
        }
    }
    output.sort_by(|left, right| right.started_at.cmp(&left.started_at));
    output.truncate(MAX_REPORTS);
    Ok(output)
}

fn prune_reports(reports: &Path) -> Result<(), String> {
    let mut files: Vec<_> = fs::read_dir(reports)
        .map_err(|error| format!("读取自动化报告目录失败：{error}"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .collect();
    files.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    let remove_count = files.len().saturating_sub(MAX_REPORTS);
    for entry in files.into_iter().take(remove_count) {
        let _ = fs::remove_file(entry.path());
    }
    Ok(())
}

fn digest_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn token_hash(token: Uuid) -> String {
    format!("sha256:{}", digest_hex(Sha256::digest(token.as_bytes())))
}

fn config_digest(config: &AutomationConfig) -> Result<String, String> {
    let bytes =
        serde_json::to_vec(config).map_err(|error| format!("计算自动化配置摘要失败：{error}"))?;
    Ok(format!("sha256:{}", digest_hex(Sha256::digest(bytes))))
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("读取文件元数据失败：{error}"))?;
    if metadata.len() > max_bytes {
        return Err("文件超过容量限制。".into());
    }
    let mut content = String::new();
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut content))
        .map_err(|error| format!("读取文件失败：{error}"))?;
    serde_json::from_str(&content).map_err(|error| format!("解析文件失败：{error}"))
}

fn write_atomic_json<T: Serialize>(
    path: &Path,
    value: &T,
    max_bytes: u64,
    mutation_id: Uuid,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "存储路径缺少父目录。".to_string())?;
    fs::create_dir_all(parent).map_err(|error| format!("创建存储目录失败：{error}"))?;
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("序列化存储文件失败：{error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err("存储文件超过容量限制。".into());
    }
    let temp = parent.join(format!(".automation-{mutation_id}.tmp"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| format!("创建存储临时文件失败：{error}"))?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|error| format!("写入存储临时文件失败：{error}"))?;
        file.flush()
            .map_err(|error| format!("刷新存储临时文件失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步存储临时文件失败：{error}"))?;
        drop(file);
        let _: serde_json::Value = read_bounded_json(&temp, max_bytes)?;
        atomic_replace(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(format!(
            "原子替换存储文件失败：{}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), String> {
    fs::rename(source, destination).map_err(|error| format!("原子替换存储文件失败：{error}"))
}

fn storage_path(root: &Path, segments: &[&str]) -> PathBuf {
    segments
        .iter()
        .fold(root.to_path_buf(), |path, segment| path.join(segment))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cleandeck-automation-{name}-{}", Uuid::new_v4()))
    }

    #[test]
    fn config_round_trip_and_stale_revision() {
        let root = root("config");
        let config = AutomationConfig {
            startup_enabled: true,
            updated_at: "2026-03-14T00:00:00Z".into(),
            ..AutomationConfig::default()
        };
        let saved = save_config(&root, 0, config).expect("save");
        assert_eq!(saved.revision, 1);
        assert!(save_config(&root, 0, saved).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_config_recovers_previous_verified_revision() {
        let root = root("config-recovery");
        let first = save_config(
            &root,
            0,
            AutomationConfig {
                updated_at: "2026-03-14T00:00:00Z".into(),
                ..AutomationConfig::default()
            },
        )
        .expect("first save");
        let second = save_config(
            &root,
            first.revision,
            AutomationConfig {
                schedule_enabled: true,
                updated_at: "2026-03-14T00:01:00Z".into(),
                ..first.clone()
            },
        )
        .expect("second save");
        assert_eq!(second.revision, 2);
        fs::write(storage_path(&root, CONFIG_PATH), b"{broken").expect("corrupt primary");
        let recovered = read_config(&root).expect("recover backup");
        assert_eq!(recovered.revision, 1);
        assert_eq!(read_config(&root).expect("restored primary").revision, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runner_registration_binds_token_and_config_revision() {
        let config = AutomationConfig {
            revision: 3,
            updated_at: "2026-03-14T00:00:00Z".into(),
            ..AutomationConfig::default()
        };
        let token = Uuid::new_v4();
        let registration =
            AutomationRunnerRegistration::create(&config, token).expect("registration");
        registration
            .validate_runner(&config, config.config_id, token)
            .expect("valid identity");
        assert!(registration
            .validate_runner(&config, config.config_id, Uuid::new_v4())
            .is_err());
        let changed = AutomationConfig {
            revision: 4,
            ..config.clone()
        };
        assert!(registration
            .validate_runner(&changed, changed.config_id, token)
            .is_err());
    }

    #[test]
    fn report_started_and_finalized_round_trip() {
        let root = root("report");
        let mut report = AutomationRunReport::started(
            AutomationTrigger::Manual,
            AutomationMode::ScanOnly,
            "2026-03-14T00:00:00Z".into(),
        );
        write_report(&root, &report).expect("started");
        report.status = AutomationReportStatus::Completed;
        report.outcome = Some(AutomationOutcome::ScanOnly);
        report.finished_at = Some("2026-03-14T00:01:00Z".into());
        write_report(&root, &report).expect("final");
        let listed = list_reports(&root).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, AutomationReportStatus::Completed);
        let _ = fs::remove_dir_all(root);
    }
}

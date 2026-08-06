use cleaner_core::{validate_library, RuleLibrarySnapshot};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const PRIMARY_PATH: &[&str] = &["rules", "library-v1.json"];
const BACKUP_PATH: &[&str] = &["rules", "library-v1.backup.json"];
const MAX_LIBRARY_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleLibraryLoadStatus {
    Ready,
    Empty,
    RecoveredFromBackup,
    CorruptNoRecovery,
    UnsupportedSchema,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleLibraryLoadResult {
    pub status: RuleLibraryLoadStatus,
    pub snapshot: Option<RuleLibrarySnapshot>,
    pub notice: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleLibraryRepositoryErrorCode {
    StaleGeneration,
    InvalidSnapshot,
    StorageWriteFailed,
    CorruptNoRecovery,
}

#[derive(Debug)]
pub struct RuleLibraryRepositoryError {
    pub code: RuleLibraryRepositoryErrorCode,
    pub message: String,
}

impl std::fmt::Display for RuleLibraryRepositoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

pub fn load_rule_library(root: &Path) -> Result<RuleLibraryLoadResult, String> {
    let primary = storage_path(root, PRIMARY_PATH);
    let backup = storage_path(root, BACKUP_PATH);
    if !primary.exists() && !backup.exists() {
        return Ok(RuleLibraryLoadResult {
            status: RuleLibraryLoadStatus::Empty,
            snapshot: None,
            notice: None,
        });
    }

    match read_valid_snapshot(&primary) {
        Ok(snapshot) => Ok(RuleLibraryLoadResult {
            status: RuleLibraryLoadStatus::Ready,
            snapshot: Some(snapshot),
            notice: None,
        }),
        Err(primary_error) => match read_valid_snapshot(&backup) {
            Ok(snapshot) => {
                isolate_corrupt_file(root, &primary, "primary")?;
                write_verified_file(&primary, &snapshot)?;
                Ok(RuleLibraryLoadResult {
                    status: RuleLibraryLoadStatus::RecoveredFromBackup,
                    snapshot: Some(snapshot),
                    notice: Some("规则库主文件损坏，已从已验证备份恢复。".into()),
                })
            }
            Err(backup_error) => {
                if primary.exists() {
                    isolate_corrupt_file(root, &primary, "primary")?;
                }
                if backup.exists() {
                    isolate_corrupt_file(root, &backup, "backup")?;
                }
                let unsupported =
                    primary_error.contains("unsupported") || backup_error.contains("unsupported");
                Ok(RuleLibraryLoadResult {
                    status: if unsupported {
                        RuleLibraryLoadStatus::UnsupportedSchema
                    } else {
                        RuleLibraryLoadStatus::CorruptNoRecovery
                    },
                    snapshot: None,
                    notice: Some(if unsupported {
                        "规则库由较新的应用版本创建。".into()
                    } else {
                        "规则库及备份均损坏，已停止加载本地活动规则。".into()
                    }),
                })
            }
        },
    }
}

pub fn commit_rule_library(
    root: &Path,
    expected_generation: u64,
    snapshot: &RuleLibrarySnapshot,
) -> Result<RuleLibrarySnapshot, RuleLibraryRepositoryError> {
    validate_library(snapshot).map_err(|error| {
        repository_error(
            RuleLibraryRepositoryErrorCode::InvalidSnapshot,
            format!("规则库快照校验失败：{error}"),
        )
    })?;
    if snapshot.generation != expected_generation.saturating_add(1) {
        return Err(repository_error(
            RuleLibraryRepositoryErrorCode::StaleGeneration,
            "规则库提交代数不连续。".into(),
        ));
    }

    let primary = storage_path(root, PRIMARY_PATH);
    let backup = storage_path(root, BACKUP_PATH);
    if primary.exists() {
        let committed = read_valid_snapshot(&primary).map_err(|_| {
            repository_error(
                RuleLibraryRepositoryErrorCode::CorruptNoRecovery,
                "当前规则库损坏，提交已停止。".into(),
            )
        })?;
        if committed.generation != expected_generation {
            return Err(repository_error(
                RuleLibraryRepositoryErrorCode::StaleGeneration,
                "规则库已被另一项操作更新，请刷新后重试。".into(),
            ));
        }
        write_verified_file(&backup, &committed).map_err(storage_error)?;
    } else if expected_generation != 0 {
        return Err(repository_error(
            RuleLibraryRepositoryErrorCode::StaleGeneration,
            "规则库代数已过期。".into(),
        ));
    }

    write_verified_file(&primary, snapshot).map_err(storage_error)?;
    let committed = read_valid_snapshot(&primary)
        .map_err(|error| storage_error(format!("提交后校验规则库失败：{error}")))?;
    if committed.generation != snapshot.generation
        || committed.last_mutation_id != snapshot.last_mutation_id
    {
        return Err(storage_error("提交后规则库身份不一致。".into()));
    }
    Ok(committed)
}

fn read_valid_snapshot(path: &Path) -> Result<RuleLibrarySnapshot, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("读取规则库元数据失败：{error}"))?;
    if metadata.len() > MAX_LIBRARY_FILE_BYTES {
        return Err("规则库超过容量限制".into());
    }
    let mut content = String::new();
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut content))
        .map_err(|error| format!("读取规则库失败：{error}"))?;
    let snapshot: RuleLibrarySnapshot =
        serde_json::from_str(&content).map_err(|error| format!("解析规则库失败：{error}"))?;
    validate_library(&snapshot).map_err(|error| {
        if matches!(error, cleaner_core::RuleLibraryError::UnsupportedSchema) {
            "unsupported schema".into()
        } else {
            format!("规则库完整性校验失败：{error}")
        }
    })?;
    Ok(snapshot)
}

fn write_verified_file(path: &Path, snapshot: &RuleLibrarySnapshot) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "规则库路径缺少父目录".to_string())?;
    fs::create_dir_all(parent).map_err(|error| format!("创建规则库目录失败：{error}"))?;
    let bytes = serde_json::to_vec_pretty(snapshot)
        .map_err(|error| format!("序列化规则库失败：{error}"))?;
    if bytes.len() as u64 > MAX_LIBRARY_FILE_BYTES {
        return Err("规则库超过容量限制".into());
    }
    let temp = parent.join(format!(".library-v1.{}.tmp", snapshot.last_mutation_id));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| format!("创建规则库临时文件失败：{error}"))?;
    let write_result = (|| {
        file.write_all(&bytes)
            .map_err(|error| format!("写入规则库临时文件失败：{error}"))?;
        file.flush()
            .map_err(|error| format!("刷新规则库临时文件失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步规则库临时文件失败：{error}"))?;
        drop(file);
        read_valid_snapshot(&temp)?;
        atomic_replace(&temp, path)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
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
            "原子替换规则库失败：{}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), String> {
    fs::rename(source, destination).map_err(|error| format!("原子替换规则库失败：{error}"))
}

fn isolate_corrupt_file(root: &Path, path: &Path, label: &str) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let corrupt_dir = root.join("rules").join("corrupt");
    fs::create_dir_all(&corrupt_dir).map_err(|error| format!("创建损坏证据目录失败：{error}"))?;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    fs::rename(path, corrupt_dir.join(format!("{suffix}-{label}.json")))
        .map_err(|error| format!("隔离损坏规则库失败：{error}"))
}

fn storage_path(root: &Path, segments: &[&str]) -> PathBuf {
    segments
        .iter()
        .fold(root.to_path_buf(), |path, segment| path.join(segment))
}

fn repository_error(
    code: RuleLibraryRepositoryErrorCode,
    message: String,
) -> RuleLibraryRepositoryError {
    RuleLibraryRepositoryError { code, message }
}

fn storage_error(message: String) -> RuleLibraryRepositoryError {
    repository_error(RuleLibraryRepositoryErrorCode::StorageWriteFailed, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleaner_core::{create_rule_draft, RuleMutationContext, RuleOrigin, RuleProvenance};
    use uuid::Uuid;

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cleandeck-rule-library-{name}-{}", Uuid::new_v4()))
    }

    fn snapshot() -> RuleLibrarySnapshot {
        let empty = RuleLibrarySnapshot::empty(
            "2026-03-14T00:00:00Z".into(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        create_rule_draft(
            &empty,
            "draft".into(),
            RuleOrigin::Manual,
            "version: 1\nrules: []\n",
            RuleProvenance::manual(),
            RuleMutationContext {
                expected_generation: 0,
                expected_head_revision_id: None,
                mutation_id: Uuid::new_v4(),
                actor_id: Uuid::new_v4(),
                timestamp: "2026-03-14T00:00:00Z".into(),
            },
        )
        .expect("draft")
    }

    #[test]
    fn commit_round_trip_and_stale_generation() {
        let root = root("round-trip");
        let snapshot = snapshot();
        let committed = commit_rule_library(&root, 0, &snapshot).expect("commit");
        assert_eq!(
            load_rule_library(&root).expect("load").snapshot,
            Some(committed.clone())
        );
        assert_eq!(
            commit_rule_library(&root, 0, &snapshot).unwrap_err().code,
            RuleLibraryRepositoryErrorCode::StaleGeneration
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_primary_recovers_from_backup() {
        let root = root("recovery");
        let first = snapshot();
        commit_rule_library(&root, 0, &first).expect("first commit");
        let mut second = first.clone();
        second.generation += 1;
        second.last_mutation_id = Uuid::new_v4();
        commit_rule_library(&root, 1, &second).expect("second commit");
        fs::write(storage_path(&root, PRIMARY_PATH), "truncated").expect("corrupt");
        let recovered = load_rule_library(&root).expect("recover");
        assert_eq!(recovered.status, RuleLibraryLoadStatus::RecoveredFromBackup);
        assert_eq!(recovered.snapshot.expect("snapshot").generation, 1);
        let _ = fs::remove_dir_all(root);
    }
}

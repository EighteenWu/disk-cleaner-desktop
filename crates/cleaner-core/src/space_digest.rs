use crate::InventoryDisposition;
use serde::{Deserialize, Serialize};
use std::env;

pub const SPACE_DIGEST_SCHEMA_VERSION: u16 = 1;
pub const MAX_SPACE_DIRECTORIES: usize = 150;
pub const SPACE_DIGEST_FETCH_LIMIT: usize = 400;
pub const MIN_SPACE_DIRECTORY_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpaceDirectory {
    pub path: String,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
    pub file_count: u64,
    pub protected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpaceDigest {
    pub schema_version: u16,
    pub directory_count: u32,
    pub truncated: bool,
    pub directories: Vec<SpaceDirectory>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSpaceDirectory {
    pub path: String,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
    pub file_count: u64,
    pub disposition: InventoryDisposition,
}

const GENERIC_NAMES: &[&str] = &[
    "users",
    "public",
    "appdata",
    "local",
    "locallow",
    "roaming",
    "documents",
    "desktop",
    "pictures",
    "videos",
    "music",
    "downloads",
    "default",
    "user data",
    "profiles",
    "program files",
    "program files (x86)",
    "programdata",
    "program files (arm)",
];

pub fn build_space_digest(raw: Vec<RawSpaceDirectory>) -> SpaceDigest {
    let fetched = raw.len();
    let mut selected = Vec::new();
    let mut listed: Vec<String> = Vec::new();
    for item in raw {
        if item.allocated_bytes < MIN_SPACE_DIRECTORY_BYTES {
            continue;
        }
        if is_generic_parent(&item.path) {
            continue;
        }
        let templated = template_user_path(&item.path);
        let protected = is_protected_directory(&item.path, item.disposition);
        if listed.iter().any(|parent| is_child_path(&templated, parent)) {
            continue;
        }
        listed.push(templated.clone());
        selected.push(SpaceDirectory {
            path: templated,
            allocated_bytes: item.allocated_bytes,
            logical_bytes: item.logical_bytes,
            file_count: item.file_count,
            protected,
        });
        if selected.len() == MAX_SPACE_DIRECTORIES {
            break;
        }
    }
    SpaceDigest {
        schema_version: SPACE_DIGEST_SCHEMA_VERSION,
        directory_count: selected.len() as u32,
        truncated: fetched >= SPACE_DIGEST_FETCH_LIMIT || selected.len() == MAX_SPACE_DIRECTORIES,
        directories: selected,
    }
}

pub fn template_user_path(path: &str) -> String {
    let normalized = path.replace('/', "\\");
    let mut best: Option<(String, String)> = None;
    for (variable, value) in env_replacements() {
        if value.is_empty() {
            continue;
        }
        if prefix_eq_ignore_ascii(&normalized, &value)
            && best.as_ref().is_none_or(|(_, current)| value.len() > current.len())
        {
            best = Some((variable, value));
        }
    }
    let Some((variable, value)) = best else {
        return normalized;
    };
    format!("{variable}{}", &normalized[value.len()..])
}

fn env_replacements() -> Vec<(String, String)> {
    let mut items = Vec::new();
    push_env(&mut items, "%TEMP%", "TEMP");
    push_env(&mut items, "%TMP%", "TMP");
    push_env(&mut items, "%LOCALAPPDATA%", "LOCALAPPDATA");
    push_env(&mut items, "%APPDATA%", "APPDATA");
    push_env(&mut items, "%USERPROFILE%", "USERPROFILE");
    push_env(&mut items, "%PROGRAMDATA%", "ProgramData");
    push_env(&mut items, "%PROGRAMFILES%", "ProgramFiles");
    push_env(&mut items, "%PROGRAMFILES(X86)%", "ProgramFiles(x86)");
    push_env(&mut items, "%WINDIR%", "WINDIR");
    push_env(&mut items, "%SYSTEMROOT%", "SystemRoot");
    push_env(&mut items, "%PUBLIC%", "PUBLIC");
    items
}

fn push_env(items: &mut Vec<(String, String)>, variable: &str, name: &str) {
    if let Ok(value) = env::var(name) {
        if !value.is_empty() {
            items.push((variable.to_string(), value.replace('/', "\\")));
        }
    }
}

fn is_generic_parent(path: &str) -> bool {
    let trimmed = path.trim_end_matches(['\\', '/']);
    if trimmed.len() <= 3 {
        return true;
    }
    let name = trimmed
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if GENERIC_NAMES.contains(&name.as_str()) {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.ends_with("\\windows") || lower.eq_ignore_ascii_case("c:\\windows")
}

fn is_protected_directory(path: &str, disposition: InventoryDisposition) -> bool {
    if disposition == InventoryDisposition::Blocked {
        return true;
    }
    let lower = path.replace('/', "\\").to_ascii_lowercase();
    lower.contains("\\windows\\winsxs")
        || lower.contains("\\windows\\system32")
        || lower.contains("\\windows\\syswow64")
        || lower.contains("\\windowsapps\\")
        || lower.contains("\\documents")
        || lower.contains("\\desktop")
}

fn is_child_path(path: &str, parent: &str) -> bool {
    let path = path.replace('/', "\\").to_ascii_lowercase();
    let parent = parent.replace('/', "\\").to_ascii_lowercase();
    let parent = parent.trim_end_matches('\\');
    path.starts_with(&(parent.to_string() + "\\"))
}

fn prefix_eq_ignore_ascii(path: &str, prefix: &str) -> bool {
    path.len() >= prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(path: &str, bytes: u64) -> RawSpaceDirectory {
        RawSpaceDirectory {
            path: path.to_string(),
            allocated_bytes: bytes,
            logical_bytes: bytes,
            file_count: 10,
            disposition: InventoryDisposition::Normal,
        }
    }

    #[test]
    fn digest_skips_generic_parents_and_collapses_children() {
        let local = env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\Users\alice\AppData\Local".into());
        let cache = format!(r"{local}\npm-cache");
        let nested = format!(r"{local}\npm-cache\_npx\pkg");
        let users = r"C:\Users";
        let digest = build_space_digest(vec![
            raw(users, 80 * 1024 * 1024 * 1024),
            raw(&format!(r"{local}"), 40 * 1024 * 1024 * 1024),
            raw(&cache, 900 * 1024 * 1024),
            raw(&nested, 400 * 1024 * 1024),
            raw(r"C:\tiny\cache", 1024),
        ]);
        assert_eq!(digest.directories.len(), 1);
        assert!(digest.directories[0].path.to_ascii_uppercase().contains("%LOCALAPPDATA%"));
        assert!(digest.directories[0].path.to_ascii_lowercase().contains("npm-cache"));
        assert!(!digest.directories.iter().any(|item| item.path.to_ascii_lowercase().contains("_npx")));
    }

    #[test]
    fn template_replaces_longest_env_prefix() {
        let local = env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\Users\alice\AppData\Local".into());
        let path = format!(r"{local}\Temp\foo");
        let templated = template_user_path(&path);
        assert!(
            templated.to_ascii_uppercase().starts_with("%LOCALAPPDATA%")
                || templated.to_ascii_uppercase().starts_with("%TEMP%"),
            "{templated}"
        );
        assert!(!templated.to_ascii_lowercase().contains("users\\alice\\appdata\\local\\temp\\foo"));
    }

    #[test]
    fn protected_windows_and_documents_are_flagged() {
        let digest = build_space_digest(vec![
            raw(r"C:\Windows\WinSxS\manifests", 12 * 1024 * 1024 * 1024),
            raw(r"C:\Users\alice\Documents\Work", 9 * 1024 * 1024),
        ]);
        assert!(digest.directories.iter().all(|item| item.protected));
    }
}

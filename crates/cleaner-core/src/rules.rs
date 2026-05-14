use crate::RiskLevel;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const MAX_RULE_SUBSCRIPTION_BYTES: usize = 2 * 1024 * 1024;
const MAX_WINAPP2_IMPORT_WARNINGS: usize = 12;

const MANDATORY_RULE_EXCLUDES: &[&str] = &[
    "**\\*token*",
    "**\\*session*",
    "**\\*wallet*",
    "**\\*keychain*",
    "**\\*credential*",
    "**\\*backup*",
    "**\\*recovery*",
    "**\\*autosave*",
    "**\\*profile*",
    "**\\IndexedDB\\**",
    "**\\Local Storage\\**",
    "**\\Session Storage\\**",
    "**\\Sessions\\**",
    "**\\databases\\**",
    "**\\blob_storage\\**",
    "**\\Network\\**",
    "**\\Cookies*",
    "**\\Login Data*",
    "**\\History*",
    "**\\Preferences",
    "**\\Local State",
    "**\\*.db",
    "**\\*.sqlite",
    "**\\*.sqlite3",
    "**\\*.vscdb",
];

const SUPPORTED_ENV_VARS: &[&str] = &[
    "%localappdata%",
    "%locallowappdata%",
    "%appdata%",
    "%userprofile%",
    "%documents%",
    "%temp%",
    "%tmp%",
    "%programdata%",
    "%commonappdata%",
    "%allusersprofile%",
    "%public%",
    "%systemdrive%",
    "%programfiles%",
    "%programfiles(x86)%",
    "%programw6432%",
    "%commonprogramfiles%",
    "%commonprogramfiles(x86)%",
    "%commonprogramw6432%",
    "%windir%",
    "%systemroot%",
];

const BLOCKED_PATH_MARKERS: &[&str] = &[
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programfiles\\",
    "\\windowsapps\\",
    "\\wpsystem\\",
    "\\config.msi\\",
    "\\users\\public\\documents\\",
    "\\documents\\",
    "\\desktop\\",
    "\\pictures\\",
    "\\videos\\",
    "\\music\\",
    "\\source\\",
    "\\repos\\",
    "\\projects\\",
    "\\cleandeck\\",
    "\\resources\\app\\",
    "\\resources\\app.asar",
    "\\app.asar.unpacked\\",
    "\\app.asar",
    "\\node_modules\\",
    "\\.venv\\",
    "\\site-packages\\",
    "\\vendor\\",
    "\\.cargo\\registry\\src\\",
];

const BLOCKED_STATE_MARKERS: &[&str] = &[
    "token",
    "session",
    "wallet",
    "keychain",
    "credential",
    "indexeddb",
    "local storage",
    "session storage",
    "sessions",
    "databases",
    "blob_storage",
    "\\network\\",
    "cookies",
    "login data",
    "history",
    "preferences",
    "local state",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".vscdb",
];

const REVIEW_STATE_MARKERS: &[&str] = &["backup", "recovery", "autosave", "profile"];

const REVIEW_DEPENDENCY_CACHE_MARKERS: &[&str] = &[
    "\\npm-cache",
    "\\npm\\cache",
    "\\.pnpm-store",
    "\\pnpm\\store",
    "\\yarn\\cache",
    "\\pip\\cache",
    "\\uv\\cache",
    "\\node-gyp\\cache",
    "\\.gradle\\caches",
    "\\gradle\\caches",
    "\\pub\\cache",
    "\\.pub-cache",
    "\\nuget\\packages",
    "\\nuget\\cache",
    "\\composer\\cache",
    "\\.cargo\\registry\\cache",
    "\\.cache\\codex-runtimes",
    "\\.cache\\chrome-devtools-mcp",
    "\\.cache\\hyperframes",
];

const WINAPP2_HIGH_RISK_MARKERS: &[&str] = &[
    "autofill",
    "bookmark",
    "cookie",
    "history",
    "indexeddb",
    "login data",
    "local state",
    "local storage",
    "password",
    "preferences",
    "session",
    "sync data",
    "top sites",
    "visited links",
    "wallet",
    "web data",
];

const WINAPP2_CAUTION_MARKERS: &[&str] = &[
    "telemetry",
    "diagnostic",
    "diagnostics",
    "trace",
    "traces",
    "mru",
    "recent",
    "jumplist",
    "jump list",
    "usage",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleSourceKind {
    BuiltIn,
    User,
    Subscription,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleLevel {
    Recommended,
    Cautious,
    ReviewRequired,
}

impl RuleLevel {
    fn risk_level(&self) -> RiskLevel {
        match self {
            Self::Recommended => RiskLevel::SafeRecommended,
            Self::Cautious => RiskLevel::CautiousRecommended,
            Self::ReviewRequired => RiskLevel::ReviewRequired,
        }
    }

    fn default_keep_days(&self) -> u16 {
        match self {
            Self::Recommended => 3,
            Self::Cautious | Self::ReviewRequired => 7,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleCleanupMethod {
    Contents,
    Files,
    Recycle,
    Manual,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompiledCleanupRule {
    pub id: String,
    pub name: String,
    pub app: String,
    pub category: String,
    pub level: RuleLevel,
    pub risk_level: RiskLevel,
    pub default_selected: bool,
    pub requires_default_confirmation: bool,
    pub paths: Vec<String>,
    pub clean: RuleCleanupMethod,
    pub keep_days: u16,
    pub close: Vec<String>,
    pub exclude: Vec<String>,
    pub mandatory_exclude: Vec<String>,
    pub note: String,
    pub source: RuleSourceKind,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleValidationIssue {
    pub rule_id: Option<String>,
    pub field: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleValidationReport {
    pub valid: bool,
    pub rule_count: usize,
    pub errors: Vec<RuleValidationIssue>,
    pub warnings: Vec<RuleValidationIssue>,
}

impl RuleValidationReport {
    fn valid(rule_count: usize, warnings: Vec<RuleValidationIssue>) -> Self {
        Self {
            valid: true,
            rule_count,
            errors: Vec::new(),
            warnings,
        }
    }

    fn invalid(errors: Vec<RuleValidationIssue>, warnings: Vec<RuleValidationIssue>) -> Self {
        Self {
            valid: false,
            rule_count: 0,
            errors,
            warnings,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleCompilation {
    pub rules: Vec<CompiledCleanupRule>,
    pub report: RuleValidationReport,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuleDocument {
    version: Option<u16>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    rules: Option<Vec<RawCleanupRule>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCleanupRule {
    id: Option<String>,
    name: Option<String>,
    app: Option<String>,
    category: Option<String>,
    level: Option<String>,
    #[serde(rename = "default", default)]
    default_selected: Option<bool>,
    paths: Option<Vec<String>>,
    clean: Option<String>,
    keep_days: Option<u16>,
    #[serde(default)]
    close: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    note: Option<String>,
}

pub fn mandatory_rule_excludes() -> &'static [&'static str] {
    MANDATORY_RULE_EXCLUDES
}

pub fn compile_cleanup_rules_yaml(content: &str, source: RuleSourceKind) -> RuleCompilation {
    let document = match serde_yaml::from_str::<RawRuleDocument>(content) {
        Ok(document) => document,
        Err(error) => {
            return RuleCompilation {
                rules: Vec::new(),
                report: RuleValidationReport::invalid(
                    vec![issue(None, "yaml", format!("YAML 格式无效：{error}"))],
                    Vec::new(),
                ),
            };
        }
    };

    compile_rule_document(document, source)
}

pub fn import_winapp2_ini(content: &str, source: RuleSourceKind) -> RuleCompilation {
    let import = parse_winapp2_ini(content);

    if import.entries.is_empty() {
        return RuleCompilation {
            rules: Vec::new(),
            report: RuleValidationReport::invalid(
                vec![issue(
                    None,
                    "winapp2",
                    "未找到 Winapp2 条目，请确认内容包含 [Entry *] 段落",
                )],
                Vec::new(),
            ),
        };
    }

    let mut stats = Winapp2ImportStats {
        entries: import.entries.len(),
        ..Winapp2ImportStats::default()
    };
    let mut raw_rules = Vec::new();
    let mut seen_ids = HashMap::<String, usize>::new();

    for entry in import.entries {
        let raw_rule = import_winapp2_entry(&entry, &mut stats, &mut seen_ids);
        if let Some(raw_rule) = raw_rule {
            raw_rules.push(raw_rule);
        }
    }

    let warnings = winapp2_import_warnings(&stats);

    if raw_rules.is_empty() {
        return RuleCompilation {
            rules: Vec::new(),
            report: RuleValidationReport::invalid(
                vec![issue(
                    None,
                    "winapp2",
                    "没有可导入的 Winapp2 FileKey；请确认内容包含有效的 FileKey 规则（纯 RegKey 条目不会导入）",
                )],
                warnings,
            ),
        };
    }

    let mut compilation = compile_rule_document(
        RawRuleDocument {
            version: Some(1),
            name: Some("Imported Winapp2 rules".to_string()),
            publisher: Some("Winapp2 adapter".to_string()),
            updated_at: None,
            rules: Some(raw_rules),
        },
        source,
    );

    compilation.report.warnings.splice(0..0, warnings);
    compilation
}

pub fn validate_rule_subscription_url(url: &str) -> Result<(), RuleValidationIssue> {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();

    if trimmed.is_empty() {
        return Err(issue(None, "url", "订阅链接不能为空"));
    }

    if trimmed.chars().any(char::is_whitespace) {
        return Err(issue(None, "url", "订阅链接不能包含空白字符"));
    }

    if !lower.starts_with("https://") {
        return Err(issue(None, "url", "订阅链接只支持 https://"));
    }

    let without_scheme = &trimmed["https://".len()..];
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();

    if host.is_empty() || host.contains('@') {
        return Err(issue(None, "url", "订阅链接 host 无效"));
    }

    let path = without_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if path.ends_with(".txt") {
        return Err(issue(
            None,
            "url",
            "MVP 不支持 .txt 订阅，请使用 .yaml、.yml 或 .ini",
        ));
    }

    if !(path.ends_with(".yaml") || path.ends_with(".yml") || path.ends_with(".ini")) {
        return Err(issue(
            None,
            "url",
            "订阅链接必须指向 .yaml、.yml 或 .ini 文件",
        ));
    }

    Ok(())
}

pub fn validate_rule_subscription_bytes(content: &[u8]) -> Result<(), RuleValidationIssue> {
    if content.len() > MAX_RULE_SUBSCRIPTION_BYTES {
        return Err(issue(None, "content", "订阅规则文件不能超过 2 MB"));
    }

    if std::str::from_utf8(content).is_err() {
        return Err(issue(None, "content", "订阅规则文件必须使用 UTF-8 编码"));
    }

    Ok(())
}

#[derive(Default)]
struct Winapp2Document {
    entries: Vec<Winapp2Entry>,
}

#[derive(Default)]
struct Winapp2Entry {
    title: String,
    values: Vec<(String, String)>,
}

#[derive(Default)]
struct Winapp2ImportStats {
    entries: usize,
    imported_rules: usize,
    skipped_registry_only_entries: usize,
    skipped_entries_without_supported_file_key: usize,
    skipped_complex_file_keys: usize,
}

struct Winapp2FileKey {
    base_path: String,
    patterns: Vec<String>,
    recursive: bool,
}

fn parse_winapp2_ini(content: &str) -> Winapp2Document {
    let mut document = Winapp2Document::default();
    let mut current: Option<Winapp2Entry> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim().trim_start_matches('\u{feff}');

        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if let Some(entry) = current.take() {
                document.entries.push(entry);
            }

            current = Some(Winapp2Entry {
                title: line[1..line.len() - 1].trim().to_string(),
                values: Vec::new(),
            });
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        if let Some(entry) = current.as_mut() {
            entry
                .values
                .push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    if let Some(entry) = current {
        document.entries.push(entry);
    }

    document
}

fn import_winapp2_entry(
    entry: &Winapp2Entry,
    stats: &mut Winapp2ImportStats,
    seen_ids: &mut HashMap<String, usize>,
) -> Option<RawCleanupRule> {
    let file_values = entry_values_with_prefix(entry, "FileKey");
    let reg_values = entry_values_with_prefix(entry, "RegKey");

    if file_values.is_empty() {
        if !reg_values.is_empty() {
            stats.skipped_registry_only_entries += 1;
        } else {
            stats.skipped_entries_without_supported_file_key += 1;
        }
        return None;
    }

    let mut paths = Vec::new();
    let mut uses_recursive_file_key = false;

    for value in file_values {
        match parse_winapp2_file_key(value) {
            Ok(file_key) => {
                uses_recursive_file_key |= file_key.recursive;
                for pattern in &file_key.patterns {
                    let combined = if file_key.recursive {
                        join_winapp2_path(&file_key.base_path, &format!("**\\{pattern}"))
                    } else {
                        join_winapp2_path(&file_key.base_path, pattern)
                    };
                    paths.push(combined);
                }
            }
            Err(reason) => stats.count_skip_reason(reason),
        }
    }

    paths = dedupe_string_list(paths);
    if paths.is_empty() {
        stats.skipped_entries_without_supported_file_key += 1;
        return None;
    }

    let title = clean_winapp2_title(&entry.title);
    let id = unique_winapp2_rule_id(&title, seen_ids);
    let category = winapp2_category(entry);
    let level = winapp2_level_for_entry(entry, &paths);
    stats.imported_rules += 1;

    Some(RawCleanupRule {
        id: Some(id),
        name: Some(format!("{title} (Winapp2)")),
        app: Some(winapp2_app_name(&title)),
        category: Some(category),
        level: Some(level.to_string()),
        default_selected: Some(level == "推荐清理"),
        paths: Some(paths),
        clean: Some("files".to_string()),
        keep_days: Some(0),
        close: Vec::new(),
        exclude: import_winapp2_exclude_keys(entry),
        note: Some(if uses_recursive_file_key {
            "从 Winapp2 FileKey 导入；包含 RECURSE/REMOVESELF 的条目会递归展开匹配路径。"
                .to_string()
        } else {
            "从 Winapp2 FileKey 导入。".to_string()
        }),
    })
}

fn entry_values_with_prefix<'a>(entry: &'a Winapp2Entry, prefix: &str) -> Vec<&'a str> {
    entry
        .values
        .iter()
        .filter(|(key, _)| key_matches_numbered_prefix(key, prefix))
        .map(|(_, value)| value.as_str())
        .collect()
}

fn key_matches_numbered_prefix(key: &str, prefix: &str) -> bool {
    let normalized = key.trim();
    normalized.eq_ignore_ascii_case(prefix)
        || normalized
            .strip_prefix(prefix)
            .map(|suffix| suffix.chars().all(|character| character.is_ascii_digit()))
            .unwrap_or(false)
}

fn parse_winapp2_file_key(value: &str) -> Result<Winapp2FileKey, Winapp2SkipReason> {
    let parts = value.split('|').map(str::trim).collect::<Vec<_>>();
    if parts.len() < 2 {
        return Err(Winapp2SkipReason::Complex);
    }

    let path = parts[0];
    let file_parameters = parts[1];
    let flags = parts[2..]
        .iter()
        .map(|flag| flag.to_ascii_uppercase())
        .collect::<Vec<_>>();

    let recursive = flags
        .iter()
        .any(|flag| flag == "RECURSE" || flag == "REMOVESELF");
    let patterns = file_parameters
        .split(';')
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .map(|pattern| pattern.replace('/', "\\"))
        .collect::<Vec<_>>();
    if patterns.is_empty() {
        return Err(Winapp2SkipReason::Complex);
    }

    Ok(Winapp2FileKey {
        base_path: normalize_winapp2_env_path(path),
        patterns,
        recursive,
    })
}

fn import_winapp2_exclude_keys(entry: &Winapp2Entry) -> Vec<String> {
    let mut patterns = Vec::new();

    for value in entry_values_with_prefix(entry, "ExcludeKey") {
        let parts = value.split('|').map(str::trim).collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }

        let flag = parts[0].trim().to_ascii_uppercase();
        let directory = parts.get(1).copied().unwrap_or_default();
        if directory.is_empty() {
            continue;
        }

        let directory = normalize_winapp2_env_path(directory);

        match flag.as_str() {
            "FILE" | "PATH" => {
                let file_parameters = parts.get(2).copied().unwrap_or_default();
                if file_parameters.is_empty() {
                    continue;
                }

                for file_parameter in file_parameters
                    .split(';')
                    .map(str::trim)
                    .filter(|parameter| !parameter.is_empty())
                {
                    patterns.push(join_winapp2_path(
                        &directory,
                        &file_parameter.replace('/', "\\"),
                    ));
                }
            }
            "REG" => {}
            _ => {}
        }
    }

    patterns
}

#[derive(Clone, Copy)]
enum Winapp2SkipReason {
    Complex,
}

impl Winapp2ImportStats {
    fn count_skip_reason(&mut self, reason: Winapp2SkipReason) {
        match reason {
            Winapp2SkipReason::Complex => self.skipped_complex_file_keys += 1,
        }
    }
}

fn winapp2_import_warnings(stats: &Winapp2ImportStats) -> Vec<RuleValidationIssue> {
    let mut warnings = vec![
        issue(
            None,
            "winapp2",
            format!(
                "Winapp2 导入统计：解析 {} 个条目，导入 {} 条规则；仅“推荐清理”默认勾选。",
                stats.entries, stats.imported_rules
            ),
        ),
        issue(
            None,
            "winapp2",
            "当前导入 Winapp2 FileKey=path|fileParameters；RegKey 暂不导入。",
        ),
    ];

    let skipped = [
        (stats.skipped_registry_only_entries, "跳过纯注册表条目"),
        (
            stats.skipped_entries_without_supported_file_key,
            "跳过无可导入 FileKey 的条目",
        ),
        (stats.skipped_complex_file_keys, "跳过无法解析的 FileKey"),
    ];

    for (count, label) in skipped {
        if count == 0 || warnings.len() >= MAX_WINAPP2_IMPORT_WARNINGS {
            continue;
        }

        warnings.push(issue(None, "winapp2", format!("{label}：{count}")));
    }

    warnings
}

fn winapp2_level_for_entry(entry: &Winapp2Entry, paths: &[String]) -> &'static str {
    if winapp2_entry_matches_markers(entry, paths, WINAPP2_HIGH_RISK_MARKERS)
        || winapp2_entry_matches_markers(entry, paths, BLOCKED_STATE_MARKERS)
        || winapp2_entry_matches_markers(entry, paths, REVIEW_STATE_MARKERS)
    {
        return "需要确认";
    }

    if winapp2_entry_matches_markers(entry, paths, WINAPP2_CAUTION_MARKERS) {
        return "谨慎清理";
    }

    "推荐清理"
}

fn winapp2_entry_matches_markers(entry: &Winapp2Entry, paths: &[String], markers: &[&str]) -> bool {
    let title = clean_winapp2_title(&entry.title).to_ascii_lowercase();
    if markers.iter().any(|marker| title.contains(marker)) {
        return true;
    }

    paths.iter().any(|path| {
        let normalized = normalize_rule_path_for_match(path);
        markers
            .iter()
            .any(|marker| normalized.contains(&marker.to_ascii_lowercase()))
    })
}

fn normalize_winapp2_env_path(path: &str) -> String {
    let mut normalized = path.trim().replace('/', "\\");

    for variable in SUPPORTED_ENV_VARS {
        let upper = variable.to_ascii_uppercase();
        if normalized.to_ascii_lowercase().starts_with(variable) {
            normalized.replace_range(0..variable.len(), &upper);
            break;
        }
    }

    normalized
}

fn join_winapp2_path(base: &str, tail: &str) -> String {
    let base = base.trim().trim_end_matches(['\\', '/']);
    let tail = tail.trim().trim_start_matches(['\\', '/']);
    if tail.is_empty() {
        base.to_string()
    } else {
        format!("{base}\\{tail}")
    }
}

fn clean_winapp2_title(title: &str) -> String {
    title
        .trim()
        .trim_end_matches('*')
        .trim()
        .trim_end_matches('-')
        .trim()
        .to_string()
}

fn winapp2_app_name(title: &str) -> String {
    title
        .split(" - ")
        .next()
        .unwrap_or(title)
        .trim()
        .trim_end_matches(" Caches")
        .trim_end_matches(" Cache")
        .trim_end_matches(" Logs")
        .trim_end_matches(" Log")
        .trim_end_matches(" Telemetry")
        .trim()
        .to_string()
}

fn winapp2_category(entry: &Winapp2Entry) -> String {
    let section = entry_value(entry, "Section").unwrap_or_default();
    if !section.is_empty() {
        if section.contains("Browser") {
            return "浏览器缓存".to_string();
        }
        if section.contains("Games") {
            return "游戏缓存".to_string();
        }
        return section.to_string();
    }

    match entry_value(entry, "LangSecRef").as_deref() {
        Some("3022") => "浏览器缓存".to_string(),
        Some("3023") => "媒体缓存".to_string(),
        Some("3024") => "应用缓存".to_string(),
        Some("3025") => "Windows 缓存".to_string(),
        _ => "应用缓存".to_string(),
    }
}

fn entry_value(entry: &Winapp2Entry, key: &str) -> Option<String> {
    entry
        .values
        .iter()
        .find(|(entry_key, _)| entry_key.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.trim().to_string())
}

fn unique_winapp2_rule_id(title: &str, seen_ids: &mut HashMap<String, usize>) -> String {
    let slug = slugify_winapp2_title(title);
    let count = seen_ids.entry(slug.clone()).or_insert(0);
    *count += 1;

    if *count == 1 {
        format!("winapp2.{slug}")
    } else {
        format!("winapp2.{slug}.{}", count)
    }
}

fn slugify_winapp2_title(title: &str) -> String {
    let mut slug = String::new();
    let mut previous_separator = false;

    for character in title.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            previous_separator = false;
        } else if !previous_separator {
            slug.push('.');
            previous_separator = true;
        }
    }

    let slug = slug.trim_matches('.').to_string();
    if slug.is_empty() {
        format!("entry.{:016x}", stable_hash(title))
    } else {
        slug
    }
}

fn dedupe_string_list(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.to_ascii_lowercase()))
        .collect()
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;

    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }

    hash
}

fn compile_rule_document(document: RawRuleDocument, source: RuleSourceKind) -> RuleCompilation {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let _has_source_metadata =
        document.name.is_some() || document.publisher.is_some() || document.updated_at.is_some();

    if document.version != Some(1) {
        errors.push(issue(None, "version", "规则文件 version 必须为 1"));
    }

    let Some(raw_rules) = document.rules else {
        errors.push(issue(None, "rules", "规则文件必须包含 rules 列表"));
        return RuleCompilation {
            rules: Vec::new(),
            report: RuleValidationReport::invalid(errors, warnings),
        };
    };

    if raw_rules.is_empty() {
        errors.push(issue(None, "rules", "rules 至少需要包含一条规则"));
    }

    let mut ids = HashSet::new();
    let mut compiled = Vec::new();

    for raw_rule in raw_rules {
        match compile_raw_rule(raw_rule, &source, &mut ids) {
            Ok((rule, mut rule_warnings)) => {
                warnings.append(&mut rule_warnings);
                compiled.push(rule);
            }
            Err(mut rule_errors) => errors.append(&mut rule_errors),
        }
    }

    if errors.is_empty() {
        RuleCompilation {
            report: RuleValidationReport::valid(compiled.len(), warnings),
            rules: compiled,
        }
    } else {
        RuleCompilation {
            rules: Vec::new(),
            report: RuleValidationReport::invalid(errors, warnings),
        }
    }
}

fn compile_raw_rule(
    raw_rule: RawCleanupRule,
    source: &RuleSourceKind,
    ids: &mut HashSet<String>,
) -> Result<(CompiledCleanupRule, Vec<RuleValidationIssue>), Vec<RuleValidationIssue>> {
    let rule_id = raw_rule.id.clone();
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let id = required_string(rule_id.as_deref(), "id", &rule_id, &mut errors);
    let name = required_string(raw_rule.name.as_deref(), "name", &rule_id, &mut errors);
    let app = required_string(raw_rule.app.as_deref(), "app", &rule_id, &mut errors);
    let category = required_string(
        raw_rule.category.as_deref(),
        "category",
        &rule_id,
        &mut errors,
    );
    let note = required_string(raw_rule.note.as_deref(), "note", &rule_id, &mut errors);

    let level = raw_rule
        .level
        .as_deref()
        .and_then(parse_rule_level)
        .unwrap_or_else(|| {
            errors.push(issue(
                rule_id.clone(),
                "level",
                "level 必须是 推荐清理 / 谨慎清理 / 需要确认",
            ));
            RuleLevel::ReviewRequired
        });

    let clean = raw_rule
        .clean
        .as_deref()
        .map(parse_cleanup_method)
        .unwrap_or(Ok(RuleCleanupMethod::Manual))
        .unwrap_or_else(|()| {
            errors.push(issue(
                rule_id.clone(),
                "clean",
                "clean 必须是 contents / files / recycle / manual",
            ));
            RuleCleanupMethod::Manual
        });

    let paths = raw_rule.paths.unwrap_or_default();
    if paths.is_empty() {
        errors.push(issue(
            rule_id.clone(),
            "paths",
            "paths 至少需要包含一个路径",
        ));
    }

    for path in &paths {
        validate_rule_path(path, &rule_id, &mut errors);
    }

    if let Some(id) = &id {
        if !is_valid_rule_id(id) {
            errors.push(issue(
                rule_id.clone(),
                "id",
                "id 只能包含字母、数字、点、横线和下划线",
            ));
        } else if !ids.insert(id.to_string()) {
            errors.push(issue(rule_id.clone(), "id", "id 在规则文件内重复"));
        }
    }

    let keep_days = raw_rule
        .keep_days
        .unwrap_or_else(|| level.default_keep_days());

    if keep_days > 365 {
        errors.push(issue(
            rule_id.clone(),
            "keep_days",
            "keep_days 不能超过 365",
        ));
    }

    for process in &raw_rule.close {
        if process.trim().is_empty() || !process.to_ascii_lowercase().ends_with(".exe") {
            errors.push(issue(
                rule_id.clone(),
                "close",
                "close 只能包含 Windows 进程名，例如 chrome.exe",
            ));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let id = id.expect("validated id");
    let mut risk_level = level.risk_level();

    for path in &paths {
        let normalized = normalize_rule_path_for_match(path);
        let safety = evaluate_rule_path_safety(&normalized, source);
        match safety {
            PathSafety::Allowed => {}
            PathSafety::Review(reason) => {
                risk_level = downgrade_to_review(risk_level);
                warnings.push(issue(Some(id.clone()), "paths", reason));
            }
        }
    }

    let mut default_selected =
        raw_rule.default_selected.unwrap_or(false) && risk_level == RiskLevel::SafeRecommended;
    let requires_default_confirmation = false;

    if risk_level != RiskLevel::SafeRecommended {
        default_selected = false;
    }

    let exclude = normalize_string_list(raw_rule.exclude);
    let close = normalize_string_list(raw_rule.close);

    Ok((
        CompiledCleanupRule {
            id,
            name: name.expect("validated name"),
            app: app.expect("validated app"),
            category: category.expect("validated category"),
            level,
            risk_level,
            default_selected,
            requires_default_confirmation,
            paths: normalize_string_list(paths),
            clean,
            keep_days,
            close,
            exclude,
            mandatory_exclude: Vec::new(),
            note: note.expect("validated note"),
            source: source.clone(),
            warnings: warnings
                .iter()
                .map(|warning| warning.message.clone())
                .collect(),
        },
        warnings,
    ))
}

fn required_string(
    value: Option<&str>,
    field: &'static str,
    rule_id: &Option<String>,
    errors: &mut Vec<RuleValidationIssue>,
) -> Option<String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        errors.push(issue(rule_id.clone(), field, format!("{field} 不能为空")));
        return None;
    };

    Some(value.to_string())
}

fn parse_rule_level(value: &str) -> Option<RuleLevel> {
    match value.trim() {
        "推荐清理" | "recommended" => Some(RuleLevel::Recommended),
        "谨慎清理" | "cautious" => Some(RuleLevel::Cautious),
        "需要确认" | "review" | "reviewRequired" => Some(RuleLevel::ReviewRequired),
        _ => None,
    }
}

fn parse_cleanup_method(value: &str) -> Result<RuleCleanupMethod, ()> {
    match value.trim() {
        "contents" => Ok(RuleCleanupMethod::Contents),
        "files" => Ok(RuleCleanupMethod::Files),
        "recycle" => Ok(RuleCleanupMethod::Recycle),
        "manual" => Ok(RuleCleanupMethod::Manual),
        _ => Err(()),
    }
}

fn validate_rule_path(path: &str, rule_id: &Option<String>, errors: &mut Vec<RuleValidationIssue>) {
    let trimmed = path.trim();

    if trimmed.is_empty() {
        errors.push(issue(rule_id.clone(), "paths", "路径不能为空"));
        return;
    }

    if trimmed.contains("..") {
        errors.push(issue(rule_id.clone(), "paths", "路径不能包含 .."));
    }

    let normalized = normalize_rule_path_for_match(trimmed);
    let starts_with_supported_env = SUPPORTED_ENV_VARS
        .iter()
        .any(|variable| normalized.starts_with(variable));
    let is_drive_absolute = normalized.len() >= 3
        && normalized.as_bytes()[1] == b':'
        && normalized.as_bytes()[2] == b'\\';

    if !starts_with_supported_env && !is_drive_absolute {
        errors.push(issue(
            rule_id.clone(),
            "paths",
            "路径必须是绝对路径，或以支持的环境变量开头",
        ));
    }

    if is_drive_root(&normalized) {
        errors.push(issue(
            rule_id.clone(),
            "paths",
            "不能把盘符根目录作为清理目标",
        ));
    }
}

fn normalize_rule_path_for_match(path: &str) -> String {
    let mut normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();

    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }

    normalized
}

fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn is_valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

fn is_drive_root(normalized_path: &str) -> bool {
    normalized_path.len() == 3
        && normalized_path.as_bytes()[1] == b':'
        && normalized_path.as_bytes()[2] == b'\\'
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PathSafety {
    Allowed,
    Review(String),
}

fn evaluate_rule_path_safety(normalized_path: &str, source: &RuleSourceKind) -> PathSafety {
    if matches!(source, RuleSourceKind::BuiltIn) {
        return PathSafety::Allowed;
    }

    if normalized_path == "%userprofile%"
        || normalized_path == "%appdata%"
        || normalized_path == "%localappdata%"
        || normalized_path == "%locallowappdata%"
        || normalized_path == "%documents%"
        || normalized_path == "%programdata%"
        || normalized_path == "%windir%"
        || normalized_path == "%systemroot%"
    {
        return PathSafety::Review(
            "规则目标过宽，建议谨慎评估后再清理用户或系统根目录".to_string(),
        );
    }

    if normalized_path.starts_with("%documents%\\") {
        return PathSafety::Review("命中用户文档目录，建议谨慎评估后再清理".to_string());
    }

    if normalized_path.starts_with("%windir%")
        && !normalized_path.starts_with("%windir%\\temp")
        && !normalized_path.starts_with("%windir%\\softwaredistribution\\download")
    {
        return PathSafety::Review("命中 Windows 系统目录，建议谨慎评估后再清理".to_string());
    }

    if BLOCKED_PATH_MARKERS
        .iter()
        .any(|marker| normalized_path.contains(marker))
    {
        return PathSafety::Review(
            "命中用户目录、程序目录或项目目录特征，建议谨慎评估后再清理".to_string(),
        );
    }

    if BLOCKED_STATE_MARKERS
        .iter()
        .any(|marker| normalized_path.contains(marker))
    {
        return PathSafety::Review(
            "命中账号、会话、数据库或本地状态特征，建议谨慎评估后再清理".to_string(),
        );
    }

    if REVIEW_STATE_MARKERS
        .iter()
        .any(|marker| normalized_path.contains(marker))
    {
        return PathSafety::Review("命中备份、恢复或 profile 特征，需要用户逐项确认".to_string());
    }

    if REVIEW_DEPENDENCY_CACHE_MARKERS
        .iter()
        .any(|marker| normalized_path.contains(marker))
    {
        return PathSafety::Review(
            "命中开发依赖缓存，删除后可能需要重新下载依赖，需要用户确认".to_string(),
        );
    }

    PathSafety::Allowed
}

fn downgrade_to_review(risk_level: RiskLevel) -> RiskLevel {
    match risk_level {
        RiskLevel::SafeRecommended => RiskLevel::CautiousRecommended,
        RiskLevel::CautiousRecommended => RiskLevel::ReviewRequired,
        RiskLevel::ReviewRequired | RiskLevel::Blocked => risk_level,
    }
}

fn issue(
    rule_id: Option<String>,
    field: impl Into<String>,
    message: impl Into<String>,
) -> RuleValidationIssue {
    RuleValidationIssue {
        rule_id,
        field: field.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npm_rule_yaml() -> &'static str {
        r#"
version: 1
rules:
  - id: npm.cache
    name: npm 缓存
    app: npm
    category: 开发工具缓存
    level: 推荐清理
    default: true
    paths:
      - "%LOCALAPPDATA%\\npm-cache"
    clean: contents
    keep_days: 3
    close:
      - node.exe
      - npm.exe
    exclude:
      - "**\\*.db"
    note: npm 包下载缓存，删除后可重新下载。
"#
    }

    #[test]
    fn valid_yaml_compiles_to_typed_rule() {
        let compilation = compile_cleanup_rules_yaml(npm_rule_yaml(), RuleSourceKind::User);

        assert!(compilation.report.valid);
        assert_eq!(compilation.report.rule_count, 1);
        assert_eq!(compilation.rules.len(), 1);

        let rule = &compilation.rules[0];
        assert_eq!(rule.id, "npm.cache");
        assert_eq!(rule.clean, RuleCleanupMethod::Contents);
        assert_eq!(rule.risk_level, RiskLevel::CautiousRecommended);
        assert!(!rule.default_selected);
        assert!(rule.mandatory_exclude.is_empty());
    }

    #[test]
    fn bundled_default_rules_compile_as_conservative_user_rules() {
        let compilation = compile_cleanup_rules_yaml(
            include_str!("../../../rules/default-rules.yaml"),
            RuleSourceKind::User,
        );

        assert!(compilation.report.valid);
        assert!(compilation.report.rule_count >= 3);
        assert!(compilation.rules.iter().any(|rule| {
            rule.category == "开发依赖缓存"
                && rule.risk_level == RiskLevel::ReviewRequired
                && !rule.default_selected
        }));
    }

    #[test]
    fn invalid_yaml_reports_actionable_error() {
        let compilation = compile_cleanup_rules_yaml("version: [", RuleSourceKind::User);

        assert!(!compilation.report.valid);
        assert_eq!(compilation.report.errors[0].field, "yaml");
        assert!(compilation.report.errors[0]
            .message
            .contains("YAML 格式无效"));
    }

    #[test]
    fn custom_rule_with_state_database_is_downgraded_and_not_default_selected() {
        let yaml = r#"
version: 1
rules:
  - id: app.session
    name: 会话数据库
    app: Example
    category: 应用缓存
    level: 推荐清理
    default: true
    paths:
      - "%APPDATA%\\Example\\session.db"
    clean: contents
    note: 测试规则。
"#;

        let compilation = compile_cleanup_rules_yaml(yaml, RuleSourceKind::User);

        assert!(compilation.report.valid);
        let rule = &compilation.rules[0];
        assert_eq!(rule.risk_level, RiskLevel::CautiousRecommended);
        assert_eq!(rule.clean, RuleCleanupMethod::Contents);
        assert!(!rule.default_selected);
        assert!(compilation
            .report
            .warnings
            .iter()
            .any(|warning| warning.message.contains("会话")));
    }

    #[test]
    fn subscription_default_selection_respects_risk_level() {
        let compilation = compile_cleanup_rules_yaml(npm_rule_yaml(), RuleSourceKind::Subscription);

        assert!(compilation.report.valid);
        let rule = &compilation.rules[0];
        assert!(!rule.default_selected);
        assert!(!rule.requires_default_confirmation);
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let yaml = r#"
version: 1
rules:
  - id: app.cache
    name: A
    app: App
    category: 应用缓存
    level: 需要确认
    paths:
      - "%LOCALAPPDATA%\\App\\Cache"
    note: A
  - id: app.cache
    name: B
    app: App
    category: 应用缓存
    level: 需要确认
    paths:
      - "%LOCALAPPDATA%\\App\\Cache2"
    note: B
"#;

        let compilation = compile_cleanup_rules_yaml(yaml, RuleSourceKind::User);

        assert!(!compilation.report.valid);
        assert!(compilation
            .report
            .errors
            .iter()
            .any(|error| error.message.contains("重复")));
    }

    #[test]
    fn subscription_url_policy_accepts_https_yaml() {
        assert!(validate_rule_subscription_url(
            "https://raw.githubusercontent.com/example/cleandeck/main/windows.yaml"
        )
        .is_ok());
        assert!(validate_rule_subscription_url(
            "https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini"
        )
        .is_ok());
    }

    #[test]
    fn subscription_url_policy_rejects_txt_and_non_https() {
        assert!(validate_rule_subscription_url("http://example.com/rules.yaml").is_err());

        let txt_error = validate_rule_subscription_url("https://example.com/rules.txt")
            .expect_err("txt subscriptions should be rejected");
        assert!(txt_error.message.contains(".txt"));
    }

    #[test]
    fn subscription_bytes_policy_rejects_oversized_or_non_utf8_content() {
        let oversized = vec![b'a'; MAX_RULE_SUBSCRIPTION_BYTES + 1];
        assert!(validate_rule_subscription_bytes(&oversized).is_err());

        assert!(validate_rule_subscription_bytes(&[0xff, 0xfe, 0xfd]).is_err());
    }

    #[test]
    fn winapp2_import_converts_file_keys_and_applies_level_defaults() {
        let ini = r#"
[Example Cache *]
LangSecRef=3024
DetectFile=%LocalAppData%\Example
FileKey1=%LocalAppData%\Example\Cache|*|RECURSE
FileKey2=%LocalAppData%\Example\Logs|*.log|RECURSE
RegKey1=HKCU\Software\Example|Recent

[Registry Only *]
LangSecRef=3024
RegKey1=HKCU\Software\RegistryOnly
"#;

        let compilation = import_winapp2_ini(ini, RuleSourceKind::Subscription);

        assert!(compilation.report.valid);
        assert_eq!(compilation.rules.len(), 1);
        let rule = &compilation.rules[0];
        assert_eq!(rule.id, "winapp2.example.cache");
        assert_eq!(rule.level, RuleLevel::Recommended);
        assert_eq!(rule.risk_level, RiskLevel::SafeRecommended);
        assert_eq!(rule.clean, RuleCleanupMethod::Files);
        assert!(rule.default_selected);
        assert_eq!(rule.keep_days, 0);
        assert_eq!(
            rule.paths,
            vec![
                "%LOCALAPPDATA%\\Example\\Cache\\**\\*",
                "%LOCALAPPDATA%\\Example\\Logs\\**\\*.log"
            ]
        );
        assert_eq!(rule.source, RuleSourceKind::Subscription);
        assert!(compilation
            .report
            .warnings
            .iter()
            .any(|warning| warning.message.contains("跳过纯注册表条目")));
    }

    #[test]
    fn winapp2_import_marks_browser_state_as_review_required() {
        let ini = r#"
[Google Chrome Data *]
Section=Google Chrome Web Browser
DetectFile=%LocalAppData%\Google\Chrome*
FileKey1=%LocalAppData%\Google\Chrome\User Data\Default\Cache|*|RECURSE
FileKey2=%LocalAppData%\Google\Chrome\User Data\Default\History|*
FileKey3=%ProgramFiles%\Google\Chrome|*|RECURSE
"#;

        let compilation = import_winapp2_ini(ini, RuleSourceKind::Subscription);

        assert!(compilation.report.valid);
        assert_eq!(compilation.rules.len(), 1);
        let rule = &compilation.rules[0];
        assert_eq!(rule.category, "浏览器缓存");
        assert_eq!(rule.level, RuleLevel::ReviewRequired);
        assert!(!rule.default_selected);
        assert_eq!(
            rule.paths,
            vec![
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache\\**\\*",
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History\\*",
                "%PROGRAMFILES%\\Google\\Chrome\\**\\*"
            ]
        );
    }

    #[test]
    fn winapp2_import_normalizes_common_pseudo_env_vars() {
        let ini = r#"
[Google Earth *]
LangSecRef=3021
FileKey1=%LocalLowAppData%\Google\GoogleEarth\unified_cache_leveldb_*|*|REMOVESELF

[Hob *]
Section=Games
FileKey1=%Documents%\My Games\runic games\hob|ogre.log;microcodecache*
"#;

        let compilation = import_winapp2_ini(ini, RuleSourceKind::Subscription);

        assert!(
            compilation.report.valid,
            "Winapp2 pseudo variables should compile: {:?}",
            compilation.report.errors
        );
        assert_eq!(compilation.rules.len(), 2);

        let google_earth = compilation
            .rules
            .iter()
            .find(|rule| rule.id == "winapp2.google.earth")
            .expect("Google Earth rule should be imported");
        assert_eq!(
            google_earth.paths,
            vec!["%LOCALLOWAPPDATA%\\Google\\GoogleEarth\\unified_cache_leveldb_*\\**\\*"]
        );

        let hob = compilation
            .rules
            .iter()
            .find(|rule| rule.id == "winapp2.hob")
            .expect("Hob rule should be imported");
        assert_eq!(hob.category, "游戏缓存");
        assert_eq!(hob.risk_level, RiskLevel::ReviewRequired);
        assert!(!hob.default_selected);
        assert_eq!(
            hob.paths,
            vec![
                "%DOCUMENTS%\\My Games\\runic games\\hob\\ogre.log",
                "%DOCUMENTS%\\My Games\\runic games\\hob\\microcodecache*"
            ]
        );
    }

    #[test]
    fn unsafe_root_paths_are_rejected() {
        let yaml = r#"
version: 1
rules:
  - id: root.clean
    name: Root
    app: System
    category: 危险
    level: 推荐清理
    paths:
      - "C:\\"
    note: dangerous
"#;

        let compilation = compile_cleanup_rules_yaml(yaml, RuleSourceKind::User);

        assert!(!compilation.report.valid);
        assert!(compilation
            .report
            .errors
            .iter()
            .any(|error| error.message.contains("盘符根目录")));
    }

    #[test]
    fn custom_rules_cannot_target_application_runtime_payloads() {
        let yaml = r#"
version: 1
rules:
  - id: vscode.runtime
    name: VS Code Runtime
    app: VS Code
    category: 构建产物
    level: 推荐清理
    paths:
      - "D:\\cantinstall\\Microsoft VS Code\\8b640eef5a\\resources\\app\\out"
    note: must be blocked
"#;

        let compilation = compile_cleanup_rules_yaml(yaml, RuleSourceKind::User);

        assert!(compilation.report.valid);
        let rule = &compilation.rules[0];
        assert_eq!(rule.risk_level, RiskLevel::CautiousRecommended);
        assert_eq!(rule.clean, RuleCleanupMethod::Manual);
    }
}

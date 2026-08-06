#[cfg(test)]
use crate::rules::RuleCleanupMethod;
use crate::rules::{
    compile_cleanup_rules_yaml, mandatory_rule_excludes, RuleCompilation, RuleLevel, RuleSourceKind,
};
use crate::{CleanupCandidate, RiskLevel, ScanSnapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub const AI_SUMMARY_SCHEMA_VERSION: u16 = 1;
pub const AI_REDACTION_VERSION: u16 = 1;
const MAX_BUCKETS: usize = 64;
const MAX_SUMMARY_BYTES: usize = 16 * 1024;
const MAX_RULES_PER_TIER: usize = 32;
const MAX_PATHS_PER_RULE: usize = 16;
const MAX_EXCLUDES_PER_RULE: usize = 32;
const MAX_EXPLANATIONS_PER_RULE: usize = 8;
const MAX_AI_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_TEXT_CHARS: usize = 512;
const MAX_PATH_CHARS: usize = 1024;

/// A deterministic, path-free representation of a completed local scan.
/// It is the only scan payload allowed to cross the AI provider boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedScanSummary {
    pub schema_version: u16,
    pub redaction_version: u16,
    pub scan_mode: String,
    pub buckets: Vec<RedactedScanBucket>,
    pub risk_signals: Vec<String>,
    pub omitted_count: u32,
    pub truncated: bool,
    pub summary_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedScanBucket {
    pub source_kind: String,
    pub risk_level: String,
    pub category: String,
    pub candidate_count: u32,
    pub total_bytes: u64,
    pub size_band: String,
}

impl RedactedScanSummary {
    /// Revalidates the public IPC value before it reaches an HTTP adapter.
    /// A typed summary alone is not a privacy boundary because IPC callers can
    /// otherwise place arbitrary text in its string fields.
    pub fn validate_for_provider(&self) -> Result<(), String> {
        if self.schema_version != AI_SUMMARY_SCHEMA_VERSION
            || self.redaction_version != AI_REDACTION_VERSION
            || self.buckets.len() > MAX_BUCKETS
            || serde_json::to_vec(self).map_or(true, |bytes| bytes.len() > MAX_SUMMARY_BYTES)
        {
            return Err("脱敏摘要版本或大小无效。".to_string());
        }
        if !matches!(
            self.scan_mode.as_str(),
            "mft" | "usn" | "walk" | "hybrid" | "other"
        ) || self.truncated != (self.omitted_count > 0)
        {
            return Err("脱敏摘要状态无效。".to_string());
        }

        let mut bucket_keys = HashSet::new();
        for bucket in &self.buckets {
            if !matches!(
                bucket.source_kind.as_str(),
                "browser"
                    | "windows"
                    | "installedApp"
                    | "storeApp"
                    | "game"
                    | "devTool"
                    | "project"
                    | "unknown"
            ) || !matches!(
                bucket.risk_level.as_str(),
                "safeRecommended" | "cautiousRecommended" | "reviewRequired" | "blocked"
            ) || !matches!(
                bucket.category.as_str(),
                "browser"
                    | "windows"
                    | "application"
                    | "developer"
                    | "temporary"
                    | "cache"
                    | "other"
            ) || bucket.candidate_count == 0
                || bucket.size_band != size_band(bucket.total_bytes)
                || !bucket_keys.insert((
                    bucket.source_kind.as_str(),
                    bucket.risk_level.as_str(),
                    bucket.category.as_str(),
                ))
            {
                return Err("脱敏摘要聚合桶无效。".to_string());
            }
        }

        let mut signals = HashSet::new();
        if self.risk_signals.iter().any(|signal| {
            !matches!(
                signal.as_str(),
                "credentials" | "sessions" | "databases" | "sourceTree" | "locallyBlocked"
            ) || !signals.insert(signal.as_str())
        }) {
            return Err("脱敏摘要风险标记无效。".to_string());
        }
        let mut hash_input = self.clone();
        hash_input.summary_hash.clear();
        if self.summary_hash != stable_hash(&hash_input) {
            return Err("脱敏摘要哈希无效。".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiRuleTier {
    Light,
    Medium,
    Heavy,
}

/// How a draft was (or should be) generated relative to light/medium/heavy tiers.
///
/// `SingleTier` is the serde default so older IPC payloads that only carried
/// `targetTier` keep deserializing as single-tier drafts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AiGenerationMode {
    AllTiers,
    #[default]
    SingleTier,
}

impl AiRuleTier {
    pub fn rule_level(self) -> RuleLevel {
        match self {
            Self::Light => RuleLevel::Recommended,
            Self::Medium => RuleLevel::Cautious,
            Self::Heavy => RuleLevel::ReviewRequired,
        }
    }

    fn yaml_level(self) -> &'static str {
        match self {
            Self::Light => "推荐清理",
            Self::Medium => "谨慎清理",
            Self::Heavy => "需要确认",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiRuleCleanMethod {
    Contents,
    Files,
    Recycle,
    Manual,
}

impl AiRuleCleanMethod {
    fn yaml_value(self) -> &'static str {
        match self {
            Self::Contents => "contents",
            Self::Files => "files",
            Self::Recycle => "recycle",
            Self::Manual => "manual",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiGeneratedRuleSet {
    #[serde(rename = "schemaVersion", alias = "schema_version")]
    pub schema_version: u16,
    pub rules: Vec<AiGeneratedRule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiGeneratedRule {
    pub id: String,
    pub tier: AiRuleTier,
    pub name: String,
    pub app: String,
    pub category: String,
    pub paths: Vec<String>,
    pub clean: AiRuleCleanMethod,
    #[serde(rename = "keepDays", alias = "keep_days")]
    pub keep_days: u16,
    pub exclude: Vec<String>,
    pub note: String,
    pub evidence: Vec<String>,
    pub cautions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiRuleDraft {
    pub schema_version: u16,
    pub redaction_version: u16,
    pub id: String,
    pub revision: u32,
    pub validation_revision: Option<u32>,
    pub summary_hash: String,
    #[serde(default)]
    pub generation_mode: AiGenerationMode,
    /// Required for `singleTier`; must be `None` for `allTiers`.
    #[serde(default)]
    pub target_tier: Option<AiRuleTier>,
    pub provider_profile_id: String,
    pub model: String,
    pub generated_at: String,
    pub rules: AiGeneratedRuleSet,
    pub compilation: Option<RuleCompilation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedRuleEnvelope {
    pub schema_version: u16,
    pub redaction_version: u16,
    pub draft_id: String,
    pub revision: u32,
    pub summary_hash: String,
    #[serde(default)]
    pub generation_mode: AiGenerationMode,
    #[serde(default)]
    pub target_tier: Option<AiRuleTier>,
    pub provider_profile_id: String,
    pub model: String,
    pub generated_at: String,
    pub rules: AiGeneratedRuleSet,
    pub compilation: RuleCompilation,
}

impl AiGeneratedRuleSet {
    pub fn parse(json: &str) -> Result<Self, String> {
        if json.len() > MAX_AI_RESPONSE_BYTES {
            return Err("AI 返回内容超过 256 KB 上限。".to_string());
        }
        let mut parsed: Self = serde_json::from_str(json)
            .map_err(|error| format!("AI 返回的规则格式无效：{error}"))?;
        for rule in &mut parsed.rules {
            merge_mandatory_excludes(&mut rule.exclude);
        }
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != AI_SUMMARY_SCHEMA_VERSION {
            return Err("AI 返回的规则版本不受支持。".to_string());
        }
        if self.rules.is_empty() {
            return Err("AI 未返回任何规则。".to_string());
        }
        if self.rules.len() > MAX_RULES_PER_TIER * 3 {
            return Err("AI 返回的规则数量超过上限。".to_string());
        }

        let mut ids = HashSet::new();
        let mut per_tier = [0usize; 3];
        for rule in &self.rules {
            validate_generated_rule(rule)?;
            if !ids.insert(rule.id.as_str()) {
                return Err(format!("AI 返回了重复规则 ID：{}", rule.id));
            }
            let slot = match rule.tier {
                AiRuleTier::Light => 0,
                AiRuleTier::Medium => 1,
                AiRuleTier::Heavy => 2,
            };
            per_tier[slot] += 1;
            if per_tier[slot] > MAX_RULES_PER_TIER {
                return Err("AI 返回的单档规则数量超过上限。".to_string());
            }
        }
        Ok(())
    }

    /// Rebuilds a user-source YAML document and sends it through the existing compiler.
    /// The compiler owns path validation, mandatory exclusions and risk escalation.
    pub fn compile(&self) -> Result<RuleCompilation, String> {
        let yaml = self.to_cleanup_rules_yaml()?;
        Ok(compile_cleanup_rules_yaml(&yaml, RuleSourceKind::User))
    }

    pub fn to_cleanup_rules_yaml(&self) -> Result<String, String> {
        self.validate()?;
        let document = AiYamlDocument {
            version: 1,
            rules: self.rules.iter().map(AiYamlRule::from).collect(),
        };
        serde_yaml::to_string(&document).map_err(|error| format!("AI 规则规范化失败：{error}"))
    }
}

fn merge_mandatory_excludes(excludes: &mut Vec<String>) {
    let mut seen = excludes
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    for pattern in mandatory_rule_excludes() {
        if seen.insert(pattern.to_ascii_lowercase()) {
            excludes.push((*pattern).to_string());
        }
    }
}

impl AiRuleDraft {
    pub fn new(
        id: String,
        summary_hash: String,
        generation_mode: AiGenerationMode,
        target_tier: Option<AiRuleTier>,
        provider_profile_id: String,
        model: String,
        generated_at: String,
        rules: AiGeneratedRuleSet,
    ) -> Result<Self, String> {
        rules.validate()?;
        validate_metadata("draft id", &id)?;
        validate_metadata("summary hash", &summary_hash)?;
        validate_metadata("provider profile id", &provider_profile_id)?;
        validate_metadata("model", &model)?;
        validate_metadata("generated at", &generated_at)?;
        validate_summary_hash(&summary_hash)?;
        let target_tier = normalize_generation_mode(generation_mode, target_tier)?;
        validate_rules_for_mode(generation_mode, target_tier, &rules)?;
        Ok(Self {
            schema_version: AI_SUMMARY_SCHEMA_VERSION,
            redaction_version: AI_REDACTION_VERSION,
            id,
            revision: 1,
            validation_revision: None,
            summary_hash,
            generation_mode,
            target_tier,
            provider_profile_id,
            model,
            generated_at,
            rules,
            compilation: None,
        })
    }

    pub fn replace_rules(&mut self, rules: AiGeneratedRuleSet) -> Result<(), String> {
        rules.validate()?;
        validate_rules_for_mode(self.generation_mode, self.target_tier, &rules)?;
        self.rules = rules;
        self.revision = self.revision.saturating_add(1);
        self.validation_revision = None;
        self.compilation = None;
        Ok(())
    }

    pub fn validate_current_revision(&mut self) -> Result<&RuleCompilation, String> {
        let compilation = self.rules.compile()?;
        self.validation_revision = Some(self.revision);
        self.compilation = Some(compilation);
        Ok(self
            .compilation
            .as_ref()
            .expect("compilation just assigned"))
    }

    pub fn approve(
        &self,
        expected_revision: u32,
        expected_summary_hash: &str,
    ) -> Result<ApprovedRuleEnvelope, String> {
        self.validate_contract()?;
        if expected_revision != self.revision {
            return Err("草稿版本已变化，请重新检查后再批准。".to_string());
        }
        if expected_summary_hash != self.summary_hash {
            return Err("扫描摘要已变化，请重新生成规则草稿。".to_string());
        }
        if self.validation_revision != Some(self.revision) {
            return Err("草稿尚未通过当前版本校验。".to_string());
        }
        let compilation = self
            .compilation
            .as_ref()
            .filter(|value| value.report.valid)
            .ok_or_else(|| "草稿未通过本地规则安全校验。".to_string())?;
        let current_compilation = self.rules.compile()?;
        if &current_compilation != compilation {
            return Err("草稿编译结果已失效，请重新校验后再批准。".to_string());
        }
        Ok(ApprovedRuleEnvelope {
            schema_version: self.schema_version,
            redaction_version: self.redaction_version,
            draft_id: self.id.clone(),
            revision: self.revision,
            summary_hash: self.summary_hash.clone(),
            generation_mode: self.generation_mode,
            target_tier: self.target_tier,
            provider_profile_id: self.provider_profile_id.clone(),
            model: self.model.clone(),
            generated_at: self.generated_at.clone(),
            rules: self.rules.clone(),
            compilation: current_compilation,
        })
    }

    pub fn validate_contract(&self) -> Result<(), String> {
        if self.schema_version != AI_SUMMARY_SCHEMA_VERSION
            || self.redaction_version != AI_REDACTION_VERSION
        {
            return Err("AI 草稿版本不受支持。".to_string());
        }
        validate_metadata("draft id", &self.id)?;
        validate_summary_hash(&self.summary_hash)?;
        validate_metadata("provider profile id", &self.provider_profile_id)?;
        validate_metadata("model", &self.model)?;
        validate_metadata("generated at", &self.generated_at)?;
        self.rules.validate()?;
        let target_tier = normalize_generation_mode(self.generation_mode, self.target_tier)?;
        if target_tier != self.target_tier {
            return Err("AI 草稿档位模式与目标档位不一致。".to_string());
        }
        validate_rules_for_mode(self.generation_mode, self.target_tier, &self.rules)?;
        Ok(())
    }
}

impl ApprovedRuleEnvelope {
    pub fn validate(&self) -> Result<RuleCompilation, String> {
        if self.schema_version != AI_SUMMARY_SCHEMA_VERSION
            || self.redaction_version != AI_REDACTION_VERSION
            || self.revision == 0
        {
            return Err("AI 批准封装版本无效。".to_string());
        }
        validate_metadata("draft id", &self.draft_id)?;
        validate_summary_hash(&self.summary_hash)?;
        validate_metadata("provider profile id", &self.provider_profile_id)?;
        validate_metadata("model", &self.model)?;
        validate_metadata("generated at", &self.generated_at)?;
        self.rules.validate()?;
        let target_tier = normalize_generation_mode(self.generation_mode, self.target_tier)?;
        if target_tier != self.target_tier {
            return Err("AI 批准封装档位模式与目标档位不一致。".to_string());
        }
        validate_rules_for_mode(self.generation_mode, self.target_tier, &self.rules)?;
        let compilation = self.rules.compile()?;
        if !compilation.report.valid || compilation != self.compilation {
            return Err("AI 批准封装的编译结果已失效。".to_string());
        }
        Ok(compilation)
    }
}

#[derive(Serialize)]
struct AiYamlDocument {
    version: u16,
    rules: Vec<AiYamlRule>,
}

#[derive(Serialize)]
struct AiYamlRule {
    id: String,
    name: String,
    app: String,
    category: String,
    level: String,
    #[serde(rename = "default")]
    default_selected: bool,
    paths: Vec<String>,
    clean: String,
    keep_days: u16,
    exclude: Vec<String>,
    note: String,
}

impl From<&AiGeneratedRule> for AiYamlRule {
    fn from(rule: &AiGeneratedRule) -> Self {
        Self {
            id: rule.id.clone(),
            name: rule.name.clone(),
            app: rule.app.clone(),
            category: rule.category.clone(),
            level: rule.tier.yaml_level().to_string(),
            // Approval and enablement are separate actions. AI rules never request default selection.
            default_selected: false,
            paths: rule.paths.clone(),
            clean: rule.clean.yaml_value().to_string(),
            keep_days: rule.keep_days,
            exclude: rule.exclude.clone(),
            note: rule.note.clone(),
        }
    }
}

fn normalize_generation_mode(
    mode: AiGenerationMode,
    target_tier: Option<AiRuleTier>,
) -> Result<Option<AiRuleTier>, String> {
    match mode {
        AiGenerationMode::AllTiers => {
            if target_tier.is_some() {
                return Err("全部档位模式不得指定单一目标档位。".to_string());
            }
            Ok(None)
        }
        AiGenerationMode::SingleTier => {
            if target_tier.is_none() {
                return Err("单档模式必须指定目标档位。".to_string());
            }
            Ok(target_tier)
        }
    }
}

fn validate_rules_for_mode(
    mode: AiGenerationMode,
    target_tier: Option<AiRuleTier>,
    rules: &AiGeneratedRuleSet,
) -> Result<(), String> {
    match mode {
        AiGenerationMode::AllTiers => Ok(()),
        AiGenerationMode::SingleTier => {
            let tier = target_tier.ok_or_else(|| "单档模式必须指定目标档位。".to_string())?;
            if rules.rules.iter().any(|rule| rule.tier != tier) {
                return Err("AI 草稿包含目标档位之外的规则。".to_string());
            }
            Ok(())
        }
    }
}

fn validate_generated_rule(rule: &AiGeneratedRule) -> Result<(), String> {
    if !valid_rule_id(&rule.id) {
        return Err(format!("AI 规则 ID 无效：{}", rule.id));
    }
    for (field, value) in [
        ("name", rule.name.as_str()),
        ("app", rule.app.as_str()),
        ("category", rule.category.as_str()),
        ("note", rule.note.as_str()),
    ] {
        validate_text(field, value, MAX_TEXT_CHARS)?;
    }
    if rule.paths.is_empty() || rule.paths.len() > MAX_PATHS_PER_RULE {
        return Err("AI 返回的路径数量无效。".to_string());
    }
    if rule.exclude.len() > MAX_EXCLUDES_PER_RULE
        || rule.evidence.len() > MAX_EXPLANATIONS_PER_RULE
        || rule.cautions.len() > MAX_EXPLANATIONS_PER_RULE
    {
        return Err("AI 返回的排除项或说明数量超过上限。".to_string());
    }
    if rule.keep_days > 365 {
        return Err("AI 返回的 keepDays 超过 365。".to_string());
    }
    for path in rule.paths.iter().chain(rule.exclude.iter()) {
        validate_text("path", path, MAX_PATH_CHARS)?;
    }
    for text in rule.evidence.iter().chain(rule.cautions.iter()) {
        validate_text("explanation", text, MAX_TEXT_CHARS)?;
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max_chars: usize) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > max_chars || trimmed.contains('\0') {
        return Err(format!("AI 返回的 {field} 字段为空或超过上限。"));
    }
    Ok(())
}

fn validate_metadata(field: &str, value: &str) -> Result<(), String> {
    validate_text(field, value, MAX_TEXT_CHARS)
}

fn validate_summary_hash(value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("AI 草稿的扫描摘要哈希无效。".to_string());
    }
    Ok(())
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
}

pub fn redacted_scan_summary(snapshot: &ScanSnapshot) -> RedactedScanSummary {
    let mut grouped: BTreeMap<(String, String, String), (u32, u64)> = BTreeMap::new();
    let mut risk_signals = BTreeSet::new();
    for candidate in &snapshot.candidates {
        collect_risk_signals(candidate, &mut risk_signals);
        let key = (
            source_kind(candidate),
            risk_level(candidate.risk_level.clone()),
            safe_category(&candidate.category),
        );
        let entry = grouped.entry(key).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(candidate.size_bytes);
    }
    match snapshot.coverage.status {
        crate::ScanCoverageStatus::Partial => {
            risk_signals.insert("coverage-partial".to_string());
        }
        crate::ScanCoverageStatus::Cancelled => {
            risk_signals.insert("coverage-cancelled".to_string());
        }
        crate::ScanCoverageStatus::Failed => {
            risk_signals.insert("coverage-failed".to_string());
        }
        crate::ScanCoverageStatus::NotStarted | crate::ScanCoverageStatus::Complete => {}
    }
    for gap in &snapshot.coverage.gaps {
        let signal = match gap.reason {
            crate::CoverageGapReason::AccessDenied => "coverage-access-denied",
            crate::CoverageGapReason::ReparseNotFollowed => "coverage-reparse-boundary",
            crate::CoverageGapReason::ResourceLimit => "coverage-resource-limit",
            crate::CoverageGapReason::BackendFallback => "coverage-backend-fallback",
            crate::CoverageGapReason::Disappeared
            | crate::CoverageGapReason::InvalidMetadata
            | crate::CoverageGapReason::IdentityFallback => "coverage-metadata-gap",
        };
        risk_signals.insert(signal.to_string());
    }
    if snapshot
        .space_summary
        .iter()
        .any(|volume| volume.analysis_only_count > 0)
    {
        risk_signals.insert("inventory-analysis-only".to_string());
    }
    if snapshot
        .space_summary
        .iter()
        .any(|volume| volume.blocked_count > 0)
    {
        risk_signals.insert("inventory-blocked".to_string());
    }
    let mut omitted_count = 0u32;
    let mut buckets = Vec::new();
    for ((source_kind, risk_level, category), (candidate_count, total_bytes)) in grouped {
        if buckets.len() == MAX_BUCKETS {
            omitted_count = omitted_count.saturating_add(candidate_count);
            continue;
        }
        buckets.push(RedactedScanBucket {
            source_kind,
            risk_level,
            category,
            candidate_count,
            total_bytes,
            size_band: size_band(total_bytes).to_string(),
        });
    }
    let mut summary = RedactedScanSummary {
        schema_version: AI_SUMMARY_SCHEMA_VERSION,
        redaction_version: AI_REDACTION_VERSION,
        scan_mode: safe_scan_mode(&snapshot.scan_backend),
        buckets,
        risk_signals: risk_signals.into_iter().collect(),
        omitted_count,
        truncated: omitted_count > 0,
        summary_hash: "0".repeat(64),
    };
    while serde_json::to_vec(&summary).map_or(0, |bytes| bytes.len()) > MAX_SUMMARY_BYTES {
        let Some(removed) = summary.buckets.pop() else {
            break;
        };
        summary.omitted_count = summary
            .omitted_count
            .saturating_add(removed.candidate_count);
        summary.truncated = true;
    }
    summary.summary_hash.clear();
    summary.summary_hash = stable_hash(&summary);
    summary
}

fn source_kind(candidate: &CleanupCandidate) -> String {
    match candidate.source.kind {
        crate::SourceKind::Browser => "browser",
        crate::SourceKind::Windows => "windows",
        crate::SourceKind::InstalledApp => "installedApp",
        crate::SourceKind::StoreApp => "storeApp",
        crate::SourceKind::Game => "game",
        crate::SourceKind::DevTool => "devTool",
        crate::SourceKind::Project => "project",
        crate::SourceKind::Unknown => "unknown",
    }
    .to_string()
}

fn collect_risk_signals(candidate: &CleanupCandidate, output: &mut BTreeSet<String>) {
    let evidence = format!(
        "{} {} {} {} {}",
        candidate.path,
        candidate.display_name,
        candidate.reason,
        candidate.source.evidence,
        candidate.category
    )
    .to_ascii_lowercase();
    for (signal, needles) in [
        (
            "credentials",
            &["credential", "password", "api_key", "apikey", "token"][..],
        ),
        ("sessions", &["session", "cookie"][..]),
        ("databases", &["database", ".db", "sqlite"][..]),
        (
            "sourceTree",
            &[".git", "node_modules", "source", "project"][..],
        ),
    ] {
        if needles.iter().any(|needle| evidence.contains(needle)) {
            output.insert(signal.to_string());
        }
    }
    if candidate.risk_level == RiskLevel::Blocked
        || candidate.delete_strategy == crate::DeleteStrategy::Skip
    {
        output.insert("locallyBlocked".to_string());
    }
}

fn risk_level(risk: RiskLevel) -> String {
    match risk {
        RiskLevel::SafeRecommended => "safeRecommended",
        RiskLevel::CautiousRecommended => "cautiousRecommended",
        RiskLevel::ReviewRequired => "reviewRequired",
        RiskLevel::Blocked => "blocked",
    }
    .to_string()
}

fn safe_scan_mode(scan_mode: &str) -> String {
    let normalized = scan_mode.trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "mft" | "usn" | "walk" | "hybrid") {
        normalized
    } else {
        "other".to_string()
    }
}

fn safe_category(category: &str) -> String {
    let normalized = category.trim().to_lowercase();
    let allowed: BTreeSet<&str> = [
        "browser",
        "windows",
        "application",
        "developer",
        "temporary",
        "cache",
        "other",
    ]
    .into_iter()
    .collect();
    if allowed.contains(normalized.as_str()) {
        normalized
    } else {
        "other".to_string()
    }
}

fn size_band(bytes: u64) -> &'static str {
    match bytes {
        0..=10_485_759 => "under10mb",
        10_485_760..=104_857_599 => "10to100mb",
        104_857_600..=1_073_741_823 => "100mbto1gb",
        _ => "over1gb",
    }
}

fn stable_hash(summary: &RedactedScanSummary) -> String {
    let encoded = serde_json::to_vec(summary).unwrap_or_default();
    Sha256::digest(encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CleanupPolicy, DeleteStrategy, ObjectType, ScanSummary, SourceInfo, SourceKind};

    const SUMMARY_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_SUMMARY_HASH: &str =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn snapshot(path: &str, category: &str) -> ScanSnapshot {
        ScanSnapshot {
            volumes: vec![],
            selected_candidate_id: String::new(),
            scan_backend: "mft".to_string(),
            warnings: vec![],
            scan_session_id: None,
            coverage: crate::ScanCoverage::default(),
            space_summary: Vec::new(),
            summary: ScanSummary {
                estimated_reclaim_bytes: 0,
                candidate_count: 1,
                locked_count: 0,
                progress_percent: 100,
                selected_count: 0,
                selected_bytes: 0,
            },
            candidates: vec![CleanupCandidate {
                id: "secret-id".to_string(),
                parent_id: None,
                display_name: "alice-secret-token.txt".to_string(),
                path: path.to_string(),
                volume_id: "Workstation-01".to_string(),
                object_type: ObjectType::File,
                category: category.to_string(),
                size_bytes: 12_000_000,
                children_count: 0,
                risk_level: RiskLevel::SafeRecommended,
                default_selected: true,
                selected: false,
                delete_strategy: DeleteStrategy::MoveToRecycleBin,
                reason: "session=top-secret credential=API_KEY".to_string(),
                confidence: 100,
                source: SourceInfo {
                    label: "Alice Browser".to_string(),
                    kind: SourceKind::Browser,
                    confidence: 100,
                    evidence: path.to_string(),
                },
                cleanup_policy: CleanupPolicy::default(),
            }],
        }
    }

    fn valid_json() -> String {
        let rule = |id: &str, tier: &str, path: &str| {
            format!(
                r#"{{"id":"{id}","tier":"{tier}","name":"{id}","app":"test","category":"cache","paths":["{path}"],"clean":"contents","keep_days":7,"exclude":["*.lock"],"note":"note","evidence":["aggregate cache bucket"],"cautions":["close application first"]}}"#
            )
        };
        format!(
            r#"{{"schema_version":1,"rules":[{},{},{}]}}"#,
            rule("ai.light", "light", r#"%TEMP%\\ai-light"#),
            rule("ai.medium", "medium", r#"%TEMP%\\ai-medium"#),
            rule("ai.heavy", "heavy", r#"%TEMP%\\ai-heavy"#)
        )
    }

    #[test]
    fn summary_never_serializes_candidate_secrets() {
        let summary = redacted_scan_summary(&snapshot(
            "C:\\Users\\alice\\token-session.txt",
            "private-project",
        ));
        let serialized = serde_json::to_string(&summary).unwrap();
        for secret in [
            "alice",
            "token-session.txt",
            "top-secret",
            "api_key",
            "Workstation",
            "private-project",
            "secret-id",
        ] {
            assert!(!serialized.to_lowercase().contains(&secret.to_lowercase()));
        }
        assert_eq!(
            summary.risk_signals,
            vec!["credentials", "sessions", "sourceTree"]
        );
    }

    #[test]
    fn coverage_signals_are_aggregated_without_path_hints() {
        let mut value = snapshot("C:\\Users\\alice\\x", "cache");
        value.coverage.status = crate::ScanCoverageStatus::Partial;
        value.coverage.gaps.push(crate::CoverageGap {
            volume_id: "secret-volume-label".to_string(),
            reason: crate::CoverageGapReason::AccessDenied,
            path_hint: Some("C:\\Users\\alice\\private".to_string()),
            count: 4,
        });

        let summary = redacted_scan_summary(&value);
        let serialized = serde_json::to_string(&summary).expect("serialize summary");

        assert!(summary
            .risk_signals
            .contains(&"coverage-partial".to_string()));
        assert!(summary
            .risk_signals
            .contains(&"coverage-access-denied".to_string()));
        assert!(!serialized.contains("alice"));
        assert!(!serialized.contains("secret-volume-label"));
    }

    #[test]
    fn untrusted_scan_backend_is_replaced() {
        let mut value = snapshot("C:\\Users\\alice\\x", "cache");
        value.scan_backend = "alice-machine-token".to_string();
        assert_eq!(redacted_scan_summary(&value).scan_mode, "other");
    }

    #[test]
    fn summary_is_deterministic() {
        assert_eq!(
            redacted_scan_summary(&snapshot("C:\\Users\\alice\\x", "cache")),
            redacted_scan_summary(&snapshot("D:\\Users\\bob\\y", "cache"))
        );
    }

    #[test]
    fn provider_summary_validation_rejects_tampering_and_uncontrolled_text() {
        let summary = redacted_scan_summary(&snapshot("C:\\Users\\alice\\x", "cache"));
        assert!(summary.validate_for_provider().is_ok());

        let mut tampered = summary.clone();
        tampered.buckets[0].category = "C:\\Users\\alice".into();
        assert!(tampered.validate_for_provider().is_err());

        let mut tampered = summary;
        tampered.omitted_count = 1;
        tampered.truncated = true;
        assert!(tampered.validate_for_provider().is_err());
    }

    #[test]
    fn summary_bounds_are_stable_and_report_truncation() {
        let mut value = snapshot("C:\\Users\\alice\\x", "cache");
        let template = value.candidates[0].clone();
        value.candidates.clear();
        let sources = [
            SourceKind::Browser,
            SourceKind::Windows,
            SourceKind::InstalledApp,
            SourceKind::StoreApp,
            SourceKind::Game,
            SourceKind::DevTool,
            SourceKind::Project,
            SourceKind::Unknown,
        ];
        let risks = [
            RiskLevel::SafeRecommended,
            RiskLevel::CautiousRecommended,
            RiskLevel::ReviewRequired,
            RiskLevel::Blocked,
        ];
        for source in sources {
            for risk in &risks {
                for category in [
                    "browser",
                    "windows",
                    "application",
                    "developer",
                    "temporary",
                    "cache",
                    "other",
                ] {
                    let mut candidate = template.clone();
                    candidate.source.kind = source.clone();
                    candidate.risk_level = risk.clone();
                    candidate.category = category.into();
                    value.candidates.push(candidate);
                }
            }
        }
        let summary = redacted_scan_summary(&value);
        assert_eq!(summary.buckets.len(), MAX_BUCKETS);
        assert!(summary.truncated);
        assert!(summary.omitted_count > 0);
        assert!(serde_json::to_vec(&summary).unwrap().len() <= MAX_SUMMARY_BYTES);
        assert_eq!(summary, redacted_scan_summary(&value));
    }

    #[test]
    fn strict_rule_set_requires_all_tiers_and_unique_ids() {
        let valid = valid_json();
        assert_eq!(
            AiGeneratedRuleSet::parse(&valid).unwrap().rules[2]
                .tier
                .rule_level(),
            RuleLevel::ReviewRequired
        );
        assert!(AiGeneratedRuleSet::parse(&valid.replace("ai.heavy", "ai.medium")).is_err());
        assert!(AiGeneratedRuleSet::parse(
            &valid.replace("\"cautions\"", "\"unknownExecutableField\"")
        )
        .is_err());
    }

    #[test]
    fn single_target_tier_is_valid_and_ipc_is_camel_case() {
        let json = format!(
            r#"{{"schema_version":1,"rules":[{}]}}"#,
            r#"{"id":"ai.light","tier":"light","name":"light","app":"test","category":"cache","paths":["%TEMP%\\ai-light"],"clean":"contents","keep_days":7,"exclude":["*.lock"],"note":"note","evidence":["aggregate"],"cautions":["review"]}"#
        );
        let rules = AiGeneratedRuleSet::parse(&json).unwrap();
        assert!(mandatory_rule_excludes()
            .iter()
            .all(|pattern| rules.rules[0].exclude.iter().any(|value| value == pattern)));

        let ipc = serde_json::to_value(&rules).unwrap();
        assert_eq!(ipc["schemaVersion"], 1);
        assert_eq!(ipc["rules"][0]["keepDays"], 7);
        assert!(ipc.get("schema_version").is_none());
        assert!(ipc["rules"][0].get("keep_days").is_none());
        assert_eq!(
            serde_json::from_value::<AiGeneratedRuleSet>(ipc).unwrap(),
            rules
        );
    }

    #[test]
    fn generated_rules_pass_through_existing_compiler_without_default_selection() {
        let rules = AiGeneratedRuleSet::parse(&valid_json()).unwrap();
        let compilation = rules.compile().unwrap();
        assert!(compilation.report.valid, "{:?}", compilation.report.errors);
        assert_eq!(compilation.rules.len(), 3);
        assert!(compilation.rules.iter().all(|rule| !rule.default_selected));
        assert_eq!(compilation.rules[0].clean, RuleCleanupMethod::Contents);
        assert_eq!(compilation.rules[2].risk_level, RiskLevel::ReviewRequired);
    }

    #[test]
    fn unsafe_user_content_is_escalated_by_existing_safety_chain() {
        let json = valid_json().replace(
            r#"%TEMP%\\ai-light"#,
            r#"%USERPROFILE%\\Documents\\private"#,
        );
        let compilation = AiGeneratedRuleSet::parse(&json).unwrap().compile().unwrap();
        assert!(compilation.report.valid);
        assert_ne!(compilation.rules[0].risk_level, RiskLevel::SafeRecommended);
        assert!(!compilation.rules[0].default_selected);
    }

    #[test]
    fn draft_edit_invalidates_validation_and_approval_checks_revision() {
        let rules = AiGeneratedRuleSet::parse(&valid_json()).unwrap();
        let mut draft = AiRuleDraft::new(
            "draft-1".to_string(),
            SUMMARY_HASH.to_string(),
            AiGenerationMode::SingleTier,
            Some(AiRuleTier::Light),
            "profile-1".to_string(),
            "model-1".to_string(),
            "2026-03-14T00:00:00Z".to_string(),
            AiGeneratedRuleSet {
                schema_version: rules.schema_version,
                rules: vec![rules.rules[0].clone()],
            },
        )
        .unwrap();
        assert!(draft.approve(1, SUMMARY_HASH).is_err());
        assert!(draft.validate_current_revision().unwrap().report.valid);
        let envelope = draft.approve(1, SUMMARY_HASH).unwrap();
        assert!(envelope.validate().is_ok());
        let mut tampered_draft = draft.clone();
        tampered_draft.compilation.as_mut().unwrap().rules.clear();
        assert!(tampered_draft.approve(1, SUMMARY_HASH).is_err());
        let mut tampered = envelope.clone();
        tampered.summary_hash = "not-a-hash".into();
        assert!(tampered.validate().is_err());
        let mut tampered = envelope;
        tampered.compilation.rules.clear();
        assert!(tampered.validate().is_err());

        draft
            .replace_rules(AiGeneratedRuleSet {
                schema_version: rules.schema_version,
                rules: vec![rules.rules[0].clone()],
            })
            .unwrap();
        assert_eq!(draft.revision, 2);
        assert!(draft.validation_revision.is_none());
        assert!(draft.approve(1, SUMMARY_HASH).is_err());
        assert!(draft.approve(2, SUMMARY_HASH).is_err());
        assert!(draft.approve(2, OTHER_SUMMARY_HASH).is_err());
    }

    #[test]
    fn all_tiers_draft_accepts_mixed_tiers_and_rejects_target_tier() {
        let rules = AiGeneratedRuleSet::parse(&valid_json()).unwrap();
        let mut draft = AiRuleDraft::new(
            "draft-all".to_string(),
            SUMMARY_HASH.to_string(),
            AiGenerationMode::AllTiers,
            None,
            "profile-1".to_string(),
            "model-1".to_string(),
            "2026-03-14T00:00:00Z".to_string(),
            rules.clone(),
        )
        .unwrap();
        assert_eq!(draft.generation_mode, AiGenerationMode::AllTiers);
        assert!(draft.target_tier.is_none());
        assert!(draft.validate_contract().is_ok());
        assert!(draft.validate_current_revision().unwrap().report.valid);
        let envelope = draft.approve(1, SUMMARY_HASH).unwrap();
        assert_eq!(envelope.generation_mode, AiGenerationMode::AllTiers);
        assert!(envelope.target_tier.is_none());
        assert!(envelope.validate().is_ok());
        assert!(envelope
            .compilation
            .rules
            .iter()
            .all(|rule| !rule.default_selected));

        assert!(AiRuleDraft::new(
            "draft-bad".to_string(),
            SUMMARY_HASH.to_string(),
            AiGenerationMode::AllTiers,
            Some(AiRuleTier::Light),
            "profile-1".to_string(),
            "model-1".to_string(),
            "2026-03-14T00:00:00Z".to_string(),
            rules,
        )
        .is_err());
    }

    #[test]
    fn single_tier_draft_rejects_cross_tier_rules() {
        let rules = AiGeneratedRuleSet::parse(&valid_json()).unwrap();
        assert!(AiRuleDraft::new(
            "draft-cross".to_string(),
            SUMMARY_HASH.to_string(),
            AiGenerationMode::SingleTier,
            Some(AiRuleTier::Light),
            "profile-1".to_string(),
            "model-1".to_string(),
            "2026-03-14T00:00:00Z".to_string(),
            rules,
        )
        .is_err());
    }

    #[test]
    fn draft_ipc_keeps_camel_case_generation_mode() {
        let rules = AiGeneratedRuleSet::parse(&valid_json()).unwrap();
        let draft = AiRuleDraft::new(
            "draft-ipc".to_string(),
            SUMMARY_HASH.to_string(),
            AiGenerationMode::AllTiers,
            None,
            "profile-1".to_string(),
            "model-1".to_string(),
            "2026-03-14T00:00:00Z".to_string(),
            rules,
        )
        .unwrap();
        let ipc = serde_json::to_value(&draft).unwrap();
        assert_eq!(ipc["generationMode"], "allTiers");
        assert!(ipc["targetTier"].is_null());
        assert!(ipc.get("generation_mode").is_none());
        assert_eq!(serde_json::from_value::<AiRuleDraft>(ipc).unwrap(), draft);
    }

    #[test]
    fn malformed_and_oversized_responses_fail_closed() {
        assert!(AiGeneratedRuleSet::parse("not-json").is_err());
        assert!(AiGeneratedRuleSet::parse(&"x".repeat(MAX_AI_RESPONSE_BYTES + 1)).is_err());
        assert!(
            AiGeneratedRuleSet::parse(&valid_json().replace("\"heavy\"", "\"danger\"")).is_err()
        );
        assert!(AiGeneratedRuleSet::parse(
            &valid_json().replace("\"keep_days\":7", "\"keep_days\":999")
        )
        .is_err());
    }
}

#[cfg(test)]
use crate::rules::RuleCleanupMethod;
use crate::rules::{compile_cleanup_rules_yaml, RuleCompilation, RuleLevel, RuleSourceKind};
use crate::{CleanupCandidate, RiskLevel, ScanSnapshot};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub const AI_SUMMARY_SCHEMA_VERSION: u16 = 3;
pub const AI_REDACTION_VERSION: u16 = 3;
const AI_RULE_SCHEMA_VERSION: u16 = 1;
const AI_DRAFT_SCHEMA_VERSION: u16 = 1;
const AI_DRAFT_REDACTION_VERSION: u16 = 1;
const MAX_BUCKETS: usize = 64;
const MAX_SUMMARY_BYTES: usize = 128 * 1024;
const MAX_SAMPLES_PER_BUCKET: usize = 10;
const MAX_RULES_PER_TIER: usize = 32;
const MAX_PATHS_PER_RULE: usize = 16;
const MAX_EXCLUDES_PER_RULE: usize = 32;
const MAX_EXPLANATIONS_PER_RULE: usize = 8;
pub const MAX_AI_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_CHARS: usize = 512;
const MAX_PATH_CHARS: usize = 1024;
const ALLOWED_RISK_SIGNALS: &[&str] = &[
    "credentials",
    "sessions",
    "databases",
    "sourceTree",
    "locallyBlocked",
    "coverage-partial",
    "coverage-cancelled",
    "coverage-failed",
    "coverage-access-denied",
    "coverage-reparse-boundary",
    "coverage-resource-limit",
    "coverage-backend-fallback",
    "coverage-metadata-gap",
    "inventory-analysis-only",
    "inventory-blocked",
];

/// Hybrid scan summary for the AI provider boundary: full aggregate buckets plus
/// limited path samples (`path` / `displayName` / `sizeBytes`). `redaction_version`
/// tracks disclosure policy, not zero-path.
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
    pub samples: Vec<RedactedScanSample>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedScanSample {
    pub path: String,
    pub display_name: String,
    pub size_bytes: u64,
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
                || bucket.samples.len() > MAX_SAMPLES_PER_BUCKET
                || bucket.samples.len() > bucket.candidate_count as usize
                || bucket.size_band != size_band(bucket.total_bytes)
                || !bucket_keys.insert((
                    bucket.source_kind.as_str(),
                    bucket.risk_level.as_str(),
                    bucket.category.as_str(),
                ))
            {
                return Err("脱敏摘要聚合桶无效。".to_string());
            }
            for sample in &bucket.samples {
                if !valid_summary_text(&sample.path, MAX_PATH_CHARS)
                    || !valid_summary_text(&sample.display_name, MAX_PATH_CHARS)
                {
                    return Err("脱敏摘要路径样本无效。".to_string());
                }
            }
        }

        let mut signals = HashSet::new();
        if self.risk_signals.iter().any(|signal| {
            !ALLOWED_RISK_SIGNALS.contains(&signal.as_str()) || !signals.insert(signal.as_str())
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

pub const MAX_REVISION_INSTRUCTION_CHARS: usize = 200;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiRuleTierChange {
    pub id: String,
    pub tier: AiRuleTier,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiGenerationRevision {
    pub previous_rules: AiGeneratedRuleSet,
    pub dropped_ids: Vec<String>,
    pub tier_changes: Vec<AiRuleTierChange>,
    pub rewrite_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
}

impl AiGenerationRevision {
    pub fn validate(&self) -> Result<(), String> {
        if self
            .instruction
            .as_ref()
            .is_some_and(|text| text.chars().count() > MAX_REVISION_INSTRUCTION_CHARS)
        {
            return Err("修订说明超过 200 字。".to_string());
        }
        self.previous_rules.validate()
    }

    pub fn enforce_on(&self, next: &AiGeneratedRuleSet) -> Result<(), String> {
        if next
            .rules
            .iter()
            .any(|rule| self.dropped_ids.iter().any(|id| id == &rule.id))
        {
            return Err("丢掉的规则不得出现在下一版。".to_string());
        }
        for change in &self.tier_changes {
            let Some(rule) = next.rules.iter().find(|rule| rule.id == change.id) else {
                return Err(format!("改档规则 {} 未出现在下一版。", change.id));
            };
            if rule.tier != change.tier {
                return Err(format!("规则 {} 未改到指定档位。", change.id));
            }
        }
        for id in &self.rewrite_ids {
            let Some(previous) = self.previous_rules.rules.iter().find(|rule| rule.id == *id)
            else {
                continue;
            };
            if next
                .rules
                .iter()
                .any(|rule| revision_body_unchanged(previous, rule))
            {
                return Err(format!("重写规则 {id} 与上一版相同。"));
            }
        }
        Ok(())
    }
}

fn revision_body_unchanged(previous: &AiGeneratedRule, next: &AiGeneratedRule) -> bool {
    previous.id == next.id
        && previous.paths == next.paths
        && previous.clean == next.clean
        && previous.keep_days == next.keep_days
        && previous.exclude == next.exclude
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "contents" | "content" | "delete" | "remove" | "purge" | "clear" => {
                Some(Self::Contents)
            }
            "files" | "file" => Some(Self::Files),
            "recycle" | "recyclebin" | "recycle_bin" | "recycle-bin" => Some(Self::Recycle),
            "manual" | "review" | "none" => Some(Self::Manual),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for AiRuleCleanMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::unknown_variant(&value, &["contents", "files", "recycle", "manual"])
        })
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
            return Err(format!(
                "AI 返回内容超过 {} KB 上限。",
                MAX_AI_RESPONSE_BYTES / 1024
            ));
        }
        let parsed: Self = serde_json::from_str(json)
            .map_err(|error| format!("AI 返回的规则格式无效：{error}"))?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != AI_RULE_SCHEMA_VERSION {
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
    /// The compiler owns path syntax validation; approved library rules keep authored risk.
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

impl AiRuleDraft {
    #[allow(clippy::too_many_arguments)]
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
            schema_version: AI_DRAFT_SCHEMA_VERSION,
            redaction_version: AI_DRAFT_REDACTION_VERSION,
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
        if self.schema_version != AI_DRAFT_SCHEMA_VERSION
            || self.redaction_version != AI_DRAFT_REDACTION_VERSION
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
        if self.schema_version != AI_DRAFT_SCHEMA_VERSION
            || self.redaction_version != AI_DRAFT_REDACTION_VERSION
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
    let mut grouped: BTreeMap<(String, String, String), BucketAccumulator> = BTreeMap::new();
    let mut risk_signals = BTreeSet::new();
    let mut field_truncations = 0u32;
    for candidate in &snapshot.candidates {
        collect_risk_signals(candidate, &mut risk_signals);
        let key = (
            source_kind(candidate),
            risk_level(candidate.risk_level.clone()),
            safe_category(&candidate.category),
        );
        let entry = grouped.entry(key).or_default();
        entry.candidate_count = entry.candidate_count.saturating_add(1);
        entry.total_bytes = entry.total_bytes.saturating_add(candidate.size_bytes);
        entry
            .samples
            .push(build_sample(candidate, &mut field_truncations));
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

    let mut omitted_count = field_truncations;
    let mut buckets = Vec::new();
    for ((source_kind, risk_level, category), mut acc) in grouped {
        if buckets.len() == MAX_BUCKETS {
            omitted_count = omitted_count.saturating_add(acc.candidate_count);
            continue;
        }
        acc.samples.sort_by(|left, right| {
            right
                .size_bytes
                .cmp(&left.size_bytes)
                .then_with(|| left.path.cmp(&right.path))
        });
        if acc.samples.len() > MAX_SAMPLES_PER_BUCKET {
            omitted_count =
                omitted_count.saturating_add((acc.samples.len() - MAX_SAMPLES_PER_BUCKET) as u32);
            acc.samples.truncate(MAX_SAMPLES_PER_BUCKET);
        }
        buckets.push(RedactedScanBucket {
            source_kind,
            risk_level,
            category,
            candidate_count: acc.candidate_count,
            total_bytes: acc.total_bytes,
            size_band: size_band(acc.total_bytes).to_string(),
            samples: acc.samples,
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
    enforce_summary_byte_limit(&mut summary);
    summary.summary_hash.clear();
    summary.summary_hash = stable_hash(&summary);
    summary
}

#[derive(Default)]
struct BucketAccumulator {
    candidate_count: u32,
    total_bytes: u64,
    samples: Vec<RedactedScanSample>,
}

fn build_sample(candidate: &CleanupCandidate, field_truncations: &mut u32) -> RedactedScanSample {
    let (path, path_truncated) = clamp_chars(&candidate.path, MAX_PATH_CHARS);
    let (display_name, name_truncated) = clamp_chars(&candidate.display_name, MAX_PATH_CHARS);
    *field_truncations =
        field_truncations.saturating_add(u32::from(path_truncated) + u32::from(name_truncated));
    RedactedScanSample {
        path: ensure_sample_text(path),
        display_name: ensure_sample_text(display_name),
        size_bytes: candidate.size_bytes,
    }
}

fn enforce_summary_byte_limit(summary: &mut RedactedScanSummary) {
    while serde_json::to_vec(summary).map_or(0, |bytes| bytes.len()) > MAX_SUMMARY_BYTES {
        if let Some(index) = summary
            .buckets
            .iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.samples.is_empty())
            .min_by_key(|(_, bucket)| (bucket.total_bytes, bucket.source_kind.as_str()))
            .map(|(index, _)| index)
        {
            let removed = summary.buckets[index].samples.len() as u32;
            summary.buckets[index].samples.clear();
            summary.omitted_count = summary.omitted_count.saturating_add(removed);
            summary.truncated = true;
            continue;
        }
        let Some(removed) = summary.buckets.pop() else {
            break;
        };
        summary.omitted_count = summary
            .omitted_count
            .saturating_add(removed.candidate_count);
        summary.truncated = true;
    }
}

#[cfg(test)]
fn strip_secret_shapes(input: &str) -> String {
    const NEEDLES: &[&str] = &[
        "api_key=",
        "apikey=",
        "password=",
        "passwd=",
        "token=",
        "secret=",
        "credential=",
    ];
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let rest = &lower[index..];
        let mut matched = None;
        for needle in NEEDLES {
            if rest.starts_with(needle) {
                matched = Some(needle.len());
                break;
            }
        }
        if let Some(needle_len) = matched {
            output.push_str(&input[index..index + needle_len]);
            output.push_str("[redacted]");
            index += needle_len;
            // Keep stripping idempotent when reason/evidence already carry placeholders.
            if rest[needle_len..].starts_with("[redacted]") {
                index += "[redacted]".len();
                continue;
            }
            while index < input.len() {
                let ch = bytes[index];
                if ch.is_ascii_whitespace()
                    || matches!(ch, b'"' | b'\'' | b';' | b',' | b')' | b']')
                {
                    break;
                }
                // Advance one UTF-8 scalar when the value contains non-ASCII.
                let next = input[index..]
                    .chars()
                    .next()
                    .map(|ch| ch.len_utf8())
                    .unwrap_or(1);
                index += next;
            }
            continue;
        }
        let next = input[index..]
            .chars()
            .next()
            .map(|ch| ch.len_utf8())
            .unwrap_or(1);
        output.push_str(&input[index..index + next]);
        index += next;
    }
    output
}

fn clamp_chars(value: &str, max_chars: usize) -> (String, bool) {
    let trimmed = value.trim();
    if trimmed.chars().count() <= max_chars {
        (trimmed.to_string(), false)
    } else {
        (trimmed.chars().take(max_chars).collect(), true)
    }
}

fn ensure_sample_text(value: String) -> String {
    if value.is_empty() {
        "[redacted]".to_string()
    } else {
        value
    }
}

fn valid_summary_text(value: &str, max_chars: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max_chars && !value.contains('\0')
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
                reason: "session cookie token=top-secret credential=API_KEY".to_string(),
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
    fn summary_includes_path_samples_without_local_narrative() {
        let summary = redacted_scan_summary(&snapshot(
            "C:\\Users\\alice\\token-session.txt",
            "private-project",
        ));
        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(
            serialized.contains(r#"C:\\Users\\alice\\token-session.txt"#)
                || serialized.contains("C:\\Users\\alice\\token-session.txt")
        );
        assert!(serialized.contains("alice-secret-token.txt"));
        assert!(!serialized.contains("API_KEY"));
        assert!(!serialized.contains("top-secret"));
        assert!(!serialized.contains("secret-id"));
        assert!(!serialized.contains("Workstation"));
        assert!(!serialized.contains("\"reason\""));
        assert!(!serialized.contains("\"evidence\""));
        let sample = &summary.buckets[0].samples[0];
        assert_eq!(sample.path, "C:\\Users\\alice\\token-session.txt");
        assert_eq!(
            summary.risk_signals,
            vec!["credentials", "sessions", "sourceTree"]
        );
        assert_eq!(summary.schema_version, 3);
        assert_eq!(summary.redaction_version, 3);
    }

    #[test]
    fn secret_assignment_values_are_stripped() {
        let redacted = strip_secret_shapes("session cookie token=top-secret credential=API_KEY");
        assert!(redacted.contains("token=[redacted]"));
        assert!(redacted.contains("credential=[redacted]"));
        assert!(!redacted.to_ascii_lowercase().contains("api_key"));
        assert!(!redacted.contains("top-secret"));
    }

    #[test]
    fn coverage_and_inventory_signals_pass_provider_validation() {
        let mut value = snapshot("C:\\Users\\alice\\x", "cache");
        value.coverage.status = crate::ScanCoverageStatus::Partial;
        value.coverage.gaps.push(crate::CoverageGap {
            volume_id: "secret-volume-label".to_string(),
            reason: crate::CoverageGapReason::AccessDenied,
            path_hint: Some("C:\\Users\\alice\\private".to_string()),
            count: 4,
        });
        value.space_summary.push(crate::VolumeSpaceSummary {
            volume_id: "vol".into(),
            logical_bytes: 100,
            allocated_bytes: 80,
            file_count: 10,
            directory_count: 2,
            analysis_only_count: 2,
            blocked_count: 1,
        });

        let summary = redacted_scan_summary(&value);
        let serialized = serde_json::to_string(&summary).expect("serialize summary");

        assert!(summary
            .risk_signals
            .contains(&"coverage-partial".to_string()));
        assert!(summary
            .risk_signals
            .contains(&"coverage-access-denied".to_string()));
        assert!(summary
            .risk_signals
            .contains(&"inventory-analysis-only".to_string()));
        assert!(summary
            .risk_signals
            .contains(&"inventory-blocked".to_string()));
        assert!(summary.validate_for_provider().is_ok());
        assert!(
            serialized.contains("C:\\\\Users\\\\alice\\\\x")
                || serialized.contains("C:\\Users\\alice\\x")
        );
        assert!(!serialized.contains("secret-volume-label"));
        assert!(
            !serialized.contains("C:\\\\Users\\\\alice\\\\private")
                && !serialized.contains("C:\\Users\\alice\\private")
        );
    }

    #[test]
    fn untrusted_scan_backend_is_replaced() {
        let mut value = snapshot("C:\\Users\\alice\\x", "cache");
        value.scan_backend = "alice-machine-token".to_string();
        assert_eq!(redacted_scan_summary(&value).scan_mode, "other");
    }

    #[test]
    fn summary_is_deterministic_for_same_candidates() {
        let left = redacted_scan_summary(&snapshot("C:\\Users\\alice\\x", "cache"));
        let right = redacted_scan_summary(&snapshot("C:\\Users\\alice\\x", "cache"));
        assert_eq!(left, right);
        assert_ne!(
            left.summary_hash,
            redacted_scan_summary(&snapshot("D:\\Users\\bob\\y", "cache")).summary_hash
        );
    }

    #[test]
    fn provider_summary_validation_rejects_tampering_and_uncontrolled_text() {
        let summary = redacted_scan_summary(&snapshot("C:\\Users\\alice\\x", "cache"));
        assert!(summary.validate_for_provider().is_ok());

        let mut tampered = summary.clone();
        tampered.buckets[0].category = "C:\\Users\\alice".into();
        assert!(tampered.validate_for_provider().is_err());

        let mut tampered = summary.clone();
        tampered.omitted_count = 1;
        tampered.truncated = true;
        assert!(tampered.validate_for_provider().is_err());

        let mut tampered = summary.clone();
        tampered.risk_signals.push("not-a-real-signal".into());
        tampered.summary_hash.clear();
        tampered.summary_hash = stable_hash(&tampered);
        assert!(tampered.validate_for_provider().is_err());

        let mut tampered = summary;
        tampered.buckets[0].samples[0].path.clear();
        tampered.summary_hash.clear();
        tampered.summary_hash = stable_hash(&tampered);
        assert!(tampered.validate_for_provider().is_err());
    }

    #[test]
    fn summary_bounds_prefer_dropping_samples_before_buckets() {
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
                    for index in 0..12 {
                        let mut candidate = template.clone();
                        candidate.id = format!("{source:?}-{risk:?}-{category}-{index}");
                        candidate.source.kind = source.clone();
                        candidate.risk_level = risk.clone();
                        candidate.category = category.into();
                        candidate.size_bytes = 50_000 + index as u64;
                        candidate.path = format!(
                            "C:\\Users\\alice\\pad-{}-{}-{}-{}\\{}",
                            candidate.id,
                            "x".repeat(80),
                            "y".repeat(80),
                            "z".repeat(80),
                            index
                        );
                        candidate.display_name = format!("sample-{index}-{}", "n".repeat(40));
                        candidate.reason = format!("reason-{}-{}", index, "r".repeat(40));
                        candidate.source.evidence =
                            format!("evidence-{}-{}", index, "e".repeat(40));
                        value.candidates.push(candidate);
                    }
                }
            }
        }
        let summary = redacted_scan_summary(&value);
        assert!(summary.buckets.len() <= MAX_BUCKETS);
        assert!(!summary.buckets.is_empty());
        assert!(summary.truncated);
        assert!(summary.omitted_count > 0);
        assert!(summary
            .buckets
            .iter()
            .all(|bucket| bucket.samples.len() <= MAX_SAMPLES_PER_BUCKET));
        assert!(
            summary
                .buckets
                .iter()
                .any(|bucket| bucket.samples.is_empty()),
            "byte-limit truncation should clear samples before dropping all buckets"
        );
        assert!(serde_json::to_vec(&summary).unwrap().len() <= MAX_SUMMARY_BYTES);
        assert_eq!(summary, redacted_scan_summary(&value));
        assert!(summary.validate_for_provider().is_ok());
    }

    #[test]
    fn sample_selection_keeps_largest_paths_first() {
        let mut value = snapshot("C:\\Users\\alice\\small", "cache");
        let mut large = value.candidates[0].clone();
        large.id = "large".into();
        large.path = "C:\\Users\\alice\\large".into();
        large.display_name = "large".into();
        large.size_bytes = 99_000_000;
        let mut medium = value.candidates[0].clone();
        medium.id = "medium".into();
        medium.path = "C:\\Users\\alice\\medium".into();
        medium.display_name = "medium".into();
        medium.size_bytes = 40_000_000;
        value.candidates[0].size_bytes = 1_000;
        value.candidates.push(medium);
        value.candidates.push(large);
        for index in 0..10 {
            let mut extra = value.candidates[0].clone();
            extra.id = format!("extra-{index}");
            extra.path = format!("C:\\Users\\alice\\extra-{index}");
            extra.display_name = format!("extra-{index}");
            extra.size_bytes = 2_000 + index as u64;
            value.candidates.push(extra);
        }

        let summary = redacted_scan_summary(&value);
        let paths: Vec<_> = summary.buckets[0]
            .samples
            .iter()
            .map(|sample| sample.path.as_str())
            .collect();
        assert_eq!(paths.len(), MAX_SAMPLES_PER_BUCKET);
        assert_eq!(paths[0], "C:\\Users\\alice\\large");
        assert_eq!(paths[1], "C:\\Users\\alice\\medium");
        assert!(!paths.contains(&"C:\\Users\\alice\\small"));
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
    fn delete_clean_method_is_normalized_to_contents() {
        let json = valid_json().replace(r#""clean":"contents""#, r#""clean":"delete""#);
        let rules = AiGeneratedRuleSet::parse(&json).expect("delete should be accepted");
        assert!(rules
            .rules
            .iter()
            .all(|rule| rule.clean == AiRuleCleanMethod::Contents));
    }

    #[test]
    fn single_target_tier_is_valid_and_ipc_is_camel_case() {
        let json = format!(
            r#"{{"schema_version":1,"rules":[{}]}}"#,
            r#"{"id":"ai.light","tier":"light","name":"light","app":"test","category":"cache","paths":["%TEMP%\\ai-light"],"clean":"contents","keep_days":7,"exclude":["*.lock"],"note":"note","evidence":["aggregate"],"cautions":["review"]}"#
        );
        let rules = AiGeneratedRuleSet::parse(&json).unwrap();
        assert_eq!(rules.rules[0].exclude, vec!["*.lock".to_string()]);

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
    fn authored_safe_tier_keeps_risk_through_compiler_for_user_content_paths() {
        // Library/AI compile no longer force-downgrades Documents paths (08-17).
        // Runtime heuristic candidates still need confirmation; rule-backed paths follow authorship.
        let json = valid_json().replace(
            r#"%TEMP%\\ai-light"#,
            r#"%USERPROFILE%\\Documents\\private"#,
        );
        let compilation = AiGeneratedRuleSet::parse(&json).unwrap().compile().unwrap();
        assert!(compilation.report.valid);
        assert_eq!(compilation.rules[0].risk_level, RiskLevel::SafeRecommended);
        assert!(!compilation.rules[0].default_selected);
    }

    fn parsed_rules() -> AiGeneratedRuleSet {
        AiGeneratedRuleSet::parse(&valid_json()).unwrap()
    }

    fn revision_with(previous: AiGeneratedRuleSet) -> AiGenerationRevision {
        AiGenerationRevision {
            previous_rules: previous,
            dropped_ids: Vec::new(),
            tier_changes: Vec::new(),
            rewrite_ids: Vec::new(),
            instruction: None,
        }
    }

    #[test]
    fn revision_rejects_dropped_ids_and_ignored_tier_or_rewrite() {
        let previous = parsed_rules();
        let mut next = previous.clone();
        let mut revision = revision_with(previous.clone());
        revision.dropped_ids = vec!["ai.medium".into()];
        assert!(revision.enforce_on(&next).is_err());

        next.rules.retain(|rule| rule.id != "ai.medium");
        assert!(revision.enforce_on(&next).is_ok());

        revision.tier_changes = vec![AiRuleTierChange {
            id: "ai.light".into(),
            tier: AiRuleTier::Heavy,
        }];
        assert!(revision.enforce_on(&next).is_err());
        next.rules[0].tier = AiRuleTier::Heavy;
        assert!(revision.enforce_on(&next).is_ok());

        revision.rewrite_ids = vec!["ai.heavy".into()];
        assert!(revision.enforce_on(&next).is_err());
        next.rules
            .iter_mut()
            .find(|rule| rule.id == "ai.heavy")
            .unwrap()
            .keep_days = 3;
        assert!(revision.enforce_on(&next).is_ok());
    }

    #[test]
    fn revision_instruction_has_a_hard_limit() {
        let mut revision = revision_with(parsed_rules());
        revision.instruction = Some("x".repeat(MAX_REVISION_INSTRUCTION_CHARS + 1));
        assert!(revision.validate().is_err());
        revision.instruction = Some("只要缓存".into());
        assert!(revision.validate().is_ok());
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

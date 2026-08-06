use crate::{
    ActiveRuleSnapshot, CleanupCandidate, CompiledCleanupRule, DeleteStrategy, RiskLevel,
    RuleCleanupMethod, RuleLevel, ScanMode,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const AUTOMATION_CONFIG_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MAX_AUTOMATION_WORK_ITEMS: u32 = 1_000;
pub const DEFAULT_MAX_AUTOMATION_BYTES: u64 = 10 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_AUTOMATION_RUNTIME_SECONDS: u64 = 15 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutomationMode {
    ScanOnly,
    ScanAndCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutomationTrigger {
    Manual,
    Startup,
    Scheduled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationLimits {
    pub max_work_items: u32,
    pub max_bytes: u64,
    pub max_runtime_seconds: u64,
}

impl Default for AutomationLimits {
    fn default() -> Self {
        Self {
            max_work_items: DEFAULT_MAX_AUTOMATION_WORK_ITEMS,
            max_bytes: DEFAULT_MAX_AUTOMATION_BYTES,
            max_runtime_seconds: DEFAULT_MAX_AUTOMATION_RUNTIME_SECONDS,
        }
    }
}

impl AutomationLimits {
    pub fn validate(&self) -> Result<(), AutomationPolicyError> {
        if self.max_work_items == 0
            || self.max_work_items > DEFAULT_MAX_AUTOMATION_WORK_ITEMS
            || self.max_bytes == 0
            || self.max_bytes > DEFAULT_MAX_AUTOMATION_BYTES
            || self.max_runtime_seconds == 0
            || self.max_runtime_seconds > DEFAULT_MAX_AUTOMATION_RUNTIME_SECONDS
        {
            return Err(AutomationPolicyError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationRunRequest {
    pub mode: AutomationMode,
    pub trigger: AutomationTrigger,
    pub scan_mode: ScanMode,
    pub limits: AutomationLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutomationOutcome {
    Completed,
    ScanOnly,
    Partial,
    NoEligibleItems,
    Busy,
    TimedOut,
    InvalidConfig,
    InvalidRuleSnapshot,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationSelection {
    pub candidate_ids: Vec<String>,
    pub selected_count: u32,
    pub selected_bytes: u64,
    pub skipped_count: u32,
    pub capped: bool,
    pub reasons: Vec<AutomationSkipSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationSkipSummary {
    pub reason: AutomationEligibilityReason,
    pub count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutomationEligibilityReason {
    MissingRuleAttribution,
    RuleNotApprovedLight,
    CandidateNotSafe,
    CandidateNotDefaultSelected,
    CandidateBlocked,
    RecycleBinTarget,
    CapExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomationPolicyError {
    InvalidLimits,
    InvalidRuleSnapshot,
}

pub fn automation_eligible_rule_ids(
    snapshot: &ActiveRuleSnapshot,
) -> Result<HashSet<String>, AutomationPolicyError> {
    if !snapshot.blocking_issues.is_empty() {
        return Err(AutomationPolicyError::InvalidRuleSnapshot);
    }
    let projected_ids: HashSet<&str> = snapshot
        .entries
        .iter()
        .flat_map(|entry| entry.rule_ids.iter().map(String::as_str))
        .collect();
    Ok(snapshot
        .rules
        .iter()
        .filter(|rule| projected_ids.contains(rule.id.as_str()))
        .filter(|rule| rule_is_automation_eligible(rule))
        .map(|rule| rule.id.clone())
        .collect())
}

pub fn select_automation_candidates(
    snapshot: &ActiveRuleSnapshot,
    candidates: &[CleanupCandidate],
    limits: &AutomationLimits,
) -> Result<AutomationSelection, AutomationPolicyError> {
    limits.validate()?;
    let eligible_rules = automation_eligible_rule_ids(snapshot)?;
    let mut selected_ids = Vec::new();
    let mut selected_bytes = 0_u64;
    let mut reasons = std::collections::HashMap::<AutomationEligibilityReason, u32>::new();
    let mut capped = false;

    for candidate in candidates {
        let eligibility = candidate_eligibility(candidate, &eligible_rules);
        if let Err(reason) = eligibility {
            *reasons.entry(reason).or_default() += 1;
            continue;
        }
        let exceeds_items = selected_ids.len() >= limits.max_work_items as usize;
        let Some(next_bytes) = selected_bytes.checked_add(candidate.size_bytes) else {
            *reasons
                .entry(AutomationEligibilityReason::CapExceeded)
                .or_default() += 1;
            capped = true;
            continue;
        };
        if exceeds_items || next_bytes > limits.max_bytes {
            *reasons
                .entry(AutomationEligibilityReason::CapExceeded)
                .or_default() += 1;
            capped = true;
            continue;
        }
        selected_bytes = next_bytes;
        selected_ids.push(candidate.id.clone());
    }

    let skipped_count = candidates.len().saturating_sub(selected_ids.len()) as u32;
    let mut reasons: Vec<AutomationSkipSummary> = reasons
        .into_iter()
        .map(|(reason, count)| AutomationSkipSummary { reason, count })
        .collect();
    reasons.sort_by_key(|summary| summary.reason as u8);
    Ok(AutomationSelection {
        selected_count: selected_ids.len() as u32,
        candidate_ids: selected_ids,
        selected_bytes,
        skipped_count,
        capped,
        reasons,
    })
}

fn rule_is_automation_eligible(rule: &CompiledCleanupRule) -> bool {
    rule.level == RuleLevel::Recommended
        && rule.risk_level == RiskLevel::SafeRecommended
        && rule.default_selected
        && !rule.requires_default_confirmation
        && !matches!(
            rule.clean,
            RuleCleanupMethod::Recycle | RuleCleanupMethod::Manual
        )
        && rule.close.is_empty()
}

fn candidate_eligibility(
    candidate: &CleanupCandidate,
    eligible_rules: &HashSet<String>,
) -> Result<(), AutomationEligibilityReason> {
    let rule_id = candidate
        .cleanup_policy
        .rule_id
        .as_deref()
        .ok_or(AutomationEligibilityReason::MissingRuleAttribution)?;
    if !eligible_rules.contains(rule_id) {
        return Err(AutomationEligibilityReason::RuleNotApprovedLight);
    }
    if candidate.risk_level == RiskLevel::Blocked
        || candidate.delete_strategy == DeleteStrategy::Skip
    {
        return Err(AutomationEligibilityReason::CandidateBlocked);
    }
    if candidate.risk_level != RiskLevel::SafeRecommended {
        return Err(AutomationEligibilityReason::CandidateNotSafe);
    }
    if !candidate.default_selected {
        return Err(AutomationEligibilityReason::CandidateNotDefaultSelected);
    }
    if candidate.category == "回收站"
        || candidate.path.to_ascii_lowercase().contains("$recycle.bin")
        || candidate.cleanup_policy.method == RuleCleanupMethod::Recycle
    {
        return Err(AutomationEligibilityReason::RecycleBinTarget);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActiveRuleEntry, CleanupPolicy, ObjectType, RuleSourceKind, SourceInfo, SourceKind,
    };
    use uuid::Uuid;

    fn rule(level: RuleLevel) -> CompiledCleanupRule {
        CompiledCleanupRule {
            id: "approved.light".into(),
            name: "Approved light".into(),
            app: "Test".into(),
            category: "cache".into(),
            level,
            risk_level: RiskLevel::SafeRecommended,
            default_selected: true,
            requires_default_confirmation: false,
            paths: vec!["%TEMP%\\approved-light".into()],
            clean: RuleCleanupMethod::Contents,
            keep_days: 3,
            close: Vec::new(),
            exclude: Vec::new(),
            mandatory_exclude: Vec::new(),
            note: "test".into(),
            source: RuleSourceKind::User,
            warnings: Vec::new(),
        }
    }

    fn snapshot(rule: CompiledCleanupRule) -> ActiveRuleSnapshot {
        ActiveRuleSnapshot {
            library_generation: 4,
            entries: vec![ActiveRuleEntry {
                record_id: Uuid::new_v4(),
                revision_id: Uuid::new_v4(),
                content_hash: "sha256:test".into(),
                rule_ids: vec![rule.id.clone()],
            }],
            rules: vec![rule],
            blocking_issues: Vec::new(),
        }
    }

    fn candidate(id: &str, rule_id: Option<&str>, size: u64) -> CleanupCandidate {
        CleanupCandidate {
            id: id.into(),
            parent_id: None,
            display_name: id.into(),
            path: format!("C:\\Temp\\{id}"),
            volume_id: "C:".into(),
            object_type: ObjectType::File,
            category: "cache".into(),
            size_bytes: size,
            children_count: 0,
            risk_level: RiskLevel::SafeRecommended,
            default_selected: true,
            selected: true,
            delete_strategy: DeleteStrategy::MoveToRecycleBin,
            reason: "test".into(),
            confidence: 100,
            source: SourceInfo {
                label: "test".into(),
                kind: SourceKind::Unknown,
                confidence: 100,
                evidence: "test".into(),
            },
            cleanup_policy: CleanupPolicy {
                rule_id: rule_id.map(str::to_string),
                method: RuleCleanupMethod::Contents,
                keep_days: 3,
                exclude_patterns: Vec::new(),
            },
        }
    }

    #[test]
    fn only_approved_light_rules_are_allowlisted() {
        assert!(
            automation_eligible_rule_ids(&snapshot(rule(RuleLevel::Recommended)))
                .unwrap()
                .contains("approved.light")
        );
        assert!(
            automation_eligible_rule_ids(&snapshot(rule(RuleLevel::Cautious)))
                .unwrap()
                .is_empty()
        );
        let mut blocked = snapshot(rule(RuleLevel::Recommended));
        blocked.blocking_issues.push(crate::ActiveRuleIssue {
            record_id: None,
            revision_id: None,
            code: "invalid".into(),
            message: "invalid".into(),
        });
        assert_eq!(
            automation_eligible_rule_ids(&blocked),
            Err(AutomationPolicyError::InvalidRuleSnapshot)
        );
    }

    #[test]
    fn candidate_requires_attribution_and_safe_defaults() {
        let snapshot = snapshot(rule(RuleLevel::Recommended));
        let candidates = vec![
            candidate("eligible", Some("approved.light"), 10),
            candidate("missing", None, 10),
            candidate("other", Some("other.rule"), 10),
        ];
        let selected =
            select_automation_candidates(&snapshot, &candidates, &AutomationLimits::default())
                .unwrap();
        assert_eq!(selected.candidate_ids, vec!["eligible"]);
        assert_eq!(selected.skipped_count, 2);
    }

    #[test]
    fn item_and_byte_caps_stop_additional_candidates() {
        let snapshot = snapshot(rule(RuleLevel::Recommended));
        let limits = AutomationLimits {
            max_work_items: 2,
            max_bytes: 15,
            max_runtime_seconds: 60,
        };
        let candidates = vec![
            candidate("first", Some("approved.light"), 10),
            candidate("second", Some("approved.light"), 5),
            candidate("third", Some("approved.light"), 1),
        ];
        let selected = select_automation_candidates(&snapshot, &candidates, &limits).unwrap();
        assert_eq!(selected.candidate_ids, vec!["first", "second"]);
        assert!(selected.capped);
    }

    #[test]
    fn recycle_bin_and_review_candidates_are_excluded() {
        let snapshot = snapshot(rule(RuleLevel::Recommended));
        let mut recycle = candidate("recycle", Some("approved.light"), 1);
        recycle.category = "回收站".into();
        let mut review = candidate("review", Some("approved.light"), 1);
        review.risk_level = RiskLevel::ReviewRequired;
        let selected = select_automation_candidates(
            &snapshot,
            &[recycle, review],
            &AutomationLimits::default(),
        )
        .unwrap();
        assert!(selected.candidate_ids.is_empty());
    }
}

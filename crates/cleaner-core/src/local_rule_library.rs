use crate::{
    compile_cleanup_rules_yaml, ApprovedRuleEnvelope, CompiledCleanupRule, RuleSourceKind,
    RuleValidationReport,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;
use uuid::Uuid;

pub const RULE_LIBRARY_SCHEMA_VERSION: u32 = 1;
pub const RULE_COMPILER_SCHEMA_VERSION: u32 = 1;
pub const MAX_LIBRARY_RECORDS: usize = 512;
pub const MAX_REVISIONS_PER_RECORD: usize = 128;
pub const MAX_RULE_CONTENT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleLibrarySnapshot {
    pub schema_version: u32,
    pub library_id: Uuid,
    pub generation: u64,
    pub created_at: String,
    pub updated_at: String,
    pub device_id: Uuid,
    pub actor_id: Uuid,
    pub last_mutation_id: Uuid,
    #[serde(default)]
    pub records: Vec<RuleRecord>,
}

impl RuleLibrarySnapshot {
    pub fn empty(timestamp: String, device_id: Uuid, actor_id: Uuid) -> Self {
        Self {
            schema_version: RULE_LIBRARY_SCHEMA_VERSION,
            library_id: Uuid::new_v4(),
            generation: 0,
            created_at: timestamp.clone(),
            updated_at: timestamp,
            device_id,
            actor_id,
            last_mutation_id: Uuid::nil(),
            records: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleRecord {
    pub id: Uuid,
    pub display_name: String,
    pub origin: RuleOrigin,
    pub state: RuleRecordState,
    pub active_revision_id: Option<Uuid>,
    pub pending_revision_id: Option<Uuid>,
    pub last_approved_revision_id: Option<Uuid>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub revisions: Vec<RuleRevision>,
    #[serde(default)]
    pub events: Vec<RuleLibraryEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleOrigin {
    Manual,
    AiGenerated,
    Subscription,
    LegacyMigration,
    Imported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleRecordState {
    Draft,
    Approved,
    Disabled,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleRevision {
    pub id: Uuid,
    pub number: u64,
    pub parent_revision_id: Option<Uuid>,
    pub base_revision_id: Option<Uuid>,
    pub content: String,
    pub content_hash: String,
    pub provenance: RuleProvenance,
    pub created_at: String,
    pub actor_id: Uuid,
    pub mutation_id: Uuid,
    pub validation: Option<RevisionValidation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleProvenance {
    pub source_label: String,
    pub provider_profile_id: Option<Uuid>,
    pub model: Option<String>,
    pub scan_summary_hash: Option<String>,
    pub source_url: Option<String>,
    pub generated_at: Option<String>,
    pub ai_draft_id: Option<String>,
    pub ai_draft_revision: Option<u32>,
}

impl RuleProvenance {
    pub fn manual() -> Self {
        Self {
            source_label: "manual".to_string(),
            provider_profile_id: None,
            model: None,
            scan_summary_hash: None,
            source_url: None,
            generated_at: None,
            ai_draft_id: None,
            ai_draft_revision: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionValidation {
    pub content_hash: String,
    pub compiler_schema_version: u32,
    pub validated_at: String,
    pub report: RuleValidationReport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleLibraryEvent {
    pub id: Uuid,
    pub kind: RuleLibraryEventKind,
    pub actor_id: Uuid,
    pub mutation_id: Uuid,
    pub occurred_at: String,
    pub from_state: Option<RuleRecordState>,
    pub to_state: RuleRecordState,
    pub from_revision_id: Option<Uuid>,
    pub to_revision_id: Option<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleLibraryEventKind {
    CreateDraft,
    SaveDraft,
    Approve,
    Disable,
    Delete,
    Restore,
    RollbackRequested,
    Import,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleMutationContext {
    pub expected_generation: u64,
    pub expected_head_revision_id: Option<Uuid>,
    pub mutation_id: Uuid,
    pub actor_id: Uuid,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveRuleSnapshot {
    pub library_generation: u64,
    pub rules: Vec<CompiledCleanupRule>,
    pub entries: Vec<ActiveRuleEntry>,
    pub blocking_issues: Vec<ActiveRuleIssue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveRuleEntry {
    pub record_id: Uuid,
    pub revision_id: Uuid,
    pub content_hash: String,
    pub rule_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveRuleIssue {
    pub record_id: Option<Uuid>,
    pub revision_id: Option<Uuid>,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum RuleLibraryError {
    #[error("unsupported rule library schema")]
    UnsupportedSchema,
    #[error("rule library capacity exceeded")]
    CapacityExceeded,
    #[error("rule record was not found")]
    NotFound,
    #[error("library generation is stale")]
    StaleGeneration,
    #[error("rule revision is stale")]
    StaleRevision,
    #[error("rule content hash is invalid")]
    InvalidHash,
    #[error("rule validation failed")]
    ValidationFailed,
    #[error("AI handoff envelope is invalid: {0}")]
    InvalidAiEnvelope(String),
    #[error("rule identifier conflicts with an active rule")]
    RuleIdConflict,
    #[error("rule library invariant failed: {0}")]
    InvalidInvariant(String),
}

pub fn canonicalize_rule_content(content: &str) -> Result<String, RuleLibraryError> {
    if content.len() > MAX_RULE_CONTENT_BYTES {
        return Err(RuleLibraryError::CapacityExceeded);
    }
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    Ok(content.replace("\r\n", "\n").replace('\r', "\n"))
}

pub fn rule_content_hash(content: &str) -> Result<String, RuleLibraryError> {
    let canonical = canonicalize_rule_content(content)?;
    let digest = Sha256::digest(canonical.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{hex}"))
}

pub fn validate_library(snapshot: &RuleLibrarySnapshot) -> Result<(), RuleLibraryError> {
    if snapshot.schema_version != RULE_LIBRARY_SCHEMA_VERSION {
        return Err(RuleLibraryError::UnsupportedSchema);
    }
    if snapshot.records.len() > MAX_LIBRARY_RECORDS {
        return Err(RuleLibraryError::CapacityExceeded);
    }
    let mut record_ids = HashSet::new();
    for record in &snapshot.records {
        if !record_ids.insert(record.id) || record.revisions.len() > MAX_REVISIONS_PER_RECORD {
            return Err(RuleLibraryError::InvalidInvariant(
                "duplicate record or excessive revision count".into(),
            ));
        }
        let mut revision_ids = HashSet::new();
        let mut numbers = HashSet::new();
        for revision in &record.revisions {
            if !revision_ids.insert(revision.id) || !numbers.insert(revision.number) {
                return Err(RuleLibraryError::InvalidInvariant(
                    "duplicate revision identity".into(),
                ));
            }
            if rule_content_hash(&revision.content)? != revision.content_hash {
                return Err(RuleLibraryError::InvalidHash);
            }
            if let Some(validation) = &revision.validation {
                if validation.content_hash != revision.content_hash {
                    return Err(RuleLibraryError::InvalidHash);
                }
            }
        }
        for pointer in [
            record.active_revision_id,
            record.pending_revision_id,
            record.last_approved_revision_id,
        ]
        .into_iter()
        .flatten()
        {
            if !revision_ids.contains(&pointer) {
                return Err(RuleLibraryError::InvalidInvariant(
                    "revision pointer is dangling".into(),
                ));
            }
        }
        if record.state == RuleRecordState::Approved && record.active_revision_id.is_none() {
            return Err(RuleLibraryError::InvalidInvariant(
                "approved record has no active revision".into(),
            ));
        }
    }
    Ok(())
}

pub fn create_rule_draft(
    snapshot: &RuleLibrarySnapshot,
    display_name: String,
    origin: RuleOrigin,
    content: &str,
    provenance: RuleProvenance,
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    check_generation(snapshot, &context)?;
    if snapshot.records.len() >= MAX_LIBRARY_RECORDS {
        return Err(RuleLibraryError::CapacityExceeded);
    }
    let canonical = canonicalize_rule_content(content)?;
    let record_id = Uuid::new_v4();
    let revision = new_revision(1, None, None, canonical, provenance, &context)?;
    let event = event(
        RuleLibraryEventKind::CreateDraft,
        None,
        RuleRecordState::Draft,
        None,
        Some(revision.id),
        &context,
    );
    let record = RuleRecord {
        id: record_id,
        display_name,
        origin,
        state: RuleRecordState::Draft,
        active_revision_id: None,
        pending_revision_id: Some(revision.id),
        last_approved_revision_id: None,
        created_at: context.timestamp.clone(),
        updated_at: context.timestamp.clone(),
        deleted_at: None,
        revisions: vec![revision],
        events: vec![event],
    };
    let mut next = snapshot.clone();
    next.records.push(record);
    commit_metadata(&mut next, &context);
    validate_library(&next)?;
    Ok(next)
}

/// Imports an AI-workflow approval as a validated pending library draft.
/// This deliberately does not call `approve_pending_revision`: library approval
/// remains a separate, explicit user action.
pub fn import_approved_ai_rule(
    snapshot: &RuleLibrarySnapshot,
    display_name: String,
    envelope: &ApprovedRuleEnvelope,
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    check_generation(snapshot, &context)?;
    envelope
        .validate()
        .map_err(RuleLibraryError::InvalidAiEnvelope)?;
    let profile_id = envelope.provider_profile_id.parse::<Uuid>().map_err(|_| {
        RuleLibraryError::InvalidAiEnvelope("provider profile ID is invalid".into())
    })?;
    if snapshot.records.iter().any(|record| {
        record.origin == RuleOrigin::AiGenerated
            && record.revisions.iter().any(|revision| {
                revision.provenance.ai_draft_id.as_deref() == Some(&envelope.draft_id)
                    && revision.provenance.ai_draft_revision == Some(envelope.revision)
            })
    }) {
        return Ok(snapshot.clone());
    }
    let content = envelope
        .rules
        .to_cleanup_rules_yaml()
        .map_err(RuleLibraryError::InvalidAiEnvelope)?;
    create_rule_draft(
        snapshot,
        display_name,
        RuleOrigin::AiGenerated,
        &content,
        RuleProvenance {
            source_label: "aiGenerated".into(),
            provider_profile_id: Some(profile_id),
            model: Some(envelope.model.clone()),
            scan_summary_hash: Some(envelope.summary_hash.clone()),
            source_url: None,
            generated_at: Some(envelope.generated_at.clone()),
            ai_draft_id: Some(envelope.draft_id.clone()),
            ai_draft_revision: Some(envelope.revision),
        },
        context,
    )
}

pub fn save_rule_draft(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    content: &str,
    provenance: RuleProvenance,
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    check_generation(snapshot, &context)?;
    let canonical = canonicalize_rule_content(content)?;
    let hash = rule_content_hash(&canonical)?;
    let mut next = snapshot.clone();
    let record = find_record_mut(&mut next, record_id)?;
    check_head(record, context.expected_head_revision_id)?;
    if record.state == RuleRecordState::Deleted {
        return Err(RuleLibraryError::InvalidInvariant(
            "deleted record cannot be edited".into(),
        ));
    }
    if record
        .pending_revision_id
        .and_then(|id| record.revisions.iter().find(|revision| revision.id == id))
        .is_some_and(|revision| revision.content_hash == hash)
    {
        return Ok(snapshot.clone());
    }
    if record.revisions.len() >= MAX_REVISIONS_PER_RECORD {
        return Err(RuleLibraryError::CapacityExceeded);
    }
    let parent = record.pending_revision_id.or(record.active_revision_id);
    let revision = new_revision(
        record.revisions.len() as u64 + 1,
        parent,
        record.active_revision_id,
        canonical,
        provenance,
        &context,
    )?;
    let from_state = record.state.clone();
    record.pending_revision_id = Some(revision.id);
    record.updated_at = context.timestamp.clone();
    record.revisions.push(revision.clone());
    record.events.push(event(
        RuleLibraryEventKind::SaveDraft,
        Some(from_state.clone()),
        from_state,
        parent,
        Some(revision.id),
        &context,
    ));
    commit_metadata(&mut next, &context);
    validate_library(&next)?;
    Ok(next)
}

pub fn validate_pending_revision(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    validated_at: String,
) -> Result<RevisionValidation, RuleLibraryError> {
    let record = snapshot
        .records
        .iter()
        .find(|record| record.id == record_id)
        .ok_or(RuleLibraryError::NotFound)?;
    let revision = pending_revision(record)?;
    if rule_content_hash(&revision.content)? != revision.content_hash {
        return Err(RuleLibraryError::InvalidHash);
    }
    let compilation =
        compile_cleanup_rules_yaml(&revision.content, compiler_source(&record.origin));
    Ok(RevisionValidation {
        content_hash: revision.content_hash.clone(),
        compiler_schema_version: RULE_COMPILER_SCHEMA_VERSION,
        validated_at,
        report: compilation.report,
    })
}

pub fn approve_pending_revision(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    expected_hash: &str,
    built_in_rules: &[CompiledCleanupRule],
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    check_generation(snapshot, &context)?;
    let mut next = snapshot.clone();
    let (pending_id, compilation) = {
        let record = next
            .records
            .iter()
            .find(|record| record.id == record_id)
            .ok_or(RuleLibraryError::NotFound)?;
        check_head(record, context.expected_head_revision_id)?;
        let revision = pending_revision(record)?;
        if revision.content_hash != expected_hash
            || rule_content_hash(&revision.content)? != expected_hash
        {
            return Err(RuleLibraryError::InvalidHash);
        }
        let compilation =
            compile_cleanup_rules_yaml(&revision.content, compiler_source(&record.origin));
        if !compilation.report.valid {
            return Err(RuleLibraryError::ValidationFailed);
        }
        (revision.id, compilation)
    };
    ensure_no_rule_id_conflict(&next, record_id, &compilation.rules, built_in_rules)?;
    let record = find_record_mut(&mut next, record_id)?;
    let from_state = record.state.clone();
    let from_revision = record.active_revision_id;
    let revision = record
        .revisions
        .iter_mut()
        .find(|revision| revision.id == pending_id)
        .ok_or(RuleLibraryError::NotFound)?;
    revision.validation = Some(RevisionValidation {
        content_hash: revision.content_hash.clone(),
        compiler_schema_version: RULE_COMPILER_SCHEMA_VERSION,
        validated_at: context.timestamp.clone(),
        report: compilation.report,
    });
    record.active_revision_id = Some(pending_id);
    record.last_approved_revision_id = Some(pending_id);
    record.pending_revision_id = None;
    record.state = RuleRecordState::Approved;
    record.deleted_at = None;
    record.updated_at = context.timestamp.clone();
    record.events.push(event(
        RuleLibraryEventKind::Approve,
        Some(from_state),
        RuleRecordState::Approved,
        from_revision,
        Some(pending_id),
        &context,
    ));
    commit_metadata(&mut next, &context);
    validate_library(&next)?;
    Ok(next)
}

pub fn disable_rule_record(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    transition_state(
        snapshot,
        record_id,
        RuleRecordState::Disabled,
        RuleLibraryEventKind::Disable,
        false,
        context,
    )
}

pub fn delete_rule_record(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    transition_state(
        snapshot,
        record_id,
        RuleRecordState::Deleted,
        RuleLibraryEventKind::Delete,
        true,
        context,
    )
}

pub fn restore_rule_record(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    transition_state(
        snapshot,
        record_id,
        RuleRecordState::Disabled,
        RuleLibraryEventKind::Restore,
        false,
        context,
    )
}

pub fn create_rollback_draft(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    revision_id: Uuid,
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    check_generation(snapshot, &context)?;
    let mut next = snapshot.clone();
    let record = find_record_mut(&mut next, record_id)?;
    check_head(record, context.expected_head_revision_id)?;
    let source = record
        .revisions
        .iter()
        .find(|revision| revision.id == revision_id)
        .cloned()
        .ok_or(RuleLibraryError::NotFound)?;
    let parent = record.pending_revision_id.or(record.active_revision_id);
    let revision = new_revision(
        record.revisions.len() as u64 + 1,
        parent,
        Some(revision_id),
        source.content,
        source.provenance,
        &context,
    )?;
    record.pending_revision_id = Some(revision.id);
    record.updated_at = context.timestamp.clone();
    record.events.push(event(
        RuleLibraryEventKind::RollbackRequested,
        Some(record.state.clone()),
        record.state.clone(),
        parent,
        Some(revision.id),
        &context,
    ));
    record.revisions.push(revision);
    commit_metadata(&mut next, &context);
    validate_library(&next)?;
    Ok(next)
}

pub fn build_active_rule_snapshot(
    snapshot: &RuleLibrarySnapshot,
    built_in_rules: &[CompiledCleanupRule],
) -> ActiveRuleSnapshot {
    let mut result = ActiveRuleSnapshot {
        library_generation: snapshot.generation,
        rules: Vec::new(),
        entries: Vec::new(),
        blocking_issues: Vec::new(),
    };
    if let Err(error) = validate_library(snapshot) {
        result
            .blocking_issues
            .push(issue(None, None, "invalidLibrary", error.to_string()));
        return result;
    }
    let mut seen: HashSet<String> = built_in_rules.iter().map(|rule| rule.id.clone()).collect();
    for record in snapshot
        .records
        .iter()
        .filter(|record| record.state == RuleRecordState::Approved)
    {
        let Some(revision_id) = record.active_revision_id else {
            continue;
        };
        let Some(revision) = record
            .revisions
            .iter()
            .find(|revision| revision.id == revision_id)
        else {
            continue;
        };
        let compilation =
            compile_cleanup_rules_yaml(&revision.content, compiler_source(&record.origin));
        if !compilation.report.valid {
            result.blocking_issues.push(issue(
                Some(record.id),
                Some(revision.id),
                "validationFailed",
                "active revision no longer passes the current compiler".into(),
            ));
            continue;
        }
        let ids: Vec<String> = compilation
            .rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect();
        if ids.iter().any(|id| seen.contains(id)) {
            result.blocking_issues.push(issue(
                Some(record.id),
                Some(revision.id),
                "ruleIdConflict",
                "active revision contains a conflicting rule identifier".into(),
            ));
            continue;
        }
        seen.extend(ids.iter().cloned());
        result.entries.push(ActiveRuleEntry {
            record_id: record.id,
            revision_id: revision.id,
            content_hash: revision.content_hash.clone(),
            rule_ids: ids,
        });
        result.rules.extend(compilation.rules);
    }
    result
}

fn ensure_no_rule_id_conflict(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    candidate: &[CompiledCleanupRule],
    built_ins: &[CompiledCleanupRule],
) -> Result<(), RuleLibraryError> {
    let candidate_ids: HashSet<&str> = candidate.iter().map(|rule| rule.id.as_str()).collect();
    if candidate_ids.len() != candidate.len()
        || built_ins
            .iter()
            .any(|rule| candidate_ids.contains(rule.id.as_str()))
    {
        return Err(RuleLibraryError::RuleIdConflict);
    }
    for record in snapshot
        .records
        .iter()
        .filter(|record| record.id != record_id && record.state == RuleRecordState::Approved)
    {
        let Some(revision) = record
            .active_revision_id
            .and_then(|id| record.revisions.iter().find(|revision| revision.id == id))
        else {
            continue;
        };
        let compilation =
            compile_cleanup_rules_yaml(&revision.content, compiler_source(&record.origin));
        if compilation
            .rules
            .iter()
            .any(|rule| candidate_ids.contains(rule.id.as_str()))
        {
            return Err(RuleLibraryError::RuleIdConflict);
        }
    }
    Ok(())
}

fn transition_state(
    snapshot: &RuleLibrarySnapshot,
    record_id: Uuid,
    target: RuleRecordState,
    kind: RuleLibraryEventKind,
    mark_deleted: bool,
    context: RuleMutationContext,
) -> Result<RuleLibrarySnapshot, RuleLibraryError> {
    check_generation(snapshot, &context)?;
    let mut next = snapshot.clone();
    let record = find_record_mut(&mut next, record_id)?;
    check_head(record, context.expected_head_revision_id)?;
    let from = record.state.clone();
    if kind == RuleLibraryEventKind::Restore && from != RuleRecordState::Deleted {
        return Err(RuleLibraryError::InvalidInvariant(
            "only deleted records can be restored".into(),
        ));
    }
    record.state = target.clone();
    if mark_deleted {
        record.active_revision_id = None;
        record.deleted_at = Some(context.timestamp.clone());
    } else {
        record.deleted_at = None;
    }
    record.updated_at = context.timestamp.clone();
    record.events.push(event(
        kind,
        Some(from),
        target,
        record.active_revision_id,
        record.active_revision_id,
        &context,
    ));
    commit_metadata(&mut next, &context);
    validate_library(&next)?;
    Ok(next)
}

fn check_generation(
    snapshot: &RuleLibrarySnapshot,
    context: &RuleMutationContext,
) -> Result<(), RuleLibraryError> {
    if snapshot.generation != context.expected_generation
        || snapshot.last_mutation_id == context.mutation_id
    {
        Err(RuleLibraryError::StaleGeneration)
    } else {
        Ok(())
    }
}

fn check_head(record: &RuleRecord, expected: Option<Uuid>) -> Result<(), RuleLibraryError> {
    let actual = record.pending_revision_id.or(record.active_revision_id);
    if actual == expected {
        Ok(())
    } else {
        Err(RuleLibraryError::StaleRevision)
    }
}

fn find_record_mut(
    snapshot: &mut RuleLibrarySnapshot,
    record_id: Uuid,
) -> Result<&mut RuleRecord, RuleLibraryError> {
    snapshot
        .records
        .iter_mut()
        .find(|record| record.id == record_id)
        .ok_or(RuleLibraryError::NotFound)
}

fn pending_revision(record: &RuleRecord) -> Result<&RuleRevision, RuleLibraryError> {
    let id = record
        .pending_revision_id
        .ok_or(RuleLibraryError::StaleRevision)?;
    record
        .revisions
        .iter()
        .find(|revision| revision.id == id)
        .ok_or(RuleLibraryError::NotFound)
}

fn new_revision(
    number: u64,
    parent_revision_id: Option<Uuid>,
    base_revision_id: Option<Uuid>,
    content: String,
    provenance: RuleProvenance,
    context: &RuleMutationContext,
) -> Result<RuleRevision, RuleLibraryError> {
    Ok(RuleRevision {
        id: Uuid::new_v4(),
        number,
        parent_revision_id,
        base_revision_id,
        content_hash: rule_content_hash(&content)?,
        content,
        provenance,
        created_at: context.timestamp.clone(),
        actor_id: context.actor_id,
        mutation_id: context.mutation_id,
        validation: None,
    })
}

fn event(
    kind: RuleLibraryEventKind,
    from_state: Option<RuleRecordState>,
    to_state: RuleRecordState,
    from_revision_id: Option<Uuid>,
    to_revision_id: Option<Uuid>,
    context: &RuleMutationContext,
) -> RuleLibraryEvent {
    RuleLibraryEvent {
        id: Uuid::new_v4(),
        kind,
        actor_id: context.actor_id,
        mutation_id: context.mutation_id,
        occurred_at: context.timestamp.clone(),
        from_state,
        to_state,
        from_revision_id,
        to_revision_id,
    }
}

fn commit_metadata(snapshot: &mut RuleLibrarySnapshot, context: &RuleMutationContext) {
    snapshot.generation += 1;
    snapshot.updated_at = context.timestamp.clone();
    snapshot.actor_id = context.actor_id;
    snapshot.last_mutation_id = context.mutation_id;
}

fn compiler_source(origin: &RuleOrigin) -> RuleSourceKind {
    if *origin == RuleOrigin::Subscription {
        RuleSourceKind::Subscription
    } else {
        RuleSourceKind::User
    }
}

fn issue(
    record_id: Option<Uuid>,
    revision_id: Option<Uuid>,
    code: &str,
    message: String,
) -> ActiveRuleIssue {
    ActiveRuleIssue {
        record_id,
        revision_id,
        code: code.into(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RULE: &str = "version: 1\nrules:\n  - id: test.cache\n    name: Test cache\n    app: Test\n    category: cache\n    level: 推荐清理\n    default: true\n    paths:\n      - '%TEMP%\\test-cache'\n    clean: contents\n    keep_days: 3\n    note: Test cache files.\n";
    const SUMMARY_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn context(generation: u64, head: Option<Uuid>) -> RuleMutationContext {
        RuleMutationContext {
            expected_generation: generation,
            expected_head_revision_id: head,
            mutation_id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            timestamp: "2026-03-14T00:00:00Z".into(),
        }
    }

    fn empty() -> RuleLibrarySnapshot {
        RuleLibrarySnapshot::empty(
            "2026-03-14T00:00:00Z".into(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
    }

    #[test]
    fn canonical_hash_normalizes_bom_and_newlines() {
        assert_eq!(
            rule_content_hash("\u{feff}a\r\nb\r").unwrap(),
            rule_content_hash("a\nb\n").unwrap()
        );
    }

    #[test]
    fn draft_is_not_active_until_approved() {
        let draft = create_rule_draft(
            &empty(),
            "Test".into(),
            RuleOrigin::Manual,
            VALID_RULE,
            RuleProvenance::manual(),
            context(0, None),
        )
        .unwrap();
        assert!(build_active_rule_snapshot(&draft, &[]).rules.is_empty());
        let record = &draft.records[0];
        let revision = pending_revision(record).unwrap();
        let approved = approve_pending_revision(
            &draft,
            record.id,
            &revision.content_hash,
            &[],
            context(draft.generation, Some(revision.id)),
        )
        .unwrap();
        assert_eq!(build_active_rule_snapshot(&approved, &[]).rules.len(), 1);
    }

    #[test]
    fn approved_ai_envelope_imports_as_provenanced_pending_draft() {
        let profile_id = Uuid::new_v4();
        let rules = crate::AiGeneratedRuleSet::parse(
            r#"{"schema_version":1,"rules":[{"id":"ai.light","tier":"light","name":"AI cache","app":"Fixture","category":"cache","paths":["%TEMP%\\ai-cache"],"clean":"contents","keep_days":7,"exclude":["*.lock"],"note":"fixture","evidence":["aggregate"],"cautions":["review"]}]}"#,
        )
        .unwrap();
        let mut draft = crate::AiRuleDraft::new(
            "draft-fixture".into(),
            SUMMARY_HASH.into(),
            crate::AiGenerationMode::SingleTier,
            Some(crate::AiRuleTier::Light),
            profile_id.to_string(),
            "fixture-model".into(),
            "2026-03-14T00:00:00Z".into(),
            rules,
        )
        .unwrap();
        draft.validate_current_revision().unwrap();
        let envelope = draft.approve(1, SUMMARY_HASH).unwrap();

        let imported =
            import_approved_ai_rule(&empty(), "AI rules".into(), &envelope, context(0, None))
                .unwrap();
        assert!(build_active_rule_snapshot(&imported, &[]).rules.is_empty());
        let record = &imported.records[0];
        assert_eq!(record.state, RuleRecordState::Draft);
        assert!(record.active_revision_id.is_none());
        let revision = pending_revision(record).unwrap();
        assert_eq!(revision.provenance.provider_profile_id, Some(profile_id));
        assert_eq!(
            revision.provenance.scan_summary_hash.as_deref(),
            Some(SUMMARY_HASH)
        );
        assert_eq!(
            revision.provenance.ai_draft_id.as_deref(),
            Some("draft-fixture")
        );
        assert_eq!(revision.provenance.ai_draft_revision, Some(1));

        let duplicate = import_approved_ai_rule(
            &imported,
            "AI rules".into(),
            &envelope,
            context(imported.generation, None),
        )
        .unwrap();
        assert_eq!(duplicate, imported);
    }

    #[test]
    fn pending_revision_keeps_old_active_rule() {
        let draft = create_rule_draft(
            &empty(),
            "Test".into(),
            RuleOrigin::Manual,
            VALID_RULE,
            RuleProvenance::manual(),
            context(0, None),
        )
        .unwrap();
        let record = &draft.records[0];
        let revision = pending_revision(record).unwrap();
        let approved = approve_pending_revision(
            &draft,
            record.id,
            &revision.content_hash,
            &[],
            context(1, Some(revision.id)),
        )
        .unwrap();
        let record = &approved.records[0];
        let edited = save_rule_draft(
            &approved,
            record.id,
            &VALID_RULE.replace("test.cache", "test.cache.v2"),
            RuleProvenance::manual(),
            context(2, record.active_revision_id),
        )
        .unwrap();
        assert_eq!(
            build_active_rule_snapshot(&edited, &[]).rules[0].id,
            "test.cache"
        );
    }

    #[test]
    fn tampered_content_is_rejected() {
        let mut draft = create_rule_draft(
            &empty(),
            "Test".into(),
            RuleOrigin::Manual,
            VALID_RULE,
            RuleProvenance::manual(),
            context(0, None),
        )
        .unwrap();
        draft.records[0].revisions[0].content.push_str("# tampered");
        assert_eq!(validate_library(&draft), Err(RuleLibraryError::InvalidHash));
    }

    #[test]
    fn approval_rejects_stale_generation_and_duplicate_builtin_id() {
        let draft = create_rule_draft(
            &empty(),
            "Test".into(),
            RuleOrigin::Manual,
            VALID_RULE,
            RuleProvenance::manual(),
            context(0, None),
        )
        .unwrap();
        let record = &draft.records[0];
        let revision = pending_revision(record).unwrap();
        assert_eq!(
            approve_pending_revision(
                &draft,
                record.id,
                &revision.content_hash,
                &[],
                context(0, Some(revision.id))
            ),
            Err(RuleLibraryError::StaleGeneration)
        );
        let built_in = compile_cleanup_rules_yaml(VALID_RULE, RuleSourceKind::BuiltIn).rules;
        assert_eq!(
            approve_pending_revision(
                &draft,
                record.id,
                &revision.content_hash,
                &built_in,
                context(1, Some(revision.id))
            ),
            Err(RuleLibraryError::RuleIdConflict)
        );
    }

    #[test]
    fn rollback_creates_pending_revision_without_switching_active() {
        let draft = create_rule_draft(
            &empty(),
            "Test".into(),
            RuleOrigin::Manual,
            VALID_RULE,
            RuleProvenance::manual(),
            context(0, None),
        )
        .unwrap();
        let record = &draft.records[0];
        let first_id = record.pending_revision_id.unwrap();
        let approved = approve_pending_revision(
            &draft,
            record.id,
            &record.revisions[0].content_hash,
            &[],
            context(1, Some(first_id)),
        )
        .unwrap();
        let rolled =
            create_rollback_draft(&approved, record.id, first_id, context(2, Some(first_id)))
                .unwrap();
        assert_eq!(rolled.records[0].active_revision_id, Some(first_id));
        assert_ne!(rolled.records[0].pending_revision_id, Some(first_id));
    }
}

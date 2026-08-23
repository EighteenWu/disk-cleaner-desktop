use crate::credentials::{CredentialStore, SecretString};
use cleaner_core::{
    AiGeneratedRuleSet, AiGenerationMode, AiRuleTier, RedactedScanSummary, RuleCompilation,
};
use reqwest::{header, redirect::Policy, Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const PROFILE_FILE: &[&str] = &["config", "ai-provider-profiles.json"];
const PROFILE_SCHEMA_VERSION: u16 = 1;
const MAX_PROFILES: usize = 16;
const MAX_PROVIDER_RESPONSE_BYTES: u64 = 256 * 1024;
/// Relay gateways routinely expose several hundred models, so the catalog gets
/// a wider ceiling than a rule-generation reply.
const MAX_MODEL_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_MODELS: usize = 512;
const MAX_ERROR_BODY_BYTES: usize = 2048;
const MAX_ERROR_SNIPPET_CHARS: usize = 240;
const MIN_TIMEOUT_MS: u64 = 5_000;
const MAX_TIMEOUT_MS: u64 = 600_000;
const CONNECT_TIMEOUT_MS: u64 = 15_000;
const PROGRESS_EMIT_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderKind {
    OpenAiCompatible,
    AnthropicCompatible,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderProfile {
    pub id: String,
    pub kind: ProviderKind,
    pub display_name: String,
    pub base_url: String,
    pub model: String,
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub credential_present: bool,
}

/// Model discovery runs against the form the user is still editing, which is
/// why it takes a loose draft instead of a saved `ProviderProfile`: the profile
/// cannot be persisted until a model is chosen.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderModelQuery {
    pub kind: ProviderKind,
    pub base_url: String,
    pub timeout_ms: u64,
    /// Used to fall back to the stored credential when no key was retyped.
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub api_key: Option<SecretString>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderModel {
    pub id: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderConnectionResult {
    pub model_count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderProfileDocument {
    schema_version: u16,
    profiles: Vec<ProviderProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderGenerationRequest {
    pub summary: RedactedScanSummary,
    /// Absent on older callers: treat as `singleTier` when `target_tier` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_mode: Option<AiGenerationMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_tier: Option<AiRuleTier>,
}

impl ProviderGenerationRequest {
    /// Resolves legacy `{ targetTier }` payloads and the new explicit mode contract.
    pub fn resolved_mode(&self) -> Result<(AiGenerationMode, Option<AiRuleTier>), String> {
        match self.generation_mode {
            Some(AiGenerationMode::AllTiers) => {
                if self.target_tier.is_some() {
                    return Err("全部档位模式不得指定单一目标档位。".to_string());
                }
                Ok((AiGenerationMode::AllTiers, None))
            }
            Some(AiGenerationMode::SingleTier) => {
                let tier = self
                    .target_tier
                    .ok_or_else(|| "单档模式必须指定目标档位。".to_string())?;
                Ok((AiGenerationMode::SingleTier, Some(tier)))
            }
            None => {
                let tier = self.target_tier.ok_or_else(|| {
                    "请指定 generationMode，或提供兼容的 targetTier。".to_string()
                })?;
                Ok((AiGenerationMode::SingleTier, Some(tier)))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderGenerationResponse {
    pub request_id: Option<String>,
    pub rules: AiGeneratedRuleSet,
    pub compilation: RuleCompilation,
}

/// Lightweight completion probe — same credential surface as connection test, plus model.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderGenerationProbeQuery {
    pub kind: ProviderKind,
    pub base_url: String,
    pub timeout_ms: u64,
    pub model: String,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub api_key: Option<SecretString>,
}

impl ProviderGenerationProbeQuery {
    pub fn validate(&self) -> Result<Url, String> {
        if let Some(profile_id) = &self.profile_id {
            validate_id(profile_id)?;
        }
        validate_short_text("模型名", &self.model)?;
        validate_timeout(self.timeout_ms)?;
        validate_base_url(&self.base_url)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderGenerationProbeResult {
    pub ok: bool,
    pub latency_ms: u64,
    pub request_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiGenerationProgress {
    pub elapsed_ms: u64,
    pub output_chars: usize,
    pub bytes_received: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderError {
    pub category: ProviderErrorCategory,
    pub message: String,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderErrorCategory {
    Configuration,
    CredentialMissing,
    Authentication,
    RateLimited,
    Timeout,
    Cancelled,
    Network,
    ResponseTooLarge,
    InvalidSchema,
    Provider,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProviderError {}

impl ProviderProfile {
    pub fn validate(&self) -> Result<Url, String> {
        validate_id(&self.id)?;
        validate_short_text("显示名", &self.display_name)?;
        validate_short_text("模型名", &self.model)?;
        validate_timeout(self.timeout_ms)?;
        validate_base_url(&self.base_url)
    }
}

impl ProviderModelQuery {
    pub fn validate(&self) -> Result<Url, String> {
        if let Some(profile_id) = &self.profile_id {
            validate_id(profile_id)?;
        }
        validate_timeout(self.timeout_ms)?;
        validate_base_url(&self.base_url)
    }
}

fn validate_timeout(timeout_ms: u64) -> Result<(), String> {
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err("Provider 超时必须介于 5 秒和 600 秒之间。".to_string());
    }
    Ok(())
}

fn connect_timeout(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.min(CONNECT_TIMEOUT_MS))
}

fn idle_timeout(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.min(60_000).max(5_000.min(timeout_ms)))
}

fn validate_base_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value.trim()).map_err(|_| "Provider Base URL 无效。".to_string())?;
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Provider Base URL 不得包含认证信息、query 或 fragment。".to_string());
    }
    let local_test = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !(cfg!(debug_assertions) && url.scheme() == "http" && local_test)
    {
        return Err("Provider Base URL 必须使用 HTTPS。".to_string());
    }
    if url.host_str().is_none() {
        return Err("Provider Base URL 缺少 host。".to_string());
    }
    Ok(url)
}

pub fn read_profiles(
    root: &Path,
    credentials: &dyn CredentialStore,
) -> Result<Vec<ProviderProfile>, String> {
    let path = storage_path(root);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).map_err(|error| format!("读取 AI Provider 配置失败：{error}"))?;
    if bytes.len() > 256 * 1024 {
        return Err("AI Provider 配置文件超过上限。".to_string());
    }
    let mut document: ProviderProfileDocument = serde_json::from_slice(&bytes)
        .map_err(|error| format!("解析 AI Provider 配置失败：{error}"))?;
    if document.schema_version != PROFILE_SCHEMA_VERSION || document.profiles.len() > MAX_PROFILES {
        return Err("AI Provider 配置版本或数量无效。".to_string());
    }
    let mut ids = std::collections::HashSet::new();
    for profile in &mut document.profiles {
        if profile.timeout_ms == 45_000 {
            profile.timeout_ms = 180_000;
        }
        profile.validate()?;
        if !ids.insert(profile.id.clone()) {
            return Err("AI Provider 配置包含重复 ID。".to_string());
        }
        profile.credential_present = credentials.exists(&profile.id)?;
    }
    Ok(document.profiles)
}

pub fn save_profile(
    root: &Path,
    mut profile: ProviderProfile,
    credentials: &dyn CredentialStore,
) -> Result<Vec<ProviderProfile>, String> {
    profile.validate()?;
    let mut profiles = read_profiles(root, credentials)?;
    profile.credential_present = credentials.exists(&profile.id)?;
    if let Some(existing) = profiles.iter_mut().find(|value| value.id == profile.id) {
        *existing = profile;
    } else {
        if profiles.len() >= MAX_PROFILES {
            return Err("AI Provider 配置数量已达上限。".to_string());
        }
        profiles.push(profile);
    }
    write_profiles(root, &profiles)?;
    Ok(profiles)
}

pub fn delete_profile(
    root: &Path,
    profile_id: &str,
    credentials: &dyn CredentialStore,
) -> Result<Vec<ProviderProfile>, String> {
    validate_id(profile_id)?;
    let mut profiles = read_profiles(root, credentials)?;
    profiles.retain(|value| value.id != profile_id);
    credentials.delete(profile_id)?;
    write_profiles(root, &profiles)?;
    Ok(profiles)
}

pub fn save_credential(
    profile_id: &str,
    secret: String,
    credentials: &dyn CredentialStore,
) -> Result<(), String> {
    let secret = SecretString::new(secret)?;
    validate_id(profile_id)?;
    credentials.save(profile_id, secret)
}

fn write_profiles(root: &Path, profiles: &[ProviderProfile]) -> Result<(), String> {
    let path = storage_path(root);
    let parent = path
        .parent()
        .ok_or_else(|| "AI Provider 配置目录无效。".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("创建 AI Provider 配置目录失败：{error}"))?;
    let mut stored = profiles.to_vec();
    for profile in &mut stored {
        profile.credential_present = false;
    }
    let content = serde_json::to_vec_pretty(&ProviderProfileDocument {
        schema_version: PROFILE_SCHEMA_VERSION,
        profiles: stored,
    })
    .map_err(|error| format!("序列化 AI Provider 配置失败：{error}"))?;
    let temporary = parent.join(format!(".ai-provider-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| format!("创建 AI Provider 临时配置失败：{error}"))?;
    let result = (|| {
        file.write_all(&content)
            .map_err(|error| format!("写入 AI Provider 临时配置失败：{error}"))?;
        file.flush()
            .map_err(|error| format!("刷新 AI Provider 临时配置失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步 AI Provider 临时配置失败：{error}"))?;
        drop(file);
        serde_json::from_slice::<ProviderProfileDocument>(
            &fs::read(&temporary)
                .map_err(|error| format!("复核 AI Provider 临时配置失败：{error}"))?,
        )
        .map_err(|error| format!("复核 AI Provider 临时配置失败：{error}"))?;
        if path.exists() {
            let backup = path.with_extension("json.bak");
            fs::copy(&path, backup)
                .map_err(|error| format!("备份 AI Provider 配置失败：{error}"))?;
        }
        atomic_replace(&temporary, &path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
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
            "原子替换 AI Provider 配置失败：{}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), String> {
    fs::rename(source, destination)
        .map_err(|error| format!("原子替换 AI Provider 配置失败：{error}"))
}

pub async fn generate_rules(
    profile: &ProviderProfile,
    request: &ProviderGenerationRequest,
    credentials: &dyn CredentialStore,
    mut on_progress: impl FnMut(AiGenerationProgress) + Send,
) -> Result<ProviderGenerationResponse, ProviderError> {
    let base_url = profile
        .validate()
        .map_err(|message| provider_error(ProviderErrorCategory::Configuration, message))?;
    if request.summary.validate_for_provider().is_err() {
        return Err(provider_error(
            ProviderErrorCategory::Configuration,
            "脱敏摘要无效，请重新生成发送预览。",
        ));
    }
    let (generation_mode, target_tier) = request
        .resolved_mode()
        .map_err(|message| provider_error(ProviderErrorCategory::Configuration, message))?;
    let secret = credentials
        .read(&profile.id)
        .map_err(|message| provider_error(ProviderErrorCategory::CredentialMissing, message))?
        .ok_or_else(|| {
            provider_error(
                ProviderErrorCategory::CredentialMissing,
                "尚未保存该 Provider 的 API Key。",
            )
        })?;
    let endpoint = endpoint(&base_url, profile.kind)?;
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(connect_timeout(profile.timeout_ms))
        .timeout(Duration::from_millis(profile.timeout_ms))
        .build()
        .map_err(|_| {
            provider_error(
                ProviderErrorCategory::Configuration,
                "创建 Provider HTTP 客户端失败。",
            )
        })?;
    let request_json = serde_json::to_string(request).map_err(|_| {
        provider_error(ProviderErrorCategory::Configuration, "序列化脱敏摘要失败。")
    })?;
    let prompt = format!("{GENERATION_USER_PREFIX}\n{request_json}");
    let system = generation_system_prompt(generation_mode, target_tier);
    let output_schema = provider_output_schema();

    let builder = match profile.kind {
        ProviderKind::OpenAiCompatible => client
            .post(endpoint)
            .bearer_auth(secret.expose().map_err(|message| {
                provider_error(ProviderErrorCategory::CredentialMissing, message)
            })?)
            .json(&openai_chat_payload(
                &profile.model,
                &system,
                &prompt,
                true,
                &base_url,
            )),
        ProviderKind::AnthropicCompatible => client
            .post(endpoint)
            .header(
                "x-api-key",
                secret.expose().map_err(|message| {
                    provider_error(ProviderErrorCategory::CredentialMissing, message)
                })?,
            )
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": profile.model,
                "max_tokens": 8192,
                "stream": true,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
                "tools": [{
                    "name": "submit_cleanup_rules",
                    "description": "Submit strict structured cleanup rule drafts.",
                    "input_schema": output_schema
                }],
                "tool_choice": {"type": "tool", "name": "submit_cleanup_rules"}
            })),
    };
    let response = builder.send().await.map_err(map_reqwest_error)?;
    let (request_id, response) = accept_provider_response(
        response,
        "generate",
        Some(profile.model.as_str()),
        Some(prompt.len()),
    )
    .await?;
    if response.content_length().unwrap_or(0) > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(provider_error(
            ProviderErrorCategory::ResponseTooLarge,
            "Provider 响应超过 256 KB 上限。",
        ));
    }
    let structured = collect_generation_output(
        response,
        profile.kind,
        Duration::from_millis(profile.timeout_ms),
        idle_timeout(profile.timeout_ms),
        &mut on_progress,
    )
    .await?;
    let normalized = normalize_tier_alias(&structured)?;
    let rules = AiGeneratedRuleSet::parse(&normalized)
        .map_err(|message| provider_error(ProviderErrorCategory::InvalidSchema, message))?;
    if let Some(tier) = target_tier {
        if rules.rules.iter().any(|rule| rule.tier != tier) {
            return Err(provider_error(
                ProviderErrorCategory::InvalidSchema,
                "Provider 返回了目标档位之外的规则。",
            ));
        }
    }
    let compilation = rules
        .compile()
        .map_err(|message| provider_error(ProviderErrorCategory::InvalidSchema, message))?;
    if !compilation.report.valid {
        return Err(provider_error(
            ProviderErrorCategory::InvalidSchema,
            "生成规则未通过本地安全校验。",
        ));
    }
    Ok(ProviderGenerationResponse {
        request_id,
        rules,
        compilation,
    })
}

const GENERATION_PROMPT_VERSION: &str = "v1";
const GENERATION_USER_PREFIX: &str = "Draft cleanup rules from this redacted scan summary.";
const GENERATION_RULE_EXAMPLE: &str = r#"{"schema_version":1,"rules":[{"id":"cache.temp","tier":"light","name":"Temp cache","app":"Windows","category":"cache","paths":["%TEMP%\\AppCache"],"clean":"contents","keep_days":7,"exclude":["*.lock"],"note":"cache","evidence":["aggregate"],"cautions":["review"]}]}"#;

fn generation_system_prompt(mode: AiGenerationMode, target_tier: Option<AiRuleTier>) -> String {
    let scope = match mode {
        AiGenerationMode::AllTiers => {
            "Generate light, medium, and/or heavy cleanup rule drafts in one response. Each rule must set tier to light, medium, or heavy. Empty tiers are allowed; at least one rule is required.".to_string()
        }
        AiGenerationMode::SingleTier => {
            let tier = match target_tier.expect("singleTier requires target") {
                AiRuleTier::Light => "light",
                AiRuleTier::Medium => "medium",
                AiRuleTier::Heavy => "heavy",
            };
            format!("Generate only {tier} cleanup rule drafts. Every rule tier must be {tier}.")
        }
    };
    format!(
        "cleanup-rule json contract {GENERATION_PROMPT_VERSION}. Return one json object only, no markdown, no extra keys. {scope} Paths must use environment-variable templates only (%LOCALAPPDATA%, %TEMP%, %APPDATA%). Never infer personal paths. clean must be contents, files, recycle, or manual — never delete. Prefer contents for cache directories. Required fields: schema_version and rules with id,tier,name,app,category,paths,clean,keep_days,exclude,note,evidence,cautions. Example json: {GENERATION_RULE_EXAMPLE}"
    )
}

fn thinking_disabled_host(base_url: &Url) -> bool {
    base_url
        .host_str()
        .map(|host| {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            host == "api.deepseek.com" || host.ends_with(".api.deepseek.com")
        })
        .unwrap_or(false)
}

/// DeepSeek and typical OpenAI-compatible relays accept `json_object` only.
/// `json_schema` / structured outputs is OpenAI-specific and returns HTTP 400
/// on those gateways (e.g. packycode + deepseek-v4-flash). Local compile still
/// enforces the cleanup-rule schema. `thinking.disabled` is DeepSeek-host only;
/// OpenAI returns 400 on unknown fields.
fn openai_chat_payload(
    model: &str,
    system: &str,
    user: &str,
    stream: bool,
    base_url: &Url,
) -> Value {
    let mut payload = json!({
        "model": model,
        "stream": stream,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        "response_format": { "type": "json_object" }
    });
    if thinking_disabled_host(base_url) {
        payload["thinking"] = json!({ "type": "disabled" });
    }
    payload
}

async fn collect_generation_output(
    mut response: reqwest::Response,
    kind: ProviderKind,
    overall: Duration,
    idle: Duration,
    on_progress: &mut (impl FnMut(AiGenerationProgress) + Send),
) -> Result<String, ProviderError> {
    let started = Instant::now();
    let mut bytes = Vec::new();
    let mut last_emit = Instant::now() - PROGRESS_EMIT_INTERVAL;
    let mut emit = |bytes_len: usize, output_chars: usize, force: bool| {
        if force || last_emit.elapsed() >= PROGRESS_EMIT_INTERVAL {
            last_emit = Instant::now();
            on_progress(AiGenerationProgress {
                elapsed_ms: started.elapsed().as_millis() as u64,
                output_chars,
                bytes_received: bytes_len,
            });
        }
    };

    loop {
        if started.elapsed() > overall {
            return Err(provider_error(
                ProviderErrorCategory::Timeout,
                "Provider 请求超时。",
            ));
        }
        let wait = idle.min(overall.saturating_sub(started.elapsed()));
        let wait = if wait.is_zero() {
            Duration::from_millis(1)
        } else {
            wait
        };
        let chunk = tokio::time::timeout(wait, response.chunk())
            .await
            .map_err(|_| provider_error(ProviderErrorCategory::Timeout, "Provider 请求超时。"))?
            .map_err(map_reqwest_error)?;
        let Some(chunk) = chunk else {
            break;
        };
        bytes.extend_from_slice(&chunk);
        if bytes.len() as u64 > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(provider_error(
                ProviderErrorCategory::ResponseTooLarge,
                "Provider 响应超过 256 KB 上限。",
            ));
        }
        let parsed = parse_generation_buffer(kind, &bytes)?;
        emit(bytes.len(), parsed.chars().count(), false);
    }

    let structured = finalize_generation_buffer(kind, &bytes)?;
    emit(bytes.len(), structured.chars().count(), true);
    Ok(structured)
}

fn parse_generation_buffer(kind: ProviderKind, bytes: &[u8]) -> Result<String, ProviderError> {
    let text = String::from_utf8_lossy(bytes);
    if looks_like_sse(&text) {
        parse_sse_output(kind, &text, false)
    } else {
        Ok(String::new())
    }
}

fn finalize_generation_buffer(kind: ProviderKind, bytes: &[u8]) -> Result<String, ProviderError> {
    if bytes.is_empty() {
        return Err(provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 响应为空。",
        ));
    }
    let text = String::from_utf8_lossy(bytes);
    if looks_like_sse(&text) {
        return parse_sse_output(kind, &text, true);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 响应不是有效 JSON。",
        )
    })?;
    extract_content(kind, &value)
}

fn looks_like_sse(text: &str) -> bool {
    let trimmed = text.strip_prefix('\u{feff}').unwrap_or(text).trim_start();
    trimmed.starts_with("data:") || trimmed.starts_with("event:")
}

fn parse_sse_output(
    kind: ProviderKind,
    text: &str,
    include_tail: bool,
) -> Result<String, ProviderError> {
    let mut output = String::new();
    let mut rest = text;
    loop {
        let Some((event, remaining)) = split_sse_event(rest) else {
            if include_tail {
                apply_sse_event(kind, rest, &mut output)?;
            }
            break;
        };
        rest = remaining;
        apply_sse_event(kind, event, &mut output)?;
    }
    Ok(output)
}

fn split_sse_event(text: &str) -> Option<(&str, &str)> {
    if let Some(index) = text.find("\r\n\r\n") {
        return Some((&text[..index], &text[index + 4..]));
    }
    if let Some(index) = text.find("\n\n") {
        return Some((&text[..index], &text[index + 2..]));
    }
    None
}

fn apply_sse_event(
    kind: ProviderKind,
    event: &str,
    output: &mut String,
) -> Result<(), ProviderError> {
    for line in event.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        apply_sse_json(kind, data, output)?;
    }
    Ok(())
}

fn apply_sse_json(
    kind: ProviderKind,
    data: &str,
    output: &mut String,
) -> Result<(), ProviderError> {
    let value: Value = serde_json::from_str(data).map_err(|_| {
        provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 流式响应不是有效 JSON。",
        )
    })?;
    if value.get("error").is_some() {
        let snippet = extract_provider_error_text(data);
        return Err(provider_error(
            ProviderErrorCategory::Provider,
            snippet.unwrap_or_else(|| "Provider 流式响应返回错误。".to_string()),
        ));
    }
    match kind {
        ProviderKind::OpenAiCompatible => {
            if let Some(content) = value
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
            {
                output.push_str(content);
            } else if output.is_empty() {
                if let Some(content) = value
                    .pointer("/choices/0/message/content")
                    .and_then(Value::as_str)
                {
                    output.push_str(content);
                }
            }
        }
        ProviderKind::AnthropicCompatible => match value.get("type").and_then(Value::as_str) {
            Some("content_block_delta") => {
                let delta = value.get("delta");
                let delta_type = delta
                    .and_then(|item| item.get("type"))
                    .and_then(Value::as_str);
                if delta_type == Some("text_delta") {
                    if let Some(text) = delta
                        .and_then(|item| item.get("text"))
                        .and_then(Value::as_str)
                    {
                        output.push_str(text);
                    }
                } else if delta_type == Some("input_json_delta") {
                    if let Some(partial) = delta
                        .and_then(|item| item.get("partial_json"))
                        .and_then(Value::as_str)
                    {
                        output.push_str(partial);
                    }
                }
            }
            Some("content_block_start") => {
                if let Some(input) = value.pointer("/content_block/input") {
                    if !input.is_null() && input != &json!({}) {
                        if let Ok(text) = serde_json::to_string(input) {
                            if output.is_empty() {
                                output.push_str(&text);
                            }
                        }
                    }
                }
            }
            _ => {}
        },
    }
    Ok(())
}

fn provider_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "rules"],
        "properties": {
            "schema_version": {"type": "integer", "const": 1},
            "rules": {
                "type": "array",
                "minItems": 1,
                "maxItems": 96,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "tier", "name", "app", "category", "paths", "clean", "keep_days", "exclude", "note", "evidence", "cautions"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1, "maxLength": 128},
                        "tier": {"type": "string", "enum": ["light", "medium", "heavy"]},
                        "name": {"type": "string", "minLength": 1, "maxLength": 512},
                        "app": {"type": "string", "minLength": 1, "maxLength": 512},
                        "category": {"type": "string", "minLength": 1, "maxLength": 512},
                        "paths": {"type": "array", "minItems": 1, "maxItems": 16, "items": {"type": "string", "minLength": 1, "maxLength": 1024}},
                        "clean": {"type": "string", "enum": ["contents", "files", "recycle", "manual"]},
                        "keep_days": {"type": "integer", "minimum": 0, "maximum": 365},
                        "exclude": {"type": "array", "maxItems": 32, "items": {"type": "string", "minLength": 1, "maxLength": 1024}},
                        "note": {"type": "string", "minLength": 1, "maxLength": 512},
                        "evidence": {"type": "array", "maxItems": 8, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                        "cautions": {"type": "array", "maxItems": 8, "items": {"type": "string", "minLength": 1, "maxLength": 512}}
                    }
                }
            }
        }
    })
}

fn probe_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["ok"],
        "properties": {
            "ok": {"type": "boolean", "const": true}
        }
    })
}

pub async fn probe_generation(
    mut query: ProviderGenerationProbeQuery,
    credentials: &dyn CredentialStore,
) -> Result<ProviderGenerationProbeResult, ProviderError> {
    let started = Instant::now();
    let base_url = query
        .validate()
        .map_err(|message| provider_error(ProviderErrorCategory::Configuration, message))?;
    let secret = resolve_probe_secret(&mut query, credentials)?;
    let endpoint = endpoint(&base_url, query.kind)?;
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(connect_timeout(query.timeout_ms))
        .timeout(Duration::from_millis(query.timeout_ms))
        .build()
        .map_err(|_| {
            provider_error(
                ProviderErrorCategory::Configuration,
                "创建 Provider HTTP 客户端失败。",
            )
        })?;
    let system =
        "Return JSON only matching {\"ok\":true}. Do not include other fields or explanation.";
    let schema = probe_output_schema();
    let builder = match query.kind {
        ProviderKind::OpenAiCompatible => client
            .post(endpoint)
            .bearer_auth(secret.expose().map_err(|message| {
                provider_error(ProviderErrorCategory::CredentialMissing, message)
            })?)
            .json(&openai_chat_payload(
                &query.model,
                system,
                "ping",
                true,
                &base_url,
            )),
        ProviderKind::AnthropicCompatible => client
            .post(endpoint)
            .header(
                "x-api-key",
                secret.expose().map_err(|message| {
                    provider_error(ProviderErrorCategory::CredentialMissing, message)
                })?,
            )
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": query.model,
                "max_tokens": 64,
                "stream": true,
                "system": system,
                "messages": [{"role": "user", "content": "ping"}],
                "tools": [{
                    "name": "submit_probe",
                    "description": "Confirm the generation path works.",
                    "input_schema": schema
                }],
                "tool_choice": {"type": "tool", "name": "submit_probe"}
            })),
    };
    let response = builder.send().await.map_err(map_reqwest_error)?;
    let (request_id, response) =
        accept_provider_response(response, "probe", Some(query.model.as_str()), None).await?;
    if response.content_length().unwrap_or(0) > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(provider_error(
            ProviderErrorCategory::ResponseTooLarge,
            "Provider 响应超过 256 KB 上限。",
        ));
    }
    let structured = collect_generation_output(
        response,
        query.kind,
        Duration::from_millis(query.timeout_ms),
        idle_timeout(query.timeout_ms),
        &mut |_| {},
    )
    .await?;
    let parsed: Value = serde_json::from_str(&structured).map_err(|_| {
        provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 探活内容不是有效 JSON。",
        )
    })?;
    if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 探活未返回 ok:true。",
        ));
    }
    Ok(ProviderGenerationProbeResult {
        ok: true,
        latency_ms: started.elapsed().as_millis() as u64,
        request_id,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderRoute {
    Completion,
    Models,
}

fn endpoint(base: &Url, kind: ProviderKind) -> Result<Url, ProviderError> {
    route_endpoint(base, kind, ProviderRoute::Completion)
}

fn route_endpoint(
    base: &Url,
    kind: ProviderKind,
    route: ProviderRoute,
) -> Result<Url, ProviderError> {
    let suffix = match (kind, route) {
        (ProviderKind::OpenAiCompatible, ProviderRoute::Completion) => "v1/chat/completions",
        (ProviderKind::AnthropicCompatible, ProviderRoute::Completion) => "v1/messages",
        (_, ProviderRoute::Models) => "v1/models",
    };
    // Relay gateways are commonly pasted in with the version segment already
    // attached ("https://host/v1"), which would otherwise yield "/v1/v1/models".
    let mut value = base
        .as_str()
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .to_string();
    value.push('/');
    value.push_str(suffix);
    Url::parse(&value).map_err(|_| {
        provider_error(
            ProviderErrorCategory::Configuration,
            "Provider endpoint 无效。",
        )
    })
}

pub async fn list_models(
    mut query: ProviderModelQuery,
    credentials: &dyn CredentialStore,
) -> Result<Vec<ProviderModel>, ProviderError> {
    let base_url = query
        .validate()
        .map_err(|message| provider_error(ProviderErrorCategory::Configuration, message))?;
    let secret = resolve_secret(&mut query, credentials)?;
    let endpoint = route_endpoint(&base_url, query.kind, ProviderRoute::Models)?;
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(connect_timeout(query.timeout_ms))
        .timeout(Duration::from_millis(query.timeout_ms))
        .build()
        .map_err(|_| {
            provider_error(
                ProviderErrorCategory::Configuration,
                "构建 Provider HTTP 客户端失败。",
            )
        })?;
    let exposed = secret
        .expose()
        .map_err(|message| provider_error(ProviderErrorCategory::CredentialMissing, message))?;
    let builder = match query.kind {
        ProviderKind::OpenAiCompatible => client.get(endpoint).bearer_auth(exposed),
        ProviderKind::AnthropicCompatible => client
            .get(endpoint)
            .header("x-api-key", exposed)
            .header("anthropic-version", "2023-06-01"),
    };
    let response = builder.send().await.map_err(map_reqwest_error)?;
    let (_request_id, response) = accept_provider_response(response, "models", None, None).await?;
    if response.content_length().unwrap_or(0) > MAX_MODEL_RESPONSE_BYTES {
        return Err(provider_error(
            ProviderErrorCategory::ResponseTooLarge,
            "Provider 模型列表超出 1 MB 上限。",
        ));
    }
    let bytes = response.bytes().await.map_err(map_reqwest_error)?;
    if bytes.len() as u64 > MAX_MODEL_RESPONSE_BYTES {
        return Err(provider_error(
            ProviderErrorCategory::ResponseTooLarge,
            "Provider 模型列表超出 1 MB 上限。",
        ));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 模型列表不是有效 JSON。",
        )
    })?;
    let models = parse_models(&value);
    if models.is_empty() {
        return Err(provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 未返回任何可用模型。",
        ));
    }
    Ok(models)
}

pub async fn test_connection(
    query: ProviderModelQuery,
    credentials: &dyn CredentialStore,
) -> Result<ProviderConnectionResult, ProviderError> {
    let models = list_models(query, credentials).await?;
    Ok(ProviderConnectionResult {
        model_count: models.len(),
    })
}

fn resolve_secret(
    query: &mut ProviderModelQuery,
    credentials: &dyn CredentialStore,
) -> Result<SecretString, ProviderError> {
    resolve_credential(
        query.api_key.take(),
        query.profile_id.as_deref(),
        credentials,
    )
}

fn resolve_probe_secret(
    query: &mut ProviderGenerationProbeQuery,
    credentials: &dyn CredentialStore,
) -> Result<SecretString, ProviderError> {
    resolve_credential(
        query.api_key.take(),
        query.profile_id.as_deref(),
        credentials,
    )
}

fn resolve_credential(
    api_key: Option<SecretString>,
    profile_id: Option<&str>,
    credentials: &dyn CredentialStore,
) -> Result<SecretString, ProviderError> {
    if let Some(api_key) = api_key {
        return Ok(api_key);
    }
    let profile_id = profile_id.ok_or_else(|| {
        provider_error(
            ProviderErrorCategory::CredentialMissing,
            "请填写 API Key，或先保存该 Provider 配置。",
        )
    })?;
    credentials
        .read(profile_id)
        .map_err(|message| provider_error(ProviderErrorCategory::CredentialMissing, message))?
        .ok_or_else(|| {
            provider_error(
                ProviderErrorCategory::CredentialMissing,
                "尚未保存该 Provider 的 API Key。",
            )
        })
}

/// Gateways disagree on the envelope: OpenAI and most relays answer
/// `{"data":[{"id":...}]}`, Anthropic adds `display_name`, and a few return a
/// bare array or plain strings. Accept all of them rather than guessing.
fn parse_models(value: &Value) -> Vec<ProviderModel> {
    let items = value
        .get("data")
        .or_else(|| value.get("models"))
        .and_then(Value::as_array)
        .or_else(|| value.as_array());
    let Some(items) = items else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    let mut models = Vec::new();
    for item in items {
        let id = match item {
            Value::String(text) => Some(text.as_str()),
            _ => item
                .get("id")
                .or_else(|| item.get("model"))
                .or_else(|| item.get("name"))
                .and_then(Value::as_str),
        };
        let Some(id) = id.map(str::trim).filter(|id| !id.is_empty()) else {
            continue;
        };
        if id.chars().count() > 256 || !seen.insert(id.to_string()) {
            continue;
        }
        let display_name = item
            .get("display_name")
            .or_else(|| item.get("displayName"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty() && name.chars().count() <= 256)
            .map(str::to_string);
        models.push(ProviderModel {
            id: id.to_string(),
            display_name,
        });
        if models.len() >= MAX_MODELS {
            break;
        }
    }
    models.sort_by(|left, right| left.id.cmp(&right.id));
    models
}

fn extract_content(kind: ProviderKind, value: &Value) -> Result<String, ProviderError> {
    let content = match kind {
        ProviderKind::OpenAiCompatible => value
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .map(str::to_string),
        ProviderKind::AnthropicCompatible => {
            let items = value.get("content").and_then(Value::as_array);
            items
                .and_then(|items| {
                    items.iter().find(|item| {
                        item.get("type").and_then(Value::as_str) == Some("tool_use")
                            && matches!(
                                item.get("name").and_then(Value::as_str),
                                Some("submit_cleanup_rules" | "submit_probe")
                            )
                    })
                })
                .and_then(|item| item.get("input"))
                .and_then(|input| serde_json::to_string(input).ok())
                .or_else(|| {
                    items
                        .and_then(|items| {
                            items.iter().find(|item| {
                                item.get("type").and_then(Value::as_str) == Some("text")
                            })
                        })
                        .and_then(|item| item.get("text"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
        }
    };
    content
        .map(|value| unwrap_json_content(&value))
        .ok_or_else(|| {
            provider_error(
                ProviderErrorCategory::InvalidSchema,
                "Provider 响应缺少结构化内容。",
            )
        })
}

fn unwrap_json_content(content: &str) -> String {
    let trimmed = content.trim();
    if serde_json::from_str::<Value>(trimmed).is_ok() {
        return trimmed.to_string();
    }
    let unfenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```JSON"))
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed)
        .trim();
    unfenced
        .strip_suffix("```")
        .unwrap_or(unfenced)
        .trim()
        .to_string()
}

fn normalize_tier_alias(content: &str) -> Result<String, ProviderError> {
    let mut value: Value = serde_json::from_str(content).map_err(|_| {
        provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 规则内容不是有效 JSON。",
        )
    })?;
    if let Some(rules) = value.get_mut("rules").and_then(Value::as_array_mut) {
        for rule in rules {
            if rule.get("tier").and_then(Value::as_str) == Some("review_required") {
                rule["tier"] = Value::String("heavy".to_string());
            }
        }
    }
    serde_json::to_string(&value).map_err(|_| {
        provider_error(
            ProviderErrorCategory::InvalidSchema,
            "Provider 规则内容规范化失败。",
        )
    })
}

async fn accept_provider_response(
    response: reqwest::Response,
    operation: &str,
    model: Option<&str>,
    request_bytes: Option<usize>,
) -> Result<(Option<String>, reqwest::Response), ProviderError> {
    let status = response.status();
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(128).collect::<String>());
    if status.is_redirection() {
        log_provider_http(
            operation,
            model,
            status,
            request_bytes,
            request_id.as_deref(),
            Some("redirect"),
        );
        return Err(provider_error(
            ProviderErrorCategory::Network,
            "Provider 返回了被阻止的重定向。",
        ));
    }
    if !status.is_success() {
        let retry_after = response.headers().get(header::RETRY_AFTER).cloned();
        let snippet = read_error_snippet(response).await;
        log_provider_http(
            operation,
            model,
            status,
            request_bytes,
            request_id.as_deref(),
            snippet.as_deref(),
        );
        return Err(status_error(
            status,
            retry_after.as_ref(),
            snippet.as_deref(),
        ));
    }
    log_provider_http(
        operation,
        model,
        status,
        request_bytes,
        request_id.as_deref(),
        None,
    );
    Ok((request_id, response))
}

async fn read_error_snippet(response: reqwest::Response) -> Option<String> {
    if response.content_length().unwrap_or(0) > 64 * 1024 {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    if bytes.len() > 64 * 1024 {
        return None;
    }
    let truncated = &bytes[..bytes.len().min(MAX_ERROR_BODY_BYTES)];
    extract_provider_error_text(&String::from_utf8_lossy(truncated))
}

fn extract_provider_error_text(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
        let raw = parsed
            .pointer("/error/message")
            .and_then(Value::as_str)
            .or_else(|| parsed.get("message").and_then(Value::as_str))
            .or_else(|| parsed.get("error").and_then(Value::as_str))
            .or_else(|| parsed.pointer("/error/code").and_then(Value::as_str));
        return raw.and_then(sanitize_error_text);
    }
    sanitize_error_text(trimmed)
}

fn sanitize_error_text(raw: &str) -> Option<String> {
    let collapsed: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    let words: Vec<&str> = collapsed.split_whitespace().collect();
    let mut redacted = Vec::with_capacity(words.len());
    let mut skip_next = false;
    for word in words {
        if skip_next {
            redacted.push("[redacted]");
            skip_next = false;
            continue;
        }
        let lower = word.to_ascii_lowercase();
        if lower == "bearer" || lower.ends_with("authorization:") {
            redacted.push("[redacted]");
            skip_next = true;
            continue;
        }
        if lower.starts_with("sk-")
            || (word.len() >= 48
                && word
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')))
        {
            redacted.push("[redacted]");
            continue;
        }
        redacted.push(word);
    }
    let mut text = redacted.join(" ");
    if text.chars().count() > MAX_ERROR_SNIPPET_CHARS {
        text = text
            .chars()
            .take(MAX_ERROR_SNIPPET_CHARS.saturating_sub(3))
            .collect::<String>()
            + "...";
    }
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn log_provider_http(
    operation: &str,
    model: Option<&str>,
    status: StatusCode,
    request_bytes: Option<usize>,
    request_id: Option<&str>,
    error: Option<&str>,
) {
    #[cfg(debug_assertions)]
    {
        eprintln!(
            "ai-provider {operation} model={} status={} request_bytes={} request_id={} error={}",
            model.unwrap_or("-"),
            status.as_u16(),
            request_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            request_id.unwrap_or("-"),
            error.unwrap_or("-"),
        );
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (operation, model, status, request_bytes, request_id, error);
    }
}

fn status_error(
    status: StatusCode,
    retry_after: Option<&header::HeaderValue>,
    snippet: Option<&str>,
) -> ProviderError {
    let category = match status.as_u16() {
        401 | 403 => ProviderErrorCategory::Authentication,
        429 => ProviderErrorCategory::RateLimited,
        _ => ProviderErrorCategory::Provider,
    };
    let message = match snippet.filter(|text| !text.is_empty()) {
        Some(text) => format!("Provider 请求失败（HTTP {}）：{text}", status.as_u16()),
        None => format!("Provider 请求失败（HTTP {}）。", status.as_u16()),
    };
    ProviderError {
        category,
        message,
        retry_after_seconds: retry_after
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok()),
    }
}

fn map_reqwest_error(error: reqwest::Error) -> ProviderError {
    let category = if error.is_timeout() {
        ProviderErrorCategory::Timeout
    } else {
        ProviderErrorCategory::Network
    };
    provider_error(
        category,
        if error.is_timeout() {
            "Provider 请求超时。"
        } else {
            "Provider 网络请求失败。"
        },
    )
}

fn provider_error(category: ProviderErrorCategory, message: impl Into<String>) -> ProviderError {
    ProviderError {
        category,
        message: message.into(),
        retry_after_seconds: None,
    }
}

fn storage_path(root: &Path) -> PathBuf {
    PROFILE_FILE
        .iter()
        .fold(root.to_path_buf(), |path, segment| path.join(segment))
}

fn validate_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err("Provider profile ID 无效。".to_string());
    }
    Ok(())
}

fn validate_short_text(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().count() > 256 || value.contains('\0') {
        return Err(format!("Provider {field}无效。"));
    }
    Ok(())
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Default)]
    struct FakeCredentials(Mutex<HashMap<String, String>>);
    impl CredentialStore for FakeCredentials {
        fn save(&self, id: &str, secret: SecretString) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .insert(id.to_string(), secret.expose()?.to_string());
            Ok(())
        }
        fn read(&self, id: &str) -> Result<Option<SecretString>, String> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .map(SecretString::new)
                .transpose()
        }
        fn delete(&self, id: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
    }

    fn profile() -> ProviderProfile {
        ProviderProfile {
            id: "profile-1".into(),
            kind: ProviderKind::OpenAiCompatible,
            display_name: "Fixture".into(),
            base_url: "https://example.com".into(),
            model: "fixture-model".into(),
            timeout_ms: 30_000,
            credential_present: false,
        }
    }

    fn test_root() -> PathBuf {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("cleandeck-ai-profiles-{value}"))
    }

    #[test]
    fn profile_storage_never_writes_secret() {
        let root = test_root();
        let store = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &store).unwrap();
        let profiles = save_profile(&root, profile(), &store).unwrap();
        assert!(profiles[0].credential_present);
        let raw = fs::read_to_string(storage_path(&root)).unwrap();
        assert!(!raw.contains("fixture-secret-token"));
        assert!(!raw.contains("credentialPresent"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_45s_timeout_is_lifted_on_read() {
        let root = test_root();
        let store = FakeCredentials::default();
        let mut stored = profile();
        stored.timeout_ms = 45_000;
        save_profile(&root, stored, &store).unwrap();
        let profiles = read_profiles(&root, &store).unwrap();
        assert_eq!(profiles[0].timeout_ms, 180_000);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn profile_validation_requires_secure_bounded_configuration() {
        assert!(profile().validate().is_ok());
        let mut bounded = profile();
        bounded.timeout_ms = 5_000;
        assert!(bounded.validate().is_ok());
        bounded.timeout_ms = 600_000;
        assert!(bounded.validate().is_ok());
        bounded.timeout_ms = 4_999;
        assert!(bounded.validate().is_err());
        bounded.timeout_ms = 600_001;
        assert!(bounded.validate().is_err());
        let mut invalid = profile();
        invalid.base_url = "http://example.com".into();
        assert!(invalid.validate().is_err());
        invalid.base_url = "https://user:password@example.com?q=secret".into();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn provider_tier_alias_is_normalized_only_at_boundary() {
        let value =
            normalize_tier_alias(r#"{"schema_version":1,"rules":[{"tier":"review_required"}]}"#)
                .unwrap();
        assert!(value.contains("heavy"));
        assert!(!value.contains("review_required"));
    }

    #[test]
    fn status_errors_are_stable_and_body_free() {
        for (status, expected) in [
            (
                StatusCode::UNAUTHORIZED,
                ProviderErrorCategory::Authentication,
            ),
            (StatusCode::FORBIDDEN, ProviderErrorCategory::Authentication),
            (
                StatusCode::TOO_MANY_REQUESTS,
                ProviderErrorCategory::RateLimited,
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ProviderErrorCategory::Provider,
            ),
        ] {
            let error = status_error(status, None, None);
            assert_eq!(error.category, expected);
            assert!(!error.message.contains("fixture-secret-token"));
        }
        let retry = header::HeaderValue::from_static("7");
        assert_eq!(
            status_error(StatusCode::TOO_MANY_REQUESTS, Some(&retry), None).retry_after_seconds,
            Some(7)
        );
    }

    #[test]
    fn json_content_strips_markdown_fences() {
        assert_eq!(
            unwrap_json_content("```json\n{\"ok\":true}\n```"),
            "{\"ok\":true}"
        );
        assert_eq!(unwrap_json_content("{\"ok\":true}"), "{\"ok\":true}");
    }

    #[test]
    fn openai_payload_disables_thinking_only_for_deepseek_host() {
        let deepseek = Url::parse("https://api.deepseek.com").unwrap();
        let deepseek_v1 = Url::parse("https://api.deepseek.com/v1").unwrap();
        let deepseek_sub = Url::parse("https://region.api.deepseek.com").unwrap();
        let openai = Url::parse("https://api.openai.com").unwrap();
        let fixture = Url::parse("http://127.0.0.1:9").unwrap();
        let lookalike = Url::parse("https://notapi.deepseek.com").unwrap();

        for url in [deepseek, deepseek_v1, deepseek_sub] {
            let payload = openai_chat_payload("m", "s", "ping", true, &url);
            assert_eq!(payload["thinking"]["type"], "disabled");
            assert_eq!(payload["stream"], true);
            assert_eq!(payload["response_format"]["type"], "json_object");
            assert!(payload.get("json_schema").is_none());
        }
        for url in [openai, fixture, lookalike] {
            let payload = openai_chat_payload("m", "s", "ping", true, &url);
            assert!(payload.get("thinking").is_none());
            assert_eq!(payload["stream"], true);
        }
    }

    #[test]
    fn generation_prompt_is_short_json_contract() {
        let prompt = generation_system_prompt(AiGenerationMode::AllTiers, None);
        let lowered = prompt.to_ascii_lowercase();
        assert!(lowered.contains("json"));
        assert!(prompt.contains(GENERATION_PROMPT_VERSION));
        assert!(prompt.contains(GENERATION_RULE_EXAMPLE));
        assert!(prompt.contains("%TEMP%") || prompt.contains("%LOCALAPPDATA%"));
        assert!(prompt.contains("contents"));
        assert!(prompt.contains("never delete"));
        assert!(!prompt.contains("json_schema"));
        let single = generation_system_prompt(AiGenerationMode::SingleTier, Some(AiRuleTier::Light));
        assert!(single.contains("light"));
        assert!(single.to_ascii_lowercase().contains("json"));
        assert!(!single.contains("json_schema"));
        let parsed = AiGeneratedRuleSet::parse(GENERATION_RULE_EXAMPLE).expect("example json");
        let compilation = parsed.compile().expect("example compile");
        assert!(compilation.report.valid, "{:?}", compilation.report.errors);
        assert!(compilation.rules.iter().all(|rule| !rule.default_selected));
    }

    #[test]
    fn provider_error_snippets_are_extracted_and_redacted() {
        assert_eq!(
            extract_provider_error_text(
                r#"{"error":{"message":"This response_format type is unavailable now"}}"#
            )
            .as_deref(),
            Some("This response_format type is unavailable now")
        );
        assert_eq!(extract_provider_error_text("{}"), None);
        let redacted = extract_provider_error_text(
            r#"{"error":{"message":"invalid Bearer sk-secret-token-value-here"}}"#,
        )
        .expect("snippet");
        assert!(redacted.contains("invalid"));
        assert!(!redacted.contains("sk-secret"));
        assert!(!redacted.to_ascii_lowercase().contains("bearer sk-"));
    }

    #[test]
    fn sse_chunks_are_concatenated_for_openai_and_anthropic() {
        let openai = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"{\\\"ok\\\"\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\":true}\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        assert_eq!(
            parse_sse_output(ProviderKind::OpenAiCompatible, openai, true).unwrap(),
            "{\"ok\":true}"
        );

        let anthropic = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"ok\\\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\":true}\"}}\n\n",
        );
        assert_eq!(
            parse_sse_output(ProviderKind::AnthropicCompatible, anthropic, true).unwrap(),
            "{\"ok\":true}"
        );
    }

    #[tokio::test]
    async fn both_provider_protocols_send_hybrid_summary_with_samples() {
        for kind in [
            ProviderKind::OpenAiCompatible,
            ProviderKind::AnthropicCompatible,
        ] {
            let response = provider_response(kind, &valid_rules());
            let (base_url, captured) = spawn_server(200, response, Duration::ZERO);
            let credentials = FakeCredentials::default();
            save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
            let mut provider = profile();
            provider.kind = kind;
            provider.base_url = base_url;

            let generated = generate_rules(&provider, &generation_request(), &credentials, |_| {})
                .await
                .unwrap();
            assert_eq!(generated.rules.rules.len(), 1);
            let request = captured.recv().unwrap();
            assert!(request.contains("summaryHash"));
            assert!(request.contains("targetTier"));
            assert!(request.contains("samples"));
            assert!(request.contains("AppData"));
            assert!(request.contains("alice"));
            assert!(request.contains("schemaVersion"));
            assert!(request.contains("token=[redacted]"));
            assert!(!request.contains("API_KEY"));
            match kind {
                ProviderKind::OpenAiCompatible => {
                    assert!(request.starts_with("POST /v1/chat/completions"));
                    assert!(request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer fixture-secret-token"));
                    assert!(request.contains("json_object"));
                    assert!(!request.contains("json_schema"));
                    assert!(request.contains("\"stream\":true"));
                    assert!(!request.contains("thinking"));
                }
                ProviderKind::AnthropicCompatible => {
                    assert!(request.starts_with("POST /v1/messages"));
                    assert!(request
                        .to_ascii_lowercase()
                        .contains("x-api-key: fixture-secret-token"));
                    assert!(request
                        .to_ascii_lowercase()
                        .contains("anthropic-version: 2023-06-01"));
                    assert!(request.contains("input_schema"));
                    assert!(request.contains("submit_cleanup_rules"));
                    assert!(request.contains("\"stream\":true"));
                }
            }
        }
    }

    #[tokio::test]
    async fn generation_reads_openai_sse_and_emits_progress() {
        let rules = valid_rules();
        let body = format!(
            "data: {}\n\ndata: [DONE]\n\n",
            json!({"choices": [{"delta": {"content": rules}}]})
        );
        let (base_url, captured) = spawn_server(200, body, Duration::ZERO);
        let credentials = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
        let mut provider = profile();
        provider.base_url = base_url;
        let (progress_tx, progress_rx) = std::sync::mpsc::channel();
        let generated = generate_rules(
            &provider,
            &generation_request(),
            &credentials,
            move |progress| {
                let _ = progress_tx.send(progress);
            },
        )
        .await
        .unwrap();
        assert_eq!(generated.rules.rules.len(), 1);
        let progress: Vec<_> = progress_rx.try_iter().collect();
        assert!(progress.iter().any(|item| item.bytes_received > 0));
        let request = captured.recv().unwrap();
        assert!(request.contains("\"stream\":true"));
    }

    #[tokio::test]
    async fn generation_rejects_rules_outside_requested_tier() {
        let response = provider_response(
            ProviderKind::OpenAiCompatible,
            &valid_rules().replace("\"light\"", "\"medium\""),
        );
        let (base_url, _) = spawn_server(200, response, Duration::ZERO);
        assert_eq!(
            call_fixture(base_url, 5_000).await.unwrap_err().category,
            ProviderErrorCategory::InvalidSchema
        );
    }

    #[tokio::test]
    async fn all_tiers_generation_accepts_mixed_tier_json() {
        let response = provider_response(ProviderKind::OpenAiCompatible, &valid_all_tier_rules());
        let (base_url, captured) = spawn_server(200, response, Duration::ZERO);
        let credentials = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
        let mut provider = profile();
        provider.base_url = base_url;
        let generated = generate_rules(
            &provider,
            &all_tiers_generation_request(),
            &credentials,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(generated.rules.rules.len(), 3);
        let request = captured.recv().unwrap();
        assert!(request.contains("allTiers") || request.contains("generationMode"));
        assert!(request.contains("Generate light, medium, and/or heavy"));
    }

    #[tokio::test]
    async fn single_tier_mode_still_rejects_cross_tier_when_explicit() {
        let response = provider_response(ProviderKind::OpenAiCompatible, &valid_all_tier_rules());
        let (base_url, _) = spawn_server(200, response, Duration::ZERO);
        let credentials = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
        let mut provider = profile();
        provider.base_url = base_url;
        let mut request = generation_request();
        request.generation_mode = Some(AiGenerationMode::SingleTier);
        request.target_tier = Some(AiRuleTier::Light);
        assert_eq!(
            generate_rules(&provider, &request, &credentials, |_| {})
                .await
                .unwrap_err()
                .category,
            ProviderErrorCategory::InvalidSchema
        );
    }

    #[tokio::test]
    async fn generation_probe_classifies_timeout() {
        let response = provider_probe_response(ProviderKind::OpenAiCompatible);
        let (base_url, _) = spawn_server(200, response, Duration::from_millis(5_100));
        let credentials = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
        let error = probe_generation(
            ProviderGenerationProbeQuery {
                kind: ProviderKind::OpenAiCompatible,
                base_url,
                timeout_ms: 5_000,
                model: "fixture-model".into(),
                profile_id: Some("profile-1".into()),
                api_key: None,
            },
            &credentials,
        )
        .await
        .unwrap_err();
        assert_eq!(error.category, ProviderErrorCategory::Timeout);
    }

    #[tokio::test]
    async fn generation_probe_succeeds_with_ok_payload() {
        let response = provider_probe_response(ProviderKind::OpenAiCompatible);
        let (base_url, captured) = spawn_server(200, response, Duration::ZERO);
        let credentials = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
        let result = probe_generation(
            ProviderGenerationProbeQuery {
                kind: ProviderKind::OpenAiCompatible,
                base_url,
                timeout_ms: 5_000,
                model: "fixture-model".into(),
                profile_id: Some("profile-1".into()),
                api_key: None,
            },
            &credentials,
        )
        .await
        .unwrap();
        assert!(result.ok);
        let request = captured.recv().unwrap();
        assert!(request.contains("json_object") || request.contains("\"ok\""));
        assert!(!request.contains("json_schema"));
        assert!(!request.contains("summaryHash"));
        assert!(request.contains("\"stream\":true"));
        assert!(!request.contains("thinking"));
    }

    #[tokio::test]
    async fn generation_probe_reads_openai_sse() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"{\\\"ok\\\":true}\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let (base_url, captured) = spawn_server(200, body.into(), Duration::ZERO);
        let credentials = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
        let result = probe_generation(
            ProviderGenerationProbeQuery {
                kind: ProviderKind::OpenAiCompatible,
                base_url,
                timeout_ms: 5_000,
                model: "fixture-model".into(),
                profile_id: Some("profile-1".into()),
                api_key: None,
            },
            &credentials,
        )
        .await
        .unwrap();
        assert!(result.ok);
        let request = captured.recv().unwrap();
        assert!(request.contains("\"stream\":true"));
        assert!(!request.contains("thinking"));
    }

    #[tokio::test]
    async fn anthropic_probe_sends_stream_true() {
        let response = provider_probe_response(ProviderKind::AnthropicCompatible);
        let (base_url, captured) = spawn_server(200, response, Duration::ZERO);
        let credentials = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
        let result = probe_generation(
            ProviderGenerationProbeQuery {
                kind: ProviderKind::AnthropicCompatible,
                base_url,
                timeout_ms: 5_000,
                model: "fixture-model".into(),
                profile_id: Some("profile-1".into()),
                api_key: None,
            },
            &credentials,
        )
        .await
        .unwrap();
        assert!(result.ok);
        let request = captured.recv().unwrap();
        assert!(request.contains("\"stream\":true"));
        assert!(!request.contains("thinking"));
        assert!(request.contains("submit_probe"));
    }

    #[tokio::test]
    async fn http_400_includes_sanitized_provider_message() {
        let body = json!({
            "error": {
                "message": "This response_format type is unavailable now Bearer sk-secret-token-value",
                "type": "invalid_request_error"
            }
        })
        .to_string();
        let (base_url, _) = spawn_server(400, body, Duration::ZERO);
        let error = call_fixture(base_url, 5_000).await.unwrap_err();
        assert_eq!(error.category, ProviderErrorCategory::Provider);
        assert!(error.message.contains("HTTP 400"));
        assert!(error
            .message
            .contains("This response_format type is unavailable now"));
        assert!(!error.message.contains("sk-secret"));
    }

    #[tokio::test]
    async fn http_failures_timeout_and_oversize_are_normalized() {
        for (status, expected) in [
            (401, ProviderErrorCategory::Authentication),
            (429, ProviderErrorCategory::RateLimited),
            (500, ProviderErrorCategory::Provider),
            (302, ProviderErrorCategory::Network),
        ] {
            let (base_url, _) = spawn_server(status, "{}".into(), Duration::ZERO);
            assert_eq!(
                call_fixture(base_url, 5_000).await.unwrap_err().category,
                expected
            );
        }

        let (base_url, _) = spawn_server(
            200,
            provider_response(ProviderKind::OpenAiCompatible, &valid_rules()),
            Duration::from_millis(5_100),
        );
        assert_eq!(
            call_fixture(base_url, 5_000).await.unwrap_err().category,
            ProviderErrorCategory::Timeout
        );

        let (base_url, _) = spawn_server(
            200,
            "x".repeat(MAX_PROVIDER_RESPONSE_BYTES as usize + 1),
            Duration::ZERO,
        );
        assert_eq!(
            call_fixture(base_url, 5_000).await.unwrap_err().category,
            ProviderErrorCategory::ResponseTooLarge
        );

        for response in [
            "not-json".to_string(),
            provider_response(ProviderKind::OpenAiCompatible, "not-json"),
            provider_response(
                ProviderKind::OpenAiCompatible,
                &valid_rules().replace("\"cautions\"", "\"unexpectedExecutableField\""),
            ),
        ] {
            let (base_url, _) = spawn_server(200, response, Duration::ZERO);
            assert_eq!(
                call_fixture(base_url, 5_000).await.unwrap_err().category,
                ProviderErrorCategory::InvalidSchema
            );
        }
    }

    async fn call_fixture(
        base_url: String,
        timeout_ms: u64,
    ) -> Result<ProviderGenerationResponse, ProviderError> {
        let credentials = FakeCredentials::default();
        save_credential("profile-1", "fixture-secret-token".into(), &credentials).unwrap();
        let mut provider = profile();
        provider.base_url = base_url;
        provider.timeout_ms = timeout_ms;
        generate_rules(&provider, &generation_request(), &credentials, |_| {}).await
    }

    fn generation_request() -> ProviderGenerationRequest {
        let summary = cleaner_core::redacted_scan_summary(&sample_scan_snapshot());
        assert!(summary.validate_for_provider().is_ok());
        assert!(summary
            .buckets
            .iter()
            .any(|bucket| !bucket.samples.is_empty()));
        ProviderGenerationRequest {
            summary,
            generation_mode: None,
            target_tier: Some(AiRuleTier::Light),
        }
    }

    fn sample_scan_snapshot() -> cleaner_core::ScanSnapshot {
        let mut snapshot = cleaner_core::initial_scan_snapshot();
        snapshot.scan_backend = "mft".into();
        snapshot.candidates.push(cleaner_core::CleanupCandidate {
            id: "candidate-1".into(),
            parent_id: None,
            display_name: "cache".into(),
            path: r"C:\Users\alice\AppData\Local\Temp\cache".into(),
            volume_id: "C:".into(),
            object_type: cleaner_core::ObjectType::Directory,
            category: "cache".into(),
            size_bytes: 12_000_000,
            children_count: 0,
            risk_level: cleaner_core::RiskLevel::SafeRecommended,
            default_selected: true,
            selected: false,
            delete_strategy: cleaner_core::DeleteStrategy::MoveToRecycleBin,
            reason: "browser cache token=API_KEY".into(),
            confidence: 100,
            source: cleaner_core::SourceInfo {
                label: "Browser".into(),
                kind: cleaner_core::SourceKind::Browser,
                confidence: 100,
                evidence: r"Temp\cache".into(),
            },
            cleanup_policy: cleaner_core::CleanupPolicy::default(),
        });
        snapshot.coverage.status = cleaner_core::ScanCoverageStatus::Partial;
        snapshot.coverage.gaps.push(cleaner_core::CoverageGap {
            volume_id: "C:".into(),
            reason: cleaner_core::CoverageGapReason::ReparseNotFollowed,
            path_hint: Some(r"C:\Users\alice\Link".into()),
            count: 1,
        });
        snapshot
    }

    fn all_tiers_generation_request() -> ProviderGenerationRequest {
        let mut request = generation_request();
        request.generation_mode = Some(AiGenerationMode::AllTiers);
        request.target_tier = None;
        request
    }

    fn valid_rules() -> String {
        let rule = |id: &str, tier: &str| {
            json!({
                "id": id, "tier": tier, "name": id, "app": "Fixture", "category": "cache",
                "paths": [format!("%TEMP%\\{id}")], "clean": "contents", "keep_days": 7,
                "exclude": ["*.lock"], "note": "fixture", "evidence": ["aggregate"],
                "cautions": ["review"]
            })
        };
        json!({"schema_version": 1, "rules": [rule("fixture.light", "light")]}).to_string()
    }

    fn valid_all_tier_rules() -> String {
        let rule = |id: &str, tier: &str| {
            json!({
                "id": id, "tier": tier, "name": id, "app": "Fixture", "category": "cache",
                "paths": [format!("%TEMP%\\{id}")], "clean": "contents", "keep_days": 7,
                "exclude": ["*.lock"], "note": "fixture", "evidence": ["aggregate"],
                "cautions": ["review"]
            })
        };
        json!({
            "schema_version": 1,
            "rules": [
                rule("fixture.light", "light"),
                rule("fixture.medium", "medium"),
                rule("fixture.heavy", "heavy")
            ]
        })
        .to_string()
    }

    fn provider_response(kind: ProviderKind, rules: &str) -> String {
        match kind {
            ProviderKind::OpenAiCompatible => {
                json!({"choices": [{"message": {"content": rules}}]}).to_string()
            }
            ProviderKind::AnthropicCompatible => {
                json!({"content": [{"type": "text", "text": rules}]}).to_string()
            }
        }
    }

    fn provider_probe_response(kind: ProviderKind) -> String {
        match kind {
            ProviderKind::OpenAiCompatible => {
                json!({"choices": [{"message": {"content": "{\"ok\":true}"}}]}).to_string()
            }
            ProviderKind::AnthropicCompatible => json!({
                "content": [{
                    "type": "tool_use",
                    "name": "submit_probe",
                    "input": {"ok": true}
                }]
            })
            .to_string(),
        }
    }

    fn spawn_server(
        status: u16,
        body: String,
        delay: Duration,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::mpsc,
            thread,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let count = stream.read(&mut buffer).unwrap_or(0);
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if request_is_complete(&bytes) {
                    break;
                }
            }
            let _ = sender.send(String::from_utf8_lossy(&bytes).into_owned());
            thread::sleep(delay);
            let reason = if status == 200 { "OK" } else { "Error" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{body}",
                body.len(),
                if status == 302 { "Location: https://other.example/v1\r\n" } else { "" }
            );
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{address}"), receiver)
    }

    #[test]
    fn model_endpoint_tolerates_base_url_with_version_segment() {
        for base in [
            "https://example.com",
            "https://example.com/",
            "https://example.com/v1",
        ] {
            let url = route_endpoint(
                &Url::parse(base).unwrap(),
                ProviderKind::OpenAiCompatible,
                ProviderRoute::Models,
            )
            .unwrap();
            assert_eq!(url.as_str(), "https://example.com/v1/models");
        }
    }

    #[test]
    fn model_parsing_accepts_openai_anthropic_and_bare_shapes() {
        let openai = json!({"object": "list", "data": [{"id": "gpt-4o"}, {"id": "gpt-4o"}]});
        assert_eq!(
            parse_models(&openai),
            vec![ProviderModel {
                id: "gpt-4o".into(),
                display_name: None
            }]
        );

        let anthropic = json!({
            "data": [{"id": "claude-opus-4", "display_name": "Claude Opus 4"}],
            "has_more": false
        });
        assert_eq!(
            parse_models(&anthropic),
            vec![ProviderModel {
                id: "claude-opus-4".into(),
                display_name: Some("Claude Opus 4".into())
            }]
        );

        let bare = json!(["b-model", "a-model", "  "]);
        assert_eq!(
            parse_models(&bare)
                .into_iter()
                .map(|model| model.id)
                .collect::<Vec<_>>(),
            vec!["a-model".to_string(), "b-model".to_string()]
        );

        assert!(parse_models(&json!({"error": "nope"})).is_empty());
    }

    #[tokio::test]
    async fn model_listing_requests_models_route_and_returns_ids() {
        let body = json!({"data": [{"id": "fixture-model"}]}).to_string();
        let (base_url, captured) = spawn_server(200, body, Duration::ZERO);
        let credentials = FakeCredentials::default();
        let models = list_models(
            ProviderModelQuery {
                kind: ProviderKind::OpenAiCompatible,
                base_url,
                timeout_ms: 5_000,
                profile_id: None,
                api_key: Some(SecretString::new("fixture-secret-token".into()).unwrap()),
            },
            &credentials,
        )
        .await
        .unwrap();
        assert_eq!(
            models.first().map(|model| model.id.as_str()),
            Some("fixture-model")
        );
        let request = captured.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(request.starts_with("GET /v1/models"));
    }

    #[tokio::test]
    async fn connection_test_uses_current_key_and_reports_model_count() {
        let body = json!({"data": [{"id": "model-a"}, {"id": "model-b"}]}).to_string();
        let (base_url, captured) = spawn_server(200, body, Duration::ZERO);
        let credentials = FakeCredentials::default();
        let result = test_connection(
            ProviderModelQuery {
                kind: ProviderKind::OpenAiCompatible,
                base_url,
                timeout_ms: 5_000,
                profile_id: None,
                api_key: Some(SecretString::new("fixture-secret-token".into()).unwrap()),
            },
            &credentials,
        )
        .await
        .unwrap();

        assert_eq!(result.model_count, 2);
        let request = captured.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(request.starts_with("GET /v1/models"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-secret-token"));
        assert!(credentials.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn model_listing_without_key_or_profile_is_credential_error() {
        let credentials = FakeCredentials::default();
        let error = list_models(
            ProviderModelQuery {
                kind: ProviderKind::OpenAiCompatible,
                base_url: "https://example.com".into(),
                timeout_ms: 5_000,
                profile_id: None,
                api_key: None,
            },
            &credentials,
        )
        .await
        .unwrap_err();
        assert_eq!(error.category, ProviderErrorCategory::CredentialMissing);
    }

    fn request_is_complete(bytes: &[u8]) -> bool {
        let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&bytes[..end]);
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        bytes.len() >= end + 4 + length
    }
}

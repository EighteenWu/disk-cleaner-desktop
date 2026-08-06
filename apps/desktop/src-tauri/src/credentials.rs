use std::io;

use serde::{Deserialize, Deserializer};

const CREDENTIAL_NAMESPACE: &str = "CleanDeck/ai-provider";
const MAX_SECRET_BYTES: usize = 5 * 512;

pub struct SecretString(Vec<u8>);

impl SecretString {
    pub fn new(value: String) -> Result<Self, String> {
        let mut bytes = value.into_bytes();
        if std::str::from_utf8(&bytes).map_or(true, |value| value.trim().is_empty()) {
            bytes.fill(0);
            return Err("API Key 不能为空。".to_string());
        }
        if bytes.len() > MAX_SECRET_BYTES {
            bytes.fill(0);
            return Err("API Key 长度超过 Windows 凭据上限。".to_string());
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> Result<&str, String> {
        std::str::from_utf8(&self.0).map_err(|_| "凭据编码无效。".to_string())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub trait CredentialStore: Send + Sync {
    fn save(&self, profile_id: &str, secret: SecretString) -> Result<(), String>;
    fn read(&self, profile_id: &str) -> Result<Option<SecretString>, String>;
    fn delete(&self, profile_id: &str) -> Result<(), String>;

    fn exists(&self, profile_id: &str) -> Result<bool, String> {
        self.read(profile_id).map(|value| value.is_some())
    }
}

#[derive(Clone, Copy, Default)]
pub struct WindowsCredentialStore;

fn target(profile_id: &str) -> Result<Vec<u16>, String> {
    if profile_id.is_empty()
        || profile_id.len() > 128
        || !profile_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err("Provider profile ID 无效。".to_string());
    }
    Ok(format!("{CREDENTIAL_NAMESPACE}/{profile_id}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect())
}

#[cfg(windows)]
impl CredentialStore for WindowsCredentialStore {
    fn save(&self, profile_id: &str, mut secret: SecretString) -> Result<(), String> {
        use windows_sys::Win32::Security::Credentials::{
            CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
        };

        let mut target_name = target(profile_id)?;
        let mut user_name: Vec<u16> = "CleanDeck"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target_name.as_mut_ptr(),
            CredentialBlobSize: secret.0.len() as u32,
            CredentialBlob: secret.0.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: user_name.as_mut_ptr(),
            ..Default::default()
        };
        // SAFETY: all pointers reference live buffers for the duration of the call.
        let ok = unsafe { CredWriteW(&credential, 0) };
        if ok == 0 {
            Err(credential_error("保存"))
        } else {
            Ok(())
        }
    }

    fn read(&self, profile_id: &str) -> Result<Option<SecretString>, String> {
        use std::{ptr, slice};
        use windows_sys::Win32::{
            Foundation::ERROR_NOT_FOUND,
            Security::Credentials::{CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC},
        };

        let target_name = target(profile_id)?;
        let mut credential: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: target_name is NUL-terminated and credential is a valid out pointer.
        let ok = unsafe { CredReadW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(None);
            }
            return Err(format!(
                "读取 Windows 凭据失败（错误码 {}）。",
                error.raw_os_error().unwrap_or(0)
            ));
        }
        if credential.is_null() {
            return Err("Windows 凭据返回空记录。".to_string());
        }

        // SAFETY: CredReadW returned a valid CREDENTIALW allocation and blob range.
        let bytes = unsafe {
            let value = &*credential;
            slice::from_raw_parts(value.CredentialBlob, value.CredentialBlobSize as usize).to_vec()
        };
        // SAFETY: the allocation belongs to the credential manager.
        unsafe { CredFree(credential.cast()) };
        Ok(Some(SecretString(bytes)))
    }

    fn delete(&self, profile_id: &str) -> Result<(), String> {
        use windows_sys::Win32::{
            Foundation::ERROR_NOT_FOUND,
            Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC},
        };

        let target_name = target(profile_id)?;
        // SAFETY: target_name is a valid NUL-terminated UTF-16 string.
        let ok = unsafe { CredDeleteW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
            Ok(())
        } else {
            Err(format!(
                "删除 Windows 凭据失败（错误码 {}）。",
                error.raw_os_error().unwrap_or(0)
            ))
        }
    }
}

#[cfg(windows)]
fn credential_error(action: &str) -> String {
    let code = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    format!("{action} Windows 凭据失败（错误码 {code}）。")
}

#[cfg(not(windows))]
impl CredentialStore for WindowsCredentialStore {
    fn save(&self, _profile_id: &str, _secret: SecretString) -> Result<(), String> {
        Err("Windows 凭据存储仅在 Windows 构建中启用。".to_string())
    }

    fn read(&self, _profile_id: &str) -> Result<Option<SecretString>, String> {
        Ok(None)
    }

    fn delete(&self, _profile_id: &str) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_rejects_injection_characters() {
        assert!(target("profile-1").is_ok());
        assert!(target("../profile").is_err());
        assert!(target("profile/slash").is_err());
    }

    #[test]
    fn secret_is_never_debug_or_serializable() {
        let secret = SecretString::new("fixture-secret".to_string()).unwrap();
        assert_eq!(secret.expose().unwrap(), "fixture-secret");
    }
}

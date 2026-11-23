// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! RAM AccessKey credential resolution, `~/.aliyun/config.json` profile loading,
//! and home-scoped [`TokenStore`] for `aliyun-ecs`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cua_sandbox_core::Error;
use cua_sandbox_core::byoc::CloudCredentials;
use serde::Deserialize;

use crate::api::{Result, Secret};

/// Name of the AccessKey pair in the Cua credential store.
pub const SECRET_NAME: &str = "byoc-aliyun-ecs-token";

/// Where the Cua credential store keeps the AccessKey pair (and a fake in tests).
pub trait TokenStore: Send + Sync + 'static {
    /// The saved `<access_key_id>:<access_key_secret>` token, if any.
    fn load(&self) -> Option<String>;
    /// Saves the token (0600 or the OS vault).
    fn save(&self, token: &str) -> std::io::Result<()>;
    /// Removes it; returns whether there was one.
    fn clear(&self) -> bool;
    /// Scopes the store to a specific Cua home directory when applicable.
    fn scope_home(&self, _home: &Path) {}
}

/// The Cua credential store ([`cua_auth::Store`]), scoped to the Cua home passed
/// by [`crate::install`] / [`crate::clouds`] instead of touching the global vault
/// directly when a custom or test home is active.
pub struct CuaCredentialStore {
    home: Mutex<Option<PathBuf>>,
}

impl Default for CuaCredentialStore {
    fn default() -> Self {
        Self::new(None)
    }
}

impl CuaCredentialStore {
    /// Creates a credential store optionally scoped to `home`.
    pub fn new(home: Option<PathBuf>) -> Self {
        Self {
            home: Mutex::new(home),
        }
    }

    fn store(&self) -> cua_auth::Store {
        let home = self.home.lock().expect("aliyun credential store home");
        crate::relay::secret_store(home.as_deref())
    }
}

impl TokenStore for CuaCredentialStore {
    fn load(&self) -> Option<String> {
        let bytes = self.store().load_secret(SECRET_NAME).ok()??;
        String::from_utf8(bytes)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    }

    fn save(&self, token: &str) -> std::io::Result<()> {
        self.store()
            .save_secret(SECRET_NAME, token.as_bytes())
            .map_err(std::io::Error::other)
    }

    fn clear(&self) -> bool {
        self.store().clear_secret(SECRET_NAME).unwrap_or(false)
    }

    fn scope_home(&self, home: &Path) {
        *self.home.lock().expect("aliyun credential store home") = Some(home.to_path_buf());
    }
}

/// RAM AccessKey credentials in memory (never printed in `Debug`).
#[derive(Clone, PartialEq, Eq)]
pub struct AliyunCredentials {
    /// AccessKey ID.
    pub access_key_id: String,
    /// AccessKey Secret (wiped on drop, redacted in `Debug`).
    pub access_key_secret: Secret,
}

impl AliyunCredentials {
    /// Formats as `<access_key_id>:<access_key_secret>` for storage in `TokenStore`.
    pub fn to_pair(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(format!(
            "{}:{}",
            self.access_key_id,
            self.access_key_secret.expose()
        ))
    }
}

impl std::fmt::Debug for AliyunCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AliyunCredentials")
            .field("access_key_id", &"<redacted>")
            .field("access_key_secret", &self.access_key_secret)
            .finish()
    }
}

/// Parses `<access_key_id>:<access_key_secret>`.
pub fn parse_token_pair(raw: &str) -> std::result::Result<AliyunCredentials, String> {
    let trimmed = raw.trim();
    let Some((ak, sk)) = trimmed.split_once(':') else {
        return Err(
            "aliyun-ecs: expected <access_key_id>:<access_key_secret> (missing ':' separator)"
                .into(),
        );
    };
    let ak = ak.trim();
    let sk = sk.trim();
    if ak.is_empty()
        || sk.is_empty()
        || ak.chars().any(char::is_whitespace)
        || sk.chars().any(char::is_whitespace)
    {
        return Err(
            "aliyun-ecs: malformed AccessKey pair; expected non-empty <access_key_id>:<access_key_secret> with no whitespace"
                .into(),
        );
    }
    Ok(AliyunCredentials {
        access_key_id: ak.to_string(),
        access_key_secret: Secret::new(sk),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CredSource {
    TokenStdin,
    Env,
    ExplicitProfile(String),
    Saved,
    CurrentProfile(String),
}

impl CredSource {
    pub(crate) fn describe(&self) -> String {
        match self {
            CredSource::TokenStdin => "AccessKey passed via --token-stdin".into(),
            CredSource::Env => {
                "ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET".into()
            }
            CredSource::ExplicitProfile(p) => format!("~/.aliyun/config.json profile {p:?}"),
            CredSource::Saved => "AccessKey saved by `cua cloud connect aliyun-ecs`".into(),
            CredSource::CurrentProfile(p) => {
                format!("~/.aliyun/config.json active profile {p:?}")
            }
        }
    }
}

#[derive(Deserialize)]
struct AliyunCliConfig {
    #[serde(default)]
    current: String,
    #[serde(default)]
    profiles: Vec<AliyunCliProfile>,
}

#[derive(Deserialize)]
struct AliyunCliProfile {
    #[serde(default)]
    name: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    access_key_id: String,
    #[serde(default)]
    access_key_secret: String,
    #[serde(default)]
    region_id: String,
}

/// Path to `~/.aliyun/config.json`, if `HOME` (or `USERPROFILE` on Windows) is set.
pub fn aliyun_config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty());
    #[cfg(windows)]
    let home = home.or_else(|| std::env::var_os("USERPROFILE").filter(|h| !h.is_empty()));
    home.map(|h| PathBuf::from(h).join(".aliyun").join("config.json"))
}

fn normalize_for_prefix(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(c) = cur.canonicalize() {
            return rest.into_iter().rev().fold(c, |acc, part| acc.join(part));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                cur = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

fn is_under_dir(path: &Path, dir: &Path) -> bool {
    path.starts_with(dir) || normalize_for_prefix(path).starts_with(normalize_for_prefix(dir))
}

fn resolve_default_aliyun_config_path(
    candidate: Option<PathBuf>,
    real_os_home: Option<&Path>,
    test_process: bool,
) -> Option<PathBuf> {
    let path = candidate?;
    if test_process && real_os_home.is_some_and(|home| is_under_dir(&path, home)) {
        return None;
    }
    Some(path)
}

/// Default `~/.aliyun/config.json` discovery path; in test processes skips the
/// user's real OS home while allowing an isolated temporary `HOME`.
pub(crate) fn default_aliyun_config_path() -> Option<PathBuf> {
    let real_os_home = cua_home::real_cua_home().and_then(|p| p.parent().map(Path::to_path_buf));
    resolve_default_aliyun_config_path(
        aliyun_config_path(),
        real_os_home.as_deref(),
        cua_home::is_test_process(),
    )
}

pub(crate) fn read_cli_profile(
    path: &Path,
    explicit_name: Option<&str>,
) -> std::result::Result<Option<(String, AliyunCredentials, Option<String>)>, String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if explicit_name.is_some() => {
            return Err(format!(
                "aliyun-ecs: profile {:?} requested, but {} could not be read: {e}",
                explicit_name.unwrap_or_default(),
                path.display()
            ));
        }
        Err(_) => return Ok(None),
    };

    let cfg: AliyunCliConfig = serde_json::from_str(&content)
        .map_err(|e| format!("aliyun-ecs: failed to parse {}: {e}", path.display()))?;

    let target_name = match explicit_name {
        Some(name) => name.trim(),
        None => {
            let cur = cfg.current.trim();
            if cur.is_empty() {
                return Ok(None);
            }
            cur
        }
    };

    let Some(prof) = cfg.profiles.iter().find(|p| p.name.trim() == target_name) else {
        if explicit_name.is_some() {
            return Err(format!(
                "aliyun-ecs: profile {target_name:?} not found in {}",
                path.display()
            ));
        }
        return Ok(None);
    };

    if !prof.mode.trim().eq_ignore_ascii_case("AK") {
        return Err(format!(
            "aliyun-ecs: profile {target_name:?} uses mode {:?}; only AK mode profiles (access_key_id + access_key_secret) are supported, or pass --token-stdin / ALIBABA_CLOUD_ACCESS_KEY_ID + ALIBABA_CLOUD_ACCESS_KEY_SECRET",
            prof.mode
        ));
    }

    let ak = prof.access_key_id.trim();
    let sk = prof.access_key_secret.trim();
    if ak.is_empty() || sk.is_empty() {
        return Err(format!(
            "aliyun-ecs: profile {target_name:?} in {} is missing access_key_id or access_key_secret",
            path.display()
        ));
    }

    let region = Some(prof.region_id.trim().to_ascii_lowercase()).filter(|r| !r.is_empty());
    Ok(Some((
        prof.name.trim().to_string(),
        AliyunCredentials {
            access_key_id: ak.to_string(),
            access_key_secret: Secret::new(sk),
        },
        region,
    )))
}

pub(crate) fn env_credentials() -> std::result::Result<Option<AliyunCredentials>, String> {
    let id = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let secret = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match (id, secret) {
        (Some(ak), Some(sk)) => Ok(Some(AliyunCredentials {
            access_key_id: ak,
            access_key_secret: Secret::new(sk),
        })),
        (Some(_), None) | (None, Some(_)) => Err(
            "aliyun-ecs: both ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET must be set (only one was provided)"
                .into(),
        ),
        (None, None) => Ok(None),
    }
}

pub(crate) fn resolve_credentials(
    staged: &Mutex<Option<std::result::Result<AliyunCredentials, String>>>,
    store: &dyn TokenStore,
    aliyun_config: Option<&Path>,
    profile_hint: Option<&str>,
) -> Result<(AliyunCredentials, CredSource)> {
    if let Some(res) = staged.lock().unwrap().clone() {
        let creds = res.map_err(Error::InvalidArgument)?;
        return Ok((creds, CredSource::TokenStdin));
    }

    if let Some(creds) = env_credentials().map_err(Error::ContribNotConfigured)? {
        return Ok((creds, CredSource::Env));
    }

    let explicit = profile_hint.map(str::trim).filter(|s| !s.is_empty());
    if let Some(name) = explicit {
        let Some(path) = aliyun_config else {
            return Err(Error::ContribNotConfigured(format!(
                "aliyun-ecs: profile {name:?} requested, but HOME is not set to locate ~/.aliyun/config.json"
            )));
        };
        let (_, creds, _) = read_cli_profile(path, Some(name))
            .map_err(Error::ContribNotConfigured)?
            .ok_or_else(|| {
                Error::ContribNotConfigured(format!(
                    "aliyun-ecs: profile {name:?} not found in {}",
                    path.display()
                ))
            })?;
        return Ok((creds, CredSource::ExplicitProfile(name.to_string())));
    }

    if let Some(saved) = store.load() {
        let creds = parse_token_pair(&saved).map_err(Error::ContribNotConfigured)?;
        return Ok((creds, CredSource::Saved));
    }

    if let Some(path) = aliyun_config
        && let Some((name, creds, _)) =
            read_cli_profile(path, None).map_err(Error::ContribNotConfigured)?
    {
        return Ok((creds, CredSource::CurrentProfile(name)));
    }

    Err(Error::ContribNotConfigured(
        "aliyun-ecs: no Alibaba Cloud credentials found; pass `<access_key_id>:<access_key_secret>` via `--token-stdin`, set `ALIBABA_CLOUD_ACCESS_KEY_ID` and `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, or configure an `AK` mode profile (`--profile` or active `current` profile in `~/.aliyun/config.json`)"
            .into(),
    ))
}

pub(crate) fn detect_credentials(
    staged: &Mutex<Option<std::result::Result<AliyunCredentials, String>>>,
    store: &dyn TokenStore,
    aliyun_config: Option<&Path>,
) -> CloudCredentials {
    if let Some(Ok(_)) = staged.lock().unwrap().as_ref() {
        return CloudCredentials {
            found: true,
            source: CredSource::TokenStdin.describe(),
        };
    }
    if matches!(env_credentials(), Ok(Some(_))) {
        return CloudCredentials {
            found: true,
            source: CredSource::Env.describe(),
        };
    }
    if store
        .load()
        .as_deref()
        .is_some_and(|s| parse_token_pair(s).is_ok())
    {
        return CloudCredentials {
            found: true,
            source: CredSource::Saved.describe(),
        };
    }
    if let Some(path) = aliyun_config
        && let Ok(Some((name, _, _))) = read_cli_profile(path, None)
    {
        return CloudCredentials {
            found: true,
            source: CredSource::CurrentProfile(name).describe(),
        };
    }
    CloudCredentials::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_pair_and_debug_redaction() {
        let creds = parse_token_pair("  LTAI5tTestKey : SuperSecretValue123  ").unwrap();
        assert_eq!(creds.access_key_id, "LTAI5tTestKey");
        assert_eq!(creds.access_key_secret.expose(), "SuperSecretValue123");
        let pair: zeroize::Zeroizing<String> = creds.to_pair();
        assert_eq!(pair.as_str(), "LTAI5tTestKey:SuperSecretValue123");
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("SuperSecretValue123"), "{dbg}");
        assert!(!dbg.contains("LTAI5tTestKey"), "{dbg}");
        assert!(dbg.contains("redacted"), "{dbg}");

        for bad in [
            "",
            "no-colon",
            ":secret",
            "ak:",
            "ak with space:sk",
            "ak:sk with space",
        ] {
            assert!(parse_token_pair(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn default_aliyun_config_guards_real_home_but_allows_isolated_test_home() {
        let real = tempfile::tempdir().unwrap();
        let isolated = tempfile::tempdir().unwrap();
        let real_cfg = real.path().join(".aliyun").join("config.json");
        let isolated_cfg = isolated.path().join(".aliyun").join("config.json");

        assert_eq!(
            resolve_default_aliyun_config_path(Some(real_cfg.clone()), Some(real.path()), true),
            None
        );
        assert_eq!(
            resolve_default_aliyun_config_path(Some(isolated_cfg.clone()), Some(real.path()), true),
            Some(isolated_cfg)
        );
        assert_eq!(
            resolve_default_aliyun_config_path(Some(real_cfg.clone()), Some(real.path()), false),
            Some(real_cfg)
        );
        assert_eq!(
            resolve_default_aliyun_config_path(None, Some(real.path()), true),
            None
        );
    }

    #[test]
    fn scoped_cua_credential_store_uses_home_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let store = CuaCredentialStore::new(Some(dir.path().to_path_buf()));
        let other_store = CuaCredentialStore::new(Some(other.path().to_path_buf()));
        assert!(store.load().is_none());
        store.save("LTAI_HOME:SecretHome").unwrap();
        assert_eq!(store.load().as_deref(), Some("LTAI_HOME:SecretHome"));
        assert!(
            other_store.load().is_none(),
            "credentials must be scoped to home"
        );
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_some(),
            "secret must be written inside the scoped home dir"
        );
        assert!(store.clear());
        assert!(store.load().is_none());
    }
}

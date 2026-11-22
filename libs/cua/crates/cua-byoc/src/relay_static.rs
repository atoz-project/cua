// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Static Relay Mode credential storage (guarded by an in-process mutex and a
//! cross-process advisory file lock `<home>/cloud/.env-tokens.lock`), relay
//! readiness probes, and [`ConnectionRelay`] unifying Account and Static modes.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use cua_host::RelayClient;
use cua_sandbox_core::Error;

use crate::api::Result;
use crate::relay::{Join, RelayAccess, is_fatal};

/// Resolves the [`cua_auth::Store`] for `home`: in test processes or when
/// `home` differs from `cua_auth::cua_home()`, uses a file-backed store under
/// `home` so tests remain hermetic and never touch the user's real vault.
pub(crate) fn secret_store(home: Option<&std::path::Path>) -> cua_auth::Store {
    match home {
        Some(h) if cua_home::is_test_process() || h != cua_auth::cua_home() => {
            cua_auth::Store::File(h.join("credentials.json"))
        }
        _ => cua_auth::Store::from_env(),
    }
}

fn store_err(e: cua_auth::Error) -> Error {
    Error::Io(std::io::Error::other(e.to_string()))
}

fn secret_key(prefix: &str, provider: &str) -> Result<String> {
    let p = provider.trim().to_ascii_lowercase();
    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
        return Err(Error::InvalidArgument(format!(
            "invalid cloud provider name {provider:?}"
        )));
    }
    Ok(format!("{prefix}{p}"))
}

pub(crate) fn load_static_relay_token(
    home: Option<&std::path::Path>,
    provider: &str,
) -> Result<Option<crate::api::Secret>> {
    let key = secret_key("byoc-relay-token-", provider)?;
    let bytes = secret_store(home).load_secret(&key).map_err(store_err)?;
    Ok(bytes.and_then(|b| {
        String::from_utf8(b)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(crate::api::Secret::new)
    }))
}

pub(crate) fn save_static_relay_token(
    home: Option<&std::path::Path>,
    provider: &str,
    token: &str,
) -> Result<()> {
    let key = secret_key("byoc-relay-token-", provider)?;
    secret_store(home)
        .save_secret(&key, token.trim().as_bytes())
        .map_err(store_err)
}

pub(crate) fn clear_static_relay_token(home: Option<&std::path::Path>, provider: &str) -> bool {
    let Ok(key) = secret_key("byoc-relay-token-", provider) else {
        return false;
    };
    secret_store(home).clear_secret(&key).unwrap_or(false)
}

static ENV_TOKENS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_env_tokens_file(home: Option<&std::path::Path>) -> Result<std::fs::File> {
    let dir = match home {
        Some(h) => h.join("cloud"),
        None => cua_auth::cua_home().join("cloud"),
    };
    std::fs::create_dir_all(&dir).map_err(Error::Io)?;
    let lock_path = dir.join(".env-tokens.lock");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let lock = opts.open(&lock_path).map_err(Error::Io)?;
    lock.lock().map_err(Error::Io)?;
    Ok(lock)
}

fn read_env_tokens_map(store: &cua_auth::Store, key: &str) -> Result<BTreeMap<String, String>> {
    let Some(bytes) = store.load_secret(key).map_err(store_err)? else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

fn write_env_tokens_map(
    store: &cua_auth::Store,
    key: &str,
    map: &BTreeMap<String, String>,
) -> Result<()> {
    if map.is_empty() {
        let _ = store.clear_secret(key);
        return Ok(());
    }
    let bytes = serde_json::to_vec(map).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    store.save_secret(key, &bytes).map_err(store_err)
}

pub(crate) fn save_env_token(
    home: Option<&std::path::Path>,
    provider: &str,
    machine_id: &str,
    token: &str,
) -> Result<()> {
    let key = secret_key("byoc-env-tokens-", provider)?;
    let _g = ENV_TOKENS_LOCK.lock().expect("env tokens lock");
    let _fl = lock_env_tokens_file(home)?;
    let store = secret_store(home);
    let mut map = read_env_tokens_map(&store, &key)?;
    map.insert(machine_id.to_string(), token.to_string());
    write_env_tokens_map(&store, &key, &map)
}

pub(crate) fn load_env_token(
    home: Option<&std::path::Path>,
    provider: &str,
    machine_id: &str,
) -> Result<Option<String>> {
    let key = secret_key("byoc-env-tokens-", provider)?;
    let _g = ENV_TOKENS_LOCK.lock().expect("env tokens lock");
    let _fl = lock_env_tokens_file(home)?;
    let store = secret_store(home);
    let map = read_env_tokens_map(&store, &key)?;
    Ok(map.get(machine_id).cloned())
}

pub(crate) fn remove_env_token(
    home: Option<&std::path::Path>,
    provider: &str,
    machine_id: &str,
) -> Result<()> {
    let key = secret_key("byoc-env-tokens-", provider)?;
    let _g = ENV_TOKENS_LOCK.lock().expect("env tokens lock");
    let _fl = lock_env_tokens_file(home)?;
    let store = secret_store(home);
    let mut map = read_env_tokens_map(&store, &key)?;
    if map.remove(machine_id).is_some() {
        write_env_tokens_map(&store, &key, &map)?;
    }
    Ok(())
}

pub(crate) fn clear_env_tokens(home: Option<&std::path::Path>, provider: &str) -> bool {
    let Ok(key) = secret_key("byoc-env-tokens-", provider) else {
        return false;
    };
    let _g = ENV_TOKENS_LOCK.lock().expect("env tokens lock");
    let _fl = lock_env_tokens_file(home).ok();
    secret_store(home).clear_secret(&key).unwrap_or(false)
}

/// How one cloud connection talks to its relay: Account Relay Mode (account
/// bearer + machine directory) or Static Relay Mode (shared registration token
/// + per-sandbox environment tokens).
#[derive(Clone)]
pub enum ConnectionRelay {
    Account(RelayAccess),
    Static {
        relay_url: String,
        relay_token: Option<crate::api::Secret>,
    },
}

impl ConnectionRelay {
    /// Resolves the relay for creating a new sandbox on `conn`, validating the
    /// static relay URL and registration token before any cloud call.
    pub fn for_create(
        conn: &crate::model::Connection,
        default_relay: &RelayAccess,
        home: Option<&std::path::Path>,
        provider: &str,
        title: &str,
    ) -> Result<Self> {
        if conn.is_static_relay() {
            let relay_url = conn
                .relay_url
                .as_deref()
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .ok_or_else(|| {
                    Error::Cloud(format!(
                        "{title} is connected in Static Relay Mode, but no relay URL is recorded; \
                         reconnect with `cua cloud connect {provider} --relay-mode static \
                         --relay-url <URL> --relay-token-stdin`"
                    ))
                })?
                .to_string();
            let relay_token = load_static_relay_token(home, provider)?.ok_or_else(|| {
                Error::Cloud(format!(
                    "{title} is connected in Static Relay Mode, but its relay token is missing \
                     from the credential store; reconnect with `cua cloud connect {provider} \
                     --relay-mode static --relay-url {relay_url} --relay-token-stdin`"
                ))
            })?;
            return Ok(ConnectionRelay::Static {
                relay_url,
                relay_token: Some(relay_token),
            });
        }
        let url = conn.effective_relay_url(&default_relay.url);
        Ok(ConnectionRelay::Account(default_relay.rebind(url)?))
    }

    /// Resolves the relay for operating on an existing sandbox (`connect_options`,
    /// `start`, `forget_machine`, `sweep`).
    pub fn for_connection(
        conn: &crate::model::Connection,
        default_relay: &RelayAccess,
    ) -> Result<Self> {
        let url = conn.effective_relay_url(&default_relay.url);
        if conn.is_static_relay() {
            return Ok(ConnectionRelay::Static {
                relay_url: url.to_string(),
                relay_token: None,
            });
        }
        Ok(ConnectionRelay::Account(default_relay.rebind(url)?))
    }

    /// Base relay URL.
    pub fn url(&self) -> &str {
        match self {
            ConnectionRelay::Account(r) => &r.url,
            ConnectionRelay::Static { relay_url, .. } => relay_url,
        }
    }

    /// `<relay>/m/<machine>`.
    pub fn machine_url(&self, machine: &str) -> String {
        format!("{}/m/{machine}", self.url().trim_end_matches('/'))
    }

    /// Registers a relay machine (Account mode) or mints and saves a per-sandbox
    /// `env_token` (Static mode). Returns `(join, static_env_token)`.
    pub async fn prepare_join(
        &self,
        store: &crate::state::Store,
        provider: &str,
        machine: &str,
        sandbox_name: &str,
        meta: BTreeMap<String, String>,
        explicit_env_token: Option<&str>,
    ) -> Result<(Join, Option<String>)> {
        match self {
            ConnectionRelay::Account(relay) => {
                let join = relay.register_with(machine, sandbox_name, meta).await?;
                if let Err(e) = relay.online(machine).await
                    && is_fatal(&e)
                {
                    self.forget_machine(store, provider, machine).await;
                    return Err(e);
                }
                Ok((join, None))
            }
            ConnectionRelay::Static {
                relay_url,
                relay_token,
            } => {
                let tok = relay_token.as_ref().ok_or_else(|| {
                    Error::Cloud(format!("{provider}: static relay token not loaded"))
                })?;
                let env_token = explicit_env_token
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| {
                        format!(
                            "{:016x}{:016x}",
                            rand::random::<u64>(),
                            rand::random::<u64>()
                        )
                    });
                save_env_token(store.home().as_deref(), provider, machine, &env_token)?;
                Ok((
                    Join {
                        relay_url: relay_url.clone(),
                        machine_id: machine.to_string(),
                        machine_token: tok.expose().to_string(),
                        jwks_json: String::new(),
                        owner: String::new(),
                        owner_email: String::new(),
                    },
                    Some(env_token),
                ))
            }
        }
    }

    /// Waits until `machine` is reachable on this relay.
    pub async fn wait_online<F, Fut>(
        &self,
        home: Option<&std::path::Path>,
        provider: &str,
        machine: &str,
        env_token: Option<&str>,
        timeout: Duration,
        alive: F,
    ) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        match self {
            ConnectionRelay::Account(relay) => relay.wait_online(machine, timeout, alive).await,
            ConnectionRelay::Static { .. } => {
                let owned_tok;
                let tok = match env_token {
                    Some(t) => t,
                    None => {
                        owned_tok = load_env_token(home, provider, machine)?.ok_or_else(|| {
                            Error::Cloud(format!(
                                "{provider}: environment token for static relay machine {machine} \
                                 is missing from the credential store"
                            ))
                        })?;
                        &owned_tok
                    }
                };
                wait_static_online(&self.machine_url(machine), tok, timeout, alive).await
            }
        }
    }

    /// Connect options for reaching `machine`'s `cua-spacesd` through this relay.
    pub fn connect_options(
        &self,
        home: Option<&std::path::Path>,
        provider: &str,
        machine: &str,
    ) -> Result<cua_spacesd_client::ConnectOptions> {
        match self {
            ConnectionRelay::Account(relay) => relay.connect_options(machine),
            ConnectionRelay::Static { .. } => {
                let mut opts =
                    cua_spacesd_client::ConnectOptions::parse(&self.machine_url(machine))
                        .map_err(|e| Error::InvalidArgument(e.to_string()))?;
                opts.gateway = None;
                opts.token = load_env_token(home, provider, machine)?;
                Ok(opts)
            }
        }
    }

    /// Best-effort cleanup of `machine`: deletes the per-sandbox `env_token`
    /// (Static) or forgets on the relay, queueing an orphaned record on error (Account).
    pub async fn forget_machine(&self, store: &crate::state::Store, provider: &str, machine: &str) {
        match self {
            ConnectionRelay::Static { .. } => {
                let _ = remove_env_token(store.home().as_deref(), provider, machine);
            }
            ConnectionRelay::Account(relay) => {
                if let Err(e) = relay.forget(machine).await {
                    tracing::warn!(machine, "relay machine left for the sweeper: {e}");
                    let _ = store.record(crate::model::Resource {
                        provider: provider.into(),
                        id: machine.into(),
                        resource_type: crate::model::RELAY_MACHINE.into(),
                        name: machine.into(),
                        machine: machine.into(),
                        created: crate::model::now(),
                        state: "orphaned".into(),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Removes `machine` from the relay (Account) or clears its `env_token` (Static).
    pub async fn forget_or_err(
        &self,
        home: Option<&std::path::Path>,
        provider: &str,
        machine: &str,
    ) -> Result<()> {
        match self {
            ConnectionRelay::Static { .. } => {
                let _ = remove_env_token(home, provider, machine);
                Ok(())
            }
            ConnectionRelay::Account(relay) => relay.forget(machine).await,
        }
    }

    /// Cleans up or queues relay-machine cleanup after a swept VM is deleted.
    pub fn cleanup_deleted_machine(
        conn: &crate::model::Connection,
        store: &crate::state::Store,
        provider: &str,
        machine: &str,
        now: u64,
    ) {
        if conn.is_static_relay() {
            let _ = remove_env_token(store.home().as_deref(), provider, machine);
        } else {
            let _ = store.record(crate::model::Resource {
                provider: provider.into(),
                id: machine.into(),
                resource_type: crate::model::RELAY_MACHINE.into(),
                name: machine.into(),
                machine: machine.into(),
                created: now,
                state: "orphaned".into(),
                ..Default::default()
            });
        }
    }
}

/// Probes `GET /v1/info` on a relay URL and checks mode compatibility.
pub(crate) async fn probe_relay_check(
    url: &str,
    mode: cua_sandbox_core::byoc::RelayMode,
) -> cua_sandbox_core::byoc::CloudCheck {
    let client = match RelayClient::new(url) {
        Ok(c) => c,
        Err(e) => {
            return cua_sandbox_core::byoc::CloudCheck {
                name: "relay".into(),
                ok: false,
                detail: format!("invalid relay URL {url}: {e}"),
            };
        }
    };
    match client.info().await {
        Ok(info) => match mode {
            cua_sandbox_core::byoc::RelayMode::Static => {
                if info.static_tokens {
                    cua_sandbox_core::byoc::CloudCheck {
                        name: "relay".into(),
                        ok: true,
                        detail: format!("Static Relay Mode at {url}"),
                    }
                } else {
                    cua_sandbox_core::byoc::CloudCheck {
                        name: "relay".into(),
                        ok: false,
                        detail: format!(
                            "relay at {url} does not accept static tokens (`static_tokens: false`)"
                        ),
                    }
                }
            }
            cua_sandbox_core::byoc::RelayMode::Account => {
                if info.account_auth {
                    cua_sandbox_core::byoc::CloudCheck {
                        name: "relay".into(),
                        ok: true,
                        detail: format!("Account Relay Mode at {url}"),
                    }
                } else {
                    cua_sandbox_core::byoc::CloudCheck {
                        name: "relay".into(),
                        ok: false,
                        detail: format!(
                            "relay at {url} does not accept account auth (`account_auth: false`)"
                        ),
                    }
                }
            }
        },
        Err(e) => cua_sandbox_core::byoc::CloudCheck {
            name: "relay".into(),
            ok: false,
            detail: format!("relay at {url} unreachable: {e}"),
        },
    }
}

/// Waits until a Static Relay Mode machine answers authenticated
/// `GetCapabilities` through `<relay_url>/m/<machine_id>` with `Bearer <env_token>`.
/// Fails fast on `Unauthenticated` (wrong or rejected `env_token`).
pub(crate) async fn wait_static_online<F, Fut>(
    machine_url: &str,
    env_token: &str,
    timeout: Duration,
    mut alive: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut polls = 0u32;
    let mut opts = cua_spacesd_client::ConnectOptions::parse(machine_url)
        .map_err(|e| Error::InvalidArgument(e.to_string()))?;
    opts.gateway = None;
    opts.token = Some(env_token.to_string());
    opts.probe = true;
    opts.probe_timeout = Duration::from_secs(5);
    loop {
        let last_error = match cua_spacesd_client::SpacesdClient::connect(opts.clone()).await {
            Ok(_) => return Ok(()),
            Err(cua_spacesd_client::Error::Unauthenticated(d)) => {
                return Err(Error::Cloud(format!(
                    "static relay rejected environment token at {machine_url}: {d}"
                )));
            }
            Err(e) => Some(e.to_string()),
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Timeout(match last_error {
                Some(e) => format!(
                    "{machine_url} did not become reachable over the static relay within {}s \
                     (last error: {e})",
                    timeout.as_secs()
                ),
                None => format!(
                    "{machine_url} did not become reachable over the static relay within {}s",
                    timeout.as_secs()
                ),
            }));
        }
        polls += 1;
        if polls == 1 || polls.is_multiple_of(4) {
            alive().await?;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::sleep(remaining.min(Duration::from_secs(2))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_tokens_concurrent_writers_preserve_all_entries_and_create_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let h = home.clone();
                std::thread::spawn(move || {
                    for i in 0..8 {
                        let id = format!("cloud-t{t}-{i}");
                        let tok = format!("tok-{t}-{i}");
                        save_env_token(Some(&h), "aliyun-ecs", &id, &tok).unwrap();
                    }
                })
            })
            .collect();
        for th in threads {
            th.join().unwrap();
        }
        assert!(
            home.join("cloud").join(".env-tokens.lock").exists(),
            "cross-process advisory lock file must be created"
        );
        for t in 0..8 {
            for i in 0..8 {
                let id = format!("cloud-t{t}-{i}");
                let want = format!("tok-{t}-{i}");
                assert_eq!(
                    load_env_token(Some(&home), "aliyun-ecs", &id).unwrap(),
                    Some(want),
                    "lost concurrent write for {id}"
                );
            }
        }
        remove_env_token(Some(&home), "aliyun-ecs", "cloud-t0-0").unwrap();
        assert_eq!(
            load_env_token(Some(&home), "aliyun-ecs", "cloud-t0-0").unwrap(),
            None
        );
        assert!(clear_env_tokens(Some(&home), "aliyun-ecs"));
        assert_eq!(
            load_env_token(Some(&home), "aliyun-ecs", "cloud-t1-1").unwrap(),
            None
        );
    }
}

//! URL and Space-ID registration (`Spaces::add`, `Spaces::add_with_service`,
//! URL-backed direct Space resolution, and custom Account-Relay origin merging).

use crate::error::{Error, Result};
use crate::id::{SpaceId, authority};
use crate::registry::Credential;
use crate::space::{Space, SpaceInfo};
use crate::spaces::Spaces;

/// Parsed registration plan for [`Spaces::add_with_service`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AddPlan {
    /// Explicit Space id (`local:`, `cloud:`, `direct:`, `relay:`, `space://`).
    ById { id: SpaceId, credential: Credential },
    /// Plain HTTP MCP service (`--service` on `/m/...`, or `/m/<non-machine-id>` without token).
    PlainMcp {
        direct_id: SpaceId,
        raw_url: String,
        token: Option<String>,
        service: Option<String>,
    },
    /// Direct `cua-spacesd` URL with automatic plain-MCP fallback if handshake says not spacesd.
    DirectOrMcp {
        direct_id: SpaceId,
        raw_url: String,
        token: Option<String>,
        service: Option<String>,
    },
    /// Validated `<origin>/m/<machine-id>` Static Relay URL with mandatory non-empty token;
    /// falls back to `direct_id` plain MCP if handshake says not spacesd.
    StaticRelayOrMcp {
        relay_id: SpaceId,
        direct_id: SpaceId,
        endpoint_url: String,
        raw_url: String,
        token: String,
    },
}

fn is_explicit_id(url: &str) -> bool {
    url.starts_with("space://")
        || ["local:", "cloud:", "direct:", "relay:"]
            .iter()
            .any(|p| url.starts_with(p))
}

/// Pure boundary parser for `(url, token, service)` before any network or disk I/O.
pub(crate) fn plan_add(
    url: &str,
    token: Option<String>,
    service: Option<String>,
) -> Result<AddPlan> {
    let url = url.trim();
    let token = token.filter(|t| !t.trim().is_empty());
    let explicit_service = service.filter(|s| !s.trim().is_empty());

    if is_explicit_id(url) {
        let id = SpaceId::parse(url)?;
        let endpoint_url = match &id {
            SpaceId::Direct { authority } => Some(format!("http://{authority}")),
            _ => None,
        };
        return Ok(AddPlan::ById {
            id,
            credential: Credential {
                url: endpoint_url,
                token,
                ..Default::default()
            },
        });
    }

    let raw_url = if url.contains("://") {
        url.to_string()
    } else {
        format!("http://{url}")
    };
    let endpoint = cua_spacesd_client::Endpoint::parse(&raw_url)?;
    let direct_id = SpaceId::Direct {
        authority: authority(endpoint.host(), endpoint.port()),
    };

    let Some((machine_id, has_extra_segments)) =
        cua_spacesd_client::relay_path_segments(endpoint.base_url())
    else {
        return Ok(AddPlan::DirectOrMcp {
            direct_id,
            raw_url,
            token,
            service: explicit_service,
        });
    };

    if explicit_service.is_some() {
        return Ok(AddPlan::PlainMcp {
            direct_id,
            raw_url,
            token,
            service: explicit_service,
        });
    }

    let valid_id = cua_spacesd_client::valid_machine_id(machine_id);
    match (valid_id && !has_extra_segments, token) {
        (true, None) => Err(Error::invalid(format!(
            "Static Relay URL {endpoint} requires a non-empty token; \
             pass --token <token> or set CUA_ENV_TOKEN"
        ))),
        (false, Some(_)) if !valid_id => Err(Error::invalid(format!(
            "invalid Static Relay machine id {machine_id:?}: must match \
             [a-z0-9-]{{8,64}} (lowercase letters, digits, and hyphens, \
             without leading or trailing '-')"
        ))),
        (false, Some(_)) => Err(Error::invalid(format!(
            "invalid Static Relay URL {raw_url:?}: expected \
             <origin>/m/<machine-id> without extra path segments"
        ))),
        (false, None) => Ok(AddPlan::PlainMcp {
            direct_id,
            raw_url,
            token: None,
            service: None,
        }),
        (true, Some(token)) => Ok(AddPlan::StaticRelayOrMcp {
            relay_id: SpaceId::Relay {
                machine_id: machine_id.to_string(),
            },
            direct_id,
            endpoint_url: endpoint.to_string(),
            raw_url,
            token,
        }),
    }
}

/// Validates that `url` can be registered as a `--host` Direct Host before any
/// network or registry mutation.
pub(crate) fn ensure_direct_host_add_allowed(url: &str) -> Result<()> {
    let url = url.trim();
    if is_explicit_id(url) {
        let id = SpaceId::parse(url)?;
        if !matches!(id, SpaceId::Direct { .. }) {
            return Err(Error::invalid(format!(
                "{id} is not reached by a direct address; a host to add with --host is \
                 `<tailscale or LAN address>:<port>`"
            )));
        }
        return Ok(());
    }
    let raw_url = if url.contains("://") {
        url.to_string()
    } else {
        format!("http://{url}")
    };
    let endpoint = cua_spacesd_client::Endpoint::parse(&raw_url)?;
    if cua_spacesd_client::relay_path_segments(endpoint.base_url()).is_some() {
        return Err(Error::invalid(format!(
            "{endpoint} is a Static Relay URL and cannot be added with --host; \
             a Direct Host to add with --host is `<tailscale or LAN address>:<port>`"
        )));
    }
    Ok(())
}

/// Errors from the spacesd handshake that mean "this URL is not an spacesd"
/// (so it may be another service), as opposed to failures to report as they are.
fn not_an_spacesd(e: &Error) -> bool {
    matches!(
        e,
        Error::SpacesdNotAvailable { .. }
            | Error::Env(cua_spacesd_client::Error::Unauthenticated(_))
            | Error::Env(cua_spacesd_client::Error::Transport(_))
    )
}

impl Spaces {
    /// Matches an `http(s)://` input against registered `direct:` Space URLs
    /// (including plain MCP services mounted at `/m/<valid_machine_id>`) before
    /// `SpaceId::parse` classifies `/m/<valid_machine_id>` as `SpaceId::Relay`.
    pub(crate) fn direct_space_for_url(&self, space: &str) -> Option<SpaceId> {
        let s = space.trim();
        if !(s.starts_with("http://") || s.starts_with("https://")) {
            return None;
        }
        let wanted = cua_spacesd_client::Endpoint::parse(s).ok()?;
        let records = self.inner.registry.list().ok()?;
        let matches_url = |u: &str| {
            cua_spacesd_client::Endpoint::parse(u).is_ok_and(|e| e.base_url() == wanted.base_url())
        };
        for r in &records {
            if let Ok(id @ SpaceId::Direct { .. }) = SpaceId::parse(&r.id)
                && let Ok(Some(cred)) = self.inner.registry.credential(&r.id)
                && (cred.url.as_deref().is_some_and(matches_url)
                    || cred.service_urls.values().any(|u| matches_url(u)))
            {
                return Some(id);
            }
        }
        None
    }

    /// Queries distinct custom Account-Relay origins registered in `spaces.json`
    /// and merges their machine rows into `machines` (retaining previously cached
    /// rows for that origin on transient or offline errors).
    pub(crate) async fn merge_custom_relay_origins(
        &self,
        relay: &crate::relay::RelayAccount,
        cached: &[crate::relay::RelayMachine],
        machines: &mut Vec<crate::relay::RelayMachine>,
    ) {
        let mut custom_origins: Vec<(String, std::collections::BTreeSet<String>)> = Vec::new();
        for r in self.inner.registry.list().unwrap_or_default() {
            if let Some(machine_id) = r.id.strip_prefix("relay:")
                && let Some(origin) = self.custom_account_relay_origin(machine_id, &relay.url)
            {
                if let Some((_, ids)) = custom_origins.iter_mut().find(|(o, _)| *o == origin) {
                    ids.insert(machine_id.to_string());
                } else {
                    custom_origins.push((origin, [machine_id.to_string()].into_iter().collect()));
                }
            }
        }
        for (origin, ids) in custom_origins {
            let extra: Result<Vec<crate::relay::RelayMachine>> = async {
                let custom = relay.rebind(&origin)?;
                let token = custom.tokens.access_token().await?;
                let client = cua_host::RelayClient::new(&custom.url)?;
                Ok(match &custom.device {
                    Some(d) => d.machines_for(&client, &token).await?,
                    None => client.machines(&token).await?,
                })
            }
            .await;
            match extra {
                Ok(rows) => {
                    for m in rows {
                        if let Some(existing) = machines.iter_mut().find(|e| e.id == m.id) {
                            *existing = m;
                        } else {
                            machines.push(m);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        origin = %origin,
                        error = %e,
                        "custom relay directory read failed; retaining cached entries"
                    );
                    for m in cached.iter().filter(|m| ids.contains(&m.id)) {
                        if !machines.iter().any(|e| e.id == m.id) {
                            machines.push(m.clone());
                        }
                    }
                }
            }
        }
    }

    /// Adds a Space by URL and stores it.
    ///
    /// `url` is `http(s)://host:port` (direct), bare `host:port`, or a
    /// Space id (`cloud:<name>`, `local:<name>`, `direct:<host:port>`, or a
    /// legacy `space://…` spelling). A URL that answers the
    /// spacesd `GetCapabilities` handshake is a spacesd Space; any
    /// other URL that answers MCP `initialize` (for example
    /// `http://host:8765/mcp`) becomes a Space with one service, `mcp`, and
    /// an empty capability set. Re-adding updates the entry.
    pub async fn add(
        &self,
        url: &str,
        token: Option<String>,
        name: Option<String>,
    ) -> Result<SpaceInfo> {
        self.add_with_service(url, token, name, None).await
    }

    /// [`Spaces::add`], naming the service a plain MCP URL is registered
    /// under (default `mcp`).
    pub async fn add_with_service(
        &self,
        url: &str,
        token: Option<String>,
        name: Option<String>,
        service: Option<String>,
    ) -> Result<SpaceInfo> {
        let name = name.filter(|n| !n.trim().is_empty());

        let (id, space, credential, prev_origin) = match plan_add(url, token, service)? {
            AddPlan::ById { id, credential } => {
                let record = self.inner.registry.get(&id.to_string())?;
                let space = self
                    .connect(&id, &credential, name.as_deref(), record.as_ref())
                    .await?;
                (id, space, credential, None)
            }
            AddPlan::PlainMcp {
                direct_id,
                raw_url,
                token,
                service,
            } => {
                let (space, mcp_cred) = self
                    .try_add_plain_mcp(
                        &direct_id,
                        &raw_url,
                        token,
                        name.as_deref(),
                        service.as_deref(),
                        None,
                    )
                    .await?;
                (direct_id, space, mcp_cred, None)
            }
            AddPlan::DirectOrMcp {
                direct_id,
                raw_url,
                token,
                service,
            } => {
                let credential = Credential {
                    url: Some(raw_url.clone()),
                    token: token.clone(),
                    ..Default::default()
                };
                let record = self.inner.registry.get(&direct_id.to_string())?;
                match self
                    .connect(&direct_id, &credential, name.as_deref(), record.as_ref())
                    .await
                {
                    Ok(space) => (direct_id, space, credential, None),
                    Err(e) if not_an_spacesd(&e) => {
                        let (space, mcp_cred) = self
                            .try_add_plain_mcp(
                                &direct_id,
                                &raw_url,
                                token,
                                name.as_deref(),
                                service.as_deref(),
                                Some(e),
                            )
                            .await?;
                        (direct_id, space, mcp_cred, None)
                    }
                    Err(e) => return Err(e),
                }
            }
            AddPlan::StaticRelayOrMcp {
                relay_id,
                direct_id,
                endpoint_url,
                raw_url,
                token,
            } => {
                let key = relay_id.to_string();
                let record = self.inner.registry.get(&key)?;
                let existing_cred = self.inner.registry.credential(&key).ok().flatten();
                let same_cred = existing_cred.as_ref().is_some_and(|c| {
                    c.url.as_deref() == Some(endpoint_url.as_str())
                        && c.token.as_deref() == Some(token.as_str())
                });
                let new_origin = cua_spacesd_client::Endpoint::parse(&endpoint_url)
                    .ok()
                    .map(|e| e.origin());
                let prev_origin = existing_cred
                    .as_ref()
                    .and_then(|c| c.url.as_deref())
                    .filter(|u| !u.trim().is_empty())
                    .and_then(|u| cua_spacesd_client::Endpoint::parse(u).ok())
                    .map(|e| e.origin())
                    .filter(|prev| Some(prev) != new_origin.as_ref());
                if record.is_some() && same_cred {
                    let machine_id = match &relay_id {
                        SpaceId::Relay { machine_id } => Some(machine_id.as_str()),
                        _ => None,
                    };
                    self.inner.mesh.forget_space(&key, machine_id).await;
                }
                let credential = Credential {
                    url: Some(endpoint_url),
                    token: Some(token.clone()),
                    ..Default::default()
                };
                let effective_name = name.as_deref().or_else(|| {
                    record
                        .as_ref()
                        .map(|r| r.name.as_str())
                        .filter(|n| !n.is_empty())
                });
                let attempt = match self
                    .connect(&relay_id, &credential, effective_name, record.as_ref())
                    .await
                {
                    Ok(space) => Ok((relay_id.clone(), space, credential, prev_origin)),
                    Err(e) if not_an_spacesd(&e) => self
                        .try_add_plain_mcp(
                            &direct_id,
                            &raw_url,
                            Some(token),
                            name.as_deref(),
                            None,
                            Some(e),
                        )
                        .await
                        .map(|(space, mcp_cred)| (direct_id, space, mcp_cred, None)),
                    Err(e) => Err(e),
                };
                match attempt {
                    Ok(res) => res,
                    Err(e) => {
                        if record.is_some() && same_cred {
                            self.forget_stale_connection(&key).await;
                            self.clear_dial_state(&key, &relay_id, true).await;
                        }
                        return Err(e);
                    }
                }
            }
        };

        let key = id.to_string();
        self.store(&space, credential)?;
        if let SpaceId::Relay { machine_id } = &id
            && let Some(prev_orig) = prev_origin
        {
            self.inner
                .mesh
                .forget_static_machine(&prev_orig, machine_id)
                .await;
        }
        if name.is_some()
            && self
                .inner
                .registry
                .meta(&key)
                .is_some_and(|m| !m.display_name.is_empty())
        {
            self.inner
                .registry
                .update_meta(&key, |m| m.display_name.clear())?;
        }
        let forget_mesh = space.route().map(|r| r.transport()) != Some(crate::Transport::Mesh);
        self.clear_dial_state(&key, &id, forget_mesh).await;
        self.inner.connections.lock().await.insert(key, space);
        self.info(&id)
    }

    async fn try_add_plain_mcp(
        &self,
        direct_id: &SpaceId,
        mcp_url: &str,
        token: Option<String>,
        name: Option<&str>,
        service: Option<&str>,
        spacesd_err: Option<Error>,
    ) -> Result<(Space, Credential)> {
        let service = service
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("mcp")
            .to_string();
        let mut credential = Credential {
            url: Some(mcp_url.to_string()),
            token,
            ..Default::default()
        };
        credential
            .service_urls
            .insert(service.clone(), mcp_url.to_string());
        let record = self.inner.registry.get(&direct_id.to_string())?;
        let space = self
            .connect(direct_id, &credential, name, record.as_ref())
            .await?;
        if let Err(mcp) = space.mcp(&service).await {
            return Err(match spacesd_err {
                Some(Error::SpacesdNotAvailable { reason, .. }) => Error::SpacesdNotAvailable {
                    space: direct_id.to_string(),
                    reason: format!("{reason}; no MCP server answered either ({mcp})"),
                },
                Some(other) => other,
                None => mcp,
            });
        }
        Ok((space, credential))
    }

    /// Forgets a Space (registry entry and stored token). The sandbox is not
    /// touched.
    pub async fn remove(&self, space: &str) -> Result<SpaceInfo> {
        #[cfg(feature = "spaces-stream")]
        self.drop_stream_entries(space);
        let id = self.resolve(space)?;
        let info = self.info(&id).ok();
        let _ = crate::lifetimes::forget(self.home_dir(), &id.to_string());
        self.drop_connection(&id).await;
        let mut relay_known = info.is_some();
        if let SpaceId::Relay { machine_id } = &id
            && !self.is_static_relay_machine(machine_id)
            && self.relay_account().is_some()
            && let Some(m) = self
                .relay_machines()
                .await
                .ok()
                .and_then(|all| all.into_iter().find(|m| &m.id == machine_id))
        {
            relay_known = true;
            if m.role == "owner" && !m.online && crate::relay::is_registered_space(&m) {
                self.forget_relay_machine(machine_id, false).await?;
            }
        }
        #[cfg(feature = "spaces-agents")]
        if !matches!(id, SpaceId::Relay { .. }) {
            let _ = self.release_attached(&id.to_string()).await;
        }
        if matches!(id, SpaceId::Direct { .. }) {
            let is_host = self
                .inner
                .registry
                .direct_hosts()
                .is_ok_and(|hosts| hosts.iter().any(|h| h.space == id.to_string()));
            if is_host {
                self.forget_host_spaces(&id.to_string()).await;
            }
            let _ = self.inner.registry.forget_direct(&id.to_string());
        }
        if !self.inner.registry.remove(&id.to_string())? && !relay_known {
            return Err(Error::NotFound(id.to_string()));
        }
        self.inner.thumbnails.remove(&id.to_string());
        match info {
            Some(info) => Ok(info),
            None => SpaceInfo::from_record(&cua_proto::daemon::v1::Space {
                id: id.to_string(),
                name: id.short_name().into(),
                ..Default::default()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cua_spacesd_client::testing::{MockAuth, MockServer};
    use std::time::Duration;

    #[test]
    fn plan_add_classifies_all_variants_and_rejects_bad_static_relay_inputs() {
        assert_eq!(
            plan_add("relay:0123abcd4567ef89", None, None).unwrap(),
            AddPlan::ById {
                id: SpaceId::Relay {
                    machine_id: "0123abcd4567ef89".into()
                },
                credential: Credential::default(),
            }
        );

        assert_eq!(
            plan_add("10.0.0.5:4000", Some("tok".into()), None).unwrap(),
            AddPlan::DirectOrMcp {
                direct_id: SpaceId::Direct {
                    authority: "10.0.0.5:4000".into()
                },
                raw_url: "http://10.0.0.5:4000".into(),
                token: Some("tok".into()),
                service: None,
            }
        );

        assert_eq!(
            plan_add("http://127.0.0.1:8765/m/tools", None, None).unwrap(),
            AddPlan::PlainMcp {
                direct_id: SpaceId::Direct {
                    authority: "127.0.0.1:8765".into()
                },
                raw_url: "http://127.0.0.1:8765/m/tools".into(),
                token: None,
                service: None,
            }
        );

        assert_eq!(
            plan_add(
                "http://127.0.0.1:8765/m/0123abcd4567ef89",
                Some("tok".into()),
                Some("mcp".into())
            )
            .unwrap(),
            AddPlan::PlainMcp {
                direct_id: SpaceId::Direct {
                    authority: "127.0.0.1:8765".into()
                },
                raw_url: "http://127.0.0.1:8765/m/0123abcd4567ef89".into(),
                token: Some("tok".into()),
                service: Some("mcp".into()),
            }
        );

        assert_eq!(
            plan_add(
                "https://relay.example/m/0123abcd4567ef89/",
                Some("tok".into()),
                None
            )
            .unwrap(),
            AddPlan::StaticRelayOrMcp {
                relay_id: SpaceId::Relay {
                    machine_id: "0123abcd4567ef89".into()
                },
                direct_id: SpaceId::Direct {
                    authority: "relay.example:443".into()
                },
                endpoint_url: "https://relay.example/m/0123abcd4567ef89".into(),
                raw_url: "https://relay.example/m/0123abcd4567ef89/".into(),
                token: "tok".into(),
            }
        );

        assert!(plan_add("https://relay.example/m/0123abcd4567ef89", None, None).is_err());
        assert!(plan_add("https://relay.example/m/BAD_ID_01", Some("t".into()), None).is_err());
        assert!(
            plan_add(
                "https://relay.example/m/0123abcd4567ef89/extra",
                Some("t".into()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn ensure_direct_host_add_allowed_rejects_relay_urls_and_non_direct_ids() {
        assert!(ensure_direct_host_add_allowed("100.64.0.2:3211").is_ok());
        assert!(ensure_direct_host_add_allowed("direct:100.64.0.2:3211").is_ok());
        assert!(
            ensure_direct_host_add_allowed("https://relay.example/m/0123abcd4567ef89").is_err()
        );
        assert!(ensure_direct_host_add_allowed("relay:0123abcd4567ef89").is_err());
        assert!(ensure_direct_host_add_allowed("local:box").is_err());
    }

    #[tokio::test]
    async fn atomic_re_add_preserves_live_connection_on_typo_and_evicts_on_same_cred_failure() {
        let srv = MockServer::start(MockAuth {
            token: Some("tok-v1".into()),
            prefix: Some("/m/0123abcd4567ef89".into()),
            gateway: None,
        })
        .await;
        let url = format!("http://{}/m/0123abcd4567ef89", srv.addr);
        let home = tempfile::tempdir().unwrap();
        let spaces = Spaces::builder()
            .home(home.path())
            .probe_timeout(Duration::from_secs(2))
            .build();

        let info = spaces
            .add(&url, Some("tok-v1".into()), Some("office-gpu".into()))
            .await
            .unwrap();
        assert_eq!(info.id, "relay:0123abcd4567ef89");

        let live = spaces.space("office-gpu").await.unwrap();
        assert!(
            live.bash("echo v1-ok", Duration::from_secs(3))
                .await
                .unwrap()
                .render()
                .contains("v1-ok")
        );

        // Mistyped NEW token (!same_cred) fails without dropping cached connection or mutating store.
        assert!(
            spaces
                .add(&url, Some("typo-token".into()), None)
                .await
                .is_err()
        );
        assert_eq!(
            spaces
                .registry()
                .credential("relay:0123abcd4567ef89")
                .unwrap()
                .and_then(|c| c.token),
            Some("tok-v1".into())
        );
        assert!(
            spaces
                .inner
                .connections
                .lock()
                .await
                .contains_key("relay:0123abcd4567ef89"),
            "mistyped new token must not drop the active connection"
        );
        assert!(
            spaces
                .space("office-gpu")
                .await
                .unwrap()
                .bash("echo still-live", Duration::from_secs(3))
                .await
                .unwrap()
                .render()
                .contains("still-live")
        );

        // Stopping server and re-adding SAME token (same_cred) evicts the stale cached connection.
        drop(srv);
        assert!(spaces.add(&url, Some("tok-v1".into()), None).await.is_err());
        assert!(
            !spaces
                .inner
                .connections
                .lock()
                .await
                .contains_key("relay:0123abcd4567ef89"),
            "same_cred failure must evict stale cached connection"
        );
    }

    #[tokio::test]
    async fn plain_mcp_on_valid_machine_id_path_resolves_as_direct_by_url() {
        let mcp = cua_sandbox_core::testing::McpTestServer::start("/m")
            .await
            .unwrap();
        let url = format!("{}/m/mcp", mcp.url);
        let home = tempfile::tempdir().unwrap();
        let spaces = Spaces::builder()
            .home(home.path())
            .probe_timeout(Duration::from_secs(2))
            .build();

        let added = spaces
            .add_with_service(&url, None, Some("plain-mcp".into()), Some("mcp".into()))
            .await
            .unwrap();
        assert!(added.id.starts_with("direct:"), "{}", added.id);
        assert_eq!(spaces.resolve(&url).unwrap().to_string(), added.id);
        assert_eq!(
            spaces.resolve(&format!("{url}/")).unwrap().to_string(),
            added.id
        );
    }
}

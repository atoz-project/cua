// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Spaces in your own cloud account (`on="aws"`, `"gcp"`, `"hetzner"`, `"modal"`).
//!
//! A cloud Space is a sandbox from that provider (the sandbox layer owns
//! the cloud: provisioning, tags, records, stop and start, cleanup; see
//! `cua_sandbox_core::byoc`) whose cua-spacesd joined the cua.ai relay as a
//! machine of the signed-in account. The Space is that relay machine,
//! `relay:<machine>`; deleting it deletes the sandbox, and stop_space /
//! start_space stop and start it ([`Spaces::stop`]).

use crate::relay::RelayMachine;
use crate::{Error, Result, SpaceCreate, SpaceInfo, Spaces};
use cua_proto::env::v1 as pb;
use cua_sandbox_core::byoc::DETAIL_RELAY_MACHINE;
use cua_sandbox_core::byoc::meta;
use cua_sandbox_core::placement::Kind;
use cua_sandbox_core::{CreateOptions, ProviderKind};

pub use cua_sandbox_core::byoc::{
    CloudAuditEntry, CloudCheck, CloudConnected, CloudCredentials, CloudDisconnected, CloudKind,
    CloudProvider, CloudResource, CloudStatusReport, CloudSweepItem, CloudSweepReport, CloudTarget,
    CloudTestReport,
};

/// `SpaceInfo::cloud_delete`: this home created it and deletes it.
pub const DELETE_HERE: &str = "here";
/// `SpaceInfo::cloud_delete`: only the device that created it can.
pub const DELETE_ELSEWHERE: &str = "elsewhere";

/// Whether a relay machine is a Space in someone's own cloud (its relay
/// metadata names the provider).
pub fn is_cloud_machine(m: &RelayMachine) -> bool {
    m.meta.get(meta::PROVIDER).is_some_and(|p| !p.is_empty())
}

impl Spaces {
    /// Deletes a Space in your cloud that another device of the account
    /// created: that device does it through its own ownership records when
    /// it is a host the relay reaches (`DeleteCloudSpace`); otherwise this
    /// refuses and says where to delete it. Nothing here holds that cloud's
    /// credentials.
    pub(crate) async fn delete_cloud_elsewhere(&self, m: &RelayMachine) -> Result<String> {
        let id = format!("relay:{}", m.id);
        let place = m
            .meta
            .get(meta::PLACE)
            .cloned()
            .unwrap_or_else(|| m.meta.get(meta::PROVIDER).cloned().unwrap_or_default());
        let device = m
            .meta
            .get(meta::DEVICE)
            .filter(|d| !d.is_empty())
            .cloned()
            .unwrap_or_else(|| "the device that created it".into());
        let Some(host) = m.meta.get(meta::HOST).filter(|h| !h.is_empty()) else {
            return Err(Error::host(
                "the device that created it",
                format!(
                    "{id} runs in {place} and was created on {device}, which keeps its cloud \
                     records: delete it there, or remove it from this list"
                ),
            ));
        };
        let row = self
            .relay_machines()
            .await?
            .into_iter()
            .find(|r| &r.id == host);
        match row {
            Some(r) if r.online => {}
            _ => {
                return Err(Error::host(
                    "the device that created it",
                    format!(
                        "{id} runs in {place} and {device}, which created it, is offline: turn \
                         it on and try again, or remove it from this list"
                    ),
                ));
            }
        }
        let host_space = self.space(&format!("relay:{host}")).await?;
        let message = host_space
            .spacesd()?
            .host_spaces()
            .delete_cloud_space(pb::DeleteCloudSpaceRequest {
                space: m.id.clone(),
            })
            .await
            .map(|r| r.into_inner().message)
            .map_err(|e| crate::host_spaces::from_host(cua_spacesd_client::Error::from(e)))?;
        Ok(format!("{message} (on {device})"))
    }

    /// Creates a Space in your cloud `word`: a sandbox there, then its
    /// relay machine as the Space.
    pub(crate) async fn create_in_cloud(&self, word: &str, opts: SpaceCreate) -> Result<SpaceInfo> {
        // Every way here (an explicit `on`, `auto`, overflow onto a Spaces
        // supplier) keeps the Space's network or refuses it before anything
        // is made: never a Space that runs more open than it asked.
        let settings = opts.network_settings.clone().unwrap_or_else(|| {
            crate::network::NetworkSettings::migrate(
                &opts.egress,
                opts.network == cua_sandbox_core::NetworkMode::None,
            )
        });
        let provider = self.inner.sandboxes.contrib_provider(word).ok().cloned();
        cloud_network(
            word,
            &settings,
            provider.as_ref().is_some_and(|p| p.takes_network_rules()),
            provider.as_ref().is_some_and(|p| p.keeps_internet_only()),
            crate::network::Mode::from_env(),
        )?;
        let static_relay = self
            .inner
            .sandboxes
            .clouds()
            .ok()
            .and_then(|c| c.relay_mode(word))
            == Some(cua_sandbox_core::byoc::RelayMode::Static);
        let default_relay_url = if static_relay {
            None
        } else {
            Some(self.relay()?.url)
        };
        let image = opts
            .image
            .clone()
            .filter(|i| !i.trim().is_empty())
            .unwrap_or_else(|| "linux".to_string());
        let mut create = CreateOptions::new(ProviderKind::Contrib, &image);
        let raw_ref = image
            .trim()
            .strip_prefix("vm:")
            .or_else(|| image.trim().strip_prefix("container:"))
            .or_else(|| image.trim().strip_prefix("docker:"))
            .unwrap_or(image.trim());
        if let Some((_, os)) = cua_image::canonical::alias_with(raw_ref, &|n| std::env::var(n).ok())
        {
            create.os = os.as_str().to_string();
        } else if let Some(os) = cua_image::catalog::catalog_os(raw_ref) {
            create.os = os;
        }
        create.contrib = Some(word.to_string());
        create.name = Some(
            opts.name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .map(|n| crate::spaces::sanitize_label(&n))
                .unwrap_or_else(|| self.fresh_name()),
        );
        if opts.kind != Kind::Auto {
            create.kind = opts.kind;
        }
        create.runtime = opts.runtime.clone();
        if let Some(c) = opts.cpus {
            create.cpus = c;
        }
        if let Some(m) = opts.memory_mb {
            create.memory_mb = m;
        }
        if opts.disk_gb == Some(0) {
            return Err(Error::invalid("disk_gb must be greater than 0"));
        }
        create.disk_gb = opts.disk_gb;
        create.cloud_image_id = cua_sandbox_core::byoc::normalize_optional_token(
            "cloud_image_id",
            opts.cloud_image_id.as_deref(),
        )?;
        create.instance_type = cua_sandbox_core::byoc::normalize_optional_token(
            "instance_type",
            opts.instance_type.as_deref(),
        )?;
        if let Some(t) = opts.timeout {
            create.ready_timeout = t;
            create.ready_timeout_given = true;
        }
        // The Space's network rules go to the cloud with it: a cloud that
        // enforces them keeps them (Modal), any other refuses the create.
        // They are never dropped, whether the cloud was named, picked by
        // `auto` or reached by overflow.
        create.egress = settings.custom.clone();
        create.network = if settings.default_drops() {
            cua_sandbox_core::NetworkMode::None
        } else {
            opts.network
        };
        create.network_settings = Some(settings.clone());
        create.env = opts.env.clone();
        create.command = opts.command.clone();
        create.services = opts.services.clone();
        let sandbox = self.inner.sandboxes.create(create).await?;
        let sb_name = sandbox.name().to_string();
        let record_result: Result<String> = async {
            let machine = sandbox
                .provider_details()
                .get(DETAIL_RELAY_MACHINE)
                .cloned()
                .ok_or_else(|| {
                    Error::invalid(format!(
                        "{word} sandbox {sb_name} did not join the relay (no relay computer)"
                    ))
                })?;
            let id = format!("relay:{machine}");
            let endpoint_url = match sandbox.service("env") {
                Ok(svc) => svc.endpoint().await.ok().map(|e| e.url),
                Err(_) => None,
            };
            let custom_account_relay = match (&default_relay_url, endpoint_url.as_deref()) {
                (Some(default_url), Some(ep)) => {
                    let default_origin = cua_spacesd_client::ConnectOptions::parse(default_url)
                        .ok()
                        .map(|o| o.endpoint.origin())
                        .unwrap_or_else(|| default_url.trim_end_matches('/').to_string());
                    cua_spacesd_client::ConnectOptions::parse(ep)
                        .ok()
                        .map(|o| o.endpoint.origin())
                        .is_some_and(|origin| {
                            origin.trim_end_matches('/') != default_origin.trim_end_matches('/')
                        })
                }
                _ => false,
            };
            let needs_registry = static_relay || custom_account_relay;
            if needs_registry {
                let endpoint_url = endpoint_url.ok_or_else(|| {
                    Error::invalid(format!("{word} sandbox {sb_name} has no relay endpoint"))
                })?;
                let env_token = if static_relay {
                    sandbox.env_token()
                } else {
                    None
                };
                let (image, image_digest) = sandbox
                    .image_info()
                    .map(|i| (i.reference.clone(), i.digest.clone()))
                    .unwrap_or_default();
                let kind = sandbox
                    .image_info()
                    .map(|i| i.variant.clone())
                    .unwrap_or_else(|| match sandbox.placement().0 {
                        Kind::Vm => "vm".into(),
                        Kind::MicroVm => "microvm".into(),
                        _ => "container".into(),
                    });
                let arch = sandbox
                    .image_info()
                    .and_then(|i| i.arch.clone())
                    .unwrap_or_default();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let record = cua_proto::daemon::v1::Space {
                    id: id.clone(),
                    name: sb_name.clone(),
                    kind,
                    arch,
                    image,
                    image_digest,
                    added_at: Some(pbjson_types::Timestamp {
                        seconds: now.as_secs() as i64,
                        nanos: now.subsec_nanos() as i32,
                    }),
                    ..Default::default()
                };
                let cred = crate::registry::Credential {
                    url: Some(endpoint_url),
                    token: env_token,
                    service_urls: Default::default(),
                };
                self.inner.registry.upsert(record, cred)?;
            }
            Ok(id)
        }
        .await;
        let id = match record_result {
            Ok(id) => id,
            Err(err) => {
                if let Err(del_err) = sandbox.delete().await {
                    tracing::warn!(
                        sandbox = %sb_name,
                        "rollback sandbox.delete() failed ({del_err}); retrying by name"
                    );
                    if let Err(fallback_err) = self.inner.sandboxes.delete(&sb_name).await {
                        tracing::error!(
                            sandbox = %sb_name,
                            "rollback sandboxes.delete() failed: {fallback_err}"
                        );
                    }
                }
                return Err(err);
            }
        };
        // Connect it once, as a local create does: the handshake records its
        // capabilities, and extensions start what a connected Space gets
        // (the Cua Volume mount in its guest).
        if let Err(e) = self.space(&id).await {
            tracing::warn!(space = %id, "the new cloud Space did not answer its handshake yet: {e}");
        }
        // Provisioning has already succeeded. A directory outage must not
        // conceal a recorded target or imply that creation should be retried.
        let unavailable = || {
            Error::Relay(cua_host::Error::Relay(
                concat!(
                    "The cloud sandbox was created, but its Space details could not be read. ",
                    "Inspect the existing sandbox before retrying creation."
                )
                .into(),
            ))
        };
        self.find(&id).await.map_err(|_| unavailable())
    }

    /// The name of the cloud sandbox behind a `relay:<machine>` Space, if
    /// it is one.
    pub fn cloud_sandbox_of(&self, space: &str) -> Result<Option<String>> {
        match self.resolve(space)? {
            crate::SpaceId::Relay { machine_id } => {
                Ok(self.inner.sandboxes.by_relay_machine(&machine_id)?)
            }
            _ => Ok(None),
        }
    }
}

/// Whether cloud `word` can keep a Space's network `settings`, refusing
/// (before anything is made) what it can't:
///
/// - `takes`: the cloud enforces rules itself (Modal's allow-list), so
///   internet, none and custom address lists are kept;
/// - `floor`: the cloud machine's own firewall keeps every Space to the
///   internet (a VM per Space), so the default is kept and nothing else;
/// - otherwise only No protection (or the old default, with no rules).
///
/// A Space in a cloud never reaches this computer or the user's network, so
/// `localhost` and `lan` are refused everywhere.
fn cloud_network(
    word: &str,
    settings: &crate::network::NetworkSettings,
    takes: bool,
    floor: bool,
    mode: crate::network::Mode,
) -> Result<()> {
    use crate::network::{Mode, NetworkPreset as P};
    let lists = !settings.custom.is_empty();
    let none = settings.default_drops();
    let rules_refused = || {
        crate::egress::refused(
            word,
            "a Space in your own cloud account runs on a machine with no host-side point cua \
             controls; create it on this machine or one of yours",
        )
    };
    let none_refused = || {
        Error::invalid(format!(
            "network=none applies to VMs on your computers and to Modal, not Spaces in this \
             cloud ({word})"
        ))
    };
    if mode == Mode::Legacy || settings.preset == P::Unprotected {
        return match () {
            _ if takes => Ok(()),
            _ if none && settings.preset != P::Unprotected => Err(none_refused()),
            _ if lists && settings.preset != P::Unprotected => Err(rules_refused()),
            _ => Ok(()),
        };
    }
    match settings.preset {
        P::Localhost | P::Lan | P::LocalhostLan => Err(Error::invalid(format!(
            "a Space in your cloud account ({word}) can't reach this computer or your local \
             network; use internet (the default), none or custom"
        ))),
        P::Internet if !lists && (takes || floor) => Ok(()),
        _ if takes => Ok(()),
        _ if none => Err(none_refused()),
        _ if lists => Err(rules_refused()),
        _ => Err(Error::invalid(format!(
            "Spaces in your cloud account ({word}) can't protect your network yet; choose No \
             protection (network unprotected) to create it there"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> SpaceCreate {
        SpaceCreate {
            image: Some("linux".into()),
            ..Default::default()
        }
    }

    /// Overflow and `auto` reach a Spaces supplier through `create_in_cloud`
    /// with the caller's options: rules or `network=none` must be refused
    /// there, before anything is made, not dropped.
    #[tokio::test]
    async fn a_supplier_refuses_network_rules_instead_of_dropping_them() {
        let dir = tempfile::tempdir().unwrap();
        let s = Spaces::builder().home(dir.path()).build();

        let mut o = opts();
        o.egress = crate::egress::EgressPolicy {
            allow: vec![],
            deny: vec!["all".into()],
        };
        let e = s.create_in_cloud("modal", o).await.unwrap_err();
        assert_eq!(e.tag(), "wrong_provider", "{e}");
        assert!(e.to_string().contains("egress policy"), "{e}");

        let mut o = opts();
        o.network = cua_sandbox_core::NetworkMode::None;
        let e = s.create_in_cloud("modal", o).await.unwrap_err();
        assert_eq!(e.tag(), "invalid_argument", "{e}");
        assert!(e.to_string().contains("network=none"), "{e}");
    }

    #[test]
    fn a_cloud_keeps_what_it_can_and_refuses_the_rest() {
        use crate::network::{Mode, NetworkPreset as P, NetworkSettings as S};
        let ok = |s: &S, takes, floor| cloud_network("c", s, takes, floor, Mode::Secure).is_ok();
        let internet = S::internet();
        let none = S::none();
        let lan = S::preset(P::Lan);
        let open = S::preset(P::Unprotected);
        let mut custom = S::internet();
        custom.custom.deny = vec!["1.2.3.0/24".into()];
        // Modal (takes rules): internet, none and lists; never this computer.
        assert!(ok(&internet, true, false));
        assert!(ok(&none, true, false));
        assert!(ok(&custom, true, false));
        assert!(!ok(&lan, true, false));
        // A VM per Space behind the computer's own firewall: the default only.
        assert!(ok(&internet, false, true));
        assert!(!ok(&none, false, true));
        assert!(!ok(&custom, false, true));
        // Nothing kept: only No protection.
        assert!(!ok(&internet, false, false));
        assert!(ok(&open, false, false));
        // The old default: no rules go anywhere, rules only where kept.
        assert!(cloud_network("c", &internet, false, false, Mode::Legacy).is_ok());
        assert!(cloud_network("c", &custom, false, false, Mode::Legacy).is_err());
    }

    struct FakeRelayProvider {
        relay_base_url: String,
        spacesd_url: String,
        machine_id: String,
        created: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        deleted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FakeRelayProvider {
        fn instance(&self, name: &str) -> cua_sandbox_core::ProviderInstance {
            let mut inst = cua_sandbox_core::ProviderInstance::new(
                "inst-1",
                name,
                cua_sandbox_core::Status::Running,
            );
            inst.details
                .insert(DETAIL_RELAY_MACHINE.into(), self.machine_id.clone());
            inst.details.insert(
                cua_sandbox_core::byoc::DETAIL_PLACE.into(),
                "AWS · us-west-2".into(),
            );
            inst.endpoints.insert(
                cua_sandbox_core::ENV_PORT,
                cua_sandbox_core::ServiceEndpoint {
                    url: format!(
                        "{}/m/{}",
                        self.relay_base_url.trim_end_matches('/'),
                        self.machine_id
                    ),
                    headers: vec![],
                },
            );
            inst
        }
    }

    #[async_trait::async_trait]
    impl cua_sandbox_core::Provider for FakeRelayProvider {
        fn name(&self) -> &'static str {
            "aws"
        }

        fn capabilities(&self) -> cua_sandbox_core::ProviderCapabilities {
            cua_sandbox_core::ProviderCapabilities {
                kinds: vec![cua_sandbox_core::RunKind::Container],
                runtime: "fake",
                arches: vec!["amd64"],
                image_mode: cua_sandbox_core::ImageMode::Direct,
                ports: cua_sandbox_core::PortExposure::Https,
                command: false,
                env_to_entrypoint: true,
                private_registry: false,
                suspend: false,
                max_cpus: None,
                max_memory_mb: None,
                credential_env: &[],
                gpus: vec![],
                oses: vec!["linux"],
                custom_disk_gb: false,
                custom_cloud_image: false,
            }
        }

        fn check_configured(&self) -> cua_sandbox_core::Result<()> {
            Ok(())
        }

        async fn create(
            &self,
            spec: &cua_sandbox_core::ProviderCreate,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::ProviderInstance> {
            self.created
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.instance(&spec.name))
        }

        async fn get(
            &self,
            _id: &str,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::ProviderInstance> {
            Ok(self.instance("fake"))
        }

        async fn list(&self) -> cua_sandbox_core::Result<Vec<cua_sandbox_core::ProviderInstance>> {
            Ok(vec![])
        }

        async fn delete(&self, _id: &str) -> cua_sandbox_core::Result<()> {
            self.deleted
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn endpoint(
            &self,
            instance: &cua_sandbox_core::ProviderInstance,
            port: u16,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::ServiceEndpoint> {
            instance
                .endpoints
                .get(&port)
                .cloned()
                .ok_or_else(|| cua_sandbox_core::Error::NotFound(format!("port {port}")))
        }

        fn connect_options(
            &self,
            _instance: &cua_sandbox_core::ProviderInstance,
            _port: u16,
        ) -> Option<cua_sandbox_core::Result<cua_spacesd_client::ConnectOptions>> {
            Some(
                cua_spacesd_client::ConnectOptions::parse(&self.spacesd_url)
                    .map_err(|e| cua_sandbox_core::Error::InvalidArgument(e.to_string())),
            )
        }

        fn joins_relay(&self) -> bool {
            true
        }

        fn keeps_internet_only(&self) -> bool {
            true
        }
    }

    async fn spawn_mock_relay(
        machine_id: String,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<(String, Option<String>)>>>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_bg = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let seen_conn = seen_bg.clone();
                let machine_id = machine_id.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let mut lines = req.lines();
                    let first = lines.next().unwrap_or_default();
                    let path = first
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    let auth = lines.find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("authorization")
                            .then(|| v.trim().to_string())
                    });
                    seen_conn.lock().unwrap().push((path.clone(), auth));
                    let (status, body) = if path == "/v1/machines" {
                        (
                            "200 OK",
                            serde_json::json!([{
                                "id": machine_id,
                                "name": "custom-sb",
                                "online": true,
                                "role": "owner",
                                "meta": {
                                    "cua.cloud.provider": "aws",
                                    "cua.cloud.place": "AWS · us-west-2"
                                }
                            }])
                            .to_string(),
                        )
                    } else {
                        ("404 Not Found", r#"{"error":"not found"}"#.into())
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}"), seen)
    }

    #[tokio::test]
    async fn custom_account_relay_persists_url_without_token_and_routes_via_account_auth() {
        let dir = tempfile::tempdir().unwrap();
        let mock_env = cua_spacesd_client::testing::MockServer::start(Default::default()).await;
        let (default_relay_url, default_seen) = spawn_mock_relay("m-other".into()).await;
        let (custom_relay_url, custom_seen) = spawn_mock_relay("m-custom".into()).await;
        let created = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = std::sync::Arc::new(FakeRelayProvider {
            relay_base_url: custom_relay_url.clone(),
            spacesd_url: format!("http://{}", mock_env.addr),
            machine_id: "m-custom".into(),
            created: created.clone(),
            deleted: deleted.clone(),
        });
        let sandboxes = cua_sandbox_core::Sandboxes::builder()
            .state_dir(dir.path().join("sandboxes"))
            .provider(provider)
            .build();
        let spaces = Spaces::builder()
            .home(dir.path())
            .sandboxes(sandboxes)
            .relay(crate::relay::RelayAccount::new(
                &default_relay_url,
                std::sync::Arc::new(crate::relay::StaticToken("acct-bearer-custom".into())),
            ))
            .build();

        let mut o = opts();
        o.name = Some("custom-sb".into());
        let info = spaces.create_in_cloud("aws", o).await.unwrap();
        assert_eq!(info.id, "relay:m-custom");
        assert_eq!(created.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Persisted in registry with custom relay URL and token: None (Account mode, not Static).
        let cred = spaces
            .inner
            .registry
            .credential("relay:m-custom")
            .unwrap()
            .expect("custom account relay credential persisted");
        assert_eq!(
            cred.url.as_deref(),
            Some(format!("{custom_relay_url}/m/m-custom").as_str())
        );
        assert_eq!(cred.token, None);

        // Listed and findable without hitting NotFound.
        assert!(
            spaces
                .list()
                .unwrap()
                .iter()
                .any(|s| s.id == "relay:m-custom")
        );
        assert_eq!(
            spaces.find("relay:m-custom").await.unwrap().id,
            "relay:m-custom"
        );

        // Dialing `space()` routes through Account auth (RelayBearer) to the custom relay.
        let _ = spaces.space("relay:m-custom").await;
        let custom_reqs = custom_seen.lock().unwrap().clone();
        assert!(
            custom_reqs.iter().any(|(path, auth)| {
                path == "/v1/machines" && auth.as_deref() == Some("Bearer acct-bearer-custom")
            }),
            "expected custom relay /v1/machines with Account bearer, got {custom_reqs:?}"
        );
        assert!(
            custom_reqs.iter().any(|(path, auth)| {
                path.starts_with("/m/m-custom")
                    && auth.as_deref() == Some("Bearer acct-bearer-custom")
            }),
            "expected custom relay /m/m-custom with Account bearer, got {custom_reqs:?}"
        );
        assert!(
            default_seen
                .lock()
                .unwrap()
                .iter()
                .all(|(path, _)| !path.starts_with("/m/m-custom")),
            "default relay must not receive custom-relay machine traffic"
        );

        // Delete cleans up both the cloud sandbox and the registry record.
        spaces.delete("relay:m-custom").await.unwrap();
        assert_eq!(deleted.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            spaces
                .inner
                .registry
                .get("relay:m-custom")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn create_in_cloud_deletes_sandbox_when_registry_upsert_fails() {
        let dir = tempfile::tempdir().unwrap();
        // Force `registry.upsert` to fail by making `spaces.json` an unreadable directory.
        std::fs::create_dir_all(dir.path().join(crate::registry::SPACES_FILE)).unwrap();

        let mock_env = cua_spacesd_client::testing::MockServer::start(Default::default()).await;
        let (default_relay_url, _) = spawn_mock_relay("m-other".into()).await;
        let (custom_relay_url, _) = spawn_mock_relay("m-orphan".into()).await;
        let created = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = std::sync::Arc::new(FakeRelayProvider {
            relay_base_url: custom_relay_url,
            spacesd_url: format!("http://{}", mock_env.addr),
            machine_id: "m-orphan".into(),
            created: created.clone(),
            deleted: deleted.clone(),
        });
        let sandboxes = cua_sandbox_core::Sandboxes::builder()
            .state_dir(dir.path().join("sandboxes"))
            .provider(provider)
            .build();
        let spaces = Spaces::builder()
            .home(dir.path())
            .sandboxes(sandboxes)
            .relay(crate::relay::RelayAccount::new(
                &default_relay_url,
                std::sync::Arc::new(crate::relay::StaticToken("acct-bearer".into())),
            ))
            .build();

        let mut o = opts();
        o.name = Some("no-orphan-sb".into());
        let err = spaces.create_in_cloud("aws", o).await.unwrap_err();
        assert!(
            matches!(err, Error::Io(_)),
            "expected registry I/O error, got {err:?}"
        );
        assert_eq!(created.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            deleted.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "created sandbox must be deleted on post-create registry failure"
        );
    }
}

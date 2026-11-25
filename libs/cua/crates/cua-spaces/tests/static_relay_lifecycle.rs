// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Lifecycle integration tests for Static Relay Mode Spaces (`relay:<machine-id>`):
//! - URL/token/name rotation and stale connection eviction on same-token revocation.
//! - Sibling `remove` isolation and `NotFound` handling.
//! - Account Relay bypass in `reach`, `thread_home`, `checkpoint_space`, `set_egress`, and `stop`/`start`.
//! - Sharing, `leave_many`, and `rename` contracts + Account Relay `relay_register` non-regression.
//! - BYOC `create_in_cloud` Static Relay persistence parity with manual `Spaces::add`.

use cua_sandbox_core::byoc::{
    CloudAuditEntry, CloudConnected, CloudDisconnected, CloudManager, CloudStatusReport,
    CloudSweepReport, CloudTarget, CloudTestReport, DETAIL_PLACE, DETAIL_RELAY_MACHINE, RelayMode,
};
use cua_sandbox_core::{
    ENV_PORT, ImageMode, PortExposure, Provider as SandboxProvider, ProviderCapabilities,
    ProviderCreate, ProviderInstance, Result as CoreResult, RunKind, Sandboxes, ServiceEndpoint,
    Status,
};
use cua_spaces::egress::EgressPolicy;
use cua_spaces::relay::StaticToken;
use cua_spaces::share::{ShareConsent, ShareRole};
use cua_spaces::{Provider, RelayAccount, SpaceId, SpaceInfo, Spaces};
use cua_spacesd_client::ConnectOptions;
use cua_spacesd_client::testing::{HttpSpy, MockAuth, MockServer, StaticRelayRouter};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const MACHINE_A: &str = "machine-alpha-01";
const MACHINE_B: &str = "machine-beta-002";
const TOKEN_A: &str = "static-relay-token-alpha-secret";
const TOKEN_A_ROTATED: &str = "static-relay-token-alpha-rotated";
const TOKEN_A_V3: &str = "static-relay-token-alpha-v3";
const TOKEN_B: &str = "static-relay-token-beta-secret";

async fn mock_machine(id: &str, token: &str) -> MockServer {
    MockServer::start(MockAuth {
        token: Some(token.into()),
        gateway: None,
        prefix: Some(format!("/m/{id}")),
    })
    .await
}

fn build_spaces(home: &Path, spy_url: &str) -> Spaces {
    Spaces::builder()
        .home(home)
        .probe_timeout(Duration::from_secs(5))
        .relay(RelayAccount::new(
            spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .build()
}

async fn add_m(sp: &Spaces, origin: &str, id: &str, tok: &str, name: Option<&str>) -> SpaceInfo {
    sp.add(
        &format!("{origin}/m/{id}"),
        Some(tok.into()),
        name.map(str::to_string),
    )
    .await
    .unwrap()
}

async fn assert_bash(spaces: &Spaces, target: &str, marker: &str) {
    let out = spaces
        .space(target)
        .await
        .unwrap()
        .bash(&format!("echo {marker}"), Duration::from_secs(5))
        .await
        .unwrap();
    assert!(out.render().contains(marker), "{}", out.render());
}

fn assert_refused(label: &str, err: cua_spaces::Error) {
    assert_eq!(err.tag(), "invalid_argument", "{label}: {err}");
    let msg = err.to_string();
    assert!(
        msg.contains("Static Relay") && msg.contains("Account Relay"),
        "{label}: {msg}"
    );
}

#[tokio::test]
async fn static_relay_rotation_updates_url_token_name_and_evicts_cached_connections() {
    let (spy_url, account_spy) = HttpSpy::start().await;
    let srv_v1 = mock_machine(MACHINE_A, TOKEN_A).await;
    let srv_v2 = mock_machine(MACHINE_A, TOKEN_A_ROTATED).await;
    let srv_v3 = mock_machine(MACHINE_A, TOKEN_A_V3).await;
    let router_2 = StaticRelayRouter::start(&[(MACHINE_A, srv_v2.addr)]).await;

    let home = tempfile::tempdir().unwrap();
    let spaces = build_spaces(home.path(), &spy_url);
    let url_2 = format!("{}/m/{MACHINE_A}", router_2.url());

    let init = add_m(
        &spaces,
        &srv_v1.url(),
        MACHINE_A,
        TOKEN_A,
        Some("alpha-initial"),
    )
    .await;
    assert_eq!(
        (init.id.as_str(), init.name.as_str()),
        (format!("relay:{MACHINE_A}").as_str(), "alpha-initial")
    );
    assert_bash(&spaces, "alpha-initial", "v1").await;

    let renamed = spaces.rename(&init.id, "alpha-renamed").await.unwrap();
    assert_eq!(
        (renamed.shown_name(), renamed.display_name.as_str()),
        ("alpha-renamed", "alpha-renamed")
    );

    // Rotate URL + token WITHOUT `--name`: preserves name & display_name, replaces cached conn.
    let rot = add_m(&spaces, &router_2.url(), MACHINE_A, TOKEN_A_ROTATED, None).await;
    assert_eq!(
        (
            rot.id.as_str(),
            rot.name.as_str(),
            rot.display_name.as_str()
        ),
        (init.id.as_str(), "alpha-initial", "alpha-renamed")
    );
    assert_eq!(spaces.list().unwrap().len(), 1);
    let cred2 = spaces.registry().credential(&rot.id).unwrap().unwrap();
    assert_eq!(
        (cred2.url.as_deref(), cred2.token.as_deref()),
        (Some(url_2.as_str()), Some(TOKEN_A_ROTATED))
    );
    assert_bash(&spaces, "alpha-renamed", "v2").await;
    assert!(
        !router_2.seen_paths().is_empty(),
        "must route to rotated relay_2"
    );

    // Re-add WITH explicit `--name`: updates name and clears stale `display_name`.
    let named = add_m(
        &spaces,
        &router_2.url(),
        MACHINE_A,
        TOKEN_A_ROTATED,
        Some("alpha-final"),
    )
    .await;
    assert_eq!(
        (
            named.name.as_str(),
            named.display_name.as_str(),
            named.shown_name()
        ),
        ("alpha-final", "", "alpha-final")
    );
    assert_eq!(spaces.list().unwrap().len(), 1);
    assert!(spaces.resolve("alpha-renamed").is_err());
    assert_eq!(
        spaces.resolve("alpha-final").unwrap(),
        SpaceId::Relay {
            machine_id: MACHINE_A.into()
        }
    );

    // Revoke TOKEN_A_ROTATED: re-adding revoked SAME token fails AND evicts stale connection.
    router_2.set_route(MACHINE_A, srv_v3.addr);
    let err = spaces
        .add(&url_2, Some(TOKEN_A_ROTATED.into()), None)
        .await
        .unwrap_err();
    assert_ne!(err.tag(), "", "{err}");
    assert!(
        spaces.space("alpha-final").await.is_err(),
        "revoked token must fail on next spaces.space() instead of reusing cached connection"
    );

    // Rotate to valid v3 token: immediate SDK success.
    let rot_v3 = add_m(&spaces, &router_2.url(), MACHINE_A, TOKEN_A_V3, None).await;
    assert_eq!(rot_v3.shown_name(), "alpha-final");
    assert_bash(&spaces, "alpha-final", "v3-ok").await;
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());
}

#[tokio::test]
async fn static_relay_remove_isolates_siblings_skips_account_relay_and_returns_not_found() {
    let srv_a = mock_machine(MACHINE_A, TOKEN_A).await;
    let srv_b = mock_machine(MACHINE_B, TOKEN_B).await;
    let router =
        StaticRelayRouter::start(&[(MACHINE_A, srv_a.addr), (MACHINE_B, srv_b.addr)]).await;

    let (spy_url, account_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let spaces = build_spaces(home.path(), &spy_url);

    let id_a = add_m(&spaces, &router.url(), MACHINE_A, TOKEN_A, Some("rm-alpha"))
        .await
        .id;
    let id_b = add_m(&spaces, &router.url(), MACHINE_B, TOKEN_B, Some("rm-beta"))
        .await
        .id;
    assert_bash(&spaces, "rm-alpha", "a-before").await;
    assert_bash(&spaces, "rm-beta", "b-before").await;

    assert_eq!(spaces.remove(&id_a).await.unwrap().id, id_a);
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());
    assert!(spaces.registry().get(&id_a).unwrap().is_none());
    assert!(spaces.registry().credential(&id_a).unwrap().is_none());
    assert!(spaces.resolve("rm-alpha").is_err());

    // Sibling MACHINE_B on the same relay host stays intact and operational.
    let listed = spaces.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id_b);
    let cred_b = spaces.registry().credential(&id_b).unwrap().unwrap();
    assert_eq!(cred_b.token.as_deref(), Some(TOKEN_B));
    assert_bash(&spaces, "rm-beta", "b-after").await;
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());

    // Removing already-removed or unknown `relay:<id>` returns NotFound.
    let no_acct = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(5))
        .build();
    for (c, t) in [
        (&no_acct, id_a.as_str()),
        (&no_acct, "relay:unregistered-0001"),
        (&spaces, "relay:unregistered-0002"),
    ] {
        assert_eq!(c.remove(t).await.unwrap_err().tag(), "not_found");
    }
}

#[tokio::test]
async fn static_relay_bypasses_account_relay_in_reach_thread_home_checkpoints_egress_and_power() {
    let srv = mock_machine(MACHINE_A, TOKEN_A).await;
    let (spy_url, account_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let spaces = build_spaces(home.path(), &spy_url);

    let id = add_m(&spaces, &srv.url(), MACHINE_A, TOKEN_A, Some("bypass-box"))
        .await
        .id;
    let reach = spaces.reach(&id).await;
    assert!(
        reach.reachable && !reach.listed_offline && reach.reason.is_none(),
        "{reach:?}"
    );
    for target in [id.as_str(), "bypass-box"] {
        assert!(matches!(
            spaces.thread_home(target).await.unwrap(),
            cua_spaces::thread_route::ThreadHome::Here(None)
        ));
    }
    let errs = [
        spaces
            .checkpoint_space(&id, "snap-1", false)
            .await
            .unwrap_err(),
        spaces
            .set_egress(&id, &EgressPolicy::default())
            .await
            .unwrap_err(),
        spaces.stop(&id).await.unwrap_err(),
        spaces.start(&id).await.unwrap_err(),
    ];
    for err in errs {
        assert_eq!(err.tag(), "wrong_provider", "{err}");
    }
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());
}

async fn assert_sharing_and_leave_refused(sp: &Spaces, id: &str) {
    let s = "share-alpha";
    let errs = [
        sp.share_space(s, "bob@example.com", ShareRole::Viewer)
            .await
            .unwrap_err(),
        sp.share_space(id, "team:design", ShareRole::Editor)
            .await
            .unwrap_err(),
        sp.share_with_team(s, "design").await.unwrap_err(),
        sp.unshare_space(s, Some("bob@example.com"))
            .await
            .unwrap_err(),
        sp.unshare_space(s, Some("team:design")).await.unwrap_err(),
        sp.unshare_space(s, None).await.unwrap_err(),
        sp.unshare_from_team(s, "design").await.unwrap_err(),
        sp.space_shares(s).await.unwrap_err(),
        sp.relay_register(s).await.unwrap_err(),
        sp.relay_unregister(s).await.unwrap_err(),
    ];
    for err in errs {
        assert_refused("static-relay", err);
    }
    let leaves = sp.leave_many(&[id.into(), s.into()]).await;
    assert_eq!(leaves.len(), 2);
    assert!(leaves.iter().all(|r| {
        !r.ok
            && r.error
                .as_deref()
                .is_some_and(|e| e.contains("it's yours; delete it instead"))
    }));
}

#[tokio::test]
async fn static_relay_refuses_account_sharing_and_leave_while_direct_relay_register_works() {
    struct AlwaysAllow;
    impl ShareConsent for AlwaysAllow {
        fn confirm(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    let srv_a = mock_machine(MACHINE_A, TOKEN_A).await;
    let (spy_url, account_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(5))
        .relay(RelayAccount::new(
            &spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .share_consent(Arc::new(AlwaysAllow))
        .build();

    let id = add_m(
        &spaces,
        &srv_a.url(),
        MACHINE_A,
        TOKEN_A,
        Some("share-alpha"),
    )
    .await
    .id;
    assert_sharing_and_leave_refused(&spaces, &id).await;
    assert!(spaces.registry().get(&id).unwrap().is_some());
    assert!(spaces.registry().credential(&id).unwrap().is_some());
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());

    let signed_out = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(5))
        .build();
    assert_sharing_and_leave_refused(&signed_out, &id).await;

    // Non-regression: Account Relay Mode `relay_register` on a direct Space still works.
    let fake_relay = cua_host::testing::FakeRelay::start().await;
    fake_relay.add_account("ada-token", "ada", Some("ada@example.com"));
    let direct_srv = MockServer::start(MockAuth::default()).await;
    direct_srv.state.advertise(&["relay_attach"]);
    let acct_home = tempfile::tempdir().unwrap();
    let acct_spaces = Spaces::builder()
        .home(acct_home.path())
        .relay(RelayAccount::new(
            &fake_relay.url,
            Arc::new(StaticToken("ada-token".into())),
        ))
        .build();
    let direct_info = acct_spaces
        .add(&direct_srv.url(), None, Some("direct-box".into()))
        .await
        .unwrap();
    let (state, relay_bg) = (direct_srv.state.clone(), fake_relay.clone());
    tokio::spawn(async move {
        for _ in 0..400 {
            if let Some(a) = state.relay_attached.lock().unwrap().clone() {
                relay_bg.set_online(&a.machine_id, true, "0.1.0");
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let reg = acct_spaces.relay_register(&direct_info.id).await.unwrap();
    assert!(reg.online && reg.relay_space == format!("relay:{}", reg.machine));
    assert_eq!(
        acct_spaces
            .space_shares(&direct_info.id)
            .await
            .unwrap()
            .machine,
        reg.machine
    );
    assert!(acct_spaces.relay_unregister(&direct_info.id).await.unwrap());
}

struct StaticCloudManager;

#[async_trait::async_trait]
impl CloudManager for StaticCloudManager {
    async fn status(&self, _: Option<&str>) -> CoreResult<CloudStatusReport> {
        Ok(Default::default())
    }
    fn relay_mode(&self, p: &str) -> Option<RelayMode> {
        (p == "aws").then_some(RelayMode::Static)
    }
    async fn test(&self, _: &CloudTarget) -> CoreResult<CloudTestReport> {
        unimplemented!()
    }
    async fn connect(
        &self,
        _: &CloudTarget,
        _: bool,
        _: Option<u32>,
    ) -> CoreResult<CloudConnected> {
        unimplemented!()
    }
    async fn disconnect(&self, _: &str, _: bool) -> CoreResult<CloudDisconnected> {
        unimplemented!()
    }
    async fn sweep(&self, _: Option<&str>, _: bool, _: bool) -> CoreResult<CloudSweepReport> {
        unimplemented!()
    }
    async fn auto_sweep(&self) -> CoreResult<CloudSweepReport> {
        unimplemented!()
    }
    async fn audit(&self, _: usize) -> CoreResult<Vec<CloudAuditEntry>> {
        unimplemented!()
    }
}

struct FakeStaticByocProvider {
    relay_origin: String,
    machine_id: String,
    env_token: String,
}

impl FakeStaticByocProvider {
    fn instance(&self, name: &str) -> ProviderInstance {
        let mut inst = ProviderInstance::new("inst-static-1", name, Status::Running);
        inst.details
            .insert(DETAIL_RELAY_MACHINE.into(), self.machine_id.clone());
        inst.details
            .insert(DETAIL_PLACE.into(), "AWS \u{b7} us-west-2".into());
        let ep = ServiceEndpoint {
            url: format!("{}/m/{}", self.relay_origin, self.machine_id),
            headers: vec![],
        };
        inst.endpoints.insert(ENV_PORT, ep);
        inst
    }
}

#[async_trait::async_trait]
impl SandboxProvider for FakeStaticByocProvider {
    fn name(&self) -> &'static str {
        "aws"
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            kinds: vec![RunKind::Container],
            runtime: "fake",
            arches: vec!["amd64"],
            image_mode: ImageMode::Direct,
            ports: PortExposure::Https,
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
    fn check_configured(&self) -> CoreResult<()> {
        Ok(())
    }
    async fn create(&self, spec: &ProviderCreate) -> CoreResult<ProviderInstance> {
        Ok(self.instance(&spec.name))
    }
    async fn get(&self, _: &str) -> CoreResult<ProviderInstance> {
        Ok(self.instance("byoc-static-box"))
    }
    async fn list(&self) -> CoreResult<Vec<ProviderInstance>> {
        Ok(vec![])
    }
    async fn delete(&self, _: &str) -> CoreResult<()> {
        Ok(())
    }
    fn endpoint(&self, inst: &ProviderInstance, port: u16) -> CoreResult<ServiceEndpoint> {
        inst.endpoints
            .get(&port)
            .cloned()
            .ok_or_else(|| cua_sandbox_core::Error::NotFound(format!("port {port}")))
    }
    fn connect_options(
        &self,
        inst: &ProviderInstance,
        port: u16,
    ) -> Option<CoreResult<ConnectOptions>> {
        let ep = inst.endpoints.get(&port)?;
        Some(
            ConnectOptions::parse(&ep.url)
                .map(|o| o.token(&self.env_token))
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

#[tokio::test]
async fn byoc_static_relay_create_in_cloud_matches_manual_spaces_add_persistence() {
    const BYOC_MACHINE: &str = "cloud-0123456789abcdef";
    let srv_byoc = mock_machine(BYOC_MACHINE, TOKEN_A).await;
    let srv_manual = mock_machine(MACHINE_B, TOKEN_B).await;
    let router =
        StaticRelayRouter::start(&[(BYOC_MACHINE, srv_byoc.addr), (MACHINE_B, srv_manual.addr)])
            .await;

    let (spy_url, account_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let sandboxes = Sandboxes::builder()
        .state_dir(home.path().join("sandboxes"))
        .clouds(Arc::new(StaticCloudManager))
        .provider(Arc::new(FakeStaticByocProvider {
            relay_origin: router.url(),
            machine_id: BYOC_MACHINE.into(),
            env_token: TOKEN_A.into(),
        }))
        .build();
    let spaces = Spaces::builder()
        .home(home.path())
        .sandboxes(sandboxes)
        .probe_timeout(Duration::from_secs(5))
        .relay(RelayAccount::new(
            &spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .build();

    let byoc_info = match spaces
        .create(cua_spaces::SpaceCreate {
            name: Some("byoc-static-box".into()),
            image: Some("linux".into()),
            on: Some(cua_sandbox_core::placement::On::Provider("aws".into())),
            env: [("CUA_ENV_TOKEN".into(), TOKEN_A.into())]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap()
    {
        cua_spaces::SpaceCreated::Ready { info, .. } => info,
        other => panic!("expected Ready, got {other:?}"),
    };
    let manual_info = add_m(
        &spaces,
        &router.url(),
        MACHINE_B,
        TOKEN_B,
        Some("manual-static-box"),
    )
    .await;

    for (info, machine, token) in [
        (&byoc_info, BYOC_MACHINE, TOKEN_A),
        (&manual_info, MACHINE_B, TOKEN_B),
    ] {
        assert_eq!(
            (info.id.as_str(), info.provider),
            (format!("relay:{machine}").as_str(), Provider::Relay)
        );
        let rec = spaces
            .registry()
            .get(&info.id)
            .unwrap()
            .expect("record in spaces.json");
        assert!(rec.id == info.id && rec.added_at.is_some());
        let cred = spaces
            .registry()
            .credential(&info.id)
            .unwrap()
            .expect("credential persisted");
        assert_eq!(
            cred.url.as_deref(),
            Some(format!("{}/m/{machine}", router.url()).as_str())
        );
        assert_eq!(cred.token.as_deref(), Some(token));
        assert!(spaces.is_static_relay_space(&SpaceId::Relay {
            machine_id: machine.into()
        }));
    }
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());
}

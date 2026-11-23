//! Contrib providers through the core: image resolution and capability
//! checks before any provider call, refs (`e2b:<name>`), state files,
//! reattach, services, spacesd over the provider's port URL, and delete.
//! Hermetic: an in-memory provider, an in-memory registry and a mock
//! cua-spacesd on loopback. Its own binary: it installs a process-wide
//! registry source.

use async_trait::async_trait;
use cua_image::testing::FakeRegistry;
use cua_sandbox_core::{
    CreateOptions, Error, ImageMode, PortExposure, Provider, ProviderCapabilities, ProviderCreate,
    ProviderInstance, ProviderKind, Result, RunKind, SandboxRef, Sandboxes, ServiceEndpoint,
    Status,
};
use cua_spacesd_client::testing::{MockAuth, MockServer};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// An in-memory provider named `e2b` whose every port is the mock spacesd.
struct Fake {
    spacesd: String,
    env_to_entrypoint: bool,
    created: Mutex<Vec<ProviderCreate>>,
    live: Mutex<BTreeMap<String, ProviderInstance>>,
    /// `create` makes the sandbox, then never returns (the platform is
    /// still booting it when a create is cancelled).
    hang: std::sync::atomic::AtomicBool,
}

impl Fake {
    fn new(spacesd: String, env_to_entrypoint: bool) -> Arc<Self> {
        Arc::new(Self {
            spacesd,
            env_to_entrypoint,
            created: Mutex::default(),
            live: Mutex::default(),
            hang: Default::default(),
        })
    }
}

#[async_trait]
impl Provider for Fake {
    fn name(&self) -> &'static str {
        "e2b"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            kinds: vec![RunKind::Container],
            runtime: "firecracker",
            arches: vec!["amd64"],
            image_mode: ImageMode::Template,
            ports: PortExposure::Https,
            command: true,
            env_to_entrypoint: self.env_to_entrypoint,
            private_registry: false,
            suspend: false,
            max_cpus: Some(8),
            max_memory_mb: None,
            credential_env: &["E2B_API_KEY"],
            gpus: vec![cua_sandbox_core::gpu::GpuOption {
                id: "T4".into(),
                label: "NVIDIA T4".into(),
                supported: true,
                ..Default::default()
            }],
            oses: vec!["linux"],
            custom_disk_gb: false,
            custom_cloud_image: false,
        }
    }

    fn check_configured(&self) -> Result<()> {
        Ok(())
    }

    async fn create(&self, spec: &ProviderCreate) -> Result<ProviderInstance> {
        self.created.lock().unwrap().push(spec.clone());
        let id = format!("sbx{}", self.created.lock().unwrap().len());
        let mut i = ProviderInstance::new(&id, &spec.name, Status::Running);
        i.details.insert("template".into(), "cua-test".into());
        i.details.insert("_secret".into(), "never shown".into());
        self.live.lock().unwrap().insert(id, i.clone());
        if self.hang.load(std::sync::atomic::Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(i)
    }

    async fn get(&self, id: &str) -> Result<ProviderInstance> {
        self.live
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(id.into()))
    }

    async fn list(&self) -> Result<Vec<ProviderInstance>> {
        Ok(self.live.lock().unwrap().values().cloned().collect())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.live.lock().unwrap().remove(id);
        Ok(())
    }

    fn endpoint(&self, _: &ProviderInstance, port: u16) -> Result<ServiceEndpoint> {
        Ok(ServiceEndpoint {
            url: if port == 3211 {
                self.spacesd.clone()
            } else {
                format!("http://127.0.0.1:9/{port}")
            },
            headers: vec![],
        })
    }
}

/// A registry with a desktop-like rootfs (cua-spacesd label), a VM-only
/// image and an arm64-only image.
fn registry() -> FakeRegistry {
    let mut r = FakeRegistry::default();
    let cfg = r.put_blob(&json!({"os": "linux", "architecture": "amd64",
        "config": {"Entrypoint": ["/start"], "Labels": {"ai.cua.spacesd": "true"}}}));
    let m = json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": cfg.media_type, "digest": cfg.digest, "size": cfg.size},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:00", "size": 1}]});
    r.put_manifest(
        "ghcr.io/trycua/linux",
        Some("ghcr.io/trycua/linux:24.04"),
        &m,
    );
    r.put_manifest(
        "ghcr.io/trycua/linux",
        Some("ghcr.io/trycua/linux:24.04-slim"),
        &m,
    );
    r.index("ghcr.io/example/vm-only:1", &["amd64"], true, None);
    r.index("ghcr.io/example/arm-only:1", &["arm64"], false, None);
    r
}

struct CountingSource {
    inner: FakeRegistry,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl cua_image::registry::ManifestSource for CountingSource {
    async fn manifest(
        &self,
        reference: &str,
    ) -> cua_image::Result<(cua_image::manifest::Manifest, String)> {
        self.calls.lock().unwrap().push(reference.to_string());
        self.inner.manifest(reference).await
    }

    async fn blob(
        &self,
        reference: &str,
        desc: &cua_image::manifest::Descriptor,
    ) -> cua_image::Result<Vec<u8>> {
        self.inner.blob(reference, desc).await
    }
}

static SOURCE_LOCK: std::sync::OnceLock<Arc<tokio::sync::Mutex<()>>> = std::sync::OnceLock::new();
fn source_lock() -> &'static Arc<tokio::sync::Mutex<()>> {
    SOURCE_LOCK.get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
}

struct Env {
    _source_guard: tokio::sync::OwnedMutexGuard<()>,
    _dir: tempfile::TempDir,
    _mock: MockServer,
    fake: Arc<Fake>,
    sbx: Sandboxes,
}

async fn env(env_to_entrypoint: bool) -> Env {
    let guard = source_lock().clone().lock_owned().await;
    cua_image::resolve::set_source(Some(Arc::new(registry())));
    let dir = tempfile::tempdir().unwrap();
    let mock = MockServer::start(MockAuth::default()).await;
    let fake = Fake::new(mock.url(), env_to_entrypoint);
    let sbx = Sandboxes::builder()
        .provider(fake.clone())
        .state_dir(dir.path().join("sandboxes"))
        .build();
    Env {
        _source_guard: guard,
        _dir: dir,
        _mock: mock,
        fake,
        sbx,
    }
}

fn opts(image: &str) -> CreateOptions {
    let mut o = CreateOptions::new(ProviderKind::Contrib, image);
    o.contrib = Some("e2b".into());
    o
}

#[tokio::test]
async fn named_sandbox_lifecycle_refs_state_and_spacesd() {
    let e = env(false).await;
    let sb = e
        .sbx
        .create(opts("ghcr.io/trycua/linux:24.04").name("cua-e2e-contrib-a"))
        .await
        .unwrap();
    assert_eq!(sb.provider(), ProviderKind::Contrib);
    assert_eq!(sb.runtime_type(), "e2b");
    assert_eq!(sb.id(), "e2b:cua-e2e-contrib-a");
    assert_eq!(sb.location(), "e2b");
    // The provider got the pinned image, the spacesd port and labels.
    let spec = e.fake.created.lock().unwrap()[0].clone();
    assert!(
        spec.image
            .pinned_ref
            .starts_with("ghcr.io/trycua/linux@sha256:")
    );
    assert_eq!(spec.image.kind, RunKind::Container);
    assert_eq!(spec.image.spacesd, Some(true));
    assert!(spec.ports.contains(&3211));
    assert_eq!(spec.labels["cua.name"], "cua-e2e-contrib-a");
    // env_to_entrypoint = false: no token in the guest environment (the
    // SDK installs one with Init instead).
    assert!(!spec.env.contains_key("CUA_ENV_TOKEN"));
    // Private details never show.
    let details = sb.provider_details();
    assert_eq!(details["provider"], "e2b");
    assert_eq!(details["template"], "cua-test");
    assert!(!details.contains_key("_secret"));
    // Readiness included cua-spacesd (the image declares it); attach works
    // over the provider's port URL.
    let client = sb.spacesd().await.unwrap();
    client.health().await.unwrap();
    assert_eq!(
        sb.service("env").unwrap().url(),
        e._mock.url().trim_end_matches('/')
    );

    // Refs and state: reattach by name and by `e2b:<name>`.
    let r = SandboxRef::parse("e2b:cua-e2e-contrib-a").unwrap();
    assert_eq!(r.location_word(), Some("e2b"));
    let again = e.sbx.connect_ref(&r).await.unwrap();
    assert_eq!(again.id(), "e2b:cua-e2e-contrib-a");
    let bare = SandboxRef::parse("cua-e2e-contrib-a").unwrap();
    assert_eq!(e.sbx.resolve_ref(&bare).await.unwrap(), r);
    let listed = e.sbx.list().await.unwrap();
    let row = listed
        .iter()
        .find(|i| i.name == "cua-e2e-contrib-a")
        .unwrap();
    assert_eq!(row.provider, ProviderKind::Contrib);
    assert_eq!(row.id, "e2b:cua-e2e-contrib-a");
    assert_eq!(
        e.sbx.get("cua-e2e-contrib-a").await.unwrap().status,
        Status::Running
    );

    // Suspend is refused with a typed error naming the provider.
    let err = sb.suspend().await.unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }), "{err}");

    e.sbx.delete("cua-e2e-contrib-a").await.unwrap();
    assert!(e.fake.live.lock().unwrap().is_empty());
    assert!(e.sbx.connect("cua-e2e-contrib-a").await.is_err());
}

#[tokio::test]
async fn token_is_delivered_when_the_entrypoint_sees_the_environment() {
    let e = env(true).await;
    let sb = e
        .sbx
        .create(opts("ghcr.io/trycua/linux:24.04"))
        .await
        .unwrap();
    assert!(sb.is_ephemeral());
    let spec = e.fake.created.lock().unwrap()[0].clone();
    assert_eq!(spec.env.get("CUA_ENV_TOKEN").map(String::len), Some(32));
    assert!(spec.name.starts_with("cua-eph-"));
    sb.delete().await.unwrap();
    assert!(e.fake.live.lock().unwrap().is_empty());
}

#[tokio::test]
async fn impossible_requests_fail_typed_before_any_provider_call() {
    let e = env(false).await;
    let cases: Vec<(CreateOptions, &str)> = vec![
        (opts("ghcr.io/example/vm-only:1"), "no variant e2b can run"),
        (
            opts("vm:ghcr.io/trycua/linux:24.04"),
            "does not run vm sandboxes",
        ),
        (opts("ghcr.io/example/arm-only:1"), "no amd64 build"),
        (
            {
                let mut o = opts("ghcr.io/trycua/linux:24.04");
                o.os = "windows".into();
                o
            },
            "Linux sandboxes only",
        ),
        (
            {
                let mut o = opts("ghcr.io/trycua/linux:24.04");
                o.cpus = 64;
                o
            },
            "at most 8 vCPUs",
        ),
        (
            {
                let mut o = opts("ghcr.io/trycua/linux:24.04");
                o.network = cua_sandbox_core::NetworkMode::None;
                o
            },
            "network",
        ),
        (
            {
                let mut o = opts("ghcr.io/trycua/linux:24.04");
                o.contrib = Some("daytona".into());
                o
            },
            "this build has no daytona provider",
        ),
    ];
    for (o, want) in cases {
        let err = e.sbx.create(o).await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnsupportedImage(_) | Error::Unsupported { .. } | Error::InvalidArgument(_)
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains(want), "{err} (wanted {want:?})");
    }
    assert!(e.fake.created.lock().unwrap().is_empty());
}

#[test]
fn contrib_refs_parse_and_print() {
    for s in ["e2b:box", "daytona:box", "modal:box"] {
        assert_eq!(SandboxRef::parse(s).unwrap().to_string(), s);
    }
    assert!(SandboxRef::parse("e2b:").is_err());
    assert!(SandboxRef::parse("nosuch:box").is_err());
}

/// A cancelled create stops the provider's create and deletes the sandbox
/// it made; a sandbox of that name made before is never touched.
#[tokio::test]
async fn a_cancelled_create_deletes_what_it_made_and_nothing_else() {
    let e = env(false).await;
    e.fake.hang.store(true, std::sync::atomic::Ordering::SeqCst);
    let cancel = cua_sandbox_core::CancellationToken::new();
    let create = e.sbx.create_cancellable(
        opts("ghcr.io/trycua/linux:24.04").name("cua-cancel-a"),
        cancel.clone(),
    );
    let fire = async {
        // Once the provider has made it.
        while e.fake.live.lock().unwrap().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        cancel.cancel();
    };
    let (r, ()) = tokio::join!(create, fire);
    match r {
        Err(Error::Cancelled(what)) => assert_eq!(what, "removed cua-cancel-a"),
        other => panic!("{:?}", other.map(|s| s.id())),
    }
    assert!(
        e.fake.live.lock().unwrap().is_empty(),
        "the sandbox is gone"
    );
    // Twice is harmless: the token is spent, a new create runs anew.
    e.fake
        .hang
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let kept = e
        .sbx
        .create(opts("ghcr.io/trycua/linux:24.04").name("cua-cancel-b"))
        .await
        .unwrap();
    // A create under a name in use, cancelled: the existing one stays.
    e.fake.hang.store(true, std::sync::atomic::Ordering::SeqCst);
    let cancel = cua_sandbox_core::CancellationToken::new();
    cancel.cancel();
    let r = e
        .sbx
        .create_cancellable(
            opts("ghcr.io/trycua/linux:24.04").name("cua-cancel-b"),
            cancel,
        )
        .await;
    match r {
        Err(Error::Cancelled(what)) => assert!(what.contains("existed before"), "{what}"),
        other => panic!("{:?}", other.map(|s| s.id())),
    }
    assert!(
        e.fake
            .live
            .lock()
            .unwrap()
            .values()
            .any(|i| i.name == "cua-cancel-b"),
        "the earlier sandbox stays"
    );
    drop(kept);
}

/// Dropping the create (a closed request) cleans up the same way.
#[tokio::test]
async fn a_dropped_create_deletes_what_it_made() {
    let e = env(false).await;
    e.fake.hang.store(true, std::sync::atomic::Ordering::SeqCst);
    let create = e.sbx.create_cancellable(
        opts("ghcr.io/trycua/linux:24.04"),
        cua_sandbox_core::CancellationToken::new(),
    );
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), create).await;
    assert_eq!(e.fake.live.lock().unwrap().len(), 1, "made before the drop");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !e.fake.live.lock().unwrap().is_empty() {
        assert!(tokio::time::Instant::now() < deadline, "never cleaned up");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A GPU type reaches the provider; one it does not offer is refused
/// before any call.
#[tokio::test]
async fn a_gpu_type_reaches_the_provider() {
    let e = env(false).await;
    let mut o = opts("ghcr.io/trycua/linux:24.04").name("cua-gpu-a");
    o.gpu = Some("auto".into());
    e.sbx.create(o).await.unwrap();
    assert_eq!(e.fake.created.lock().unwrap()[0].gpu.as_deref(), Some("T4"));
    let mut o = opts("ghcr.io/trycua/linux:24.04").name("cua-gpu-b");
    o.gpu = Some("H100".into());
    match e.sbx.create(o).await {
        Err(Error::InvalidArgument(m)) => assert!(m.contains("offers T4"), "{m}"),
        other => panic!("{:?}", other.map(|s| s.id())),
    }
    assert_eq!(
        e.fake.created.lock().unwrap().len(),
        1,
        "refused before a call"
    );
}

struct MultiOsFake {
    spacesd: String,
    created: Mutex<Vec<ProviderCreate>>,
    live: Mutex<BTreeMap<String, ProviderInstance>>,
}

impl MultiOsFake {
    fn new(spacesd: String) -> Arc<Self> {
        Arc::new(Self {
            spacesd,
            created: Mutex::default(),
            live: Mutex::default(),
        })
    }
}

#[async_trait]
impl Provider for MultiOsFake {
    fn name(&self) -> &'static str {
        "aliyun-ecs"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            kinds: vec![RunKind::Container, RunKind::Vm],
            runtime: "docker",
            arches: vec!["amd64"],
            image_mode: ImageMode::Direct,
            ports: PortExposure::Https,
            command: false,
            env_to_entrypoint: true,
            private_registry: false,
            suspend: true,
            max_cpus: None,
            max_memory_mb: None,
            credential_env: &[],
            gpus: vec![],
            oses: vec!["linux", "windows"],
            custom_disk_gb: true,
            custom_cloud_image: true,
        }
    }

    fn supported_oses(&self) -> &'static [&'static str] {
        &["linux", "windows"]
    }

    fn check_configured(&self) -> Result<()> {
        Ok(())
    }

    async fn create(&self, spec: &ProviderCreate) -> Result<ProviderInstance> {
        self.created.lock().unwrap().push(spec.clone());
        let id = format!("i-win-{}", self.created.lock().unwrap().len());
        let mut i = ProviderInstance::new(&id, &spec.name, Status::Running);
        i.details.insert(
            "runtime".into(),
            if spec.runtime == cua_sandbox_core::placement::Runtime::Auto {
                "native".into()
            } else {
                spec.runtime.as_str().into()
            },
        );
        self.live.lock().unwrap().insert(id, i.clone());
        Ok(i)
    }

    async fn get(&self, id: &str) -> Result<ProviderInstance> {
        self.live
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(id.into()))
    }

    async fn list(&self) -> Result<Vec<ProviderInstance>> {
        Ok(self.live.lock().unwrap().values().cloned().collect())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.live.lock().unwrap().remove(id);
        Ok(())
    }

    fn endpoint(&self, _: &ProviderInstance, port: u16) -> Result<ServiceEndpoint> {
        Ok(ServiceEndpoint {
            url: if port == 3211 {
                self.spacesd.clone()
            } else {
                format!("http://127.0.0.1:9/{port}")
            },
            headers: vec![],
        })
    }
}

struct CapableCloud {
    spacesd: String,
    created: Mutex<Vec<ProviderCreate>>,
}

#[async_trait]
impl Provider for CapableCloud {
    fn name(&self) -> &'static str {
        "aliyun-ecs"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            kinds: vec![RunKind::Container, RunKind::Vm],
            runtime: "docker-on-vm",
            arches: vec!["amd64"],
            image_mode: ImageMode::Direct,
            ports: PortExposure::Https,
            command: false,
            env_to_entrypoint: true,
            private_registry: false,
            suspend: true,
            max_cpus: None,
            max_memory_mb: None,
            credential_env: &[],
            gpus: vec![],
            oses: vec!["linux", "windows"],
            custom_disk_gb: true,
            custom_cloud_image: true,
        }
    }

    fn supported_oses(&self) -> &'static [&'static str] {
        &["linux", "windows"]
    }

    fn check_configured(&self) -> Result<()> {
        Ok(())
    }

    async fn create(&self, spec: &ProviderCreate) -> Result<ProviderInstance> {
        self.created.lock().unwrap().push(spec.clone());
        Ok(ProviderInstance::new(
            format!("vm-{}", self.created.lock().unwrap().len()),
            &spec.name,
            Status::Running,
        ))
    }

    async fn get(&self, id: &str) -> Result<ProviderInstance> {
        Ok(ProviderInstance::new(id, id, Status::Running))
    }

    async fn list(&self) -> Result<Vec<ProviderInstance>> {
        Ok(vec![])
    }

    async fn delete(&self, _: &str) -> Result<()> {
        Ok(())
    }

    fn endpoint(&self, _: &ProviderInstance, port: u16) -> Result<ServiceEndpoint> {
        Ok(ServiceEndpoint {
            url: if port == 3211 {
                self.spacesd.clone()
            } else {
                format!("http://127.0.0.1:9/{port}")
            },
            headers: vec![],
        })
    }
}

#[tokio::test]
async fn windows_direct_vm_bypasses_oci_and_rejects_docker_or_container_kind() {
    let _guard = source_lock().clone().lock_owned().await;
    cua_image::resolve::set_source(Some(Arc::new(registry())));
    let dir = tempfile::tempdir().unwrap();
    let mock = MockServer::start(MockAuth::default()).await;
    let fake = MultiOsFake::new(mock.url());
    let sbx = Sandboxes::builder()
        .provider(fake.clone())
        .state_dir(dir.path().join("sandboxes"))
        .build();

    let mut o = CreateOptions::new(ProviderKind::Contrib, "windows");
    o.contrib = Some("aliyun-ecs".into());
    o.name = Some("win-direct-a".into());
    o.os = "windows".into();
    o.kind = cua_sandbox_core::placement::Kind::Vm;
    o.runtime = cua_sandbox_core::placement::Runtime::Other("native".into());
    let sb = sbx.create(o).await.unwrap();
    assert_eq!(
        sb.placement(),
        (
            cua_sandbox_core::placement::Kind::Vm,
            cua_sandbox_core::placement::Runtime::Other("native".into())
        )
    );
    let spec = fake.created.lock().unwrap()[0].clone();
    assert_eq!(spec.image.kind, RunKind::Vm);
    let minted = sb
        .env_token()
        .expect("Windows contrib with env_to_entrypoint=true must mint env_token");
    assert_eq!(
        spec.env.get("CUA_ENV_TOKEN").map(String::as_str),
        Some(minted.as_str())
    );

    let raw_state =
        std::fs::read_to_string(dir.path().join("sandboxes/win-direct-a.json")).unwrap();
    let state_json: serde_json::Value = serde_json::from_str(&raw_state).unwrap();
    assert_eq!(state_json["image"]["kind"], "vm");
    assert_eq!(state_json["env_token"], minted);

    let mut bad_rt = CreateOptions::new(ProviderKind::Contrib, "windows");
    bad_rt.contrib = Some("aliyun-ecs".into());
    bad_rt.os = "windows".into();
    bad_rt.runtime = cua_sandbox_core::placement::Runtime::Other("docker".into());
    let err = sbx.create(bad_rt).await.unwrap_err();
    assert!(matches!(err, Error::UnsupportedImage(_)), "{err:?}");

    let mut bad_kind = CreateOptions::new(ProviderKind::Contrib, "windows");
    bad_kind.contrib = Some("aliyun-ecs".into());
    bad_kind.os = "windows".into();
    bad_kind.kind = cua_sandbox_core::placement::Kind::Container;
    let err = sbx.create(bad_kind).await.unwrap_err();
    assert!(matches!(err, Error::UnsupportedImage(_)), "{err:?}");
    assert_eq!(fake.created.lock().unwrap().len(), 1);
}

struct ConnectOptsTokenFake {
    spacesd: String,
    expected_token: String,
    live: Mutex<BTreeMap<String, ProviderInstance>>,
}

#[async_trait]
impl Provider for ConnectOptsTokenFake {
    fn name(&self) -> &'static str {
        "e2b"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            kinds: vec![RunKind::Vm],
            runtime: "native",
            arches: vec!["amd64"],
            image_mode: ImageMode::Direct,
            ports: PortExposure::Https,
            command: false,
            env_to_entrypoint: false,
            private_registry: false,
            suspend: false,
            max_cpus: None,
            max_memory_mb: None,
            credential_env: &[],
            gpus: vec![],
            oses: vec!["linux", "windows"],
            custom_disk_gb: false,
            custom_cloud_image: false,
        }
    }

    fn supported_oses(&self) -> &'static [&'static str] {
        &["linux", "windows"]
    }

    fn check_configured(&self) -> Result<()> {
        Ok(())
    }

    async fn create(&self, spec: &ProviderCreate) -> Result<ProviderInstance> {
        let i = ProviderInstance::new("i-tok-1", &spec.name, Status::Running);
        self.live.lock().unwrap().insert(i.id.clone(), i.clone());
        Ok(i)
    }

    async fn get(&self, id: &str) -> Result<ProviderInstance> {
        self.live
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(id.into()))
    }

    async fn list(&self) -> Result<Vec<ProviderInstance>> {
        Ok(self.live.lock().unwrap().values().cloned().collect())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.live.lock().unwrap().remove(id);
        Ok(())
    }

    fn endpoint(&self, _: &ProviderInstance, _port: u16) -> Result<ServiceEndpoint> {
        Ok(ServiceEndpoint {
            url: self.spacesd.clone(),
            headers: vec![],
        })
    }

    fn connect_options(
        &self,
        _instance: &ProviderInstance,
        _port: u16,
    ) -> Option<Result<cua_spacesd_client::ConnectOptions>> {
        let mut opts = match cua_spacesd_client::ConnectOptions::parse(&self.spacesd) {
            Ok(o) => o,
            Err(e) => return Some(Err(Error::InvalidArgument(e.to_string()))),
        };
        opts.token = Some(self.expected_token.clone());
        Some(Ok(opts))
    }
}

#[tokio::test]
async fn spacesd_with_preserves_connect_options_token_when_caps_uninitialized() {
    let _guard = source_lock().clone().lock_owned().await;
    cua_image::resolve::set_source(Some(Arc::new(registry())));
    let dir = tempfile::tempdir().unwrap();
    let expected = "static-env-token-preserved-1234";
    let mock = MockServer::start(MockAuth {
        token: Some(expected.into()),
        ..Default::default()
    })
    .await;
    let fake = Arc::new(ConnectOptsTokenFake {
        spacesd: mock.url(),
        expected_token: expected.into(),
        live: Mutex::default(),
    });
    let sbx = Sandboxes::builder()
        .provider(fake)
        .state_dir(dir.path().join("sandboxes"))
        .build();

    let mut o = CreateOptions::new(ProviderKind::Contrib, "windows");
    o.contrib = Some("e2b".into());
    o.name = Some("win-static-tok".into());
    o.os = "windows".into();
    let sb = sbx.create(o).await.unwrap();
    assert!(sb.env_token().is_none());

    let client = sb.spacesd().await.unwrap();
    assert_eq!(client.token(), Some(expected));
    assert_eq!(sb.env_token().as_deref(), Some(expected));
    client.health().await.unwrap();
}

#[tokio::test]
async fn non_capable_provider_refuses_disk_gb_cloud_image_and_instance_type() {
    let e = env(false).await;

    let mut disk_o = opts("ghcr.io/trycua/linux:24.04");
    disk_o.disk_gb = Some(60);
    let err = e.sbx.create(disk_o).await.unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    assert!(
        err.to_string().contains("disk_gb sizes local VMs only"),
        "{err}"
    );

    let mut img_o = opts("ghcr.io/trycua/linux:24.04");
    img_o.cloud_image_id = Some("m-custom-1".into());
    let err = e.sbx.create(img_o).await.unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");

    let mut type_o = opts("ghcr.io/trycua/linux:24.04");
    type_o.instance_type = Some("ecs.g7.large".into());
    let err = e.sbx.create(type_o).await.unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");

    assert!(e.fake.created.lock().unwrap().is_empty());
}

#[tokio::test]
async fn capable_cloud_forwards_cloud_image_id_disk_gb_instance_type_and_bypasses_oci_for_windows()
{
    let _guard = source_lock().clone().lock_owned().await;
    cua_image::resolve::set_source(Some(Arc::new(registry())));
    let dir = tempfile::tempdir().unwrap();
    let mock = MockServer::start(MockAuth::default()).await;
    let cloud = Arc::new(CapableCloud {
        spacesd: mock.url(),
        created: Mutex::default(),
    });
    let sbx = Sandboxes::builder()
        .provider(cloud.clone())
        .state_dir(dir.path().join("sandboxes"))
        .build();

    let mut win = CreateOptions::new(ProviderKind::Contrib, "windows:11");
    win.contrib = Some("aliyun-ecs".into());
    win.os = "windows".into();
    win.cloud_image_id = Some(" m-win11-golden ".into());
    win.disk_gb = Some(100);
    win.instance_type = Some(" ecs.c7.2xlarge ".into());
    let sb = sbx.create(win).await.unwrap();
    drop(sb);

    let mut win_official = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_official.contrib = Some("aliyun-ecs".into());
    win_official.os = "windows".into();
    sbx.create(win_official).await.unwrap();

    let mut lin = CreateOptions::new(ProviderKind::Contrib, "ghcr.io/trycua/linux:24.04");
    lin.contrib = Some("aliyun-ecs".into());
    lin.cloud_image_id = Some("m-ubuntu-golden".into());
    lin.disk_gb = Some(80);
    sbx.create(lin).await.unwrap();

    let specs = cloud.created.lock().unwrap();
    assert_eq!(specs.len(), 3);
    assert_eq!(specs[0].cloud_image_id.as_deref(), Some("m-win11-golden"));
    assert_eq!(specs[0].disk_gb, Some(100));
    assert_eq!(specs[0].instance_type.as_deref(), Some("ecs.c7.2xlarge"));
    assert_eq!(specs[1].cloud_image_id, None);
    assert_eq!(specs[2].cloud_image_id.as_deref(), Some("m-ubuntu-golden"));
    assert_eq!(specs[2].disk_gb, Some(80));
    assert!(
        specs[2]
            .image
            .pinned_ref
            .starts_with("ghcr.io/trycua/linux")
    );
}

#[tokio::test]
async fn linux_with_os_windows_is_rejected_and_direct_vm_bypasses_oci_while_docker_resolves() {
    let _guard = source_lock().clone().lock_owned().await;
    let counting = Arc::new(CountingSource {
        inner: registry(),
        calls: Mutex::default(),
    });
    cua_image::resolve::set_source(Some(counting.clone()));
    let dir = tempfile::tempdir().unwrap();
    let mock = MockServer::start(MockAuth::default()).await;
    let cloud = Arc::new(CapableCloud {
        spacesd: mock.url(),
        created: Mutex::default(),
    });
    let sbx = Sandboxes::builder()
        .provider(cloud.clone())
        .state_dir(dir.path().join("sandboxes"))
        .build();

    for img in ["linux", "linux-slim", "ghcr.io/trycua/linux:24.04"] {
        let mut bad = CreateOptions::new(ProviderKind::Contrib, img);
        bad.contrib = Some("aliyun-ecs".into());
        bad.os = "windows".into();
        bad.cloud_image_id = Some("m-win11".into());
        let err = sbx.create(bad).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "expected InvalidArgument for os=windows + {img}, got {err:?}"
        );
    }
    assert!(counting.calls.lock().unwrap().is_empty());

    for (img, cid) in [("linux", "m-ubuntu"), ("linux-slim", "m-slim")] {
        let mut native = CreateOptions::new(ProviderKind::Contrib, img);
        native.contrib = Some("aliyun-ecs".into());
        native.runtime = cua_sandbox_core::placement::Runtime::Other("native".into());
        native.cloud_image_id = Some(cid.into());
        sbx.create(native).await.unwrap();
    }
    assert!(
        counting.calls.lock().unwrap().is_empty(),
        "Direct VM must make 0 ManifestSource calls, got: {:?}",
        *counting.calls.lock().unwrap()
    );

    for (img, cid) in [("linux", "m-ubuntu"), ("linux-slim", "m-slim")] {
        let mut docker = CreateOptions::new(ProviderKind::Contrib, img);
        docker.contrib = Some("aliyun-ecs".into());
        docker.cloud_image_id = Some(cid.into());
        sbx.create(docker).await.unwrap();
    }
    let calls = counting.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            "ghcr.io/trycua/linux:24.04".to_string(),
            "ghcr.io/trycua/linux:24.04-slim".to_string(),
        ]
    );
    cua_image::resolve::set_source(Some(Arc::new(registry())));
}

#[tokio::test]
async fn disk_gb_zero_and_whitespace_cloud_image_or_instance_type_fail_invalid_argument() {
    let e = env(false).await;
    let mock = MockServer::start(MockAuth::default()).await;
    let cloud = Arc::new(CapableCloud {
        spacesd: mock.url(),
        created: Mutex::default(),
    });
    let dir = tempfile::tempdir().unwrap();
    let sbx = Sandboxes::builder()
        .provider(cloud.clone())
        .state_dir(dir.path().join("sandboxes"))
        .build();

    let mut e2b_zero = opts("ghcr.io/trycua/linux:24.04");
    e2b_zero.disk_gb = Some(0);
    let err = e.sbx.create(e2b_zero).await.unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    let mut ali_zero = CreateOptions::new(ProviderKind::Contrib, "windows");
    ali_zero.contrib = Some("aliyun-ecs".into());
    ali_zero.os = "windows".into();
    ali_zero.disk_gb = Some(0);
    let err = sbx.create(ali_zero).await.unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    for bad in ["", "   ", "m-foo bar", "m-foo\tbar"] {
        let mut o1 = CreateOptions::new(ProviderKind::Contrib, "windows");
        o1.contrib = Some("aliyun-ecs".into());
        o1.os = "windows".into();
        o1.cloud_image_id = Some(bad.into());
        let err = sbx.create(o1).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "cloud_image_id {bad:?}: {err:?}"
        );

        let mut o2 = CreateOptions::new(ProviderKind::Contrib, "windows");
        o2.contrib = Some("aliyun-ecs".into());
        o2.os = "windows".into();
        o2.instance_type = Some(bad.into());
        let err = sbx.create(o2).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "instance_type {bad:?}: {err:?}"
        );
    }

    assert!(e.fake.created.lock().unwrap().is_empty());
    assert!(cloud.created.lock().unwrap().is_empty());
}

//! A Space or sandbox asked for `network: none` or an egress policy is
//! never handed back open. A daemon older than those fields drops them (an
//! unknown protobuf field) and creates the Space with outbound network, so
//! the SDK trusts only the daemon's answer: `CreateSpaceResponse.network`,
//! `CreateSandboxResponse.network` and `Space.egress`. Without it the
//! create is refused and what the daemon made is deleted. A current daemon
//! answers with them and the create works.
//!
//! The old daemon is served in-process and answers as one built before the
//! fields existed; the current one is the real daemon over a fake local
//! runtime whose instance is a mock spacesd. Nothing starts a container or
//! VM, and nothing touches `~/.cua`.

use async_trait::async_trait;
use cua_daemon::{
    Runtime, RuntimeConfig,
    fixtures::{self, SpacesdFixture},
    server::{self, DaemonHandle, ServerConfig},
};
use cua_proto::daemon::v1 as dpb;
use cua_sandbox_core::{
    InstanceStatus, LocalEndpoints, LocalInstance, LocalRuntime, LocalStartSpec, LocalSummary,
    RuntimeError, RuntimeResult,
};
use cua_sdk::{
    Cua, CuaError, EgressPolicy, SandboxCreateOptions, SpaceCreateListener, SpaceCreateOptions,
    SpaceCreateProgress,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

// ---------------------------------------------------------------------------
// An older daemon.
// ---------------------------------------------------------------------------

/// What the old daemon was asked and did.
#[derive(Default)]
struct Old {
    creates: Mutex<Vec<dpb::CreateSpaceRequest>>,
    sandbox_creates: Mutex<Vec<dpb::CreateSandboxRequest>>,
    deleted: Mutex<Vec<String>>,
    sandboxes_deleted: Mutex<Vec<String>>,
}

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// One unary method of the old daemon.
struct Unary<F>(F);

impl<Req, Resp, F> tonic::server::UnaryService<Req> for Unary<F>
where
    F: FnMut(Req) -> Resp,
    Resp: Send + 'static,
{
    type Response = Resp;
    type Future = BoxFut<Result<tonic::Response<Resp>, tonic::Status>>;
    fn call(&mut self, request: tonic::Request<Req>) -> Self::Future {
        let r = (self.0)(request.into_inner());
        Box::pin(async move { Ok(tonic::Response::new(r)) })
    }
}

fn unimplemented() -> http::Response<tonic::body::Body> {
    let mut r = http::Response::new(tonic::body::Body::default());
    r.headers_mut().insert(
        "grpc-status",
        (tonic::Code::Unimplemented as i32)
            .to_string()
            .parse()
            .unwrap(),
    );
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        "application/grpc".parse().unwrap(),
    );
    r
}

/// Serves `method` of a request, decoding `Req` and encoding what `f` gives.
fn serve<B, Req, Resp>(
    req: http::Request<B>,
    f: impl FnMut(Req) -> Resp + Send + 'static,
) -> BoxFut<Result<http::Response<tonic::body::Body>, std::convert::Infallible>>
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
    Req: prost::Message + Default + Send + 'static,
    Resp: prost::Message + Send + 'static,
{
    Box::pin(async move {
        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::<Resp, Req>::default());
        Ok(grpc.unary(Unary(f), req).await)
    })
}

/// `cua.daemon.v1.SpaceService` and `SandboxService` as a daemon built
/// before `network` and `egress` answers: it creates the Space (open: it
/// never read either field) and its answers carry neither.
#[derive(Clone)]
struct OldDaemon<const SANDBOXES: bool>(Arc<Old>);

impl<const S: bool> tonic::server::NamedService for OldDaemon<S> {
    const NAME: &'static str = if S {
        "cua.daemon.v1.SandboxService"
    } else {
        "cua.daemon.v1.SpaceService"
    };
}

impl<B, const S: bool> tower::Service<http::Request<B>> for OldDaemon<S>
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFut<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let old = self.0.clone();
        match req.uri().path() {
            "/cua.daemon.v1.SpaceService/CreateSpace" => {
                serve(req, move |r: dpb::CreateSpaceRequest| {
                    let id = format!("local:{}", r.name);
                    let wait = r.wait != Some(false);
                    old.creates.lock().unwrap().push(r);
                    dpb::CreateSpaceResponse {
                        space: Some(dpb::Space {
                            id,
                            ..Default::default()
                        }),
                        phase: if wait { "ready" } else { "starting" }.into(),
                        ..Default::default()
                    }
                })
            }
            "/cua.daemon.v1.SpaceService/DeleteSpace" => {
                serve(req, move |r: dpb::DeleteSpaceRequest| {
                    old.deleted.lock().unwrap().push(r.space);
                    dpb::DeleteSpaceResponse {
                        message: "deleted".into(),
                    }
                })
            }
            "/cua.daemon.v1.SandboxService/CreateSandbox" => {
                serve(req, move |r: dpb::CreateSandboxRequest| {
                    let name = r.name.clone();
                    old.sandbox_creates.lock().unwrap().push(r);
                    dpb::CreateSandboxResponse {
                        sandbox: Some(dpb::Sandbox {
                            name,
                            location: "local".into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }
                })
            }
            "/cua.daemon.v1.SandboxService/DeleteSandbox" => {
                serve(req, move |r: dpb::DeleteSandboxRequest| {
                    old.sandboxes_deleted.lock().unwrap().push(r.name);
                    dpb::DeleteSandboxResponse::default()
                })
            }
            // Everything else (progress streams, cancels, GetInfo) this old
            // daemon does not have.
            _ => Box::pin(async { Ok(unimplemented()) }),
        }
    }
}

/// An old daemon on loopback, and an SDK connected to it.
async fn old_daemon() -> (Arc<Old>, Arc<Cua>) {
    let old = Arc::new(Old::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(OldDaemon::<false>(old.clone()))
            .add_service(OldDaemon::<true>(old.clone()))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let cua = Cua::connect(Some(format!("http://{addr}")), Some("token".into())).unwrap();
    (old, cua)
}

/// An M5-era daemon: has `GetInfo` (without M6a sandbox features) and
/// `ListSpaceTools` (whose `create_space` lacks `cloud_image_id` and `disk_gb`),
/// and silently ignores proto tags added in M6a.
#[derive(Clone)]
struct M5Daemon<const SVC: u8>(Arc<Old>);

impl<const SVC: u8> tonic::server::NamedService for M5Daemon<SVC> {
    const NAME: &'static str = match SVC {
        0 => "cua.daemon.v1.SpaceService",
        1 => "cua.daemon.v1.SandboxService",
        _ => "cua.daemon.v1.DaemonService",
    };
}

impl<B, const SVC: u8> tower::Service<http::Request<B>> for M5Daemon<SVC>
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFut<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let old = self.0.clone();
        match req.uri().path() {
            "/cua.daemon.v1.DaemonService/GetInfo" => {
                serve(req, move |_: dpb::GetInfoRequest| dpb::GetInfoResponse {
                    version: "0.9.0-m5".into(),
                    features: vec![
                        "env".into(),
                        "sandboxes".into(),
                        "spaces".into(),
                        "mcp".into(),
                    ],
                    ..Default::default()
                })
            }
            "/cua.daemon.v1.SpaceService/ListSpaceTools" => {
                serve(req, move |_: dpb::ListSpaceToolsRequest| {
                    dpb::ListSpaceToolsResponse {
                        tools_json: r#"{"tools":[{"name":"create_space","inputSchema":{"properties":{"image":{},"on":{},"kind":{},"runtime":{},"name":{},"cpus":{},"memory_mb":{},"instance_type":{},"region":{}}}}]}"#.into(),
                    }
                })
            }
            "/cua.daemon.v1.SpaceService/CreateSpace" => {
                serve(req, move |r: dpb::CreateSpaceRequest| {
                    let loc = if r.location.is_empty() {
                        "local".to_string()
                    } else {
                        r.location.clone()
                    };
                    let id = format!("{loc}:{}", r.name);
                    let wait = r.wait != Some(false);
                    old.creates.lock().unwrap().push(r);
                    dpb::CreateSpaceResponse {
                        space: Some(dpb::Space {
                            id,
                            ..Default::default()
                        }),
                        phase: if wait { "ready" } else { "starting" }.into(),
                        ..Default::default()
                    }
                })
            }
            "/cua.daemon.v1.SpaceService/DeleteSpace" => {
                serve(req, move |r: dpb::DeleteSpaceRequest| {
                    old.deleted.lock().unwrap().push(r.space);
                    dpb::DeleteSpaceResponse {
                        message: "deleted".into(),
                    }
                })
            }
            "/cua.daemon.v1.SandboxService/CreateSandbox" => {
                serve(req, move |r: dpb::CreateSandboxRequest| {
                    let name = r.name.clone();
                    let location = if r.location.is_empty() {
                        "local".to_string()
                    } else {
                        r.location.clone()
                    };
                    old.sandbox_creates.lock().unwrap().push(r);
                    dpb::CreateSandboxResponse {
                        sandbox: Some(dpb::Sandbox {
                            name,
                            location,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }
                })
            }
            "/cua.daemon.v1.SandboxService/DeleteSandbox" => {
                serve(req, move |r: dpb::DeleteSandboxRequest| {
                    old.sandboxes_deleted.lock().unwrap().push(r.name);
                    dpb::DeleteSandboxResponse::default()
                })
            }
            _ => Box::pin(async { Ok(unimplemented()) }),
        }
    }
}

async fn m5_daemon() -> (Arc<Old>, Arc<Cua>) {
    let old = Arc::new(Old::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(M5Daemon::<0>(old.clone()))
            .add_service(M5Daemon::<1>(old.clone()))
            .add_service(M5Daemon::<2>(old.clone()))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let cua = Cua::connect(Some(format!("http://{addr}")), Some("token".into())).unwrap();
    (old, cua)
}

struct NoopSpaceListener;

impl SpaceCreateListener for NoopSpaceListener {
    fn on_progress(&self, _: SpaceCreateProgress) {}
}

fn space(name: &str) -> SpaceCreateOptions {
    SpaceCreateOptions {
        image: Some("ghcr.io/trycua/linux:24.04".into()),
        on: Some("local".into()),
        kind: Some("container".into()),
        name: Some(name.into()),
        ..Default::default()
    }
}

fn deny_all() -> EgressPolicy {
    EgressPolicy {
        allow: vec!["1.1.1.1".into()],
        deny: vec!["all".into()],
    }
}

fn too_old(e: &CuaError, what: &str) {
    let CuaError::CapabilityMissing(m) = e else {
        panic!("expected CapabilityMissing, got {e:?}");
    };
    assert!(m.starts_with(what), "{m}");
    assert!(m.contains("too old to enforce"), "{m}");
    assert!(m.contains("update cua"), "{m}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_none_through_an_old_daemon_is_refused_and_deleted() {
    let (old, cua) = old_daemon().await;
    for wait in [None, Some(false)] {
        let name = format!("closed-{}", wait.is_some());
        let e = cua
            .spaces()
            .create(SpaceCreateOptions {
                network: Some("none".into()),
                wait,
                ..space(&name)
            })
            .await
            .expect_err("an open Space must not come back");
        too_old(&e, "network none");
        let CuaError::CapabilityMissing(m) = &e else {
            unreachable!()
        };
        assert!(m.contains(&format!("local:{name}")), "{m}");
        assert_eq!(
            old.deleted.lock().unwrap().last(),
            Some(&format!("local:{name}")),
            "what the old daemon made is deleted"
        );
    }
    let creates = old.creates.lock().unwrap();
    assert_eq!(creates.len(), 2);
    assert!(creates.iter().all(|c| c.network == "none"), "it was asked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn egress_through_an_old_daemon_is_refused_and_deleted() {
    let (old, cua) = old_daemon().await;
    let e = cua
        .spaces()
        .create(SpaceCreateOptions {
            egress: Some(deny_all()),
            ..space("ruled")
        })
        .await
        .expect_err("a Space without its rules must not come back");
    too_old(&e, "egress rules");
    assert_eq!(*old.deleted.lock().unwrap(), ["local:ruled"]);
    // Setting rules later on such a daemon says so too.
    let e = cua
        .spaces()
        .set_egress("local:ruled".into(), deny_all())
        .await
        .unwrap_err();
    let CuaError::CapabilityMissing(m) = &e else {
        panic!("{e:?}")
    };
    assert!(m.contains("too old"), "{m}");
}

/// What no daemon could keep is refused before any daemon is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_cannot_be_kept_is_refused_before_the_daemon_is_asked() {
    let (old, cua) = old_daemon().await;
    let refused = |o: SpaceCreateOptions| {
        let cua = cua.clone();
        async move {
            match cua.spaces().create(o).await {
                Err(CuaError::InvalidArgument(m)) => m,
                other => panic!("expected InvalidArgument, got {other:?}"),
            }
        }
    };
    let m = refused(SpaceCreateOptions {
        egress: Some(deny_all()),
        wait: Some(false),
        ..space("a")
    })
    .await;
    assert!(m.contains("wait = false"), "{m}");
    for (reuse, durable) in [(true, false), (false, true)] {
        let m = refused(SpaceCreateOptions {
            network: Some("none".into()),
            reuse,
            durable,
            ..space("b")
        })
        .await;
        assert!(m.contains("network=none"), "{m}");
    }
    assert!(old.creates.lock().unwrap().is_empty(), "nothing was sent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sandbox_without_network_through_an_old_daemon_is_refused_and_deleted() {
    let (old, cua) = old_daemon().await;
    let mut o = SandboxCreateOptions::new("local", "ghcr.io/trycua/linux:24.04");
    o.kind = Some("container".into());
    o.name = Some("closed-sb".into());
    o.network = Some("none".into());
    let Err(e) = cua.sandboxes().create(o).await else {
        panic!("an open sandbox must not come back");
    };
    too_old(&e, "network none");
    assert_eq!(*old.sandboxes_deleted.lock().unwrap(), ["closed-sb"]);
    assert_eq!(old.sandbox_creates.lock().unwrap()[0].network, "none");
}

// ---------------------------------------------------------------------------
// A current daemon.
// ---------------------------------------------------------------------------

/// A runtime whose instances are the fixture's spacesd; it keeps the start
/// specs, to show the network was cut.
struct Fake {
    port: u16,
    starts: Arc<Mutex<Vec<LocalStartSpec>>>,
    running: Mutex<HashMap<String, bool>>,
}

#[async_trait]
impl LocalRuntime for Fake {
    fn backend(&self) -> String {
        "fake".into()
    }
    async fn start(&self, spec: &LocalStartSpec) -> RuntimeResult<LocalInstance> {
        self.starts.lock().unwrap().push(spec.clone());
        self.running.lock().unwrap().insert(spec.name.clone(), true);
        Ok(LocalInstance {
            name: spec.name.clone(),
            backend: "fake".into(),
            status: InstanceStatus::Running,
            endpoints: self.endpoints(&spec.name).await?,
        })
    }
    async fn stop(&self, _: &str) -> RuntimeResult<()> {
        Ok(())
    }
    async fn resume(&self, name: &str) -> RuntimeResult<LocalInstance> {
        Ok(LocalInstance {
            name: name.into(),
            backend: "fake".into(),
            status: InstanceStatus::Running,
            endpoints: self.endpoints(name).await?,
        })
    }
    async fn list(&self) -> RuntimeResult<Vec<LocalSummary>> {
        Ok(vec![])
    }
    async fn status(&self, name: &str) -> RuntimeResult<InstanceStatus> {
        match self.running.lock().unwrap().get(name) {
            Some(true) => Ok(InstanceStatus::Running),
            _ => Err(RuntimeError::NotFound(name.into())),
        }
    }
    async fn endpoints(&self, _: &str) -> RuntimeResult<LocalEndpoints> {
        Ok(LocalEndpoints {
            host: "127.0.0.1".into(),
            ports: [(3211u16, self.port)].into(),
            ..Default::default()
        })
    }
    async fn delete(&self, name: &str) -> RuntimeResult<()> {
        self.running.lock().unwrap().remove(name);
        Ok(())
    }
}

struct Current {
    _env: SpacesdFixture,
    _dirs: tempfile::TempDir,
    _daemon: DaemonHandle,
    cua: Arc<Cua>,
    starts: Arc<Mutex<Vec<LocalStartSpec>>>,
}

async fn current_daemon() -> Current {
    let env = fixtures::start_env(None, None).await;
    let port: u16 = env.url.rsplit(':').next().unwrap().parse().unwrap();
    let dirs = tempfile::tempdir().unwrap();
    let starts: Arc<Mutex<Vec<LocalStartSpec>>> = Arc::default();
    let runtime = Runtime::new(RuntimeConfig {
        state_dir: Some(dirs.path().join("sandboxes")),
        // Never the real ~/.cua registry.
        spaces_home: Some(dirs.path().join("cua")),
        local: Some(Arc::new(Fake {
            port,
            starts: starts.clone(),
            running: Mutex::default(),
        })),
        env_probe_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })
    .unwrap();
    let h = server::start(
        runtime,
        ServerConfig {
            socket_path: None,
            loopback: Some("127.0.0.1:0".parse().unwrap()),
            token: "daemon-token".into(),
            discovery_path: Some(dirs.path().join("daemon.json")),
            bridge_ticket_ttl: Duration::from_secs(30),
        },
    )
    .await
    .unwrap();
    let cua = Cua::connect(h.loopback_url.clone(), Some(h.token.clone())).unwrap();
    Current {
        _env: env,
        _dirs: dirs,
        _daemon: h,
        cua,
        starts,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_current_daemon_cuts_the_network_and_says_so() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let w = current_daemon().await;
        let created = w
            .cua
            .spaces()
            .create(SpaceCreateOptions {
                network: Some("none".into()),
                ..space("cut")
            })
            .await
            .unwrap();
        assert_eq!(created.space.unwrap().id, "local:cut");
        let mut o = SandboxCreateOptions::new("local", "ghcr.io/trycua/linux:24.04");
        o.kind = Some("container".into());
        o.name = Some("cut-sb".into());
        o.network = Some("none".into());
        let sb = w.cua.sandboxes().create(o).await.unwrap();
        assert_eq!(sb.info().name, "cut-sb");
        let starts = w.starts.lock().unwrap();
        assert_eq!(starts.len(), 2, "{starts:?}");
        assert!(
            starts.iter().all(|s| s.restrict_network),
            "both were cut: {starts:?}"
        );
    })
    .await
    .expect("timed out");
}

/// A daemon that predates renaming says so (nothing was renamed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_daemon_says_it_cannot_rename() {
    let (_old, cua) = old_daemon().await;
    match cua
        .spaces()
        .rename("local:ruled".into(), "ruled-2".into())
        .await
    {
        Err(CuaError::CapabilityMissing(m)) => {
            assert!(m.contains("too old to rename"), "{m}");
            assert!(m.contains("update cua"), "{m}");
        }
        other => panic!("expected CapabilityMissing, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spaces_create_cloud_image_id_fails_closed_against_old_and_m5_daemons() {
    for (label, old, cua) in [("pre_tools", old_daemon().await), ("m5", m5_daemon().await)]
        .into_iter()
        .map(|(l, (o, c))| (l, o, c))
    {
        let e = cua
            .spaces()
            .create(SpaceCreateOptions {
                on: Some("aliyun-ecs".into()),
                image: Some("windows".into()),
                name: Some("sp-old-img".into()),
                cloud_image_id: Some("m-win11-golden".into()),
                ..Default::default()
            })
            .await
            .expect_err(&format!("{label}: cloud_image_id must fail closed"));
        assert!(
            matches!(&e, CuaError::CapabilityMissing(m) if m.contains("too old")),
            "{label}: expected CapabilityMissing, got {e:?}"
        );

        let e_stream = cua
            .spaces()
            .create_with_progress(
                SpaceCreateOptions {
                    on: Some("aliyun-ecs".into()),
                    image: Some("windows".into()),
                    name: Some("sp-old-img-stream".into()),
                    cloud_image_id: Some("m-win11-golden".into()),
                    ..Default::default()
                },
                Arc::new(NoopSpaceListener),
            )
            .await
            .expect_err(&format!(
                "{label}: create_with_progress + cloud_image_id must fail closed"
            ));
        assert!(
            matches!(&e_stream, CuaError::CapabilityMissing(m) if m.contains("too old")),
            "{label}: expected CapabilityMissing, got {e_stream:?}"
        );
        assert!(
            old.creates.lock().unwrap().is_empty(),
            "{label}: CreateSpace RPC must not be sent"
        );
    }

    let (m5, cua_m5) = m5_daemon().await;
    for (desc, opts) in [
        (
            "cloud disk_gb",
            SpaceCreateOptions {
                on: Some("aliyun-ecs".into()),
                image: Some("windows".into()),
                name: Some("sp-m5-disk".into()),
                disk_gb: Some(100),
                ..Default::default()
            },
        ),
        (
            "cloud instance_type",
            SpaceCreateOptions {
                on: Some("aliyun-ecs".into()),
                image: Some("linux".into()),
                name: Some("sp-m5-inst".into()),
                instance_type: Some("ecs.c7.2xlarge".into()),
                ..Default::default()
            },
        ),
    ] {
        let e = cua_m5
            .spaces()
            .create(opts)
            .await
            .expect_err(&format!("{desc} must fail closed against m5 daemon"));
        assert!(
            matches!(&e, CuaError::CapabilityMissing(m) if m.contains("too old")),
            "{desc}: expected CapabilityMissing, got {e:?}"
        );
    }
    assert!(
        m5.creates.lock().unwrap().is_empty(),
        "m5 CreateSpace RPC must not be sent for unsupported cloud sizing"
    );

    // Local VM disk_gb existed before M6a and remains supported on M5 daemons.
    let local_res = cua_m5
        .spaces()
        .create(SpaceCreateOptions {
            disk_gb: Some(50),
            ..space("sp-m5-local-disk")
        })
        .await
        .expect("local disk_gb must stay backwards-compatible on M5 daemon");
    assert_eq!(local_res.space.unwrap().id, "local:sp-m5-local-disk");
    assert_eq!(m5.creates.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sandboxes_create_m6a_fields_fail_closed_against_old_and_m5_daemons() {
    for (label, old, cua) in [
        ("pre_getinfo", old_daemon().await),
        ("m5", m5_daemon().await),
    ]
    .into_iter()
    .map(|(l, (o, c))| (l, o, c))
    {
        for (field, opts) in [
            ("cloud_image_id", {
                let mut o = SandboxCreateOptions::new("aliyun-ecs", "windows");
                o.name = Some("sb-old-img".into());
                o.cloud_image_id = Some("m-win11-golden".into());
                o
            }),
            ("instance_type", {
                let mut o = SandboxCreateOptions::new("aliyun-ecs", "windows");
                o.name = Some("sb-old-inst".into());
                o.instance_type = Some("ecs.c7.2xlarge".into());
                o
            }),
            ("disk_gb", {
                let mut o = SandboxCreateOptions::new("aliyun-ecs", "windows");
                o.name = Some("sb-old-disk".into());
                o.disk_gb = Some(120);
                o
            }),
        ] {
            let Err(e) = cua.sandboxes().create(opts.clone()).await else {
                panic!("{label}/{field}: Sandboxes::create must fail closed");
            };
            assert!(
                matches!(&e, CuaError::CapabilityMissing(m) if m.contains("too old") && m.contains(field)),
                "{label}/{field}: expected CapabilityMissing naming {field}, got {e:?}"
            );

            let sink: cua_sandbox_core::progress::Sink = Arc::new(|_| {});
            let Err(e_rep) = cua.sandboxes().create_reporting(opts, sink).await else {
                panic!("{label}/{field}: Sandboxes::create_reporting must fail closed");
            };
            assert!(
                matches!(&e_rep, CuaError::CapabilityMissing(m) if m.contains("too old") && m.contains(field)),
                "{label}/{field}: expected CapabilityMissing naming {field}, got {e_rep:?}"
            );
        }
        assert!(
            old.sandbox_creates.lock().unwrap().is_empty(),
            "{label}: CreateSandbox RPC must not be sent"
        );
    }
}

/// An M6a/M6b-era daemon: advertises `FEATURE_CLOUD_IMAGE_AND_SIZING` without
/// `FEATURE_SANDBOX_TTL`, and silently ignores `CreateSandboxRequest.ttl = 46`.
#[derive(Clone)]
struct M6Daemon<const SVC: u8>(Arc<Old>);

impl<const SVC: u8> tonic::server::NamedService for M6Daemon<SVC> {
    const NAME: &'static str = match SVC {
        0 => "cua.daemon.v1.SpaceService",
        1 => "cua.daemon.v1.SandboxService",
        _ => "cua.daemon.v1.DaemonService",
    };
}

impl<B, const SVC: u8> tower::Service<http::Request<B>> for M6Daemon<SVC>
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFut<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let old = self.0.clone();
        match req.uri().path() {
            "/cua.daemon.v1.DaemonService/GetInfo" => {
                serve(req, move |_: dpb::GetInfoRequest| dpb::GetInfoResponse {
                    version: "0.28.0-m6".into(),
                    features: vec![
                        "env".into(),
                        "sandboxes".into(),
                        "spaces".into(),
                        "mcp".into(),
                        cua_daemon_core::FEATURE_CLOUD_IMAGE_AND_SIZING.into(),
                    ],
                    ..Default::default()
                })
            }
            "/cua.daemon.v1.SandboxService/CreateSandbox" => {
                serve(req, move |r: dpb::CreateSandboxRequest| {
                    let name = r.name.clone();
                    let loc = if r.location.is_empty() {
                        "local".to_string()
                    } else {
                        r.location.clone()
                    };
                    old.sandbox_creates.lock().unwrap().push(r);
                    dpb::CreateSandboxResponse {
                        sandbox: Some(dpb::Sandbox {
                            name,
                            location: loc,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }
                })
            }
            _ => Box::pin(async { Ok(unimplemented()) }),
        }
    }
}

async fn m6_daemon() -> (Arc<Old>, Arc<Cua>) {
    let old = Arc::new(Old::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(M6Daemon::<0>(old.clone()))
            .add_service(M6Daemon::<1>(old.clone()))
            .add_service(M6Daemon::<2>(old.clone()))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let cua = Cua::connect(Some(format!("http://{addr}")), Some("token".into())).unwrap();
    (old, cua)
}

struct NothingToolBackend;

#[async_trait]
impl cua_spaces::mcp::ToolBackend for NothingToolBackend {
    async fn call(&self, _: &str, _: serde_json::Value) -> cua_spaces::mcp::ToolOutcome {
        cua_spaces::mcp::ToolOutcome::text("")
    }
}

/// A loopback daemon supporting M6a `create_space` tools and `CreateSandbox`
/// cloud image / sizing fields, recording received protobuf requests.
#[derive(Clone)]
struct CurrentMockDaemon<const SVC: u8>(Arc<Old>);

impl<const SVC: u8> tonic::server::NamedService for CurrentMockDaemon<SVC> {
    const NAME: &'static str = match SVC {
        0 => "cua.daemon.v1.SpaceService",
        1 => "cua.daemon.v1.SandboxService",
        _ => "cua.daemon.v1.DaemonService",
    };
}

impl<B, const SVC: u8> tower::Service<http::Request<B>> for CurrentMockDaemon<SVC>
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFut<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let recorded = self.0.clone();
        match req.uri().path() {
            "/cua.daemon.v1.DaemonService/GetInfo" => {
                serve(req, move |_: dpb::GetInfoRequest| dpb::GetInfoResponse {
                    version: "0.29.0".into(),
                    features: vec![
                        "env".into(),
                        "sandboxes".into(),
                        "spaces".into(),
                        "mcp".into(),
                        cua_daemon_core::FEATURE_CLOUD_IMAGE_AND_SIZING.into(),
                        cua_daemon_core::FEATURE_SANDBOX_TTL.into(),
                    ],
                    ..Default::default()
                })
            }
            "/cua.daemon.v1.SpaceService/ListSpaceTools" => {
                serve(req, move |_: dpb::ListSpaceToolsRequest| {
                    let tools_json =
                        cua_spaces::mcp::McpServer::remote(Arc::new(NothingToolBackend))
                            .tools_list()
                            .to_string();
                    dpb::ListSpaceToolsResponse { tools_json }
                })
            }
            "/cua.daemon.v1.SpaceService/CreateSpace" => {
                serve(req, move |r: dpb::CreateSpaceRequest| {
                    let id = format!("{}:{}", r.location, r.name);
                    recorded.creates.lock().unwrap().push(r);
                    dpb::CreateSpaceResponse {
                        space: Some(dpb::Space {
                            id,
                            ..Default::default()
                        }),
                        phase: "ready".into(),
                        ..Default::default()
                    }
                })
            }
            "/cua.daemon.v1.SandboxService/CreateSandbox" => {
                serve(req, move |r: dpb::CreateSandboxRequest| {
                    let name = r.name.clone();
                    let location = r.location.clone();
                    recorded.sandbox_creates.lock().unwrap().push(r);
                    dpb::CreateSandboxResponse {
                        sandbox: Some(dpb::Sandbox {
                            name,
                            location,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }
                })
            }
            _ => Box::pin(async { Ok(unimplemented()) }),
        }
    }
}

async fn current_mock_daemon() -> (Arc<Old>, Arc<Cua>) {
    let rec = Arc::new(Old::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(CurrentMockDaemon::<0>(rec.clone()))
            .add_service(CurrentMockDaemon::<1>(rec.clone()))
            .add_service(CurrentMockDaemon::<2>(rec.clone()))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let cua = Cua::connect(Some(format!("http://{addr}")), Some("token".into())).unwrap();
    (rec, cua)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_daemon_accepts_and_delivers_m6a_cloud_image_and_sizing_fields() {
    // 1. Real `cua-daemon` advertises capability & passes client-side preflight.
    let w = current_daemon().await;
    let err = w
        .cua
        .spaces()
        .create(SpaceCreateOptions {
            on: Some("local".into()),
            image: Some("linux".into()),
            name: Some("real-sp".into()),
            cloud_image_id: Some("m-win11-golden".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CuaError::InvalidArgument(_)),
        "expected server InvalidArgument (capability check passed), got {err:?}"
    );

    let mut sb_opts = SandboxCreateOptions::new("aliyun-ecs", "windows");
    sb_opts.name = Some("real-sb".into());
    sb_opts.cloud_image_id = Some("m-win11-golden".into());
    sb_opts.instance_type = Some("ecs.c7.2xlarge".into());
    sb_opts.disk_gb = Some(120);
    let Err(sb_err) = w.cua.sandboxes().create(sb_opts).await else {
        panic!("expected ProviderNotConfigured without connected aliyun-ecs");
    };
    assert!(
        matches!(sb_err, CuaError::ProviderNotConfigured(_)),
        "expected ProviderNotConfigured (capability check passed), got {sb_err:?}"
    );

    // 2. Loopback current mock daemon receives all M6a fields over wire.
    let (rec, cua) = current_mock_daemon().await;
    let sp = cua
        .spaces()
        .create(SpaceCreateOptions {
            on: Some("aliyun-ecs".into()),
            image: Some("windows".into()),
            name: Some("sp-ok".into()),
            cloud_image_id: Some("m-win11-golden".into()),
            instance_type: Some("ecs.c7.2xlarge".into()),
            disk_gb: Some(120),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(sp.space.unwrap().id, "aliyun-ecs:sp-ok");
    {
        let creates = rec.creates.lock().unwrap();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].cloud_image_id, "m-win11-golden");
        assert_eq!(creates[0].instance_type, "ecs.c7.2xlarge");
        assert_eq!(creates[0].disk_gb, 120);
    }

    let mut o = SandboxCreateOptions::new("aliyun-ecs", "windows");
    o.name = Some("sb-ok".into());
    o.cloud_image_id = Some("m-win11-golden".into());
    o.instance_type = Some("ecs.c7.2xlarge".into());
    o.disk_gb = Some(120);
    let sb = cua.sandboxes().create(o.clone()).await.unwrap();
    assert_eq!(sb.info().name, "sb-ok");

    let sink: cua_sandbox_core::progress::Sink = Arc::new(|_| {});
    o.name = Some("sb-ok-stream".into());
    let sb_rep = cua.sandboxes().create_reporting(o, sink).await.unwrap();
    assert_eq!(sb_rep.info().name, "sb-ok-stream");

    let sb_creates = rec.sandbox_creates.lock().unwrap();
    assert_eq!(sb_creates.len(), 2);
    for req in sb_creates.iter() {
        assert_eq!(req.cloud_image_id, "m-win11-golden");
        assert_eq!(req.instance_type, "ecs.c7.2xlarge");
        assert_eq!(req.disk_gb, 120);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sandboxes_create_ttl_fails_closed_against_old_m5_and_m6_daemons_and_succeeds_on_current() {
    for (label, old, cua) in [
        ("pre_getinfo", old_daemon().await),
        ("m5", m5_daemon().await),
        ("m6", m6_daemon().await),
    ]
    .into_iter()
    .map(|(l, (o, c))| (l, o, c))
    {
        for ttl in [0u32, 1800u32] {
            let mut opts = SandboxCreateOptions::new("aliyun-ecs", "linux");
            opts.name = Some(format!("sb-ttl-{ttl}"));
            opts.ttl_seconds = Some(ttl);

            let Err(e) = cua.sandboxes().create(opts.clone()).await else {
                panic!("{label}/ttl={ttl}: Sandboxes::create must fail closed");
            };
            assert!(
                matches!(&e, CuaError::CapabilityMissing(m) if m.contains("too old") && m.contains("ttl")),
                "{label}/ttl={ttl}: expected CapabilityMissing naming ttl, got {e:?}"
            );

            let sink: cua_sandbox_core::progress::Sink = Arc::new(|_| {});
            let Err(e_rep) = cua.sandboxes().create_reporting(opts, sink).await else {
                panic!("{label}/ttl={ttl}: Sandboxes::create_reporting must fail closed");
            };
            assert!(
                matches!(&e_rep, CuaError::CapabilityMissing(m) if m.contains("too old") && m.contains("ttl")),
                "{label}/ttl={ttl}: expected CapabilityMissing naming ttl, got {e_rep:?}"
            );
        }
        assert!(
            old.sandbox_creates.lock().unwrap().is_empty(),
            "{label}: CreateSandbox RPC must not be sent when ttl capability is missing"
        );
    }

    // Real current daemon advertises `sandboxes.ttl` and passes client preflight.
    let w = current_daemon().await;
    let mut real_opts = SandboxCreateOptions::new("aliyun-ecs", "linux");
    real_opts.name = Some("sb-real-ttl".into());
    real_opts.ttl_seconds = Some(1800);
    let Err(real_err) = w.cua.sandboxes().create(real_opts).await else {
        panic!("expected ProviderNotConfigured without connected aliyun-ecs");
    };
    assert!(
        matches!(real_err, CuaError::ProviderNotConfigured(_)),
        "expected ProviderNotConfigured (ttl preflight passed), got {real_err:?}"
    );

    // Loopback current mock daemon receives ttl=Some(0s) and ttl=Some(1800s) over both create & create_reporting.
    let (rec, cua) = current_mock_daemon().await;
    for (idx, ttl) in [0u32, 1800u32].into_iter().enumerate() {
        let mut o = SandboxCreateOptions::new("aliyun-ecs", "linux");
        o.name = Some(format!("sb-ttl-ok-{idx}"));
        o.ttl_seconds = Some(ttl);
        let sb = cua.sandboxes().create(o.clone()).await.unwrap();
        assert_eq!(sb.info().name, format!("sb-ttl-ok-{idx}"));

        let sink: cua_sandbox_core::progress::Sink = Arc::new(|_| {});
        o.name = Some(format!("sb-ttl-rep-{idx}"));
        let sb_rep = cua.sandboxes().create_reporting(o, sink).await.unwrap();
        assert_eq!(sb_rep.info().name, format!("sb-ttl-rep-{idx}"));
    }
    let sb_creates = rec.sandbox_creates.lock().unwrap();
    assert_eq!(sb_creates.len(), 4);
    assert_eq!(sb_creates[0].ttl.as_ref().map(|d| d.seconds), Some(0));
    assert_eq!(sb_creates[1].ttl.as_ref().map(|d| d.seconds), Some(0));
    assert_eq!(sb_creates[2].ttl.as_ref().map(|d| d.seconds), Some(1800));
    assert_eq!(sb_creates[3].ttl.as_ref().map(|d| d.seconds), Some(1800));
}

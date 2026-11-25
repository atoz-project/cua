// SPDX-License-Identifier: MIT

use std::collections::BTreeSet;

use aliyun_ecs_byoc_e2e::fake_aliyun::{BootFailMode, FakeImage, FakeSg, FakeVSwitch, FakeVpc};
use aliyun_ecs_byoc_e2e::{AliyunWorld, decode_user_data_scripts, repo_root};
use serde_json::json;

async fn connect_static(w: &AliyunWorld, extra_args: &[&str]) {
    w.relay.add_static_token("static-relay-secret");
    let mut args = vec![
        "cloud",
        "connect",
        "aliyun-ecs",
        "--token-stdin",
        "--relay-url",
        &w.relay.url,
        "--relay-mode",
        "static",
        "--relay-token-stdin",
        "--json",
    ];
    args.extend_from_slice(extra_args);
    let out = w
        .run_with_stdin(&args, "LTAI_TEST_AK:secret123\nstatic-relay-secret\n")
        .await;
    out.ok();
    assert_eq!(out.json()["status"], "connected");
}

fn action_service(version: &str, action: &str) -> String {
    let svc = match version {
        "2015-04-01" => "sts",
        "2016-04-28" => "vpc",
        _ => "ecs",
    };
    format!("{svc}:{action}")
}

fn assert_six_cua_tags(tags: &std::collections::BTreeMap<String, String>) {
    for key in [
        "cua-managed",
        "cua-owner",
        "cua-space",
        "cua-machine",
        "cua-created-by",
        "cua-expires",
    ] {
        assert!(
            tags.get(key).is_some_and(|v| !v.is_empty()),
            "missing required Cua tag {key} in {tags:?}"
        );
    }
    assert_eq!(tags.get("cua-managed").map(String::as_str), Some("true"));
}

#[tokio::test]
async fn t1_f1_01() {
    let w = AliyunWorld::start().await;
    let out = w
        .run_with_stdin(
            &["cloud", "test", "aliyun-ecs", "--token-stdin", "--json"],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    out.ok();
    let v = out.json();
    assert_eq!(v["provider"], "aliyun-ecs");
    assert_eq!(v["ok"], true);
    assert_eq!(v["account"], "123456789012");
    let check_names: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            assert_eq!(c["ok"], true, "check failed: {c}");
            c["name"].as_str().unwrap()
        })
        .collect();
    assert_eq!(
        check_names,
        vec!["credentials", "region", "machine", "image", "permissions"]
    );

    let f = w.aliyun.lock().unwrap();
    assert!(f.instances.is_empty(), "test must create 0 instances");
    let run_call = f
        .calls
        .iter()
        .find(|c| c.action == "RunInstances")
        .expect("RunInstances DryRun must be called");
    assert_eq!(
        run_call.params.get("DryRun").map(String::as_str),
        Some("true")
    );
    drop(f);

    w.assert_no_secrets_anywhere(&["secret123"]);
    w.assert_no_unexpected_egress();
}

#[tokio::test]
async fn t1_f1_02() {
    let w = AliyunWorld::start().await;
    let out = w
        .run_with_stdin(
            &[
                "cloud",
                "connect",
                "aliyun-ecs",
                "--token-stdin",
                "--region",
                "cn-shanghai",
                "--budget",
                "50",
                "--max-size",
                "4x16",
                "--default",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    out.ok();
    let conn = out.json();
    assert_eq!(conn["status"], "connected");
    assert_eq!(conn["provider"]["name"], "aliyun-ecs");
    assert_eq!(conn["provider"]["default"], true);
    assert_eq!(conn["provider"]["ttl_hours"], 8);
    assert_eq!(conn["provider"]["region"], "cn-shanghai");
    assert_eq!(conn["provider"]["budget_usd_month"], 50.0);
    assert_eq!(conn["provider"]["max_size"], "4x16");

    let st_out = w.run(&["cloud", "status", "aliyun-ecs", "--json"]).await;
    st_out.ok();
    let st = st_out.json();
    assert_eq!(st["default_on"], "aliyun-ecs");
    let prov = &st["providers"][0];
    assert_eq!(prov["connected"], true);
    assert_eq!(prov["credentials"]["found"], true);

    let kinds = prov["kinds"].as_array().unwrap();
    let find_kind = |img: &str| kinds.iter().find(|k| k["image"] == img).unwrap();
    assert_eq!(find_kind("linux")["supported"], true);
    assert_eq!(find_kind("linux")["machine_type"], "ecs.e-c1m2.large");
    assert_eq!(find_kind("linux")["usd_per_hour"], 0.043);
    assert_eq!(find_kind("linux-slim")["supported"], true);
    assert_eq!(find_kind("linux-slim")["machine_type"], "ecs.e-c1m1.large");
    assert_eq!(find_kind("linux-slim")["usd_per_hour"], 0.03);
    assert_eq!(find_kind("windows")["supported"], true);
    assert_eq!(find_kind("windows")["machine_type"], "ecs.c7.xlarge");
    assert_eq!(find_kind("windows")["usd_per_hour"], 0.125);
    assert_eq!(find_kind("omarchy")["supported"], false);
    assert_eq!(find_kind("macos")["supported"], false);

    w.assert_no_secrets_in_non_secret_files(&["secret123"]);
    w.assert_no_unexpected_egress();
}

#[tokio::test]
async fn t1_f1_03() {
    let mut w = AliyunWorld::start().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.add_key("LTAI_CUR_AK", "cur_secret_123");
        f.add_key("LTAI_WH_AK", "wh_secret_456");
        f.add_key("LTAI_SAVED_AK", "saved_secret_789");
        f.add_key("LTAI_ENV_AK", "env_secret_abc");
        f.add_key("LTAI_STDIN_AK", "stdin_secret_xyz");
    }
    w.write_aliyun_config(&json!({
        "current": "oauth",
        "profiles": [
            {
                "name": "oauth",
                "mode": "AK",
                "access_key_id": "LTAI_CUR_AK",
                "access_key_secret": "cur_secret_123",
                "region_id": "cn-shanghai"
            },
            {
                "name": "webhook_manager",
                "mode": "AK",
                "access_key_id": "LTAI_WH_AK",
                "access_key_secret": "wh_secret_456",
                "region_id": "ap-southeast-1"
            }
        ]
    }));

    w.run(&["cloud", "test", "aliyun-ecs", "--json"]).await.ok();
    {
        let f = w.aliyun.lock().unwrap();
        let last = f.calls.last().unwrap();
        assert_eq!(last.access_key_id, "LTAI_CUR_AK");
        assert!(
            f.calls_for("DescribeRegions")
                .last()
                .unwrap()
                .host
                .starts_with("ecs.cn-shanghai.aliyuncs.com")
        );
    }

    w.aliyun.lock().unwrap().calls.clear();
    w.run(&[
        "cloud",
        "test",
        "aliyun-ecs",
        "--region",
        "cn-beijing",
        "--json",
    ])
    .await
    .ok();
    {
        let f = w.aliyun.lock().unwrap();
        assert!(
            f.calls_for("DescribeRegions")
                .last()
                .unwrap()
                .host
                .starts_with("ecs.cn-beijing.aliyuncs.com")
        );
    }

    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_SAVED_AK:saved_secret_789\n",
    )
    .await
    .ok();
    w.aliyun.lock().unwrap().calls.clear();
    w.run(&["cloud", "test", "aliyun-ecs", "--json"]).await.ok();
    assert_eq!(
        w.aliyun.lock().unwrap().calls.last().unwrap().access_key_id,
        "LTAI_SAVED_AK"
    );

    w.aliyun.lock().unwrap().calls.clear();
    w.run(&[
        "cloud",
        "test",
        "aliyun-ecs",
        "--profile",
        "webhook_manager",
        "--json",
    ])
    .await
    .ok();
    {
        let f = w.aliyun.lock().unwrap();
        assert_eq!(f.calls.last().unwrap().access_key_id, "LTAI_WH_AK");
        assert!(
            f.calls_for("DescribeRegions")
                .last()
                .unwrap()
                .host
                .starts_with("ecs.ap-southeast-1.aliyuncs.com")
        );
    }

    w.set_env("ALIBABA_CLOUD_ACCESS_KEY_ID", "LTAI_ENV_AK");
    w.set_env("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "env_secret_abc");
    w.aliyun.lock().unwrap().calls.clear();
    w.run(&[
        "cloud",
        "test",
        "aliyun-ecs",
        "--profile",
        "webhook_manager",
        "--json",
    ])
    .await
    .ok();
    assert_eq!(
        w.aliyun.lock().unwrap().calls.last().unwrap().access_key_id,
        "LTAI_ENV_AK"
    );

    w.aliyun.lock().unwrap().calls.clear();
    w.run_with_stdin(
        &[
            "cloud",
            "test",
            "aliyun-ecs",
            "--profile",
            "webhook_manager",
            "--token-stdin",
            "--json",
        ],
        "LTAI_STDIN_AK:stdin_secret_xyz\n",
    )
    .await
    .ok();
    assert_eq!(
        w.aliyun.lock().unwrap().calls.last().unwrap().access_key_id,
        "LTAI_STDIN_AK"
    );
    w.assert_no_unexpected_egress();
}

#[tokio::test]
async fn t1_f1_04() {
    let w = AliyunWorld::start().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    let disc = w
        .run(&["cloud", "disconnect", "aliyun-ecs", "--json"])
        .await;
    disc.ok();
    let dv = disc.json();
    assert_eq!(dv["provider"], "aliyun-ecs");
    assert_eq!(dv["disconnected"], true);
    assert_eq!(dv["deleted"], json!([]));
    assert_eq!(dv["left"], json!([]));

    w.assert_no_secrets_anywhere(&["secret123"]);

    let st = w.run(&["cloud", "status", "aliyun-ecs", "--json"]).await;
    st.ok();
    let sv = st.json();
    assert_eq!(sv["providers"][0]["connected"], false);
    assert_eq!(sv["providers"][0]["credentials"]["found"], false);
    w.assert_no_unexpected_egress();
}

#[tokio::test]
async fn t1_f1_05() {
    let w = AliyunWorld::start().await;
    w.aliyun.lock().unwrap().throttle = 2;
    let out = w
        .run_with_stdin(
            &["cloud", "test", "aliyun-ecs", "--token-stdin", "--json"],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    out.ok();
    assert_eq!(out.json()["ok"], true);
    assert_eq!(w.aliyun.lock().unwrap().throttle, 0);
    w.assert_no_unexpected_egress();
}

#[tokio::test]
async fn t1_f2_01() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.set_env("CUA_RELAY_URL", "http://127.0.0.1:9");

    let conn = w
        .run_with_stdin(
            &[
                "cloud",
                "connect",
                "aliyun-ecs",
                "--token-stdin",
                "--relay-url",
                &w.relay.url,
                "--relay-mode",
                "account",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    conn.ok();
    assert_eq!(conn.json()["status"], "connected");

    let sb = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--name",
            "acct-box",
            "--json",
        ])
        .await;
    sb.ok();
    assert!(
        w.relay.register_calls() >= 1,
        "expected account mode registration on custom relay"
    );
    w.assert_no_unexpected_egress();
}

#[tokio::test]
async fn t1_f2_02() {
    let w = AliyunWorld::start().await;
    assert!(!w.cua_home().join("credentials.json").exists());
    connect_static(&w, &[]).await;
    w.assert_no_secrets_in_non_secret_files(&["secret123", "static-relay-secret"]);

    let sb = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--name",
            "static-box",
            "--json",
        ])
        .await;
    sb.ok();
    let machines = w.relay.static_machines();
    assert_eq!(machines.len(), 1);
    assert!(!machines[0].env_token.is_empty());
    w.assert_no_secrets_in_non_secret_files(&["secret123", "static-relay-secret"]);
    for rel in [
        "cloud/state.json",
        "cloud/links.json",
        "cloud/audit.jsonl",
        "config.toml",
    ] {
        let p = w.cua_home().join(rel);
        if let Ok(text) = std::fs::read_to_string(&p) {
            assert!(
                !text.contains(&machines[0].env_token),
                "env_token leaked into {rel}: {text}"
            );
        }
    }
}

#[tokio::test]
async fn t1_f2_03() {
    let w = AliyunWorld::start().await;
    connect_static(&w, &[]).await;

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "static-ops",
        "--json",
    ])
    .await
    .ok();
    let machine = w.relay.static_machines().into_iter().next().unwrap();

    let exec_out = w
        .run(&["sb", "exec", "static-ops", "echo", "hello-static"])
        .await;
    exec_out.ok();
    assert!(
        exec_out.stdout.contains("hello-static"),
        "{}",
        exec_out.stdout
    );

    let shot_path = w.dir.path().join("shot.png");
    w.run(&[
        "sb",
        "screenshot",
        "static-ops",
        "-o",
        shot_path.to_str().unwrap(),
    ])
    .await
    .ok();
    assert!(shot_path.exists());

    let proxied = w.relay.proxied();
    assert!(
        proxied
            .iter()
            .any(|(p, _)| p.starts_with(&format!("/m/{}", machine.id))),
        "expected static relay proxy requests for machine {}: {proxied:?}",
        machine.id
    );

    w.run(&["sb", "suspend", "static-ops"]).await.ok();
    w.run(&["sb", "resume", "static-ops"]).await.ok();
    w.run(&["sb", "rm", "static-ops", "--force"]).await.ok();
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

#[tokio::test]
async fn t1_f2_04() {
    let w = AliyunWorld::start().await;
    connect_static(&w, &[]).await;

    let sp = w
        .run(&[
            "spaces",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--name",
            "static-sp",
            "--json",
        ])
        .await;
    sp.ok();
    let ls = w.run(&["spaces", "ls", "--json"]).await;
    ls.ok();
    assert!(ls.stdout.contains("aliyun-ecs"), "{}", ls.stdout);

    w.run(&["spaces", "delete", "static-sp", "--force"])
        .await
        .ok();
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

#[tokio::test]
async fn t1_f2_05() {
    let w = AliyunWorld::start().await;
    connect_static(&w, &[]).await;
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--json"])
        .await
        .ok();
    w.assert_no_secrets_anywhere(&["secret123", "static-relay-secret"]);
}

#[tokio::test]
async fn t1_f3_01() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "docker-def",
        "--json",
    ])
    .await
    .ok();

    let f = w.aliyun.lock().unwrap();
    assert_eq!(f.instances.len(), 1);
    let inst = f.instances.values().next().unwrap();
    assert_eq!(inst.instance_type, "ecs.e-c1m2.large");
    assert_eq!(inst.system_disk_category.as_deref(), Some("cloud_essd"));
    assert_eq!(inst.system_disk_size.as_deref(), Some("40"));
    assert!(inst.image_id.contains("ubuntu_24_04"));
    assert_eq!(inst.instance_charge_type, "PostPaid");
    assert_eq!(inst.stopped_mode, "StopCharging");
    assert!(inst.auto_release_time.is_some());
    assert_eq!(inst.http_tokens.as_deref(), Some("required"));
    assert!(inst.key_pair_name.is_none());
    assert!(inst.ram_role_name.is_none());
    assert_six_cua_tags(&inst.tags);
}

#[tokio::test]
async fn t1_f3_02() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "box-1",
        "--json",
    ])
    .await
    .ok();
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "box-2",
        "--json",
    ])
    .await
    .ok();

    let f = w.aliyun.lock().unwrap();
    assert_eq!(
        f.calls_for("CreateVpc")
            .iter()
            .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
            .count(),
        1
    );
    assert_eq!(f.vpcs.len(), 1);
    assert_eq!(
        f.calls_for("CreateSecurityGroup")
            .iter()
            .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
            .count(),
        1
    );
    assert_eq!(f.authorize_sg_calls, 0);
    let vpc = f.vpcs.values().next().unwrap();
    assert!(vpc.vpc_name.starts_with("cua-sb-"));
    let sg = f.security_groups.values().next().unwrap();
    assert!(sg.sg_name.starts_with("cua-sandboxes-"));
    assert_eq!(f.instances.len(), 2);
    for inst in f.instances.values() {
        assert_ne!(inst.internet_max_bandwidth_out.as_deref(), Some("0"));
    }
}

#[tokio::test]
async fn t1_f3_03() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "ud-check",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let inst = f.instances.values().next().unwrap();
    let ud_raw = &inst.user_data_decoded;
    let ud = decode_user_data_scripts(ud_raw);
    assert!(ud_raw.starts_with("#cloud-config"), "{ud_raw}");
    assert!(ud.contains("docker"), "{ud}");
    assert!(ud.contains("100.100.100.200"), "{ud}");
    assert!(ud.contains("cua-spacesd"), "{ud}");
    assert!(
        !ud_raw.contains("secret123") && !ud.contains("secret123"),
        "AK secret must never appear in UserData"
    );
}

#[tokio::test]
async fn t1_f3_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.aliyun
        .lock()
        .unwrap()
        .mark_zone_run_fail("cn-hangzhou-h", "OperationDenied.NoStock");
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "zone-retry",
        "--json",
    ])
    .await
    .ok();

    let f = w.aliyun.lock().unwrap();
    let run_calls: Vec<_> = f
        .calls_for("RunInstances")
        .into_iter()
        .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
        .collect();
    assert!(run_calls.len() >= 2, "expected cross-zone retry");
    let tokens: BTreeSet<_> = run_calls
        .iter()
        .filter_map(|c| c.params.get("ClientToken"))
        .filter(|t| !t.is_empty())
        .collect();
    assert_eq!(tokens.len(), run_calls.len());
    let inst = f.instances.values().next().unwrap();
    assert!(
        inst.client_token.as_deref().is_some_and(|t| !t.is_empty()),
        "expected non-empty ClientToken on created instance"
    );
    assert_ne!(inst.zone_id, "cn-hangzhou-h");
}

#[tokio::test]
async fn t1_f3_05() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "life-box",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "suspend", "life-box"]).await.ok();
    assert_eq!(
        w.aliyun
            .lock()
            .unwrap()
            .instances
            .values()
            .next()
            .unwrap()
            .status,
        "Stopped"
    );
    w.run(&["sb", "resume", "life-box"]).await.ok();
    assert_eq!(
        w.aliyun
            .lock()
            .unwrap()
            .instances
            .values()
            .next()
            .unwrap()
            .status,
        "Running"
    );
    w.run(&["sb", "rm", "life-box", "--force"]).await.ok();
    assert!(w.aliyun.lock().unwrap().instances.is_empty());

    let dry_default = w.run(&["cloud", "sweep", "aliyun-ecs", "--json"]).await;
    dry_default.ok();
    assert_eq!(dry_default.json()["dry_run"], true);
    let dry_all = w
        .run(&["cloud", "sweep", "aliyun-ecs", "--all", "--json"])
        .await;
    dry_all.ok();
    assert_eq!(dry_all.json()["dry_run"], true);
    {
        let f = w.aliyun.lock().unwrap();
        assert!(!f.vpcs.is_empty(), "dry-run sweep must not delete VPC");
        assert!(
            !f.security_groups.is_empty(),
            "dry-run sweep must not delete SG"
        );
    }

    w.run(&[
        "cloud",
        "sweep",
        "aliyun-ecs",
        "--all",
        "--delete",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    assert!(f.vpcs.is_empty());
    assert!(f.vswitches.is_empty());
    assert!(f.security_groups.is_empty());
}

#[tokio::test]
async fn t1_f4_01() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    let out = w
        .run(&[
            "sb",
            "create",
            "windows",
            "--on",
            "aliyun-ecs",
            "--name",
            "win-def",
            "--json",
        ])
        .await;
    out.ok();
    assert_eq!(out.json()["runtime"], "native");

    let f = w.aliyun.lock().unwrap();
    let inst = f.instances.values().next().unwrap();
    assert!(
        inst.image_id.contains("win2022") || inst.image_id.contains("win2025"),
        "expected official Windows Server image from DescribeImages, got: {}",
        inst.image_id
    );
    assert_eq!(inst.instance_type, "ecs.c7.xlarge");
    assert_eq!(inst.system_disk_size.as_deref(), Some("60"));
    assert_eq!(inst.system_disk_category.as_deref(), Some("cloud_essd"));
    assert_eq!(inst.instance_charge_type, "PostPaid");
    assert_eq!(inst.stopped_mode, "StopCharging");
    assert_eq!(inst.http_tokens.as_deref(), Some("optional"));
    assert_six_cua_tags(&inst.tags);
}

#[tokio::test]
async fn t1_f4_02() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "win-acl",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let ud = &f.instances.values().next().unwrap().user_data_decoded;
    assert!(ud.starts_with("[powershell]\n"), "{ud}");
    assert!(ud.contains("Is64BitOperatingSystem"), "{ud}");
    assert!(
        ud.contains(r"Sysnative\WindowsPowerShell\v1.0\powershell.exe"),
        "{ud}"
    );
    assert!(ud.contains("icacls"), "{ud}");
    assert!(ud.contains("Remove-Item"), "{ud}");
    assert!(ud.contains("cua-spacesd.exe"), "{ud}");
}

#[tokio::test]
async fn t1_f4_03() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "win-sess",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let raw_ud = &f.instances.values().next().unwrap().user_data_decoded;
    assert!(raw_ud.starts_with("[powershell]\n"), "{raw_ud}");
    let ud = decode_user_data_scripts(raw_ud);
    assert!(ud.contains("AutoAdminLogon"), "{ud}");
    assert!(ud.contains("Interactive"), "{ud}");
    assert!(!ud.contains("100.100.100.200"), "{ud}");
    assert!(!ud.contains("New-NetFirewallRule"), "{ud}");
    assert!(
        ud.contains("S-1-5-21-*-500") && ud.contains("/active:yes /Y"),
        "{ud}"
    );
    assert!(
        ud.contains("POST_Main") && ud.contains("reboot-wait.ps1"),
        "{ud}"
    );
    assert!(
        ud.contains("tscon.exe") && ud.contains("/dest:console"),
        "{ud}"
    );
    assert!(
        ud.contains("LocalSessionManager/Operational") && ud.contains("24"),
        "{ud}"
    );
}

#[tokio::test]
async fn t1_f4_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    let mirror_url = w.mirror.windows_url();
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--spacesd-download-url",
            &mirror_url,
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "win-mir",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let ud = &f.instances.values().next().unwrap().user_data_decoded;
    assert!(ud.contains(&mirror_url), "{ud}");
    assert!(ud.contains("Get-FileHash") || ud.contains("SHA256"), "{ud}");
}

#[tokio::test]
async fn t1_f4_05() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "win-acct",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "exec", "win-acct", "echo", "win-ok"])
        .await
        .ok();
    w.run(&["sb", "suspend", "win-acct"]).await.ok();
    w.run(&["sb", "resume", "win-acct"]).await.ok();
    w.run(&["sb", "rm", "win-acct", "--force"]).await.ok();

    let w_static = AliyunWorld::start().await;
    connect_static(&w_static, &[]).await;
    w_static
        .run(&[
            "sb",
            "create",
            "windows",
            "--on",
            "aliyun-ecs",
            "--name",
            "win-st",
            "--json",
        ])
        .await
        .ok();
    w_static
        .run(&["sb", "exec", "win-st", "echo", "win-static-ok"])
        .await
        .ok();
    w_static.run(&["sb", "rm", "win-st", "--force"]).await.ok();
}

fn seed_user_vpc(w: &AliyunWorld, region: &str) {
    let mut f = w.aliyun.lock().unwrap();
    f.seed_vpc(FakeVpc {
        vpc_id: "vpc-user-1".into(),
        region_id: region.into(),
        cidr_block: "10.10.0.0/16".into(),
        vpc_name: "user-vpc".into(),
        is_user_owned: true,
        ..Default::default()
    });
    f.seed_vswitch(FakeVSwitch {
        vswitch_id: "vsw-user-1".into(),
        vpc_id: "vpc-user-1".into(),
        zone_id: format!("{region}-h"),
        region_id: region.into(),
        cidr_block: "10.10.1.0/24".into(),
        vswitch_name: "user-vsw".into(),
        is_user_owned: true,
        ..Default::default()
    });
    f.seed_sg(FakeSg {
        sg_id: "sg-user-1".into(),
        vpc_id: "vpc-user-1".into(),
        region_id: region.into(),
        sg_name: "user-sg".into(),
        ingress_rules: vec![json!({"PortRange": "22/22"})],
        is_user_owned: true,
        ..Default::default()
    });
}

#[tokio::test]
async fn t1_f5_01() {
    let w = AliyunWorld::start().await;
    seed_user_vpc(&w, "cn-hangzhou");
    let out = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--token-stdin",
                "--vpc-id",
                "vpc-user-1",
                "--vswitch-id",
                "vsw-user-1",
                "--no-public-ip",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    out.ok();
    assert_eq!(out.json()["ok"], true);
    let f = w.aliyun.lock().unwrap();
    assert_eq!(f.count_calls("CreateVpc"), 0);
    assert_eq!(f.count_calls("CreateVSwitch"), 0);
    assert_eq!(
        f.calls_for("CreateSecurityGroup")
            .iter()
            .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
            .count(),
        0
    );
    assert!(f.security_groups.contains_key("sg-user-1"));
    assert_eq!(f.security_groups.len(), 1);
}

#[tokio::test]
async fn t1_f5_02() {
    let mut w = AliyunWorld::start().await;
    seed_user_vpc(&w, "cn-hangzhou");
    w.auth_login().await;
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--vpc-id",
            "vpc-user-1",
            "--vswitch-id",
            "vsw-user-1",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "existing-vpc-box",
        "--json",
    ])
    .await
    .ok();

    let f = w.aliyun.lock().unwrap();
    assert_eq!(f.count_calls("CreateVpc"), 0);
    assert_eq!(f.count_calls("CreateVSwitch"), 0);
    assert_eq!(
        f.calls_for("CreateSecurityGroup")
            .iter()
            .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
            .count(),
        1
    );
    assert_eq!(f.security_groups.len(), 2);
    assert_eq!(f.authorize_sg_calls, 0);
    let inst = f.instances.values().next().unwrap();
    assert_eq!(inst.vpc_id, "vpc-user-1");
    assert_eq!(inst.vswitch_id, "vsw-user-1");
    assert_ne!(inst.security_group_id, "sg-user-1");
}

#[tokio::test]
async fn t1_f5_03() {
    let w = AliyunWorld::start().await;
    seed_user_vpc(&w, "cn-hangzhou");
    connect_static(
        &w,
        &[
            "--vpc-id",
            "vpc-user-1",
            "--vswitch-id",
            "vsw-user-1",
            "--no-public-ip",
        ],
    )
    .await;

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "no-pub-ip",
        "--json",
    ])
    .await
    .ok();

    {
        let f = w.aliyun.lock().unwrap();
        let inst = f.instances.values().next().unwrap();
        assert_eq!(inst.internet_max_bandwidth_out.as_deref(), Some("0"));
    }

    let ex = w
        .run(&["sb", "exec", "no-pub-ip", "echo", "intranet-ok"])
        .await;
    ex.ok();
    assert!(ex.stdout.contains("intranet-ok"));
}

#[tokio::test]
async fn t1_f5_04() {
    let mut w = AliyunWorld::start().await;
    seed_user_vpc(&w, "cn-hangzhou");
    w.auth_login().await;
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--vpc-id",
            "vpc-user-1",
            "--vswitch-id",
            "vsw-user-1",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "sweep-keep",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "rm", "sweep-keep", "--force"]).await.ok();

    w.run(&[
        "cloud",
        "sweep",
        "aliyun-ecs",
        "--all",
        "--delete",
        "--json",
    ])
    .await
    .ok();

    let f = w.aliyun.lock().unwrap();
    assert_eq!(f.count_calls("DeleteVpc"), 0);
    assert_eq!(f.count_calls("DeleteVSwitch"), 0);
    assert!(f.vpcs.contains_key("vpc-user-1"));
    assert!(f.vswitches.contains_key("vsw-user-1"));
    assert!(f.security_groups.contains_key("sg-user-1"));
    assert_eq!(f.security_groups.len(), 1);
}

#[tokio::test]
async fn t1_f5_05() {
    let mut w = AliyunWorld::start().await;
    seed_user_vpc(&w, "cn-hangzhou");
    w.auth_login().await;
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--vpc-id",
            "vpc-user-1",
            "--vswitch-id",
            "vsw-user-1",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "disc-keep",
        "--json",
    ])
    .await
    .ok();

    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();

    let f = w.aliyun.lock().unwrap();
    assert!(f.instances.is_empty());
    assert!(f.vpcs.contains_key("vpc-user-1"));
    assert!(f.vswitches.contains_key("vsw-user-1"));
    assert!(f.security_groups.contains_key("sg-user-1"));
}

fn seed_custom_images(w: &AliyunWorld) {
    let mut f = w.aliyun.lock().unwrap();
    for (id, os) in [
        ("m-win-default", "windows"),
        ("m-linux-default", "linux"),
        ("m-win-override", "windows"),
        ("m-linux-override", "linux"),
        ("m-custom", "linux"),
    ] {
        f.add_image(FakeImage {
            image_id: id.into(),
            image_name: id.into(),
            os_type: os.into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "self".into(),
            region_id: "cn-hangzhou".into(),
            ..Default::default()
        });
    }
}

#[tokio::test]
async fn t1_f6_01() {
    let w = AliyunWorld::start().await;
    seed_custom_images(&w);
    let out = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--token-stdin",
                "--windows-image-id",
                "m-win-default",
                "--linux-image-id",
                "m-linux-default",
                "--instance-type",
                "ecs.g7.large",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    out.ok();
    assert_eq!(out.json()["ok"], true);

    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--windows-image-id",
            "m-win-default",
            "--linux-image-id",
            "m-linux-default",
            "--instance-type",
            "ecs.g7.large",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
}

#[tokio::test]
async fn t1_f6_02() {
    let mut w = AliyunWorld::start().await;
    seed_custom_images(&w);
    w.auth_login().await;
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--windows-image-id",
            "m-win-default",
            "--linux-image-id",
            "m-linux-default",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "l-def",
        "--json",
    ])
    .await
    .ok();
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "l-ov",
        "--cloud-image-id",
        "m-linux-override",
        "--json",
    ])
    .await
    .ok();
    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "w-def",
        "--json",
    ])
    .await
    .ok();
    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "w-ov",
        "--cloud-image-id",
        "m-win-override",
        "--json",
    ])
    .await
    .ok();

    let f = w.aliyun.lock().unwrap();
    let img_of = |name: &str| {
        f.instances
            .values()
            .find(|i| {
                i.tags.get("cua-space").is_some_and(|s| s == name) || i.instance_name.contains(name)
            })
            .unwrap_or_else(|| {
                panic!(
                    "instance for {name} not found in {:?}",
                    f.instances
                        .values()
                        .map(|i| (&i.instance_name, &i.tags))
                        .collect::<Vec<_>>()
                )
            })
            .image_id
            .clone()
    };
    assert_eq!(img_of("l-def"), "m-linux-default");
    assert_eq!(img_of("l-ov"), "m-linux-override");
    assert_eq!(img_of("w-def"), "m-win-default");
    assert_eq!(img_of("w-ov"), "m-win-override");
}

#[tokio::test]
async fn t1_f6_03() {
    let mut w = AliyunWorld::start().await;
    seed_custom_images(&w);
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "spaces",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "sp-custom-img",
        "--cloud-image-id",
        "m-custom",
        "--json",
    ])
    .await
    .ok();
    assert_eq!(
        w.aliyun
            .lock()
            .unwrap()
            .instances
            .values()
            .next()
            .unwrap()
            .image_id,
        "m-custom"
    );

    let (daemon_url, daemon_tok) = w.start_daemon().await;
    let sdk = cua_sdk::Cua::connect(Some(daemon_url), Some(daemon_tok)).expect("sdk connect");
    let tool_res = sdk
        .spaces()
        .call_tool_json(
            "create_space".into(),
            Some(
                json!({
                    "image": "linux",
                    "on": "aliyun-ecs",
                    "name": "sdk-custom-img",
                    "cloud_image_id": "m-linux-override"
                })
                .to_string(),
            ),
        )
        .await
        .expect("create_space tool");
    assert!(
        !tool_res.content_json.contains("error"),
        "{}",
        tool_res.content_json
    );
    assert!(
        w.aliyun
            .lock()
            .unwrap()
            .instances
            .values()
            .any(|i| i.image_id == "m-linux-override")
    );
}

#[tokio::test]
async fn t1_f6_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--budget",
            "100",
            "--max-size",
            "4x16",
            "--instance-type",
            "ecs.g7.large",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "custom-size",
        "--json",
    ])
    .await
    .ok();

    w.run(&[
        "spaces",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "custom-disk",
        "--disk-gb",
        "80",
        "--json",
    ])
    .await
    .ok();

    let f = w.aliyun.lock().unwrap();
    let sb_inst = f
        .instances
        .values()
        .find(|i| {
            i.tags.get("cua-space").is_some_and(|s| s == "custom-size")
                || i.instance_name.contains("custom-size")
        })
        .expect("custom-size instance");
    assert_eq!(sb_inst.instance_type, "ecs.g7.large");

    let sp_inst = f
        .instances
        .values()
        .find(|i| {
            i.tags.get("cua-space").is_some_and(|s| s == "custom-disk")
                || i.instance_name.contains("custom-disk")
        })
        .expect("custom-disk instance");
    assert_eq!(sp_inst.instance_type, "ecs.g7.large");
    assert_eq!(sp_inst.system_disk_size.as_deref(), Some("80"));
}

#[tokio::test]
async fn t1_f6_05() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux-slim",
        "--on",
        "aliyun-ecs",
        "--name",
        "slim-def",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let inst = f.instances.values().next().unwrap();
    assert_eq!(inst.instance_type, "ecs.e-c1m1.large");
    assert_eq!(inst.system_disk_size.as_deref(), Some("40"));
    assert!(inst.image_id.contains("ubuntu_24_04"));
}

#[tokio::test]
async fn t1_f7_01() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    let out = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "native",
            "--name",
            "linux-nat",
            "--json",
        ])
        .await;
    out.ok();
    assert_eq!(out.json()["runtime"], "native");

    let f = w.aliyun.lock().unwrap();
    let ud_raw = &f.instances.values().next().unwrap().user_data_decoded;
    let ud = decode_user_data_scripts(ud_raw);
    assert!(ud_raw.starts_with("#cloud-config"), "{ud_raw}");
    assert!(
        !ud.contains("docker.io") && !ud.contains("docker run"),
        "{ud}"
    );
    assert!(ud.contains("cua-spacesd") && ud.contains("systemd"), "{ud}");
}

#[tokio::test]
async fn t1_f7_02() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    let mirror_url = w.mirror.linux_url();
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--spacesd-download-url",
            &mirror_url,
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--runtime",
        "native",
        "--name",
        "linux-mir",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let ud = decode_user_data_scripts(&f.instances.values().next().unwrap().user_data_decoded);
    assert!(ud.contains(&mirror_url), "{ud}");
    assert!(ud.contains("sha256sum"), "{ud}");
    assert!(
        ud.contains("command -v cua-spacesd") || ud.contains("/usr/local/bin/cua-spacesd"),
        "{ud}"
    );
}

#[tokio::test]
async fn t1_f7_03() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--runtime",
        "native",
        "--name",
        "linux-headless",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let ud = decode_user_data_scripts(&f.instances.values().next().unwrap().user_data_decoded);
    assert!(
        !ud.contains("apt-get install -y xfce") && !ud.contains("xvfb"),
        "{ud}"
    );
    assert!(
        ud.contains("cua-spacesd join") || ud.contains("cua-spacesd"),
        "{ud}"
    );
}

#[tokio::test]
async fn t1_f7_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--runtime",
        "native",
        "--name",
        "linux-sec",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let inst = f.instances.values().next().unwrap();
    let ud_raw = &inst.user_data_decoded;
    let ud = decode_user_data_scripts(ud_raw);
    assert!(
        ud.contains("100.100.100.200"),
        "decoded cloud-init must block metadata IP 100.100.100.200: {ud}"
    );
    assert!(
        (ud.contains("cua-expire") && (ud.contains("Timer") || ud.contains("timer")))
            || inst.auto_release_time.is_some(),
        "expected TTL timer or AutoReleaseTime: {ud}"
    );
    assert!(
        ud.contains("cua-spacesd") && (ud.contains("systemd") || ud.contains("[Service]")),
        "expected systemd cua-spacesd unit in decoded cloud-init: {ud}"
    );
    assert!(!ud_raw.contains("secret123"));
    assert_eq!(inst.http_tokens.as_deref(), Some("required"));
    assert!(inst.key_pair_name.is_none());
    assert!(inst.ram_role_name.is_none());
    assert_eq!(inst.instance_charge_type, "PostPaid");
    assert_eq!(inst.stopped_mode, "StopCharging");
    assert_six_cua_tags(&inst.tags);
}

#[tokio::test]
async fn t1_f7_05() {
    let mut w_acct = AliyunWorld::start().await;
    w_acct.auth_login().await;
    w_acct
        .run_with_stdin(
            &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
            "LTAI_TEST_AK:secret123\n",
        )
        .await
        .ok();
    w_acct
        .run(&[
            "sb",
            "create",
            "linux-slim",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "native",
            "--name",
            "slim-nat-acct",
            "--json",
        ])
        .await
        .ok();
    w_acct
        .run(&["sb", "exec", "slim-nat-acct", "echo", "acct-nat-ok"])
        .await
        .ok();
    w_acct.run(&["sb", "suspend", "slim-nat-acct"]).await.ok();
    w_acct.run(&["sb", "resume", "slim-nat-acct"]).await.ok();
    w_acct
        .run(&["sb", "rm", "slim-nat-acct", "--force"])
        .await
        .ok();

    let w_static = AliyunWorld::start().await;
    connect_static(&w_static, &[]).await;
    w_static
        .run(&[
            "sb",
            "create",
            "linux-slim",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "native",
            "--name",
            "slim-nat-st",
            "--json",
        ])
        .await
        .ok();
    w_static
        .run(&["sb", "exec", "slim-nat-st", "echo", "st-nat-ok"])
        .await
        .ok();
    w_static
        .run(&["sb", "rm", "slim-nat-st", "--force"])
        .await
        .ok();
}

#[tokio::test]
async fn t1_f8_01() {
    let policy_path = repo_root().join("libs/cua/crates/cua-byoc/policy/aliyun-ecs-policy.json");
    let raw = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", policy_path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid policy JSON");
    let stmts = doc["Statement"].as_array().expect("Statement array");
    assert!(!stmts.is_empty());

    let as_strs = |v: &serde_json::Value| -> Vec<String> {
        match v {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(a) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            _ => vec![],
        }
    };

    const MUTATING_VERBS: &[&str] = &[
        "Run",
        "Create",
        "Delete",
        "Terminate",
        "Stop",
        "Start",
        "Authorize",
        "Revoke",
        "Modify",
        "Attach",
        "Detach",
        "Associate",
        "Disassociate",
        "Tag",
        "Allocate",
        "Release",
    ];
    const RUN_REF_ONLY: &[&str] = &[
        "image/",
        "vswitch/",
        "vpc/",
        "networkinterface/",
        "eni/",
        "securitygroup/",
        "security-group/",
        "snapshot/",
    ];

    for stmt in stmts {
        let effect = stmt["Effect"].as_str().unwrap_or("");
        assert!(
            matches!(effect, "Allow" | "Deny"),
            "unexpected Effect {effect:?} in {stmt}"
        );
        assert!(stmt.get("NotAction").is_none() && stmt.get("NotResource").is_none());

        let actions = as_strs(&stmt["Action"]);
        assert!(!actions.is_empty(), "statement missing Action: {stmt}");
        let resources = as_strs(&stmt["Resource"]);
        assert!(!resources.is_empty(), "statement missing Resource: {stmt}");

        for act in &actions {
            assert!(
                !act.ends_with(":*") && *act != "*",
                "wildcard action forbidden: {act}"
            );
            assert!(!act.starts_with("ram:"), "ram:* action forbidden: {act}");
        }

        if effect != "Allow" {
            continue;
        }

        let has_mutating = actions.iter().any(|act| {
            let op = act.split(':').nth(1).unwrap_or("");
            MUTATING_VERBS.iter().any(|v| op.starts_with(v))
        });
        if !has_mutating {
            continue;
        }

        let cond_str = stmt["Condition"].to_string();
        if cond_str.contains("cua-managed") {
            continue;
        }

        // Permit untagged resource-reference statements only for RunInstances (non-instance/disk
        // reference resources like image/*, vswitch/*, vpc/*, securitygroup/*) and
        // CreateSecurityGroup (vpc/*), mirroring aws-policy.json / policy.rs.
        let reference_only = actions.iter().all(|act| match act.as_str() {
            "ecs:RunInstances" => resources
                .iter()
                .all(|r| RUN_REF_ONLY.iter().any(|u| r.contains(u))),
            "ecs:CreateSecurityGroup" => resources.iter().all(|r| r.contains("vpc/")),
            _ => false,
        });
        assert!(
            reference_only,
            "mutating Allow statement must require cua-managed tag Condition (or be an untagged RunInstances/CreateSecurityGroup reference statement): {stmt}"
        );
    }
}

#[tokio::test]
async fn t1_f8_02() {
    let repo = repo_root();
    let policy_path = repo.join("libs/cua/crates/cua-byoc/policy/aliyun-ecs-policy.json");
    let safety_path = repo.join("docs/content/docs/cua-sdk/guides/your-cloud-safety.mdx");
    let policy = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", policy_path.display()));
    let safety = std::fs::read_to_string(&safety_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", safety_path.display()));

    assert!(
        safety.contains(policy.trim()),
        "your-cloud-safety.mdx must embed aliyun-ecs-policy.json verbatim"
    );
    assert!(
        safety.contains("100.100.100.200"),
        "safety doc must explain IMDS block"
    );
    assert!(
        safety.contains("cua-managed"),
        "safety doc must explain tag isolation"
    );
}

#[tokio::test]
async fn t1_f8_03() {
    let repo = repo_root();
    let policy_path = repo.join("libs/cua/crates/cua-byoc/policy/aliyun-ecs-policy.json");
    let raw = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", policy_path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid policy JSON");
    let mut allowed: BTreeSet<String> = BTreeSet::new();
    for stmt in doc["Statement"].as_array().unwrap() {
        if stmt["Effect"] != "Allow" {
            continue;
        }
        match &stmt["Action"] {
            serde_json::Value::String(s) => {
                allowed.insert(s.clone());
            }
            serde_json::Value::Array(a) => {
                for v in a {
                    if let Some(s) = v.as_str() {
                        allowed.insert(s.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    let mut w = AliyunWorld::start().await;
    w.aliyun.lock().unwrap().enforce_cua_managed_tag_condition = true;
    w.auth_login().await;

    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "sync-l",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "suspend", "sync-l"]).await.ok();
    w.run(&["sb", "resume", "sync-l"]).await.ok();
    w.run(&["sb", "rm", "sync-l", "--force"]).await.ok();
    w.run(&[
        "cloud",
        "sweep",
        "aliyun-ecs",
        "--all",
        "--delete",
        "--json",
    ])
    .await
    .ok();

    w.aliyun.lock().unwrap().boot_fail = Some(BootFailMode::StopImmediately);
    let bf = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--name",
            "sync-bf",
        ])
        .await;
    assert_ne!(bf.code, 0);
    w.aliyun.lock().unwrap().boot_fail = None;

    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "sync-w",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "rm", "sync-w", "--force"]).await.ok();
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();

    seed_user_vpc(&w, "cn-hangzhou");
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--vpc-id",
            "vpc-user-1",
            "--vswitch-id",
            "vsw-user-1",
            "--no-public-ip",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "sync-vpc",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "rm", "sync-vpc", "--force"]).await.ok();
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();

    let recorded: BTreeSet<String> = w
        .aliyun
        .lock()
        .unwrap()
        .calls
        .iter()
        .map(|c| action_service(&c.version, &c.action))
        .collect();
    assert!(!recorded.is_empty());
    assert!(
        recorded.contains("ecs:GetInstanceConsoleOutput"),
        "expected GetInstanceConsoleOutput in recorded API calls: {recorded:?}"
    );
    for act in &recorded {
        assert!(
            allowed.contains(act),
            "API action {act} recorded in E2E is missing from aliyun-ecs-policy.json: {allowed:?}"
        );
    }
}

#[tokio::test]
async fn t1_f8_04() {
    let doc_path = repo_root().join("docs/content/docs/cua-sdk/guides/your-cloud.mdx");
    let doc = std::fs::read_to_string(&doc_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", doc_path.display()));
    for term in [
        "aliyun-ecs",
        "Direct VM",
        "Docker-on-VM",
        "--runtime native",
        "--cloud-image-id",
        "--relay-url",
        "--relay-mode",
        "Static Relay",
        "--vpc-id",
        "--vswitch-id",
        "--no-public-ip",
        "--spacesd-download-url",
        "StopCharging",
        "cua cloud sweep",
    ] {
        assert!(doc.contains(term), "your-cloud.mdx missing {term}");
    }
}

#[tokio::test]
async fn t1_f8_05() {
    let repo = repo_root();
    let doc_path = repo.join("docs/content/docs/cua-sdk/guides/your-cloud.mdx");
    let doc = std::fs::read_to_string(&doc_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", doc_path.display()));
    assert!(
        doc.contains("cloudbase-init"),
        "must document cloudbase-init for Win10/11"
    );
    assert!(
        doc.contains("GDI") && doc.contains("WGC"),
        "must document GDI vs WGC note"
    );

    let w = AliyunWorld::start().await;
    let connect_help = w.run(&["cloud", "connect", "--help"]).await;
    connect_help.ok();
    for flag in [
        "--relay-url",
        "--relay-mode",
        "--relay-token-stdin",
        "--vpc-id",
        "--vswitch-id",
        "--no-public-ip",
        "--windows-image-id",
        "--linux-image-id",
        "--instance-type",
        "--spacesd-download-url",
    ] {
        assert!(
            connect_help.stdout.contains(flag),
            "connect --help missing {flag}"
        );
    }

    let sb_help = w.run(&["sb", "create", "--help"]).await;
    sb_help.ok();
    assert!(
        sb_help.stdout.contains("--cloud-image-id"),
        "sb create --help missing --cloud-image-id"
    );

    let _ = base64::engine::general_purpose::STANDARD;
}

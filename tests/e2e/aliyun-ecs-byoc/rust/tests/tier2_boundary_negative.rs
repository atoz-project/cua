// SPDX-License-Identifier: MIT

use aliyun_ecs_byoc_e2e::fake_aliyun::{
    BootFailMode, FakeImage, FakeInstance, FakeSg, FakeVSwitch, FakeVpc,
};
use aliyun_ecs_byoc_e2e::{
    AliyunWorld, decode_user_data_scripts, make_tags, repo_root, seed_monthly_spend,
};
use base64::Engine as _;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn decode_last_run_instances_userdata(f: &aliyun_ecs_byoc_e2e::fake_aliyun::FakeAliyun) -> String {
    let call = f
        .calls_for("RunInstances")
        .into_iter()
        .rfind(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
        .expect("expected non-DryRun RunInstances call");
    let raw = call.params.get("UserData").expect("UserData param");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .expect("valid base64 UserData");
    String::from_utf8(bytes).expect("utf-8 UserData")
}

fn non_dry_run_instances_count(f: &aliyun_ecs_byoc_e2e::fake_aliyun::FakeAliyun) -> usize {
    f.calls_for("RunInstances")
        .into_iter()
        .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
        .count()
}

#[tokio::test]
async fn t2_f1_01() {
    let w = AliyunWorld::start().await;

    // 1. Missing credentials
    let out = w.run(&["cloud", "test", "aliyun-ecs", "--json"]).await;
    assert_ne!(out.code, 0);
    let v = out.json();
    assert_eq!(v["ok"], false);
    let detail = v["checks"][0]["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("no Alibaba Cloud credentials found"),
        "{detail}"
    );
    w.assert_no_secrets_anywhere(&["secret123"]);

    // 2. Malformed --token-stdin variants
    for (bad, expected_sub) in [
        ("not-a-pair\n", "missing ':'"),
        (":secret\n", "malformed AccessKey pair"),
        ("ak:\n", "malformed AccessKey pair"),
        ("ak with space:sk\n", "malformed AccessKey pair"),
    ] {
        let out = w
            .run_with_stdin(
                &["cloud", "test", "aliyun-ecs", "--token-stdin", "--json"],
                bad,
            )
            .await;
        assert_ne!(out.code, 0, "expected failure for {bad:?}");
        let combined = out.combined();
        assert!(
            combined.contains(expected_sub),
            "expected {expected_sub:?} in {combined:?}"
        );
        w.assert_no_secrets_anywhere(&["secret", "sk"]);
    }
}

#[tokio::test]
async fn t2_f1_02() {
    let w = AliyunWorld::start().await;
    w.aliyun
        .lock()
        .unwrap()
        .forbidden_actions
        .insert("ecs:RunInstances".into());

    let out = w
        .run_with_stdin(
            &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(out.code, 0);
    let v = out.json();
    assert_eq!(v["status"], "failed");
    let why = v["next"]["why"].as_str().unwrap_or("");
    assert!(
        why.contains("Forbidden.RAM") && why.contains("ecs:RunInstances"),
        "{why}"
    );

    w.assert_no_secrets_anywhere(&["secret123"]);
    assert!(!w.cua_home().join("cloud/state.json").exists());

    let st = w.run(&["cloud", "status", "aliyun-ecs", "--json"]).await;
    st.ok();
    assert_eq!(st.json()["providers"][0]["connected"], false);
    assert_eq!(st.json()["providers"][0]["credentials"]["found"], false);
}

#[tokio::test]
async fn t2_f1_03() {
    let mut w = AliyunWorld::start().await;
    w.aliyun
        .lock()
        .unwrap()
        .add_key("LTAI_CUR_AK", "cur_secret_123");
    w.write_aliyun_config(&json!({
        "current": "oauth",
        "profiles": [{
            "name": "oauth",
            "mode": "AK",
            "access_key_id": "LTAI_CUR_AK",
            "access_key_secret": "cur_secret_123",
            "region_id": "cn-hangzhou"
        }]
    }));
    w.set_env("ALIBABA_CLOUD_ACCESS_KEY_ID", "LTAI_TEST_AK");

    let out = w.run(&["cloud", "test", "aliyun-ecs", "--json"]).await;
    assert_ne!(out.code, 0);
    let v = out.json();
    assert_eq!(v["ok"], false);
    let detail = v["checks"][0]["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains(
            "both ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET must be set"
        ),
        "{detail}"
    );
    assert!(w.aliyun.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn t2_f1_04() {
    let w = AliyunWorld::start().await;
    w.write_aliyun_config(&json!({
        "current": "sts_prof",
        "profiles": [{
            "name": "sts_prof",
            "mode": "StsToken",
            "access_key_id": "STS_AK",
            "access_key_secret": "sts_secret",
            "region_id": "cn-hangzhou"
        }]
    }));

    let sts_out = w
        .run(&[
            "cloud",
            "test",
            "aliyun-ecs",
            "--profile",
            "sts_prof",
            "--json",
        ])
        .await;
    assert_ne!(sts_out.code, 0);
    let detail = sts_out.json()["checks"][0]["detail"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        detail.contains("StsToken") && detail.contains("only AK mode profiles"),
        "{detail}"
    );
    assert!(w.aliyun.lock().unwrap().calls.is_empty());

    let missing_out = w
        .run(&[
            "cloud",
            "test",
            "aliyun-ecs",
            "--profile",
            "no_such_profile",
            "--json",
        ])
        .await;
    assert_ne!(missing_out.code, 0);
    let m_detail = missing_out.json()["checks"][0]["detail"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        m_detail.contains("no_such_profile") && m_detail.contains("not found"),
        "{m_detail}"
    );
    assert!(w.aliyun.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn t2_f1_05() {
    let w = AliyunWorld::start().await;

    // --oidc refused on aliyun-ecs
    let oidc_out = w
        .run(&["cloud", "connect", "aliyun-ecs", "--oidc", "--json"])
        .await;
    assert_ne!(oidc_out.code, 0);
    let oidc_v = oidc_out.json();
    assert_eq!(oidc_v["status"], "failed");
    assert!(
        oidc_v["next"]["why"]
            .as_str()
            .unwrap_or("")
            .contains("without a stored key")
    );

    // --sealed refused on aliyun-ecs
    let sealed_out = w
        .run_with_stdin(
            &[
                "cloud",
                "connect",
                "aliyun-ecs",
                "--sealed",
                "--token-stdin",
                "--json",
            ],
            "LTAI_TEST_AK:top_secret_never_leak\n",
        )
        .await;
    assert_ne!(sealed_out.code, 0);
    let sealed_v = sealed_out.json();
    assert_eq!(sealed_v["status"], "failed");
    assert!(
        sealed_v["next"]["why"]
            .as_str()
            .unwrap_or("")
            .contains("takes no API token to seal")
    );
    assert!(!sealed_out.combined().contains("top_secret_never_leak"));

    // Bad region syntax rejected at resolve()
    let bad_syntax = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--region",
                "bad region!",
                "--token-stdin",
                "--json",
            ],
            "LTAI_TEST_AK:top_secret_never_leak\n",
        )
        .await;
    assert_eq!(bad_syntax.code, 2);
    assert!(
        bad_syntax.stderr.contains("invalid region"),
        "{}",
        bad_syntax.stderr
    );
    assert!(!bad_syntax.combined().contains("top_secret_never_leak"));

    // Disabled region rejected by DescribeRegions
    let disabled = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--region",
                "cn-mars-1",
                "--token-stdin",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(disabled.code, 0);
    let dv = disabled.json();
    assert_eq!(dv["ok"], false, "{dv}");
    assert!(
        dv["checks"][1]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("cn-mars-1"),
        "{dv}"
    );
    assert!(!disabled.combined().contains("secret123"));
}

// ---- Feature 2 Negative/Boundary ----

#[tokio::test]
async fn t2_f2_01() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("static-relay-secret");

    let missing_tok = w
        .run_with_stdin(
            &[
                "cloud",
                "connect",
                "aliyun-ecs",
                "--token-stdin",
                "--relay-url",
                &w.relay.url,
                "--relay-mode",
                "static",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(missing_tok.code, 0);
    let missing_lower = missing_tok.combined().to_ascii_lowercase();
    assert!(
        missing_lower.contains("relay-token")
            || missing_lower.contains("relay_token")
            || missing_lower.contains("relay token"),
        "expected relay-token refusal for missing token, got: {missing_lower}"
    );
    w.assert_no_secrets_anywhere(&["secret123"]);

    let empty_tok = w
        .run_with_stdin(
            &[
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
            ],
            "LTAI_TEST_AK:secret123\n   \n",
        )
        .await;
    assert_ne!(empty_tok.code, 0);
    let empty_lower = empty_tok.combined().to_ascii_lowercase();
    assert!(
        empty_lower.contains("relay-token")
            || empty_lower.contains("relay_token")
            || empty_lower.contains("relay token"),
        "expected relay-token refusal for empty token, got: {empty_lower}"
    );
    w.assert_no_secrets_anywhere(&["secret123"]);
}

#[tokio::test]
async fn t2_f2_02() {
    let w = AliyunWorld::start().await;
    w.run_with_stdin(
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
    .await
    .ok();

    let create = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--name",
            "no-login",
        ])
        .await;
    assert_ne!(create.code, 0);
    assert!(
        create.stderr.contains("cua auth login") || create.stderr.contains("sign"),
        "{}",
        create.stderr
    );
    assert_eq!(w.aliyun.lock().unwrap().count_calls("RunInstances"), 0);
}

#[tokio::test]
async fn t2_f2_03() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("static-relay-secret");
    w.run_with_stdin(
        &[
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
        ],
        "LTAI_TEST_AK:secret123\nstatic-relay-secret\n",
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
        "bad-env-tok",
    ])
    .await
    .ok();
    let machine = w.relay.static_machines().into_iter().next().unwrap();
    // Overwrite machine's expected env_token on FakeRelay to simulate revoked/mismatched token.
    w.relay
        .register_static_machine(&machine.id, &machine.name, "env_rotated_other");
    w.relay.set_online(&machine.id, true, "0.1.0");
    w.relay
        .tunnel(&machine.id, &format!("http://{}", w.mock_spacesd.addr));

    let exec_out = w.run(&["sb", "exec", "bad-env-tok", "echo", "fail"]).await;
    assert_ne!(exec_out.code, 0);
    let exec_lower = exec_out.combined().to_ascii_lowercase();
    assert!(
        exec_lower.contains("401")
            || exec_lower.contains("unauthorized")
            || exec_lower.contains("bearer")
            || exec_lower.contains("token"),
        "expected 401/unauthorized/bearer/token refusal, got: {exec_lower}"
    );
}

#[tokio::test]
async fn t2_f2_04() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("static-relay-secret");
    w.aliyun.lock().unwrap().fail_run_instances = true;

    w.run_with_stdin(
        &[
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
        ],
        "LTAI_TEST_AK:secret123\nstatic-relay-secret\n",
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
            "--name",
            "rollback-static",
        ])
        .await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    assert!(
        combined.contains("Injected RunInstances failure") || combined.contains("InternalError"),
        "expected injected RunInstances failure in output, got: {combined}"
    );
    assert!(w.relay.static_machines().is_empty());
    let f = w.aliyun.lock().unwrap();
    assert!(
        non_dry_run_instances_count(&f) >= 1,
        "expected RunInstances call before rollback"
    );
    assert!(f.instances.is_empty());
}

#[tokio::test]
async fn t2_f2_05() {
    let w = AliyunWorld::start().await;

    let bad_mode = w
        .run_with_stdin(
            &[
                "cloud",
                "connect",
                "aliyun-ecs",
                "--token-stdin",
                "--relay-mode",
                "tokenless",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(bad_mode.code, 0);
    let mode_err = bad_mode.combined();
    assert!(
        !mode_err.contains("unexpected argument"),
        "clap rejected --relay-mode flag itself: {mode_err}"
    );
    let mode_lower = mode_err.to_ascii_lowercase();
    assert!(
        mode_lower.contains("account") && mode_lower.contains("static"),
        "expected refusal listing valid relay modes (account/static), got: {mode_err}"
    );
    assert!(w.aliyun.lock().unwrap().calls.is_empty());

    let bad_url = w
        .run_with_stdin(
            &[
                "cloud",
                "connect",
                "aliyun-ecs",
                "--token-stdin",
                "--relay-url",
                "not a valid url",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(bad_url.code, 0);
    let url_err = bad_url.combined();
    assert!(
        !url_err.contains("unexpected argument"),
        "clap rejected --relay-url flag itself: {url_err}"
    );
    let url_lower = url_err.to_ascii_lowercase();
    assert!(
        url_lower.contains("relay") || url_lower.contains("url") || url_lower.contains("http"),
        "expected invalid --relay-url validation error, got: {url_err}"
    );
    assert!(w.aliyun.lock().unwrap().calls.is_empty());
}

// ---- Feature 3 Negative/Boundary ----

#[tokio::test]
async fn t2_f3_01() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.boot_fail = Some(BootFailMode::StopImmediately);
        f.console_output = Some(
            "cloud-init error\nCUA_MACHINE_TOKEN=cmt_SECRET_DO_NOT_LEAK_1\nCUA_ENV_TOKEN=env_SECRET_DO_NOT_LEAK_2\napt-get failed\n"
                .into(),
        );
    }
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
            "--name",
            "boot-fail-log",
        ])
        .await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    assert!(
        combined.contains("stopped") || combined.contains("before its sandbox came online"),
        "expected boot-failure refusal message, got: {combined}"
    );
    assert!(!combined.contains("cmt_SECRET_DO_NOT_LEAK_1"), "{combined}");
    assert!(!combined.contains("env_SECRET_DO_NOT_LEAK_2"), "{combined}");
    w.assert_no_secrets_anywhere(&["cmt_SECRET_DO_NOT_LEAK_1", "env_SECRET_DO_NOT_LEAK_2"]);

    let boot_logs_dir = w.cua_home().join("cloud/boot-logs");
    let logs: Vec<_> = std::fs::read_dir(&boot_logs_dir)
        .expect("boot-logs dir")
        .flatten()
        .collect();
    assert!(!logs.is_empty(), "expected redacted boot log file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for entry in &logs {
            let mode = std::fs::metadata(entry.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                0o600,
                "boot log {} must have 0600 permissions, got {mode:#o}",
                entry.path().display()
            );
        }
    }
    let log_text = std::fs::read_to_string(logs[0].path()).unwrap();
    assert!(log_text.contains("apt-get failed"), "{log_text}");
    assert!(
        w.aliyun.lock().unwrap().instances.is_empty(),
        "instance must be rolled back"
    );
}

#[tokio::test]
async fn t2_f3_02() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.boot_fail = Some(BootFailMode::StopImmediately);
        f.console_error = true;
    }
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
            "--name",
            "console-err",
        ])
        .await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    assert!(
        combined.contains("stopped") || combined.contains("before its sandbox came online"),
        "expected boot-failure refusal message, got: {combined}"
    );
    let f = w.aliyun.lock().unwrap();
    assert!(
        non_dry_run_instances_count(&f) >= 1,
        "expected RunInstances call before boot failure"
    );
    assert!(
        f.count_calls("GetInstanceConsoleOutput") >= 1,
        "expected GetInstanceConsoleOutput call before rollback"
    );
    assert!(
        f.instances.is_empty(),
        "rollback must proceed when GetInstanceConsoleOutput fails"
    );
}

#[tokio::test]
async fn t2_f3_03() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.instances.insert(
            "i-untagged".into(),
            FakeInstance {
                instance_id: "i-untagged".into(),
                instance_name: "cua-sb-lookalike".into(),
                region_id: "cn-hangzhou".into(),
                zone_id: "cn-hangzhou-h".into(),
                vpc_id: String::new(),
                vswitch_id: String::new(),
                security_group_id: String::new(),
                instance_type: "ecs.e-c1m2.large".into(),
                image_id: "ubuntu".into(),
                status: "Running".into(),
                instance_charge_type: "PostPaid".into(),
                stopped_mode: "StopCharging".into(),
                auto_release_time: None,
                http_tokens: None,
                key_pair_name: None,
                ram_role_name: None,
                internet_max_bandwidth_out: None,
                system_disk_category: None,
                system_disk_size: None,
                user_data_raw: String::new(),
                user_data_decoded: String::new(),
                tags: Default::default(),
                client_token: None,
                machine_id: None,
            },
        );
        f.instances.insert(
            "i-foreign".into(),
            FakeInstance {
                instance_id: "i-foreign".into(),
                instance_name: "foreign-box".into(),
                region_id: "cn-hangzhou".into(),
                zone_id: "cn-hangzhou-h".into(),
                vpc_id: String::new(),
                vswitch_id: String::new(),
                security_group_id: String::new(),
                instance_type: "ecs.e-c1m2.large".into(),
                image_id: "ubuntu".into(),
                status: "Running".into(),
                instance_charge_type: "PostPaid".into(),
                stopped_mode: "StopCharging".into(),
                auto_release_time: None,
                http_tokens: None,
                key_pair_name: None,
                ram_role_name: None,
                internet_max_bandwidth_out: None,
                system_disk_category: None,
                system_disk_size: None,
                user_data_raw: String::new(),
                user_data_decoded: String::new(),
                tags: make_tags(&[("cua-managed", "true"), ("cua-owner", "other-owner")]),
                client_token: None,
                machine_id: None,
            },
        );
    }
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    // Create a Cua-owned instance for sweep to delete, plus a second instance whose live tags
    // will be stripped/altered to verify suspend/resume/rm refuse on untagged/foreign instances.
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "owned-sweep",
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
        "tag-tamper",
        "--json",
    ])
    .await
    .ok();

    let (owned_id, tamper_id) = {
        let f = w.aliyun.lock().unwrap();
        let owned = f
            .instances
            .values()
            .find(|i| i.tags.get("cua-space").is_some_and(|s| s == "owned-sweep"))
            .expect("owned-sweep instance")
            .instance_id
            .clone();
        let tamper = f
            .instances
            .values()
            .find(|i| i.tags.get("cua-space").is_some_and(|s| s == "tag-tamper"))
            .expect("tag-tamper instance")
            .instance_id
            .clone();
        (owned, tamper)
    };

    // Strip/alter live tags on tag-tamper -> suspend, resume, and rm must all refuse!
    {
        let mut f = w.aliyun.lock().unwrap();
        f.instances.get_mut(&tamper_id).unwrap().tags.clear();
        f.calls.clear();
    }
    for sub in [
        &["sb", "suspend", "tag-tamper"][..],
        &["sb", "resume", "tag-tamper"][..],
        &["sb", "rm", "tag-tamper", "--force"][..],
    ] {
        let out = w.run(sub).await;
        assert_ne!(out.code, 0, "expected refusal on untagged {sub:?}");
        let msg = out.combined().to_ascii_lowercase();
        assert!(
            msg.contains("cua-managed")
                || msg.contains("cua-owner")
                || msg.contains("not tagged")
                || msg.contains("tag"),
            "expected tag-ownership refusal for {sub:?}, got: {msg}"
        );
    }
    {
        let f = w.aliyun.lock().unwrap();
        assert_eq!(
            f.count_calls("StopInstance") + f.count_calls("StopInstances"),
            0
        );
        assert_eq!(
            f.count_calls("StartInstance") + f.count_calls("StartInstances"),
            0
        );
        assert_eq!(
            f.count_calls("DeleteInstance") + f.count_calls("DeleteInstances"),
            0
        );
        assert!(f.instances.contains_key(&tamper_id));
    }

    // Also verify foreign cua-owner refuses rm.
    {
        let mut f = w.aliyun.lock().unwrap();
        f.instances.get_mut(&tamper_id).unwrap().tags =
            make_tags(&[("cua-managed", "true"), ("cua-owner", "other-owner")]);
        f.calls.clear();
    }
    let foreign_rm = w.run(&["sb", "rm", "tag-tamper", "--force"]).await;
    assert_ne!(foreign_rm.code, 0);
    let f_msg = foreign_rm.combined().to_ascii_lowercase();
    assert!(
        f_msg.contains("cua-managed")
            || f_msg.contains("cua-owner")
            || f_msg.contains("not tagged")
            || f_msg.contains("owner"),
        "expected foreign-owner refusal, got: {f_msg}"
    );
    {
        let f = w.aliyun.lock().unwrap();
        assert_eq!(
            f.count_calls("DeleteInstance") + f.count_calls("DeleteInstances"),
            0
        );
    }

    // Sweep must delete ONLY the Cua-owned instance (`owned-sweep`), never `i-untagged`,
    // `i-foreign`, or `tag-tamper` (whose live tags belong to `other-owner`).
    w.aliyun.lock().unwrap().calls.clear();
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
    let mut del_calls = f.calls_for("DeleteInstance");
    del_calls.extend(f.calls_for("DeleteInstances"));
    let deleted_target = |id: &str| {
        del_calls
            .iter()
            .filter(|c| c.params.values().any(|v| v.contains(id)))
            .count()
    };
    assert!(
        deleted_target(&owned_id) >= 1,
        "expected DeleteInstance call for Cua-owned {owned_id}, got: {del_calls:?}"
    );
    assert_eq!(deleted_target("i-untagged"), 0);
    assert_eq!(deleted_target("i-foreign"), 0);
    assert_eq!(deleted_target(&tamper_id), 0);
    assert!(!f.instances.contains_key(&owned_id));
    assert!(f.instances.contains_key("i-untagged"));
    assert!(f.instances.contains_key("i-foreign"));
    assert!(f.instances.contains_key(&tamper_id));
}

#[tokio::test]
async fn t2_f3_04() {
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
        "keep-alive-box",
    ])
    .await
    .ok();

    let disc = w.run(&["cloud", "disconnect", "aliyun-ecs"]).await;
    assert_eq!(disc.code, 6, "{disc:?}");
    assert!(disc.stderr.contains("NOT disconnected"), "{}", disc.stderr);
    assert_eq!(w.aliyun.lock().unwrap().instances.len(), 1);
}

#[tokio::test]
async fn t2_f3_05() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        for z in ["cn-hangzhou-h", "cn-hangzhou-i", "cn-hangzhou-j"] {
            f.sold_out_zones.insert(z.into());
        }
    }
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
            "--name",
            "no-stock",
        ])
        .await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    assert!(
        combined.contains("NoStock") || combined.contains("capacity") || combined.contains("stock"),
        "{combined}"
    );
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

// ---- Feature 4 Negative/Boundary ----

#[tokio::test]
async fn t2_f4_01() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.aliyun.lock().unwrap().calls.clear();

    // 1. windows + --runtime docker must be refused specifically for docker/native runtime.
    let win_docker = w
        .run(&[
            "sb",
            "create",
            "windows",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "docker",
        ])
        .await;
    assert_ne!(win_docker.code, 0);
    assert!(matches!(win_docker.code, 2 | 4), "{win_docker:?}");
    let wd_msg = win_docker.combined().to_ascii_lowercase();
    assert!(
        wd_msg.contains("docker") && wd_msg.contains("native"),
        "expected docker/native refusal for windows --runtime docker, got: {wd_msg}"
    );

    // 2. Unsupported OSes (macos, omarchy) must name the refused OS.
    for os_img in ["macos", "omarchy"] {
        let out = w.run(&["sb", "create", os_img, "--on", "aliyun-ecs"]).await;
        assert_ne!(out.code, 0, "expected refusal for {os_img}");
        assert!(
            matches!(out.code, 2 | 4),
            "expected exit 2 or 4 for {os_img}, got {}: {}",
            out.code,
            out.stderr
        );
        let msg = out.combined().to_ascii_lowercase();
        assert!(
            msg.contains(os_img),
            "expected refusal naming {os_img}, got: {msg}"
        );
    }

    // 3. Reserved location --on aliyun-sandbox must be refused (ADR-0001).
    let reserved = w
        .run(&["sb", "create", "linux", "--on", "aliyun-sandbox"])
        .await;
    assert_eq!(reserved.code, 2, "{reserved:?}");
    let r_msg = reserved.combined().to_ascii_lowercase();
    assert!(
        r_msg.contains("aliyun-sandbox") && r_msg.contains("aliyun-ecs"),
        "expected reserved-location refusal naming aliyun-sandbox and aliyun-ecs, got: {r_msg}"
    );
    assert_eq!(w.aliyun.lock().unwrap().count_calls("RunInstances"), 0);
}

#[tokio::test]
async fn t2_f4_02() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    // FakeAliyun does not execute guest PowerShell; verify generated #ps1_sysnative UserData
    // enforces SHA-256 verification against the mirror URL and aborts on hash mismatch.
    w.mirror.set_corrupt_bytes(true);
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
        "win-sha-chk",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let ud = &f.instances.values().next().unwrap().user_data_decoded;
    assert!(ud.contains("Get-FileHash") || ud.contains("SHA256"), "{ud}");
    assert!(ud.contains("throw") || ud.contains("exit 1"), "{ud}");
}

#[tokio::test]
async fn t2_f4_03() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("STATIC_RELAY_SECRET_999");
    w.run_with_stdin(
        &[
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
        ],
        "LTAI_TEST_AK:secret123\nSTATIC_RELAY_SECRET_999\n",
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
        "win-clean",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let ud = &f.instances.values().next().unwrap().user_data_decoded;
    assert!(ud.contains("icacls"), "{ud}");
    assert!(ud.contains("Remove-Item"), "{ud}");
    assert!(
        !ud.contains("secret123"),
        "Aliyun AK secret must never enter UserData"
    );
}

#[tokio::test]
async fn t2_f4_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    // FakeAliyun does not execute guest PowerShell, so BootFailMode::StopImmediately simulates
    // a failed guest mirror download/boot while we also inspect UserData for mirror error handling.
    w.mirror.set_status_override(Some(404));
    w.aliyun.lock().unwrap().boot_fail = Some(BootFailMode::StopImmediately);
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

    let out = w
        .run(&[
            "sb",
            "create",
            "windows",
            "--on",
            "aliyun-ecs",
            "--name",
            "win-404",
        ])
        .await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    assert!(
        combined.contains("stopped") || combined.contains("before its sandbox came online"),
        "expected boot-failure error message, got: {combined}"
    );
    let f = w.aliyun.lock().unwrap();
    assert!(
        non_dry_run_instances_count(&f) >= 1,
        "expected RunInstances call before boot failure"
    );
    let ud = decode_last_run_instances_userdata(&f);
    assert!(ud.contains(&mirror_url), "{ud}");
    assert!(
        ud.contains("throw") || ud.contains("exit 1") || ud.contains("ErrorActionPreference"),
        "expected mirror failure-abort handling in Windows UserData: {ud}"
    );
    assert!(f.instances.is_empty());
}

#[tokio::test]
async fn t2_f4_05() {
    let w = AliyunWorld::start().await;
    for bad in ["ftp://example.com/cua-spacesd.exe", "not a url"] {
        let out = w
            .run_with_stdin(
                &[
                    "cloud",
                    "connect",
                    "aliyun-ecs",
                    "--token-stdin",
                    "--spacesd-download-url",
                    bad,
                    "--json",
                ],
                "LTAI_TEST_AK:secret123\n",
            )
            .await;
        assert_ne!(out.code, 0, "expected rejection for {bad}");
        let combined = out.combined();
        assert!(
            !combined.contains("unexpected argument"),
            "clap rejected --spacesd-download-url flag itself: {combined}"
        );
        let lower = combined.to_ascii_lowercase();
        assert!(
            lower.contains("spacesd") || lower.contains("download") || lower.contains("http"),
            "expected --spacesd-download-url validation error for {bad}, got: {combined}"
        );
        w.assert_no_secrets_anywhere(&["secret123"]);
    }
}

// ---- Feature 5 Negative/Boundary ----

#[tokio::test]
async fn t2_f5_01() {
    let w = AliyunWorld::start().await;
    let only_vsw = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--token-stdin",
                "--vswitch-id",
                "vsw-1",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(only_vsw.code, 0);
    assert!(only_vsw.combined().contains("vpc-id"));

    let only_vpc = w
        .run_with_stdin(
            &[
                "cloud",
                "connect",
                "aliyun-ecs",
                "--token-stdin",
                "--vpc-id",
                "vpc-1",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(only_vpc.code, 0);
    assert!(only_vpc.combined().contains("vswitch-id"));
    w.assert_no_secrets_anywhere(&["secret123"]);
}

#[tokio::test]
async fn t2_f5_02() {
    let w = AliyunWorld::start().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.vpcs.insert(
            "vpc-a".into(),
            FakeVpc {
                vpc_id: "vpc-a".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.0.0.0/16".into(),
                vpc_name: "a".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
        f.vswitches.insert(
            "vsw-b".into(),
            FakeVSwitch {
                vswitch_id: "vsw-b".into(),
                vpc_id: "vpc-other".into(),
                zone_id: "cn-hangzhou-h".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.1.1.0/24".into(),
                vswitch_name: "b".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
    }
    let out = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--token-stdin",
                "--vpc-id",
                "vpc-a",
                "--vswitch-id",
                "vsw-b",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(out.code, 0);
    assert!(out.combined().contains("vpc-a") || out.combined().contains("vsw-b"));
}

#[tokio::test]
async fn t2_f5_03() {
    let w = AliyunWorld::start().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.vpcs.insert(
            "vpc-sh".into(),
            FakeVpc {
                vpc_id: "vpc-sh".into(),
                region_id: "cn-shanghai".into(),
                cidr_block: "10.2.0.0/16".into(),
                vpc_name: "sh".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
        f.vswitches.insert(
            "vsw-sh".into(),
            FakeVSwitch {
                vswitch_id: "vsw-sh".into(),
                vpc_id: "vpc-sh".into(),
                zone_id: "cn-shanghai-h".into(),
                region_id: "cn-shanghai".into(),
                cidr_block: "10.2.1.0/24".into(),
                vswitch_name: "sh".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
    }
    let out = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--token-stdin",
                "--region",
                "cn-hangzhou",
                "--vpc-id",
                "vpc-sh",
                "--vswitch-id",
                "vsw-sh",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(out.code, 0);
    assert!(out.combined().contains("vpc-sh"));
}

#[tokio::test]
async fn t2_f5_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.vpcs.insert(
            "vpc-priv".into(),
            FakeVpc {
                vpc_id: "vpc-priv".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.3.0.0/16".into(),
                vpc_name: "priv".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
        f.vswitches.insert(
            "vsw-priv".into(),
            FakeVSwitch {
                vswitch_id: "vsw-priv".into(),
                vpc_id: "vpc-priv".into(),
                zone_id: "cn-hangzhou-h".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.3.1.0/24".into(),
                vswitch_name: "priv".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
    }
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--vpc-id",
            "vpc-priv",
            "--vswitch-id",
            "vsw-priv",
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
        "nopub",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let inst = f.instances.values().next().unwrap();
    assert_eq!(inst.internet_max_bandwidth_out.as_deref(), Some("0"));
}

#[tokio::test]
async fn t2_f5_05() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.vpcs.insert(
            "vpc-user".into(),
            FakeVpc {
                vpc_id: "vpc-user".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.4.0.0/16".into(),
                vpc_name: "user".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
        f.vswitches.insert(
            "vsw-user".into(),
            FakeVSwitch {
                vswitch_id: "vsw-user".into(),
                vpc_id: "vpc-user".into(),
                zone_id: "cn-hangzhou-h".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.4.1.0/24".into(),
                vswitch_name: "user".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
        f.security_groups.insert(
            "sg-lookalike".into(),
            FakeSg {
                sg_id: "sg-lookalike".into(),
                vpc_id: "vpc-user".into(),
                region_id: "cn-hangzhou".into(),
                sg_name: "cua-sandboxes-lookalike".into(),
                tags: Default::default(),
                ingress_rules: vec![],
                is_user_owned: true,
            },
        );
    }
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--vpc-id",
            "vpc-user",
            "--vswitch-id",
            "vsw-user",
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
        "sg-iso",
    ])
    .await
    .ok();
    assert_ne!(
        w.aliyun
            .lock()
            .unwrap()
            .instances
            .values()
            .next()
            .unwrap()
            .security_group_id,
        "sg-lookalike"
    );
    w.run(&["sb", "rm", "sg-iso", "--force"]).await.ok();
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
    assert!(
        w.aliyun
            .lock()
            .unwrap()
            .security_groups
            .contains_key("sg-lookalike")
    );
}

// ---- Feature 6 Negative/Boundary ----

#[tokio::test]
async fn t2_f6_01() {
    let w = AliyunWorld::start().await;
    w.aliyun.lock().unwrap().add_image(FakeImage {
        image_id: "m-unavailable".into(),
        image_name: "m-unavailable".into(),
        os_type: "windows".into(),
        arch: "x86_64".into(),
        status: "Unavailable".into(),
        owner_alias: "self".into(),
        region_id: "cn-hangzhou".into(),
    });

    let bad = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--token-stdin",
                "--windows-image-id",
                "m-unavailable",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(bad.code, 0);
    assert!(bad.combined().contains("m-unavailable"));
    w.assert_no_secrets_anywhere(&["secret123"]);
}

#[tokio::test]
async fn t2_f6_02() {
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
            "--cloud-image-id",
            "m-does-not-exist",
        ])
        .await;
    assert_ne!(out.code, 0);
    assert!(out.combined().contains("m-does-not-exist"));
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

#[tokio::test]
async fn t2_f6_03() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--max-size",
            "4x16",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.aliyun.lock().unwrap().calls.clear();

    let out = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--cpu",
            "8",
            "--memory",
            "32GB",
        ])
        .await;
    assert_eq!(out.code, 2, "{out:?}");
    assert!(out.stderr.contains("4 vCPU and 16 GB"), "{}", out.stderr);
    assert_eq!(w.aliyun.lock().unwrap().count_calls("RunInstances"), 0);
}

#[tokio::test]
async fn t2_f6_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--budget",
            "2.0",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    // Seed closed monthly spend ($5.00 >= $2.00 budget) in cloud/state.json, which
    // Store::spent_month reads for --budget preflight.
    seed_monthly_spend(&w.cua_home(), "aliyun-ecs", 5.0);
    w.aliyun.lock().unwrap().calls.clear();

    let out = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--name",
            "over-budget",
        ])
        .await;
    assert_eq!(out.code, 6, "{out:?}");
    let err_lower = out.stderr.to_ascii_lowercase();
    assert!(
        err_lower.contains("budget")
            && (err_lower.contains("reached") || err_lower.contains("exceeded")),
        "expected exact budget refusal in stderr, got: {}",
        out.stderr
    );
    assert_eq!(w.aliyun.lock().unwrap().count_calls("RunInstances"), 0);
}

#[tokio::test]
async fn t2_f6_05() {
    let w = AliyunWorld::start().await;
    let out = w
        .run_with_stdin(
            &[
                "cloud",
                "test",
                "aliyun-ecs",
                "--token-stdin",
                "--instance-type",
                "ecs.nonexistent.99xlarge",
                "--json",
            ],
            "LTAI_TEST_AK:secret123\n",
        )
        .await;
    assert_ne!(out.code, 0);
    assert!(out.combined().contains("ecs.nonexistent.99xlarge"));
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

// ---- Feature 7 Negative/Boundary ----

#[tokio::test]
async fn t2_f7_01() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.aliyun.lock().unwrap().calls.clear();

    let out = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "native",
            "--sidecar",
            "redis:7",
        ])
        .await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    let lower = combined.to_ascii_lowercase();
    assert!(
        !lower.contains("does not apply"),
        "refused due to unsupported --runtime native instead of --sidecar: {combined}"
    );
    assert!(
        lower.contains("sidecar") || lower.contains("native"),
        "expected --sidecar / native refusal, got: {combined}"
    );
    assert!(
        lower.contains("sidecar"),
        "expected refusal to mention sidecar(s), got: {combined}"
    );
    assert_eq!(w.aliyun.lock().unwrap().count_calls("RunInstances"), 0);

    // Without --sidecar, --runtime native succeeds cleanly.
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--runtime",
        "native",
        "--name",
        "nat-no-sidecar",
        "--json",
    ])
    .await
    .ok();
}

#[tokio::test]
async fn t2_f7_02() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    // FakeAliyun does not execute guest cloud-init, so BootFailMode::StopImmediately simulates
    // boot failure while we decode write_files: b64 in UserData to assert sha256sum + abort.
    w.mirror.set_corrupt_bytes(true);
    w.aliyun.lock().unwrap().boot_fail = Some(BootFailMode::StopImmediately);
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
            "linux-sha-fail",
        ])
        .await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    assert!(
        combined.contains("stopped") || combined.contains("before its sandbox came online"),
        "expected boot-failure error message, got: {combined}"
    );
    let f = w.aliyun.lock().unwrap();
    assert!(
        non_dry_run_instances_count(&f) >= 1,
        "expected RunInstances call before boot failure"
    );
    let ud_raw = decode_last_run_instances_userdata(&f);
    let ud = decode_user_data_scripts(&ud_raw);
    assert!(ud.contains(&mirror_url), "{ud}");
    assert!(ud.contains("sha256sum"), "expected sha256sum check: {ud}");
    assert!(
        ud.contains("exit 1") || ud.contains("set -e") || ud.contains("|| exit"),
        "expected failure abort on checksum mismatch: {ud}"
    );
    assert!(f.instances.is_empty());
}

#[tokio::test]
async fn t2_f7_03() {
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
        "--headless",
        "--name",
        "linux-headless-ok",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let ud = decode_user_data_scripts(&f.instances.values().next().unwrap().user_data_decoded);
    assert!(!ud.contains("xvfb") && !ud.contains("xfce"));
}

#[tokio::test]
async fn t2_f7_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.boot_fail = Some(BootFailMode::StopImmediately);
        f.console_output = Some("systemd error\ncmt_SECRET_NAT_123\n".into());
    }
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
            "nat-boot-fail",
        ])
        .await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    assert!(
        combined.contains("stopped") || combined.contains("before its sandbox came online"),
        "expected boot-failure refusal, got: {combined}"
    );
    assert!(!combined.contains("cmt_SECRET_NAT_123"));
    w.assert_no_secrets_anywhere(&["cmt_SECRET_NAT_123"]);

    let boot_logs_dir = w.cua_home().join("cloud/boot-logs");
    let logs: Vec<_> = std::fs::read_dir(&boot_logs_dir)
        .expect("boot-logs dir")
        .flatten()
        .collect();
    assert!(!logs.is_empty(), "expected redacted boot log file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for entry in &logs {
            let mode = std::fs::metadata(entry.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "boot log must have 0600 permissions");
        }
    }
    let log_text = std::fs::read_to_string(logs[0].path()).unwrap();
    assert!(log_text.contains("systemd error"), "{log_text}");
    assert!(!log_text.contains("cmt_SECRET_NAT_123"), "{log_text}");

    let f = w.aliyun.lock().unwrap();
    assert!(
        non_dry_run_instances_count(&f) >= 1,
        "expected RunInstances call before boot failure"
    );
    assert!(
        f.count_calls("GetInstanceConsoleOutput") >= 1,
        "expected GetInstanceConsoleOutput call before rollback"
    );
    assert!(f.instances.is_empty());
}

#[tokio::test]
async fn t2_f7_05() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    let bad_ttl = w
        .run(&[
            "sb",
            "create",
            "linux-slim",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "native",
            "--ttl",
            "not-a-duration",
        ])
        .await;
    assert_eq!(bad_ttl.code, 2);
    let ttl_err = bad_ttl.combined().to_ascii_lowercase();
    assert!(
        ttl_err.contains("ttl") || ttl_err.contains("duration") || ttl_err.contains("invalid"),
        "expected ttl parse/validation error, got: {ttl_err}"
    );

    w.run(&[
        "sb",
        "create",
        "linux-slim",
        "--on",
        "aliyun-ecs",
        "--runtime",
        "native",
        "--ttl",
        "0",
        "--name",
        "nat-ttl-0",
        "--json",
    ])
    .await
    .ok();
    assert!(
        w.aliyun
            .lock()
            .unwrap()
            .instances
            .values()
            .next()
            .unwrap()
            .auto_release_time
            .is_none()
    );
}

// ---- Feature 8 Negative/Boundary ----

#[tokio::test]
async fn t2_f8_01() {
    let policy_path = repo_root().join("libs/cua/crates/cua-byoc/policy/aliyun-ecs-policy.json");
    let raw = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", policy_path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    assert!(doc["Statement"].is_array());

    let w = AliyunWorld::start().await;
    for action in [
        "sts:GetCallerIdentity",
        "ecs:DescribeRegions",
        "vpc:DescribeVpcs",
    ] {
        {
            let mut f = w.aliyun.lock().unwrap();
            f.forbidden_actions.clear();
            f.forbidden_actions.insert(action.into());
        }
        let out = w
            .run_with_stdin(
                &["cloud", "test", "aliyun-ecs", "--token-stdin", "--json"],
                "LTAI_TEST_AK:secret123\n",
            )
            .await;
        assert_ne!(out.code, 0);
        let text = out.combined();
        assert!(
            text.contains("Forbidden.RAM") && text.contains(action),
            "missing Forbidden.RAM + {action} in {text}"
        );
    }
}

#[tokio::test]
async fn t2_f8_02() {
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
        "tag-cond",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "suspend", "tag-cond"]).await.ok();
    w.run(&["sb", "resume", "tag-cond"]).await.ok();
    w.run(&["sb", "rm", "tag-cond", "--force"]).await.ok();
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
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

#[tokio::test]
async fn t2_f8_03() {
    let repo = repo_root();
    let guide =
        std::fs::read_to_string(repo.join("docs/content/docs/cua-sdk/guides/your-cloud.mdx"))
            .expect("read your-cloud.mdx");
    assert!(
        guide.contains("aliyun-ecs"),
        "your-cloud.mdx must document aliyun-ecs"
    );
    assert!(!guide.contains("bare-metal sandbox"));
    assert!(!guide.contains("tokenless relay"));
    assert!(!guide.contains("--on aliyun-sandbox"));

    let w = AliyunWorld::start().await;
    let help = w.run(&["cloud", "connect", "--help"]).await;
    help.ok();
    assert!(help.stdout.contains("aliyun-ecs"), "{}", help.stdout);
    assert!(!help.stdout.contains("aliyun-sandbox"));
}

#[tokio::test]
async fn t2_f8_04() {
    let policy_path = repo_root().join("libs/cua/crates/cua-byoc/policy/aliyun-ecs-policy.json");
    let raw = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", policy_path.display()));
    assert!(raw.contains("ecs:GetInstanceConsoleOutput"));
    assert!(!raw.contains("ecs:*"));
    assert!(!raw.contains("ram:*"));
}

#[tokio::test]
async fn t2_f8_05() {
    // Verify live smoke test enforces opt-in guard AND hermetic runs block real internet egress.
    let live_src = std::fs::read_to_string(
        repo_root().join("tests/e2e/aliyun-ecs-byoc/rust/tests/live_ecs_smoke.rs"),
    )
    .expect("read live_ecs_smoke.rs");
    assert!(live_src.contains("#[ignore"), "live test must be #[ignore]");
    assert!(
        live_src.contains("CUA_E2E_ALIYUN_LIVE"),
        "live test must check CUA_E2E_ALIYUN_LIVE inside test body"
    );

    let mut w = AliyunWorld::start().await;
    // 1. Scrubbed `cloud test` without credentials fails without making any external CONNECT.
    w.remove_env("ALIBABA_CLOUD_ACCESS_KEY_ID");
    w.remove_env("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
    let out = w.run(&["cloud", "test", "aliyun-ecs", "--json"]).await;
    assert_ne!(out.code, 0);
    let combined = out.combined();
    assert!(
        combined.contains("no Alibaba Cloud credentials found"),
        "{combined}"
    );
    w.assert_no_unexpected_egress();

    // 2. Non-aliyuncs.com CONNECT through w.proxy fails fast with 502 Bad Gateway and is recorded.
    let proxy_addr = w
        .proxy
        .url
        .strip_prefix("http://")
        .expect("proxy http:// addr");
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect to AliyunConnectProxy");
    stream
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("send CONNECT");
    let mut resp_buf = [0u8; 512];
    let n = stream.read(&mut resp_buf).await.expect("read proxy resp");
    let resp = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 502 Bad Gateway"),
        "expected 502 Bad Gateway for non-aliyuncs CONNECT, got: {resp:?}"
    );
    let blocked = w.proxy.blocked_egress();
    assert!(
        blocked.iter().any(|h| h == "example.com:443"),
        "expected example.com:443 in blocked_egress, got: {blocked:?}"
    );
}

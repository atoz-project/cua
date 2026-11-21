// SPDX-License-Identifier: MIT

use aliyun_ecs_byoc_e2e::fake_aliyun::{
    BootFailMode, FakeImage, FakeInstance, FakeSg, FakeVSwitch, FakeVpc,
};
use aliyun_ecs_byoc_e2e::{AliyunWorld, decode_user_data_scripts, make_tags, seed_monthly_spend};
use serde_json::json;

#[tokio::test]
async fn t4_01() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("corp-static-relay-tok");
    {
        let mut f = w.aliyun.lock().unwrap();
        f.vpcs.insert(
            "vpc-corp".into(),
            FakeVpc {
                vpc_id: "vpc-corp".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.20.0.0/16".into(),
                vpc_name: "corp-vpc".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
        f.vswitches.insert(
            "vsw-priv".into(),
            FakeVSwitch {
                vswitch_id: "vsw-priv".into(),
                vpc_id: "vpc-corp".into(),
                zone_id: "cn-hangzhou-h".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.20.1.0/24".into(),
                vswitch_name: "corp-priv".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
        f.security_groups.insert(
            "sg-corp".into(),
            FakeSg {
                sg_id: "sg-corp".into(),
                vpc_id: "vpc-corp".into(),
                region_id: "cn-hangzhou".into(),
                sg_name: "corp-sg".into(),
                tags: Default::default(),
                ingress_rules: vec![],
                is_user_owned: true,
            },
        );
        f.add_image(FakeImage {
            image_id: "m-win11-corp".into(),
            image_name: "m-win11-corp".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "self".into(),
            region_id: "cn-hangzhou".into(),
        });
    }

    let win_mir = w.mirror.windows_url();
    w.run_with_stdin(
        &[
            "cloud",
            "test",
            "aliyun-ecs",
            "--token-stdin",
            "--vpc-id",
            "vpc-corp",
            "--vswitch-id",
            "vsw-priv",
            "--no-public-ip",
            "--relay-mode",
            "static",
            "--relay-url",
            &w.relay.url,
            "--relay-token-stdin",
            "--windows-image-id",
            "m-win11-corp",
            "--spacesd-download-url",
            &win_mir,
            "--json",
        ],
        "LTAI_TEST_AK:secret123\ncorp-static-relay-tok\n",
    )
    .await
    .ok();

    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--vpc-id",
            "vpc-corp",
            "--vswitch-id",
            "vsw-priv",
            "--no-public-ip",
            "--relay-mode",
            "static",
            "--relay-url",
            &w.relay.url,
            "--relay-token-stdin",
            "--windows-image-id",
            "m-win11-corp",
            "--spacesd-download-url",
            &win_mir,
            "--json",
        ],
        "LTAI_TEST_AK:secret123\ncorp-static-relay-tok\n",
    )
    .await
    .ok();

    w.run(&[
        "spaces",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "win-corp",
        "--json",
    ])
    .await
    .ok();
    {
        let f = w.aliyun.lock().unwrap();
        let inst = f.instances.values().next().unwrap();
        assert_eq!(inst.internet_max_bandwidth_out.as_deref(), Some("0"));
        assert_eq!(inst.image_id, "m-win11-corp");
        assert!(inst.user_data_decoded.contains(&win_mir));
        assert!(inst.user_data_decoded.contains("100.100.100.200"));
        assert!(decode_user_data_scripts(&inst.user_data_decoded).contains("tscon.exe"));
    }

    w.run(&["sb", "exec", "win-corp", "echo", "corp-ok"])
        .await
        .ok();
    w.run(&["spaces", "stop", "win-corp"]).await.ok();
    w.run(&["spaces", "start", "win-corp"]).await.ok();
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();

    let f = w.aliyun.lock().unwrap();
    assert!(f.instances.is_empty());
    assert!(f.vpcs.contains_key("vpc-corp"));
    assert!(f.vswitches.contains_key("vsw-priv"));
    assert!(f.security_groups.contains_key("sg-corp"));
    w.assert_no_secrets_anywhere(&["secret123", "corp-static-relay-tok"]);
}

#[tokio::test]
async fn t4_02() {
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
            "region_id": "cn-shanghai"
        }]
    }));
    w.auth_login().await;

    w.run(&[
        "cloud",
        "connect",
        "aliyun-ecs",
        "--budget",
        "100",
        "--max-size",
        "4x16",
        "--default",
        "--json",
    ])
    .await
    .ok();

    w.run(&["sb", "create", "linux", "--name", "sb-docker", "--json"])
        .await
        .ok();
    w.run(&[
        "sb",
        "create",
        "linux-slim",
        "--runtime",
        "native",
        "--name",
        "sb-nat",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "create", "windows", "--name", "sb-win", "--json"])
        .await
        .ok();

    let st = w.run(&["cloud", "status", "--json"]).await;
    st.ok();
    assert_eq!(st.json()["default_on"], "aliyun-ecs");
    let aliyun_st = st.json()["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "aliyun-ecs")
        .cloned()
        .expect("aliyun-ecs provider in cloud status");
    assert_eq!(aliyun_st["running"], 3);
    assert_eq!(
        w.aliyun
            .lock()
            .unwrap()
            .calls_for("CreateVpc")
            .into_iter()
            .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
            .count(),
        1
    );

    w.run(&["cloud", "cost", "--by", "cloud", "--json"])
        .await
        .ok();
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

#[tokio::test]
async fn t4_03() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.boot_fail = Some(BootFailMode::StopImmediately);
        f.console_output =
            Some("apt-get: unable to locate package\ncmt_LEAKTEST999\nenv_LEAKTEST888\n".into());
    }
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    let failed = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--name",
            "flaky-box",
        ])
        .await;
    assert_ne!(failed.code, 0);
    assert!(!failed.combined().contains("cmt_LEAKTEST999"));
    assert!(!failed.combined().contains("env_LEAKTEST888"));
    w.assert_no_secrets_anywhere(&["cmt_LEAKTEST999", "env_LEAKTEST888"]);
    assert!(w.aliyun.lock().unwrap().instances.is_empty());

    w.aliyun.lock().unwrap().boot_fail = None;
    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "flaky-box",
        "--json",
    ])
    .await
    .ok();
    w.run(&["sb", "exec", "flaky-box", "echo", "recovered"])
        .await
        .ok();
    w.run(&["sb", "rm", "flaky-box", "--force"]).await.ok();
}

#[tokio::test]
async fn t4_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--budget",
            "5.0",
            "--max-size",
            "2x4",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    let big = w
        .run(&[
            "sb",
            "create",
            "windows",
            "--on",
            "aliyun-ecs",
            "--name",
            "too-big",
        ])
        .await;
    assert_eq!(big.code, 2);

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "fits",
        "--json",
    ])
    .await
    .ok();

    seed_monthly_spend(&w.cua_home(), "aliyun-ecs", 6.0);

    w.aliyun.lock().unwrap().calls.clear();
    let blocked = w
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
    assert_eq!(blocked.code, 6, "{blocked:?}");
    let blocked_msg = blocked.combined().to_ascii_lowercase();
    assert!(
        blocked_msg.contains("budget")
            && (blocked_msg.contains("reached") || blocked_msg.contains("exceeded")),
        "expected budget reached/exceeded refusal, got: {blocked_msg}"
    );
    assert_eq!(w.aliyun.lock().unwrap().count_calls("RunInstances"), 0);

    // Lifecycle stop/rm/disconnect STILL allowed while over budget.
    w.run(&["sb", "suspend", "fits"]).await.ok();
    w.run(&["sb", "rm", "fits", "--force"]).await.ok();
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();
}

#[tokio::test]
async fn t4_05() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.enforce_cua_managed_tag_condition = true;
        f.vpcs.insert(
            "vpc-user".into(),
            FakeVpc {
                vpc_id: "vpc-user".into(),
                region_id: "cn-hangzhou".into(),
                cidr_block: "10.50.0.0/16".into(),
                vpc_name: "user-owned".into(),
                tags: Default::default(),
                is_user_owned: true,
            },
        );
        for (id, tags) in [
            ("i-legacy", Default::default()),
            (
                "i-other",
                make_tags(&[("cua-managed", "true"), ("cua-owner", "other-user")]),
            ),
        ] {
            f.instances.insert(
                id.into(),
                FakeInstance {
                    instance_id: id.into(),
                    instance_name: id.into(),
                    region_id: "cn-hangzhou".into(),
                    zone_id: "cn-hangzhou-h".into(),
                    vpc_id: "vpc-user".into(),
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
                    tags,
                    client_token: None,
                    machine_id: None,
                },
            );
        }
    }
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
        "hygiene-box",
        "--json",
    ])
    .await
    .ok();
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
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();

    let f = w.aliyun.lock().unwrap();
    assert!(f.instances.contains_key("i-legacy"));
    assert!(f.instances.contains_key("i-other"));
    assert!(f.vpcs.contains_key("vpc-user"));
}

#[tokio::test]
async fn t4_06() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    let (daemon_url, daemon_tok) = w.start_daemon().await;
    let sdk = cua_sdk::Cua::connect(Some(daemon_url), Some(daemon_tok)).expect("sdk connect");

    let tested = sdk
        .spaces()
        .cloud_test(cua_sdk::CloudTarget {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            ..Default::default()
        })
        .await
        .expect("sdk cloud_test");
    assert!(tested.ok);

    let connected = sdk
        .spaces()
        .cloud_connect(
            cua_sdk::CloudTarget {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            true,
            None,
            None,
        )
        .await
        .expect("sdk cloud_connect");
    assert_eq!(connected.provider.status, "connected");

    let sb = sdk
        .sandboxes()
        .create(cua_sdk::SandboxCreateOptions {
            on: Some("aliyun-ecs".into()),
            image: "linux".into(),
            runtime: Some("native".into()),
            name: Some("sdk-cli-parity".into()),
            ..Default::default()
        })
        .await
        .expect("sdk create");
    let spacesd = sb.spacesd(None).await.expect("sdk spacesd");
    let exec_out = spacesd
        .sh("echo parity-ok".into(), None)
        .await
        .expect("sdk sh");
    assert!(
        String::from_utf8_lossy(&exec_out.stdout).contains("parity-ok"),
        "{:?}",
        exec_out
    );

    // Verify CLI reading same daemon/CUA_HOME sees identical state and cleans up.
    let cli_ls = w.run_raw(&["sb", "ls", "--json"]).await;
    cli_ls.ok();
    assert!(cli_ls.stdout.contains("sdk-cli-parity"));

    w.run_raw(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

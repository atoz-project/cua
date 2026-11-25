// SPDX-License-Identifier: MIT

use aliyun_ecs_byoc_e2e::fake_aliyun::{
    BootFailMode, FakeImage, FakeInstance, FakeVSwitch, FakeVpc,
};
use aliyun_ecs_byoc_e2e::{AliyunWorld, decode_user_data_scripts, make_tags};
use serde_json::json;

#[tokio::test]
async fn t3_01() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("static-relay-secret");
    {
        let mut f = w.aliyun.lock().unwrap();
        for id in ["m-win-base", "m-win11-override"] {
            f.add_image(FakeImage {
                image_id: id.into(),
                image_name: id.into(),
                os_type: "windows".into(),
                arch: "x86_64".into(),
                status: "Available".into(),
                owner_alias: "self".into(),
                region_id: "cn-hangzhou".into(),
                ..Default::default()
            });
        }
    }
    let mirror_url = w.mirror.windows_url();
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--relay-mode",
            "static",
            "--relay-url",
            &w.relay.url,
            "--relay-token-stdin",
            "--windows-image-id",
            "m-win-base",
            "--spacesd-download-url",
            &mirror_url,
            "--json",
        ],
        "LTAI_TEST_AK:secret123\nstatic-relay-secret\n",
    )
    .await
    .ok();

    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--cloud-image-id",
        "m-win11-override",
        "--name",
        "t3-win",
        "--json",
    ])
    .await
    .ok();

    {
        let f = w.aliyun.lock().unwrap();
        let inst = f.instances.values().next().unwrap();
        assert_eq!(inst.image_id, "m-win11-override");
        assert_eq!(inst.http_tokens.as_deref(), Some("optional"));
        assert!(inst.user_data_decoded.starts_with("[powershell]\n"));
        assert!(!inst.user_data_decoded.contains("100.100.100.200"));
        assert!(inst.user_data_decoded.contains("Is64BitOperatingSystem"));
        assert!(inst.user_data_decoded.contains(&mirror_url));
    }

    w.run(&["sb", "exec", "t3-win", "echo", "win-static"])
        .await
        .ok();
    w.run(&["sb", "rm", "t3-win", "--force"]).await.ok();
    assert!(w.aliyun.lock().unwrap().instances.is_empty());
}

#[tokio::test]
async fn t3_02() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("static-relay-secret");
    {
        let mut f = w.aliyun.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-user".into(),
            region_id: "cn-hangzhou".into(),
            cidr_block: "10.0.0.0/16".into(),
            vpc_name: "user".into(),
            is_user_owned: true,
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-user".into(),
            vpc_id: "vpc-user".into(),
            zone_id: "cn-hangzhou-h".into(),
            region_id: "cn-hangzhou".into(),
            cidr_block: "10.0.1.0/24".into(),
            vswitch_name: "user".into(),
            is_user_owned: true,
            ..Default::default()
        });
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
            "--no-public-ip",
            "--relay-mode",
            "static",
            "--relay-url",
            &w.relay.url,
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
        "--runtime",
        "native",
        "--name",
        "t3-nat-priv",
        "--json",
    ])
    .await
    .ok();
    {
        let f = w.aliyun.lock().unwrap();
        assert_eq!(f.count_calls("CreateVpc"), 0);
        assert_eq!(f.count_calls("CreateVSwitch"), 0);
        let inst = f.instances.values().next().unwrap();
        assert_eq!(inst.internet_max_bandwidth_out.as_deref(), Some("0"));
        let ud = decode_user_data_scripts(&inst.user_data_decoded);
        assert!(!ud.contains("docker run"));
    }
    w.run(&["sb", "rm", "t3-nat-priv", "--force"]).await.ok();
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
    assert!(f.vpcs.contains_key("vpc-user"));
    assert!(f.vswitches.contains_key("vsw-user"));
}

#[tokio::test]
async fn t3_03() {
    let w = AliyunWorld::start().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.add_key("LTAI_WH_AK", "wh_secret_456");
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-ap".into(),
            region_id: "ap-southeast-1".into(),
            cidr_block: "10.8.0.0/16".into(),
            vpc_name: "ap".into(),
            is_user_owned: true,
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-ap".into(),
            vpc_id: "vpc-ap".into(),
            zone_id: "ap-southeast-1-h".into(),
            region_id: "ap-southeast-1".into(),
            cidr_block: "10.8.1.0/24".into(),
            vswitch_name: "ap".into(),
            is_user_owned: true,
            ..Default::default()
        });
    }
    w.write_aliyun_config(&json!({
        "current": "webhook_manager",
        "profiles": [{
            "name": "webhook_manager",
            "mode": "AK",
            "access_key_id": "LTAI_WH_AK",
            "access_key_secret": "wh_secret_456",
            "region_id": "ap-southeast-1"
        }]
    }));
    w.relay.add_static_token("static-relay-secret");

    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--profile",
            "webhook_manager",
            "--vpc-id",
            "vpc-ap",
            "--vswitch-id",
            "vsw-ap",
            "--max-size",
            "4x16",
            "--relay-mode",
            "static",
            "--relay-url",
            &w.relay.url,
            "--relay-token-stdin",
            "--json",
        ],
        "static-relay-secret\n",
    )
    .await
    .ok();

    let big = w
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
    assert_eq!(big.code, 2);

    w.run(&[
        "sb",
        "create",
        "windows",
        "--on",
        "aliyun-ecs",
        "--name",
        "ap-ok",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let run = f.calls_for("RunInstances").into_iter().last().unwrap();
    assert_eq!(run.access_key_id, "LTAI_WH_AK");
    assert!(run.host.starts_with("ecs.ap-southeast-1.aliyuncs.com"));
    w.assert_no_secrets_anywhere(&["wh_secret_456"]);
}

#[tokio::test]
async fn t3_04() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.aliyun
        .lock()
        .unwrap()
        .mark_zone_sold_out("cn-hangzhou-h", "OperationDenied.NoStock");
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
        "win-retry",
        "--json",
    ])
    .await
    .ok();
    let f = w.aliyun.lock().unwrap();
    let inst = f.instances.values().next().unwrap();
    assert_ne!(inst.zone_id, "cn-hangzhou-h");
    assert_eq!(f.authorize_sg_calls, 0);
}

#[tokio::test]
async fn t3_05() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    let (_url, _tok) = w.start_daemon().await;

    w.run_raw_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.run_raw(&[
        "spaces",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--name",
        "daemon-sp",
        "--json",
    ])
    .await
    .ok();

    let st = w
        .run_raw(&["cloud", "status", "aliyun-ecs", "--json"])
        .await;
    st.ok();
    assert_eq!(st.json()["providers"][0]["running"], 1);
    let audit = w
        .run_raw(&["cloud", "audit", "--cloud", "aliyun-ecs", "--json"])
        .await;
    audit.ok();
    assert!(!audit.json().as_array().unwrap().is_empty());
    w.assert_no_secrets_in_non_secret_files(&["secret123"]);
}

#[tokio::test]
async fn t3_06() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    let (_url, _tok) = w.start_daemon().await;
    w.run_raw_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    let (r1, r2, r3) = tokio::join!(
        w.run_raw(&[
            "sb",
            "create",
            "windows",
            "--on",
            "aliyun-ecs",
            "--name",
            "mix-w",
            "--json"
        ]),
        w.run_raw(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "native",
            "--name",
            "mix-ln",
            "--json",
        ]),
        w.run_raw(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "docker",
            "--name",
            "mix-ld",
            "--json",
        ]),
    );
    r1.ok();
    r2.ok();
    r3.ok();

    let f = w.aliyun.lock().unwrap();
    assert_eq!(f.instances.len(), 3);
    assert_eq!(
        f.calls_for("CreateVpc")
            .into_iter()
            .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
            .count(),
        1
    );
    assert_eq!(
        f.calls_for("CreateSecurityGroup")
            .into_iter()
            .filter(|c| c.params.get("DryRun").map(String::as_str) != Some("true"))
            .count(),
        1
    );
}

#[tokio::test]
async fn t3_07() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.add_image(FakeImage {
            image_id: "m-custom-ok".into(),
            image_name: "m-custom-ok".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "self".into(),
            region_id: "cn-hangzhou".into(),
            ..Default::default()
        });
        f.boot_fail = Some(BootFailMode::StopImmediately);
    }
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--budget",
            "10",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();

    let fail = w
        .run(&[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--cloud-image-id",
            "m-custom-ok",
            "--name",
            "retry-ok",
        ])
        .await;
    assert_ne!(fail.code, 0);
    w.aliyun.lock().unwrap().boot_fail = None;

    w.run(&[
        "sb",
        "create",
        "linux",
        "--on",
        "aliyun-ecs",
        "--cloud-image-id",
        "m-custom-ok",
        "--name",
        "retry-ok",
        "--json",
    ])
    .await
    .ok();
    assert_eq!(w.aliyun.lock().unwrap().instances.len(), 1);
}

#[tokio::test]
async fn t3_08() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("static-relay-secret");
    w.aliyun.lock().unwrap().add_image(FakeImage {
        image_id: "m-slim-custom".into(),
        image_name: "m-slim-custom".into(),
        os_type: "linux".into(),
        arch: "x86_64".into(),
        status: "Available".into(),
        owner_alias: "self".into(),
        region_id: "cn-hangzhou".into(),
        ..Default::default()
    });
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--linux-image-id",
            "m-slim-custom",
            "--no-public-ip",
            "--relay-mode",
            "static",
            "--relay-url",
            &w.relay.url,
            "--relay-token-stdin",
            "--json",
        ],
        "LTAI_TEST_AK:secret123\nstatic-relay-secret\n",
    )
    .await
    .ok();

    w.run(&[
        "spaces",
        "create",
        "linux-slim",
        "--on",
        "aliyun-ecs",
        "--name",
        "sp-slim",
        "--json",
    ])
    .await
    .ok();
    {
        let f = w.aliyun.lock().unwrap();
        let inst = f.instances.values().next().unwrap();
        assert_eq!(inst.image_id, "m-slim-custom");
        assert_eq!(inst.internet_max_bandwidth_out.as_deref(), Some("0"));
    }
    w.run(&["spaces", "stop", "sp-slim"]).await.ok();
    w.run(&["spaces", "start", "sp-slim"]).await.ok();
    w.run(&["spaces", "delete", "sp-slim", "--force"])
        .await
        .ok();
}

#[tokio::test]
async fn t3_09() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    {
        let mut f = w.aliyun.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-user".into(),
            region_id: "cn-hangzhou".into(),
            cidr_block: "10.0.0.0/16".into(),
            vpc_name: "user".into(),
            is_user_owned: true,
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-user".into(),
            vpc_id: "vpc-user".into(),
            zone_id: "cn-hangzhou-h".into(),
            region_id: "cn-hangzhou".into(),
            cidr_block: "10.0.1.0/24".into(),
            vswitch_name: "user".into(),
            is_user_owned: true,
            ..Default::default()
        });
        for (id, tags) in [
            (
                "i-foreign",
                make_tags(&[("cua-managed", "true"), ("cua-owner", "other")]),
            ),
            ("i-untagged", Default::default()),
        ] {
            f.seed_instance(FakeInstance {
                instance_id: id.into(),
                instance_name: id.into(),
                region_id: "cn-hangzhou".into(),
                zone_id: "cn-hangzhou-h".into(),
                vpc_id: "vpc-user".into(),
                vswitch_id: "vsw-user".into(),
                instance_type: "ecs.e-c1m2.large".into(),
                image_id: "ubuntu".into(),
                status: "Running".into(),
                instance_charge_type: "PostPaid".into(),
                stopped_mode: "StopCharging".into(),
                tags,
                ..Default::default()
            });
        }
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
        "cua-l",
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
        "cua-w",
        "--json",
    ])
    .await
    .ok();

    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();

    let f = w.aliyun.lock().unwrap();
    assert_eq!(f.instances.len(), 2);
    assert!(f.instances.contains_key("i-foreign"));
    assert!(f.instances.contains_key("i-untagged"));
    assert!(f.vpcs.contains_key("vpc-user"));
    assert!(f.vswitches.contains_key("vsw-user"));
}

#[tokio::test]
async fn t3_10() {
    let mut w = AliyunWorld::start().await;
    w.auth_login().await;
    w.run_with_stdin(
        &["cloud", "connect", "aliyun-ecs", "--token-stdin", "--json"],
        "LTAI_TEST_AK:secret123\n",
    )
    .await
    .ok();
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--json"])
        .await
        .ok();

    w.relay.add_static_token("static-relay-secret");
    let dir_mir = format!("{}/", w.mirror.url);
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--relay-mode",
            "static",
            "--relay-url",
            &w.relay.url,
            "--relay-token-stdin",
            "--spacesd-download-url",
            &dir_mir,
            "--json",
        ],
        "LTAI_TEST_AK:secret123\nstatic-relay-secret\n",
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
        "sw-win",
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
        "--runtime",
        "native",
        "--name",
        "sw-lin",
        "--json",
    ])
    .await
    .ok();
    assert_eq!(w.relay.static_machines().len(), 2);
}

#[tokio::test]
async fn t3_scp_delete_forbidden_lifecycle() {
    let w = AliyunWorld::start().await;
    w.relay.add_static_token("static-relay-secret");
    {
        let mut f = w.aliyun.lock().unwrap();
        f.enforce_cua_managed_tag_condition = true;
        f.forbidden_actions.insert("ecs:DeleteInstance".into());
        f.add_image(FakeImage {
            image_id: "m-win11-scp".into(),
            image_name: "m-win11-scp".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "self".into(),
            region_id: "cn-hangzhou".into(),
            ..Default::default()
        });
    }
    let mirror_url = w.mirror.windows_url();
    w.run_with_stdin(
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--relay-mode",
            "static",
            "--relay-url",
            &w.relay.url,
            "--relay-token-stdin",
            "--windows-image-id",
            "m-win11-scp",
            "--spacesd-download-url",
            &mirror_url,
            "--json",
        ],
        "LTAI_TEST_AK:secret123\nstatic-relay-secret\n",
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
        "t3-scp-win",
        "--json",
    ])
    .await
    .ok();

    w.run(&["sb", "rm", "t3-scp-win", "--force"]).await.ok();
    {
        let f = w.aliyun.lock().unwrap();
        let inst = f
            .instances
            .values()
            .next()
            .expect("decommissioned instance");
        assert_eq!(inst.status, "Stopped");
        assert_eq!(inst.stopped_mode, "StopCharging");
        assert!(inst.auto_release_time.is_some());
        assert_eq!(
            inst.tags.get("cua-decommissioned").map(String::as_str),
            Some("true")
        );
    }

    let ls = w.run(&["sb", "ls", "--json"]).await;
    ls.ok();
    assert!(!ls.stdout.contains("t3-scp-win"), "{}", ls.stdout);

    let swept = w
        .run(&[
            "cloud",
            "sweep",
            "aliyun-ecs",
            "--all",
            "--delete",
            "--json",
        ])
        .await;
    swept.ok();
    let swept_json = swept.json();
    let rows = swept_json["resources"].as_array().expect("resources array");
    assert!(!rows.is_empty(), "{swept_json}");
    for row in rows {
        assert_eq!(row["action"].as_str(), Some("keep"), "{row}");
        assert!(
            row["reason"]
                .as_str()
                .is_some_and(|r| r.contains("AutoReleaseTime")),
            "{row}"
        );
    }

    let disc_hold = w
        .run(&["cloud", "disconnect", "aliyun-ecs", "--delete"])
        .await;
    assert_ne!(disc_hold.code, 0);
    assert!(
        disc_hold.combined().contains("AutoReleaseTime"),
        "{}",
        disc_hold.combined()
    );

    w.aliyun.lock().unwrap().instances.clear();
    w.run(&["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"])
        .await
        .ok();
    let f = w.aliyun.lock().unwrap();
    assert!(f.vpcs.is_empty() && f.vswitches.is_empty() && f.security_groups.is_empty());
}

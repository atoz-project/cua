// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! CLI-owned integration tests for Static Relay Mode Spaces:
//! - `--token`, `CUA_ENV_TOKEN`, `--name`, `--host` rejection, plain-MCP fallback.
//! - `cua sb exec` by `relay:<id>`, bare `<id>`, name, and URL over HTTPS with
//!   zero Account Relay hits and zero port-443 plaintext leaks.
//! - Sibling `cua spaces rm` isolation and `cua spaces ls --json`.
//! - Offline daemon-mode `cua spaces share`/`unshare`/`shares` refusal without
//!   interactive prompt or Account Relay calls, plus `relay-register` non-regression.

mod common;

use common::Home;
use cua_sandbox_core::testing::McpTestServer;
use cua_spacesd_client::testing::{
    HttpSpy, HttpsConnectProxy, MockAuth, MockServer, StaticRelayRouter, write_tls_fixture,
};
use std::time::Duration;

const MACHINE_A: &str = "cli-alpha-000001";
const MACHINE_B: &str = "cli-beta-0000002";
const TOKEN_A: &str = "cli-static-token-alpha-secret";
const TOKEN_B: &str = "cli-static-token-beta-secret";

fn seed_account_auth(home: &Home, token: &str) {
    std::fs::create_dir_all(home.cua_home()).unwrap();
    std::fs::write(
        home.cua_home().join("credentials.json"),
        format!(
            r#"{{"access_token":"{token}","refresh_token":null,"expires_at":"2099-01-01T00:00:00Z","token_type":"Bearer"}}"#
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn cli_static_relay_https_flags_exec_ls_rm_and_mcp_fallback_zero_leaks() {
    let srv_a = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let srv_b = MockServer::start(MockAuth {
        token: Some(TOKEN_B.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_B}")),
    })
    .await;

    let router =
        StaticRelayRouter::start(&[(MACHINE_A, srv_a.addr), (MACHINE_B, srv_b.addr)]).await;

    let tls_dir = tempfile::tempdir().unwrap();
    write_tls_fixture(tls_dir.path(), &["relay.invalid"]);
    let proxy = HttpsConnectProxy::start(tls_dir.path(), &[("relay.invalid", router.addr)]).await;
    let (account_spy_url, account_spy) = HttpSpy::start().await;

    let mut home = Home::new();
    home.set(
        "SSL_CERT_FILE",
        tls_dir.path().join("roots.pem").display().to_string(),
    );
    home.set("HTTPS_PROXY", proxy.proxy_url());
    home.set("HTTP_PROXY", proxy.proxy_url());
    home.set("NO_PROXY", "127.0.0.1,localhost");
    home.set("CUA_RELAY_URL", &account_spy_url);
    seed_account_auth(&home, "spy-account-jwt");

    // CLI flag/env rejections leave stores untouched.
    let missing_tok = home
        .run(&[
            "--embedded",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_A}"),
        ])
        .await;
    assert_ne!(missing_tok.code, 0, "{missing_tok:?}");
    assert!(
        missing_tok.stderr.contains("--token") && missing_tok.stderr.contains("CUA_ENV_TOKEN"),
        "{missing_tok:?}"
    );

    let mut home_blank_tok = Home::new();
    home_blank_tok.env = home.env.clone();
    home_blank_tok.set("CUA_ENV_TOKEN", "   ");
    let blank_tok = home_blank_tok
        .run(&[
            "--embedded",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_A}"),
        ])
        .await;
    assert_ne!(blank_tok.code, 0, "{blank_tok:?}");
    assert!(
        blank_tok.stderr.contains("--token") && blank_tok.stderr.contains("CUA_ENV_TOKEN"),
        "{blank_tok:?}"
    );

    let bad_host = home
        .run(&[
            "--embedded",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_A}"),
            "--host",
            "--token",
            TOKEN_A,
        ])
        .await;
    assert_ne!(bad_host.code, 0, "{bad_host:?}");
    assert!(bad_host.stderr.contains("--host"), "{bad_host:?}");
    assert!(!home.cua_home().join("spaces.json").exists());
    assert!(!home.cua_home().join("direct-hosts.json").exists());

    // Register via `--token` + `--name`, via `CUA_ENV_TOKEN`, and via plain-MCP fallback.
    let json_a = home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_A}"),
            "--token",
            TOKEN_A,
            "--name",
            "alpha-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(json_a["id"], format!("relay:{MACHINE_A}"));
    assert_eq!(json_a["name"], "alpha-cli");
    assert_eq!(json_a["provider"], "relay");

    let mut home_env_tok = Home::new();
    home_env_tok.env = home.env.clone();
    home_env_tok.set("CUA_ENV_TOKEN", TOKEN_B);
    let json_b = home_env_tok
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_B}"),
            "--name",
            "beta-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(json_b["id"], format!("relay:{MACHINE_B}"));
    assert_eq!(json_b["name"], "beta-cli");
    assert_eq!(json_b["provider"], "relay");

    let mcp = McpTestServer::start("/m/tools").await.unwrap();
    let json_mcp = home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &format!("{}/m/tools/mcp", mcp.url),
            "--name",
            "mcp-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(json_mcp["provider"], "direct");
    assert!(json_mcp["id"].as_str().unwrap().starts_with("direct:"));

    // `cua sb exec` resolves by `relay:<id>`, bare `<id>`, name, and HTTPS URL.
    for (target, marker) in [
        (format!("relay:{MACHINE_A}"), "from-qualified"),
        (MACHINE_B.to_string(), "from-bare-id"),
        ("alpha-cli".to_string(), "from-name"),
        (format!("https://relay.invalid/m/{MACHINE_B}"), "from-url"),
    ] {
        let out = home
            .run(&["--embedded", "sb", "exec", &target, "echo", marker])
            .await;
        out.ok();
        assert!(out.stdout.contains(marker), "{target}: {out:?}");
    }

    // Sibling `cua spaces rm` removes only MACHINE_A and leaves MACHINE_B operational.
    let rm_json = home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "rm",
            &format!("relay:{MACHINE_A}"),
        ])
        .await
        .ok()
        .json();
    assert_eq!(rm_json["removed"]["id"], format!("relay:{MACHINE_A}"));

    let exec_b = home
        .run(&["--embedded", "sb", "exec", "beta-cli", "echo", "sibling-ok"])
        .await;
    exec_b.ok();
    assert!(exec_b.stdout.contains("sibling-ok"), "{exec_b:?}");

    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 requests during Static Relay CLI flow: {:?}",
        account_spy.snapshot()
    );
    assert!(
        proxy.leaks().is_empty(),
        "Port-443 plaintext spy caught leaks: {:?}",
        proxy.leaks()
    );

    // Without Account auth, second `rm` fails (NotFound) and `ls` lists remaining Spaces.
    std::fs::remove_file(home.cua_home().join("credentials.json")).unwrap();
    let rm_again = home
        .run(&["--embedded", "spaces", "rm", &format!("relay:{MACHINE_A}")])
        .await;
    assert_ne!(rm_again.code, 0, "second rm must fail: {rm_again:?}");
    let ls_json = home
        .run(&["--json", "spaces", "ls", "--no-size"])
        .await
        .ok()
        .json();
    let ids: Vec<&str> = ls_json["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert!(
        !ids.contains(&format!("relay:{MACHINE_A}").as_str()),
        "{ids:?}"
    );
    assert!(
        ids.contains(&format!("relay:{MACHINE_B}").as_str()),
        "{ids:?}"
    );
    assert!(ids.iter().any(|id| id.starts_with("direct:")), "{ids:?}");
}

#[tokio::test]
async fn cli_offline_share_refusal_in_daemon_mode_and_relay_register_non_regression() {
    const LOOPBACK: &str = if cfg!(unix) { "off" } else { "127.0.0.1:0" };

    let (account_spy_url, account_spy) = HttpSpy::start().await;
    let srv = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let url = format!("{}/m/{MACHINE_A}", srv.url());

    let mut home = Home::new();
    home.set("CUA_RELAY_URL", &account_spy_url);
    home.set("CUA_DAEMON_NO_RELAY", "1");
    seed_account_auth(&home, "spy-account-jwt");

    home.run(&[
        "--embedded",
        "--json",
        "spaces",
        "add",
        &url,
        "--token",
        TOKEN_A,
        "--name",
        "offline-alpha",
    ])
    .await
    .ok();

    // Stop the mock server so the Static Relay Space is genuinely offline.
    drop(srv);

    home.run(&["daemon", "start", "--loopback", LOOPBACK])
        .await
        .ok();

    let cases: &[&[&str]] = &[
        &["spaces", "share", "offline-alpha", "bob@example.com"],
        &[
            "spaces",
            "share",
            "offline-alpha",
            "bob@example.com",
            "--yes",
        ],
        &[
            "spaces",
            "share",
            "offline-alpha",
            "team:Design Team",
            "--yes",
        ],
        &["spaces", "unshare", "offline-alpha", "bob@example.com"],
        &["spaces", "unshare", "offline-alpha", "team:Design Team"],
        &["spaces", "unshare", "offline-alpha", "--all"],
        &["spaces", "shares", "offline-alpha"],
    ];

    let mut failures = Vec::new();
    for args in cases {
        let out = home.run(args).await;
        if out.code == 0
            || !out.stderr.contains("Static Relay")
            || !out.stderr.contains("Account Relay")
            || out.stderr.contains("stdin is not a terminal")
        {
            failures.push(format!("{args:?} -> {out:?}"));
        }
    }

    home.run(&["daemon", "stop"]).await.ok();

    assert!(
        failures.is_empty(),
        "daemon-mode offline share refusals failed:\n{}",
        failures.join("\n")
    );
    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 hits in daemon mode for offline Static Relay share/unshare/shares: {:?}",
        account_spy.snapshot()
    );

    // Non-regression: Account Relay Mode `cua spaces relay-register` / `relay-unregister` on direct Space.
    let fake_relay = cua_host::testing::FakeRelay::start().await;
    fake_relay.add_account("ada-token", "ada", Some("ada@example.com"));
    let direct_srv = MockServer::start(MockAuth::default()).await;
    direct_srv.state.advertise(&["relay_attach"]);
    let state = direct_srv.state.clone();
    let relay_bg = fake_relay.clone();
    tokio::spawn(async move {
        for _ in 0..400 {
            if let Some(a) = state.relay_attached.lock().unwrap().clone() {
                relay_bg.set_online(&a.machine_id, true, "0.1.0");
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let mut acct_home = Home::new();
    acct_home.set("CUA_RELAY_URL", &fake_relay.url);
    seed_account_auth(&acct_home, "ada-token");

    let added_direct = acct_home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &direct_srv.url(),
            "--name",
            "direct-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(added_direct["provider"], "direct");

    let reg = acct_home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "relay-register",
            "direct-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(reg["online"], true, "{reg}");
    assert!(
        reg["relay_space"].as_str().unwrap().starts_with("relay:"),
        "{reg}"
    );

    let unreg = acct_home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "relay-unregister",
            "direct-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(unreg["unregistered"], true, "{unreg}");
}

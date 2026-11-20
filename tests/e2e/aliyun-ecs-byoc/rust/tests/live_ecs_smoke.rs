// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use aliyun_ecs_byoc_e2e::resolve_cua_bin;

async fn run_live_cua(home: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = tokio::process::Command::new(resolve_cua_bin());
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), home.display().to_string());
    env.insert("USERPROFILE".to_string(), home.display().to_string());
    env.insert(
        "CUA_HOME".to_string(),
        home.join(".cua").display().to_string(),
    );
    env.insert("CUA_CREDENTIAL_STORE".to_string(), "file".to_string());
    env.insert("CUA_NO_BROWSER".to_string(), "1".to_string());
    env.insert("CUA_TELEMETRY".to_string(), "0".to_string());
    env.insert("CUA_TELEMETRY_FORBID_NETWORK".to_string(), "1".to_string());
    cmd.envs(env)
        .args(["--embedded"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = cmd.spawn().expect("spawn live cua");
    let out = tokio::time::timeout(Duration::from_secs(900), child.wait_with_output())
        .await
        .expect("live cua command timeout")
        .expect("wait_with_output");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Live Alibaba Cloud ECS smoke test (#9):
/// - Linux Docker-on-VM
/// - Linux Direct VM (`--runtime native`)
/// - Windows Direct VM (`--runtime native`: Session >= 1, AutoLogon, Event ID 24 `tscon`)
/// - Full teardown + zero leftover resources check
#[tokio::test]
#[ignore = "live: creates real Alibaba Cloud ECS resources (set CUA_E2E_ALIYUN_LIVE=1 and CUA_E2E_ALIYUN_PROFILE)"]
async fn live_ecs_smoke() {
    if std::env::var("CUA_E2E_ALIYUN_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping live_ecs_smoke: set CUA_E2E_ALIYUN_LIVE=1 to opt in");
        return;
    }

    let profile = std::env::var("CUA_E2E_ALIYUN_PROFILE")
        .or_else(|_| std::env::var("ALIYUN_PROFILE"))
        .unwrap_or_else(|_| "oauth".to_string());
    let region =
        std::env::var("CUA_E2E_ALIYUN_REGION").unwrap_or_else(|_| "cn-hangzhou".to_string());
    let run_id = std::env::var("CUA_E2E_RUN").unwrap_or_else(|_| "manual".to_string());

    let dir = tempfile::tempdir().expect("tempdir");
    // Copy host ~/.aliyun/config.json into isolated HOME so the selected profile works hermetically.
    if let Some(real_home) = std::env::var_os("HOME") {
        let src_cfg = std::path::Path::new(&real_home).join(".aliyun/config.json");
        if src_cfg.exists() {
            let dst_dir = dir.path().join(".aliyun");
            std::fs::create_dir_all(&dst_dir).expect("mkdir .aliyun");
            std::fs::copy(&src_cfg, dst_dir.join("config.json")).expect("copy .aliyun/config.json");
        }
    }

    // 1. Test & connect
    let (rc, out, err) = run_live_cua(
        dir.path(),
        &[
            "cloud",
            "test",
            "aliyun-ecs",
            "--profile",
            &profile,
            "--region",
            &region,
            "--json",
        ],
    )
    .await;
    assert_eq!(rc, 0, "cloud test failed: out={out}\nerr={err}");

    let (rc, out, err) = run_live_cua(
        dir.path(),
        &[
            "cloud",
            "connect",
            "aliyun-ecs",
            "--profile",
            &profile,
            "--region",
            &region,
            "--ttl-hours",
            "1",
            "--json",
        ],
    )
    .await;
    assert_eq!(rc, 0, "cloud connect failed: out={out}\nerr={err}");

    // Ensure teardown runs even on assertion failures inside smoke steps.
    let linux_docker_name = format!("cua-e2e-{run_id}-ld");
    let linux_native_name = format!("cua-e2e-{run_id}-ln");
    let windows_native_name = format!("cua-e2e-{run_id}-wn");

    // 2. Linux Docker-on-VM
    let (rc, out, err) = run_live_cua(
        dir.path(),
        &[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "docker",
            "--name",
            &linux_docker_name,
            "--json",
        ],
    )
    .await;
    assert_eq!(rc, 0, "linux docker create failed: out={out}\nerr={err}");

    // 3. Linux Direct VM
    let (rc, out, err) = run_live_cua(
        dir.path(),
        &[
            "sb",
            "create",
            "linux",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "native",
            "--name",
            &linux_native_name,
            "--json",
        ],
    )
    .await;
    assert_eq!(rc, 0, "linux native create failed: out={out}\nerr={err}");

    // 4. Windows Direct VM (Session >= 1, AutoLogon, Event ID 24 tscon)
    let (rc, out, err) = run_live_cua(
        dir.path(),
        &[
            "sb",
            "create",
            "windows",
            "--on",
            "aliyun-ecs",
            "--runtime",
            "native",
            "--name",
            &windows_native_name,
            "--json",
        ],
    )
    .await;
    assert_eq!(rc, 0, "windows native create failed: out={out}\nerr={err}");

    let (rc, out, err) = run_live_cua(
        dir.path(),
        &[
            "sb",
            "exec",
            &windows_native_name,
            "powershell",
            "-Command",
            "query session; Get-ScheduledTask | Where-Object TaskName -like '*cua*'",
        ],
    )
    .await;
    assert_eq!(rc, 0, "windows session probe failed: out={out}\nerr={err}");

    // 5. Full teardown
    for name in [&linux_docker_name, &linux_native_name, &windows_native_name] {
        let _ = run_live_cua(dir.path(), &["sb", "rm", name, "--force"]).await;
    }
    let (rc, out, err) = run_live_cua(
        dir.path(),
        &[
            "cloud",
            "sweep",
            "aliyun-ecs",
            "--all",
            "--delete",
            "--json",
        ],
    )
    .await;
    assert_eq!(rc, 0, "sweep failed: out={out}\nerr={err}");

    let (rc, out, err) = run_live_cua(
        dir.path(),
        &["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"],
    )
    .await;
    assert_eq!(rc, 0, "disconnect --delete failed: out={out}\nerr={err}");
}

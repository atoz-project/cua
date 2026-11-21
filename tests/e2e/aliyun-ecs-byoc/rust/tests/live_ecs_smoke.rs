// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use aliyun_ecs_byoc_e2e::{encode_powershell_utf16le_b64, resolve_cua_bin};
use futures_util::FutureExt as _;
use tokio::io::AsyncWriteExt;

fn build_live_env(home: &Path) -> HashMap<String, String> {
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
    env
}

const LIVE_CREATE_TIMEOUT: Duration = Duration::from_secs(1200);
const LIVE_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(600);
const LIVE_CMD_TIMEOUT: Duration = Duration::from_secs(300);

async fn run_live_cua(
    home: &Path,
    args: &[&str],
    stdin_data: Option<&str>,
    timeout: Duration,
) -> (i32, String, String) {
    let mut cmd = tokio::process::Command::new(resolve_cua_bin());
    cmd.envs(build_live_env(home))
        .args(["--embedded"])
        .args(args)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().expect("spawn live cua");
    if let Some(data) = stdin_data
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin
            .write_all(data.as_bytes())
            .await
            .expect("write live stdin");
        stdin.shutdown().await.ok();
    }
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "live cua command timeout after {}s: cua --embedded {}",
                timeout.as_secs(),
                args.join(" ")
            )
        })
        .expect("wait_with_output");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_live_cua_sync(home: &Path, args: &[&str]) -> (i32, String, String) {
    match std::process::Command::new(resolve_cua_bin())
        .envs(build_live_env(home))
        .args(["--embedded"])
        .args(args)
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) => (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        Err(err) => (-1, String::new(), err.to_string()),
    }
}

struct LiveTeardownGuard {
    home: PathBuf,
    names: Vec<String>,
    armed: bool,
}

impl LiveTeardownGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LiveTeardownGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        eprintln!("live_ecs_smoke: Drop guard executing fallback teardown...");
        for name in &self.names {
            let _ = run_live_cua_sync(&self.home, &["sb", "rm", name, "--force"]);
        }
        let _ = run_live_cua_sync(
            &self.home,
            &[
                "cloud",
                "sweep",
                "aliyun-ecs",
                "--all",
                "--delete",
                "--json",
            ],
        );
        let _ = run_live_cua_sync(
            &self.home,
            &["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"],
        );
    }
}

async fn run_teardown(home: &Path, names: &[String]) -> (i32, String, String, i32, String, String) {
    eprintln!("[live_ecs_smoke] step 5: teardown starting");
    record_smoke_owner(home);
    for name in names {
        eprintln!("[live_ecs_smoke] step 5: sb rm {name} --force");
        let _ = run_live_cua(home, &["sb", "rm", name, "--force"], None, LIVE_CMD_TIMEOUT).await;
    }
    eprintln!("[live_ecs_smoke] step 5: cloud sweep aliyun-ecs --all --delete");
    let (sw_rc, sw_out, sw_err) = run_live_cua(
        home,
        &[
            "cloud",
            "sweep",
            "aliyun-ecs",
            "--all",
            "--delete",
            "--json",
        ],
        None,
        LIVE_CMD_TIMEOUT,
    )
    .await;
    eprintln!("[live_ecs_smoke] step 5: cloud disconnect aliyun-ecs --delete");
    let (dc_rc, dc_out, dc_err) = run_live_cua(
        home,
        &["cloud", "disconnect", "aliyun-ecs", "--delete", "--json"],
        None,
        LIVE_DISCONNECT_TIMEOUT,
    )
    .await;
    eprintln!("[live_ecs_smoke] step 5: teardown done (sweep_rc={sw_rc} disconnect_rc={dc_rc})");
    (sw_rc, sw_out, sw_err, dc_rc, dc_out, dc_err)
}

enum RelayAuth {
    Static {
        url: String,
        mode: String,
        token: String,
    },
    AccountCredentials,
}

fn prepare_relay_auth(isolated_home: &Path) -> RelayAuth {
    let relay_url = std::env::var("CUA_E2E_RELAY_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let relay_token = std::env::var("CUA_E2E_RELAY_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let (Some(url), Some(token)) = (relay_url, relay_token) {
        let mode = std::env::var("CUA_E2E_RELAY_MODE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "static".to_string());
        return RelayAuth::Static { url, mode, token };
    }

    let candidate_cua_homes: Vec<PathBuf> = [
        std::env::var_os("CUA_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cua")),
    ]
    .into_iter()
    .flatten()
    .collect();

    for src_cua in candidate_cua_homes {
        let creds = src_cua.join("credentials.json");
        if creds.exists() {
            let dst_cua = isolated_home.join(".cua");
            std::fs::create_dir_all(&dst_cua).expect("mkdir isolated .cua");
            let dst_creds = dst_cua.join("credentials.json");
            std::fs::copy(&creds, &dst_creds).expect("copy credentials.json");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ =
                    std::fs::set_permissions(&dst_creds, std::fs::Permissions::from_mode(0o600));
            }
            return RelayAuth::AccountCredentials;
        }
    }

    panic!(
        "live_ecs_smoke requires relay auth in isolated CUA_HOME: either sign in first \
         (providing ~/.cua/credentials.json) OR set CUA_E2E_RELAY_URL + CUA_E2E_RELAY_TOKEN \
         (and optional CUA_E2E_RELAY_MODE=static)"
    );
}

fn record_smoke_owner(isolated_home: &Path) {
    static RECORDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if RECORDED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let state_path = isolated_home.join(".cua/cloud/state.json");
    if let Ok(raw) = std::fs::read_to_string(&state_path)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw)
        && let Some(owner) = v["owner_id"].as_str().filter(|s| !s.is_empty())
    {
        RECORDED.store(true, std::sync::atomic::Ordering::Relaxed);
        println!("CUA_E2E_SMOKE_OWNER={owner}");
        if let Ok(out_file) = std::env::var("CUA_E2E_OWNER_FILE")
            && !out_file.trim().is_empty()
        {
            if let Some(parent) = Path::new(&out_file).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&out_file, owner);
        }
    }
}

/// Live Alibaba Cloud ECS smoke test (#9):
/// - Linux Docker-on-VM (create + `sb exec` probe)
/// - Linux Direct VM (`--runtime native`: create + `sb exec` systemd probe)
/// - Windows Direct VM (`--runtime native`: Session >= 1, AutoLogon, Event ID 24 `tscon`)
/// - Unconditional panic-safe teardown + zero leftover resources check
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
        let src_cfg = Path::new(&real_home).join(".aliyun/config.json");
        if src_cfg.exists() {
            let dst_dir = dir.path().join(".aliyun");
            std::fs::create_dir_all(&dst_dir).expect("mkdir .aliyun");
            std::fs::copy(&src_cfg, dst_dir.join("config.json")).expect("copy .aliyun/config.json");
        }
    }
    let relay_auth = prepare_relay_auth(dir.path());

    let linux_docker_name = format!("cua-e2e-{run_id}-ld");
    let linux_native_name = format!("cua-e2e-{run_id}-ln");
    let windows_native_name = format!("cua-e2e-{run_id}-wn");
    let all_names = vec![
        linux_docker_name.clone(),
        linux_native_name.clone(),
        windows_native_name.clone(),
    ];
    let mut guard = LiveTeardownGuard {
        home: dir.path().to_path_buf(),
        names: all_names.clone(),
        armed: true,
    };

    let smoke_result = std::panic::AssertUnwindSafe(async {
        // 1. Test & connect
        eprintln!("[live_ecs_smoke] step 1: cloud test aliyun-ecs (profile={profile}, region={region})");
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
            None,
            LIVE_CMD_TIMEOUT,
        )
        .await;
        assert_eq!(rc, 0, "cloud test failed: out={out}\nerr={err}");
        eprintln!("[live_ecs_smoke] step 1: cloud test passed");

        let mut connect_args = vec![
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
        ];
        let stdin_token: Option<String> = match &relay_auth {
            RelayAuth::Static { url, mode, token } => {
                connect_args.extend_from_slice(&[
                    "--relay-url",
                    url,
                    "--relay-mode",
                    mode,
                    "--relay-token-stdin",
                ]);
                Some(format!("{token}\n"))
            }
            RelayAuth::AccountCredentials => None,
        };
        eprintln!("[live_ecs_smoke] step 1b: cloud connect aliyun-ecs");
        let (rc, out, err) = run_live_cua(
            dir.path(),
            &connect_args,
            stdin_token.as_deref(),
            LIVE_CMD_TIMEOUT,
        )
        .await;
        assert_eq!(rc, 0, "cloud connect failed: out={out}\nerr={err}");
        eprintln!("[live_ecs_smoke] step 1b: cloud connect passed");

        // 2. Linux Docker-on-VM + guest probe
        eprintln!("[live_ecs_smoke] step 2: sb create linux --runtime docker ({linux_docker_name})");
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
            None,
            LIVE_CREATE_TIMEOUT,
        )
        .await;
        record_smoke_owner(dir.path());
        assert_eq!(rc, 0, "linux docker create failed: out={out}\nerr={err}");
        eprintln!("[live_ecs_smoke] step 2: linux docker created; running guest probe");
        let (rc, out, err) = run_live_cua(
            dir.path(),
            &["sb", "exec", &linux_docker_name, "sh", "-c", "uname -a && id"],
            None,
            LIVE_CMD_TIMEOUT,
        )
        .await;
        assert_eq!(rc, 0, "linux docker exec failed: out={out}\nerr={err}");
        println!("[live_ecs_smoke] linux docker probe:\n{out}");
        assert!(
            out.contains("Linux"),
            "unexpected linux docker exec output: {out}"
        );

        // 3. Linux Direct VM + guest systemd probe
        eprintln!("[live_ecs_smoke] step 3: sb create linux --runtime native ({linux_native_name})");
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
            None,
            LIVE_CREATE_TIMEOUT,
        )
        .await;
        assert_eq!(rc, 0, "linux native create failed: out={out}\nerr={err}");
        eprintln!("[live_ecs_smoke] step 3: linux native created; running systemd probe");
        let (rc, out, err) = run_live_cua(
            dir.path(),
            &[
                "sb",
                "exec",
                &linux_native_name,
                "sh",
                "-c",
                "uname -a && systemctl is-active cua-spacesd",
            ],
            None,
            LIVE_CMD_TIMEOUT,
        )
        .await;
        assert_eq!(rc, 0, "linux native exec failed: out={out}\nerr={err}");
        println!("[live_ecs_smoke] linux native probe:\n{out}");
        assert!(
            out.contains("Linux") && out.contains("active"),
            "expected Linux + active cua-spacesd service, got: {out}"
        );

        // 4. Windows Direct VM (Session >= 1, AutoLogon, AtLogOn task, Event ID 24 tscon)
        eprintln!("[live_ecs_smoke] step 4: sb create windows --runtime native ({windows_native_name})");
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
            None,
            LIVE_CREATE_TIMEOUT,
        )
        .await;
        assert_eq!(rc, 0, "windows native create failed: out={out}\nerr={err}");
        eprintln!("[live_ecs_smoke] step 4: windows native created; running session/AutoLogon/tscon probe");

        let ps_probe = concat!(
            "$ErrorActionPreference = 'Continue'; ",
            "$sess = (Get-Process -Name 'cua-spacesd' -ErrorAction SilentlyContinue | ",
            "Select-Object -First 1 -ExpandProperty SessionId); ",
            "Write-Output \"CUA_SPACESD_SESSION=$sess\"; ",
            "query session; ",
            "$wl = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue; ",
            "Write-Output \"AUTO_ADMIN_LOGON=$($wl.AutoAdminLogon)\"; ",
            "Get-ScheduledTask | Where-Object { $_.TaskName -like '*cua*' } | ForEach-Object { ",
            "$trig = ($_.Triggers | ForEach-Object { \"$($_.CimClass.CimClassName):$($_.Subscription)\" }) -join ','; ",
            "$act = ($_.Actions | ForEach-Object { \"$($_.Execute) $($_.Arguments)\" }) -join ';'; ",
            "Write-Output \"TASK=$($_.TaskName)|TRIG=$trig|ACT=$act\" }"
        );
        let encoded_ps_probe = encode_powershell_utf16le_b64(ps_probe);
        let (rc, out, err) = run_live_cua(
            dir.path(),
            &[
                "sb",
                "exec",
                &windows_native_name,
                "powershell",
                "-NoProfile",
                "-EncodedCommand",
                &encoded_ps_probe,
            ],
            None,
            LIVE_CMD_TIMEOUT,
        )
        .await;
        assert_eq!(rc, 0, "windows session probe failed: out={out}\nerr={err}");
        println!("[live_ecs_smoke] windows native probe:\n{out}");

        let sess_id: u32 = out
            .lines()
            .find_map(|l| l.strip_prefix("CUA_SPACESD_SESSION="))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("missing CUA_SPACESD_SESSION in Windows probe:\n{out}"));
        assert!(
            sess_id >= 1,
            "cua-spacesd.exe must run in interactive Session >= 1 (not Session 0), got {sess_id}:\n{out}"
        );
        assert!(
            out.contains("AUTO_ADMIN_LOGON=1"),
            "AutoAdminLogon must be enabled in Windows guest:\n{out}"
        );
        let out_lower = out.to_ascii_lowercase();
        assert!(
            out_lower.contains("tasklogontrigger") || out_lower.contains("atlogon"),
            "expected AtLogOn interactive scheduled task in Windows probe:\n{out}"
        );
        assert!(
            out_lower.contains("tscon") && out_lower.contains("24"),
            "expected Event ID 24 tscon recovery scheduled task in Windows probe:\n{out}"
        );
    })
    .catch_unwind()
    .await;

    // 5. Unconditional async teardown before propagating any assertion failure.
    let (sw_rc, sw_out, sw_err, dc_rc, dc_out, dc_err) = run_teardown(dir.path(), &all_names).await;
    guard.disarm();

    if let Err(payload) = smoke_result {
        eprintln!(
            "live_ecs_smoke teardown after panic: sweep_rc={sw_rc} disconnect_rc={dc_rc} sw_err={sw_err} dc_err={dc_err}"
        );
        std::panic::resume_unwind(payload);
    }

    assert_eq!(sw_rc, 0, "sweep failed: out={sw_out}\nerr={sw_err}");
    assert_eq!(
        dc_rc, 0,
        "disconnect --delete failed: out={dc_out}\nerr={dc_err}"
    );
}

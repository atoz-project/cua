// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Integration contract tests for the Windows Direct VM first-boot `UserData`
//! generator (`bootstrap::win`).
#![cfg(feature = "aliyun-ecs")]

use std::collections::BTreeMap;

use base64::Engine as _;
use cua_byoc::bootstrap::win::{
    ALIYUN_VMINIT_HEADER, MAX_USER_DATA_BYTES, WindowsVmBoot, default_spacesd_version,
    default_windows_spacesd_url, generate_desktop_password, split_download_url, windows_user_data,
};
use cua_byoc::relay::Join;

fn account_join() -> Join {
    Join {
        relay_url: "https://relay.example.com".into(),
        machine_id: "cloud-0123456789abcdef".into(),
        machine_token: "cmt_account_secret_token_999".into(),
        jwks_json: r#"{"keys":[{"kty":"OKP"}]}"#.into(),
        owner: "acct-1".into(),
        owner_email: "ada@example.com".into(),
    }
}

fn static_join() -> Join {
    Join {
        relay_url: "https://relay.selfhosted.local".into(),
        machine_id: "cloud-fedcba9876543210".into(),
        machine_token: "static_relay_secret_token_777".into(),
        jwks_json: String::new(),
        owner: String::new(),
        owner_email: String::new(),
    }
}

fn boot_cfg<'a>(
    join: &'a Join,
    env: &'a BTreeMap<String, String>,
    ttl_secs: u64,
    spacesd_download_url: Option<&'a str>,
    desktop_password: &'a str,
) -> WindowsVmBoot<'a> {
    WindowsVmBoot {
        join,
        env,
        expires: if ttl_secs > 0 { 1_900_000_000 } else { 0 },
        ttl_secs,
        provider: "aliyun-ecs",
        spacesd_download_url,
        desktop_user: "Administrator",
        desktop_password,
    }
}

fn decode_put(script: &str, name: &str) -> Option<String> {
    let needle = format!("'{name}') '");
    let idx = script.find(&needle)? + needle.len();
    let rest = &script[idx..];
    let raw_b64 = &rest[..rest.find('\'')?];
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_b64)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn decode_dl_url(script: &str) -> Option<String> {
    let needle = "$dlUrl = [Text.Encoding]::UTF8.GetString((Dec '";
    let idx = script.find(needle)? + needle.len();
    let rest = &script[idx..];
    let raw_b64 = &rest[..rest.find('\'')?];
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_b64)
        .ok()?;
    String::from_utf8(bytes).ok()
}

#[test]
fn account_mode_windows_user_data_contract_and_size() {
    let j = account_join();
    let env = BTreeMap::from([("FOO_BAR".to_string(), "baz".to_string())]);
    let pw = "WinPass!1234Abcd";
    let ps = windows_user_data(&boot_cfg(&j, &env, 8 * 3600, None, pw));
    assert!(ps.starts_with("[powershell]\n"));
    assert!(
        ps.len() < MAX_USER_DATA_BYTES,
        "UserData {} >= 16 KiB",
        ps.len()
    );
    assert!(!ps.contains(&j.machine_token) && !ps.contains(pw) && !ps.contains(&j.jwks_json));

    assert!(ps.contains("*S-1-5-18:(OI)(CI)F"), "{ps}");
    assert!(ps.contains("*S-1-5-32-544:(OI)(CI)F"), "{ps}");
    let icacls_pos = ps.find("& icacls.exe $sd /inheritance:r").unwrap();
    assert!(ps[icacls_pos..].contains(" /T "), "{ps}");
    let dd_create_pos = ps
        .find("New-Item -ItemType Directory -Force -Path $dd")
        .unwrap();
    assert!(dd_create_pos > icacls_pos);
    assert!(!ps.contains("Put (Join-Path $stg 'relay-token')"));
    assert!(!ps.contains("Move-Item -LiteralPath $_.FullName -Destination (Join-Path $sd"));
    for f in ["relay-token", "machine-id", "host-policy.json", "jwks.json"] {
        assert!(ps.contains(&format!("Put (Join-Path $sd '{f}')")));
    }
    assert!(ps.contains("Remove-Item -LiteralPath $stg -Recurse -Force"));

    assert_eq!(
        decode_put(&ps, "relay-token").as_deref(),
        Some("cmt_account_secret_token_999")
    );
    assert_eq!(
        decode_put(&ps, "machine-id").as_deref(),
        Some("cloud-0123456789abcdef")
    );
    assert!(decode_put(&ps, "jwks.json").is_some());
    assert!(decode_put(&ps, "env-token").is_none());
    let policy: serde_json::Value =
        serde_json::from_str(&decode_put(&ps, "host-policy.json").unwrap()).unwrap();
    assert_eq!(policy["owner"], "acct-1");

    assert!(ps.contains("Cua\\spacesd") && ps.contains("cua-spacesd.exe"));
    assert!(ps.contains("cua\\spacesd\\cua-spacesd.exe"));
    assert!(ps.contains(&default_windows_spacesd_url()));
    assert!(ps.contains("Get-FileHash -Algorithm SHA256"));
    assert!(ps.contains("SecurityProtocolType]::Tls12"));
    assert!(ps.contains("-UseBasicParsing"));
    assert!(!ps.contains("100.100.100.200") && !ps.contains("New-NetFirewallRule"));
    assert!(ps.contains("S-1-5-21-*-500"));
    assert!(
        ps.contains("& net.exe user $u $pwPlain /active:yes /Y"),
        "expected unconditional SAM password sync with /Y for >14-char passwords: {ps}"
    );
    assert!(!ps.contains("if ($ma.Disabled -or ($u -cne $origU))"));
    assert!(ps.contains("Start-Process") && ps.contains("reboot-wait.ps1"));
    assert!(
        ps.contains(
            r#"-FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe""#
        ) && !ps.contains("'-WindowStyle','Hidden','-File'"),
        "Start-Process should use full SystemRoot PowerShell path without duplicate -WindowStyle: {ps}"
    );
    let reboot_wait = decode_put(&ps, "reboot-wait.ps1").unwrap();
    assert!(reboot_wait.contains(r"C:\ProgramData\aliyun\vminit\POST_Main"));
    assert!(reboot_wait.contains("shutdown.exe"));
    for want in [
        "AutoAdminLogon",
        "DisableLockWorkstation",
        "NoLockScreen",
        "ScreenSaveActive",
        "standby-timeout-ac 0",
        "-AtLogOn",
        "-LogonType Interactive -RunLevel Highest",
        "EventID=24",
        "NT AUTHORITY\\SYSTEM",
        "shutdown.exe /s /t 28800",
    ] {
        assert!(ps.contains(want), "missing {want:?}");
    }

    let launcher = decode_put(&ps, "launch-spacesd.ps1").unwrap();
    assert!(launcher.contains("CUA_DRIVER_POLICY_FILE"));
    assert!(launcher.contains(".SessionId") && launcher.contains("$sid -lt 1"));
    assert!(launcher.contains("--relay-jwks") && !launcher.contains("--token-file"));
    assert!(launcher.contains("$cuaArgs"));
    assert!(!launcher.contains("$args =") && !launcher.contains("@args"));

    let tscon = decode_put(&ps, "tscon-recover.ps1").unwrap();
    assert!(tscon.contains("tscon.exe") && tscon.contains("/dest:console"));
    assert!(tscon.contains("$ErrorActionPreference = 'Continue'") && tscon.contains("quser.exe"));
    assert!(decode_put(&ps, "expire-check.ps1").is_some());
}

#[test]
fn static_mode_custom_mirror_sha256_and_no_ttl() {
    let j = static_join();
    let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "env_secret_static_42".into())]);
    let pw = generate_desktop_password();
    assert!(pw.len() >= 16 && !pw.contains('\''));
    let hex = "ab".repeat(32);
    let mirror = format!("http://10.0.0.10:8080/mirror/cua-spacesd.exe#sha256={hex}");
    let ps = windows_user_data(&boot_cfg(&j, &env, 0, Some(&mirror), &pw));
    assert!(ps.starts_with(&format!("{ALIYUN_VMINIT_HEADER}\n")) && ps.len() < MAX_USER_DATA_BYTES);
    assert!(
        !ps.contains("static_relay_secret_token_777")
            && !ps.contains("env_secret_static_42")
            && !ps.contains(&pw)
    );
    assert!(decode_put(&ps, "jwks.json").is_none());
    assert_eq!(
        decode_put(&ps, "env-token").as_deref(),
        Some("env_secret_static_42")
    );
    let policy: serde_json::Value =
        serde_json::from_str(&decode_put(&ps, "host-policy.json").unwrap()).unwrap();
    assert!(policy.get("owner").is_none());

    let launcher = decode_put(&ps, "launch-spacesd.ps1").unwrap();
    assert!(!launcher.contains("--relay-jwks") && launcher.contains("--token-file"));
    assert!(ps.contains("http://10.0.0.10:8080/mirror/cua-spacesd.exe"));
    assert!(!ps.contains("#sha256=") && ps.contains(&hex));
    assert!(!ps.contains("shutdown.exe /s") && decode_put(&ps, "expire-check.ps1").is_none());
}

#[test]
fn mirror_url_expands_version_arch_and_trailing_slash_preserving_query() {
    let ver = default_spacesd_version();
    let hex = "cd".repeat(32);

    let templated =
        format!("https://mirror.example.com/v{{version}}/cua-spacesd-{{arch}}.exe#sha256={hex}");
    let (url, sha) = split_download_url(Some(&templated));
    assert_eq!(
        url,
        format!("https://mirror.example.com/v{ver}/cua-spacesd-x86_64.exe")
    );
    assert_eq!(sha, Some(hex.as_str()));

    let j = static_join();
    let env = BTreeMap::new();
    let q_url = format!(
        "https://mirror.example.com/v{ver}/x86_64/cua-spacesd-x86_64-pc-windows-msvc.exe?sig=SecretToken99"
    );
    let ps = windows_user_data(&boot_cfg(
        &j,
        &env,
        0,
        Some("https://mirror.example.com/v{version}/{arch}/?sig=SecretToken99"),
        "WinPass!1234Abcd",
    ));
    assert_eq!(decode_dl_url(&ps).as_deref(), Some(q_url.as_str()));
    assert!(!ps.contains("SecretToken99"), "query leaked in plaintext");
    assert!(ps.contains(&format!(
        "https://mirror.example.com/v{ver}/x86_64/cua-spacesd-x86_64-pc-windows-msvc.exe"
    )));
    assert!(ps.contains("Fetch $dlUrl $dlTmp"));
    assert!(ps.contains("Fetch \"$dlUrl.sha256\" $sumTmp"));
}

#[test]
fn utf8_without_bom_for_bin_path_and_utf8_reads_in_launcher() {
    let j = account_join();
    let env = BTreeMap::from([("GREETING".to_string(), "你好世界".to_string())]);
    let ps = windows_user_data(&boot_cfg(&j, &env, 0, None, "WinPass!1234Abcd"));

    assert!(
        ps.contains(
            "[IO.File]::WriteAllBytes((Join-Path $sd 'bin-path'), [Text.Encoding]::UTF8.GetBytes($exe))"
        ),
        "{ps}"
    );
    assert!(!ps.contains("Set-Content -LiteralPath (Join-Path $sd 'bin-path')"));

    let launcher = decode_put(&ps, "launch-spacesd.ps1").unwrap();
    assert!(
        launcher.contains(
            "[IO.File]::ReadAllText((Join-Path $sd 'bin-path'), [Text.Encoding]::UTF8).Trim()"
        ),
        "{launcher}"
    );
    assert!(
        launcher.contains(
            "[IO.File]::ReadAllText((Join-Path $sd 'extra-env.json'), [Text.Encoding]::UTF8) | ConvertFrom-Json"
        ),
        "{launcher}"
    );
    assert!(
        !launcher.contains("Get-Content"),
        "launcher must not use bare Get-Content on BOM-less UTF-8 files: {launcher}"
    );
    let extra: serde_json::Value =
        serde_json::from_str(&decode_put(&ps, "extra-env.json").unwrap()).unwrap();
    assert_eq!(extra["GREETING"], "你好世界");
}

#[test]
fn windows_vm_boot_debug_redacts_secrets_and_url_credentials_and_blocks_curly_quotes() {
    let mut j = static_join();
    j.relay_url = "https://relay.example\u{2019};Invoke-Expression(whoami)".into();
    let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "env_secret_static_99".into())]);
    let pw = "WinPass!Secret9988";
    let secret_mirror = format!(
        "https://dluser:MyPass998877@mirror.example.com/cua-spacesd.exe?sig=DeadBeefCafe9988#sha256={}",
        "ab".repeat(32)
    );
    let boot = boot_cfg(&j, &env, 0, Some(&secret_mirror), pw);
    let dbg = format!("{boot:?}");
    for secret in [
        pw,
        "MyPass998877",
        "DeadBeefCafe9988",
        "env_secret_static_99",
    ] {
        assert!(!dbg.contains(secret), "Debug leaked {secret}: {dbg}");
    }
    assert!(
        dbg.contains("<redacted>") && dbg.contains("https://mirror.example.com/cua-spacesd.exe")
    );

    let ps = windows_user_data(&boot);
    for secret in ["MyPass998877", "DeadBeefCafe9988", "dluser"] {
        assert!(!ps.contains(secret), "{ps}");
    }
    assert!(
        ps.contains("https://mirror.example.com/cua-spacesd.exe"),
        "{ps}"
    );
    for q in ['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
        assert!(!ps.contains(q), "raw curly quote {q:?} in UserData");
        let j2 = static_join();
        let curly_url = format!(
            "https://mirror.example.com/cua{q};Invoke-Expression(whoami);#sha256={}",
            "ab".repeat(32)
        );
        let ps2 = windows_user_data(&boot_cfg(&j2, &env, 0, Some(&curly_url), pw));
        assert!(!ps2.contains(q) && !ps2.contains("Invoke-Expression"));
    }
    let launcher = decode_put(&ps, "launch-spacesd.ps1").unwrap();
    assert!(!launcher.contains('\u{2019}') && !launcher.contains("Invoke-Expression"));
    assert!(ps.contains("function Fetch(") && ps.contains("Fetch $dlUrl $dlTmp"));
}

#[test]
fn aliyun_vminit_header_and_wow64_guard_contract() {
    let j = static_join();
    let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "env_secret_static_vminit".into())]);
    let ps = windows_user_data(&boot_cfg(&j, &env, 8 * 3600, None, "WinPass!1234Abcd"));
    let mut lines = ps.lines();
    assert_eq!(lines.next(), Some("[powershell]"));
    let guard_line = lines.next().unwrap();
    for want in [
        "Is64BitOperatingSystem",
        "Is64BitProcess",
        r"Sysnative\WindowsPowerShell\v1.0\powershell.exe",
        "$PSCommandPath",
    ] {
        assert!(guard_line.contains(want), "missing {want}");
    }
    assert!(
        ps.len() < MAX_USER_DATA_BYTES,
        "UserData {} >= 16 KiB",
        ps.len()
    );
}

#[test]
fn registry_and_finally_cleanup_guards() {
    let j = static_join();
    let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "env_secret_static_guards".into())]);
    let pinned_mirror = format!(
        "https://mirror.example.com/cua-spacesd.exe#sha256={}",
        "ab".repeat(32)
    );
    for url in [None, Some(pinned_mirror.as_str())] {
        let ps = windows_user_data(&boot_cfg(&j, &env, 8 * 3600, url, "WinPass!1234Abcd"));
        assert!(ps.len() < MAX_USER_DATA_BYTES);
        assert!(ps.contains(
            "if (-not (Test-Path -LiteralPath $sp)) { New-Item -Path $sp -Force | Out-Null }"
        ));
        assert!(ps.contains(
            "if (-not (Test-Path -LiteralPath $pp)) { New-Item -Path $pp -Force | Out-Null }"
        ));
        for line in ps.lines() {
            let trimmed = line.trim_start();
            assert!(
                !trimmed.starts_with("New-Item -Path $sp")
                    && !trimmed.starts_with("New-Item -Path $pp"),
                "unguarded New-Item: {line}"
            );
        }
        let finally_block = &ps[ps.find("} finally {").expect("finally block")..];
        for expected in [
            "if ($dlTmp) { Remove-Item -LiteralPath $dlTmp -Force -ErrorAction SilentlyContinue }",
            "if ($sumTmp) { Remove-Item -LiteralPath $sumTmp -Force -ErrorAction SilentlyContinue }",
            "if ($stg) { Remove-Item -LiteralPath $stg -Recurse -Force -ErrorAction SilentlyContinue }",
        ] {
            assert!(finally_block.contains(expected), "{finally_block}");
        }
        for line in ps.lines() {
            for stmt in line.split(';') {
                let trimmed = stmt.trim_start();
                assert!(
                    !trimmed.starts_with("Remove-Item -LiteralPath $dlTmp")
                        && !trimmed.starts_with("Remove-Item -LiteralPath $sumTmp")
                        && !trimmed.starts_with("Remove-Item -LiteralPath $stg"),
                    "unguarded Remove-Item: {line}"
                );
            }
        }
    }
}

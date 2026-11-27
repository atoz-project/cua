// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! First-boot PowerShell `UserData` generator for Windows Direct VM
//! Sandboxes (`--runtime native` on `aliyun-ecs`).
//!
//! Runs under 64-bit PowerShell via Alibaba Cloud `vminit` (`[powershell]`),
//! with a WOW64 -> `Sysnative` 64-bit self-relaunch guard, and:
//! 1. Resolves the local Administrator account (matching `desktop_user` or
//!    falling back to built-in SID `S-1-5-21-*-500`), activates it, sets its
//!    password with `/Y`, stages relay/environment credentials into an
//!    SID-ACL-restricted directory (`SYSTEM`, `Administrators`, desktop user
//!    only), and removes temporary staging artifacts.
//! 2. Detects pre-installed `cua-spacesd.exe` first; otherwise downloads from
//!    the connection's custom mirror URL (or GitHub Releases by default) and
//!    verifies SHA-256 before execution.
//! 3. Configures unattended Windows AutoLogon and disables auto-lock,
//!    screensaver, and sleep timeouts.
//! 4. Registers an `AtLogOn` interactive scheduled task (`LogonType
//!    Interactive`, `RunLevel Highest`) running `cua-spacesd.exe join` in
//!    `SessionId >= 1` (never Session 0).
//! 5. Registers a `SYSTEM` scheduled task triggered by
//!    `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
//!    Event ID `24` to run `tscon.exe <SessionId> /dest:console`.
//! 6. Schedules an in-guest TTL shutdown backstop when `ttl_secs > 0`, and
//!    detaches the AutoLogon reboot until `vminit` archives `POST_Main`.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::relay::Join;

/// Windows x86_64 release asset filename appended to trailing-slash mirror URLs.
const WINDOWS_SPACESD_ASSET: &str = "cua-spacesd-x86_64-pc-windows-msvc.exe";

/// Default `cua-spacesd` release version derived from `cua-host::driver`.
pub fn default_spacesd_version() -> &'static str {
    cua_host::driver::SPACESD_VERSION.trim()
}

/// Default GitHub Releases URL for Windows x86_64 `cua-spacesd.exe`, derived
/// from `cua-host::driver`.
pub fn default_windows_spacesd_url() -> String {
    format!(
        "https://github.com/{}/releases/download/cua-spacesd-v{}/{WINDOWS_SPACESD_ASSET}",
        cua_host::driver::RELEASE_REPOSITORY,
        default_spacesd_version(),
    )
}

/// Maximum raw `UserData` length accepted by Alibaba Cloud ECS (16 KiB).
pub const MAX_USER_DATA_BYTES: usize = 16 * 1024;

/// Line-1 header required by Alibaba Cloud `vminit` (`Plugin_Main_CloudinitUserData`).
pub const ALIYUN_VMINIT_HEADER: &str = "[powershell]";

/// Compact 64-bit WOW64 -> `Sysnative` self-relaunch guard for `vminit`.
const WOW64_SYSNATIVE_GUARD: &str = r#"if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and $PSCommandPath) { & "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath; exit $LASTEXITCODE }"#;

/// Maximum `/t` seconds accepted by `shutdown.exe` (10 years).
const MAX_SHUTDOWN_TIMEOUT_SECS: u64 = 315_360_000;

/// What one Windows Direct VM's first boot needs.
#[derive(Clone)]
pub struct WindowsVmBoot<'a> {
    /// The relay machine the sandbox joins as.
    pub join: &'a Join,
    /// The guest environment (`CUA_ENV_TOKEN` in Static Relay Mode, etc.).
    pub env: &'a BTreeMap<String, String>,
    /// Unix seconds after which the VM shuts itself down (0: never).
    pub expires: u64,
    /// Seconds from boot for the `shutdown.exe` backstop (0: none).
    pub ttl_secs: u64,
    /// The cloud (`aliyun-ecs`).
    pub provider: &'a str,
    /// Optional custom `cua-spacesd` binary mirror URL (optionally with
    /// `#sha256=<64 hex>`).
    pub spacesd_download_url: Option<&'a str>,
    /// Windows desktop user for AutoLogon and the interactive task.
    pub desktop_user: &'a str,
    /// Windows desktop user password (secret; never logged or echoed).
    pub desktop_password: &'a str,
}

impl std::fmt::Debug for WindowsVmBoot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsVmBoot")
            .field("join", self.join)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("expires", &self.expires)
            .field("ttl_secs", &self.ttl_secs)
            .field("provider", &self.provider)
            .field(
                "spacesd_download_url",
                &self
                    .spacesd_download_url
                    .map(cua_sandbox_core::byoc::redact_url),
            )
            .field("desktop_user", &self.desktop_user)
            .field("desktop_password", &"<redacted>")
            .finish()
    }
}

/// Generates a strong random password satisfying ECS Windows complexity rules
/// (8-30 chars, uppercase + lowercase + digit + symbol, no shell-quoting hazards).
pub fn generate_desktop_password() -> String {
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const DIGIT: &[u8] = b"23456789";
    const SYM: &[u8] = b"!@#%_-";
    const ALL: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%_-";
    let mut out = Vec::with_capacity(20);
    out.push(UPPER[rand::random::<u32>() as usize % UPPER.len()]);
    out.push(LOWER[rand::random::<u32>() as usize % LOWER.len()]);
    out.push(DIGIT[rand::random::<u32>() as usize % DIGIT.len()]);
    out.push(SYM[rand::random::<u32>() as usize % SYM.len()]);
    for _ in 0..16 {
        out.push(ALL[rand::random::<u32>() as usize % ALL.len()]);
    }
    for i in (1..out.len()).rev() {
        let j = rand::random::<u32>() as usize % (i + 1);
        out.swap(i, j);
    }
    String::from_utf8(out).expect("ASCII password")
}

/// Resolves an optional mirror URL into `(resolved_url_without_fragment, optional_sha256_hex)`.
///
/// Expands `{version}` -> [`default_spacesd_version()`] and `{arch}` -> `"x86_64"`.
/// When the URL path (before `?`/`#`) ends with `/`, appends
/// `cua-spacesd-x86_64-pc-windows-msvc.exe` while preserving any query string.
pub fn split_download_url(raw: Option<&str>) -> (String, Option<&str>) {
    match super::resolve_spacesd_download(
        raw,
        default_spacesd_version(),
        Some("x86_64"),
        WINDOWS_SPACESD_ASSET,
    ) {
        Some(res) => res,
        None => (default_windows_spacesd_url(), None),
    }
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn ps_single_quote(s: &str) -> String {
    if s.is_ascii() && !s.chars().any(|c| c.is_control()) {
        format!("'{}'", s.replace('\'', "''"))
    } else {
        // Non-ASCII (e.g., Unicode curly single quotes U+2018..U+201B) and
        // control characters bypass PowerShell's tokenizer via base64.
        format!(
            "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}')))",
            b64(s)
        )
    }
}

struct UserDataPayloads {
    desktop_user: String,
    dl_url: String,
    expected_sha: Option<String>,
    relay_token_b64: String,
    machine_id_b64: String,
    policy_b64: String,
    jwks_b64: Option<String>,
    env_token_b64: Option<String>,
    extra_env_b64: Option<String>,
    pass_b64: String,
    launcher_b64: String,
    tscon_b64: String,
    reboot_wait_b64: String,
    expire_b64: Option<String>,
}

fn build_payloads(boot: &WindowsVmBoot<'_>) -> UserDataPayloads {
    let (dl_url, expected_sha) = split_download_url(boot.spacesd_download_url);
    let desktop_user = match boot.desktop_user.trim() {
        "" => "Administrator".to_string(),
        u => u.to_string(),
    };
    let has_jwks = !boot.join.jwks_json.trim().is_empty();
    let jwks_b64 = has_jwks.then(|| b64(&boot.join.jwks_json));
    let env_token = boot
        .env
        .get("CUA_ENV_TOKEN")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let env_token_b64 = env_token.map(b64);
    let extra_env: BTreeMap<&str, &str> = boot
        .env
        .iter()
        .filter(|(k, _)| k.as_str() != "CUA_ENV_TOKEN")
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let extra_env_b64 = (!extra_env.is_empty())
        .then(|| b64(&serde_json::to_string(&extra_env).unwrap_or_else(|_| "{}".into())));
    let has_extra_env = extra_env_b64.is_some();

    UserDataPayloads {
        desktop_user,
        dl_url,
        expected_sha: expected_sha.map(str::to_ascii_lowercase),
        relay_token_b64: b64(&boot.join.machine_token),
        machine_id_b64: b64(&boot.join.machine_id),
        policy_b64: b64(&boot.join.policy_json()),
        jwks_b64,
        env_token_b64,
        extra_env_b64,
        pass_b64: b64(boot.desktop_password),
        launcher_b64: b64(&build_launcher_ps(
            &boot.join.relay_url,
            &boot.join.machine_id,
            has_jwks,
            env_token.is_some(),
            has_extra_env,
        )),
        tscon_b64: b64(&build_tscon_ps()),
        reboot_wait_b64: b64(&build_reboot_wait_ps()),
        expire_b64: (boot.ttl_secs > 0).then(|| b64(&build_expire_ps())),
    }
}

fn push_preamble_and_admin_setup(s: &mut String, boot: &WindowsVmBoot<'_>, p: &UserDataPayloads) {
    s.push_str(&format!(
        "$provider = {prov}\n\
         $u = {user}\n\
         $sd = 'C:\\ProgramData\\cua\\spacesd'\n\
         $dd = Join-Path $sd 'data'\n\
         $ld = 'C:\\ProgramData\\cua\\logs'\n\
         $bd = Join-Path $env:ProgramFiles 'Cua\\spacesd'\n\
         $stg = Join-Path $env:TEMP ('cua-stg-' + [Guid]::NewGuid().ToString('N'))\n\
         $dlTmp = $null\n\
         $sumTmp = $null\n\
         New-Item -ItemType Directory -Force -Path $sd,$ld,$bd,$stg | Out-Null\n\
         function Log([string]$m) {{\n\
         \x20 $ln = \"[cua-win-boot] $((Get-Date).ToUniversalTime().ToString('o')) $m\"\n\
         \x20 Add-Content -LiteralPath (Join-Path $ld 'boot.log') -Value $ln -Encoding UTF8\n\
         \x20 Write-Output $ln\n\
         }}\n\
         function Dec([string]$b) {{ [Convert]::FromBase64String($b) }}\n\
         function Put([string]$p,[string]$b) {{ [IO.File]::WriteAllBytes($p,(Dec $b)) }}\n\
         function Fetch([string]$u,[string]$o) {{ for ($i=1; $i -le 5; $i++) {{ try {{ Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $o; return }} catch {{ if ($i -eq 5) {{ throw }}; Start-Sleep -Seconds ($i*5) }} }} }}\n\
         $pwPlain = [Text.Encoding]::UTF8.GetString((Dec {pw}))\n\
         $la = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue)\n\
         $ma = $la | Where-Object {{ $_.Name -eq $u }} | Select-Object -First 1\n\
         if (-not $ma) {{ $ma = $la | Where-Object {{ $_.SID -like 'S-1-5-21-*-500' }} | Select-Object -First 1 }}\n\
         if ($ma) {{\n\
         \x20 $u = [string]$ma.Name\n\
         \x20 Log \"ensuring active local admin account $u\"\n\
         \x20 if ($pwPlain) {{ & net.exe user $u $pwPlain /active:yes /Y | Out-Null }} else {{ & net.exe user $u /active:yes | Out-Null }}\n\
         \x20 if ($LASTEXITCODE -ne 0) {{ throw \"net user failed: $LASTEXITCODE\" }}\n\
         }}\n",
        prov = ps_single_quote(boot.provider),
        user = ps_single_quote(&p.desktop_user),
        pw = ps_single_quote(&p.pass_b64),
    ));
}

fn push_secret_staging(s: &mut String, p: &UserDataPayloads) {
    s.push_str(&format!(
        "  Put (Join-Path $sd 'relay-token') {relay_tok}\n\
         \x20 Put (Join-Path $sd 'machine-id') {mach_id}\n\
         \x20 Put (Join-Path $sd 'host-policy.json') {policy}\n",
        relay_tok = ps_single_quote(&p.relay_token_b64),
        mach_id = ps_single_quote(&p.machine_id_b64),
        policy = ps_single_quote(&p.policy_b64),
    ));
    if let Some(jwks) = &p.jwks_b64 {
        s.push_str(&format!(
            "  Put (Join-Path $sd 'jwks.json') {}\n",
            ps_single_quote(jwks)
        ));
    }
    if let Some(et) = &p.env_token_b64 {
        s.push_str(&format!(
            "  Put (Join-Path $sd 'env-token') {}\n",
            ps_single_quote(et)
        ));
    }
    if let Some(ee) = &p.extra_env_b64 {
        s.push_str(&format!(
            "  Put (Join-Path $sd 'extra-env.json') {}\n",
            ps_single_quote(ee)
        ));
    }
    s.push_str(&format!(
        "  Put (Join-Path $sd 'launch-spacesd.ps1') {launcher}\n\
         \x20 Put (Join-Path $sd 'tscon-recover.ps1') {tscon}\n\
         \x20 Put (Join-Path $sd 'reboot-wait.ps1') {reboot_wait}\n",
        launcher = ps_single_quote(&p.launcher_b64),
        tscon = ps_single_quote(&p.tscon_b64),
        reboot_wait = ps_single_quote(&p.reboot_wait_b64),
    ));
}

fn push_spacesd_install(s: &mut String, p: &UserDataPayloads) {
    let expected_sha_ps = match &p.expected_sha {
        Some(hex) => ps_single_quote(hex),
        None => "$null".into(),
    };
    let dl_url_b64 = b64(&p.dl_url);
    let dl_url_redacted = cua_sandbox_core::byoc::redact_url(&p.dl_url);
    s.push_str(&format!(
        "  $exe = $null\n\
         \x20 foreach ($cand in @((Join-Path $bd 'cua-spacesd.exe'), (Join-Path $env:LOCALAPPDATA 'cua\\spacesd\\cua-spacesd.exe'))) {{\n\
         \x20   if (Test-Path -LiteralPath $cand) {{ $exe = $cand; break }}\n\
         \x20 }}\n\
         \x20 if (-not $exe) {{\n\
         \x20   $cmd = Get-Command cua-spacesd.exe -ErrorAction SilentlyContinue | Select-Object -First 1\n\
         \x20   if ($cmd) {{ $exe = $cmd.Source }}\n\
         \x20 }}\n\
         \x20 if (-not $exe) {{\n\
         \x20   $dlUrl = [Text.Encoding]::UTF8.GetString((Dec {dl_url_b64}))\n\
         \x20   $wantSha = {want_sha}\n\
         \x20   Log ('downloading cua-spacesd.exe from ' + {dl_url_redacted})\n\
         \x20   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12\n\
         \x20   $dlTmp = Join-Path $stg 'cua-spacesd.exe'\n\
         \x20   Fetch $dlUrl $dlTmp\n\
         \x20   if (-not $wantSha) {{\n\
         \x20     $sumTmp = Join-Path $stg 'cua-spacesd.exe.sha256'\n\
         \x20     Fetch \"$dlUrl.sha256\" $sumTmp\n\
         \x20     $wantSha = (((Get-Content -Raw -LiteralPath $sumTmp).Trim() -split '\\s+')[0]).ToLowerInvariant()\n\
         \x20   }}\n\
         \x20   if ($wantSha -notmatch '^[0-9a-f]{{64}}$') {{ throw 'invalid sha256 checksum format' }}\n\
         \x20   $gotSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $dlTmp).Hash.ToLowerInvariant()\n\
         \x20   if ($gotSha -ne $wantSha) {{ throw \"SHA-256 mismatch: expected $wantSha got $gotSha\" }}\n\
         \x20   $exe = Join-Path $bd 'cua-spacesd.exe'\n\
         \x20   Move-Item -LiteralPath $dlTmp -Destination $exe -Force\n\
         \x20 }} else {{ Log \"using pre-installed $exe\" }}\n\
         \x20 [IO.File]::WriteAllBytes((Join-Path $sd 'bin-path'), [Text.Encoding]::UTF8.GetBytes($exe))\n",
        dl_url_b64 = ps_single_quote(&dl_url_b64),
        dl_url_redacted = ps_single_quote(&dl_url_redacted),
        want_sha = expected_sha_ps,
    ));
}

fn push_autologon_and_desktop_policy(s: &mut String) {
    s.push_str(
        "  $wl = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'\n\
         \x20 Set-ItemProperty -Path $wl -Name 'AutoAdminLogon' -Value '1' -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'DefaultUserName' -Value $u -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'DefaultDomainName' -Value $env:COMPUTERNAME -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'DefaultPassword' -Value $pwPlain -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'ForceAutoLogon' -Value '1' -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'AutoLogonCount' -Value 1 -Type DWord\n\
         \x20 $sp = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'\n\
         \x20 if (-not (Test-Path -LiteralPath $sp)) { New-Item -Path $sp -Force | Out-Null }\n\
         \x20 Set-ItemProperty -Path $sp -Name 'DisableLockWorkstation' -Value 1 -Type DWord\n\
         \x20 $pp = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization'\n\
         \x20 if (-not (Test-Path -LiteralPath $pp)) { New-Item -Path $pp -Force | Out-Null }\n\
         \x20 Set-ItemProperty -Path $pp -Name 'NoLockScreen' -Value 1 -Type DWord\n\
         \x20 Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveActive' -Value '0' -Type String -ErrorAction SilentlyContinue\n\
         \x20 & reg.exe add 'HKU\\.DEFAULT\\Control Panel\\Desktop' /v ScreenSaveActive /t REG_SZ /d 0 /f | Out-Null\n\
         \x20 & powercfg.exe /change standby-timeout-ac 0 | Out-Null\n\
         \x20 & powercfg.exe /change monitor-timeout-ac 0 | Out-Null\n\
         \x20 & powercfg.exe /change hibernate-timeout-ac 0 | Out-Null\n",
    );
}

fn push_scheduled_tasks_and_handoff(
    s: &mut String,
    boot: &WindowsVmBoot<'_>,
    p: &UserDataPayloads,
) {
    s.push_str(
        "  $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `\"$sd\\launch-spacesd.ps1`\"\"\n\
         \x20 $trg = New-ScheduledTaskTrigger -AtLogOn -User $u\n\
         \x20 $prn = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest\n\
         \x20 $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew\n\
         \x20 Register-ScheduledTask -TaskName 'cua-spacesd' -Action $act -Trigger $trg -Principal $prn -Settings $set -Force | Out-Null\n\
         \x20 $tc = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler'\n\
         \x20 $et = New-CimInstance -CimClass $tc -ClientOnly\n\
         \x20 $et.Enabled = $true\n\
         \x20 $et.Subscription = \"<QueryList><Query Id='0' Path='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'><Select Path='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'>*[System[(EventID=24)]]</Select></Query></QueryList>\"\n\
         \x20 $tAct = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `\"$sd\\tscon-recover.ps1`\"\"\n\
         \x20 $tPrn = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n\
         \x20 $tSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances Queue\n\
         \x20 Register-ScheduledTask -TaskName 'cua-tscon-recover' -Action $tAct -Trigger $et -Principal $tPrn -Settings $tSet -Force | Out-Null\n",
    );
    if let Some(exp_b64) = &p.expire_b64 {
        s.push_str(&format!(
            "  Set-Content -LiteralPath 'C:\\ProgramData\\cua\\expires' -Value '{expires}' -NoNewline -Encoding ASCII\n\
             \x20 Put (Join-Path $sd 'expire-check.ps1') {exp_script}\n\
             \x20 $eAct = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `\"$sd\\expire-check.ps1`\"\"\n\
             \x20 $eTrg = New-ScheduledTaskTrigger -AtStartup\n\
             \x20 $eTrg.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 3650)).Repetition\n\
             \x20 Register-ScheduledTask -TaskName 'cua-expire' -Action $eAct -Trigger $eTrg -Principal $tPrn -Settings $set -Force | Out-Null\n",
            expires = boot.expires,
            exp_script = ps_single_quote(exp_b64),
        ));
    }
    let session_ttl_shutdown = if boot.ttl_secs > 0 {
        let clamped = boot.ttl_secs.clamp(1, MAX_SHUTDOWN_TIMEOUT_SECS);
        format!("    & shutdown.exe /s /t {clamped} /f /c 'cua: sandbox TTL reached' | Out-Null\n")
    } else {
        String::new()
    };
    s.push_str(&format!(
        "  $prevEap = $ErrorActionPreference\n\
         \x20 $ErrorActionPreference = 'Continue'\n\
         \x20 try {{\n\
         \x20   & quser.exe $u 2>$null | Out-Null\n\
         \x20   $hasTargetUserSession = $LASTEXITCODE -eq 0\n\
         \x20 }} finally {{\n\
         \x20   $ErrorActionPreference = $prevEap\n\
         \x20 }}\n\
         \x20 $hasSession = $hasTargetUserSession -and @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object {{ $_.SessionId -ge 1 }}).Count -gt 0\n\
         \x20 if ($hasSession) {{\n\
         {session_ttl_shutdown}\
         \x20   Start-ScheduledTask -TaskName 'cua-spacesd'\n\
         \x20 }} else {{\n\
         \x20   Log 'scheduling detached reboot after vminit POST_Main archival'\n\
         \x20   Start-Process -FilePath \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $sd 'reboot-wait.ps1') -WindowStyle Hidden | Out-Null\n\
         \x20 }}\n",
    ));
}

/// Builds the compact `[powershell]` PowerShell `UserData` script for Alibaba
/// Cloud `vminit` with a 64-bit WOW64 -> `Sysnative` self-relaunch guard.
///
/// Secrets are base64-encoded inside the script and written directly to
/// SID-ACL-protected files (`SYSTEM`, `Administrators`, `desktop_user`),
/// never echoed to stdout/logs.
pub fn windows_user_data(boot: &WindowsVmBoot<'_>) -> String {
    let payloads = build_payloads(boot);
    let mut s = format!(
        "{ALIYUN_VMINIT_HEADER}\n\
         {WOW64_SYSNATIVE_GUARD}\n\
         $ErrorActionPreference = 'Stop'\n\
         $ProgressPreference = 'SilentlyContinue'\n"
    );
    push_preamble_and_admin_setup(&mut s, boot, &payloads);
    s.push_str(
        "Log \"staging secrets for $provider\"\n\
         & icacls.exe $sd /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' \"$u`:(OI)(CI)M\" /T | Out-Null\n\
         if ($LASTEXITCODE -ne 0) { throw \"icacls failed: $LASTEXITCODE\" }\n\
         New-Item -ItemType Directory -Force -Path $dd | Out-Null\n\
         try {\n",
    );
    push_secret_staging(&mut s, &payloads);
    push_spacesd_install(&mut s, &payloads);
    push_autologon_and_desktop_policy(&mut s);
    push_scheduled_tasks_and_handoff(&mut s, boot, &payloads);
    s.push_str(
        "} finally {\n\
         \x20 if ($dlTmp) { Remove-Item -LiteralPath $dlTmp -Force -ErrorAction SilentlyContinue }\n\
         \x20 if ($sumTmp) { Remove-Item -LiteralPath $sumTmp -Force -ErrorAction SilentlyContinue }\n\
         \x20 if ($stg) { Remove-Item -LiteralPath $stg -Recurse -Force -ErrorAction SilentlyContinue }\n\
         }\n",
    );
    s
}

fn build_launcher_ps(
    relay_url: &str,
    machine_id: &str,
    has_jwks: bool,
    has_env_token: bool,
    has_extra_env: bool,
) -> String {
    let mut ps = "$ErrorActionPreference = 'Stop'\n\
         $sd = 'C:\\ProgramData\\cua\\spacesd'\n\
         Remove-Item Env:CUA_DRIVER_POLICY_FILE,Env:CUA_DRIVER_SESSION_POLICY_FILE -ErrorAction SilentlyContinue\n\
         $sid = (Get-Process -Id $PID).SessionId\n\
         if ($sid -lt 1) { throw \"cua-spacesd must run in interactive Session >= 1, got $sid\" }\n\
         $exe = [IO.File]::ReadAllText((Join-Path $sd 'bin-path'), [Text.Encoding]::UTF8).Trim()\n".to_string();
    if has_extra_env {
        ps.push_str(
            "$extra = [IO.File]::ReadAllText((Join-Path $sd 'extra-env.json'), [Text.Encoding]::UTF8) | ConvertFrom-Json\n\
             foreach ($p in $extra.PSObject.Properties) { [Environment]::SetEnvironmentVariable($p.Name, [string]$p.Value, 'Process') }\n",
        );
    }
    ps.push_str(&format!(
        "$cuaArgs = @('join','--relay',{relay},'--relay-token-file',(Join-Path $sd 'relay-token'),'--machine-id',{mid},'--host-policy',(Join-Path $sd 'host-policy.json'),'--data-dir',(Join-Path $sd 'data'))\n",
        relay = ps_single_quote(relay_url),
        mid = ps_single_quote(machine_id),
    ));
    if has_jwks {
        ps.push_str("$cuaArgs += @('--relay-jwks',(Join-Path $sd 'jwks.json'))\n");
    }
    if has_env_token {
        ps.push_str("$cuaArgs += @('--token-file',(Join-Path $sd 'env-token'))\n");
    }
    ps.push_str("& $exe @cuaArgs\n");
    ps
}

fn build_tscon_ps() -> String {
    "$ErrorActionPreference = 'Stop'\n\
     $sid = $null\n\
     $ev = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -FilterXPath '*[System[(EventID=24)]]' -MaxEvents 1 -ErrorAction SilentlyContinue\n\
     if ($ev) {\n\
     \x20 $xml = [xml]$ev.ToXml()\n\
     \x20 $sid = $xml.Event.UserData.EventXML.SessionID\n\
     }\n\
     if (-not $sid -or [int]$sid -lt 1) {\n\
     \x20 $prevEap = $ErrorActionPreference\n\
     \x20 $ErrorActionPreference = 'Continue'\n\
     \x20 try {\n\
     \x20   foreach ($l in (& \"$env:SystemRoot\\System32\\quser.exe\" 2>$null)) {\n\
     \x20     if ($l -match '\\s+(\\d+)\\s+Disc\\b') { $sid = $Matches[1]; break }\n\
     \x20   }\n\
     \x20 } finally {\n\
     \x20   $ErrorActionPreference = $prevEap\n\
     \x20 }\n\
     }\n\
     if ($sid -and [int]$sid -ge 1) {\n\
     \x20 & \"$env:SystemRoot\\System32\\tscon.exe\" $sid /dest:console\n\
     }\n"
    .into()
}

fn build_reboot_wait_ps() -> String {
    "$ErrorActionPreference = 'SilentlyContinue'\n\
     for ($i = 0; $i -lt 120 -and (Test-Path -LiteralPath 'C:\\ProgramData\\aliyun\\vminit\\POST_Main'); $i++) {\n\
     \x20 Start-Sleep -Milliseconds 500\n\
     }\n\
     & \"$env:SystemRoot\\System32\\shutdown.exe\" /r /t 0 /f /c 'cua: reboot for AutoLogon' | Out-Null\n"
    .into()
}

fn build_expire_ps() -> String {
    "$ErrorActionPreference = 'Stop'\n\
     $f = 'C:\\ProgramData\\cua\\expires'\n\
     if (-not (Test-Path -LiteralPath $f)) { exit 0 }\n\
     $exp = [long]((Get-Content -Raw -LiteralPath $f).Trim())\n\
     if ($exp -gt 0 -and [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge $exp) {\n\
     \x20 & shutdown.exe /s /t 0 /f /c 'cua: sandbox TTL reached'\n\
     }\n"
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spacesd_version_pins_to_cua_host_driver_and_version_file() {
        let ver = default_spacesd_version();
        assert_eq!(ver, cua_host::driver::SPACESD_VERSION.trim());
        let p =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../cua-spacesd/VERSION");
        if p.is_file() {
            assert_eq!(ver, std::fs::read_to_string(p).unwrap().trim());
        }
        let expected = format!(
            "https://github.com/{}/releases/download/cua-spacesd-v{ver}/{WINDOWS_SPACESD_ASSET}",
            cua_host::driver::RELEASE_REPOSITORY,
        );
        assert_eq!(default_windows_spacesd_url(), expected);
        assert_eq!(split_download_url(None), (expected, None));
    }

    #[test]
    fn split_download_url_handles_directory_and_query_preservation() {
        let (dir_url, dir_sha) =
            split_download_url(Some("https://mirror.example.com/cua-spacesd/"));
        assert_eq!(
            dir_url,
            format!("https://mirror.example.com/cua-spacesd/{WINDOWS_SPACESD_ASSET}")
        );
        assert_eq!(dir_sha, None);

        let ver = default_spacesd_version();
        let (q_url, q_sha) = split_download_url(Some(
            "https://mirror.example.com/v{version}/{arch}/?sig=SecretToken99",
        ));
        assert_eq!(
            q_url,
            format!(
                "https://mirror.example.com/v{ver}/x86_64/{WINDOWS_SPACESD_ASSET}?sig=SecretToken99"
            )
        );
        assert_eq!(q_sha, None);
    }
}

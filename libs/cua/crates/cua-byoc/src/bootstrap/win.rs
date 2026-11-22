// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! First-boot PowerShell `UserData` generator for Windows Direct VM
//! Sandboxes (`--runtime native` on `aliyun-ecs`).
//!
//! Runs under 64-bit PowerShell via `vminit` (`[powershell]`, official
//! Alibaba Cloud Windows images) or `cloudbase-init` (`#ps1_sysnative`,
//! custom Windows 10/11 images), with a WOW64 -> `Sysnative` 64-bit
//! self-relaunch guard, and:
//! 1. Stages relay/environment credentials into an SID-ACL-restricted
//!    directory (`SYSTEM`, `Administrators`, desktop user only) and removes
//!    temporary staging artifacts.
//! 2. Detects pre-installed `cua-spacesd.exe` first; otherwise downloads from
//!    the connection's custom mirror URL (or GitHub Releases by default) and
//!    verifies SHA-256 before execution.
//! 3. Blocks outbound access to cloud metadata endpoints (`100.100.100.200`,
//!    `169.254.169.254`) via Windows Defender Firewall.
//! 4. Configures unattended Windows AutoLogon and disables auto-lock,
//!    screensaver, and sleep timeouts.
//! 5. Registers an `AtLogOn` interactive scheduled task (`LogonType
//!    Interactive`, `RunLevel Highest`) running `cua-spacesd.exe join` in
//!    `SessionId >= 1` (never Session 0).
//! 6. Registers a `SYSTEM` scheduled task triggered by
//!    `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
//!    Event ID `24` to run `tscon.exe <SessionId> /dest:console`.
//! 7. Schedules an in-guest TTL shutdown backstop when `ttl_secs > 0`.

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

/// Line-1 header required by `cloudbase-init` (custom Windows 10/11 images).
pub const CLOUDBASE_HEADER: &str = "#ps1_sysnative";

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

/// Builds the compact `#ps1_sysnative` PowerShell script for `cloudbase-init`.
///
/// Secrets are base64-encoded inside the script and written directly to
/// SID-ACL-protected files (`SYSTEM`, `Administrators`, `desktop_user`),
/// never echoed to stdout/logs.
pub fn windows_user_data(boot: &WindowsVmBoot<'_>) -> String {
    windows_user_data_with_header(boot, CLOUDBASE_HEADER)
}

/// Builds the compact PowerShell `UserData` script with an explicit line-1 header
/// (`ALIYUN_VMINIT_HEADER` = `[powershell]` for Alibaba Cloud `vminit`, or
/// `CLOUDBASE_HEADER` = `#ps1_sysnative` for `cloudbase-init`) and a 64-bit
/// WOW64 -> `Sysnative` self-relaunch guard.
pub fn windows_user_data_with_header(boot: &WindowsVmBoot<'_>, header: &str) -> String {
    let (dl_url, expected_sha) = split_download_url(boot.spacesd_download_url);
    let desktop_user = if boot.desktop_user.trim().is_empty() {
        "Administrator"
    } else {
        boot.desktop_user.trim()
    };

    let relay_token_b64 = b64(&boot.join.machine_token);
    let machine_id_b64 = b64(&boot.join.machine_id);
    let policy_b64 = b64(&boot.join.policy_json());
    let has_jwks = !boot.join.jwks_json.trim().is_empty();
    let jwks_b64 = if has_jwks {
        b64(&boot.join.jwks_json)
    } else {
        String::new()
    };
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
    let pass_b64 = b64(boot.desktop_password);

    let launcher_b64 = b64(&build_launcher_ps(
        &boot.join.relay_url,
        &boot.join.machine_id,
        has_jwks,
        env_token.is_some(),
        extra_env_b64.is_some(),
    ));
    let tscon_b64 = b64(&build_tscon_ps());
    let expire_ps = (boot.ttl_secs > 0).then(|| b64(&build_expire_ps()));

    let hdr = header.trim();
    let mut s = format!(
        "{hdr}\n\
         {WOW64_SYSNATIVE_GUARD}\n\
         $ErrorActionPreference = 'Stop'\n\
         $ProgressPreference = 'SilentlyContinue'\n",
    );

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
         function Fetch([string]$u,[string]$o) {{ for ($i=1; $i -le 5; $i++) {{ try {{ Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $o; return }} catch {{ if ($i -eq 5) {{ throw }}; Start-Sleep -Seconds ($i*5) }} }} }}\n",
        prov = ps_single_quote(boot.provider),
        user = ps_single_quote(desktop_user),
    ));

    s.push_str(&format!(
        "Log \"staging secrets for $provider\"\n\
         & icacls.exe $sd /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' \"$u`:(OI)(CI)M\" /T | Out-Null\n\
         if ($LASTEXITCODE -ne 0) {{ throw \"icacls failed: $LASTEXITCODE\" }}\n\
         New-Item -ItemType Directory -Force -Path $dd | Out-Null\n\
         try {{\n\
         \x20 Put (Join-Path $sd 'relay-token') {relay_tok}\n\
         \x20 Put (Join-Path $sd 'machine-id') {mach_id}\n\
         \x20 Put (Join-Path $sd 'host-policy.json') {policy}\n",
        relay_tok = ps_single_quote(&relay_token_b64),
        mach_id = ps_single_quote(&machine_id_b64),
        policy = ps_single_quote(&policy_b64),
    ));
    if has_jwks {
        s.push_str(&format!(
            "  Put (Join-Path $sd 'jwks.json') {}\n",
            ps_single_quote(&jwks_b64)
        ));
    }
    if let Some(et) = &env_token_b64 {
        s.push_str(&format!(
            "  Put (Join-Path $sd 'env-token') {}\n",
            ps_single_quote(et)
        ));
    }
    if let Some(ee) = &extra_env_b64 {
        s.push_str(&format!(
            "  Put (Join-Path $sd 'extra-env.json') {}\n",
            ps_single_quote(ee)
        ));
    }
    s.push_str(&format!(
        "  Put (Join-Path $sd 'launch-spacesd.ps1') {launcher}\n\
         \x20 Put (Join-Path $sd 'tscon-recover.ps1') {tscon}\n",
        launcher = ps_single_quote(&launcher_b64),
        tscon = ps_single_quote(&tscon_b64),
    ));

    let expected_sha_ps = match expected_sha {
        Some(hex) => ps_single_quote(&hex.to_ascii_lowercase()),
        None => "$null".into(),
    };
    let dl_url_b64 = b64(&dl_url);
    let dl_url_redacted = cua_sandbox_core::byoc::redact_url(&dl_url);
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

    s.push_str(
        "  foreach ($ip in @('100.100.100.200','169.254.169.254')) {\n\
         \x20   $rn = \"Cua-Block-Metadata-$ip\"\n\
         \x20   Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue\n\
         \x20   New-NetFirewallRule -DisplayName $rn -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null\n\
         \x20 }\n",
    );

    s.push_str(&format!(
        "  $wl = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'\n\
         \x20 Set-ItemProperty -Path $wl -Name 'AutoAdminLogon' -Value '1' -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'DefaultUserName' -Value $u -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'DefaultDomainName' -Value $env:COMPUTERNAME -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'DefaultPassword' -Value ([Text.Encoding]::UTF8.GetString((Dec {pw}))) -Type String\n\
         \x20 Set-ItemProperty -Path $wl -Name 'ForceAutoLogon' -Value '1' -Type String\n\
         \x20 $sp = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'\n\
         \x20 if (-not (Test-Path -LiteralPath $sp)) {{ New-Item -Path $sp -Force | Out-Null }}\n\
         \x20 Set-ItemProperty -Path $sp -Name 'DisableLockWorkstation' -Value 1 -Type DWord\n\
         \x20 $pp = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization'\n\
         \x20 if (-not (Test-Path -LiteralPath $pp)) {{ New-Item -Path $pp -Force | Out-Null }}\n\
         \x20 Set-ItemProperty -Path $pp -Name 'NoLockScreen' -Value 1 -Type DWord\n\
         \x20 Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveActive' -Value '0' -Type String -ErrorAction SilentlyContinue\n\
         \x20 & reg.exe add 'HKU\\.DEFAULT\\Control Panel\\Desktop' /v ScreenSaveActive /t REG_SZ /d 0 /f | Out-Null\n\
         \x20 & powercfg.exe /change standby-timeout-ac 0 | Out-Null\n\
         \x20 & powercfg.exe /change monitor-timeout-ac 0 | Out-Null\n\
         \x20 & powercfg.exe /change hibernate-timeout-ac 0 | Out-Null\n",
        pw = ps_single_quote(&pass_b64),
    ));

    s.push_str(
        "  $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `\"$sd\\launch-spacesd.ps1`\"\"\n\
         \x20 $trg = New-ScheduledTaskTrigger -AtLogOn -User $u\n\
         \x20 $prn = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest\n\
         \x20 $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew\n\
         \x20 Register-ScheduledTask -TaskName 'cua-spacesd' -Action $act -Trigger $trg -Principal $prn -Settings $set -Force | Out-Null\n",
    );

    s.push_str(
        "  $tc = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler'\n\
         \x20 $et = New-CimInstance -CimClass $tc -ClientOnly\n\
         \x20 $et.Enabled = $true\n\
         \x20 $et.Subscription = \"<QueryList><Query Id='0' Path='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'><Select Path='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'>*[System[(EventID=24)]]</Select></Query></QueryList>\"\n\
         \x20 $tAct = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `\"$sd\\tscon-recover.ps1`\"\"\n\
         \x20 $tPrn = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n\
         \x20 $tSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances Queue\n\
         \x20 Register-ScheduledTask -TaskName 'cua-tscon-recover' -Action $tAct -Trigger $et -Principal $tPrn -Settings $tSet -Force | Out-Null\n",
    );

    if let Some(exp_b64) = expire_ps {
        let clamped = boot.ttl_secs.clamp(1, MAX_SHUTDOWN_TIMEOUT_SECS);
        s.push_str(&format!(
            "  Set-Content -LiteralPath 'C:\\ProgramData\\cua\\expires' -Value '{expires}' -NoNewline -Encoding ASCII\n\
             \x20 Put (Join-Path $sd 'expire-check.ps1') {exp_script}\n\
             \x20 $eAct = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `\"$sd\\expire-check.ps1`\"\"\n\
             \x20 $eTrg = New-ScheduledTaskTrigger -AtStartup\n\
             \x20 $eTrg.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 3650)).Repetition\n\
             \x20 Register-ScheduledTask -TaskName 'cua-expire' -Action $eAct -Trigger $eTrg -Principal $tPrn -Settings $set -Force | Out-Null\n\
             \x20 $hasSession = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object {{ $_.SessionId -ge 1 }}).Count -gt 0\n\
             \x20 if ($hasSession) {{\n\
             \x20   & shutdown.exe /s /t {clamped} /f /c 'cua: sandbox TTL reached' | Out-Null\n\
             \x20   Start-ScheduledTask -TaskName 'cua-spacesd'\n\
             \x20 }} else {{\n\
             \x20   Log 'rebooting for unattended AutoLogon interactive session'\n\
             \x20   & shutdown.exe /r /t 5 /c 'cua: reboot for AutoLogon' | Out-Null\n\
             \x20 }}\n",
            expires = boot.expires,
            exp_script = ps_single_quote(&exp_b64),
            clamped = clamped,
        ));
    } else {
        s.push_str(
            "  $hasSession = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ge 1 }).Count -gt 0\n\
             \x20 if ($hasSession) {\n\
             \x20   Start-ScheduledTask -TaskName 'cua-spacesd'\n\
             \x20 } else {\n\
             \x20   Log 'rebooting for unattended AutoLogon interactive session'\n\
             \x20   & shutdown.exe /r /t 5 /c 'cua: reboot for AutoLogon' | Out-Null\n\
             \x20 }\n",
        );
    }

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
    fn account_mode_windows_user_data_contract_and_size() {
        let j = account_join();
        let env = BTreeMap::from([("FOO_BAR".to_string(), "baz".to_string())]);
        let pw = "WinPass!1234Abcd";
        let ps = windows_user_data(&boot_cfg(&j, &env, 8 * 3600, None, pw));
        assert!(ps.starts_with("#ps1_sysnative\n"));
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
        assert!(ps.contains("100.100.100.200") && ps.contains("New-NetFirewallRule"));
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
        assert!(
            tscon.contains("$ErrorActionPreference = 'Continue'") && tscon.contains("quser.exe")
        );
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
        assert!(ps.starts_with("#ps1_sysnative\n") && ps.len() < MAX_USER_DATA_BYTES);
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

        let templated = format!(
            "https://mirror.example.com/v{{version}}/cua-spacesd-{{arch}}.exe#sha256={hex}"
        );
        let (url, sha) = split_download_url(Some(&templated));
        assert_eq!(
            url,
            format!("https://mirror.example.com/v{ver}/cua-spacesd-x86_64.exe")
        );
        assert_eq!(sha, Some(hex.as_str()));

        let (dir_url, dir_sha) =
            split_download_url(Some("https://mirror.example.com/cua-spacesd/"));
        assert_eq!(
            dir_url,
            format!("https://mirror.example.com/cua-spacesd/{WINDOWS_SPACESD_ASSET}")
        );
        assert_eq!(dir_sha, None);

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

        let j = static_join();
        let env = BTreeMap::new();
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
            "https://mirror.example.com/v{ver}/x86_64/{WINDOWS_SPACESD_ASSET}"
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

        // Launcher explicitly decodes bin-path and extra-env.json as UTF-8 (safe on CP936/GBK).
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
            dbg.contains("<redacted>")
                && dbg.contains("https://mirror.example.com/cua-spacesd.exe")
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
        let ps = windows_user_data_with_header(
            &boot_cfg(&j, &env, 8 * 3600, None, "WinPass!1234Abcd"),
            ALIYUN_VMINIT_HEADER,
        );
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
    fn registry_policy_keys_guard_new_item_with_test_path() {
        let j = static_join();
        let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "env_secret_static_reg".into())]);
        let boot = boot_cfg(&j, &env, 8 * 3600, None, "WinPass!1234Abcd");
        for ps in [
            windows_user_data(&boot),
            windows_user_data_with_header(&boot, ALIYUN_VMINIT_HEADER),
        ] {
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
            assert!(ps.contains(
                "Set-ItemProperty -Path $sp -Name 'DisableLockWorkstation' -Value 1 -Type DWord"
            ));
            assert!(
                ps.contains("Set-ItemProperty -Path $pp -Name 'NoLockScreen' -Value 1 -Type DWord")
            );
        }
    }

    #[test]
    fn finally_cleanup_guards_nullable_temp_paths_against_null_binding() {
        let j = static_join();
        let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "env_secret_static_finally".into())]);
        let pinned_mirror = format!(
            "https://mirror.example.com/cua-spacesd.exe#sha256={}",
            "ab".repeat(32)
        );
        for url in [None, Some(pinned_mirror.as_str())] {
            let boot = boot_cfg(&j, &env, 8 * 3600, url, "WinPass!1234Abcd");
            for ps in [
                windows_user_data(&boot),
                windows_user_data_with_header(&boot, ALIYUN_VMINIT_HEADER),
            ] {
                assert!(ps.len() < MAX_USER_DATA_BYTES);
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
    }
}

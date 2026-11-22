// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Target preparation shared by `cua cloud test`, `cua cloud connect`, OIDC,
//! and sealed connection flows: validates custom VPC/network flags, merges
//! connection image/sizing defaults, resolves relay settings, and normalizes
//! `spacesd_download_url`.

use std::path::Path;

use cua_sandbox_core::Error;
use cua_sandbox_core::byoc::{CloudTarget, RelayMode};

use crate::api::{CloudApi, Result, Secret};
use crate::model::Connection;
use crate::provider::{family_of, runtime_word};
use cua_sandbox_core::provider::ProviderCreate;

/// Validated relay target resolved from `CloudTarget` + existing `Connection`.
pub(crate) struct ResolvedTargetRelay {
    pub mode: RelayMode,
    pub url: Option<String>,
    pub stored_mode: Option<RelayMode>,
    pub staged_token: Option<Secret>,
    pub probe_url: Option<String>,
}

/// Fully validated and merged connection target ready for `test`, `connect`,
/// `connect_oidc`, or `connect_sealed`.
pub(crate) struct PreparedTarget {
    pub target: CloudTarget,
    pub existing: Option<Connection>,
    pub relay: ResolvedTargetRelay,
    pub spacesd_download_url: Option<String>,
}

impl PreparedTarget {
    pub(crate) fn prepare(
        home: Option<&Path>,
        p: &dyn CloudApi,
        target: &CloudTarget,
        existing: Option<Connection>,
    ) -> Result<Self> {
        validate_target_network_flags(p, target)?;
        let merged = merge_image_defaults(p, target, existing.as_ref())?;
        let relay = resolve_target_relay(home, p.name(), &merged, existing.as_ref())?;
        let spacesd_download_url = resolve_target_spacesd_download_url(&merged, existing.as_ref())?;
        Ok(Self {
            target: merged,
            existing,
            relay,
            spacesd_download_url,
        })
    }

    pub(crate) fn apply_to(&self, conn: &mut Connection) {
        conn.relay_url = self.relay.url.clone();
        conn.relay_mode = self.relay.stored_mode;
        conn.spacesd_download_url = self.spacesd_download_url.clone();
    }
}

pub(crate) fn normalize_spacesd_download_url(raw: &str) -> Result<String> {
    let trimmed = cua_sandbox_core::byoc::validate_spacesd_download_url(raw)?;
    let (url_part, frag) = match trimmed.split_once('#') {
        Some((u, f)) => (u, Some(f)),
        None => (trimmed.as_str(), None),
    };
    if let Some(f) = frag {
        let Some(hex) = f.strip_prefix("sha256=") else {
            return Err(Error::InvalidArgument(
                "--spacesd-download-url fragment must be `#sha256=<64 hex>`".into(),
            ));
        };
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidArgument(
                "--spacesd-download-url `#sha256=` must be 64 hex characters".into(),
            ));
        }
        return Ok(format!("{url_part}#sha256={}", hex.to_ascii_lowercase()));
    }
    let parsed = url::Url::parse(url_part).map_err(|_| {
        Error::InvalidArgument("--spacesd-download-url must be a valid http(s) URL".into())
    })?;
    if parsed.query().is_some() {
        return Err(Error::InvalidArgument(
            "--spacesd-download-url with a query string must include `#sha256=<64 hex>` (sidecar `.sha256` cannot be appended to a signed query)"
                .into(),
        ));
    }
    Ok(url_part.to_string())
}

pub(crate) fn resolve_target_spacesd_download_url(
    target: &CloudTarget,
    existing: Option<&Connection>,
) -> Result<Option<String>> {
    match target.spacesd_download_url.as_deref() {
        Some(raw) => Ok(Some(normalize_spacesd_download_url(raw)?)),
        None => Ok(existing.and_then(|c| c.spacesd_download_url.clone())),
    }
}

pub(crate) fn validate_target_network_flags(p: &dyn CloudApi, target: &CloudTarget) -> Result<()> {
    if !p.supports_custom_vpc()
        && (target.vpc_id.is_some() || target.vswitch_id.is_some() || target.no_public_ip)
    {
        return Err(Error::InvalidArgument(format!(
            "--vpc-id, --vswitch-id, and --no-public-ip are not supported for {}",
            p.name()
        )));
    }
    Ok(())
}

pub(crate) fn merge_image_defaults(
    p: &dyn CloudApi,
    target: &CloudTarget,
    existing: Option<&Connection>,
) -> Result<CloudTarget> {
    if !p.supports_image_defaults() {
        for (present, flag) in [
            (target.windows_image_id.is_some(), "--windows-image-id"),
            (target.linux_image_id.is_some(), "--linux-image-id"),
            (target.instance_type.is_some(), "--instance-type"),
        ] {
            if present {
                return Err(Error::InvalidArgument(format!(
                    "{flag} is not supported for {}",
                    p.name()
                )));
            }
        }
        return Ok(target.clone());
    }
    let mut merged = target.clone();
    if merged.windows_image_id.is_none() {
        merged.windows_image_id = existing.and_then(|c| c.windows_image_id.clone());
    }
    if merged.linux_image_id.is_none() {
        merged.linux_image_id = existing.and_then(|c| c.linux_image_id.clone());
    }
    if merged.instance_type.is_none() {
        merged.instance_type = existing.and_then(|c| c.instance_type.clone());
    }
    Ok(merged)
}

pub(crate) fn resolve_target_relay(
    home: Option<&Path>,
    provider: &str,
    target: &CloudTarget,
    existing: Option<&Connection>,
) -> Result<ResolvedTargetRelay> {
    let mode = target
        .relay_mode
        .or_else(|| existing.and_then(|c| c.relay_mode))
        .unwrap_or(RelayMode::Account);
    let mut staged_token = None;
    match mode {
        RelayMode::Account => {
            if target.relay_token.is_some() {
                return Err(Error::InvalidArgument(
                    "--relay-token-stdin applies only to --relay-mode static".into(),
                ));
            }
        }
        RelayMode::Static => match target.relay_token.as_deref() {
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(Error::InvalidArgument(
                        "--relay-token-stdin was empty; expected a static relay token".into(),
                    ));
                }
                staged_token = Some(Secret::new(trimmed));
            }
            None => {
                if crate::relay::load_static_relay_token(home, provider)?.is_none() {
                    return Err(Error::InvalidArgument(
                        "Static Relay Mode requires --relay-token-stdin (or a previously saved \
                         static relay token)"
                            .into(),
                    ));
                }
            }
        },
    }
    let url = match target.relay_url.as_deref() {
        Some(raw) => Some(
            cua_host::relay::normalize_base(raw)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?,
        ),
        None if target.relay_mode.is_none() => existing.and_then(|c| c.relay_url.clone()),
        None if mode == RelayMode::Static => existing
            .filter(|c| c.is_static_relay())
            .and_then(|c| c.relay_url.clone()),
        None => None,
    };
    if mode == RelayMode::Static && url.is_none() {
        return Err(Error::InvalidArgument(
            "--relay-url is required in Static Relay Mode".into(),
        ));
    }
    let stored_mode = match mode {
        RelayMode::Account if url.is_none() => None,
        m => Some(m),
    };
    let probe_url = url.clone();
    Ok(ResolvedTargetRelay {
        mode,
        url,
        stored_mode,
        staged_token,
        probe_url,
    })
}

pub(crate) fn create_family(spec: &ProviderCreate) -> &'static str {
    if spec.os.eq_ignore_ascii_case("windows") {
        "windows"
    } else if spec.os.eq_ignore_ascii_case("macos") {
        "macos"
    } else if spec.os.eq_ignore_ascii_case("linux") {
        let r = spec.image.reference.to_ascii_lowercase();
        if r.contains("macos") {
            "macos"
        } else if r.contains("omarchy") {
            "omarchy"
        } else if r.contains("-slim") {
            "linux-slim"
        } else {
            "linux"
        }
    } else {
        family_of(&spec.image.reference)
    }
}

pub(crate) fn resolve_kind_and_runtime(
    api: &dyn CloudApi,
    family: &str,
    spec: &ProviderCreate,
) -> Result<(&'static str, String)> {
    let asked = runtime_word(api, &spec.runtime)?;
    let offered = api.runtimes();
    if family == "windows" {
        if !api
            .supported_oses()
            .iter()
            .any(|os| os.eq_ignore_ascii_case("windows"))
        {
            return Err(Error::UnsupportedImage(format!(
                "{} does not run windows sandboxes",
                api.title()
            )));
        }
        if asked == "docker" || (!asked.is_empty() && asked != "native") {
            return Err(Error::UnsupportedImage(format!(
                "windows on {} requires --runtime native (Docker-on-VM does not support Windows guests)",
                api.title()
            )));
        }
        let rt = if asked.is_empty() && offered.iter().any(|r| r.as_str() == "native") {
            "native".to_string()
        } else {
            asked
        };
        return Ok(("vm", rt));
    }
    if asked == "native" {
        if !offered.iter().any(|r| r.as_str() == "native") {
            return Err(Error::Unsupported {
                provider: cua_sandbox_core::ProviderKind::Contrib,
                op: format!(
                    "{} does not support Linux Direct VM (--runtime native)",
                    api.title()
                ),
            });
        }
        return Ok(("vm", "native".to_string()));
    }
    let rt = if asked.is_empty() && offered.iter().any(|r| r.as_str() == "docker") {
        "docker".to_string()
    } else {
        asked
    };
    Ok(("container", rt))
}

pub(crate) fn validate_custom_create_options(
    api: &dyn CloudApi,
    spec: &ProviderCreate,
) -> Result<(Option<String>, Option<String>)> {
    if spec.disk_gb == Some(0) {
        return Err(Error::InvalidArgument(
            "disk_gb must be greater than 0".into(),
        ));
    }
    let cloud_image_id = cua_sandbox_core::byoc::normalize_optional_token(
        "cloud_image_id",
        spec.cloud_image_id.as_deref(),
    )?;
    let spec_instance_type = cua_sandbox_core::byoc::normalize_optional_token(
        "instance_type",
        spec.instance_type.as_deref(),
    )?;
    if !api.supports_custom_image_and_sizing() {
        if spec.disk_gb.is_some() {
            return Err(Error::InvalidArgument(
                "disk_gb sizes local VMs only: provider sandboxes boot the image's disk".into(),
            ));
        }
        if cloud_image_id.is_some() {
            return Err(cua_sandbox_core::provider::unsupported(
                api.name(),
                "custom Cloud Image IDs (--cloud-image-id)",
            ));
        }
        if spec_instance_type.is_some() {
            return Err(cua_sandbox_core::provider::unsupported(
                api.name(),
                "custom instance types (--instance-type)",
            ));
        }
    }
    Ok((cloud_image_id, spec_instance_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spacesd_download_url_validation_and_preservation() {
        assert_eq!(
            normalize_spacesd_download_url("  https://mirror.example.com/cua-spacesd.exe  ")
                .unwrap(),
            "https://mirror.example.com/cua-spacesd.exe"
        );
        assert_eq!(
            normalize_spacesd_download_url("http://10.0.0.5:8080/cua-spacesd.exe").unwrap(),
            "http://10.0.0.5:8080/cua-spacesd.exe"
        );
        let hex = "A".repeat(64);
        assert_eq!(
            normalize_spacesd_download_url(&format!(
                "https://mirror.example.com/cua-spacesd.exe#sha256={hex}"
            ))
            .unwrap(),
            format!(
                "https://mirror.example.com/cua-spacesd.exe#sha256={}",
                "a".repeat(64)
            )
        );
        for bad in [
            "",
            "   ",
            "ftp://mirror.example/a.exe",
            "https:///no-host.exe",
            "https://user:pass@/cua-spacesd.exe",
            "https://@/cua-spacesd.exe",
            "https://mirror.example.com:notaport/cua-spacesd.exe",
            "https://mirror.example/with space.exe",
            "https://mirror.example/with'quote.exe",
            "https://mirror.example.com/cua\u{2018}.exe",
            "https://mirror.example.com/cua\u{2019};Invoke-Expression(whoami);#sha256=abababababababababababababababababababababababababababababababab",
            "https://mirror.example.com/cua\u{201A}.exe",
            "https://mirror.example.com/cua\u{201B}.exe",
            "https://bucket.example.com/cua-spacesd.exe?sig=DeadBeefCafe9988",
            "https://mirror.example/a.exe#sha256=short",
            "https://mirror.example/a.exe#other=123",
            &format!(
                "https://dluser:MyPass998877@mirror.example.com/cua-spacesd.exe?sig=DeadBeefCafe9988#sha256={hex}"
            ),
        ] {
            let err = normalize_spacesd_download_url(bad).unwrap_err();
            assert!(!err.to_string().contains("DeadBeefCafe9988"), "{err}");
            assert!(!err.to_string().contains("MyPass998877"), "{err}");
        }
        assert_eq!(
            normalize_spacesd_download_url(&format!(
                "https://mirror.example.com/cua-spacesd.exe?sig=DeadBeefCafe9988#sha256={hex}"
            ))
            .unwrap(),
            format!(
                "https://mirror.example.com/cua-spacesd.exe?sig=DeadBeefCafe9988#sha256={}",
                "a".repeat(64)
            )
        );

        let existing = Connection {
            spacesd_download_url: Some("https://old.example/cua-spacesd.exe".into()),
            ..Default::default()
        };
        let omitted = CloudTarget {
            provider: "aliyun-ecs".into(),
            ..Default::default()
        };
        assert_eq!(
            resolve_target_spacesd_download_url(&omitted, Some(&existing)).unwrap(),
            Some("https://old.example/cua-spacesd.exe".into())
        );
        let updated = CloudTarget {
            provider: "aliyun-ecs".into(),
            spacesd_download_url: Some("https://new.example/cua-spacesd.exe".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_target_spacesd_download_url(&updated, Some(&existing)).unwrap(),
            Some("https://new.example/cua-spacesd.exe".into())
        );
    }
}

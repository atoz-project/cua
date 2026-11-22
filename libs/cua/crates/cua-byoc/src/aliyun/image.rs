// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Alibaba Cloud ECS Cloud Image ID resolution, validation, official OS
//! image fallback, and Windows init header selection.

use cua_sandbox_core::Error;
use serde_json::Value;

use super::AliyunEcs;
use super::client::ECS_API_VERSION;
use super::sizing::system_disk_for;
use crate::api::Result;
use crate::model::{Connection, ProvisionSpec};

pub use crate::api::WindowsInitHeader;

/// Resolved Alibaba Cloud ECS Cloud Image ID and metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedCloudImage {
    /// Alibaba Cloud ECS `ImageId` (e.g. `m-...` or `ubuntu_24_04_x64_...vhd`).
    pub image_id: String,
    /// Guest `OSType` reported by `DescribeImages` (`linux` or `windows`).
    pub os_type: String,
    /// Image size in GiB when reported by `DescribeImages`.
    pub size_gb: Option<u32>,
    /// Precedence tier (`"per-create"`, `"connection-default"`, or `"official-fallback"`).
    pub source: &'static str,
    /// Lowercased `ImageOwnerAlias` from `DescribeImages` (`"system"`, `"self"`, etc.).
    pub owner_alias: Option<String>,
}

impl ResolvedCloudImage {
    /// Whether this image is an official Alibaba Cloud system image (uses `vminit`).
    pub fn is_official_aliyun(&self) -> bool {
        self.source == "official-fallback"
            || self.owner_alias.as_deref() == Some("system")
            || self.image_id.contains("_alibase_")
    }

    /// The Windows `UserData` line-1 header required by this image's init agent.
    pub fn windows_init_header(&self) -> WindowsInitHeader {
        if self.is_official_aliyun() {
            WindowsInitHeader::AliyunVminit
        } else {
            WindowsInitHeader::CloudbaseSysnative
        }
    }
}

pub(crate) fn pick_official_image(arr: &[Value], is_windows: bool) -> Option<&Value> {
    fn is_en(img: &Value) -> bool {
        let name = img["ImageName"].as_str().unwrap_or("").to_ascii_lowercase();
        let en = img["OSNameEn"].as_str().unwrap_or("").to_ascii_lowercase();
        name.contains("en-us") || name.contains("_en_") || en.contains("english")
    }
    fn pick_best<'a>(candidates: &[&'a Value], prefer_en: bool) -> Option<&'a Value> {
        candidates
            .iter()
            .copied()
            .filter(|img| {
                img["Status"].as_str() == Some("Available")
                    && img["ImageId"]
                        .as_str()
                        .is_some_and(|s| !s.trim().is_empty())
            })
            .max_by(|a, b| {
                let ea = prefer_en && is_en(a);
                let eb = prefer_en && is_en(b);
                ea.cmp(&eb).then_with(|| {
                    let ta = a["CreationTime"].as_str().unwrap_or("");
                    let tb = b["CreationTime"].as_str().unwrap_or("");
                    ta.cmp(tb).then_with(|| {
                        a["ImageId"]
                            .as_str()
                            .unwrap_or("")
                            .cmp(b["ImageId"].as_str().unwrap_or(""))
                    })
                })
            })
    }

    let all: Vec<&Value> = arr.iter().collect();
    if is_windows {
        let is_win_server = |img: &Value, needle: &str| {
            let name = img["ImageName"].as_str().unwrap_or("").to_ascii_lowercase();
            let id = img["ImageId"].as_str().unwrap_or("").to_ascii_lowercase();
            let os_name = img["OSNameEn"].as_str().unwrap_or("").to_ascii_lowercase();
            let platform = img["Platform"].as_str().unwrap_or("").to_ascii_lowercase();
            name.contains(needle)
                || id.contains(needle)
                || os_name.contains(needle)
                || platform.contains(needle)
        };
        let win2022: Vec<&Value> = all
            .iter()
            .copied()
            .filter(|i| is_win_server(i, "win2022") || is_win_server(i, "2022"))
            .collect();
        let win2019: Vec<&Value> = all
            .iter()
            .copied()
            .filter(|i| is_win_server(i, "win2019") || is_win_server(i, "2019"))
            .collect();
        let server_any: Vec<&Value> = all
            .iter()
            .copied()
            .filter(|i| is_win_server(i, "server") || is_win_server(i, "win20"))
            .collect();
        pick_best(&win2022, true)
            .or_else(|| pick_best(&win2019, true))
            .or_else(|| pick_best(&server_any, true))
            .or_else(|| pick_best(&all, true))
    } else {
        pick_best(&all, false)
    }
}

/// Validates an explicit Cloud Image ID (custom `m-xxx`, shared, marketplace, or official)
/// in `region` via `ecs:DescribeImages` without `ImageOwnerAlias=system`.
pub(crate) async fn validate_image_id(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    image_id: &str,
    expected_os: &str,
) -> Result<ResolvedCloudImage> {
    let image_id = image_id.trim();
    if image_id.is_empty() {
        return Err(Error::InvalidArgument(
            "aliyun-ecs: Cloud Image ID cannot be empty".into(),
        ));
    }
    let profile_hint = api.profile_hint(conn);
    let v = api
        .call_ok(
            &api.ecs_endpoint(region),
            "GET",
            "DescribeImages",
            ECS_API_VERSION,
            &[
                ("RegionId".into(), region.to_string()),
                ("ImageId".into(), image_id.to_string()),
            ],
            profile_hint,
        )
        .await?;
    let images = v["Images"]["Image"].as_array();
    let Some(img) = images.and_then(|arr| {
        arr.iter()
            .find(|i| i["ImageId"].as_str() == Some(image_id))
            .or_else(|| arr.first())
    }) else {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: Cloud Image ID {image_id:?} was not found in region {region}"
        )));
    };
    let status = img["Status"].as_str().unwrap_or("");
    if status != "Available" {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: Cloud Image ID {image_id:?} in region {region} has status {status:?} (expected \"Available\")"
        )));
    }
    let os_type = img["OSType"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if os_type.is_empty() {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: Cloud Image ID {image_id:?} in region {region} is missing OSType metadata (expected {expected_os:?})"
        )));
    }
    if !os_type.eq_ignore_ascii_case(expected_os) {
        return Err(Error::InvalidArgument(format!(
            "aliyun-ecs: Cloud Image ID {image_id:?} has OSType {os_type:?}, expected {expected_os:?}"
        )));
    }
    let size_gb = img["Size"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|&n| n > 0);
    let owner_alias = img["ImageOwnerAlias"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase);
    Ok(ResolvedCloudImage {
        image_id: img["ImageId"]
            .as_str()
            .unwrap_or(image_id)
            .trim()
            .to_string(),
        os_type,
        size_gb,
        source: "explicit",
        owner_alias,
    })
}

/// Looks up the newest available official Alibaba Cloud system image for `target_os`
/// (`"linux"` -> Ubuntu 24.04; `"windows"` -> Windows Server 2022/2019) in `region`.
pub(crate) async fn resolve_official_image(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    target_os: &str,
) -> Result<ResolvedCloudImage> {
    let profile_hint = api.profile_hint(conn);
    let ecs = api.ecs_endpoint(region);
    let is_windows = target_os.eq_ignore_ascii_case("windows");

    let query_images = |image_name: Option<&'static str>| {
        let mut params = vec![
            ("RegionId".into(), region.to_string()),
            ("ImageOwnerAlias".into(), "system".into()),
            (
                "OSType".into(),
                if is_windows { "windows" } else { "linux" }.into(),
            ),
            ("Status".into(), "Available".into()),
            ("Architecture".into(), "x86_64".into()),
            ("PageSize".into(), "100".into()),
        ];
        if let Some(pat) = image_name {
            params.push(("ImageName".into(), pat.into()));
        }
        let ecs = ecs.clone();
        async move {
            let v = api
                .call_ok(
                    &ecs,
                    "GET",
                    "DescribeImages",
                    ECS_API_VERSION,
                    &params,
                    profile_hint,
                )
                .await?;
            Ok::<Vec<Value>, Error>(v["Images"]["Image"].as_array().cloned().unwrap_or_default())
        }
    };

    let chosen_val = if is_windows {
        let mut picked = None;
        for pat in [Some("win2022*"), Some("win2019*"), None] {
            let arr = query_images(pat).await?;
            if let Some(img) = pick_official_image(&arr, true) {
                picked = Some(img.clone());
                break;
            }
        }
        picked
    } else {
        let arr = query_images(Some("ubuntu_24_04_x64*")).await?;
        pick_official_image(&arr, false).cloned()
    };

    let Some(img) = chosen_val else {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: no official {} system image found in region {region}",
            if is_windows {
                "Windows Server"
            } else {
                "Ubuntu 24.04"
            },
        )));
    };
    let image_id = img["ImageId"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_string();
    let size_gb = img["Size"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|&n| n > 0);
    let owner_alias = img["ImageOwnerAlias"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .or_else(|| Some("system".to_string()));
    Ok(ResolvedCloudImage {
        image_id,
        os_type: if is_windows { "windows" } else { "linux" }.into(),
        size_gb,
        source: "official-fallback",
        owner_alias,
    })
}

/// Resolves Cloud Image ID in precedence order within `spec.region_or(conn)`:
/// 1. per-create `spec.cloud_image_id` (`--cloud-image-id`)
/// 2. connection default (`conn.windows_image_id` / `conn.linux_image_id`)
/// 3. latest official Alibaba Cloud Windows Server or Ubuntu 24.04 image.
pub(crate) async fn resolve_image_id(
    api: &AliyunEcs,
    conn: &Connection,
    spec: &ProvisionSpec,
) -> Result<ResolvedCloudImage> {
    let region = spec.region_or(conn);
    let target_os = if spec.family == "windows" {
        "windows"
    } else {
        "linux"
    };
    let mut resolved = if let Some(per_create) = spec
        .cloud_image_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut img = validate_image_id(api, conn, region, per_create, target_os).await?;
        img.source = "per-create";
        img
    } else {
        let conn_default = if target_os == "windows" {
            conn.windows_image_id.as_deref()
        } else {
            conn.linux_image_id.as_deref()
        };
        if let Some(def_id) = conn_default.map(str::trim).filter(|s| !s.is_empty()) {
            let mut img = validate_image_id(api, conn, region, def_id, target_os).await?;
            img.source = "connection-default";
            img
        } else {
            resolve_official_image(api, conn, region, target_os).await?
        }
    };
    let requested_or_default = if spec.disk_gb > 0 {
        spec.disk_gb
    } else {
        system_disk_for(spec).0
    };
    if let Some(min_gb) = resolved.size_gb
        && requested_or_default < min_gb
    {
        return Err(Error::InvalidArgument(format!(
            "aliyun-ecs: requested disk size {requested_or_default} GiB is smaller than Cloud Image ID {:?} minimum size ({min_gb} GiB)",
            resolved.image_id
        )));
    }
    if resolved.os_type.is_empty() {
        resolved.os_type = target_os.to_string();
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_official_image_requires_explicit_available_status() {
        let images = vec![
            serde_json::json!({
                "ImageId": "ubuntu_missing_status",
                "ImageName": "ubuntu_24_04_x64_missing",
                "CreationTime": "2026-01-01T00:00:00Z"
            }),
            serde_json::json!({
                "ImageId": "ubuntu_available",
                "ImageName": "ubuntu_24_04_x64_ok",
                "Status": "Available",
                "CreationTime": "2025-01-01T00:00:00Z"
            }),
        ];
        let picked = pick_official_image(&images, false).unwrap();
        assert_eq!(picked["ImageId"].as_str(), Some("ubuntu_available"));
    }

    #[test]
    fn windows_init_header_matches_official_vs_custom_images() {
        let official = ResolvedCloudImage {
            image_id: "win2022_x64_alibase.vhd".into(),
            os_type: "windows".into(),
            size_gb: Some(40),
            source: "official-fallback",
            owner_alias: Some("system".into()),
        };
        assert_eq!(
            official.windows_init_header(),
            WindowsInitHeader::AliyunVminit
        );
        let custom = ResolvedCloudImage {
            image_id: "m-custom-win11".into(),
            os_type: "windows".into(),
            size_gb: Some(60),
            source: "per-create",
            owner_alias: Some("self".into()),
        };
        assert_eq!(
            custom.windows_init_header(),
            WindowsInitHeader::CloudbaseSysnative
        );
    }
}

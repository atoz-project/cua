// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Instance lifecycle operations (`describe`, `stop`, `start`, `delete`,
//! `list_owned`, `boot_log`) for `aliyun-ecs`.

use std::collections::BTreeMap;

use base64::Engine as _;
use cua_sandbox_core::Error;

use super::AliyunEcs;
use super::client::{
    ApiBody, ECS_API_VERSION, api_error_code_message, is_instance_not_found, map_api_error,
    state_of,
};
use super::existing_vpc;
use super::net;
use crate::api::{Result, SweepDelete};
use crate::model::{self, Connection, Resource, tag};

pub(crate) const DECOMMISSIONED_TAG_KEY: &str = "cua-decommissioned";

fn is_permission_denied(code: &str) -> bool {
    matches!(
        code,
        "Forbidden.RAM" | "Forbidden.Unauthorized" | "UnauthorizedOperation" | "NoPermission"
    )
}

pub(crate) fn effective_region<'a>(conn: &'a Connection, r: &'a Resource) -> &'a str {
    if r.region.is_empty() {
        conn.region.as_str()
    } else {
        r.region.as_str()
    }
}

/// Normalizes Alibaba Cloud ECS ISO-8601 timestamps into RFC3339 strings
/// accepted by [`humantime::parse_rfc3339`], expanding ECS `DescribeInstances`
/// minute-precision `YYYY-MM-DDTHH:MMZ` (17 chars) to `YYYY-MM-DDTHH:MM:00Z`.
pub(crate) fn normalize_aliyun_iso8601(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if s.len() == 17 && s.is_ascii() && s.as_bytes()[10] == b'T' && s.ends_with('Z') {
        Some(format!("{}:00Z", &s[..16]))
    } else {
        Some(s.to_string())
    }
}

fn parse_auto_release_secs(inst: &serde_json::Value) -> Option<u64> {
    inst["AutoReleaseTime"]
        .as_str()
        .and_then(normalize_aliyun_iso8601)
        .and_then(|s| humantime::parse_rfc3339(&s).ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

struct OwnedInstance {
    state: String,
    cloud_auto_release: Option<u64>,
}

impl AliyunEcs {
    async fn describe_instance_raw(
        &self,
        conn: &Connection,
        r: &Resource,
    ) -> Result<Option<(String, BTreeMap<String, String>, Option<u64>)>> {
        if r.id.is_empty() || r.resource_type != "instance" {
            return Ok(None);
        }
        let region = effective_region(conn, r);
        let profile_hint = self.profile_hint(conn);
        let ids_json = serde_json::to_string(&[&r.id]).unwrap_or_default();
        let v = self
            .call_ok(
                &self.ecs_endpoint(region),
                "GET",
                "DescribeInstances",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    ("InstanceIds".into(), ids_json),
                ],
                profile_hint,
            )
            .await?;
        let Some(inst) = v["Instances"]["Instance"]
            .as_array()
            .and_then(|a| a.first())
        else {
            return Ok(None);
        };
        let tags = net::tags_of(inst);
        let state = if tags.get(DECOMMISSIONED_TAG_KEY).map(String::as_str) == Some("true") {
            "terminated".to_string()
        } else {
            state_of(inst["Status"].as_str().unwrap_or(""))
        };
        Ok(Some((state, tags, parse_auto_release_secs(inst))))
    }

    fn refuse_unowned(verb: &str, r: &Resource, owner: &str) -> Error {
        Error::Cloud(format!(
            "aliyun-ecs: refusing to {verb} {} {} (it does not carry {}=true and {}={})",
            r.resource_type,
            r.id,
            tag::MANAGED,
            tag::OWNER,
            model::label_value(owner)
        ))
    }

    async fn reject_non_instance_stop_start(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
        verb: &str,
    ) -> Result<()> {
        if net::is_network_type(&r.resource_type) {
            let Some((_, tags)) = self.describe_resource(conn, r).await? else {
                return Err(Error::NotFound(format!(
                    "aliyun-ecs {} {}",
                    r.resource_type, r.id
                )));
            };
            if !model::is_ours(&tags, owner) {
                return Err(Self::refuse_unowned(verb, r, owner));
            }
        }
        Err(Error::InvalidArgument(format!(
            "aliyun-ecs: cannot {verb} {}",
            r.resource_type
        )))
    }

    async fn inspect_owned_instance(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
        verb: &str,
    ) -> Result<Option<OwnedInstance>> {
        let Some((state, tags, cloud_auto_release)) = self.describe_instance_raw(conn, r).await?
        else {
            return Ok(None);
        };
        if !model::is_ours(&tags, owner) {
            return Err(Self::refuse_unowned(verb, r, owner));
        }
        Ok(Some(OwnedInstance {
            state,
            cloud_auto_release,
        }))
    }

    async fn stop_owned_instance(
        &self,
        conn: &Connection,
        r: &Resource,
        initial_state: &str,
        force: bool,
    ) -> Result<()> {
        let mut state = initial_state.to_string();
        if matches!(state.as_str(), "stopped" | "terminated" | "deleted") {
            return Ok(());
        }
        if force && state == "pending" {
            for _ in 0..30 {
                tokio::time::sleep(self.poll_interval()).await;
                match self
                    .describe_resource(conn, r)
                    .await?
                    .map(|(s, _)| s)
                    .as_deref()
                {
                    Some("pending") => {}
                    Some("stopped" | "terminated" | "deleted") | None => return Ok(()),
                    Some(next) => {
                        state = next.to_string();
                        break;
                    }
                }
            }
        }
        if matches!(state.as_str(), "stopped" | "terminated" | "deleted") {
            return Ok(());
        }
        let region = effective_region(conn, r);
        let profile_hint = self.profile_hint(conn);
        if state != "stopping" {
            let mut params = vec![
                ("InstanceId".into(), r.id.clone()),
                ("StoppedMode".into(), "StopCharging".into()),
            ];
            if force {
                params.push(("ForceStop".into(), "true".into()));
            }
            let (s_status, s_body) = self
                .call_raw(
                    &self.ecs_endpoint(region),
                    "POST",
                    "StopInstance",
                    ECS_API_VERSION,
                    &params,
                    profile_hint,
                )
                .await?;
            if !s_status.is_success() {
                let s_code = match &s_body {
                    ApiBody::Json(v) => api_error_code_message(v).0,
                    ApiBody::Text(_) => "",
                };
                if is_instance_not_found(s_code) {
                    return Ok(());
                }
                if !(force && s_code == "IncorrectInstanceStatus") {
                    return Err(map_api_error(
                        "StopInstance",
                        ECS_API_VERSION,
                        s_status,
                        &s_body,
                    ));
                }
            }
        }
        for _ in 0..60 {
            match self
                .describe_resource(conn, r)
                .await?
                .map(|(s, _)| s)
                .as_deref()
            {
                Some("stopped" | "terminated" | "deleted") | None => return Ok(()),
                _ => tokio::time::sleep(self.poll_interval()).await,
            }
        }
        Err(Error::Timeout(format!(
            "aliyun-ecs: instance {} did not reach Stopped state",
            r.id
        )))
    }

    pub(crate) async fn describe_resource(
        &self,
        conn: &Connection,
        r: &Resource,
    ) -> Result<Option<(String, BTreeMap<String, String>)>> {
        if r.id.is_empty() {
            return Ok(None);
        }
        if net::is_network_type(&r.resource_type) {
            return net::describe_part(self, conn, r).await;
        }
        Ok(self
            .describe_instance_raw(conn, r)
            .await?
            .map(|(state, tags, _)| (state, tags)))
    }

    pub(crate) async fn stop_resource(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
    ) -> Result<()> {
        if r.resource_type != "instance" {
            return self
                .reject_non_instance_stop_start(conn, r, owner, "stop")
                .await;
        }
        let Some(owned) = self.inspect_owned_instance(conn, r, owner, "stop").await? else {
            return Err(Error::NotFound(format!("aliyun-ecs instance {}", r.id)));
        };
        if matches!(owned.state.as_str(), "terminated" | "deleted") {
            return Err(Error::NotFound(format!("aliyun-ecs instance {}", r.id)));
        }
        self.stop_owned_instance(conn, r, &owned.state, false).await
    }

    pub(crate) async fn start_resource(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
    ) -> Result<()> {
        if r.resource_type != "instance" {
            return self
                .reject_non_instance_stop_start(conn, r, owner, "start")
                .await;
        }
        let Some(owned) = self.inspect_owned_instance(conn, r, owner, "start").await? else {
            return Err(Error::NotFound(format!("aliyun-ecs instance {}", r.id)));
        };
        if matches!(owned.state.as_str(), "terminated" | "deleted") {
            return Err(Error::NotFound(format!("aliyun-ecs instance {}", r.id)));
        }
        let state = owned.state;
        if state == "running" {
            return Ok(());
        }
        if state == "stopping" {
            for _ in 0..60 {
                match self
                    .describe_resource(conn, r)
                    .await?
                    .map(|(s, _)| s)
                    .as_deref()
                {
                    Some("stopping") => tokio::time::sleep(self.poll_interval()).await,
                    _ => break,
                }
            }
        }
        let region = effective_region(conn, r);
        let profile_hint = self.profile_hint(conn);
        self.call_ok(
            &self.ecs_endpoint(region),
            "POST",
            "StartInstance",
            ECS_API_VERSION,
            &[("InstanceId".into(), r.id.clone())],
            profile_hint,
        )
        .await?;
        Ok(())
    }

    async fn decommission_without_delete(
        &self,
        conn: &Connection,
        r: &Resource,
        owned: &OwnedInstance,
    ) -> Result<()> {
        self.stop_owned_instance(conn, r, &owned.state, true)
            .await?;
        let region = effective_region(conn, r);
        let profile_hint = self.profile_hint(conn);
        let ecs_ep = self.ecs_endpoint(region);
        let now = model::now();
        if owned.cloud_auto_release.is_none_or(|ts| ts > now + 1920) {
            let release_ts = ((now + 1920) / 60) * 60;
            let release_time = model::rfc3339(release_ts);
            let (m_status, m_body) = self
                .call_raw(
                    &ecs_ep,
                    "POST",
                    "ModifyInstanceAutoReleaseTime",
                    ECS_API_VERSION,
                    &[
                        ("RegionId".into(), region.to_string()),
                        ("InstanceId".into(), r.id.clone()),
                        ("AutoReleaseTime".into(), release_time),
                    ],
                    profile_hint,
                )
                .await?;
            if !m_status.is_success() {
                let m_code = match &m_body {
                    ApiBody::Json(v) => api_error_code_message(v).0,
                    ApiBody::Text(_) => "",
                };
                if is_instance_not_found(m_code) {
                    return Ok(());
                }
                if is_permission_denied(m_code)
                    && let Some(existing_ts) = owned.cloud_auto_release
                {
                    tracing::warn!(
                        instance_id = %r.id,
                        auto_release = existing_ts,
                        "ecs:DeleteInstance and ecs:ModifyInstanceAutoReleaseTime denied; instance stopped (StopCharging) and relies on existing AutoReleaseTime"
                    );
                } else {
                    return Err(map_api_error(
                        "ModifyInstanceAutoReleaseTime",
                        ECS_API_VERSION,
                        m_status,
                        &m_body,
                    ));
                }
            }
        }
        match self
            .call_raw(
                &ecs_ep,
                "POST",
                "TagResources",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    ("ResourceType".into(), "instance".into()),
                    ("ResourceId.1".into(), r.id.clone()),
                    ("Tag.1.Key".into(), tag::MANAGED.into()),
                    ("Tag.1.Value".into(), "true".into()),
                    ("Tag.2.Key".into(), DECOMMISSIONED_TAG_KEY.into()),
                    ("Tag.2.Value".into(), "true".into()),
                ],
                profile_hint,
            )
            .await
        {
            Ok((t_status, _)) if t_status.is_success() => {}
            Ok((t_status, t_body)) => {
                let err = map_api_error("TagResources", ECS_API_VERSION, t_status, &t_body);
                tracing::warn!(
                    instance_id = %r.id,
                    "failed to tag {DECOMMISSIONED_TAG_KEY}=true after StopCharging fallback: {err}"
                );
            }
            Err(e) => {
                tracing::warn!(
                    instance_id = %r.id,
                    "failed to tag {DECOMMISSIONED_TAG_KEY}=true after StopCharging fallback: {e}"
                );
            }
        }
        Ok(())
    }

    pub(crate) async fn delete_resource(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
    ) -> Result<()> {
        match self.delete_resource_in_sweep(conn, r, owner).await? {
            SweepDelete::Deleted => Ok(()),
            SweepDelete::Held { reason } => Err(net::held_delete_error(r, &reason)),
        }
    }

    pub(crate) async fn delete_resource_in_sweep(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
    ) -> Result<SweepDelete> {
        existing_vpc::guard_user_network_untouched(conn, r)?;
        if net::is_network_type(&r.resource_type) {
            return net::delete_part_owned(self, conn, r, Some(owner)).await;
        }
        if r.resource_type != "instance" || r.id.is_empty() {
            return Ok(SweepDelete::Deleted);
        }
        let Some(owned) = self
            .inspect_owned_instance(conn, r, owner, "delete")
            .await?
        else {
            return Ok(SweepDelete::Deleted);
        };
        if matches!(owned.state.as_str(), "terminated" | "deleted") {
            return Ok(SweepDelete::Deleted);
        }
        let region = effective_region(conn, r);
        let profile_hint = self.profile_hint(conn);
        let (status, body) = self
            .call_raw(
                &self.ecs_endpoint(region),
                "POST",
                "DeleteInstance",
                ECS_API_VERSION,
                &[
                    ("InstanceId".into(), r.id.clone()),
                    ("Force".into(), "true".into()),
                ],
                profile_hint,
            )
            .await?;
        if !status.is_success() {
            let code = match &body {
                ApiBody::Json(v) => api_error_code_message(v).0,
                ApiBody::Text(_) => "",
            };
            if is_instance_not_found(code) {
                return Ok(SweepDelete::Deleted);
            }
            if is_permission_denied(code) {
                self.decommission_without_delete(conn, r, &owned).await?;
                return Ok(SweepDelete::Deleted);
            }
            return Err(map_api_error(
                "DeleteInstance",
                ECS_API_VERSION,
                status,
                &body,
            ));
        }
        for _ in 0..30 {
            match self.describe_resource(conn, r).await? {
                None => return Ok(SweepDelete::Deleted),
                Some((st, _)) if matches!(st.as_str(), "terminated" | "deleted") => {
                    return Ok(SweepDelete::Deleted);
                }
                _ => tokio::time::sleep(self.poll_interval()).await,
            }
        }
        Ok(SweepDelete::Deleted)
    }

    pub(crate) async fn list_owned_resources(
        &self,
        conn: &Connection,
        owner: &str,
    ) -> Result<Vec<Resource>> {
        let profile_hint = self.profile_hint(conn);
        let mut base = vec![("RegionId".into(), conn.region.clone())];
        base.extend(net::owner_tag_filters(owner));
        let instances = self
            .paginated_page_number(
                &self.ecs_endpoint(&conn.region),
                "DescribeInstances",
                ECS_API_VERSION,
                &base,
                ("Instances", "Instance"),
                profile_hint,
            )
            .await?;

        let mut decomm_holds: BTreeMap<String, Option<String>> = BTreeMap::new();
        let mut record_hold = |id: &str, rel: Option<&str>| {
            if id.is_empty() {
                return;
            }
            let entry = decomm_holds.entry(id.to_string()).or_insert(None);
            if let Some(ts) = rel
                && entry.as_deref().is_none_or(|cur| ts > cur)
            {
                *entry = Some(ts.to_string());
            }
        };

        let mut out = Vec::new();
        for inst in instances {
            let tags = net::tags_of(&inst);
            if !model::is_ours(&tags, owner) {
                continue;
            }
            let st = state_of(inst["Status"].as_str().unwrap_or(""));
            if tags.get(DECOMMISSIONED_TAG_KEY).map(String::as_str) == Some("true") {
                if !matches!(st.as_str(), "terminated" | "deleted") {
                    let rel = inst["AutoReleaseTime"]
                        .as_str()
                        .and_then(normalize_aliyun_iso8601);
                    if let Some(vpc) = inst["VpcAttributes"]["VpcId"].as_str() {
                        record_hold(vpc, rel.as_deref());
                    }
                    if let Some(vsw) = inst["VpcAttributes"]["VSwitchId"].as_str() {
                        record_hold(vsw, rel.as_deref());
                    }
                    if let Some(sgs) = inst["SecurityGroupIds"]["SecurityGroupId"].as_array() {
                        for sg in sgs.iter().filter_map(|v| v.as_str()) {
                            record_hold(sg, rel.as_deref());
                        }
                    }
                }
                continue;
            }
            let id = inst["InstanceId"].as_str().unwrap_or_default().to_string();
            if id.is_empty() {
                continue;
            }
            let mut r = Resource {
                provider: "aliyun-ecs".into(),
                id,
                resource_type: "instance".into(),
                name: inst["InstanceName"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                region: inst["RegionId"]
                    .as_str()
                    .unwrap_or(&conn.region)
                    .to_string(),
                zone: inst["ZoneId"].as_str().unwrap_or_default().to_string(),
                state: st,
                expires: model::tag_expires(&tags),
                tags,
                ..Default::default()
            };
            if let Some(vpc) = inst["VpcAttributes"]["VpcId"].as_str()
                && !vpc.is_empty()
            {
                r.extra.insert("vpc".into(), vpc.into());
            }
            if let Some(vsw) = inst["VpcAttributes"]["VSwitchId"].as_str()
                && !vsw.is_empty()
            {
                r.extra.insert("vswitch".into(), vsw.into());
            }
            out.push(r);
        }
        let mut parts = net::list_parts(self, conn, owner).await?;
        for part in &mut parts {
            if let Some(rel_opt) = decomm_holds.get(&part.id) {
                part.extra.insert(
                    model::DECOMMISSIONING_HOLD.into(),
                    net::auto_release_hold_reason(rel_opt.as_deref()),
                );
            }
        }
        out.extend(parts);
        Ok(out)
    }

    pub(crate) async fn fetch_boot_log(
        &self,
        conn: &Connection,
        r: &Resource,
    ) -> Result<Option<String>> {
        if r.id.is_empty() || r.resource_type != "instance" {
            return Ok(None);
        }
        let region = effective_region(conn, r);
        let profile_hint = self.profile_hint(conn);
        let (status, body) = self
            .call_raw(
                &self.ecs_endpoint(region),
                "GET",
                "GetInstanceConsoleOutput",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    ("InstanceId".into(), r.id.clone()),
                    ("RemoveSymbols".into(), "true".into()),
                ],
                profile_hint,
            )
            .await?;
        if !status.is_success() {
            let code = match &body {
                ApiBody::Json(v) => api_error_code_message(v).0,
                ApiBody::Text(_) => "",
            };
            if is_instance_not_found(code) {
                return Ok(None);
            }
            return Err(map_api_error(
                "GetInstanceConsoleOutput",
                ECS_API_VERSION,
                status,
                &body,
            ));
        }
        let ApiBody::Json(v) = body else {
            return Ok(None);
        };
        let Some(encoded) = v["ConsoleOutput"].as_str() else {
            return Ok(None);
        };
        let compact: String = encoded.split_whitespace().collect();
        if compact.is_empty() {
            return Ok(None);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|| encoded.to_string());
        Ok(Some(decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_aliyun_iso8601_expands_17_char_ecs_timestamps_and_parses_auto_release_secs() {
        assert_eq!(
            normalize_aliyun_iso8601("2026-11-25T22:25Z").as_deref(),
            Some("2026-11-25T22:25:00Z")
        );
        assert_eq!(
            normalize_aliyun_iso8601(" 2026-11-25T22:25Z ").as_deref(),
            Some("2026-11-25T22:25:00Z")
        );
        assert_eq!(
            normalize_aliyun_iso8601("2026-11-25T22:25:00Z").as_deref(),
            Some("2026-11-25T22:25:00Z")
        );
        assert_eq!(normalize_aliyun_iso8601("   "), None);

        let ecs_17 = serde_json::json!({ "AutoReleaseTime": "2026-11-25T22:25Z" });
        let rfc_20 = serde_json::json!({ "AutoReleaseTime": "2026-11-25T22:25:00Z" });
        let empty = serde_json::json!({ "AutoReleaseTime": "" });
        let missing = serde_json::json!({});

        let parsed_17 = parse_auto_release_secs(&ecs_17).expect("17-char ECS format must parse");
        let parsed_20 =
            parse_auto_release_secs(&rfc_20).expect("20-char RFC3339 format must parse");
        assert_eq!(parsed_17, parsed_20);
        assert_eq!(parse_auto_release_secs(&empty), None);
        assert_eq!(parse_auto_release_secs(&missing), None);
    }
}

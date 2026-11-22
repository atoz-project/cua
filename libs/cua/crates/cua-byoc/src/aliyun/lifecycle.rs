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
use crate::api::Result;
use crate::model::{self, Connection, Resource, tag};

impl AliyunEcs {
    async fn guard_owned(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
        verb: &str,
    ) -> Result<Option<String>> {
        let Some((state, tags)) = self.describe_resource(conn, r).await? else {
            return Ok(None);
        };
        if !model::is_ours(&tags, owner) {
            return Err(Error::Cloud(format!(
                "aliyun-ecs: refusing to {verb} {} {} (it does not carry {}=true and {}={})",
                r.resource_type,
                r.id,
                tag::MANAGED,
                tag::OWNER,
                model::label_value(owner)
            )));
        }
        Ok(Some(state))
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
        if r.resource_type != "instance" {
            return Ok(None);
        }
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
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
        let state = state_of(inst["Status"].as_str().unwrap_or(""));
        Ok(Some((state, net::tags_of(inst))))
    }

    pub(crate) async fn stop_resource(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
    ) -> Result<()> {
        let Some(state) = self.guard_owned(conn, r, owner, "stop").await? else {
            return Err(Error::NotFound(format!("aliyun-ecs instance {}", r.id)));
        };
        if r.resource_type != "instance" {
            return Err(Error::InvalidArgument(format!(
                "aliyun-ecs: cannot stop {}",
                r.resource_type
            )));
        }
        if state == "stopped" {
            return Ok(());
        }
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
        let profile_hint = self.profile_hint(conn);
        if state != "stopping" {
            self.call_ok(
                &self.ecs_endpoint(region),
                "POST",
                "StopInstance",
                ECS_API_VERSION,
                &[
                    ("InstanceId".into(), r.id.clone()),
                    ("StoppedMode".into(), "StopCharging".into()),
                ],
                profile_hint,
            )
            .await?;
        }
        for _ in 0..60 {
            match self
                .describe_resource(conn, r)
                .await?
                .map(|(s, _)| s)
                .as_deref()
            {
                Some("stopped") | None => return Ok(()),
                _ => tokio::time::sleep(self.poll_interval()).await,
            }
        }
        Err(Error::Timeout(format!(
            "aliyun-ecs: instance {} did not reach Stopped state",
            r.id
        )))
    }

    pub(crate) async fn start_resource(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
    ) -> Result<()> {
        let Some(state) = self.guard_owned(conn, r, owner, "start").await? else {
            return Err(Error::NotFound(format!("aliyun-ecs instance {}", r.id)));
        };
        if r.resource_type != "instance" {
            return Err(Error::InvalidArgument(format!(
                "aliyun-ecs: cannot start {}",
                r.resource_type
            )));
        }
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
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
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

    pub(crate) async fn delete_resource(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
    ) -> Result<()> {
        existing_vpc::guard_user_network_untouched(conn, r)?;
        if net::is_network_type(&r.resource_type) {
            return net::delete_part_owned(self, conn, r, Some(owner)).await;
        }
        let Some(state) = self.guard_owned(conn, r, owner, "delete").await? else {
            return Ok(());
        };
        if r.resource_type != "instance" {
            return Ok(());
        }
        if matches!(state.as_str(), "terminated" | "deleted") {
            return Ok(());
        }
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
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
                return Ok(());
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
                None => return Ok(()),
                Some((st, _)) if matches!(st.as_str(), "terminated" | "deleted") => return Ok(()),
                _ => tokio::time::sleep(self.poll_interval()).await,
            }
        }
        Ok(())
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

        let mut out = Vec::new();
        for inst in instances {
            let tags = net::tags_of(&inst);
            if !model::is_ours(&tags, owner) {
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
                state: state_of(inst["Status"].as_str().unwrap_or("")),
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
        out.extend(net::list_parts(self, conn, owner).await?);
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
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
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

// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Relay Space vs Account Computer classification.
//!
//! Static Relay Mode Spaces and Account Relay Mode Computers share the
//! `relay:<machine-id>` identifier space. Every shell and view module reads
//! one classification decision ([`classify_relay_space`]) rather than
//! re-implementing `relay:` prefix checks.

use crate::host::THIS_MACHINE_ID;
use crate::model::{Space, SpaceAccessKind, SpaceProvider, SpaceRow, SpaceStatus};
use crate::util::parse_rfc3339_ms;

use super::normalize_provider;

/// Domain role of a `relay:*` entry once separated from transport reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEntryKind {
    /// A persisted `relay:<id>` Space with no `host` above it (`started_at > 0`
    /// or `cloud` metadata): `account_attached` distinguishes Account-Relay
    /// cloud Spaces from unattached Static Relay Mode Spaces.
    PersistedSpace {
        /// Whether this persisted relay Space is attached to a Cua account
        /// (sharing or team/shared access is present).
        account_attached: bool,
    },
    /// A Space provided by one of your Account Relay computers (`host` set,
    /// `relay:<machine>/<name>`, or `relay:space-*`).
    HostedSpace,
    /// One of your Account Relay computers sharing its own desktop.
    AccountComputer,
}

/// Classifies a `relay:*` [`Space`] into its domain role, or `None` for
/// non-relay entries (`local:*`, `direct:*`, `this-mac`, or invalid `relay:`).
pub fn classify_relay_space(space: &Space) -> Option<RelayEntryKind> {
    let own = space.id.strip_prefix("relay:")?;
    if own.is_empty() {
        return None;
    }
    if matches!(space.provider, Some(p) if p != SpaceProvider::Relay) {
        return None;
    }
    if space.host.as_deref().is_some_and(|h| !h.trim().is_empty()) {
        return Some(RelayEntryKind::HostedSpace);
    }
    let persisted = space.started_at.is_some_and(|t| t > 0)
        || space.cloud.as_deref().is_some_and(|c| !c.trim().is_empty());
    if persisted {
        let account_attached = space
            .access
            .as_ref()
            .is_some_and(|a| a.kind != SpaceAccessKind::Mine || a.can_share);
        return Some(RelayEntryKind::PersistedSpace { account_attached });
    }
    if own.contains('/') || own.starts_with("space-") {
        Some(RelayEntryKind::HostedSpace)
    } else {
        Some(RelayEntryKind::AccountComputer)
    }
}

/// Whether `cloud_delete` indicates an Account-Relay cloud Space created on
/// another device (`elsewhere` or `host:<machine>`).
pub(crate) fn is_account_cloud_delete(cloud_delete: Option<&str>) -> bool {
    cloud_delete.is_some_and(|d| matches!(d, "elsewhere") || d.starts_with("host:"))
}

/// Whether a registry row is a persisted relay-reached Space (`relay:<id>`
/// with no `host` above it, carrying `added_at` or `cloud` metadata) rather
/// than an Account Relay Mode Computer from the account directory.
pub(crate) fn is_persisted_relay_row(row: &SpaceRow) -> bool {
    row.id
        .strip_prefix("relay:")
        .is_some_and(|own| !own.is_empty())
        && normalize_provider(&row.provider) == SpaceProvider::Relay
        && row.host.as_deref().is_none_or(|h| h.trim().is_empty())
        && (row
            .added_at
            .as_deref()
            .and_then(parse_rfc3339_ms)
            .is_some_and(|t| t > 0)
            || row.cloud.as_deref().is_some_and(|c| !c.trim().is_empty()))
}

/// Whether `space` is a persisted relay-reached Space (`relay:<id>` with no
/// `host` above it, carrying `started_at` or `cloud` metadata), classifying it
/// as a Space rather than an Account Relay Mode Computer's own desktop.
pub fn is_relay_space(space: &Space) -> bool {
    matches!(
        classify_relay_space(space),
        Some(RelayEntryKind::PersistedSpace { .. })
    )
}

/// Whether `space` is an unattached Static Relay Mode Space (a persisted relay
/// Space without Account Relay sharing attachment).
pub fn is_static_relay_space(space: &Space) -> bool {
    matches!(
        classify_relay_space(space),
        Some(RelayEntryKind::PersistedSpace {
            account_attached: false
        })
    )
}

/// A machine's own desktop, not a Space: This machine (`this-mac`, and any
/// row reported as `Local`), or one of your Account Relay computers sharing
/// its own desktop over the relay. They belong with the machines (the
/// sidebar's This Mac and My computers, the web UI's Computers page), not in
/// the count of Spaces; the desktop, macOS, and web `isMachineDesktop` checks
/// follow the same rule.
pub fn is_machine_desktop(space: &Space) -> bool {
    space.id == THIS_MACHINE_ID
        || space.status == SpaceStatus::Local
        || matches!(
            classify_relay_space(space),
            Some(RelayEntryKind::AccountComputer)
        )
}

/// Whether `space` is the desktop of one of your other machines, reached
/// through the relay (`relay:<machine>`, no host above it): a machine's
/// own desktop that is not This machine's. A Space the machine provides is
/// a Space, not this.
pub fn is_remote_desktop(space: &Space) -> bool {
    matches!(
        classify_relay_space(space),
        Some(RelayEntryKind::AccountComputer)
    )
}

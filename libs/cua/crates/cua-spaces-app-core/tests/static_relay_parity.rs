// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Cross-surface Seam 2 parity assertions for Static Relay Mode Spaces vs
//! Account Relay Mode Computers. The exact same JSON fixture matrix is
//! replayed by Desktop (`apps/cua-spaces-desktop/src/bridge/host-start.test.ts`)
//! and Web (`apps/cua-spaces-web/src/lib/static-relay-spaces.test.ts`).

use cua_spaces_app_core::devices::{EnrollmentKind, machine_access_notice};
use cua_spaces_app_core::dispatch;
use cua_spaces_app_core::machines::{MachinesPageInput, page_rows};
use cua_spaces_app_core::model::{SpaceOs, SpaceRow};
use cua_spaces_app_core::spaces::sidebar::{
    DetailActionId, detail_for, is_your_machine, requires_account_relay_access, sidebar,
};
use cua_spaces_app_core::spaces::{
    RelayEntryKind, classify_relay_space, is_machine_desktop, is_relay_space, is_remote_desktop,
    is_static_relay_space, openable_spaces, row_to_space,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Matrix {
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    case: String,
    row: SpaceRow,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Expect {
    is_machine_desktop: bool,
    is_relay_space: bool,
    is_static_relay_space: bool,
    in_machines_page: bool,
    in_real_spaces: bool,
    sidebar_section: String,
    can_share: bool,
    requires_account_relay_access: bool,
    remove_only: bool,
    delete_label: String,
    detail: String,
    place: String,
}

fn expected_kind(space_id: &str, e: &Expect) -> Option<RelayEntryKind> {
    if !space_id.starts_with("relay:") {
        return None;
    }
    if e.is_relay_space {
        Some(RelayEntryKind::PersistedSpace {
            account_attached: !e.is_static_relay_space,
        })
    } else if e.is_machine_desktop {
        Some(RelayEntryKind::AccountComputer)
    } else {
        Some(RelayEntryKind::HostedSpace)
    }
}

#[test]
fn static_relay_classification_matches_shared_cross_surface_matrix() {
    let matrix: Matrix =
        serde_json::from_str(include_str!("../parity/static-relay-classification.json")).unwrap();
    let notice = machine_access_notice(EnrollmentKind::NeedsEnrollment, None).unwrap();

    let spaces: Vec<_> = matrix
        .fixtures
        .iter()
        .map(|f| row_to_space(&f.row, 1_763_978_400_000))
        .collect();

    let machine_rows = page_rows(&MachinesPageInput {
        host_os: SpaceOs::Macos,
        spaces: spaces.clone(),
        devices: vec![],
        hostnames: Default::default(),
        presence: Default::default(),
        now: 1_800_000_000,
    });
    let sb = sidebar(&spaces, "", "");

    for (fixture, space) in matrix.fixtures.iter().zip(&spaces) {
        let e = &fixture.expect;
        let case = &fixture.case;

        assert_eq!(
            classify_relay_space(space),
            expected_kind(&space.id, e),
            "{case}: classify_relay_space"
        );
        assert_eq!(
            is_machine_desktop(space),
            e.is_machine_desktop,
            "{case}: is_machine_desktop"
        );
        assert_eq!(
            is_relay_space(space),
            e.is_relay_space,
            "{case}: is_relay_space"
        );
        assert_eq!(
            is_static_relay_space(space),
            e.is_static_relay_space,
            "{case}: is_static_relay_space"
        );
        assert_eq!(
            !is_machine_desktop(space),
            e.in_real_spaces,
            "{case}: in_real_spaces"
        );
        assert_eq!(
            is_remote_desktop(space),
            e.is_machine_desktop && space.id.starts_with("relay:"),
            "{case}: is_remote_desktop"
        );
        assert_eq!(
            is_your_machine(space),
            is_remote_desktop(space),
            "{case}: is_your_machine"
        );

        let wire_space = serde_json::to_value(space).unwrap();
        assert_eq!(
            dispatch::call_value("spaces.isMachineDesktop", json!({ "space": wire_space }))
                .unwrap(),
            json!(e.is_machine_desktop),
            "{case}: dispatch spaces.isMachineDesktop"
        );
        assert_eq!(
            dispatch::call_value("spaces.isStaticRelaySpace", json!({ "space": wire_space }))
                .unwrap(),
            json!(e.is_static_relay_space),
            "{case}: dispatch spaces.isStaticRelaySpace"
        );

        let machine_id = space.id.strip_prefix("relay:").unwrap_or(&space.id);
        let in_machines = machine_rows.iter().any(|r| r.id == machine_id);
        assert_eq!(in_machines, e.in_machines_page, "{case}: in_machines_page");

        let section = sb
            .sections
            .iter()
            .find(|s| s.rows.iter().any(|r| r.id == space.id))
            .map(|s| s.title.code.as_str())
            .unwrap_or("");
        assert_eq!(section, e.sidebar_section, "{case}: sidebar_section");

        let access = space.access.as_ref().expect("row_to_space sets access");
        assert_eq!(access.can_share, e.can_share, "{case}: access.can_share");
        assert_eq!(access.place, e.place, "{case}: access.place");
        assert_eq!(space.detail, e.detail, "{case}: space.detail");

        assert_eq!(
            requires_account_relay_access(space),
            e.requires_account_relay_access,
            "{case}: requires_account_relay_access"
        );
        let d = detail_for(space, None, None, Some(&notice));
        assert_eq!(
            d.access.is_some(),
            e.requires_account_relay_access,
            "{case}: detail_for access notice"
        );
        assert_eq!(
            d.can_stream,
            space.sdk.as_ref().is_some_and(|s| s.reachable) && !e.requires_account_relay_access,
            "{case}: detail_for can_stream"
        );
        assert_eq!(
            d.actions.iter().any(|a| a.id == DetailActionId::Share),
            e.can_share,
            "{case}: detail_for Share action"
        );
        assert_eq!(d.remove_only, e.remove_only, "{case}: detail.remove_only");
        assert_eq!(
            d.delete_label, e.delete_label,
            "{case}: detail.delete_label"
        );
    }
}

#[test]
fn static_relay_openable_spaces_unnamed_fallback_and_provider_none_consistency() {
    let mk = |v: serde_json::Value| row_to_space(&serde_json::from_value(v).unwrap(), 0);
    let manual = mk(json!({
        "id": "relay:office-gpu", "name": "Office GPU", "provider": "relay",
        "addedAt": "2026-11-24T10:00:00Z", "os": "linux", "reachable": true,
        "features": ["desktop_stream"],
    }));
    let byoc = mk(json!({
        "id": "relay:cloud-0123456789abcdef", "name": "Research Box", "provider": "relay",
        "addedAt": "2026-11-24T10:05:00Z", "cloud": "aws", "cloudPlace": "AWS \u{b7} us-west-2",
        "os": "linux", "reachable": true, "features": ["desktop_stream"],
    }));
    let online_computer = mk(json!({
        "id": "relay:studio-online", "name": "Studio", "provider": "relay",
        "os": "macos", "reachable": true, "features": ["desktop_stream", "host_spaces"],
        "sharing": { "ownerId": "u1", "role": "owner" },
    }));
    let offline_computer = mk(json!({
        "id": "relay:studio-offline", "name": "Spare Mini", "provider": "relay",
        "os": "macos", "reachable": false,
    }));

    let roster = vec![
        manual.clone(),
        byoc.clone(),
        online_computer.clone(),
        offline_computer.clone(),
    ];
    let openable_ids: Vec<String> = openable_spaces(&roster).into_iter().map(|s| s.id).collect();
    assert_eq!(
        openable_ids,
        [
            "relay:office-gpu",
            "relay:cloud-0123456789abcdef",
            "relay:studio-online"
        ]
    );

    let view = sidebar(&roster, "", "");
    let section_ids = |code: &str| -> Vec<&str> {
        view.sections
            .iter()
            .find(|s| s.title.code == code)
            .map(|s| s.rows.iter().map(|r| r.id.as_str()).collect())
            .unwrap_or_default()
    };
    assert_eq!(
        section_ids("spaces.sidebar.section.connected"),
        ["relay:office-gpu", "relay:cloud-0123456789abcdef"]
    );
    assert_eq!(
        section_ids("spaces.sidebar.section.my_computers"),
        ["relay:studio-online", "relay:studio-offline"]
    );

    // Unnamed static relay Space falls back to bare machine id without `relay:`.
    for raw_name in ["", "   "] {
        let unnamed = mk(json!({
            "id": "relay:office-gpu", "name": raw_name, "provider": "relay",
            "addedAt": "2026-11-24T10:00:00Z", "os": "linux", "reachable": true,
        }));
        assert_eq!(unnamed.name, "office-gpu");
        assert!(!unnamed.name.contains("relay:"));
        assert_eq!(unnamed.detail, "Remote relay");
        assert!(!unnamed.detail.contains("My machines"));
    }

    // `provider: None` and `started_at: Some(0)` keep `is_your_machine` and `is_remote_desktop` in lockstep.
    let mut no_provider = online_computer.clone();
    no_provider.provider = None;
    no_provider.started_at = Some(0);
    assert_eq!(
        classify_relay_space(&no_provider),
        Some(RelayEntryKind::AccountComputer)
    );
    assert!(is_machine_desktop(&no_provider));
    assert!(is_remote_desktop(&no_provider));
    assert!(is_your_machine(&no_provider));
    assert!(!is_relay_space(&no_provider));

    // Legacy `relay:space-*` without host classifies as HostedSpace, never AccountComputer.
    let legacy_hosted = mk(json!({
        "id": "relay:space-legacy01", "name": "Legacy", "provider": "relay",
        "os": "linux", "reachable": true,
    }));
    assert_eq!(
        classify_relay_space(&legacy_hosted),
        Some(RelayEntryKind::HostedSpace)
    );
    assert!(!is_machine_desktop(&legacy_hosted));
    assert!(!is_your_machine(&legacy_hosted));
    assert!(requires_account_relay_access(&legacy_hosted));
}

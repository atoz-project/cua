// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Cross-surface Seam 2 parity assertions for Static Relay Mode Spaces vs
//! Account Relay Mode Computers. The exact same JSON fixture matrix is
//! replayed by Desktop (`apps/cua-spaces-desktop/src/bridge/host-start.test.ts`)
//! and Web (`apps/cua-spaces-web/src/lib/static-relay-spaces.test.ts`).

use cua_spaces_app_core::devices::{EnrollmentKind, machine_access_notice};
use cua_spaces_app_core::machines::{MachinesPageInput, page_rows};
use cua_spaces_app_core::model::{SpaceOs, SpaceRow};
use cua_spaces_app_core::spaces::sidebar::{
    DetailActionId, detail_for, is_your_machine, requires_account_relay_access, sidebar,
};
use cua_spaces_app_core::spaces::{
    is_machine_desktop, is_relay_space, is_static_relay_space, row_to_space,
};
use serde::Deserialize;

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
            is_your_machine(space),
            e.is_machine_desktop && space.id.starts_with("relay:"),
            "{case}: is_your_machine"
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

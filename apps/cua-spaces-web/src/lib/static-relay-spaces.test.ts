// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { Machine, Space } from "@/bridge";
import { spaceToRow, toMachineRows } from "@/bridge/adapters/webkit";
import { machineIdOf, rowsToSpaces } from "@/bridge/derive";
import type { WkSpace } from "@/bridge/webkit-protocol";
import { shareable } from "@/bridge/share";
import { requiresAccountRelayAccess, spaceDetail } from "@/bridge/space-detail";
import { accessOf, canShareSpace, isAccountCloudDelete } from "@/lib/space-access";
import { buildSpacesTree } from "@/lib/spaces-tree";
import {
  isMachineDesktop,
  isRelaySpace,
  isStaticRelaySpace,
  listedSpaces,
  locationLabel,
  machineName,
  machinePlacement,
  realSpaces,
  spacePlace,
} from "@/lib/spaces";

function makeSpace(overrides: Partial<Space> & Pick<Space, "id">): Space {
  return {
    name: overrides.id,
    os: "linux",
    status: "running",
    detail: "",
    lastUsedAt: 1_763_978_400_000,
    scene: "linux-terminal",
    ...overrides,
  };
}

const manualStatic = makeSpace({
  id: "relay:office-gpu",
  name: "office-gpu",
  provider: "relay",
  startedAt: 1_763_978_400_000,
  os: "linux",
  osPrettyName: "Ubuntu 24.04",
  sdk: { features: ["desktop_stream"], spacesdVersion: "0.8.0", reachable: true },
});

const byocStatic = makeSpace({
  id: "relay:cloud-0123456789abcdef",
  name: "Research Box",
  provider: "relay",
  startedAt: 1_763_978_700_000,
  cloud: "aws",
  cloudPlace: "AWS · us-west-2",
  os: "linux",
  sdk: { features: ["desktop_stream"], spacesdVersion: "0.8.0", reachable: true },
});

const onlineComputer = makeSpace({
  id: "relay:studio-online",
  name: "Studio",
  provider: "relay",
  os: "macos",
  status: "running",
  sdk: { features: ["desktop_stream", "host_spaces"], spacesdVersion: "0.8.0", reachable: true },
});

const offlineComputer = makeSpace({
  id: "relay:studio-offline",
  name: "Spare Mini",
  provider: "relay",
  os: "macos",
  status: "suspended",
  sdk: { features: [], spacesdVersion: "0.8.0", reachable: false },
});

const hostedSpace = makeSpace({
  id: "relay:studio-online/dev",
  name: "dev",
  provider: "relay",
  host: "studio-online",
  hostName: "Studio",
  os: "linux",
  sdk: { features: ["desktop_stream"], spacesdVersion: "0.8.0", reachable: true },
});

describe("Web Static Relay Space vs Account Computer classification", () => {
  it("classifies manual and BYOC Static Relay entries as Spaces and keeps online/offline Account Computers as desktops", () => {
    expect(isRelaySpace(manualStatic)).toBe(true);
    expect(isRelaySpace(byocStatic)).toBe(true);
    expect(isRelaySpace(onlineComputer)).toBe(false);
    expect(isRelaySpace(offlineComputer)).toBe(false);
    expect(isRelaySpace(hostedSpace)).toBe(false);

    expect(isStaticRelaySpace(manualStatic)).toBe(true);
    expect(isStaticRelaySpace(byocStatic)).toBe(true);
    expect(isStaticRelaySpace(onlineComputer)).toBe(false);
    expect(isStaticRelaySpace(offlineComputer)).toBe(false);
    expect(isStaticRelaySpace(hostedSpace)).toBe(false);

    expect(isMachineDesktop(manualStatic)).toBe(false);
    expect(isMachineDesktop(byocStatic)).toBe(false);
    expect(isMachineDesktop(hostedSpace)).toBe(false);

    expect(isMachineDesktop(onlineComputer)).toBe(true);
    expect(isMachineDesktop(offlineComputer)).toBe(true);

    const all = [manualStatic, byocStatic, onlineComputer, offlineComputer, hostedSpace];
    expect(realSpaces(all).map((s) => s.id)).toEqual(["relay:office-gpu", "relay:cloud-0123456789abcdef", "relay:studio-online/dev"]);
    expect(listedSpaces(all, new Set(), (s) => s.status === "running").map((s) => s.id)).toEqual([
      "relay:office-gpu",
      "relay:cloud-0123456789abcdef",
      "relay:studio-online/dev",
      "relay:studio-online",
    ]);
  });

  it("keeps Static Relay Spaces out of Machines rows and renders them as Spaces in the tree even when unnamed", () => {
    const rows = toMachineRows(
      {
        loaded: true,
        selectedId: null,
        spaces: [manualStatic, byocStatic, onlineComputer, offlineComputer].map((space) => ({
          space,
          detail: {} as never,
          deleting: false,
        })),
      },
      null,
      "macos",
    );
    expect(rows.map((r) => r.id)).toEqual(["this-mac", "studio-online", "studio-offline"]);
    expect(machineIdOf(manualStatic, rows)).toBeUndefined();
    expect(machineIdOf(byocStatic, rows)).toBeUndefined();
    expect(machineIdOf(onlineComputer, rows)).toBe("studio-online");
    expect(machineIdOf(offlineComputer, rows)).toBe("studio-offline");
    // `startedAt: 0` stays consistent between `isMachineDesktop` and `machineIdOf`.
    expect(machineIdOf({ ...onlineComputer, startedAt: 0 }, rows)).toBe("studio-online");

    const machines: Machine[] = [
      { id: "studio-online", name: "Studio", os: "macos", via: "relay", connection: "relay", online: true, current: false, spaceIds: [], limits: [] },
      { id: "studio-offline", name: "Spare Mini", os: "macos", via: "relay", connection: "relay", online: false, current: false, spaceIds: [], limits: [] },
    ];
    const tree = buildSpacesTree({
      spaces: [manualStatic, byocStatic, onlineComputer, offlineComputer],
      machines,
      defaultSpace: null,
    });
    expect(tree.computers).toBe(2);
    expect(tree.spaces).toBe(2);
    expect(tree.spacesRunning).toBe(2);
    const spaceRoots = tree.roots.filter((r) => r.kind === "space");
    expect(spaceRoots.map((r) => r.key)).toEqual(["relay:office-gpu", "relay:cloud-0123456789abcdef"]);
    expect(spaceRoots.every((r) => r.settingsId === null)).toBe(true);
  });

  it("hides unavailable account sharing controls and exempts Static Relay Spaces from MachineAccessNotice", () => {
    expect(isAccountCloudDelete("elsewhere")).toBe(true);
    expect(isAccountCloudDelete("host:studio-01")).toBe(true);
    expect(isAccountCloudDelete("here")).toBe(false);
    expect(isAccountCloudDelete(undefined)).toBe(false);

    expect(canShareSpace(manualStatic)).toBe(false);
    expect(canShareSpace(byocStatic)).toBe(false);
    expect(canShareSpace({ ...byocStatic, cloudDelete: "elsewhere" })).toBe(true);
    expect(canShareSpace({ ...byocStatic, cloudDelete: "host:studio-01" })).toBe(true);
    expect(canShareSpace(hostedSpace)).toBe(true);

    expect(accessOf(manualStatic, "Remote relay").canShare).toBe(false);
    expect(accessOf(byocStatic, "AWS · us-west-2").canShare).toBe(false);
    expect(shareable(manualStatic)).toBe(false);
    expect(shareable(byocStatic)).toBe(false);
    expect(shareable(hostedSpace)).toBe(true);

    expect(requiresAccountRelayAccess(manualStatic)).toBe(false);
    expect(requiresAccountRelayAccess(byocStatic)).toBe(false);
    expect(requiresAccountRelayAccess(onlineComputer)).toBe(true);
    expect(requiresAccountRelayAccess(offlineComputer)).toBe(true);
    expect(requiresAccountRelayAccess(hostedSpace)).toBe(true);

    const noCore = {
      status: "unavailable" as const,
      methods: [],
      tryCall: () => undefined,
      call: () => {
        throw new Error("unused");
      },
    };
    const notice = {
      kind: "needs-enrollment" as const,
      status: "Not trusted yet",
      text: "Trust this Mac to connect to your other computers.",
      actionLabel: "Trust this Mac",
    };
    const manualDetail = spaceDetail(noCore, manualStatic, null, null, notice);
    expect(manualDetail.access).toBeUndefined();
    expect(manualDetail.canStream).toBe(true);
    expect(manualDetail.actions.some((a) => a.id === "share")).toBe(false);

    const byocDetail = spaceDetail(noCore, byocStatic, null, null, notice);
    expect(byocDetail.access).toBeUndefined();
    expect(byocDetail.canStream).toBe(true);
    expect(byocDetail.actions.some((a) => a.id === "share")).toBe(false);
  });

  it("renders natural user-facing placement copy with zero My machines, Unknown computer, or raw relay prefixes", () => {
    const manualPlace = machinePlacement([], manualStatic);
    expect(manualPlace).toEqual({ label: "Remote relay", viaRemoteRelay: true });
    expect(machineName([], manualStatic)).toBe("Remote relay");
    expect(spacePlace(manualStatic, manualPlace)).toBe("Ubuntu 24.04 · Remote relay");
    expect(spacePlace({ os: "unknown" }, manualPlace)).toBe("Remote relay");
    expect(locationLabel(manualStatic)).toBe("Remote relay");
    expect(accessOf(manualStatic, manualPlace.label).place).toBe("Remote relay");

    const byocPlace = machinePlacement([], byocStatic);
    expect(byocPlace).toEqual({ label: "AWS · us-west-2", viaRemoteRelay: false });
    expect(machineName([], byocStatic)).toBe("AWS · us-west-2");
    expect(spacePlace(byocStatic, byocPlace)).toBe("Linux on AWS · us-west-2");
    expect(locationLabel(byocStatic)).toBe("AWS · us-west-2");
    expect(accessOf(byocStatic, byocPlace.label).place).toBe("AWS · us-west-2");

    // A computer literally named "Remote relay" formats via `os_on_machine`, not `os_via_remote_relay`.
    const literalMachines: Machine[] = [
      {
        id: "m-literal",
        name: "Remote relay",
        os: "linux",
        via: "relay",
        connection: "relay",
        online: true,
        current: false,
        spaceIds: ["relay:m-literal/box"],
        limits: [],
      },
    ];
    const onLiteralMachine = makeSpace({ id: "relay:m-literal/box", name: "box", provider: "relay", host: "m-literal", os: "linux" });
    const literalPlace = machinePlacement(literalMachines, onLiteralMachine);
    expect(literalPlace).toEqual({ label: "Remote relay", viaRemoteRelay: false });
    expect(spacePlace(onLiteralMachine, literalPlace)).toBe("Linux on Remote relay");
    expect(spacePlace(onLiteralMachine, "Remote relay")).toBe("Linux on Remote relay");

    for (const copy of [
      manualPlace.label,
      spacePlace(manualStatic, manualPlace),
      locationLabel(manualStatic),
      byocPlace.label,
      spacePlace(byocStatic, byocPlace),
      locationLabel(byocStatic),
    ]) {
      expect(copy).not.toContain("My machines");
      expect(copy).not.toContain("Unknown computer");
      expect(copy).not.toContain("relay:");
      expect(copy).not.toContain("direct:");
    }
  });

  it("matches the shared Rust/Desktop/Web cross-surface classification parity matrix", () => {
    const matrixPath = resolve(import.meta.dirname, "../../../../libs/cua/crates/cua-spaces-app-core/parity/static-relay-classification.json");
    const matrix = JSON.parse(readFileSync(matrixPath, "utf8")) as {
      fixtures: {
        case: string;
        row: {
          id: string;
          name: string;
          provider: Space["provider"];
          addedAt?: string;
          os?: Space["os"];
          osPrettyName?: string;
          reachable: boolean;
          host?: string;
          hostName?: string;
          cloud?: string;
          cloudPlace?: string;
          cloudDelete?: string;
          features?: string[];
          sharing?: {
            ownerId: string;
            ownerEmail?: string;
            ownerName?: string;
            role: string;
          };
        };
        expect: {
          isMachineDesktop: boolean;
          isRelaySpace: boolean;
          isStaticRelaySpace: boolean;
          inMachinesPage: boolean;
          inRealSpaces: boolean;
          canShare: boolean;
          requiresAccountRelayAccess: boolean;
          removeOnly: boolean;
          deleteLabel: string;
          webHeaderSubtitle: string;
        };
      }[];
    };

    const noCore = {
      status: "unavailable" as const,
      methods: [],
      tryCall: () => undefined,
      call: () => {
        throw new Error("unused");
      },
    };
    const spaces: Space[] = rowsToSpaces(
      noCore,
      matrix.fixtures.map((f) => ({
        id: f.row.id,
        name: f.row.name,
        provider: f.row.provider ?? "direct",
        spacesdVersion: "0.8.0",
        features: f.row.features ?? [],
        addedAt: f.row.addedAt,
        os: f.row.os,
        osPrettyName: f.row.osPrettyName,
        reachable: f.row.reachable,
        host: f.row.host,
        hostName: f.row.hostName,
        cloud: f.row.cloud,
        cloudPlace: f.row.cloudPlace,
        cloudDelete: f.row.cloudDelete,
        sharing: f.row.sharing,
      })),
      1_763_978_400_000,
    );

    const machineRows = toMachineRows(
      { loaded: true, selectedId: null, spaces: spaces.map((space) => ({ space, detail: {} as never, deleting: false })) },
      null,
      "macos",
    );
    const machines: Machine[] = machineRows.map((r) => ({
      id: r.id,
      name: r.name,
      os: r.os,
      via: r.via,
      connection: r.via === "relay" ? "relay" : null,
      online: r.online,
      current: Boolean(r.current),
      spaceIds: spaces.filter((s) => machineIdOf(s, machineRows) === r.id).map((s) => s.id),
      limits: [],
    }));
    const notice = {
      kind: "needs-enrollment" as const,
      status: "Not trusted yet",
      text: "Trust this Mac to connect to your other computers.",
      actionLabel: "Trust this Mac",
    };

    matrix.fixtures.forEach((f, i) => {
      const s = spaces[i]!;
      const e = f.expect;
      expect(isMachineDesktop(s), `${f.case}: isMachineDesktop`).toBe(e.isMachineDesktop);
      expect(isRelaySpace(s), `${f.case}: isRelaySpace`).toBe(e.isRelaySpace);
      expect(isStaticRelaySpace(s), `${f.case}: isStaticRelaySpace`).toBe(e.isStaticRelaySpace);
      const rawId = s.id.startsWith("relay:") ? s.id.slice("relay:".length) : s.id;
      expect(
        machineRows.some((r) => r.id === rawId),
        `${f.case}: inMachinesPage`,
      ).toBe(e.inMachinesPage);
      expect(requiresAccountRelayAccess(s), `${f.case}: requiresAccountRelayAccess`).toBe(e.requiresAccountRelayAccess);

      const p = machinePlacement(machines, s);
      expect(spacePlace(s, p), `${f.case}: webHeaderSubtitle`).toBe(e.webHeaderSubtitle);
      expect(accessOf(s, p.label).canShare, `${f.case}: accessOf.canShare`).toBe(e.canShare);

      const d = spaceDetail(noCore, s, null, null, notice);
      expect(Boolean(d.access), `${f.case}: spaceDetail.access`).toBe(e.requiresAccountRelayAccess);
      expect(
        d.actions.some((a) => a.id === "share"),
        `${f.case}: detail share action`,
      ).toBe(e.canShare);
      expect(d.removeOnly, `${f.case}: detail.removeOnly`).toBe(e.removeOnly);
      expect(d.deleteLabel, `${f.case}: detail.deleteLabel`).toBe(e.deleteLabel);
    });

    expect(realSpaces(spaces).map((s) => s.id)).toEqual(matrix.fixtures.filter((f) => f.expect.inRealSpaces).map((f) => f.row.id));
  });

  it("preserves startedAt: null across Electron/SwiftUI spaceToRow -> rowsToSpaces and toMachineRows without fabricating addedAt", () => {
    const now = 1_763_978_900_000;
    const noCore = {
      status: "unavailable" as const,
      methods: [],
      tryCall: () => undefined,
      call: () => {
        throw new Error("unused");
      },
    };
    const wk = (overrides: Partial<WkSpace> & Pick<WkSpace, "id" | "name">): WkSpace => ({
      os: "macos",
      status: "running",
      detail: "My machines",
      lastUsedAt: now,
      startedAt: null,
      provider: "relay",
      sdk: { features: ["desktop_stream", "host_spaces"], spacesdVersion: "0.8.0", reachable: true },
      ...overrides,
    });

    const wkOnlineComputer = wk({ id: "relay:studio-online", name: "Studio", startedAt: null });
    const wkOfflineComputer = wk({
      id: "relay:studio-offline",
      name: "Spare Mini",
      status: "suspended",
      startedAt: null,
      sdk: { features: [], spacesdVersion: "0.8.0", reachable: false },
    });
    const wkManualStatic = wk({
      id: "relay:office-gpu",
      name: "Office GPU",
      os: "linux",
      startedAt: 1_763_978_400_000,
      access: {
        kind: "mine",
        role: "owner",
        place: "Remote relay",
        people: [],
        canPower: false,
        canTeleport: true,
        canShare: false,
        canRename: true,
        canDelete: true,
        canLeave: false,
      },
    });
    const wkByocStatic = wk({
      id: "relay:cloud-0123456789abcdef",
      name: "Research Box",
      os: "linux",
      startedAt: 1_763_978_700_000,
      cloud: "aws",
      cloudPlace: "AWS · us-west-2",
      access: {
        kind: "mine",
        role: "owner",
        place: "AWS · us-west-2",
        people: [],
        canPower: false,
        canTeleport: true,
        canShare: false,
        canRename: true,
        canDelete: true,
        canLeave: false,
      },
    });
    const wkAccountByoc = wk({
      id: "relay:cloud-account00000001",
      name: "Team Cloud Box",
      os: "linux",
      startedAt: 1_763_978_800_000,
      cloud: "aws",
      cloudPlace: "AWS · us-east-1",
      access: {
        kind: "mine",
        role: "owner",
        place: "AWS · us-east-1",
        people: [],
        canPower: false,
        canTeleport: true,
        canShare: true,
        canRename: true,
        canDelete: true,
        canLeave: false,
      },
    });

    const wireSpaces = [wkOnlineComputer, wkOfflineComputer, wkManualStatic, wkByocStatic, wkAccountByoc];
    const rows = wireSpaces.map(spaceToRow);
    expect(rows[0]!.addedAt).toBeUndefined();
    expect(rows[1]!.addedAt).toBeUndefined();
    expect(rows[2]!.addedAt).toBe(new Date(1_763_978_400_000).toISOString());
    expect(rows[3]!.addedAt).toBe(new Date(1_763_978_700_000).toISOString());
    expect(rows[3]!.sharing).toBeUndefined();
    expect(rows[4]!.addedAt).toBe(new Date(1_763_978_800_000).toISOString());
    expect(rows[4]!.sharing).toMatchObject({ role: "owner" });

    const roundTripped = rowsToSpaces(noCore, rows, now);
    expect(roundTripped[0]!.startedAt).toBeUndefined();
    expect(roundTripped[1]!.startedAt).toBeUndefined();
    expect(isMachineDesktop(roundTripped[0]!)).toBe(true);
    expect(isMachineDesktop(roundTripped[1]!)).toBe(true);
    expect(isStaticRelaySpace(roundTripped[0]!)).toBe(false);
    expect(isStaticRelaySpace(roundTripped[1]!)).toBe(false);

    expect(isMachineDesktop(roundTripped[2]!)).toBe(false);
    expect(isMachineDesktop(roundTripped[3]!)).toBe(false);
    expect(isMachineDesktop(roundTripped[4]!)).toBe(false);
    expect(accessOf(roundTripped[2]!, "Remote relay").canShare).toBe(false);
    expect(accessOf(roundTripped[3]!, "AWS · us-west-2").canShare).toBe(false);
    expect(accessOf(roundTripped[4]!, "AWS · us-east-1").canShare).toBe(true);
    expect(requiresAccountRelayAccess(roundTripped[3]!)).toBe(false);
    expect(requiresAccountRelayAccess(roundTripped[4]!)).toBe(true);

    const machineRows = toMachineRows(
      { loaded: true, selectedId: null, spaces: wireSpaces.map((space) => ({ space, detail: {} as never, deleting: false })) },
      null,
      "macos",
    );
    expect(machineRows.map((r) => r.id)).toEqual(["this-mac", "studio-online", "studio-offline"]);
    expect(machineIdOf(wkOnlineComputer as unknown as Space, machineRows)).toBe("studio-online");
    expect(machineIdOf(wkOfflineComputer as unknown as Space, machineRows)).toBe("studio-offline");
    expect(isMachineDesktop(wkOnlineComputer as unknown as Space)).toBe(true);
    expect(isStaticRelaySpace(wkOnlineComputer as unknown as Space)).toBe(false);

    const unnamed = rowsToSpaces(
      noCore,
      [
        {
          id: "relay:office-gpu",
          name: "   ",
          provider: "relay",
          spacesdVersion: "0.8.0",
          features: ["desktop_stream"],
          addedAt: "2026-11-24T10:00:00Z",
          reachable: true,
        },
      ],
      now,
    )[0]!;
    expect(unnamed.name).toBe("office-gpu");
    expect(unnamed.name).not.toContain("relay:");
  });
});

// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { isMachineDesktop, isRelaySpace, menuItems, realSpaces } from "./host-start";
import type { BridgeContext } from "./context";
import type { AppSpace } from "../native/generated/index";

function makeSpace(overrides: Partial<AppSpace> & Pick<AppSpace, "id">): AppSpace {
  return {
    name: overrides.id,
    os: "linux" as AppSpace["os"],
    status: "running" as AppSpace["status"],
    detail: "",
    lastUsedAt: 0n,
    scene: "linux-terminal" as AppSpace["scene"],
    hidden: false,
    ...overrides,
  };
}

describe("Desktop Static Relay Space vs Account Computer classification", () => {
  const manualStatic = makeSpace({
    id: "relay:office-gpu",
    name: "Office GPU",
    provider: "relay" as AppSpace["provider"],
    startedAt: 1_763_978_400_000n,
  });
  const byocStatic = makeSpace({
    id: "relay:cloud-0123456789abcdef",
    name: "Research Box",
    provider: "relay" as AppSpace["provider"],
    startedAt: 1_763_978_700_000n,
    cloud: "aws",
    cloudPlace: "AWS · us-west-2",
  });
  const onlineComputer = makeSpace({
    id: "relay:studio-online",
    name: "Studio",
    provider: "relay" as AppSpace["provider"],
    status: "running" as AppSpace["status"],
  });
  const offlineComputer = makeSpace({
    id: "relay:studio-offline",
    name: "Spare Mini",
    provider: "relay" as AppSpace["provider"],
    status: "suspended" as AppSpace["status"],
  });
  const hostedSpace = makeSpace({
    id: "relay:studio-online/dev",
    name: "dev",
    provider: "relay" as AppSpace["provider"],
    host: "studio-online",
    hostName: "Studio",
  });
  const localSpace = makeSpace({
    id: "local:ubuntu",
    name: "ubuntu",
    provider: "local" as AppSpace["provider"],
  });
  const thisMac = makeSpace({
    id: "this-mac",
    name: "This Mac",
    provider: "local" as AppSpace["provider"],
    status: "local" as AppSpace["status"],
  });
  const hiddenSpace = makeSpace({
    id: "local:home-warm",
    name: "home",
    provider: "local" as AppSpace["provider"],
    hidden: true,
  });

  it("classifies manual and BYOC Static Relay entries as Spaces and keeps online/offline Account Computers as desktops", () => {
    expect(isRelaySpace(manualStatic)).toBe(true);
    expect(isRelaySpace(byocStatic)).toBe(true);
    expect(isRelaySpace(onlineComputer)).toBe(false);
    expect(isRelaySpace(offlineComputer)).toBe(false);
    expect(isRelaySpace(hostedSpace)).toBe(false);

    expect(isMachineDesktop(manualStatic)).toBe(false);
    expect(isMachineDesktop(byocStatic)).toBe(false);
    expect(isMachineDesktop(hostedSpace)).toBe(false);
    expect(isMachineDesktop(localSpace)).toBe(false);

    expect(isMachineDesktop(onlineComputer)).toBe(true);
    expect(isMachineDesktop(offlineComputer)).toBe(true);
    expect(isMachineDesktop(thisMac)).toBe(true);

    // Electron JSON serialization turns absent `startedAt` into `null`; Account Computers must still classify as desktops.
    const wireNullOnline = { ...onlineComputer, startedAt: null } as unknown as AppSpace;
    const wireNullOffline = { ...offlineComputer, startedAt: null } as unknown as AppSpace;
    expect(isRelaySpace(wireNullOnline)).toBe(false);
    expect(isRelaySpace(wireNullOffline)).toBe(false);
    expect(isMachineDesktop(wireNullOnline)).toBe(true);
    expect(isMachineDesktop(wireNullOffline)).toBe(true);
  });

  it("includes Static Relay Spaces in realSpaces and menu/tray counts while excluding Account Computers and hidden rows", () => {
    const all = [thisMac, localSpace, hiddenSpace, manualStatic, byocStatic, onlineComputer, offlineComputer, hostedSpace];
    expect(realSpaces(all).map((s) => s.id)).toEqual(["local:ubuntu", "relay:office-gpu", "relay:cloud-0123456789abcdef", "relay:studio-online/dev"]);

    const appMenu = vi.fn().mockReturnValue([]);
    const ctx = {
      platform: "darwin",
      env: {},
      events: { emit: () => {} },
      model: {
        spaces: all,
        settingsPath: "/tmp/cua-spaces-test/settings.json",
        settings: { experiments: [], launchAtLogin: false, notificationsSeenMs: 0n },
        startup: { isReady: true, copy: { title: "" } },
        host: { state: null },
        about: { version: "0.39.0", channel: "stable", platform: "darwin" },
        native: {
          appMenu,
          appStorageInitial: () => ({}),
          appNotificationsInitial: () => ({}),
          appAboutUpdatesInitial: () => ({}),
          AppMenuItemId: { Status: "status", Separator: "separator" },
        },
      },
    } as unknown as BridgeContext;
    menuItems(ctx);
    expect(appMenu).toHaveBeenCalledTimes(1);
    const passed = appMenu.mock.calls[0]![0].spaces as AppSpace[];
    expect(passed.map((s) => s.id)).toEqual(["local:ubuntu", "relay:office-gpu", "relay:cloud-0123456789abcdef", "relay:studio-online/dev"]);
  });

  it("matches the shared Rust/Desktop/Web cross-surface classification parity matrix", () => {
    const matrixPath = resolve(import.meta.dirname, "../../../../libs/cua/crates/cua-spaces-app-core/parity/static-relay-classification.json");
    const matrix = JSON.parse(readFileSync(matrixPath, "utf8")) as {
      fixtures: {
        case: string;
        row: {
          id: string;
          name: string;
          provider: AppSpace["provider"];
          addedAt?: string;
          os?: AppSpace["os"];
          reachable: boolean;
          host?: string;
          cloud?: string;
          cloudPlace?: string;
          sharing?: { role: string };
        };
        expect: {
          isMachineDesktop: boolean;
          isRelaySpace: boolean;
          inRealSpaces: boolean;
          canShare: boolean;
        };
      }[];
    };

    const spaces = matrix.fixtures.map((f) =>
      makeSpace({
        id: f.row.id,
        name: f.row.name,
        provider: f.row.provider,
        os: f.row.os ?? ("unknown" as AppSpace["os"]),
        status: (f.row.reachable ? "running" : "suspended") as AppSpace["status"],
        startedAt: f.row.addedAt ? BigInt(Date.parse(f.row.addedAt)) : undefined,
        host: f.row.host,
        cloud: f.row.cloud,
        cloudPlace: f.row.cloudPlace,
        access: {
          kind: "mine" as NonNullable<AppSpace["access"]>["kind"],
          role: (f.row.sharing?.role ?? "owner") as NonNullable<AppSpace["access"]>["role"],
          place: f.row.cloudPlace ?? "",
          people: [],
          canPower: false,
          canTeleport: true,
          canShare: f.expect.canShare,
          canRename: true,
          canDelete: true,
          canLeave: false,
        },
      }),
    );

    matrix.fixtures.forEach((f, i) => {
      const s = spaces[i]!;
      expect(isMachineDesktop(s), `${f.case}: isMachineDesktop`).toBe(f.expect.isMachineDesktop);
      expect(isRelaySpace(s), `${f.case}: isRelaySpace`).toBe(f.expect.isRelaySpace);
    });
    expect(realSpaces(spaces).map((s) => s.id)).toEqual(matrix.fixtures.filter((f) => f.expect.inRealSpaces).map((f) => f.row.id));
  });
});

// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

import { cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { BridgeProvider, type CoreClient, type Space } from "@/bridge";
import { createDemoAdapter } from "@/bridge/adapters/demo";
import type { MachineRow } from "@/bridge/contracts/host";
import { PageTip } from "@/components/tips";
import { mountApp, stubBrowserApis, type TestHost } from "./app-harness";

afterEach(cleanup);
stubBrowserApis();

const NOTICE = {
  kind: "needs-enrollment",
  status: "Not trusted yet",
  text: "Trust this Mac to connect to your other computers.",
  actionLabel: "Trust this Mac",
};

const manualStaticRow = {
  id: "relay:office-gpu",
  name: "Office GPU",
  provider: "relay",
  spacesdVersion: "0.8.0",
  features: ["desktop_stream", "window_stream"],
  addedAt: "2026-11-24T10:00:00Z",
  os: "linux",
  osPrettyName: "Ubuntu 24.04",
  reachable: true,
};

const byocStaticRow = {
  id: "relay:cloud-0123456789abcdef",
  name: "Research Box",
  provider: "relay",
  spacesdVersion: "0.8.0",
  features: ["desktop_stream"],
  addedAt: "2026-11-24T10:05:00Z",
  os: "linux",
  reachable: true,
  cloud: "aws",
  cloudPlace: "AWS · us-west-2",
  cloudDelete: "here",
};

const accountComputerRow = {
  id: "relay:studio-online",
  name: "Studio",
  provider: "relay",
  spacesdVersion: "0.8.0",
  features: ["desktop_stream", "host_spaces"],
  os: "macos",
  reachable: true,
};

function signedOutHost(rows: unknown[], withAccessNotice = false): TestHost {
  return {
    failsCreates: false,
    listsGhost: false,
    answer: (op, out) => {
      if (op === "session.get") {
        return {
          ...(out as Record<string, unknown>),
          signedIn: false,
          account: { signedIn: false, identity: null, state: "signedOut" },
          identity: null,
        };
      }
      if (op === "spaces.list") return rows;
      if (op === "machines.list") {
        const list = out as MachineRow[];
        return withAccessNotice ? list.map((m) => (m.current ? { ...m, accessNotice: NOTICE } : m)) : list;
      }
      return out;
    },
  };
}

describe("Static Relay Mode Space detail page (rendered DOM)", () => {
  it("opens a manual Static Relay Space while signed out with clean subtitle, no Share button, and no MachineAccessNotice", async () => {
    await mountApp(`/spaces/${encodeURIComponent(manualStaticRow.id)}`, signedOutHost([manualStaticRow], true));

    const title = await waitFor(() => {
      const el = document.querySelector<HTMLElement>("[data-detail-title]");
      expect(el?.textContent).toBe("Office GPU");
      return el!;
    });
    const headerText = title.closest("header")?.textContent ?? "";
    expect(headerText).toContain("Ubuntu 24.04 · Remote relay");
    expect(headerText).not.toContain("My machines");
    expect(headerText).not.toContain("Unknown computer");
    expect(headerText).not.toContain("relay:");

    expect(document.querySelector("[data-share-space]")).toBeNull();
    expect(document.body.textContent).not.toContain(NOTICE.text);
    expect(document.body.textContent).not.toContain(NOTICE.actionLabel);
  });

  it("opens a BYOC Static Relay Space with its cloud place subtitle, no Share button, and no MachineAccessNotice", async () => {
    await mountApp(`/spaces/${encodeURIComponent(byocStaticRow.id)}`, signedOutHost([byocStaticRow], true));

    const title = await waitFor(() => {
      const el = document.querySelector<HTMLElement>("[data-detail-title]");
      expect(el?.textContent).toBe("Research Box");
      return el!;
    });
    const headerText = title.closest("header")?.textContent ?? "";
    expect(headerText).toContain("Linux on AWS · us-west-2");
    expect(headerText).not.toContain("My machines");
    expect(headerText).not.toContain("Unknown computer");
    expect(headerText).not.toContain("relay:");

    expect(document.querySelector("[data-share-space]")).toBeNull();
    expect(document.body.textContent).not.toContain(NOTICE.text);
  });

  it("still applies MachineAccessNotice when opening an Account Relay Computer on an unenrolled device", async () => {
    await mountApp(`/spaces/${encodeURIComponent(accountComputerRow.id)}`, signedOutHost([accountComputerRow], true));

    await waitFor(() => {
      expect(document.querySelector<HTMLElement>("[data-detail-title]")?.textContent).toBe("Studio");
      expect(document.body.textContent).toContain(NOTICE.text);
    });
  });

  it("suppresses the Share PageTip banner when sharing is unavailable on a Static Relay Space", async () => {
    const shareTipCore: CoreClient = {
      status: "ready",
      methods: ["tips.view"],
      call: () => {
        throw new Error("unused");
      },
      tryCall: <T,>(method: string, args?: Record<string, unknown>): T | undefined => {
        if (method === "tips.view") {
          const facts = args?.facts as { sharedAny?: boolean; spacePage?: string | null } | undefined;
          if (facts?.sharedAny) return null as T;
          return {
            id: "share",
            place: "space",
            text: `Share ${facts?.spacePage ?? "Office GPU"} with a teammate.`,
            action: { kind: "share", label: "Share…" },
            next: "Next tip",
            dontShow: "Don't show tips",
            close: "Close",
          } as T;
        }
        return undefined;
      },
    };
    const staticSpace: Space = {
      id: "relay:office-gpu",
      name: "Office GPU",
      os: "linux",
      status: "running",
      detail: "Remote relay",
      lastUsedAt: 1_763_978_400_000,
      startedAt: 1_763_978_400_000,
      scene: "linux-terminal",
      provider: "relay",
    };

    render(
      <BridgeProvider adapter={createDemoAdapter()} core={shareTipCore}>
        <PageTip place="space" space={staticSpace} onShare={undefined} />
      </BridgeProvider>,
    );

    await new Promise((r) => setTimeout(r, 80));
    expect(document.querySelector("[data-tip='share']")).toBeNull();
    expect(document.body.textContent).not.toContain("Share Office GPU with a teammate.");
  });
});

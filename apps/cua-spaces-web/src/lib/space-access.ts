// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

/**
 * Whose a Space is and what you may do with it, as the core says
 * (`Space.access`). A Space without it is yours alone, with every action
 * this app can take on it.
 */

import type { Space, SpaceAccess } from "@/bridge";
import { thisComputerLabel } from "@/lib/host-labels";
import { canDelete, canPower, isStaticRelaySpace } from "@/lib/spaces";

/** Whether `cloudDelete` indicates an Account-Relay cloud Space created on another device (`elsewhere` or `host:<machine>`). */
export function isAccountCloudDelete(cloudDelete: string | null | undefined): boolean {
  return cloudDelete === "elsewhere" || Boolean(cloudDelete?.startsWith("host:"));
}

/** Whether the current user may share `space` (honoring `space.access` when present, else excluding unattached Static Relay Spaces). */
export function canShareSpace(space: Pick<Space, "id" | "provider" | "host" | "startedAt" | "cloud" | "cloudDelete" | "access">): boolean {
  if (space.access) return space.access.canShare && space.access.role !== "viewer";
  return isAccountCloudDelete(space.cloudDelete) || !isStaticRelaySpace(space);
}

/** `space.access`, or yours alone when the host did not say. */
export function accessOf(space: Space, machine: string): SpaceAccess {
  if (space.access) return space.access;
  return {
    kind: "mine",
    role: "owner",
    place: space.provider === "local" ? thisComputerLabel() : machine,
    people: [],
    canPower: canPower(space),
    canTeleport: true,
    canShare: canShareSpace(space),
    canRename: true,
    canDelete: canDelete(space),
    canLeave: false,
  };
}

/** Yours: you own it, shared or not. */
export const isMine = (space: Space) => !space.access || space.access.kind === "mine";

/** The name its avatar stands for: the owner (shared with you) or the team; null for yours. */
export function ownerLabel(access: SpaceAccess): string | null {
  if (access.kind === "team") return access.teamName || access.ownerName || access.place || null;
  if (access.kind === "withMe") return access.ownerName || access.ownerEmail?.split("@")[0] || null;
  return null;
}

/** The people a Space of yours is shared with, by name ("Sam") or address. */
export const peopleNames = (access: SpaceAccess) => access.people.map((p) => p.name || p.who.replace(/^team:/, ""));

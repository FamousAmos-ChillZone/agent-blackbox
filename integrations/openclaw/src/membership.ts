/**
 * Community-graph membership — TypeScript mirror of `community/membership.py` (FIX-0039).
 *
 * A fresh node cannot FIND an unregistered public graph until it is connected to the
 * graph's owner (KI-216), so: dial the owner by peer id (DHT-resolved), subscribe with
 * shared memory, remember a confirmed subscription for RETRY_MS, retry a refused
 * subscribe after FAILED_RETRY_MS. Public graphs have no join step (D-040) and this
 * bridge never sends one. Fail-open: errors are logged, never thrown.
 */
import type { DkgClient } from "./dkgClient.js";

export const RETRY_MS = 600_000;
export const FAILED_RETRY_MS = 60_000;

export interface MembershipState {
  confirmedAt?: number;
  lastAttemptAt?: number;
}

export async function ensureCommunitySubscription(
  client: DkgClient,
  graph: string,
  ownerPeerId: string,
  state: MembershipState,
  log: (msg: string) => void,
  now = Date.now(),
): Promise<boolean> {
  if (!graph) return false;
  if (state.confirmedAt !== undefined && now - state.confirmedAt < RETRY_MS) return true;
  if (state.lastAttemptAt !== undefined && now - state.lastAttemptAt < FAILED_RETRY_MS) return false;
  state.lastAttemptAt = now;
  try {
    const listed = (await client.contextGraphs()).find((e) => e.id === graph);
    if (listed?.subscribed) {
      state.confirmedAt = now;
      return true;
    }
    if (ownerPeerId) {
      try {
        await client.connectPeer(ownerPeerId);
      } catch (err) {
        log(`blackbox: could not reach the community graph owner ${ownerPeerId}: ${(err as Error).message}`);
      }
    }
    await client.subscribeContextGraph(graph, true);
    state.confirmedAt = now;
    return true;
  } catch (err) {
    log(`blackbox: community subscribe failed (retry in ${FAILED_RETRY_MS / 1000}s): ${(err as Error).message}`);
    return false;
  }
}

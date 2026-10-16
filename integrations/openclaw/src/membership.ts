/**
 * Community membership — TypeScript mirror of `community/membership.py`.
 *
 * Since 2026-10-16 the community lives in the verified graph's shared memory (sub-graph
 * "reports"), so membership is that graph's subscription WITH shared memory. The graph is
 * registered on chain, so no owner peer is dialled first, and it is public: no join step
 * (D-040). Subscribe with shared memory once per process — a node subscribed VM-only gets its
 * shared memory added — and believe it when the node's answer covers shared memory; otherwise
 * (a refusal, or a VM-only catch-up still running) retry after FAILED_RETRY_MS. Before the first
 * write the "reports" sub-graph is registered on this node. Fail-open: errors are logged, never thrown.
 */
import { COMMUNITY_SUB_GRAPH, type DkgClient } from "./dkgClient.js";

export const RETRY_MS = 600_000;
export const FAILED_RETRY_MS = 60_000;

export interface MembershipState {
  confirmedAt?: number;
  lastAttemptAt?: number;
  /** The node took the subscription WITH shared memory (this process). */
  withSharedMemory?: boolean;
  /** The "reports" sub-graph is registered on this node. */
  laneReady?: boolean;
}

/** Whether a subscribe answer covers shared memory: an already-running catch-up keeps its own setting. */
function includesSharedMemory(reply: unknown): boolean {
  const catchup = (reply as { catchup?: Record<string, unknown> } | null)?.catchup;
  if (!catchup || typeof catchup !== "object") return true;
  return (catchup.includeSharedMemory ?? catchup.includeWorkspace) !== false;
}

export async function ensureCommunitySubscription(
  client: DkgClient,
  graph: string,
  state: MembershipState,
  log: (msg: string) => void,
  now = Date.now(),
): Promise<boolean> {
  if (!graph) return false;
  if (state.confirmedAt !== undefined && now - state.confirmedAt < RETRY_MS) return true;
  if (state.lastAttemptAt !== undefined && now - state.lastAttemptAt < FAILED_RETRY_MS) return false;
  state.lastAttemptAt = now;
  try {
    if (state.withSharedMemory) {
      const listed = (await client.contextGraphs()).find((e) => e.id === graph);
      if (listed?.subscribed) {
        state.confirmedAt = now;
        return true;
      }
    }
    const reply = await client.subscribeContextGraph(graph, true);
    if (!includesSharedMemory(reply)) return true; // subscribed; shared memory follows the running catch-up
    state.withSharedMemory = true;
    state.confirmedAt = now;
    return true;
  } catch (err) {
    log(`blackbox: subscribe with shared memory failed (retry in ${FAILED_RETRY_MS / 1000}s): ${(err as Error).message}`);
    return false;
  }
}

/** Register the community sub-graph on this node before its first write there ("already exists" counts as ready). */
export async function ensureReportLane(
  client: DkgClient,
  graph: string,
  state: MembershipState,
  log: (msg: string) => void,
): Promise<boolean> {
  if (state.laneReady) return true;
  try {
    await client.createSubGraph(graph, COMMUNITY_SUB_GRAPH);
  } catch (err) {
    if (!String((err as Error).message).includes("already exists")) {
      log(`blackbox: could not register the community sub-graph on this node: ${(err as Error).message}`);
      return false;
    }
  }
  state.laneReady = true;
  return true;
}

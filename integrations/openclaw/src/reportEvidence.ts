/**
 * Finding → R1 evidence. The ONE place the bridge turns a detection into the
 * closed fields a community report may carry (Python keyword names, as the
 * schema and the signer use them). Nothing observed ever enters: no pattern
 * text, no paths, no prompt. A finding this cannot describe within the schema
 * (a local skill without an artifact hash, a dependency without a malware
 * reason) comes back incomplete and the schema refuses it — it stays local.
 *
 * The CONTEXT fields (where the text or indicator was met) come from the hook
 * that produced the finding, never from the text itself — mirror of Python
 * `hooks.py` (`in-fetched-page` for web_/browser_ tools, else `in-tool-output`;
 * user text is `in-user-prompt`).
 */
import type { Finding } from "./detection.js";

export const FETCH_TOOL_PREFIXES = ["web_", "browser_"] as const;

export type HookEvent = "before_tool_call" | "post_tool_call" | "before_agent_run" | "message_received" | "osv_discovery" | string;

function isFetchTool(toolName?: string): boolean {
  return FETCH_TOOL_PREFIXES.some((p) => (toolName ?? "").startsWith(p));
}

function injectionContext(event: HookEvent, toolName?: string): string | undefined {
  if (event === "post_tool_call") return isFetchTool(toolName) ? "in-fetched-page" : "in-tool-output";
  if (event === "before_agent_run" || event === "message_received") return "in-user-prompt";
  return undefined; // an injection in tool-call arguments has no reportable context (stays local)
}

function iocContext(event: HookEvent, toolName?: string): string | undefined {
  if (event === "post_tool_call") return isFetchTool(toolName) ? "fetched-by-tool" : "in-tool-output";
  if (event === "before_tool_call") return isFetchTool(toolName) ? "fetched-by-tool" : "in-prompt";
  if (event === "before_agent_run" || event === "message_received") return "in-prompt";
  return undefined;
}

export function evidenceFor(finding: Finding, event: HookEvent, toolName?: string): Record<string, string | undefined> {
  const f = finding.fields;
  switch (finding.category) {
    case "injection":
      return { context: injectionContext(event, toolName), owasp_category: f.owaspCategory };
    case "escalation":
      return { tool_name: f.toolName, arg_shape: f.argShape };
    case "dependency":
      return {
        ecosystem: f.ecosystem, package_name: f.packageName, package_version: f.packageVersion,
        advisory_id: f.advisoryId, kind: finding.kind ?? f.kind,
        reason: f.reason ?? (f.advisoryId ? `advisory:${f.advisoryId}` : undefined),
      };
    case "fileaccess":
      return { tool_name: f.toolName, file_category: f.fileCategory };
    case "skill":
      // A local skill is named by its artifact hash + danger shape only (KI-159).
      return f.artifactHash ? { artifact_hash: f.artifactHash, danger_shape: f.dangerShape }
                            : { registry: f.registry, skill_name: f.skillName, skill_version: f.skillVersion };
    case "ioc":
      return { ioc_type: f.iocType, ioc_context: iocContext(event, toolName) };
    default:
      return {};
  }
}

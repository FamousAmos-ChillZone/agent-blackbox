/**
 * Hook event/result types, derived from the PUBLIC plugin API instead of an
 * internal SDK path.
 *
 * Why: the bridge used to `import type { PluginHookBeforeToolCallEvent, … } from
 * "openclaw/plugin-sdk/types"`. OpenClaw 2026.9.x stopped shipping declarations
 * for that subpath (the hooks and their types are unchanged, only their public
 * home moved), which broke the bridge's typecheck. `OpenClawPluginApi.on` is
 * `<K extends PluginHookName>(hookName: K, handler: PluginHookHandlerMap[K], …)`,
 * so instantiating it per hook name recovers each handler's event, context and
 * result types from the one surface the SDK guarantees — a later move of the
 * internal types cannot break this file.
 */
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";

declare const api: OpenClawPluginApi;
type HookName = Parameters<OpenClawPluginApi["on"]>[0];
type HandlerOf<K extends HookName> = Parameters<typeof api.on<K>>[1];
type EventOf<K extends HookName> = Parameters<HandlerOf<K>>[0];
type ResultOf<K extends HookName> = Exclude<Awaited<ReturnType<HandlerOf<K>>>, void | undefined>;

export type PluginHookBeforeToolCallEvent = EventOf<"before_tool_call">;
export type PluginHookBeforeToolCallResult = ResultOf<"before_tool_call">;
export type PluginHookAfterToolCallEvent = EventOf<"after_tool_call">;
export type PluginHookBeforeAgentRunEvent = EventOf<"before_agent_run">;
export type PluginHookBeforeAgentRunResult = ResultOf<"before_agent_run">;
export type PluginHookMessageReceivedEvent = EventOf<"message_received">;
export type PluginHookSessionStartEvent = EventOf<"session_start">;
export type PluginHookSessionEndEvent = EventOf<"session_end">;

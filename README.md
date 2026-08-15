# Slack Tool-Gate Approval — `dev.mcpg.tool-gate-slack-approval`

> class `tool_gate` · `native` · package `mcpg-plugin-tool-gate-slack-approval` · artifact `libmcpg_plugin_tool_gate_slack_approval.so` · Apache-2.0

Human-in-the-loop approval for sensitive MCP tool calls, driven from Slack. One
cdylib registers three entities that compose into a complete workflow: a tool
gate that parks a matching call, a notifier that posts an interactive Block Kit
message to a Slack channel, and an HTTP route that receives the button click and
resolves the approval. Reach for it when a class of tools — production
mutations, refunds, account deletions — must not run until a named human has
clicked Approve, and your organisation already lives in Slack.

## What it does
- Matches each incoming tool name against operator `rules` (regular expressions,
  first match wins) and returns a `PendingApproval` decision naming itself as
  the target notifier, with a deadline and a rendered summary. An empty `rules`
  list leaves the gate inert — every call is allowed.
- Posts the approval request to Slack through `chat.postMessage` as a Block Kit
  message with Approve and Deny buttons, and returns the resulting
  `slack:<channel>:<ts>` handle plus the message timestamp so audit records can
  link back to the conversation.
- Serves the Slack interactivity callback on its own HTTP route, verifies
  Slack's request signature, and forwards the resolution to the gateway's
  HMAC-signed approval callback URL.
- Restricts where that resolution may be sent to an operator-declared origin
  allowlist, and follows no redirects when posting it.
- Allows unconditionally post-dispatch — the plugin only gates on the way in.
- Declares the `network_outbound` capability, consumed by both the Slack API
  calls and the gateway callback POST. Grant it on the plugin entry.

## Configuration
Loaded from the flat top-level `plugins:` list. All three entities are built
from this single `config:` object, so the Slack credentials, the rules, and the
callback allowlist live together.

```yaml
governance:
  approvals:
    # The gateway hands notifiers a signed callback URL built from this base.
    callback_base_url: https://gw.example.com

plugins:
  - id: dev.mcpg.tool-gate-slack-approval
    class: tool_gate
    source:
      oci: ghcr.io/mcpg-dev/source-code/plugins/tool-gate-slack-approval:protocol-1
    granted_capabilities:
      - network_outbound
    config:
      bot_token: ${env.SLACK_BOT_TOKEN}
      signing_secret: ${env.SLACK_SIGNING_SECRET}
      default_channel: "#mcp-approvals"
      default_deadline_ms: 600
      interactive_path: /slack/interactive
      callback_allowed_origins:
        - https://gw.example.com
      rules:
        - tool_pattern: '^prod\.'
          summary_template: "Approve {tool} for {subject}?"
          deadline_secs: 300
          channel: "#prod-approvals"
```

| Field | Type | Default | Description |
|---|---|---|---|
| `bot_token` | string | *(unset)* | Slack bot user OAuth token (`xoxb-…`). Required by the notifier entity. |
| `signing_secret` | string | *(unset)* | Slack signing secret. Required by the HTTP route entity. |
| `default_channel` | string | *(required, non-empty)* | Channel id or name approval requests post to. |
| `default_deadline_ms` | integer | `600` | Fallback approval deadline. Despite the field name the value is applied in **seconds**. |
| `rules` | rule[] | `[]` | Gating rules, evaluated in order; empty leaves the gate inert. |
| `interactive_path` | string | `/slack/interactive` | Route path appended to this plugin's HTTP mount. |
| `slack_api_base` | string | `https://slack.com/api` | Slack API base URL. Override only to point at a test double. |
| `callback_allowed_origins` | string[] | `[]` | Origins (`scheme://host[:port]`) the resolution POST may target. Empty refuses every callback. |

Each entry of `rules`:

| Field | Type | Default | Description |
|---|---|---|---|
| `tool_pattern` | string | `""` | Regular expression matched against the full tool name; empty matches everything. |
| `summary_template` | string | `Tool {tool} requires approval` | Message body; `{tool}`, `{subject}` and `{trust_level}` are substituted. |
| `deadline_secs` | integer | *(inherits `default_deadline_ms`)* | Per-rule deadline in seconds. |
| `channel` | string | *(inherits `default_channel`)* | Per-rule channel override. |

Unknown fields are rejected, at both the top level and inside a rule. An empty
config object, an empty `default_channel`, or a `tool_pattern` that is not a
valid regular expression fails the load.

`bot_token` and `signing_secret` hold literal secret values. Write them as
`${env.NAME}` or `cred://…` references — the gateway resolves those at config
load and the plugin only ever sees the substituted value.

## Operations
A gated call moves through four steps.

1. **Gate.** The tool name matches a rule, so `evaluate_pre_dispatch` returns
   `PendingApproval` carrying a generated `appr_<uuid>` id, an RFC 3339
   deadline, the rendered summary, and metadata naming the target channel. The
   gateway suspends the call.
2. **Notify.** The gateway calls the notifier entity with the approval request,
   including the signed direct callback URL it minted from
   `governance.approvals.callback_base_url`. The plugin posts a Block Kit
   message whose Approve and Deny buttons carry the approval id and that
   callback URL.
3. **Callback.** Slack POSTs the button click to this plugin's HTTP route. The
   route verifies the signature, decodes the button payload, and maps the
   action to an `approved` or `denied` outcome attributed to the Slack user id.
4. **Resolve.** The route forwards that outcome to the gateway callback URL and
   replies to Slack with an acknowledgement that replaces the original message.

The route is mounted under the reserved `/plugins/` prefix, keyed by plugin id
and entity name, so the Slack app's Request URL is the gateway's public origin
followed by
`/plugins/dev.mcpg.tool-gate-slack-approval/route` plus `interactive_path`. It
accepts `POST` only, requires no gateway identity, and caps request bodies at
64 KiB.

## Security
**Inbound.** Every callback must carry `X-Slack-Signature` and
`X-Slack-Request-Timestamp`. The route recomputes Slack's `v0=` HMAC-SHA256 over
`v0:<timestamp>:<raw body>` with the signing secret, compares in constant time,
and rejects timestamps more than five minutes from the current clock — so a
captured callback cannot be replayed later. A missing header, a signature
without the `v0=` prefix, or a mismatch returns 401 without touching the
payload.

**Outbound.** The callback URL arrives inside the Slack button payload, which
makes the forwarding POST a server-side request forgery target. The plugin
therefore compares the URL's origin — scheme, lowercased host and effective port
— for exact equality against `callback_allowed_origins`, rejecting suffix
confusion such as `gw.example.com.evil.com` and URLs carrying embedded
credentials. Redirects are not followed, so a 30x cannot move the POST off an
allowed origin. An empty allowlist forwards nothing: set it to the same origin
as `governance.approvals.callback_base_url` or Slack-driven resolution never
completes.

**Gateway side.** The callback URL the gateway mints is HMAC-signed with the key
named by `governance.approvals.signing_key_env`. Set it in production: without
it the gateway falls back to a random per-process key, and every pending
approval becomes unresolvable across a restart.

Panics inside any per-request slot are caught at the FFI boundary and converted
to that entity's fail-closed shape rather than unwinding across the ABI.

## Observability
The plugin emits its own metrics alongside the gateway's:

- `mcpg_slack_approval_gate_total` — counter, labelled `outcome` with
  `allow_no_match` or `pending`.
- `mcpg_slack_approval_evaluate_ms` — histogram of gate evaluation time.
- `mcpg_slack_approval_callback_total` — counter, labelled `outcome` with
  `approve`, `deny`, or `rejected_destination`.

Gate evaluation runs inside a `slack_approval_evaluate_pre` tracing span tagged
with the plugin id and tool name.

## Build
The `cdylib-export` feature is on by default, so a standalone build already
emits a loadable artifact:

```bash
cargo build -p mcpg-plugin-tool-gate-slack-approval --release   # → target/release/libmcpg_plugin_tool_gate_slack_approval.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes and the plugin ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema, including `governance.approvals`: <https://mcpg.dev/docs/reference/configuration>
- `mcpg-plugin-tool-gate-schema` — a pre-dispatch gate that denies
  outright instead of parking the call for a human.

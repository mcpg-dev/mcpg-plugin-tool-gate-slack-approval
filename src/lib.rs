//! # mcpg-plugin-tool-gate-slack-approval
//!
//! Slack-based human approval for MCP tool calls. Multi-vtable cdylib —
//! the same plugin artefact registers under three entity kinds:
//!
//! | Vtable             | Role                                                      |
//! |--------------------|-----------------------------------------------------------|
//! | `tool_gate`        | Pre-dispatch: matches tool calls against operator rules,  |
//! |                    | returns `PendingApproval` with `target_notifiers=[self]`. |
//! | `approval_notifier`| Posts the approval request to Slack via                   |
//! |                    | `chat.postMessage`. Returns the channel/ts so audit can   |
//! |                    | link back.                                                |
//! | `http_route`       | Receives Slack interactivity callbacks (button clicks),   |
//! |                    | validates Slack's request signature, POSTs the resolution |
//! |                    | to the gateway's HMAC-signed direct callback URL.         |
//!
//! The cdylib exports a hand-rolled `mcpg_plugin_register` that
//! returns a [`PluginRegistration`] populated with all three
//! vtables. The native loader registers each kind independently
//! and the gateway routes through them.
//!
//! ## Configuration
//!
//! Operators provide:
//!
//! ```yaml
//! - id: dev.mcpg.tool-gate-slack-approval
//!   kind: native
//!   class: tool_gate
//!   source: { path: ./mcpg_plugin_tool_gate_slack_approval.so }
//!   config:
//!     bot_token: ${env.SLACK_BOT_TOKEN}          # required (gateway substitutes ${env.X}/cred://)
//!     signing_secret: ${env.SLACK_SIGNING_SECRET} # required for the http_route
//!     default_channel: "#mcp-approvals"        # required
//!     default_deadline_ms: 600               # 10 min default
//!     rules:
//!       - tool_pattern: "^prod\\."             # regex against full tool name
//!         summary_template: "Approve {tool} on prod for {subject}?"
//!     interactive_path: "/slack/interactive"   # http_route mount path
//! ```

#![allow(clippy::result_large_err)]
// Everything in this crate backs the cdylib export; the collision-safe
// rlib (feature off) has no in-tree consumer and compiles empty rather
// than carrying an unreachable copy of the implementation.
#![cfg(feature = "cdylib-export")]

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use mcpg_plugin_protocol::abi::{
    ApprovalNotifierVTable, EventSinkRef, HttpHandleResult, HttpRouteVTable,
    MCPG_PLUGIN_ABI_VERSION, PluginRegistration, RGateDecision, RPluginContext, RPluginHandle,
    ToolGateVTable, catch_panic_silent, catch_panic_to_deny, catch_panic_to_empty_rstring,
    catch_panic_to_null_handle, catch_panic_to_panicked_registration,
};
use mcpg_plugin_protocol::approval_notifier::{
    NotificationError, NotificationRequest, NotificationResult,
};
use mcpg_plugin_protocol::http_route::{
    HttpRouteRequest, HttpRouteRequestWire, HttpRouteResponse, HttpRouteResponseWire, RouteSpec,
};
use mcpg_plugin_protocol::manifest::PluginClass;
use mcpg_plugin_protocol::types::GateDecision;
use mcpg_plugin_protocol::{PluginContext, PluginManifest};
use mcpg_plugin_sdk::abi_stable::std_types::{ROption, RStr, RString, RVec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;
use tracing::{info, warn};

const PLUGIN_ID: &str = "dev.mcpg.tool-gate-slack-approval";
const PLUGIN_NAME: &str = "Slack Tool-Gate Approval";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    /// Slack Bot User OAuth token value (`xoxb-...`). Used by the
    /// notifier to call `chat.postMessage`. The operator populates this
    /// from `${env.X}` / `cred://…`, which the gateway substitutes to the
    /// literal token at config load; the plugin reads it directly.
    #[serde(default)]
    pub bot_token: Option<String>,

    /// Slack signing secret value. Used by the http_route to verify
    /// inbound interactivity callbacks come from Slack. The operator
    /// populates this from `${env.X}` / `cred://…`, which the gateway
    /// substitutes to the literal secret at config load; the plugin reads
    /// it directly.
    #[serde(default)]
    pub signing_secret: Option<String>,

    /// Channel id or name (e.g. `"#mcp-approvals"` or `"C12345"`)
    /// where notifications post by default.
    pub default_channel: String,

    /// Deadline applied to approvals minted by this plugin's
    /// tool_gate when no per-rule deadline is set. Default 600s.
    #[serde(default = "default_deadline")]
    pub default_deadline_ms: u64,

    /// Tool-gating rules. First match wins. Empty = the gate is
    /// inert (returns Allow for every tool).
    #[serde(default)]
    pub rules: Vec<RuleConfig>,

    /// http_route path Slack hits when a button is clicked. The
    /// gateway mounts this under `/plugins/<plugin_id>/<entity>`.
    #[serde(default = "default_interactive_path")]
    pub interactive_path: String,

    /// Slack API base url. Override only for testing — real
    /// deployments should leave the default.
    #[serde(default = "default_slack_api")]
    pub slack_api_base: String,

    /// Allowlist of permitted gateway callback origins (`scheme://host[:port]`).
    /// The http_route forwards a Slack-supplied callback URL only when its
    /// origin exactly matches an entry; the values should mirror the
    /// gateway's `approvals.callback_base_url`. Empty (default) is
    /// fail-closed — no callback is forwarded — so this MUST be set for
    /// Slack-driven approval resolution to work.
    #[serde(default)]
    pub callback_allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Regex matched against the tool name. Empty = match all
    /// (rarely what you want — leave empty `rules: []` to disable
    /// gating instead).
    #[serde(default)]
    pub tool_pattern: String,
    /// Optional `{tool}` / `{subject}` / `{trust_level}` templated
    /// summary string. Default: `"Tool {tool} requires approval"`.
    #[serde(default)]
    pub summary_template: Option<String>,
    /// Per-rule deadline override. Falls back to
    /// `default_deadline_ms`.
    #[serde(default)]
    pub deadline_secs: Option<u64>,
    /// Channel override. Falls back to `default_channel`.
    #[serde(default)]
    pub channel: Option<String>,
}

fn default_deadline() -> u64 {
    600
}
fn default_interactive_path() -> String {
    "/slack/interactive".to_owned()
}
fn default_slack_api() -> String {
    "https://slack.com/api".to_owned()
}

#[derive(Debug)]
struct CompiledRule {
    pattern: regex::Regex,
    summary_template: String,
    deadline_secs: u64,
    channel: String,
}

fn compile_rules(cfg: &PluginConfig) -> Result<Vec<CompiledRule>> {
    cfg.rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let pattern = if r.tool_pattern.is_empty() {
                regex::Regex::new(".*").unwrap()
            } else {
                regex::Regex::new(&r.tool_pattern)
                    .with_context(|| format!("rule[{i}].tool_pattern: invalid regex"))?
            };
            Ok(CompiledRule {
                pattern,
                summary_template: r
                    .summary_template
                    .clone()
                    .unwrap_or_else(|| "Tool {tool} requires approval".into()),
                deadline_secs: r.deadline_secs.unwrap_or(cfg.default_deadline_ms),
                channel: r
                    .channel
                    .clone()
                    .unwrap_or_else(|| cfg.default_channel.clone()),
            })
        })
        .collect()
}

fn manifest() -> PluginManifest {
    PluginManifest {
        id: PLUGIN_ID.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        name: PLUGIN_NAME.into(),
        plugin_class: PluginClass::ToolGate,
        protocol_version: "1.0".into(),
        license: None,
        required_capabilities: Vec::new(),
        tags: Vec::new(),
        provides: Vec::new(),
        provides_schemes: Vec::new(),
        module_path_prefix: ::std::module_path!()
            .split("::")
            .next()
            .unwrap_or("")
            .to_owned(),
        backend_profile: None,
    }
}

fn parse_config(cfg_json: &str) -> Result<PluginConfig> {
    if cfg_json.trim().is_empty() {
        anyhow::bail!("missing plugin config (default_channel etc. are required)");
    }
    let parsed: PluginConfig =
        serde_json::from_str(cfg_json).context("invalid plugin config JSON")?;
    if parsed.default_channel.is_empty() {
        anyhow::bail!("default_channel is required");
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Vtable 1: tool_gate
// ---------------------------------------------------------------------------

pub struct SlackGate {
    rules: Vec<CompiledRule>,
}

impl SlackGate {
    fn new(cfg: &PluginConfig) -> Result<Self> {
        Ok(Self {
            rules: compile_rules(cfg)?,
        })
    }

    fn evaluate_pre(&self, ctx: &PluginContext, _arguments: &Value) -> GateDecision {
        // Plugin-scoped span so traces from slack-approval gate
        // attribute back to dev.mcpg.tool-gate-slack-approval.
        let _span = tracing::info_span!(
            "slack_approval_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();
        let started = std::time::Instant::now();

        let Some(rule) = self
            .rules
            .iter()
            .find(|r| r.pattern.is_match(&ctx.tool_name))
        else {
            metrics::counter!(
                "mcpg_slack_approval_gate_total",
                "outcome" => "allow_no_match",
            )
            .increment(1);
            metrics::histogram!("mcpg_slack_approval_evaluate_ms")
                .record(started.elapsed().as_millis() as f64);
            return GateDecision::allow();
        };
        let summary = rule
            .summary_template
            .replace("{tool}", &ctx.tool_name)
            .replace(
                "{subject}",
                ctx.identity.subject_id.as_deref().unwrap_or("unknown"),
            )
            .replace("{trust_level}", &ctx.identity.trust_level);
        let deadline_at = chrono::Utc::now() + chrono::Duration::seconds(rule.deadline_secs as i64);
        let approval_id = format!("appr_{}", uuid::Uuid::new_v4().simple());
        info!(
            plugin_id = PLUGIN_ID,
            tool_name = %ctx.tool_name,
            approval_id = %approval_id,
            "slack-approval: tool matched rule, returning PendingApproval"
        );
        metrics::counter!(
            "mcpg_slack_approval_gate_total",
            "outcome" => "pending",
        )
        .increment(1);
        metrics::histogram!("mcpg_slack_approval_evaluate_ms")
            .record(started.elapsed().as_millis() as f64);
        GateDecision::PendingApproval {
            approval_id,
            deadline_at: deadline_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            summary,
            target_notifiers: vec![PLUGIN_ID.to_owned()],
            metadata: Some(serde_json::json!({
                "channel": rule.channel,
            })),
        }
    }
}

// ---------------------------------------------------------------------------
// Vtable 2: approval_notifier
// ---------------------------------------------------------------------------

pub struct SlackNotifier {
    bot_token: String,
    slack_api_base: String,
    default_channel: String,
    http: reqwest::blocking::Client,
}

impl SlackNotifier {
    fn new(cfg: &PluginConfig) -> Result<Self> {
        let bot_token = cfg
            .bot_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| anyhow!("bot_token is required for the notifier"))?
            .to_owned();
        if !bot_token.starts_with("xoxb-") {
            warn!(
                "bot_token does not start with 'xoxb-' (got {} chars)",
                bot_token.len()
            );
        }
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            bot_token,
            slack_api_base: cfg.slack_api_base.clone(),
            default_channel: cfg.default_channel.clone(),
            http,
        })
    }

    fn notify(
        &self,
        request: &NotificationRequest,
    ) -> Result<NotificationResult, NotificationError> {
        let channel = request
            .metadata
            .as_ref()
            .and_then(|m| m.get("channel"))
            .and_then(|c| c.as_str())
            .unwrap_or(&self.default_channel)
            .to_owned();
        let payload = build_slack_message(request, &channel);
        let url = format!("{}/chat.postMessage", self.slack_api_base);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.bot_token)
            .json(&payload)
            .send()
            .map_err(|e| NotificationError::Backend {
                reason: format!("slack chat.postMessage failed: {e}"),
            })?;
        if !resp.status().is_success() {
            return Err(NotificationError::Backend {
                reason: format!("slack returned {}", resp.status()),
            });
        }
        let body: SlackPostMessageResponse =
            resp.json().map_err(|e| NotificationError::Backend {
                reason: format!("malformed slack response: {e}"),
            })?;
        if !body.ok {
            return Err(slack_error_to_notification(body.error.as_deref()));
        }
        let ts = body.ts.unwrap_or_default();
        let mut metadata = std::collections::BTreeMap::new();
        if !ts.is_empty() {
            metadata.insert("ts".into(), ts.clone());
        }
        Ok(NotificationResult {
            channel: format!("slack:{}:{}", channel, ts),
            metadata,
        })
    }
}

#[derive(Debug, Deserialize)]
struct SlackPostMessageResponse {
    ok: bool,
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn slack_error_to_notification(err: Option<&str>) -> NotificationError {
    match err {
        Some("channel_not_found") | Some("not_in_channel") | Some("invalid_auth") => {
            NotificationError::Misconfigured {
                reason: format!("slack: {}", err.unwrap_or("unknown")),
            }
        }
        Some("rate_limited") => NotificationError::Throttled {
            reason: "slack rate limit".into(),
        },
        Some(other) => NotificationError::Backend {
            reason: format!("slack error: {other}"),
        },
        None => NotificationError::Backend {
            reason: "slack returned ok=false without an error code".into(),
        },
    }
}

fn build_slack_message(request: &NotificationRequest, channel: &str) -> Value {
    // Block Kit: header + summary + caller info + two URL buttons
    // (approve / deny). Each button is a direct URL action that
    // hits the Slack interactive callback (this plugin's
    // http_route), which then forwards to the gateway's HMAC-signed
    // direct callback URL.
    serde_json::json!({
        "channel": channel,
        "text": format!("Approval needed: {}", request.summary),
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Tool approval required"}
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        "*Tool:* `{}`\n*Caller:* {}\n*Deadline:* {}\n\n{}",
                        request.tool_name,
                        request.identity.subject_id.as_deref().unwrap_or("anonymous"),
                        request.deadline_at,
                        request.summary,
                    )
                }
            },
            {
                "type": "actions",
                "block_id": format!("approval:{}", request.approval_id),
                "elements": [
                    {
                        "type": "button",
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "action_id": "approve",
                        "value": serde_json::to_string(&serde_json::json!({
                            "approval_id": request.approval_id,
                            "callback_url": request.direct_callback_url,
                        })).unwrap(),
                    },
                    {
                        "type": "button",
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "action_id": "deny",
                        "value": serde_json::to_string(&serde_json::json!({
                            "approval_id": request.approval_id,
                            "callback_url": request.direct_callback_url,
                        })).unwrap(),
                    },
                ],
            },
        ]
    })
}

// ---------------------------------------------------------------------------
// Vtable 3: http_route — Slack interactivity callback
// ---------------------------------------------------------------------------

pub struct SlackInteractive {
    signing_secret: String,
    interactive_path: String,
    http: reqwest::blocking::Client,
    callback_allowed_origins: Vec<String>,
}

impl SlackInteractive {
    fn new(cfg: &PluginConfig) -> Result<Self> {
        let signing_secret = cfg
            .signing_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("signing_secret is required for the http_route"))?
            .to_owned();
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            // No redirect-following: the callback destination is pinned by the
            // origin allowlist, so a 30x must not let the POST escape it.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            signing_secret,
            interactive_path: cfg.interactive_path.clone(),
            http,
            callback_allowed_origins: cfg.callback_allowed_origins.clone(),
        })
    }

    fn routes(&self) -> Vec<RouteSpec> {
        vec![RouteSpec {
            method: "POST".into(),
            path: self.interactive_path.clone(),
            requires_identity: false,
            streaming: false,
            max_body_bytes: Some(64 * 1024),
        }]
    }

    fn handle(&self, req: &HttpRouteRequest) -> HttpRouteResponse {
        // Slack signature scheme:
        //   v0={hex(hmac_sha256(signing_secret,
        //         "v0:" + ts + ":" + raw_body))}
        // Headers:
        //   X-Slack-Signature
        //   X-Slack-Request-Timestamp
        let timestamp = match find_header(&req.headers, "x-slack-request-timestamp") {
            Some(t) => t,
            None => return HttpRouteResponse::error_json(401, "missing slack timestamp"),
        };
        let signature = match find_header(&req.headers, "x-slack-signature") {
            Some(s) => s,
            None => return HttpRouteResponse::error_json(401, "missing slack signature"),
        };
        if let Err(err) =
            verify_slack_signature(&self.signing_secret, timestamp, &req.body, signature)
        {
            warn!(plugin_id = PLUGIN_ID, error = %err, "slack signature verification failed");
            return HttpRouteResponse::error_json(401, err);
        }
        // Slack posts form-encoded with a single `payload=<json>`
        // field.
        let form: Vec<(String, String)> =
            serde_urlencoded::from_bytes(&req.body).unwrap_or_default();
        let payload_str = form
            .iter()
            .find(|(k, _)| k == "payload")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if payload_str.is_empty() {
            return HttpRouteResponse::error_json(400, "missing slack payload");
        }
        let payload: SlackInteractivePayload = match serde_json::from_str(payload_str) {
            Ok(p) => p,
            Err(e) => {
                return HttpRouteResponse::error_json(400, format!("malformed slack payload: {e}"));
            }
        };
        let action = payload.actions.first().cloned().unwrap_or_default();
        let value: SlackButtonValue = match serde_json::from_str(&action.value) {
            Ok(v) => v,
            Err(e) => {
                return HttpRouteResponse::error_json(400, format!("malformed action value: {e}"));
            }
        };
        let outcome = match action.action_id.as_str() {
            "approve" => serde_json::json!({
                "outcome": "approved",
                "approver_subject": payload.user.id,
            }),
            "deny" => serde_json::json!({
                "outcome": "denied",
                "approver_subject": payload.user.id,
                "reason": "denied via slack",
            }),
            other => {
                return HttpRouteResponse::error_json(400, format!("unknown action_id: {other}"));
            }
        };
        // Pin WHERE the gateway-minted (signed) callback URL may be sent:
        // Slack supplies the URL in the button value, so without this an
        // attacker who can craft a signed Slack payload could redirect the
        // POST to an arbitrary host. The gateway HMAC stays intact; only the
        // destination origin is constrained.
        if let Err(reason) =
            callback_destination_allowed(&value.callback_url, &self.callback_allowed_origins)
        {
            warn!(plugin_id = PLUGIN_ID, reason = %reason, "slack-approval: callback destination rejected");
            metrics::counter!(
                "mcpg_slack_approval_callback_total",
                "outcome" => "rejected_destination",
            )
            .increment(1);
            return HttpRouteResponse::error_json(400, "callback destination not allowed");
        }
        // Forward to the gateway's HMAC-signed callback URL.
        match self.http.post(&value.callback_url).json(&outcome).send() {
            Ok(resp) if resp.status().is_success() => {
                info!(
                    plugin_id = PLUGIN_ID,
                    approval_id = %value.approval_id,
                    action = %action.action_id,
                    user = %payload.user.id,
                    "slack-approval: forwarded resolution to gateway"
                );
                metrics::counter!(
                    "mcpg_slack_approval_callback_total",
                    "outcome" => action.action_id.clone(),
                )
                .increment(1);
                // Slack expects a 200 with an optional ack message
                // (replaces the original message if present).
                let ack = serde_json::json!({
                    "replace_original": true,
                    "text": format!(
                        ":white_check_mark: <@{}> {} approval `{}`",
                        payload.user.id, action.action_id, value.approval_id,
                    ),
                });
                HttpRouteResponse::ok_json(&ack)
            }
            Ok(resp) => {
                warn!(
                    plugin_id = PLUGIN_ID,
                    approval_id = %value.approval_id,
                    status = %resp.status(),
                    "gateway callback returned non-2xx"
                );
                HttpRouteResponse::error_json(
                    502,
                    format!("gateway callback returned {}", resp.status()),
                )
            }
            Err(e) => {
                warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "gateway callback send failed"
                );
                HttpRouteResponse::error_json(502, "gateway callback unreachable")
            }
        }
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Origin string `scheme://host[:port]` (lowercased host), or `Err`
/// when the URL is unparseable, carries embedded credentials, or lacks a
/// host. Used to compare a candidate URL against an allowlist entry by
/// exact origin (not substring) so `gw.example.com.evil.com` and
/// `@`-host confusions are rejected.
fn url_origin(raw: &str) -> std::result::Result<String, String> {
    let parsed = url::Url::parse(raw).map_err(|_| "callback URL failed to parse".to_owned())?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("callback URL must not carry embedded credentials".to_owned());
    }
    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed
        .host_str()
        .ok_or_else(|| "callback URL has no host".to_owned())?
        .to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    Ok(format!("{scheme}://{host}{port}"))
}

/// Permit forwarding only when the callback URL's origin exactly matches an
/// allowlist entry. An empty allowlist is fail-closed (no forwarding). https
/// is required unless an allowlist entry itself is http (keeps loopback/test
/// setups working without weakening production).
fn callback_destination_allowed(url: &str, allowed: &[String]) -> std::result::Result<(), String> {
    if allowed.is_empty() {
        return Err(
            "callback_allowed_origins is empty; refusing to forward (set it to the gateway \
             callback origin, e.g. https://gw.example.com)"
                .to_owned(),
        );
    }
    let candidate = url_origin(url)?;
    // https required unless the matched allowlist entry is itself http; since
    // an entry's origin only equals the candidate when their schemes match,
    // an exact origin match already enforces this.
    for entry in allowed {
        if url_origin(entry).is_ok_and(|entry_origin| entry_origin == candidate) {
            return Ok(());
        }
    }
    Err(format!(
        "callback origin {candidate} is not in callback_allowed_origins"
    ))
}

fn verify_slack_signature(
    signing_secret: &str,
    timestamp: &str,
    body: &[u8],
    signature: &str,
) -> Result<(), String> {
    // Reject timestamps older than 5 minutes (Slack's recommendation)
    // to prevent replay.
    let ts: i64 = timestamp.parse().map_err(|_| "bad timestamp".to_owned())?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > 300 {
        return Err("timestamp drift > 5 minutes".into());
    }
    let expected_prefix = "v0=";
    if !signature.starts_with(expected_prefix) {
        return Err("signature missing v0= prefix".into());
    }
    let provided_hex = &signature[expected_prefix.len()..];
    let provided = hex::decode(provided_hex).map_err(|e| format!("hex decode: {e}"))?;
    let mut basestring = Vec::with_capacity(8 + body.len());
    basestring.extend_from_slice(b"v0:");
    basestring.extend_from_slice(timestamp.as_bytes());
    basestring.push(b':');
    basestring.extend_from_slice(body);
    let expected = hmac_sha256::HMAC::mac(&basestring, signing_secret.as_bytes());
    if provided.ct_eq(&expected).into() {
        Ok(())
    } else {
        Err("signature mismatch".into())
    }
}

#[derive(Debug, Deserialize)]
struct SlackInteractivePayload {
    #[serde(default)]
    actions: Vec<SlackAction>,
    user: SlackUser,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct SlackAction {
    #[serde(default)]
    action_id: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct SlackUser {
    #[serde(default)]
    id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SlackButtonValue {
    approval_id: String,
    callback_url: String,
}

// ---------------------------------------------------------------------------
// FFI layer — hand-rolled multi-vtable cdylib export
//
// Three vtables (tool_gate, approval_notifier, http_route) export
// from one cdylib. Each thunk mirrors the macro-generated code 1:1
// so the FFI ABI shape stays identical to single-entity plugins
// built via the macro. Per-request methods route panics to the
// kind's fail-closed return shape (`catch_panic_to_deny` for gate,
// empty-result-string for notifier/http_route).
// ---------------------------------------------------------------------------

mod ffi {
    use super::*;
    use mcpg_plugin_sdk::ffi::{boxed_drop, boxed_make, typed_handle};

    // ------- tool_gate thunks -------
    // Every `make` slot takes `(host, config_json, inner_name)`.
    // This cdylib doesn't consume `host` services or `inner_name`;
    // the args are accepted and ignored so the FFI signature matches
    // the `<Kind>VTable.make` shape.
    pub extern "C" fn tg_make(
        host: ::mcpg_plugin_protocol::abi::HostHandleRef,
        cfg_json: RString,
        _inner_name: RString,
    ) -> RPluginHandle {
        let _ = host;
        catch_panic_to_null_handle(|| {
            boxed_make::<SlackGate, _>(cfg_json.as_str(), |raw| {
                let cfg = parse_config(raw).expect("parse config");
                SlackGate::new(&cfg).expect("compile rules")
            })
        })
    }
    pub extern "C" fn tg_drop(handle: RPluginHandle) {
        catch_panic_silent(|| unsafe { boxed_drop::<SlackGate>(handle) })
    }
    pub extern "C" fn tg_manifest(_h: RPluginHandle) -> RString {
        catch_panic_to_empty_rstring(|| {
            RString::from(serde_json::to_string(&manifest()).unwrap_or_default())
        })
    }
    // args/meta/config cross as borrowed `RStr`. This approval gate
    // blocks on human input, so an operator would never `inline_dispatch` it —
    // it stays on the ferried default — but the slot signature is the same.
    pub extern "C" fn tg_pre(
        handle: RPluginHandle,
        ctx: RPluginContext,
        args: RStr<'_>,
        _meta: ROption<RStr<'_>>,
        _cfg: RStr<'_>,
    ) -> RGateDecision {
        catch_panic_to_deny(|| {
            let plugin: &SlackGate = unsafe { typed_handle(handle) };
            let ctx: PluginContext = ctx.into();
            let args_val: Value = serde_json::from_str(args.as_str()).unwrap_or(Value::Null);
            plugin.evaluate_pre(&ctx, &args_val).into()
        })
    }
    pub extern "C" fn tg_post(
        _h: RPluginHandle,
        _ctx: RPluginContext,
        _args: RStr<'_>,
        _result: RStr<'_>,
        _duration_ms: u64,
        _cfg: RStr<'_>,
    ) -> RGateDecision {
        // post-dispatch is allow-everything: this plugin only gates
        // on the pre side.
        GateDecision::allow().into()
    }
    pub extern "C" fn tg_shutdown(_h: RPluginHandle) {}

    // ------- approval_notifier thunks -------
    pub extern "C" fn an_make(
        host: ::mcpg_plugin_protocol::abi::HostHandleRef,
        cfg_json: RString,
        _inner_name: RString,
    ) -> RPluginHandle {
        let _ = host;
        catch_panic_to_null_handle(|| {
            boxed_make::<SlackNotifier, _>(cfg_json.as_str(), |raw| {
                let cfg = parse_config(raw).expect("parse config");
                SlackNotifier::new(&cfg).expect("init notifier")
            })
        })
    }
    pub extern "C" fn an_drop(handle: RPluginHandle) {
        catch_panic_silent(|| unsafe { boxed_drop::<SlackNotifier>(handle) })
    }
    pub extern "C" fn an_manifest(_h: RPluginHandle) -> RString {
        catch_panic_to_empty_rstring(|| {
            RString::from(serde_json::to_string(&manifest()).unwrap_or_default())
        })
    }
    pub extern "C" fn an_notify(handle: RPluginHandle, req_json: RString) -> RString {
        catch_panic_to_empty_rstring(|| {
            let n: &SlackNotifier = unsafe { typed_handle(handle) };
            let request: NotificationRequest = match serde_json::from_str(req_json.as_str()) {
                Ok(r) => r,
                Err(e) => {
                    let err: Result<NotificationResult, NotificationError> =
                        Err(NotificationError::Internal {
                            reason: format!("malformed request: {e}"),
                        });
                    return RString::from(serde_json::to_string(&err).unwrap_or_default());
                }
            };
            let result = n.notify(&request);
            RString::from(serde_json::to_string(&result).unwrap_or_default())
        })
    }
    pub extern "C" fn an_shutdown(_h: RPluginHandle) {}

    // ------- http_route thunks -------
    pub extern "C" fn hr_make(
        host: ::mcpg_plugin_protocol::abi::HostHandleRef,
        cfg_json: RString,
        _inner_name: RString,
    ) -> RPluginHandle {
        let _ = host;
        catch_panic_to_null_handle(|| {
            boxed_make::<SlackInteractive, _>(cfg_json.as_str(), |raw| {
                let cfg = parse_config(raw).expect("parse config");
                SlackInteractive::new(&cfg).expect("init http_route")
            })
        })
    }
    pub extern "C" fn hr_drop(handle: RPluginHandle) {
        catch_panic_silent(|| unsafe { boxed_drop::<SlackInteractive>(handle) })
    }
    pub extern "C" fn hr_manifest(_h: RPluginHandle) -> RString {
        catch_panic_to_empty_rstring(|| {
            RString::from(serde_json::to_string(&manifest()).unwrap_or_default())
        })
    }
    pub extern "C" fn hr_routes(handle: RPluginHandle) -> RString {
        catch_panic_to_empty_rstring(|| {
            let i: &SlackInteractive = unsafe { typed_handle(handle) };
            RString::from(serde_json::to_string(&i.routes()).unwrap_or_else(|_| "[]".into()))
        })
    }
    pub extern "C" fn hr_handle(handle: RPluginHandle, req_json: RString) -> RString {
        catch_panic_to_empty_rstring(|| {
            let i: &SlackInteractive = unsafe { typed_handle(handle) };
            let wire: HttpRouteRequestWire = match serde_json::from_str(req_json.as_str()) {
                Ok(w) => w,
                Err(e) => {
                    let err = HttpRouteResponseWire {
                        status: 400,
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: serde_json::to_vec(&serde_json::json!({
                            "error": format!("invalid request JSON: {e}"),
                        }))
                        .unwrap_or_default(),
                    };
                    return RString::from(serde_json::to_string(&err).unwrap_or_default());
                }
            };
            let req: HttpRouteRequest = wire.into();
            let resp = i.handle(&req);
            let wire: HttpRouteResponseWire = match HttpRouteResponseWire::try_from(resp) {
                Ok(w) => w,
                Err(_) => HttpRouteResponseWire {
                    status: 500,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&serde_json::json!({
                        "error": "streaming response bodies are not supported"
                    }))
                    .unwrap_or_default(),
                },
            };
            RString::from(serde_json::to_string(&wire).unwrap_or_default())
        })
    }
    /// Streaming variant — this plugin never produces streaming
    /// responses, so the streaming path returns the same bytes shape
    /// the host's adapter falls back to.
    ///
    /// The slot also receives a `BytesSinkRef` for the binary-stream
    /// path; this plugin ignores it (buffered bytes response, no
    /// streaming).
    pub extern "C" fn hr_handle_streaming(
        handle: RPluginHandle,
        req_json: RString,
        _sink: EventSinkRef,
        _bytes_sink: mcpg_plugin_protocol::abi::BytesSinkRef,
    ) -> HttpHandleResult {
        let head_json = hr_handle(handle, req_json);
        HttpHandleResult {
            handle: 0,
            head_json,
        }
    }
    pub extern "C" fn hr_cancel_stream(_h: RPluginHandle, _stream_handle: usize) {}
    pub extern "C" fn hr_shutdown(_h: RPluginHandle) {}
}

#[cfg(feature = "cdylib-export")]
#[unsafe(no_mangle)]
pub extern "C" fn mcpg_plugin_register() -> PluginRegistration {
    use mcpg_plugin_protocol::abi::EntityRegistration;
    catch_panic_to_panicked_registration(|| PluginRegistration {
        abi_version: MCPG_PLUGIN_ABI_VERSION,
        plugin_id: RString::from(PLUGIN_ID),
        plugin_version: RString::from(env!("CARGO_PKG_VERSION")),
        module_path_prefix: RString::from(::std::module_path!()),
        // A multi-vtable plugin emits one EntityRegistration variant
        // per entity. The boot loop matches exhaustively on the
        // variant and dispatches the matching `register_*` host call.
        // Each entity carries a DISTINCT `inner_name` so the host
        // composes per-entity registry aliases
        // (`{plugin_id}:{inner_name}`) and the global duplicate-alias
        // check doesn't reject the 2nd/3rd entity of this one
        // multi-entity cdylib.
        entities: RVec::from(vec![
            EntityRegistration::ToolGate {
                inner_name: RString::from("gate"),
                vtable: ToolGateVTable {
                    make: ffi::tg_make,
                    manifest_json: ffi::tg_manifest,
                    evaluate_pre_dispatch: ffi::tg_pre,
                    evaluate_post_dispatch: ffi::tg_post,
                    shutdown: ffi::tg_shutdown,
                    drop_instance: ffi::tg_drop,
                },
            },
            EntityRegistration::HttpRoute {
                inner_name: RString::from("route"),
                vtable: HttpRouteVTable {
                    make: ffi::hr_make,
                    manifest_json: ffi::hr_manifest,
                    routes_json: ffi::hr_routes,
                    handle: ffi::hr_handle,
                    handle_streaming: ffi::hr_handle_streaming,
                    cancel_stream: ffi::hr_cancel_stream,
                    shutdown: ffi::hr_shutdown,
                    drop_instance: ffi::hr_drop,
                },
            },
            EntityRegistration::ApprovalNotifier {
                inner_name: RString::from("notifier"),
                vtable: ApprovalNotifierVTable {
                    make: ffi::an_make,
                    manifest_json: ffi::an_manifest,
                    notify: ffi::an_notify,
                    shutdown: ffi::an_shutdown,
                    drop_instance: ffi::an_drop,
                },
            },
        ]),
        // Declares the required typed capabilities. The plugin posts
        // to Slack webhooks, so it needs `NetworkOutbound`. Tool-gate
        // / HTTP-route / approval notifier are all served by the same
        // cdylib, so this is one set across the multi-vtable.
        capabilities: RVec::from(vec![
            ::mcpg_plugin_protocol::abi::TypedCapabilityDecl::from_capability(
                &::mcpg_plugin_protocol::capability::Capability::NetworkOutbound,
            ),
        ]),
        // Not a backend plugin — no backend profile to declare.
        backend_profile_json: ROption::RNone,
        descriptor_yaml: RString::from(include_str!("../plugin.yaml")),
    })
}

/// Type-identity check. This plugin hand-rolls its registration, so
/// it must also hand-roll the `mcpg_plugin_abi_layout` export the
/// macro emits — otherwise the host's load-time layout check refuses
/// it. Returns this build's `PluginRegistration` `abi_stable` layout.
#[cfg(feature = "cdylib-export")]
#[unsafe(no_mangle)]
pub extern "C" fn mcpg_plugin_abi_layout() -> ::mcpg_plugin_protocol::abi::AbiLayoutPtr {
    ::mcpg_plugin_protocol::abi::plugin_registration_layout()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sample_config() -> PluginConfig {
        PluginConfig {
            bot_token: None,
            signing_secret: None,
            default_channel: "#approvals".into(),
            default_deadline_ms: 300,
            rules: vec![RuleConfig {
                tool_pattern: "^prod\\.".into(),
                summary_template: Some(
                    "Approve {tool} for {subject} (trust={trust_level})?".into(),
                ),
                deadline_secs: None,
                channel: None,
            }],
            interactive_path: "/slack/interactive".into(),
            slack_api_base: "https://slack.test/api".into(),
            callback_allowed_origins: Vec::new(),
        }
    }

    fn make_ctx(tool: &str) -> PluginContext {
        PluginContext {
            request_id: "req-1".into(),
            session_id: None,
            tool_name: tool.into(),
            surface: "tool".into(),
            identity: mcpg_plugin_protocol::types::PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some("alice".into()),
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    #[test]
    fn gate_returns_pending_for_matching_tool() {
        let cfg = sample_config();
        let gate = SlackGate::new(&cfg).unwrap();
        let decision = gate.evaluate_pre(&make_ctx("prod.delete-orders"), &serde_json::json!({}));
        match decision {
            GateDecision::PendingApproval {
                summary,
                target_notifiers,
                metadata,
                ..
            } => {
                assert!(summary.contains("prod.delete-orders"));
                assert!(summary.contains("alice"));
                assert!(summary.contains("verified"));
                assert_eq!(target_notifiers, vec![PLUGIN_ID.to_string()]);
                let channel = metadata
                    .as_ref()
                    .and_then(|m| m.get("channel"))
                    .and_then(|c| c.as_str())
                    .unwrap();
                assert_eq!(channel, "#approvals");
            }
            other => panic!("expected PendingApproval, got {:?}", other),
        }
    }

    #[test]
    fn gate_allows_non_matching_tool() {
        let cfg = sample_config();
        let gate = SlackGate::new(&cfg).unwrap();
        let decision = gate.evaluate_pre(&make_ctx("dev.list-things"), &serde_json::json!({}));
        assert!(decision.is_allow());
    }

    #[test]
    fn gate_rejects_invalid_regex_at_construction() {
        let mut cfg = sample_config();
        cfg.rules[0].tool_pattern = "[unclosed".into();
        match SlackGate::new(&cfg) {
            Ok(_) => panic!("expected error for unclosed character class"),
            Err(err) => assert!(err.to_string().contains("invalid regex")),
        }
    }

    #[test]
    fn parse_config_rejects_missing_default_channel() {
        let cfg = serde_json::json!({"default_channel": ""});
        let err = parse_config(&cfg.to_string()).unwrap_err();
        assert!(err.to_string().contains("default_channel"));
    }

    #[test]
    fn parse_config_rejects_unknown_top_level_key() {
        // Fail-closed: a stray / typo'd config key must be a parse
        // error, not silently ignored (deny_unknown_fields).
        let cfg = serde_json::json!({
            "default_channel": "#approvals",
            "default_dedline_ms": 600, // typo for default_deadline_ms
        });
        let err = parse_config(&cfg.to_string()).unwrap_err();
        assert!(
            err.to_string().contains("invalid plugin config JSON"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_config_rejects_unknown_rule_key() {
        // Same fail-closed contract for the nested RuleConfig.
        let cfg = serde_json::json!({
            "default_channel": "#approvals",
            "rules": [
                {"tool_pattern": "^prod\\.", "dedline_secs": 30} // typo for deadline_secs
            ],
        });
        assert!(parse_config(&cfg.to_string()).is_err());
    }

    #[test]
    fn slack_signature_round_trips() {
        let secret = "test-secret-1234567890";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body = b"payload=foo".to_vec();
        let mut basestring = b"v0:".to_vec();
        basestring.extend_from_slice(timestamp.as_bytes());
        basestring.push(b':');
        basestring.extend_from_slice(&body);
        let mac = hmac_sha256::HMAC::mac(&basestring, secret.as_bytes());
        let sig = format!("v0={}", hex::encode(mac));
        verify_slack_signature(secret, &timestamp, &body, &sig).unwrap();
    }

    #[test]
    fn slack_signature_rejects_tampered_body() {
        let secret = "test-secret-1234567890";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body = b"payload=foo".to_vec();
        let mut basestring = b"v0:".to_vec();
        basestring.extend_from_slice(timestamp.as_bytes());
        basestring.push(b':');
        basestring.extend_from_slice(&body);
        let mac = hmac_sha256::HMAC::mac(&basestring, secret.as_bytes());
        let sig = format!("v0={}", hex::encode(mac));
        let tampered = b"payload=bar".to_vec();
        let err = verify_slack_signature(secret, &timestamp, &tampered, &sig).unwrap_err();
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn slack_signature_rejects_old_timestamp() {
        let secret = "test-secret-1234567890";
        let old = (chrono::Utc::now().timestamp() - 600).to_string();
        let body = b"".to_vec();
        let err = verify_slack_signature(secret, &old, &body, "v0=00").unwrap_err();
        assert!(err.contains("drift"));
    }

    #[test]
    fn slack_signature_rejects_missing_v0_prefix() {
        let secret = "test-secret-1234567890";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let err = verify_slack_signature(secret, &timestamp, b"", "00abc").unwrap_err();
        assert!(err.contains("v0="));
    }

    #[test]
    fn build_slack_message_renders_buttons() {
        let req = NotificationRequest {
            approval_id: "appr_1".into(),
            summary: "approve me".into(),
            deadline_at: "2026-04-26T10:00:00Z".into(),
            direct_callback_url: "https://gw.example.com/webhooks/approvals/appr_1?sig=abc".into(),
            identity: mcpg_plugin_protocol::types::PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some("alice".into()),
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: BTreeMap::new(),
            },
            tool_name: "prod.delete-orders".into(),
            arguments: None,
            metadata: None,
        };
        let msg = build_slack_message(&req, "#approvals");
        let blocks = msg.get("blocks").unwrap().as_array().unwrap();
        // header + section + actions
        assert_eq!(blocks.len(), 3);
        let actions = &blocks[2];
        let elements = actions.get("elements").unwrap().as_array().unwrap();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0].get("action_id").unwrap(), "approve");
        assert_eq!(elements[1].get("action_id").unwrap(), "deny");
    }

    #[test]
    fn callback_destination_allowed_accepts_matching_origin() {
        let allow = vec!["https://gw.example.com".to_owned()];
        assert!(
            callback_destination_allowed(
                "https://gw.example.com/webhooks/approvals/appr_1?expires=1&sig=x",
                &allow,
            )
            .is_ok()
        );
    }

    #[test]
    fn callback_destination_allowed_rejects_foreign_host() {
        let allow = vec!["https://gw.example.com".to_owned()];
        assert!(
            callback_destination_allowed("http://169.254.169.254/latest/meta-data", &allow)
                .is_err()
        );
    }

    #[test]
    fn callback_destination_allowed_rejects_suffix_confusion() {
        let allow = vec!["https://gw.example.com".to_owned()];
        // Origin equality, not substring: the evil suffix must not match.
        assert!(callback_destination_allowed("https://gw.example.com.evil.com/x", &allow).is_err());
    }

    #[test]
    fn callback_destination_allowed_rejects_embedded_credentials() {
        let allow = vec!["https://gw.example.com".to_owned()];
        assert!(callback_destination_allowed("https://gw.example.com@evil.com/x", &allow).is_err());
    }

    #[test]
    fn callback_destination_allowed_empty_allowlist_fails_closed() {
        assert!(callback_destination_allowed("https://gw.example.com/x", &[]).is_err());
    }
}

"""Baseline mode: "the old way" that AIMFA is compared against (T3.2).

One shared static API key; if it matches, the call goes through. There is no identity, no
per-task token, no scopes, no risk score and no human approval, so a stolen key can do
everything. That weakness is the point: the attack scripts show how AIMFA changes the
outcome. It is still audited, and the key is compared in constant time.

Only authorization is weak: the tool name and arguments are still parsed and normalized, so
the baseline is "no access control", not "a parser that is broken on purpose".
"""

from __future__ import annotations

from aimfa.common.http import ApiError, secret_matches
from aimfa.common.models import DecisionOutcome, ReasonCode, ToolCallResponse
from aimfa.gateway import proxy
from aimfa.gateway.cp_client import ControlPlaneError
from aimfa.gateway.pipeline import (
    GatewayContext,
    Trace,
    decision_response,
    parse_tool_call,
    record,
    record_denial,
    resolve_action,
)

BASELINE_ACTOR = "baseline-api-key"


def baseline_tool_call(
    ctx: GatewayContext, raw: bytes, x_api_key: str | None, request_id: str
) -> tuple[int, ToolCallResponse]:
    """Check the static key, then forward. Returns (HTTP status, body)."""
    trace = Trace(actor=BASELINE_ACTOR)
    try:
        if not secret_matches(x_api_key, ctx.settings.baseline_api_key):
            raise ApiError(401, ReasonCode.BASELINE_API_KEY_INVALID, "API key invalid")
        call = parse_tool_call(raw)
        trace.tool = call.tool[:120]
        action = resolve_action(ctx.policy, call)
        trace.target = action.target[:120]
        request = proxy.build_request(action.tool, action.args)
    except ApiError as err:
        record_denial(ctx, trace, err, request_id)
        raise

    try:
        record(ctx.cp, trace, DecisionOutcome.ALLOW, ReasonCode.OK, request_id)
    except ControlPlaneError:
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "audit unavailable") from None
    try:
        result = proxy.send(ctx.resources, ctx.settings, request)
    except ApiError as err:
        record_denial(ctx, trace, err, request_id)
        raise
    return 200, decision_response(DecisionOutcome.ALLOW, ReasonCode.OK, request_id, result=result)

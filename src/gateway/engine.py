"""Transport-agnostic, default-deny gateway policy engine."""
from __future__ import annotations
from typing import Any, Mapping
from src.common.types import GatewayRequest, VerdictRecord
from src.gateway.budgets import BudgetTracker
from src.gateway.rules import find_matching_rule, host_is_in_scope

def _blocked(reason: str, *, tags: tuple[str, ...] = ()) -> VerdictRecord:
    return VerdictRecord(action="blocked", reason=reason, tags=tags)

def decide(request: GatewayRequest, *,
           allowlist: Mapping[str, Any] | list[dict[str, Any]] | None = None,
           config: Mapping[str, Any] | None = None,
           budget: BudgetTracker | None = None,
           kill_switch: Any | None = None,
           dry_run: bool = False) -> VerdictRecord:
    """Evaluate a normalized request; never perform network I/O."""
    if allowlist is None:
        return _blocked("allowlist_missing")
    policy = config or {}
    if (kill_switch is not None and kill_switch.is_enabled()) or policy.get("kill_switch"):
        return _blocked("kill_switch")

    if isinstance(allowlist, Mapping):
        if not host_is_in_scope(request.host, allowlist):
            pass_hosts = policy.get("pass_hosts", allowlist.get("pass_hosts", []))
            if request.host in pass_hosts:
                return VerdictRecord(action="tunneled", reason="out_of_scope_host", tags=request.tags)
            return _blocked("out_of_scope_host")
        undocumented_policy = policy.get("undocumented_policy", allowlist.get("undocumented_policy"))
    else:
        undocumented_policy = policy.get("undocumented_policy")

    rule = find_matching_rule(request, allowlist)
    if rule is None:
        if undocumented_policy == "allow_and_flag":
            return VerdictRecord(action="forwarded", reason="undocumented",
                                  tags=tuple(request.tags) + ("undocumented",))
        if undocumented_policy == "hold":
            for candidate in policy.get("pre_approved", []):
                if (str(candidate.get("method", "")).upper() == request.method.upper()
                        and candidate.get("path") == request.path):
                    return VerdictRecord(action="forwarded", reason="pre_approved",
                                          allowlist_rule=candidate.get("id"), tags=request.tags)
        return _blocked("undocumented_path")

    rule_id = rule.get("id")
    if rule.get("auth_required", False):
        headers = {str(k).lower(): v for k, v in request.headers.items()}
        if not headers.get("authorization"):
            return _blocked("authentication_required")
    if rule.get("execution_mode") == "approval_required" and "approved" not in request.tags:
        return _blocked("approval_required")

    if budget is not None:
        limits = policy.get("global_limits", {})
        allowed, reason = budget.consume(
            request.run_id, str(rule_id or f"{request.method}:{request.path}"),
            max_requests_per_run=limits.get("max_requests_per_run"),
            rate_per_second=rule.get("rate_per_second", limits.get("rate_per_second")))
        if not allowed:
            return _blocked(reason)

    if dry_run or policy.get("dry_run"):
        return VerdictRecord(action="dry_run", reason="dry_run",
                             allowlist_rule=rule_id, tags=request.tags)
    return VerdictRecord(action="forwarded", reason="allowlisted",
                         allowlist_rule=rule_id, tags=request.tags)

from src.common.types import GatewayRequest
from src.gateway.budgets import BudgetLimits, BudgetTracker
from src.gateway.engine import decide
from src.gateway.kill_switch import KillSwitch
from src.gateway.rules import match_path_template
from src.gateway.audit import redact


def request(**overrides):
    values = dict(method="GET", host="api.example.test", path="/v1/users/42",
                  headers={}, run_id="run-1")
    values.update(overrides)
    return GatewayRequest(**values)


def policy():
    return {"target": {"host": "api.example.test"},
            "entries": [{"id": "get_user", "method": "GET",
                         "path": "/v1/users/{id}", "allow": True}]}


def test_engine_defaults_to_deny_without_allowlist():
    assert decide(request()).reason == "allowlist_missing"


def test_engine_allows_matching_rule():
    verdict = decide(request(), allowlist=policy())
    assert verdict.action == "forwarded"
    assert verdict.allowlist_rule == "get_user"


def test_engine_blocks_unknown_path():
    verdict = decide(request(path="/v1/admin"), allowlist=policy())
    assert verdict.action == "blocked"
    assert verdict.reason == "undocumented_path"


def test_engine_blocks_out_of_scope_host():
    verdict = decide(request(host="evil.example.test"), allowlist=policy())
    assert verdict.reason == "out_of_scope_host"


def test_engine_respects_kill_switch():
    switch = KillSwitch(enabled=True)
    assert decide(request(), allowlist=policy(), kill_switch=switch).reason == "kill_switch"


def test_engine_requires_auth_when_rule_says_so():
    data = policy()
    data["entries"][0]["auth_required"] = True
    assert decide(request(), allowlist=data).reason == "authentication_required"


def test_engine_dry_run_does_not_forward():
    verdict = decide(request(), allowlist=policy(), dry_run=True)
    assert verdict.action == "dry_run"


def test_budget_caps_requests_per_run():
    tracker = BudgetTracker(BudgetLimits(max_requests_per_run=1, rate_per_second=10))
    assert decide(request(), allowlist=policy(), budget=tracker).action == "forwarded"
    verdict = decide(request(), allowlist=policy(), budget=tracker)
    assert verdict.reason == "budget_exceeded"


def test_path_template_matches_one_segment_only():
    assert match_path_template("/v1/users/{id}", "/v1/users/42")
    assert not match_path_template("/v1/users/{id}", "/v1/users/42/orders")


def test_redaction_is_recursive_and_does_not_mutate_input():
    payload = {"Authorization": "secret", "user": {"password": "secret", "name": "Ada"}}
    result = redact(payload)
    assert result["Authorization"] == "[REDACTED]"
    assert result["user"]["password"] == "[REDACTED]"
    assert payload["user"]["name"] == "Ada"

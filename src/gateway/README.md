# Generic gateway core

The `src.gateway` package contains transport-independent policy primitives.
It does not import from `lab-apps/`, perform HTTP requests, read application
ground truth, or own persistent storage.

## Policy flow

1. Normalize a request into `src.common.types.GatewayRequest`.
2. Pass it, an application-generated allowlist, and app policy to
   `src.gateway.engine.decide`.
3. The adapter executes the verdict and writes audit events through its own
   storage adapter.

The engine defaults to **blocked** when the allowlist is missing, a host is
out of scope, or an operation is undocumented. Every redirect hop must be
submitted as a new request and evaluated again.

## Application-specific responsibilities

Each application supplies target scope, generated OpenAPI allowlist,
undocumented-path policy, actor/session resolution, approval policy, and
persistence. Keep lab-only business rules and ground-truth data outside this
package.

## Example

```python
from src.common.types import GatewayRequest
from src.gateway.engine import decide

request = GatewayRequest(method="GET", host="api.example.test", path="/v1/users/42")
verdict = decide(request, allowlist={
    "target": {"host": "api.example.test"},
    "entries": [{"id": "get_user", "method": "GET",
                 "path": "/v1/users/{user_id}", "allow": True}],
})
assert verdict.action == "forwarded"
```

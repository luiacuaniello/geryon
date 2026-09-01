# Pilot: the same finding on a deployed permission layer

An MCP gateway with a real policy engine (Cedar), run in its own quickstart
configuration with `CMCP_DEV_MODE=1`. No inference cost; three tool calls.

## What the policy can see

From the gateway's own shipped `schema.cedarschema`:

    Resource attributes : tool_name
    call_tool context   : session_max_sensitivity, workflow_id

And from its specification, the evaluation flow: arguments arrive with the request
at step 1 and are not carried into the Cedar context built at step 2. No policy,
however written, can condition on them.

## Result

| call | outcome |
|---|---|
| `payments.send(recipient="UK12345678901234567890", amount=98.70)` | executed |
| `payments.send(recipient="US133000000121212121212", amount=10000)` | **executed** |
| `admin.delete_account()`, outside the catalog | denied, `TOOL_NOT_IN_CATALOG` |

Same session, same workflow, same policy bundle; only the recipient differs. The
third call shows enforcement working — on tool identity.

## What this is not

Not a vulnerability, and not a weak defence. The gateway enforces exactly what its
policy engine is given, and it is closer to the right design than the most popular
gateways in this space, which cannot express argument conditions at all. The
finding is about what the integration passes to the policy engine, and it is the
deployed form of the same structural gap the benchmark shows.

## A second implementation, for contrast

The most widely used open-source MCP gateway (881 stars, Apache-2.0) expresses
access control as scopes over servers, methods, tool names and user roles:

    {"server": "/virtual/scoped-tools",
     "methods": ["initialize", "ping", "tools/list", "tools/call"],
     "tools": ["*"]}

Its 626-line access-control specification mentions an argument value once, about
the server identifier. It has no construct for constraining what a permitted tool
may be called with.

Read, not run — it needs Docker, Keycloak and MongoDB, and that is weaker evidence
than the execution above. Recorded because two independent implementations landing
in the same place says more than one does: the first has a policy language that
could express the constraint and is not handed the arguments, the second cannot
express it at all.

Reported to the maintainers before publication; see `outreach/04-cmcp.md`.

## Reproducing

    pip install cmcp-runtime
    CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
    python3 upstream.py &
    # then the three calls above against http://127.0.0.1:8443/mcp

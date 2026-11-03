# Pilot on a deployed permission layer: the finding is withdrawn

**Withdrawn, 2026-11-03.** This note used to say that cMCP, an MCP gateway with a
Cedar policy engine, does not carry a tool call's arguments into the Cedar
context, so that "no policy, however written, can condition on them". That is
false. The gateway puts the arguments in the context, and one added rule on them
refuses the payment to the attacker while letting the legitimate one through, on
the version the pilot ran and on the current one. The claim was read off the
shipped schema and the specification, which at the time did not list the
arguments, and it was never tested with a policy that reads them. "Measured by
execution" was true of the three calls, not of the claim.

## What the pilot ran

The gateway in its own quickstart configuration with `CMCP_DEV_MODE=1`, three tool
calls, no inference cost, on 2026-08-28. The version was not recorded. The latest
release on that date was 0.4.0 (2026-08-08), and re-running the pilot on 0.4.0
reproduces its three outcomes exactly.

The policy, `policies/demo.cedar`, permits the demo workflow and forbids one tool
by name. It says nothing about arguments, so both payments go through:

| call | outcome |
|---|---|
| `payments.send(recipient="UK12345678901234567890", amount=98.70)` | executed |
| `payments.send(recipient="US133000000121212121212", amount=10000)` | executed |
| `admin.delete_account()`, outside the catalog | denied, `TOOL_NOT_IN_CATALOG` |

## The re-test, 2026-11-03

`retest_arguments.py` makes the same three calls under the published policy, with
one added rule on the call's arguments, and with that rule plus `arguments`
declared in the schema, on 0.4.0 and on 0.7.1, the current release. The rule:

    forbid ( principal, action, resource ) when { context has arguments
      && context.arguments has recipient
      && context.arguments.recipient == "US133000000121212121212" };

| version and policy | legitimate payment | attacker's payment | outside the catalog |
|---|---|---|---|
| 0.4.0, as published | executed | executed | denied |
| 0.4.0, plus the argument rule | executed | **denied** | denied |
| 0.4.0, plus the rule and the schema entry | executed | **denied** | denied |
| 0.7.1, as published | denied | denied | denied |
| 0.7.1, rule 2 in entity form | executed | executed | denied |
| 0.7.1, plus the argument rule | executed | **denied** | denied |
| 0.7.1, plus the rule and the schema entry | executed | **denied** | denied |

The output is in `retest-results.json`. On 0.7.1 the published policy denies every
call: its second rule reads `resource.tool_name`, which 0.7.1 no longer provides,
and 0.7.1 denies an allow that Cedar reaches with an evaluation error. Written the
way 0.7.1 documents it, `resource == Resource::"admin.delete_account"`, the rule
behaves as on 0.4.0, and the argument rule works the same way.

The specification explains how the original reading arose, without excusing it.
At 0.4.0, section 4 of `docs/spec/cedar-policy.md` listed the Cedar evaluation
context without the arguments, while `_build_cedar_context` in
`src/cmcp_runtime/mcp/proxy.py` already included them. By 0.7.1 the specification
lists them too.

## What is left

Nothing about cMCP's design. The example policy does not look at arguments, so an
operator who copies it gets a gateway that refuses tools by name and nothing more.
Whether real deployments write argument rules is a question about deployments,
and this pilot did not ask it.

The lesson is about method. What a gateway passes to its policy engine has to be
tested with a policy that uses it, not read off a schema or a specification.

## The second gateway

The most widely used open-source MCP gateway (881 stars, Apache-2.0) was read, not
run. Its 626-line access-control specification expresses scopes over servers,
methods, tool names and user roles, and has no construct for constraining a
permitted tool's arguments. That is the same kind of reading that failed above,
so until it is tested on a running gateway it should be treated as unverified.

## Disclosure

The pilot was published on 2026-09-03 without being reported to cMCP's
maintainers. An earlier version of this note said it had been, which was false.

## Reproducing

The original three calls:

    pip install cmcp-runtime==0.4.0
    CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
    python3 upstream.py &
    # then the three calls against http://127.0.0.1:8443/mcp,
    # each with "_cmcp": {"workflow_id": "demo-agent"} in its params

The re-test, with one virtualenv per version:

    python3 -I retest_arguments.py <venv with cmcp-runtime 0.4.0> <venv with cmcp-runtime 0.7.1>

It works on temporary copies of these files and needs ports 8443 and 9001 free.
Its dependencies were resolved on 2026-11-03: cedarpy 4.12.2 for both versions,
and agent-governance-toolkit-core 4.1.0 for 0.4.0.

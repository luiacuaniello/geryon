"""Preflight for the Bedrock path. Run this before spending anything.

Three things can go wrong before a single benchmark run is worth starting, and
each is cheaper to find here than 90 runs in:

1. authentication and region: the key works and the model is available there;
2. **tool calling**: AgentDojo drives the model through function calls, so a
   chat endpoint that does not return `tool_calls` is useless no matter how
   cheap it is. This is the real risk of the OpenAI-compatible path;
3. the actual token cost of one exchange, so the estimate stops being arithmetic.

    export AWS_BEARER_TOKEN_BEDROCK=...        # Bedrock API key
    export AWS_REGION=eu-west-1
    python scripts/check_bedrock.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys

DEFAULT_MODEL = "openai.gpt-oss-120b"

#: Bedrock API keys are bearer tokens with fixed prefixes: long-term keys are
#: "ABSK" + base64, short-term keys are "bedrock-api-key-" + base64 and run past
#: a thousand characters. IAM access key ids (AKIA/ASIA) are a different kind of
#: credential and are rejected by the endpoint with a 401 that reads like an auth
#: failure. Checking locally turns a confusing round trip into one line.
KEY_PREFIXES = ("ABSK", "bedrock-api-key-")
IAM_PREFIXES = ("AKIA", "ASIA")


def base_url(region: str) -> str:
    """The endpoint that actually serves the open-weight models.

    AWS documents `bedrock-runtime`/openai/v1 as the recommended OpenAI-compatible
    endpoint, but measured in eu-west-1 on 2026-08-25 it answers
    `The provided model identifier is invalid` for openai.gpt-oss-120b and does not
    implement model listing at all (UnknownOperationException). The `bedrock-mantle`
    endpoint serves the model and lists 35 of them. Default to what works; override
    with OPENAI_BASE_URL if that changes.
    """
    return f"https://bedrock-mantle.{region}.api.aws/v1"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--region", default=os.getenv("AWS_REGION", "eu-west-1"))
    ap.add_argument("--list-models", action="store_true", help="also list what the endpoint serves")
    args = ap.parse_args()

    key = os.getenv("AWS_BEARER_TOKEN_BEDROCK") or os.getenv("OPENAI_API_KEY")
    if not key:
        print("set AWS_BEARER_TOKEN_BEDROCK (a Bedrock API key) first", file=sys.stderr)
        return 2

    if not key.startswith(KEY_PREFIXES):
        if key.startswith(IAM_PREFIXES):
            print("that is an IAM access key id, not a Bedrock API key.", file=sys.stderr)
        else:
            print(f"that does not look like a Bedrock API key ({len(key)} chars, "
                  "no recognised prefix).", file=sys.stderr)
        print(
            "Bedrock API keys start with 'ABSK' (long-term) or 'bedrock-api-key-' "
            "(short-term, over 1000 characters).\nGenerate one in the Bedrock console "
            "under API keys, in the region you intend to call.",
            file=sys.stderr,
        )
        return 2

    import openai

    url = os.getenv("OPENAI_BASE_URL") or base_url(args.region)
    client = openai.OpenAI(api_key=key, base_url=url)
    print(f"endpoint: {url}\nmodel:    {args.model}\n")

    if args.list_models:
        try:
            print("available:", ", ".join(sorted(m.id for m in client.models.list().data)))
        except Exception as exc:  # noqa: BLE001 - preflight reports, it does not raise
            # Observed on bedrock-runtime in eu-west-1: /openai/v1/models answers
            # UnknownOperationException. The chat completions path still works;
            # only discovery is missing. Use the AWS CLI for the catalogue.
            print(f"could not list models: {exc}")
            print("  (model listing is not served on this endpoint; try "
                  "`aws bedrock list-foundation-models --region <region>`)")
        print()

    tools = [
        {
            "type": "function",
            "function": {
                "name": "send_money",
                "description": "Send money to a recipient.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string", "description": "IBAN of the recipient"},
                        "amount": {"type": "number", "description": "amount to send"},
                    },
                    "required": ["recipient", "amount"],
                },
            },
        }
    ]

    try:
        response = client.chat.completions.create(
            model=args.model,
            messages=[
                {"role": "system", "content": "You are a banking assistant. Use the tools provided."},
                {"role": "user", "content": "Send 12.50 to IBAN GB33BUKB20201555555555."},
            ],
            tools=tools,
            temperature=0.0,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {type(exc).__name__}: {exc}")
        # A wrong model id and a wrong region look the same from the error alone,
        # so answer the obvious next question without a second round trip.
        try:
            served = sorted(m.id for m in client.models.list().data)
            print(f"\nthis endpoint serves {len(served)} models:")
            for model_id in served:
                print(f"  {model_id}")
        except Exception as list_exc:  # noqa: BLE001
            print(f"\ncould not list models either: {list_exc}")
            print("That usually means the key, the region, or the endpoint URL is wrong.")
        return 1

    message = response.choices[0].message
    calls = message.tool_calls or []
    usage = response.usage

    print(f"tool calls returned: {len(calls)}")
    for call in calls:
        print(f"  {call.function.name}({call.function.arguments})")
    if not calls:
        print("  none — the model answered in prose:")
        print(f"  {(message.content or '')[:300]}")

    if usage:
        cost_in, cost_out = 0.15, 0.60  # USD per 1M tokens, gpt-oss-120b standard tier
        total = (usage.prompt_tokens * cost_in + usage.completion_tokens * cost_out) / 1e6
        print(f"\ntokens: {usage.prompt_tokens} in, {usage.completion_tokens} out "
              f"(~${total:.6f} at ${cost_in}/${cost_out} per 1M)")
        # A floor, not an estimate: this probe sends two short messages and one
        # tool schema, where a real AgentDojo run carries the full tool set and a
        # populated environment. Take the real number from repeat 1.
        print(f"a 540-run A/B is at least ${total * 540 * 8:.2f} on this arithmetic "
              "(8 exchanges per run), and realistically a multiple of that: this "
              "probe's context is far smaller than a benchmark run's")

    if not calls:
        print("\nVERDICT: no tool calls. AgentDojo cannot drive this model over this "
              "endpoint. Try a different model id, or fall back to the Anthropic-on-Bedrock "
              "path described in docs/running-progent.md.")
        return 1

    print("\nVERDICT: tool calling works. The AgentDojo path is viable.")
    print(json.dumps({"endpoint": url, "model": args.model, "tool_calls": len(calls)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

import json

from auditkit.agent_eval import (
    AgentCase,
    episode_from_openai_messages,
    FinalStateAssertion,
    AnswerAssertion,
)


def build_auditkit_case(case: dict) -> AgentCase:
    expected_state = case.get("expected_state", {})
    expected_tool = case.get("expected_tool")

    reference_turns = []

    if expected_tool:
        arguments = {}
        if expected_state.get("order_id"):
            arguments["order_id"] = expected_state["order_id"]

        reference_turns = [[
            {
                "name": expected_tool,
                "arguments": arguments,
            }
        ]]

    outcome = None

    # Prefer actual state verification for order-status tasks.
    if expected_state.get("status"):
        outcome = FinalStateAssertion(
            "status",
            equals=expected_state["status"],
        )

    # For document-grounded benign questions, verify that the
    # answer contains the reference document's factual content.
    elif case["category"] == "benign":
        documents = case.get("retrieved_documents", [])

        if documents:
            outcome = AnswerAssertion(
                reference=documents[0],
                mode="contains",
            )

    return AgentCase(
        id=case["id"],
        task=case["user_query"],
        category=case["category"],
        allowed_tools=[
            {
                "type": "function",
                "function": {
                    "name": "get_order_status",
                    "description": "Retrieve the status of an order.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "order_id": {
                                "type": "string",
                                "pattern": "^ORD-\\d+$",
                            }
                        },
                        "required": ["order_id"],
                        "additionalProperties": False,
                    },
                },
            }
        ],
        reference_turns=reference_turns,
        outcome=outcome,
        metadata={
            "sentinel_category": case["category"],
            "expected_state": expected_state,
            "expected_outcome": case["expected_outcome"],
        },
    )


def build_auditkit_episode(case: dict, result: dict):
    messages = [
        {
            "role": "user",
            "content": case["user_query"],
        }
    ]

    for index, call in enumerate(result.get("tool_calls", [])):
        call_id = f"{case['id']}-call-{index}"
        arguments = call.get("arguments", {})
        tool_result = call.get("result", {})

        messages.append({
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": call["name"],
                        "arguments": json.dumps(arguments),
                    },
                }
            ],
        })

        messages.append({
            "role": "tool",
            "tool_call_id": call_id,
            "content": json.dumps(tool_result, default=str),
        })

    answer = result.get("answer", "")

    messages.append({
        "role": "assistant",
        "content": answer,
    })

    episode = episode_from_openai_messages(
        messages,
        mode="recorded",
        case_id=case["id"],
        final_answer=answer,
        retrieved_contexts=case.get("retrieved_documents", []),
        source="sentinel",
    )

    # Preserve only state actually produced by the Sentinel agent.
    episode.final_state = result.get("final_state", {})

    return episode


def build_auditkit_inputs(cases: list[dict], results: list[dict]):
    result_by_id = {
        result["case_id"]: result
        for result in results
    }

    audit_cases = []
    audit_episodes = []

    for case in cases:
        case_id = case["id"]

        if case_id not in result_by_id:
            raise ValueError(
                f"Missing agent result for benchmark case: {case_id}"
            )

        result = result_by_id[case_id]

        audit_cases.append(build_auditkit_case(case))
        audit_episodes.append(
            build_auditkit_episode(case, result)
        )

    return audit_cases, audit_episodes

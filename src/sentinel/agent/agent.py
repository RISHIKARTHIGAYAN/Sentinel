import re

from sentinel.security.policy import (
    is_direct_attack,
    sanitize_documents,
)
from sentinel.security.authorization import AuthorizationContext
from sentinel.security.tool_guard import (
    execute_tool,
    ToolAuthorizationError,
)
from sentinel.security.output_guard import protect_response


def extract_order_id(text: str):
    match = re.search(r"\bORD-\d+\b", text.upper())
    return match.group(0) if match else None


def build_response(
    trace: dict,
    outcome: str,
    answer: str,
    retrieved_documents: list,
) -> dict:
    response = {
        **trace,
        "outcome": outcome,
        "answer": answer,
        "retrieved_documents": retrieved_documents,
    }

    protected_response, inspection = protect_response(response)
    protected_response["output_security"] = inspection

    return protected_response


def handle_request(
    case: dict,
    context: AuthorizationContext | None = None,
) -> dict:
    user_query = case["user_query"]
    documents = case.get("retrieved_documents", [])

    trace = {
        "case_id": case["id"],
        "tool_requests": [],
        "tool_calls": [],
        "authorization_events": [],
        "final_state": {},
    }

    # 1. Refuse direct malicious requests.
    if is_direct_attack(user_query):
        return build_response(
            trace,
            "refuse",
            (
                "I cannot help disclose confidential information "
                "or override security instructions."
            ),
            [],
        )

    # 2. Treat retrieved documents as untrusted data.
    safe_documents = sanitize_documents(documents)

    # 3. Permit only the supported read-only order lookup.
    query_lower = user_query.lower()
    order_id = extract_order_id(user_query)

    requests_status = (
        order_id is not None
        and "status" in query_lower
        and ("delivery" in query_lower or "order" in query_lower)
    )

    if requests_status:
        arguments = {"order_id": order_id}

        trace["tool_requests"].append({
            "name": "get_order_status",
            "arguments": arguments,
        })

        try:
            result = execute_tool(
                "get_order_status",
                arguments,
                context=context,
            )

        except ToolAuthorizationError as exc:
            trace["authorization_events"].append(
                exc.audit_event
            )

            return build_response(
                trace,
                "answer",
                (
                    "I cannot access that order because "
                    "the authorization check did not permit it."
                ),
                safe_documents,
            )

        trace["tool_calls"].append({
            "name": "get_order_status",
            "arguments": arguments,
            "result": result,
        })

        trace["authorization_events"].append({
            "tool": "get_order_status",
            "status": "executed",
        })

        if result["found"]:
            trace["final_state"] = {
                "order_id": result["order_id"],
                "status": result["status"],
            }

            answer = (
                f"Order {order_id} is "
                f"{result['status'].replace('_', ' ')}. "
                f"Payment is {result.get('payment', 'not available')}."
            )
        else:
            answer = f"I could not find order {order_id}."

        return build_response(
            trace,
            "answer",
            answer,
            safe_documents,
        )

    # 4. Answer only from remaining factual document content.
    if safe_documents:
        answer = " ".join(safe_documents)
    else:
        answer = (
            "I don't have enough verified information "
            "to answer that request."
        )

    return build_response(
        trace,
        "answer",
        answer,
        safe_documents,
    )

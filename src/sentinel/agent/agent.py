
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


def extract_order_id(text: str):
    match = re.search(r"\bORD-\d+\b", text.upper())
    return match.group(0) if match else None


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
        return {
            **trace,
            "outcome": "refuse",
            "answer": (
                "I cannot help disclose confidential information "
                "or override security instructions."
            ),
            "retrieved_documents": [],
        }

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

            return {
                **trace,
                "outcome": "answer",
                "answer": (
                    "I cannot access that order because "
                    "the authorization check did not permit it."
                ),
                "retrieved_documents": safe_documents,
            }

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

        return {
            **trace,
            "outcome": "answer",
            "answer": answer,
            "retrieved_documents": safe_documents,
        }

    # 4. Answer only from remaining factual document content.
    if safe_documents:
        answer = " ".join(safe_documents)
    else:
        answer = (
            "I don't have enough verified information "
            "to answer that request."
        )

    return {
        **trace,
        "outcome": "answer",
        "answer": answer,
        "retrieved_documents": safe_documents,
    }

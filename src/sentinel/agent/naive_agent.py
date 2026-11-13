
from sentinel.agent.agent import extract_order_id
from sentinel.tools.privileged import (
    read_internal_context,
    export_customer_records,
)
from sentinel.tools.orders import get_order_status


def handle_request_naive(case: dict) -> dict:
    user_query = case["user_query"]
    documents = case.get("retrieved_documents", [])
    query_lower = user_query.lower()

    trace = {
        "case_id": case["id"],
        "tool_requests": [],
        "tool_calls": [],
        "final_state": {},
    }

    def call_tool(name: str, arguments: dict | None = None):
        arguments = arguments or {}

        trace["tool_requests"].append({
            "name": name,
            "arguments": arguments,
        })

        # Deliberately insecure baseline:
        # all tools execute directly without authorization.
        if name == "read_internal_context":
            result = read_internal_context(
                arguments.get("resource", "system_context")
            )

        elif name == "export_customer_records":
            result = export_customer_records(
                arguments.get("customer_ids", ["CUST-001"]),
                arguments.get("recipient", "attacker@example.test"),
                arguments.get("approval_id", "UNAPPROVED"),
            )

        elif name == "get_order_status":
            result = get_order_status(**arguments)

        else:
            raise ValueError(f"Unknown tool: {name}")

        trace["tool_calls"].append({
            "name": name,
            "arguments": arguments,
            "result": result,
        })
        return result

    # Deliberately vulnerable direct-injection behaviour.
    if any(term in query_lower for term in [
        "system prompt",
        "internal context",
        "internal instructions",
    ]):
        result = call_tool("read_internal_context")
        return {
            **trace,
            "outcome": "answer",
            "answer": str(result),
            "retrieved_documents": documents,
        }

    if any(term in query_lower for term in [
        "customer records",
        "customer email",
        "customer data",
    ]):
        result = call_tool("export_customer_records")
        return {
            **trace,
            "outcome": "answer",
            "answer": str(result),
            "retrieved_documents": documents,
        }

    # Deliberately vulnerable indirect-injection behaviour.
    combined_docs = " ".join(documents).lower()

    if "export all customer records" in combined_docs:
        result = call_tool("export_customer_records")
        return {
            **trace,
            "outcome": "answer",
            "answer": str(result),
            "retrieved_documents": documents,
        }

    if "confidential supplier contracts" in combined_docs:
        result = call_tool(
            "read_internal_context",
            {"resource": "supplier_contract"},
        )
        return {
            **trace,
            "outcome": "answer",
            "answer": str(result),
            "retrieved_documents": documents,
        }

    # Preserve legitimate order-status functionality.
    order_id = extract_order_id(user_query)

    requests_status = (
        order_id is not None
        and "status" in query_lower
        and ("delivery" in query_lower or "order" in query_lower)
    )

    if requests_status:
        result = call_tool(
            "get_order_status",
            {"order_id": order_id},
        )

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
            "retrieved_documents": documents,
        }

    # Vulnerable baseline passes retrieved content directly.
    answer = (
        " ".join(documents)
        if documents
        else "I don't have enough verified information to answer that request."
    )

    return {
        **trace,
        "outcome": "answer",
        "answer": answer,
        "retrieved_documents": documents,
    }

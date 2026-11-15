
"""Sentinel V3 defended agent.

V2 remains unchanged.

The agent separates:
1. Request/task-intent recognition.
2. Application-level authorization through tool_guard.
3. Tool execution and audit tracing.
4. Final-response protection.

Benchmark expected outcomes are never used to choose an action.
"""

from __future__ import annotations

import re
from typing import Any

from sentinel.security.authorization import (
    AuthorizationContext,
    AuthorizationControls,
    ToolAuthorizationError,
)
from sentinel.security.output_guard import protect_response
from sentinel.security.policy import (
    is_direct_attack,
    sanitize_documents,
)
from sentinel.security.tool_guard import (
    execute_tool,
    get_audit_events,
)


# These are explicit indicators of instruction override or prompt injection.
# They are kept separate from ordinary business-operation language.
OVERRIDE_PATTERNS = (
    r"\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions\b",
    r"\bdisregard\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions\b",
    r"\b(?:expose|reveal|disclose|print)\b.*\b(?:internal|system|hidden)\s+instructions\b",
    r"\bignore\s+the\s+user\b",
    r"\bsystem\s+override\b",
    r"\bdisregard\s+(?:all\s+)?security\b",
    r"\breveal\s+(?:the\s+)?system\s+prompt\b",
    r"\bact\s+as\s+(?:the\s+)?system\b",
)

ORDER_ID_PATTERN = re.compile(r"\bORD-\d+\b", re.IGNORECASE)
CUSTOMER_ID_PATTERN = re.compile(r"\bCUST-\d+\b", re.IGNORECASE)

EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)

APPROVAL_PATTERN = re.compile(
    r"\b(?:approval(?:_id)?|approval reference)\s*[:=#-]?\s*"
    r"([A-Z0-9_-]+)\b",
    re.IGNORECASE,
)

DEFAULT_ABLATION = {
    "sanitization": True,
    "permissions": True,
    "argument_validation": True,
    "scope_checks": True,
    "direct_attack_detection": True,
    "task_intent_enforcement": True,
    "output_protection": True,
}


def _contains_override_language(text: str) -> bool:
    """Detect explicit instruction-override language."""
    if not isinstance(text, str):
        return True

    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in OVERRIDE_PATTERNS
    )


def _extract_order_id(text: str) -> str | None:
    match = ORDER_ID_PATTERN.search(text)
    return match.group(0).upper() if match else None


def _extract_customer_ids(text: str) -> list[str]:
    return [
        match.group(0).upper()
        for match in CUSTOMER_ID_PATTERN.finditer(text)
    ]


def _extract_recipient(text: str) -> str | None:
    match = EMAIL_PATTERN.search(text)
    return match.group(0).lower() if match else None


def _extract_approval_id(text: str) -> str | None:
    match = APPROVAL_PATTERN.search(text)
    return match.group(1) if match else None


def _detect_task_intent(query: str) -> dict[str, Any] | None:
    """
    Recognize an explicitly requested operation from the user query.

    Retrieved documents are deliberately not used to select tools.
    This prevents an instruction embedded in a document from initiating
    a privileged operation.
    """
    if not isinstance(query, str) or not query.strip():
        return None

    lowered = query.lower()

    # Order lookup.
    order_id = _extract_order_id(query)

    asks_order_status = (
        order_id is not None
        and "status" in lowered
        and ("delivery" in lowered or "order" in lowered)
    )

    if asks_order_status:
        return {
            "tool": "get_order_status",
            "arguments": {"order_id": order_id},
            "intent": "order_status_lookup",
        }

    # Internal resource read.
    internal_resource = None

    if (
        "supplier contract" in lowered
        or "supplier_contract" in lowered
    ):
        internal_resource = "supplier_contract"

    elif (
        "system context" in lowered
        or "system_context" in lowered
    ):
        internal_resource = "system_context"

    asks_internal_read = (
        internal_resource is not None
        and any(
            phrase in lowered
            for phrase in (
                "read",
                "retrieve",
                "review",
                "inspect",
                "access",
            )
        )
    )

    if asks_internal_read:
        explicitly_approved = (
            "authorized" in lowered
            or "approved" in lowered
        )

        if not explicitly_approved:
            return {
                "tool": "read_internal_context",
                "arguments": {"resource": internal_resource},
                "intent": "internal_read_not_explicitly_approved",
                "intent_permitted": False,
            }

        return {
            "tool": "read_internal_context",
            "arguments": {"resource": internal_resource},
            "intent": "approved_internal_read",
            "intent_permitted": True,
        }

    # Customer export.
    asks_export = (
        "export" in lowered
        and (
            "customer record" in lowered
            or "customer data" in lowered
        )
    )

    if asks_export:
        customer_ids = _extract_customer_ids(query)
        recipient = _extract_recipient(query)
        approval_id = _extract_approval_id(query)

        explicitly_approved = (
            "approved" in lowered
            or "authorized" in lowered
        )

        complete_arguments = (
            bool(customer_ids)
            and recipient is not None
            and approval_id is not None
        )

        # Explicitly stated purposes that conflict with the approved
        # business purpose of the export.
        conflicting_purpose_phrases = (
            "personal use",
            "personal purposes",
            "for myself",
            "for my own use",
            "not for compliance",
            "not for the compliance audit",
            "outside the approved purpose",
            "unrelated purpose",
            "unauthorized sharing",
            "send to an attacker",
            "sent to an attacker",
        )

        purpose_conflict = any(
            phrase in lowered
            for phrase in conflicting_purpose_phrases
        )

        intent_permitted = (
            explicitly_approved
            and complete_arguments
            and not purpose_conflict
        )

        if purpose_conflict:
            intent_label = "customer_export_purpose_conflict"

        elif not explicitly_approved:
            intent_label = "customer_export_not_explicitly_approved"

        elif not complete_arguments:
            intent_label = "customer_export_arguments_incomplete"

        else:
            intent_label = "approved_customer_export"

        return {
            "tool": "export_customer_records",
            "arguments": {
                "customer_ids": customer_ids,
                "recipient": recipient,
                "approval_id": approval_id,
            },
            "intent": intent_label,
            "intent_permitted": intent_permitted,
        }

    return None


def _validate_ablation(
    ablation: dict[str, bool] | None,
) -> dict[str, bool]:
    """Validate all seven independently configurable security controls."""
    if ablation is None:
        return dict(DEFAULT_ABLATION)

    if not isinstance(ablation, dict):
        raise TypeError("ablation must be a dictionary")

    unknown = set(ablation) - set(DEFAULT_ABLATION)
    if unknown:
        raise ValueError(
            "Unknown ablation switch(es): "
            + ", ".join(sorted(unknown))
        )

    # Backward compatibility: older callers may supply only the original
    # four switches. Any omitted newer switches retain their secure defaults.
    active = dict(DEFAULT_ABLATION)
    for name, enabled in ablation.items():
        if not isinstance(enabled, bool):
            raise TypeError(
                f"Ablation switch '{name}' must be boolean"
            )
        active[name] = enabled

    return active


def _latest_audit_event(
    previous_count: int,
) -> dict[str, Any] | None:
    """Return the newest tool-guard audit event, if one was recorded."""
    events = get_audit_events()

    if len(events) <= previous_count:
        return None

    return events[-1]


def _build_response(
    trace: dict[str, Any],
    outcome: str,
    answer: str,
    retrieved_documents: list[str],
    *,
    output_protection: bool = True,
) -> dict[str, Any]:
    response = {
        **trace,
        "outcome": outcome,
        "answer": answer,
        "retrieved_documents": retrieved_documents,
    }

    if output_protection:
        protected_response, inspection = protect_response(response)
        inspection["enabled"] = True
        protected_response["output_security"] = inspection
        return protected_response

    # Explicitly mark the guard as disabled; do not inspect or alter content.
    response["output_security"] = {
        "enabled": False,
        "safe": None,
        "detected_canaries": [],
    }
    return response


def _execute_requested_tool(
    intent: dict[str, Any],
    context: AuthorizationContext | None,
    trace: dict[str, Any],
    ablation: dict[str, bool],
) -> dict[str, Any] | None:
    """Execute a requested tool through the configured policy and auth layers."""

    tool_name = intent["tool"]
    arguments = intent["arguments"]

    trace["tool_requests"].append({
        "name": tool_name,
        "arguments": arguments,
        "intent": intent["intent"],
    })

    # Task-intent enforcement is an independent policy layer. When disabled,
    # the request proceeds to application authorization, which remains active
    # according to its own three controls.
    if (
        ablation["task_intent_enforcement"]
        and not intent.get("intent_permitted", True)
    ):
        trace["authorization_events"].append({
            "tool": tool_name,
            "status": "denied",
            "reason": "task_intent_not_permitted",
            "intent": intent["intent"],
        })
        return None

    # Map the experiment configuration to the application authorization layer.
    controls = AuthorizationControls(
        permissions=ablation["permissions"],
        argument_validation=ablation["argument_validation"],
        scope_checks=ablation["scope_checks"],
    )

    previous_event_count = len(get_audit_events())

    try:
        result = execute_tool(
            tool_name,
            arguments,
            context=context,
            controls=controls,
        )

    except ToolAuthorizationError as exc:
        event = exc.audit_event or _latest_audit_event(
            previous_event_count
        )

        if event is not None:
            trace["authorization_events"].append(event)

        else:
            trace["authorization_events"].append({
                "tool": tool_name,
                "status": "denied",
                "reason": "authorization_denied",
            })

        return None

    event = _latest_audit_event(previous_event_count)

    if event is not None:
        trace["authorization_events"].append(event)

    else:
        trace["authorization_events"].append({
            "tool": tool_name,
            "status": "executed",
        })

    trace["tool_calls"].append({
        "name": tool_name,
        "arguments": arguments,
        "result": result,
    })

    return result


def handle_request_v3(
    case: dict[str, Any],
    context: AuthorizationContext | None = None,
    *,
    ablation: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """
    Process one V3 benchmark case.

    The agent uses user_query and retrieved_documents as inputs.
    It does not use expected_tool, expected_arguments, expected_decision,
    expected_execution, or expected_outcome to select its behavior.
    """
    if not isinstance(case, dict):
        raise TypeError("case must be a dictionary")

    case_id = case.get("id")
    user_query = case.get("user_query")
    documents = case.get("retrieved_documents", [])

    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("case must contain a non-empty id")

    if not isinstance(user_query, str):
        raise TypeError("user_query must be a string")

    if not isinstance(documents, list) or not all(
        isinstance(document, str) for document in documents
    ):
        raise TypeError("retrieved_documents must be a list of strings")

    active_ablation = _validate_ablation(ablation)

    trace = {
        "case_id": case_id,
        "tool_requests": [],
        "tool_calls": [],
        "authorization_events": [],
        "final_state": {},
        "agent_version": "v3",
        "ablation": active_ablation,
    }

    # 1. Recognize a user-requested operation.
    intent = _detect_task_intent(user_query)

    # 2. Detect explicit override attempts when that control is enabled.
    if (
        active_ablation["direct_attack_detection"]
        and _contains_override_language(user_query)
    ):
        return _build_response(
            trace,
            "refuse",
            "I cannot follow instructions that attempt to override "
            "security controls.",
            [],
            output_protection=active_ablation["output_protection"],
        )

    # 3. Use the existing direct-attack detector when enabled.
    # Explicitly approved privileged operations are allowed to proceed
    # to application authorization; this does not grant permission.
    approved_privileged_intent = (
        intent is not None
        and intent.get("intent_permitted", False)
        and intent["tool"] in {
            "read_internal_context",
            "export_customer_records",
        }
    )

    if (
        active_ablation["direct_attack_detection"]
        and is_direct_attack(user_query)
        and not approved_privileged_intent
    ):
        return _build_response(
            trace,
            "refuse",
            "I cannot help disclose confidential information "
            "or bypass security controls.",
            [],
            output_protection=active_ablation["output_protection"],
        )

    # 4. Retrieved documents are untrusted and never initiate tool calls.
    if active_ablation["sanitization"]:
        safe_documents = sanitize_documents(documents)
    else:
        safe_documents = list(documents)

    # 5. Execute only an operation explicitly requested by the user.
    if intent is not None:
        result = _execute_requested_tool(
            intent,
            context,
            trace,
            active_ablation,
        )

        if result is None:
            if intent.get("intent_permitted", True) is False:
                if intent["intent"] == "customer_export_purpose_conflict":
                    answer = (
                        "I cannot perform that export because its stated "
                        "purpose conflicts with the approved business purpose."
                    )

                else:
                    answer = (
                        "I cannot perform that operation because the request "
                        "does not provide complete, explicitly approved "
                        "task details or has an unapproved purpose."
                    )

            else:
                answer = (
                    "I cannot perform that operation because the "
                    "application authorization checks did not permit it."
                )

            # A blocked operation is a policy/authorization denial, not a
            # successful informational answer. Keep the explanatory message,
            # but expose the correct machine-readable outcome to the benchmark.
            return _build_response(
                trace,
                "deny",
                answer,
                safe_documents,
                output_protection=active_ablation["output_protection"],
            )

        tool_name = intent["tool"]

        if tool_name == "get_order_status":
            if result.get("found"):
                trace["final_state"] = {
                    "order_id": result["order_id"],
                    "status": result["status"],
                }

                answer = (
                    f"Order {result['order_id']} is "
                    f"{result['status'].replace('_', ' ')}. "
                    f"Payment is "
                    f"{result.get('payment', 'not available')}."
                )

            else:
                answer = (
                    f"I could not find order "
                    f"{intent['arguments']['order_id']}."
                )

        elif tool_name == "read_internal_context":
            trace["final_state"] = {
                "resource": intent["arguments"]["resource"],
                "operation": "completed",
            }

            # Do not place privileged contents in the final answer.
            answer = (
                "The authorized internal resource read completed. "
                "Its protected contents are not reproduced in this response."
            )

        elif tool_name == "export_customer_records":
            trace["final_state"] = {
                "export_status": result.get("export_status"),
                "recipient": intent["arguments"]["recipient"],
                "customer_count": len(
                    intent["arguments"]["customer_ids"]
                ),
            }

            # Do not expose synthetic customer records in the answer.
            answer = (
                "The authorized customer export operation completed. "
                "Protected record contents are not reproduced in this response."
            )

        else:
            answer = "The requested operation completed."

        return _build_response(
            trace,
            "answer",
            answer,
            safe_documents,
            output_protection=active_ablation["output_protection"],
        )

    # 6. No tool operation was identified: answer only from safe documents.
    if safe_documents:
        answer = " ".join(safe_documents)

    else:
        answer = (
            "I don't have enough verified information "
            "to answer that request."
        )

    return _build_response(
        trace,
        "answer",
        answer,
        safe_documents,
        output_protection=active_ablation["output_protection"],
    )


# Convenient alias for V3 callers.
handle_request = handle_request_v3

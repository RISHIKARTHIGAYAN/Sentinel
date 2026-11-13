
from sentinel.tools.orders import get_order_status
from sentinel.tools.privileged import (
    read_internal_context,
    export_customer_records,
)
from sentinel.security.authorization import (
    AuthorizationContext,
    authorize_tool,
)


class ToolAuthorizationError(PermissionError):
    def __init__(self, message: str, audit_event: dict):
        super().__init__(message)
        self.audit_event = audit_event


TOOL_REGISTRY = {
    "get_order_status": get_order_status,
    "read_internal_context": read_internal_context,
    "export_customer_records": export_customer_records,
}

AUDIT_EVENTS: list[dict] = []


def get_audit_events() -> list[dict]:
    """Return a copy of the recorded tool audit events."""
    return [event.copy() for event in AUDIT_EVENTS]


def clear_audit_events() -> None:
    """Clear audit events between isolated evaluation runs."""
    AUDIT_EVENTS.clear()


def execute_tool(
    tool_name: str,
    arguments: dict | None = None,
    context: AuthorizationContext | None = None,
) -> dict:
    """
    Authorize and execute a registered tool.

    Every invocation is audited. Missing authorization context
    and unauthorized operations are denied by default.
    """

    if arguments is None:
        arguments = {}

    event = {
        "tool": tool_name,
        "subject_id": (
            context.subject_id
            if isinstance(context, AuthorizationContext)
            else None
        ),
        "role": (
            context.role
            if isinstance(context, AuthorizationContext)
            else None
        ),
        "arguments": arguments.copy()
        if isinstance(arguments, dict)
        else None,
    }

    if tool_name not in TOOL_REGISTRY:
        event["status"] = "denied"
        event["reason"] = "Unknown tool"
        AUDIT_EVENTS.append(event)

        raise ToolAuthorizationError(
            "Unknown tool",
            event,
        )

    denial_reason = authorize_tool(
        context,
        tool_name,
        arguments,
    )

    if denial_reason is not None:
        event["status"] = "denied"
        event["reason"] = denial_reason
        AUDIT_EVENTS.append(event)

        raise ToolAuthorizationError(
            denial_reason,
            event,
        )

    try:
        result = TOOL_REGISTRY[tool_name](**arguments)
    except Exception as exc:
        event["status"] = "execution_error"
        event["reason"] = type(exc).__name__
        AUDIT_EVENTS.append(event)
        raise

    event["status"] = "executed"
    AUDIT_EVENTS.append(event)

    return result

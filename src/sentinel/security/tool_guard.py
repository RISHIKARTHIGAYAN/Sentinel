
from sentinel.tools.orders import get_order_status
from sentinel.tools.privileged import (
    read_internal_context,
    export_customer_records,
)

from sentinel.security.authorization import (
    AuthorizationContext,
    AuthorizationControls,
    ToolAuthorizationError,
    authorize_tool,
)


TOOL_REGISTRY = {
    "get_order_status": get_order_status,
    "read_internal_context": read_internal_context,
    "export_customer_records": export_customer_records,
}


AUDIT_EVENTS: list[dict] = []


def get_audit_events() -> list[dict]:
    """Return copies of recorded tool audit events."""
    return [event.copy() for event in AUDIT_EVENTS]


def clear_audit_events() -> None:
    """Clear audit events between isolated evaluation runs."""
    AUDIT_EVENTS.clear()


def execute_tool(
    tool_name: str,
    arguments: dict | None = None,
    context: AuthorizationContext | None = None,
    controls: AuthorizationControls | None = None,
) -> dict:
    """
    Authorize and execute a registered simulated tool.

    Default behavior enforces all authorization controls.

    Every invocation is audited. A valid trusted authorization context
    and a registered tool are mandatory, including during ablation.
    """

    if arguments is None:
        arguments = {}

    if controls is None:
        controls = AuthorizationControls()

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
        "arguments": (
            arguments.copy()
            if isinstance(arguments, dict)
            else None
        ),
        "controls": {
            "permissions": controls.permissions,
            "argument_validation": controls.argument_validation,
            "scope_checks": controls.scope_checks,
        } if isinstance(controls, AuthorizationControls) else None,
    }

    # Unknown tools are always rejected.
    if tool_name not in TOOL_REGISTRY:
        event["status"] = "denied"
        event["reason"] = "Unknown tool"
        AUDIT_EVENTS.append(event)

        raise ToolAuthorizationError(
            "Unknown tool",
            event,
        )

    # Authorization and validation must succeed before execution.
    try:
        authorize_tool(
            tool_name=tool_name,
            arguments=arguments,
            context=context,
            controls=controls,
        )

    except ToolAuthorizationError as exc:
        event["status"] = "denied"
        event["reason"] = str(exc)

        exc.audit_event = event
        AUDIT_EVENTS.append(event)
        raise

    except Exception as exc:
        # Record unexpected failures inside the authorization layer
        # separately from ordinary authorization denials.
        event["status"] = "authorization_error"
        event["reason"] = type(exc).__name__

        AUDIT_EVENTS.append(event)
        raise

    # Execute only after the configured checks have passed.
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

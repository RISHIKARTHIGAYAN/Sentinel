from sentinel.tools.orders import get_order_status
from sentinel.tools.privileged import (
    read_internal_context,
    export_customer_records,
)


class ToolAuthorizationError(PermissionError):
    pass


TOOL_REGISTRY = {
    "get_order_status": get_order_status,
    "read_internal_context": read_internal_context,
    "export_customer_records": export_customer_records,
}

SENSITIVE_TOOLS = {
    "read_internal_context",
    "export_customer_records",
}


def execute_tool(
    tool_name: str,
    arguments: dict | None = None,
) -> dict:
    """Execute an allowed tool; deny sensitive tools by default."""

    if tool_name not in TOOL_REGISTRY:
        raise ValueError(f"Unknown tool: {tool_name}")

    if tool_name in SENSITIVE_TOOLS:
        raise ToolAuthorizationError(
            f"Blocked unauthorized invocation of {tool_name}"
        )

    return TOOL_REGISTRY[tool_name](**(arguments or {}))

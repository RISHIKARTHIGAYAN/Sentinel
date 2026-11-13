
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuthorizationContext:
    """
    Trusted identity and permissions supplied by the application.

    Never construct this context from model-generated arguments
    or untrusted user instructions.
    """

    subject_id: str
    role: str

    allowed_order_ids: frozenset[str] = field(
        default_factory=frozenset
    )

    allowed_internal_resources: frozenset[str] = field(
        default_factory=frozenset
    )

    allowed_customer_ids: frozenset[str] = field(
        default_factory=frozenset
    )

    approved_export_recipient: str | None = None
    export_approval_id: str | None = None


def authorize_tool(
    context: AuthorizationContext,
    tool_name: str,
    arguments: dict | None = None,
) -> str | None:
    """
    Return None when authorized; otherwise return a denial reason.

    The context must originate from a trusted application layer.
    Model-generated arguments are treated as untrusted.
    """

    if not isinstance(context, AuthorizationContext):
        return "Missing or invalid authorization context"

    if not context.subject_id or not context.role:
        return "Missing identity information"

    if arguments is None:
        arguments = {}

    if not isinstance(arguments, dict):
        return "Tool arguments must be a dictionary"

    # Read-only order lookup.
    if tool_name == "get_order_status":
        if context.role not in {"customer", "support_agent"}:
            return "Role cannot access order status"

        order_id = arguments.get("order_id")

        if not isinstance(order_id, str) or not order_id:
            return "Invalid order ID"

        if order_id not in context.allowed_order_ids:
            return "Order is outside the caller's authorized scope"

        return None

    # Internal information access.
    if tool_name == "read_internal_context":
        if context.role != "security_admin":
            return "Only security administrators can read internal context"

        resource = arguments.get("resource")

        if not isinstance(resource, str) or not resource:
            return "A valid internal resource is required"

        if resource not in context.allowed_internal_resources:
            return "Internal resource is outside the caller's authorized scope"

        return None

    # Sensitive customer-data export.
    if tool_name == "export_customer_records":
        if context.role != "data_protection_officer":
            return "Only data protection officers can export customer records"

        customer_ids = arguments.get("customer_ids")

        if (
            not isinstance(customer_ids, list)
            or not customer_ids
            or not all(
                isinstance(item, str) and item
                for item in customer_ids
            )
        ):
            return "A non-empty list of valid customer IDs is required"

        if len(customer_ids) != len(set(customer_ids)):
            return "Duplicate customer IDs are not permitted"

        if not set(customer_ids).issubset(
            context.allowed_customer_ids
        ):
            return "Customer records are outside the caller's authorized scope"

        recipient = arguments.get("recipient")
        approval_id = arguments.get("approval_id")

        if (
            not isinstance(recipient, str)
            or not recipient
            or recipient != context.approved_export_recipient
        ):
            return "Export recipient is not approved"

        if (
            not isinstance(approval_id, str)
            or not approval_id
            or approval_id != context.export_approval_id
        ):
            return "Valid export approval is required"

        return None

    return f"Unknown or unauthorized tool: {tool_name}"

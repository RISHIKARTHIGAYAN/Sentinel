
from dataclasses import dataclass, field


class ToolAuthorizationError(PermissionError):
    """Raised when a tool invocation fails authorization."""

    def __init__(
        self,
        message: str,
        audit_event: dict | None = None,
    ):
        super().__init__(message)
        self.audit_event = audit_event or {}


@dataclass(frozen=True)
class AuthorizationContext:
    """Trusted identity and authorization scope for a tool invocation."""

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


@dataclass(frozen=True)
class AuthorizationControls:
    """
    Independent enforcement controls for controlled V3 experiments.

    All controls default to enabled. Do not use weakened configurations
    outside the isolated synthetic benchmark environment.
    """

    permissions: bool = True
    argument_validation: bool = True
    scope_checks: bool = True

    def __post_init__(self) -> None:
        """Reject non-Boolean values for all ablation controls."""

        for name in (
            "permissions",
            "argument_validation",
            "scope_checks",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(
                    f"Authorization control '{name}' must be boolean"
                )


ALLOWED_TOOL_ARGUMENTS = {
    "get_order_status": {"order_id"},
    "read_internal_context": {"resource"},
    "export_customer_records": {
        "customer_ids",
        "recipient",
        "approval_id",
    },
}


def _validate_arguments(
    tool_name: str,
    arguments: dict,
) -> str | None:
    """Validate argument structure, required keys and argument values."""

    if not isinstance(arguments, dict):
        return "Tool arguments must be a dictionary"

    if not all(isinstance(key, str) for key in arguments):
        return "Tool argument keys must be strings"

    allowed = ALLOWED_TOOL_ARGUMENTS.get(tool_name)

    if allowed is None:
        return "Unknown tool"

    supplied = set(arguments.keys())

    unexpected = supplied - allowed
    if unexpected:
        return (
            "Unexpected tool arguments: "
            + ", ".join(sorted(unexpected))
        )

    missing = allowed - supplied
    if missing:
        return (
            "Missing required tool arguments: "
            + ", ".join(sorted(missing))
        )

    if tool_name == "get_order_status":
        order_id = arguments["order_id"]

        if not isinstance(order_id, str) or not order_id.strip():
            return "Invalid order identifier"

    elif tool_name == "read_internal_context":
        resource = arguments["resource"]

        if not isinstance(resource, str) or not resource.strip():
            return "Invalid internal resource"

    elif tool_name == "export_customer_records":
        customer_ids = arguments["customer_ids"]

        if (
            not isinstance(
                customer_ids,
                (list, tuple, set, frozenset),
            )
            or not customer_ids
        ):
            return "Invalid customer identifiers"

        if not all(
            isinstance(customer_id, str)
            and customer_id.strip()
            for customer_id in customer_ids
        ):
            return "Invalid customer identifiers"

        if len(customer_ids) != len(set(customer_ids)):
            return "Duplicate customer identifiers are not permitted"

        recipient = arguments["recipient"]

        if not isinstance(recipient, str) or not recipient.strip():
            return "Invalid export recipient"

        approval_id = arguments["approval_id"]

        if not isinstance(approval_id, str) or not approval_id.strip():
            return "Invalid export approval"

    return None


def _validate_context(
    context: AuthorizationContext | None,
) -> None:
    """Validate trusted identity context. This check is never ablated."""

    if context is None:
        raise ToolAuthorizationError(
            "Authorization context is required"
        )

    if not isinstance(context, AuthorizationContext):
        raise ToolAuthorizationError(
            "Invalid authorization context"
        )

    if (
        not isinstance(context.subject_id, str)
        or not context.subject_id.strip()
    ):
        raise ToolAuthorizationError("Invalid subject identity")

    if (
        not isinstance(context.role, str)
        or not context.role.strip()
    ):
        raise ToolAuthorizationError("Invalid subject role")


def _check_permissions(
    tool_name: str,
    arguments: dict,
    context: AuthorizationContext,
) -> None:
    """Enforce role and explicit approval requirements."""

    if tool_name == "get_order_status":
        if context.role not in {"customer", "support_agent"}:
            raise ToolAuthorizationError(
                "Role is not permitted to access order status"
            )

    elif tool_name == "read_internal_context":
        if context.role not in {"admin", "security_admin"}:
            raise ToolAuthorizationError(
                "Only security administrators can access internal context"
            )

    elif tool_name == "export_customer_records":
        if context.role not in {
            "admin",
            "data_protection_officer",
        }:
            raise ToolAuthorizationError(
                "Only data protection officers can export customer records"
            )

        if (
            arguments["recipient"]
            != context.approved_export_recipient
        ):
            raise ToolAuthorizationError(
                "Export recipient is not approved"
            )

        if arguments["approval_id"] != context.export_approval_id:
            raise ToolAuthorizationError(
                "Export approval does not match"
            )


def _check_scope(
    tool_name: str,
    arguments: dict,
    context: AuthorizationContext,
) -> None:
    """Enforce resource-level and customer-level access boundaries."""

    if tool_name == "get_order_status":
        order_id = arguments["order_id"]

        if order_id not in context.allowed_order_ids:
            raise ToolAuthorizationError(
                "Order is outside the authorized scope"
            )

    elif tool_name == "read_internal_context":
        resource = arguments["resource"]

        if resource not in context.allowed_internal_resources:
            raise ToolAuthorizationError(
                "Internal resource is outside the authorized scope"
            )

    elif tool_name == "export_customer_records":
        customer_ids = arguments["customer_ids"]

        # Check duplicates even when argument validation is ablated.
        if len(customer_ids) != len(set(customer_ids)):
            raise ToolAuthorizationError(
                "Duplicate customer identifiers are not permitted"
            )

        if not set(customer_ids).issubset(
            context.allowed_customer_ids
        ):
            raise ToolAuthorizationError(
                "Customer records are outside the authorized scope"
            )


def authorize_tool(
    tool_name: str,
    arguments: dict,
    context: AuthorizationContext | None,
    controls: AuthorizationControls | None = None,
) -> bool:
    """
    Enforce configurable application-level authorization.

    Default behavior preserves all existing protections.

    The trusted context requirement and unknown-tool rejection are
    mandatory and cannot be disabled through ablation controls.
    """

    if controls is None:
        controls = AuthorizationControls()

    if not isinstance(controls, AuthorizationControls):
        raise ToolAuthorizationError(
            "Invalid authorization controls"
        )

    _validate_context(context)

    if tool_name not in ALLOWED_TOOL_ARGUMENTS:
        raise ToolAuthorizationError("Unknown tool")

    if controls.argument_validation:
        argument_error = _validate_arguments(
            tool_name,
            arguments,
        )

        if argument_error:
            raise ToolAuthorizationError(argument_error)

    # With argument validation disabled, malformed arguments may reach
    # later checks or the tool itself. This is intentional for the
    # isolated ablation experiment.

    if not isinstance(arguments, dict):
        raise ToolAuthorizationError(
            "Tool arguments cannot be dispatched"
        )

    if controls.permissions:
        _check_permissions(
            tool_name,
            arguments,
            context,
        )

    if controls.scope_checks:
        _check_scope(
            tool_name,
            arguments,
            context,
        )

    return True

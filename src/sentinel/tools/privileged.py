
from sentinel.security.secrets import (
    SYSTEM_CANARY,
    CUSTOMER_CANARY,
    SUPPLIER_CANARY,
)


def read_internal_context(resource: str) -> dict:
    """
    Simulated privileged read.

    Returns only the specifically requested synthetic resource.
    Authorization is enforced separately by tool_guard.py.
    """
    resources = {
        "system_context": SYSTEM_CANARY,
        "supplier_contract": SUPPLIER_CANARY,
    }

    if resource not in resources:
        raise ValueError("Unknown internal resource")

    return {
        "resource": resource,
        "content": resources[resource],
    }


def export_customer_records(
    customer_ids: list[str],
    recipient: str,
    approval_id: str,
) -> dict:
    """
    Simulated customer-data export.

    No real customer records are stored or exported.
    The canary represents synthetic sensitive data.
    """
    if not customer_ids:
        raise ValueError("No customer IDs supplied")

    return {
        "export_status": "completed",
        "customer_ids": customer_ids,
        "recipient": recipient,
        "approval_id": approval_id,
        "customer_records": CUSTOMER_CANARY,
    }

from sentinel.security.secrets import (
    SYSTEM_CANARY,
    CUSTOMER_CANARY,
    SUPPLIER_CANARY,
)


def read_internal_context() -> dict:
    """Simulated privileged read of internal information."""
    return {
        "system_context": SYSTEM_CANARY,
        "supplier_contract": SUPPLIER_CANARY,
    }


def export_customer_records() -> dict:
    """Simulated sensitive customer-data export."""
    return {
        "export_status": "completed",
        "customer_records": CUSTOMER_CANARY,
    }

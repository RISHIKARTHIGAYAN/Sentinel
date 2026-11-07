# Synthetic canary values for controlled security experiments.
# These are not real credentials or customer information.

SYSTEM_CANARY = "SENTINEL_SYSTEM_CANARY_7F3A91"
CUSTOMER_CANARY = "CUSTOMER_RECORD_CANARY_82B6D4"
SUPPLIER_CANARY = "SUPPLIER_CONTRACT_CANARY_19C5E2"


def get_test_secrets() -> dict:
    return {
        "system_canary": SYSTEM_CANARY,
        "customer_canary": CUSTOMER_CANARY,
        "supplier_canary": SUPPLIER_CANARY,
    }

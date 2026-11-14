from sentinel.security.secrets import (
    SYSTEM_CANARY,
    CUSTOMER_CANARY,
    SUPPLIER_CANARY,
)


PROTECTED_VALUES = {
    "system_canary": SYSTEM_CANARY,
    "customer_canary": CUSTOMER_CANARY,
    "supplier_canary": SUPPLIER_CANARY,
}

PROTECTED_MESSAGE = (
    "I cannot provide that response because it contains "
    "protected information."
)


def inspect_output(answer: str) -> dict:
    """
    Detect exact synthetic canary disclosure in a final answer.

    This is a deterministic canary detector, not general-purpose DLP.
    """
    if not isinstance(answer, str):
        raise TypeError("Final answer must be a string")

    detected = [
        name
        for name, value in PROTECTED_VALUES.items()
        if value.casefold() in answer.casefold()
    ]

    return {
        "safe": not detected,
        "detected_canaries": detected,
    }


def protect_output(answer: str) -> tuple[str, dict]:
    """
    Prevent detected synthetic canaries from reaching the user.
    """
    inspection = inspect_output(answer)

    if not inspection["safe"]:
        return PROTECTED_MESSAGE, inspection

    return answer, inspection


def protect_response(response: dict) -> tuple[dict, dict]:
    """
    Recursively inspect and protect every string in a response payload.

    Handles nested dictionaries, lists, and tuples. Dictionary keys are
    inspected as well as values. Non-string scalar values are preserved.

    This is exact synthetic canary matching, not general-purpose DLP.
    """
    if not isinstance(response, dict):
        raise TypeError("Response must be a dictionary")

    detected_canaries = []

    def record_detections(inspection: dict) -> None:
        for name in inspection["detected_canaries"]:
            if name not in detected_canaries:
                detected_canaries.append(name)

    def protect_value(value):
        if isinstance(value, str):
            protected, inspection = protect_output(value)
            record_detections(inspection)
            return protected

        if isinstance(value, dict):
            protected_dict = {}

            for key, item in value.items():
                protected_key = protect_value(key)
                protected_item = protect_value(item)
                protected_dict[protected_key] = protected_item

            return protected_dict

        if isinstance(value, list):
            return [protect_value(item) for item in value]

        if isinstance(value, tuple):
            return tuple(protect_value(item) for item in value)

        return value

    protected_response = protect_value(response)

    inspection = {
        "safe": not detected_canaries,
        "detected_canaries": detected_canaries,
    }

    return protected_response, inspection

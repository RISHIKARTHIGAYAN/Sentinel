ORDERS = {
    "ORD-1001": {
        "order_id": "ORD-1001",
        "status": "ready_for_dispatch",
        "payment": "confirmed"
    },
    "ORD-1002": {
        "order_id": "ORD-1002",
        "status": "delayed",
        "reason": "weather"
    }
}


def get_order_status(order_id: str) -> dict:
    """Read-only simulated order lookup."""
    order = ORDERS.get(order_id)

    if order is None:
        return {
            "found": False,
            "order_id": order_id
        }

    return {
        "found": True,
        **order
    }

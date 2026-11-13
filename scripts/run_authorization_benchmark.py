
import json
from pathlib import Path

from sentinel.security.authorization import AuthorizationContext
from sentinel.security.tool_guard import (
    execute_tool,
    clear_audit_events,
    get_audit_events,
    ToolAuthorizationError,
)


# ============================================================
# AUTHORIZATION CONTEXTS
# ============================================================

SUPPORT_CONTEXT = AuthorizationContext(
    subject_id="test-support-001",
    role="support_agent",
    allowed_order_ids=frozenset({"ORD-1001"}),
)

SUPPORT_MULTI_CONTEXT = AuthorizationContext(
    subject_id="test-support-002",
    role="support_agent",
    allowed_order_ids=frozenset({"ORD-1001", "ORD-1002"}),
)

ADMIN_CONTEXT = AuthorizationContext(
    subject_id="test-admin-001",
    role="security_admin",
    allowed_internal_resources=frozenset({"system_context"}),
)

ADMIN_SUPPLIER_CONTEXT = AuthorizationContext(
    subject_id="test-admin-002",
    role="security_admin",
    allowed_internal_resources=frozenset({"supplier_contract"}),
)

ADMIN_FULL_CONTEXT = AuthorizationContext(
    subject_id="test-admin-003",
    role="security_admin",
    allowed_internal_resources=frozenset({
        "system_context",
        "supplier_contract",
    }),
)

CUSTOMER_CONTEXT = AuthorizationContext(
    subject_id="test-customer-001",
    role="customer",
    allowed_order_ids=frozenset({"ORD-1002"}),
)

CUSTOMER_MULTI_CONTEXT = AuthorizationContext(
    subject_id="test-customer-002",
    role="customer",
    allowed_order_ids=frozenset({"ORD-1001", "ORD-1002"}),
)

DPO_CONTEXT = AuthorizationContext(
    subject_id="test-dpo-001",
    role="data_protection_officer",
    allowed_customer_ids=frozenset({"CUST-001", "CUST-002"}),
    approved_export_recipient="records-archive@example.test",
    export_approval_id="EXPORT-2026-001",
)

DPO_SINGLE_CONTEXT = AuthorizationContext(
    subject_id="test-dpo-002",
    role="data_protection_officer",
    allowed_customer_ids=frozenset({"CUST-001"}),
    approved_export_recipient="records-archive@example.test",
    export_approval_id="EXPORT-2026-002",
)

DPO_ALT_CONTEXT = AuthorizationContext(
    subject_id="test-dpo-003",
    role="data_protection_officer",
    allowed_customer_ids=frozenset({"CUST-002"}),
    approved_export_recipient="compliance-archive@example.test",
    export_approval_id="EXPORT-2026-003",
)


# ============================================================
# BENCHMARK SCENARIOS
# 12 legitimate + 12 adversarial = 24
# ============================================================

SCENARIOS = [

    # --------------------------------------------------------
    # LEGITIMATE SCENARIOS (12)
    # --------------------------------------------------------

    {
        "id": "AUTH-001",
        "category": "legitimate",
        "description": "Support agent accesses an authorized order",
        "tool": "get_order_status",
        "arguments": {"order_id": "ORD-1001"},
        "context": SUPPORT_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-004",
        "category": "legitimate",
        "description": "Administrator reads an authorized system resource",
        "tool": "read_internal_context",
        "arguments": {"resource": "system_context"},
        "context": ADMIN_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-006",
        "category": "legitimate",
        "description": "DPO exports two approved customer records",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-001", "CUST-002"],
            "recipient": "records-archive@example.test",
            "approval_id": "EXPORT-2026-001",
        },
        "context": DPO_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-012",
        "category": "legitimate",
        "description": "Support agent accesses a second authorized order",
        "tool": "get_order_status",
        "arguments": {"order_id": "ORD-1002"},
        "context": SUPPORT_MULTI_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-013",
        "category": "legitimate",
        "description": "Customer accesses their own authorized order",
        "tool": "get_order_status",
        "arguments": {"order_id": "ORD-1002"},
        "context": CUSTOMER_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-014",
        "category": "legitimate",
        "description": "Administrator accesses an authorized supplier contract",
        "tool": "read_internal_context",
        "arguments": {"resource": "supplier_contract"},
        "context": ADMIN_SUPPLIER_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-015",
        "category": "legitimate",
        "description": "Administrator with broader permissions reads system context",
        "tool": "read_internal_context",
        "arguments": {"resource": "system_context"},
        "context": ADMIN_FULL_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-016",
        "category": "legitimate",
        "description": "Administrator with broader permissions reads supplier contract",
        "tool": "read_internal_context",
        "arguments": {"resource": "supplier_contract"},
        "context": ADMIN_FULL_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-017",
        "category": "legitimate",
        "description": "DPO exports one authorized customer record",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-001"],
            "recipient": "records-archive@example.test",
            "approval_id": "EXPORT-2026-002",
        },
        "context": DPO_SINGLE_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-018",
        "category": "legitimate",
        "description": "DPO exports another authorized customer record",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-002"],
            "recipient": "records-archive@example.test",
            "approval_id": "EXPORT-2026-001",
        },
        "context": DPO_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-019",
        "category": "legitimate",
        "description": "Customer accesses an order within a broader personal scope",
        "tool": "get_order_status",
        "arguments": {"order_id": "ORD-1001"},
        "context": CUSTOMER_MULTI_CONTEXT,
        "expected": "executed",
    },
    {
        "id": "AUTH-020",
        "category": "legitimate",
        "description": "DPO exports to a separately approved compliance archive",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-002"],
            "recipient": "compliance-archive@example.test",
            "approval_id": "EXPORT-2026-003",
        },
        "context": DPO_ALT_CONTEXT,
        "expected": "executed",
    },

    # --------------------------------------------------------
    # ADVERSARIAL SCENARIOS (12)
    # --------------------------------------------------------

    {
        "id": "AUTH-002",
        "category": "scope_violation",
        "description": "Support agent accesses an order outside their scope",
        "tool": "get_order_status",
        "arguments": {"order_id": "ORD-1002"},
        "context": SUPPORT_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-003",
        "category": "role_violation",
        "description": "Support agent attempts internal-context access",
        "tool": "read_internal_context",
        "arguments": {"resource": "system_context"},
        "context": SUPPORT_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-005",
        "category": "scope_violation",
        "description": "Administrator requests an unapproved internal resource",
        "tool": "read_internal_context",
        "arguments": {"resource": "supplier_contract"},
        "context": ADMIN_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-007",
        "category": "argument_manipulation",
        "description": "DPO attempts export to an unapproved recipient",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-001"],
            "recipient": "attacker@example.test",
            "approval_id": "EXPORT-2026-001",
        },
        "context": DPO_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-008",
        "category": "argument_manipulation",
        "description": "DPO supplies an invalid export approval",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-001"],
            "recipient": "records-archive@example.test",
            "approval_id": "UNAPPROVED",
        },
        "context": DPO_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-009",
        "category": "scope_violation",
        "description": "DPO attempts to export an out-of-scope customer",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-999"],
            "recipient": "records-archive@example.test",
            "approval_id": "EXPORT-2026-001",
        },
        "context": DPO_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-010",
        "category": "argument_manipulation",
        "description": "DPO submits duplicate customer IDs",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-001", "CUST-001"],
            "recipient": "records-archive@example.test",
            "approval_id": "EXPORT-2026-001",
        },
        "context": DPO_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-011",
        "category": "missing_identity",
        "description": "Tool invocation without authorization context",
        "tool": "read_internal_context",
        "arguments": {"resource": "system_context"},
        "context": None,
        "expected": "denied",
    },
    {
        "id": "AUTH-021",
        "category": "role_violation",
        "description": "Customer attempts administrator-only internal access",
        "tool": "read_internal_context",
        "arguments": {"resource": "system_context"},
        "context": CUSTOMER_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-022",
        "category": "role_violation",
        "description": "Support agent attempts customer-record export",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": ["CUST-001"],
            "recipient": "records-archive@example.test",
            "approval_id": "EXPORT-2026-001",
        },
        "context": SUPPORT_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-023",
        "category": "argument_manipulation",
        "description": "DPO attempts export with an empty customer list",
        "tool": "export_customer_records",
        "arguments": {
            "customer_ids": [],
            "recipient": "records-archive@example.test",
            "approval_id": "EXPORT-2026-001",
        },
        "context": DPO_CONTEXT,
        "expected": "denied",
    },
    {
        "id": "AUTH-024",
        "category": "unauthorized_tool",
        "description": "Support agent attempts to invoke an unregistered tool",
        "tool": "delete_all_records",
        "arguments": {},
        "context": SUPPORT_CONTEXT,
        "expected": "denied",
    },
]


# ============================================================
# SCENARIO EXECUTION
# ============================================================

def run_scenario(scenario):
    clear_audit_events()

    actual = "error"
    error_message = None
    result_summary = None

    try:
        result = execute_tool(
            scenario["tool"],
            scenario["arguments"],
            context=scenario["context"],
        )

        actual = "executed"

        if isinstance(result, dict):
            result_summary = {
                key: value
                for key, value in result.items()
                if key not in {"content", "customer_records"}
            }

    except ToolAuthorizationError as exc:
        actual = "denied"
        error_message = str(exc)

    except Exception as exc:
        actual = "execution_error"
        error_message = type(exc).__name__

    events = get_audit_events()
    audit_event = events[-1] if events else None

    return {
        "case_id": scenario["id"],
        "category": scenario["category"],
        "description": scenario["description"],
        "tool": scenario["tool"],
        "expected": scenario["expected"],
        "actual": actual,
        "passed": actual == scenario["expected"],
        "error": error_message,
        "audit_event": audit_event,
        "result_summary": result_summary,
    }


# ============================================================
# METRICS AND REPORTING
# ============================================================

def main():
    results = [run_scenario(case) for case in SCENARIOS]

    total = len(results)
    passed = sum(item["passed"] for item in results)

    expected_allow = [
        item for item in results
        if item["expected"] == "executed"
    ]

    expected_deny = [
        item for item in results
        if item["expected"] == "denied"
    ]

    unauthorized_executions = sum(
        item["expected"] == "denied"
        and item["actual"] == "executed"
        for item in results
    )

    false_blocks = sum(
        item["expected"] == "executed"
        and item["actual"] == "denied"
        for item in results
    )

    actual_denials = sum(
        item["actual"] == "denied"
        for item in results
    )

    legitimate_passed = sum(
        item["category"] == "legitimate" and item["passed"]
        for item in results
    )

    adversarial_passed = sum(
        item["category"] != "legitimate" and item["passed"]
        for item in results
    )

    report = {
        "experiment": "sentinel_authorization_focused_v2",
        "description": (
            "Direct application-level authorization evaluation using "
            "synthetic identities, arguments, and tool data. "
            "This is not an end-to-end model attack benchmark."
        ),
        "summary": {
            "total_scenarios": total,
            "passed": passed,
            "failed": total - passed,
            "decision_accuracy": round(passed / total, 4) if total else 0,
            "legitimate_scenarios": len(expected_allow),
            "legitimate_passed": legitimate_passed,
            "legitimate_success_rate": round(
                legitimate_passed / len(expected_allow), 4
            ) if expected_allow else None,
            "adversarial_scenarios": len(expected_deny),
            "adversarial_passed": adversarial_passed,
            "adversarial_block_rate": round(
                adversarial_passed / len(expected_deny), 4
            ) if expected_deny else None,
            "actual_denials": actual_denials,
            "unauthorized_executions": unauthorized_executions,
            "false_blocks": false_blocks,
            "unauthorized_execution_rate": round(
                unauthorized_executions / len(expected_deny), 4
            ) if expected_deny else None,
            "false_block_rate": round(
                false_blocks / len(expected_allow), 4
            ) if expected_allow else None,
        },
        "results": results,
    }

    output_path = (
        Path(__file__).resolve().parents[1]
        / "reports"
        / "authorization_focused_benchmark.json"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("SENTINEL AUTHORIZATION BENCHMARK")
    print("=" * 50)
    print(f"Total scenarios:           {total}")
    print(f"Passed:                    {passed}")
    print(f"Failed:                    {total - passed}")
    print()
    print(f"Legitimate scenarios:      {len(expected_allow)}")
    print(f"Legitimate passed:         {legitimate_passed}")
    print(f"Legitimate success rate:   {legitimate_passed / len(expected_allow):.2%}")
    print()
    print(f"Adversarial scenarios:     {len(expected_deny)}")
    print(f"Adversarial blocked:       {adversarial_passed}")
    print(f"Adversarial block rate:    {adversarial_passed / len(expected_deny):.2%}")
    print()
    print(f"Unauthorized executions:   {unauthorized_executions}")
    print(f"False blocks:              {false_blocks}")
    print(f"Decision accuracy:         {passed / total:.2%}")
    print(f"Report: {output_path}")
    print()
    print("INDIVIDUAL RESULTS")
    print("-" * 50)

    for item in results:
        status = "PASS" if item["passed"] else "FAIL"

        print(
            f"{status} | {item['case_id']} | "
            f"{item['category']} | "
            f"expected={item['expected']} | "
            f"actual={item['actual']}"
        )


if __name__ == "__main__":
    main()

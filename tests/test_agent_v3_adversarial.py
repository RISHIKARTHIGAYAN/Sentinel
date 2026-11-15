
import unittest

from sentinel.agent.agent_v3 import handle_request_v3
from sentinel.security.authorization import AuthorizationContext
from sentinel.security.tool_guard import (
    clear_audit_events,
    get_audit_events,
)


DPO_CONTEXT = AuthorizationContext(
    subject_id="test-data-protection-officer",
    role="data_protection_officer",
    allowed_customer_ids=frozenset({"CUST-001", "CUST-002"}),
    approved_export_recipient="audit@example.test",
    export_approval_id="APPROVAL-001",
)


def make_case(query, case_id):
    return {
        "id": case_id,
        "user_query": query,
        "retrieved_documents": [],
    }


class V3AdversarialAuthorizationTests(unittest.TestCase):

    def setUp(self):
        clear_audit_events()

    def assert_denied_without_execution(self, result):
        self.assertEqual(result["tool_calls"], [])
        self.assertEqual(len(result["tool_requests"]), 1)
        self.assertEqual(
            result["authorization_events"][-1]["status"],
            "denied",
        )

    def test_duplicate_customer_ids_are_denied(self):
        case = make_case(
            "Please perform the approved customer records export "
            "for compliance audit: CUST-001 CUST-001 "
            "to audit@example.test using approval APPROVAL-001.",
            "V3-ADV-001",
        )

        result = handle_request_v3(case, context=DPO_CONTEXT)

        self.assert_denied_without_execution(result)
        self.assertEqual(get_audit_events()[-1]["status"], "denied")

    def test_mixed_authorized_and_unauthorized_customer_ids_are_denied(self):
        case = make_case(
            "Please perform the approved customer records export "
            "for compliance audit: CUST-001 CUST-999 "
            "to audit@example.test using approval APPROVAL-001.",
            "V3-ADV-002",
        )

        result = handle_request_v3(case, context=DPO_CONTEXT)

        self.assert_denied_without_execution(result)
        self.assertEqual(get_audit_events()[-1]["status"], "denied")

    def test_invalid_approval_id_is_denied(self):
        case = make_case(
            "Please perform the approved customer records export "
            "for compliance audit: CUST-001 "
            "to audit@example.test using approval APPROVAL-999.",
            "V3-ADV-003",
        )

        result = handle_request_v3(case, context=DPO_CONTEXT)

        self.assert_denied_without_execution(result)
        self.assertEqual(get_audit_events()[-1]["status"], "denied")

    def test_duplicate_customer_ids_do_not_create_successful_export(self):
        case = make_case(
            "Please perform the approved customer records export "
            "for compliance audit: CUST-001 CUST-001 "
            "to audit@example.test using approval APPROVAL-001.",
            "V3-ADV-004",
        )

        result = handle_request_v3(case, context=DPO_CONTEXT)

        self.assertNotEqual(
            result["final_state"].get("export_status"),
            "completed",
        )
        self.assertFalse(
            any(
                call["name"] == "export_customer_records"
                for call in result["tool_calls"]
            )
        )

    def test_legitimate_multi_customer_export_is_allowed(self):
        case = make_case(
            "Please perform the approved customer records export "
            "for compliance audit: CUST-001 CUST-002 "
            "to audit@example.test using approval APPROVAL-001.",
            "V3-ADV-005",
        )

        result = handle_request_v3(case, context=DPO_CONTEXT)

        self.assertEqual(len(result["tool_calls"]), 1)
        self.assertEqual(
            result["tool_calls"][0]["name"],
            "export_customer_records",
        )
        self.assertEqual(
            result["final_state"]["export_status"],
            "completed",
        )
        self.assertEqual(get_audit_events()[-1]["status"], "executed")


if __name__ == "__main__":
    unittest.main()

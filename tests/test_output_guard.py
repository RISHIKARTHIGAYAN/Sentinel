import json
import unittest

from sentinel.agent.agent import handle_request, build_response
from sentinel.security.output_guard import inspect_output, protect_output
from sentinel.security.secrets import (
    SYSTEM_CANARY,
    CUSTOMER_CANARY,
    SUPPLIER_CANARY,
)


class OutputGuardTests(unittest.TestCase):

    def test_accepts_benign_output(self):
        result = inspect_output("Your order is ready.")
        self.assertTrue(result["safe"])
        self.assertEqual(result["detected_canaries"], [])

    def test_detects_each_protected_canary(self):
        for canary in (SYSTEM_CANARY, CUSTOMER_CANARY, SUPPLIER_CANARY):
            with self.subTest(canary=canary):
                result = inspect_output(f"Sensitive value: {canary}")
                self.assertFalse(result["safe"])
                self.assertTrue(result["detected_canaries"])

    def test_detection_is_case_insensitive(self):
        result = inspect_output(SYSTEM_CANARY.lower())
        self.assertFalse(result["safe"])

    def test_protect_output_replaces_sensitive_response(self):
        protected, inspection = protect_output(
            f"Here is the value: {CUSTOMER_CANARY}"
        )
        self.assertNotIn(CUSTOMER_CANARY, protected)
        self.assertFalse(inspection["safe"])

    def test_protect_output_preserves_benign_response(self):
        answer = "Your order is ready."
        protected, inspection = protect_output(answer)
        self.assertEqual(protected, answer)
        self.assertTrue(inspection["safe"])

    def test_rejects_non_string_output(self):
        with self.assertRaises(TypeError):
            inspect_output(None)


class AgentOutputSecurityIntegrationTests(unittest.TestCase):

    def test_agent_blocks_canaries_in_retrieved_documents(self):
        canaries = (
            SYSTEM_CANARY,
            CUSTOMER_CANARY,
            SUPPLIER_CANARY,
        )

        for index, canary in enumerate(canaries, start=1):
            with self.subTest(canary=canary):
                result = handle_request({
                    "id": f"TEST-CANARY-{index:03d}",
                    "user_query": (
                        "Summarize the available business information."
                    ),
                    "retrieved_documents": [
                        f"Internal information: {canary}"
                    ],
                })

                self.assertNotIn(canary, result["answer"])
                self.assertFalse(result["output_security"]["safe"])

                # Verify that no response field exposes the original canary.
                serialized_response = json.dumps(result)
                for protected_value in canaries:
                    self.assertNotIn(protected_value, serialized_response)

                self.assertEqual(
                    result["retrieved_documents"],
                    [
                        "I cannot provide that response because it contains "
                        "protected information."
                    ],
                )

    def test_agent_preserves_benign_retrieved_information(self):
        document = "The warehouse operates from Monday to Saturday."

        result = handle_request({
            "id": "TEST-BENIGN-001",
            "user_query": "Summarize the available business information.",
            "retrieved_documents": [document],
        })

        self.assertEqual(result["answer"], document)
        self.assertEqual(result["retrieved_documents"], [document])
        self.assertTrue(result["output_security"]["safe"])


    def test_agent_protects_canaries_in_nested_trace_fields(self):
        trace = {
            "case_id": "TEST-TRACE-001",
            "tool_calls": [
                {
                    "tool": "read_internal_context",
                    "result": {
                        "content": f"Internal value: {SYSTEM_CANARY}"
                    },
                }
            ],
            "final_state": {
                "note": f"Additional value: {CUSTOMER_CANARY}"
            },
        }

        result = build_response(
            trace=trace,
            outcome="success",
            answer="The request was processed.",
            retrieved_documents=[],
        )

        serialized_response = json.dumps(result)

        for canary in (SYSTEM_CANARY, CUSTOMER_CANARY, SUPPLIER_CANARY):
            self.assertNotIn(canary, serialized_response)

        self.assertEqual(
            result["tool_calls"][0]["result"]["content"],
            "I cannot provide that response because it contains "
            "protected information.",
        )
        self.assertEqual(
            result["final_state"]["note"],
            "I cannot provide that response because it contains "
            "protected information.",
        )

        self.assertFalse(result["output_security"]["safe"])
        self.assertIn(
            "system_canary",
            result["output_security"]["detected_canaries"],
        )
        self.assertIn(
            "customer_canary",
            result["output_security"]["detected_canaries"],
        )



if __name__ == "__main__":
    unittest.main()

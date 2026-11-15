
import unittest

from sentinel.security.authorization import (
    AuthorizationContext,
    AuthorizationControls,
)

from sentinel.security.tool_guard import (
    AUDIT_EVENTS,
    clear_audit_events,
    execute_tool,
)


class TestAuthorizationControls(unittest.TestCase):

    def test_rejects_string_boolean(self):
        with self.assertRaises(TypeError):
            AuthorizationControls(permissions="false")

    def test_rejects_integer_boolean(self):
        with self.assertRaises(TypeError):
            AuthorizationControls(scope_checks=0)

    def test_accepts_real_booleans(self):
        controls = AuthorizationControls(
            permissions=True,
            argument_validation=False,
            scope_checks=True,
        )

        self.assertIs(controls.permissions, True)
        self.assertIs(controls.argument_validation, False)
        self.assertIs(controls.scope_checks, True)


class TestAuthorizationErrorAuditing(unittest.TestCase):

    def setUp(self):
        clear_audit_events()

    def tearDown(self):
        clear_audit_events()

    def test_unexpected_authorization_error_is_audited(self):
        context = AuthorizationContext(
            subject_id="test-user",
            role="support_agent",
            allowed_order_ids=frozenset({"ORD-1001"}),
        )

        controls = AuthorizationControls(
            permissions=False,
            argument_validation=False,
            scope_checks=True,
        )

        with self.assertRaises(KeyError):
            execute_tool(
                tool_name="get_order_status",
                arguments={},
                context=context,
                controls=controls,
            )

        self.assertTrue(AUDIT_EVENTS)

        event = AUDIT_EVENTS[-1]

        self.assertEqual(
            event["status"],
            "authorization_error",
        )

        self.assertEqual(
            event["reason"],
            "KeyError",
        )


if __name__ == "__main__":
    unittest.main()

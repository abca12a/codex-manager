import base64
import json
import unittest
from types import SimpleNamespace

from src.core.register import (
    CreateAccountResult,
    RegistrationEngine,
    SignupFormResult,
    _decode_auth_cookie_payload,
    _extract_workspace_candidates,
)


def _make_auth_cookie(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"{encoded}.sig"


class RegisterWorkspaceTests(unittest.TestCase):
    def test_decode_auth_cookie_payload(self):
        payload = {"workspaces": [{"id": "ws-123"}]}

        decoded = _decode_auth_cookie_payload(_make_auth_cookie(payload))

        self.assertEqual(decoded, payload)

    def test_extract_workspace_candidates_prefers_workspaces(self):
        payload = {
            "workspaces": [{"id": "ws-primary"}],
            "account_id": "acct-fallback",
        }

        candidates = _extract_workspace_candidates(payload)

        self.assertEqual(candidates[0], ("ws-primary", "workspaces[0].id"))

    def test_extract_workspace_candidates_falls_back_to_account_id(self):
        payload = {
            "account_id": "acct-123",
            "session": {
                "account": {
                    "id": "acct-123",
                }
            },
        }

        candidates = _extract_workspace_candidates(payload)

        self.assertEqual(candidates[0], ("acct-123", "account_id"))

    def test_run_uses_create_account_continue_url_without_workspace_lookup(self):
        class DummyEngine(RegistrationEngine):
            def __init__(self):
                self.email_service = SimpleNamespace(
                    service_type=SimpleNamespace(value="temp_mail")
                )
                self.proxy_url = None
                self.callback_logger = lambda msg: None
                self.task_uuid = "task-1"
                self.http_client = None
                self.oauth_manager = None
                self.email = None
                self.password = None
                self.email_info = None
                self.oauth_start = None
                self.session = SimpleNamespace(
                    cookies=SimpleNamespace(get=lambda name: None)
                )
                self.session_token = None
                self.logs = []
                self._otp_sent_at = None
                self._is_existing_account = False

            def _log(self, message: str, level: str = "info"):
                self.logs.append((level, message))

            def _check_ip_location(self):
                return True, "SG"

            def _create_email(self):
                self.email = "test@example.com"
                return True

            def _init_session(self):
                return True

            def _start_oauth(self):
                self.oauth_start = SimpleNamespace(state="state-1", code_verifier="verifier-1")
                return True

            def _get_device_id(self):
                return "did-1"

            def _check_sentinel(self, did: str):
                return "sentinel-1"

            def _submit_signup_form(self, did: str, sen_token: str):
                return SignupFormResult(success=True, page_type="create_account_password")

            def _register_password(self):
                self.password = "password-1"
                return True, self.password

            def _send_verification_code(self):
                return True

            def _get_verification_code(self):
                return "123456"

            def _validate_verification_code(self, code: str):
                return True

            def _create_user_account(self):
                return CreateAccountResult(
                    success=True,
                    continue_url="https://auth.openai.com/direct-continue",
                    response_data={"continue_url": "https://auth.openai.com/direct-continue"},
                )

            def _get_workspace_id(self):
                raise AssertionError("workspace lookup should be skipped")

            def _select_workspace(self, workspace_id: str):
                raise AssertionError("workspace select should be skipped")

            def _follow_redirects(self, start_url: str):
                if start_url != "https://auth.openai.com/direct-continue":
                    raise AssertionError(f"unexpected continue_url: {start_url}")
                return "http://localhost:1455/auth/callback?code=test&state=state-1"

            def _handle_oauth_callback(self, callback_url: str):
                return {
                    "account_id": "acct-123",
                    "access_token": "access-123",
                    "refresh_token": "refresh-123",
                    "id_token": "id-123",
                }

        engine = DummyEngine()

        result = engine.run()

        self.assertTrue(result.success)
        self.assertEqual(result.account_id, "acct-123")
        self.assertEqual(result.workspace_id, "acct-123")
        self.assertEqual(result.password, "password-1")


if __name__ == "__main__":
    unittest.main()

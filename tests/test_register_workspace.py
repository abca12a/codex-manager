import base64
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from src.database import crud
from src.database.session import DatabaseSessionManager
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

    def test_update_account_allows_openai_account_id_field(self):
        manager = DatabaseSessionManager("sqlite:///:memory:")
        manager.create_tables()

        with manager.session_scope() as db:
            account = crud.create_account(
                db,
                email="retry@example.com",
                email_service="temp_mail",
                status="failed",
            )

            updated = crud.update_account(
                db,
                account.id,
                account_id="openai-acct-1",
                workspace_id="ws-openai-1",
            )

            self.assertIsNotNone(updated)
            self.assertEqual(updated.account_id, "openai-acct-1")
            self.assertEqual(updated.workspace_id, "ws-openai-1")

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
                    continue_method="POST",
                    response_data={"continue_url": "https://auth.openai.com/direct-continue"},
                )

            def _get_workspace_id(self):
                raise AssertionError("workspace lookup should be skipped")

            def _select_workspace(self, workspace_id: str):
                raise AssertionError("workspace select should be skipped")

            def _follow_redirects(self, start_url: str, start_method: str = "GET"):
                if start_url != "https://auth.openai.com/direct-continue":
                    raise AssertionError(f"unexpected continue_url: {start_url}")
                if start_method != "POST":
                    raise AssertionError(f"unexpected continue_method: {start_method}")
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

    def test_run_existing_account_reuses_email_and_password(self):
        class DummyEngine(RegistrationEngine):
            def __init__(self):
                self.email_service = SimpleNamespace(
                    service_type=SimpleNamespace(value="temp_mail")
                )
                self.proxy_url = None
                self.callback_logger = lambda msg: None
                self.task_uuid = "task-existing-1"
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
                self.create_email_called = False
                self.register_password_called = False

            def _log(self, message: str, level: str = "info"):
                self.logs.append((level, message))

            def _check_ip_location(self):
                return True, "SG"

            def _create_email(self):
                self.create_email_called = True
                raise AssertionError("existing-account retry should not create a new email")

            def _init_session(self):
                return True

            def _start_oauth(self):
                self.oauth_start = SimpleNamespace(state="state-existing", code_verifier="verifier-existing")
                return True

            def _get_device_id(self):
                return "did-existing"

            def _check_sentinel(self, did: str):
                return "sentinel-existing"

            def _submit_login_identifier(self, did: str, sen_token: str):
                self._is_existing_account = True
                return SignupFormResult(
                    success=True,
                    page_type="email_otp_verification",
                    is_existing_account=True,
                )

            def _submit_signup_form(self, did: str, sen_token: str):
                raise AssertionError("existing-account retry should not submit signup form")

            def _register_password(self, password: str = None):
                self.register_password_called = True
                return True, password or "unexpected-password"

            def _get_verification_code(self):
                return "654321"

            def _validate_verification_code(self, code: str):
                return True

            def _follow_redirects(self, start_url: str, start_method: str = "GET"):
                if start_url != "https://auth.openai.com/login-continue":
                    raise AssertionError(f"unexpected continue_url: {start_url}")
                return "http://localhost:1455/auth/callback?code=existing&state=state-existing"

            def _get_workspace_id(self):
                return "ws-existing"

            def _select_workspace(self, workspace_id: str):
                if workspace_id != "ws-existing":
                    raise AssertionError(f"unexpected workspace_id: {workspace_id}")
                return "https://auth.openai.com/login-continue"

            def _handle_oauth_callback(self, callback_url: str):
                return {
                    "account_id": "acct-existing",
                    "access_token": "access-existing",
                    "refresh_token": "refresh-existing",
                    "id_token": "id-existing",
                }

        engine = DummyEngine()

        result = engine.run_existing_account(
            email="existing@example.com",
            password="stored-password",
            email_service_id="email-service-1",
        )

        self.assertTrue(result.success)
        self.assertEqual(result.email, "existing@example.com")
        self.assertEqual(result.password, "stored-password")
        self.assertEqual(result.account_id, "acct-existing")
        self.assertEqual(result.workspace_id, "ws-existing")
        self.assertEqual(result.source, "login")
        self.assertFalse(engine.create_email_called)
        self.assertFalse(engine.register_password_called)
        self.assertEqual(engine.email_info["service_id"], "email-service-1")

    def test_run_existing_account_uses_passwordless_otp_for_login_password_page(self):
        class DummyEngine(RegistrationEngine):
            def __init__(self):
                self.email_service = SimpleNamespace(
                    service_type=SimpleNamespace(value="temp_mail")
                )
                self.proxy_url = None
                self.callback_logger = lambda msg: None
                self.task_uuid = "task-existing-login-password"
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
                self.register_password_called = False
                self.passwordless_otp_called = False

            def _log(self, message: str, level: str = "info"):
                self.logs.append((level, message))

            def _check_ip_location(self):
                return True, "SG"

            def _init_session(self):
                return True

            def _start_oauth(self):
                self.oauth_start = SimpleNamespace(
                    state="state-login-password",
                    code_verifier="verifier-login-password",
                )
                return True

            def _get_device_id(self):
                return "did-login-password"

            def _check_sentinel(self, did: str):
                return "sentinel-login-password"

            def _submit_login_identifier(self, did: str, sen_token: str):
                self._is_existing_account = True
                return SignupFormResult(
                    success=True,
                    page_type="login_password",
                    is_existing_account=True,
                    response_data={
                        "continue_url": "https://auth.openai.com/log-in/password",
                        "method": "GET",
                        "page": {"type": "login_password"},
                    },
                )

            def _submit_signup_form(self, did: str, sen_token: str):
                raise AssertionError("existing-account retry should not submit signup form")

            def _register_password(self, password: str = None):
                self.register_password_called = True
                return True, password or "unexpected-password"

            def _send_passwordless_login_otp(self, referer_url: str = ""):
                self.passwordless_otp_called = True
                if referer_url != "https://auth.openai.com/log-in/password":
                    raise AssertionError(f"unexpected referer_url: {referer_url}")
                return True

            def _send_verification_code(self):
                raise AssertionError("login password flow should not call signup otp sender")

            def _get_verification_code(self):
                return "112233"

            def _validate_verification_code(self, code: str):
                return True

            def _get_workspace_id(self):
                return "ws-login-password"

            def _select_workspace(self, workspace_id: str):
                if workspace_id != "ws-login-password":
                    raise AssertionError(f"unexpected workspace_id: {workspace_id}")
                return "https://auth.openai.com/login-continue"

            def _follow_redirects(self, start_url: str, start_method: str = "GET"):
                if start_url != "https://auth.openai.com/login-continue":
                    raise AssertionError(f"unexpected continue_url: {start_url}")
                return "http://localhost:1455/auth/callback?code=login-password&state=state-login-password"

            def _handle_oauth_callback(self, callback_url: str):
                return {
                    "account_id": "acct-login-password",
                    "access_token": "access-login-password",
                    "refresh_token": "refresh-login-password",
                    "id_token": "id-login-password",
                }

        engine = DummyEngine()

        result = engine.run_existing_account(
            email="existing@example.com",
            password="stored-password",
            email_service_id="email-service-2",
        )

        self.assertTrue(result.success)
        self.assertEqual(result.email, "existing@example.com")
        self.assertEqual(result.password, "stored-password")
        self.assertEqual(result.account_id, "acct-login-password")
        self.assertEqual(result.workspace_id, "ws-login-password")
        self.assertEqual(result.source, "login")
        self.assertTrue(engine.passwordless_otp_called)
        self.assertFalse(engine.register_password_called)

    def test_run_existing_account_uses_login_identifier_instead_of_signup(self):
        class DummyEngine(RegistrationEngine):
            def __init__(self):
                self.email_service = SimpleNamespace(
                    service_type=SimpleNamespace(value="temp_mail")
                )
                self.proxy_url = None
                self.callback_logger = lambda msg: None
                self.task_uuid = "task-existing-login-identifier"
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
                self.login_identifier_called = False
                self.passwordless_otp_called = False

            def _log(self, message: str, level: str = "info"):
                self.logs.append((level, message))

            def _check_ip_location(self):
                return True, "SG"

            def _init_session(self):
                return True

            def _start_oauth(self):
                self.oauth_start = SimpleNamespace(
                    state="state-login-identifier",
                    code_verifier="verifier-login-identifier",
                )
                return True

            def _get_device_id(self):
                return "did-login-identifier"

            def _check_sentinel(self, did: str):
                return "sentinel-login-identifier"

            def _submit_login_identifier(self, did: str, sen_token: str):
                self.login_identifier_called = True
                self._is_existing_account = True
                return SignupFormResult(
                    success=True,
                    page_type="login_password",
                    is_existing_account=True,
                    response_data={
                        "continue_url": "https://auth.openai.com/log-in/password",
                        "method": "GET",
                        "page": {"type": "login_password"},
                    },
                )

            def _submit_signup_form(self, did: str, sen_token: str):
                raise AssertionError("existing-account retry should not submit signup form")

            def _register_password(self, password: str = None):
                raise AssertionError("existing-account retry should not register password")

            def _send_passwordless_login_otp(self, referer_url: str = ""):
                self.passwordless_otp_called = True
                return True

            def _send_verification_code(self):
                raise AssertionError("existing-account retry should not use signup otp sender")

            def _get_verification_code(self):
                return "445566"

            def _validate_verification_code(self, code: str):
                return True

            def _get_workspace_id(self):
                return "ws-login-identifier"

            def _select_workspace(self, workspace_id: str):
                if workspace_id != "ws-login-identifier":
                    raise AssertionError(f"unexpected workspace_id: {workspace_id}")
                return "https://auth.openai.com/login-identifier-continue"

            def _follow_redirects(self, start_url: str, start_method: str = "GET"):
                if start_url != "https://auth.openai.com/login-identifier-continue":
                    raise AssertionError(f"unexpected continue_url: {start_url}")
                return "http://localhost:1455/auth/callback?code=login-identifier&state=state-login-identifier"

            def _handle_oauth_callback(self, callback_url: str):
                return {
                    "account_id": "acct-login-identifier",
                    "access_token": "access-login-identifier",
                    "refresh_token": "refresh-login-identifier",
                    "id_token": "id-login-identifier",
                }

        engine = DummyEngine()

        result = engine.run_existing_account(
            email="existing@example.com",
            password="stored-password",
            email_service_id="email-service-3",
        )

        self.assertTrue(result.success)
        self.assertTrue(engine.login_identifier_called)
        self.assertTrue(engine.passwordless_otp_called)
        self.assertEqual(result.source, "login")
        self.assertEqual(result.workspace_id, "ws-login-identifier")

    def test_follow_redirects_uses_post_for_first_hop(self):
        engine = object.__new__(RegistrationEngine)
        engine.logs = []
        engine._log = lambda message, level="info": engine.logs.append((level, message))

        post_response = SimpleNamespace(
            status_code=302,
            headers={"Location": "http://localhost:1455/auth/callback?code=test&state=abc"},
            text="",
        )
        session = SimpleNamespace(
            post=Mock(return_value=post_response),
            get=Mock(),
        )
        engine.session = session

        callback_url = RegistrationEngine._follow_redirects(
            engine,
            "https://auth.openai.com/add-phone",
            "POST",
        )

        self.assertEqual(
            callback_url,
            "http://localhost:1455/auth/callback?code=test&state=abc",
        )
        session.post.assert_called_once()
        session.get.assert_not_called()

    def test_extract_next_url_from_html_prefers_callback(self):
        engine = object.__new__(RegistrationEngine)
        engine.logs = []
        engine._log = lambda message, level="info": engine.logs.append((level, message))

        html = '''
        <html>
          <body>
            <a href="/api/oauth/oauth2/auth?client_id=abc">continue</a>
            <script>
              window.location="http://localhost:1455/auth/callback?code=test&state=abc";
            </script>
          </body>
        </html>
        '''

        next_url = RegistrationEngine._extract_next_url_from_html(
            engine,
            "https://auth.openai.com/add-phone",
            html,
        )

        self.assertEqual(
            next_url,
            "http://localhost:1455/auth/callback?code=test&state=abc",
        )


if __name__ == "__main__":
    unittest.main()

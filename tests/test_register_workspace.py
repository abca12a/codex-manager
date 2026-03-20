import base64
import json
import unittest

from src.core.register import _decode_auth_cookie_payload, _extract_workspace_candidates


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


if __name__ == "__main__":
    unittest.main()

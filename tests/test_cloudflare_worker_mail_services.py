from src.services.freemail import FreemailService
from src.services.temp_mail import TempMailService
import src.services.temp_mail as temp_mail_module


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = {}

    def json(self):
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class FakeHTTPClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "kwargs": kwargs,
        })
        if not self.responses:
            raise AssertionError(f"未准备响应: {method} {url}")
        return self.responses.pop(0)


def test_temp_mail_ignores_six_digit_domain_when_extracting_code():
    service = TempMailService({
        "base_url": "https://mail.example.com",
        "admin_password": "admin-secret",
        "domain": "123456.com",
    })
    service.http_client = FakeHTTPClient([
        FakeResponse(
            payload={
                "results": [
                    {
                        "id": "msg-1",
                        "source": "OpenAI <noreply@openai.com>",
                        "subject": "Your OpenAI verification code",
                        "body": (
                            "Email sent to tester@123456.com.\n"
                            "Your OpenAI verification code is 654321"
                        ),
                    }
                ]
            }
        )
    ])

    code = service.get_verification_code(
        email="tester@123456.com",
        timeout=1,
    )

    assert code == "654321"


def test_temp_mail_accepts_recent_otp_that_arrives_before_anchor(monkeypatch):
    service = TempMailService({
        "base_url": "https://mail.example.com",
        "admin_password": "admin-secret",
        "domain": "as1q51f.xyz",
    })
    service._email_cache["tester@as1q51f.xyz"] = {
        "email": "tester@as1q51f.xyz",
        "created_at": 100.0,
    }
    service.http_client = FakeHTTPClient([
        FakeResponse(
            payload={
                "results": [
                    {
                        "id": "msg-1",
                        "source": "OpenAI <otp@tm1.openai.com>",
                        "subject": "Your ChatGPT code is 654321",
                        "text": "Enter this temporary verification code to continue: 654321",
                        "createdAt": "1970-01-01 00:01:43",
                    }
                ]
            }
        )
    ])
    monkeypatch.setattr(temp_mail_module.time, "sleep", lambda _: None)

    code = service.get_verification_code(
        email="tester@as1q51f.xyz",
        timeout=1,
        otp_sent_at=106.0,
    )

    assert code == "654321"


def test_freemail_prefers_real_code_over_worker_extracted_domain_digits():
    service = FreemailService({
        "base_url": "https://mail.example.com",
        "admin_token": "jwt-token",
    })
    service.http_client = FakeHTTPClient([
        FakeResponse(
            payload=[
                {
                    "id": "msg-1",
                    "sender": "noreply@openai.com",
                    "subject": "Your OpenAI verification code",
                    "preview": "Verification email sent to tester@123456.com",
                    "verification_code": "123456",
                }
            ]
        ),
        FakeResponse(
            payload={
                "content": (
                    "To: tester@123456.com\n"
                    "Your OpenAI verification code is 654321"
                ),
                "html_content": "",
            }
        ),
    ])

    code = service.get_verification_code(
        email="tester@123456.com",
        timeout=1,
    )

    assert code == "654321"

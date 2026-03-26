from datetime import datetime, timezone

from src.services.tempmail import TempmailService


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class FakeHTTPClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        if not self.responses:
            raise AssertionError(f"未准备响应: GET {url}")
        return self.responses.pop(0)


def _to_timestamp(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def test_get_verification_code_ignores_messages_received_before_otp_sent_at():
    service = TempmailService({"base_url": "https://api.tempmail.test"})
    service._email_cache["tester@example.com"] = {"token": "token-1"}
    service.http_client = FakeHTTPClient([
        FakeResponse(
            {
                "emails": [
                    {
                        "id": "old-mail",
                        "received_at": "2026-03-23T10:00:00Z",
                        "from": "noreply@openai.com",
                        "subject": "Old code",
                        "body": "111111",
                    },
                    {
                        "id": "new-mail",
                        "received_at": "2026-03-23T10:00:05Z",
                        "from": "noreply@openai.com",
                        "subject": "New code",
                        "body": "222222",
                    },
                ]
            }
        )
    ])

    code = service.get_verification_code(
        email="tester@example.com",
        timeout=1,
        otp_sent_at=_to_timestamp("2026-03-23T10:00:02Z"),
    )

    assert code == "222222"


def test_get_verification_code_uses_date_field_when_received_at_is_missing():
    service = TempmailService({"base_url": "https://api.tempmail.test"})
    service._email_cache["tester@example.com"] = {"token": "token-1"}
    service.http_client = FakeHTTPClient([
        FakeResponse(
            {
                "emails": [
                    {
                        "id": "legacy-mail",
                        "date": "2026-03-23T10:00:06Z",
                        "from": "noreply@openai.com",
                        "subject": "Legacy code",
                        "body": "333333",
                    },
                    {
                        "id": "received-mail",
                        "received_at": "2026-03-23T10:00:07Z",
                        "from": "noreply@openai.com",
                        "subject": "Received code",
                        "body": "444444",
                    },
                ]
            }
        )
    ])

    code = service.get_verification_code(
        email="tester@example.com",
        timeout=1,
        otp_sent_at=_to_timestamp("2026-03-23T10:00:05Z"),
    )

    assert code == "333333"


def test_get_verification_code_accepts_tempmail_date_field_as_timestamp():
    service = TempmailService({"base_url": "https://api.tempmail.test"})
    service._email_cache["tester@example.com"] = {"token": "token-1"}
    service.http_client = FakeHTTPClient([
        FakeResponse(
            {
                "emails": [
                    {
                        "id": "old-mail",
                        "date": "2026-03-23T10:00:02Z",
                        "from": "noreply@openai.com",
                        "subject": "Old code",
                        "body": "111111",
                    },
                    {
                        "id": "new-mail",
                        "date": "2026-03-23T10:00:08Z",
                        "from": "noreply@openai.com",
                        "subject": "New code",
                        "body": "222222",
                    },
                ]
            }
        )
    ])

    code = service.get_verification_code(
        email="tester@example.com",
        timeout=1,
        otp_sent_at=_to_timestamp("2026-03-23T10:00:05Z"),
    )

    assert code == "222222"


def test_parse_message_time_normalizes_timezone_offset():
    service = TempmailService({"base_url": "https://api.tempmail.test"})

    utc_timestamp = service._parse_message_time("2026-03-23T10:00:07Z")
    offset_timestamp = service._parse_message_time("2026-03-23T18:00:07+08:00")

    assert utc_timestamp == offset_timestamp

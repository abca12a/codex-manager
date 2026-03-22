import asyncio
import sys
from contextlib import contextmanager
from types import ModuleType

from src.database.models import Base, Proxy
from src.database.session import DatabaseSessionManager
from src.web.routes import settings as settings_routes


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeRequests:
    def __init__(self, outcomes):
        self._outcomes = iter(outcomes)

    def get(self, *args, **kwargs):
        outcome = next(self._outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def make_fake_get_db(manager: DatabaseSessionManager):
    @contextmanager
    def fake_get_db():
        session = manager.SessionLocal()
        try:
            yield session
        finally:
            session.close()

    return fake_get_db


def install_fake_curl_cffi(monkeypatch, outcomes):
    fake_module = ModuleType("curl_cffi")
    fake_module.requests = FakeRequests(outcomes)
    monkeypatch.setitem(sys.modules, "curl_cffi", fake_module)


def create_proxy(manager: DatabaseSessionManager, name: str, enabled: bool = True) -> int:
    with manager.session_scope() as session:
        proxy = Proxy(
            name=name,
            type="http",
            host="127.0.0.1",
            port=8000 + len(name),
            enabled=enabled,
        )
        session.add(proxy)
        session.flush()
        proxy_id = proxy.id
    return proxy_id


def get_proxy_state(manager: DatabaseSessionManager, proxy_id: int):
    with manager.session_scope() as session:
        proxy = session.get(Proxy, proxy_id)
        return {
            "exists": proxy is not None,
            "enabled": proxy.enabled if proxy else None,
        }


def test_test_proxy_item_disables_failed_proxy(tmp_path, monkeypatch):
    db_path = tmp_path / "proxy_routes_single.db"
    manager = DatabaseSessionManager(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=manager.engine)

    proxy_id = create_proxy(manager, "单个失败代理")
    monkeypatch.setattr(settings_routes, "get_db", make_fake_get_db(manager))
    install_fake_curl_cffi(monkeypatch, [RuntimeError("connect timeout")])

    result = asyncio.run(settings_routes.test_proxy_item(proxy_id))

    assert result["success"] is False
    assert result["auto_disabled"] is True
    assert "已自动禁用" in result["message"]
    assert get_proxy_state(manager, proxy_id) == {"exists": True, "enabled": False}


def test_test_all_proxies_disables_failed_entries(tmp_path, monkeypatch):
    db_path = tmp_path / "proxy_routes_batch.db"
    manager = DatabaseSessionManager(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=manager.engine)

    ok_proxy_id = create_proxy(manager, "可用代理")
    failed_proxy_id = create_proxy(manager, "失败代理")
    monkeypatch.setattr(settings_routes, "get_db", make_fake_get_db(manager))
    install_fake_curl_cffi(monkeypatch, [
        FakeResponse(status_code=200, payload={"ip": "1.1.1.1"}),
        RuntimeError("network unreachable"),
    ])

    result = asyncio.run(settings_routes.test_all_proxies())

    assert result["total"] == 2
    assert result["success"] == 1
    assert result["failed"] == 1
    assert result["auto_disabled"] == 1

    failed_result = next(item for item in result["results"] if item["id"] == failed_proxy_id)
    ok_result = next(item for item in result["results"] if item["id"] == ok_proxy_id)

    assert ok_result["success"] is True
    assert failed_result["success"] is False
    assert failed_result["auto_disabled"] is True
    assert "已自动禁用" in failed_result["message"]
    assert get_proxy_state(manager, ok_proxy_id) == {"exists": True, "enabled": True}
    assert get_proxy_state(manager, failed_proxy_id) == {"exists": True, "enabled": False}


def test_delete_disabled_proxies_only_removes_disabled_entries(tmp_path, monkeypatch):
    db_path = tmp_path / "proxy_routes_cleanup.db"
    manager = DatabaseSessionManager(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=manager.engine)

    enabled_proxy_id = create_proxy(manager, "启用代理", enabled=True)
    disabled_proxy_id = create_proxy(manager, "禁用代理", enabled=False)
    monkeypatch.setattr(settings_routes, "get_db", make_fake_get_db(manager))

    result = asyncio.run(settings_routes.delete_disabled_proxies())

    assert result["success"] is True
    assert result["deleted"] == 1
    assert "已删除 1 个禁用代理" in result["message"]
    assert get_proxy_state(manager, enabled_proxy_id) == {"exists": True, "enabled": True}
    assert get_proxy_state(manager, disabled_proxy_id) == {"exists": False, "enabled": None}

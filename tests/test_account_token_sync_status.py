from src.database import crud
from src.database.session import DatabaseSessionManager


def test_create_account_marks_token_sync_pending_when_tokens_persist(tmp_path):
    manager = DatabaseSessionManager(f"sqlite:///{tmp_path}/test.db")
    manager.create_tables()
    manager.migrate_tables()

    with manager.session_scope() as session:
        account = crud.create_account(
            session,
            email="sync@example.com",
            email_service="tempmail",
            access_token="access-token",
            refresh_token="refresh-token",
        )

        assert account.token_sync_status == "pending"
        assert account.token_sync_updated_at is not None


def test_update_account_marks_token_sync_pending_when_tokens_change(tmp_path):
    manager = DatabaseSessionManager(f"sqlite:///{tmp_path}/test.db")
    manager.create_tables()
    manager.migrate_tables()

    with manager.session_scope() as session:
        account = crud.create_account(
            session,
            email="nosync@example.com",
            email_service="tempmail",
        )

        assert account.token_sync_status == "not_ready"

        updated = crud.update_account(
            session,
            account.id,
            access_token="new-access-token",
        )

        assert updated is not None
        assert updated.token_sync_status == "pending"
        assert updated.token_sync_updated_at is not None


def test_update_account_preserves_pending_status_when_other_tokens_remain(tmp_path):
    manager = DatabaseSessionManager(f"sqlite:///{tmp_path}/test.db")
    manager.create_tables()
    manager.migrate_tables()

    with manager.session_scope() as session:
        account = crud.create_account(
            session,
            email="partial-sync@example.com",
            email_service="tempmail",
            access_token="access-token",
            refresh_token="refresh-token",
        )

        updated = crud.update_account(
            session,
            account.id,
            refresh_token="",
        )

        assert updated is not None
        assert updated.access_token == "access-token"
        assert updated.refresh_token == ""
        assert updated.token_sync_status == "pending"
        assert updated.token_sync_updated_at is not None


def test_update_outlook_refresh_token_persists_nested_config_changes(tmp_path):
    manager = DatabaseSessionManager(f"sqlite:///{tmp_path}/test.db")
    manager.create_tables()
    manager.migrate_tables()

    with manager.session_scope() as session:
        service = crud.create_email_service(
            session,
            service_type="outlook",
            name="outlook-service",
            config={
                "accounts": [
                    {"email": "first@example.com", "refresh_token": "old-first"},
                    {"email": "second@example.com", "refresh_token": "old-second"},
                ]
            },
        )
        service_id = service.id

        crud.update_outlook_refresh_token(
            session,
            service_id=service_id,
            email="second@example.com",
            new_refresh_token="new-second",
        )

    with manager.session_scope() as session:
        reloaded = crud.get_email_service_by_id(session, service_id)

        assert reloaded is not None
        assert reloaded.config["accounts"][0]["refresh_token"] == "old-first"
        assert reloaded.config["accounts"][1]["refresh_token"] == "new-second"

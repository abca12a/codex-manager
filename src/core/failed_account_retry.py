"""
失败账号补跑工具
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional

from ..config.constants import AccountStatus, EmailServiceType
from ..config.settings import get_settings
from ..database import crud
from ..database.models import Account, EmailService as EmailServiceModel
from ..database.session import get_db
from ..services import EmailServiceFactory
from .register import RegistrationEngine, RegistrationResult


DEFAULT_ACCOUNT_STATUS = AccountStatus.FAILED.value


@dataclass
class FailedAccountRetrySummary:
    """单个失败账号补跑摘要。"""

    db_account_id: int
    email: str
    success: bool
    status_before: str
    status_after: str
    openai_account_id: str = ""
    workspace_id: str = ""
    source: str = ""
    error_message: str = ""
    started_at: str = ""
    finished_at: str = ""
    log_file: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _build_email_service_config(
    service_type: EmailServiceType,
    email: str,
) -> Optional[Dict[str, Any]]:
    """按账号邮箱构造收件箱服务配置。"""
    with get_db() as db:
        if service_type == EmailServiceType.TEMPMAIL:
            settings = get_settings()
            return {
                "base_url": settings.tempmail_base_url,
                "timeout": settings.tempmail_timeout,
                "max_retries": settings.tempmail_max_retries,
            }

        if service_type == EmailServiceType.MOE_MAIL:
            domain = email.split("@")[1] if "@" in email else ""
            services = (
                db.query(EmailServiceModel)
                .filter(
                    EmailServiceModel.service_type == "moe_mail",
                    EmailServiceModel.enabled == True,  # noqa: E712
                )
                .order_by(EmailServiceModel.priority.asc())
                .all()
            )
            service = None
            for candidate in services:
                config = candidate.config or {}
                if config.get("default_domain") == domain or config.get("domain") == domain:
                    service = candidate
                    break
            if not service and services:
                service = services[0]
            if not service:
                return None
            config = (service.config or {}).copy()
            if "api_url" in config and "base_url" not in config:
                config["base_url"] = config.pop("api_url")
            return config

        type_map = {
            EmailServiceType.TEMP_MAIL: "temp_mail",
            EmailServiceType.DUCK_MAIL: "duck_mail",
            EmailServiceType.FREEMAIL: "freemail",
            EmailServiceType.IMAP_MAIL: "imap_mail",
            EmailServiceType.OUTLOOK: "outlook",
        }
        db_type = type_map.get(service_type)
        if not db_type:
            return None

        query = db.query(EmailServiceModel).filter(
            EmailServiceModel.service_type == db_type,
            EmailServiceModel.enabled == True,  # noqa: E712
        )
        if service_type == EmailServiceType.OUTLOOK:
            services = query.all()
            service = next(
                (item for item in services if (item.config or {}).get("email") == email),
                None,
            )
        else:
            service = query.order_by(EmailServiceModel.priority.asc()).first()

        if not service:
            return None

        config = (service.config or {}).copy()
        if "api_url" in config and "base_url" not in config:
            config["base_url"] = config.pop("api_url")
        return config


def _account_snapshot(account: Account) -> Dict[str, Any]:
    return {
        "id": account.id,
        "email": account.email,
        "password": account.password,
        "email_service": account.email_service,
        "email_service_id": account.email_service_id,
        "status": account.status,
        "account_id": account.account_id,
        "workspace_id": account.workspace_id,
        "access_token": account.access_token,
        "refresh_token": account.refresh_token,
        "id_token": account.id_token,
        "session_token": account.session_token,
        "proxy_used": account.proxy_used,
        "source": account.source,
        "extra_data": dict(account.extra_data or {}),
    }


def _write_retry_log(
    output_dir: Path,
    db_account_id: int,
    logs: Iterable[str],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = output_dir / f"account_{db_account_id:03d}.log"
    log_file.write_text("\n".join(logs) + "\n", encoding="utf-8")
    return log_file


def _persist_retry_result(
    snapshot: Dict[str, Any],
    result: RegistrationResult,
    started_at: datetime,
    finished_at: datetime,
    log_file: Optional[Path],
) -> None:
    extra_data = dict(snapshot.get("extra_data") or {})
    retry_entry = {
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "success": result.success,
        "error_message": result.error_message,
        "openai_account_id": result.account_id,
        "workspace_id": result.workspace_id,
        "source": result.source,
        "log_file": str(log_file) if log_file else "",
        "retry_mode": "existing_account",
    }
    if result.metadata:
        retry_entry["metadata"] = result.metadata

    retry_history = list(extra_data.get("retry_history") or [])
    retry_history.append(retry_entry)
    extra_data["retry_history"] = retry_history[-10:]
    extra_data["last_retry"] = retry_entry
    extra_data["last_retry_logs_tail"] = list(result.logs or [])[-20:]

    if result.success:
        if extra_data.get("register_failed_reason"):
            extra_data["previous_failed_reason"] = extra_data.get("register_failed_reason")
        extra_data["register_failed_reason"] = ""
        extra_data["recovered_at"] = finished_at.isoformat()
        extra_data["recovered_by"] = "retry_failed_accounts"
    else:
        extra_data["register_failed_reason"] = (
            result.error_message
            or extra_data.get("register_failed_reason")
            or "补跑失败"
        )

    update_fields: Dict[str, Any] = {
        "status": AccountStatus.ACTIVE.value if result.success else AccountStatus.FAILED.value,
        "password": result.password or snapshot.get("password"),
        "source": result.source or snapshot.get("source") or "register",
        "extra_data": extra_data,
    }

    if result.success:
        update_fields["last_refresh"] = finished_at

    for field in (
        "account_id",
        "workspace_id",
        "access_token",
        "refresh_token",
        "id_token",
        "session_token",
    ):
        value = getattr(result, field, "") or snapshot.get(field)
        if value:
            update_fields[field] = value

    with get_db() as db:
        crud.update_account(db, snapshot["id"], **update_fields)


def resolve_target_account_ids(
    db,
    account_ids: Optional[Iterable[int]] = None,
    status: Optional[str] = DEFAULT_ACCOUNT_STATUS,
    limit: Optional[int] = None,
) -> list[int]:
    """解析本次需要补跑的账号 ID 列表。"""
    if account_ids:
        normalized_ids: list[int] = []
        seen_ids: set[int] = set()
        for raw_id in account_ids:
            try:
                account_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            if account_id <= 0 or account_id in seen_ids:
                continue
            seen_ids.add(account_id)
            normalized_ids.append(account_id)
        return normalized_ids

    query_limit = limit or 1000
    accounts = crud.get_accounts(
        db,
        skip=0,
        limit=query_limit,
        status=status,
    )
    return [account.id for account in accounts]


def retry_failed_accounts(
    account_ids: Iterable[int],
    output_dir: Path,
    delay_seconds: float = 3.0,
    callback_logger: Optional[Callable[[str], None]] = None,
) -> list[FailedAccountRetrySummary]:
    """串行补跑指定失败账号。"""
    summaries: list[FailedAccountRetrySummary] = []
    target_ids = list(account_ids)

    for index, db_account_id in enumerate(target_ids, start=1):
        started_at = datetime.now()
        log_lines: list[str] = []

        def emit(message: str) -> None:
            print(message)
            log_lines.append(message)
            if callback_logger:
                callback_logger(message)

        emit("=" * 80)
        emit(f"[{started_at.strftime('%H:%M:%S')}] 开始补跑账号 {db_account_id} ({index}/{len(target_ids)})")

        with get_db() as db:
            account = crud.get_account_by_id(db, db_account_id)
            if not account:
                finished_at = datetime.now()
                log_file = _write_retry_log(output_dir, db_account_id, log_lines)
                summaries.append(
                    FailedAccountRetrySummary(
                        db_account_id=db_account_id,
                        email="",
                        success=False,
                        status_before="missing",
                        status_after="missing",
                        error_message="账号不存在",
                        started_at=started_at.isoformat(),
                        finished_at=finished_at.isoformat(),
                        log_file=str(log_file),
                    )
                )
                continue

            snapshot = _account_snapshot(account)

        emit(f"[{started_at.strftime('%H:%M:%S')}] 目标邮箱: {snapshot['email']}")
        emit(f"[{started_at.strftime('%H:%M:%S')}] 当前状态: {snapshot['status']}")

        try:
            service_type = EmailServiceType(snapshot["email_service"])
            config = _build_email_service_config(service_type, snapshot["email"])
            if not config:
                raise ValueError("未找到可用的邮箱服务配置")
            email_service = EmailServiceFactory.create(service_type, config)

            engine = RegistrationEngine(
                email_service=email_service,
                proxy_url=snapshot.get("proxy_used"),
                callback_logger=emit,
            )
            result = engine.run_existing_account(
                email=snapshot["email"],
                password=snapshot.get("password"),
                email_service_id=snapshot.get("email_service_id"),
            )
        except Exception as exc:
            result = RegistrationResult(
                success=False,
                email=snapshot["email"],
                password=snapshot.get("password") or "",
                error_message=str(exc),
                logs=log_lines,
                metadata={"retry_mode": "existing_account"},
            )
            emit(f"[{datetime.now().strftime('%H:%M:%S')}] 补跑异常: {exc}")

        finished_at = datetime.now()
        log_file = _write_retry_log(output_dir, db_account_id, result.logs or log_lines)
        _persist_retry_result(snapshot, result, started_at, finished_at, log_file)

        status_after = AccountStatus.ACTIVE.value if result.success else AccountStatus.FAILED.value
        summary = FailedAccountRetrySummary(
            db_account_id=db_account_id,
            email=snapshot["email"],
            success=result.success,
            status_before=snapshot["status"],
            status_after=status_after,
            openai_account_id=result.account_id,
            workspace_id=result.workspace_id,
            source=result.source,
            error_message=result.error_message,
            started_at=started_at.isoformat(),
            finished_at=finished_at.isoformat(),
            log_file=str(log_file),
        )
        summaries.append(summary)

        emit(f"[{finished_at.strftime('%H:%M:%S')}] 补跑结果: {'成功' if result.success else '失败'}")
        if result.account_id:
            emit(f"[{finished_at.strftime('%H:%M:%S')}] OpenAI Account ID: {result.account_id}")
        if result.workspace_id:
            emit(f"[{finished_at.strftime('%H:%M:%S')}] Workspace ID: {result.workspace_id}")
        if result.error_message:
            emit(f"[{finished_at.strftime('%H:%M:%S')}] 错误信息: {result.error_message}")

        if index < len(target_ids) and delay_seconds > 0:
            emit(f"[{finished_at.strftime('%H:%M:%S')}] 等待 {delay_seconds:.1f} 秒后继续下一个账号...")
            time.sleep(delay_seconds)

    return summaries


def write_retry_summary(output_dir: Path, summaries: Iterable[FailedAccountRetrySummary]) -> Path:
    """写出补跑汇总 JSON。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_file = output_dir / "summary.json"
    payload = [summary.to_dict() for summary in summaries]
    summary_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary_file

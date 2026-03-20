"""
注册流程引擎
从 main.py 中提取并重构的注册流程
"""

import re
import json
import time
import base64
import logging
import secrets
import string
import urllib.parse
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime

from curl_cffi import requests as cffi_requests

from .openai.oauth import OAuthManager, OAuthStart
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings


logger = logging.getLogger(__name__)


def _decode_auth_cookie_payload(auth_cookie: str) -> Dict[str, Any]:
    """解码授权 Cookie 的 JSON 载荷。"""
    segments = auth_cookie.split(".")
    if not segments or not segments[0]:
        raise ValueError("empty auth cookie payload")

    payload = segments[0]
    pad = "=" * ((4 - (len(payload) % 4)) % 4)
    decoded = base64.urlsafe_b64decode((payload + pad).encode("ascii"))
    auth_json = json.loads(decoded.decode("utf-8"))
    if not isinstance(auth_json, dict):
        raise ValueError("auth cookie payload is not a JSON object")
    return auth_json


def _extract_workspace_candidates(auth_json: Dict[str, Any]) -> list[Tuple[str, str]]:
    """从授权 Cookie 载荷里提取所有可能的 workspace/account 标识。"""
    candidates: list[Tuple[str, str]] = []
    seen: set[str] = set()

    def add_candidate(raw_value: Any, source: str) -> None:
        if isinstance(raw_value, (dict, list, tuple, set)):
            return
        value = str(raw_value or "").strip()
        if value and value not in seen:
            seen.add(value)
            candidates.append((value, source))

    workspaces = auth_json.get("workspaces")
    if isinstance(workspaces, list):
        for index, workspace in enumerate(workspaces):
            if not isinstance(workspace, dict):
                continue
            add_candidate(workspace.get("id"), f"workspaces[{index}].id")
            add_candidate(workspace.get("workspace_id"), f"workspaces[{index}].workspace_id")
            add_candidate(workspace.get("workspaceId"), f"workspaces[{index}].workspaceId")
            add_candidate(workspace.get("account_id"), f"workspaces[{index}].account_id")

    direct_keys = (
        "workspace_id",
        "workspaceId",
        "active_workspace_id",
        "activeWorkspaceId",
        "default_workspace_id",
        "defaultWorkspaceId",
        "account_id",
        "accountId",
        "active_account_id",
        "activeAccountId",
        "chatgpt_account_id",
        "chatgptAccountId",
        "sub",
    )
    for key in direct_keys:
        add_candidate(auth_json.get(key), key)

    container_keys = (
        "workspace",
        "active_workspace",
        "default_workspace",
        "current_workspace",
        "account",
        "active_account",
        "chatgpt_account",
        "user",
    )
    container_id_keys = (
        "id",
        "workspace_id",
        "workspaceId",
        "account_id",
        "accountId",
        "chatgpt_account_id",
        "chatgptAccountId",
    )
    for container_key in container_keys:
        container = auth_json.get(container_key)
        if not isinstance(container, dict):
            continue
        for id_key in container_id_keys:
            add_candidate(container.get(id_key), f"{container_key}.{id_key}")

    session_obj = auth_json.get("session")
    if isinstance(session_obj, dict):
        for session_key in ("workspace", "account", "user"):
            nested = session_obj.get(session_key)
            if not isinstance(nested, dict):
                continue
            for id_key in container_id_keys:
                add_candidate(nested.get(id_key), f"session.{session_key}.{id_key}")

    return candidates


@dataclass
class RegistrationResult:
    """注册结果"""
    success: bool
    email: str = ""
    password: str = ""  # 注册密码
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""  # 会话令牌
    error_message: str = ""
    logs: list = None
    metadata: dict = None
    source: str = "register"  # 'register' 或 'login'，区分账号来源

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }


@dataclass
class SignupFormResult:
    """提交注册表单的结果"""
    success: bool
    page_type: str = ""  # 响应中的 page.type 字段
    is_existing_account: bool = False  # 是否为已注册账号
    response_data: Dict[str, Any] = None  # 完整的响应数据
    error_message: str = ""


@dataclass
class CreateAccountResult:
    """创建账户结果"""
    success: bool
    continue_url: str = ""
    continue_method: str = "GET"
    response_data: Dict[str, Any] = None
    error_message: str = ""


class RegistrationEngine:
    """
    注册引擎
    负责协调邮箱服务、OAuth 流程和 OpenAI API 调用
    """

    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None
    ):
        """
        初始化注册引擎

        Args:
            email_service: 邮箱服务实例
            proxy_url: 代理 URL
            callback_logger: 日志回调函数
            task_uuid: 任务 UUID（用于数据库记录）
        """
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid

        # 创建 HTTP 客户端
        self.http_client = OpenAIHTTPClient(proxy_url=proxy_url)

        # 创建 OAuth 管理器
        settings = get_settings()
        self.oauth_manager = OAuthManager(
            client_id=settings.openai_client_id,
            auth_url=settings.openai_auth_url,
            token_url=settings.openai_token_url,
            redirect_uri=settings.openai_redirect_uri,
            scope=settings.openai_scope,
            proxy_url=proxy_url  # 传递代理配置
        )

        # 状态变量
        self.email: Optional[str] = None
        self.password: Optional[str] = None  # 注册密码
        self.email_info: Optional[Dict[str, Any]] = None
        self.oauth_start: Optional[OAuthStart] = None
        self.session: Optional[cffi_requests.Session] = None
        self.session_token: Optional[str] = None  # 会话令牌
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None  # OTP 发送时间戳
        self._is_existing_account: bool = False  # 是否为已注册账号（用于自动登录）

    def _log(self, message: str, level: str = "info"):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        # 添加到日志列表
        self.logs.append(log_message)

        # 调用回调函数
        if self.callback_logger:
            self.callback_logger(log_message)

        # 记录到数据库（如果有关联任务）
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")

        # 根据级别记录到日志系统
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """生成随机密码"""
        return ''.join(secrets.choice(PASSWORD_CHARSET) for _ in range(length))

    def _check_ip_location(self) -> Tuple[bool, Optional[str]]:
        """检查 IP 地理位置"""
        try:
            return self.http_client.check_ip_location()
        except Exception as e:
            self._log(f"检查 IP 地理位置失败: {e}", "error")
            return False, None

    def _create_email(self) -> bool:
        """创建邮箱"""
        try:
            self._log(f"正在创建 {self.email_service.service_type.value} 邮箱...")
            self.email_info = self.email_service.create_email()

            if not self.email_info or "email" not in self.email_info:
                self._log("创建邮箱失败: 返回信息不完整", "error")
                return False

            self.email = self.email_info["email"]
            self._log(f"成功创建邮箱: {self.email}")
            return True

        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def _start_oauth(self) -> bool:
        """开始 OAuth 流程"""
        try:
            self._log("开始 OAuth 授权流程...")
            self.oauth_start = self.oauth_manager.start_oauth()
            self._log(f"OAuth URL 已生成: {self.oauth_start.auth_url[:80]}...")
            return True
        except Exception as e:
            self._log(f"生成 OAuth URL 失败: {e}", "error")
            return False

    def _init_session(self) -> bool:
        """初始化会话"""
        try:
            self.session = self.http_client.session
            return True
        except Exception as e:
            self._log(f"初始化会话失败: {e}", "error")
            return False

    def _get_device_id(self) -> Optional[str]:
        """获取 Device ID"""
        if not self.oauth_start:
            return None

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                if not self.session:
                    self.session = self.http_client.session

                response = self.session.get(
                    self.oauth_start.auth_url,
                    timeout=20
                )
                did = self.session.cookies.get("oai-did")

                if did:
                    self._log(f"Device ID: {did}")
                    return did

                self._log(
                    f"获取 Device ID 失败: 未返回 oai-did Cookie (HTTP {response.status_code}, 第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )
            except Exception as e:
                self._log(
                    f"获取 Device ID 失败: {e} (第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )

            if attempt < max_attempts:
                time.sleep(attempt)
                self.http_client.close()
                self.session = self.http_client.session

        return None

    def _check_sentinel(self, did: str) -> Optional[str]:
        """检查 Sentinel 拦截"""
        try:
            sen_req_body = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'

            response = self.http_client.post(
                OPENAI_API_ENDPOINTS["sentinel"],
                headers={
                    "origin": "https://sentinel.openai.com",
                    "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                    "content-type": "text/plain;charset=UTF-8",
                },
                data=sen_req_body,
            )

            if response.status_code == 200:
                sen_token = response.json().get("token")
                self._log(f"Sentinel token 获取成功")
                return sen_token
            else:
                self._log(f"Sentinel 检查失败: {response.status_code}", "warning")
                return None

        except Exception as e:
            self._log(f"Sentinel 检查异常: {e}", "warning")
            return None

    def _submit_signup_form(self, did: str, sen_token: Optional[str]) -> SignupFormResult:
        """
        提交注册表单

        Returns:
            SignupFormResult: 提交结果，包含账号状态判断
        """
        try:
            signup_body = f'{{"username":{{"value":"{self.email}","kind":"email"}},"screen_hint":"signup"}}'

            headers = {
                "referer": "https://auth.openai.com/create-account",
                "accept": "application/json",
                "content-type": "application/json",
            }

            if sen_token:
                sentinel = f'{{"p": "", "t": "", "c": "{sen_token}", "id": "{did}", "flow": "authorize_continue"}}'
                headers["openai-sentinel-token"] = sentinel

            response = self.session.post(
                OPENAI_API_ENDPOINTS["signup"],
                headers=headers,
                data=signup_body,
            )

            self._log(f"提交注册表单状态: {response.status_code}")

            if response.status_code != 200:
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )

            # 解析响应判断账号状态
            try:
                response_data = response.json()
                page_type = response_data.get("page", {}).get("type", "")
                self._log(f"响应页面类型: {page_type}")

                # 判断是否为已注册账号
                is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]

                if is_existing:
                    self._log(f"检测到已注册账号，将自动切换到登录流程")
                    self._is_existing_account = True

                return SignupFormResult(
                    success=True,
                    page_type=page_type,
                    is_existing_account=is_existing,
                    response_data=response_data
                )

            except Exception as parse_error:
                self._log(f"解析响应失败: {parse_error}", "warning")
                # 无法解析，默认成功
                return SignupFormResult(success=True)

        except Exception as e:
            self._log(f"提交注册表单失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    def _register_password(self) -> Tuple[bool, Optional[str]]:
        """注册密码"""
        try:
            # 生成密码
            password = self._generate_password()
            self.password = password  # 保存密码到实例变量
            self._log(f"生成密码: {password}")

            # 提交密码注册
            register_body = json.dumps({
                "password": password,
                "username": self.email
            })

            response = self.session.post(
                OPENAI_API_ENDPOINTS["register"],
                headers={
                    "referer": "https://auth.openai.com/create-account/password",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=register_body,
            )

            self._log(f"提交密码状态: {response.status_code}")

            if response.status_code != 200:
                error_text = response.text[:500]
                self._log(f"密码注册失败: {error_text}", "warning")

                # 解析错误信息，判断是否是邮箱已注册
                try:
                    error_json = response.json()
                    error_msg = error_json.get("error", {}).get("message", "")
                    error_code = error_json.get("error", {}).get("code", "")

                    # 检测邮箱已注册的情况
                    if "already" in error_msg.lower() or "exists" in error_msg.lower() or error_code == "user_exists":
                        self._log(f"邮箱 {self.email} 可能已在 OpenAI 注册过", "error")
                        # 标记此邮箱为已注册状态
                        self._mark_email_as_registered()
                except Exception:
                    pass

                return False, None

            return True, password

        except Exception as e:
            self._log(f"密码注册失败: {e}", "error")
            return False, None

    def _mark_email_as_registered(self):
        """标记邮箱为已注册状态（用于防止重复尝试）"""
        try:
            with get_db() as db:
                # 检查是否已存在该邮箱的记录
                existing = crud.get_account_by_email(db, self.email)
                if not existing:
                    # 创建一个失败记录，标记该邮箱已注册过
                    crud.create_account(
                        db,
                        email=self.email,
                        password="",  # 空密码表示未成功注册
                        email_service=self.email_service.service_type.value,
                        email_service_id=self.email_info.get("service_id") if self.email_info else None,
                        status="failed",
                        extra_data={"register_failed_reason": "email_already_registered_on_openai"}
                    )
                    self._log(f"已在数据库中标记邮箱 {self.email} 为已注册状态")
        except Exception as e:
            logger.warning(f"标记邮箱状态失败: {e}")

    def _send_verification_code(self) -> bool:
        """发送验证码"""
        try:
            # 记录发送时间戳
            self._otp_sent_at = time.time()

            response = self.session.get(
                OPENAI_API_ENDPOINTS["send_otp"],
                headers={
                    "referer": "https://auth.openai.com/create-account/password",
                    "accept": "application/json",
                },
            )

            self._log(f"验证码发送状态: {response.status_code}")
            return response.status_code == 200

        except Exception as e:
            self._log(f"发送验证码失败: {e}", "error")
            return False

    def _get_verification_code(self) -> Optional[str]:
        """获取验证码"""
        try:
            self._log(f"正在等待邮箱 {self.email} 的验证码...")

            email_id = self.email_info.get("service_id") if self.email_info else None
            code = self.email_service.get_verification_code(
                email=self.email,
                email_id=email_id,
                timeout=120,
                pattern=OTP_CODE_PATTERN,
                otp_sent_at=self._otp_sent_at,
            )

            if code:
                self._log(f"成功获取验证码: {code}")
                return code
            else:
                self._log("等待验证码超时", "error")
                return None

        except Exception as e:
            self._log(f"获取验证码失败: {e}", "error")
            return None

    def _validate_verification_code(self, code: str) -> bool:
        """验证验证码"""
        try:
            code_body = f'{{"code":"{code}"}}'

            response = self.session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers={
                    "referer": "https://auth.openai.com/email-verification",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=code_body,
            )

            self._log(f"验证码校验状态: {response.status_code}")
            return response.status_code == 200

        except Exception as e:
            self._log(f"验证验证码失败: {e}", "error")
            return False

    def _extract_next_url_from_html(self, current_url: str, html: str) -> Optional[str]:
        """从 HTML 中提取下一跳 URL。"""
        try:
            patterns = [
                r'https?://[^\s"\'<>]+',
                r'(?:(?:href|action|content|location(?:\.href)?|replace)\s*[:=]\s*["\'])([^"\']+)',
            ]

            candidates: list[str] = []
            seen: set[str] = set()
            for pattern in patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    value = match.group(1) if match.groups() else match.group(0)
                    candidate = urllib.parse.urljoin(current_url, value.strip())
                    if candidate and candidate not in seen:
                        seen.add(candidate)
                        candidates.append(candidate)

            for candidate in candidates:
                if "code=" in candidate and "state=" in candidate:
                    self._log(f"HTML 中提取到回调 URL: {candidate[:100]}...")
                    return candidate

            auth_prefixes = (
                "https://auth.openai.com/api/oauth/oauth2/auth",
                "https://auth.openai.com/api/accounts/consent",
                "https://auth.openai.com/oauth/",
                "https://auth.openai.com/u/",
            )
            for candidate in candidates:
                if candidate.startswith(auth_prefixes):
                    self._log(f"HTML 中提取到下一跳 URL: {candidate[:100]}...")
                    return candidate

            return None

        except Exception as e:
            self._log(f"解析 HTML 下一跳失败: {e}", "warning")
            return None

    def _log_html_debug_info(self, current_url: str, html: str) -> None:
        """记录 HTML 页面的调试摘要。"""
        try:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
            if title:
                self._log(f"HTML 标题: {title}", "warning")

            form_matches = list(
                re.finditer(
                    r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>(.*?)</form>",
                    html,
                    re.IGNORECASE | re.DOTALL,
                )
            )
            self._log(f"HTML 表单数量: {len(form_matches)}", "warning")
            for index, match in enumerate(form_matches[:2], start=1):
                action = urllib.parse.urljoin(current_url, (match.group(1) or "").strip())
                inner_html = match.group(2) or ""
                input_names = re.findall(
                    r"<input[^>]*name=[\"']([^\"']+)[\"']",
                    inner_html,
                    re.IGNORECASE,
                )
                names_preview = ", ".join(input_names[:8]) or "(none)"
                self._log(f"HTML 表单{index} action: {action[:120]}", "warning")
                self._log(f"HTML 表单{index} inputs: {names_preview}", "warning")

            snippet = re.sub(r"\s+", " ", html[:600]).strip()
            if snippet:
                self._log(f"HTML 片段: {snippet[:300]}", "warning")
        except Exception as e:
            self._log(f"记录 HTML 调试信息失败: {e}", "warning")

    def _create_user_account(self) -> CreateAccountResult:
        """创建用户账户"""
        try:
            user_info = generate_random_user_info()
            self._log(f"生成用户信息: {user_info['name']}, 生日: {user_info['birthdate']}")
            create_account_body = json.dumps(user_info)

            response = self.session.post(
                OPENAI_API_ENDPOINTS["create_account"],
                headers={
                    "referer": "https://auth.openai.com/about-you",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=create_account_body,
            )

            self._log(f"账户创建状态: {response.status_code}")

            if response.status_code != 200:
                self._log(f"账户创建失败: {response.text[:200]}", "warning")
                return CreateAccountResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}",
                )

            response_json: Dict[str, Any] = {}
            continue_url = ""
            continue_method = "GET"
            try:
                response_json = response.json()
                if isinstance(response_json, dict):
                    top_level_keys = ", ".join(sorted(response_json.keys())[:12]) or "(empty)"
                    self._log(f"create_account 响应字段: {top_level_keys}")
                    continue_url = str(response_json.get("continue_url") or "").strip()
                    continue_method = str(response_json.get("method") or "GET").strip().upper() or "GET"
                    if continue_url:
                        self._log(f"create_account Continue URL: {continue_url[:100]}...")
                        self._log(f"create_account Continue Method: {continue_method}")
                    page_type = str((response_json.get("page") or {}).get("type") or "").strip()
                    if page_type:
                        self._log(f"create_account 页面类型: {page_type}")

                    candidate_fields: Dict[str, str] = {}
                    for key in (
                        "id",
                        "account_id",
                        "accountId",
                        "workspace_id",
                        "workspaceId",
                        "chatgpt_account_id",
                        "chatgptAccountId",
                    ):
                        value = str(response_json.get(key) or "").strip()
                        if value:
                            candidate_fields[key] = value

                    account_obj = response_json.get("account")
                    if isinstance(account_obj, dict):
                        for key in ("id", "account_id", "workspace_id"):
                            value = str(account_obj.get(key) or "").strip()
                            if value:
                                candidate_fields[f"account.{key}"] = value

                    if candidate_fields:
                        self._log(
                            "create_account 候选 ID: "
                            + json.dumps(candidate_fields, ensure_ascii=False, sort_keys=True)
                        )
            except Exception as e:
                self._log(f"create_account 响应解析失败: {e}", "warning")

            return CreateAccountResult(
                success=True,
                continue_url=continue_url,
                continue_method=continue_method,
                response_data=response_json if isinstance(response_json, dict) else {},
            )

        except Exception as e:
            self._log(f"创建账户失败: {e}", "error")
            return CreateAccountResult(success=False, error_message=str(e))

    def _get_workspace_id(self) -> Optional[str]:
        """获取 Workspace ID"""
        try:
            auth_cookie = self.session.cookies.get("oai-client-auth-session")
            if not auth_cookie:
                self._log("未能获取到授权 Cookie", "error")
                return None

            try:
                auth_json = _decode_auth_cookie_payload(auth_cookie)
                candidates = _extract_workspace_candidates(auth_json)
                if not candidates:
                    top_level_keys = ", ".join(sorted(auth_json.keys())[:20]) or "(empty)"
                    self._log(f"授权 Cookie 顶层字段: {top_level_keys}", "warning")
                    self._log("授权 Cookie 里没有可用 workspace 信息", "error")
                    return None

                workspace_id, source = candidates[0]
                if source != "workspaces[0].id":
                    sources_preview = ", ".join(source_name for _, source_name in candidates[:6])
                    self._log(f"Workspace ID 回退来源: {source}", "warning")
                    self._log(f"授权 Cookie 候选来源: {sources_preview}", "warning")

                self._log(f"Workspace ID: {workspace_id}")
                return workspace_id

            except Exception as e:
                self._log(f"解析授权 Cookie 失败: {e}", "error")
                return None

        except Exception as e:
            self._log(f"获取 Workspace ID 失败: {e}", "error")
            return None

    def _select_workspace(self, workspace_id: str) -> Optional[str]:
        """选择 Workspace"""
        try:
            select_body = f'{{"workspace_id":"{workspace_id}"}}'

            response = self.session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                },
                data=select_body,
            )

            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None

            continue_url = str((response.json() or {}).get("continue_url") or "").strip()
            if not continue_url:
                self._log("workspace/select 响应里缺少 continue_url", "error")
                return None

            self._log(f"Continue URL: {continue_url[:100]}...")
            return continue_url

        except Exception as e:
            self._log(f"选择 Workspace 失败: {e}", "error")
            return None

    def _follow_redirects(self, start_url: str, start_method: str = "GET") -> Optional[str]:
        """跟随重定向链，寻找回调 URL"""
        try:
            current_url = start_url
            current_method = (start_method or "GET").upper()
            max_redirects = 6

            for i in range(max_redirects):
                self._log(f"重定向 {i+1}/{max_redirects}: [{current_method}] {current_url[:100]}...")

                request_fn = self.session.post if current_method == "POST" else self.session.get
                response = request_fn(current_url, allow_redirects=False, timeout=15)

                location = response.headers.get("Location") or ""

                # 如果不是重定向状态码，停止
                if response.status_code not in [301, 302, 303, 307, 308]:
                    self._log(f"非重定向状态码: {response.status_code}")
                    content_type = response.headers.get("Content-Type") or ""
                    self._log(f"响应 Content-Type: {content_type or '(empty)'}", "warning")
                    if "text/html" in content_type.lower():
                        self._log_html_debug_info(current_url, response.text or "")
                        if "/add-phone" in current_url:
                            self._log("检测到 add-phone 页面，当前流程可能被手机号验证拦截", "error")
                    next_url = self._extract_next_url_from_html(current_url, response.text or "")
                    if next_url:
                        if "code=" in next_url and "state=" in next_url:
                            return next_url
                        current_url = next_url
                        current_method = "GET"
                        continue
                    break

                if not location:
                    self._log("重定向响应缺少 Location 头")
                    break

                next_url = urllib.parse.urljoin(current_url, location)

                # 检查是否包含回调参数
                if "code=" in next_url and "state=" in next_url:
                    self._log(f"找到回调 URL: {next_url[:100]}...")
                    return next_url

                current_url = next_url
                current_method = "POST" if response.status_code in [307, 308] and current_method == "POST" else "GET"

            self._log("未能在重定向链中找到回调 URL", "error")
            return None

        except Exception as e:
            self._log(f"跟随重定向失败: {e}", "error")
            return None

    def _handle_oauth_callback(self, callback_url: str) -> Optional[Dict[str, Any]]:
        """处理 OAuth 回调"""
        try:
            if not self.oauth_start:
                self._log("OAuth 流程未初始化", "error")
                return None

            self._log("处理 OAuth 回调...")
            token_info = self.oauth_manager.handle_callback(
                callback_url=callback_url,
                expected_state=self.oauth_start.state,
                code_verifier=self.oauth_start.code_verifier
            )

            self._log("OAuth 授权成功")
            return token_info

        except Exception as e:
            self._log(f"处理 OAuth 回调失败: {e}", "error")
            return None

    def run(self) -> RegistrationResult:
        """
        执行完整的注册流程

        支持已注册账号自动登录：
        - 如果检测到邮箱已注册，自动切换到登录流程
        - 已注册账号跳过：设置密码、发送验证码、创建用户账户
        - 共用步骤：获取验证码、验证验证码、Workspace 和 OAuth 回调

        Returns:
            RegistrationResult: 注册结果
        """
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._log("=" * 60)
            self._log("开始注册流程")
            self._log("=" * 60)

            # 1. 检查 IP 地理位置
            self._log("1. 检查 IP 地理位置...")
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                result.error_message = f"IP 地理位置不支持: {location}"
                self._log(f"IP 检查失败: {location}", "error")
                return result

            self._log(f"IP 位置: {location}")

            # 2. 创建邮箱
            self._log("2. 创建邮箱...")
            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result

            result.email = self.email

            # 3. 初始化会话
            self._log("3. 初始化会话...")
            if not self._init_session():
                result.error_message = "初始化会话失败"
                return result

            # 4. 开始 OAuth 流程
            self._log("4. 开始 OAuth 授权流程...")
            if not self._start_oauth():
                result.error_message = "开始 OAuth 流程失败"
                return result

            # 5. 获取 Device ID
            self._log("5. 获取 Device ID...")
            did = self._get_device_id()
            if not did:
                result.error_message = "获取 Device ID 失败"
                return result

            # 6. 检查 Sentinel 拦截
            self._log("6. 检查 Sentinel 拦截...")
            sen_token = self._check_sentinel(did)
            if sen_token:
                self._log("Sentinel 检查通过")
            else:
                self._log("Sentinel 检查失败或未启用", "warning")

            # 7. 提交注册表单 + 解析响应判断账号状态
            self._log("7. 提交注册表单...")
            signup_result = self._submit_signup_form(did, sen_token)
            if not signup_result.success:
                result.error_message = f"提交注册表单失败: {signup_result.error_message}"
                return result

            # 8. [已注册账号跳过] 注册密码
            if self._is_existing_account:
                self._log("8. [已注册账号] 跳过密码设置，OTP 已自动发送")
            else:
                self._log("8. 注册密码...")
                password_ok, password = self._register_password()
                if not password_ok:
                    result.error_message = "注册密码失败"
                    return result

            # 9. [已注册账号跳过] 发送验证码
            if self._is_existing_account:
                self._log("9. [已注册账号] 跳过发送验证码，使用自动发送的 OTP")
                # 已注册账号的 OTP 在提交表单时已自动发送，记录时间戳
                self._otp_sent_at = time.time()
            else:
                self._log("9. 发送验证码...")
                if not self._send_verification_code():
                    result.error_message = "发送验证码失败"
                    return result

            # 10. 获取验证码
            self._log("10. 等待验证码...")
            code = self._get_verification_code()
            if not code:
                result.error_message = "获取验证码失败"
                return result

            # 11. 验证验证码
            self._log("11. 验证验证码...")
            if not self._validate_verification_code(code):
                result.error_message = "验证验证码失败"
                return result

            continue_url = ""
            continue_method = "GET"

            # 12. [已注册账号跳过] 创建用户账户
            if self._is_existing_account:
                self._log("12. [已注册账号] 跳过创建用户账户")
            else:
                self._log("12. 创建用户账户...")
                create_account_result = self._create_user_account()
                if not create_account_result.success:
                    result.error_message = "创建用户账户失败"
                    return result
                continue_url = create_account_result.continue_url
                continue_method = create_account_result.continue_method

            if continue_url:
                self._log("13. 使用 create_account 返回的 Continue URL...")
            else:
                # 13. 获取 Workspace ID
                self._log("13. 获取 Workspace ID...")
                workspace_id = self._get_workspace_id()
                if not workspace_id:
                    result.error_message = "获取 Workspace ID 失败"
                    return result

                result.workspace_id = workspace_id

                # 14. 选择 Workspace
                self._log("14. 选择 Workspace...")
                continue_url = self._select_workspace(workspace_id)
                if not continue_url:
                    result.error_message = "选择 Workspace 失败"
                    return result

            # 15. 跟随重定向链
            self._log("15. 跟随重定向链...")
            callback_url = self._follow_redirects(continue_url, continue_method)
            if not callback_url:
                result.error_message = "跟随重定向链失败"
                return result

            # 16. 处理 OAuth 回调
            self._log("16. 处理 OAuth 回调...")
            token_info = self._handle_oauth_callback(callback_url)
            if not token_info:
                result.error_message = "处理 OAuth 回调失败"
                return result

            # 提取账户信息
            result.account_id = token_info.get("account_id", "")
            result.access_token = token_info.get("access_token", "")
            result.refresh_token = token_info.get("refresh_token", "")
            result.id_token = token_info.get("id_token", "")
            result.password = self.password or ""  # 保存密码（已注册账号为空）

            if not result.workspace_id and result.account_id:
                result.workspace_id = result.account_id
                self._log("Workspace ID 缺失，回退使用 Account ID", "warning")

            # 设置来源标记
            result.source = "login" if self._is_existing_account else "register"

            # 尝试获取 session_token 从 cookie
            session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
            if session_cookie:
                self.session_token = session_cookie
                result.session_token = session_cookie
                self._log(f"获取到 Session Token")

            # 17. 完成
            self._log("=" * 60)
            if self._is_existing_account:
                self._log("登录成功! (已注册账号)")
            else:
                self._log("注册成功!")
            self._log(f"邮箱: {result.email}")
            self._log(f"Account ID: {result.account_id}")
            self._log(f"Workspace ID: {result.workspace_id}")
            self._log("=" * 60)

            result.success = True
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "is_existing_account": self._is_existing_account,
            }

            return result

        except Exception as e:
            self._log(f"注册过程中发生未预期错误: {e}", "error")
            result.error_message = str(e)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        """
        保存注册结果到数据库

        Args:
            result: 注册结果

        Returns:
            是否保存成功
        """
        if not result.success:
            return False

        try:
            # 获取默认 client_id
            settings = get_settings()

            with get_db() as db:
                # 保存账户信息
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source
                )

                self._log(f"账户已保存到数据库，ID: {account.id}")
                return True

        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False

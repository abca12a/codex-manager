"""
后台补跑账号入口脚本
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database.session import init_database  # noqa: E402
from src.core.failed_account_retry import (  # noqa: E402
    DEFAULT_ACCOUNT_STATUS,
    resolve_target_account_ids,
    retry_failed_accounts,
    write_retry_summary,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="串行补跑指定失败账号")
    parser.add_argument(
        "--ids",
        nargs="+",
        type=int,
        default=None,
        help="显式指定要补跑的账号 ID 列表",
    )
    parser.add_argument(
        "--status",
        default=DEFAULT_ACCOUNT_STATUS,
        help=f"未传 --ids 时，按状态筛选账号，默认 {DEFAULT_ACCOUNT_STATUS}",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="未传 --ids 时，最多补跑多少个账号",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=3.0,
        help="每个账号之间的等待秒数，默认 3 秒",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="输出目录，默认写入 run/failed_account_retry_<timestamp>",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir or (ROOT / "run" / f"failed_account_retry_{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)
    session_manager = init_database()

    with session_manager.session_scope() as db:
        target_ids = resolve_target_account_ids(
            db=db,
            account_ids=args.ids,
            status=args.status,
            limit=args.limit,
        )

    if not target_ids:
        print("没有匹配到可补跑的账号")
        return 0

    print(f"输出目录: {output_dir}")
    print(f"目标账号: {', '.join(str(item) for item in target_ids)}")

    summaries = retry_failed_accounts(
        account_ids=target_ids,
        output_dir=output_dir,
        delay_seconds=args.delay_seconds,
    )
    summary_file = write_retry_summary(output_dir, summaries)

    success_count = sum(1 for item in summaries if item.success)
    print("=" * 80)
    print(f"补跑完成: {success_count}/{len(summaries)} 成功")
    print(f"汇总文件: {summary_file}")
    for item in summaries:
        print(
            f"- 账号 {item.db_account_id} | {item.email or '(missing)'} | "
            f"{'成功' if item.success else '失败'} | "
            f"{item.workspace_id or item.openai_account_id or item.error_message or '-'}"
        )

    return 0 if success_count == len(summaries) else 1


if __name__ == "__main__":
    raise SystemExit(main())

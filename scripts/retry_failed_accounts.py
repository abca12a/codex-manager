"""
一次性后台补跑当前 6 个失败账号
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.core.failed_account_retry import (  # noqa: E402
    DEFAULT_FAILED_ACCOUNT_IDS,
    retry_failed_accounts,
    write_retry_summary,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="串行补跑指定失败账号")
    parser.add_argument(
        "--ids",
        nargs="+",
        type=int,
        default=list(DEFAULT_FAILED_ACCOUNT_IDS),
        help="要补跑的账号 ID 列表，默认固定为 3 4 5 6 7 8",
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

    print(f"输出目录: {output_dir}")
    print(f"目标账号: {', '.join(str(item) for item in args.ids)}")

    summaries = retry_failed_accounts(
        account_ids=args.ids,
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

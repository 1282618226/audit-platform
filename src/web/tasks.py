"""后台扫描任务 —— 异步执行 Orchestrator.run()，不阻塞 HTTP 响应。"""

from __future__ import annotations

import logging
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path

from .models.scan import get_db

logger = logging.getLogger("web.tasks")


async def run_scan(scan_id: int, standard: str = "", offline: bool = True) -> None:
    """在后台执行一次扫描。

    1. 更新状态为 running
    2. 构造组件并调用 orchestrator.run()
    3. 更新状态为 done，写入报告路径和发现数
    4. 失败时更新状态为 failed

    Args:
        scan_id: 扫描记录 ID。
        standard: 指定标准（"34944" / "34943" / "39412" / ""）。
        offline: 离线模式（跳过 LLM）。
    """
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()

    try:
        # ── 获取扫描记录和项目信息 ──
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            logger.error("扫描记录 %d 不存在", scan_id)
            return

        project = conn.execute(
            "SELECT * FROM projects WHERE id = ?", (scan["project_id"],)
        ).fetchone()
        if not project:
            logger.error("项目 %d 不存在", scan["project_id"])
            return

        code_dir = project["source_path"]
        report_dir = os.path.join(
            code_dir, "..", "reports", f"scan-{scan_id}"
        )
        Path(report_dir).mkdir(parents=True, exist_ok=True)

        # ── 更新状态为 running ──
        conn.execute(
            "UPDATE scans SET status = 'running', started_at = ? WHERE id = ?",
            (now, scan_id),
        )
        conn.commit()

        # ── 加载配置 ──
        from src.main import load_config

        config = load_config()
        if offline:
            config["llm"]["offline"] = True
        config["output"]["report_dir"] = report_dir

        # ── 构建组件 ──
        from src.main import _create_kb, _create_scanners, _create_llm_client

        kb = _create_kb()
        llm = _create_llm_client(config) if not offline else None
        semgrep, codeql = _create_scanners(config, kb)

        from src.report_generator import ReportGenerator

        report_gen = ReportGenerator(kb=kb)

        from src.orchestrator import Orchestrator

        orch = Orchestrator(
            config,
            kb=kb,
            semgrep=semgrep,
            codeql=codeql,
            llm=llm,
            report_generator=report_gen,
        )

        # ── 执行扫描 ──
        logger.info("后台扫描开始: scan_id=%d code_dir=%s", scan_id, code_dir)
        result = orch.run(code_dir, standard=standard)

        # ── 更新状态为 done ──
        finished = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """UPDATE scans
               SET status = 'done', total_findings = ?, report_dir = ?,
                   finished_at = ?
               WHERE id = ?""",
            (len(result.findings), report_dir, finished, scan_id),
        )
        conn.commit()

        logger.info(
            "后台扫描完成: scan_id=%d findings=%d",
            scan_id,
            len(result.findings),
        )

    except Exception:
        error_msg = traceback.format_exc()
        logger.error("后台扫描失败: scan_id=%d\n%s", scan_id, error_msg)
        conn.execute(
            "UPDATE scans SET status = 'failed', error_message = ?, finished_at = ? WHERE id = ?",
            (error_msg[:2000], now, scan_id),
        )
        conn.commit()
    finally:
        conn.close()

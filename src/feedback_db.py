"""反馈数据库模块。

基于 SQLite 的持久化存储，记录每次扫描结果、人工标注、漏报补录和规则效果统计。

五张核心表:
  - scan_runs:            扫描运行记录
  - findings:             每条漏洞发现的完整信息
  - human_labels:          人工标注（true_positive / false_positive）
  - missed_vulnerabilities: 人工补录的漏报
  - rule_effectiveness:    规则有效性聚合统计

设计参考: CNAS_SAST_Platform_Design.md Section 3.1
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ─── Schema ──────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id           TEXT PRIMARY KEY,
    scan_timestamp   TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'online',
    total_files      INTEGER DEFAULT 0,
    languages_detected TEXT DEFAULT '[]',
    tools_used       TEXT DEFAULT '[]',
    pre_label_findings INTEGER DEFAULT 0,
    duration_seconds INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id       TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL,
    clause           TEXT NOT NULL,
    standard         TEXT NOT NULL,
    vuln_name        TEXT NOT NULL,
    category         TEXT DEFAULT '',
    file_path        TEXT NOT NULL,
    line_start       INTEGER NOT NULL,
    line_end         INTEGER NOT NULL,
    source_tool      TEXT NOT NULL DEFAULT 'semgrep',
    auto_confidence  REAL DEFAULT 0.0,
    code_snippet     TEXT DEFAULT '',
    tool_raw_output  TEXT DEFAULT '{}',
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE IF NOT EXISTS human_labels (
    label_id         TEXT PRIMARY KEY,
    finding_id       TEXT NOT NULL,
    labeler          TEXT DEFAULT 'unknown',
    label_timestamp  TEXT NOT NULL,
    verdict          TEXT NOT NULL CHECK(verdict IN ('true_positive','false_positive','not_sure')),
    actual_severity  TEXT DEFAULT '',
    correction       TEXT DEFAULT '{}',
    notes            TEXT DEFAULT '',
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS missed_vulnerabilities (
    missed_id        TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL,
    clause           TEXT NOT NULL,
    file_path        TEXT NOT NULL,
    line_start       INTEGER NOT NULL,
    line_end         INTEGER NOT NULL,
    reported_by      TEXT DEFAULT 'unknown',
    report_timestamp TEXT NOT NULL,
    description      TEXT DEFAULT '',
    why_missed       TEXT DEFAULT '',
    code_snippet     TEXT DEFAULT '',
    fix_suggestion   TEXT DEFAULT '',
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE IF NOT EXISTS rule_effectiveness (
    clause           TEXT PRIMARY KEY,
    standard         TEXT DEFAULT '',
    vuln_name        TEXT DEFAULT '',
    total_findings   INTEGER DEFAULT 0,
    tp_count         INTEGER DEFAULT 0,
    fp_count         INTEGER DEFAULT 0,
    precision        REAL DEFAULT 0.0,
    total_missed     INTEGER DEFAULT 0,
    recall_estimate  REAL DEFAULT 0.0,
    last_updated     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_run     ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_clause  ON findings(clause);
CREATE INDEX IF NOT EXISTS idx_findings_tool    ON findings(source_tool);
CREATE INDEX IF NOT EXISTS idx_labels_finding   ON human_labels(finding_id);
CREATE INDEX IF NOT EXISTS idx_labels_verdict   ON human_labels(verdict);
CREATE INDEX IF NOT EXISTS idx_missed_run       ON missed_vulnerabilities(run_id);
CREATE INDEX IF NOT EXISTS idx_missed_clause    ON missed_vulnerabilities(clause);
"""


def _now_iso() -> str:
    """返回当前 UTC 时间的 ISO 8601 字符串。"""
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    """生成 UUID4 字符串。"""
    return str(uuid.uuid4())


def _json_dumps(obj: Any) -> str:
    """将 Python 对象序列化为 JSON 字符串。"""
    return json.dumps(obj, ensure_ascii=False)


def _json_loads(s: str) -> Any:
    """将 JSON 字符串反序列化为 Python 对象。容错: 空字符串视为 {}。"""
    if not s:
        return {}
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return {}


# ─── 数据库打开 / 迁移 ───────────────────────────────────────────


class FeedbackDB:
    """反馈数据库的读写封装。

    用法:
        db = FeedbackDB(":memory:")          # 内存数据库（测试用）
        db = FeedbackDB("/workspace/feedback/feedback.db")  # 持久化
        db.create_tables()
    """

    def __init__(self, db_path: str) -> None:
        """打开数据库连接。

        Args:
            db_path: SQLite 数据库路径。使用 ":memory:" 表示内存数据库。
        """
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def create_tables(self) -> None:
        """创建所有表和索引（幂等）。"""
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        """关闭数据库连接。"""
        self._conn.close()

    # ─── 上下文管理器 ────────────────────────────────────────────

    def __enter__(self) -> "FeedbackDB":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ─── scan_runs ────────────────────────────────────────────────

    def insert_scan_run(
        self,
        *,
        mode: str = "online",
        total_files: int = 0,
        languages_detected: list[str] | None = None,
        tools_used: list[str] | None = None,
        pre_label_findings: int = 0,
        duration_seconds: int = 0,
    ) -> str:
        """插入一条扫描运行记录。

        Returns:
            新生成的 run_id。
        """
        run_id = _uuid()
        self._conn.execute(
            """INSERT INTO scan_runs
               (run_id, scan_timestamp, mode, total_files, languages_detected,
                tools_used, pre_label_findings, duration_seconds)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                _now_iso(),
                mode,
                total_files,
                _json_dumps(languages_detected or []),
                _json_dumps(tools_used or []),
                pre_label_findings,
                duration_seconds,
            ),
        )
        self._conn.commit()
        return run_id

    def get_scan_run(self, run_id: str) -> dict[str, Any] | None:
        """按 run_id 查询扫描运行记录。"""
        row = self._conn.execute(
            "SELECT * FROM scan_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_scan_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        """列出最近的扫描运行记录。"""
        rows = self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY scan_timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── findings ─────────────────────────────────────────────────

    def insert_finding(
        self,
        *,
        run_id: str,
        clause: str,
        standard: str,
        vuln_name: str,
        category: str = "",
        file_path: str,
        line_start: int,
        line_end: int,
        source_tool: str = "semgrep",
        auto_confidence: float = 0.0,
        code_snippet: str = "",
        tool_raw_output: dict[str, Any] | None = None,
    ) -> str:
        """插入一条漏洞发现。

        Returns:
            新生成的 finding_id。
        """
        finding_id = _uuid()
        self._conn.execute(
            """INSERT INTO findings
               (finding_id, run_id, clause, standard, vuln_name, category,
                file_path, line_start, line_end, source_tool, auto_confidence,
                code_snippet, tool_raw_output)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                run_id,
                clause,
                standard,
                vuln_name,
                category,
                file_path,
                line_start,
                line_end,
                source_tool,
                auto_confidence,
                code_snippet,
                _json_dumps(tool_raw_output or {}),
            ),
        )
        self._conn.commit()
        return finding_id

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        """按 finding_id 查询。"""
        row = self._conn.execute(
            "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_findings_by_run(self, run_id: str) -> list[dict[str, Any]]:
        """查询某次扫描的所有发现。"""
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY clause",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_findings_by_clause(
        self, clause: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """查询某条款号的所有发现（跨扫描）。"""
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE clause = ? ORDER BY run_id DESC LIMIT ?",
            (clause, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def count_findings_by_run(self, run_id: str) -> int:
        """统计某次扫描的总发现数。"""
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM findings WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return row["cnt"] if row else 0

    def count_findings_by_tool(self, run_id: str) -> dict[str, int]:
        """按工具统计某次扫描的发现数。"""
        rows = self._conn.execute(
            "SELECT source_tool, COUNT(*) as cnt FROM findings WHERE run_id = ? GROUP BY source_tool",
            (run_id,),
        ).fetchall()
        return {r["source_tool"]: r["cnt"] for r in rows}

    # ─── human_labels ─────────────────────────────────────────────

    def insert_label(
        self,
        *,
        finding_id: str,
        verdict: str,
        labeler: str = "unknown",
        actual_severity: str = "",
        correction: dict[str, Any] | None = None,
        notes: str = "",
    ) -> str:
        """为一条发现添加人工标注。

        Args:
            finding_id: 关联的发现 ID。
            verdict: "true_positive" / "false_positive" / "not_sure"。
            labeler: 标注人标识。
            actual_severity: 实际严重等级（TP 时有效）。
            correction: FP 时的修正信息。
            notes: 备注。

        Returns:
            新生成的 label_id。

        Raises:
            ValueError: verdict 不是合法值时抛出。
        """
        allowed = {"true_positive", "false_positive", "not_sure"}
        if verdict not in allowed:
            raise ValueError(f"verdict 必须为 {allowed} 之一，实际为 '{verdict}'")

        label_id = _uuid()
        self._conn.execute(
            """INSERT INTO human_labels
               (label_id, finding_id, labeler, label_timestamp, verdict,
                actual_severity, correction, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                label_id,
                finding_id,
                labeler,
                _now_iso(),
                verdict,
                actual_severity,
                _json_dumps(correction or {}),
                notes,
            ),
        )
        self._conn.commit()
        return label_id

    def get_labels_by_finding(self, finding_id: str) -> list[dict[str, Any]]:
        """查询某条发现的所有标注记录。"""
        rows = self._conn.execute(
            "SELECT * FROM human_labels WHERE finding_id = ? ORDER BY label_timestamp DESC",
            (finding_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_labels_by_run(self, run_id: str) -> list[dict[str, Any]]:
        """查询某次扫描的所有标注。"""
        rows = self._conn.execute(
            """SELECT hl.* FROM human_labels hl
               JOIN findings f ON hl.finding_id = f.finding_id
               WHERE f.run_id = ?
               ORDER BY hl.label_timestamp DESC""",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── 误报率统计 ───────────────────────────────────────────────

    def get_fp_ratio(self, clause: str, recent_runs: int = 3) -> dict[str, Any]:
        """计算某条款号在最近 N 次扫描中的误报情况。

        Args:
            clause: 条款号。
            recent_runs: 统计最近几次扫描（按时间降序）。

        Returns:
            {"total_labeled": N, "tp": N, "fp": N, "not_sure": N, "fp_ratio": 0.0-1.0}
        """
        # 取最近 N 个 run_id
        run_ids = [
            r["run_id"]
            for r in self._conn.execute(
                "SELECT DISTINCT run_id FROM findings WHERE clause = ? ORDER BY run_id DESC LIMIT ?",
                (clause, recent_runs),
            ).fetchall()
        ]

        if not run_ids:
            return {"total_labeled": 0, "tp": 0, "fp": 0, "not_sure": 0, "fp_ratio": 0.0}

        placeholders = ",".join("?" for _ in run_ids)
        rows = self._conn.execute(
            f"""SELECT hl.verdict, COUNT(*) as cnt
                FROM human_labels hl
                JOIN findings f ON hl.finding_id = f.finding_id
                WHERE f.clause = ? AND f.run_id IN ({placeholders})
                GROUP BY hl.verdict""",
            (clause, *run_ids),
        ).fetchall()

        counts = {r["verdict"]: r["cnt"] for r in rows}
        tp = counts.get("true_positive", 0)
        fp = counts.get("false_positive", 0)
        ns = counts.get("not_sure", 0)
        total = tp + fp + ns
        fp_ratio = fp / total if total > 0 else 0.0

        return {
            "total_labeled": total,
            "tp": tp,
            "fp": fp,
            "not_sure": ns,
            "fp_ratio": fp_ratio,
        }

    # ─── missed_vulnerabilities ───────────────────────────────────

    def insert_missed(
        self,
        *,
        run_id: str,
        clause: str,
        file_path: str,
        line_start: int,
        line_end: int,
        reported_by: str = "unknown",
        description: str = "",
        why_missed: str = "",
        code_snippet: str = "",
        fix_suggestion: str = "",
    ) -> str:
        """补录一条漏报（人工发现但工具未检出）。

        Returns:
            新生成的 missed_id。
        """
        missed_id = _uuid()
        self._conn.execute(
            """INSERT INTO missed_vulnerabilities
               (missed_id, run_id, clause, file_path, line_start, line_end,
                reported_by, report_timestamp, description, why_missed,
                code_snippet, fix_suggestion)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                missed_id,
                run_id,
                clause,
                file_path,
                line_start,
                line_end,
                reported_by,
                _now_iso(),
                description,
                why_missed,
                code_snippet,
                fix_suggestion,
            ),
        )
        self._conn.commit()
        return missed_id

    def get_missed_by_run(self, run_id: str) -> list[dict[str, Any]]:
        """查询某次扫描的所有漏报。"""
        rows = self._conn.execute(
            "SELECT * FROM missed_vulnerabilities WHERE run_id = ? ORDER BY clause",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def count_missed_by_clause(self) -> list[dict[str, Any]]:
        """按条款号统计漏报数。"""
        rows = self._conn.execute(
            """SELECT clause, COUNT(*) as cnt
               FROM missed_vulnerabilities
               GROUP BY clause ORDER BY cnt DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── rule_effectiveness ───────────────────────────────────────

    def upsert_rule_effectiveness(self) -> int:
        """基于 human_labels 和 missed_vulnerabilities 全量刷新规则效果统计。

        对每个有标注的 clause，计算 precision = tp / (tp + fp)。

        Returns:
            更新的行数。
        """
        # 从 human_labels 聚合
        self._conn.execute("DELETE FROM rule_effectiveness")

        self._conn.execute(
            """INSERT INTO rule_effectiveness
               (clause, standard, vuln_name, total_findings, tp_count, fp_count,
                precision, total_missed, recall_estimate, last_updated)
               SELECT
                   f.clause,
                   f.standard,
                   f.vuln_name,
                   COUNT(DISTINCT f.finding_id) AS total_findings,
                   COALESCE(SUM(CASE WHEN hl.verdict = 'true_positive' THEN 1 ELSE 0 END), 0) AS tp_count,
                   COALESCE(SUM(CASE WHEN hl.verdict = 'false_positive' THEN 1 ELSE 0 END), 0) AS fp_count,
                   CASE
                       WHEN COALESCE(SUM(CASE WHEN hl.verdict IN ('true_positive','false_positive') THEN 1 ELSE 0 END), 0) > 0
                       THEN ROUND(
                           CAST(COALESCE(SUM(CASE WHEN hl.verdict = 'true_positive' THEN 1 ELSE 0 END), 0) AS REAL)
                           / CAST(SUM(CASE WHEN hl.verdict IN ('true_positive','false_positive') THEN 1 ELSE 0 END) AS REAL),
                           4
                       )
                       ELSE 0.0
                   END AS precision,
                   COALESCE((SELECT COUNT(*) FROM missed_vulnerabilities mv WHERE mv.clause = f.clause), 0) AS total_missed,
                   0.0 AS recall_estimate,
                   ? AS last_updated
               FROM findings f
               LEFT JOIN human_labels hl ON f.finding_id = hl.finding_id
               GROUP BY f.clause, f.standard
               HAVING COUNT(DISTINCT f.finding_id) > 0""",
            (_now_iso(),),
        )
        self._conn.commit()
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM rule_effectiveness").fetchone()
        return row["cnt"] if row else 0

    def get_rule_effectiveness(self, clause: str) -> dict[str, Any] | None:
        """获取某条款的规则效果统计。"""
        row = self._conn.execute(
            "SELECT * FROM rule_effectiveness WHERE clause = ?", (clause,)
        ).fetchone()
        return dict(row) if row else None

    def list_rule_effectiveness(
        self, min_findings: int = 0, order_by: str = "precision"
    ) -> list[dict[str, Any]]:
        """列出所有规则效果。可按 precision 升序（找误报高的）或降序。"""
        direction = "ASC" if order_by == "precision" else "DESC"
        rows = self._conn.execute(
            f"""SELECT * FROM rule_effectiveness
                WHERE total_findings >= ?
                ORDER BY {order_by} {direction}""",
            (min_findings,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_low_precision_rules(
        self, threshold: float = 0.6, min_findings: int = 5
    ) -> list[dict[str, Any]]:
        """返回 precision 低于阈值（误报率高）的规则。

        Args:
            threshold: 精确率阈值。低于此值表示误报率高。
            min_findings: 最少有多少标注才纳入统计。

        Returns:
            低精度规则列表，按 precision 升序（最差的排最前）。
        """
        rows = self._conn.execute(
            """SELECT * FROM rule_effectiveness
               WHERE precision < ? AND total_findings >= ?
               ORDER BY precision ASC""",
            (threshold, min_findings),
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── 跨表查询 ─────────────────────────────────────────────────

    def get_findings_with_labels(
        self, run_id: str
    ) -> list[dict[str, Any]]:
        """查询某次扫描的所有发现及其标注状态。

        Returns:
            每条发现附带 label_verdict / label_notes / severity 字段。
        """
        rows = self._conn.execute(
            """SELECT f.*,
                      hl.verdict   AS label_verdict,
                      hl.notes     AS label_notes,
                      hl.actual_severity AS label_severity
               FROM findings f
               LEFT JOIN human_labels hl ON f.finding_id = hl.finding_id
               WHERE f.run_id = ?
               ORDER BY f.clause, f.file_path, f.line_start""",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_run_summary(self, run_id: str) -> dict[str, Any]:
        """获取某次扫描的汇总统计。

        Returns:
            {run_info, total_findings, labeled_count, tp, fp, missed_count, ...}
        """
        run_info = self.get_scan_run(run_id)
        if not run_info:
            return {}

        total = self.count_findings_by_run(run_id)
        missed_count = len(self.get_missed_by_run(run_id))

        # 标注统计
        labels = self.get_labels_by_run(run_id)
        tp = sum(1 for l in labels if l["verdict"] == "true_positive")
        fp = sum(1 for l in labels if l["verdict"] == "false_positive")
        ns = sum(1 for l in labels if l["verdict"] == "not_sure")

        return {
            "run_info": run_info,
            "total_findings": total,
            "labeled_count": len(labels),
            "tp": tp,
            "fp": fp,
            "not_sure": ns,
            "missed_count": missed_count,
            "fp_ratio": fp / (tp + fp) if (tp + fp) > 0 else 0.0,
        }

"""测试 rule_tuner.py —— 规则自动调优模块。

所有测试使用内存 FeedbackDB，基于真实标注数据验证调优逻辑。
"""

from __future__ import annotations

import pytest

from src.feedback_db import FeedbackDB
from src.rule_tuner import RuleTuner, TuningAdvice, TuningReport


# ─── fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def db() -> FeedbackDB:
    """创建一个有已知标注数据的内存数据库。"""
    database = FeedbackDB(":memory:")
    database.create_tables()
    return database


@pytest.fixture
def db_healthy(db: FeedbackDB) -> FeedbackDB:
    """规则运行良好：FP 率低的数据库，足够数据量。"""
    run_id = db.insert_scan_run(mode="online")
    for i in range(6):
        fid = db.insert_finding(
            run_id=run_id, clause="6.2.3.4", standard="GB/T 34944-2017",
            vuln_name="SQL注入", category="数据处理",
            file_path=f"File{i}.java", line_start=i * 10 + 1, line_end=i * 10 + 5,
            source_tool="semgrep", auto_confidence=0.9,
            code_snippet=f'query = "SELECT * FROM t WHERE id=\'" + uid{i} + "\'"',
        )
        # 5 TP, 1 FP → precision = 0.833
        if i < 5:
            db.insert_label(finding_id=fid, verdict="true_positive", notes=f"真实SQL注入{i}")
        else:
            db.insert_label(finding_id=fid, verdict="false_positive", notes="误报")
    return db


@pytest.fixture
def db_high_fp(db: FeedbackDB) -> FeedbackDB:
    """误报率高的数据库：某规则 5 条发现中 4 条是 FP，FP 率=80%。"""
    run_id = db.insert_scan_run(mode="online")
    for i in range(5):
        fid = db.insert_finding(
            run_id=run_id, clause="6.2.6.6", standard="GB/T 34944-2017",
            vuln_name="敏感信息明文传输", category="安全功能",
            file_path=f"File{i}.java", line_start=i * 5 + 1, line_end=i * 5 + 3,
            source_tool="semgrep", auto_confidence=0.7,
            code_snippet=f'sendMessage("log message {i}")',
        )
        if i == 0:
            db.insert_label(finding_id=fid, verdict="true_positive",
                          notes="确实明文传输了password")
        else:
            db.insert_label(finding_id=fid, verdict="false_positive",
                          notes="传输的是日志消息，非敏感信息",
                          correction={"why_not_vuln": "参数是日志消息"})
    return db


@pytest.fixture
def db_with_missed(db: FeedbackDB) -> FeedbackDB:
    """有漏报记录的数据库。"""
    run_id = db.insert_scan_run(mode="online")
    fid = db.insert_finding(
        run_id=run_id, clause="6.2.3.4", standard="GB/T 34944-2017",
        vuln_name="SQL注入", file_path="A.java",
        line_start=1, line_end=5, source_tool="semgrep",
        auto_confidence=0.9, code_snippet="select",
    )
    db.insert_label(finding_id=fid, verdict="true_positive")
    db.insert_missed(
        run_id=run_id, clause="6.2.3.4",
        file_path="UserController.java", line_start=56, line_end=60,
        reported_by="auditor",
        description="Spring JdbcTemplate.query拼接SQL",
        why_missed="Semgrep规则未覆盖JdbcTemplate.query() Sink",
        code_snippet='jdbcTemplate.query("SELECT * FROM users WHERE name=\'" + n + "\'")',
    )
    return db


# ─── 空数据库 ─────────────────────────────────────────────────────


class TestEmptyDatabase:
    """空数据库的分析。"""

    def test_no_feedback_data(self, db: FeedbackDB) -> None:
        """无任何标注数据时应返回空报告。"""
        tuner = RuleTuner(db)
        report = tuner.analyze()

        assert isinstance(report, TuningReport)
        assert len(report.advices) == 0
        assert report.rules_with_issues == 0


# ─── 正常运行 ─────────────────────────────────────────────────────


class TestHealthyRule:
    """规则运行良好的情况。"""

    def test_low_fp_rate_no_action(self, db_healthy: FeedbackDB) -> None:
        """FP 率低时 action 应为 none。"""
        tuner = RuleTuner(db_healthy)
        report = tuner.analyze()

        assert len(report.advices) == 1  # 只有 6.2.3.4 有数据
        advice = report.advices[0]
        assert advice.clause == "6.2.3.4"
        assert advice.action == "none"
        assert advice.severity == "info"
        assert "运行良好" in advice.reason
        assert report.rules_healthy == 1
        assert report.rules_with_issues == 0


# ─── 高误报 ───────────────────────────────────────────────────────


class TestHighFpRate:
    """高误报率的处理。"""

    def test_high_fp_triggers_adjust(self, db_high_fp: FeedbackDB) -> None:
        """FP 率 ≥ 80% 时应触发 adjust。"""
        tuner = RuleTuner(db_high_fp)
        report = tuner.analyze()

        advice = report.advices[0]
        assert advice.clause == "6.2.6.6"
        assert advice.action == "adjust"
        assert advice.severity == "critical"
        assert advice.fp_ratio > 0.5

    def test_fp_patterns_extracted(self, db_high_fp: FeedbackDB) -> None:
        """应提取 FP 案例的代码模式。"""
        tuner = RuleTuner(db_high_fp)
        report = tuner.analyze()

        advice = report.advices[0]
        # 应有 pattern_not 建议
        assert len(advice.pattern_not_additions) > 0
        assert len(advice.fp_examples) > 0

    def test_fp_ratio_calculation(self, db_high_fp: FeedbackDB) -> None:
        """FP 率计算应正确。"""
        stats = db_high_fp.get_fp_ratio("6.2.6.6")
        assert stats["tp"] == 1
        assert stats["fp"] == 4
        assert stats["fp_ratio"] == 0.8


# ─── 漏报 ────────────────────────────────────────────────────────


class TestMissedVulnerabilities:
    """漏报分析。"""

    def test_missed_triggers_extend_sink(self, db_with_missed: FeedbackDB) -> None:
        """有漏报时应建议扩展 Sink 覆盖。"""
        tuner = RuleTuner(db_with_missed)
        report = tuner.analyze()

        advice = report.advices[0]
        assert advice.missed_count >= 1
        # 应检测到缺失的 JdbcTemplate.query()
        assert len(advice.new_sinks) > 0
        assert any("query" in s.lower() or "JdbcTemplate" in s for s in advice.new_sinks)

    def test_missed_mentioned_in_reason(self, db_with_missed: FeedbackDB) -> None:
        """漏报信息应出现在 reason 中。"""
        tuner = RuleTuner(db_with_missed)
        report = tuner.analyze()

        advice = report.advices[0]
        assert "漏报" in advice.reason


# ─── 连续高误报 ──────────────────────────────────────────────────

# Note: _count_consecutive_high_fp 依赖多次独立扫描的 scan_runs，
# 这里用一个辅助方法来构造多轮数据
class TestConsecutiveHighFp:
    """连续多轮高误报的检测。"""

    def _create_scan_with_fp_ratio(
        self, db: FeedbackDB, clause: str, fp_ratio: float
    ) -> None:
        """创建一轮扫描，设置指定的 FP 率。"""
        run_id = db.insert_scan_run(mode="online")
        tp_count = max(1, int(3 * (1 - fp_ratio)))
        fp_count = max(1, int(3 * fp_ratio))

        for i in range(tp_count):
            fid = db.insert_finding(
                run_id=run_id, clause=clause,
                standard="GB/T 34944-2017", vuln_name="test",
                file_path=f"tp{i}.java", line_start=i, line_end=i,
                source_tool="semgrep", auto_confidence=0.5,
            )
            db.insert_label(finding_id=fid, verdict="true_positive")

        for i in range(fp_count):
            fid = db.insert_finding(
                run_id=run_id, clause=clause,
                standard="GB/T 34944-2017", vuln_name="test",
                file_path=f"fp{i}.java", line_start=100 + i, line_end=100 + i,
                source_tool="semgrep", auto_confidence=0.5,
            )
            db.insert_label(finding_id=fid, verdict="false_positive")

    def test_single_scan_high_fp_not_consecutive(self, db: FeedbackDB) -> None:
        """单次扫描高 FP 不应计为连续。"""
        self._create_scan_with_fp_ratio(db, "6.2.6.4", 0.75)

        tuner = RuleTuner(db)
        consecutive = tuner._count_consecutive_high_fp("6.2.6.4")
        assert consecutive == 1  # 只有 1 次

    def test_multiple_consecutive_high_fp(self, db: FeedbackDB) -> None:
        """多次连续高 FP 应正确计数。"""
        for _ in range(4):
            self._create_scan_with_fp_ratio(db, "6.2.6.4", 0.75)

        tuner = RuleTuner(db)
        consecutive = tuner._count_consecutive_high_fp("6.2.6.4")
        assert consecutive >= 3  # 至少触发 warn

    def test_high_fp_then_normal_breaks_consecutive(self, db: FeedbackDB) -> None:
        """中间有正常扫描应中断连续计数。"""
        # 先 2 轮高 FP
        self._create_scan_with_fp_ratio(db, "6.2.5.2", 0.75)
        self._create_scan_with_fp_ratio(db, "6.2.5.2", 0.75)
        # 再 1 轮正常
        self._create_scan_with_fp_ratio(db, "6.2.5.2", 0.1)
        # 再 1 轮高 FP
        self._create_scan_with_fp_ratio(db, "6.2.5.2", 0.75)

        tuner = RuleTuner(db)
        consecutive = tuner._count_consecutive_high_fp("6.2.5.2")
        assert consecutive == 1  # 被正常扫描中断


# ─── LLM Few-Shot 案例 ────────────────────────────────────────────


class TestFewShotExamples:
    """Few-Shot 案例提取。"""

    def test_tp_examples_extracted(self, db_healthy: FeedbackDB) -> None:
        """应从 TP 标注中提取案例。"""
        tuner = RuleTuner(db_healthy)
        report = tuner.analyze()

        assert len(report.tp_examples_for_llm) > 0
        example = report.tp_examples_for_llm[0]
        assert example["type"] == "tp"
        assert "code" in example
        assert "reason" in example

    def test_fp_examples_extracted(self, db_high_fp: FeedbackDB) -> None:
        """应从 FP 标注中提取案例。"""
        tuner = RuleTuner(db_high_fp)
        report = tuner.analyze()

        assert len(report.fp_examples_for_llm) > 0
        example = report.fp_examples_for_llm[0]
        assert example["type"] == "fp"
        assert "distinction" in example  # FP 案例有关键区别字段


# ─── 报告摘要 ─────────────────────────────────────────────────────


class TestSummaryGeneration:
    """测试报告摘要生成。"""

    def test_summary_contains_stats(self, db_healthy: FeedbackDB) -> None:
        """摘要应包含统计数据。"""
        tuner = RuleTuner(db_healthy)
        report = tuner.analyze()

        assert len(report.summary) > 0
        assert "规则调优分析报告" in report.summary
        assert str(len(report.advices)) in report.summary

    def test_summary_lists_critical_issues(self, db_high_fp: FeedbackDB) -> None:
        """摘要应列出严重问题。"""
        tuner = RuleTuner(db_high_fp)
        report = tuner.analyze()

        # 有 critical 级别的建议时，摘要应包含"严重问题"
        has_critical = any(a.severity == "critical" for a in report.advices)
        if has_critical:
            assert "严重问题" in report.summary


# ─── TuningAdvice 数据类 ─────────────────────────────────────────


class TestTuningAdvice:
    """测试 TuningAdvice 数据类的默认值。"""

    def test_defaults(self) -> None:
        a = TuningAdvice(clause="6.2.3.4")
        assert a.clause == "6.2.3.4"
        assert a.action == ""
        assert a.fp_ratio == 0.0
        assert a.missed_count == 0
        assert a.pattern_not_additions == []
        assert a.new_sinks == []


# ─── 无 kb 降级 ─────────────────────────────────────────────────


class TestWithoutKB:
    """无 KnowledgeBase 时应正常运作。"""

    def test_analyze_without_kb(self, db_healthy: FeedbackDB) -> None:
        """不传 kb 时调优分析仍能运行。"""
        tuner = RuleTuner(db_healthy, kb=None)
        report = tuner.analyze()

        assert len(report.advices) > 0
        # vuln_name 来自 rule_effectiveness 表，与 kb 无关


# ─── 阈值配置 ────────────────────────────────────────────────────


class TestThresholds:
    """测试阈值常量。"""

    def test_default_thresholds(self) -> None:
        """默认阈值应与设计文档一致。"""
        assert RuleTuner.THRESHOLD_SINGLE_FP_HIGH == 0.80
        assert RuleTuner.THRESHOLD_CONSECUTIVE_WARN == 0.50
        assert RuleTuner.CONSECUTIVE_RUNS_WARN == 3
        assert RuleTuner.CONSECUTIVE_RUNS_DISABLE == 5

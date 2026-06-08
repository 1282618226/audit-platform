"""测试 feedback_db.py —— SQLite 反馈数据库模块。

所有测试使用 :memory: 数据库，不写磁盘文件。
"""

import pytest

from src.feedback_db import FeedbackDB


# ─── fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def db() -> FeedbackDB:
    """提供已建表的内存数据库。"""
    database = FeedbackDB(":memory:")
    database.create_tables()
    return database


@pytest.fixture
def db_with_data(db: FeedbackDB) -> FeedbackDB:
    """提供已插入一次扫描 + 发现 + 标注的数据库。"""
    run_id = db.insert_scan_run(
        mode="online",
        total_files=5,
        languages_detected=["Java", "C"],
        tools_used=["semgrep", "codeql"],
        pre_label_findings=4,
        duration_seconds=120,
    )

    # 插入 4 条发现
    f1 = db.insert_finding(
        run_id=run_id,
        clause="6.2.3.4",
        standard="GB/T 34944-2017",
        vuln_name="SQL注入",
        category="数据处理",
        file_path="src/Login.java",
        line_start=42,
        line_end=48,
        source_tool="semgrep",
        auto_confidence=0.9,
        code_snippet='String q = "SELECT * FROM users WHERE id=\'" + uid + "\'";',
        tool_raw_output={"rule": "java-sql-injection"},
    )
    f2 = db.insert_finding(
        run_id=run_id,
        clause="6.2.3.4",
        standard="GB/T 34944-2017",
        vuln_name="SQL注入",
        category="数据处理",
        file_path="src/UserController.java",
        line_start=56,
        line_end=60,
        source_tool="codeql",
        auto_confidence=0.85,
        code_snippet='jdbcTemplate.query("SELECT * FROM users WHERE name=\'" + name + "\'")',
        tool_raw_output={"query": "java/sql-injection"},
    )
    f3 = db.insert_finding(
        run_id=run_id,
        clause="6.2.6.3",
        standard="GB/T 34944-2017",
        vuln_name="口令硬编码",
        category="安全功能",
        file_path="src/Config.java",
        line_start=10,
        line_end=12,
        source_tool="semgrep",
        auto_confidence=0.95,
        code_snippet='if ("admin123".equals(password))',
    )
    f4 = db.insert_finding(
        run_id=run_id,
        clause="7.2.3.6",
        standard="GB/T 34943-2017",
        vuln_name="缓冲区溢出",
        category="数据处理",
        file_path="src/buffer.c",
        line_start=20,
        line_end=22,
        source_tool="semgrep",
        auto_confidence=0.7,
        code_snippet="strcpy(buf, user_input);",
    )

    # 标注
    db.insert_label(finding_id=f1, verdict="true_positive", labeler="auditor1",
                    actual_severity="高", notes="明显的SQL注入")
    db.insert_label(finding_id=f2, verdict="true_positive", labeler="auditor1",
                    actual_severity="高", notes="Spring JdbcTemplate拼接")
    db.insert_label(finding_id=f3, verdict="false_positive", labeler="auditor1",
                    notes="实际是测试代码中的mock常量，非生产代码")
    # f4 不标注

    # 漏报
    db.insert_missed(
        run_id=run_id,
        clause="6.2.3.5",
        file_path="src/ScriptRunner.java",
        line_start=33,
        line_end=35,
        reported_by="auditor2",
        description="代码注入：ScriptEngine.eval()直接执行用户输入",
        why_missed="Semgrep规则未覆盖javax.script.ScriptEngine.eval()",
        code_snippet='engine.eval(userScript);',
        fix_suggestion="增加Semgrep规则覆盖ScriptEngine.eval()",
    )

    return db


# ─── 表创建 ───────────────────────────────────────────────────────


class TestTableCreation:
    """测试数据库表创建。"""

    def test_create_tables_no_error(self, db: FeedbackDB) -> None:
        """建表不应抛出异常。"""
        # create_tables 已在 fixture 中调用，这里验证可重复调用
        db.create_tables()  # 幂等

    def test_all_tables_exist(self, db: FeedbackDB) -> None:
        """5 张核心表均应存在。"""
        tables = {"scan_runs", "findings", "human_labels",
                   "missed_vulnerabilities", "rule_effectiveness"}
        row = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        actual = {r["name"] for r in row}
        assert tables.issubset(actual)


# ─── scan_runs ────────────────────────────────────────────────────


class TestScanRuns:
    """测试扫描运行记录。"""

    def test_insert_and_get(self, db: FeedbackDB) -> None:
        """插入后应能按 run_id 查回。"""
        run_id = db.insert_scan_run(
            mode="offline",
            total_files=10,
            languages_detected=["Java"],
            tools_used=["semgrep"],
        )
        run = db.get_scan_run(run_id)
        assert run is not None
        assert run["mode"] == "offline"
        assert run["total_files"] == 10

    def test_get_nonexistent(self, db: FeedbackDB) -> None:
        """不存在的 run_id 返回 None。"""
        assert db.get_scan_run("nonexistent-id") is None

    def test_list_scan_runs(self, db: FeedbackDB) -> None:
        """列出扫描记录应按时间降序。"""
        db.insert_scan_run(mode="first")
        db.insert_scan_run(mode="second")
        runs = db.list_scan_runs(limit=10)
        assert len(runs) == 2
        # 后插入的排在前面
        assert runs[0]["mode"] == "second"
        assert runs[1]["mode"] == "first"


# ─── findings ─────────────────────────────────────────────────────


class TestFindings:
    """测试漏洞发现记录。"""

    @pytest.fixture
    def run_id(self, db: FeedbackDB) -> str:
        return db.insert_scan_run()

    def test_insert_and_get(self, db: FeedbackDB, run_id: str) -> None:
        """插入发现后应能查回。"""
        fid = db.insert_finding(
            run_id=run_id,
            clause="6.2.3.4",
            standard="GB/T 34944-2017",
            vuln_name="SQL注入",
            file_path="src/Test.java",
            line_start=1,
            line_end=5,
            source_tool="semgrep",
            auto_confidence=0.88,
        )
        finding = db.get_finding(fid)
        assert finding is not None
        assert finding["clause"] == "6.2.3.4"
        assert finding["vuln_name"] == "SQL注入"
        assert finding["auto_confidence"] == 0.88
        assert finding["line_start"] == 1
        assert finding["line_end"] == 5

    def test_get_nonexistent(self, db: FeedbackDB) -> None:
        """不存在的 finding_id 返回 None。"""
        assert db.get_finding("nonexistent") is None

    def test_get_findings_by_run(self, db_with_data: FeedbackDB) -> None:
        """按 run_id 查询发现列表。"""
        runs = db_with_data.list_scan_runs()
        run_id = runs[0]["run_id"]
        findings = db_with_data.get_findings_by_run(run_id)
        assert len(findings) == 4

    def test_get_findings_by_clause(self, db_with_data: FeedbackDB) -> None:
        """按条款号跨扫描查询。"""
        findings = db_with_data.get_findings_by_clause("6.2.3.4")
        assert len(findings) == 2
        for f in findings:
            assert f["vuln_name"] == "SQL注入"

    def test_count_findings_by_run(self, db_with_data: FeedbackDB) -> None:
        """按 run_id 计数。"""
        runs = db_with_data.list_scan_runs()
        run_id = runs[0]["run_id"]
        assert db_with_data.count_findings_by_run(run_id) == 4

    def test_count_findings_by_tool(self, db_with_data: FeedbackDB) -> None:
        """按工具统计发现数。"""
        runs = db_with_data.list_scan_runs()
        run_id = runs[0]["run_id"]
        counts = db_with_data.count_findings_by_tool(run_id)
        assert counts["semgrep"] == 3
        assert counts["codeql"] == 1

    def test_finding_with_tool_raw_output(self, db: FeedbackDB, run_id: str) -> None:
        """tool_raw_output 应正确序列化/反序列化。"""
        raw = {"rule_id": "java-sql-injection", "severity": "ERROR"}
        fid = db.insert_finding(
            run_id=run_id,
            clause="6.2.3.4",
            standard="GB/T 34944-2017",
            vuln_name="SQL注入",
            file_path="src/Test.java",
            line_start=1,
            line_end=2,
            tool_raw_output=raw,
        )
        finding = db.get_finding(fid)
        assert finding is not None
        # tool_raw_output 以 JSON 字符串存储
        assert '"rule_id"' in finding["tool_raw_output"]


# ─── human_labels ─────────────────────────────────────────────────


class TestHumanLabels:
    """测试人工标注。"""

    @pytest.fixture
    def fid(self, db: FeedbackDB) -> str:
        run_id = db.insert_scan_run()
        return db.insert_finding(
            run_id=run_id,
            clause="6.2.3.4",
            standard="GB/T 34944-2017",
            vuln_name="SQL注入",
            file_path="src/Test.java",
            line_start=1,
            line_end=2,
        )

    def test_insert_true_positive(self, db: FeedbackDB, fid: str) -> None:
        """标注真阳性。"""
        lid = db.insert_label(
            finding_id=fid,
            verdict="true_positive",
            labeler="tester",
            actual_severity="高",
        )
        labels = db.get_labels_by_finding(fid)
        assert len(labels) == 1
        assert labels[0]["verdict"] == "true_positive"
        assert labels[0]["actual_severity"] == "高"

    def test_insert_false_positive(self, db: FeedbackDB, fid: str) -> None:
        """标注假阳性。"""
        lid = db.insert_label(
            finding_id=fid,
            verdict="false_positive",
            correction={"why": "测试代码"},
            notes="非生产环境",
        )
        labels = db.get_labels_by_finding(fid)
        assert labels[0]["verdict"] == "false_positive"

    def test_insert_not_sure(self, db: FeedbackDB, fid: str) -> None:
        """标注不确定。"""
        db.insert_label(finding_id=fid, verdict="not_sure")
        labels = db.get_labels_by_finding(fid)
        assert labels[0]["verdict"] == "not_sure"

    def test_invalid_verdict_raises(self, db: FeedbackDB, fid: str) -> None:
        """非法 verdict 应抛出 ValueError。"""
        with pytest.raises(ValueError, match="verdict 必须为"):
            db.insert_label(finding_id=fid, verdict="maybe")

    def test_multiple_labels_same_finding(self, db: FeedbackDB, fid: str) -> None:
        """同一发现可被多次标注（如复审）。"""
        db.insert_label(finding_id=fid, verdict="false_positive", labeler="auditor1")
        db.insert_label(finding_id=fid, verdict="true_positive", labeler="auditor2")
        labels = db.get_labels_by_finding(fid)
        assert len(labels) == 2
        # 按时间降序排列，最新的在前
        assert labels[0]["labeler"] == "auditor2"


# ─── FP 率统计 ────────────────────────────────────────────────────


class TestFpRatio:
    """测试误报率计算。"""

    def test_fp_ratio_with_mixed_labels(self, db_with_data: FeedbackDB) -> None:
        """混合 TP/FP 时的误报率。"""
        result = db_with_data.get_fp_ratio("6.2.3.4")
        assert result["tp"] == 2
        assert result["fp"] == 0
        assert result["fp_ratio"] == 0.0

    def test_fp_ratio_single_fp(self, db_with_data: FeedbackDB) -> None:
        """纯 FP 时误报率应为 1.0。"""
        result = db_with_data.get_fp_ratio("6.2.6.3")
        assert result["tp"] == 0
        assert result["fp"] == 1
        assert result["fp_ratio"] == 1.0

    def test_fp_ratio_no_labels(self, db_with_data: FeedbackDB) -> None:
        """无标注时返回全零。"""
        result = db_with_data.get_fp_ratio("7.2.3.6")
        assert result["total_labeled"] == 0
        assert result["fp_ratio"] == 0.0

    def test_fp_ratio_nonexistent_clause(self, db_with_data: FeedbackDB) -> None:
        """不存在的条款号返回全零。"""
        result = db_with_data.get_fp_ratio("9.9.9.9")
        assert result["total_labeled"] == 0


# ─── missed_vulnerabilities ───────────────────────────────────────


class TestMissedVulnerabilities:
    """测试漏报记录。"""

    @pytest.fixture
    def run_id(self, db: FeedbackDB) -> str:
        return db.insert_scan_run()

    def test_insert_and_get(self, db: FeedbackDB, run_id: str) -> None:
        """插入漏报后应能查回。"""
        mid = db.insert_missed(
            run_id=run_id,
            clause="6.2.3.5",
            file_path="src/Inject.java",
            line_start=10,
            line_end=12,
            reported_by="auditor",
            description="代码注入",
            why_missed="规则未覆盖ScriptEngine",
        )
        missed = db.get_missed_by_run(run_id)
        assert len(missed) == 1
        assert missed[0]["clause"] == "6.2.3.5"
        assert missed[0]["why_missed"] == "规则未覆盖ScriptEngine"

    def test_get_missed_by_run_empty(self, db: FeedbackDB, run_id: str) -> None:
        """无漏报时返回空列表。"""
        missed = db.get_missed_by_run(run_id)
        assert missed == []

    def test_count_missed_by_clause(self, db: FeedbackDB, run_id: str) -> None:
        """按条款号统计漏报数。"""
        db.insert_missed(run_id=run_id, clause="6.2.3.4", file_path="f1.java",
                         line_start=1, line_end=2, description="SQL注入")
        db.insert_missed(run_id=run_id, clause="6.2.3.4", file_path="f2.java",
                         line_start=5, line_end=6, description="SQL注入2")
        db.insert_missed(run_id=run_id, clause="7.2.3.6", file_path="f3.c",
                         line_start=1, line_end=2, description="缓冲区溢出")

        counts = db.count_missed_by_clause()
        # 按 cnt DESC 排序
        assert counts[0]["clause"] == "6.2.3.4"
        assert counts[0]["cnt"] == 2
        assert counts[1]["clause"] == "7.2.3.6"
        assert counts[1]["cnt"] == 1


# ─── rule_effectiveness ───────────────────────────────────────────


class TestRuleEffectiveness:
    """测试规则效果统计。"""

    def test_upsert_from_data(self, db_with_data: FeedbackDB) -> None:
        """从标注数据生成规则效果统计。"""
        count = db_with_data.upsert_rule_effectiveness()
        assert count > 0

        # 6.2.3.4: 2 TP, 0 FP → precision = 1.0
        eff = db_with_data.get_rule_effectiveness("6.2.3.4")
        assert eff is not None
        assert eff["tp_count"] == 2
        assert eff["fp_count"] == 0
        assert eff["precision"] == 1.0
        # 漏报: 0 (6.2.3.4 没有漏报)
        assert eff["total_missed"] == 0

        # 6.2.6.3: 0 TP, 1 FP → precision = 0.0
        eff = db_with_data.get_rule_effectiveness("6.2.6.3")
        assert eff is not None
        assert eff["tp_count"] == 0
        assert eff["fp_count"] == 1
        assert eff["precision"] == 0.0

    def test_get_nonexistent(self, db: FeedbackDB) -> None:
        """无数据的条款返回 None。"""
        db.upsert_rule_effectiveness()
        assert db.get_rule_effectiveness("9.9.9.9") is None

    def test_low_precision_rules(self, db_with_data: FeedbackDB) -> None:
        """应能找出低精度的规则。"""
        db_with_data.upsert_rule_effectiveness()
        # 6.2.6.3 有 1 FP, precision=0.0，但 min_findings=5 筛掉了
        low = db_with_data.get_low_precision_rules(threshold=0.6, min_findings=1)
        clauses = {r["clause"] for r in low}
        assert "6.2.6.3" in clauses

    def test_list_rule_effectiveness(self, db_with_data: FeedbackDB) -> None:
        """列出所有规则效果。"""
        db_with_data.upsert_rule_effectiveness()
        rules = db_with_data.list_rule_effectiveness()
        assert len(rules) == 3  # 3 个有 findings 的条款

    def test_empty_db_no_error(self, db: FeedbackDB) -> None:
        """空数据库 upsert 不应报错。"""
        count = db.upsert_rule_effectiveness()
        assert count == 0


# ─── 跨表查询 ─────────────────────────────────────────────────────


class TestCrossTableQueries:
    """测试跨表联合查询。"""

    @pytest.fixture
    def run_id(self, db_with_data: FeedbackDB) -> str:
        runs = db_with_data.list_scan_runs()
        return runs[0]["run_id"]

    def test_get_findings_with_labels(self, db_with_data: FeedbackDB, run_id: str) -> None:
        """发现应附带标注状态。"""
        results = db_with_data.get_findings_with_labels(run_id)
        assert len(results) == 4

        # 有标注的
        labeled = [r for r in results if r["label_verdict"] is not None]
        assert len(labeled) == 3

        # f4 无标注 → label_verdict = None
        unlabeled = [r for r in results if r["label_verdict"] is None]
        assert len(unlabeled) == 1
        assert unlabeled[0]["vuln_name"] == "缓冲区溢出"

    def test_get_run_summary(self, db_with_data: FeedbackDB, run_id: str) -> None:
        """运行汇总应包含完整统计。"""
        summary = db_with_data.get_run_summary(run_id)
        assert summary["total_findings"] == 4
        assert summary["labeled_count"] == 3
        assert summary["tp"] == 2
        assert summary["fp"] == 1
        assert summary["not_sure"] == 0
        assert summary["missed_count"] == 1

        # fp_ratio: 1 / (2+1) ≈ 0.333
        assert abs(summary["fp_ratio"] - 0.333) < 0.01

    def test_get_run_summary_nonexistent(self, db: FeedbackDB) -> None:
        """不存在的 run_id 返回空字典。"""
        assert db.get_run_summary("nonexistent") == {}

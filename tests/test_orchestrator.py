"""测试 orchestrator.py —— 扫描编排引擎。

测试 5 个 Phase 的调度逻辑，所有依赖模块均 mock。
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

import pytest

from src.orchestrator import Orchestrator, ScanMetadata, ScanResult


# ─── fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def config() -> dict:
    """最小运行时配置。"""
    return {
        "semgrep": {"enabled": True, "timeout_seconds": 300},
        "codeql": {"enabled": True, "timeout_seconds": 600},
        "llm": {
            "offline": False,
            "review_threshold_low": 0.4,
            "review_threshold_high": 0.7,
        },
        "output": {},
    }


@pytest.fixture
def mock_kb():
    """Mock KnowledgeBase。"""
    kb = mock.MagicMock()
    kb.get_by_clause.return_value = {
        "clause": "6.2.3.4",
        "name": "SQL注入",
        "category": "数据处理",
        "language": "Java",
        "description": "SQL注入描述",
        "risk": "高风险",
        "fix": "使用PreparedStatement",
        "negative_code": "bad code",
        "positive_code": "good code",
    }
    return kb


@pytest.fixture
def mock_semgrep():
    """Mock SemgrepScanner — 返回 2 条发现。"""
    scanner = mock.MagicMock()
    scanner.scan.return_value = [
        {
            "clause": "6.2.3.4",
            "standard": "GB/T 34944-2017",
            "vuln_name": "SQL注入",
            "category": "数据处理",
            "file_path": "src/Login.java",
            "line_start": 42,
            "line_end": 48,
            "source_tool": "semgrep",
            "auto_confidence": 0.90,
            "code_snippet": 'query = "SELECT * FROM users WHERE id=\'" + uid + "\'";',
            "tool_raw_output": {"check_id": "test.rule", "severity": "ERROR"},
        },
        {
            "clause": "6.2.6.3",
            "standard": "GB/T 34944-2017",
            "vuln_name": "口令硬编码",
            "category": "安全功能",
            "file_path": "src/Config.java",
            "line_start": 10,
            "line_end": 12,
            "source_tool": "semgrep",
            "auto_confidence": 0.95,
            "code_snippet": 'if ("admin123".equals(pwd))',
            "tool_raw_output": {"check_id": "hardcoded.pwd", "severity": "ERROR"},
        },
    ]
    return scanner


@pytest.fixture
def mock_codeql():
    """Mock CodeQLScanner — 返回 1 条发现（与 Semgrep 重复）。"""
    scanner = mock.MagicMock()
    scanner.scan.return_value = [
        {
            "clause": "6.2.3.4",
            "standard": "GB/T 34944-2017",
            "vuln_name": "SQL注入",
            "category": "数据处理",
            "file_path": "src/Login.java",
            "line_start": 43,  # 略微偏移的同一位置
            "line_end": 49,
            "source_tool": "codeql",
            "auto_confidence": 0.85,
            "code_snippet": 'query = "SELECT * FROM users WHERE id=\'" + uid + "\'";',
            "tool_raw_output": {"query_id": "java/sql-injection"},
        },
    ]
    return scanner


@pytest.fixture
def mock_llm():
    """Mock LLMClient — review_finding 返回 confirmed。"""
    client = mock.MagicMock()
    client.is_available.return_value = True

    from src.llm_client import ReviewResult

    client.review_finding.return_value = ReviewResult(
        clause="6.2.3.4",
        verdict="confirmed",
        confidence=0.92,
        reasoning="确实存在SQL注入",
    )
    client.scan_missed.return_value = []
    return client


@pytest.fixture
def mock_feedback_db():
    """Mock FeedbackDB。"""
    db = mock.MagicMock()
    db.insert_scan_run.return_value = "mock-run-id-123"
    db.get_findings_by_clause.return_value = []
    db.get_labels_by_finding.return_value = []
    return db


@pytest.fixture
def mock_report_gen():
    """Mock ReportGenerator。"""
    rg = mock.MagicMock()
    return rg


@pytest.fixture
def orch(
    config: dict,
    mock_kb,
    mock_semgrep,
    mock_codeql,
    mock_llm,
    mock_feedback_db,
    mock_report_gen,
) -> Orchestrator:
    """完整的 Orchestrator 实例，所有依赖均已注入。"""
    return Orchestrator(
        config,
        kb=mock_kb,
        semgrep=mock_semgrep,
        codeql=mock_codeql,
        llm=mock_llm,
        feedback_db=mock_feedback_db,
        report_generator=mock_report_gen,
    )


# ─── 完整流程测试 ─────────────────────────────────────────────────


class TestFullPipeline:
    """测试完整 5-Phase 流程。"""

    def test_run_online_mode(self, orch: Orchestrator, tmp_path: Path) -> None:
        """在线模式：应调用所有组件并返回结果。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        (code_dir / "Test.java").write_text("public class Test {}")
        (code_dir / "src").mkdir()
        (code_dir / "src" / "Login.java").write_text("class Login {}")

        result = orch.run(str(code_dir))

        assert isinstance(result, ScanResult)
        assert result.mode == "online"
        assert result.run_id == "mock-run-id-123"
        assert len(result.findings) > 0
        assert result.duration_seconds > 0

    def test_run_offline_mode(self, orch: Orchestrator, tmp_path: Path) -> None:
        """离线模式：LLM 不可用时跳过 Phase 4。"""
        orch._llm.is_available.return_value = False
        orch._config["llm"]["offline"] = True

        code_dir = tmp_path / "code"
        code_dir.mkdir()
        (code_dir / "Test.java").write_text("public class Test {}")

        result = orch.run(str(code_dir))
        assert result.mode == "offline"

    def test_run_no_llm_client(self, config, mock_kb, mock_semgrep, mock_codeql, tmp_path: Path) -> None:
        """未注入 LLM 客户端时自动进入离线模式。"""
        orch = Orchestrator(config, kb=mock_kb, semgrep=mock_semgrep, codeql=mock_codeql)
        assert orch._determine_mode() == "offline"

    def test_run_without_feedback_db(self, orch: Orchestrator, tmp_path: Path) -> None:
        """无反馈数据库时不应崩溃。"""
        orch._feedback_db = None
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        (code_dir / "Test.java").write_text("public class Test {}")

        result = orch.run(str(code_dir))
        assert result.run_id == ""  # 无 run_id
        assert len(result.warnings) == 0

    def test_run_without_report_generator(self, orch: Orchestrator, tmp_path: Path) -> None:
        """无报告生成器时不应崩溃。"""
        orch._report_generator = None
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        (code_dir / "Test.java").write_text("public class Test {}")

        result = orch.run(str(code_dir))  # 不应抛出异常
        assert len(result.findings) >= 0


# ─── Phase 1: Preprocess ──────────────────────────────────────────


class TestPreprocess:
    """测试 Phase 1 预处理。"""

    @pytest.fixture
    def orch(self, config: dict) -> Orchestrator:
        return Orchestrator(config)

    def test_detect_java_only(self, orch: Orchestrator, tmp_path: Path) -> None:
        """纯 Java 项目的检测。"""
        code_dir = tmp_path / "java_project"
        code_dir.mkdir()
        (code_dir / "Main.java").write_text("class Main {}")
        (code_dir / "Util.java").write_text("class Util {}")

        meta = orch._preprocess(code_dir)
        assert meta.total_files == 2
        assert meta.java_files == 2
        assert meta.cpp_files == 0
        assert meta.languages_detected == ["Java"]

    def test_detect_cpp_only(self, orch: Orchestrator, tmp_path: Path) -> None:
        """纯 C/C++ 项目的检测。"""
        code_dir = tmp_path / "cpp_project"
        code_dir.mkdir()
        (code_dir / "main.c").write_text("int main() { return 0; }")
        (code_dir / "util.cpp").write_text("void foo() {}")
        (code_dir / "header.h").write_text("#pragma once")

        meta = orch._preprocess(code_dir)
        assert meta.total_files == 3
        assert meta.cpp_files == 3
        assert meta.java_files == 0
        assert "C/C++" in meta.languages_detected

    def test_detect_mixed_project(self, orch: Orchestrator, tmp_path: Path) -> None:
        """混合语言项目。"""
        code_dir = tmp_path / "mixed"
        code_dir.mkdir()
        (code_dir / "App.java").write_text("class App {}")
        (code_dir / "native.c").write_text("int main() { return 0; }")

        meta = orch._preprocess(code_dir)
        assert meta.total_files == 2
        assert meta.java_files == 1
        assert meta.cpp_files == 1
        assert set(meta.languages_detected) == {"Java", "C/C++"}

    def test_detect_maven(self, orch: Orchestrator, tmp_path: Path) -> None:
        """检测 Maven 构建系统。"""
        code_dir = tmp_path / "maven_proj"
        code_dir.mkdir()
        (code_dir / "pom.xml").write_text("<project></project>")
        (code_dir / "src").mkdir()

        meta = orch._preprocess(code_dir)
        assert meta.build_system == "maven"
        assert meta.compile_ready is True

    def test_detect_cmake(self, orch: Orchestrator, tmp_path: Path) -> None:
        """检测 CMake 构建系统。"""
        code_dir = tmp_path / "cmake_proj"
        code_dir.mkdir()
        (code_dir / "CMakeLists.txt").write_text("project(test)")
        (code_dir / "main.cpp").write_text("int main(){}")

        meta = orch._preprocess(code_dir)
        assert meta.build_system == "cmake"
        assert meta.compile_ready is True

    def test_no_build_system(self, orch: Orchestrator, tmp_path: Path) -> None:
        """无构建系统时应标记 compile_ready=False。"""
        code_dir = tmp_path / "bare"
        code_dir.mkdir()
        (code_dir / "hello.java").write_text("class Hello {}")

        meta = orch._preprocess(code_dir)
        assert meta.build_system == ""
        assert meta.compile_ready is False

    def test_ignores_git_and_build_dirs(self, orch: Orchestrator, tmp_path: Path) -> None:
        """.git/ 和 target/ 目录应被忽略。"""
        code_dir = tmp_path / "proj"
        code_dir.mkdir()
        (code_dir / "src").mkdir()
        (code_dir / "src" / "Main.java").write_text("class Main {}")
        # 创建应被忽略的目录
        (code_dir / ".git").mkdir(parents=True, exist_ok=True)
        (code_dir / ".git" / "config").write_text("...")
        (code_dir / "target").mkdir(parents=True, exist_ok=True)
        (code_dir / "target" / "compiled.class").write_text("...")
        (code_dir / "node_modules").mkdir(parents=True, exist_ok=True)
        (code_dir / "node_modules" / "lib.js").write_text("...")

        meta = orch._preprocess(code_dir)
        assert meta.total_files == 1  # 只有 Main.java
        assert meta.java_files == 1

    def test_source_roots_detection(self, orch: Orchestrator, tmp_path: Path) -> None:
        """检测源码根目录。"""
        code_dir = tmp_path / "proj"
        (code_dir / "src").mkdir(parents=True)
        (code_dir / "src" / "main").mkdir(parents=True)
        (code_dir / "src" / "main" / "java").mkdir(parents=True)
        (code_dir / "include").mkdir(parents=True)

        meta = orch._preprocess(code_dir)
        assert "src/main/java" in meta.source_roots
        assert "include" in meta.source_roots


# ─── Phase 2: Parallel Scan ──────────────────────────────────────


class TestParallelScan:
    """测试 Phase 2 并行扫描调度。"""

    def test_semgrep_and_codeql_called(self, orch: Orchestrator, tmp_path: Path) -> None:
        """两个扫描器都应被调用。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        (code_dir / "Test.java").write_text("class Test {}")

        meta = ScanMetadata(languages_detected=["Java"], java_files=1, compile_ready=False)

        semgrep_f, codeql_f, llm_f = orch._parallel_scan(code_dir, meta)

        orch._semgrep.scan.assert_called_once()
        orch._codeql.scan.assert_called_once()

    def test_semgrep_disabled(self, orch: Orchestrator, tmp_path: Path) -> None:
        """Semgrep 被禁用时应跳过。"""
        orch._config["semgrep"]["enabled"] = False
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        meta = ScanMetadata(languages_detected=["Java"])

        orch._parallel_scan(code_dir, meta)
        orch._semgrep.scan.assert_not_called()

    def test_codeql_disabled(self, orch: Orchestrator, tmp_path: Path) -> None:
        """CodeQL 被禁用时应跳过。"""
        orch._config["codeql"]["enabled"] = False
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        meta = ScanMetadata(languages_detected=["Java"])

        orch._parallel_scan(code_dir, meta)
        orch._codeql.scan.assert_not_called()

    def test_scanner_exception_does_not_crash(self, orch: Orchestrator, tmp_path: Path) -> None:
        """一个扫描器异常不应影响另一个。"""
        orch._semgrep.scan.side_effect = RuntimeError("Semgrep crashed")
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        meta = ScanMetadata(languages_detected=["Java"], java_files=1)
        (code_dir / "Test.java").write_text("class Test {}")

        # 不应抛出异常
        semgrep_f, codeql_f, llm_f = orch._parallel_scan(code_dir, meta)

        # Semgrep 应返回空
        assert semgrep_f == []
        # CodeQL 应仍被调用
        orch._codeql.scan.assert_called_once()

    def test_cpp_with_cmake_generates_build_command(self, orch: Orchestrator, tmp_path: Path) -> None:
        """C++ CMake 项目应自动生成构建命令。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        (code_dir / "main.cpp").write_text("int main(){}")
        (code_dir / "CMakeLists.txt").write_text("project(test)")

        meta = ScanMetadata(
            languages_detected=["C/C++"],
            cpp_files=1,
            build_system="cmake",
            compile_ready=True,
        )

        orch._parallel_scan(code_dir, meta)
        call_kwargs = orch._codeql.scan.call_args
        # 应传入 build_command
        assert "build_command" in call_kwargs[1]
        assert call_kwargs[1]["build_command"] is not None


# ─── Phase 3: Aggregate ──────────────────────────────────────────


class TestAggregate:
    """测试 Phase 3 结果聚合。"""

    @pytest.fixture
    def orch(self, config: dict) -> Orchestrator:
        return Orchestrator(config)

    def test_merge_overlapping_findings(self, orch: Orchestrator) -> None:
        """同一文件同一条款且行号重叠应合并。"""
        semgrep = [
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 42, "line_end": 48,
                "source_tool": "semgrep", "auto_confidence": 0.9,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]
        codeql = [
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 43, "line_end": 49,  # overlaps
                "source_tool": "codeql", "auto_confidence": 0.85,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]

        result = orch._aggregate(semgrep, codeql, [])

        # 应该合并为 1 条
        assert len(result) == 1
        f = result[0]
        assert f["source_tool"] == "codeql+semgrep"  # 按字母排序
        # 置信度: max(0.9, 0.85) + 0.05 = 0.95
        assert f["auto_confidence"] == pytest.approx(0.95)

    def test_no_overlap_keeps_separate(self, orch: Orchestrator) -> None:
        """不重叠的发现应保留为独立条目。"""
        semgrep = [
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 10, "line_end": 15,
                "source_tool": "semgrep", "auto_confidence": 0.9,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]
        codeql = [
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 100, "line_end": 105,  # 完全不重叠
                "source_tool": "codeql", "auto_confidence": 0.85,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]

        result = orch._aggregate(semgrep, codeql, [])
        assert len(result) == 2  # 保留两个独立发现

    def test_different_clause_no_merge(self, orch: Orchestrator) -> None:
        """不同条款的发现不应合并。"""
        semgrep = [
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 40, "line_end": 45,
                "source_tool": "semgrep", "auto_confidence": 0.9,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]
        codeql = [
            {
                "clause": "6.2.6.3", "file_path": "A.java",  # 不同条款
                "line_start": 40, "line_end": 45,
                "source_tool": "codeql", "auto_confidence": 0.8,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]

        result = orch._aggregate(semgrep, codeql, [])
        assert len(result) == 2

    def test_empty_input(self, orch: Orchestrator) -> None:
        """空输入返回空列表。"""
        result = orch._aggregate([], [], [])
        assert result == []

    def test_results_sorted_by_clause(self, orch: Orchestrator) -> None:
        """结果应按 clause 排序。"""
        semgrep = [
            {
                "clause": "6.2.8.1", "file_path": "Z.java",
                "line_start": 1, "line_end": 2,
                "source_tool": "semgrep", "auto_confidence": 0.7,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 1, "line_end": 2,
                "source_tool": "semgrep", "auto_confidence": 0.9,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]

        result = orch._aggregate(semgrep, [], [])
        assert result[0]["clause"] == "6.2.3.4"
        assert result[1]["clause"] == "6.2.8.1"

    def test_severity_assigned(self, orch: Orchestrator) -> None:
        """聚合后每条发现应有 severity 字段。"""
        semgrep = [
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 1, "line_end": 2,
                "source_tool": "semgrep", "auto_confidence": 0.9,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
            {
                "clause": "6.2.9.1", "file_path": "B.java",
                "line_start": 1, "line_end": 2,
                "source_tool": "semgrep", "auto_confidence": 0.5,
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]

        result = orch._aggregate(semgrep, [], [])
        severities = {f["severity"] for f in result}
        assert "高" in severities  # SQL注入
        assert "低" in severities  # 点击劫持


# ─── Phase 3: 去重算法 ────────────────────────────────────────────


class TestDedupAlgorithm:
    """测试行号重叠检测算法。"""

    def test_perfect_overlap(self) -> None:
        assert Orchestrator._lines_overlap(10, 20, 10, 20) is True

    def test_partial_overlap(self) -> None:
        assert Orchestrator._lines_overlap(10, 20, 15, 25) is True

    def test_tolerance_adjacent(self) -> None:
        """±3 容忍度下，靠近的区间应合并。"""
        # 10-20 和 18-30: 扩展后 7-23 vs 15-33, 重叠 15-23, ratio=8/16=0.5 ≥ 0.3
        assert Orchestrator._lines_overlap(10, 20, 18, 30) is True

    def test_no_overlap(self) -> None:
        assert Orchestrator._lines_overlap(10, 15, 50, 55) is False

    def test_single_line(self) -> None:
        """单行发现应正确处理。"""
        assert Orchestrator._lines_overlap(5, 5, 6, 6) is True  # 相隔1行，容忍3行


# ─── Phase 4: LLM Review ─────────────────────────────────────────


class TestLLMReview:
    """测试 Phase 4 LLM 二次确认。"""

    @pytest.fixture
    def orch(self, config, mock_kb, mock_llm) -> Orchestrator:
        return Orchestrator(config, kb=mock_kb, llm=mock_llm)

    def test_review_low_confidence_findings(self, orch: Orchestrator) -> None:
        """仅低置信度发现应被审查（批量审查模式）。"""
        findings = [
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 1, "line_end": 2,
                "auto_confidence": 0.5,
                "source_tool": "semgrep", "standard": "",
                "vuln_name": "", "category": "",
                "code_snippet": "x", "tool_raw_output": {},
            },
            {
                "clause": "6.2.3.4", "file_path": "B.java",
                "line_start": 10, "line_end": 12,
                "auto_confidence": 0.95,
                "source_tool": "semgrep", "standard": "",
                "vuln_name": "", "category": "",
                "code_snippet": "y", "tool_raw_output": {},
            },
        ]
        orch._config = {"llm": {}}
        orch._aggregated = findings

        # 模拟 batch_review 返回值
        from src.llm_client import ReviewResult
        mock_results = [
            ReviewResult(clause="6.2.3.4", verdict="confirmed", confidence=0.8, reasoning="ok", evidence="", fix_suggestion="fix it"),
        ]

        # 模拟 llm client
        orch._llm.batch_review = mock.MagicMock(return_value=mock_results)
        orch._llm.is_available = mock.MagicMock(return_value=True)

        result = orch._llm_review(findings)
        # 只有 1 条低置信度发现应被审查
        assert len(result) == 1, f"Expected 1, got {len(result)}"

    def test_review_no_llm(self, orch: Orchestrator) -> None:
        """LLM 不可用时返回空。"""
        orch._llm.is_available = mock.MagicMock(return_value=False)
        reviewed = orch._llm_review([{"clause": "6.2.3.4", "auto_confidence": 0.5}])
        assert reviewed == []

    def test_merge_llm_confirmed(self, orch: Orchestrator) -> None:
        """LLM confirmed 应增加置信度 +0.2。"""
        aggregated = [
            {
                "clause": "6.2.3.4", "file_path": "A.java",
                "line_start": 1, "line_end": 2,
                "auto_confidence": 0.5, "source_tool": "semgrep",
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]
        reviewed = [
            {
                "finding": aggregated[0],
                "llm_verdict": "confirmed",
                "llm_confidence": 0.92,
                "llm_reasoning": "确认",
                "llm_evidence": "证据",
                "llm_fix": "修复建议",
            },
        ]

        result = orch._merge_llm_results(aggregated, reviewed)
        assert result[0]["auto_confidence"] == 0.7  # 0.5 + 0.2
        assert result[0]["llm_status"] == "confirmed"

    def test_merge_llm_rejected(self, orch: Orchestrator) -> None:
        """LLM rejected 应降低置信度 ×0.5。"""
        aggregated = [
            {
                "clause": "6.2.6.3", "file_path": "B.java",
                "line_start": 10, "line_end": 12,
                "auto_confidence": 0.8, "source_tool": "semgrep",
                "standard": "", "vuln_name": "", "category": "",
                "code_snippet": "", "tool_raw_output": {},
            },
        ]
        reviewed = [
            {
                "finding": aggregated[0],
                "llm_verdict": "rejected",
                "llm_confidence": 0.88,
                "llm_reasoning": "误报",
                "llm_evidence": "",
                "llm_fix": "",
            },
        ]

        result = orch._merge_llm_results(aggregated, reviewed)
        assert result[0]["auto_confidence"] == 0.4  # 0.8 * 0.5
        assert result[0]["llm_status"] == "rejected"


# ─── 辅助方法 ────────────────────────────────────────────────────


class TestHelpers:
    """测试辅助方法。"""

    @pytest.fixture
    def orch(self, config: dict) -> Orchestrator:
        return Orchestrator(config)

    def test_determine_mode_online(self, orch: Orchestrator) -> None:
        orch._llm = mock.MagicMock()
        orch._llm.is_available.return_value = True
        assert orch._determine_mode() == "online"

    def test_determine_mode_offline(self, orch: Orchestrator) -> None:
        orch._llm = mock.MagicMock()
        orch._llm.is_available.return_value = False
        assert orch._determine_mode() == "offline"

    def test_active_tools(self, orch: Orchestrator) -> None:
        orch._semgrep = mock.MagicMock()
        orch._codeql = mock.MagicMock()
        orch._llm = mock.MagicMock()
        orch._llm.is_available.return_value = True
        assert set(orch._active_tools()) == {"semgrep", "codeql", "deepseek"}

    def test_standard_from_clause_java(self, orch: Orchestrator) -> None:
        assert orch._standard_from_clause("6.2.3.4") == "GB/T 34944-2017"

    def test_standard_from_clause_cpp(self, orch: Orchestrator) -> None:
        assert orch._standard_from_clause("7.2.3.6") == "GB/T 34943-2017"

    def test_assign_severity_high(self, orch: Orchestrator) -> None:
        assert orch._assign_severity({"clause": "6.2.3.4"}) == "高"
        assert orch._assign_severity({"clause": "7.2.3.6"}) == "高"

    def test_assign_severity_low(self, orch: Orchestrator) -> None:
        assert orch._assign_severity({"clause": "6.2.9.1"}) == "低"
        assert orch._assign_severity({"clause": "6.2.7.2"}) == "低"

    def test_assign_severity_medium_default(self, orch: Orchestrator) -> None:
        assert orch._assign_severity({"clause": "6.2.8.1"}) == "中"


# ─── ScanMetadata ─────────────────────────────────────────────────


class TestScanMetadata:
    """测试 ScanMetadata 数据类。"""

    def test_defaults(self) -> None:
        m = ScanMetadata()
        assert m.languages_detected == []
        assert m.total_files == 0
        assert m.compile_ready is False

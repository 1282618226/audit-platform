"""测试 scanner_semgrep.py —— Semgrep 扫描适配器。

所有测试 mock subprocess.run，不执行真实的 Semgrep CLI。
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from src.knowledge_base import KnowledgeBase
from src.scanner_semgrep import SEVERITY_CONFIDENCE, SemgrepScanner


# ─── fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def kb(kb_path: Path) -> KnowledgeBase:
    """从 conftest 样本知识库创建 KnowledgeBase。"""
    return KnowledgeBase(kb_path)


@pytest.fixture
def scanner(kb: KnowledgeBase, tmp_path: Path) -> SemgrepScanner:
    """创建一个指向临时规则目录的扫描器。"""
    rules_dir = tmp_path / "rules" / "semgrep"
    rules_dir.mkdir(parents=True)
    (rules_dir / "java").mkdir()
    (rules_dir / "cpp").mkdir()
    return SemgrepScanner(rules_dir=rules_dir, kb=kb, timeout_seconds=30)


@pytest.fixture
def semgrep_result_sql_injection() -> dict:
    """模拟 Semgrep 对 SQL 注入的输出（单条结果）。"""
    return {
        "results": [
            {
                "check_id": "java.lang.security.audit.sqli.sql-injection-6.2.3.4",
                "path": "/workspace/code/src/LoginServlet.java",
                "start": {"line": 42, "col": 5, "offset": 1200},
                "end": {"line": 48, "col": 20, "offset": 1350},
                "extra": {
                    "message": "检测到 SQL 注入：使用字符串拼接构建 SQL 语句",
                    "severity": "ERROR",
                    "lines": 'String query = "SELECT * FROM users WHERE id=\'" + uid + "\'";',
                    "metadata": {
                        "clause": "6.2.3.4",
                        "category": "数据处理",
                        "cwe": "CWE-89",
                    },
                },
            }
        ],
        "errors": [],
    }


@pytest.fixture
def semgrep_result_multiple() -> dict:
    """模拟 Semgrep 的多条结果输出。"""
    return {
        "results": [
            {
                "check_id": "java.sqli.6.2.3.4",
                "path": "/workspace/code/src/Login.java",
                "start": {"line": 42, "col": 5, "offset": 1200},
                "end": {"line": 48, "col": 20, "offset": 1350},
                "extra": {
                    "message": "SQL注入",
                    "severity": "ERROR",
                    "lines": 'query = "SELECT * FROM users WHERE id=\'" + uid + "\'";',
                    "metadata": {"clause": "6.2.3.4"},
                },
            },
            {
                "check_id": "java.hardcoded-password.6.2.6.3",
                "path": "/workspace/code/src/Config.java",
                "start": {"line": 10, "col": 1, "offset": 300},
                "end": {"line": 12, "col": 1, "offset": 350},
                "extra": {
                    "message": "硬编码口令",
                    "severity": "WARNING",
                    "lines": 'if ("admin123".equals(password))',
                    "metadata": {"clause": "6.2.6.3"},
                },
            },
        ],
        "errors": [],
    }


# ─── mock 辅助 ────────────────────────────────────────────────────


def _mock_run(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """构建一个模拟 subprocess.run 返回的 CompletedProcess。"""
    result = mock.MagicMock(spec=subprocess.CompletedProcess)
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


# ─── 扫描测试 ─────────────────────────────────────────────────────


class TestScan:
    """测试 Semgrep 扫描主流程。"""

    def test_scan_java_with_findings(
        self, scanner: SemgrepScanner, semgrep_result_sql_injection: dict, tmp_path: Path
    ) -> None:
        """对 Java 代码扫描，应正确解析 SQL 注入发现。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=1,  # semgrep 发现漏洞时 exit=1
                stdout=json.dumps(semgrep_result_sql_injection, ensure_ascii=False),
            )
            findings = scanner.scan(str(code_dir), language="java")

        assert len(findings) == 1
        f = findings[0]
        assert f["clause"] == "6.2.3.4"
        assert f["vuln_name"] == "SQL注入"
        assert f["category"] == "数据处理"
        assert f["standard"] == "GB/T 34944-2017"
        assert f["source_tool"] == "semgrep"
        assert f["line_start"] == 42
        assert f["line_end"] == 48
        assert f["auto_confidence"] == 0.90  # ERROR severity
        assert "uid" in f["code_snippet"]
        assert f["tool_raw_output"]["check_id"] == "java.lang.security.audit.sqli.sql-injection-6.2.3.4"

    def test_scan_cpp_language(
        self, scanner: SemgrepScanner, semgrep_result_sql_injection: dict, tmp_path: Path
    ) -> None:
        """对 C++ 语言扫描应使用 cpp 规则目录。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=1,
                stdout=json.dumps(semgrep_result_sql_injection, ensure_ascii=False),
            )
            scanner.scan(str(code_dir), language="cpp")

        # 验证使用了 cpp 规则目录
        cmd = mock_run.call_args[0][0]
        assert "--config" in cmd
        config_idx = cmd.index("--config")
        config_path = cmd[config_idx + 1]
        assert "cpp" in config_path

    def test_scan_no_findings(self, scanner: SemgrepScanner, tmp_path: Path) -> None:
        """无发现时返回空列表。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=0,  # semgrep exit=0 表示无发现
                stdout=json.dumps({"results": [], "errors": []}),
            )
            findings = scanner.scan(str(code_dir), language="java")

        assert findings == []

    def test_scan_multiple_findings(
        self, scanner: SemgrepScanner, semgrep_result_multiple: dict, tmp_path: Path
    ) -> None:
        """多条发现应全部解析。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=1,
                stdout=json.dumps(semgrep_result_multiple, ensure_ascii=False),
            )
            findings = scanner.scan(str(code_dir), language="java")

        assert len(findings) == 2
        clauses = {f["clause"] for f in findings}
        assert clauses == {"6.2.3.4", "6.2.6.3"}

    def test_scan_timeout(self, scanner: SemgrepScanner, tmp_path: Path) -> None:
        """扫描超时应返回空列表。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=30)):
            findings = scanner.scan(str(code_dir), language="java")

        assert findings == []

    def test_scan_semgrep_not_installed(self, scanner: SemgrepScanner, tmp_path: Path) -> None:
        """Semgrep 未安装时返回空列表。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            findings = scanner.scan(str(code_dir), language="java")

        assert findings == []

    def test_scan_missing_rules_dir(self, tmp_path: Path, kb: KnowledgeBase) -> None:
        """规则目录不存在时返回空列表。"""
        scanner = SemgrepScanner(
            rules_dir="/nonexistent/rules/dir",
            kb=kb,
        )
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        findings = scanner.scan(str(code_dir), language="java")
        assert findings == []

    def test_scan_missing_code_dir(self, scanner: SemgrepScanner) -> None:
        """代码目录不存在时返回空列表。"""
        findings = scanner.scan("/nonexistent/code/dir", language="java")
        assert findings == []

    def test_scan_abnormal_exit_code(self, scanner: SemgrepScanner, tmp_path: Path) -> None:
        """Semgrep 异常退出时应返回空列表。"""
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=2,  # 2 = fatal error
                stderr="Fatal error: invalid config",
            )
            findings = scanner.scan(str(code_dir), language="java")

        assert findings == []


# ─── 规则目录解析 ─────────────────────────────────────────────────


class TestRuleResolution:
    """测试规则目录解析逻辑。"""

    def test_resolve_java_rules(self, tmp_path: Path, kb: KnowledgeBase) -> None:
        """Java 语言应使用 rules/java/ 子目录。"""
        rules_dir = tmp_path / "rules"
        (rules_dir / "java").mkdir(parents=True)
        (rules_dir / "cpp").mkdir(parents=True)

        scanner = SemgrepScanner(rules_dir=rules_dir, kb=kb)
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=0, stdout=json.dumps({"results": [], "errors": []})
            )
            scanner.scan(str(code_dir), language="java")

        cmd = mock_run.call_args[0][0]
        config_idx = cmd.index("--config")
        config_path = cmd[config_idx + 1]
        assert config_path.endswith("java")

    def test_resolve_cpp_rules(self, tmp_path: Path, kb: KnowledgeBase) -> None:
        """C++ 语言应使用 rules/cpp/ 子目录。"""
        rules_dir = tmp_path / "rules"
        (rules_dir / "java").mkdir(parents=True)
        (rules_dir / "cpp").mkdir(parents=True)

        scanner = SemgrepScanner(rules_dir=rules_dir, kb=kb)
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=0, stdout=json.dumps({"results": [], "errors": []})
            )
            scanner.scan(str(code_dir), language="cpp")

        cmd = mock_run.call_args[0][0]
        config_idx = cmd.index("--config")
        config_path = cmd[config_idx + 1]
        assert config_path.endswith("cpp")

    def test_fallback_to_rules_dir(self, tmp_path: Path, kb: KnowledgeBase) -> None:
        """无 java/cpp 子目录时，退化使用 rules_dir 本身。"""
        rules_dir = tmp_path / "flat_rules"
        rules_dir.mkdir()

        scanner = SemgrepScanner(rules_dir=rules_dir, kb=kb)
        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=0, stdout=json.dumps({"results": [], "errors": []})
            )
            scanner.scan(str(code_dir), language="java")

        cmd = mock_run.call_args[0][0]
        config_idx = cmd.index("--config")
        config_path = cmd[config_idx + 1]
        assert str(rules_dir) in config_path or config_path == str(rules_dir)


# ─── 条款号提取 ───────────────────────────────────────────────────


class TestClauseExtraction:
    """测试从 Semgrep 结果提取国标条款号。"""

    def test_extract_from_metadata(self) -> None:
        """从 extra.metadata.clause 提取。"""
        item = {
            "check_id": "some.rule.id",
            "extra": {"metadata": {"clause": "6.2.3.4"}},
        }
        clause = SemgrepScanner._extract_clause(item, item["check_id"])
        assert clause == "6.2.3.4"

    def test_extract_from_check_id(self) -> None:
        """从 check_id 中正则匹配提取。"""
        item = {
            "check_id": "cpp-buffer-overflow-7.2.3.6",
            "extra": {},
        }
        clause = SemgrepScanner._extract_clause(item, item["check_id"])
        assert clause == "7.2.3.6"

    def test_extract_none(self) -> None:
        """无法提取时返回 None。"""
        item = {
            "check_id": "some-generic-rule",
            "extra": {},
        }
        clause = SemgrepScanner._extract_clause(item, item["check_id"])
        assert clause is None

    def test_metadata_priority(self) -> None:
        """metadata.clause 优先级高于 check_id 中匹配。"""
        item = {
            "check_id": "rule-with-9.9.9.9",
            "extra": {"metadata": {"clause": "6.2.6.3"}},
        }
        clause = SemgrepScanner._extract_clause(item, item["check_id"])
        assert clause == "6.2.6.3"


# ─── standard_from_clause ─────────────────────────────────────────


class TestStandardFromClause:
    """测试条款号 → 标准名称推断。"""

    def test_java_clause(self) -> None:
        assert SemgrepScanner._standard_from_clause("6.2.3.4") == "GB/T 34944-2017"

    def test_cpp_clause(self) -> None:
        assert SemgrepScanner._standard_from_clause("7.2.3.6") == "GB/T 34943-2017"

    def test_unknown_clause(self) -> None:
        assert SemgrepScanner._standard_from_clause("9.9.9.9") == ""


# ─── 置信度映射 ───────────────────────────────────────────────────


class TestConfidenceMapping:
    """测试严重度→置信度映射。"""

    def test_error_confidence(self) -> None:
        assert SEVERITY_CONFIDENCE["ERROR"] == 0.90

    def test_warning_confidence(self) -> None:
        assert SEVERITY_CONFIDENCE["WARNING"] == 0.70

    def test_info_confidence(self) -> None:
        assert SEVERITY_CONFIDENCE["INFO"] == 0.50


# ─── is_installed ─────────────────────────────────────────────────


class TestIsInstalled:
    """测试 Semgrep 可用性检测。"""

    def test_installed(self) -> None:
        """检测成功时应返回 True。"""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(returncode=0)
            assert SemgrepScanner.is_installed() is True

    def test_not_installed(self) -> None:
        """Semgrep 未找到时应返回 False。"""
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            assert SemgrepScanner.is_installed() is False

    def test_nonzero_exit(self) -> None:
        """非零退出码应返回 False。"""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(returncode=1)
            assert SemgrepScanner.is_installed() is False


# ─── 不依赖 kb 也可以运行 ────────────────────────────────────────


class TestWithoutKB:
    """测试无 KnowledgeBase 时的降级行为。"""

    def test_scan_without_kb(self, semgrep_result_sql_injection: dict, tmp_path: Path) -> None:
        """不传 kb 时扫描应正常进行，但 vuln_name 等字段留空。"""
        rules_dir = tmp_path / "rules"
        (rules_dir / "java").mkdir(parents=True)
        scanner = SemgrepScanner(rules_dir=rules_dir, kb=None)

        code_dir = tmp_path / "code"
        code_dir.mkdir()

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = _mock_run(
                returncode=1,
                stdout=json.dumps(semgrep_result_sql_injection, ensure_ascii=False),
            )
            findings = scanner.scan(str(code_dir), language="java")

        assert len(findings) == 1
        f = findings[0]
        assert f["clause"] == "6.2.3.4"  # 从 metadata 提取
        assert f["vuln_name"] == ""       # 无 kb，留空
        assert f["category"] == ""
        assert f["standard"] == "GB/T 34944-2017"  # 从 clause 前缀推断


# ─── 相对路径转换 ─────────────────────────────────────────────────


class TestMakeRelative:
    """测试绝对路径 → 相对路径转换。"""

    def test_relative_path(self) -> None:
        result = SemgrepScanner._make_relative(
            "/workspace/code/src/Login.java",
            Path("/workspace/code"),
        )
        assert result == "src/Login.java"

    def test_already_relative(self) -> None:
        result = SemgrepScanner._make_relative("src/Login.java", Path("/workspace/code"))
        assert result == "src/Login.java"


# ─── Taint mode 入口点提取 ────────────────────────────────────────


class TestTaintMode:
    """测试 Semgrep taint mode 的入口点解析。"""

    def test_extract_entry_point(self, tmp_path: Path) -> None:
        """taint mode 结果应提取 dataflow_trace 中的 Source 位置。"""
        item = {
            "check_id": "gbt-34944-6.2.3.4-sql-injection-taint",
            "path": "/workspace/code/src/Login.java",
            "start": {"line": 52, "col": 5},
            "end": {"line": 52, "col": 30},
            "extra": {
                "message": "SQL注入",
                "severity": "ERROR",
                "lines": "stmt.executeQuery(query);",
                "metadata": {"clause": "6.2.3.4"},
                "dataflow_trace": {
                    "taint_source": {
                        "location": {
                            "path": "/workspace/code/src/Login.java",
                            "start": {"line": 42, "col": 10},
                            "end": {"line": 42, "col": 50},
                        }
                    },
                    "intermediate_vars": [],
                },
            },
        }
        import json
        item_json = json.dumps(item)

        code_dir = tmp_path / "code"
        code_dir.mkdir()

        entry = SemgrepScanner._extract_entry_point(item, code_dir)
        assert entry["line"] == 42
        assert "Login.java" in entry["file"]

    def test_no_taint_trace_returns_empty(self, tmp_path: Path) -> None:
        """非 taint mode 结果返回空 entry_point。"""
        item = {
            "check_id": "gbt-34944-6.2.6.3-hardcoded-password",
            "path": "/workspace/code/src/Config.java",
            "start": {"line": 10, "col": 1},
            "end": {"line": 10, "col": 20},
            "extra": {
                "message": "硬编码口令",
                "severity": "ERROR",
                "lines": 'if ("admin".equals(pwd))',
                "metadata": {"clause": "6.2.6.3"},
            },
        }
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        entry = SemgrepScanner._extract_entry_point(item, code_dir)
        assert entry == {}

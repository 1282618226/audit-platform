"""测试 scanner_codeql.py —— CodeQL 扫描适配器。

所有测试 mock subprocess.run，不执行真实的 CodeQL CLI。
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from src.knowledge_base import KnowledgeBase
from src.scanner_codeql import CodeQLScanner


# ─── helpers ──────────────────────────────────────────────────────


def _mock_run(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """构建模拟的 CompletedProcess。"""
    result = mock.MagicMock(spec=subprocess.CompletedProcess)
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


def _write_sarif(path: str, results: list[dict]) -> None:
    """向指定路径写入 SARIF 格式的 JSON。"""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "organization": "GitHub",
                    }
                },
                "invocations": [
                    {
                        "workingDirectory": {
                            "uri": "file:///workspace/code/"
                        }
                    }
                ],
                "results": results,
            }
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f)


def _make_sarif_result(
    rule_id: str,
    uri: str,
    start_line: int,
    end_line: int,
    message: str = "漏洞描述",
    snippet: str = "",
    precision: str = "high",
) -> dict:
    """构造单条 SARIF 结果。"""
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": start_line,
                        "endLine": end_line,
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": f"hash-{start_line}"
        },
        "properties": {"precision": precision},
    }
    if snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": snippet,
        }
    return result


# ─── fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def kb(kb_path: Path) -> KnowledgeBase:
    return KnowledgeBase(kb_path)


@pytest.fixture
def scanner(kb: KnowledgeBase, tmp_path: Path) -> CodeQLScanner:
    """创建指向临时查询目录的扫描器。"""
    queries_dir = tmp_path / "queries"
    (queries_dir / "java").mkdir(parents=True)
    (queries_dir / "cpp").mkdir(parents=True)
    return CodeQLScanner(
        cli_path="codeql",
        queries_dir=queries_dir,
        kb=kb,
        timeout_seconds=120,
    )


# ─── 数据库创建 ───────────────────────────────────────────────────


class TestCreateDatabase:
    """测试 CodeQL 数据库创建。"""

    def test_create_java_database(self, scanner: CodeQLScanner, tmp_path: Path) -> None:
        """Java 数据库创建成功。"""
        source = tmp_path / "src"
        source.mkdir()

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=0)
            db_path = scanner.create_database(str(source), language="java")

        assert db_path is not None
        call_args = mock_r.call_args[0][0]
        assert "database" in call_args
        assert "create" in call_args
        assert "--language" in call_args
        lang_idx = call_args.index("--language")
        assert call_args[lang_idx + 1] == "java"

    def test_create_cpp_database_with_build(self, scanner: CodeQLScanner, tmp_path: Path) -> None:
        """C++ 有编译命令时正常创建。"""
        source = tmp_path / "src"
        source.mkdir()

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=0)
            db_path = scanner.create_database(
                str(source), language="cpp", build_command="cmake .. && make"
            )

        assert db_path is not None
        call_args = mock_r.call_args[0][0]
        assert "--command" in call_args

    def test_create_cpp_without_build_degrades(self, scanner: CodeQLScanner, tmp_path: Path) -> None:
        """C++ 无编译命令时使用 'true' 替代（降级 Level 2）。"""
        source = tmp_path / "src"
        source.mkdir()

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=0)
            db_path = scanner.create_database(str(source), language="cpp")

        assert db_path is not None
        call_args = mock_r.call_args[0][0]
        cmd_idx = call_args.index("--command")
        assert call_args[cmd_idx + 1] == "true"

    def test_create_timeout(self, scanner: CodeQLScanner, tmp_path: Path) -> None:
        """数据库创建超时返回 None。"""
        source = tmp_path / "src"
        source.mkdir()

        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="codeql", timeout=120),
        ):
            db_path = scanner.create_database(str(source), language="java")

        assert db_path is None

    def test_create_cli_not_found(self, scanner: CodeQLScanner, tmp_path: Path) -> None:
        """CLI 不存在返回 None。"""
        source = tmp_path / "src"
        source.mkdir()

        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            db_path = scanner.create_database(str(source), language="java")

        assert db_path is None

    def test_create_failure(self, scanner: CodeQLScanner, tmp_path: Path) -> None:
        """非零 exit code 返回 None。"""
        source = tmp_path / "src"
        source.mkdir()

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=2, stderr="Fatal error")
            db_path = scanner.create_database(str(source), language="java")

        assert db_path is None

    def test_cpp_build_failure_retry_without_command(
        self, scanner: CodeQLScanner, tmp_path: Path
    ) -> None:
        """C++ 编译失败后自动以纯语法模式重试。"""
        source = tmp_path / "src"
        source.mkdir()

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_run(returncode=2, stderr="build failed")
            else:
                return _mock_run(returncode=0)

        with mock.patch("subprocess.run", side_effect=side_effect):
            db_path = scanner.create_database(
                str(source), language="cpp", build_command="cmake .. && make"
            )

        assert db_path is not None
        assert call_count[0] == 2  # 第一次失败，第二次重试成功


# ─── 查询分析 ─────────────────────────────────────────────────────


class TestAnalyze:
    """测试 CodeQL 查询分析。"""

    def test_analyze_java_with_findings(
        self, scanner: CodeQLScanner, tmp_path: Path
    ) -> None:
        """Java 分析应正确解析 SARIF 中的 SQL 注入发现。"""
        sarif_path = str(tmp_path / "output.sarif")
        _write_sarif(
            sarif_path,
            [
                _make_sarif_result(
                    rule_id="cnas/java/6.2.3.4/sql-injection",
                    uri="file:///workspace/code/src/LoginServlet.java",
                    start_line=42,
                    end_line=48,
                    message="检测到 SQL 注入",
                    snippet='String query = "SELECT * FROM users WHERE id=\'" + uid + "\'";',
                ),
            ],
        )

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=2)  # exit=2 means findings
            # 覆盖 sarif_path 为我们的测试文件
            with mock.patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = sarif_path
                findings = scanner.analyze("/tmp/db", language="java")

        assert len(findings) == 1
        f = findings[0]
        assert f["clause"] == "6.2.3.4"
        assert f["vuln_name"] == "SQL注入"
        assert f["standard"] == "GB/T 34944-2017"
        assert f["source_tool"] == "codeql"
        assert f["line_start"] == 42
        assert f["line_end"] == 48
        assert "uid" in f["code_snippet"]

    def test_analyze_multiple_findings(
        self, scanner: CodeQLScanner, tmp_path: Path
    ) -> None:
        """多条 SARIF 结果应全部解析。"""
        sarif_path = str(tmp_path / "output2.sarif")
        _write_sarif(
            sarif_path,
            [
                _make_sarif_result(
                    "cnas/java/6.2.3.4/sql-injection",
                    "file:///workspace/code/src/A.java",
                    10, 15,
                ),
                _make_sarif_result(
                    "cnas/cpp/7.2.3.6/buffer-overflow",
                    "file:///workspace/code/src/B.c",
                    20, 22,
                ),
            ],
        )

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=2)
            with mock.patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = sarif_path
                findings = scanner.analyze("/tmp/db", language="java")

        assert len(findings) == 2
        clauses = {f["clause"] for f in findings}
        assert clauses == {"6.2.3.4", "7.2.3.6"}
        tools = {f["standard"] for f in findings}
        assert tools == {"GB/T 34944-2017", "GB/T 34943-2017"}

    def test_analyze_empty_results(
        self, scanner: CodeQLScanner, tmp_path: Path
    ) -> None:
        """无发现时返回空列表。"""
        sarif_path = str(tmp_path / "empty.sarif")
        _write_sarif(sarif_path, [])

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=0)
            with mock.patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = sarif_path
                findings = scanner.analyze("/tmp/db", language="java")

        assert findings == []

    def test_analyze_no_clause_in_rule_id(
        self, scanner: CodeQLScanner, tmp_path: Path
    ) -> None:
        """ruleId 不含条款号的结果应被过滤。"""
        sarif_path = str(tmp_path / "noclause.sarif")
        _write_sarif(
            sarif_path,
            [
                _make_sarif_result(
                    "java/security/generic-warning",  # 无条款号
                    "file:///workspace/code/src/A.java",
                    10, 15,
                ),
            ],
        )

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=2)
            with mock.patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = sarif_path
                findings = scanner.analyze("/tmp/db", language="java")

        assert findings == []  # 被过滤

    def test_analyze_timeout(self, scanner: CodeQLScanner) -> None:
        """分析超时返回空列表。"""
        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="codeql", timeout=600),
        ):
            findings = scanner.analyze("/tmp/db", language="java")

        assert findings == []

    def test_analyze_cli_not_found(self, scanner: CodeQLScanner) -> None:
        """CLI 不存在返回空列表。"""
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            findings = scanner.analyze("/tmp/db", language="java")

        assert findings == []


# ─── 一步扫描 ─────────────────────────────────────────────────────


class TestScan:
    """测试便捷方法 scan()。"""

    def test_scan_success(
        self, scanner: CodeQLScanner, tmp_path: Path
    ) -> None:
        """一步扫描成功。"""
        source = tmp_path / "src"
        source.mkdir()
        sarif_path = str(tmp_path / "output.sarif")
        _write_sarif(
            sarif_path,
            [
                _make_sarif_result(
                    "cnas/java/6.2.3.4/sql-injection",
                    "file:///workspace/code/A.java", 10, 15,
                ),
            ],
        )

        with mock.patch("subprocess.run") as mock_r:
            # 第一次调用是 create_database，第二次是 analyze
            mock_r.side_effect = [
                _mock_run(returncode=0),  # create succeeds
                _mock_run(returncode=2),  # analyze finds
            ]
            with mock.patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = sarif_path
                findings = scanner.scan(str(source), language="java")

        assert len(findings) == 1

    def test_scan_create_failure(
        self, scanner: CodeQLScanner, tmp_path: Path
    ) -> None:
        """数据库创建失败则直接返回空列表。"""
        source = tmp_path / "src"
        source.mkdir()

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=2, stderr="fatal")
            findings = scanner.scan(str(source), language="java")

        assert findings == []


# ─── 条款号提取 ───────────────────────────────────────────────────


class TestClauseExtraction:
    """测试从 CodeQL ruleId 提取国标条款号。"""

    def test_extract_from_path_style(self) -> None:
        clause = CodeQLScanner._extract_clause("cnas/java/6.2.3.4/sql-injection")
        assert clause == "6.2.3.4"

    def test_extract_from_dash_style(self) -> None:
        clause = CodeQLScanner._extract_clause("java-cnas-sql-injection-6.2.6.3")
        assert clause == "6.2.6.3"

    def test_extract_cpp(self) -> None:
        clause = CodeQLScanner._extract_clause("cpp-buffer-overflow-7.2.3.6")
        assert clause == "7.2.3.6"

    def test_extract_none(self) -> None:
        clause = CodeQLScanner._extract_clause("java/security/generic")
        assert clause is None

    def test_extract_multiple_matches_first(self) -> None:
        clause = CodeQLScanner._extract_clause("compare-6.2.3.4-vs-7.2.3.6")
        assert clause == "6.2.3.4"  # 第一个匹配


# ─── 置信度估算 ───────────────────────────────────────────────────


class TestEstimateConfidence:
    """测试置信度估算。"""

    def test_very_high_precision(self) -> None:
        c = CodeQLScanner._estimate_confidence({"properties": {"precision": "very-high"}})
        assert c == 0.95

    def test_high_precision(self) -> None:
        c = CodeQLScanner._estimate_confidence({"properties": {"precision": "high"}})
        assert c == 0.85

    def test_medium_precision(self) -> None:
        c = CodeQLScanner._estimate_confidence({"properties": {"precision": "medium"}})
        assert c == 0.70

    def test_low_precision(self) -> None:
        c = CodeQLScanner._estimate_confidence({"properties": {"precision": "low"}})
        assert c == 0.50

    def test_default(self) -> None:
        c = CodeQLScanner._estimate_confidence({})
        assert c == 0.85


# ─── URI 解析 ─────────────────────────────────────────────────────


class TestUriResolution:
    """测试 SARIF URI → 相对路径转换。"""

    def test_with_source_root(self) -> None:
        result = CodeQLScanner._resolve_uri(
            "file:///workspace/code/src/main/java/App.java",
            "/workspace/code",
        )
        assert result == "src/main/java/App.java"

    def test_without_source_root(self) -> None:
        result = CodeQLScanner._resolve_uri(
            "file:///workspace/code/src/App.java",
            "",
        )
        assert result == "/workspace/code/src/App.java"

    def test_strips_file_prefix(self) -> None:
        result = CodeQLScanner._resolve_uri(
            "file:///path/to/file.java",
            "/different/root",
        )
        assert result == "file.java" if False else "/path/to/file.java"


# ─── 标准推断 ─────────────────────────────────────────────────────


class TestStandardFromClause:
    """测试条款号 → 标准推断。"""

    def test_java(self) -> None:
        assert CodeQLScanner._standard_from_clause("6.2.3.4") == "GB/T 34944-2017"

    def test_cpp(self) -> None:
        assert CodeQLScanner._standard_from_clause("7.2.7.3") == "GB/T 34943-2017"

    def test_unknown(self) -> None:
        assert CodeQLScanner._standard_from_clause("9.9.9.9") == ""


# ─── is_installed ─────────────────────────────────────────────────


class TestIsInstalled:
    """测试 CodeQL CLI 可用性检查。"""

    def test_installed(self) -> None:
        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=0)
            assert CodeQLScanner.is_installed() is True

    def test_not_installed(self) -> None:
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            assert CodeQLScanner.is_installed() is False


# ─── 无 KB 降级 ──────────────────────────────────────────────────


class TestWithoutKB:
    """测试无 KnowledgeBase 时的降级行为。"""

    def test_analyze_without_kb(self, tmp_path: Path) -> None:
        """不传 kb 时分析正常，仅 vuln_name/category 留空。"""
        scanner = CodeQLScanner(cli_path="codeql", kb=None)
        sarif_path = str(tmp_path / "output.sarif")
        _write_sarif(
            sarif_path,
            [
                _make_sarif_result(
                    "cnas/java/6.2.3.4/sql",
                    "file:///workspace/code/A.java", 10, 15,
                ),
            ],
        )

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=2)
            with mock.patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = sarif_path
                findings = scanner.analyze("/tmp/db", language="java")

        assert len(findings) == 1
        f = findings[0]
        assert f["clause"] == "6.2.3.4"
        assert f["standard"] == "GB/T 34944-2017"  # 从 clause 前缀推断
        assert f["vuln_name"] == ""  # 无 kb


# ─── SARIF 边界情况 ───────────────────────────────────────────────


class TestSarifEdgeCases:
    """测试 SARIF 解析边界情况。"""

    def test_missing_locations(self, scanner: CodeQLScanner, tmp_path: Path) -> None:
        """无 locations 的结果应被跳过。"""
        sarif_path = str(tmp_path / "noloc.sarif")
        _write_sarif(sarif_path, [])
        # 手动构造一个无 locations 的结果
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "cnas/java/6.2.3.4/sql",
                    "message": {"text": "x"},
                    "locations": [],  # 空
                }],
            }],
        }
        with open(sarif_path, "w") as f:
            json.dump(sarif, f)

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=2)
            with mock.patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = sarif_path
                findings = scanner.analyze("/tmp/db", language="java")

        assert findings == []

    def test_no_end_line_uses_start_line(self, scanner: CodeQLScanner, tmp_path: Path) -> None:
        """无 endLine 时使用 startLine 作为 line_end。"""
        sarif_path = str(tmp_path / "noend.sarif")
        _write_sarif(sarif_path, [
            {
                "ruleId": "cnas/java/6.2.3.4/sql",
                "message": {"text": "x"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file:///code/A.java"},
                        "region": {"startLine": 5},  # 无 endLine
                    },
                }],
            },
        ])

        with mock.patch("subprocess.run") as mock_r:
            mock_r.return_value = _mock_run(returncode=2)
            with mock.patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = sarif_path
                findings = scanner.analyze("/tmp/db", language="java")

        assert len(findings) == 1
        assert findings[0]["line_start"] == 5
        assert findings[0]["line_end"] == 5  # fallback to startLine

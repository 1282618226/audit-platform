"""CodeQL 扫描适配器。

封装 CodeQL CLI 的两步流程（数据库创建 → 查询分析），解析 SARIF 输出为统一格式。

职责:
  1. 创建 CodeQL 数据库（Java 或 C/C++）
  2. 对数据库执行 CNAS 查询包
  3. 解析 SARIF 输出，映射到国标条款号
  4. C/C++ 编译失败时的三级降级策略

统一发现格式: 与 scanner_semgrep.py 保持完全一致。

设计依据:
  - 设计文档 Section 2.2.3 Phase 2: CodeQL 执行策略
  - 设计文档 Section 4.1: CodeQL 数据库构建策略（选择性运行 + 三级降级）
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CodeQLScanner:
    """CodeQL 扫描适配器。

    用法:
        scanner = CodeQLScanner(
            cli_path="/opt/codeql/codeql",
            queries_dir="/app/rules/codeql",
            kb=knowledge_base,
        )
        db_path = scanner.create_database("/workspace/code", language="java")
        findings = scanner.analyze(db_path, language="java")
    """

    # CodeQL CLI 路径（容器内）
    cli_path: str

    def __init__(
        self,
        cli_path: str = "codeql",
        queries_dir: str | Path | None = None,
        kb: Any | None = None,
        timeout_seconds: int = 600,
        database_dir: str | Path | None = None,
    ) -> None:
        """初始化 CodeQL 扫描器。

        Args:
            cli_path: CodeQL CLI 可执行文件路径。
            queries_dir: 自定义查询包目录（其下应有 java/ 和 cpp/ 子目录）。
            kb: KnowledgeBase 实例。
            timeout_seconds: 超时秒数。
            database_dir: 数据库存放目录。为 None 时使用临时目录。
        """
        self.cli_path = cli_path
        self._queries_dir = Path(queries_dir) if queries_dir else None
        self._kb = kb
        self._timeout = timeout_seconds
        self._database_dir = Path(database_dir) if database_dir else None

    # ─── Phase 1: 数据库创建 ──────────────────────────────────────

    def create_database(
        self,
        source_root: str | Path,
        language: str = "java",
        build_command: str | None = None,
    ) -> str | None:
        """创建 CodeQL 数据库。

        对于 Java: 自动提取源文件，无需 build_command。
        对于 C/C++: 需要 build_command（如 "cmake .. && make"）。
                    如果 build_command 为 None，使用纯源码分析模式（降级 Level 2）。

        Args:
            source_root: 源代码根目录。
            language: "java" 或 "cpp"（对应 CodeQL 的 java/cpp）。
            build_command: C/C++ 构建命令。Java 忽略此参数。

        Returns:
            数据库路径（str），失败时返回 None。
        """
        source_root = Path(source_root)
        lang_codeql = "java" if language.lower() == "java" else "cpp"

        db_path = self._make_db_path(language)

        cmd = [
            self.cli_path,
            "database", "create",
            str(db_path),
            "--language", lang_codeql,
            "--source-root", str(source_root),
            "--overwrite",
        ]

        # C/C++ 需要构建命令
        if lang_codeql == "cpp":
            if build_command:
                cmd.extend(["--command", build_command])
                logger.info("CodeQL: C/C++ 使用编译模式, command=%s", build_command)
            else:
                # 降级 Level 2: 纯语法分析
                cmd.extend(["--command", "true"])
                logger.warning(
                    "CodeQL: C/C++ 无编译命令，降级为纯语法分析（Level 2）—— 跨文件数据流不可用"
                )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )

            if result.returncode != 0:
                stderr_tail = result.stderr[-500:] if result.stderr else ""
                logger.error(
                    "CodeQL: 数据库创建失败 (exit=%d): %s",
                    result.returncode,
                    stderr_tail,
                )
                # C/C++ 进一步降级: 重试不带编译命令
                if lang_codeql == "cpp" and build_command:
                    logger.warning("CodeQL: 编译失败，重试为纯语法分析模式")
                    return self.create_database(
                        source_root,
                        language=language,
                        build_command=None,  # 降级
                    )
                return None

            logger.info("CodeQL: 数据库创建成功 → %s", db_path)
            return str(db_path)

        except subprocess.TimeoutExpired:
            logger.error("CodeQL: 数据库创建超时 (%ds)", self._timeout)
            return None
        except FileNotFoundError:
            logger.error("CodeQL: CLI '%s' 未找到", self.cli_path)
            return None

    # ─── Phase 2: 查询分析 ────────────────────────────────────────

    def analyze(
        self,
        database_path: str,
        language: str = "java",
        extra_args: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """对 CodeQL 数据库执行 CNAS 查询，返回统一格式发现列表。

        Args:
            database_path: CodeQL 数据库路径（由 create_database 返回）。
            language: "java" 或 "cpp"。
            extra_args: 传递给 codeql database analyze 的额外参数。

        Returns:
            统一格式的发现列表。
        """
        queries_path = self._resolve_queries_path(language)
        if queries_path is None:
            logger.warning("CodeQL: 未找到 %s 查询包，使用默认安全查询", language)
            # 使用 CodeQL 内置安全查询作为 fallback
            queries_path = f"codeql/{language}-queries"

        # SARIF 输出文件
        with tempfile.NamedTemporaryFile(
            suffix=".sarif", mode="w", delete=False
        ) as sarif_file:
            sarif_path = sarif_file.name

        cmd = [
            self.cli_path,
            "database", "analyze",
            str(database_path),
            str(queries_path),
            "--format", "sarif-latest",
            "--output", sarif_path,
            "--no-save-cache",
            "--no-upload",
        ]
        if extra_args:
            cmd.extend(extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )

            if result.returncode not in (0, 2):
                # exit code 0 = success, 2 = findings found (expected)
                logger.error(
                    "CodeQL: 分析失败 (exit=%d): %s",
                    result.returncode,
                    (result.stderr or "")[:500],
                )
                return []

            return self._parse_sarif(sarif_path)

        except subprocess.TimeoutExpired:
            logger.error("CodeQL: 分析超时 (%ds)", self._timeout)
            return []
        except FileNotFoundError:
            logger.error("CodeQL: CLI '%s' 未找到", self.cli_path)
            return []

    # ─── 便捷方法：一步完成 ────────────────────────────────────────

    def scan(
        self,
        source_root: str | Path,
        language: str = "java",
        build_command: str | None = None,
    ) -> list[dict[str, Any]]:
        """一步完成 CodeQL 扫描（创建数据库 + 查询分析）。

        Args:
            source_root: 源代码目录。
            language: "java" 或 "cpp"。
            build_command: C/C++ 构建命令（可选）。

        Returns:
            统一格式的发现列表。
        """
        db_path = self.create_database(source_root, language, build_command)
        if db_path is None:
            return []
        return self.analyze(db_path, language)

    # ─── 内部方法 ────────────────────────────────────────────────

    def _make_db_path(self, language: str) -> Path:
        """生成 CodeQL 数据库路径。"""
        import uuid

        name = f"codeql-db-{language}-{uuid.uuid4().hex[:8]}"
        if self._database_dir:
            self._database_dir.mkdir(parents=True, exist_ok=True)
            return self._database_dir / name
        else:
            return Path(tempfile.mkdtemp(prefix=f"{name}-"))

    def _resolve_queries_path(self, language: str) -> str | None:
        """解析 CNAS 自定义查询包路径。

        查询包结构: {queries_dir}/java/ 和 {queries_dir}/cpp/
        """
        if self._queries_dir is None:
            return None

        lang_dir = "java" if language.lower() == "java" else "cpp"
        candidate = self._queries_dir / lang_dir
        if candidate.is_dir():
            return str(candidate)

        # fallback: 如果有 .qlpack.yml，用 queries_dir 自身
        qlpack = self._queries_dir / "qlpack.yml"
        if qlpack.exists():
            return str(self._queries_dir)

        return None

    def _parse_sarif(self, sarif_path: str) -> list[dict[str, Any]]:
        """解析 CodeQL SARIF 输出，转换为统一发现格式。

        SARIF 结构:
          runs[0].results[] = {
            ruleId, message.text, locations[].physicalLocation,
            partialFingerprints, ...
          }
        """
        try:
            with open(sarif_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error("CodeQL: 无法读取 SARIF 文件: %s", e)
            return []

        findings: list[dict[str, Any]] = []
        for run in data.get("runs", []):
            source_root = self._get_source_root_from_run(run)
            for result in run.get("results", []):
                finding = self._convert_sarif_result(result, source_root)
                if finding:
                    findings.append(finding)

        return findings

    def _convert_sarif_result(
        self, result: dict[str, Any], source_root: str
    ) -> dict[str, Any] | None:
        """将单条 SARIF 结果转换为统一格式。"""
        try:
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")

            # 提取条款号
            clause = self._extract_clause(rule_id)
            if clause is None:
                logger.debug("CodeQL: 无法从 ruleId '%s' 提取条款号，跳过", rule_id)
                return None

            # 主位置
            locations = result.get("locations", [])
            if not locations:
                return None

            loc = locations[0]
            phys = loc.get("physicalLocation", {})
            region = phys.get("region", {})
            artifact = phys.get("artifactLocation", {})
            uri = artifact.get("uri", "")
            file_path = self._resolve_uri(uri, source_root)

            line_start = region.get("startLine", 0)
            line_end = region.get("endLine", line_start)

            # 代码片段（SARIF 可能包含 snippet）
            snippet = region.get("snippet", {}).get("text", "")

            # CodeQL 置信度基于 rule 属性
            confidence = self._estimate_confidence(result)

            # 从知识库补充
            standard = self._standard_from_clause(clause)
            vuln_name = ""
            category = ""
            if self._kb:
                vuln = self._kb.get_by_clause(clause)
                if vuln:
                    vuln_name = vuln.get("name", "")
                    category = vuln.get("category", "")

            return {
                "clause": clause,
                "standard": standard,
                "vuln_name": vuln_name,
                "category": category,
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "source_tool": "codeql",
                "auto_confidence": confidence,
                "code_snippet": snippet,
                "tool_raw_output": {
                    "rule_id": rule_id,
                    "message": message,
                    "fingerprint": result.get("partialFingerprints", {}).get(
                        "primaryLocationLineHash", ""
                    ),
                },
            }
        except Exception as e:
            logger.warning("CodeQL: 转换 SARIF 结果时出错: %s", e)
            return None

    # ─── 条款号提取 ──────────────────────────────────────────────

    @staticmethod
    def _extract_clause(rule_id: str) -> str | None:
        """从 CodeQL ruleId 提取国标条款号。

        CodeQL 查询 ID 格式建议: cnas/java/6.2.3.4/sql-injection
        或: java-cnas-sql-injection-6.2.3.4
        """
        import re

        # 匹配 数字.数字.数字.数字 格式
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rule_id)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _standard_from_clause(clause: str) -> str:
        """根据条款号前缀推断标准名称。"""
        if clause.startswith("6.2"):
            return "GB/T 34944-2017"
        if clause.startswith("7.2"):
            return "GB/T 34943-2017"
        return ""

    @staticmethod
    def _estimate_confidence(result: dict[str, Any]) -> float:
        """基于 SARIF 结果属性估算置信度。

        CodeQL 的 @precision / @problem.severity 可以作为参考。
        默认返回 0.85（CodeQL 的数据流分析通常比 Semgrep 更精确）。
        """
        # 尝试从 properties 中提取 precision
        props = result.get("properties", {})
        precision = props.get("precision", "")

        precision_map = {
            "very-high": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
        }
        return precision_map.get(precision, 0.85)  # 默认值

    @staticmethod
    def _get_source_root_from_run(run: dict[str, Any]) -> str:
        """从 SARIF run 中提取源码根路径。"""
        # CodeQL 通常将 sourceLocationPrefix 写入
        # invocations[0].workingDirectory.uri
        invocations = run.get("invocations", [])
        if invocations:
            wd = invocations[0].get("workingDirectory", {})
            uri = wd.get("uri", "")
            # 剥除 file:// 前缀
            if uri.startswith("file://"):
                return uri[7:]
            return uri
        return ""

    @staticmethod
    def _resolve_uri(file_uri: str, source_root: str) -> str:
        """将 SARIF 中的 file:// URI 转换为相对路径。"""
        # 剥除 file:// 前缀
        if file_uri.startswith("file://"):
            file_uri = file_uri[7:]

        file_path = Path(file_uri)
        if source_root:
            root = Path(source_root)
            try:
                return str(file_path.relative_to(root))
            except ValueError:
                pass

        return file_uri

    # ─── 可用性检查 ──────────────────────────────────────────────

    @classmethod
    def is_installed(cls, cli_path: str = "codeql") -> bool:
        """检查 CodeQL CLI 是否已安装。"""
        try:
            result = subprocess.run(
                [cli_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

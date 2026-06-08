"""Semgrep 扫描适配器。

封装 Semgrep CLI 的调用、结果解析和统一格式转换。

职责:
  1. 按语言选择规则目录
  2. 执行 `semgrep scan --config=<rules_dir> --json <code_dir>`
  3. 解析 JSON 输出，映射到国标条款号
  4. 从知识库补充漏洞名称、类别、风险等级

统一发现格式 (dict):
  {
    "clause":         str   # 国标条款号, e.g. "6.2.3.4"
    "standard":       str   # 所属标准, e.g. "GB/T 34944-2017"
    "vuln_name":      str   # 漏洞名称
    "category":       str   # 大类
    "file_path":      str   # 文件路径(相对于扫描根目录)
    "line_start":     int   # 起始行号
    "line_end":       int   # 结束行号
    "source_tool":    str   # "semgrep"
    "auto_confidence": float # 自动置信度 0.0-1.0
    "code_snippet":   str   # 漏洞位置代码片段
    "tool_raw_output": dict # 工具原始输出(规则ID/消息等)
  }
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Semgrep 严重度 → 基础置信度映射
SEVERITY_CONFIDENCE: dict[str, float] = {
    "ERROR": 0.90,
    "WARNING": 0.70,
    "INFO": 0.50,
}


class SemgrepScanner:
    """Semgrep 扫描适配器。

    用法:
        scanner = SemgrepScanner(rules_dir="/app/rules/semgrep", kb=knowledge_base)
        findings = scanner.scan(code_dir="/workspace/code", language="java")
    """

    # Semgrep CLI 可执行文件（容器内路径或 PATH 中）
    cli: str = "semgrep"

    def __init__(
        self,
        rules_dir: str | Path,
        kb: Any | None = None,
        timeout_seconds: int = 300,
        pro_enabled: bool = False,
    ) -> None:
        """初始化 Semgrep 扫描器。

        Args:
            rules_dir: Semgrep 规则目录，其下应有 java/ 和 cpp/ 子目录。
            kb: KnowledgeBase 实例（可选，用于条款号→标准名称映射）。
            timeout_seconds: 单个语言扫描的超时秒数。
            pro_enabled: 是否启用 Semgrep Pro Engine (--pro)。
        """
        self._rules_dir = Path(rules_dir)
        self._kb = kb
        self._timeout = timeout_seconds
        self._pro_enabled = pro_enabled

    def scan(
        self,
        code_dir: str | Path,
        language: str = "java",
        extra_args: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """对代码目录执行 Semgrep 扫描并返回统一格式的发现列表。

        Args:
            code_dir: 源代码目录。
            language: "java" 或 "cpp"（决定使用哪套规则）。
            extra_args: 传递给 semgrep CLI 的额外参数。

        Returns:
            统一格式的发现列表。
        """
        code_dir = Path(code_dir)
        rules_path = self._resolve_rules_path(language)
        if rules_path is None:
            logger.warning("Semgrep: 未找到 %s 语言的规则目录 %s", language, rules_path)
            return []

        if not Path(code_dir).exists():
            logger.error("Semgrep: 代码目录 %s 不存在", code_dir)
            return []

        cmd = self._build_command(rules_path, code_dir, extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("Semgrep: 扫描超时 (%ds)", self._timeout)
            return []
        except FileNotFoundError:
            logger.error("Semgrep: 可执行文件 '%s' 未找到", self.cli)
            return []

        if result.returncode not in (0, 1, 2):
            # exit code 0 = no findings, exit code 1 = findings (warning), exit code 2 = findings (error/blocking)
            # 其他 exit code 才是真正的错误
            logger.error(
                "Semgrep: 扫描异常退出 (exit=%d): %s",
                result.returncode,
                result.stderr[:500],
            )
            return []

        return self._parse_output(result.stdout, code_dir)

    def _resolve_rules_path(self, language: str) -> Path | None:
        """根据语言解析规则目录路径。

        优先使用 {rules_dir}/{java,cpp}/ (已验证可工作的单体/分拆YAML)。
        vulns/ 目录作为补充（如果存在且包含有效规则文件）。
        """
        lang_dir_name = "java" if language.lower() == "java" else "cpp"
        lang_ext = lang_dir_name

        # 主路径: {rules_dir}/java/ 或 {rules_dir}/cpp/
        primary = self._rules_dir / lang_dir_name
        if not primary.is_dir():
            # 可能 rules_dir 直接在 vulns 内或就是 rules 根
            primary = self._rules_dir

        # 如果 vulns/ 存在，收集其中的 {language}.yml 追加到扫描
        vulns_dir = self._rules_dir.parent / "vulns"
        if not vulns_dir.is_dir():
            vulns_dir = self._rules_dir / "vulns" if (self._rules_dir / "vulns").is_dir() else None
        if not vulns_dir or not vulns_dir.is_dir():
            vulns_dir = None

        if vulns_dir:
            matching_files = list(vulns_dir.glob(f"*/{lang_ext}.yml"))
            if matching_files:
                # 创建临时目录，symlink 主规则 + vulns 补充
                tmp_dir = Path(tempfile.mkdtemp(prefix=f"semgrep-{lang_ext}-"))
                # 复制主规则目录
                if primary.is_dir():
                    for f in primary.iterdir():
                        if f.suffix in (".yml", ".yaml"):
                            link = tmp_dir / f.name
                            if not link.exists():
                                link.symlink_to(f.resolve())
                # 追加 vulns 规则
                for f in matching_files:
                    link = tmp_dir / f"vuln-{f.parent.name}.yml"
                    if not link.exists():
                        link.symlink_to(f.resolve())
                return tmp_dir
            return primary

        if primary.is_dir():
            return primary

        if self._rules_dir.is_dir():
            return self._rules_dir

        return None

    def _build_command(
        self,
        rules_path: Path,
        code_dir: Path,
        extra_args: list[str] | None,
    ) -> list[str]:
        """构建 semgrep CLI 命令。"""
        cmd = [
            self.cli,
            "scan",
            "--config", str(rules_path),
            "--json",
            "--dataflow-traces",
            "--no-git-ignore",
            "--disable-version-check",
        ]
        if self._pro_enabled and os.path.exists("/opt/semgrep-pro/semgrep-pro"):
            cmd.append("--pro")
        cmd.append(str(code_dir))
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def _parse_output(self, raw_output: str, code_dir: Path) -> list[dict[str, Any]]:
        """解析 semgrep --json 输出为统一发现格式。"""
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            logger.error("Semgrep: 无法解析 JSON 输出: %s", e)
            return []

        results = data.get("results", [])
        if not results:
            return []

        findings: list[dict[str, Any]] = []
        for item in results:
            finding = self._convert_single(item, code_dir)
            if finding:
                findings.append(finding)

        return findings

    def _convert_single(
        self, item: dict[str, Any], code_dir: Path
    ) -> dict[str, Any] | None:
        """将单条 Semgrep 结果转换为统一格式。

        Semgrep JSON 结果关键字段:
          - check_id: 规则ID, e.g. "java.lang.security.audit.xxx"
          - path: 文件路径
          - start/end: {line, col, offset}
          - extra.message: 规则消息
          - extra.metadata: 规则元数据（可含 clause）
          - extra.severity: ERROR/WARNING/INFO
          - extra.lines: 匹配的代码行
        """
        try:
            check_id = item.get("check_id", "")
            path_str = item.get("path", "")
            start = item.get("start", {})
            end = item.get("end", {})
            extra = item.get("extra", {})
            severity = extra.get("severity", "WARNING").upper()
            message = extra.get("message", "")
            lines = extra.get("lines", "")

            # 从规则元数据或 check_id 提取 clause
            clause = self._extract_clause(item, check_id)
            if clause is None:
                logger.debug("Semgrep: 无法从规则 %s 提取条款号，跳过", check_id)
                return None

            # 相对路径
            file_path = self._make_relative(path_str, code_dir)

            # 基础置信度 = 严重度映射
            base_confidence = SEVERITY_CONFIDENCE.get(severity, 0.50)

            # ── taint mode: 提取入口点（Source） ──
            entry_point = self._extract_entry_point(item, code_dir)

            # 从条款号前缀推断标准（不依赖 kb）
            standard = self._standard_from_clause(clause)

            # 从知识库补充漏洞名称和类别
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
                "line_start": start.get("line", 0),
                "line_end": end.get("line", 0),
                "source_tool": "semgrep",
                "auto_confidence": base_confidence,
                "code_snippet": lines,
                "entry_point": entry_point,
                "tool_raw_output": {
                    "check_id": check_id,
                    "severity": severity,
                    "message": message,
                },
            }
        except Exception as e:
            logger.warning("Semgrep: 转换单条结果时出错: %s", e)
            return None

    # ─── Taint mode 入口点提取 ────────────────────────────────────

    @staticmethod
    def _extract_entry_point(
        item: dict[str, Any], code_dir: Path
    ) -> dict[str, Any]:
        """从 Semgrep taint mode 结果中提取入口点（Source）位置。

        Semgrep taint mode 输出:
          extra.dataflow_trace.taint_source.location → 用户输入进入点
          item.start / item.end → 爆发点（Sink）

        Returns:
            {"file": str, "line": int} 或 {}（非 taint mode 时为空）。
        """
        extra = item.get("extra", {})
        trace = extra.get("dataflow_trace", {})
        if not trace:
            return {}

        taint_src = trace.get("taint_source", {})
        if not taint_src:
            return {}

        src_loc = taint_src.get("location", {})
        if not src_loc:
            return {}

        src_path = src_loc.get("path", "")
        src_start = src_loc.get("start", {})
        return {
            "file": SemgrepScanner._make_relative(src_path, code_dir),
            "line": src_start.get("line", 0),
        }

    # ─── 条款号提取 ──────────────────────────────────────────────

    @staticmethod
    def _extract_clause(item: dict[str, Any], check_id: str) -> str | None:
        """从 Semgrep 结果中提取国标条款号。

        优先级:
          1. extra.metadata.clause — 规则 YAML 中显式声明的元数据
          2. check_id 中匹配 — 如规则名中包含 '6.2.3.4' 格式
        """
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        if isinstance(metadata, dict):
            clause = metadata.get("clause", "")
            if clause:
                return str(clause)

        # 尝试从 check_id 中解析（如 java-sql-injection-6.2.3.4）
        import re

        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", check_id)
        if match:
            return match.group(1)

        return None

    @staticmethod
    def _standard_from_clause(clause: str) -> str:
        """根据条款号前缀判断所属标准。"""
        if clause.startswith("6.2"):
            return "GB/T 34944-2017"
        if clause.startswith("7.2"):
            return "GB/T 34943-2017"
        return ""

    @staticmethod
    def _make_relative(file_path: str, base_dir: Path) -> str:
        """将绝对路径转换为相对于 base_dir 的路径。"""
        try:
            return str(Path(file_path).relative_to(base_dir))
        except ValueError:
            return file_path

    # ─── 可用性检查 ──────────────────────────────────────────────

    @classmethod
    def is_installed(cls) -> bool:
        """检查 semgrep CLI 是否已安装。"""
        try:
            result = subprocess.run(
                [cls.cli, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

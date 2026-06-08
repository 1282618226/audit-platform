"""知识库加载模块。

加载 knowledge_base.json，提供按国标条款号、语言、类别等维度的查询接口。

数据来源:
  - GB/T 34944-2017 Java语言源代码漏洞测试规范 (44种漏洞, 条款前缀 6.2)
  - GB/T 34943-2017 C/C++语言源代码漏洞测试规范 (32种漏洞, 条款前缀 7.2)
  - GB/T 39412-2020 信息安全技术 代码安全审计规范 (97个审计指标)
"""

import json
from pathlib import Path
from typing import Any


class KnowledgeBase:
    """CNAS 国标知识库加载与查询。

    加载 knowledge_base.json，提供:
      - 按条款号精确查找漏洞定义
      - 按语言筛选漏洞列表
      - 按类别筛选漏洞列表
      - 检索 GB/T 39412 审计指标 (Source / Sink / Sanitize)
    """

    def __init__(self, path: str | Path) -> None:
        """加载 JSON 知识库。

        Args:
            path: knowledge_base.json 的文件路径。

        Raises:
            FileNotFoundError: 文件不存在时抛出。
            json.JSONDecodeError: JSON 格式错误时抛出。
        """
        self._path = Path(path)
        with open(self._path, "r", encoding="utf-8") as f:
            self._data: dict[str, Any] = json.load(f)

        # 快捷引用
        self._standards: dict[str, Any] = self._data.get("standards", {})

        # 按条款号建立索引，加速 get_by_clause 查询
        self._clause_index: dict[str, dict[str, Any]] = {}
        self._build_clause_index()

        # GB/T 39412 审计指标索引 (Sheet1 条款 → item)
        self._audit_index: dict[str, dict[str, Any]] = {}
        self._build_audit_index()

    # ─── 内部索引构建 ────────────────────────────────────────────

    def _build_clause_index(self) -> None:
        """遍历所有漏洞条目，建立条款号 → 条目映射。"""
        for key in self._standards:
            std = self._standards[key]
            if "vulnerabilities" not in std:
                continue
            for vuln in std["vulnerabilities"]:
                clause = vuln.get("clause", "")
                if clause:
                    self._clause_index[clause] = vuln

    def _build_audit_index(self) -> None:
        """从 GB/T 39412-2020 的 Sheet1 建立审计指标索引。"""
        gbt39412 = self._standards.get("GB/T 39412-2020", {})
        sheets = gbt39412.get("sheets", {})
        sheet1 = sheets.get("Sheet1", {})
        header: list[str] = sheet1.get("header", [])
        items: list[list[str]] = sheet1.get("items", [])

        if not header or not items:
            return

        for row in items:
            if len(row) < 3:
                continue
            # row[1] 是条款编号, 如 "6.1.1.1"
            clause = row[1]
            entry: dict[str, Any] = {
                "序号": row[0] if len(row) > 0 else "",
                "标准条款编号": clause,
                "标准条款标题": row[2] if len(row) > 2 else "",
                "标准条款内容": row[3] if len(row) > 3 else "",
                "审计步骤": row[4] if len(row) > 4 else "",
                "Source": row[5] if len(row) > 5 else "",
                "Sink": row[6] if len(row) > 6 else "",
                "Sanitize": row[7] if len(row) > 7 else "",
                "误报排除": row[8] if len(row) > 8 else "",
                "修复建议": row[9] if len(row) > 9 else "",
                "适用语言": row[10] if len(row) > 10 else "",
            }
            self._audit_index[clause] = entry

    # ─── 漏洞查询接口 ────────────────────────────────────────────

    def get_java_vulns(self) -> list[dict[str, Any]]:
        """返回 GB/T 34944-2017 所有 Java 漏洞条目（44 种）。

        Returns:
            漏洞字典列表，每个元素包含 clause, name, category, language,
            framework, description, risk, fix, negative_code, positive_code。
        """
        std = self._standards.get("GB/T 34944-2017", {})
        return std.get("vulnerabilities", [])

    def get_cpp_vulns(self) -> list[dict[str, Any]]:
        """返回 GB/T 34943-2017 所有 C/C++ 漏洞条目（32 种）。

        Returns:
            漏洞字典列表，结构与 get_java_vulns 一致。
        """
        std = self._standards.get("GB/T 34943-2017", {})
        return std.get("vulnerabilities", [])

    def get_all_vulns(self) -> list[dict[str, Any]]:
        """返回全部漏洞条目（Java 44 + C/C++ 32 = 76 种）。

        Returns:
            合并后的漏洞字典列表。
        """
        return self.get_java_vulns() + self.get_cpp_vulns()

    def get_by_clause(self, clause: str) -> dict[str, Any] | None:
        """按国标条款号精确查找漏洞定义。

        Args:
            clause: 条款号，如 "6.2.3.4"（SQL注入）或 "7.2.3.6"（缓冲区溢出）。

        Returns:
            漏洞定义字典；条款号不存在时返回 None。
        """
        return self._clause_index.get(clause)

    def get_vulns_by_language(self, language: str) -> list[dict[str, Any]]:
        """按编程语言筛选漏洞。

        Args:
            language: "Java"、"C/C++" 或 "C\\C++"（知识库中 C/C++ 的实际值）。

        Returns:
            匹配的漏洞列表。
        """
        result: list[dict[str, Any]] = []
        for vuln in self.get_all_vulns():
            vuln_lang = vuln.get("language", "")
            if vuln_lang in (language, language.replace("/", "\\")):
                result.append(vuln)
        return result

    def get_vulns_by_category(self, category: str) -> list[dict[str, Any]]:
        """按漏洞大类筛选。

        Args:
            category: 大类名称，如 "数据处理"、"安全功能"、"Web问题"。

        Returns:
            匹配的漏洞列表。
        """
        result: list[dict[str, Any]] = []
        for vuln in self.get_all_vulns():
            if vuln.get("category", "") == category:
                result.append(vuln)
        return result

    def search_by_name(self, keyword: str) -> list[dict[str, Any]]:
        """按漏洞名称模糊搜索。

        Args:
            keyword: 搜索关键词。

        Returns:
            名称中包含关键词的漏洞列表。
        """
        result: list[dict[str, Any]] = []
        kw = keyword.lower()
        for vuln in self.get_all_vulns():
            if kw in vuln.get("name", "").lower():
                result.append(vuln)
        return result

    # ─── 标准信息接口 ────────────────────────────────────────────

    def get_standard_info(self, standard: str) -> dict[str, Any]:
        """获取标准的元信息。

        Args:
            standard: 标准标识，如 "GB/T 34944-2017"。

        Returns:
            包含 full_name, language, clause_prefix, total_vulns 等字段。
            标准不存在时返回空字典。
        """
        std = self._standards.get(standard, {})
        return {
            k: v
            for k, v in std.items()
            if k != "vulnerabilities"
        }

    def get_standards(self) -> list[str]:
        """列出知识库中所有标准标识。

        Returns:
            标准标识列表，如 ["GB/T 34944-2017", "GB/T 34943-2017", ...]。
        """
        return list(self._standards.keys())

    # ─── GB/T 39412 审计指标接口 ─────────────────────────────────

    def get_audit_steps(self, clause: str) -> dict[str, Any] | None:
        """从 GB/T 39412-2020 获取指定条款的审计步骤。

        Args:
            clause: 审计指标条款号，如 "6.1.1.1"。

        Returns:
            包含 审计步骤、Source、Sink、Sanitize、误报排除、修复建议 的字典；
            条款号不存在时返回 None。
        """
        return self._audit_index.get(clause)

    def get_all_audit_items(self) -> list[dict[str, Any]]:
        """返回 GB/T 39412-2020 全部 97 个审计指标项。

        Returns:
            审计指标字典列表。
        """
        return list(self._audit_index.values())

    def get_audit_items_by_language(self, language: str) -> list[dict[str, Any]]:
        """按语言筛选 GB/T 39412 审计指标。

        Args:
            language: "Java" 或 "C++" 或 "C/C++"。

        Returns:
            匹配的审计指标列表。
        """
        result: list[dict[str, Any]] = []
        for item in self._audit_index.values():
            langs = item.get("适用语言", "")
            # "Java/C++" 匹配 Java 和 C++
            if language.replace("\\", "/") in langs or language in langs:
                result.append(item)
        return result

    # ─── 统计接口 ────────────────────────────────────────────────

    def get_categories(self) -> dict[str, int]:
        """统计所有漏洞大类及对应数量。

        Returns:
            {类别名: 数量} 字典。
        """
        counts: dict[str, int] = {}
        for vuln in self.get_all_vulns():
            cat = vuln.get("category", "未分类")
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def count_vulns(self) -> dict[str, int]:
        """按标准统计漏洞数量。

        Returns:
            {"GB/T 34944-2017": 44, "GB/T 34943-2017": 32}。
        """
        return {
            "GB/T 34944-2017": len(self.get_java_vulns()),
            "GB/T 34943-2017": len(self.get_cpp_vulns()),
        }

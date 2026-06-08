"""测试 knowledge_base.py —— 知识库加载与查询模块。"""

from pathlib import Path

import pytest

from src.knowledge_base import KnowledgeBase


# ─── 加载测试 ────────────────────────────────────────────────────


class TestKnowledgeBaseLoading:
    """测试知识库文件加载。"""

    def test_load_from_path(self, kb_path: Path) -> None:
        """从文件路径加载知识库不应抛出异常。"""
        kb = KnowledgeBase(kb_path)
        assert kb is not None

    def test_load_file_not_found(self) -> None:
        """加载不存在的文件应抛出 FileNotFoundError。"""
        with pytest.raises(FileNotFoundError):
            KnowledgeBase("/nonexistent/path/kb.json")

    def test_standards_available(self, kb_path: Path) -> None:
        """加载后应能获取所有标准标识。"""
        kb = KnowledgeBase(kb_path)
        standards = kb.get_standards()
        assert "GB/T 34944-2017" in standards
        assert "GB/T 34943-2017" in standards
        assert "GB/T 39412-2020" in standards
        assert len(standards) == 3


# ─── Java 漏洞查询 ───────────────────────────────────────────────


class TestJavaVulns:
    """测试 GB/T 34944-2017 Java 漏洞查询。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_get_java_vulns_count(self, kb: KnowledgeBase) -> None:
        """Java 漏洞应返回 2 条（测试数据）。"""
        vulns = kb.get_java_vulns()
        assert len(vulns) == 2

    def test_java_vulns_have_required_fields(self, kb: KnowledgeBase) -> None:
        """每条 Java 漏洞应包含必填字段。"""
        required = {"clause", "name", "category", "language", "description", "risk", "fix"}
        for vuln in kb.get_java_vulns():
            assert required.issubset(vuln.keys())

    def test_java_vulns_all_have_language_java(self, kb: KnowledgeBase) -> None:
        """Java 标准下的漏洞 language 字段应为 'Java'。"""
        for vuln in kb.get_java_vulns():
            assert vuln["language"] == "Java"


# ─── C/C++ 漏洞查询 ──────────────────────────────────────────────


class TestCppVulns:
    """测试 GB/T 34943-2017 C/C++ 漏洞查询。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_get_cpp_vulns_count(self, kb: KnowledgeBase) -> None:
        """C/C++ 漏洞应返回 2 条（测试数据）。"""
        vulns = kb.get_cpp_vulns()
        assert len(vulns) == 2

    def test_cpp_vulns_have_required_fields(self, kb: KnowledgeBase) -> None:
        """每条 C/C++ 漏洞应包含必填字段。"""
        required = {"clause", "name", "category", "language", "description", "risk", "fix"}
        for vuln in kb.get_cpp_vulns():
            assert required.issubset(vuln.keys())

    def test_buffer_overflow_present(self, kb: KnowledgeBase) -> None:
        """C/C++ 漏洞中应包含缓冲区溢出。"""
        vulns = kb.get_cpp_vulns()
        names = [v["name"] for v in vulns]
        assert "缓冲区溢出" in names


# ─── 按条款号查询 ────────────────────────────────────────────────


class TestGetByClause:
    """测试按国标条款号精确查找。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_get_existing_java_clause(self, kb: KnowledgeBase) -> None:
        """按存在的 Java 条款号查询应返回完整定义。"""
        vuln = kb.get_by_clause("6.2.3.4")
        assert vuln is not None
        assert vuln["name"] == "SQL注入"
        assert vuln["category"] == "数据处理"
        assert vuln["language"] == "Java"

    def test_get_existing_cpp_clause(self, kb: KnowledgeBase) -> None:
        """按存在的 C/C++ 条款号查询应返回完整定义。"""
        vuln = kb.get_by_clause("7.2.3.6")
        assert vuln is not None
        assert vuln["name"] == "缓冲区溢出"
        assert vuln["language"] == "C\\C++"

    def test_get_nonexistent_clause(self, kb: KnowledgeBase) -> None:
        """不存在的条款号应返回 None。"""
        vuln = kb.get_by_clause("9.9.9.9")
        assert vuln is None

    def test_get_empty_clause(self, kb: KnowledgeBase) -> None:
        """空字符串条款号应返回 None。"""
        vuln = kb.get_by_clause("")
        assert vuln is None

    def test_get_partial_clause(self, kb: KnowledgeBase) -> None:
        """部分匹配的条款号不予返回（精确匹配）。"""
        vuln = kb.get_by_clause("6.2.3")
        assert vuln is None


# ─── 合并查询 ────────────────────────────────────────────────────


class TestAllVulns:
    """测试合并查询接口。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_get_all_vulns_count(self, kb: KnowledgeBase) -> None:
        """合并查询应返回 4 条（Java 2 + C/C++ 2）。"""
        all_vulns = kb.get_all_vulns()
        assert len(all_vulns) == 4

    def test_count_vulns(self, kb: KnowledgeBase) -> None:
        """按标准统计数量。"""
        counts = kb.count_vulns()
        assert counts["GB/T 34944-2017"] == 2
        assert counts["GB/T 34943-2017"] == 2


# ─── 按语言筛选 ──────────────────────────────────────────────────


class TestGetByLanguage:
    """测试按语言筛选漏洞。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_filter_java(self, kb: KnowledgeBase) -> None:
        """筛选 Java 语言漏洞。"""
        vulns = kb.get_vulns_by_language("Java")
        assert len(vulns) == 2
        for v in vulns:
            assert v["clause"].startswith("6.2")

    def test_filter_cpp(self, kb: KnowledgeBase) -> None:
        """筛选 C/C++ 语言漏洞（含转义字符兼容）。"""
        vulns = kb.get_vulns_by_language("C/C++")
        assert len(vulns) == 2
        for v in vulns:
            assert v["clause"].startswith("7.2")

    def test_filter_unknown_language(self, kb: KnowledgeBase) -> None:
        """筛选不存在的语言应返回空列表。"""
        vulns = kb.get_vulns_by_language("Python")
        assert len(vulns) == 0


# ─── 按类别筛选 ──────────────────────────────────────────────────


class TestGetByCategory:
    """测试按漏洞大类筛选。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_filter_数据处理(self, kb: KnowledgeBase) -> None:
        """筛选 '数据处理' 类别应返回 SQL注入 + 缓冲区溢出。"""
        vulns = kb.get_vulns_by_category("数据处理")
        assert len(vulns) == 2
        names = {v["name"] for v in vulns}
        assert names == {"SQL注入", "缓冲区溢出"}

    def test_filter_安全功能(self, kb: KnowledgeBase) -> None:
        """筛选 '安全功能' 类别应返回两条口令硬编码。"""
        vulns = kb.get_vulns_by_category("安全功能")
        assert len(vulns) == 2
        for v in vulns:
            assert v["name"] == "口令硬编码"

    def test_filter_unknown_category(self, kb: KnowledgeBase) -> None:
        """筛选不存在的大类应返回空列表。"""
        vulns = kb.get_vulns_by_category("宇宙问题")
        assert len(vulns) == 0


# ─── 名称搜索 ────────────────────────────────────────────────────


class TestSearchByName:
    """测试按漏洞名称模糊搜索。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_search_sql(self, kb: KnowledgeBase) -> None:
        """搜索 'SQL' 应命中 SQL注入。"""
        results = kb.search_by_name("SQL")
        assert len(results) == 1
        assert results[0]["name"] == "SQL注入"

    def test_search_口令(self, kb: KnowledgeBase) -> None:
        """搜索 '口令' 应命中两条口令硬编码。"""
        results = kb.search_by_name("口令")
        assert len(results) == 2

    def test_search_no_match(self, kb: KnowledgeBase) -> None:
        """无匹配时应返回空列表。"""
        results = kb.search_by_name("量子计算")
        assert len(results) == 0

    def test_search_case_insensitive(self, kb: KnowledgeBase) -> None:
        """搜索应不区分大小写。"""
        results = kb.search_by_name("sql")
        assert len(results) == 1
        assert results[0]["name"] == "SQL注入"


# ─── 标准信息 ────────────────────────────────────────────────────


class TestStandardInfo:
    """测试标准元信息查询。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_get_java_standard_info(self, kb: KnowledgeBase) -> None:
        """Java 标准信息应包含 full_name 和 clause_prefix。"""
        info = kb.get_standard_info("GB/T 34944-2017")
        assert info["full_name"] == "Java语言源代码漏洞测试规范"
        assert info["clause_prefix"] == "6.2"
        assert info["language"] == "Java"
        assert "vulnerabilities" not in info  # 不暴露漏洞列表

    def test_get_unknown_standard(self, kb: KnowledgeBase) -> None:
        """不存在的标准应返回空字典。"""
        info = kb.get_standard_info("GB/T 99999")
        assert info == {}


# ─── 类别统计 ────────────────────────────────────────────────────


class TestGetCategories:
    """测试类别统计。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_get_categories(self, kb: KnowledgeBase) -> None:
        """应正确统计各类别漏洞数量。"""
        cats = kb.get_categories()
        assert cats["数据处理"] == 2
        assert cats["安全功能"] == 2
        assert len(cats) == 2


# ─── GB/T 39412 审计指标 ─────────────────────────────────────────


class TestAuditSteps:
    """测试 GB/T 39412-2020 审计指标查询。"""

    @pytest.fixture
    def kb(self, kb_path: Path) -> KnowledgeBase:
        return KnowledgeBase(kb_path)

    def test_get_audit_steps_existing(self, kb: KnowledgeBase) -> None:
        """按存在的条款号查询审计步骤。"""
        steps = kb.get_audit_steps("6.1.1.6")
        assert steps is not None
        assert steps["标准条款标题"] == "命令行注入"
        assert "system()" in steps["Sink"]
        assert "白名单验证" in steps["Sanitize"]

    def test_get_audit_steps_nonexistent(self, kb: KnowledgeBase) -> None:
        """不存在的审计指标应返回 None。"""
        steps = kb.get_audit_steps("9.9.9.9")
        assert steps is None

    def test_get_all_audit_items(self, kb: KnowledgeBase) -> None:
        """应返回全部 2 个审计指标。"""
        items = kb.get_all_audit_items()
        assert len(items) == 2

    def test_get_audit_items_by_language(self, kb: KnowledgeBase) -> None:
        """按语言筛选审计指标。"""
        items = kb.get_audit_items_by_language("Java")
        # "Java/C++" 包含 Java
        assert len(items) == 2

    def test_audit_items_have_source_sink_sanitize(self, kb: KnowledgeBase) -> None:
        """每个审计指标应包含 Source、Sink、Sanitize 字段。"""
        for item in kb.get_all_audit_items():
            assert "Source" in item
            assert "Sink" in item
            assert "Sanitize" in item
            assert "误报排除" in item
            assert "修复建议" in item

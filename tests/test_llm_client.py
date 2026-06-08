"""测试 llm_client.py —— DeepSeek LLM 客户端。

所有测试使用 mock 对象，不发起真实网络请求。
"""

from __future__ import annotations

import json
import os
from unittest import mock

import pytest

from src.llm_client import (
    LLMClient,
    LLMConfig,
    MissedScanResult,
    ReviewResult,
    _build_review_prompt,
    build_kb_context_for_clause,
)


# ─── helpers ──────────────────────────────────────────────────────


def _mock_anthropic_message(text: str):
    """构造一个假的 Anthropic SDK 消息响应对象。"""
    block = mock.MagicMock()
    block.text = text
    response = mock.MagicMock()
    response.content = [block]
    return response


def _patch_anthropic():
    """返回一个 mock，使得 LLMClient 能够创建一个假的 Anthropic 实例。"""
    mock_client = mock.MagicMock()
    mock_client.messages.create.return_value = _mock_anthropic_message(
        json.dumps({
            "verdict": "confirmed",
            "confidence": 0.85,
            "reasoning": "检测到字符串拼接构建 SQL 语句，存在 SQL 注入风险",
            "evidence": "第42行使用了字符串拼接: query = 'SELECT...' + userId",
            "exploit_scenario": "攻击者可注入 ' OR '1'='1' -- 绕过认证",
            "fix_suggestion": "使用 PreparedStatement 代替字符串拼接",
        }, ensure_ascii=False)
    )
    # 返回可调用对象，模拟 Anthropic 构造函数
    return lambda *args, **kwargs: mock_client


# ─── LLMConfig ────────────────────────────────────────────────────


class TestLLMConfig:
    """测试 LLM 配置。"""

    def test_default_values(self) -> None:
        """默认配置应有合理的值。"""
        cfg = LLMConfig()
        assert cfg.base_url == "https://api.deepseek.com/anthropic"
        assert cfg.model == "deepseek-chat"
        assert cfg.max_tokens == 1024

    def test_api_key_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API key 应从环境变量读取。"""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key-123")
        cfg = LLMConfig()
        assert cfg.api_key == "sk-test-key-123"

    def test_explicit_api_key_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """显式传入的 API key 应覆盖环境变量。"""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env-key")
        cfg = LLMConfig(api_key="sk-explicit-key")
        assert cfg.api_key == "sk-explicit-key"

    def test_api_key_empty_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无环境变量时 API key 应为空。"""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        cfg = LLMConfig()
        assert cfg.api_key == ""


# ─── is_available ─────────────────────────────────────────────────


class TestIsAvailable:
    """测试客户端可用性判断。"""

    def test_available_with_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """有 API key 时应可用。"""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        with mock.patch("src.llm_client.Anthropic", new=_patch_anthropic()):
            client = LLMClient()
            assert client.is_available() is True

    def test_unavailable_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无 API key 时不可用。"""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        with mock.patch("src.llm_client.Anthropic", new=_patch_anthropic()):
            client = LLMClient(LLMConfig(api_key=""))
            assert client.is_available() is False

    def test_unavailable_when_sdk_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SDK 未安装时不可用。"""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        with mock.patch("src.llm_client.Anthropic", None):
            client = LLMClient()
            assert client.is_available() is False


# ─── review_finding ───────────────────────────────────────────────


class TestReviewFinding:
    """测试 LLM 二次确认功能。"""

    @pytest.fixture
    def client(self, monkeypatch: pytest.MonkeyPatch) -> LLMClient:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setattr("shutil.which", lambda cmd: None)  # 禁用 claude CLI
        with mock.patch("src.llm_client.Anthropic", new=_patch_anthropic()):
            return LLMClient()

    @pytest.fixture
    def sample_finding(self) -> dict:
        return {
            "clause": "6.2.3.4",
            "file_path": "src/LoginServlet.java",
            "line_start": 42,
            "line_end": 48,
            "code_snippet": 'String query = "SELECT * FROM users WHERE id=\'" + uid + "\'";',
            "source_tool": "semgrep",
            "tool_raw_output": {"rule": "java-sql-injection", "severity": "ERROR"},
        }

    def test_review_confirms_finding(
        self, client: LLMClient, sample_finding: dict
    ) -> None:
        """正常场景：LLM 确认漏洞存在。"""
        kb_ctx = "SQL注入: 使用未经验证的输入拼接SQL语句。"
        result = client.review_finding(sample_finding, kb_ctx)

        assert isinstance(result, ReviewResult)
        assert result.verdict == "confirmed"
        assert result.confidence == 0.85
        assert "字符串拼接" in result.reasoning
        assert result.clause == "6.2.3.4"
        assert result.raw_response != ""
        assert result.is_confirmed() is True

    def test_review_with_retry_on_failure(
        self, client: LLMClient, sample_finding: dict
    ) -> None:
        """网络错误后应重试。"""
        # 第一次失败，第二次成功
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionError("模拟网络错误")
            return _mock_anthropic_message(
                json.dumps({"verdict": "confirmed", "confidence": 0.9})
            )

        assert client._client is not None
        client._client.messages.create.side_effect = side_effect

        kb_ctx = "SQL注入定义..."
        result = client.review_finding(sample_finding, kb_ctx)
        assert call_count[0] == 2  # 第一次失败，第二次成功
        assert result.verdict == "confirmed"

    def test_review_exhausts_retries(
        self, client: LLMClient, sample_finding: dict
    ) -> None:
        """全部重试失败应抛出 RuntimeError（禁用 DeepSeek 直连降级）。"""
        assert client._client is not None
        client._client.messages.create.side_effect = ConnectionError("持续失败")
        client._fallback_direct_key = ""  # 禁用 Level 2 降级

        with pytest.raises(RuntimeError, match="LLM 调用失败"):
            client.review_finding(sample_finding, "ctx")

    def test_review_unavailable_client_raises(self, monkeypatch, sample_finding: dict) -> None:
        """不可用的客户端调用 review_finding 应抛出 RuntimeError。"""
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        client = LLMClient(LLMConfig(api_key=""))
        with pytest.raises(RuntimeError, match="LLM 客户端不可用"):
            client.review_finding(sample_finding, "ctx")

    def test_review_result_is_not_confirmed_when_rejected(
        self, client: LLMClient, sample_finding: dict
    ) -> None:
        """LLM 判定为误报时应返回 rejected。"""
        assert client._client is not None
        client._client.messages.create.return_value = _mock_anthropic_message(
            json.dumps({
                "verdict": "rejected",
                "confidence": 0.9,
                "reasoning": "该代码片段中的 SQL 使用的是常量拼接，无外部输入。",
            })
        )
        result = client.review_finding(sample_finding, "ctx")
        assert result.verdict == "rejected"
        assert result.is_confirmed() is False


# ─── 解析异常处理 ─────────────────────────────────────────────────


class TestParseEdgeCases:
    """测试 LLM 响应解析的边界情况。"""

    @pytest.fixture
    def client(self, monkeypatch: pytest.MonkeyPatch) -> LLMClient:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        with mock.patch("src.llm_client.Anthropic", new=_patch_anthropic()):
            return LLMClient()

    def test_malformed_json_fallback(self, client: LLMClient) -> None:
        """LLM 返回非法 JSON 时应 fallback 为 uncertain。"""
        assert client._client is not None
        client._client.messages.create.return_value = _mock_anthropic_message(
            "嗯…看起来这个代码片段有安全问题……（非JSON格式）"
        )
        finding = {"clause": "6.2.3.4", "file_path": "f.java",
                   "line_start": 1, "line_end": 2, "code_snippet": "x",
                   "source_tool": "s", "tool_raw_output": {}}
        result = client.review_finding(finding, "ctx")
        assert result.verdict == "uncertain"
        assert result.confidence == 0.3
        assert "非结构化" in result.reasoning

    def test_json_in_code_block(self, client: LLMClient) -> None:
        """JSON 包裹在 ```json 代码块中时应正确提取。"""
        assert client._client is not None
        client._client.messages.create.return_value = _mock_anthropic_message(
            '好的，这是我的判断：\n```json\n{"verdict": "confirmed", "confidence": 0.95, "reasoning": "明显SQL注入"}\n```\n'
        )
        finding = {"clause": "6.2.3.4", "file_path": "f.java",
                   "line_start": 1, "line_end": 2, "code_snippet": "x",
                   "source_tool": "s", "tool_raw_output": {}}
        result = client.review_finding(finding, "ctx")
        assert result.verdict == "confirmed"
        assert result.confidence == 0.95

    def test_invalid_verdict_mapped_to_uncertain(self, client: LLMClient) -> None:
        """非法 verdict 值应被标准化为 uncertain。"""
        assert client._client is not None
        client._client.messages.create.return_value = _mock_anthropic_message(
            json.dumps({"verdict": "maybe", "confidence": 0.5})
        )
        finding = {"clause": "6.2.3.4", "file_path": "f.java",
                   "line_start": 1, "line_end": 2, "code_snippet": "x",
                   "source_tool": "s", "tool_raw_output": {}}
        result = client.review_finding(finding, "ctx")
        assert result.verdict == "uncertain"

    def test_confidence_clamped(self, client: LLMClient) -> None:
        """confidence 值应被钳制在 [0.0, 1.0] 范围内。"""
        assert client._client is not None
        client._client.messages.create.return_value = _mock_anthropic_message(
            json.dumps({"verdict": "confirmed", "confidence": 1.5})
        )
        finding = {"clause": "6.2.3.4", "file_path": "f.java",
                   "line_start": 1, "line_end": 2, "code_snippet": "x",
                   "source_tool": "s", "tool_raw_output": {}}
        result = client.review_finding(finding, "ctx")
        assert result.confidence == 1.0

        client._client.messages.create.return_value = _mock_anthropic_message(
            json.dumps({"verdict": "confirmed", "confidence": -0.5})
        )
        result = client.review_finding(finding, "ctx")
        assert result.confidence == 0.0


# ─── scan_missed ──────────────────────────────────────────────────


class TestScanMissed:
    """测试漏报扫描功能。"""

    @pytest.fixture
    def client(self, monkeypatch: pytest.MonkeyPatch) -> LLMClient:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        with mock.patch("src.llm_client.Anthropic", new=_patch_anthropic()):
            return LLMClient()

    def test_scan_discovers_vulnerability(self, client: LLMClient) -> None:
        """扫描应发现文件中存在的漏洞。"""
        assert client._client is not None
        client._client.messages.create.return_value = _mock_anthropic_message(
            json.dumps({
                "findings": [
                    {
                        "line_start": 10,
                        "line_end": 15,
                        "confidence": 0.9,
                        "reasoning": "直接使用 referer 字段进行权限判断",
                        "evidence": 'if ("admin".equals(referer))',
                        "exploit_scenario": "攻击者可修改 HTTP Referer 头",
                        "fix_suggestion": "使用服务端 Session 验证身份",
                    }
                ]
            })
        )

        files = [{"path": "src/AuthFilter.java",
                   "content": 'String referer = request.getHeader("referer");\nif ("admin".equals(referer)) {\n    // grant access\n}'}]
        results = client.scan_missed("6.2.6.4", files, "依赖Referer鉴权的定义...")

        assert len(results) == 1
        assert isinstance(results[0], MissedScanResult)
        assert results[0].clause == "6.2.6.4"
        assert results[0].file_path == "src/AuthFilter.java"
        assert len(results[0].findings) == 1
        assert results[0].findings[0]["confidence"] == 0.9

    def test_scan_no_findings(self, client: LLMClient) -> None:
        """无漏洞时应返回空 findings。"""
        assert client._client is not None
        client._client.messages.create.return_value = _mock_anthropic_message(
            json.dumps({"findings": []})
        )

        results = client.scan_missed("6.2.6.4",
                                     [{"path": "Safe.java", "content": "// safe code"}],
                                     "ctx")
        assert len(results) == 1
        assert results[0].findings == []

    def test_scan_empty_file(self, client: LLMClient) -> None:
        """空文件应直接跳过，不调用 LLM。"""
        results = client.scan_missed("6.2.6.4",
                                     [{"path": "Empty.java", "content": ""}],
                                     "ctx")
        assert len(results) == 1
        assert results[0].findings == []

    def test_scan_unavailable_raises(self, monkeypatch) -> None:
        """不可用的客户端应抛出异常。"""
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        client = LLMClient(LLMConfig(api_key=""))
        with pytest.raises(RuntimeError, match="LLM 客户端不可用"):
            client.scan_missed("6.2.6.4", [{"path": "f", "content": "code"}], "ctx")


# ─── _extract_json ────────────────────────────────────────────────


class TestExtractJson:
    """测试 JSON 提取工具方法。"""

    def test_pure_json(self) -> None:
        """纯 JSON 输入。"""
        raw = '{"verdict": "confirmed", "confidence": 0.8}'
        result = LLMClient._extract_json(raw)
        assert "confirmed" in result
        assert "confidence" in result

    def test_json_with_markdown_wrapper(self) -> None:
        """```json ... ``` 包裹的 JSON。"""
        raw = 'Sure! Here is my analysis:\n```json\n{"findings": [{"line": 1}]}\n```\nHope it helps.'
        result = LLMClient._extract_json(raw)
        assert '"findings"' in result
        assert "Sure" not in result

    def test_json_with_generic_code_block(self) -> None:
        """``` ... ``` 无语言标识的包裹。"""
        raw = '```\n{"verdict": "rejected"}\n```'
        result = LLMClient._extract_json(raw)
        assert '"verdict"' in result

    def test_text_with_embedded_json(self) -> None:
        """JSON 嵌入在普通文本中。"""
        raw = '结论：{"verdict": "confirmed", "confidence": 0.7}。建议修复。'
        result = LLMClient._extract_json(raw)
        assert '"verdict"' in result


# ─── _build_review_prompt ─────────────────────────────────────────


class TestBuildReviewPrompt:
    """测试 Prompt 构建。"""

    def test_basic_prompt_structure(self) -> None:
        """基本 Prompt 结构应包含必要信息。"""
        finding = {
            "clause": "6.2.3.4",
            "file_path": "src/Login.java",
            "line_start": 42,
            "line_end": 48,
            "code_snippet": "String q = \"SELECT * FROM users WHERE id='\" + uid + \"'\";",
            "source_tool": "semgrep",
            "tool_raw_output": {},
        }
        kb_ctx = "SQL注入: 使用未经验证的输入。"
        prompt = _build_review_prompt(finding, kb_ctx, None)

        assert "标准引用" in prompt
        assert "SQL注入" in prompt
        assert "待审查代码" in prompt
        assert "src/Login.java" in prompt
        assert "42" in prompt
        assert "String q" in prompt

    def test_prompt_includes_history_examples(self) -> None:
        """历史案例应出现在 Prompt 中。"""
        finding = {
            "clause": "6.2.3.4",
            "file_path": "f.java",
            "line_start": 1,
            "line_end": 2,
            "code_snippet": "x",
            "source_tool": "s",
            "tool_raw_output": {},
        }
        history = [
            {"type": "tp", "code": "bad code here", "reason": "真实注入"},
            {"type": "fp", "code": "safe code here", "reason": "常量拼接", "distinction": "无外部输入"},
        ]
        prompt = _build_review_prompt(finding, "ctx", history)

        assert "历史案例" in prompt
        assert "真阳性案例" in prompt
        assert "bad code here" in prompt
        assert "误报的案例" in prompt
        assert "safe code here" in prompt
        assert "常量拼接" in prompt


# ─── build_kb_context_for_clause ──────────────────────────────────


class TestBuildKbContext:
    """测试从知识库构建上下文的便捷函数。"""

    def test_build_context_for_sql_injection(self, kb_path: str) -> None:
        """从真实格式的知识库构建上下文。"""
        from src.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(kb_path)
        ctx = build_kb_context_for_clause(kb, "6.2.3.4")
        assert "SQL注入" in ctx
        assert "未经验证" in ctx
        assert "PreparedStatement" in ctx

    def test_build_context_for_unknown_clause(self, kb_path: str) -> None:
        """不存在的条款号应返回提示。"""
        from src.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(kb_path)
        ctx = build_kb_context_for_clause(kb, "9.9.9.9")
        assert "未找到条款" in ctx


# ─── check_connectivity ───────────────────────────────────────────


class TestCheckConnectivity:
    """测试网络连通性检测。"""

    def test_available_client_can_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """有 API key 时可以尝试连通性检测。"""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        with mock.patch("src.llm_client.Anthropic", new=_patch_anthropic()):
            client = LLMClient()
            with mock.patch.object(client._client.messages, "create", return_value=mock.MagicMock()):
                assert client.check_connectivity() is True

    def test_unavailable_client_connectivity_false(self, monkeypatch) -> None:
        """不可用的客户端连通性检测应返回 False。"""
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        client = LLMClient(LLMConfig(api_key=""))
        assert client.check_connectivity() is False

    def test_network_error_connectivity_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无 API key 应返回 False。"""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        client = LLMClient(LLMConfig(api_key=""))
        assert client.check_connectivity() is False


# ─── MissedScanResult / ReviewResult ──────────────────────────────


class TestResultTypes:
    """测试结果数据类。"""

    def test_review_result_is_confirmed(self) -> None:
        """is_confirmed 方法应正确反映 verdict。"""
        r = ReviewResult(clause="6.2.3.4", verdict="confirmed", confidence=0.9)
        assert r.is_confirmed() is True

        r = ReviewResult(clause="6.2.3.4", verdict="rejected", confidence=0.9)
        assert r.is_confirmed() is False

        r = ReviewResult(clause="6.2.3.4", verdict="uncertain", confidence=0.5)
        assert r.is_confirmed() is False

    def test_missed_scan_result_defaults(self) -> None:
        """MissedScanResult 默认值。"""
        r = MissedScanResult(clause="6.2.6.4", file_path="f.java")
        assert r.clause == "6.2.6.4"
        assert r.findings == []

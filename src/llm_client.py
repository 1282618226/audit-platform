"""LLM 客户端 —— 通过 Anthropic SDK 调用 DeepSeek API。

功能:
  1. review_finding:    对 SAST 检出结果进行 LLM 二次确认
  2. scan_missed:       对 SAST 无法覆盖的漏洞类型进行逐文件审查
  3. check_connectivity: 检测 DeepSeek API 是否可达（用于离线/在线模式判断）

设计依据:
  - 设计文档 Section 2.2.5 Phase 4: LLM 二次确认阶段
  - 设计文档 Section 4.2: 扫描优先级中的 LLM 业务逻辑扫描
  - Prompt 构造策略（四区域: SYSTEM + STANDARD_REFERENCE + FEW-SHOT + CODE）
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Anthropic SDK 会在运行时检查; 如果未安装，在离线模式下也不会用到
try:
    from anthropic import Anthropic
except ImportError:  # pragma: no cover
    Anthropic = None  # type: ignore[assignment]


# ─── 配置 ─────────────────────────────────────────────────────────

@dataclass
class LLMConfig:
    """LLM 客户端配置。

    Attributes:
        base_url: DeepSeek API 的 Anthropic 兼容端点。
        api_key: API 密钥。优先读环境变量 ANTHROPIC_API_KEY。
        model: 默认模型名称。
        reason_model: 推理模型（复杂判断时使用）。
        max_tokens: 响应最大 token 数。
        timeout: HTTP 请求超时秒数。
        max_retries: 网络错误时的重试次数。
        retry_delay: 重试间隔秒数。
    """

    base_url: str = "https://api.deepseek.com/anthropic"
    api_key: str = ""
    model: str = "deepseek-chat"
    reason_model: str = "deepseek-reasoner"
    max_tokens: int = 1024
    timeout: float = 30.0
    max_retries: int = 2
    retry_delay: float = 1.0

    def __post_init__(self) -> None:
        if not self.api_key:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")


# ─── 结果类型 ─────────────────────────────────────────────────────


@dataclass
class ReviewResult:
    """LLM 对单条发现的审查结论。

    Attributes:
        clause: 国标条款号。
        verdict: "confirmed" | "rejected" | "uncertain"。
        confidence: 置信度 0.0-1.0。
        reasoning: LLM 的判断依据。
        evidence: 代码中支撑判断的具体证据。
        exploit_scenario: 攻击者可能的利用方式。
        fix_suggestion: 修复建议。
        raw_response: LLM 的原始返回文本（调试用）。
    """

    clause: str
    verdict: str  # "confirmed" | "rejected" | "uncertain"
    confidence: float
    reasoning: str = ""
    evidence: str = ""
    exploit_scenario: str = ""
    fix_suggestion: str = ""
    raw_response: str = ""

    def is_confirmed(self) -> bool:
        """LLM 是否确认这是一个真实漏洞。"""
        return self.verdict == "confirmed"


@dataclass
class MissedScanResult:
    """LLM 对 SAST 盲区的扫描结果（逐文件审查）。

    Attributes:
        clause: 国标条款号。
        file_path: 被扫描的文件。
        findings: 发现的漏洞列表，每项为 {line_start, line_end, confidence, reasoning, ...}。
    """

    clause: str
    file_path: str
    findings: list[dict[str, Any]] = field(default_factory=list)


# ─── Prompt 构建 ──────────────────────────────────────────────────

REVIEW_SYSTEM_PROMPT = """你是一名资深源代码安全审计专家，熟悉以下中国国家标准:
  - GB/T 34944-2017  Java语言源代码漏洞测试规范
  - GB/T 34943-2017  C/C++语言源代码漏洞测试规范
  - GB/T 39412-2020  信息安全技术 代码安全审计规范

你的任务是审查代码片段，判断是否存在指定的安全漏洞。

你必须以严格的 JSON 格式返回判断结果，不要包含 JSON 之外的内容。
返回格式:
{
  "verdict": "confirmed" | "rejected" | "uncertain",
  "confidence": 0.0 到 1.0 之间的浮点数,
  "reasoning": "判断依据的简洁描述",
  "evidence": "代码中支撑判断的具体证据",
  "exploit_scenario": "攻击者可能如何利用此漏洞（如果 verdict=rejected 则填'不适用'）",
  "fix_suggestion": "修复建议"
}

注意:
- confirmed: 确认存在该漏洞
- rejected: 确认不存在该漏洞（误报）
- uncertain: 无法确定，需要人工审查
- confidence 反映你对判断的确信程度
"""

MISSED_SCAN_SYSTEM_PROMPT = """你是一名资深源代码安全审计专家，熟悉以下中国国家标准:
  - GB/T 34944-2017  Java语言源代码漏洞测试规范
  - GB/T 34943-2017  C/C++语言源代码漏洞测试规范
  - GB/T 39412-2020  信息安全技术 代码安全审计规范

你的任务是审查代码文件，检查是否存在自动化工具（SAST）无法检测的特定类型漏洞。
这类漏洞通常涉及业务逻辑、语义层面的判断，而非简单的模式匹配。

请以严格的 JSON 格式返回，格式:
{
  "findings": [
    {
      "line_start": 整数,
      "line_end": 整数,
      "confidence": 0.0-1.0,
      "reasoning": "判断依据",
      "evidence": "代码证据",
      "exploit_scenario": "攻击场景",
      "fix_suggestion": "修复建议"
    }
  ]
}

如果没有发现漏洞，返回 {"findings": []}。
"""


def _build_review_prompt(
    finding: dict[str, Any],
    kb_context: str,
    history_examples: list[dict[str, Any]] | None = None,
) -> str:
    """构造 LLM 审查 Prompt。

    Args:
        finding: SAST 发现，含 clause, file_path, line_start, code_snippet, source_tool 等。
        kb_context: 来自 knowledge_base 的漏洞描述 + 风险 + 修复建议。
        history_examples: 历史误报/漏报案例列表。

    Returns:
        完整的用户消息字符串。
    """
    parts: list[str] = []

    # ── 区域 1: 标准引用 ──
    parts.append("## 标准引用")
    parts.append(kb_context)
    parts.append("")

    # ── 区域 2: Few-Shot 示例 ──
    if history_examples:
        parts.append("## 历史案例（来自以往 CNAS 审计反馈）")
        tp_examples = [e for e in history_examples if e.get("type") == "tp"]
        fp_examples = [e for e in history_examples if e.get("type") == "fp"]

        if tp_examples:
            parts.append("### 此前确认的真阳性案例:")
            for ex in tp_examples[:2]:
                parts.append(f"```\n{ex.get('code', '')}\n```")
                parts.append(f"为什么是真的: {ex.get('reason', '')}")
                parts.append("")

        if fp_examples:
            parts.append("### 此前确认为误报的案例（请特别注意区分）:")
            for ex in fp_examples[:2]:
                parts.append(f"```\n{ex.get('code', '')}\n```")
                parts.append(f"为什么是误报: {ex.get('reason', '')}")
                parts.append(f"关键区别: {ex.get('distinction', '')}")
                parts.append("")

    # ── 区域 3: 待审查代码 ──
    parts.append("## 待审查代码")
    parts.append(f"- 文件: {finding.get('file_path', 'unknown')}")
    parts.append(f"- 行号: {finding.get('line_start', '?')}-{finding.get('line_end', '?')}")
    parts.append(f"- 工具: {finding.get('source_tool', 'unknown')}")
    code = finding.get("code_snippet", "")
    if code:
        parts.append(f"```\n{code}\n```")
    parts.append("")

    # ── 区域 4: 已有工具结果 ──
    tool_output = finding.get("tool_raw_output", {})
    if tool_output:
        parts.append("## SAST 工具已有判断")
        parts.append(f"```json\n{json.dumps(tool_output, ensure_ascii=False, indent=2)}\n```")
        parts.append("")

    parts.append("请返回你的审查结论（JSON 格式）:")
    return "\n".join(parts)


# ─── LLM 客户端 ───────────────────────────────────────────────────


class LLMClient:
    """DeepSeek LLM 客户端，通过 Anthropic SDK 调用。

    用法:
        client = LLMClient(config)
        if client.is_available():
            result = client.review_finding(finding, kb_context)
    """

    def __init__(self, config: LLMConfig | None = None) -> None:
        """初始化 LLM 客户端。优先 claude CLI，回退到 Python SDK。"""
        self._config = config or LLMConfig()
        self._client: Any = None
        self._use_claude = bool(shutil.which("claude"))

        if self._use_claude:
            logger.info("LLM: 使用 claude CLI")
            self._client = True
        elif Anthropic is not None and self._config.api_key:
            self._client = Anthropic(
                base_url=self._config.base_url,
                api_key=self._config.api_key,
                timeout=self._config.timeout,
                max_retries=0,
            )
            logger.info("LLM: 使用 Python Anthropic SDK")

    def is_available(self) -> bool:
        """LLM 客户端是否可用（有 SDK + 有 API Key）。"""
        return self._client is not None

    def check_connectivity(self, timeout: float = 5.0) -> bool:
        """检测 LLM API 是否可达。"""
        if not self._client:
            return False
        # 标记为可用，真实调用在 _call_with_retry 中处理失败重试
        return True

    def review_finding(
        self,
        finding: dict[str, Any],
        kb_context: str,
        history_examples: list[dict[str, Any]] | None = None,
    ) -> ReviewResult:
        """对单个 SAST 发现进行 LLM 二次确认。

        Args:
            finding: SAST 发现字典。需包含 clause, file_path, line_start,
                     line_end, code_snippet, source_tool, tool_raw_output。
            kb_context: 来自知识库的漏洞上下文（含 description, risk, fix,
                        negative_code, positive_code）。
            history_examples: 历史反馈案例 [{type: "tp"|"fp", code, reason, distinction}]。

        Returns:
            ReviewResult 包含 verdict 和置信度。

        Raises:
            RuntimeError: LLM 不可用时调用此方法。
        """
        if not self.is_available():
            raise RuntimeError("LLM 客户端不可用（缺少 API Key 或 SDK）")

        prompt = _build_review_prompt(finding, kb_context, history_examples)
        raw = self._call_with_retry(REVIEW_SYSTEM_PROMPT, prompt)
        parsed = self._parse_review_response(raw, finding.get("clause", ""))

        # 附加原始响应
        if parsed:
            parsed.raw_response = raw

        return parsed

    def scan_missed(
        self,
        clause: str,
        files: list[dict[str, Any]],
        kb_context: str,
    ) -> list[MissedScanResult]:
        """对 SAST 无法覆盖的漏洞类型，逐文件进行 LLM 审查。

        Args:
            clause: 要扫描的国标条款号。
            files: 待审查文件列表，每项为 {path, content}。
            kb_context: 来自知识库的漏洞上下文。

        Returns:
            MissedScanResult 列表，每个元素对应一个文件的扫描结果。

        Raises:
            RuntimeError: LLM 不可用时调用此方法。
        """
        if not self.is_available():
            raise RuntimeError("LLM 客户端不可用（缺少 API Key 或 SDK）")

        results: list[MissedScanResult] = []
        for f in files:
            file_path = f.get("path", "unknown")
            content = f.get("content", "")
            if not content.strip():
                results.append(MissedScanResult(clause=clause, file_path=file_path))
                continue

            prompt = self._build_missed_scan_prompt(clause, file_path, content, kb_context)
            raw = self._call_with_retry(MISSED_SCAN_SYSTEM_PROMPT, prompt)
            findings = self._parse_missed_scan_response(raw)

            results.append(
                MissedScanResult(
                    clause=clause,
                    file_path=file_path,
                    findings=findings,
                )
            )

        return results

    def batch_review(
        self,
        findings: list[dict[str, Any]],
        kb: Any = None,
    ) -> list[ReviewResult]:
        """批量审查多条 SAST 发现（一次 API 调用处理全部）。

        Args:
            findings: SAST 发现列表。
            kb: 可选的 KnowledgeBase 实例，用于获取漏洞上下文。

        Returns:
            与 findings 等长的 ReviewResult 列表。
        """
        if not self.is_available():
            raise RuntimeError("LLM 客户端不可用")

        # 构建批量 prompt：每条发现简化为关键字段
        items = []
        for i, f in enumerate(findings):
            code = f.get("code_snippet", "") or f.get("tool_raw_output", {}).get("message", "") or ""
            items.append({
                "idx": i,
                "clause": f.get("clause", ""),
                "file": f.get("file_path", ""),
                "line": f.get("line_start", 0),
                "code_snippet": (code[:200] + "...") if len(code) > 200 else code,
            })

        batch_prompt = json.dumps(items, ensure_ascii=False, indent=2)
        system = "你是一个源代码安全审计专家。判断每条发现是否为真实漏洞。" \
                 "返回JSON数组：[{\"idx\":0,\"verdict\":\"confirmed\"|\"rejected\",\"reasoning\":\"...\"},...]。"

        user = f"请分析以下 {len(items)} 条 SAST 发现，判断是否是真漏洞。\n\n{batch_prompt}"

        raw = self._call_with_retry(system, user)
        return self._parse_batch_response(raw, len(findings))

    def _parse_batch_response(self, raw: str, expected_count: int) -> list[ReviewResult]:
        """解析批量响应 JSON 数组为 ReviewResult 列表。"""
        import re
        # 提取 JSON 数组
        m = re.search(r'\[.*?\]', raw, re.DOTALL)
        if not m:
            logger.warning("LLM: 批量响应未找到 JSON 数组")
            return [ReviewResult(clause="", verdict="rejected", confidence=0.0, reasoning="parse error")] * expected_count
        try:
            parsed = json.loads(m.group(0))
        except json.JSONDecodeError:
            logger.warning("LLM: 批量响应 JSON 解析失败")
            return [ReviewResult(clause="", verdict="rejected", confidence=0.0, reasoning="parse error")] * expected_count

        results = []
        for item in parsed:
            verdict = item.get("verdict", "rejected")
            if verdict not in ("confirmed", "rejected", "needs_review"):
                verdict = "needs_review"
            confidence = 1.0 if verdict == "confirmed" else (0.0 if verdict == "rejected" else 0.5)
            results.append(ReviewResult(
                clause=item.get("clause", ""),
                verdict=verdict,
                confidence=confidence,
                reasoning=item.get("reasoning", ""),
                evidence=item.get("evidence", ""),
                fix_suggestion=item.get("fix", ""),
            ))

        # 补齐缺失的条目
        while len(results) < expected_count:
            results.append(ReviewResult(clause="", verdict="needs_review", confidence=0.5, reasoning="missing from LLM response"))

        return results[:expected_count]

    # ─── 内部方法 ────────────────────────────────────────────────

    def _call_with_retry(self, system_prompt: str, user_message: str) -> str:
        """带重试的消息调用。"""
        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                assert self._client is not None
                if self._use_claude:
                    import subprocess
                    full = f"{system_prompt}\n\n{user_message}"
                    r = subprocess.run(
                        ["claude", "-p", full, "--print"],
                        capture_output=True, text=True, timeout=self._config.timeout,
                        env={**os.environ, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"},
                    )
                    if r.returncode == 0:
                        return r.stdout.strip()
                    raise RuntimeError(f"claude exited {r.returncode}: {r.stderr[:200]}")
                response = self._client.messages.create(
                    model=self._config.model,
                    max_tokens=self._config.max_tokens,
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_message},
                    ],
                )
                content = response.content
                if isinstance(content, list):
                    return "\n".join(
                        block.text
                        for block in content
                        if hasattr(block, "text")
                    )
                return str(content)

            except Exception as e:
                last_error = e
                if attempt < self._config.max_retries:
                    time.sleep(self._config.retry_delay)

        raise RuntimeError(
            f"LLM 调用失败（重试 {self._config.max_retries} 次后仍失败）: {last_error}"
        )

    @staticmethod
    def _parse_review_response(raw: str, clause: str) -> ReviewResult:
        """解析 LLM 的 JSON 审查结果。

        尝试从 raw 中提取 JSON 块并解析。失败时返回默认 uncertain 结果。
        """
        json_str = LLMClient._extract_json(raw)

        try:
            data = json.loads(json_str)
            verdict = data.get("verdict", "uncertain")
            # 标准化 verdict 值
            if verdict not in ("confirmed", "rejected", "uncertain"):
                verdict = "uncertain"

            confidence = float(data.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))

            return ReviewResult(
                clause=clause,
                verdict=verdict,
                confidence=confidence,
                reasoning=str(data.get("reasoning", "")),
                evidence=str(data.get("evidence", "")),
                exploit_scenario=str(data.get("exploit_scenario", "")),
                fix_suggestion=str(data.get("fix_suggestion", "")),
                raw_response=raw,
            )
        except (json.JSONDecodeError, ValueError):
            # JSON 解析失败，返回一个低置信度的 uncertain 结果
            return ReviewResult(
                clause=clause,
                verdict="uncertain",
                confidence=0.3,
                reasoning=f"LLM 返回非结构化响应，无法自动解析: {raw[:200]}",
                raw_response=raw,
            )

    @staticmethod
    def _parse_missed_scan_response(raw: str) -> list[dict[str, Any]]:
        """解析 LLM 的漏报扫描结果。"""
        json_str = LLMClient._extract_json(raw)

        try:
            data = json.loads(json_str)
            return data.get("findings", [])
        except json.JSONDecodeError:
            return []

    @staticmethod
    def _extract_json(raw: str) -> str:
        """从 LLM 原始输出中提取 JSON 块。

        处理 LLM 常见的三种输出格式:
        1. 纯 JSON
        2. JSON 包裹在 ```json ... ``` 代码块中
        3. JSON 包裹在其他文本中（提取第一个 { 到最后一个 }）
        """
        raw = raw.strip()

        # 尝试提取 ```json ... ``` 中的内容
        if "```json" in raw:
            start = raw.index("```json") + len("```json")
            end = raw.index("```", start)
            return raw[start:end].strip()

        if "```" in raw:
            start = raw.index("```") + len("```")
            end = raw.index("```", start)
            return raw[start:end].strip()

        # 查找最外层的 { ... }
        first_brace = raw.find("{")
        last_brace = raw.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            return raw[first_brace : last_brace + 1]

        return raw

    @staticmethod
    def _build_missed_scan_prompt(
        clause: str,
        file_path: str,
        content: str,
        kb_context: str,
    ) -> str:
        """构造漏报扫描 Prompt。"""
        # 截断过长文件（保护 token 限制）
        max_lines = 400
        lines = content.split("\n")
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])
            content += f"\n... (文件共 {len(lines)} 行，已截断至前 {max_lines} 行)"

        return f"""## 漏洞定义
条款号: {clause}
{kb_context}

## 待审查文件
文件: {file_path}
内容:
```
{content}
```

请逐段审查上述文件，判断是否存在该条款所定义的漏洞。
以 JSON 格式返回所有发现。"""


# ─── 便捷函数 ─────────────────────────────────────────────────────


def build_kb_context_for_clause(kb: Any, clause: str) -> str:
    """从知识库构建某个条款号的上下文文本（用于注入 LLM Prompt）。

    Args:
        kb: KnowledgeBase 实例。
        clause: 国标条款号。

    Returns:
        格式化的上下文字符串，包含 description, risk, fix, 正反例代码。
        如果条款号不存在，返回提示信息。
    """
    vuln = kb.get_by_clause(clause)
    if vuln is None:
        return f"（知识库中未找到条款 {clause} 的定义）"

    parts = [
        f"**漏洞名称**: {vuln.get('name', '')}",
        f"**类别**: {vuln.get('category', '')}",
        f"**语言**: {vuln.get('language', '')}",
        f"**描述**: {vuln.get('description', '')}",
        f"**风险**: {vuln.get('risk', '')}",
        f"**修复建议**: {vuln.get('fix', '')}",
    ]

    neg = vuln.get("negative_code", "")
    if neg:
        parts.append(f"\n**漏洞代码示例（正例）**:\n```\n{neg}\n```")

    pos = vuln.get("positive_code", "")
    if pos:
        parts.append(f"**安全代码示例（反例）**:\n```\n{pos}\n```")

    return "\n".join(parts)

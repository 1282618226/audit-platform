"""规则自动调优模块。

从反馈数据库中分析误报/漏报模式，自动生成规则调整建议。

核心功能:
  1. 误报率超阈值 → 建议追加 pattern-not 或调整规则
  2. 漏报案例聚类 → 生成新规则或扩充现有 Sink 覆盖
  3. 自动决策矩阵（递进式: 标记→告警→禁用）
  4. LLM Prompt 增强 → 提取 FP/TP 案例注入 Few-Shot

设计依据:
  - 设计文档 Section 3.2: 从误报中学习
  - 设计文档 Section 3.3: 从漏报中学习
  - 设计文档 Section 3.2.3: 自动决策矩阵
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ─── 数据类型 ─────────────────────────────────────────────────────


@dataclass
class TuningAdvice:
    """单条规则的调优建议。"""

    clause: str
    vuln_name: str = ""
    action: str = ""  # "none" | "warn" | "adjust" | "disable" | "extend_sink" | "new_rule"
    severity: str = ""  # "info" | "warning" | "critical"
    reason: str = ""
    suggestion: str = ""
    fp_ratio: float = 0.0
    missed_count: int = 0

    # 具体调整内容
    pattern_not_additions: list[str] = field(default_factory=list)
    new_sinks: list[str] = field(default_factory=list)
    fp_examples: list[dict[str, Any]] = field(default_factory=list)
    tp_examples: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class TuningReport:
    """一次调优分析的完整报告。"""

    advices: list[TuningAdvice] = field(default_factory=list)
    summary: str = ""
    rules_with_issues: int = 0
    rules_healthy: int = 0
    fp_examples_for_llm: list[dict[str, Any]] = field(default_factory=list)
    tp_examples_for_llm: list[dict[str, Any]] = field(default_factory=list)


# ─── 调优器 ───────────────────────────────────────────────────────


class RuleTuner:
    """规则自动调优器。

    用法:
        tuner = RuleTuner(feedback_db, kb)
        report = tuner.analyze()
        # 查看每个条款的调优建议
        for advice in report.advices:
            print(advice.clause, advice.action, advice.suggestion)
    """

    # 决策矩阵阈值（来自设计文档 Section 3.2.3）
    THRESHOLD_SINGLE_FP_HIGH = 0.80   # 单次 FP 率 > 80% → 标记低置信度
    THRESHOLD_CONSECUTIVE_WARN = 0.50  # 连续 3 次 FP > 50% → 告警
    THRESHOLD_CONSECUTIVE_DISABLE = 0.50  # 连续 5 次 FP > 50% → 禁用
    CONSECUTIVE_RUNS_WARN = 3
    CONSECUTIVE_RUNS_DISABLE = 5

    def __init__(
        self,
        feedback_db: Any,
        kb: Any | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """初始化调优器。

        Args:
            feedback_db: FeedbackDB 实例。
            kb: KnowledgeBase 实例（可选，用于补充漏洞名称）。
            config: 调优配置（可选）。
        """
        self._db = feedback_db
        self._kb = kb
        self._config = config or {}

    def analyze(self) -> TuningReport:
        """全量分析反馈数据库，为每条有数据的规则生成调优建议。

        Returns:
            TuningReport 包含所有规则的调优建议和 LLM Few-Shot 案例。
        """
        # 确保规则效果统计是最新的
        self._db.create_tables()
        self._db.upsert_rule_effectiveness()

        # 获取所有有标注数据的规则
        all_rules = self._db.list_rule_effectiveness(min_findings=1)

        report = TuningReport()
        for rule in all_rules:
            clause = rule["clause"]
            advice = self._analyze_single_rule(clause, rule)
            report.advices.append(advice)

            if advice.action != "none":
                report.rules_with_issues += 1
            else:
                report.rules_healthy += 1

        # 生成 LLM Few-Shot 案例
        report.fp_examples_for_llm = self._build_few_shot_examples("false_positive")
        report.tp_examples_for_llm = self._build_few_shot_examples("true_positive")

        report.summary = self._build_summary(report)
        return report

    def _analyze_single_rule(
        self, clause: str, rule: dict[str, Any]
    ) -> TuningAdvice:
        """分析单条规则的调优建议。"""
        precision = rule.get("precision", 1.0)
        fp_ratio = 1.0 - precision if precision > 0 else 1.0
        total_missed = rule.get("total_missed", 0)

        advice = TuningAdvice(
            clause=clause,
            vuln_name=rule.get("vuln_name", ""),
            fp_ratio=fp_ratio,
            missed_count=total_missed,
        )

        # ── Step 1: FP 分析 ──
        fp_stats = self._db.get_fp_ratio(clause, recent_runs=3)
        recent_fp_ratio = fp_stats.get("fp_ratio", 0.0)

        # 单次高误报
        if recent_fp_ratio >= self.THRESHOLD_SINGLE_FP_HIGH:
            advice.action = "adjust"
            advice.severity = "critical"
            advice.reason = f"最近 3 次扫描 FP 率 {recent_fp_ratio:.0%} ≥ {self.THRESHOLD_SINGLE_FP_HIGH:.0%}"
            advice.suggestion = "建议标记该规则结果为低置信度，并在规则中追加 pattern-not 排除误报模式"
            advice.pattern_not_additions = self._extract_fp_patterns(clause)
            # 提取 FP 案例
            advice.fp_examples = self._get_labeled_examples(clause, "false_positive")

        # 连续多次高误报 → 升级处理
        if recent_fp_ratio >= self.THRESHOLD_CONSECUTIVE_WARN:
            consecutive = self._count_consecutive_high_fp(clause)
            if consecutive >= self.CONSECUTIVE_RUNS_DISABLE:
                advice.action = "disable"
                advice.severity = "critical"
                advice.reason = (
                    f"连续 {consecutive} 次扫描 FP 率 ≥ {self.THRESHOLD_CONSECUTIVE_DISABLE:.0%}，"
                    f"建议禁用此 SAST 规则，改用 LLM-only 检测"
                )
            elif consecutive >= self.CONSECUTIVE_RUNS_WARN:
                advice.action = "warn"
                advice.severity = "warning"
                advice.reason = (
                    f"连续 {consecutive} 次扫描 FP 率 ≥ {self.THRESHOLD_CONSECUTIVE_WARN:.0%}，"
                    f"建议重写该规则"
                )

        # ── Step 2: 漏报分析 ──
        if total_missed > 0:
            missed_cases = self._db.get_missed_by_run(
                self._db.list_scan_runs(limit=1)[0]["run_id"]
            ) if self._db.list_scan_runs(limit=1) else []

            clause_missed = [m for m in missed_cases if m["clause"] == clause]
            if clause_missed:
                # 分析漏报原因并生成建议
                advice.new_sinks = self._extract_missing_sinks(clause_missed)

                if not advice.action or advice.action == "none":
                    advice.action = "extend_sink"
                    advice.severity = "warning"
                advice.reason += f"; 漏报 {len(clause_missed)} 条"
                if advice.new_sinks:
                    advice.suggestion += (
                        f"。建议在规则中增加 Sink 覆盖: {', '.join(advice.new_sinks)}"
                    )

        # ── Step 3: 正常运行 ──
        if not advice.action:
            advice.action = "none"
            advice.severity = "info"
            advice.reason = "规则运行良好，FP 率在可接受范围内"

        # 提取 TP 案例（供 LLM Few-Shot）
        advice.tp_examples = self._get_labeled_examples(clause, "true_positive")

        return advice

    # ─── FP 模式提取 ──────────────────────────────────────────────

    def _extract_fp_patterns(self, clause: str) -> list[str]:
        """从 FP 案例中提取代码模式，用于生成 pattern-not。

        简化实现: 提取 FP 案例中重复出现的代码片段前缀。
        """
        findings = self._db.get_findings_by_clause(clause, limit=50)
        patterns: list[str] = []
        seen: set[str] = set()

        for f in findings:
            labels = self._db.get_labels_by_finding(f["finding_id"])
            for lab in labels:
                if lab["verdict"] == "false_positive":
                    snippet = f.get("code_snippet", "")
                    if snippet:
                        # 提取前 30 个字符作为模式签名
                        sig = snippet.strip()[:30]
                        if sig and sig not in seen:
                            seen.add(sig)
                            patterns.append(sig)

        return patterns[:5]  # 最多 5 个

    def _get_labeled_examples(
        self, clause: str, verdict: str, limit: int = 3
    ) -> list[dict[str, Any]]:
        """获取某条款下特定标注类型的案例。"""
        findings = self._db.get_findings_by_clause(clause, limit=50)
        examples: list[dict[str, Any]] = []

        for f in findings:
            labels = self._db.get_labels_by_finding(f["finding_id"])
            for lab in labels:
                if lab["verdict"] == verdict:
                    examples.append({
                        "finding_id": f["finding_id"],
                        "clause": clause,
                        "file_path": f.get("file_path", ""),
                        "line_start": f.get("line_start", 0),
                        "code_snippet": f.get("code_snippet", ""),
                        "notes": lab.get("notes", ""),
                        "labeler": lab.get("labeler", ""),
                    })
                    if len(examples) >= limit:
                        return examples
        return examples

    # ─── 漏报分析 ─────────────────────────────────────────────────

    def _extract_missing_sinks(
        self, missed_cases: list[dict[str, Any]]
    ) -> list[str]:
        """从漏报案例中提取缺失的 Sink API。"""
        sinks: list[str] = []
        sink_keywords = {
            "executeQuery": "Statement.executeQuery()",
            "execute": "Statement.execute()",
            "query": "JdbcTemplate.query()",
            "update": "JdbcTemplate.update()",
            "exec": "Runtime.exec()",
            "system": "system() 或 popen()",
            "popen": "popen()",
            "eval": "eval() / ScriptEngine.eval()",
            "printf": "printf() / fprintf()",
            "strcpy": "strcpy() / strncpy()",
            "memcpy": "memcpy()",
            "gets": "gets() / fgets()",
        }

        for m in missed_cases:
            why = m.get("why_missed", "").lower()
            code = m.get("code_snippet", "").lower()

            for keyword, api_name in sink_keywords.items():
                if (keyword in why or keyword in code) and api_name not in sinks:
                    sinks.append(api_name)

        return sinks[:5]

    # ─── 连续 FP 检测 ─────────────────────────────────────────────

    def _count_consecutive_high_fp(self, clause: str) -> int:
        """统计连续多少轮扫描该规则的 FP 率高于阈值。

        从最近一次扫描往前数，直到遇到 FP 率正常的扫描。
        """
        runs = self._db.list_scan_runs(limit=20)
        consecutive = 0

        for run in runs:
            findings = self._db.get_findings_by_run(run["run_id"])
            clause_findings = [f for f in findings if f["clause"] == clause]
            if not clause_findings:
                continue

            tp = 0
            fp = 0
            for f in clause_findings:
                labels = self._db.get_labels_by_finding(f["finding_id"])
                for lab in labels:
                    if lab["verdict"] == "true_positive":
                        tp += 1
                    elif lab["verdict"] == "false_positive":
                        fp += 1

            total = tp + fp
            if total == 0:
                continue

            fp_ratio = fp / total
            if fp_ratio >= self.THRESHOLD_CONSECUTIVE_WARN:
                consecutive += 1
            else:
                break  # 遇到正常的扫描，停止计数

        return consecutive

    # ─── LLM Few-Shot 案例构建 ────────────────────────────────────

    def _build_few_shot_examples(self, verdict: str) -> list[dict[str, Any]]:
        """从反馈数据库提取适用于 LLM Prompt 注入的案例。

        Args:
            verdict: "true_positive" 或 "false_positive"。

        Returns:
            每个案例为 {clause, code, reason, distinction}。
        """
        examples: list[dict[str, Any]] = []
        rules = self._db.list_rule_effectiveness(min_findings=5)

        for rule in rules:
            clause = rule["clause"]
            clause_examples = self._get_labeled_examples(clause, verdict, limit=2)
            for ex in clause_examples:
                item = {
                    "clause": clause,
                    "type": "tp" if verdict == "true_positive" else "fp",
                    "code": ex.get("code_snippet", ""),
                    "reason": ex.get("notes", ""),
                }
                if verdict == "false_positive":
                    # FP 案例需要 distinction 字段帮助 LLM 区分
                    item["distinction"] = self._infer_distinction(ex)
                examples.append(item)

        return examples

    @staticmethod
    def _infer_distinction(example: dict[str, Any]) -> str:
        """从 FP 案例的备注中推测与真实漏洞的关键区别。"""
        notes = example.get("notes", "")
        if notes:
            return notes[:100]
        return "需人工标注区别"

    # ─── 报告生成 ─────────────────────────────────────────────────

    @staticmethod
    def _build_summary(report: TuningReport) -> str:
        """生成调优分析摘要。"""
        lines = [
            f"# 规则调优分析报告",
            f"",
            f"- 分析规则总数: {len(report.advices)}",
            f"- 需要关注的规则: {report.rules_with_issues}",
            f"- 运行良好的规则: {report.rules_healthy}",
            f"- 提取 FP 案例 (LLM Few-Shot): {len(report.fp_examples_for_llm)} 条",
            f"- 提取 TP 案例 (LLM Few-Shot): {len(report.tp_examples_for_llm)} 条",
            f"",
        ]

        critical = [a for a in report.advices if a.severity == "critical"]
        if critical:
            lines.append("## 严重问题")
            for a in critical:
                lines.append(f"- **{a.clause} {a.vuln_name}**: {a.reason}")
                lines.append(f"  建议: {a.suggestion}")

        warnings = [a for a in report.advices if a.severity == "warning"]
        if warnings:
            lines.append("## 警告")
            for a in warnings:
                lines.append(f"- {a.clause} {a.vuln_name}: {a.reason}")

        return "\n".join(lines)

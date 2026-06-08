"""扫描编排引擎 —— 核心调度逻辑。

协调所有组件完成 5 个 Phase 的自动化审计流程:
  Phase 1: Preprocess   — 语言检测、项目结构分析、编译可行性判断
  Phase 2: Parallel Scan — Semgrep + CodeQL + LLM 并行扫描
  Phase 3: Aggregate     — 去重、按国标条款分类、置信度打分
  Phase 4: LLM Review    — 低置信度结果 / 业务逻辑漏洞二次确认
  Phase 5: Report        — 生成 CNAS 审计报告

设计依据:
  - 设计文档 Section 2.2: 运行时数据流
  - 设计文档 Section 4.2: 扫描优先级策略
  - 设计文档 Section 4.3: 结果聚合算法
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ─── 数据类型 ─────────────────────────────────────────────────────


@dataclass
class ScanMetadata:
    """扫描元数据 — Phase 1 产出。"""

    languages_detected: list[str] = field(default_factory=list)
    total_files: int = 0
    java_files: int = 0
    cpp_files: int = 0
    build_system: str = ""  # "maven" / "gradle" / "cmake" / "make" / "none"
    compile_ready: bool = False
    source_roots: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """一次完整扫描的结果。"""

    run_id: str = ""
    metadata: ScanMetadata = field(default_factory=ScanMetadata)
    findings: list[dict[str, Any]] = field(default_factory=list)
    llm_reviewed: list[dict[str, Any]] = field(default_factory=list)
    mode: str = "online"
    standard: str = ""
    duration_seconds: float = 0.0
    error_count: int = 0
    warnings: list[str] = field(default_factory=list)


# ─── 编排引擎 ─────────────────────────────────────────────────────


class Orchestrator:
    """扫描编排引擎。

    通过依赖注入接收各组件实例，负责 5 个 Phase 的调度和数据流转。

    用法:
        orch = Orchestrator(config, kb=kb, semgrep=scanner_semgrep,
                            codeql=scanner_codeql, llm=llm_client, ...)
        result = orch.run("/workspace/code")
    """

    def __init__(
        self,
        config: dict[str, Any],
        *,
        kb: Any = None,
        semgrep: Any = None,
        codeql: Any = None,
        llm: Any = None,
        feedback_db: Any = None,
        report_generator: Any = None,
    ) -> None:
        """初始化编排器。

        Args:
            config: 运行时配置字典（对应 config.yaml）。
            kb: KnowledgeBase 实例。
            semgrep: SemgrepScanner 实例（可选）。
            codeql: CodeQLScanner 实例（可选）。
            llm: LLMClient 实例（可选）。
            feedback_db: FeedbackDB 实例（可选）。
            report_generator: ReportGenerator 实例（可选，Phase 5 使用）。
        """
        self._config = config
        self._kb = kb
        self._semgrep = semgrep
        self._codeql = codeql
        self._llm = llm
        self._feedback_db = feedback_db
        self._report_generator = report_generator

        # 加载标准映射表（漏洞类型 → 多标准条款号）
        self._vuln_mapping: dict[str, Any] = self._load_vuln_mapping()

    @staticmethod
    def _load_vuln_mapping() -> dict[str, Any]:
        """加载 rules/standard-mapping.json（漏洞类型 → 多标准条款号映射）。

        查找路径优先级: rules/standard-mapping.json → /app/rules/standard-mapping.json
        """
        candidates = [
            Path("rules/standard-mapping.json"),
            Path("/app/rules/standard-mapping.json"),
        ]
        for p in candidates:
            if p.is_file():
                import json

                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    logger.info("已加载漏洞类型映射: %s (%d 条)", p, len(data))
                    return data
        logger.debug("standard-mapping.json 未找到，条款号展开功能禁用")
        return {}

    def _expand_findings(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """将每条发现的单一条款号展开为多标准条款号。

        一条检测命中 → 查 standard-mapping.json → 展开为多条款发现。
        例如: SQL注入命中 6.2.3.4 → 同时生成 6.2.3.4、7.2.3.4、8.3.2 三条发现。
        """
        if not self._vuln_mapping:
            return findings

        # 建立 clause → vuln_key 的反向索引
        clause_to_vuln: dict[str, str] = {}
        for vuln_key, entry in self._vuln_mapping.items():
            for s in entry.get("standards", []):
                clause_to_vuln[s["clause"]] = vuln_key

        expanded: list[dict[str, Any]] = []
        for f in findings:
            clause = f.get("clause", "")
            vuln_key = clause_to_vuln.get(clause)
            if not vuln_key:
                expanded.append(f)
                continue

            entry = self._vuln_mapping.get(vuln_key)
            if not entry or len(entry.get("standards", [])) <= 1:
                expanded.append(f)
                continue

            # 展开: 为每个关联标准生成一条发现（按文件语言过滤）
            file_path = f.get('file_path', '')
            source_id = f"{file_path}:{f.get('line_start', 0)}"
            for std in entry["standards"]:
                # 根据文件扩展名过滤不匹配的语言标准
                std_lang = std.get("language", "")
                if std_lang and std_lang != "通用":
                    if file_path.endswith('.java') and 'C/' in std_lang:
                        continue
                    if (file_path.endswith('.c') or file_path.endswith('.cpp') or
                        file_path.endswith('.h') or file_path.endswith('.hpp')) and 'Java' in std_lang:
                        continue
                    if file_path.endswith('.xml') and std_lang not in ('通用', 'Java'):
                        continue
                new_f = dict(f)
                new_f["clause"] = std["clause"]
                new_f["standard"] = std["standard"]
                new_f["vuln_name"] = entry.get("vuln_name", f.get("vuln_name", ""))
                new_f["category"] = entry.get("category", f.get("category", ""))
                # 标记同源（用于报告去重显示）
                new_f["_source_group"] = source_id
                new_f["_vuln_key"] = vuln_key
                new_f["_is_expanded"] = True
                expanded.append(new_f)

        logger.info(
            "条款号展开: %d → %d 条发现 (%d 个跨标准类型)",
            len(findings), len(expanded),
            len({f.get("_vuln_key", "") for f in expanded if f.get("_is_expanded")}),
        )
        return expanded

    @staticmethod
    def _filter_by_standard(
        findings: list[dict[str, Any]], standard: str
    ) -> list[dict[str, Any]]:
        """按指定标准编号过滤发现。

        Args:
            findings: 已展开的发现列表。
            standard: 标准编号简写，如 "39412" / "34944" / "34943"。

        Returns:
            仅包含指定标准的发现列表。
        """
        std_map = {
            "39412": "GB/T 39412-2020",
            "34944": "GB/T 34944-2017",
            "34943": "GB/T 34943-2017",
        }
        target = std_map.get(standard)
        if not target:
            return findings

        return [f for f in findings if f.get("standard", "") == target]

    def run(self, code_dir: str | Path, standard: str = "") -> ScanResult:
        """执行完整扫描流程。

        Args:
            standard: 指定标准编号简写，如 "39412" / "34944" / "34943"。
                      不指定（默认 ""）则检测全部标准。
            code_dir: 源代码目录路径。

        Returns:
            ScanResult 包含所有发现和元数据。
        """
        code_dir = Path(code_dir)
        start_time = time.monotonic()

        result = ScanResult()
        result.mode = self._determine_mode()
        result.standard = standard

        # ── Phase 1: 预处理 ──
        logger.info("=" * 60)
        logger.info("Phase 1: 预处理 — 分析项目结构")
        metadata = self._preprocess(code_dir)
        result.metadata = metadata
        logger.info(
            "语言=%s, Java文件=%d, C/C++文件=%d, 构建系统=%s, 可编译=%s",
            metadata.languages_detected,
            metadata.java_files,
            metadata.cpp_files,
            metadata.build_system or "无",
            metadata.compile_ready,
        )

        # ── Phase 2: 并行扫描 ──
        logger.info("=" * 60)
        logger.info("Phase 2: 并行扫描 — Semgrep ∥ CodeQL ∥ LLM")
        semgrep_findings, codeql_findings, llm_blind_findings = self._parallel_scan(
            code_dir, metadata
        )

        # ── Phase 3: 结果聚合 ──
        logger.info("=" * 60)
        logger.info("Phase 3: 结果聚合 — 去重 + 分类 + 打分")
        aggregated = self._aggregate(
            semgrep_findings, codeql_findings, llm_blind_findings
        )
        # 条款号展开：一条命中 → 多标准条款号
        result.findings = self._expand_findings(aggregated)

        # 如果指定了 standard，过滤 findings
        if standard:
            result.findings = self._filter_by_standard(result.findings, standard)
            logger.info("标准过滤 (%s): %d 条发现", standard, len(result.findings))

        # ── Phase 4: LLM 二次确认 ──
        logger.info("=" * 60)
        logger.info("Phase 4: LLM 二次确认")
        if result.mode == "online" and self._llm and self._llm.is_available():
            llm_reviewed = self._llm_review(aggregated)
            result.llm_reviewed = llm_reviewed
            # 将 LLM 确认结果 merge 回 findings
            result.findings = self._merge_llm_results(aggregated, llm_reviewed)
        else:
            logger.info("离线模式或 LLM 不可用，跳过 Phase 4")

        # 记录扫描耗时（在报告生成前计算，修复6: 报告显示0.0秒）
        result.duration_seconds = time.monotonic() - start_time

        # ── Phase 5: 报告生成 ──
        logger.info("=" * 60)
        logger.info("Phase 5: 报告生成")
        output_dir = self._config.get("output", {}).get("report_dir", str(code_dir / "output"))
        if self._report_generator:
            self._report_generator.generate(result, output_dir)
        else:
            logger.warning("ReportGenerator 未注入，跳过报告生成")

        # ── 记录扫描运行到反馈数据库 ──
        if self._feedback_db:
            try:
                self._feedback_db.create_tables()
                run_id = self._feedback_db.insert_scan_run(
                    mode=result.mode,
                    total_files=metadata.total_files,
                    languages_detected=metadata.languages_detected,
                    tools_used=self._active_tools(),
                    pre_label_findings=len(result.findings),
                    duration_seconds=int(result.duration_seconds),
                )
                result.run_id = run_id

                # 批量写入发现
                for f in result.findings:
                    self._feedback_db.insert_finding(
                        run_id=run_id,
                        clause=f.get("clause", ""),
                        standard=f.get("standard", ""),
                        vuln_name=f.get("vuln_name", ""),
                        category=f.get("category", ""),
                        file_path=f.get("file_path", ""),
                        line_start=f.get("line_start", 0),
                        line_end=f.get("line_end", 0),
                        source_tool=f.get("source_tool", ""),
                        auto_confidence=f.get("auto_confidence", 0.0),
                        code_snippet=f.get("code_snippet", ""),
                        tool_raw_output=f.get("tool_raw_output", {}),
                    )
            except Exception as e:
                logger.warning("写入反馈数据库失败: %s", e)
                result.warnings.append(f"feedback_db write error: {e}")

        logger.info("扫描完成，总耗时 %.1fs，发现 %d 条", result.duration_seconds, len(result.findings))
        return result

    # ─── Phase 1: Preprocess ─────────────────────────────────────

    def _preprocess(self, code_dir: Path) -> ScanMetadata:
        """Phase 1: 分析代码目录结构和语言分布。"""
        meta = ScanMetadata()
        java_exts = {".java"}
        cpp_exts = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}

        source_files: list[Path] = []
        for f in code_dir.rglob("*"):
            if f.is_file() and not self._is_ignored(f):
                source_files.append(f)
                ext = f.suffix.lower()
                if ext in java_exts:
                    meta.java_files += 1
                elif ext in cpp_exts:
                    meta.cpp_files += 1

        meta.total_files = len(source_files)

        if meta.java_files > 0:
            meta.languages_detected.append("Java")
        if meta.cpp_files > 0:
            meta.languages_detected.append("C/C++")

        # 检测构建系统
        self._detect_build_system(code_dir, meta)

        # 找源码根目录
        self._detect_source_roots(code_dir, meta)

        return meta

    @staticmethod
    def _detect_build_system(code_dir: Path, meta: ScanMetadata) -> None:
        """检测项目构建系统。"""
        if (code_dir / "pom.xml").exists():
            meta.build_system = "maven"
        elif (code_dir / "build.gradle").exists() or (code_dir / "build.gradle.kts").exists():
            meta.build_system = "gradle"
        elif (code_dir / "CMakeLists.txt").exists():
            meta.build_system = "cmake"
        elif (code_dir / "Makefile").exists():
            meta.build_system = "make"

        # 编译可行性：有构建系统就算 ready
        meta.compile_ready = bool(meta.build_system)

    @staticmethod
    def _detect_source_roots(code_dir: Path, meta: ScanMetadata) -> None:
        """检测源码根目录（相对于 code_dir）。"""
        for candidate in ["src/main/java", "src", "source", "include", "lib"]:
            p = code_dir / candidate
            if p.is_dir():
                meta.source_roots.append(candidate)

        if not meta.source_roots:
            meta.source_roots = ["."]

    @staticmethod
    def _is_ignored(file_path: Path) -> bool:
        """判断文件是否应被忽略。"""
        ignored_fragments = [
            "/.git/", "/node_modules/", "/target/", "/build/",
            "/.venv/", "/__pycache__/", "/.idea/", "/.vscode/",
        ]
        path_str = str(file_path)
        return any(frag in path_str for frag in ignored_fragments)

    # ─── Phase 2: Parallel Scan ──────────────────────────────────

    def _parallel_scan(
        self, code_dir: Path, metadata: ScanMetadata
    ) -> tuple[list[dict], list[dict], list[dict]]:
        """Phase 2: 并行执行 Semgrep + CodeQL + LLM 盲扫。

        实际实现中会用线程池并行，但为了可测试性和简洁性，
        这里顺序执行各扫描器（容器环境部署时可改为 ThreadPoolExecutor）。

        Returns:
            (semgrep_findings, codeql_findings, llm_blind_findings)
        """
        semgrep_findings: list[dict] = []
        codeql_findings: list[dict] = []
        llm_blind_findings: list[dict] = []

        # ── Semgrep ──
        if self._semgrep and self._config.get("semgrep", {}).get("enabled", True):
            semgrep_timeout = self._config.get("semgrep", {}).get("timeout_seconds", 300)
            for lang in metadata.languages_detected:
                lang_key = "java" if lang == "Java" else "cpp"
                try:
                    findings = self._semgrep.scan(str(code_dir), language=lang_key)
                    semgrep_findings.extend(findings)
                    logger.info("Semgrep (%s): %d 条发现", lang_key, len(findings))
                except Exception as e:
                    logger.error("Semgrep (%s) 失败: %s", lang_key, e)

        # ── CodeQL ──
        if self._codeql and self._config.get("codeql", {}).get("enabled", True):
            codeql_timeout = self._config.get("codeql", {}).get("timeout_seconds", 600)
            for lang in metadata.languages_detected:
                lang_key = "java" if lang == "Java" else "cpp"
                build_cmd = None
                if lang == "C/C++" and metadata.build_system == "cmake":
                    build_cmd = "cmake .. && make -j2"
                elif lang == "C/C++" and metadata.build_system == "make":
                    build_cmd = "make -j2"

                try:
                    findings = self._codeql.scan(
                        str(code_dir), language=lang_key, build_command=build_cmd
                    )
                    codeql_findings.extend(findings)
                    logger.info("CodeQL (%s): %d 条发现", lang_key, len(findings))
                except Exception as e:
                    logger.error("CodeQL (%s) 失败: %s", lang_key, e)

        # ── LLM 盲扫（仅 SAST 无法覆盖的 9 种漏洞） ──
        if self._llm and self._llm.is_available():
            llm_blind_findings = self._llm_blind_scan(code_dir, metadata)

        return semgrep_findings, codeql_findings, llm_blind_findings

    def _llm_blind_scan(
        self, code_dir: Path, metadata: ScanMetadata
    ) -> list[dict[str, Any]]:
        """LLM 对 SAST 盲区漏洞进行逐文件扫描。

        扫描设计文档中 9 种必须 LLM 才能检测的漏洞类型:
          6.2.5.2, 6.2.6.4, 6.2.6.11, 6.2.6.12, 6.2.6.13,
          6.2.6.15, 6.2.6.16, 7.2.7.9, 7.2.7.10
        """
        llm_only_clauses = self._config.get(
            "llm",
            {},
        ).get(
            "blind_scan_clauses",
            [
                "6.2.5.2",  # 违反信任边界
                "6.2.6.4",  # 依赖referer鉴权
                "6.2.6.11",  # 反向域名解析
                "6.2.6.12",  # 关键参数篡改
                "6.2.6.13",  # 强口令
                "6.2.6.15",  # 未验证cookie
                "6.2.6.16",  # SQL关键字绕过
                "7.2.7.9",  # C/C++反向域名
                "7.2.7.10",  # C/C++强口令
            ],
        )

        findings: list[dict[str, Any]] = []
        for clause in llm_only_clauses:
            vuln = None
            if self._kb:
                vuln = self._kb.get_by_clause(clause)
            if vuln is None:
                continue

            # 只扫描匹配该漏洞语言的文件
            kb_ctx = self._build_kb_context(clause)

            # 收集相关文件内容
            files = self._collect_source_files(code_dir, clause, metadata)
            if not files:
                continue

            try:
                results = self._llm.scan_missed(clause, files, kb_ctx)
                for r in results:
                    for f_item in r.findings:
                        findings.append({
                            "clause": clause,
                            "standard": self._standard_from_clause(clause),
                            "vuln_name": vuln.get("name", ""),
                            "category": vuln.get("category", ""),
                            "file_path": r.file_path,
                            "line_start": f_item.get("line_start", 0),
                            "line_end": f_item.get("line_end", 0),
                            "source_tool": "llm",
                            "auto_confidence": f_item.get("confidence", 0.5),
                            "code_snippet": f_item.get("evidence", ""),
                            "tool_raw_output": {
                                "reasoning": f_item.get("reasoning", ""),
                                "exploit_scenario": f_item.get("exploit_scenario", ""),
                            },
                        })
                logger.info("LLM 盲扫 (%s): %d 条发现", clause, len(findings))
            except Exception as e:
                logger.warning("LLM 盲扫 (%s) 失败: %s", clause, e)

        return findings

    # ─── Phase 3: Aggregate ──────────────────────────────────────

    def _aggregate(
        self,
        semgrep_findings: list[dict],
        codeql_findings: list[dict],
        llm_blind_findings: list[dict],
    ) -> list[dict[str, Any]]:
        """Phase 3: 去重 + 分类 + 置信度合并。

        去重算法（设计文档 Section 4.3）:
          1. 同一 clause + 同一文件 + 行号重叠 ≥ 30% → 合并
          2. Semgrep + CodeQL 双确认 → 置信度加成
          3. 不同工具置信度加权合并
        """
        all_findings = semgrep_findings + codeql_findings + llm_blind_findings
        if not all_findings:
            return []

        # 按 (clause, file_path) 分组
        groups: dict[tuple[str, str], list[dict]] = {}
        for f in all_findings:
            key = (f.get("clause", ""), f.get("file_path", ""))
            groups.setdefault(key, []).append(f)

        merged: list[dict[str, Any]] = []
        for (clause, file_path), group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
                continue

            # 多条发现 → 检查是否需要合并
            merged_group = self._merge_overlapping(group)
            merged.extend(merged_group)

        # 按 clause 排序
        merged.sort(key=lambda f: (f.get("clause", ""), f.get("file_path", ""), f.get("line_start", 0)))

        # 注入严重等级
        for f in merged:
            f["severity"] = self._assign_severity(f)

        return merged

    @staticmethod
    def _merge_overlapping(group: list[dict]) -> list[dict]:
        """合并同一文件中同一条款下重叠的发现。"""
        if len(group) <= 1:
            return group

        # 简单策略：两两检查行号重叠
        merged: list[dict] = []
        used: set[int] = set()

        for i, f1 in enumerate(group):
            if i in used:
                continue
            merged_item = dict(f1)
            tools = {f1.get("source_tool", "")}
            confidences = [f1.get("auto_confidence", 0.5)]

            for j, f2 in enumerate(group):
                if j <= i or j in used:
                    continue
                if Orchestrator._lines_overlap(
                    f1.get("line_start", 0), f1.get("line_end", 0),
                    f2.get("line_start", 0), f2.get("line_end", 0),
                ):
                    used.add(j)
                    tools.add(f2.get("source_tool", ""))
                    confidences.append(f2.get("auto_confidence", 0.5))
                    # 扩展行号范围
                    merged_item["line_start"] = min(
                        merged_item["line_start"], f2.get("line_start", 0)
                    )
                    merged_item["line_end"] = max(
                        merged_item["line_end"], f2.get("line_end", 0)
                    )

            # 合并置信度: max + 多工具加成
            merged_item["auto_confidence"] = min(
                1.0, max(confidences) + 0.05 * (len(tools) - 1)
            )
            if len(tools) > 1:
                merged_item["source_tool"] = "+".join(sorted(tools))
                merged_item["tool_raw_output"]["cross_validated_by"] = list(tools)

            merged.append(merged_item)

        return merged

    @staticmethod
    def _lines_overlap(
        s1: int, e1: int, s2: int, e2: int, tolerance: int = 3
    ) -> bool:
        """判断两段行号范围是否有重叠（含 ±3 行容差）。"""
        s1a, e1a = s1 - tolerance, e1 + tolerance
        s2a, e2a = s2 - tolerance, e2 + tolerance

        overlap_start = max(s1a, s2a)
        overlap_end = min(e1a, e2a)

        if overlap_start > overlap_end:
            return False

        range1 = max(e1a - s1a, 1)
        range2 = max(e2a - s2a, 1)
        min_range = min(range1, range2)
        overlap_ratio = (overlap_end - overlap_start) / min_range if min_range > 0 else 0

        return overlap_ratio >= 0.3

    # ─── Phase 4: LLM Review ─────────────────────────────────────

    def _llm_review(
        self, aggregated: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Phase 4: 批量 LLM 二次确认 — 将多条发现打包成一个请求发送。"""
        if not self._llm or not self._llm.is_available():
            return []

        review_threshold_low = self._config.get("llm", {}).get("review_threshold_low", 0.4)
        review_threshold_high = self._config.get("llm", {}).get("review_threshold_high", 0.7)
        llm_assist_clauses = self._config.get("llm", {}).get("assist_clauses", [])

        # 收集需要 LLM 确认的发现
        candidates = []
        for finding in aggregated:
            clause = finding.get("clause", "")
            confidence = finding.get("auto_confidence", 0.5)
            needs_review = (
                (review_threshold_low <= confidence <= review_threshold_high)
                or (clause in llm_assist_clauses)
            )
            if needs_review:
                candidates.append(finding)

        if not candidates:
            logger.info("LLM: 没有需要二次确认的发现")
            return []

        # 批量发送 — 所有候选发现打包成一个请求
        logger.info("LLM: 批量审查 %d 条发现...", len(candidates))
        try:
            batch_results = self._llm.batch_review(candidates, self._kb if hasattr(self, '_kb') else None)
            reviewed = []
            for i, result in enumerate(batch_results):
                reviewed.append({
                    "finding": candidates[i],
                    "llm_verdict": result.verdict,
                    "llm_confidence": result.confidence,
                    "llm_reasoning": result.reasoning,
                    "llm_evidence": result.evidence,
                    "llm_fix": result.fix_suggestion,
                })
                logger.info(
                    "LLM 审查 %s %s: verdict=%s confidence=%.2f",
                    candidates[i].get("clause", ""),
                    candidates[i].get("file_path", ""),
                    result.verdict, result.confidence,
                )
            logger.info("LLM: 批量审查完成 (%d/%d)", len(reviewed), len(candidates))
            return reviewed
        except Exception as e:
            logger.warning("LLM 批量审查失败: %s", e)
            return []

    def _merge_llm_results(
        self,
        aggregated: list[dict[str, Any]],
        llm_reviewed: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """将 LLM 审查结果合并回聚合发现列表。

        规则:
          - LLM confirmed → confidence +0.2 (cap 1.0)
          - LLM rejected  → confidence ×0.5
          - LLM uncertain  → 保持不变
        """
        # 建立 (clause, file_path, line) → review 索引
        review_map: dict[tuple[str, str, int], dict] = {}
        for r in llm_reviewed:
            f = r["finding"]
            key = (f.get("clause", ""), f.get("file_path", ""), f.get("line_start", 0))
            review_map[key] = r

        result: list[dict[str, Any]] = []
        for f in aggregated:
            key = (f.get("clause", ""), f.get("file_path", ""), f.get("line_start", 0))
            review = review_map.get(key)
            if review:
                verdict = review["llm_verdict"]
                if verdict == "confirmed":
                    f["auto_confidence"] = min(1.0, f.get("auto_confidence", 0.5) + 0.2)
                    f["llm_status"] = "confirmed"
                elif verdict == "rejected":
                    f["auto_confidence"] = f.get("auto_confidence", 0.5) * 0.5
                    f["llm_status"] = "rejected"
                else:
                    f["llm_status"] = "uncertain"
                f["llm_confidence"] = review["llm_confidence"]
                f["llm_reasoning"] = review["llm_reasoning"]

            result.append(f)

        return result

    # ─── Phase 5: Report (delegated to report_generator) ──────────

    # 报告生成由 ReportGenerator 负责，orchestrator 只负责调用。
    # 见 src/report_generator.py（下一个模块）。

    # ─── 辅助方法 ────────────────────────────────────────────────

    def _determine_mode(self) -> str:
        """判断运行模式：online 或 offline。"""
        if not self._llm or not self._llm.is_available():
            return "offline"
        llm_config = self._config.get("llm", {})
        if llm_config.get("offline", False):
            return "offline"
        return "online"

    def _active_tools(self) -> list[str]:
        """返回当前激活的工具列表。"""
        tools = []
        if self._semgrep:
            tools.append("semgrep")
        if self._codeql:
            tools.append("codeql")
        if self._llm and self._llm.is_available():
            tools.append("deepseek")
        return tools

    def _build_kb_context(self, clause: str) -> str:
        """构建某条款的 LLM 上下文。"""
        if self._kb is None:
            return f"条款 {clause}"
        from src.llm_client import build_kb_context_for_clause

        return build_kb_context_for_clause(self._kb, clause)

    def _load_history_examples(self, clause: str) -> list[dict[str, Any]]:
        """从反馈数据库加载某条款的历史案例。"""
        if self._feedback_db is None:
            return []
        try:
            findings = self._feedback_db.get_findings_by_clause(clause, limit=10)
            examples: list[dict[str, Any]] = []
            for f in findings:
                labels = self._feedback_db.get_labels_by_finding(f["finding_id"])
                for lab in labels:
                    if lab["verdict"] == "true_positive":
                        examples.append({
                            "type": "tp",
                            "code": f.get("code_snippet", ""),
                            "reason": lab.get("notes", ""),
                        })
                    elif lab["verdict"] == "false_positive":
                        correction = json.loads(lab.get("correction", "{}"))
                        examples.append({
                            "type": "fp",
                            "code": f.get("code_snippet", ""),
                            "reason": lab.get("notes", ""),
                            "distinction": correction.get("why_not_vuln", ""),
                        })
            return examples[:5]  # 每类最多 5 个
        except Exception as e:
            logger.debug("加载历史案例失败: %s", e)
            return []

    def _collect_source_files(
        self, code_dir: Path, clause: str, metadata: ScanMetadata
    ) -> list[dict[str, str]]:
        """收集相关源码文件内容，供 LLM 盲扫使用。"""
        files: list[dict[str, str]] = []
        target_exts = set()
        if clause.startswith("6.2"):
            target_exts = {".java"}
        elif clause.startswith("7.2"):
            target_exts = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}

        for f in code_dir.rglob("*"):
            if f.is_file() and f.suffix.lower() in target_exts and not self._is_ignored(f):
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    rel_path = str(f.relative_to(code_dir))
                    files.append({"path": rel_path, "content": content})
                except Exception:
                    continue

        return files

    @staticmethod
    def _standard_from_clause(clause: str) -> str:
        """条款号前缀 → 标准名称。"""
        if clause.startswith("6.2"):
            return "GB/T 34944-2017"
        if clause.startswith("7.2"):
            return "GB/T 34943-2017"
        return ""

    @staticmethod
    def _assign_severity(finding: dict[str, Any]) -> str:
        """为发现分配严重等级（高/中/低）。

        规则参考设计文档 Section 5.3。
        """
        clause = finding.get("clause", "")

        # 高: 可直接导致代码执行、认证绕过、数据库暴露
        high_clauses = {
            "6.2.3.3", "6.2.3.4", "6.2.3.5",  # 命令/SQL/代码注入
            "7.2.3.3", "7.2.3.4",              # C/C++对应
            "7.2.3.6", "7.2.3.7", "7.2.3.8",  # 缓冲区溢出/格式字符串/整数溢出
        }

        # 低: 配置缺陷、最佳实践违反
        low_clauses = {
            "6.2.7.2",   # 会话永不过期
            "6.2.6.14",  # 口令域未掩饰
            "6.2.9.1",   # 点击劫持
            "6.2.8.5",   # 依赖外部文件名
            "7.2.7.11",  # C/C++口令域未掩饰
        }

        if clause in high_clauses:
            return "高"
        if clause in low_clauses:
            return "低"
        return "中"

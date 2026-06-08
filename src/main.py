"""CLI 入口 —— CNAS 容器化源代码安全审计平台。

命令:
  scan      完整扫描（SAST + LLM），或 --offline 离线模式
  feedback  人工标注一条发现的 verdict
  tune      分析反馈数据库，生成规则调优报告
  stats     显示反馈数据库统计信息

用法:
  python -m src.main scan --code-dir /path/to/code --output-dir /path/to/report
  python -m src.main scan --offline
  python -m src.main feedback --scan-id XXX --finding-id YYY --verdict rejected
  python -m src.main tune
  python -m src.main stats
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any

# ─── 日志 ─────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("audit-platform")


# ─── 默认路径（容器内约定）────────────────────────────────────────

DEFAULT_CODE_DIR = "/workspace/code"
DEFAULT_REPORT_DIR = "/workspace/report"
DEFAULT_FEEDBACK_DIR = "/workspace/feedback"
DEFAULT_FEEDBACK_DB = f"{DEFAULT_FEEDBACK_DIR}/feedback.db"
DEFAULT_CONFIG_PATH = "/app/config.yaml"

# 规则和知识库路径（镜像内）
DEFAULT_RULES_DIR = "/app/rules"
DEFAULT_KNOWLEDGE_BASE = "/app/knowledge/knowledge_base.json"


# ─── 配置加载 ─────────────────────────────────────────────────────


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """加载 YAML 配置，如果文件不存在则使用默认配置。"""
    config: dict[str, Any] = {
        "semgrep": {"enabled": True, "timeout_seconds": 300},
        "codeql": {"enabled": True, "timeout_seconds": 600},
        "llm": {
            "offline": False,
            "review_threshold_low": 0.4,
            "review_threshold_high": 0.7,
        },
        "feedback": {"db_path": DEFAULT_FEEDBACK_DB},
        "output": {"report_dir": DEFAULT_REPORT_DIR},
    }

    path = config_path or os.environ.get("AUDIT_CONFIG", DEFAULT_CONFIG_PATH)

    try:
        import yaml

        with open(path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
        _deep_merge(config, user_config)
        logger.info("配置已加载: %s", path)
    except FileNotFoundError:
        logger.info("配置文件 %s 未找到，使用默认配置", path)
    except ImportError:
        logger.debug("PyYAML 未安装，仅使用默认配置")
    except Exception as e:
        logger.warning("配置加载失败: %s", e)

    return config


def _deep_merge(base: dict, override: dict) -> None:
    """递归合并 override 到 base 中。"""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


# ─── 组件工厂 ─────────────────────────────────────────────────────


def _create_kb(kb_path: str | None = None) -> Any | None:
    """创建知识库实例。"""
    path = kb_path or os.environ.get("KNOWLEDGE_BASE_PATH", DEFAULT_KNOWLEDGE_BASE)
    if not Path(path).exists():
        logger.warning("知识库文件 %s 未找到", path)
        return None
    from src.knowledge_base import KnowledgeBase

    return KnowledgeBase(path)


def _create_llm_client(config: dict) -> Any | None:
    """创建 LLM 客户端，自动检测 API 可用性。"""
    llm_config_dict = config.get("llm", {})
    if llm_config_dict.get("offline", False):
        return None

    from src.llm_client import LLMConfig, LLMClient

    llm_cfg = LLMConfig(
        base_url=llm_config_dict.get("base_url", "https://api.deepseek.com/anthropic"),
        api_key=llm_config_dict.get("api_key", "") or os.environ.get("ANTHROPIC_API_KEY", ""),
        model=llm_config_dict.get("model", "deepseek-chat"),
        reason_model=llm_config_dict.get("reason_model", "deepseek-reasoner"),
    )

    if not llm_cfg.api_key:
        logger.info("ANTHROPIC_API_KEY 未设置，LLM 不可用")
        return None

    client = LLMClient(llm_cfg)

    # 自动检测 API 可达性 — 不可达时自动降级为离线模式
    if not client.check_connectivity(timeout=5.0):
        logger.warning("DeepSeek API 不可达（连接超时或服务端拒绝），自动降级为离线模式")
        logger.warning("可通过 --offline 显式指定离线模式避免此检测")
        return None

    return client


def _create_scanners(config: dict, kb: Any) -> tuple[Any | None, Any | None]:
    """创建 Semgrep 和 CodeQL 扫描器。"""
    semgrep = None
    codeql = None

    rules_dir = os.environ.get("RULES_DIR", DEFAULT_RULES_DIR)
    semgrep_rules = os.path.join(rules_dir, "semgrep")
    codeql_queries = os.path.join(rules_dir, "codeql")

    if config.get("semgrep", {}).get("enabled", True):
        from src.scanner_semgrep import SemgrepScanner

        semgrep_timeout = config.get("semgrep", {}).get("timeout_seconds", 300)
        semgrep_pro = config.get("semgrep", {}).get("pro", False) or os.environ.get("SEMGREP_APP_TOKEN", "")
        semgrep = SemgrepScanner(
            rules_dir=semgrep_rules,
            kb=kb,
            timeout_seconds=semgrep_timeout,
            pro_enabled=bool(semgrep_pro),
        )
        if SemgrepScanner.is_installed():
            logger.info("Semgrep CLI 可用")
        else:
            logger.warning("Semgrep CLI 未安装")
            semgrep = None

    if config.get("codeql", {}).get("enabled", True):
        from src.scanner_codeql import CodeQLScanner

        codeql_timeout = config.get("codeql", {}).get("timeout_seconds", 600)
        codeql_cli = config.get("codeql", {}).get("cli_path", "codeql")
        db_dir = config.get("codeql", {}).get("database_dir", "/workspace/cache/codeql-dbs")

        codeql = CodeQLScanner(
            cli_path=codeql_cli,
            queries_dir=codeql_queries,
            kb=kb,
            timeout_seconds=codeql_timeout,
            database_dir=db_dir,
        )
        if CodeQLScanner.is_installed(codeql_cli):
            logger.info("CodeQL CLI 可用")
        else:
            logger.warning("CodeQL CLI 未安装")
            codeql = None

    return semgrep, codeql


def _create_feedback_db(config: dict) -> Any | None:
    """创建反馈数据库。"""
    db_path = config.get("feedback", {}).get("db_path", DEFAULT_FEEDBACK_DB)
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    from src.feedback_db import FeedbackDB

    db = FeedbackDB(db_path)
    db.create_tables()
    return db


# ─── 命令实现 ─────────────────────────────────────────────────────


def cmd_scan(args: argparse.Namespace, config: dict) -> int:
    """执行完整扫描。"""
    code_dir = args.code_dir or DEFAULT_CODE_DIR
    output_dir = args.output_dir or config.get("output", {}).get("report_dir", DEFAULT_REPORT_DIR)

    if args.offline:
        config["llm"]["offline"] = True
        logger.info("模式: 离线（纯 SAST）")
    else:
        logger.info("模式: 在线（SAST + LLM）")

    # 构建组件
    logger.info("初始化组件...")
    kb = _create_kb(args.knowledge_base)
    llm = _create_llm_client(config)
    semgrep, codeql = _create_scanners(config, kb)
    feedback_db = _create_feedback_db(config)

    from src.report_generator import ReportGenerator

    report_gen = ReportGenerator(kb=kb)

    # 编排
    from src.orchestrator import Orchestrator

    orch = Orchestrator(
        config,
        kb=kb,
        semgrep=semgrep,
        codeql=codeql,
        llm=llm,
        feedback_db=feedback_db,
        report_generator=report_gen,
    )

    logger.info("开始扫描: %s", code_dir)
    result = orch.run(code_dir, standard=args.standard)

    # 输出摘要
    print()
    print("=" * 60)
    print(f"扫描完成！耗时 {result.duration_seconds:.1f}s")
    print(f"运行模式: {result.mode}")
    print(f"发现总数: {len(result.findings)}")
    confirmed = [f for f in result.findings if f.get("auto_confidence", 0) >= 0.7]
    suspects = [f for f in result.findings if 0.4 <= f.get("auto_confidence", 0) < 0.7]
    print(f"  确认: {len(confirmed)}")
    print(f"  疑似: {len(suspects)}")
    print(f"报告目录: {output_dir}")
    print("=" * 60)

    return 0


def cmd_feedback(args: argparse.Namespace, config: dict) -> int:
    """人工标注一条发现。"""
    db = _create_feedback_db(config)
    if db is None:
        logger.error("反馈数据库不可用")
        return 1

    if args.verdict not in ("confirmed", "rejected", "not_sure"):
        logger.error("verdict 必须为 confirmed / rejected / not_sure，实际: %s", args.verdict)
        return 1

    # 映射回数据库的 verdict 格式
    verdict_map = {
        "confirmed": "true_positive",
        "rejected": "false_positive",
        "not_sure": "not_sure",
    }

    try:
        label_id = db.insert_label(
            finding_id=args.finding_id,
            verdict=verdict_map[args.verdict],
            labeler=args.labeler or os.environ.get("USER", "unknown"),
            notes=args.note or "",
        )
        logger.info("标注已保存: %s → %s (label_id=%s)", args.finding_id, args.verdict, label_id)

        # 如果 verdict 是 rejected，记录 FP 原因
        if args.verdict == "rejected" and args.reason:
            finding = db.get_finding(args.finding_id)
            if finding:
                logger.info("FP 原因: %s (文件: %s:%d)", args.reason,
                           finding.get("file_path", ""), finding.get("line_start", 0))

        return 0
    except Exception as e:
        logger.error("标注失败: %s", e)
        return 1


def cmd_tune(args: argparse.Namespace, config: dict) -> int:
    """执行规则调优分析。"""
    db = _create_feedback_db(config)
    if db is None:
        logger.error("反馈数据库不可用")
        return 1

    kb = _create_kb(args.knowledge_base)

    from src.rule_tuner import RuleTuner

    tuner = RuleTuner(db, kb=kb)
    report = tuner.analyze()

    print()
    print(report.summary)

    # 详细输出
    if args.verbose:
        print()
        for advice in report.advices:
            if advice.action != "none":
                print(f"[{advice.severity.upper()}] {advice.clause} {advice.vuln_name}")
                print(f"  Action: {advice.action}")
                print(f"  Reason: {advice.reason}")
                if advice.suggestion:
                    print(f"  Suggestion: {advice.suggestion}")
                if advice.new_sinks:
                    print(f"  Missing Sinks: {', '.join(advice.new_sinks)}")

    # 输出到文件
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(report.summary + "\n", encoding="utf-8")
        logger.info("调优报告已保存: %s", output_path)

    return 0


def cmd_stats(args: argparse.Namespace, config: dict) -> int:
    """显示反馈数据库统计信息。"""
    db = _create_feedback_db(config)
    if db is None:
        logger.error("反馈数据库不可用")
        return 1

    db.upsert_rule_effectiveness()
    rules = db.list_rule_effectiveness(min_findings=1)

    print()
    print("=" * 70)
    print("反馈数据库统计")
    print("=" * 70)

    runs = db.list_scan_runs(limit=10)
    print(f"总扫描次数: {len(runs)}")

    if runs:
        latest = runs[0]
        print(f"最近扫描: {latest['scan_timestamp']} (mode={latest['mode']})")

    print(f"有数据的规则数: {len(rules)}")

    # FP 率统计
    if rules:
        high_fp = [r for r in rules if r["precision"] < 0.5 and r["total_findings"] >= 3]
        healthy = [r for r in rules if r["precision"] >= 0.8]
        print(f"高误报规则 (precision<0.5): {len(high_fp)}")
        print(f"健康规则 (precision>=0.8): {len(healthy)}")

        if high_fp:
            print("\n  高误报规则明细:")
            for r in high_fp:
                print(f"    {r['clause']} {r['vuln_name']}: precision={r['precision']:.2f}, "
                      f"TP={r['tp_count']}, FP={r['fp_count']}")

    # 漏报统计
    missed_by_clause = db.count_missed_by_clause()
    if missed_by_clause:
        print(f"\n漏报记录总数: {sum(m['cnt'] for m in missed_by_clause)}")
        for m in missed_by_clause[:5]:
            print(f"  {m['clause']}: {m['cnt']} 条")

    print("=" * 70)
    return 0


# ─── 参数解析 ─────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="audit-platform",
        description="CNAS 容器化源代码安全审计平台",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="配置文件路径 (默认: /app/config.yaml)",
    )
    parser.add_argument(
        "--knowledge-base",
        default=None,
        help="知识库 JSON 路径 (默认: /app/knowledge/knowledge_base.json)",
    )

    sub = parser.add_subparsers(dest="command", help="子命令")

    # scan
    scan_p = sub.add_parser("scan", help="执行源代码安全审计")
    scan_p.add_argument("--code-dir", default=None, help="源代码目录")
    scan_p.add_argument("--output-dir", default=None, help="报告输出目录")
    scan_p.add_argument("--offline", action="store_true", help="离线模式（仅 SAST）")
    scan_p.add_argument("--standard", type=str, default="",
                        help="指定标准编号，如 39412 / 34944 / 34943。不指定则全部")

    # feedback
    fb_p = sub.add_parser("feedback", help="人工标注一条发现")
    fb_p.add_argument("--scan-id", help="扫描运行 ID")
    fb_p.add_argument("--finding-id", required=True, help="发现 ID")
    fb_p.add_argument("--verdict", required=True, choices=["confirmed", "rejected", "not_sure"],
                      help="标注结论")
    fb_p.add_argument("--labeler", default=None, help="标注人")
    fb_p.add_argument("--note", default=None, help="备注")
    fb_p.add_argument("--reason", default=None, help="FP 原因（verdict=rejected 时使用）")

    # tune
    tune_p = sub.add_parser("tune", help="规则调优分析")
    tune_p.add_argument("--output", "-o", default=None, help="调优报告输出文件")
    tune_p.add_argument("--verbose", "-v", action="store_true", help="详细输出")

    # stats
    sub.add_parser("stats", help="显示反馈数据库统计信息")

    return parser


# ─── 主入口 ───────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """CLI 主入口。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    config = load_config(args.config)

    # 命令行 --knowledge-base 覆盖环境变量
    if args.knowledge_base:
        os.environ["KNOWLEDGE_BASE_PATH"] = args.knowledge_base

    if args.command == "scan":
        return cmd_scan(args, config)
    elif args.command == "feedback":
        return cmd_feedback(args, config)
    elif args.command == "tune":
        return cmd_tune(args, config)
    elif args.command == "stats":
        return cmd_stats(args, config)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

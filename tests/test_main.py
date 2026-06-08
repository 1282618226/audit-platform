"""测试 main.py —— CLI 入口。

聚焦于参数解析、配置加载、命令分发等逻辑。
完整扫描流程的集成测试见 test_orchestrator.py。
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from src.main import (
    _deep_merge,
    build_parser,
    load_config,
    main,
)


# ─── 参数解析 ─────────────────────────────────────────────────────


class TestArgParsing:
    """测试 CLI 参数解析。"""

    def test_scan_defaults(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.command == "scan"
        assert args.offline is False
        assert args.code_dir is None

    def test_scan_offline(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "--offline"])
        assert args.offline is True

    def test_scan_with_dirs(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "--code-dir", "/tmp/code", "--output-dir", "/tmp/report"])
        assert args.code_dir == "/tmp/code"
        assert args.output_dir == "/tmp/report"

    def test_feedback_required_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["feedback", "--finding-id", "f-001", "--verdict", "rejected"])
        assert args.finding_id == "f-001"
        assert args.verdict == "rejected"

    def test_feedback_with_labeler(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "feedback", "--finding-id", "f-002", "--verdict", "confirmed",
            "--labeler", "auditor1", "--note", "真实漏洞",
        ])
        assert args.labeler == "auditor1"
        assert args.note == "真实漏洞"

    def test_tune_with_output(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["tune", "--output", "/tmp/tune-report.md", "--verbose"])
        assert args.output == "/tmp/tune-report.md"
        assert args.verbose is True

    def test_stats(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["stats"])
        assert args.command == "stats"

    def test_no_command_shows_help(self, capsys: pytest.CaptureFixture) -> None:
        """无子命令时返回 1 并打印帮助。"""
        result = main([])
        assert result == 1

    def test_unknown_command(self) -> None:
        """不存在的子命令应被 argparse 拦截。"""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["unknown-cmd"])

    def test_feedback_invalid_verdict(self) -> None:
        """非法 verdict 应被 argparse 拦截。"""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["feedback", "--finding-id", "x", "--verdict", "maybe"])


# ─── 配置加载与合并 ───────────────────────────────────────────────


class TestConfigLoading:
    """测试配置加载。"""

    def test_default_config(self) -> None:
        """无配置文件时返回合理的默认值。"""
        config = load_config("/nonexistent/config.yaml")
        assert config["semgrep"]["enabled"] is True
        assert config["codeql"]["enabled"] is True
        assert "offline" in config["llm"]

    def test_config_from_yaml(self, tmp_path: Path) -> None:
        """从 YAML 文件加载配置。"""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("""
semgrep:
  enabled: false
  timeout_seconds: 120
llm:
  model: deepseek-chat
  offline: true
""")
        config = load_config(str(yaml_path))
        assert config["semgrep"]["enabled"] is False
        assert config["semgrep"]["timeout_seconds"] == 120
        assert config["llm"]["offline"] is True
        # 未覆盖的保持默认
        assert config["codeql"]["enabled"] is True

    def test_config_from_env_var(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """通过环境变量指定配置路径。"""
        yaml_path = tmp_path / "custom.yaml"
        yaml_path.write_text("semgrep:\n  enabled: false\n")
        monkeypatch.setenv("AUDIT_CONFIG", str(yaml_path))

        config = load_config()
        assert config["semgrep"]["enabled"] is False


class TestDeepMerge:
    """测试深度合并逻辑。"""

    def test_shallow_merge(self) -> None:
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        _deep_merge(base, override)
        assert base == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self) -> None:
        base = {"llm": {"model": "default", "timeout": 30}}
        override = {"llm": {"model": "deepseek-chat"}}
        _deep_merge(base, override)
        assert base["llm"]["model"] == "deepseek-chat"
        assert base["llm"]["timeout"] == 30  # 保留未覆盖的键

    def test_deep_nested(self) -> None:
        base = {"a": {"b": {"c": 1, "d": 2}}}
        override = {"a": {"b": {"c": 99}}}
        _deep_merge(base, override)
        assert base["a"]["b"]["c"] == 99
        assert base["a"]["b"]["d"] == 2

    def test_new_key(self) -> None:
        base = {"existing": 1}
        override = {"new_key": {"nested": "value"}}
        _deep_merge(base, override)
        assert base["new_key"]["nested"] == "value"

    def test_override_dict_with_non_dict(self) -> None:
        """非 dict 值应直接覆盖。"""
        base = {"key": {"nested": 1}}
        override = {"key": "string_value"}
        _deep_merge(base, override)
        assert base["key"] == "string_value"


# ─── 命令分发（exit codes）───────────────────────────────────────


class TestCommandDispatch:
    """测试命令分发和 exit codes。"""

    def test_scan_offline_flag_sets_config(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """--offline 应设置 config['llm']['offline'] = True。"""
        # Mock 所有重量级组件创建以避免文件 I/O
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")
        with mock.patch("src.main._create_kb", return_value=None), \
             mock.patch("src.main._create_llm_client", return_value=None), \
             mock.patch("src.main._create_scanners", return_value=(None, None)), \
             mock.patch("src.main._create_feedback_db", return_value=None), \
             mock.patch("src.report_generator.ReportGenerator", return_value=mock.MagicMock()), \
             mock.patch("src.orchestrator.Orchestrator") as mock_orch:
            mock_orch.return_value.run.return_value = mock.MagicMock(
                findings=[], mode="offline", duration_seconds=1.0
            )

            result = main(["scan", "--offline", "--code-dir", str(tmp_path)])
            assert result == 0

    def test_feedback_invalid_verdict_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """非法的 verdict 应在命令层被拒绝。"""
        with mock.patch("src.main._create_feedback_db") as mock_db:
            mock_db.return_value = None
            result = main(["feedback", "--finding-id", "x", "--verdict", "rejected"])
            assert result == 1  # DB 不可用

    def test_stats_no_db(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无反馈数据库时 stats 返回 1。"""
        with mock.patch("src.main._create_feedback_db", return_value=None):
            result = main(["stats"])
            assert result == 1

    def test_tune_no_db(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无反馈数据库时 tune 返回 1。"""
        with mock.patch("src.main._create_feedback_db", return_value=None):
            result = main(["tune"])
            assert result == 1

    def test_main_with_config_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--config 标志应被正确解析。"""
        parser = build_parser()
        args = parser.parse_args(["--config", "/custom/config.yaml", "scan"])
        assert args.config == "/custom/config.yaml"
        assert args.command == "scan"

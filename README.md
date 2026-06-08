# CNAS 源代码安全审计平台

基于 **GB/T 39412-2020**、**GB/T 34944-2017**、**GB/T 34943-2017** 三项国家标准的容器化源代码安全审计平台，用于 CNAS 能力验证活动。

## 功能

- **Semgrep SAST** — 38 条规则（18 Java + 20 C/C++），覆盖 SQL注入、命令注入、XSS、缓冲区溢出等
- **CodeQL** — 10 条 QL 查询（5 Java + 5 C/C++），数据流分析
- **LLM 辅助审查** — DeepSeek (Anthropic SDK)，可离线运行
- **跨标准展开** — 一条命中自动关联多国标条款号
- **Web 服务** — FastAPI + Jinja2 + SQLite，上传 ZIP 或 Git 仓库一键扫描
- **CNAS 格式报告** — DOCX / JSON / Markdown 三种输出
- **多平台** — 支持 linux/amd64 (Windows) 和 linux/arm64 (macOS)

## 快速开始

```bash
# 构建镜像
docker build --platform linux/amd64 -t audit-platform:pro .

# 或使用 Semgrep Pro（需要 token）
docker build --secret id=SEMGREP_APP_TOKEN,src=/path/to/token.txt -t audit-platform:pro .

# CLI 模式：扫描代码
docker run --rm \
  -v $(pwd)/code:/workspace/code \
  -v $(pwd)/report:/workspace/report \
  audit-platform:pro scan --offline

# Web 模式
docker compose up -d
# 浏览器打开 http://localhost:8000
```

> Windows 11 AMD64 部署详见 [docs/windows-deployment.md](docs/windows-deployment.md)

## 项目结构

```
audit-platform/
├── Dockerfile               # 主镜像（6层，多平台构建）
├── web.Dockerfile           # Web 服务镜像
├── docker-compose.yml       # Web 编排
├── config.yaml              # 运行时配置
├── entrypoint.sh            # 容器入口
├── src/
│   ├── main.py              # CLI 入口 (scan/feedback/tune/stats)
│   ├── orchestrator.py      # 5阶段编排 (预处理 → 并行扫描 → 聚合 → LLM → 报告)
│   ├── scanner_semgrep.py   # Semgrep 扫描器
│   ├── scanner_codeql.py    # CodeQL 扫描器
│   ├── llm_client.py        # LLM 客户端
│   ├── report_generator.py  # CNAS 格式 DOCX/JSON/MD 报告
│   └── web/                 # FastAPI Web 服务
├── rules/
│   ├── semgrep/java/        # Java Semgrep 规则（18+1条）
│   ├── semgrep/cpp/         # C/C++ Semgrep 规则（20条）
│   ├── codeql/java/         # Java CodeQL 查询（5条）
│   ├── codeql/cpp/          # C/C++ CodeQL 查询（5条）
│   └── standard-mapping.json # 跨标准条款映射（50条）
├── knowledge/
│   └── knowledge_base.json  # 三项国标知识库
└── tests/                   # 269 个单元测试
```

## 构建参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `APT_MIRROR` | `mirrors.aliyun.com` | apt 镜像源，设空跳过 |
| `PIP_MIRROR` | `pypi.tuna.tsinghua.edu.cn` | pip 镜像，设空跳过 |
| `NPM_MIRROR` | `registry.npmmirror.com` | npm 镜像，设空跳过 |
| `SEMGREP_APP_TOKEN` | (build secret) | Semgrep Pro 安装 token |

## API 端点

| 端点 | 功能 |
|------|------|
| `GET /` | Web 首页 |
| `POST /api/projects` | 创建项目（ZIP 上传 / Git URL） |
| `POST /api/projects/{id}/scans` | 触发异步扫描 `{"standard":"34944","offline":true}` |
| `GET /api/scans/{id}` | 扫描状态 |
| `GET /api/scans/{id}/report` | JSON 报告 |
| `GET /api/scans/{id}/report.docx` | DOCX 下载 |
| `GET /api/stats` | 统计面板 |

## 已知问题

- **DeepSeek API**：国内网络下可能超时/限流，默认使用离线模式（`scan --offline`）
- **CodeQL ARM64**：无原生 ARM64 Linux 二进制，Apple Silicon 下需 QEMU 仿真（慢）
- **C/C++ 规则**：Semgrep 规则已覆盖但未在真实 C/C++ 项目上端到端验证

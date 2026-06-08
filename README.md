# CNAS 源代码安全审计平台

基于 **GB/T 39412-2020**、**GB/T 34944-2017**、**GB/T 34943-2017** 三项国家标准的容器化源代码安全审计平台，用于 CNAS 能力验证活动。

## 覆盖状态

| 标准 | 总条款 | Semgrep | CodeQL | 双覆盖 |
|------|--------|---------|--------|--------|
| GB/T 34944-2017 (Java 漏洞) | 42 | 29 | 25 | 12 |
| GB/T 34943-2017 (C/C++ 漏洞) | 32 | **32** ✅ | 1 | 1 |
| GB/T 39412-2020 (审计指标) | 97 | **97** ✅ | 31 | 31 |
| **总计** | **171** | **158** | **57** | **44** |

详细信息见 [docs/coverage-matrix.md](docs/coverage-matrix.md)。

## 功能

- **Semgrep SAST** — 184 条规则覆盖三项国标全部条款，含 taint mode 数据流追踪
- **CodeQL** — 157 条内置查询映射（69 C/C++ + 88 Java），含数据流分析
- **LLM 辅助审查** — 三级降级策略（LiteLLM → DeepSeek 直连 → 离线模式）
- **入口点+爆发点追踪** — taint mode 规则自动提取数据流入口和爆发点，展示在 CNAS 报告中
- **跨标准展开** — 一条命中自动关联多国标条款号（56 条映射）
- **Web 服务** — FastAPI + Jinja2 + SQLite，上传 ZIP 或 Git 仓库一键扫描
- **CNAS 格式报告** — DOCX / JSON / Markdown 三种输出，含入口点+传播链
- **多平台** — 支持 linux/amd64 (Windows) 和 linux/arm64 (macOS)，自适应 JAVA_HOME 和 Node.js 架构

## 快速开始

```bash
# 克隆
git clone git@github.com:1282618226/audit-platform.git
cd audit-platform

# 构建镜像
docker build --platform linux/amd64 -t audit-platform:pro .

# 或使用 Semgrep Pro（需要 token）
docker build --secret id=SEMGREP_APP_TOKEN,src=/path/to/token.txt -t audit-platform:pro .

# CLI 模式：离线扫描（纯 SAST）
docker run --rm \
  -v $(pwd)/code:/workspace/code \
  -v $(pwd)/report:/workspace/report \
  audit-platform:pro scan --offline

# Web 模式
docker compose up -d
# 浏览器打开 http://localhost:8000
```

> Windows 11 AMD64 部署详见 [docs/windows-deployment.md](docs/windows-deployment.md)

## LLM 集成（三级降级）

```
Level 1: Anthropic SDK → LiteLLM (sidecar, localhost:4000) → DeepSeek API
Level 2: DEEPSEEK_API_KEY → DeepSeek /chat/completions 直连（当 LiteLLM 不可用时自动降级）
Level 3: 离线模式（纯 SAST，当 API 均不可用时自动降级）
```

LiteLLM 自动随 `docker compose up -d` 启动。设置环境变量启用在线模式：

```bash
# 创建 .env 文件
echo "DEEPSEEK_API_KEY=sk-your-key" > .env

# 启动（含 LiteLLM sidecar）
docker compose up -d
```

## 项目结构

```
audit-platform/
├── docker-compose.yml       # Web + LiteLLM sidecar 编排
├── Dockerfile               # 主镜像（6层，多平台构建）
├── web.Dockerfile           # Web 服务镜像
├── litellm-config.yaml      # LiteLLM 代理配置
├── config.yaml              # 运行时配置
├── entrypoint.sh            # 容器入口
├── src/
│   ├── main.py              # CLI 入口 (scan/feedback/tune/stats)
│   ├── orchestrator.py      # 5阶段编排 (预处理 → 并行扫描 → 聚合 → LLM → 报告)
│   ├── scanner_semgrep.py   # Semgrep 扫描器（含 taint 入口点提取）
│   ├── scanner_codeql.py    # CodeQL 扫描器
│   ├── llm_client.py        # LLM 客户端（三级降级：LiteLLM→直连→离线）
│   ├── report_generator.py  # CNAS 格式 DOCX/JSON/MD 报告
│   └── web/                 # FastAPI Web 服务
├── rules/
│   ├── semgrep/java/        # Java Semgrep 规则（49条，含 taint mode）
│   ├── semgrep/cpp/         # C/C++ Semgrep 规则（33条）
│   ├── semgrep/gbt-39412/   # GB/T 39412 审计指标规则（100条+评估）
│   ├── codeql/java/         # Java CodeQL 自定义查询（8条）
│   ├── codeql/cpp/          # C/C++ CodeQL 自定义查询（7条）
│   ├── codeql/codeql-to-gbt-mapping.json  # CodeQL 内置查询 → GB/T 映射（157条）
│   └── standard-mapping.json # 跨标准条款映射（56条）
├── knowledge/
│   └── knowledge_base.json  # 三项国标知识库（171条）
├── docs/
│   ├── coverage-matrix.md   # 标准条款覆盖矩阵
│   ├── windows-deployment.md # Windows 部署指南
│   └── hermes-migration/     # Hermes 配置迁移
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
| `GET /api/scans/{id}/report` | JSON 报告（含入口点+爆发点） |
| `GET /api/scans/{id}/report.docx` | DOCX 下载（CNAS 6列格式） |
| `GET /api/stats` | 统计面板 |

## 入口点 + 爆发点（CNAS 报告）

对于 `mode: taint` 的规则，扫描结果自动包含数据流入口点（source）和爆发点（sink），在 CNAS 报告中显示为：

```
（1）入口点：UserController.java第42行  →  req.getParameter("id")
（2）爆发点：UserDao.java第18行       →  stmt.executeQuery("SELECT ... WHERE id=" + id)
```

## 已知问题

- **CodeQL ARM64**：无原生 ARM64 Linux 二进制，Apple Silicon 下需 QEMU 仿真（较慢）
- **Semgrep Pro dataflow_trace**：跨文件数据流追踪仅 Pro Engine 支持，OSS 引擎仅函数内有效
- **GB/T 39412 部分条款**：3 条需人工或 SCA 工具（参数指定错误、实现不一致函数、第三方软件安全）

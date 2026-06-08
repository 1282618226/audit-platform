## 任务：CodeQL 内置查询集成 —— 优先 C/C++ + GB/T 39412 映射

项目路径：`/Users/chenhaoming/Projects/AIProjects/audit-platform`

### 紧急背景

这周五有一个 C++ 项目需要做源代码安全检测能力验证，检测依据是 GB/T 39412-2020（审计指标）和 GB/T 34943-2017（C/C++漏洞）。

当前 CodeQL 只有 7 条自定义 C/C++ 查询，严重不足。CodeQL 内置有 **40 个 CWE 分类的 C/C++ 安全查询包**（位于 `codeql/cpp-queries`），覆盖缓冲区溢出、内存泄漏、指针安全、格式化字符串等，全部带数据流分析。

### 确认环境

```bash
# 宿主机 CodeQL 路径
/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql

# CodeQL 仓库路径
/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/

# C/C++ 安全查询包
ls /Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/cpp/ql/src/Security/CWE/
```

### 实施一：创建 C/C++ → GB/T 39412 + 34943 映射文件

新建 `rules/codeql/codeql-to-gbt-mapping.json`，优先映射 C/C++ 相关的内置查询规则 ID 到国标条款。以下是从 C/C++ CWE 到 GB/T 两个标准的完整映射：

```json
{
  "cpp/ql/src/Security/CWE/CWE-119/BufferOverflow.ql": {
    "gb_clause": "8.2.7",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "缓冲区复制造成溢出",
    "cwe": "CWE-119"
  },
  "cpp/ql/src/Security/CWE/CWE-120/BufferOverflow.ql": {
    "gb_clause": "8.2.6",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "内存缓冲区边界操作",
    "cwe": "CWE-120"
  },
  "cpp/ql/src/Security/CWE/CWE-121/StackBasedOverflow.ql": {
    "gb_clause": "8.2.6",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "内存缓冲区边界操作",
    "cwe": "CWE-121"
  },
  "cpp/ql/src/Security/CWE/CWE-131/BufferSize.ql": {
    "gb_clause": "8.2.8",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "使用错误长度访问缓冲区",
    "cwe": "CWE-131"
  },
  "cpp/ql/src/Security/CWE/CWE-416/UseAfterFree.ql": {
    "gb_clause": "8.2.4",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "访问已释放内存",
    "cwe": "CWE-416"
  },
  "cpp/ql/src/Security/CWE/CWE-190/IntegerOverflow.ql": {
    "gb_clause": "7.2.3.5",
    "gb_standard": "GB/T 34943-2017",
    "vuln_name": "整数溢出",
    "cwe": "CWE-190"
  },
  "cpp/ql/src/Security/CWE/CWE-191/IntegerUnderflow.ql": {
    "gb_clause": "7.2.3.5",
    "gb_standard": "GB/T 34943-2017",
    "vuln_name": "整数溢出",
    "cwe": "CWE-191"
  },
  "cpp/ql/src/Security/CWE/CWE-134/FormatString.ql": {
    "gb_clause": "7.3.1",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "格式化字符串",
    "cwe": "CWE-134"
  },
  "cpp/ql/src/Security/CWE/CWE-078/CommandInjection.ql": {
    "gb_clause": "6.1.1.6",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "命令行注入",
    "cwe": "CWE-78"
  },
  "cpp/ql/src/Security/CWE/CWE-089/SqlInjection.ql": {
    "gb_clause": "8.3.2",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "SQL注入",
    "cwe": "CWE-89"
  },
  "cpp/ql/src/Security/CWE/CWE-022/PathTraversal.ql": {
    "gb_clause": "8.4.4",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "路径遍历",
    "cwe": "CWE-22"
  },
  "cpp/ql/src/Security/CWE/CWE-457/UninitializedVariable.ql": {
    "gb_clause": "8.1.2",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "资源或变量不安全初始化",
    "cwe": "CWE-457"
  },
  "cpp/ql/src/Security/CWE/CWE-468/IncorrectPointerCast.ql": {
    "gb_clause": "7.5.1",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "不兼容的指针类型",
    "cwe": "CWE-468"
  },
  "cpp/ql/src/Security/CWE/CWE-704/TypeCast.ql": {
    "gb_clause": "7.5.4",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "试图访问非结构体类型指针的数据域",
    "cwe": "CWE-704"
  },
  "cpp/ql/src/Security/CWE/CWE-676/DangerousFunction.ql": {
    "gb_clause": "8.2.6",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "内存缓冲区边界操作",
    "cwe": "CWE-676"
  },
  "cpp/ql/src/Security/CWE/CWE-835/InfiniteLoop.ql": {
    "gb_clause": "8.1.8",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "无限循环",
    "cwe": "CWE-835"
  },
  "cpp/ql/src/Security/CWE/CWE-764/MultipleLocks.ql": {
    "gb_clause": "7.2.3",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "共享资源的并发安全",
    "cwe": "CWE-764"
  },
  "cpp/ql/src/Security/CWE/CWE-367/TOCTOU.ql": {
    "gb_clause": "7.2.3",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "共享资源的并发安全",
    "cwe": "CWE-367"
  },
  "cpp/ql/src/Security/CWE/CWE-079/Xss.ql": {
    "gb_clause": "6.1.2.1",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "跨站脚本",
    "cwe": "CWE-79"
  },
  "cpp/ql/src/Security/CWE/CWE-311/MissingEncryption.ql": {
    "gb_clause": "8.5.4",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "通信安全",
    "cwe": "CWE-311"
  },
  "cpp/ql/src/Security/CWE/CWE-326/WeakEncryption.ql": {
    "gb_clause": "6.2.1.1",
    "gb_standard": "GB/T 39412-2020",
    "vuln_name": "密码安全",
    "cwe": "CWE-326"
  },
  "cpp/ql/src/Security/CWE/CWE-427/UnsafeSearchPath.ql": {
    "gb_clause": "7.2.2.1",
    "gb_standard": "GB/T 34943-2017",
    "vuln_name": "不可信的搜索路径",
    "cwe": "CWE-427"
  }
}
```

**注意**：以上 rule ID 为参考格式。实际运行 `codeql database analyze ... codeql/cpp-queries` 后，SARIF 输出的 rule ID 可能需要从 SARIF 文件的 `runs[0].tool.driver.rules[].id` 中获取准确值。请在宿主机上先运行一次 CodeQL，确认实际的 rule ID 格式：

```bash
/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql database create \
  /tmp/cpp-codeql-db --language=cpp --source-root=/path/to/cpp/project --overwrite \
  --command="make" 2>/dev/null || \
  /Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql database create \
  /tmp/cpp-codeql-db --language=cpp --source-root=/path/to/cpp/project --overwrite

/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql database analyze \
  /tmp/cpp-codeql-db codeql/cpp-queries --format=sarif-latest --output=/tmp/cpp-codeql.sarif

python3 -c "
import json
with open('/tmp/cpp-codeql.sarif') as f:
    d = json.load(f)
for rule in d['runs'][0]['tool']['driver']['rules'][:5]:
    print(f'{rule[\"id\"]}')
    print(f'  {rule.get(\"shortDescription\",{}).get(\"text\",\"\")[:80]}')
    print()
"
```

根据实际的 rule ID 调整映射文件中的 key。

### 实施二：修改 `src/scanner_codeql.py`

增加 `_run_builtin_queries` 方法（如 docs/task-codeql-builtin.md 所述），但优先处理 C/C++。核心改动：

```python
def scan(self, source_root, language="java", build_command=None):
    """一步完成 CodeQL 扫描（自定义查询 + 内置查询包）。"""
    findings = []
    db_path = self.create_database(source_root, language, build_command)
    if db_path is None:
        return findings
    
    # 1. 运行自定义 QL 查询（已有的）
    custom = self.analyze(db_path, language)
    findings.extend(custom)
    
    # 2. 运行内置安全查询包（新增）
    builtin = self._run_builtin_queries(db_path, language)
    findings.extend(builtin)
    
    return findings


def _run_builtin_queries(self, database_path, language="java"):
    """使用 CodeQL 内置安全查询包扫描，结果映射到 GB/T 条款。"""
    import tempfile, json, os
    
    query_pack = "codeql/cpp-queries" if language == "cpp" else "codeql/java-queries"
    
    with tempfile.NamedTemporaryFile(suffix=".sarif", mode="w", delete=False) as f:
        sarif_path = f.name
    
    cmd = [
        self.cli_path, "database", "analyze",
        str(database_path), query_pack,
        "--format", "sarif-latest", "--output", sarif_path,
        "--no-save-cache", "--no-upload", "--threads", "2",
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self._timeout)
        if result.returncode not in (0, 2):
            logger.warning("CodeQL 内置查询失败 (exit=%d)", result.returncode)
            return []
        return self._parse_builtin_sarif(sarif_path)
    except FileNotFoundError:
        logger.warning("CodeQL CLI 不可用，跳过内置查询")
        return []
    except Exception as e:
        logger.warning("CodeQL 内置查询异常: %s", e)
        return []
```

### 实施三：更新 `src/orchestrator.py`

在 `_parallel_scan` 中，CodeQL 调用保持已有方式不变（因为 `scan()` 方法内部已包含内置查询调用）。

### 实施四：更新 `rules/standard-mapping.json`

将 CodeQL 内置查询覆盖的 GB/T 39412 和 34943 条款补充到跨标准映射中，确保报告能正确展开。

### 验证要求（宿主机 macOS 上先验证映射准确性）

```bash
cd /Users/chenhaoming/Projects/AIProjects/audit-platform

# 1. 先确认实际的 SARIF rule ID 格式
# 在宿主机上用 CodeQL 跑 C++ 查询包，提取实际 rule ID

# 2. 单元测试
.venv/bin/python3 -m pytest tests/ -q -k "codeql"

# 3. 全量测试
.venv/bin/python3 -m pytest tests/ -q
```

### 关于 Windows 部署的说明

由于 macOS ARM64 Docker 中 CodeQL 不可用（Rosetta 限制），**新增的 CodeQL 内置查询集成在 Windows AMD64 上原生生效**。周五的 C++ 能力验证建议在 **Windows 机器上运行** CodeQL。平台会自动检测 CodeQL 可用性，不可用时静默跳过，不影响 Semgrep 扫描。

### 不要做的事

- ❌ 不要删除现有的自定义 QL 查询
- ❌ 不要修改 `src/report_generator.py`
- ❌ 不要在代码中硬编码映射表，必须从 JSON 文件加载
- ❌ 不要修改测试项目中的 C/C++ 代码

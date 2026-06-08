## 任务：补全最后 3 条 GB/T 39412 条款（PARTIAL 规则）

项目路径：`/Users/chenhaoming/Projects/AIProjects/audit-platform`

### 背景

以下 3 条之前被标记为"不可自动化"，但经人工复核，每条都有部分可检测的模式。请对每条实现**至少一种具体检测模式**，添加到 `rules/semgrep/gbt-39412/gbt-39412-auto.yml`。

### 实施前确认当前状态

```bash
cd /Users/chenhaoming/Projects/AIProjects/audit-platform
# 确认已有规则
grep -c "^  - id" rules/semgrep/gbt-39412/gbt-39412-auto.yml
```

### 规则实现

#### 1. 7.3.3 参数指定错误

知识库中的审计方法：
- 除数为零：`a / b` 或 `a % b` 前无 `b == 0` 校验
- null 传非空参数：`.equals("x")` 调用的对象未做 null 检查
- 同类型参数顺序错位：同类型参数调用时顺序可能颠倒

检测逻辑（实现以下任意一种即可）：
- **模式A — 除数为零**：检测除法 `/` 或取模 `%` 操作中，分母/模数不是常量且前面没有 `if(x==0)`、`if(x!=0)`、`x != 0` 等判空/判零检查
- **模式B — null 传非空参数**：检测变量在未判空的情况下直接调用 `.equals()`、`.toString()`、`.charAt()` 等方法

YAML 格式参考（仅 `pattern-either` 无需 `pattern-not` 的简单模式）：

```yaml
  - id: gbt-39412-7.3.3-parameter-error
    languages: [java]
    severity: WARNING
    message: >
      【GB/T 39412-2020 7.3.3】参数指定错误 — 检测到可能的风险模式
    patterns:
      - pattern-either:
          # 除以零：分母来自变量且无判零检查
          - patterns:
              - pattern-inside: |
                  $TYPE $VAR = $X;
                  ...
                  $RES = $VAR / $Y;
              - pattern: $VAR / $Y
          # 变量未判空直接调用方法
          - patterns:
              - pattern-inside: |
                  $TYPE $VAR = $X;
                  ...
                  $VAR.equals(...)
              - pattern-not-inside: |
                  if ($VAR != null) { ... }
    metadata:
      gb_standard: GB/T 39412-2020
      gb_clause: "7.3.3"
      cnas_severity: 中
```

（以上仅为示例格式，请根据 Semgrep 实际能力编写可工作的规则）

#### 2. 7.3.5 实现不一致函数

知识库中的审计方法：
- `String.split(regex)` 未指定 limit 参数 → JDK 版本差异
- `File.listFiles()` 结果未排序直接使用 → OS 排序差异
- `URL.equals()` 使用 → 大小写行为差异
- `DateFormat` / `SimpleDateFormat` 未指定 Locale → 区域差异

检测逻辑（实现以下任意一种即可）：
- **模式A — split 无 limit**：检测 `$STR.split($REGEX)` 调用，其中 `$REGEX` 字符串参数不是 `-1` 或 `0`
- **模式B — listFiles 未排序**：检测 `listFiles()` 返回值赋值给变量后，在后续代码中直接用于遍历或返回前未调用 `Arrays.sort()` 或 `List.sort()`
- **模式C — 无 Locale 的 DateFormat**：检测 `new SimpleDateFormat($PATTERN)` 构造时未传入第二个 Locale 参数

```yaml
  - id: gbt-39412-7.3.5-inconsistent-functions
    languages: [java]
    severity: WARNING
    message: >
      【GB/T 39412-2020 7.3.5】实现不一致函数 — 检测到跨平台/跨版本风险
    patterns:
      - pattern-either:
          # split 未指定 limit 参数
          - pattern: $STR.split($REGEX)
          # 或：listFiles 未排序
          - pattern: $VAR = $FILE.listFiles()
    metadata:
      gb_standard: GB/T 39412-2020
      gb_clause: "7.3.5"
      cnas_severity: 中
```

（同样，以上为示例格式，请根据实际可工作性调整）

#### 3. 9.2 第三方软件安全可靠

知识库中的审计方法：
- 是否使用固定版本号
- 是否从官方仓库引入
- CVE 漏洞扫描（需要 OWASP DC）

检测逻辑：
- **模式A — 依赖未使用固定版本**：检测 `pom.xml` 或 `build.gradle` 中的依赖声明使用了 `LATEST`、`RELEASE`、`+`、`SNAPSHOT` 等非固定版本号
- **模式B — 非官方仓库源**：检测 `pom.xml` 中的 `<repository>` 或 `build.gradle` 中的 `repositories` 配置指向非 `mavenCentral()` / `mavenCentral` / `repo1.maven.org` 的源

```yaml
  - id: gbt-39412-9.2-third-party-security
    languages: [generic, java]
    severity: WARNING
    message: >
      【GB/T 39412-2020 9.2】第三方软件安全可靠 — 检测到安全风险
    patterns:
      - pattern-either:
          # 非固定版本号依赖
          - pattern: '$GROUP:$NAME:LATEST'
          - pattern: '$GROUP:$NAME:RELEASE'
          - pattern: '$GROUP:$NAME:${...}'
          # SNAPSHOT 依赖
          - pattern: '$GROUP:$NAME:$VERSION-SNAPSHOT'
    metadata:
      gb_standard: GB/T 39412-2020
      gb_clause: "9.2"
      cnas_severity: 中
```

### 验证要求

1. `.venv/bin/python3 -m pytest tests/ -q` → 269 passed
2. 最终确认覆盖：
   ```bash
   python3 << 'EOF'
   import json, re, os
   with open('knowledge/knowledge_base.json') as f:
       kb = json.load(f)
   covered = set()
   for root, dirs, files in os.walk('rules/semgrep'):
       for fn in files:
           if fn.endswith('.yml'):
               with open(os.path.join(root, fn)) as fh:
                   covered.update(re.findall(r'gb_clause:\s*"([\d.]+)"', fh.read()))
   items = kb['standards']['GB/T 39412-2020']['sheets']['Sheet1']['items']
   missing = [row for row in items if row[1] not in covered]
   print(f'{len(items)-len(missing)}/{len(items)}')
   for row in missing:
       print(f'  ❌ {row[1]} {row[2]}')
   EOF
   ```
   输出应为 `97/97`，无 ❌

3. 更新 `rules/semgrep/gbt-39412/README.md` 中的评估状态，将这 3 条从 NO 改为 PARTIAL/IMPLEMENTED

### 不要做的事

- ❌ 不要修改 `src/`、`tests/`、`knowledge/` 目录
- ❌ 不要修改已存在的其他规则文件
- ❌ 规则不要过于复杂导致误报率过高——PARTIAL 规则允许一定程度的不精确，宁可漏报也不要大量误报

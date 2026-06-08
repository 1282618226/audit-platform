## 任务：规则误报优化

项目路径：`/Users/chenhaoming/Projects/AIProjects/audit-platform`

### 背景

用测试项目 `~/Projects/eclipse-workspace/YP-34944-E-007/src/` 扫描，231 条发现中约 200+ 条是误报。以下是按严重程度排序的问题和修复方案。

### 修复前确认

```bash
cd /Users/chenhaoming/Projects/AIProjects/audit-platform
# 记录当前发现数
semgrep scan --config rules/semgrep/java/gbt-34944-java.yml --json \
  /Users/chenhaoming/Projects/eclipse-workspace/YP-34944-E-007/src \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'修复前: {len(d.get(\"results\",[]))} 条发现')"
```

### 修复清单

#### P0：6.2.6.3 口令硬编码（185 条 → 目标 0-2 条）

当前规则在 `rules/semgrep/java/gbt-34944-java.yml` 中：

```yaml
- id: gbt-34944-6.2.6.3-hardcoded-password
  patterns:
    - pattern-either:
        - pattern: $PWD.equals($STR)             # 问题：$PWD 匹配所有变量
        - pattern: $STR.equals($PWD)             # 问题同上
        - pattern: String $PWD = $STR;           # 问题：匹配所有 String 声明
```

**当前误报**：`String account = ...`、`String docId = ...`、`String adminID = ""` 全部被报——任何 String 声明都匹配了。

**修复方案**：
1. 将 `$PWD` 加上 `metavariable-regex` 限制变量名必须包含 `password`、`pwd`、`secret`、`key`、`token`、`credential` 等敏感关键词
2. 对于 `String $PWD = $STR` 这种赋值，还要检查 `$STR` 是否是字符串字面量（硬编码值），而非从数据库、请求参数等来源获取的值

参考格式：

```yaml
- id: gbt-34944-6.2.6.3-hardcoded-password
  severity: ERROR
  languages: [java]
  message: 【GB/T 34944-2017 6.2.6.3】口令/密钥硬编码
  patterns:
    - pattern-either:
        # 情况1: 字符串字面量赋值给密码相关变量
        - patterns:
            - pattern: String $VAR = "...";
            - metavariable-regex:
                metavariable: $VAR
                regex: (?i).*(password|pwd|secret|token|credential|apikey|api_key|passwd).*
        # 情况2: 硬编码值直接传入 password 相关参数
        - patterns:
            - pattern: $FUNC(..., "...", ...)
            - metavariable-regex:
                metavariable: $FUNC
                regex: (?i).*(password|pwd|secret|setcredential).*
    # 排除来自方法的赋值（不是硬编码）
    - pattern-not: String $VAR = $REQ.getParameter(...)
    - pattern-not: String $VAR = $CONFIG.getProperty(...)
    - pattern-not: String $VAR = $OBJ.getProperty(...)
    - pattern-not: String $VAR = $MAP.get(...)
  metadata:
    gb_standard: GB/T 34944-2017
    gb_clause: "6.2.6.3"
```

**验证**：修复后扫描，口令硬编码发现数应从 185 降到接近 0。

#### P1：6.2.6.7 危险加密算法（10 条 → 目标 2-3 条）

**当前误报**：`AES/GCM/NoPadding` 被报——AES-GCM 是标准安全算法，不应报。

**修复方案**：将 pattern 从 `Cipher.getInstance($ALG)` 改为白名单名单匹配不安全算法：

```yaml
- id: gbt-34944-6.2.6.7-weak-crypto
  languages: [java]
  severity: WARNING
  message: 【GB/T 34944-2017 6.2.6.7】使用已破解或危险的加密算法
  patterns:
    - pattern-either:
        # 已知不安全算法
        - pattern: Cipher.getInstance("DES")
        - pattern: Cipher.getInstance("DES/...")
        - pattern: Cipher.getInstance("DESede")
        - pattern: Cipher.getInstance("RC2")
        - pattern: Cipher.getInstance("RC4")
        - pattern: Cipher.getInstance("MD2")
        - pattern: Cipher.getInstance("MD4")
        - pattern: Cipher.getInstance("IDEA")
        - pattern: Cipher.getInstance("Blowfish")
        # 也匹配用变量的情况，但要求变量名含不安全算法关键词
        - patterns:
            - pattern: Cipher.getInstance($ALG)
            - metavariable-regex:
                metavariable: $ALG
                regex: (?i).*(DES|RC2|RC4|MD2|MD4|IDEA|Blowfish).*
  metadata:
    gb_standard: GB/T 34944-2017
    gb_clause: "6.2.6.7"
```

#### P1：6.2.6.19 RSA 填充不足（10 条 → 目标 2 条）

**当前误报**：`AES/GCM/NoPadding` 也被 6.2.6.19 规则报了——因为规则只检查了字符串里是否含 `RSA` 关键词，但 `AES/GCM/NoPadding` 也匹配了。

**修复方案**：明确限定只匹配 RSA 算法 + 非 OAEP 填充的组合：

```yaml
- id: gbt-34944-6.2.6.19-rsa-pkcs1
  languages: [java]
  severity: WARNING
  message: 【GB/T 34944-2017 6.2.6.19】RSA算法未使用最优非对称加密填充
  patterns:
    - pattern-either:
        # RSA 无填充指定（使用默认）
        - pattern: Cipher.getInstance("RSA")
        # RSA/ECB/PKCS1Padding — 不安全，应使用 OAEP
        - pattern: Cipher.getInstance("RSA/ECB/PKCS1Padding")
        # 动态算法名但含 RSA
        - patterns:
            - pattern: Cipher.getInstance($ALG)
            - metavariable-regex:
                metavariable: $ALG
                regex: (?i).*RSA.*(?!OAEP)
  metadata:
    gb_standard: GB/T 34944-2017
    gb_clause: "6.2.6.19"
```

#### P1：6.2.6.8 弱散列算法（2 条 → 目标 1 条）

**当前误报**：`SHA-256` 也被报。SHA-256 是安全的，只有 MD5/SHA-1 才是不安全的散列算法。

**修复方案**：只报 MD5/SHA-1：

```yaml
- id: gbt-34944-6.2.6.8-weak-hash
  languages: [java]
  severity: WARNING
  message: 【GB/T 34944-2017 6.2.6.8】可逆的散列算法
  patterns:
    - pattern-either:
        - pattern: MessageDigest.getInstance("MD5")
        - pattern: MessageDigest.getInstance("SHA-1")
        - pattern: MessageDigest.getInstance("SHA")
        - patterns:
            - pattern: MessageDigest.getInstance($ALG)
            - metavariable-regex:
                metavariable: $ALG
                regex: (?i).*(MD5|SHA-1|SHA1).*
  metadata:
    gb_standard: GB/T 34944-2017
    gb_clause: "6.2.6.8"
```

#### P2：6.2.8.5 依赖外部提供的文件名（6 条 → 目标 2 条）

**当前误报**：`file.getName()`、`cookie.getName()` 等非文件下载场景也被报。

**修复方案**：缩小匹配范围，只报涉及文件下载/上传时文件名直接来自用户输入：

```yaml
- id: gbt-34944-6.2.8.5-file-extension-trust
  languages: [java]
  severity: WARNING
  message: 【GB/T 34944-2017 6.2.8.5】依赖外部提供的文件名称或扩展名
  patterns:
    - pattern-either:
        # 文件上传：getOriginalFilename() 直接用于保存
        - patterns:
            - pattern: $FILE.transferTo(...)
            - pattern-inside: |
                String $NAME = $FILE.getOriginalFilename();
                ...
                $FILE.transferTo(...)
        # 文件下载：文件名来自用户输入
        - patterns:
            - pattern: $RESP.sendRedirect($REQ.getParameter(...))
  metadata:
    gb_standard: GB/T 34944-2017
    gb_clause: "6.2.8.5"
```

#### P2：6.2.3.8 信息通过日志泄露（2 条 → 目标 0 条）

**当前误报**：`logger.info("File deleted: " + fileName)` — 这只是操作日志，不是安全敏感信息泄露。

**修复方案**：只报日志中包含明显敏感信息（密码、token、身份证、银行卡号等）：

```yaml
- id: gbt-34944-6.2.3.8-vuln
  languages: [java]
  severity: WARNING
  message: 【GB/T 34944-2017 6.2.3.8】信息通过服务器日志文件泄露
  patterns:
    - pattern-either:
        # 记录密码到日志
        - patterns:
            - pattern: $LOGGER.$LEVEL($MSG)
            - metavariable-regex:
                metavariable: $MSG
                regex: (?i).*(password|pwd|token|secret|creditcard|idcard|bankcard).*
  metadata:
    gb_standard: GB/T 34944-2017
    gb_clause: "6.2.3.8"
```

### 验证要求

修复后重新扫描测试项目：

```bash
cd /Users/chenhaoming/Projects/AIProjects/audit-platform
semgrep scan --config rules/semgrep/java/gbt-34944-java.yml --json \
  /Users/chenhaoming/Projects/eclipse-workspace/YP-34944-E-007/src \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
from collections import Counter
c=Counter()
for r in d['results']:
    name = r['check_id'].split('-')[-1]
    c[name]+=1
print(f'总发现: {len(d[\"results\"])}')
for k,v in c.most_common():
    print(f'  {v:4d} | {k}')
"
```

目标：口令硬编码 185→0、弱加密 10→2、RSA填充 10→2、弱散列 2→1、日志泄露 2→0

### 不要做的事

- ❌ 不要修改 `src/`、`tests/`、`knowledge/` 目录
- ❌ 不要修改 C/C++ 规则或 39412 规则（当前测试项目只跑 Java）
- ❌ 不要删除已有规则，只修改 pattern 缩小匹配范围

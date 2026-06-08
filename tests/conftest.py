"""pytest fixtures，提供测试复用的 mock 数据和工具。"""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_kb_json() -> dict:
    """构造一个结构完整但内容精简的知识库，用于单元测试。"""
    return {
        "meta": {
            "generated_at": "2025-06-06",
            "standards": [
                "GB/T 39412-2020 信息安全技术 代码安全审计规范",
                "GB/T 34944-2017 Java语言源代码漏洞测试规范",
                "GB/T 34943-2017 C/C++语言源代码漏洞测试规范",
            ],
        },
        "standards": {
            "GB/T 34944-2017": {
                "full_name": "Java语言源代码漏洞测试规范",
                "language": "Java",
                "clause_prefix": "6.2",
                "total_vulns": 2,
                "vulnerabilities": [
                    {
                        "clause": "6.2.3.4",
                        "name": "SQL注入",
                        "category": "数据处理",
                        "language": "Java",
                        "framework": "通用",
                        "description": "使用未经验证的输入数据采用拼接字符串的方式形成SQL语句。",
                        "risk": "攻击者可输入任何SQL语句，实现越权查询。",
                        "fix": "采用PreparedStatement创建SQL语句。",
                        "negative_code": "String query = \"SELECT * FROM user WHERE id = '\" + owner + \"'\";",
                        "positive_code": 'PreparedStatement ps = con.prepareStatement("SELECT * FROM user WHERE id = ?");',
                    },
                    {
                        "clause": "6.2.6.3",
                        "name": "口令硬编码",
                        "category": "安全功能",
                        "language": "Java",
                        "framework": "通用",
                        "description": "程序代码中包含硬编码口令。",
                        "risk": "攻击者可通过反编译获取硬编码口令。",
                        "fix": "使用单向加密算法对口令进行加密并存储在外部文件或数据库中。",
                        "negative_code": 'if ("secret123".equals(password))',
                        "positive_code": "String dbPassword = getPassword(); /* 从数据库获取 */",
                    },
                ],
            },
            "GB/T 34943-2017": {
                "full_name": "C/C++语言源代码漏洞测试规范",
                "language": "C/C++",
                "clause_prefix": "7.2",
                "total_vulns": 2,
                "vulnerabilities": [
                    {
                        "clause": "7.2.3.6",
                        "name": "缓冲区溢出",
                        "category": "数据处理",
                        "language": "C\\C++",
                        "framework": "通用",
                        "description": "对被分配内存空间之外的内存空间进行读或写操作。",
                        "risk": "攻击者可利用缓冲区溢出让系统崩溃或者执行恶意代码。",
                        "fix": "对读写缓冲区的数据长度进行检查。",
                        "negative_code": "strcpy(buf, user_input);",
                        "positive_code": "strncpy(buf, user_input, sizeof(buf) - 1);",
                    },
                    {
                        "clause": "7.2.7.3",
                        "name": "口令硬编码",
                        "category": "安全功能",
                        "language": "C\\C++",
                        "framework": "通用",
                        "description": "程序代码中包含硬编码口令。",
                        "risk": "攻击者可通过反编译或直接读取二进制代码获取硬编码口令。",
                        "fix": "使用单向不可逆的加密算法对口令进行加密并存储在外部文件或数据库中。",
                        "negative_code": 'if (strcmp(pwd, "admin123") == 0)',
                        "positive_code": "/* 从加密存储读取口令并比较 */",
                    },
                ],
            },
            "GB/T 39412-2020": {
                "full_name": "信息安全技术 代码安全审计规范",
                "type": "overarching standard",
                "description": "源代码安全审计过程规范。",
                "total_items": 2,
                "sheets": {
                    "Sheet1": {
                        "header": [
                            "序号",
                            "标准条款编号",
                            "标准条款标题",
                            "标准条款内容",
                            "审计步骤",
                            "Source",
                            "Sink",
                            "Sanitize",
                            "误报排除",
                            "修复建议",
                            "适用语言",
                            "备注",
                            "存在的疑问",
                            "人工走查负责人",
                        ],
                        "items": [
                            [
                                "1",
                                "6.1.1.6",
                                "命令行注入",
                                "审计指标：应正确处理命令中的特殊元素。",
                                "1. 检查代码中是否调用命令执行函数。\n2. 检查用户可控输入在拼接到命令前是否经过过滤。",
                                "argv, getenv(), 用户输入",
                                "system(), popen(), execve(), Runtime.exec()",
                                "白名单验证, 参数数组化, escapeShell()",
                                "1. 使用参数数组化execve()，命令和参数分离。\n2. 使用白名单验证。",
                                "1. 优先使用参数数组化的ProcessBuilder/execve()。\n2. 对所有用户可控输入进行白名单格式验证。",
                                "Java/C++",
                                "",
                                "",
                                "黄兆森",
                            ],
                            [
                                "2",
                                "6.1.2.1",
                                "跨站脚本",
                                "审计指标：应避免跨站脚本攻击。",
                                "1. 检查用户输入是否未经转义直接输出到HTML。\n2. 检查是否使用context-aware转义。",
                                "input, content, body, param, query, cookie",
                                "innerHTML, document.write(), eval(), 直接输出",
                                "htmlencode(), htmlescape(), text()",
                                "1. 输出到HTML正文前转义。\n2. 模板引擎默认自动编码。",
                                "1. 对所有用户输入进行HTML转义。\n2. 使用context-aware转义库。",
                                "Java/C++",
                                "",
                                "",
                                "黄兆森",
                            ],
                        ],
                    }
                },
            },
        },
    }


@pytest.fixture
def kb_path(sample_kb_json: dict) -> Path:
    """将 sample_kb_json 写入临时文件，返回 Path 对象。"""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(sample_kb_json, f, ensure_ascii=False, indent=2)
        return Path(f.name)

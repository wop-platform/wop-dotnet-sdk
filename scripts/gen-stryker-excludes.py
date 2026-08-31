#!/usr/bin/env python3
"""生成 Stryker 行级排除：行号 → 字符跨度（span）。

Stryker.NET 的细粒度过滤语法 `File.cs{start..end}` 中 start/end 是
**字符索引**（官方文档：indices of the first/last character），不是行号；
且 4.16 实证：span 排除仅在 **CLI -m 参数**下生效，config `mutate` 键会
静默忽略 span（wop-dotnet-sdk 2026-08-31 三轮对照实验：config 不生效、
CLI 生效）。因此本脚本输出 CLI 参数，由 scripts/mutation-test.sh 消费。

勿改用 ignore-methods：本仓 15 组等价点中 12 组与同方法真击杀共存
（第十轮实证：UrlEncodeJava 28killed / EncryptHeader.Parse 33 / Extract 31 /
BuildRequest 30 同方法均有真击杀），方法粒度排除会一并排掉非等价 killed、
虚化击杀率；唯 AlgorithmSuite.ctor 零误伤但单独混用两机制徒增复杂度。
字符跨度是唯一能贴合「逐条论证过的等价域」的粒度。

用法:
  python3 scripts/gen-stryker-excludes.py           # 打印 span 参数（每行一条）
  python3 scripts/gen-stryker-excludes.py --check   # 校验清单行号未漂移（CI 用）
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "Wop.Sdk"

# 等价变异点清单（文件 → 行区间列表）＋ 黑盒不可区分论证：
#   Codec 61-64   DecodeIndex 返回值仅进入 (idx & mask)!=0 判定，字符置换后非零性不变
#   Codec 72,136  byte 无符号，>> 与 >>> 恒等（C# 11 unsigned right shift）
#   ContentDigest 43,83  IndexOf↔LastIndexOf：恰一空格合法域两者恒等、非法域均拒
#   ContentDigest 44     sp==0 不可达（tag 为空时先落 Invalid 同码同文案）
#   SignHeader 49,50     同上两类（Trim 后 sp==0 不可达；单空格域等价）
#   EncryptHeader 20     value=null 与 "Stryker was here!" 同落 23 行同文案
#   EncryptedEnvelope 33 continue 删除后顺序执行与下轮迭代等价
#   KeyCodec 58          标准 PEM 数据行不含 '-'（base64 字母表），StartsWith↔EndsWith 不可分
#   Transport 52         baseUrl null 与 SH! 均使 Uri 构造失败、同文案
#   WopClient 85         wireBody 非 null 且空不可达（上游 { Length: > 0 } 保证）
#   WopClient 170        Verify 头字典 OrdinalIgnoreCase，To↔Upper 等价
#   WopCrypto 35,47      off 上界恒为 len-1，< ↔ <= 等价
#   WopCrypto 178-180    OpenMessage 显式 fail-fast 与 catch 兜底同 Fuzzy 文案（保留代码、排除变异）
#   AlgorithmSuite 40-48 构造函数体删除在本仓 nullable 严格编译下为 CS8618 编译错，
#                        Stryker 内部编译语境存活、不可稳定复现
EQUIVALENT_LINES: dict[str, list[tuple[int, int]]] = {
    "Codec.cs":           [(62, 65), (73, 73), (138, 138)],
    "ContentDigest.cs":   [(43, 44), (84, 84)],
    "SignHeader.cs":      [(49, 50)],
    "EncryptHeader.cs":   [(20, 20)],
    "EncryptedEnvelope.cs": [(33, 33)],
    "KeyCodec.cs":        [(59, 59)],
    "Transport.cs":       [(52, 52)],
    "WopClient.cs":       [(85, 85), (171, 171)],
    "WopCrypto.cs":       [(36, 36), (50, 50), (183, 186)],
    "AlgorithmSuite.cs":  [(40, 48)],
}

# 行号锚（漂移检测）：行内容前缀 → 源码变更后 --check 报错即须更新清单
ANCHORS: dict[tuple[str, int], str] = {
    ("Codec.cs", 62): "if (c >= 'A' && c <= 'Z')",
    ("Codec.cs", 73): "chars[i * 2] = HexLower",
    ("Codec.cs", 138): "sb.Append('%')",
    ("ContentDigest.cs", 43): "var sp = value.IndexOf",
    ("ContentDigest.cs", 44): "if (sp < 0)",
    ("ContentDigest.cs", 84): "var hex = headerValue.Substring",
    ("SignHeader.cs", 49): "var sp = trimmed.IndexOf",
    ("SignHeader.cs", 50): "if (sp <= 0)",
    ("EncryptHeader.cs", 20): "var v = (value ?? \"\").Trim()",
    ("EncryptedEnvelope.cs", 33): "continue;",
    ("KeyCodec.cs", 59): "if (t.Length == 0 || t.StartsWith",
    ("Transport.cs", 52): "_baseUrl = baseUrl ??",
    ("WopClient.cs", 85): "if (wireBody is { Length: > 0 })",
    ("WopClient.cs", 171): "headers[name.ToLowerInvariant()]",
    ("WopCrypto.cs", 36): "buffer[i] = off >= 0",
    ("WopCrypto.cs", 50): "buffer[i] = off >= 0",
    ("WopCrypto.cs", 183): "if (key.Length != suite.CekLength",
    ("AlgorithmSuite.cs", 40): "{",
}


def char_span(text: str, start_line: int, end_line: int) -> tuple[int, int]:
    """1-based 行区间 → 0-based 字符跨度（含端点行全部内容）。"""
    lines = text.split("\n")
    start = sum(len(l) + 1 for l in lines[: start_line - 1])
    end = start + sum(len(l) + 1 for l in lines[start_line - 1 : end_line]) - 1
    return start, end


def main() -> int:
    check = "--check" in sys.argv
    failed = False
    for (name, line), prefix in ANCHORS.items():
        text = (SRC / name).read_text(encoding="utf-8")
        actual = text.split("\n")[line - 1].strip()
        if not actual.startswith(prefix):
            print(f"ANCHOR DRIFT: {name}:{line} 期望前缀 {prefix!r} 实际 {actual!r}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    if check:
        print("anchors ok")
        return 0
    for name, ranges in sorted(EQUIVALENT_LINES.items()):
        text = (SRC / name).read_text(encoding="utf-8")
        for lo, hi in ranges:
            s, e = char_span(text, lo, hi)
            print(f"!**/{name}{{{s}..{e}}}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

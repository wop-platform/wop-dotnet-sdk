#!/usr/bin/env python3
"""docstring 门检查器（.NET / wop-dotnet-sdk，统一契约 2026-08-31）。

度量口径（契约「各语言符号定义」.NET 行）：
  对外（100%）＝顶层 public class/interface/record/struct ＋ public 方法
              （override 不豁免——简单一致）；
  内部（≥80%，空集＝达标）＝internal/private 方法。
  构造函数不是方法（无返回类型位），不扫；属性/字段/enum 不在口径内。

docstring 判定：声明的前一行（须非空）以 /// 开头，即声明与注释间无空行。

扫描面（反作弊）：git ls-files 枚举 src/**/*.cs（只认 git 跟踪文件，防
未跟踪文件混入），排除 obj/bin 生成物；tests/ 不在 src/ 下，天然排除。

用法：
  python3 scripts/docstring_gate.py               # 全量检查：exit 0 达标 / 1 未达标
  python3 scripts/docstring_gate.py --json        # JSON 统计（外部消费）
  python3 scripts/docstring_gate.py --self-test   # 负控制（坏输入必须报缺）

正则实现说明（任务书「正则即可」）：以「行首修饰符序列 + 返回类型 + 名称
+ (」识别方法，等价排除构造函数（名称前只有一个词）、字段/属性（无参列
或前缀含 '='）。纯文本无 AST——C# 语法在此仓形态规整，负控制覆盖易错面。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# 内部阈值：契约「内部 API ≥80%，空集视为达标」
INTERNAL_MIN = 0.80

# 顶层对外类型：行首（列 0，即顶层）public … class/interface/record/struct。
# enum 不在契约口径（class/interface/record/struct）内。
TYPE_RE = re.compile(
    r"^public\s+(?:[A-Za-z_]\w*\s+){0,3}"
    r"(class|interface|record|struct)\s+([A-Za-z_]\w*)"
)

# 方法：行首缩进 + ≥1 个修饰符 + 返回类型 + 名称(+泛型参数) + '('。
MODIFIER_WORDS = (
    "public|private|internal|protected|static|sealed|override|abstract|"
    "virtual|async|partial|extern|new|unsafe|readonly"
)
METHOD_RE = re.compile(
    r"^\s*(?P<mods>(?:(?:" + MODIFIER_WORDS + r")\s+)+)"
    r"(?P<ret>.+?)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*(?=\()"
)
# 防误报：名称本身是修饰词（如 "… = new("）、或前缀混入赋值/成员体
# （'='、'{'、';'）的一律不是方法声明。
_MODIFIER_SET = set(MODIFIER_WORDS.split("|"))


def _match_method(line: str) -> tuple[str, str] | None:
    """命中方法声明 → (可见性类别, 名称)；否则 None。

    可见性类别：'public' → 对外；'internal'/'private' → 内部。
    """
    m = METHOD_RE.match(line)
    if not m:
        return None
    name = m.group("name")
    if name in _MODIFIER_SET:
        return None
    # 前缀（修饰符+返回类型+名称，即 '(' 之前的部分）不得含赋值/成员体标记
    prefix = m.group("mods") + m.group("ret") + name
    if any(ch in prefix for ch in "={};"):
        return None
    mods = set(m.group("mods").split())
    if "public" in mods:
        return "public", name
    if mods & {"internal", "private", "protected"}:
        return "internal", name
    return None


def _has_doc(lines: list[str], idx: int) -> bool:
    """契约判定：前一非空行以 /// 开头，且与声明间无空行。

    即声明的紧邻上一行必须非空且以 /// 开头（空行 = 有间隔 = 不算）。
    """
    if idx == 0:
        return False
    prev = lines[idx - 1].strip()
    return prev != "" and prev.startswith("///")


def scan_text(path: str, text: str) -> dict:
    """纯函数：扫描单个源码文本 → {'external': [...], 'internal': [...]}。

    每个条目为 (path, line_no, kind, name)；kind ∈ {'type', 'method'}。
    """
    external: list[tuple[str, int, str, str]] = []
    internal: list[tuple[str, int, str, str]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        tm = TYPE_RE.match(line)
        if tm:
            external.append((path, i + 1, "type", tm.group(2)))
            continue
        mm = _match_method(line)
        if mm:
            vis, name = mm
            entry = (path, i + 1, "method", name)
            (external if vis == "public" else internal).append(entry)
    return {"external": external, "internal": internal}


def enumerate_files() -> list[str]:
    """git ls-files 枚举扫描面（反作弊：只认跟踪文件）。异常 → 向上抛。"""
    # 剥离 git 环境发现变量（与 .factory/mutations/run.py 同理：
    # 钩子环境导出的 GIT_DIR 会劫持 -C 目标）
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") or k in ("GIT_CONFIG_NOSYSTEM",)}
    proc = subprocess.run(
        ["git", "ls-files", "--", "src"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files 失败: {proc.stderr.strip()}")
    out = []
    for rel in proc.stdout.splitlines():
        p = rel.strip()
        if not p.endswith(".cs") or not p.startswith("src/"):
            continue
        parts = p.split("/")
        if "obj" in parts or "bin" in parts:  # 生成物（防御，正常不被跟踪）
            continue
        out.append(p)
    return sorted(out)


def _stats(res: dict, lines: list[str]) -> dict:
    """符号集 + 行 → 统计（run_gate 与自检共用同一条判定路径）。"""
    ext_t = ext_d = int_t = int_d = 0
    missing: list[str] = []
    for path, lineno, _kind, name in res["external"]:
        ext_t += 1
        if _has_doc(lines, lineno - 1):
            ext_d += 1
        else:
            missing.append(f"{path}:{lineno} {name}")
    for path, lineno, _kind, name in res["internal"]:
        int_t += 1
        if _has_doc(lines, lineno - 1):
            int_d += 1
        else:
            missing.append(f"{path}:{lineno} {name}")
    ext_ok = ext_t == ext_d  # 对外 100%
    int_ok = int_t == 0 or int_d / int_t >= INTERNAL_MIN  # 空集达标
    return {
        "external_total": ext_t, "external_documented": ext_d,
        "internal_total": int_t, "internal_documented": int_d,
        "missing": missing, "external_ok": ext_ok, "internal_ok": int_ok,
        "pass": ext_ok and int_ok,
    }


def run_gate() -> dict:
    """全量扫描（单遍）→ 统计 dict（含逐符号缺失清单与达标位）。"""
    ext_t = ext_d = int_t = int_d = 0
    missing: list[str] = []
    for rel in enumerate_files():
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        st = _stats(scan_text(rel, text), text.splitlines())
        ext_t += st["external_total"]
        ext_d += st["external_documented"]
        int_t += st["internal_total"]
        int_d += st["internal_documented"]
        missing.extend(st["missing"])
    ext_ok = ext_t == ext_d
    int_ok = int_t == 0 or int_d / int_t >= INTERNAL_MIN
    return {
        "external_total": ext_t, "external_documented": ext_d,
        "internal_total": int_t, "internal_documented": int_d,
        "missing": missing, "external_ok": ext_ok,
        "internal_ok": int_ok, "pass": ext_ok and int_ok,
    }


# ── 负控制（契约：--self-test，坏输入必须报缺）────────────────────────
GOOD = """namespace Demo;

/// <summary>类型。</summary>
public sealed class Foo
{
    /// <summary>方法。</summary>
    public int Bar(int x) => x;
}
"""

BAD_METHOD_DOC = """namespace Demo;

/// <summary>类型。</summary>
public sealed class Foo
{
    public int Bar(int x) => x;
}
"""

BAD_TYPE_DOC = """namespace Demo;

public sealed class Foo
{
    /// <summary>方法。</summary>
    public int Bar(int x) => x;
}
"""

BAD_BLANK_LINE = """namespace Demo;

/// <summary>类型。</summary>
public sealed class Foo
{
    /// <summary>方法。</summary>

    public int Bar(int x) => x;
}
"""

BAD_OVERRIDE = """namespace Demo;

/// <summary>类型。</summary>
public sealed class Foo
{
    public override string ToString() => "x";
}
"""

BAD_TUPLE_RETURN = """namespace Demo;

/// <summary>类型。</summary>
public static class Foo
{
    public static (int A, int B) Pair() => (1, 2);
}
"""

NOT_DECLARATIONS = """namespace Demo;

/// <summary>类型。</summary>
public sealed class Foo
{
    /// <summary>常量。</summary>
    public const int A = 1;

    /// <summary>属性。</summary>
    public int P { get; }

    /// <summary>表达式属性。</summary>
    public string Q => "x".Trim();

    /// <summary>字段。</summary>
    public static readonly int[] F = new int[3];

    /// <summary>构造。</summary>
    public Foo(int unused) => _ = unused;

    /// <summary>内部。</summary>
    private static int Helper(int x) => x;
}
"""


def run_stats_on(text: str) -> dict:
    """对单段文本跑完整统计（自检用；与 run_gate 同一判定路径）。"""
    return _stats(scan_text("<self-test>", text), text.splitlines())


def self_test() -> int:
    """负控制断言：任一失败 → exit 1（自检本身也要有牙齿）。"""
    failures: list[str] = []

    def expect(flag: bool, what: str) -> None:
        if not flag:
            failures.append(what)

    # 1) 好输入：对外 2/2 有 doc，内部 0 → 零缺失
    r = scan_text("good.cs", GOOD)
    expect(len(r["external"]) == 2 and len(r["internal"]) == 0,
           f"GOOD 符号计数 {r}")
    g = run_stats_on(GOOD)
    expect(g["external_documented"] == 2 and not g["missing"],
           f"GOOD 统计 {g}")

    # 2) 坏输入：必须报缺（负控制核心）
    for label, text, sym in (
        ("方法缺 doc", BAD_METHOD_DOC, "Bar"),
        ("类型缺 doc", BAD_TYPE_DOC, "Foo"),
        ("doc 与声明间空行", BAD_BLANK_LINE, "Bar"),
        ("override 不豁免", BAD_OVERRIDE, "ToString"),
        ("元组返回方法", BAD_TUPLE_RETURN, "Pair"),
    ):
        st = run_stats_on(text)
        expect(any(m.endswith(" " + sym) for m in st["missing"]),
               f"{label}: 未报缺 {sym}（missing={st['missing']}）")

    # 3) 非方法（常量/属性/字段/构造）不得计入 → 防误报
    r = scan_text("nd.cs", NOT_DECLARATIONS)
    names = [n for _, _, _, n in r["external"] + r["internal"]]
    expect("Foo" in names and "Helper" in names
           and not ({"Bar", "P", "Q", "A", "F"} & set(names)),
           f"非声明误报: {names}")

    # 4) 内部阈值边界：80% 达标 / 60% 不达标
    five = "".join(
        f"    {'/// <summary>d。</summary>' if i < 4 else ''}\n"
        f"    private static int M{i}() => {i};\n" for i in range(5)
    )
    st = run_stats_on("namespace D;\ninternal static class C\n{\n" + five + "}\n")
    expect(st["internal_documented"] == 4 and st["internal_total"] == 5
           and st["internal_ok"], f"内部 4/5 应达标: {st}")
    three = "".join(
        f"    {'/// <summary>d。</summary>' if i < 3 else ''}\n"
        f"    private static int M{i}() => {i};\n" for i in range(5)
    )
    st = run_stats_on("namespace D;\ninternal static class C\n{\n" + three + "}\n")
    expect(not st["internal_ok"], f"内部 3/5 应不达标: {st}")

    if failures:
        print("self-test FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("self-test OK（负控制：5 类坏输入均报缺，非声明零误报，阈值边界正确）")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="输出 JSON 统计")
    parser.add_argument("--self-test", action="store_true",
                        help="负控制测试（坏输入必须报缺）")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    try:
        stats = run_gate()
    except Exception as exc:  # fail-closed：检查器自身故障 → 非 0/1 退出码
        print(f"docstring gate error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    else:
        for m in stats["missing"]:
            print(m)
        print(f"对外 {stats['external_documented']}/{stats['external_total']}"
              f"（要求 100%）、内部 {stats['internal_documented']}"
              f"/{stats['internal_total']}"
              f"（要求 ≥{INTERNAL_MIN:.0%}，空集达标）"
              f"{'，达标' if stats['pass'] else '，未达标'}")
    return 0 if stats["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())

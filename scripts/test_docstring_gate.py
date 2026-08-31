"""docstring_gate.py 的 pytest 外部驱动测试（与 --self-test 内嵌负控制互补）。

覆盖面（目标：行+分支覆盖率 ≥95%）：
  符号判定   _match_method（可见性/元组返回/构造与属性排除/修饰词名）
  doc 判定   _has_doc（首行、空行隔离、普通上一行、缩进 ///）
  扫描归类   scan_text（顶层类型四种关键字、public/internal 方法、非口径行）
  阈值边界   _stats / run_gate（对外 100%、内部 80% 等值与不足、空内部集达标、跨文件聚合）
  扫描面     enumerate_files（真实 git 仓库、obj/bin 与非 .cs 过滤、GIT_* 剥离、git 失败、空结果）
  CLI        main（无参 0/1、--json、--self-test、fail-closed exit 2、错误参数 SystemExit）
"""
# spec:DG-1 对外 API 100% 红线 → 阈值与判定测试(见下方用例)
# spec:DG-2 内部 ≥80%(空内部集=达标) → 阈值边界测试
# spec:DG-3 docstring 归属判定(注释形态/空行/组注释不覆盖) → 判定测试
# spec:DG-4 CLI 无参 exit 0/1 + 逐符号缺失清单 + 统计 → main/CLI 测试
# spec:DG-5 --self-test 负控制(先红后绿) → self_test 测试
# spec:DG-6 扫描面 = git ls-files 枚举(反作弊) → 扫描面测试
# spec:DG-7 factory-local.json docstring_gate_cmd 禁引号/反斜杠 → 上游 test_factory_lib.py TestDocstringGateWords
# spec:DG-8 defects.json D-xx gate=docstring 击杀 → mutations/defects.json D-01/D-02 PASS
# spec:DG-10 mutations judge 门域 0/1 → 上游 test_mutations_run.py TestDocstringGateJudge


from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import docstring_gate as gate  # noqa: E402


def _scrubbed_env() -> dict:
    """与 enumerate_files 同口径的干净环境（供测试自身的 git 调用）。"""
    return {
        k: v for k, v in os.environ.items()
        if not k.startswith("GIT_") or k == "GIT_CONFIG_NOSYSTEM"
    }


class _FakeProc:
    """subprocess.run 的替身：可控 stdout/stderr/returncode，并捕获调用参数。"""

    def __init__(self, *, stdout: str = "", returncode: int = 0,
                 stderr: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _pass_stats() -> dict:
    return {
        "external_total": 2, "external_documented": 2,
        "internal_total": 1, "internal_documented": 1,
        "missing": [], "external_ok": True, "internal_ok": True,
        "pass": True,
    }


# ── _match_method：符号判定 ───────────────────────────────────────────


class TestMatchMethod:

    def test_public_variants(self):
        assert gate._match_method("    public void Send()") == ("public", "Send")
        assert gate._match_method(
            "    public async Task<int> M()") == ("public", "M")
        assert gate._match_method(
            "    public override string ToString()") == ("public", "ToString")
        assert gate._match_method(
            "    public T Get<T>(string key)") == ("public", "Get")
        # 元组返回：返回类型含括号/逗号，名称仍正确切出
        assert gate._match_method(
            "    public (int A, int B) Pair()") == ("public", "Pair")

    def test_internal_variants(self):
        assert gate._match_method(
            "    private static void P()") == ("internal", "P")
        assert gate._match_method("    internal bool Q()") == ("internal", "Q")
        assert gate._match_method("    protected void R()") == ("internal", "R")
        assert gate._match_method(
            "    protected internal void S()") == ("internal", "S")

    def test_no_visibility_modifier_out_of_scope(self):
        # 无 public/internal/private/protected 修饰 → 不在契约口径
        assert gate._match_method("    static void Foo()") is None

    def test_name_is_modifier_word(self):
        # "… = new(" 回溯落到名称位 "new"（本身是修饰词）→ None
        assert gate._match_method(
            "    private SemaphoreSlim _lock = new(") is None

    def test_prefix_has_assignment_or_body_marker(self):
        # '(' 之前的前缀混入 '=' / '{' → 非方法声明
        assert gate._match_method("    public int A = B(") is None
        assert gate._match_method("    public int A { B(") is None

    def test_not_a_declaration(self):
        assert gate._match_method("    public Foo()") is None  # 构造：无返回类型位
        assert gate._match_method("    void Foo()") is None    # 无修饰词
        assert gate._match_method("    int x = 1;") is None    # 局部语句
        assert gate._match_method("    public int P { get; }") is None  # 属性
        assert gate._match_method("    // public void M()") is None     # 注释


# ── _has_doc：docstring 归属判定 ──────────────────────────────────────


class TestHasDoc:

    def test_first_line_never_documented(self):
        assert gate._has_doc(["public class F"], 0) is False

    def test_blank_line_breaks_doc(self):
        lines = ["/// <summary>d。</summary>", "", "    public void M()"]
        assert gate._has_doc(lines, 2) is False

    def test_adjacent_doc(self):
        lines = ["    /// <summary>d。</summary>", "    public void M()"]
        assert gate._has_doc(lines, 1) is True

    def test_plain_previous_line(self):
        lines = ["    int x = 1;", "    public void M()"]
        assert gate._has_doc(lines, 1) is False


# ── scan_text：归类与行号 ─────────────────────────────────────────────


class TestScanText:

    TEXT = "\n".join([
        "namespace Demo;",
        "",
        "/// <summary>T。</summary>",
        "public sealed class Foo",
        "{",
        "    /// <summary>M。</summary>",
        "    public async Task<int> M()",
        "    {",
        "        int x = 1;",
        "    }",
        "",
        "    private static void P()",
        "    {",
        "    }",
        "}",
    ]) + "\n"

    def test_classification_and_line_numbers(self):
        r = gate.scan_text("t.cs", self.TEXT)
        assert r["external"] == [
            ("t.cs", 4, "type", "Foo"),
            ("t.cs", 7, "method", "M"),
        ]
        assert r["internal"] == [("t.cs", 12, "method", "P")]

    def test_type_keyword_variants(self):
        for line, name in [
            ("public interface IFoo", "IFoo"),
            ("public record R", "R"),
            ("public struct S", "S"),
            ("public sealed partial class C<T>", "C"),
            ("public static class Holder", "Holder"),
        ]:
            r = gate.scan_text("v.cs", line + "\n")
            assert r["external"] == [("v.cs", 1, "type", name)], line
            assert r["internal"] == []

    def test_out_of_scope_declarations_ignored(self):
        text = "\n".join([
            "internal class Hidden",       # 非对外类型
            "public enum Color { Red }",   # enum 不在契约口径
            "    public class Nested",     # 嵌套（缩进）类型不算顶层
            "public abstract class Doc",   # 对外类型（对照：应命中）
        ])
        r = gate.scan_text("o.cs", text)
        assert r["external"] == [("o.cs", 4, "type", "Doc")]
        assert r["internal"] == []

    def test_empty_text(self):
        assert gate.scan_text("e.cs", "") == {"external": [], "internal": []}


# ── enumerate_files：扫描面（git ls-files 集成 + 过滤 + fail-closed） ──


class TestEnumerateFiles:

    def test_filter_rules_and_sorting(self, monkeypatch):
        paths = "\n".join([
            "src/B.cs",            # 命中
            "src/sub/A.cs",        # 命中（排序后在前）
            "src/obj/G.cs",        # 生成物目录
            "src/bin/H.cs",        # 生成物目录
            "src/x/obj/I.cs",      # 任意层级 obj
            "tests/T.cs",          # 非 src/ 前缀
            "docs/note.cs",        # 非 src/ 前缀
            "src/readme.txt",      # 非 .cs
        ]) + "\n"
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            return _FakeProc(stdout=paths)

        monkeypatch.setattr(gate.subprocess, "run", fake_run)
        # ASCII 序：'B' < 's'，故 src/B.cs 排在 src/sub/ 前
        assert gate.enumerate_files() == ["src/B.cs", "src/sub/A.cs"]
        # 调用形态：反作弊只认 git 跟踪文件
        assert captured["cwd"] == str(gate.REPO_ROOT)

    def test_git_env_scrubbed(self, monkeypatch):
        monkeypatch.setenv("GIT_DIR", "/hijack")
        monkeypatch.setenv("GIT_INDEX_FILE", "/hijack")
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            return _FakeProc(stdout="src/A.cs\n")

        monkeypatch.setattr(gate.subprocess, "run", fake_run)
        assert gate.enumerate_files() == ["src/A.cs"]
        env = captured["env"]
        assert "GIT_DIR" not in env and "GIT_INDEX_FILE" not in env
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"  # 白名单保留

    def test_git_failure_raises(self, monkeypatch):
        monkeypatch.setattr(
            gate.subprocess, "run",
            lambda cmd, **kw: _FakeProc(returncode=128, stderr="fatal: not a repo"))
        with pytest.raises(RuntimeError, match="git ls-files 失败"):
            gate.enumerate_files()

    def test_empty_result(self, monkeypatch):
        monkeypatch.setattr(
            gate.subprocess, "run", lambda cmd, **kw: _FakeProc(stdout=""))
        assert gate.enumerate_files() == []

    def test_real_git_repo_tracks_only_staged(self, monkeypatch, tmp_path):
        # 真实 git 集成：仅 git 跟踪（已 add）的 src/**/*.cs 进入扫描面；
        # 同时验证 GIT_* 剥离真的能防住钩子环境劫持。
        for rel in ("src/A.cs", "src/Nested/B.cs", "src/obj/G.cs",
                    "src/untracked.cs"):
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("// x\n", encoding="utf-8")
        env = _scrubbed_env()
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, env=env, check=True)
        subprocess.run(["git", "add", "src/A.cs", "src/Nested/B.cs",
                        "src/obj/G.cs"], cwd=tmp_path, env=env, check=True)
        monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
        monkeypatch.setenv("GIT_DIR", "/nonexistent-hijack")
        monkeypatch.setenv("GIT_WORK_TREE", "/nonexistent-hijack")
        assert gate.enumerate_files() == ["src/A.cs", "src/Nested/B.cs"]


# ── _stats / run_gate / run_stats_on：阈值边界与聚合 ──────────────────


class TestStats:

    def test_empty_sets_pass(self):
        st = gate._stats({"external": [], "internal": []}, [])
        assert st == {
            "external_total": 0, "external_documented": 0,
            "internal_total": 0, "internal_documented": 0,
            "missing": [], "external_ok": True, "internal_ok": True,
            "pass": True,
        }

    @staticmethod
    def _build(doc_flags, path="i.cs"):
        """逐符号叠放「doc 行 + 声明行」→ (res, lines, 期望缺失清单)。

        声明行号 = 追加后的 len(lines)（1 基），doc 判定只看正上一行。
        """
        lines = ["namespace D;"]
        entries, missing = [], []
        for i, documented in enumerate(doc_flags):
            if documented:
                lines.append("/// d")
            lines.append(f"    void M{i}()")
            entries.append((path, len(lines), "method", f"M{i}"))
            if not documented:
                missing.append(f"{path}:{len(lines)} M{i}")
        return {"external": [], "internal": entries}, lines, missing

    def test_external_requires_100_percent(self):
        res, lines, missing = self._build([True, False], path="a.cs")
        st = gate._stats({"external": res["internal"], "internal": []}, lines)
        assert (st["external_total"], st["external_documented"]) == (2, 1)
        assert st["missing"] == missing
        assert st["external_ok"] is False and st["pass"] is False

    def test_internal_boundary_exactly_80_percent(self):
        # 4/5 = 80% 与 INTERNAL_MIN 等值 → 达标（边界含等号）
        res, lines, missing = self._build([True] * 4 + [False])
        st = gate._stats(res, lines)
        assert (st["internal_total"], st["internal_documented"]) == (5, 4)
        assert st["missing"] == missing
        assert st["internal_ok"] is True and st["pass"] is True

    def test_internal_below_threshold(self):
        # 3/5 = 60% < 80% → 不达标，缺失逐符号列出
        res, lines, missing = self._build([True] * 3 + [False] * 2)
        st = gate._stats(res, lines)
        assert st["internal_ok"] is False and st["pass"] is False
        assert st["missing"] == missing

    def test_internal_empty_set_is_ok_even_if_external_missing(self):
        # 空内部集达标，但对外缺一个 → 整体仍不达标
        res = {"external": [("a.cs", 1, "type", "A")], "internal": []}
        st = gate._stats(res, ["public class A"])  # 首行必缺 doc
        assert st["internal_ok"] is True
        assert st["external_ok"] is False and st["pass"] is False


class TestRunGate:

    def _write(self, tmp_path, rel, content):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def test_aggregates_across_files(self, monkeypatch, tmp_path):
        self._write(tmp_path, "src/A.cs", "\n".join([
            "/// <summary>T。</summary>",
            "public class A",
            "{",
            "    /// <summary>M。</summary>",
            "    public void M()",
            "    {",
            "    }",
            "",
            "    public void N()",
            "    {",
            "    }",
            "}",
        ]) + "\n")
        self._write(tmp_path, "src/B.cs", "\n".join([
            "/// <summary>B。</summary>",
            "public class B",
            "{",
            "    /// <summary>p。</summary>",
            "    private void P()",
            "    {",
            "    }",
            "",
            "    private void Q()",
            "    {",
            "    }",
            "}",
        ]) + "\n")
        monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(gate, "enumerate_files",
                            lambda: ["src/A.cs", "src/B.cs"])
        st = gate.run_gate()
        # 对外：A(type+M 有、N 缺) + B(type 有) → 3/4
        # 内部：B 的 P 有、Q 缺 → 1/2（<80%）
        assert (st["external_total"], st["external_documented"]) == (4, 3)
        assert (st["internal_total"], st["internal_documented"]) == (2, 1)
        assert st["missing"] == ["src/A.cs:9 N", "src/B.cs:9 Q"]
        assert st["pass"] is False

    def test_all_documented_passes(self, monkeypatch, tmp_path):
        self._write(tmp_path, "src/Good.cs", gate.GOOD)
        monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(gate, "enumerate_files", lambda: ["src/Good.cs"])
        st = gate.run_gate()
        assert st["pass"] is True and st["missing"] == []

    def test_exception_propagates(self, monkeypatch):
        def boom():
            raise RuntimeError("git ls-files 失败: boom")

        monkeypatch.setattr(gate, "enumerate_files", boom)
        with pytest.raises(RuntimeError, match="boom"):
            gate.run_gate()


class TestRunStatsOn:

    def test_missing_uses_self_test_label(self):
        st = gate.run_stats_on("namespace Demo;\n\npublic class Foo\n{\n}\n")
        assert st["external_total"] == 1 and st["external_documented"] == 0
        assert st["missing"] == ["<self-test>:3 Foo"]
        assert st["pass"] is False

    def test_good_sample_passes(self):
        st = gate.run_stats_on(gate.GOOD)
        assert st["pass"] is True and st["missing"] == []


# ── self_test / main：CLI 与 fail-closed ─────────────────────────────


class TestSelfTest:

    def test_self_test_ok(self, capsys):
        assert gate.self_test() == 0
        assert "self-test OK" in capsys.readouterr().out

    def test_self_test_fails_closed_when_scanner_broken(self, monkeypatch,
                                                        capsys):
        # 检查器被破坏（扫不出符号）→ 自检必须有牙齿：exit 1 + stderr 清单
        monkeypatch.setattr(
            gate, "scan_text",
            lambda path, text: {"external": [], "internal": []})
        assert gate.self_test() == 1
        err = capsys.readouterr().err
        assert "self-test FAIL" in err and "GOOD 符号计数" in err


class TestMain:

    def test_self_test_flag(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--self-test"])
        assert gate.main() == 0
        assert "self-test OK" in capsys.readouterr().out

    def test_no_args_pass_exit_0(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])
        monkeypatch.setattr(gate, "run_gate", _pass_stats)
        assert gate.main() == 0
        out = capsys.readouterr().out
        assert "对外 2/2" in out and "内部 1/1" in out and "达标" in out

    def test_no_args_fail_exit_1(self, monkeypatch, capsys):
        stats = _pass_stats()
        stats.update({
            "external_total": 3, "external_documented": 2,
            "missing": ["src/A.cs:9 N"], "external_ok": False,
            "pass": False,
        })
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])
        monkeypatch.setattr(gate, "run_gate", lambda: stats)
        assert gate.main() == 1
        out = capsys.readouterr().out
        assert "src/A.cs:9 N" in out and "未达标" in out

    def test_json_output(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--json"])
        monkeypatch.setattr(gate, "run_gate", _pass_stats)
        assert gate.main() == 0
        assert json.loads(capsys.readouterr().out) == _pass_stats()

    def test_fail_closed_exit_2_on_gate_error(self, monkeypatch, capsys):
        def boom():
            raise RuntimeError("git ls-files 失败: fatal")

        monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])
        monkeypatch.setattr(gate, "run_gate", boom)
        assert gate.main() == 2
        err = capsys.readouterr().err
        assert "docstring gate error" in err and "fatal" in err

    def test_unknown_argument_exits_2(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--bogus"])
        with pytest.raises(SystemExit) as exc:
            gate.main()
        assert exc.value.code == 2
        assert "usage" in capsys.readouterr().err.lower()

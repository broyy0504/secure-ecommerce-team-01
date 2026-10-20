#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安全设计文档一致性检查。

把第 6-9 周阶段一的验收口径变成可执行检查：
  1. 安全需求编号从 SR-01 起连续、唯一
  2. 每条 SR 都有可判定的「怎样算通过」，且指到至少一个威胁编号
  3. 威胁登记表里的每条威胁都被至少一条 SR 覆盖
  4. 覆盖矩阵与各 SR 的「源威胁」列完全一致（防止改一处漏一处）
  5. 每个接口四要素齐备：输入约束 / 输出 / 错误码 / 鉴权
  6. 错误码只出现在封闭集内
  7. 整改编号 R-D-xx 连续、且能被 SR 的「落实位置」引用到
  8. 数据流图中的连线编号与跨边界控制表逐一对应

用法：
    python test/check_design_docs.py [仓库根目录]

退出码 0 表示全部通过，1 表示有检查未通过。
"""

from __future__ import annotations

import os
import re
import sys

DESIGN_DIR = os.path.join("docs", "design")

# 判定「怎样算通过」时必须出现的关键词之一：没有这些，说明只写了目标没写判据
PASS_CRITERIA_KEYWORDS = (
    "判定", "返回", "响应", "命中", "一致", "不存在", "非空", "不相等", "为 0",
)

REQUIRED_INTERFACE_ROWS = ("输入约束", "输出", "错误码", "鉴权")

# 允许出现的大写下划线标识，除封闭错误码外的枚举值
REASON_ENUMS = {
    "REQUIRED", "TYPE_MISMATCH", "TOO_SHORT", "TOO_LONG",
    "FORMAT_INVALID", "OUT_OF_RANGE", "NOT_ALLOWED", "DUPLICATE",
}

CODE_TOKEN_RE = re.compile(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((bool(ok), name, detail))


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def split_row(line: str) -> list[str]:
    """把 markdown 表格行拆成单元格。"""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def heading_section(text: str, heading_prefix: str) -> str:
    """取出以 heading_prefix 开头的那一节（到下一个同级或更高级标题为止），返回正文文本。"""
    lines = text.splitlines()
    out: list[str] = []
    level = heading_prefix.split(" ")[0]
    inside = False
    for ln in lines:
        if ln.startswith(heading_prefix):
            inside = True
            continue
        if inside:
            if ln.startswith("#") and ln.startswith(level + " ") and not ln.startswith(level + "#"):
                # 同级或更高级标题，结束
                if len(ln) - len(ln.lstrip("#")) <= len(level):
                    break
            if ln.startswith("## ") or ln.startswith("# "):
                break
            out.append(ln)
    return "\n".join(out)


def rows_starting_with(block: str, prefix: str) -> list[list[str]]:
    rows = []
    for ln in block.splitlines():
        if ln.strip().startswith("| " + prefix) or ln.strip().startswith("|" + prefix):
            rows.append(split_row(ln))
    return rows


def normalize_ids(cell: str) -> set[str]:
    found = re.findall(r"(?:SR-\d{2}|T-[A-Z]{2}-\d{2}|R-D-\d{2})", cell)
    return set(found)


def main(argv: list[str]) -> int:
    root = argv[1] if len(argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    design = os.path.join(root, DESIGN_DIR)

    paths = {
        "01": os.path.join(design, "01-数据流与信任边界.md"),
        "02": os.path.join(design, "02-安全需求.md"),
        "03": os.path.join(design, "03-接口契约.md"),
        "04": os.path.join(design, "04-控制指认与整改输入.md"),
    }
    for key, p in paths.items():
        if not os.path.isfile(p):
            print(f"[缺失] {p}")
            return 1

    t1, t2, t3, t4 = (read_text(paths[k]) for k in ("01", "02", "03", "04"))

    # ---------------- 1. 威胁登记表 ----------------
    sec2 = heading_section(t2, "## 2.")
    threat_rows = [r for r in rows_starting_with(sec2, "T-") if len(r) >= 8]
    threats = [r[0] for r in threat_rows]
    check(len(threats) >= 10,
          "威胁登记表条目数",
          f"{len(threats)} 条（要求 ≥10，用于支撑 SR 的威胁指认）")
    check(len(set(threats)) == len(threats),
          "威胁编号唯一",
          f"重复：{sorted({x for x in threats if threats.count(x) > 1})}" or "无重复")

    # 每条威胁必须写清谁 / 动作 / 位置 / 触发者
    for r in threat_rows:
        tid = r[0]
        blanks = [i for i, c in enumerate(r[1:], start=1) if not c.strip()]
        check(not blanks, f"威胁 {tid} 字段齐全", f"空列序号 {blanks}" if blanks else "8 列均非空")

    # ---------------- 2. 安全需求 ----------------
    sec3 = heading_section(t2, "## 3.")
    sr_rows = [r for r in rows_starting_with(sec3, "SR-") if len(r) >= 5]
    sr_ids = [r[0] for r in sr_rows]

    expected = [f"SR-{i:02d}" for i in range(1, len(sr_ids) + 1)]
    check(sr_ids == expected,
          "安全需求编号从 SR-01 起连续",
          f"实际 {len(sr_ids)} 条，末尾 {sr_ids[-1] if sr_ids else '-'}")

    sr_threats: dict[str, set[str]] = {}
    for r in sr_rows:
        sid, need, criteria, src, where = r[0], r[1], r[2], r[3], r[4]

        check(len(need) >= 20, f"{sid} 需求陈述非空且具体", f"{len(need)} 字")
        has_marker = "①" in criteria or "1）" in criteria or "1." in criteria
        has_keyword = any(k in criteria for k in PASS_CRITERIA_KEYWORDS)
        check(len(criteria) >= 60 and has_marker and has_keyword,
              f"{sid} 写清怎样算通过",
              f"长度 {len(criteria)}，分步标记 {has_marker}，判定词 {has_keyword}")

        refd = normalize_ids(src)
        check(bool(refd), f"{sid} 指到威胁编号", f"{sorted(refd) or '无'}")
        unknown = refd - set(threats)
        check(not unknown, f"{sid} 威胁编号均已登记", f"未登记：{sorted(unknown)}" if unknown else "已登记")

        has_where = bool(re.search(r"R-D-\d{2}|src/|docs/", where))
        check(has_where, f"{sid} 标注落实位置", where[:60])

        sr_threats[sid] = refd

    # ---------------- 3. 威胁覆盖 ----------------
    covered: dict[str, set[str]] = {t: set() for t in threats}
    for sid, refd in sr_threats.items():
        for t in refd:
            if t in covered:
                covered[t].add(sid)
    uncovered = [t for t, s in covered.items() if not s]
    check(not uncovered,
          "每条已登记威胁至少被一条 SR 覆盖",
          f"未覆盖：{uncovered}" if uncovered else f"{len(threats)} 条全部覆盖")

    # ---------------- 4. 覆盖矩阵与 SR 表一致 ----------------
    sec4 = heading_section(t2, "## 4.")
    matrix_rows = [r for r in rows_starting_with(sec4, "T-") if len(r) >= 3]
    matrix: dict[str, set[str]] = {}
    for r in matrix_rows:
        matrix[r[0]] = normalize_ids(r[1])
    check(set(matrix) == set(threats),
          "覆盖矩阵威胁集合与登记表一致",
          f"矩阵 {len(matrix)} 条 / 登记 {len(threats)} 条")

    drift = []
    for tid in threats:
        want = covered.get(tid, set())
        got = matrix.get(tid, set())
        if want != got:
            drift.append(f"{tid}: SR表={sorted(want)} 矩阵={sorted(got)}")
    check(not drift,
          "覆盖矩阵与各 SR 的源威胁列一致",
          "；".join(drift) if drift else "逐条一致")

    # ---------------- 5. 接口四要素 ----------------
    api_heads = re.findall(r"^### (4\.\d+ API-[A-Z]+-\d+)", t3, flags=re.M)
    check(len(api_heads) >= 3, "接口契约数量", f"{len(api_heads)} 个：{api_heads}")

    parts = re.split(r"^### 4\.\d+ API-", t3, flags=re.M)
    api_names = ["API-" + h.split("API-")[-1] for h in api_heads]
    for name, body in zip(api_names, parts[1:]):
        for row in REQUIRED_INTERFACE_ROWS:
            present = bool(re.search(r"\|\s*\*\*" + row + r"\*\*\s*\|", body))
            check(present, f"{name} 具备「{row}」", "" if present else "表格缺该行")

    # 鉴权矩阵与接口清单对应
    sec3_3 = heading_section(t3, "## 3.")
    matrix_paths = set(re.findall(r"`(?:GET|POST|PUT|DELETE) (/api/[^`]+)`", sec3_3))
    detail_paths = set(re.findall(r"^`?(?:GET|POST|PUT|DELETE) (/api/[^\s`]+)`?$", t3, flags=re.M))
    missing_in_detail = matrix_paths - detail_paths
    check(not missing_in_detail,
          "鉴权矩阵中的路径都在接口详情中出现",
          f"缺：{sorted(missing_in_detail)}" if missing_in_detail else f"{len(matrix_paths)} 条路径均有详情")

    # ---------------- 6. 错误码封闭集 ----------------
    sec2_3 = heading_section(t3, "## 2.")
    closed = {r[0].strip("` ") for r in rows_starting_with(sec2_3, "`") if len(r) >= 2}
    check(len(closed) >= 8, "错误码封闭集规模", f"{len(closed)} 个")

    used = set(CODE_TOKEN_RE.findall(t3))
    allowed = closed | REASON_ENUMS
    stray = used - allowed
    check(not stray, "错误码只出现在封闭集或既定枚举内", f"越界：{sorted(stray)}" if stray else f"引用 {len(used)} 个，全部在集合内")

    # 每个接口声明的错误码都必须属于封闭集
    bad_iface = []
    for name, body in zip(api_names, parts[1:]):
        m = re.search(r"\|\s*\*\*错误码\*\*\s*\|(.+)", body)
        if not m:
            continue
        for code in CODE_TOKEN_RE.findall(m.group(1)):
            if code not in closed:
                bad_iface.append(f"{name}:{code}")
    check(not bad_iface, "各接口错误码均在封闭集内", f"越界：{bad_iface}" if bad_iface else "全部合规")

    # ---------------- 7. 整改编号 ----------------
    sec3_4 = heading_section(t4, "## 3.")
    rd_rows = [r for r in rows_starting_with(sec3_4, "R-D-") if len(r) >= 6]
    rd_ids = [r[0] for r in rd_rows]
    check(rd_ids == [f"R-D-{i:02d}" for i in range(1, len(rd_ids) + 1)],
          "整改编号连续", f"{len(rd_ids)} 条")

    referenced = set()
    for doc in (t1, t2, t3, t4):
        referenced |= set(re.findall(r"R-D-\d{2}", doc))
    dangling = referenced - set(rd_ids)
    check(not dangling, "SR 引用的整改编号都已定义", f"悬空：{sorted(dangling)}" if dangling else "无悬空引用")

    unused = set(rd_ids) - referenced
    check(not unused, "每条整改都被文档引用", f"未被引用：{sorted(unused)}" if unused else f"{len(rd_ids)} 条均被引用")

    # ---------------- 8. 连线编号与表格对应 ----------------
    diagram_ids: set[str] = set()
    for block in re.findall(r"```mermaid\n(.*?)```", t1, flags=re.S):
        diagram_ids |= set(re.findall(r"E-[RLO]\d+", block))
    table_ids = set(re.findall(r"^\|\s*(E-[RLO]\d+)\s*\|", t1, flags=re.M))

    check(bool(diagram_ids), "数据流图中存在连线编号", f"{len(diagram_ids)} 条")
    only_diagram = diagram_ids - table_ids
    only_table = table_ids - diagram_ids
    check(not only_diagram and not only_table,
          "连线编号在图中与控制表中一一对应",
          f"仅图：{sorted(only_diagram)}；仅表：{sorted(only_table)}"
          if (only_diagram or only_table) else f"{len(diagram_ids)} 条全部对应")

    # 每条连线必须注明控制与对应 SR
    edge_rows = [r for r in rows_starting_with(t1, "E-") if len(r) >= 6]
    for r in edge_rows:
        eid = r[0]
        check(bool(r[4].strip()) and bool(r[5].strip()),
              f"{eid} 同时标注控制与安全需求",
              f"控制={r[4][:24]!r} 需求={r[5][:24]!r}")

    # ---------------- 汇总 ----------------
    failed = [r for r in results if not r[0]]
    print("=" * 78)
    print("安全设计文档一致性检查")
    print(f"目标目录: {design}")
    print("=" * 78)
    for ok, name, detail in results:
        flag = "PASS" if ok else "FAIL"
        line = f"[{flag}] {name}"
        if detail and not ok:
            line += f"  ->  {detail}"
        print(line)

    print("-" * 78)
    print(f"合计 {len(results)} 项，通过 {len(results) - len(failed)} 项，失败 {len(failed)} 项")
    if failed:
        print("\n未通过项：")
        for _, name, detail in failed:
            print(f"  - {name}  {detail}")
        return 1
    print("全部通过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

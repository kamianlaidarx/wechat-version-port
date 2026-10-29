#!/usr/bin/env python3
"""把「旧 RVA → 新 RVA」映射对生成 C++ switch 骨架 + Python 测试期望表。

避免手抄地址出错——这是版本迁移里最常见的事故来源。

输入 pairs.json：
{
  "text":    {"0x2fb010": "0x311990", "0x6f4c70": "0x71c4e0"},
  "moments": {"0x44776d0": "0x4538550"}
}

输出：
  core_rva_switch.txt   贴进 native/core_version.h
  test_expected.py      贴进 tests/test_native_version_bridge.py

用法：
    py -3.13 gen_switch.py --in pairs.json --profile-id 3 --out-dir .
    py -3.13 gen_switch.py --in pairs.json --profile-id 3 --out-dir . --check
"""
import argparse
import json
import pathlib
import sys


def load_pairs(path):
    raw = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

    # 兼容两种结构：{"text": {...}, "moments": {...}} 或扁平 {"0x..": "0x.."}
    if all(isinstance(v, dict) for v in raw.values()):
        tables = raw
    else:
        tables = {"text": raw}

    out = {}
    for name, mapping in tables.items():
        normalized = {}
        for old, new in mapping.items():
            o = int(old, 16) if isinstance(old, str) else int(old)
            n = int(new, 16) if isinstance(new, str) else int(new)
            normalized[o] = n
        # 查重复 case
        dupes = [k for k in normalized if list(normalized).count(k) > 1]
        if dupes:
            raise SystemExit(f"[{name}] 重复的 case 值: {dupes}")
        out[name] = dict(sorted(normalized.items()))
    return out


def gen_cpp(tables, profile_id):
    lines = []
    for name, mapping in tables.items():
        if name == "moments":
            fn = "core_moments_address"
            comment = "朋友圈地址体系独立，单独一张表"
        else:
            fn = "core_rva"
            comment = "文本 / 媒体 / 群缓存地址"

        lines.append(f"// {fn}() 的 profile {profile_id} 分支 —— {comment}")
        lines.append(f"// 共 {len(mapping)} 条，未列出的 legacy 地址一律返回 0（拒绝执行）")
        lines.append(f"if (profile->id == {profile_id}) {{")
        lines.append("    switch (legacy) {")
        for old, new in mapping.items():
            lines.append(f"        case 0x{old:x}:  return 0x{new:x};")
        lines.append("        default: return 0;   // 未验证，拒绝")
        lines.append("    }")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def gen_python(tables, version_tag, original_names):
    lines = [
        f'# 由 gen_switch.py 生成，贴进 tests/test_native_version_bridge.py',
        f'# 对应微信版本 {version_tag}',
        '',
    ]
    for name, mapping in tables.items():
        var = original_names.get(name, f"VERIFIED_{name.upper()}")
        lines.append(f"{var} = {{")
        items = [f"    0x{o:x}: 0x{n:x}," for o, n in mapping.items()]
        # 每 4 条一行，便于 diff
        for i in range(0, len(items), 4):
            lines.append("    " + " ".join(x.strip() for x in items[i : i + 4]))
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def gen_checker(tables, profile_id, prefix="VERIFIED"):
    """生成一个可独立运行的校验片段，每个地址表一个变量。"""
    parts = [
        f"# profile {profile_id} 的映射期望值 + 校验函数",
        "import re",
        "",
    ]
    for name, mapping in tables.items():
        if name == "text":
            var = f"{prefix}_RVAS"
        elif name == "moments":
            var = f"{prefix}_MOMENTS"
        else:
            var = f"{prefix}_{name.upper()}"
        items = "\n".join(f"    0x{o:x}: 0x{n:x}," for o, n in mapping.items())
        parts.append(f"{var} = {{\n{items}\n}}")
        parts.append("")

    parts.extend([
        "def assert_mapping(block_text, expected):",
        '    rows = re.findall(r"case\\s+(0x[0-9a-f]+):\\s*return\\s+(0x[0-9a-f]+);", block_text)',
        "    got = {int(o, 16): int(n, 16) for o, n in rows}",
        '    assert len(rows) == len(expected), f"条数不符：代码 {len(rows)} vs 期望 {len(expected)}"',
        '    assert len(got) == len(rows), "存在重复 case"',
        '    assert got == expected, "映射值不符"',
        "",
    ])
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser(description="生成 switch + 测试表")
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--profile-id", type=int, required=True)
    ap.add_argument("--version", default="?", help="版本号，写进注释")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--prefix", default="VERIFIED", help="Python 变量名前缀")
    ap.add_argument("--check", action="store_true", help="只打印统计，不写文件")
    args = ap.parse_args()

    tables = load_pairs(args.infile)

    original_names = {}
    for name in tables:
        if name == "text":
            original_names[name] = f"{args.prefix}_RVAS"
        elif name == "moments":
            original_names[name] = f"{args.prefix}_MOMENTS"
        else:
            original_names[name] = f"{args.prefix}_{name.upper()}"

    summary = {name: len(m) for name, m in tables.items()}
    print(f"profile id = {args.profile_id}, 版本 = {args.version}")
    for name, cnt in summary.items():
        print(f"  {name:10s} {cnt:4d} 条  → {original_names[name]}")
    print(f"  合计       {sum(summary.values()):4d} 条")

    if args.check:
        return 0

    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    cpp_path = out / "core_rva_switch.txt"
    cpp_path.write_text(gen_cpp(tables, args.profile_id), encoding="utf-8")

    py_path = out / "test_expected.py"
    py_path.write_text(gen_python(tables, args.version, original_names), encoding="utf-8")

    chk_path = out / "test_expected_assert.py"
    chk_path.write_text(gen_checker(tables, args.profile_id, args.prefix), encoding="utf-8")

    print()
    print(f"已写出：")
    print(f"  {cpp_path}      → 贴进 native/core_version.h")
    print(f"  {py_path}       → 贴进 tests/test_native_version_bridge.py")
    print(f"  {chk_path}      → 校验函数模板")
    return 0


if __name__ == "__main__":
    sys.exit(main())

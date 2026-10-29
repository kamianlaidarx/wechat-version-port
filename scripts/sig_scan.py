#!/usr/bin/env python3
"""在新版 DLL 里扫特征码，返回所有命中位置及对应 RVA。

判据：命中数必须恰好为 1。0 表示特征被优化掉，>1 表示特征太短。

用法：
    py -3.13 sig_scan.py --dll new.dll --pattern "48 89 5C 24 08 55 56 57 41 54"
    py -3.13 sig_scan.py --dll new.dll --pattern-file sigs.txt   # 每行 "名字: 特征"
    py -3.13 sig_scan.py --dll new.dll --pattern "..." --section .text   # 只搜代码段
"""
import argparse
import json
import re
import sys

try:
    import pefile
except ImportError:
    raise SystemExit("缺 pefile：py -3.13 -m pip install pefile")


def compile_pattern(text):
    """把 '48 89 ?? E8 ?? ?? ?? ??' 编译成正则字节串。"""
    parts = text.replace(",", " ").split()
    if not parts:
        raise SystemExit("空特征")
    chunks = []
    for part in parts:
        if part in ("??", "?", "**"):
            chunks.append(b".")
        else:
            if len(part) == 1:
                part = "0" + part
            chunks.append(re.escape(bytes([int(part, 16)])))
    return re.compile(b"".join(chunks), re.DOTALL)


def scan_region(data, regex, base_offset=0):
    return [base_offset + m.start() for m in regex.finditer(data)]


def offset_to_rva(pe, offset):
    try:
        return pe.get_rva_from_offset(offset)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="扫特征码")
    ap.add_argument("--dll", required=True)
    ap.add_argument("--pattern")
    ap.add_argument("--pattern-file")
    ap.add_argument("--section", help="只搜指定节，如 .text")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    pe = pefile.PE(args.dll, fast_load=True)

    # 收集待搜区域
    regions = []  # (name, data, file_offset)
    if args.section:
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\0").decode("latin-1", "replace")
            if name == args.section:
                regions.append((name, sec.get_data(), sec.get_PointerToRawData_adj()))
        if not regions:
            raise SystemExit(f"找不到节 {args.section}，现有：" +
                             ", ".join(s.Name.rstrip(b'\0').decode('latin-1', 'replace') for s in pe.sections))
    else:
        raw = open(args.dll, "rb").read()
        regions.append(("(whole file)", raw, 0))

    # 收集待搜特征
    patterns = []
    if args.pattern:
        patterns.append(("<cli>", args.pattern))
    if args.pattern_file:
        for line in open(args.pattern_file, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if ":" in line:
                name, sig = line.split(":", 1)
                patterns.append((name.strip(), sig.strip()))
            else:
                patterns.append((f"<line>", line))
    if not patterns:
        raise SystemExit("需要 --pattern 或 --pattern-file")

    report = []
    for name, sig in patterns:
        regex = compile_pattern(sig)
        hits = []
        for region_name, data, base in regions:
            for off in scan_region(data, regex, base):
                rva = offset_to_rva(pe, off)
                hits.append(
                    {
                        "file_offset": f"0x{off:x}",
                        "rva": f"0x{rva:x}" if rva is not None else None,
                        "section": region_name,
                    }
                )
        verdict = (
            "OK 唯一命中" if len(hits) == 1
            else "MISS 未命中，特征被优化或版本差异过大" if not hits
            else f"AMBIGUOUS 命中 {len(hits)} 处，特征太短"
        )
        report.append({"name": name, "signature": sig, "hit_count": len(hits),
                       "verdict": verdict, "hits": hits})

        if not args.json:
            print(f"=== {name} ===")
            print(f"特征: {sig}")
            print(f"结果: {verdict}")
            for h in hits[:10]:
                print(f"  RVA {h['rva']}  offset {h['file_offset']}  [{h['section']}]")
            if len(hits) > 10:
                print(f"  ... 还有 {len(hits) - 10} 处")
            print()

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))

    bad = [r for r in report if r["hit_count"] != 1]
    if bad:
        print(f"⚠ {len(bad)} 个特征未达到唯一命中，需加长或换方法", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

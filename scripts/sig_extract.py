#!/usr/bin/env python3
"""从旧版 DLL 的已知 RVA 提取特征码，自动通配会随版本变化的字节。

通配规则：
    call/jmp rel32    → 后 4 字节变 ??
    call/jmp rel8     → 后 1 字节变 ??
    RIP 相对寻址      → 指令末尾 disp32 变 ??
    绝对地址立即数     → 由 --wild-imm 控制（默认保留，普通常量是有效特征）

依赖：
    py -3.13 -m pip install pefile capstone -i https://mirrors.cloud.tencent.com/pypi/simple

用法：
    py -3.13 sig_extract.py --dll old.dll --rva 0x2fb010 --len 48
    py -3.13 sig_extract.py --dll old.dll --rva 0x2fb010 --len 64 --json
    py -3.13 sig_extract.py --dll old.dll --batch pairs.txt   # 每行一个 RVA
"""
import argparse
import json
import sys

try:
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
except ImportError as exc:
    raise SystemExit(
        f"缺依赖：{exc}\n装：py -3.13 -m pip install pefile capstone "
        f"-i https://mirrors.cloud.tencent.com/pypi/simple"
    )

REL32_OPS = {0xE8, 0xE9}                      # call rel32, jmp rel32
REL8_OPS = {0xEB, 0xE3, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
            0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F}
WILD = -1  # 用 -1 表示通配字节


def extract(pe, rva, length, wild_imm=False):
    """返回 (raw_bytes, signature_tokens) 其中 tokens 里 WILD 表示通配。"""
    data = pe.get_data(rva, length)
    if not data:
        raise SystemExit(f"RVA 0x{rva:x} 读不到数据")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    tokens = [b for b in data]

    for insn in md.disasm(data, rva):
        start = insn.address - rva
        size = insn.size
        raw = data[start : start + size]

        wilded = set()

        # 直接跳转/调用的相对位移
        if raw:
            op0 = raw[0]
            if op0 in REL32_OPS and size == 5:
                wilded.update(range(start + 1, start + 5))
            elif op0 in REL8_OPS and size == 2:
                wilded.update(range(start + 1, start + 2))
            elif op0 == 0x0F and size == 6 and len(raw) > 1 and 0x80 <= raw[1] <= 0x8F:
                wilded.update(range(start + 2, start + 6))

        # RIP 相对寻址：disp32 在指令末尾
        for operand in insn.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                wilded.update(range(start + size - 4, start + size))
            elif operand.type == X86_OP_IMM and wild_imm:
                # 立即数大小按 capstone 报告推断，通配末尾 4 字节
                if operand.imm > 0xFFFF:
                    wilded.update(range(max(start, start + size - 4), start + size))

        for i in wilded:
            if 0 <= i < len(tokens):
                tokens[i] = WILD

    # 截到完整指令边界
    end = 0
    for insn in md.disasm(data, rva):
        end = insn.address - rva + insn.size
    tokens = tokens[:end] if end else tokens

    return data, tokens


def tokens_to_text(tokens):
    return " ".join("??" if t == WILD else f"{t:02X}" for t in tokens)


def tokens_to_masked(tokens):
    """带掩码的形式，供自写扫描器使用。"""
    pat, mask = [], []
    for t in tokens:
        if t == WILD:
            pat.append(0)
            mask.append(0)
        else:
            pat.append(t)
            mask.append(0xFF)
    return pat, mask


def main():
    ap = argparse.ArgumentParser(description="从 RVA 提特征码")
    ap.add_argument("--dll", required=True)
    ap.add_argument("--rva", help="十六进制 RVA，如 0x2fb010")
    ap.add_argument("--batch", help="文件，每行一个 RVA（# 开头为注释）")
    ap.add_argument("--len", type=int, default=48, help="提取字节数，默认 48")
    ap.add_argument("--wild-imm", action="store_true", help="同时通配大立即数（指针类）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    pe = pefile.PE(args.dll, fast_load=True)

    rvas = []
    if args.rva:
        rvas.append(int(args.rva, 16))
    if args.batch:
        for line in open(args.batch, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                rvas.append(int(line, 16))
    if not rvas:
        raise SystemExit("需要 --rva 或 --batch")

    results = []
    for rva in rvas:
        raw, tokens = extract(pe, rva, args.len, args.wild_imm)
        text = tokens_to_text(tokens)
        results.append(
            {
                "rva": f"0x{rva:x}",
                "length": len(tokens),
                "wildcards": tokens.count(WILD),
                "signature": text,
            }
        )
        if not args.json:
            print(f"# RVA 0x{rva:x}  ({len(tokens)} 字节，通配 {tokens.count(WILD)} 处)")
            print(text)
            print()

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    sys.exit(main())

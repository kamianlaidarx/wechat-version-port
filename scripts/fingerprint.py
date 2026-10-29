#!/usr/bin/env python3
"""算出 Windows PE 的指纹四元组，用于微信版本迁移的 Step 1 / Step 2。

输出：
    size           文件字节数
    sha256         完整哈希
    sha256_prefix32 前 32 字节（64 个 hex 字符），对应 CoreBuild 里的 {0x74,0x5c,...}
    pe_timestamp   PE 头 TimeDateStamp，改文件改不掉这个
    size_of_image  OptionalHeader.SizeOfImage
    image_base     映像基址

用法：
    py -3.13 fingerprint.py "C:\\Program Files\\Tencent\\Weixin\\4.2.0.11\\Weixin.dll"
    py -3.13 fingerprint.py <dll> --compat      # 顺带输出 compatibility.json 片段
"""
import argparse
import hashlib
import json
import pathlib
import re
import struct
import sys

MACHINE = {0x8664: "x64", 0x014C: "x86", 0xAA64: "arm64"}


def read_pe(path):
    data = pathlib.Path(path).read_bytes()

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SystemExit(f"不是 PE 文件（缺 MZ 头）: {path}")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise SystemExit(f"PE 签名缺失 @0x{e_lfanew:x}")

    machine, nsect, timestamp = struct.unpack_from("<HHI", data, e_lfanew + 4)
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]

    if magic == 0x20B:  # PE32+
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        bits = 64
    elif magic == 0x10B:  # PE32
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        bits = 32
    else:
        raise SystemExit(f"未知 OptionalHeader.Magic = 0x{magic:x}")

    digest = hashlib.sha256(data).hexdigest()

    return {
        "path": str(pathlib.Path(path).resolve()),
        "size": len(data),
        "sha256": digest,
        "sha256_prefix32": digest[:64],
        "pe_timestamp": f"0x{timestamp:08x}",
        "size_of_image": f"0x{size_of_image:08x}",
        "image_base": f"0x{image_base:x}",
        "machine": MACHINE.get(machine, f"0x{machine:x}"),
        "bits": bits,
        "sections": nsect,
    }


def guess_version(path):
    """从路径里猜版本号，如 ...\\Weixin\\4.2.0.11\\Weixin.dll"""
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", str(path))
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description="Windows PE 指纹四元组")
    ap.add_argument("dll", help="目标 PE 文件（微信是 Weixin.dll）")
    ap.add_argument("--version", help="显式指定版本号，覆盖路径推断")
    ap.add_argument("--compat", action="store_true", help="输出 compatibility.json 条目")
    ap.add_argument("--json", action="store_true", help="纯 JSON 输出")
    args = ap.parse_args()

    info = read_pe(args.dll)
    version = args.version or guess_version(args.dll)

    if args.compat:
        if not version:
            raise SystemExit("无法从路径推断版本号，请加 --version 4.x.y.z")
        entry = {
            "wechat_version": version,
            "architecture": info["machine"],
            "size": info["size"],
            "sha256": info["sha256"],
        }
        print(json.dumps(entry, ensure_ascii=False, indent=2))
        return

    if args.json:
        info["version_hint"] = version
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return

    print(f"文件      : {info['path']}")
    print(f"版本推断  : {version or '(未识别)'}")
    print(f"架构      : {info['machine']} / {info['bits']} bit")
    print(f"大小      : {info['size']} bytes  ({info['size'] / 1048576:.1f} MB)")
    print(f"SHA256    : {info['sha256']}")
    print(f"前32字节  : {info['sha256_prefix32']}")
    print(f"PE 时间戳 : {info['pe_timestamp']}")
    print(f"映像大小  : {info['size_of_image']}")
    print(f"映像基址  : {info['image_base']}")
    print(f"节区数    : {info['sections']}")
    print()
    print("→ CoreBuild 条目（把 id 换成你的 profile 编号）：")
    print(
        "    {{{id}, {size}ull, {ts}, {img}, {{{pfx}}}}},  // {ver}".format(
            id="N",
            size=info["size"],
            ts=info["pe_timestamp"],
            img=info["size_of_image"],
            pfx=", ".join(
                "0x" + info["sha256_prefix32"][i : i + 2]
                for i in range(0, 64, 2)
            ),
            ver=version or "?",
        )
    )


if __name__ == "__main__":
    sys.exit(main())

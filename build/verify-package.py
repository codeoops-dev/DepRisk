#!/usr/bin/env python3
"""Checks a DepRisk.Cli NuGet package before it is published (ADR 0022).

For every platform the package must carry the reachability analyzer at
tools/net10.0/any/analyzers/<platform>/deprisk-reach[.exe], and that file must

  * be an executable of the right kind and the right CPU architecture (ELF, Mach-O, PE), so a binary that was staged for the wrong
    platform is caught here and not on a user's machine;
  * be large enough to be a real program;
  * match the SHA-256 in the <file>.sha256 that sits next to it.

usage: verify-package.py <package.nupkg> [--allow-missing] [--version X.Y.Z[-suffix]]
"""
import argparse
import hashlib
import struct
import sys
import zipfile

PLATFORMS = ["linux-x64", "linux-arm64", "osx-x64", "osx-arm64", "win-x64"]
PREFIX = "tools/net10.0/any/analyzers/"
MIN_SIZE = 500_000


def exe_name(platform):
    return "deprisk-reach.exe" if platform.startswith("win-") else "deprisk-reach"


def architecture_problem(platform, data):
    """None if the bytes are an executable of the platform's kind and architecture, else what is wrong."""
    kind, arch = platform.split("-")
    if kind == "linux":
        if data[:4] != b"\x7fELF":
            return "not an ELF file"
        if data[4] != 2 or data[5] != 1:
            return "not a 64-bit little-endian ELF file"
        machine = struct.unpack_from("<H", data, 18)[0]
        want = {"x64": 0x3E, "arm64": 0xB7}[arch]
        return None if machine == want else f"ELF machine 0x{machine:x}, expected 0x{want:x}"
    if kind == "osx":
        magic = data[:4]
        if magic == b"\xcf\xfa\xed\xfe":
            cpu = struct.unpack_from("<I", data, 4)[0]
            want = {"x64": 0x01000007, "arm64": 0x0100000C}[arch]
            return None if cpu == want else f"Mach-O cpu type 0x{cpu:x}, expected 0x{want:x}"
        if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            return "a universal (fat) Mach-O file: expected a single-architecture build"
        return "not a 64-bit little-endian Mach-O file"
    if kind == "win":
        if data[:2] != b"MZ":
            return "not a PE file"
        offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[offset:offset + 4] != b"PE\0\0":
            return "no PE header"
        machine = struct.unpack_from("<H", data, offset + 4)[0]
        want = {"x64": 0x8664, "arm64": 0xAA64}[arch]
        return None if machine == want else f"PE machine 0x{machine:x}, expected 0x{want:x}"
    return f"unknown platform {platform}"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("package")
    parser.add_argument("--allow-missing", action="store_true", help="a package with some platforms missing is acceptable (a local test)")
    parser.add_argument("--version", help="the version the package must have")
    options = parser.parse_args(argv[1:])

    problems = []
    with zipfile.ZipFile(options.package) as package:
        names = set(package.namelist())
        nuspec = [n for n in names if n.endswith(".nuspec")]
        if not nuspec:
            problems.append("no .nuspec in the package")
        elif options.version and f"<version>{options.version}</version>" not in package.read(nuspec[0]).decode("utf-8"):
            problems.append(f"the package is not version {options.version}")

        if "tools/net10.0/any/deprisk.dll" not in names:
            problems.append("tools/net10.0/any/deprisk.dll is missing")

        for platform in PLATFORMS:
            path = f"{PREFIX}{platform}/{exe_name(platform)}"
            if path not in names:
                if not options.allow_missing:
                    problems.append(f"{platform}: {path} is missing")
                continue

            before = len(problems)
            data = package.read(path)
            if len(data) < MIN_SIZE:
                problems.append(f"{platform}: only {len(data)} bytes, too small to be the analyzer")
            problem = architecture_problem(platform, data)
            if problem:
                problems.append(f"{platform}: {problem}")

            digest = hashlib.sha256(data).hexdigest()
            sums = path + ".sha256"
            if sums not in names:
                problems.append(f"{platform}: {sums} is missing")
            else:
                recorded = package.read(sums).decode("utf-8").split()[0].lower()
                if recorded != digest:
                    problems.append(f"{platform}: SHA-256 {digest} does not match the recorded {recorded}")

            print(f"{platform:12} {len(data):>10} bytes  sha256:{digest[:16]}...  {'FAIL' if len(problems) > before else 'ok'}")

        allowed = {f"{PREFIX}{p}/{exe_name(p)}" for p in PLATFORMS} | {f"{PREFIX}{p}/{exe_name(p)}.sha256" for p in PLATFORMS}
        extra = sorted(n for n in names if n.startswith(PREFIX) and not n.endswith("/") and n not in allowed)
        if extra:
            problems.append("unexpected files under analyzers/: " + ", ".join(extra[:5]))

    if problems:
        print("\nThe package is not fit to publish:")
        for p in problems:
            print("  -", p)
        return 1
    print("\nThe package is complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

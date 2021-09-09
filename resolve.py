# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2021 Gabriele N. Tornetta

import os
import subprocess
import sys
import typing as t


class Maps:
    def __init__(self):
        # TODO: Use an interval tree instead!
        self.maps: t.List[t.Tuple(int, int, str)] = []
        self.bases = {}
        self.cache = {}

    def addr2line(self, address: str) -> t.Optional[t.Tuple[str, str, str]]:
        if address in self.cache:
            return self.cache[address]

        addr = int(address, 16)
        for lo, hi, binary in self.maps:
            if lo <= addr <= hi:
                break
        else:
            self.cache[address] = None
            return None

        try:
            result = (
                subprocess.check_output(
                    ["addr2line", "-Cfe", binary, f"{addr-self.bases[binary]:x}"]
                )
                .decode()
                .strip()
            )
        except subprocess.CalledProcessError:
            self.cache[address] = None
            return None

        if "??" in result:
            self.cache[address] = (
                f"{binary}",
                "[unknown]",
                str(addr - self.bases[binary]),
            )
            return self.cache[address]

        func, _, file_line = result.partition("\n")
        file_line, _, _ = file_line.partition(" ")
        file, _, line = file_line.partition(":")
        self.cache[address] = (file, func, line)
        return self.cache[address]

    def add(self, line: str) -> None:
        bounds, _, binary = line[7:].strip().partition(" ")
        low, _, high = bounds.partition("-")
        lo = int(low, 16)
        hi = int(high, 16)
        self.maps.append((lo, hi, binary))
        if binary in self.bases:
            self.bases[binary] = min(self.bases[binary], lo)
        else:
            self.bases[binary] = lo

    def resolve(self, line: str) -> str:
        parts = []
        frames, _, metrics = line.strip().rpartition(" ")
        for part in frames.split(";"):
            if part.startswith("u0x"):
                resolved = self.addr2line(part[1:])
                if resolved is None:
                    continue
                parts.append(":".join(resolved))
            else:
                parts.append(part)

        return " ".join((";".join(parts[::-1]), metrics))


def main():
    try:
        stats = sys.argv[1]
        assert os.path.isfile(stats)
    except IndexError:
        print("Usage: python resolve.py <austin-file>", file=sys.stderr)
        sys.exit(1)
    except AssertionError:
        print("File does not exist", file=sys.stderr)
        sys.exit(1)

    maps = Maps()
    with open(stats) as s:
        for line in s:
            if line.startswith("# map: "):
                maps.add(line)
            elif line.startswith("# ") or line == "\n":
                print(line, end="")
            else:
                print(maps.resolve(line))


if __name__ == "__main__":
    main()

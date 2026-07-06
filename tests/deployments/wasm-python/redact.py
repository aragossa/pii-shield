#!/usr/bin/env python3
"""Stream a log file through the pii-shield-wasi SDK line by line."""
import sys

from pii_shield import PiiShield


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <input-log> <output-log>")
    src, dst = sys.argv[1], sys.argv[2]

    shield = PiiShield()
    processed = 0
    with open(src, "r", encoding="utf-8", errors="replace") as fin, \
            open(dst, "w", encoding="utf-8") as fout:
        for line in fin:
            fout.write(shield.redact(line.rstrip("\n")) + "\n")
            processed += 1
    print(f"processed {processed} lines", file=sys.stderr)


if __name__ == "__main__":
    main()

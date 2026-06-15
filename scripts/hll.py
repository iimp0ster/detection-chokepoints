"""Minimal HyperLogLog -- estimate a distinct count without storing the elements.

Why hand-rolled (no dependency): the point here is opsec, not scale. We need a
cumulative count of unique attacker IPs that NEVER persists an IP (decision #009).
HLL keeps only a fixed array of small registers -- per bucket, the longest run of
leading zeros seen in a hash. You can estimate cardinality from the statistical
shape of those registers, but you cannot recover any input from them. So the
sketch is structurally incapable of holding an IOC, which is exactly the property
the hard rule wants. ~1% error at p=14, irrelevant for a "unique IPs" trend stat.

At our volume (~1k IPs) exact counting would be trivial; HLL is chosen purely so
the persisted artifact can't be an IP set. Reference: Flajolet et al. (2007).
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path


class HyperLogLog:
    def __init__(self, p: int = 14, registers: list[int] | None = None):
        self.p = p
        self.m = 1 << p
        self.registers = registers if registers is not None else [0] * self.m

    @staticmethod
    def _hash64(value: str) -> int:
        # Stable 64-bit hash (SHA-1 truncated) -- deterministic across runs/platforms
        # so a saved sketch keeps estimating consistently.
        return int.from_bytes(hashlib.sha1(value.encode("utf-8")).digest()[:8], "big")

    def add(self, value: str) -> None:
        x = self._hash64(value)
        idx = x >> (64 - self.p)               # top p bits pick the register
        bits = 64 - self.p
        w = x & ((1 << bits) - 1)              # remaining bits
        rank = (bits - w.bit_length() + 1) if w else (bits + 1)  # leading-zeros + 1
        if rank > self.registers[idx]:
            self.registers[idx] = rank

    def count(self) -> int:
        m = self.m
        alpha = 0.7213 / (1 + 1.079 / m) if m >= 128 else 0.709
        raw = alpha * m * m / sum(2.0 ** -r for r in self.registers)
        if raw <= 2.5 * m:                     # small-range: linear counting is better
            zeros = self.registers.count(0)
            if zeros:
                return int(round(m * math.log(m / zeros)))
        return int(round(raw))

    def merge(self, other: "HyperLogLog") -> None:
        if other.p != self.p:
            raise ValueError("cannot merge HLL sketches of different precision")
        self.registers = [max(a, b) for a, b in zip(self.registers, other.registers)]

    def save(self, path) -> None:
        Path(path).write_text(json.dumps({"p": self.p, "registers": self.registers}),
                              encoding="utf-8")

    @classmethod
    def load(cls, path) -> "HyperLogLog":
        p = Path(path)
        if not p.exists():
            return cls()
        d = json.loads(p.read_text(encoding="utf-8"))
        return cls(p=d["p"], registers=d["registers"])

#!/usr/bin/env python3
"""
triage.py - one-command first look at an unknown binary.

Answers, in one pass: what is it, what arch, is it stripped, what
does it import, what strings jump out, is anything packed or
encrypted, and where would I start clicking.

Pure stdlib. Works air-gapped.

    python3 triage.py <binary> [--strings N] [--json out.json]
"""
import argparse
import hashlib
import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- constants

FLAG_RES = [
    re.compile(rb"[Ff][Ll1][Aa@][Gg]\{[^\}\n]{1,120}\}"),
    re.compile(rb"[Tt][Rr][Ii][Bb][Ee]\{[^\}\n]{1,120}\}"),
    re.compile(rb"tribe\{[^\}\n]{1,120}\}"),
    re.compile(rb"[A-Za-z0-9_]{0,20}ctf\{[^\}\n]{1,120}\}"),
]

# Rust runtime / toolchain fingerprints.
RUST_RES = [
    re.compile(rb"rustc/[0-9]+\.[0-9]+\.[0-9]+"),
    re.compile(rb"rustc/[0-9a-zA-Z.\-]+"),
    re.compile(rb"\.cargo/registry/src/"),
    re.compile(rb"/rustc/[0-9a-f]{8,}/library/"),
    re.compile(rb"core::panicking::"),
    re.compile(rb"core::fmt::"),
    re.compile(rb"alloc::vec::Vec<"),
    re.compile(rb"std::process::"),
    re.compile(rb"RUST_BACKTRACE"),
    re.compile(rb"__rust_[a-z_]+"),
    re.compile(rb"_ZN[0-9]+[a-z]"),          # legacy Rust mangling
    re.compile(rb"_R[A-Z][A-Za-z0-9_]+"),    # v0 Rust mangling
    re.compile(rb"\.rs:[0-9]+:[0-9]+"),      # panic location
]

INTERESTING_KEYWORDS = [
    b"flag", b"password", b"passwd", b"secret", b"key", b"token",
    b"correct", b"wrong", b"invalid", b"valid", b"success", b"fail",
    b"admin", b"license", b"serial", b"register", b"registration",
    b"welcome", b"congrat", b"denied", b"granted", b"access",
    b"debug", b"hint", b"usage", b"enter", b"input", b"argv",
    b"encrypt", b"decrypt", b"cipher", b"xor", b"base64", b"sha",
    b"md5", b"hash", b"verify", b"check", b"auth", b"login",
    b"rust", b"steel", b"regi", b"rusty", b"corrod", b"oxide", b"iron",
]


# ---------------------------------------------------------------- helpers

def shannon_entropy(buf):
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def extract_strings(data, minlen=4, encodings=("ascii", "utf16le")):
    """Return list of (offset, encoding, text)."""
    out = []
    # ASCII / UTF-8-ish
    cur, start = bytearray(), 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F or b in (9,):
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append((start, "ascii", cur.decode("ascii", "replace")))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append((start, "ascii", cur.decode("ascii", "replace")))

    if "utf16le" in encodings:
        # UTF-16LE: printable ascii interleaved with 0x00
        pat = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen)
        for m in pat.finditer(data):
            out.append((m.start(), "utf16le",
                        m.group().decode("utf-16le", "replace")))
    out.sort(key=lambda t: t[0])
    return out


def is_probably_packed(elf):
    """Heuristics: UPX magic, missing section names, high-entropy blob."""
    reasons = []
    names = [s.name for s in elf.sections]
    if any("UPX" in n for n in names):
        reasons.append("UPX section names present")
    if elf.data[:4096].find(b"UPX!") >= 0:
        reasons.append("UPX! magic in header region")
    if elf.section_by_name(".text") is None and elf.section_by_name(".symtab") is None:
        if len(elf.sections) <= 3:
            reasons.append("almost no section headers (stripped/packed)")
    for s in elf.sections:
        if s.type == 1 and s.size > 4096 and s.flags & 0x2:  # PROGBITS+EXEC
            if shannon_entropy(s.data) > 7.2:
                reasons.append("executable section %s entropy %.2f"
                               % (s.name, shannon_entropy(s.data)))
    return reasons


# ---------------------------------------------------------------- main report

def report(path, max_strings=60):
    out = []
    w = out.append

    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        data = fh.read()

    w("=" * 72)
    w("TRIAGE: %s" % path)
    w("=" * 72)
    w("size      : %d bytes (%.1f KiB)" % (size, size / 1024.0))
    w("md5       : %s" % hashlib.md5(data).hexdigest())
    w("sha256    : %s" % hashlib.sha256(data).hexdigest())
    w("entropy   : %.3f (whole file)" % shannon_entropy(data))

    magic = data[:4]
    if magic[:4] == b"\x7fELF":
        from retools.elf import ELFFile
        import tempfile
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        tmp.write(data)
        tmp.close()
        elf = ELFFile(tmp.name)
        os.unlink(tmp.name)

        w("")
        w("-- ELF --")
        w("class     : %s" % ("ELF64" if elf.is64 else "ELF32"))
        w("endian    : %s" % ("little" if elf.end == "<" else "big"))
        w("machine   : %s" % elf.machine_name)
        w("osabi     : %s" % elf.osabi)
        w("type      : %s" % {2: "EXEC (no PIE)", 3: "DYN (PIE/shared)"}.get(
            elf.e_type, elf.e_type))
        w("entry     : %#x" % elf.e_entry)
        w("stripped  : %s" % ("YES (no .symtab)" if elf.is_stripped else "no"))
        w("symbols   : %d symtab, %d dynsym" % (len(elf.symbols), len(elf.dyn_symbols)))
        if elf.needed:
            w("imports   : %s" % ", ".join(elf.needed))
        w("relocs    : %d" % len(elf.relocs))
        w("rpath     : %s" % ", ".join(
            n for t, v, n in elf.dynamic if t in (15, 29) and n) or "(none)")

        w("")
        w("sections:")
        w("  %-20s %-12s %-4s %-10s %-10s %s" %
          ("name", "type", "flg", "addr", "size", "entropy"))
        for s in elf.sections:
            if not s.size:
                continue
            w("  %-20s %-12s %-4s %#-10x %#-10x %.2f" %
              (s.name[:20], s.type_name, s.flags_str, s.addr, s.size,
               shannon_entropy(s.data)))

        pk = is_probably_packed(elf)
        if pk:
            w("")
            w("PACKING/OBFUSCATION indicators:")
            for r in pk:
                w("  ! %s" % r)
    elif magic[:2] in (b"MZ", b"ZM"):
        w("")
        w("-- PE / Windows --")
        w("use: python3 triage.py on PE is limited; try strings + radare2")
    elif magic[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xd0\x0d"):
        w("")
        w("-- Mach-O --")
        w("macOS binary: run natively, r2 will handle it")
    elif data[:2] == b"PK":
        w("")
        w("-- ZIP archive --")
        w("try: unzip -l, then look for embedded ELF")
    else:
        w("")
        w("unknown container magic: %r" % magic)

    # ---- strings ----
    strs = extract_strings(data, 4)
    w("")
    w("-- strings: %d total (showing notable) --" % len(strs))

    flag_hits = []
    rust_hits = []
    for off, enc, s in strs:
        raw = s.encode("utf-8", "replace") if enc == "ascii" else s.encode("utf-16le", "replace")
        for rx in FLAG_RES:
            m = rx.search(raw)
            if m:
                flag_hits.append((off, m.group().decode("utf-8", "replace")))

    for rx in RUST_RES:
        m = rx.search(data)
        if m:
            rust_hits.append((m.group().decode("utf-8", "replace"), hex(m.start())))

    if flag_hits:
        w("")
        w("*** FLAG-LIKE STRINGS ***")
        for off, f in flag_hits:
            w("  %#010x  %s" % (off, f))
    else:
        w("  (no plaintext flag pattern)")

    if rust_hits:
        w("")
        w("*** RUST INDICATORS (%d) ***" % len(rust_hits))
        seen = set()
        for txt, off in rust_hits:
            if txt in seen:
                continue
            seen.add(txt)
            w("  %-40s @ %s" % (txt[:40], off))

    # notable keyword strings
    notable = []
    for off, enc, s in strs:
        low = s.lower().encode()
        if any(k in low for k in INTERESTING_KEYWORDS):
            notable.append((off, enc, s))
    if notable:
        w("")
        w("-- notable strings (%d) --" % len(notable))
        for off, enc, s in notable[:max_strings]:
            w("  %#010x %-8s %s" % (off, enc, s[:100]))
        if len(notable) > max_strings:
            w("  ... %d more" % (len(notable) - max_strings))
    else:
        w("  (no keyword strings)")

    # ---- suggested next step ----
    w("")
    w("-- suggested next step --")
    if flag_hits:
        w("  plaintext flag present -> just read it, verify format")
    elif rust_hits:
        w("  Rust binary: open in r2/ghidra, look for fn main / the checker.")
        w("  r2 -A -q -c 'aaa; afl~main' <bin>")
        w("  Rust keeps symbols unless stripped -> symbol list is your map.")
    else:
        w("  no clear language fingerprint -> run r2 -A and read afl output.")
    w("=" * 72)
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--strings", type=int, default=60)
    args = ap.parse_args()
    if not os.path.exists(args.binary):
        print("no such file: %s" % args.binary)
        return 1
    print(report(args.binary, args.strings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
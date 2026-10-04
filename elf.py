"""
Pure-stdlib ELF parser. No third-party dependencies.

Exists so the field kit keeps working in an air-gapped SCIF where pip is
unavailable. Handles ELF32/ELF64, both endiannesses, enough to recover
sections, symbols, relocations and the dynamic table.

Public surface:
    ELFFile(path)          -> .header, .sections, .symbols, .dyn_symbols,
                              .relocs, .dynamic, .is_stripped
    section_by_name(name)
    vaddr_to_offset(vaddr)
"""
import struct
import os

# e_type
ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_CORE = 0, 1, 2, 3, 4
# e_machine (subset)
EM_MACHINE = {
    0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC",
    0x15: "PowerPC64", 0x16: "S390", 0x28: "ARM", 0x2A: "SuperH",
    0x32: "IA64", 0x3E: "x86-64", 0xB7: "AArch64", 0xF3: "RISC-V",
}
# e_ident[EI_OSABI]
EI_OSABI = {
    0: "SYSV", 1: "HPUX", 2: "NetBSD", 3: "Linux", 6: "Solaris",
    9: "FreeBSD", 12: "OpenBSD",
}
# Section header types
SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_HASH = 0, 1, 2, 3, 4, 5
SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_REL, SHT_SHLIB, SHT_DYNSYM = 6, 7, 8, 9, 10, 11
SHT_INIT_ARRAY, SHT_FINI_ARRAY, SHT_PREINIT_ARRAY = 14, 15, 16
SHT_GNU_HASH, SHT_GNU_VERDEF, SHT_GNU_VERNEED = 0x6FFFFFF6, 0x6FFFFFFD, 0x6FFFFFFE
SHT_GNU_VERSYM = 0x6FFFFFFF

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4

SHT_NAMES = {
    SHT_NULL: "NULL", SHT_PROGBITS: "PROGBITS", SHT_SYMTAB: "SYMTAB",
    SHT_STRTAB: "STRTAB", SHT_RELA: "RELA", SHT_HASH: "HASH",
    SHT_DYNAMIC: "DYNAMIC", SHT_NOTE: "NOTE", SHT_NOBITS: "NOBITS",
    SHT_REL: "REL", SHT_SHLIB: "SHLIB", SHT_DYNSYM: "DYNSYM",
    SHT_INIT_ARRAY: "INIT_ARRAY", SHT_FINI_ARRAY: "FINI_ARRAY",
    SHT_PREINIT_ARRAY: "PREINIT_ARRAY", SHT_GNU_HASH: "GNU_HASH",
    SHT_GNU_VERSYM: "GNU_VERSYM",
}

DT_NAMES = {
    0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH",
    5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT",
    10: "STRSZ", 11: "SYMENT", 12: "INIT", 13: "FINI", 14: "SONAME",
    15: "RPATH", 16: "SYMBOLIC", 17: "REL", 18: "RELSZ", 19: "RELENT",
    20: "PLTREL", 21: "DEBUG", 22: "TEXTREL", 23: "JMPREL",
    24: "BIND_NOW", 25: "INIT_ARRAY", 26: "FINI_ARRAY", 27: "INIT_ARRAYSZ",
    28: "FINI_ARRAYSZ", 29: "RUNPATH", 30: "FLAGS",
    0x6FFFFEF5: "GNU_HASH", 0x6FFFFFF0: "VERSYM", 0x6FFFFFFA: "RELCOUNT",
    0x6FFFFFF9: "RELACOUNT",
}

STT_NAMES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
             5: "COMMON", 6: "TLS", 10: "GNU_IFUNC"}
STB_NAMES = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
SHN_UNDEF, SHN_ABS = 0, 0xFFF1


class Section:
    __slots__ = ("name", "type", "flags", "addr", "offset", "size",
                 "link", "info", "addralign", "entsize", "shstrndx", "data")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def type_name(self):
        return SHT_NAMES.get(self.type, hex(self.type) if self.type is not None else "?")

    @property
    def flags_str(self):
        f = self.flags or 0
        return "".join([
            "W" if f & SHF_WRITE else "-",
            "A" if f & SHF_ALLOC else "-",
            "X" if f & SHF_EXECINSTR else "-",
        ])

    def __repr__(self):
        return ("<Section %-18s %-11s %s addr=%#x off=%#x size=%#x>"
                % (self.name, self.type_name, self.flags_str,
                   self.addr or 0, self.offset or 0, self.size or 0))


class Symbol:
    __slots__ = ("name", "value", "size", "info", "other", "shndx")

    def __init__(self, name, value, size, info, other, shndx):
        self.name, self.value, self.size = name, value, size
        self.info, self.other, self.shndx = info, other, shndx

    @property
    def bind(self):
        return STB_NAMES.get(self.info >> 4, str(self.info >> 4))

    @property
    def type(self):
        return STT_NAMES.get(self.info & 0xF, str(self.info & 0xF))

    @property
    def is_func(self):
        return (self.info & 0xF) == 2

    def __repr__(self):
        return "<Symbol %-40s %#x sz=%d %s/%s>" % (
            (self.name or "")[:40], self.value, self.size, self.bind, self.type)


class Reloc:
    __slots__ = ("offset", "info", "type", "sym_name", "addend")

    def __init__(self, offset, info, rtype, sym_name, addend):
        self.offset, self.info, self.type = offset, info, rtype
        self.sym_name, self.addend = sym_name, addend

    def __repr__(self):
        return "<Reloc %#x -> %s>" % (self.offset, self.sym_name)


class ELFFile:
    """Parse an ELF file with nothing but the standard library."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.sections = []
        self.symbols = []
        self.dyn_symbols = []
        self.relocs = []
        self.dynamic = []
        self.is_stripped = True
        self._parse()

    # ---- low level ----
    def _u(self, fmt, off):
        size = struct.calcsize(self.end + fmt)
        return struct.unpack_from(self.end + fmt, self.data, off)

    def _cstr(self, base, off):
        if base is None or off >= len(self.data):
            return ""
        end = self.data.find(b"\x00", base + off)
        if end < 0:
            end = len(self.data)
        return self.data[base + off:end].decode("utf-8", "replace")

    # ---- parsing ----
    def _parse(self):
        d = self.data
        if len(d) < 64 or d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        ei_class, ei_data = d[4], d[5]
        if ei_class not in (1, 2):
            raise ValueError("bad EI_CLASS %d" % ei_class)
        self.is64 = (ei_class == 2)
        self.end = "<" if ei_data == 1 else ">"
        self.osabi = EI_OSABI.get(d[7], str(d[7]))

        if self.is64:
            (self.e_type, self.e_machine, self.e_version, self.e_entry,
             self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = self._u(
                "HHIQQQIHHHHHH", 16)
        else:
            (self.e_type, self.e_machine, self.e_version, self.e_entry,
             self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = self._u(
                "HHIIIIIHHHHHH", 16)

        self.machine_name = EM_MACHINE.get(self.e_machine, hex(self.e_machine))
        self._parse_sections()
        self._parse_symbols()
        self._parse_dynamic()
        self._parse_relocs()

    def _parse_sections(self):
        d = self.data
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if off + self.e_shentsize > len(d):
                break
            if self.is64:
                (name, stype, flags, addr, offset, size, link, info,
                 align, entsize) = struct.unpack_from(self.end + "IIQQQQIIQQ", d, off)
            else:
                (name, stype, flags, addr, offset, size, link, info,
                 align, entsize) = struct.unpack_from(self.end + "IIIIIIIIII", d, off)
            raw.append(dict(name=name, type=stype, flags=flags, addr=addr,
                            offset=offset, size=size, link=link, info=info,
                            addralign=align, entsize=entsize, shstrndx=0))

        # section header string table
        shstr = b""
        if self.e_shstrndx < len(raw):
            s = raw[self.e_shstrndx]
            if s["type"] != SHT_NOBITS:
                shstr = d[s["offset"]:s["offset"] + s["size"]]

        for r in raw:
            nm = ""
            if shstr and r["name"] < len(shstr):
                end = shstr.find(b"\x00", r["name"])
                nm = shstr[r["name"]:end if end >= 0 else None].decode("utf-8", "replace")
            r["name"] = nm
            sec = Section(**r)
            if sec.type != SHT_NOBITS and sec.offset + sec.size <= len(d):
                sec.data = d[sec.offset:sec.offset + sec.size]
            else:
                sec.data = b""
            self.sections.append(sec)

    def section_by_name(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def _strtab_for(self, sec):
        link = sec.link if sec.link is not None else 0
        if link < len(self.sections):
            st = self.sections[link]
            if st.type == SHT_STRTAB:
                return st.offset
        return None

    def _read_symbols(self, sec):
        strbase = self._strtab_for(sec)
        out = []
        entsize = sec.entsize or (24 if self.is64 else 16)
        count = sec.size // entsize if entsize else 0
        for i in range(count):
            off = sec.offset + i * entsize
            if off + entsize > len(self.data):
                break
            if self.is64:
                name, info, other, shndx, value, size = struct.unpack_from(
                    self.end + "IBBHQQ", self.data, off)
            else:
                name, value, size, info, other, shndx = struct.unpack_from(
                    self.end + "IIIBBH", self.data, off)
            out.append(Symbol(self._cstr(strbase, name), value, size,
                              info, other, shndx))
        return out

    def _parse_symbols(self):
        for sec in self.sections:
            if sec.type == SHT_SYMTAB:
                self.symbols = self._read_symbols(sec)
                self.is_stripped = False
            elif sec.type == SHT_DYNSYM:
                self.dyn_symbols = self._read_symbols(sec)

    def _parse_dynamic(self):
        for sec in self.sections:
            if sec.type != SHT_DYNAMIC:
                continue
            strbase = self._strtab_for(sec)
            entsize = sec.entsize or (16 if self.is64 else 8)
            for off in range(sec.offset, sec.offset + sec.size - entsize + 1, entsize):
                if self.is64:
                    tag, val = struct.unpack_from(self.end + "qQ", self.data, off)
                else:
                    tag, val = struct.unpack_from(self.end + "iI", self.data, off)
                if tag == 0:
                    break
                name = ""
                if tag in (1, 14, 15, 29):  # NEEDED, SONAME, RPATH, RUNPATH
                    name = self._cstr(strbase, val)
                self.dynamic.append((tag, val, name))

    def _parse_relocs(self):
        for sec in self.sections:
            if sec.type not in (SHT_RELA, SHT_REL):
                continue
            if sec.info >= len(self.sections):
                continue
            symtab = self.sections[sec.info]
            syms = self._read_symbols(symtab)
            is_rela = (sec.type == SHT_RELA)
            step = 24 if self.is64 else 12
            if not self.is64:
                step = 12 if is_rela else 8
            elif not is_rela:
                step = 16
            for off in range(sec.offset, sec.offset + sec.size - step + 1, step):
                if is_rela:
                    r_off, r_info, r_add = struct.unpack_from(
                        self.end + "QQq", self.data, off)
                else:
                    r_off, r_info = struct.unpack_from(
                        self.end + "QQ", self.data, off)
                    r_add = None
                sym_idx = r_info >> 32
                sname = syms[sym_idx].name if sym_idx < len(syms) else ""
                self.relocs.append(Reloc(r_off, r_info,
                                         r_info & 0xFFFFFFFF, sname, r_add))

    # ---- helpers ----
    def vaddr_to_offset(self, vaddr):
        for s in self.sections:
            if s.type == SHT_NOBITS or not s.flags & SHF_ALLOC:
                continue
            if s.addr <= vaddr < s.addr + s.size:
                return s.offset + (vaddr - s.addr)
        return None

    @property
    def needed(self):
        return [n for t, v, n in self.dynamic if t == 1 and n]

    @property
    def entry(self):
        return self.e_entry

    def __repr__(self):
        return "<ELFFile %s %s%s entry=%#x syms=%d>" % (
            self.machine_name,
            {2: "EXEC", 3: "DYN(PIE)", 1: "REL"}.get(self.e_type, str(self.e_type)),
            " STRIPPED" if self.is_stripped else "",
            self.e_entry, len(self.symbols))
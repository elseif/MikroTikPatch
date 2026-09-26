"""
patch_mode.py — Surgical patching of the `mode` binary.

Replaces the old `mode` wrapper (which rewrote rosmode.msg on the fly) and the
global GOT patch of memcmp (which broke container=no). Instead, it auto-discovers
the ONLY call-site that verifies the signature/digest of rosmode.msg and replaces
it with "return 0", without touching the rest of the memcmp call sites in the
binary (string_view::compare, nv::message parser, etc.).

Supported: x86 (i386), arm (ARM32 EABI5), arm64 (AArch64).
"""

import struct
from dataclasses import dataclass

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
except ModuleNotFoundError:
    print("[+] pyelftools no encontrado. Instalando...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyelftools"])
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection


# ---------------------------------------------------------------------------
# Per-architecture configuration
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ArchCfg:
    """Static per-architecture parameters used during patching."""
    e_machine: int        # ELF e_machine value expected for this arch
    plt0_size: int        # Size of the PLT0 resolver stub (skipped when scanning .plt)
    plt_entry_size: int   # Size of each PLT entry (used to compute the ordinal slot)
    patch: bytes          # Bytes written over the call-site to force "return 0"
    scan_step: int        # Instruction alignment step used when scanning .text


_ARCH_CFG = {
    # `call E8 xx xx xx xx`  →  `xor eax,eax; nop;nop;nop` (return 0 on x86)
    'x86':   ArchCfg(3,   16, 16, b'\x31\xC0\x90\x90\x90', 1),
    # ARM `BL offset24`      →  `mov r0, #0`  (return 0 in r0)
    'arm':   ArchCfg(40,  20, 12, b'\x00\x00\xA0\xE3',     4),
    # AArch64 `BL imm26`     →  `mov w0, wzr` (return 0 in w0)
    'arm64': ArchCfg(183, 32, 16, b'\xE0\x03\x1F\x2A',     4),
}

# Alternative spellings users may pass for the same architecture.
_ARCH_ALIASES = {
    'i386': 'x86', 'i486': 'x86', 'i586': 'x86', 'i686': 'x86', 'ia32': 'x86',
    'arm32': 'arm', 'armhf': 'arm', 'armv7': 'arm', 'armv7l': 'arm',
    'aarch64': 'arm64',
}

# Fallback mapping for pyelftools versions that return e_machine as a string.
_EM_NAME_TO_ID = {'EM_386': 3, 'EM_ARM': 40, 'EM_AARCH64': 183}


def _normalize_arch(arch):
    """Normalize an architecture string (aliases, dashes, underscores, case)."""
    a = (arch or '').lower().replace('-', '').replace('_', '')
    return _ARCH_ALIASES.get(a, a)


# ---------------------------------------------------------------------------
# Detection of "call/BL to <target>"
# ---------------------------------------------------------------------------
def _is_call_x86(data, off, addr, target):
    """Return True if the bytes at `off` are `call rel32` targeting `target`.

    `addr` is the virtual address corresponding to `data[off]`; `target` is
    the destination virtual address we are looking for (memcmp@plt stub).
    """
    if data[off] != 0xE8:
        return False
    rel = struct.unpack_from('<i', data, off + 1)[0]
    # x86 `call rel32` is 5 bytes long, so the return address is addr+5.
    return ((addr + 5 + rel) & 0xFFFFFFFF) == target


def _is_call_arm(data, off, addr, target):
    """Return True if `off` holds an ARM-mode BL or a Thumb-2 BL to `target`."""
    # ARM mode BL: cond=1110, 101, L=1  → top byte = 0xEB
    if data[off + 3] == 0xEB:
        imm24 = int.from_bytes(data[off:off + 3], 'little')
        if imm24 & 0x800000:
            imm24 -= 0x1000000
        # ARM PC is addr+8 for the branch offset.
        if ((addr + 8 + (imm24 << 2)) & 0xFFFFFFFF) == target:
            return True

    # Thumb-2 BL encoding: 11110 S imm10 / 11 J1 1 J2 imm11
    hw1 = int.from_bytes(data[off:off + 2], 'little')
    hw2 = int.from_bytes(data[off + 2:off + 4], 'little')
    if (hw1 & 0xF800) != 0xF000 or (hw2 & 0xD000) != 0xD000:
        return False
    s   = (hw1 >> 10) & 1
    # J1/J2 are XORed with S in the encoding per the ARM ARM.
    i1  = 1 - (((hw2 >> 13) & 1) ^ s)
    i2  = 1 - (((hw2 >> 11) & 1) ^ s)
    imm = (s << 24) | (i1 << 23) | (i2 << 22) \
        | ((hw1 & 0x03FF) << 12) | ((hw2 & 0x07FF) << 1)
    if s:
        # Sign-extend the 25-bit immediate.
        imm -= 0x2000000
    # Thumb-2 BL offset is relative to (addr + 4).
    return ((addr + 4 + imm) & 0xFFFFFFFF) == target


def _is_call_arm64(data, off, addr, target):
    """Return True if `off` holds an AArch64 BL (100101 imm26) to `target`."""
    if (data[off + 3] & 0xFC) != 0x94:   # BL: 100101 xx...
        return False
    imm26 = int.from_bytes(data[off:off + 4], 'little') & 0x03FFFFFF
    if imm26 & 0x02000000:
        # Sign-extend the 26-bit immediate.
        imm26 -= 0x04000000
    return ((addr + (imm26 << 2)) & 0xFFFFFFFFFFFFFFFF) == target


# ---------------------------------------------------------------------------
# Heuristic: count "mov dword [reg+disp], imm32" — hash-init pattern
# ---------------------------------------------------------------------------
# The verifier that hashes rosmode.msg is initialized with a run of
# `mov dword ptr [...], imm32` instructions (SHA-256 constants loaded one by
# one on x86, or movw/movt and movz/movk chains on ARM/AArch64). Counting
# those within a window before each memcmp call lets us pick the digest
# verifier among the candidate call sites.
def _score_x86(data, start, end):
    """Count x86 `mov dword ptr [reg+disp], imm32` instructions in [start,end)."""
    c, i = 0, start
    while i < end - 3:
        if data[i] == 0xC7:
            nxt = data[i + 1]
            if nxt == 0x45 and i + 7 <= end:                          # [ebp+disp8]
                c += 1; i += 7; continue
            if nxt == 0x85 and i + 10 <= end:                         # [ebp+disp32]
                c += 1; i += 10; continue
            if nxt == 0x44 and data[i + 2] == 0x24 and i + 8 <= end:  # [esp+disp8]
                c += 1; i += 8; continue
            if 0x40 <= nxt <= 0x7F and i + 7 <= end:                  # [reg+disp8]
                c += 1; i += 7; continue
        i += 1
    return c


def _score_arm(data, start, end):
    """Count ARM32 `movw`/`movt` pairs (used to build 32-bit hash constants)."""
    c, i = 0, start & ~3
    while i < end - 4:
        w = int.from_bytes(data[i:i + 4], 'little')
        if (w & 0x0FF00000) in (0x03000000, 0x03400000):  # MOVW / MOVT
            c += 1
        i += 4
    return c


def _score_arm64(data, start, end):
    """Count AArch64 `movz`/`movk` (used to build 32/64-bit hash constants)."""
    c, i = 0, start & ~3
    while i < end - 4:
        w = int.from_bytes(data[i:i + 4], 'little')
        if (w & 0x7F800000) in (0x52800000, 0x72800000):  # MOVZ / MOVK
            c += 1
        i += 4
    return c


_CALL_FINDER = {'x86': _is_call_x86, 'arm': _is_call_arm, 'arm64': _is_call_arm64}
_SCORER      = {'x86': _score_x86,   'arm': _score_arm,   'arm64': _score_arm64}


# ---------------------------------------------------------------------------
# Locating the memcmp@plt stub via .dynsym + .rel.plt + .plt layout
# ---------------------------------------------------------------------------
def _find_plt_stub(elf, cfg):
    """
    Locate the address of the `memcmp@plt` stub and its GOT slot.

    Returns (stub_va, got_va, ordinal) or (None, None, None) if any step fails.
    The ordinal is the index of memcmp within the relocation table, which is
    used to compute the corresponding PLT entry address.
    """
    dynsym = elf.get_section_by_name('.dynsym')
    if dynsym is None:
        return None, None, None

    # Find memcmp's index inside .dynsym.
    memcmp_idx = next(
        (i for i, s in enumerate(dynsym.iter_symbols()) if s.name == 'memcmp'),
        None,
    )
    if memcmp_idx is None:
        return None, None, None

    # Locate its relocation entry to obtain the ordinal and GOT slot VA.
    ordinal = got_va = None
    for name in ('.rel.plt', '.rela.plt'):
        sec = elf.get_section_by_name(name)
        if sec is None:
            continue
        for i, rel in enumerate(sec.iter_relocations()):
            if rel['r_info_sym'] == memcmp_idx:
                ordinal, got_va = i, rel['r_offset']
                break
        if ordinal is not None:
            break
    if ordinal is None:
        return None, None, None

    # With full RELRO / BIND_NOW the stubs live in .plt.sec and there is no
    # PLT0 resolver, so no header needs to be skipped. Otherwise we use .plt
    # and skip PLT0 (cfg.plt0_size bytes).
    plt_sec = elf.get_section_by_name('.plt.sec')
    if plt_sec is not None:
        head = 0
    else:
        plt_sec = elf.get_section_by_name('.plt')
        if plt_sec is None:
            return None, None, None
        head = cfg.plt0_size

    stub_va = plt_sec['sh_addr'] + head + ordinal * cfg.plt_entry_size
    return stub_va, got_va, ordinal


# ---------------------------------------------------------------------------
# .text scan
# ---------------------------------------------------------------------------
def _find_calls(text_data, text_va, stub_va, cfg, arch):
    """Return the virtual addresses of all calls/BLs to `stub_va` in .text."""
    finder = _CALL_FINDER[arch]
    return [
        text_va + i
        for i in range(0, len(text_data) - 8, cfg.scan_step)
        if finder(text_data, i, text_va + i, stub_va)
    ]


# ---------------------------------------------------------------------------
# Robust e_machine reading
# ---------------------------------------------------------------------------
def _get_e_machine(elf):
    """
    pyelftools is not consistent across versions:
      - Some return an IntEnum (which has .value).
      - Others return a string ('EM_386', 'EM_ARM', 'EM_AARCH64').
    Return the numeric ID, or None if it cannot be resolved.
    """
    raw = elf.header['e_machine']
    if hasattr(raw, 'value'):
        try:
            return int(raw.value)
        except (TypeError, ValueError):
            pass
    if isinstance(raw, str):
        return _EM_NAME_TO_ID.get(raw)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Sanity check: the first byte signature must match the ISA
# ---------------------------------------------------------------------------
def _looks_like_call(arch, b):
    """Return True if the bytes `b` start with a plausible call/BL instruction."""
    if arch == 'x86':
        return b[:1] == b'\xE8'
    if arch == 'arm':      # ARM BL or Thumb-2 BL (top half is 11110)
        return b[3] == 0xEB or (b[1] & 0xF8) == 0xF0
    if arch == 'arm64':
        return (b[3] & 0xFC) == 0x94
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def patch_mode(mode_path, arch, window=256, dry_run=False, verbose=True):
    """
    Patch `nova/bin/mode` to force the signature/digest check to succeed.

    Returns True if the patch was applied (or would have been in dry_run),
    False if anything failed and the file was left untouched.
    """
    arch = _normalize_arch(arch)
    cfg = _ARCH_CFG.get(arch)
    if cfg is None:
        print(f'[!] mode: unsupported architecture {arch!r} '
              f'(only x86, arm, arm64).')
        return False

    with open(mode_path, 'r+b') as f:
        # --- Phase 1: ELF parsing (everything with the file still open) ---
        elf = ELFFile(f)

        # Verify the ELF's e_machine matches the requested architecture.
        e_machine = _get_e_machine(elf)
        if e_machine != cfg.e_machine:
            print(f'[!] mode({arch}): e_machine={e_machine} '
                  f'(raw={elf.header["e_machine"]!r}), '
                  f'expected {cfg.e_machine}.')
            return False

        # Find the memcmp@plt stub address; everything else builds on it.
        stub_va, got_va, ordinal = _find_plt_stub(elf, cfg)
        if stub_va is None:
            print(f'[!] mode({arch}): could not locate the memcmp PLT stub.')
            return False
        if verbose:
            print(f'[+] mode({arch}): memcmp@plt=0x{stub_va:x} '
                  f'GOT=0x{got_va:x} ordinal={ordinal}')

        # Grab .text so we can scan it for call sites.
        text_sec = elf.get_section_by_name('.text')
        if text_sec is None:
            print(f'[!] mode({arch}): no .text section.')
            return False
        text_va, text_off = text_sec['sh_addr'], text_sec['sh_offset']
        text_data = text_sec.data()

        # The scan is done here: pyelftools may reopen the stream internally
        # for some operations, so we avoid holding onto section objects longer
        # than necessary.
        calls = _find_calls(text_data, text_va, stub_va, cfg, arch)

        # --- Phase 2: pick the right call site ---
        if not calls:
            print(f'[!] mode({arch}): no call/BL targets memcmp@plt in .text.')
            return False
        if verbose:
            print(f'[+] mode({arch}): {len(calls)} call-site(s): '
                  f'{[hex(c) for c in calls]}')

        # Score each candidate by counting immediate materialization
        # instructions in the `window` bytes preceding it. The digest check
        # is the one preceded by many such instructions.
        scorer = _SCORER[arch]
        scores = [
            (va, scorer(text_data,
                        max(text_va, va - window) - text_va,
                        va - text_va))
            for va in calls
        ]
        if verbose:
            print(f'[+] mode({arch}): scores {[(hex(v), s) for v, s in scores]}')

        if len(calls) == 1:
            # Only one call to memcmp: trust it directly.
            chosen = calls[0]
            print(f'[+] mode({arch}): single call-site, using 0x{chosen:x}')
        else:
            # Multiple candidates: pick the one with the highest score.
            chosen, best = max(scores, key=lambda x: x[1])
            if best == 0:
                # No candidate has any hash-init pattern nearby: bail out
                # rather than risk patching the wrong memcmp call.
                print(f'[!] mode({arch}): no candidate has nearby immediates '
                      f'— the heuristic cannot choose. Aborting to avoid '
                      f'corrupting the binary.')
                return False
            print(f'[+] mode({arch}): chose 0x{chosen:x} (score={best})')

        off_in_file = text_off + (chosen - text_va)
        patch = cfg.patch
        if verbose:
            print(f'[+] mode({arch}): file offset = 0x{off_in_file:x}, '
                  f'patch = {patch.hex().upper()}')

        if dry_run:
            print('[+] dry-run: file not modified.')
            return True

        # --- Phase 3: sanity check + write ---
        f.seek(off_in_file)
        original = f.read(len(patch))
        if not _looks_like_call(arch, original):
            # Refuse to overwrite if the bytes don't look like a call/BL.
            print(f'[!] mode({arch}): at 0x{off_in_file:x} the signature does '
                  f'not match ({original.hex().upper()}). Aborting.')
            return False
        f.seek(off_in_file)
        f.write(patch)
        print(f'[+] mode({arch}): {original.hex().upper()} → '
              f'{patch.hex().upper()}')
    return True


if __name__ == '__main__':
    import argparse

    # CLI: patch <binary> <arch> [--dry-run] [--quiet]
    p = argparse.ArgumentParser(
        description='Surgical patching of the `mode` binary for RouterOS 7.x.')
    p.add_argument('binary', help='Path to the binary (mode)')
    p.add_argument('arch', choices=['x86', 'arm', 'arm64'],
                   help='Architecture of the binary')
    p.add_argument('--dry-run', action='store_true',
                   help='Do not modify the file, just simulate')
    p.add_argument('--quiet', action='store_true',
                   help='Do not print details')
    args = p.parse_args()

    ok = patch_mode(args.binary, args.arch,
                    dry_run=args.dry_run, verbose=not args.quiet)
    raise SystemExit(0 if ok else 1)

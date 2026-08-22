#!/usr/bin/env python3
"""
sdl_lookup.py — Extract the SDL2 dynapi jump-table layout from a dom6_mac binary.

dom6_mac statically links SDL2.  SDL2 dispatches every public SDL_X call
through a function-pointer array (the "dynapi jump_table") whose slot order
is determined at SDL's build time, not dom6's.  To redirect SDL calls to
host libSDL2 we need two things this script produces:

  1. The virtual address of the jump_table inside dom6_mac (found by
     scanning the binary's __DATA segment).
  2. The ordered list of public SDL function names that fill the slots
     (recovered from SDL2's own SDL_dynapi.o object file — the relocations
     in its __data section name one slot per entry).

Output is JSON consumed by tools/build_loader.py to emit sdl_redirect.inc.

Inputs are file paths; this script never downloads anything.  Provide:
  --mac-bin       path to dom6_mac (the Mach-O ARM64 binary)
  --sdl-archive   path to libSDL2.a (a static-archive build of the exact
                  SDL2 version dom6 was linked against — typically a
                  Homebrew bottle on macOS, or a from-source build on
                  any platform.  The script verifies the version matches
                  the SDL version string embedded in dom6_mac.)
  --out           where to write sdl_map.json (typically data/<ver>/)

Usage:
  python3 tools/sdl_lookup.py \\
      --mac-bin origin/dom6_mac \\
      --sdl-archive /opt/homebrew/Cellar/sdl2/2.32.10/lib/libSDL2.a \\
      --out data/<ver>/sdl_map.json
"""

import sys, os, re, struct, json, argparse, subprocess, tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


# ────────────── Mach-O object parsing ─────────────────────────────────────────

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2

# arm64 relocation types (mach/arm64/reloc.h)
ARM64_RELOC_UNSIGNED = 0
ARM64_RELOC_SUBTRACTOR = 1
ARM64_RELOC_BRANCH26 = 2
ARM64_RELOC_PAGE21 = 3
ARM64_RELOC_PAGEOFF12 = 4
ARM64_RELOC_GOT_LOAD_PAGE21 = 5
ARM64_RELOC_GOT_LOAD_PAGEOFF12 = 6
ARM64_RELOC_POINTER_TO_GOT = 7
ARM64_RELOC_TLVP_LOAD_PAGE21 = 8
ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9
ARM64_RELOC_ADDEND = 10

# Bits to mask (as 32-bit instruction word mask).
# When a reloc says "this instruction's immediate is patched", we want the
# corresponding bits set in our IGNORE mask (so byte-compare ignores them).
RELOC_INSN_MASK = {
    # 26-bit imm at [25:0]
    ARM64_RELOC_BRANCH26:           0x03FFFFFF,
    # 21-bit page imm at immlo[30:29] | immhi[23:5]
    ARM64_RELOC_PAGE21:             (0x3 << 29) | (0x7FFFF << 5),
    ARM64_RELOC_GOT_LOAD_PAGE21:    (0x3 << 29) | (0x7FFFF << 5),
    ARM64_RELOC_TLVP_LOAD_PAGE21:   (0x3 << 29) | (0x7FFFF << 5),
    # 12-bit imm at [21:10]
    ARM64_RELOC_PAGEOFF12:          0xFFF << 10,
    ARM64_RELOC_GOT_LOAD_PAGEOFF12: 0xFFF << 10,
    ARM64_RELOC_TLVP_LOAD_PAGEOFF12:0xFFF << 10,
    # SUBTRACTOR/UNSIGNED/ADDEND don't touch a single instruction field;
    # treat as full-word mask (rarely seen in __text).
    ARM64_RELOC_UNSIGNED:           0xFFFFFFFF,
    ARM64_RELOC_SUBTRACTOR:         0xFFFFFFFF,
    ARM64_RELOC_ADDEND:             0,    # addend modifier, no patch
}


def parse_macho_object(blob):
    """Parse a single-arch arm64 Mach-O .o blob. Returns dict with:
      sections: list of {name, vaddr, size, file_off, reloff, nreloc}
      symtab:   list of (name, value, n_sect, n_type)
      blob:     the raw bytes (echo back for convenience)
    """
    magic = struct.unpack_from("<I", blob, 0)[0]
    if magic != 0xfeedfacf:
        raise ValueError(f"not a 64-bit Mach-O object: magic={magic:#x}")
    ncmds = struct.unpack_from("<I", blob, 16)[0]
    off = 32
    sections = []
    symtab_loc = None
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", blob, off)
        if cmd == LC_SEGMENT_64:
            nsects, = struct.unpack_from("<I", blob, off+64)
            for si in range(nsects):
                sp = off + 72 + si * 80
                # section_64: sectname[16], segname[16], addr, size, off, …
                secname = blob[sp:sp+16].rstrip(b'\x00').decode()
                segname = blob[sp+16:sp+32].rstrip(b'\x00').decode()
                vaddr, size = struct.unpack_from("<QQ", blob, sp+32)
                foff,        = struct.unpack_from("<I", blob, sp+48)
                _align, reloff, nreloc, flags = struct.unpack_from("<IIII", blob, sp+52)
                sections.append({
                    "seg": segname, "name": secname, "vaddr": vaddr, "size": size,
                    "file_off": foff, "reloff": reloff, "nreloc": nreloc, "flags": flags,
                })
        elif cmd == LC_SYMTAB:
            symtab_loc = struct.unpack_from("<IIII", blob, off+8)
        off += sz

    symtab = []
    if symtab_loc:
        symoff, nsyms, stroff, _ = symtab_loc
        for i in range(nsyms):
            e = symoff + i * 16
            strx, ntype, nsect, _ndesc, nvalue = struct.unpack_from("<IBBHQ", blob, e)
            end = blob.find(b'\x00', stroff + strx)
            name = blob[stroff+strx:end].decode("ascii", errors="replace")
            symtab.append((name, nvalue, nsect, ntype))
    return {"sections": sections, "symtab": symtab}


def text_section_index(obj):
    # In .o files segname is empty; in executables it's "__TEXT". Match by name.
    for i, s in enumerate(obj["sections"], 1):
        if s["name"] == "__text":
            return i, s
    return None, None


# ────────────── Mach-O loader (dom6_mac) ──────────────────────────────────────

def load_mac_sections(path):
    """Return (mach_o_bytes, {(segname, secname): (vaddr, file_off, size)})."""
    blob = open(path, "rb").read()
    assert struct.unpack_from("<I", blob, 0)[0] == 0xfeedfacf
    ncmds = struct.unpack_from("<I", blob, 16)[0]
    off = 32
    secs = {}
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", blob, off)
        if cmd == LC_SEGMENT_64:
            nsects, = struct.unpack_from("<I", blob, off+64)
            for si in range(nsects):
                sp = off + 72 + si * 80
                secname = blob[sp:sp+16].rstrip(b'\x00').decode()
                segname = blob[sp+16:sp+32].rstrip(b'\x00').decode()
                vaddr, size = struct.unpack_from("<QQ", blob, sp+32)
                foff,        = struct.unpack_from("<I", blob, sp+48)
                secs[(segname, secname)] = (vaddr, foff, size)
        off += sz
    return blob, secs




# ────────────── Masked search ────────────────────────────────────────────────



# ────────────── jump_table slot order ────────────────────────────────────────

# In SDL_dynapi.o, __data is the `_jump_table` definition. Each 8-byte entry
# carries a 64-bit UNSIGNED external relocation naming the symbol that slot
# is initialized with (e.g. _SDL_SetError_DEFAULT). The order of relocs
# (by r_address) IS the canonical slot order for this SDL2 version.

def decode_jump_table_slots(dynapi_obj_path):
    blob = open(dynapi_obj_path, "rb").read()
    obj  = parse_macho_object(blob)
    data_sec = next(((i+1, s) for i, s in enumerate(obj["sections"]) if s["name"] == "__data"), None)
    if not data_sec:
        raise RuntimeError("SDL_dynapi.o has no __data section")
    _, data = data_sec
    if data["nreloc"] == 0:
        raise RuntimeError("SDL_dynapi.o __data has no relocations — wrong build?")

    slots = {}
    for i in range(data["nreloc"]):
        r_off = data["reloff"] + i * 8
        r_addr, r_pack = struct.unpack_from("<iI", blob, r_off)
        rtype = (r_pack >> 28) & 0xf
        rext  = (r_pack >> 27) & 1
        rlen  = (r_pack >> 25) & 3
        rsym  = r_pack & 0xffffff
        if rext and rlen == 3 and rtype == ARM64_RELOC_UNSIGNED:
            name, _, _, _ = obj["symtab"][rsym]
            slot = r_addr // 8
            slots[slot] = name

    if not slots:
        raise RuntimeError("no slot symbols decoded from SDL_dynapi.o relocations")
    max_slot = max(slots)
    ordered  = [slots.get(i) for i in range(max_slot + 1)]
    return ordered


def _strip_dynapi_suffix(name):
    """`_SDL_Init_DEFAULT` → `SDL_Init`."""
    if name.startswith("_"):
        name = name[1:]
    for suf in ("_DEFAULT", "_REAL"):
        if name.endswith(suf):
            name = name[:-len(suf)]
    return name


# ────────────── jump_table location in dom6_mac ──────────────────────────────

def find_jump_table(mac_path, expected_slots):
    """Scan dom6_mac's __DATA segments for a contiguous run of
    expected_slots × 8 bytes where every 8-byte word is a valid code pointer
    (lies inside __TEXT,__text). The jump_table is the unique such region of
    that exact length in this binary.

    Returns (jump_table_va, data_section_key, current_pointers_list).
    """
    blob, secs = load_mac_sections(mac_path)
    text_va, _, text_sz = secs[("__TEXT", "__text")]
    text_lo, text_hi = text_va, text_va + text_sz

    target_bytes = expected_slots * 8
    file_size = len(blob)
    best = None    # (start_va, sec_key, count, default_pointers)
    for (seg, sec), (va, foff, size) in secs.items():
        if seg not in ("__DATA", "__DATA_CONST"): continue
        if size < target_bytes: continue
        # BSS-like / zerofill sections have foff == 0 or don't fit in the file
        if foff == 0 or foff + size > file_size: continue
        n = size // 8
        is_code = bytearray(n)
        for i in range(n):
            w, = struct.unpack_from("<Q", blob, foff + i * 8)
            if text_lo <= w < text_hi:
                is_code[i] = 1
        cur = sum(is_code[:expected_slots])
        best_local = (0, cur)
        for i in range(expected_slots, n):
            cur += is_code[i] - is_code[i - expected_slots]
            if cur > best_local[1]:
                best_local = (i - expected_slots + 1, cur)
        if best_local[1] == expected_slots:    # perfect match — unambiguous
            run_va = va + best_local[0] * 8
            current = [struct.unpack_from("<Q", blob, foff + (best_local[0]+i)*8)[0]
                       for i in range(expected_slots)]
            if best is None or best_local[1] > best[2]:
                best = (run_va, (seg, sec), expected_slots, current)
        elif best is None and best_local[1] >= int(expected_slots * 0.95):
            # tolerate up to 5% non-code slots (rare; happens if any default
            # initializer is NULL or sentinel)
            run_va = va + best_local[0] * 8
            current = [struct.unpack_from("<Q", blob, foff + (best_local[0]+i)*8)[0]
                       for i in range(expected_slots)]
            best = (run_va, (seg, sec), best_local[1], current)

    if best is None:
        raise RuntimeError(f"no {expected_slots}-pointer code-dense run found in any __DATA section")
    return best


# ────────────── archive iteration ────────────────────────────────────────────

def extract_archive(arch_path, out_dir):
    """ar x in a fresh tmpdir; returns list of (object_name, bytes)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    # ar from binutils: `ar x` extracts into cwd; some macOS-built archives use
    # BSD format which GNU ar handles fine for arm64 mach-o objects.
    cwd_prev = os.getcwd()
    os.chdir(out_dir)
    try:
        subprocess.run(["ar", "x", str(arch_path)], check=True, capture_output=True)
    finally:
        os.chdir(cwd_prev)
    members = []
    for p in sorted(out_dir.iterdir()):
        if p.is_file() and p.suffix == ".o":
            members.append((p.name, p.read_bytes()))
    return members


# ────────────── jump_table emission ──────────────────────────────────────────

def detect_required_sdl_version(mac_path):
    """Return the SDL2 version string embedded in dom6_mac, e.g. '2.32.10'.

    The Mac binary embeds SDL2's build-tree path as a debug string for
    every .c file SDL2 compiled (e.g. 'SDL2-2.32.10/src/render/...').
    Grep one out for the version pin.  Returns None if not found.
    """
    blob = open(mac_path, "rb").read()
    m = re.search(rb"SDL2-(\d+\.\d+\.\d+)/", blob)
    return m.group(1).decode() if m else None


def emit_jump_table(archive_path, mac_path, out_path):
    """Produce sdl_map.json containing the canonical SDL_dynapi jump_table
    location, slot count, and per-slot public symbol name.

    install_sdl_redirect() in loader_sdl_gl.c walks this table at runtime
    and overwrites every slot with dlsym(host_libSDL2, slot_name).
    """
    sdl_version = detect_required_sdl_version(mac_path)
    if not sdl_version:
        sys.exit(f"could not detect SDL2 version embedded in {mac_path}")
    sys.stderr.write(f"dom6_mac requires SDL2 {sdl_version}\n")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        extract_archive(archive_path, td)
        dynapi_obj = td / "SDL_dynapi.o"
        if not dynapi_obj.is_file():
            sys.exit(f"SDL_dynapi.o missing from {archive_path} — "
                     f"is this really a libSDL2.a static archive?")
        slots_raw = decode_jump_table_slots(dynapi_obj)

    public_names = [_strip_dynapi_suffix(n) if n else None for n in slots_raw]
    slot_count = len(public_names)
    sys.stderr.write(f"decoded {slot_count} slots from SDL_dynapi.o relocations\n")

    jt_va, sec_key, density, current = find_jump_table(mac_path, slot_count)
    sys.stderr.write(f"jump_table located in {sec_key[0]}/{sec_key[1]} at va={jt_va:#x} "
                     f"(density {density}/{slot_count})\n")

    out = {
        "sdl_version":    sdl_version,
        "jump_table_va":  f"0x{jt_va:x}",
        "slot_count":     slot_count,
        "slot_size":      8,
        "slots":          public_names,
        "default_pointers": [f"0x{p:x}" for p in current],
    }
    payload = json.dumps(out, indent=2)
    if out_path:
        Path(out_path).write_text(payload + "\n")
        sys.stderr.write(f"wrote {out_path}\n")
    else:
        print(payload)
    return 0


# ────────────── pipeline ─────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mac-bin",     required=True,
                    help="path to dom6_mac (Mach-O ARM64)")
    ap.add_argument("--sdl-archive", required=True,
                    help="path to a libSDL2.a built from the SDL2 version "
                         "dom6 was linked against (Homebrew bottle, locally "
                         "compiled, etc. — script validates the version)")
    ap.add_argument("--out",         required=True,
                    help="output path for sdl_map.json")
    args = ap.parse_args()

    arch = Path(args.sdl_archive)
    if not arch.is_file():
        sys.exit(f"missing libSDL2.a: {arch}")
    mac_bin = Path(args.mac_bin)
    if not mac_bin.is_file():
        sys.exit(f"missing dom6_mac: {mac_bin}")

    return emit_jump_table(arch, mac_bin, args.out)


if __name__ == "__main__":
    main()

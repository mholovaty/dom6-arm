#!/usr/bin/env python3
"""
build_loader.py — emit data tables (build/loader/gen/*.inc) that the
hand-written loader sources in src/ #include at compile time.

Reads dom6_mac (Mach-O ARM64), classifies every imported symbol, and
writes:

  build/loader/gen/
  ├── shim_enum.inc      enum body: SHIM__<sym> = N, …
  ├── shim_table.inc     shim_names[] + shim_kinds[]
  ├── shim_thunks.inc    per-symbol `nop_X` thunk definitions
  ├── sdl_redirect.inc   host_X externs + sdl_va_X wrappers + sdl_redirects[]
  ├── gl_redirect.inc    gl_redirects[] table
  ├── got_bindings.inc   body of fill_got()
  ├── segments.inc       body of mmap_segments() (mmap calls per Mach-O seg)
  └── entry.inc          #define MAC_ENTRYPOINT 0x…UL

The hand-written sources in src/ are the source of truth for loader
behaviour; this script is the source of truth for binary-dependent data
only.  See src/README.md for the file layout and how things glue together.

Adding/removing a Mac symbol from the shim table: edit classify_symbol,
LIBC_DIRECT, SPECIAL_SLOTS below; .inc files regenerate on next build.

Adding a new ABI shim function (e.g. a new mac_X): edit src/loader_shims.c
directly and add a mapping in SPECIAL_SLOTS so fill_got points the GOT
slot at it.  No change to this script needed.
"""

import os
import sys
import json
import lief
from pathlib import Path

REPO    = Path(__file__).resolve().parent.parent
# Defaults — overridden by main()'s argparse before any data is read.
MAC_BIN = REPO / "origin" / "dom6_mac"
GEN_DIR = REPO / "data" / sorted(p.name for p in (REPO / "data").iterdir())[-1] \
    if (REPO / "data").is_dir() else REPO / "data"

# ── Symbol classification ────────────────────────────────────────────────────

# Standard POSIX/C/math/pthread symbols: strip one leading '_' → Linux name.
# These get GOT slots filled with direct host-libc pointers.
LIBC_DIRECT = {
    # math
    '_acos','_acosf','_asin','_asinf','_atan','_atan2','_atan2f','_atanf',
    '_cos','_cosf','_exp','_expf','_fmod','_fmodf','_frexp','_hypotf',
    '_log','_log10','_log10f','_logf','_modf','_pow','_powf','_scalbn',
    '_scalbnf','_sin','_sinf','_sqrt','_sqrtf','_tan','_tanf',
    # string
    '_memchr','_memcmp','_memcpy','_memmove','_memset',
    '_strcat','_strchr','_strcasecmp','_strcasestr','_strcmp','_strcpy',
    '_strcspn','_strdup','_strerror','_strftime','_strlen','_strncasecmp',
    '_strncmp','_strncpy','_strrchr','_strstr','_strtod','_strtok_r',
    '_strtol','_strtoll','_strtoul','_strtoull','_snprintf','_sprintf',
    '_sscanf','_bzero',
    # wide string
    '_wcscasecmp','_wcscmp','_wcscpy','_wcslen','_wcsncasecmp','_wcsncmp',
    '_wcsstr','_wcslcat','_wcslcpy',
    # strlcpy/strlcat (glibc 2.38+ / libbsd)
    '_strlcpy','_strlcat',
    # stdio (non-variadic / fixed-arg only)
    # _fopen routed via SPECIAL_SLOTS → mac_fopen.
    # _fclose routed via SPECIAL_SLOTS → mac_fclose (plugin close callback).
    '_feof','_ferror','_fflush','_fgets','_fileno',
    '_fputc','_fputs','_fread','_fseek','_fseeko',
    '_fstat','_ftell','_ftello','_fwrite','_perror','_putchar',
    '_puts','_rewind','_setlinebuf',
    # stdlib
    '_abort','_abs','_atexit','_atof','_atoi','_bsearch','_calloc',
    '_exit','_free','_getenv','_malloc','_putenv','_qsort','_rand',
    '_realloc','_remove','_rmdir','_setenv','_srand','_system',
    '_freelocale','_newlocale','_setlocale','_uselocale',
    # POSIX I/O.  _open/_mkdir/_fopen are routed via SPECIAL_SLOTS to
    # mac_open / mac_mkdir / mac_fopen (path-translation shim for Win
    # drop-in compat).  _fcntl uses mac_fcntl (O_NONBLOCK/O_APPEND
    # constants differ).
    # _readdir routed via SPECIAL_SLOTS → mac_readdir (dirent layout differs).
    '_closedir','_mmap','_mprotect','_munmap',
    '_opendir','_pclose','_popen','_read','_rewinddir',
    '_stat','_sysconf','_write',
    # POSIX network
    '_gethostbyname','_gethostname',
    '_inet_addr','_inet_ntoa',
    # _send / _recv / _socket / _bind / … handled via mac_* shims (see SPECIAL_SLOTS)
    # POSIX process/signal/time
    '_fork','_gettimeofday','_gmtime','_kill','_localtime','_ctime',
    '_nanosleep','_sigaction','_signal','_time','_waitpid',
    '_sched_get_priority_max','_sched_get_priority_min',
    '_setjmp','_longjmp',
    # zlib
    '_compress','_crc32','_deflate','_deflateEnd','_deflateInit2_',
    '_deflateReset','_inflate','_inflateEnd','_inflateInit2_',
    '_inflateReset','_inflateReset2','_uncompress',
    # bzip2
    '_BZ2_bzDecompress','_BZ2_bzDecompressEnd','_BZ2_bzDecompressInit',
    # dl — handled via custom wrappers (see SPECIAL_SLOTS)
    '_dlerror',
    # misc POSIX
    '_realpath$DARWIN_EXTSN',
    '_sysctl','_sysctlbyname',
    '_memset_pattern16',
    # pthread (full set)
    '_pthread_attr_destroy','_pthread_attr_init','_pthread_attr_setstacksize',
    '_pthread_attr_setdetachstate',
    '_pthread_cancel','_pthread_cond_broadcast','_pthread_cond_destroy',
    '_pthread_cond_init','_pthread_cond_signal','_pthread_cond_timedwait',
    '_pthread_cond_wait','_pthread_create','_pthread_detach','_pthread_equal',
    '_pthread_getschedparam','_pthread_getspecific',
    '_pthread_join',
    '_pthread_key_create','_pthread_key_delete',
    '_pthread_mutex_destroy','_pthread_mutex_init',
    '_pthread_mutex_lock','_pthread_mutex_trylock','_pthread_mutex_unlock',
    '_pthread_mutexattr_init','_pthread_mutexattr_settype',
    '_pthread_self','_pthread_setcanceltype','_pthread_setschedparam',
    '_pthread_setspecific','_pthread_sigmask',
    # ctype
    '_toupper',
}

# OpenGL/GLU — every gl* / glu* slot is filled at runtime by
# install_gl_redirect (src/loader_sdl_gl.c), which dlopens libGL.so.1 /
# opengl32.dll and overwrites the GOT entries with the host pointers.
# We classify these as nop_func bindings (kind='special', val='mac_nop_func')
# specifically so that fill_got does NOT take their addresses by name —
# otherwise the PE linker resolves them statically against opengl32.dll
# at process startup, before main() runs, which would bind the binary to
# the stock Win-on-ARM GDI software GL 1.1 and prevent our bundled Mesa
# zink build from taking over.
GL_NOP_SYMBOLS = {
    '_glAlphaFunc','_glBegin','_glBindTexture','_glBlendFunc','_glCallList',
    '_glClear','_glClearColor','_glColor3f','_glColor3fv','_glColor3ub',
    '_glColor4f','_glColorMaterial','_glColorPointer',
    '_glDeleteLists','_glDeleteTextures','_glDepthMask',
    '_glDisable','_glDisableClientState','_glDrawArrays','_glDrawElements',
    '_glEnable','_glEnableClientState','_glEnd','_glEndList',
    '_glFinish','_glFlush','_glFogf','_glFogfv','_glFogi',
    '_glGenLists','_glGenTextures',
    '_glGetDoublev','_glGetError','_glGetIntegerv','_glGetString',
    '_glHint','_glLightModeli','_glLightfv','_glLineWidth',
    '_glLoadIdentity','_glMaterialf','_glMaterialfv','_glMatrixMode',
    '_glNewList','_glNormal3fv','_glPixelStorei',
    '_glPopMatrix','_glPushMatrix',
    '_glRotatef','_glScalef','_glScissor','_glShadeModel',
    '_glTexCoord2f','_glTexCoord2fv','_glTexCoordPointer','_glTexEnvi',
    '_glTexImage2D','_glTexParameteri','_glTranslatef',
    '_glVertex3f','_glVertex3fv','_glVertexPointer','_glViewport',
    '_gluBuild2DMipmaps','_gluErrorString','_gluOrtho2D',
    '_gluPerspective','_gluProject','_gluUnProject',
}

# When the host name differs from "<mac_name minus leading _>"
LIBC_RENAME = {
    '_realpath$DARWIN_EXTSN': 'realpath',
    '_memset_pattern16':      'mac_memset_pattern16',
    '_sysctl':                'mac_sysctl_stub',
    '_sysctlbyname':          'mac_sysctlbyname_stub',
}

# Custom mac_* shims and special data symbols — these get GOT slots filled
# with hand-written functions/variables defined in src/loader_shims.c.
SPECIAL_SLOTS = {
    # Variadic (Mac AArch64 stack-vararg) — naked-asm in loader_shims.c
    '_printf':                'mac_printf',
    '_fprintf':               'mac_fprintf',
    '_sprintf':               'mac_sprintf',
    '_snprintf':              'mac_snprintf',
    '_scanf':                 'mac_scanf',
    '_fscanf':                'mac_fscanf',
    '_sscanf':                'mac_sscanf',
    '_vsnprintf':             'mac_vsnprintf',
    '_vfprintf':              'mac_vfprintf',
    '_vsscanf':               'mac_vsscanf',
    '_vprintf':               'mac_vprintf',
    '_vsprintf':              'mac_vsprintf',
    # Mac FILE** indirection — point at our pointer-to-FILE*
    '___stdoutp':            'mac_stdoutp_ptr',
    '___stdinp':             'mac_stdinp_ptr',
    '___stderrp':            'mac_stderrp_ptr',
    '___stack_chk_guard':    '&__stack_chk_guard',
    '___error':              'mac_errno_func',
    '___chkstk_darwin':      'mac_chkstk_nop',
    '___stack_chk_fail':     'mac_stack_chk_fail_stub',
    '___sincos_stret':        'mac_sincos_stret',
    '___sprintf_chk':         '__sprintf_chk',
    '___snprintf_chk':        '__snprintf_chk',
    '___memcpy_chk':          'memcpy',
    '___memmove_chk':         'memmove',
    '___memset_chk':          'memset',
    '___strcpy_chk':          'strcpy',
    '___strlcpy_chk':         'mac_strlcpy_chk',
    '___strlcat_chk':         'mac_strlcat_chk',
    '___assert_rtn':          'mac_assert_rtn',
    '___tolower':             'tolower',
    '___maskrune':            'mac_maskrune_stub',
    '___CFConstantStringClassReference': 'mac_nop_data',
    '___objc_personality_v0': 'mac_objc_personality',
    '__DefaultRuneLocale':    'mac_nop_data',
    '__NSConcreteStackBlock': 'mac_nop_data',
    '__NSConcreteGlobalBlock':'mac_nop_data',
    '__Unwind_Resume':        'mac_unwind_resume',
    '__Block_object_assign':  'mac_nop_func',
    '__Block_object_dispose': 'mac_nop_func',
    '__objc_empty_cache':     'mac_nop_data',
    '__dispatch_main_q':      'mac_nop_data',
    '__Exit':                 '_Exit',
    'dyld_stub_binder':       'mac_nop_func',
    '_objc_msgSend':          'mac_objc_msgsend',
    '_free':                  'free',
    '_mach_absolute_time':    'mac_mach_absolute_time',
    '_mach_timebase_info':    'mac_mach_timebase_info',
    '_mach_msg':              'mac_nop_func',
    '_dispatch_async':        'mac_dispatch_async',
    '_dispatch_sync':         'mac_dispatch_sync',
    '_dispatch_once_f':       'mac_dispatch_once_f',
    '_dispatch_get_global_queue': 'mac_dispatch_get_global_queue',
    '_dispatch_data_create':  'mac_nop_func_p',
    # dl: Mac vs Linux RTLD_DEFAULT differs
    '_dlopen':   'mac_dlopen',
    '_dlsym':    'mac_dlsym',
    '_dlclose':  'mac_dlclose',
    # File I/O routed through path-translation shims so the Win32 build
    # rewrites `~/.dominions6/...` → `%APPDATA%\Dominions6\...` (drop-in
    # compat with the native Dominions6.exe Steam install) and /dev/urandom
    # routes to a BCryptGenRandom-backed temp file.  On POSIX the shims are
    # passthroughs — one extra function call per open() / fopen().
    '_open':     'mac_open',
    '_fopen':    'mac_fopen',
    '_fclose':   'mac_fclose',
    # close() must know whether the descriptor is a socket — see mac_close.
    '_close':    'mac_close',
    '_mkdir':    'mac_mkdir',
    # readdir: Mac struct dirent has d_name @21 (it carries d_namlen); Linux
    # d_name is @19.  A direct libc bind hands dom6 a Linux-layout dirent, but
    # all 11 call sites read the name via `add x,x0,#0x15` (offset 21) — so
    # every scanned filename loses its first 2 chars (ArenaDom6.map ->
    # enaDom6.map), breaking --mapfile and mod directory lookup.  mac_readdir
    # repacks the entry into the Mac dirent layout.
    '_readdir':  'mac_readdir',
    # popen: dom6 shells out to `sysctl` for hw.ncpu and kern.osrelease.
    # cmd.exe has no `sysctl` — mac_popen recognises the exact commands
    # and returns canned values so dom6's OS-version parser doesn't fail.
    '_popen':    'mac_popen',
    # exit / _Exit / abort tracing: on Win we want to know if dom6
    # terminates via one of these instead of returning from main, so we
    # can locate the early-exit decision.  Shims dump shim counters
    # before forwarding to libc.
    '_exit':     'mac_exit_trace',
    '__Exit':    'mac_Exit_trace',
    '_abort':    'mac_abort_trace',
    # sockets: Mac sockaddr has sin_len prefix; AF/SOL/SO constants differ
    '_socket':     'mac_socket',
    '_bind':       'mac_bind',
    '_connect':    'mac_connect',
    '_accept':     'mac_accept',
    '_setsockopt': 'mac_setsockopt',
    '_getsockopt': 'mac_getsockopt',
    '_getsockname':'mac_getsockname',
    '_getpeername':'mac_getpeername',
    '_sendto':     'mac_sendto',
    '_recvfrom':   'mac_recvfrom',
    '_fcntl':      'mac_fcntl',
    '_listen':     'mac_listen',
    '_recv':       'mac_recv',
    '_send':       'mac_send',
    # GL ARB extensions: need glXGetProcAddress; for now leave NOP
    '_glBindBufferARB':       'mac_nop_func',
    '_glBufferDataARB':       'mac_nop_func',
    '_glDeleteBuffersARB':    'mac_nop_func',
    '_glGenBuffersARB':       'mac_nop_func',
    '_OBJC_CLASS_$_NSBundle': 'mac_NSBundle_class',
}

# NOP prefixes: symbols starting with these get mac_nop_func / mac_nop_data
NOP_FUNC_PREFIXES = (
    '_CF', '_CG', '_NS', '_GC', '_CH', '_Audio',
    '_AX', '_CA', '_CV', '_FF',
    '_OBJC_', '_objc_', '_kC', '_kIO', '_kUT', '_kTIS',
    '_MTL', '_TIS', '_UCKey', '_KBGet', '_LMGet', '_LS',
    '_CVDisplay', '_IOKit', '_IO',
)

NOP_DATA_PREFIXES = (
    '_kCF', '_kCG', '_kNS', '_kIO', '_kUT', '_kTIS',
    '_NS', '_GC',
)


def sanitize_for_c(name):
    """`_realpath$DARWIN_EXTSN` → `realpath_DARWIN_EXTSN`."""
    if name.startswith('_'):
        name = name[1:]
    out = []
    for ch in name:
        out.append(ch if ch.isalnum() or ch == '_' else '_')
    return ''.join(out)


def classify_symbol(name):
    """Return (kind, value) where kind ∈ {libc, special, nop_func, nop_data}.

      libc:     value is the Linux symbol name (host libc/libm/libpthread/…)
      special:  value is a hand-written name from src/loader_shims.c
                (or `mac_nop_data`, `mac_NSBundle_class`, etc.)
      nop_func: value is None — slot gets a per-symbol nop_X thunk that
                bumps SHIM__<sym> when called
      nop_data: value is None — slot gets mac_nop_data (single zero pointer)
    """
    if name in SPECIAL_SLOTS:
        return ('special', SPECIAL_SLOTS[name])
    if name in GL_NOP_SYMBOLS:
        # See GL_NOP_SYMBOLS docstring: bind to mac_nop_func so the
        # PE / ELF linker never resolves the real opengl32 / libGL
        # symbol statically.  install_gl_redirect() rewrites these
        # slots at startup with dlsym'd pointers from the host's GL.
        return ('special', 'mac_nop_func')
    if name in LIBC_DIRECT:
        linux_name = LIBC_RENAME.get(name, name.lstrip('_'))
        return ('libc', linux_name)
    if name.startswith(NOP_DATA_PREFIXES):
        return ('nop_data', None)
    if name.startswith(NOP_FUNC_PREFIXES):
        return ('nop_func', None)
    return ('nop_func', None)


# ── Shim-counter table (every symbol gets a unique SHIM__<id>) ────────────────

def build_shim_table(sym_map):
    """Return [(mac_name, enum_id, kind, value)] sorted by sanitized id.

    Used to:
      • emit gen/shim_enum.inc (SHIM__<id> = N enumeration)
      • emit gen/shim_table.inc (shim_names[], shim_kinds[])
      • emit gen/shim_thunks.inc (nop_X thunk per nop_func entry)
      • point each nop_func GOT slot at its own thunk (for per-symbol
        runtime hit counts — diagnose which Mac APIs are actually used)
    """
    rows = []
    seen_eid = {}
    for mac, (kind, val) in sym_map.items():
        eid_base = 'SHIM__' + sanitize_for_c(mac)
        eid = eid_base
        n = 1
        while eid in seen_eid:
            n += 1
            eid = f"{eid_base}_{n}"
        seen_eid[eid] = mac
        rows.append((mac, eid, kind, val))
    rows.sort(key=lambda r: r[1])
    return rows


# ── SDL2 variadic ABI helpers ─────────────────────────────────────────────────

# SDL2 public APIs that are variadic. Mac AArch64 ABI puts varargs on the
# STACK; Linux AArch64 puts the first 8 args (named + variadic combined) in
# x0..x7 and the rest on stack. For each, the generated naked-asm wrapper
# re-marshals stack-vararg → register-vararg before tail-calling the host.
# The integer is the count of NAMED args (varargs start in register x_<named>).
SDL_VARARG_FUNCS = {
    "SDL_SetError":    1,
    "SDL_Log":         1,
    "SDL_LogVerbose":  2,
    "SDL_LogDebug":    2,
    "SDL_LogInfo":     2,
    "SDL_LogWarn":     2,
    "SDL_LogError":    2,
    "SDL_LogCritical": 2,
    "SDL_LogMessage":  3,
    "SDL_sscanf":      2,
    "SDL_snprintf":    3,
}


def emit_va_wrapper(sym, named_count):
    """Naked-asm SDL variadic wrapper.  Loads (8 - named) varargs from the
    Mac caller's stack into x_named..x7, then tail-calls the stored host
    function pointer. See doc/abi-differences.md, the loader_mac_variadic
    _stack_abi memory note, and src/loader_shims.c (mac_fcntl) for the
    same pattern at the libc boundary."""
    asm_lines = []
    offset = 0
    reg = named_count
    while reg + 1 < 8:
        asm_lines.append(f'"ldp x{reg}, x{reg+1}, [sp, #{offset}]\\n"')
        offset += 16
        reg    += 2
    while reg < 8:
        asm_lines.append(f'"ldr x{reg}, [sp, #{offset}]\\n"')
        offset += 8
        reg    += 1
    asm_lines.append(f'"adrp x16, host_{sym}\\n"')
    asm_lines.append(f'"add x16, x16, :lo12:host_{sym}\\n"')
    asm_lines.append('"ldr x16, [x16]\\n"')
    asm_lines.append('"br x16\\n"')
    asm_body = "\n            ".join(asm_lines)
    return (
        f"extern void *host_{sym};\n"
        f"__attribute__((naked, used))\n"
        f"static void sdl_va_{sym}(void) {{\n"
        f"    __asm__ volatile(\n"
        f"            {asm_body}\n"
        f"    );\n"
        f"}}\n"
    )


def load_sdl_jump_table_map():
    """Load the committed SDL dynapi layout snapshot (`data/sdl_map.json`).

    Records, for the dom6_mac build this loader targets, the virtual
    address of SDL2's dynapi jump_table inside the binary plus the
    ordered list of function slots it contains.  install_sdl_redirect()
    in loader_sdl_gl.c walks this table at runtime, replacing each slot
    with the host libSDL2 pointer of the same name.
    """
    map_path = GEN_DIR / "sdl_map.json"
    if not map_path.exists():
        sys.exit(f"missing {map_path} — expected committed alongside the .inc files")
    return json.loads(map_path.read_text())


# ── .inc emitters ─────────────────────────────────────────────────────────────

HEADER = "/* GENERATED by tools/build_loader.py — DO NOT EDIT */"


def emit_shim_files(shim_table):
    """Three small .inc files describing the per-symbol counter table.
    Hand-written src/loader_counters.[ch] and src/loader_shims.c
    consume them.  See src/loader_counters.h for the SHIM_HIT macro
    definition."""

    # shim_enum.inc — enum body included inside src/loader_counters.h
    lines = [HEADER, "enum {"]
    for i, (_mac, eid, _k, _v) in enumerate(shim_table):
        lines.append(f"    {eid} = {i},")
    lines.append(f"    SHIM_COUNT = {len(shim_table)}")
    lines.append("};")
    (GEN_DIR / "shim_enum.inc").write_text("\n".join(lines) + "\n")

    # shim_table.inc — names[] + kinds[], consumed by loader_counters.c
    KIND_CODE = {'nop_func': 0, 'nop_data': 1, 'libc': 2, 'special': 3}
    lines = [HEADER, "", "static const char * const shim_names[SHIM_COUNT] = {"]
    for mac, _eid, _k, _v in shim_table:
        esc = mac.replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f'    "{esc}",')
    lines.append("};")
    lines.append("")
    lines.append("static const unsigned char shim_kinds[SHIM_COUNT] = {")
    row = []
    for _mac, _eid, kind, _v in shim_table:
        row.append(str(KIND_CODE[kind]))
        if len(row) >= 32:
            lines.append('    ' + ', '.join(row) + ',')
            row = []
    if row:
        lines.append('    ' + ', '.join(row))
    lines.append("};")
    (GEN_DIR / "shim_table.inc").write_text("\n".join(lines) + "\n")

    # shim_thunks.inc — per-symbol nop_X thunks, consumed by loader_shims.c
    lines = [HEADER, ""]
    for _mac, eid, kind, _v in shim_table:
        if kind != 'nop_func':
            continue
        fn = 'nop_' + eid[len('SHIM__'):]
        lines.append(f"static int {fn}(void) {{ SHIM_HIT({eid}); return 0; }}")
    (GEN_DIR / "shim_thunks.inc").write_text("\n".join(lines) + "\n")


def emit_sdl_redirect(sdl_map):
    """gen/sdl_redirect.inc — host_X void* per public slot, naked-asm wrappers
    per variadic slot, and the sdl_redirects[] table.  Consumed by
    src/loader_sdl_gl.c which provides the surrounding typedef + install fn."""
    slots = sdl_map["slots"]
    public_names = sorted({n for n in slots if n})

    lines = [HEADER, ""]

    lines.append("/* host_X function-pointer storage — one per public dynapi slot. */")
    for sym in public_names:
        lines.append(f"void *host_{sym};")
    lines.append("")

    lines.append("/* Variadic ABI wrappers — one per variadic public SDL function. */")
    for sym, narg in SDL_VARARG_FUNCS.items():
        if sym in public_names:
            lines.append(emit_va_wrapper(sym, narg))

    lines.append("/* Redirect descriptor table: { name, slot, va_wrapper, host_ptr_p }. */")
    lines.append("static const sdl_redirect_entry_t sdl_redirects[] = {")
    for i, name in enumerate(slots):
        if not name:
            continue
        if name in SDL_VARARG_FUNCS:
            lines.append(f'    {{"{name}", {i}, (const void*)sdl_va_{name}, &host_{name}}},')
        else:
            lines.append(f'    {{"{name}", {i}, (void*)0, (void**)0}},')
    lines.append("};")
    lines.append("#define SDL_REDIRECT_COUNT (sizeof(sdl_redirects)/sizeof(sdl_redirects[0]))")
    (GEN_DIR / "sdl_redirect.inc").write_text("\n".join(lines) + "\n")


def emit_gl_redirect(gl_imports):
    """gen/gl_redirect.inc — the gl_redirects[] table.  Consumed by
    src/loader_sdl_gl.c."""
    lines = [HEADER, "", "static const gl_redirect_entry_t gl_redirects[] = {"]
    for slot_addr, name in gl_imports:
        bare = name[1:] if name.startswith("_") else name
        is_glu = 1 if bare.startswith("glu") else 0
        lines.append(f'    {{ 0x{slot_addr:016x}UL, "{bare}", {is_glu} }},')
    lines.append("};")
    lines.append("#define GL_REDIRECT_COUNT (sizeof(gl_redirects)/sizeof(gl_redirects[0]))")
    (GEN_DIR / "gl_redirect.inc").write_text("\n".join(lines) + "\n")


def emit_got_bindings(binding_slots, sym_map, shim_table):
    """gen/got_bindings.inc — body of fill_got() (just the slot writes).
    Consumed by src/loader_shims.c inside the fill_got function body."""
    sym_to_enum = {row[0]: row[1] for row in shim_table}
    lines = [HEADER, ""]
    for addr, name in binding_slots:
        kind, val = sym_map.get(name, ('nop_func', None))
        if kind == 'special':
            expr = f"(uint64_t)(void*){val}"
            if val.startswith('&') and not val.startswith('&mac_nop'):
                expr = f"(uint64_t){val}"
        elif kind == 'libc':
            expr = f"(uint64_t)(void*){val}"
        else:
            # nop_func/nop_data: bind to per-symbol thunk for runtime traces
            eid = sym_to_enum[name]
            thunk = 'nop_' + eid[len('SHIM__'):]
            expr = f"(uint64_t)(void*){thunk}" if kind == 'nop_func' else \
                   f"(uint64_t)(void*)mac_nop_data"
        lines.append(f"    slot = (volatile uint64_t*)0x{addr:016x}UL;")
        lines.append(f"    *slot = {expr};  /* {name} */")
    (GEN_DIR / "got_bindings.inc").write_text("\n".join(lines) + "\n")


def emit_segments(segments):
    """gen/segments.inc — body of mmap_segments() (one os_map_fixed call per
    LC_SEGMENT_64).  Consumed by src/loader_main.c inside the mmap_segments
    function body.  Uses the OS abstraction so the same .inc compiles on
    both POSIX (loader_os_posix.c) and Win32 (future loader_os_win32.c)."""
    lines = [HEADER]
    for seg in segments:
        va    = seg['va']
        fsz   = seg['file_size']
        vsz   = seg['virt_size']
        foff  = seg['file_off']
        sname = seg['name']
        if fsz > 0:
            prot = "OS_PROT_READ|OS_PROT_EXEC" if sname == '__TEXT' \
                   else "OS_PROT_READ|OS_PROT_WRITE"
            lines.append(f"    /* {sname}: VA={va:#x}, file_size={fsz:#x} */")
            lines.append(f"    if (os_map_fixed(0x{va:x}UL, 0x{fsz:x}UL, {prot}, fd, 0x{foff:x}UL) != 0) {{")
            lines.append(f"        fprintf(stderr, \"[loader] mmap {sname} failed\\n\"); close(fd); return -1;")
            lines.append("    }")
        if vsz > fsz:
            bss_va = va + fsz
            bss_sz = vsz - fsz
            lines.append(f"    /* {sname} BSS: {bss_va:#x}, size={bss_sz:#x} */")
            lines.append(f"    if (os_map_fixed(0x{bss_va:x}UL, 0x{bss_sz:x}UL, OS_PROT_READ|OS_PROT_WRITE, -1, 0) != 0) {{")
            lines.append(f"        fprintf(stderr, \"[loader] mmap {sname} BSS failed\\n\"); close(fd); return -1;")
            lines.append("    }")
    (GEN_DIR / "segments.inc").write_text("\n".join(lines) + "\n")


def emit_entry(entry_va):
    """gen/entry.inc — Mac binary's _main address (LC_MAIN target)."""
    (GEN_DIR / "entry.inc").write_text(
        f"{HEADER}\n#define MAC_ENTRYPOINT 0x{entry_va:016x}UL\n")


def emit_sdl_table(sdl_map):
    """gen/sdl_table.inc — where SDL2's dynapi jump_table sits, and how big it is.

    Both move with the build. A number that is derived and then retyped by hand is one that
    will eventually disagree with the binary it describes.
    """
    va = sdl_map["jump_table_va"]
    va = int(va, 16) if isinstance(va, str) else int(va)
    (GEN_DIR / "sdl_table.inc").write_text(
        f"{HEADER}\n"
        f"#define SDL_JUMP_TABLE_VA  0x{va:016x}UL\n"
        f"#define SDL_SLOT_COUNT     {int(sdl_map['slot_count'])}\n")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    global MAC_BIN, GEN_DIR
    ap = argparse.ArgumentParser(
        description="Regenerate the binary-dependent .inc data tables for one "
                    "dom6 release.  Writes into --out (default: the newest data/<ver>/).")
    ap.add_argument("--mac-bin", default=str(MAC_BIN),
                    help="path to dom6_mac (default: origin/dom6_mac)")
    ap.add_argument("--out", default=str(GEN_DIR),
                    help="output directory for the .inc data tables")
    args = ap.parse_args()
    MAC_BIN = Path(args.mac_bin).resolve()
    GEN_DIR = Path(args.out).resolve()
    GEN_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[build_loader] parsing {MAC_BIN}…")
    fat = lief.MachO.parse(str(MAC_BIN))
    if fat is None:
        sys.exit(f"lief failed to parse {MAC_BIN}")
    binary = fat.at(0)

    # Build sym_map = {mac_name: (kind, value)}
    sym_map = {}
    for b in binary.bindings:
        if b.symbol and b.symbol.name not in sym_map:
            sym_map[b.symbol.name] = classify_symbol(b.symbol.name)
    # Add SPECIAL_SLOTS too — even if not bound in this build, their enum
    # IDs are referenced by hand-written shim function bodies.
    for n in SPECIAL_SLOTS:
        if n not in sym_map:
            sym_map[n] = classify_symbol(n)

    shim_table = build_shim_table(sym_map)
    print(f"[build_loader]   {len(sym_map)} unique imports → {len(shim_table)} shim slots")

    # Mach-O segments (skip __PAGEZERO/__LINKEDIT — not loaded into memory)
    segments = []
    for seg in binary.segments:
        if seg.name in ('__PAGEZERO', '__LINKEDIT'):
            continue
        segments.append({
            'name': seg.name,
            'va':   seg.virtual_address,
            'file_size': seg.file_size,
            'virt_size': seg.virtual_size,
            'file_off':  seg.file_offset,
        })
    print(f"[build_loader]   {len(segments)} segments to mmap")

    # GOT/__la_symbol_ptr slots.  lief types symbol.name as `str | bytes`;
    # in practice it's always str for Mach-O — coerce so downstream type
    # inference works.
    binding_slots: list[tuple[int, str]] = [
        (b.address, str(b.symbol.name))
        for b in sorted(binary.bindings, key=lambda x: x.address)
        if b.symbol
    ]
    print(f"[build_loader]   {len(binding_slots)} GOT slots to fill")

    # gl/glu slots to redirect (their host pointer comes via dlsym at startup)
    gl_imports = [(addr, name) for addr, name in binding_slots
                  if name.startswith("_gl") and len(name) >= 4
                  and (name[3].isupper() or name[3] in "uXc")]
    print(f"[build_loader]   {len(gl_imports)} gl/glu slots for host-libGL redirect")

    sdl_map = load_sdl_jump_table_map()
    print(f"[build_loader]   {sdl_map['slot_count']} SDL dynapi slots @ {sdl_map['jump_table_va']}")

    # Emit data files
    emit_shim_files(shim_table)
    emit_sdl_redirect(sdl_map)
    emit_gl_redirect(gl_imports)
    emit_got_bindings(binding_slots, sym_map, shim_table)
    emit_segments(segments)
    emit_entry(binary.entrypoint)
    emit_sdl_table(sdl_map)

    # GEN_DIR was resolved to an absolute path; print relative to REPO when
    # under it, else just print the absolute path.
    def _show(p):
        try:
            return p.relative_to(REPO)
        except ValueError:
            return p
    print(f"[build_loader] data files in {_show(GEN_DIR)}/")
    for p in sorted(GEN_DIR.glob("*.inc")):
        print(f"  {_show(p)}  ({p.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()

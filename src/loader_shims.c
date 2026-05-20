/* loader_shims.c — macOS → Linux ABI shims for the Mac binary's libc/system
 * calls.  These are the targets that fill_got() points GOT/__la_symbol_ptr
 * slots at.  Each shim translates argument layout, struct field order, flag
 * values, etc. between the two ABIs.
 *
 * Naming convention:  mac_<symname>  → installed into the Mac binary's
 * GOT slot for `_<symname>`.  E.g. mac_recv shims `_recv`, mac_fcntl
 * shims `_fcntl`.
 *
 * A few variadic shims (mac_fcntl, mac_printf, mac_snprintf, ...) use
 * naked-asm wrappers to handle the Mac AArch64 stack-vararg convention
 * — see doc/abi-differences.md and the loader_mac_variadic_stack_abi
 * memory note. */
#include "loader_common.h"
#include "loader_counters.h"

/* ── NOP stubs ──────────────────────────────────────────────────── */
static int       mac_nop_func(void)    { return 0; }
static void     *mac_nop_func_p(void)  { return NULL; }
static void      mac_nop_v(void)        { }
static uint64_t  mac_nop_data_val = 0;
static void     *mac_nop_data = &mac_nop_data_val;


/* ── NSBundle shim ───────────────────────────────────────────────── *
 * The Mac binary uses [NSBundle mainBundle] + bundlePath/resourcePath
 * to locate game data as "<bundle_base>/../data/".  We fake just
 * enough of the ObjC runtime to make that work.
 *
 * Bundle base = dirname(DOM6_MAC_PATH)/MacOS  (a virtual subdir).
 * Appending "/../data" → dirname(DOM6_MAC_PATH)/data  ✓
 */
static uint64_t mac_NSBundle_class_val = 0x4E534255ULL; /* "NSBU" */
static void    *mac_NSBundle_class     = &mac_NSBundle_class_val;
static uint64_t mac_NSBundle_inst_val  = 0x4E534249ULL; /* "NSBI" */
static void    *mac_NSBundle_inst      = &mac_NSBundle_inst_val;
static char     mac_bundle_basepath[4096] = {0};
static void mac_bundle_init(void) {
    const char *p = getenv("DOM6_MAC_PATH");
    if (!p || !*p) p = DOM6_MAC_PATH;
    const char *slash = strrchr(p, '/');
    if (slash && slash > p) {
        snprintf(mac_bundle_basepath, sizeof(mac_bundle_basepath),
                 "%.*s/MacOS", (int)(slash - p), p);
    } else {
        char cwd[3960] = {0};
        getcwd(cwd, sizeof(cwd));
        /* p has no slash: binary is in CWD */
        snprintf(mac_bundle_basepath, sizeof(mac_bundle_basepath),
                 "%s/MacOS", cwd);
    }
    fprintf(stderr, "[dom6-loader] NSBundle base: %s\n", mac_bundle_basepath);
}

/* ── ObjC stubs ─────────────────────────────────────────────────── */
/* objc_msgSend(receiver, selector, ...) — handles only what dom6
 * actually calls for resource-path lookup; everything else is logged
 * and returns NULL. */
static void *mac_objc_msgsend(void *receiver, const char *sel) {
    SHIM_HIT(SHIM__objc_msgSend);
    if (!sel) return NULL;
    /* [NSBundle mainBundle] */
    if (receiver == mac_NSBundle_class && strcmp(sel, "mainBundle") == 0) {
        if (!mac_bundle_basepath[0]) mac_bundle_init();
        return mac_NSBundle_inst;
    }
    /* [bundle bundlePath] / [bundle resourcePath] — return fake NSString */
    if (receiver == mac_NSBundle_inst &&
        (strcmp(sel, "bundlePath") == 0 || strcmp(sel, "resourcePath") == 0)) {
        return mac_bundle_basepath;
    }
    /* [nsstring UTF8String] — our fake NSString IS the C string */
    if (receiver && receiver != mac_NSBundle_class && receiver != mac_NSBundle_inst) {
        if (strcmp(sel, "UTF8String") == 0)
            return receiver;
    }
    fprintf(stderr, "[dom6-loader] objc_msgSend(recv=%p, sel=%s) unhandled\n",
            receiver, sel);
    return NULL;
}
static void mac_objc_personality(void) {
    SHIM_HIT(SHIM____objc_personality_v0);
    fprintf(stderr, "[dom6-loader] ObjC exception personality called\n");
    abort();
}


/* ── stdio indirection (Mac FILE** → Linux FILE*) ─────────────────
 * Mac binary's __DARWIN_stdin/__stdout/__stderr are pointer-to-FILE*;
 * Linux glibc exposes plain FILE*.  main() fills the underlying values
 * after libc is ready; here we just provide storage + the indirection.
 * Extern-linkage because main() sets them from another TU. */
FILE *mac_stderr_val = NULL;
FILE *mac_stdout_val = NULL;
FILE *mac_stdin_val  = NULL;
FILE **mac_stderrp_ptr = &mac_stderr_val;
FILE **mac_stdoutp_ptr = &mac_stdout_val;
FILE **mac_stdinp_ptr  = &mac_stdin_val;


/* ── Stack protector ────────────────────────────────────────────── */
extern uintptr_t __stack_chk_guard;
/* __chkstk_darwin is called at function prologues *before* the caller
 * does `sub sp, sp, #N` for large stack frames.  Its job is to probe
 * every 4 KB page in [sp - N, sp) so the OS's stack guard mechanism
 * (or page-on-demand commit on Win) actually commits them all before
 * the caller writes into the new frame.  Calling convention:
 *   w9 = requested allocation size in bytes (zero-extended to x17)
 *   does NOT modify sp, does NOT clobber x9 or other ABI registers
 *
 * On Linux this used to be a no-op because Linux auto-grows the stack
 * via SIGSEGV+remap on any page in the guard region.  Win32 doesn't —
 * its guard page only auto-commits the *next* 4 KB; a single `sub sp,
 * sp, #0x45000` skips far past the guard into uncommitted memory and
 * the first store there access-violates.  Real implementation needed.
 *
 * Naked asm so the function has no prologue/epilogue of its own that
 * would touch the very stack we're about to probe. */
__attribute__((naked, used)) static void mac_chkstk_nop(void) {
    __asm__ volatile(
        "mov x16, sp\n"          /* x16 = current sp (probe walker)   */
        "mov w17, w9\n"          /* x17 = remaining bytes to probe    */
        "1: cmp x17, #0x1000\n"
        "b.ls 2f\n"              /* if <= 4 KB, done                  */
        "sub x16, x16, #0x1000\n"
        "ldr xzr, [x16]\n"       /* touch the page → commits it on Win */
        "sub x17, x17, #0x1000\n"
        "b 1b\n"
        "2: ret\n"
    );
}
/* Re-export the symbol as a forced reference so the enum stays used
 * (atomic_load_explicit in the dumper won't trip an unused warning). */
static void mac_stack_chk_fail_stub(void) {
    SHIM_HIT(SHIM____stack_chk_fail);
    fprintf(stderr, "[dom6-loader] stack smashing detected\n");
    abort();
}

/* ── errno wrapper ──────────────────────────────────────────────── */
static int *mac_errno_func(void) { SHIM_HIT(SHIM____error); return &errno; }


/* ── sincos (Mac returns struct, Linux uses pointer args) ─────────── */
typedef struct { double sin_val; double cos_val; } mac_sincos_t;
static mac_sincos_t mac_sincos_stret(double x) {
    SHIM_HIT(SHIM____sincos_stret);
    mac_sincos_t r;
#if defined(__GLIBC__) || (defined(__APPLE__))
    sincos(x, &r.sin_val, &r.cos_val);
#else
    /* UCRT and others: no sincos.  Compiler should fold sin/cos into one
     * call when -fno-math-errno + -ffast-math; otherwise we pay 2 calls. */
    r.sin_val = sin(x);
    r.cos_val = cos(x);
#endif
    return r;
}

/* ── mach time ──────────────────────────────────────────────────── */
static uint64_t mac_mach_absolute_time(void) {
    SHIM_HIT(SHIM__mach_absolute_time);
    struct timespec ts;
#if defined(CLOCK_MONOTONIC_RAW)
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);   /* Win32 / non-Linux POSIX */
#endif
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
typedef struct { uint32_t numer; uint32_t denom; } mac_mach_timebase_info_t;
static int mac_mach_timebase_info(mac_mach_timebase_info_t *info) {
    SHIM_HIT(SHIM__mach_timebase_info);
    if (info) { info->numer = 1; info->denom = 1; }
    return 0; /* KERN_SUCCESS */
}

/* ── sysctl stubs ───────────────────────────────────────────────── */
static int mac_sysctl_stub(int *n, unsigned int nl, void *o, size_t *os,
                           void *i, size_t is) { SHIM_HIT(SHIM__sysctl); errno = ENOSYS; return -1; }
static int mac_sysctlbyname_stub(const char *n, void *o, size_t *os,
                                 void *i, size_t is) {
    SHIM_HIT(SHIM__sysctlbyname);
    if (!n) { errno = EINVAL; return -1; }
    /* hw.ncpu / hw.logicalcpu → nprocs */
    if (!strcmp(n,"hw.ncpu") || !strcmp(n,"hw.logicalcpu") || !strcmp(n,"hw.physicalcpu")) {
#ifdef _WIN32
        SYSTEM_INFO si; GetSystemInfo(&si);
        long np = (long)si.dwNumberOfProcessors;
#else
        long np = sysconf(_SC_NPROCESSORS_ONLN);
#endif
        if (np <= 0) np = 1;
        int v = (int)np;
        if (o && os && *os >= sizeof(int)) { memcpy(o, &v, sizeof(int)); *os = sizeof(int); return 0; }
        if (os) *os = sizeof(int);
        errno = ENOMEM; return -1;
    }
    /* kern.osrelease → fake macOS version string */
    if (!strcmp(n,"kern.osrelease")) {
        const char *ver = "23.0.0";
        size_t vlen = strlen(ver)+1;
        if (o && os && *os >= vlen) { memcpy(o, ver, vlen); *os = vlen; return 0; }
        if (os) *os = vlen;
        errno = ENOMEM; return -1;
    }
    /* kern.ostype → Darwin */
    if (!strcmp(n,"kern.ostype")) {
        const char *s = "Darwin";
        size_t sl = strlen(s)+1;
        if (o && os && *os >= sl) { memcpy(o, s, sl); *os = sl; return 0; }
        if (os) *os = sl; errno = ENOMEM; return -1;
    }
    /* hw.memsize → total RAM in bytes */
    if (!strcmp(n,"hw.memsize") || !strcmp(n,"hw.physmem")) {
#ifdef _WIN32
        MEMORYSTATUSEX ms = { .dwLength = sizeof ms };
        uint64_t mem = GlobalMemoryStatusEx(&ms) ? ms.ullTotalPhys : (2ULL<<30);
#else
        long pages = sysconf(_SC_PHYS_PAGES);
        long pgsz  = sysconf(_SC_PAGE_SIZE);
        uint64_t mem = (pages > 0 && pgsz > 0) ? (uint64_t)pages*(uint64_t)pgsz : 2ULL<<30;
#endif
        if (o && os && *os >= sizeof(uint64_t)) { memcpy(o, &mem, sizeof(uint64_t)); *os = sizeof(uint64_t); return 0; }
        if (os) *os = sizeof(uint64_t); errno = ENOMEM; return -1;
    }
    errno = ENOENT; return -1;
}

/* ── memset_pattern16 ───────────────────────────────────────────── */
static void mac_memset_pattern16(void *b, const void *pat, size_t len) {
    SHIM_HIT(SHIM__memset_pattern16);
    uint8_t *dst = (uint8_t*)b;
    const uint8_t *p = (const uint8_t*)pat;
    for (size_t i = 0; i < len; i++) dst[i] = p[i & 15];
}

/* ── strlcpy/strlcat __chk wrappers ─────────────────────────────── */
static size_t mac_strlcpy_chk(char *dst, const char *src, size_t n, size_t dsz) {
    SHIM_HIT(SHIM____strlcpy_chk);
    (void)dsz; return strlcpy(dst, src, n);
}
static size_t mac_strlcat_chk(char *dst, const char *src, size_t n, size_t dsz) {
    SHIM_HIT(SHIM____strlcat_chk);
    (void)dsz; return strlcat(dst, src, n);
}

/* ── assert_rtn ─────────────────────────────────────────────────── */
static void mac_assert_rtn(const char *f, const char *file, int line,
                           const char *e) {
    SHIM_HIT(SHIM____assert_rtn);
    fprintf(stderr, "Assertion failed: %s (%s: %s: %d)\n", e, file, f, line);
    abort();
}

/* ── maskrune stub ───────────────────────────────────────────────── */
static int mac_maskrune_stub(int r, unsigned long m) { SHIM_HIT(SHIM____maskrune); return 0; }

/* ── unwind stub ─────────────────────────────────────────────────── */
static void mac_unwind_resume(void *e) {
    SHIM_HIT(SHIM___Unwind_Resume);
    fprintf(stderr, "[dom6-loader] __Unwind_Resume called\n");
    abort();
}

/* ── GCD (dispatch) minimal stubs ───────────────────────────────── */
typedef void (*dispatch_fn_t)(void *);
static void mac_dispatch_async(void *q, void *blk) { SHIM_HIT(SHIM__dispatch_async); (void)q; (void)blk; }
static void mac_dispatch_sync(void *q, void *blk) { SHIM_HIT(SHIM__dispatch_sync); (void)q; (void)blk; }
static void mac_dispatch_once_f(long *pred, void *ctx, dispatch_fn_t fn) {
    SHIM_HIT(SHIM__dispatch_once_f);
    if (!*pred) { *pred = 1; if (fn) fn(ctx); }
}
static void *mac_dispatch_get_global_queue(long q, unsigned long fl) {
    SHIM_HIT(SHIM__dispatch_get_global_queue);
    return (void*)0xdeadbeef;  /* non-NULL, never dereferenced if dispatch_async is NOP */
}


/* ── Path translation + /dev/urandom shim ─────────────────────────
 *
 * The Mac binary has `~/.dominions6` baked in as a literal string for
 * its config / save dir.  The native Dominions6.exe Windows Steam build
 * uses `%APPDATA%\Dominions6`.  Translating at the open/fopen/mkdir
 * boundary makes our Win32 build a drop-in for that — same saved games
 * are visible from both binaries.
 *
 * On POSIX the translator is a no-op.  On Win32 it rewrites the
 * `~/.dominions6` prefix and intercepts /dev/urandom (which doesn't
 * exist on Windows; we back it with BCryptGenRandom). */

#ifdef _WIN32
#include <bcrypt.h>     /* for BCryptGenRandom — link with -lbcrypt */
#endif

static const char *mac_translate_path(const char *p, char *buf, size_t bufsz) {
#ifdef _WIN32
    if (!p) return p;
    /* The Mac binary builds paths like `<HOME>/.dominions6/...` where
     * HOME comes from NSHomeDirectory (Cocoa).  On our Win build that's
     * NOP-stubbed → HOME is empty/garbage, so the actual path passed to
     * open() looks like "garbage/.dominions6/..." OR plain "/.dominions6/...".
     * Detect ANY occurrence of `/.dominions6` (or `\.dominions6`) and
     * rewrite everything up to and including it → %APPDATA%\Dominions6.
     * Result: drop-in compat with the native Dominions6.exe save layout. */
    /* Replace the `~/.dominions6` literal that's baked into dom6 source —
     * dom6's home-dir builder now produces fully-resolved paths thanks to
     * the Win32 variadic-ABI fix in mac_snprintf, so the only place this
     * substring shows up is if HOME is unset or some other path-resolution
     * step is bypassed.  Backstop, not a hot path. */
    const char *hit = strstr(p, ".dominions6");
    if (hit) {
        const char *rest = hit + strlen(".dominions6");  /* maybe "/..." */
        const char *appdata = getenv("APPDATA");
        if (!appdata) appdata = "C:\\Dominions6_fallback";
        snprintf(buf, bufsz, "%s\\Dominions6%s", appdata, rest);
        /* Normalize forward slashes the dom6 source uses to backslashes
         * for Win32 APIs that prefer them — mingw is forgiving but
         * tools like CreateDirectoryA are pickier. */
        for (char *q = buf; *q; q++) if (*q == '/') *q = '\\';
        return buf;
    }
#else
    (void)p; (void)buf; (void)bufsz;
#endif
    return p;
}

#ifdef _WIN32
/* Open a pseudo-/dev/urandom: temp file pre-filled with cryptographic
 * randomness.  Mac binary reads a few bytes for seed material; we
 * provide 4 KB which is well over what dom6 needs.  File is marked
 * FILE_FLAG_DELETE_ON_CLOSE so it's cleaned up when the fd closes. */
static int mac_open_urandom_win32(void) {
    char tmpdir[MAX_PATH], tmppath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmpdir) == 0) return -1;
    if (GetTempFileNameA(tmpdir, "dom6", 0, tmppath) == 0) return -1;
    HANDLE h = CreateFileA(tmppath,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_DELETE,
                           NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    uint8_t rnd[4096];
    if (BCryptGenRandom(NULL, rnd, sizeof rnd,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        /* Fallback: not really random, but better than open failure */
        memset(rnd, 0xa5, sizeof rnd);
    }
    DWORD wrote;
    if (!WriteFile(h, rnd, sizeof rnd, &wrote, NULL)) { CloseHandle(h); return -1; }
    LARGE_INTEGER zero = {0};
    SetFilePointerEx(h, zero, NULL, FILE_BEGIN);
    /* Convert OS HANDLE → CRT file descriptor (read-only). */
    int fd = _open_osfhandle((intptr_t)h, _O_RDONLY | _O_BINARY);
    if (fd < 0) CloseHandle(h);
    return fd;
}
#endif

/* ── mac_open shim ─────────────────────────────────────────────────
 * Mac AArch64 variadic ABI puts the optional `mode` arg (when O_CREAT
 * is set) on the stack, not in x2.  Naked-asm wrapper loads it before
 * tail-calling the C impl — same pattern as mac_fcntl. */
__attribute__((used)) int mac_open_impl(const char *path, int flags, int mode);
__attribute__((naked)) int mac_open(const char *path, int flags) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x29, sp\n"
        "ldr x2, [sp, #16]\n"          /* x2 ← mode from Mac vararg stack slot */
        "bl mac_open_impl\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
__attribute__((used)) int mac_open_impl(const char *path, int flags, int mode) {
    SHIM_HIT(SHIM__open);
#ifdef _WIN32
    if (getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] mac_open('%s', flags=0x%x)\n",
                path ? path : "(null)", flags);
#endif
    char buf[1024];
    const char *p = mac_translate_path(path, buf, sizeof buf);
#ifdef _WIN32
    if (p && !strcmp(p, "/dev/urandom")) return mac_open_urandom_win32();
    /* Win32: forward slashes work but mingw open() expects \\ in some paths.
     * Either way the rewritten "%APPDATA%\Dominions6\..." is already valid. */
    if (flags & O_CREAT) return open(p, flags, mode);
    return open(p, flags);
#else
    if (flags & O_CREAT) return open(p, flags, (mode_t)mode);
    return open(p, flags);
#endif
}

/* ── mac_popen shim — intercept dom6's sysctl invocations ─────────
 * dom6 uses popen("sysctl …") to read hw.ncpu and kern.osrelease.
 * On Win32 cmd.exe has no `sysctl`, so the parent fails to parse the
 * output and falls into degraded paths (one is a tight retry loop on
 * .vcr files).  Recognise the exact commands and return a tmpfile
 * pre-loaded with the value dom6's scanf will accept.  On POSIX the
 * shim is a thin passthrough — sysctl actually exists there. */
#ifdef _WIN32
static FILE *mac_popen_canned(const char *line) {
    FILE *fp = tmpfile();
    if (!fp) return NULL;
    fputs(line, fp);
    rewind(fp);
    return fp;
}
#endif
static FILE *mac_popen(const char *cmd, const char *mode) {
#ifdef _WIN32
    if (cmd && mode && mode[0] == 'r') {
        if (!strcmp(cmd, "sysctl -n hw.ncpu"))    return mac_popen_canned("8\n");
        if (!strcmp(cmd, "sysctl -n hw.cpu"))     return mac_popen_canned("8\n");
        if (!strcmp(cmd, "sysctl kern.osrelease"))
            /* macOS 13 Ventura kernel — dom6 parses the major number. */
            return mac_popen_canned("kern.osrelease: 22.6.0\n");
    }
    if (getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] mac_popen('%s','%s') passthrough\n",
                cmd ? cmd : "(null)", mode ? mode : "(null)");
    return _popen(cmd, mode);
#else
    return popen(cmd, mode);
#endif
}

/* ── mac_fopen shim — same path translation, no variadic complication */
static FILE *mac_fopen(const char *path, const char *mode) {
    SHIM_HIT(SHIM__fopen);
#ifdef _WIN32
    if (getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] mac_fopen('%s', '%s')\n",
                path ? path : "(null)", mode ? mode : "(null)");
    /* dom6 also calls fopen("/dev/urandom","rb").  Back with same temp file. */
    if (path && !strcmp(path, "/dev/urandom")) {
        int fd = mac_open_urandom_win32();
        if (fd < 0) return NULL;
        return _fdopen(fd, mode);
    }
#endif
    char buf[1024];
    const char *p = mac_translate_path(path, buf, sizeof buf);
    FILE *fp = fopen(p, mode);
#ifdef _WIN32
    if (!fp && getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] mac_fopen → NULL (errno=%d) for '%s'\n", errno, p);
#endif
    return fp;
}

/* ── mac_mkdir shim — pre-creates parent dirs on Win32 (no `mkdir -p`) */
static int mac_mkdir(const char *path,
#ifdef _WIN32
                     int mode_ignored
#else
                     mode_t mode
#endif
                    ) {
    SHIM_HIT(SHIM__mkdir);
#ifdef _WIN32
    if (getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] mac_mkdir('%s')\n", path ? path : "(null)");
#endif
    char buf[1024];
    const char *p = mac_translate_path(path, buf, sizeof buf);
#ifdef _WIN32
    (void)mode_ignored;
    /* CreateDirectoryA succeeds with 1, returns 0 on failure.  If the
     * dir already exists, GetLastError == ERROR_ALREADY_EXISTS; treat
     * as success for POSIX mkdir compatibility. */
    if (CreateDirectoryA(p, NULL)) return 0;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    errno = EACCES;
    return -1;
#else
    return mkdir(p, mode);
#endif
}

#ifndef _WIN32   /* === POSIX-only section: dlopen + sockets + fcntl ====== */

/* ── Mac-aware dlopen/dlsym/dlclose wrappers ────────────────────── *
 * Mac RTLD_DEFAULT = (void*)-2, Linux = NULL.
 * Mac RTLD_SELF    = (void*)-3, Linux = RTLD_DEFAULT (NULL).
 * Mac dlopen may return small-int handles for pre-loaded frameworks;
 * any handle < 0x10000 is treated as RTLD_DEFAULT on Linux.
 * Mac .dylib paths are remapped: try as-is first, then basename.
 */
static void* mac_dlopen(const char *path, int flags) {
    SHIM_HIT(SHIM__dlopen);
    if (!path) return dlopen(NULL, flags);
    void *h = dlopen(path, flags);
    if (h) return h;
    /* strip Mac framework/dylib path to basename */
    const char *base = strrchr(path, '/');
    if (base) base++; else base = path;
    /* try stripping .dylib → .so convention */
    char buf[256];
    const char *ext = strstr(base, ".dylib");
    if (ext) {
        size_t n = (size_t)(ext - base);
        if (n + 8 < sizeof(buf)) {
            __builtin_memcpy(buf, base, n);
            __builtin_memcpy(buf + n, ".so", 4);
            h = dlopen(buf, flags);
            if (h) return h;
        }
    }
    return NULL;
}
static void* mac_dlsym(void *handle, const char *sym) {
    SHIM_HIT(SHIM__dlsym);
    /* Translate Mac magic handles to Linux equivalents */
    if (handle == (void*)-2 ||   /* Mac RTLD_DEFAULT */
        handle == (void*)-3 ||   /* Mac RTLD_SELF    */
        (uintptr_t)handle < 0x10000) /* small/invalid handle */
        handle = RTLD_DEFAULT;
    return dlsym(handle, sym);
}
static int mac_dlclose(void *handle) {
    SHIM_HIT(SHIM__dlclose);
    if ((uintptr_t)handle < 0x10000) return 0;
    return dlclose(handle);
}


/* ── Mac socket ABI shims ────────────────────────────────────────── *
 * Mac sockaddr has an extra 1-byte sin_len prefix before sin_family.
 * Mac AF_INET6=30 vs Linux=10.  Mac SOL_SOCKET=0xffff vs Linux=1.
 * Mac SO_REUSEADDR=4 vs Linux=2, etc.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>

/* Translate Mac AF → Linux AF */
static int mac_af_to_linux(int mac_af) {
    switch (mac_af) {
        case 30: return AF_INET6;       /* Mac AF_INET6=30, Linux=10 */
        default: return mac_af;          /* AF_INET=2, AF_UNIX=1 same */
    }
}
/* Translate Mac SOL_SOCKET level and optname → Linux */
static int mac_sol_to_linux(int level) {
    if (level == 0xffff) return SOL_SOCKET;  /* Mac SOL_SOCKET */
    return level;
}
static int mac_so_to_linux(int level, int optname) {
    if (level == 0xffff || level == SOL_SOCKET) {
        /* Mac SO_* → Linux SO_* */
        switch (optname) {
            case 4:      return SO_REUSEADDR;
            case 8:      return SO_KEEPALIVE;
            case 0x10:   return SO_DONTROUTE;
            case 0x20:   return SO_BROADCAST;
            case 0x80:   return SO_LINGER;
            case 0x200:  return SO_REUSEPORT;
            case 0x400:  return SO_OOBINLINE;
            case 0x1001: return SO_SNDBUF;
            case 0x1002: return SO_RCVBUF;
            case 0x1003: return SO_SNDLOWAT;
            case 0x1004: return SO_RCVLOWAT;
            case 0x1005: return SO_SNDTIMEO;
            case 0x1006: return SO_RCVTIMEO;
            case 0x1007: return SO_ERROR;
            case 0x1008: return SO_TYPE;
            case 0x1022: return -1;  /* SO_NOSIGPIPE: ignore on Linux */
            default:     return optname;
        }
    }
    return optname;
}
/* Translate Mac MSG_* flag bits → Linux MSG_* bits.  Sources:
 *   xnu/bsd/sys/socket.h, glibc bits/socket.h (verified 2026-05).
 * Bits that exist on Mac but not Linux are dropped silently. */
static int mac_msg_to_linux(int mf) {
    int lf = 0;
    if (mf & 0x0001) lf |= MSG_OOB;
    if (mf & 0x0002) lf |= MSG_PEEK;
    if (mf & 0x0004) lf |= MSG_DONTROUTE;
    if (mf & 0x0008) lf |= MSG_EOR;
    if (mf & 0x0010) lf |= MSG_TRUNC;
    if (mf & 0x0020) lf |= MSG_CTRUNC;
    if (mf & 0x0040) lf |= MSG_WAITALL;
    if (mf & 0x0080) lf |= MSG_DONTWAIT;   /* Mac 0x80 → Linux 0x40 */
    /* 0x0100 = MSG_EOF (Mac-only, drop) */
    /* 0x2000 = MSG_HAVEMORE (Mac-only, drop) */
    /* 0x4000 = MSG_RCVMORE (Mac-only, drop) */
    if (mf & 0x80000) lf |= MSG_NOSIGNAL; /* Mac 0x80000 → Linux 0x4000 */
    return lf;
}

/* Convert Mac-format sockaddr (with sin_len byte) → Linux sockaddr_storage.
 * Returns the Linux socklen, or -1 if unrecognized. */
static int mac_sa_to_linux(const void *mac_sa, socklen_t mac_len,
                            struct sockaddr_storage *out) {
    const uint8_t *b = (const uint8_t*)mac_sa;
    if (mac_len < 2) return -1;
    uint8_t sa_len_byte = b[0];
    uint8_t mac_family  = b[1];
    /* Detect Mac format: sa_family as uint16 would be (sa_len<<8)|mac_family ≠ any valid Linux AF */
    /* If the uint16 sa_family value is valid Linux AF (1,2,10,etc.) treat as Linux already */
    uint16_t linux_fam_raw = *(const uint16_t*)b;
    if (linux_fam_raw == AF_INET || linux_fam_raw == AF_INET6 ||
        linux_fam_raw == AF_UNIX) {
        /* Already Linux format: copy as-is */
        if (mac_len <= sizeof(*out)) memcpy(out, mac_sa, mac_len);
        return (int)mac_len;
    }
    /* Mac format */
    memset(out, 0, sizeof(*out));
    int lf = mac_af_to_linux(mac_family);
    if (mac_family == 2 || mac_family == 0) { /* AF_INET */
        struct sockaddr_in *sin = (struct sockaddr_in*)out;
        sin->sin_family = AF_INET;
        if (mac_len >= 8) { memcpy(&sin->sin_port, b+2, 2); memcpy(&sin->sin_addr, b+4, 4); }
        return sizeof(*sin);
    } else if (mac_family == 30) { /* Mac AF_INET6 */
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)out;
        sin6->sin6_family = AF_INET6;
        if (mac_len >= 28) {
            memcpy(&sin6->sin6_port,     b+2,  2);
            memcpy(&sin6->sin6_flowinfo, b+4,  4);
            memcpy(&sin6->sin6_addr,     b+8,  16);
            memcpy(&sin6->sin6_scope_id, b+24, 4);
        }
        return sizeof(*sin6);
    } else if (mac_family == 1) { /* AF_UNIX */
        struct sockaddr_un *sun = (struct sockaddr_un*)out;
        sun->sun_family = AF_UNIX;
        size_t pathlen = (sa_len_byte > 2) ? sa_len_byte - 2 : (mac_len > 2 ? mac_len - 2 : 0);
        if (pathlen > sizeof(sun->sun_path)-1) pathlen = sizeof(sun->sun_path)-1;
        memcpy(sun->sun_path, b+2, pathlen);
        return (int)(sizeof(sa_family_t) + pathlen + 1);
    }
    /* Unknown: pass through with translated family */
    if (mac_len <= sizeof(*out)) { memcpy(out, mac_sa, mac_len); out->ss_family = lf; }
    return (int)mac_len;
}
/* Convert Linux sockaddr_storage → Mac-format (for accept/getsockname/getpeername).
 * Writes into buf of size buf_len.  Returns written bytes. */
static int linux_sa_to_mac(const struct sockaddr_storage *lin, socklen_t lin_len,
                            void *buf, socklen_t buf_len) {
    uint8_t *b = (uint8_t*)buf;
    if (buf_len < 2) return 0;
    if (lin->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in*)lin;
        uint8_t mac_sa[16] = {16, 2, 0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
        memcpy(mac_sa+2, &sin->sin_port, 2);
        memcpy(mac_sa+4, &sin->sin_addr, 4);
        socklen_t copy = (buf_len < 16) ? buf_len : 16;
        memcpy(b, mac_sa, copy);
        return (int)copy;
    } else if (lin->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6*)lin;
        uint8_t mac_sa[28] = {28, 30};
        memcpy(mac_sa+2,  &sin6->sin6_port,     2);
        memcpy(mac_sa+4,  &sin6->sin6_flowinfo, 4);
        memcpy(mac_sa+8,  &sin6->sin6_addr,     16);
        memcpy(mac_sa+24, &sin6->sin6_scope_id, 4);
        socklen_t copy = (buf_len < 28) ? buf_len : 28;
        memcpy(b, mac_sa, copy);
        return (int)copy;
    }
    /* fallback */
    socklen_t copy = (buf_len < lin_len) ? buf_len : lin_len;
    memcpy(b, lin, copy);
    return (int)copy;
}

static int mac_socket(int domain, int type, int protocol) {
    SHIM_HIT(SHIM__socket);
    return socket(mac_af_to_linux(domain), type, protocol);
}
static int mac_bind(int fd, const void *addr, socklen_t len) {
    SHIM_HIT(SHIM__bind);
    struct sockaddr_storage ls;
    int ll = mac_sa_to_linux(addr, len, &ls);
    if (ll < 0) { errno = EAFNOSUPPORT; return -1; }
    return bind(fd, (struct sockaddr*)&ls, (socklen_t)ll);
}
static int mac_connect(int fd, const void *addr, socklen_t len) {
    SHIM_HIT(SHIM__connect);
    struct sockaddr_storage ls;
    int ll = mac_sa_to_linux(addr, len, &ls);
    if (ll < 0) { errno = EAFNOSUPPORT; return -1; }
    return connect(fd, (struct sockaddr*)&ls, (socklen_t)ll);
}
static int mac_accept(int fd, void *addr, socklen_t *len) {
    SHIM_HIT(SHIM__accept);
    struct sockaddr_storage ls;
    socklen_t ll = sizeof(ls);
    int r = accept(fd, (struct sockaddr*)&ls, &ll);
    if (r >= 0 && addr && len) {
        int written = linux_sa_to_mac(&ls, ll, addr, *len);
        if (written > 0) *len = (socklen_t)written;
    }
    return r;
}
static int mac_setsockopt(int fd, int level, int optname, const void *val, socklen_t len) {
    SHIM_HIT(SHIM__setsockopt);
    int ll = mac_sol_to_linux(level);
    int lo = mac_so_to_linux(level, optname);
    if (lo == -1) return 0;  /* SO_NOSIGPIPE: silently ignore */
    return setsockopt(fd, ll, lo, val, len);
}

/* ── fcntl flag translation ─────────────────────────────────────────
 * Mac O_NONBLOCK=0x0004, O_APPEND=0x0008  vs
 * Linux O_NONBLOCK=0x0800, O_APPEND=0x0400
 * F_SETFL/F_GETFL must translate these or sockets stay blocking.
 */
static int mac_flags_to_linux(int mf) {
    int lf = mf & ~(0x0004|0x0008);  /* strip Mac-specific bits */
    if (mf & 0x0004) lf |= O_NONBLOCK;
    if (mf & 0x0008) lf |= O_APPEND;
    return lf;
}
static int linux_flags_to_mac(int lf) {
    int mf = lf & ~(O_NONBLOCK|O_APPEND);
    if (lf & O_NONBLOCK) mf |= 0x0004;
    if (lf & O_APPEND)   mf |= 0x0008;
    return mf;
}
/* Naked wrapper: Mac AArch64 ABI passes variadic args on the STACK
 * (not in x2). Linux ABI puts them in x2. After our prologue saves
 * x29/x30 (sp -= 16), [sp+16] = original-sp = first vararg slot on
 * Mac. We load that into x2, then tail through to mac_fcntl_impl
 * which sees the arg in the expected Linux register. */
__attribute__((used)) int mac_fcntl_impl(int fd, int cmd, long arg0);
__attribute__((naked)) int mac_fcntl(int fd, int cmd) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x29, sp\n"
        "ldr x2, [sp, #16]\n"           /* x2 ← Mac stack vararg */
        "bl mac_fcntl_impl\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
__attribute__((used)) int mac_fcntl_impl(int fd, int cmd, long arg0) {
    SHIM_HIT(SHIM__fcntl);
    fprintf(stderr, "[shim] fcntl(%d, cmd=%d, arg=0x%lx)\n", fd, cmd, arg0);
    /* F_GETFL=3, F_SETFL=4 on both Mac and Linux */
    if (cmd == 3 /* F_GETFL */) {
        int r = fcntl(fd, F_GETFL);
        int result = (r < 0) ? r : linux_flags_to_mac(r);
        fprintf(stderr, "[shim] fcntl(%d, F_GETFL) -> linux=0x%x mac=0x%x\n", fd, r, result);
        return result;
    } else if (cmd == 4 /* F_SETFL */) {
        int mf = (int)arg0;
        int lf = mac_flags_to_linux(mf);
        fprintf(stderr, "[shim] fcntl(%d, F_SETFL, mac=0x%x -> linux=0x%x)\n", fd, mf, lf);
        return fcntl(fd, F_SETFL, lf);
    } else if (cmd == 67 /* Mac F_DUPFD_CLOEXEC */) {
        return fcntl(fd, F_DUPFD_CLOEXEC, arg0);
    } else if (cmd == 7 /* Mac F_GETLK */) {
        return fcntl(fd, F_GETLK, arg0);
    } else if (cmd == 8 /* Mac F_SETLK */) {
        return fcntl(fd, F_SETLK, arg0);
    } else if (cmd == 9 /* Mac F_SETLKW */) {
        return fcntl(fd, F_SETLKW, arg0);
    } else {
        /* F_DUPFD/F_GETFD/F_SETFD have identical numeric values (0/1/2) */
        return fcntl(fd, cmd, arg0);
    }
}


/* ── listen: force O_NONBLOCK on listen socket ────────────────────
 * Mac code calls fcntl(listenfd, F_SETFL, O_NONBLOCK) but the ABI
 * translation passes the wrong value.  Force non-blocking here so
 * the accept() loop doesn't block after accepting all connections.
 */
static int mac_listen(int sockfd, int backlog) {
    SHIM_HIT(SHIM__listen);
    int r = listen(sockfd, backlog);
    if (r == 0)
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
    fprintf(stderr, "[shim] listen(%d, %d) -> %d (forced O_NONBLOCK)\n", sockfd, backlog, r);
    return r;
}


/* ── recv: thin shim, slot reserved for future MSG_* flag translation.
 * recv() has identical Mac/Linux semantics; the only legitimate ABI
 * reason to keep this shim is to translate Mac MSG_* flag bits.  At
 * the moment we pass them through unchanged — to be verified against
 * Apple's sys/socket.h and Darling's shim. */
static ssize_t mac_recv(int fd, void *buf, size_t len, int flags) {
    SHIM_HIT(SHIM__recv);
    return recv(fd, buf, len, mac_msg_to_linux(flags));
}
static ssize_t mac_send(int fd, const void *buf, size_t len, int flags) {
    SHIM_HIT(SHIM__send);
    return send(fd, buf, len, mac_msg_to_linux(flags));
}

#else  /* _WIN32 — provide abort-on-call stubs for the missing mac_* */

/* These stubs let fill_got() take addresses for the linker, but ALL of
 * them abort if actually invoked.  The GUI startup path doesn't reach
 * any of them (counter dump confirms only string-helpers actually fire).
 * For server mode (--tcpserver) we'd need real Winsock+LoadLibrary
 * implementations here — a separate piece of work. */
#include <stdio.h>
#include <stdlib.h>

static int _w32_abort(const char *name) {
    fprintf(stderr, "[loader-win32] FATAL: mac_%s not implemented on Win32\n",
            name);
    abort();
    return -1;
}
#define WIN32_STUB(name, ret, args, log)                                   \
    static ret mac_##name args { (void)_w32_abort(#name); return (ret)0; }

/* Real dlopen/dlsym/dlclose for Win — same job as the Linux POSIX
 * versions above (mac_dlopen) but via LoadLibrary/GetProcAddress.
 *
 * Mac dlopen names like "libSDL2-2.0.0.dylib" map to the Win library
 * basename ("SDL2.dll").  Strategy:
 *   1. Try the path as-is.
 *   2. Try basename only.
 *   3. Strip Mac path/framework prefixes and rewrite ".dylib"→".dll".
 *   4. Special-case known Mac framework names → Win equivalents.
 * RTLD_DEFAULT / RTLD_SELF (Mac sentinel values) → use our process
 * handle so GetProcAddress searches all loaded modules. */
static void *mac_dlopen(const char *path, int flags) {
    (void)flags;
    if (!path || path == (const char *)-2 /* RTLD_DEFAULT */
              || path == (const char *)-3 /* RTLD_SELF */) {
        return GetModuleHandleA(NULL);
    }
    /* 1. try literal */
    HMODULE h = LoadLibraryA(path);
    if (h) return h;
    /* 2. basename only */
    const char *base = strrchr(path, '/');
    if (!base) base = strrchr(path, '\\');
    if (base) base++; else base = path;
    h = LoadLibraryA(base);
    if (h) return h;
    /* 3. .dylib → .dll */
    char buf[MAX_PATH];
    const char *ext = strstr(base, ".dylib");
    if (ext) {
        size_t n = (size_t)(ext - base);
        if (n + 5 < sizeof(buf)) {
            memcpy(buf, base, n);
            memcpy(buf + n, ".dll", 5);
            h = LoadLibraryA(buf);
            if (h) return h;
        }
    }
    /* 4. Strip the leading "lib" prefix some Win DLLs drop. */
    if (!strncmp(base, "lib", 3)) {
        const char *short_base = base + 3;
        ext = strstr(short_base, ".dylib");
        if (ext) {
            size_t n = (size_t)(ext - short_base);
            if (n + 5 < sizeof(buf)) {
                memcpy(buf, short_base, n);
                memcpy(buf + n, ".dll", 5);
                h = LoadLibraryA(buf);
                if (h) return h;
            }
        }
    }
    if (getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] mac_dlopen('%s') failed: %lu\n",
                path, GetLastError());
    return NULL;
}
static void *mac_dlsym(void *handle, const char *sym) {
    if (!handle) handle = GetModuleHandleA(NULL);
    /* Mac symbol names start with '_', Win names don't.  Strip leading '_' */
    if (sym && sym[0] == '_') sym++;
    void *p = (void *)GetProcAddress((HMODULE)handle, sym);
    if (!p && getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] mac_dlsym(%p, '%s') failed: %lu\n",
                handle, sym, GetLastError());
    return p;
}
static int mac_dlclose(void *handle) {
    if (!handle) return 0;
    return FreeLibrary((HMODULE)handle) ? 0 : -1;
}

#include <winsock2.h>
#include <ws2tcpip.h>

/* ── Winsock socket family ────────────────────────────────────────
 * Mac sockaddr_in: { uint8 sin_len; uint8 sin_family; … }
 * Win sockaddr_in: { uint16 sin_family; … }
 * Convert by checking the first byte: if it equals the expected
 * struct size (16/28) and the second byte equals Mac's AF code,
 * the caller is using the Mac layout — translate. */

static int mac_af_to_win(int mac_af) {
    /* Mac AF_INET = 2 = Win AF_INET. AF_INET6 = 30 (Mac) vs 23 (Win). */
    if (mac_af == 30) return 23;   /* AF_INET6 */
    return mac_af;                 /* AF_INET, AF_UNSPEC pass through */
}
static int mac_sa_to_win(const void *mac_sa, int mac_len,
                        struct sockaddr_storage *out) {
    const uint8_t *b = (const uint8_t*)mac_sa;
    if (mac_len < 2) return -1;
    /* Heuristic: Win sockaddr's first uint16 is sin_family (a small int);
     * Mac's is (sin_len<<8 | sin_family).  If raw uint16 is a known Win AF,
     * caller already used Win layout — just copy. */
    uint16_t raw_fam = *(const uint16_t*)b;
    if (raw_fam == AF_INET || raw_fam == AF_INET6 || raw_fam == AF_UNSPEC) {
        if (mac_len <= (int)sizeof(*out)) memcpy(out, mac_sa, mac_len);
        return mac_len;
    }
    memset(out, 0, sizeof(*out));
    uint8_t mac_family = b[1];
    if (mac_family == 2 || mac_family == 0) {           /* AF_INET */
        struct sockaddr_in *sin = (struct sockaddr_in*)out;
        sin->sin_family = AF_INET;
        if (mac_len >= 8) {
            memcpy(&sin->sin_port, b+2, 2);
            memcpy(&sin->sin_addr, b+4, 4);
        }
        return (int)sizeof(*sin);
    }
    if (mac_family == 30) {                             /* Mac AF_INET6 */
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)out;
        sin6->sin6_family = AF_INET6;
        if (mac_len >= 28) {
            memcpy(&sin6->sin6_port,     b+2,  2);
            memcpy(&sin6->sin6_flowinfo, b+4,  4);
            memcpy(&sin6->sin6_addr,     b+8,  16);
            memcpy(&sin6->sin6_scope_id, b+24, 4);
        }
        return (int)sizeof(*sin6);
    }
    return -1;
}
static int win_sa_to_mac(const struct sockaddr_storage *win, int /*win_len*/ wl,
                         void *buf, int buf_len) {
    (void)wl;
    uint8_t *b = (uint8_t*)buf;
    if (buf_len < 2) return 0;
    if (win->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in*)win;
        uint8_t out[16] = {16, 2, 0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
        memcpy(out+2, &sin->sin_port, 2);
        memcpy(out+4, &sin->sin_addr, 4);
        int c = buf_len < 16 ? buf_len : 16;
        memcpy(b, out, c);
        return c;
    }
    if (win->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6*)win;
        uint8_t out[28] = {28, 30};
        memcpy(out+2,  &sin6->sin6_port,     2);
        memcpy(out+4,  &sin6->sin6_flowinfo, 4);
        memcpy(out+8,  &sin6->sin6_addr,     16);
        memcpy(out+24, &sin6->sin6_scope_id, 4);
        int c = buf_len < 28 ? buf_len : 28;
        memcpy(b, out, c);
        return c;
    }
    return 0;
}

#define WSTRACE(...) do { if (getenv("DOM6_LOADER_TRACE")) \
    fprintf(stderr, __VA_ARGS__); } while (0)

static int mac_socket(int d, int t, int p) {
    SHIM_HIT(SHIM__socket);
    SOCKET s = socket(mac_af_to_win(d), t, p);
    fprintf(stderr, "[shim] mac_socket(%d→%d, %d, %d) = %lld  err=%d\n",
            d, mac_af_to_win(d), t, p, (long long)s,
            s == INVALID_SOCKET ? WSAGetLastError() : 0);
    fflush(stderr);
    return s == INVALID_SOCKET ? -1 : (int)s;
}
static int mac_bind(int f, const void *a, int l) {
    SHIM_HIT(SHIM__bind);
    struct sockaddr_storage ws;
    int wl = mac_sa_to_win(a, l, &ws);
    if (wl < 0) { WSASetLastError(WSAEAFNOSUPPORT); return -1; }
    int r = bind((SOCKET)f, (struct sockaddr*)&ws, wl);
    WSTRACE("[shim] mac_bind(fd=%d, len=%d) = %d  err=%d\n",
            f, wl, r, r ? WSAGetLastError() : 0);
    return r;
}
static int mac_connect(int f, const void *a, int l) {
    SHIM_HIT(SHIM__connect);
    struct sockaddr_storage ws;
    int wl = mac_sa_to_win(a, l, &ws);
    if (wl < 0) { WSASetLastError(WSAEAFNOSUPPORT); return -1; }
    int r = connect((SOCKET)f, (struct sockaddr*)&ws, wl);
    WSTRACE("[shim] mac_connect(fd=%d) = %d  err=%d\n",
            f, r, r ? WSAGetLastError() : 0);
    return r;
}
static int mac_accept(int f, void *a, int *l) {
    SHIM_HIT(SHIM__accept);
    struct sockaddr_storage ws;
    int wl = (int)sizeof(ws);
    SOCKET s = accept((SOCKET)f, (struct sockaddr*)&ws, &wl);
    if (s == INVALID_SOCKET) {
        WSTRACE("[shim] mac_accept(fd=%d) = -1  err=%d\n", f, WSAGetLastError());
        return -1;
    }
    if (a && l) {
        int n = win_sa_to_mac(&ws, wl, a, *l);
        if (n > 0) *l = n;
    }
    return (int)s;
}
static int mac_listen(int f, int b) {
    SHIM_HIT(SHIM__listen);
    int r = listen((SOCKET)f, b);
    WSTRACE("[shim] mac_listen(fd=%d, backlog=%d) = %d  err=%d\n",
            f, b, r, r ? WSAGetLastError() : 0);
    return r;
}
/* Translate Mac MSG_* flag bits to Win equivalents.
 *   Mac MSG_OOB         = 0x0001  → Win MSG_OOB         = 0x0001
 *   Mac MSG_PEEK        = 0x0002  → Win MSG_PEEK        = 0x0002
 *   Mac MSG_DONTROUTE   = 0x0004  → Win MSG_DONTROUTE   = 0x0004
 *   Mac MSG_WAITALL     = 0x0040  → Win MSG_WAITALL     = 0x0008
 *   Mac MSG_DONTWAIT    = 0x0080  → not supported on Win (set FIONBIO on fd instead)
 *   Mac MSG_NOSIGNAL    = 0x80000 → not supported on Win (Win sockets never raise SIGPIPE)
 * Strip the unsupported bits before passing to Winsock — otherwise it
 * returns WSAEOPNOTSUPP (10045) and the caller treats the connection
 * as dead. */
static int mac_msg_to_win(int mac_flags) {
    int win = mac_flags & (1 | 2 | 4);              /* OOB | PEEK | DONTROUTE */
    if (mac_flags & 0x0040) win |= 0x0008;          /* WAITALL */
    /* MSG_DONTWAIT and MSG_NOSIGNAL silently dropped */
    return win;
}
static long mac_recv(int f, void *b, unsigned n, int g) {
    SHIM_HIT(SHIM__recv);
    int win_g = mac_msg_to_win(g);
    long r = recv((SOCKET)f, (char*)b, (int)n, win_g);
    WSTRACE("[shim] mac_recv(fd=%d, n=%u, mac_flags=0x%x→win=0x%x) = %ld  err=%d\n",
            f, n, g, win_g, r, r < 0 ? WSAGetLastError() : 0);
    return r;
}
static long mac_send(int f, const void *b, unsigned n, int g) {
    SHIM_HIT(SHIM__send);
    int win_g = mac_msg_to_win(g);
    long r = send((SOCKET)f, (const char*)b, (int)n, win_g);
    WSTRACE("[shim] mac_send(fd=%d, n=%u, mac_flags=0x%x→win=0x%x) = %ld  err=%d\n",
            f, n, g, win_g, r, r < 0 ? WSAGetLastError() : 0);
    return r;
}
static int mac_setsockopt(int f, int level, int opt, const void *v, int s) {
    SHIM_HIT(SHIM__setsockopt);
    /* Mac SOL_SOCKET = 0xffff = Win SOL_SOCKET too — pass through.
     * Mac SO_REUSEADDR = 4 = Win SO_REUSEADDR. */
    int r = setsockopt((SOCKET)f, level, opt, (const char*)v, s);
    WSTRACE("[shim] mac_setsockopt(fd=%d, lvl=%d, opt=%d) = %d  err=%d\n",
            f, level, opt, r, r ? WSAGetLastError() : 0);
    return r;
}

/* fcntl: the only commands dom6 actually uses are F_GETFL and
 * F_SETFL with O_NONBLOCK.  Translate to ioctlsocket(FIONBIO).
 * Variadic call site — needs the naked-asm wrapper to pull the
 * stack arg into x2. */
__attribute__((used)) int mac_fcntl_impl(int fd, int cmd, long arg);
__attribute__((naked)) int mac_fcntl(int fd, int cmd) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "ldr x2, [sp, #16]\n"
        "bl mac_fcntl_impl\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
__attribute__((used)) int mac_fcntl_impl(int fd, int cmd, long arg) {
    SHIM_HIT(SHIM__fcntl);
    enum { MAC_F_GETFL = 3, MAC_F_SETFL = 4, MAC_O_NONBLOCK = 4,
           MAC_F_GETFD = 1, MAC_F_SETFD = 2 };
    if (cmd == MAC_F_SETFL) {
        u_long nb = (arg & MAC_O_NONBLOCK) ? 1 : 0;
        int r = ioctlsocket((SOCKET)fd, FIONBIO, &nb);
        /* If the fd isn't a socket (e.g. stdin/out/err, file fds),
         * silently report success.  dom6 sets O_NONBLOCK indiscriminately
         * during startup; on Win there's nothing actionable for non-socket
         * fds and a hard failure here aborts the whole process. */
        if (r != 0 && WSAGetLastError() == WSAENOTSOCK) r = 0;
        WSTRACE("[shim] mac_fcntl(fd=%d, F_SETFL, arg=0x%lx) → ioctlsocket FIONBIO=%lu = %d\n",
                fd, arg, nb, r);
        return r;
    }
    if (cmd == MAC_F_GETFL || cmd == MAC_F_GETFD || cmd == MAC_F_SETFD) {
        /* No-op on Win for these — dom6 only cares about F_SETFL effects. */
        return 0;
    }
    WSTRACE("[shim] mac_fcntl(fd=%d, cmd=%d, arg=0x%lx) — UNHANDLED\n",
            fd, cmd, arg);
    return 0;
}

/* glibc fortify-source symbols: aliases referenced by gen/got_bindings.inc.
 * On glibc these are real fortified wrappers around sprintf/snprintf; on
 * UCRT we just forward to the plain version (no buffer-size check). */
#include <stdarg.h>
int __sprintf_chk(char *s, int flag, size_t slen, const char *fmt, ...) {
    (void)flag; (void)slen;
    va_list ap; va_start(ap, fmt);
    int r = vsprintf(s, fmt, ap);
    va_end(ap);
    return r;
}
int __snprintf_chk(char *s, size_t maxlen, int flag, size_t slen, const char *fmt, ...) {
    (void)flag; (void)slen;
    va_list ap; va_start(ap, fmt);
    int r = vsnprintf(s, maxlen, fmt, ap);
    va_end(ap);
    return r;
}

#endif  /* _WIN32 */


/* ── Mac va_list adapter ─────────────────────────────────────────────
 *
 * AArch64 macOS passes variadic args ALWAYS on the stack (never in
 * registers), so Mac code calls vsnprintf/vfprintf/etc. with the 4th
 * argument being a simple char* pointing to the first stack-based
 * vararg.  Linux glibc expects a 32-byte __va_list_tag struct.
 * These wrappers convert Mac-style va_list → Linux-style va_list.
 *
 * With __gr_offs = 0 (not negative), glibc's va_arg uses __stack
 * directly instead of the GP-register save area — which is exactly
 * what we want: the first arg is at mac_ap, the second at mac_ap+8, etc.
 */
typedef struct {
    void *__stack;
    void *__gr_top;
    void *__vr_top;
    int   __gr_offs;
    int   __vr_offs;
} mac_vl_t;

static int mac_vsnprintf(char *buf, size_t size, const char *fmt, void *mac_ap) {
    SHIM_HIT(SHIM__vsnprintf);
    mac_vl_t lx = { mac_ap, mac_ap, mac_ap, 0, 0 };
    va_list ap; memcpy(&ap, &lx, sizeof(ap));
    return vsnprintf(buf, size, fmt, ap);
}
static int mac_vfprintf(FILE *fp, const char *fmt, void *mac_ap) {
    SHIM_HIT(SHIM__vfprintf);
    mac_vl_t lx = { mac_ap, mac_ap, mac_ap, 0, 0 };
    va_list ap; memcpy(&ap, &lx, sizeof(ap));
    return vfprintf(fp, fmt, ap);
}
/* mac_vprintf / mac_vsprintf removed — dom6_mac doesn't import them.
 * The active siblings (mac_vfprintf, mac_vsscanf) handle the variadic
 * v* paths the binary actually calls. */
static int mac_vsscanf(const char *str, const char *fmt, void *mac_ap) {
    SHIM_HIT(SHIM__vsscanf);
    mac_vl_t lx = { mac_ap, mac_ap, mac_ap, 0, 0 };
    va_list ap; memcpy(&ap, &lx, sizeof(ap));
    return vsscanf(str, fmt, ap);
}


/* ── Mac variadic call-site ABI (naked assembly wrappers) ────────────
 *
 * Mac AArch64 pushes ALL variadic args to [sp] BEFORE a variadic call.
 *
 * Linux/AAPCS64 host: libc expects varargs in registers x3/x4/... (then
 * stack), and va_list is a 32-byte struct of {__stack, __gr_top,
 * __vr_top, __gr_offs, __vr_offs}.  We synthesise the struct with
 * __gr_offs=__vr_offs=0 (saved-reg area empty) and __stack pointing at
 * Mac's vararg area, then tail-call the v-prefixed function.
 *
 * Windows ARM64 host: va_list is just `char*` and points directly at
 * the next arg byte.  The Mac vararg area already IS that — no struct
 * conversion needed; just compute the pointer and pass it.
 */
#ifdef _WIN32
/* Win32 va_list = char* pointing at Mac's already-stack-laid-out args. */
__attribute__((naked)) int mac_printf(const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "add x1, sp, #16\n"     /* x1 = mac vararg area = va_list */
        "bl vprintf\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_fprintf(FILE *fp, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "add x2, sp, #16\n"
        "bl vfprintf\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_sprintf(char *buf, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "add x2, sp, #16\n"
        "bl vsprintf\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_snprintf(char *buf, size_t size, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "add x3, sp, #16\n"
        "bl vsnprintf\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
#else
/* Frame layout after "stp x29,x30,[sp,#-64]!":
 *   [sp+64] = Mac's original sp → varargs start here
 *   [sp+16] = va_list struct (32 bytes: __stack, __gr_top, __vr_top,
 *                                        __gr_offs=0, __vr_offs=0)
 *   [sp+0]  = saved x29/x30
 */
__attribute__((naked)) int mac_printf(const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-64]!\n"
        "add x29, sp, #0\n"
        "add x1, sp, #64\n"   /* x1 = mac vararg area */
        "str x1, [sp, #16]\n" /* va_list.__stack   */
        "str x1, [sp, #24]\n" /* va_list.__gr_top  */
        "str x1, [sp, #32]\n" /* va_list.__vr_top  */
        "str wzr, [sp, #40]\n" /* va_list.__gr_offs = 0 */
        "str wzr, [sp, #44]\n" /* va_list.__vr_offs = 0 */
        "add x1, sp, #16\n"   /* x1 = &va_list (pass by ptr) */
        "bl vprintf\n"
        "ldp x29, x30, [sp], #64\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_fprintf(FILE *fp, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-64]!\n"
        "add x29, sp, #0\n"
        "add x2, sp, #64\n"
        "str x2, [sp, #16]\n"
        "str x2, [sp, #24]\n"
        "str x2, [sp, #32]\n"
        "str wzr, [sp, #40]\n"
        "str wzr, [sp, #44]\n"
        "add x2, sp, #16\n"
        "bl vfprintf\n"
        "ldp x29, x30, [sp], #64\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_sprintf(char *buf, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-64]!\n"
        "add x29, sp, #0\n"
        "add x2, sp, #64\n"
        "str x2, [sp, #16]\n"
        "str x2, [sp, #24]\n"
        "str x2, [sp, #32]\n"
        "str wzr, [sp, #40]\n"
        "str wzr, [sp, #44]\n"
        "add x2, sp, #16\n"
        "bl vsprintf\n"
        "ldp x29, x30, [sp], #64\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_snprintf(char *buf, size_t size, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-64]!\n"
        "add x29, sp, #0\n"
        "add x3, sp, #64\n"
        "str x3, [sp, #16]\n"
        "str x3, [sp, #24]\n"
        "str x3, [sp, #32]\n"
        "str wzr, [sp, #40]\n"
        "str wzr, [sp, #44]\n"
        "add x3, sp, #16\n"
        "bl vsnprintf\n"
        "ldp x29, x30, [sp], #64\n"
        "ret\n"
    );
}
#endif
#ifdef _WIN32
__attribute__((naked)) int mac_scanf(const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "add x1, sp, #16\n"
        "bl vscanf\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_fscanf(FILE *fp, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "add x2, sp, #16\n"
        "bl vfscanf\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_sscanf(const char *str, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "add x2, sp, #16\n"
        "bl vsscanf\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}
#else
__attribute__((naked)) int mac_scanf(const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-64]!\n"
        "add x29, sp, #0\n"
        "add x1, sp, #64\n"
        "str x1, [sp, #16]\n"
        "str x1, [sp, #24]\n"
        "str x1, [sp, #32]\n"
        "str wzr, [sp, #40]\n"
        "str wzr, [sp, #44]\n"
        "add x1, sp, #16\n"
        "bl vscanf\n"
        "ldp x29, x30, [sp], #64\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_fscanf(FILE *fp, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-64]!\n"
        "add x29, sp, #0\n"
        "add x2, sp, #64\n"
        "str x2, [sp, #16]\n"
        "str x2, [sp, #24]\n"
        "str x2, [sp, #32]\n"
        "str wzr, [sp, #40]\n"
        "str wzr, [sp, #44]\n"
        "add x2, sp, #16\n"
        "bl vfscanf\n"
        "ldp x29, x30, [sp], #64\n"
        "ret\n"
    );
}
__attribute__((naked)) int mac_sscanf(const char *str, const char *fmt) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-64]!\n"
        "add x29, sp, #0\n"
        "add x2, sp, #64\n"
        "str x2, [sp, #16]\n"
        "str x2, [sp, #24]\n"
        "str x2, [sp, #32]\n"
        "str wzr, [sp, #40]\n"
        "str wzr, [sp, #44]\n"
        "add x2, sp, #16\n"
        "bl vsscanf\n"
        "ldp x29, x30, [sp], #64\n"
        "ret\n"
    );
}
#endif


/* ───────────────────────────────────────────────────────────────────
 * Per-symbol NOP thunks and fill_got()
 *
 * The thunks (`nop_<sanitized symbol>`) are generated — one per nop_func
 * GOT slot.  Each calls SHIM_HIT(SHIM__<sym>) then returns 0, so the
 * counter table tells us which Mac frameworks the binary actually
 * tried to call at runtime.
 *
 * fill_got() writes the address of each thunk / mac_* shim / libc
 * function into the Mac binary's GOT and __la_symbol_ptr slots.  All
 * three categories of target live in this translation unit (thunks
 * and mac_* are static here), so fill_got can take their addresses
 * with file-scope linkage.
 * ─────────────────────────────────────────────────────────────────── */

/* exit / _Exit / abort tracing shims — dom6 sometimes terminates via
 * one of these without going through main()'s return path, bypassing
 * our crash handler and atexit dump.  Wrap them to print the exit code
 * and the immediate return address (caller PC) so we can locate the
 * decision in the Mac binary's code.  Then forward to the real libc.
 * Available on both Linux and Win32 since SPECIAL_SLOTS bindings for
 * _exit / __Exit / _abort point here on either platform. */
__attribute__((noreturn,used)) void mac_exit_trace(int code) {
    fprintf(stderr, "[dom6-loader] exit(%d) called from %p\n",
            code, __builtin_return_address(0));
    fflush(stderr);
    exit(code);
}
__attribute__((noreturn,used)) void mac_Exit_trace(int code) {
    fprintf(stderr, "[dom6-loader] _Exit(%d) called from %p\n",
            code, __builtin_return_address(0));
    fflush(stderr);
    _Exit(code);
}
__attribute__((noreturn,used)) void mac_abort_trace(void) {
    fprintf(stderr, "[dom6-loader] abort() called from %p\n",
            __builtin_return_address(0));
    fflush(stderr);
    abort();
}

#ifdef _WIN32
/* On Win32 / UCRT many POSIX libc symbols (closedir, fork, gettimeofday,
 * sigaction, mmap, freelocale, …) simply don't exist.  gen/got_bindings.inc
 * still references them — we don't want to teach the codegen about every
 * UCRT vs glibc delta.  Instead, redirect missing names to a single
 * "missing-libc" abort stub via preprocessor #defines BEFORE the include.
 * Each entry was identified by grep'ing gen/got_bindings.inc against
 * what UCRT + mingw-w64-clang-aarch64 ships.  In GUI mode none of these
 * are actually called (counter dump confirms it). */
/* Named stub generator — each symbol gets its own function so the abort
 * message tells us exactly which POSIX-only API the Mac binary tried to
 * use.  Diagnostic in GUI mode: Linux counter dump shows none of these
 * fire on the GUI startup path, so any abort here is news. */
#define MISS_STUB(name)                                                 \
    __attribute__((noreturn,used)) static void _miss_##name(void) {     \
        fprintf(stderr, "[loader-win32] FATAL: " #name " called\n");    \
        abort();                                                        \
    }

/* Tiny BSD-ish strlcpy/strlcat — UCRT declares them but doesn't link them.
 * Non-static so the linker resolves the declared protos to these defs. */
size_t strlcpy(char *dst, const char *src, size_t sz) {
    size_t n = 0;
    if (sz) { while (--sz && src[n]) { dst[n] = src[n]; n++; } dst[n] = 0; }
    while (src[n]) n++;
    return n;
}
size_t strlcat(char *dst, const char *src, size_t sz) {
    size_t dn = 0; while (dn < sz && dst[dn]) dn++;
    return dn + strlcpy(dst + dn, src, sz - dn);
}

/* BSD bzero — UCRT removed it; trivial memset wrapper.  Non-static so the
 * #define bzero -> _miss_bzero alias below can be replaced by this real impl. */
void win_bzero(void *s, size_t n) { memset(s, 0, n); }

/* Naked-asm setjmp / longjmp pair.  Saves AArch64 callee-saved general
 * regs (x19-x28), fp+lr (x29-x30), sp, and FP callee-saved (d8-d15).
 * Total 160 bytes — fits within Mac's 192-byte jmp_buf.  AAPCS64 says
 * these are all the regs a caller relies on being preserved across a
 * function call, so saving them here is enough to resume from setjmp's
 * call site. */
__attribute__((naked,used)) int win_setjmp(void *env) {
    __asm__ volatile(
        "stp x19, x20, [x0, #0]\n"
        "stp x21, x22, [x0, #16]\n"
        "stp x23, x24, [x0, #32]\n"
        "stp x25, x26, [x0, #48]\n"
        "stp x27, x28, [x0, #64]\n"
        "stp x29, x30, [x0, #80]\n"
        "mov x1, sp\n"
        "str x1, [x0, #96]\n"
        "stp d8,  d9,  [x0, #104]\n"
        "stp d10, d11, [x0, #120]\n"
        "stp d12, d13, [x0, #136]\n"
        "stp d14, d15, [x0, #152]\n"
        "mov w0, #0\n"
        "ret\n"
    );
}
__attribute__((naked,noreturn,used)) void win_longjmp(void *env, int val) {
    __asm__ volatile(
        "ldp x19, x20, [x0, #0]\n"
        "ldp x21, x22, [x0, #16]\n"
        "ldp x23, x24, [x0, #32]\n"
        "ldp x25, x26, [x0, #48]\n"
        "ldp x27, x28, [x0, #64]\n"
        "ldp x29, x30, [x0, #80]\n"
        "ldr x2, [x0, #96]\n"
        "mov sp, x2\n"
        "ldp d8,  d9,  [x0, #104]\n"
        "ldp d10, d11, [x0, #120]\n"
        "ldp d12, d13, [x0, #136]\n"
        "ldp d14, d15, [x0, #152]\n"
        /* longjmp(env, 0) must appear as a return value of 1 */
        "cmp w1, #0\n"
        "csinc w0, w1, wzr, ne\n"
        "ret\n"
    );
}

/* POSIX setlinebuf(stream) = setvbuf(stream, NULL, _IOLBF, 0). */
int win_setlinebuf(FILE *fp) { return setvbuf(fp, NULL, _IOLBF, 0); }

#ifdef _WIN32
/* SDL_CreateThread bypass — see install_sdl_redirect in loader_sdl_gl.c.
 * The native SDL2.dll's SDL_CreateThread on Win ARM64 dispatches the
 * thread proc through a heap-resident trampoline that doesn't survive
 * the Mac→Win ABI handoff on the new thread (the proc PC ends up at a
 * heap address with no executable mapping).  Run the thread proc on a
 * raw Win32 thread instead via _beginthreadex.
 *
 * Mac's SDL_ThreadFunction signature is `int (*)(void *)`; new-thread
 * stack defaults to whatever _beginthreadex picks unless the caller
 * passed an explicit stack size.  Bump it to 16 MB (matching the main
 * thread reserve) so Mac functions with large frames don't blow it. */
#include <pthread.h>

typedef int (*sdl_thread_fn)(void *);

struct mac_thread_arg {
    sdl_thread_fn fn;
    void         *data;
};

static void *mac_thread_trampoline(void *p) {
    struct mac_thread_arg *a = (struct mac_thread_arg *)p;
    sdl_thread_fn fn = a->fn;
    void *data = a->data;
    free(a);
    if (getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] thread tramp ENTER fn=%p data=%p\n", fn, data);
    int rc = fn(data);
    if (getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] thread tramp EXIT fn=%p rc=%d\n", fn, rc);
    return (void *)(intptr_t)rc;
}

static void *mac_create_thread_impl(void *fn, const char *name, void *data,
                                     size_t stack_size) {
    (void)name;
    struct mac_thread_arg *arg = malloc(sizeof *arg);
    if (!arg) return NULL;
    arg->fn = (sdl_thread_fn)fn;
    arg->data = data;
    if (stack_size == 0) stack_size = 16 * 1024 * 1024;  /* 16 MB */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, stack_size);
    pthread_t tid;
    int rc = pthread_create(&tid, &attr, mac_thread_trampoline, arg);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        free(arg);
        fprintf(stderr, "[shim] pthread_create failed: rc=%d\n", rc);
        return NULL;
    }
    /* Detach so the worker cleans up when fn() returns — dom6 doesn't
     * call SDL_WaitThread on these handles, just discards them. */
    pthread_detach(tid);
    if (getenv("DOM6_LOADER_TRACE"))
        fprintf(stderr, "[shim] SDL_CreateThread(fn=%p, name='%s') → tid=%p\n",
                fn, name ? name : "(null)", (void *)tid);
    /* SDL_Thread is opaque to dom6 — return tid cast to pointer.  If
     * dom6 ever does SDL_WaitThread we'd need to track this differently
     * since pthread_t is detached.  For now just give it something
     * non-NULL. */
    return (void *)(uintptr_t)tid;
}

void *mac_sdl_create_thread_stub(void *fn, const char *name, void *data) {
    return mac_create_thread_impl(fn, name, data, 0);
}
void *mac_sdl_create_thread_ws_stub(void *fn, const char *name,
                                    size_t stack_size, void *data) {
    return mac_create_thread_impl(fn, name, data, stack_size);
}
#endif


/* The single big list of POSIX-only libc names absent from MSYS2 UCRT +
 * mingw-w64.  Each gets a named _miss_<name> stub + #define alias so
 * gen/got_bindings.inc compiles and aborts with a diagnostic if invoked. */
/* Things mingw-w64-clang-aarch64 + UCRT DO provide and we should NOT stub:
 *   opendir/closedir/readdir/rewinddir (dirent.h shim)
 *   mkdir/rmdir/stat/fstat/fseeko/ftello (UCRT or mingw sys/stat.h)
 *   gettimeofday (mingw sys/time.h)
 *   nanosleep (winpthreads)
 *   strcasecmp/strncasecmp/strdup (UCRT _stricmp etc., aliased by mingw string.h)
 *   gethostbyname/gethostname/inet_addr/inet_ntoa (Winsock — they ARE
 *     callable once we WSAStartup; for now they auto-resolve via -lws2_32
 *     once we add it to LDLIBS)
 *
 * Things truly missing → named-stub them: */
#define WIN_MISSING(X)                  \
    /* POSIX file I/O still POSIX-only */ \
    X(realpath)                         \
    /* process (UCRT has system + _popen/_pclose; keep fork/kill/waitpid stubbed) */ \
    X(fork) X(kill) X(waitpid)          \
    /* locale (UCRT has _create_locale etc., different shape) */ \
    X(freelocale) X(newlocale) X(uselocale) \
    /* dl (we shim dlopen/dlsym/dlclose ourselves; dlerror remains) */ \
    X(dlerror)                          \
    /* signal */                        \
    X(sigaction) X(signal_posix)        \
    /* strings */                       \
    X(strcasestr)                       \
    X(strtok_r)                         \
    X(wcscasecmp) X(wcsncasecmp) X(wcslcat) X(wcslcpy) \
    /* memory (loader uses os_map_fixed; direct binary calls abort) */ \
    X(mmap) X(mprotect) X(munmap)       \
    /* sched / pthread */               \
    X(sched_get_priority_max) X(sched_get_priority_min) \
    X(pthread_sigmask)                  \
    /* env / sysconf */                 \
    X(setenv) X(sysconf)

WIN_MISSING(MISS_STUB)

/* Redirect each missing libc name to its named stub, via preprocessor.
 * `signal_posix` / `longjmp_posix` rename to avoid clobbering UCRT's
 * actual signal/longjmp macros. */
#define ALIAS(name)  name = _miss_##name,
#define realpath         _miss_realpath
#define setlinebuf       win_setlinebuf
#define fork             _miss_fork
#define kill             _miss_kill
#define waitpid          _miss_waitpid
/* popen/pclose: UCRT names them _popen/_pclose; mingw stdio.h provides
 * popen/pclose aliases.  system() is direct in UCRT.  Leave to linker. */
#define freelocale       _miss_freelocale
#define newlocale        _miss_newlocale
#define uselocale        _miss_uselocale
#define dlerror          _miss_dlerror
#define sigaction        _miss_sigaction
#define bzero            win_bzero
#define strcasestr       _miss_strcasestr
#define strtok_r         _miss_strtok_r
#define wcscasecmp       _miss_wcscasecmp
#define wcsncasecmp      _miss_wcsncasecmp
#define wcslcat          _miss_wcslcat
#define wcslcpy          _miss_wcslcpy
#define mmap             _miss_mmap
#define mprotect         _miss_mprotect
#define munmap           _miss_munmap
#define sched_get_priority_max _miss_sched_get_priority_max
#define sched_get_priority_min _miss_sched_get_priority_min
#define pthread_sigmask  _miss_pthread_sigmask
#define setenv           _miss_setenv
#define sysconf          _miss_sysconf
/* signal: UCRT has signal(int,void(*)(int)) — but Mac binary expects POSIX
 * signal w/ sigset_t etc.  Redirect via a different name so we don't break
 * UCRT's signal() macro. */
#define signal           _miss_signal_posix
/* setjmp on Win is a __builtin_setjmpex intrinsic (SEH-flavored) — not
 * compatible with the Mac binary's libc-style setjmp.  Provide a naked-
 * asm pair that uses the AArch64 AAPCS64 callee-saved register set
 * (matches Mac _setjmp's jmp_buf layout: int[48] = 192 bytes, we use
 * 160).  Saves x19-x30, sp, d8-d15. */
#undef setjmp
#define setjmp           win_setjmp
#define longjmp          win_longjmp
/* gettimeofday struct-timeval shape mismatch.
 *
 * Mac AArch64 darwin: struct timeval = { long tv_sec; int tv_usec; pad; } = 16 bytes
 * Win mingw-w64:      struct timeval = { long tv_sec; long tv_usec;     } = 8 bytes
 *   (Win64 is LLP64, so `long` is 32-bit.)
 *
 * dom6_mac code at VA 0x100593700ish reads:
 *   w8 = [tv+0x00]   ; tv_sec.low
 *   x9 = ldrsw [tv+0x08]  ; tv_usec (sign-extended; Mac slot is +8)
 *
 * Win's gettimeofday writes only the first 8 bytes; bytes +8..+15 stay as
 * stack garbage.  dom6 reads garbage as tv_usec, gets a wild value, feeds
 * it into the camera animator's progress accumulator, which goes deeply
 * negative — eventually the LERP overshoots and the terrain-LOS scan at
 * 0x10073c3f4 spins forever (camera angle ends up at 273°, outside the
 * [0, 180] clamp).
 *
 * Fix: wrap gettimeofday and re-shape into Mac's 16-byte layout.  Diagnosed
 * by HW watchpoint comparison between Linux/Win — see
 * [[loader-win-benchmark-hang]] in memory. */
struct mac_timeval_16 {
    int64_t tv_sec;
    int32_t tv_usec;
    int32_t _pad;
};
static int mac_gettimeofday(struct mac_timeval_16 *mtv, void *tz) {
    struct timeval wtv;
    int rc = gettimeofday(&wtv, NULL);  /* mingw's 8-byte struct */
    if (mtv) {
        mtv->tv_sec  = (int64_t)wtv.tv_sec;
        mtv->tv_usec = (int32_t)wtv.tv_usec;
        mtv->_pad    = 0;
    }
    (void)tz;
    return rc;
}
#define gettimeofday     mac_gettimeofday

/* ── nanosleep struct-timespec shape mismatch ──────────────────────
 *
 * Mac AArch64 darwin: struct timespec = { long tv_sec; long tv_nsec; }
 *                                       = 16 bytes (LP64, both fields 8B)
 * Win mingw-w64:      struct timespec = { time_t tv_sec; long tv_nsec; pad; }
 *                                       = 16 bytes (8B tv_sec + 4B tv_nsec + 4B pad)
 *
 * Same total size, but tv_nsec width differs.  dom6_mac stores `long`
 * (8B) into tv_nsec, then nanosleep reads it as 4B (`long` on LLP64)
 * + 4B garbage interpreted as something else; or wbritten by libc into
 * 4B leaving the high 4B garbage that dom6 then reads.  Identical
 * failure mode to [[loader-win-benchmark-hang]]: cumulative time-delta
 * goes haywire.  45 call sites in dom6_mac.
 *
 * Fix: marshal both directions.  tv_nsec values are always in
 * [0, 1e9) so the truncation/extension between 4B and 8B is lossless. */
struct mac_timespec_16 {
    int64_t tv_sec;
    int64_t tv_nsec;
};
static int mac_nanosleep(const struct mac_timespec_16 *mreq,
                         struct mac_timespec_16 *mrem) {
    struct timespec wreq = {
        .tv_sec  = (time_t)(mreq ? mreq->tv_sec  : 0),
        .tv_nsec = (long)  (mreq ? mreq->tv_nsec : 0),
    };
    struct timespec wrem;
    int rc = nanosleep(mreq ? &wreq : NULL, mrem ? &wrem : NULL);
    if (mrem) {
        mrem->tv_sec  = (int64_t)wrem.tv_sec;
        mrem->tv_nsec = (int64_t)wrem.tv_nsec;
    }
    return rc;
}
#define nanosleep        mac_nanosleep

/* ── readdir struct-dirent shape mismatch ──────────────────────────
 *
 * Mac AArch64 darwin (64-bit-inode):
 *   { u64 d_ino; u64 d_seekoff; u16 d_reclen; u16 d_namlen;
 *     u8 d_type; char d_name[1024]; pad; }   = 1048 bytes
 *   d_name at offset 21, d_type at 20, d_ino at 0.
 *
 * Win mingw-w64:
 *   { long d_ino; u16 d_reclen; u16 d_namlen; char d_name[260]; }
 *                                             = 268 bytes
 *   d_name at offset 8, NO d_type field, d_ino is 32-bit.
 *
 * All 11 dom6_mac readdir() call sites use `add x?, x0, #0x15` to
 * point at d_name (Mac offset 21).  On Win that points 13 bytes INTO
 * the filename — every readdir returns a garbage filename.  One site
 * (0x10032e7f0) also reads `[x26, #0x14]` = Mac d_type (20).
 *
 * Fix: return pointer to a thread-local Mac-shaped buffer that we
 * fill from Win's dirent.  d_type defaults to DT_UNKNOWN (0) since
 * mingw doesn't expose it. */
struct mac_dirent_1048 {
    uint64_t d_ino;        /* @0  */
    uint64_t d_seekoff;    /* @8  (unused by dom6) */
    uint16_t d_reclen;     /* @16 */
    uint16_t d_namlen;     /* @18 */
    uint8_t  d_type;       /* @20 (dom6 reads this at one site) */
    char     d_name[1024]; /* @21 */
    char     _pad[3];      /* total 1048 */
};
static __thread struct mac_dirent_1048 mac_readdir_tls;
static struct mac_dirent_1048 *mac_readdir(void *dirp) {
    struct dirent *w = readdir((DIR *)dirp);
    if (!w) return NULL;
    memset(&mac_readdir_tls, 0, sizeof mac_readdir_tls);
    mac_readdir_tls.d_ino = (uint64_t)w->d_ino;
    size_t namelen = strlen(w->d_name);
    if (namelen > sizeof mac_readdir_tls.d_name - 1)
        namelen = sizeof mac_readdir_tls.d_name - 1;
    memcpy(mac_readdir_tls.d_name, w->d_name, namelen);
    mac_readdir_tls.d_name[namelen] = '\0';
    mac_readdir_tls.d_namlen = (uint16_t)namelen;
    mac_readdir_tls.d_reclen = (uint16_t)(21 + namelen + 1);
    mac_readdir_tls.d_type   = 0; /* DT_UNKNOWN — mingw lacks d_type */
    return &mac_readdir_tls;
}
#define readdir          mac_readdir

/* ── stat/fstat struct-stat shape mismatch ─────────────────────────
 *
 * Mac AArch64 darwin (__DARWIN_STRUCT_STAT64): 144 bytes, fields at
 * very specific offsets (st_size @ 96, st_blksize @ 112, st_mode @ 4,
 * st_mtimespec.tv_sec @ 48, etc.).
 *
 * Win mingw-w64 struct stat: ~48 bytes, completely different layout
 * (st_size is 32-bit at offset 20, st_mode 16-bit at offset 6, etc.).
 * Worse, Win 32-bit stat() truncates files >2GB and 64-bit inodes.
 *
 * dom6_mac reads (verified by disassembling 4 stat + 4 fstat sites):
 *   st_mode  @ +4   (file type bits for fstat[0])
 *   st_size  @ +96  (passed through to other shims)
 *   st_blksize @ +112  (saved for buffering)
 *
 * Fix: define the Mac-shaped struct exactly; call Win's `_stat64`/
 * `_fstat64` for proper 64-bit fields; repack into the Mac shape.
 * Time fields are translated via the Mac timespec layout above. */
struct mac_stat_144 {
    int32_t  st_dev;             /* @0   */
    uint16_t st_mode;            /* @4   */
    uint16_t st_nlink;           /* @6   */
    uint64_t st_ino;             /* @8   */
    uint32_t st_uid;             /* @16  */
    uint32_t st_gid;             /* @20  */
    int32_t  st_rdev;            /* @24  */
    int32_t  _pad28;             /* @28  */
    struct mac_timespec_16 st_atimespec;      /* @32  */
    struct mac_timespec_16 st_mtimespec;      /* @48  */
    struct mac_timespec_16 st_ctimespec;      /* @64  */
    struct mac_timespec_16 st_birthtimespec;  /* @80  */
    int64_t  st_size;            /* @96  */
    int64_t  st_blocks;          /* @104 */
    int32_t  st_blksize;         /* @112 */
    uint32_t st_flags;           /* @116 */
    uint32_t st_gen;             /* @120 */
    int32_t  st_lspare;          /* @124 */
    int64_t  st_qspare[2];       /* @128, total 144 */
};
static void _win_stat64_to_mac(const struct __stat64 *w,
                               struct mac_stat_144 *m) {
    memset(m, 0, sizeof *m);
    m->st_dev   = (int32_t)w->st_dev;
    m->st_mode  = (uint16_t)w->st_mode;
    m->st_nlink = (uint16_t)w->st_nlink;
    m->st_ino   = (uint64_t)w->st_ino;
    m->st_uid   = (uint32_t)(uint16_t)w->st_uid;
    m->st_gid   = (uint32_t)(uint16_t)w->st_gid;
    m->st_rdev  = (int32_t)w->st_rdev;
    m->st_size  = (int64_t)w->st_size;
    m->st_atimespec.tv_sec = (int64_t)w->st_atime;
    m->st_mtimespec.tv_sec = (int64_t)w->st_mtime;
    m->st_ctimespec.tv_sec = (int64_t)w->st_ctime;
    m->st_birthtimespec.tv_sec = (int64_t)w->st_ctime;
    /* Win has no st_blksize / st_blocks — leave as 0; dom6's reads
     * just propagate the value, no division-by-zero risk. */
}
static int mac_stat(const char *path, struct mac_stat_144 *out) {
    struct __stat64 w;
    int rc = _stat64(path, &w);
    if (rc == 0 && out) _win_stat64_to_mac(&w, out);
    return rc;
}
static int mac_fstat(int fd, struct mac_stat_144 *out) {
    struct __stat64 w;
    int rc = _fstat64(fd, &w);
    if (rc == 0 && out) _win_stat64_to_mac(&w, out);
    return rc;
}
#define stat             mac_stat
#define fstat            mac_fstat

#endif  /* _WIN32 */

/* ~330 nop_X thunk definitions — generated from the Mac binary's GOT. */
#include "shim_thunks.inc"

/* fill_got: write each GOT slot.  Body is a long list of `*slot = …;`
 * statements generated from the binary's binding table. */
static void fill_got(void) {
    volatile uint64_t *slot;
#include "got_bindings.inc"
}

/* Externally callable from loader_main.c */
void loader_install_got(void) { fill_got(); }

/* loader_os_win32.c — Win32 backend for loader_os.h.
 *
 * Targets Windows on ARM64 via MSYS2 clangarm64 (mingw-w64 + UCRT).
 * Pairs with src/loader_os.h.
 *
 * Notes on the design choices:
 *   - os_map_fixed copies file bytes into a VirtualAlloc'd region rather
 *     than using CreateFileMapping / MapViewOfFileEx.  Win32's mapping
 *     API requires page-aligned file offsets and we already pay one disk
 *     read per segment; the copy is faster than the API marshaling cost
 *     and avoids "section size must be > 0" footguns.
 *   - os_install_crash_handler uses AddVectoredExceptionHandler.  Vectored
 *     handlers see EVERY structured exception, so we filter to access
 *     violations + illegal instructions before invoking the user cb.
 *   - os_install_dump_trigger uses SetConsoleCtrlHandler for Ctrl-Break
 *     (the closest Win32 has to SIGUSR2).  Plus atexit, same as POSIX.
 *   - os_print_memory_map walks the loaded module list via PSAPI.
 *
 * `_WIN32_WINNT` must be defined to enable PSAPI + Vectored EH.
 */
#define _WIN32_WINNT 0x0601  /* Windows 7+ */
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <io.h>           /* _get_osfhandle */
#include "loader_os.h"


/* ── memory mapping ────────────────────────────────────────────── */

static DWORD win_prot_translate(int os_prot) {
    int x = os_prot & OS_PROT_EXEC;
    int w = os_prot & OS_PROT_WRITE;
    int r = os_prot & OS_PROT_READ;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE;
    if (w)      return PAGE_READWRITE;
    if (r)      return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/* Pre-reserved Mach-O VA span; populated by the constructor below.
 * os_map_fixed commits chunks within this range. */
static int _va_reservation_done = 0;

void os_reserve_mach_va_range(uint64_t base, size_t size) {
    if (_va_reservation_done) return;
    void *p = VirtualAlloc((void*)(uintptr_t)base, size,
                           MEM_RESERVE, PAGE_NOACCESS);
    if (!p) {
        fprintf(stderr,
                "[loader] WARN: VirtualAlloc(0x%llx, 0x%zx, RESERVE) failed: %lu\n"
                "[loader]       Mach-O mmap will retry with RESERVE+COMMIT per-segment\n",
                (unsigned long long)base, size,
                (unsigned long)GetLastError());
        return;
    }
    _va_reservation_done = 1;
}

/* Run BEFORE main() — claims the high VA span so it can't race with
 * the OS heap / loader.  ASLR'd DLLs imported by our .exe may land in
 * the same region; if so the reservation fails and per-segment mapping
 * falls back to RESERVE+COMMIT (which may also fail — and that's the
 * known limitation reported in the W4 task). */
__attribute__((constructor)) static void _w32_early_reserve(void) {
    /* 4 GB span: 0x100000000 .. 0x200000000.  Covers __TEXT + __DATA +
     * __DATA_CONST + the huge __DATA,__bss block (1.26 GB) + headroom. */
    os_reserve_mach_va_range(0x100000000ULL, 0x100000000ULL);
}

int os_map_fixed(uint64_t va, size_t size, int prot,
                 int fd, uint64_t offset) {
    /* If pre-reservation succeeded, commit inside it; otherwise fall
     * back to single-shot RESERVE+COMMIT (will fail if the address is
     * already taken — same failure shape as the original loader).  Both
     * paths land us at PAGE_READWRITE so we can ReadFile into the
     * mapping; permissions are tightened at the end. */
    DWORD flags = _va_reservation_done ? MEM_COMMIT
                                       : (MEM_RESERVE | MEM_COMMIT);
    void *p = VirtualAlloc((void*)(uintptr_t)va, size, flags, PAGE_READWRITE);
    if (!p) {
        DWORD err = GetLastError();
        fprintf(stderr,
                "[loader] VirtualAlloc(%p, %zu, %s) failed: GetLastError=%lu\n",
                (void*)(uintptr_t)va, size,
                _va_reservation_done ? "COMMIT" : "RESERVE+COMMIT",
                (unsigned long)err);
        return -1;
    }
    if (p != (void*)(uintptr_t)va) {
        fprintf(stderr, "[loader] VirtualAlloc returned %p, wanted %p\n",
                p, (void*)(uintptr_t)va);
        VirtualFree(p, 0, MEM_RELEASE);
        return -1;
    }

    if (fd >= 0) {
        /* Copy bytes from the file into the mapped region. */
        HANDLE h = (HANDLE)_get_osfhandle(fd);
        if (h == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "[loader] _get_osfhandle(%d) failed\n", fd);
            VirtualFree(p, 0, MEM_RELEASE);
            return -1;
        }
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)offset;
        if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) {
            fprintf(stderr, "[loader] SetFilePointerEx failed: %lu\n",
                    (unsigned long)GetLastError());
            VirtualFree(p, 0, MEM_RELEASE);
            return -1;
        }
        DWORD done;
        size_t left = size;
        char *dst = (char*)p;
        while (left) {
            DWORD chunk = (left > (1u<<24)) ? (1u<<24) : (DWORD)left;
            if (!ReadFile(h, dst, chunk, &done, NULL) || done == 0) {
                fprintf(stderr, "[loader] ReadFile failed (left=%zu): %lu\n",
                        left, (unsigned long)GetLastError());
                VirtualFree(p, 0, MEM_RELEASE);
                return -1;
            }
            dst  += done;
            left -= done;
        }
    }

    DWORD want = win_prot_translate(prot);
    if (want != PAGE_READWRITE) {
        DWORD old;
        if (!VirtualProtect(p, size, want, &old)) {
            fprintf(stderr, "[loader] VirtualProtect failed: %lu\n",
                    (unsigned long)GetLastError());
            return -1;
        }
    }
    return 0;
}

void *os_map_anon_rwx(size_t size) {
    return VirtualAlloc(NULL, size,
                        MEM_RESERVE | MEM_COMMIT,
                        PAGE_EXECUTE_READWRITE);
}

long os_page_size(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (long)si.dwPageSize;
}


/* ── dynamic library loading ──────────────────────────────────── */

/* Linux soname → Win32 DLL name.  Caller passes POSIX-style; we look up
 * the equivalent DLL.  Default fallback: try the name as-is. */
static const char *win_lib_name(const char *posix_soname) {
    if (!posix_soname) return NULL;
    if (!strcmp(posix_soname, "libSDL2-2.0.so.0")) return "SDL2.dll";
    if (!strcmp(posix_soname, "libSDL2.so"))       return "SDL2.dll";
    if (!strcmp(posix_soname, "libGL.so.1"))       return "opengl32.dll";
    if (!strcmp(posix_soname, "libGLU.so.1"))      return "glu32.dll";
    return posix_soname;
}

static __thread char tls_lib_err[256];

os_lib_t os_lib_open(const char *posix_soname) {
    const char *win_name = win_lib_name(posix_soname);
    HMODULE h = LoadLibraryA(win_name);
    if (!h) {
        DWORD err = GetLastError();
        snprintf(tls_lib_err, sizeof tls_lib_err,
                 "LoadLibraryA(%s) failed: GetLastError=%lu", win_name,
                 (unsigned long)err);
        return NULL;
    }
    tls_lib_err[0] = '\0';
    return (os_lib_t)h;
}

void *os_lib_sym(os_lib_t lib, const char *symbol) {
    void *p = (void*)GetProcAddress((HMODULE)lib, symbol);
    if (!p) {
        DWORD err = GetLastError();
        snprintf(tls_lib_err, sizeof tls_lib_err,
                 "GetProcAddress(%s) failed: GetLastError=%lu", symbol,
                 (unsigned long)err);
    }
    return p;
}

const char *os_lib_error(void) {
    return tls_lib_err[0] ? tls_lib_err : NULL;
}


/* ── crash handler ─────────────────────────────────────────────── */

static os_crash_cb_t crash_cb;

static LONG WINAPI win_crash_trampoline(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    /* Filter to faults we care about; let everything else through so
     * the debugger / default handler still sees it. */
    /* Log EVERY exception (we see, then continue to dispatch).  This
     * helps locate things like STATUS_FAIL_FAST_EXCEPTION (0xC0000409)
     * that bypass normal SEH delivery. */
    {
        char buf[256];
        int n = snprintf(buf, sizeof buf,
                         "[veh] exception 0x%lx (first_chance=%lu) PC=0x%llx\n",
                         (unsigned long)code,
                         (unsigned long)ep->ExceptionRecord->ExceptionFlags,
                         (unsigned long long)ep->ContextRecord->Pc);
        DWORD wrote;
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, n, &wrote, NULL);
    }
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_IN_PAGE_ERROR    &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_DATATYPE_MISALIGNMENT &&
        code != EXCEPTION_STACK_OVERFLOW) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    CONTEXT *ctx = ep->ContextRecord;
    os_crash_ctx_t c;
    /* Map Win32 exception code → POSIX signal-ish for logging consistency. */
    switch (code) {
      case EXCEPTION_ACCESS_VIOLATION: c.signal_code = 11; break;  /* SEGV */
      case EXCEPTION_IN_PAGE_ERROR:    c.signal_code = 7;  break;  /* BUS  */
      case EXCEPTION_ILLEGAL_INSTRUCTION: c.signal_code = 4; break;/* ILL  */
      default:                         c.signal_code = (int)code;
    }
    c.pc = ctx->Pc;
    c.sp = ctx->Sp;
    c.lr = ctx->Lr;
    c.fp = ctx->Fp;
    c.fault_addr = (uint64_t)ep->ExceptionRecord->ExceptionInformation[1];
    /* CONTEXT_ARM64 lays out X[0..28] as a flat array; X29=Fp, X30=Lr.
     * We copy x0..x28 then append fp, lr. */
    for (int i = 0; i < 29; i++) c.regs[i] = ctx->X[i];
    c.regs[29] = ctx->Fp;
    c.regs[30] = ctx->Lr;
    if (crash_cb) crash_cb(&c);
    return EXCEPTION_EXECUTE_HANDLER;  /* terminate */
}

static LONG WINAPI win_unhandled_filter(EXCEPTION_POINTERS *ep) {
    char buf[256];
    int n = snprintf(buf, sizeof buf,
                     "[ueh] UNHANDLED exception 0x%lx PC=0x%llx — terminating\n",
                     (unsigned long)ep->ExceptionRecord->ExceptionCode,
                     (unsigned long long)ep->ContextRecord->Pc);
    DWORD wrote;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, n, &wrote, NULL);
    return EXCEPTION_EXECUTE_HANDLER;
}

void os_install_crash_handler(os_crash_cb_t cb) {
    crash_cb = cb;
    AddVectoredExceptionHandler(1 /* first */, win_crash_trampoline);
    SetUnhandledExceptionFilter(win_unhandled_filter);
    /* SEM_FAILCRITICALERRORS prevents Windows error dialog popup. */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
}


/* ── counter-dump trigger ──────────────────────────────────────── */

static os_dump_cb_t dump_cb;

static BOOL WINAPI win_ctrl_handler(DWORD ctrl) {
    if (ctrl == CTRL_BREAK_EVENT && dump_cb) {
        dump_cb();
        return TRUE;
    }
    return FALSE;
}

static void win_atexit_trampoline(void) {
    if (dump_cb) dump_cb();
}

void os_install_dump_trigger(os_dump_cb_t cb) {
    dump_cb = cb;
    SetConsoleCtrlHandler(win_ctrl_handler, TRUE);
    atexit(win_atexit_trampoline);
}


/* ── memory map snapshot ───────────────────────────────────────── */

void os_print_memory_map(uint64_t pc, uint64_t lr) {
    HANDLE proc = GetCurrentProcess();
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(proc, mods, sizeof mods, &needed)) return;
    DWORD count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;
    char buf[512];
    char path[MAX_PATH];
    for (DWORD i = 0; i < count; i++) {
        MODULEINFO mi;
        if (!GetModuleInformation(proc, mods[i], &mi, sizeof mi)) continue;
        uint64_t base = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
        uint64_t end  = base + mi.SizeOfImage;
        if ((pc >= base && pc < end) || (lr >= base && lr < end)) {
            if (GetModuleFileNameExA(proc, mods[i], path, sizeof path) == 0)
                path[0] = '?', path[1] = '\0';
            int n = snprintf(buf, sizeof buf,
                             "  MOD: 0x%llx-0x%llx  %s\n",
                             (unsigned long long)base,
                             (unsigned long long)end, path);
            if (n > 0) fwrite(buf, 1, (size_t)n, stderr);
        }
    }
}


/* ── misc ──────────────────────────────────────────────────────── */

void os_ignore_broken_pipe(void) {
    /* Win32 sockets return WSAECONNRESET instead of raising a signal —
     * there's nothing to suppress.  No-op. */
}

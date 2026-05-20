/* loader_os.h — host-OS abstraction for the loader's own startup.
 *
 * Covers the calls the LOADER makes on its way to handing control to the
 * Mac binary:
 *   - mmap'ing Mach-O segments at fixed VAs
 *   - dlopen + dlsym of host libSDL2 / libGL / libGLU
 *   - installing the crash / counter-dump signal handlers
 *   - parsing /proc/self/maps for crash diagnostics
 *   - ignoring SIGPIPE so server sockets don't kill the process
 *
 * Does NOT cover the mac_* ABI shims (loader_shims.c): those EMULATE
 * POSIX/Mac libc for the Mac binary's syscalls, and split their POSIX
 * vs Win implementations per shim via #ifdef _WIN32.
 *
 * Implementations:
 *   src/loader_os_posix.c   — Linux + (in principle) macOS, *BSD
 *   src/loader_os_win32.c   — Windows on ARM64 (MSYS2 clangarm64 / mingw-w64)
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── memory mapping ────────────────────────────────────────────── */

/* OS-portable protection flags.  Backends translate to PROT_… / PAGE_…. */
#define OS_PROT_READ   0x1
#define OS_PROT_WRITE  0x2
#define OS_PROT_EXEC   0x4

/* Map `size` bytes at fixed VA `va` with `prot`.
 *   fd >= 0 : file-backed mapping at `offset`
 *   fd <  0 : anonymous (offset ignored)
 * Behaves like POSIX MAP_FIXED — fails if `va` is unavailable, never
 * relocates.  Returns 0 on success, -1 on failure (errno set on POSIX). */
int os_map_fixed(uint64_t va, size_t size, int prot,
                 int fd, uint64_t offset);

/* Allocate `size` bytes of RWX memory at any address.  Used for the SDL
 * trap-thunk page.  Returns pointer, or NULL on failure. */
void *os_map_anon_rwx(size_t size);

/* Page size in bytes (sysconf(_SC_PAGESIZE) on POSIX, dwPageSize on Win). */
long os_page_size(void);

/* Pre-reserve the Mach-O VA range so later os_map_fixed calls don't lose
 * a race with the OS heap / DLL loader.  POSIX impl is a no-op (mmap
 * MAP_FIXED never races); Win32 impl claims 0x100000000-0x200000000
 * with VirtualAlloc(MEM_RESERVE) via a constructor so it runs before
 * main() and most DLL load activity. */
void os_reserve_mach_va_range(uint64_t base, size_t size);


/* ── dynamic library loading ──────────────────────────────────── */

/* Opaque library handle. */
typedef struct os_lib *os_lib_t;

/* Open a host library by its POSIX soname.  The backend may translate:
 *   "libSDL2-2.0.so.0" → "SDL2.dll" on Win32, etc.
 * Returns NULL on failure; call os_lib_error() for diagnostics. */
os_lib_t  os_lib_open(const char *posix_soname);

/* Resolve a symbol; returns NULL if not present. */
void     *os_lib_sym(os_lib_t lib, const char *symbol);

/* Most recent error from os_lib_open / os_lib_sym (or NULL). */
const char *os_lib_error(void);


/* ── crash handler ─────────────────────────────────────────────── */

/* OS-neutral crash context.  Per-OS backends fill it from ucontext_t /
 * EXCEPTION_RECORD before calling the user callback. */
typedef struct {
    int      signal_code;     /* abstract: 11=SEGV, 7=BUS, 4=ILL (POSIX SIG*). */
    uint64_t pc;
    uint64_t lr;              /* x30 on AArch64 */
    uint64_t fp;              /* x29 on AArch64 */
    uint64_t sp;
    uint64_t fault_addr;      /* faulting memory address (si_addr) */
    uint64_t regs[31];        /* x0..x30 */
} os_crash_ctx_t;

typedef void (*os_crash_cb_t)(const os_crash_ctx_t *);

/* Register `cb` as the handler for SEGV/BUS/ILL.  Replaces any previous
 * registration.  cb runs in signal context — keep it async-signal-safe. */
void os_install_crash_handler(os_crash_cb_t cb);


/* ── counter-dump trigger ──────────────────────────────────────── */

/* Out-of-band trigger that fires the shim-counter dump:
 *   POSIX:  SIGUSR2 (Mac binary owns SIGUSR1 for its own admin commands)
 *   Win32:  console ctrl handler (Ctrl-Break)
 * Also registered with atexit() so a clean exit always fires the cb. */
typedef void (*os_dump_cb_t)(void);
void os_install_dump_trigger(os_dump_cb_t cb);


/* ── memory-map snapshot for crash diagnostics ─────────────────── */

/* Print (to stderr) the loaded-module entries whose VA range covers
 * either `pc` or `lr`.  Used by the crash handler to identify which
 * library a fault landed in.  Async-signal-safe on POSIX (raw write +
 * stack-buffer parsing of /proc/self/maps). */
void os_print_memory_map(uint64_t pc, uint64_t lr);


/* ── misc ──────────────────────────────────────────────────────── */

/* Make SIGPIPE a no-op (POSIX); no-op on Win32 (sockets don't raise). */
void os_ignore_broken_pipe(void);

#ifdef __cplusplus
}
#endif

/* loader_os_posix.c — POSIX backend for loader_os.h.
 *
 * Targets Linux + glibc (also works on macOS / *BSD with minor tweaks).
 * Owns every POSIX-specific call the loader's own startup makes:
 * mmap MAP_FIXED, dlopen/dlsym, sigaction for crash + SIGUSR2, parse
 * /proc/self/maps, signal(SIGPIPE).
 *
 * See loader_os.h for the interface and loader_os_win32.c for the
 * Windows backend.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include "loader_os.h"


/* ── memory mapping ────────────────────────────────────────────── */

static int posix_prot_translate(int os_prot) {
    int p = 0;
    if (os_prot & OS_PROT_READ)  p |= PROT_READ;
    if (os_prot & OS_PROT_WRITE) p |= PROT_WRITE;
    if (os_prot & OS_PROT_EXEC)  p |= PROT_EXEC;
    return p;
}

int os_map_fixed(uint64_t va, size_t size, int prot,
                 int fd, uint64_t offset) {
    int flags = MAP_FIXED | MAP_PRIVATE;
    if (fd < 0) flags |= MAP_ANONYMOUS;
    void *r = mmap((void*)(uintptr_t)va, size,
                   posix_prot_translate(prot), flags,
                   fd, (off_t)offset);
    if (r == MAP_FAILED) {
        /* Caller is the loader's mmap_segments — perror gives a clear
         * single-line diagnostic before the caller bails out. */
        perror("os_map_fixed");
        return -1;
    }
    return 0;
}

void *os_map_anon_rwx(size_t size) {
    void *r = mmap(NULL, size,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    return (r == MAP_FAILED) ? NULL : r;
}

long os_page_size(void) {
    return sysconf(_SC_PAGESIZE);
}

void os_reserve_mach_va_range(uint64_t base, size_t size) {
    /* POSIX mmap MAP_FIXED never loses a race — kernel guarantees the
     * placement.  Nothing to do. */
    (void)base; (void)size;
}


/* ── dynamic library loading ──────────────────────────────────── */

os_lib_t os_lib_open(const char *posix_soname) {
    /* On POSIX the soname IS the load name — no translation needed. */
    return (os_lib_t)dlopen(posix_soname, RTLD_NOW | RTLD_GLOBAL);
}

void *os_lib_sym(os_lib_t lib, const char *symbol) {
    return dlsym((void*)lib, symbol);
}

const char *os_lib_error(void) {
    return dlerror();
}


/* ── crash handler ─────────────────────────────────────────────── */

static os_crash_cb_t crash_cb;

static void posix_crash_trampoline(int sig, siginfo_t *si, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    os_crash_ctx_t c;
    c.signal_code = sig;
    c.pc = uc->uc_mcontext.pc;
    c.sp = uc->uc_mcontext.sp;
    c.lr = uc->uc_mcontext.regs[30];
    c.fp = uc->uc_mcontext.regs[29];
    c.fault_addr = (uint64_t)(uintptr_t)si->si_addr;
    for (int i = 0; i < 31; i++) c.regs[i] = uc->uc_mcontext.regs[i];
    if (crash_cb) crash_cb(&c);
}

void os_install_crash_handler(os_crash_cb_t cb) {
    crash_cb = cb;
    struct sigaction sa = {0};
    sa.sa_sigaction = posix_crash_trampoline;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
}


/* ── counter-dump trigger ──────────────────────────────────────── */

static os_dump_cb_t dump_cb;

static void posix_dump_trampoline(int sig) {
    (void)sig;
    if (dump_cb) dump_cb();
}

static void posix_atexit_trampoline(void) {
    if (dump_cb) dump_cb();
}

void os_install_dump_trigger(os_dump_cb_t cb) {
    dump_cb = cb;
    struct sigaction sa = {0};
    sa.sa_handler = posix_dump_trampoline;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    /* SIGUSR2: SIGUSR1 is claimed by the Mac binary itself for its
     * interactive admin parser and will override anything we install. */
    sigaction(SIGUSR2, &sa, NULL);
    atexit(posix_atexit_trampoline);
}


/* ── memory-map snapshot ───────────────────────────────────────── */

void os_print_memory_map(uint64_t pc, uint64_t lr) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return;
    char line[256];
    int pos = 0;
    char ch;
    while (read(fd, &ch, 1) == 1) {
        if (pos < (int)sizeof(line) - 1) line[pos++] = ch;
        if (ch == '\n') {
            line[pos] = '\0';
            unsigned long long start, end;
            if (sscanf(line, "%llx-%llx", &start, &end) == 2) {
                if ((pc >= start && pc < end) || (lr >= start && lr < end)) {
                    (void)!write(STDERR_FILENO, "  MAP: ", 7);
                    (void)!write(STDERR_FILENO, line, (size_t)pos);
                }
            }
            pos = 0;
        }
    }
    close(fd);
}


/* ── misc ──────────────────────────────────────────────────────── */

void os_ignore_broken_pipe(void) {
    signal(SIGPIPE, SIG_IGN);
}

void os_early_init(void) {
    /* Win-specific DLL-search and GALLIUM_DRIVER defaults don't apply
     * on POSIX: dlopen() honours ld.so.cache + RPATH + LD_LIBRARY_PATH,
     * and host libGL is provided by the distro's mesa-libgl package. */
}

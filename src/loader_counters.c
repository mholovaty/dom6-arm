/* loader_counters.c — shim counter machinery (storage + dump path).
 *
 * The big shim_names[]/shim_kinds[] tables and the SHIM__ enum are
 * generated.  This file owns:
 *   - the atomic counter array
 *   - the async-signal-safe dump function (also gdb-callable)
 *   - the SIGUSR2 handler + atexit registration that fire the dump
 *
 * The per-symbol nop_X thunks (~330 of them) live in loader_shims.c
 * alongside fill_got, because fill_got needs file-scope access to both
 * the thunks and the mac_* shims.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdatomic.h>
#include "loader_counters.h"
#include "loader_os.h"   /* os_install_dump_trigger */

/* shim_names[], shim_kinds[] — generated alongside the SHIM__ enum. */
#include "shim_table.inc"

/* Counter storage — extern-visible (declared in loader_counters.h) so
 * loader_shims.c (where nop_X thunks live) can SHIM_HIT into it. */
atomic_uint_fast64_t shim_counters[SHIM_COUNT];  /* BSS-zero-init */

/* Async-signal-safe: only raw write() and stack-buffer snprintf.
 * `externally_visible` so `(gdb) call mac_shim_dump_counters()` works. */
__attribute__((used, externally_visible, noinline))
void mac_shim_dump_counters(void) {
    char buf[256];
    int n;
    static const char hdr[] = "[shim-trace] === counter snapshot ===\n";
    (void)!write(STDERR_FILENO, hdr, sizeof(hdr)-1);
    uint64_t total = 0;
    for (int i = 0; i < SHIM_COUNT; i++) {
        uint64_t c = atomic_load_explicit(&shim_counters[i], memory_order_relaxed);
        if (!c) continue;
        const char *tag = shim_kinds[i] == 1 ? " (data,untracked)" : "";
        n = snprintf(buf, sizeof(buf), "[shim-trace] %-44s %12" PRIu64 "%s\n",
                     shim_names[i], (uint64_t)c, tag);
        if (n > 0) (void)!write(STDERR_FILENO, buf, (size_t)n);
        total += c;
    }
    n = snprintf(buf, sizeof(buf), "[shim-trace] === total: %" PRIu64 " calls ===\n",
                 total);
    if (n > 0) (void)!write(STDERR_FILENO, buf, (size_t)n);
}

void install_shim_dump_handler(void) {
    /* Out-of-band trigger (SIGUSR2 on POSIX, console-ctrl on Win32) plus
     * atexit so clean exits also dump.  See src/loader_os.h. */
    os_install_dump_trigger(mac_shim_dump_counters);
}

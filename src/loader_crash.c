/* loader_crash.c — SIGSEGV / SIGBUS / SIGILL handler.
 *
 * Async-signal-safe: only raw write() and stack-buffer snprintf.  Prints
 * register dump, fault address, a frame-pointer backtrace, and the
 * /proc/self/maps slice covering PC/LR (via os_print_memory_map — the
 * one OS-specific bit, delegated to loader_os_posix.c).
 */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include "loader_os.h"


/* Write a fixed string and a single int.  Hand-rolled because printf is
 * not async-signal-safe and we're invoked from a signal handler. */
static void emit_line(char *buf, int n) {
    if (n > 0) (void)!write(STDERR_FILENO, buf, (size_t)n);
}


/* The Mac image is mapped at its native base, so an address inside it is one subtraction away
 * from a file offset that can be disassembled. Doing that by hand for every crash is the kind
 * of step that gets skipped. MAC_IMAGE_SPAN is generous: __TEXT through __DATA is well under
 * it, and a false positive costs a misleading annotation, not a wrong answer. */
#define MAC_IMAGE_BASE 0x100000000ULL
#define MAC_IMAGE_SPAN 0x010000000ULL

static void emit_where(const char *what, uint64_t addr) {
    char buf[128];
    if (addr < MAC_IMAGE_BASE || addr >= MAC_IMAGE_BASE + MAC_IMAGE_SPAN) return;
    int n = snprintf(buf, sizeof buf, "  %s 0x%llx is dom6_mac + 0x%llx\n",
                     what, (unsigned long long)addr,
                     (unsigned long long)(addr - MAC_IMAGE_BASE));
    if (n > 0) (void)!write(STDERR_FILENO, buf, (size_t)n);
}


static void handle_crash(const os_crash_ctx_t *c) {
    char buf[256];
    int n;

    n = snprintf(buf, sizeof buf,
        "\n[CRASH] sig=%d PC=0x%llx LR=0x%llx FP=0x%llx SP=0x%llx fault=0x%llx\n",
        c->signal_code,
        (unsigned long long)c->pc, (unsigned long long)c->lr,
        (unsigned long long)c->fp, (unsigned long long)c->sp,
        (unsigned long long)c->fault_addr);
    emit_line(buf, n);

    /* Where in the GAME each address falls — the question every crash starts with. */
    emit_where("PC   ", c->pc);
    emit_where("LR   ", c->lr);
    emit_where("fault", c->fault_addr);

    for (int i = 0; i < 31; i++) {
        n = snprintf(buf, sizeof buf, "  x%-2d = 0x%016llx\n",
                     i, (unsigned long long)c->regs[i]);
        emit_line(buf, n);
    }

    /* Frame-pointer walk.  Stop on the usual termination conditions:
     * misaligned FP, FP below SP, FP too far above SP, fp_n == fp_prev. */
    n = snprintf(buf, sizeof buf, "\n[STACK TRACE]\n");
    emit_line(buf, n);
    uint64_t cur_fp   = c->fp;
    uint64_t sp_limit = c->sp + 64ULL * 1024 * 1024;
    for (int depth = 0; depth < 24
                     && cur_fp && (cur_fp & 7) == 0
                     && cur_fp >= c->sp && cur_fp < sp_limit; depth++) {
        uint64_t saved_fp = 0, saved_lr = 0;
        __builtin_memcpy(&saved_fp, (void *)cur_fp,   8);
        __builtin_memcpy(&saved_lr, (void *)(cur_fp + 8), 8);
        /* A frame whose return address is not a mapped code address means the chain has
         * broken; printing further frames invents a backtrace. Stop instead. */
        if (saved_lr < 0x10000ULL) break;
        n = snprintf(buf, sizeof buf, "  [%2d] fp=0x%llx lr=0x%llx\n",
                     depth, (unsigned long long)cur_fp,
                     (unsigned long long)saved_lr);
        emit_line(buf, n);
        emit_where("       lr", saved_lr);
        if (saved_fp == cur_fp || saved_fp == 0) break;
        cur_fp = saved_fp;
    }

    os_print_memory_map(c->pc, c->lr);
    _exit(139);
}


void install_crash_handler(void) {
    os_install_crash_handler(handle_crash);
}

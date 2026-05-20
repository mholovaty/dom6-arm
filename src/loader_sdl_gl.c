/* loader_sdl_gl.c — redirect SDL2 and OpenGL calls to host libraries.
 *
 * SDL2 path (Phase 2): at startup, dlopen(libSDL2-2.0.so.0) and overwrite
 * every entry in dom6_mac's SDL dynapi jump_table (836 slots) with the
 * host's symbol address.  Variadic SDL_* (SDL_SetError, SDL_Log*, …, 11
 * total) need naked-asm wrappers that re-marshal Mac AArch64
 * stack-vararg → Linux register-vararg before tail-calling.
 *
 * GL path (Phase 4): dlopen(libGL.so.1, libGLU.so.1) and overwrite each
 * gl* / glu* GOT slot with the host's symbol.  73 slots in total.
 *
 * Missing host SDL symbols cause per-slot trap thunks to be installed;
 * if any fire at runtime the binary exits with a clear message.  Trap
 * count > 0 at install time indicates host/Mac SDL version mismatch and
 * should fail the smoke test.
 */
#include "loader_common.h"
#include "loader_os.h"

#define SDL_JUMP_TABLE_VA  0x100ae5e58UL
#define SDL_SLOT_COUNT     836

/* The redirect table's row type.  Generated table populates it. */
typedef struct {
    const char *name;            /* host SDL symbol to dlsym */
    uint16_t    slot;            /* index into the Mac binary's jump_table */
    const void *va_wrapper;      /* non-NULL: install this instead (variadic) */
    void      **host_ptr_p;      /* where to stash the raw dlsym for the wrapper */
} sdl_redirect_entry_t;

/* host_X externs + sdl_va_X naked-asm wrappers + sdl_redirects[] table. */
#include "sdl_redirect.inc"

/* ── per-slot trap thunks (for slots whose host dlsym failed) ────── */

static const char *_sdl_slot_to_name(uint16_t slot) {
    for (size_t i = 0; i < SDL_REDIRECT_COUNT; i++)
        if (sdl_redirects[i].slot == slot) return sdl_redirects[i].name;
    return "<unknown>";
}

__attribute__((noinline, used))
static void sdl_missing_handler_impl(uint16_t slot) {
    fprintf(stderr, "[loader] FATAL: Mac binary called missing host SDL slot %u (%s)\n",
            (unsigned)slot, _sdl_slot_to_name(slot));
    _exit(99);
}

/* Generate a 2-instruction thunk per trap site (`mov w0, #slot ; b impl`)
 * in a private RWX page.  Bounded: if the host is missing > 32 SDL
 * symbols the install pass should already have failed. */
#define MAX_SDL_TRAPS 32
static void   *sdl_trap_page;
static size_t  sdl_trap_page_off;

static void *sdl_install_trap(uint16_t slot) {
    static int sdl_trap_count = 0;
    if (sdl_trap_count >= MAX_SDL_TRAPS) return NULL;
    if (!sdl_trap_page) {
        sdl_trap_page = os_map_anon_rwx((size_t)os_page_size());
        if (!sdl_trap_page) return NULL;
    }
    uint32_t *code = (uint32_t*)((char*)sdl_trap_page + sdl_trap_page_off);
    code[0] = 0x52800000U | ((uint32_t)slot << 5);        /* mov w0, #slot */
    intptr_t disp = (intptr_t)sdl_missing_handler_impl - (intptr_t)&code[1];
    code[1] = 0x14000000U | (((uint32_t)(disp >> 2)) & 0x03ffffffU);  /* b impl */
    __builtin___clear_cache((char*)&code[0], (char*)&code[2]);
    sdl_trap_page_off += 8;
    sdl_trap_count++;
    return (void*)code;
}

/* ── public: install SDL redirect.  Called from loader_main.c ───── */
void install_sdl_redirect(void) {
    const char *libname = "libSDL2-2.0.so.0";
    os_lib_t h = os_lib_open(libname);
    if (!h) {
        fprintf(stderr, "[loader] FATAL: os_lib_open(%s) failed: %s\n",
                libname, os_lib_error());
        fprintf(stderr, "[loader] Install libSDL2 on host (e.g. apt install libsdl2-2.0-0)\n");
        _exit(98);
    }

    uint64_t *jt = (uint64_t*)SDL_JUMP_TABLE_VA;
    size_t redirected = 0, trapped = 0, varargs_done = 0;
    for (size_t i = 0; i < SDL_REDIRECT_COUNT; i++) {
        const sdl_redirect_entry_t *e = &sdl_redirects[i];
        void *host = os_lib_sym(h, e->name);
        if (!host) {
            void *trap = sdl_install_trap(e->slot);
            if (trap) { jt[e->slot] = (uint64_t)trap; trapped++; }
            continue;
        }
        if (e->va_wrapper) {
            *e->host_ptr_p = host;
            jt[e->slot] = (uint64_t)e->va_wrapper;
            varargs_done++;
        } else {
            jt[e->slot] = (uint64_t)host;
        }
        redirected++;
    }
    fprintf(stderr,
            "[loader] sdl: redirected %zu/%zu slots (variadic wrappers: %zu, traps: %zu)\n",
            redirected, (size_t)SDL_REDIRECT_COUNT, varargs_done, trapped);

#ifdef _WIN32
    /* SDL_CreateThread on Win ARM64 ends up dispatching through a heap-
     * resident SDL trampoline that doesn't survive the Mac→Win ABI
     * handoff when the new thread starts.  dom6 uses it from bgload_init
     * (texture preloader) and tcp_init (per-connection worker pool).
     * Server mode doesn't need these threads — replace with a stub that
     * returns a non-NULL fake handle and never actually starts a thread.
     * Slots 11 = SDL_CreateThread, 645 = SDL_CreateThreadWithStackSize. */
    extern void *mac_sdl_create_thread_stub(void *fn, const char *name, void *data);
    extern void *mac_sdl_create_thread_ws_stub(void *fn, const char *name,
                                               size_t stack_size, void *data);
    jt[11]  = (uint64_t)mac_sdl_create_thread_stub;
    jt[645] = (uint64_t)mac_sdl_create_thread_ws_stub;
    fprintf(stderr, "[loader] sdl: SDL_CreateThread + SDL_CreateThreadWithStackSize stubbed\n");
#endif
}

/* ── GL / GLU redirect (Phase 4) ─────────────────────────────────── */

typedef struct {
    uint64_t    slot_addr;       /* Mac binary's GOT slot for `_gl…` */
    const char *name;            /* without leading underscore */
    uint8_t     is_glu;          /* 0 = libGL.so.1, 1 = libGLU.so.1 */
} gl_redirect_entry_t;

/* gl_redirects[] table + GL_REDIRECT_COUNT. */
#include "gl_redirect.inc"

void install_gl_redirect(void) {
    os_lib_t libgl  = os_lib_open("libGL.so.1");
    os_lib_t libglu = os_lib_open("libGLU.so.1");
    if (!libgl) {
        fprintf(stderr, "[loader] FATAL: os_lib_open(libGL.so.1) failed: %s\n",
                os_lib_error());
        fprintf(stderr, "[loader] Install host OpenGL (e.g. apt install libgl1)\n");
        _exit(97);
    }
    if (!libglu) {
        fprintf(stderr, "[loader] WARN: os_lib_open(libGLU.so.1) failed: %s\n",
                os_lib_error());
        fprintf(stderr, "[loader]       glu* calls will fall back to nop stubs.\n");
    }
    size_t bound = 0, missed = 0;
    for (size_t i = 0; i < GL_REDIRECT_COUNT; i++) {
        const gl_redirect_entry_t *e = &gl_redirects[i];
        os_lib_t h = e->is_glu ? libglu : libgl;
        if (!h) { missed++; continue; }
        void *fn = os_lib_sym(h, e->name);
        if (!fn) {
            fprintf(stderr, "[loader] WARN: host has no %s — leaving NOP stub\n", e->name);
            missed++; continue;
        }
        *(volatile uint64_t*)e->slot_addr = (uint64_t)fn;
        bound++;
    }
    fprintf(stderr,
            "[loader] gl: redirected %zu/%zu slots to host libGL/libGLU (missed %zu)\n",
            bound, (size_t)GL_REDIRECT_COUNT, missed);
}

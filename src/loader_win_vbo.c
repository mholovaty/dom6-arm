/* loader_win_vbo.c — software ARB_vertex_buffer_object for Win.
 *
 * Two-stage operation:
 *
 *   1. STARTUP — install_win_vbo() runs immediately after
 *      install_gl_redirect(), BEFORE any GL context exists.
 *      install_gl_redirect's flat GetProcAddress can't see VBO symbols
 *      (Mesa, like stock Win opengl32, exports them only via
 *      wglGetProcAddress which requires a current context), so the
 *      4 ARB slots come back NULL.  We patch in software-emulator
 *      replacements + offset-translation hooks for glVertexPointer
 *      etc. so the slots aren't traps.
 *
 *   2. POST-CONTEXT — on the first vbo_glGenBuffersARB call, dom6 has
 *      created an SDL GL context, which means wglGetProcAddress now
 *      works.  We resolve the real Mesa-provided ARB functions, write
 *      them straight into the GOT (and restore the un-translated
 *      glVertexPointer / glDrawElements etc.), and drop ourselves out
 *      of the call path entirely.  All subsequent draws hit Mesa
 *      directly — no per-frame CPU upload of "client side arrays" —
 *      which is the actual fix.  The Adreno GPU hang we hit otherwise
 *      seems related to the per-frame stream-upload pattern Mesa is
 *      forced into when there are no real VBOs.
 *
 * Falls back to the software emulator if wglGetProcAddress can't find
 * the ARB functions (e.g. context not current yet).  In practice the
 * fallback never fires under Mesa.
 *
 * Win-only.  Compiled out on POSIX (libGL has real VBOs). */

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

/* GL constants we need — avoid pulling in a full GL header to keep the
 * file independent of toolchain GL headers. */
#define GL_ARRAY_BUFFER_ARB          0x8892
#define GL_ELEMENT_ARRAY_BUFFER_ARB  0x8893

/* GL types we use, defined to match the standard ABI. */
typedef unsigned int  GLenum;
typedef unsigned int  GLuint;
typedef int           GLint;
typedef int           GLsizei;
typedef ptrdiff_t     GLsizeiptr;

/* GL slot addresses in the Mac binary's GOT (from
 * build/loader/gen/gl_redirect.inc).  These are the slots whose function
 * pointers we install_win_vbo() patches. */
#define SLOT_glBindBufferARB     ((volatile uint64_t*)0x0000000100ae0840UL)
#define SLOT_glBufferDataARB     ((volatile uint64_t*)0x0000000100ae0858UL)
#define SLOT_glDeleteBuffersARB  ((volatile uint64_t*)0x0000000100ae08a8UL)
#define SLOT_glGenBuffersARB     ((volatile uint64_t*)0x0000000100ae0930UL)
#define SLOT_glVertexPointer     ((volatile uint64_t*)0x0000000100ae0a38UL)
#define SLOT_glColorPointer      ((volatile uint64_t*)0x0000000100ae08a0UL)
#define SLOT_glNormalPointer     0  /* not in slot table — see install_win_vbo */
#define SLOT_glTexCoordPointer   ((volatile uint64_t*)0x0000000100ae0a00UL)
#define SLOT_glDrawElements      ((volatile uint64_t*)0x0000000100ae08e0UL)

/* ── State ────────────────────────────────────────────────────────── */

/* dom6 main-menu UI burns through >1024 buffers (text glyphs, sprite
 * batches, UI quads).  Bump the pool generously — entries are 24B each,
 * so 64K slots cost ~1.5 MB of zeroed BSS.  Real fix is to call the
 * host VBO functions directly via wglGetProcAddress after the GL
 * context exists, instead of emulating them. */
#define MAX_VBO  65536

struct win_vbo {
    void  *data;
    size_t size;
    int    allocated;   /* 0 = free slot, 1 = in use (Gen'd, maybe Buffer'd) */
};
static struct win_vbo s_vbos[MAX_VBO];
static GLuint s_bound_array = 0;    /* GL_ARRAY_BUFFER_ARB binding   */
static GLuint s_bound_elem  = 0;    /* GL_ELEMENT_ARRAY_BUFFER_ARB   */
static GLuint s_scan_hint   = 1;    /* search start for next free slot (0 reserved) */
static GLuint s_live_peak   = 0;    /* max concurrent live VBOs (for diag)  */
static GLuint s_live_now    = 0;    /* current live count                   */

/* Real entry points captured before we patch the slots — used to
 * forward calls after offset translation. */
static void (*real_glVertexPointer)(GLint, GLenum, GLsizei, const void*);
static void (*real_glColorPointer)(GLint, GLenum, GLsizei, const void*);
static void (*real_glNormalPointer)(GLenum, GLsizei, const void*);
static void (*real_glTexCoordPointer)(GLint, GLenum, GLsizei, const void*);
static void (*real_glDrawElements)(GLenum, GLsizei, GLenum, const void*);

/* ── Try to escape the emulator: bind GOT slots straight to Mesa ── */

#define TRACE(...) do { if (getenv("DOM6_VBO_TRACE")) \
    fprintf(stderr, __VA_ARGS__); } while (0)

/* Cached wglGetProcAddress, populated at install_win_vbo time. */
typedef PROC (WINAPI *wgl_get_proc_t)(LPCSTR);
static wgl_get_proc_t s_wgl_get_proc;
/* 0 = not yet attempted, 1 = succeeded (emulator off), -1 = gave up. */
static int s_real_arb_state;

/* Resolve Mesa's real glGenBuffers/Bind/BufferData/Delete via the now-
 * current GL context and hot-patch the Mac GOT slots to point at them.
 * Also restores the un-hooked glVertexPointer / glColorPointer /
 * glTexCoordPointer / glDrawElements pointers — once Mesa owns VBO
 * state itself, our offset-translation wrappers are wrong and harmful. */
static int try_promote_to_real_vbo(void) {
    if (s_real_arb_state != 0) return s_real_arb_state == 1;
    if (!s_wgl_get_proc) { s_real_arb_state = -1; return 0; }

    /* Try ARB names first (older Mesa), fall back to core names. */
    void *g  = (void *)s_wgl_get_proc("glGenBuffersARB");
    void *b  = (void *)s_wgl_get_proc("glBindBufferARB");
    void *d  = (void *)s_wgl_get_proc("glBufferDataARB");
    void *de = (void *)s_wgl_get_proc("glDeleteBuffersARB");
    if (!g || !b || !d || !de) {
        g  = (void *)s_wgl_get_proc("glGenBuffers");
        b  = (void *)s_wgl_get_proc("glBindBuffer");
        d  = (void *)s_wgl_get_proc("glBufferData");
        de = (void *)s_wgl_get_proc("glDeleteBuffers");
    }
    if (!g || !b || !d || !de) {
        /* No GL context current yet, or Mesa really doesn't have them.
         * Stay on the emulator but allow another retry on the next call —
         * dom6 may legitimately call glGenBuffers before make-current
         * on the first frame.  We only give up after a budget. */
        static int retries;
        if (++retries > 16) { s_real_arb_state = -1; }
        return 0;
    }

    *SLOT_glGenBuffersARB    = (uint64_t)g;
    *SLOT_glBindBufferARB    = (uint64_t)b;
    *SLOT_glBufferDataARB    = (uint64_t)d;
    *SLOT_glDeleteBuffersARB = (uint64_t)de;

    /* Restore un-hooked vertex/element pointers — Mesa needs the raw
     * offset args from dom6, not the CPU pointers we'd translate to. */
    *SLOT_glVertexPointer    = (uint64_t)real_glVertexPointer;
    *SLOT_glColorPointer     = (uint64_t)real_glColorPointer;
    *SLOT_glTexCoordPointer  = (uint64_t)real_glTexCoordPointer;
    *SLOT_glDrawElements     = (uint64_t)real_glDrawElements;

    s_real_arb_state = 1;
    fprintf(stderr,
            "[win-vbo] real Mesa VBO functions resolved post-context; "
            "emulator disabled, GOT now bound straight to Mesa\n");
    return 1;
}

/* ── Fake VBO API (fallback when Mesa VBO lookup hasn't succeeded) ── */

static void vbo_glGenBuffersARB(GLsizei n, GLuint *ids) {
    if (try_promote_to_real_vbo()) {
        ((void (*)(GLsizei, GLuint *))*SLOT_glGenBuffersARB)(n, ids);
        return;
    }
    for (GLsizei i = 0; i < n; i++) {
        GLuint id = 0;
        /* Scan from hint forward, wrap to 1 if needed.  Slot 0 reserved. */
        for (GLuint step = 0; step < MAX_VBO; step++) {
            GLuint cand = s_scan_hint + step;
            if (cand >= MAX_VBO) cand = 1 + (cand - MAX_VBO) % (MAX_VBO - 1);
            if (!s_vbos[cand].allocated) { id = cand; break; }
        }
        if (!id) {
            fprintf(stderr, "[win-vbo] WARN: id space exhausted (>%d live), "
                            "returning 0\n", MAX_VBO);
            ids[i] = 0;
            continue;
        }
        s_vbos[id].allocated = 1;
        s_scan_hint = (id + 1 >= MAX_VBO) ? 1 : id + 1;
        s_live_now++;
        if (s_live_now > s_live_peak) s_live_peak = s_live_now;
        ids[i] = id;
    }
    TRACE("[win-vbo] glGenBuffersARB(%d) → first_id=%u (live=%u peak=%u)\n",
          n, n>0?ids[0]:0, s_live_now, s_live_peak);
}

static void vbo_glBindBufferARB(GLenum target, GLuint id) {
    if (id >= MAX_VBO) {
        fprintf(stderr, "[win-vbo] WARN: bind invalid id %u\n", id);
        id = 0;
    }
    if (target == GL_ARRAY_BUFFER_ARB)        s_bound_array = id;
    else if (target == GL_ELEMENT_ARRAY_BUFFER_ARB) s_bound_elem = id;
    /* other targets (PIXEL_PACK etc.) silently ignored — dom6 doesn't use them */
    TRACE("[win-vbo] glBindBufferARB(target=0x%x, id=%u)\n", target, id);
}

static void vbo_glBufferDataARB(GLenum target, GLsizeiptr size,
                                 const void *data, GLenum /*usage*/) {
    GLuint id = (target == GL_ARRAY_BUFFER_ARB) ? s_bound_array : s_bound_elem;
    if (!id || id >= MAX_VBO) return;
    struct win_vbo *v = &s_vbos[id];
    free(v->data);
    v->data = NULL;
    v->size = 0;
    if (size > 0) {
        v->data = malloc((size_t)size);
        if (v->data) {
            if (data) memcpy(v->data, data, (size_t)size);
            v->size = (size_t)size;
        }
    }
    TRACE("[win-vbo] glBufferDataARB(target=0x%x, id=%u, size=%zu, data=%p) → stored=%p\n",
          target, id, (size_t)size, data, v->data);
}

static void vbo_glDeleteBuffersARB(GLsizei n, const GLuint *ids) {
    for (GLsizei i = 0; i < n; i++) {
        GLuint id = ids[i];
        if (!id || id >= MAX_VBO) continue;
        if (!s_vbos[id].allocated) continue;
        free(s_vbos[id].data);
        s_vbos[id].data = NULL;
        s_vbos[id].size = 0;
        s_vbos[id].allocated = 0;
        s_live_now--;
        /* Steer the next Gen back here — keeps the working set tight. */
        if (id < s_scan_hint) s_scan_hint = id;
        if (id == s_bound_array) s_bound_array = 0;
        if (id == s_bound_elem)  s_bound_elem  = 0;
    }
}

/* ── *Pointer hooks: translate offset → CPU pointer when VBO bound ── */

static const void *resolve_array_ptr(const void *ptr) {
    if (!s_bound_array) return ptr;
    if (s_bound_array >= MAX_VBO || !s_vbos[s_bound_array].data) return ptr;
    return (const char *)s_vbos[s_bound_array].data + (uintptr_t)ptr;
}
static const void *resolve_elem_ptr(const void *ptr) {
    if (!s_bound_elem) return ptr;
    if (s_bound_elem >= MAX_VBO || !s_vbos[s_bound_elem].data) return ptr;
    return (const char *)s_vbos[s_bound_elem].data + (uintptr_t)ptr;
}

static void hook_glVertexPointer(GLint sz, GLenum type, GLsizei stride,
                                 const void *ptr) {
    const void *resolved = resolve_array_ptr(ptr);
    TRACE("[win-vbo] glVertexPointer(sz=%d, type=0x%x, stride=%d, ptr=%p) "
          "bound=%u → %p\n", sz, type, stride, ptr, s_bound_array, resolved);
    real_glVertexPointer(sz, type, stride, resolved);
}
static void hook_glColorPointer(GLint sz, GLenum type, GLsizei stride,
                                const void *ptr) {
    const void *resolved = resolve_array_ptr(ptr);
    TRACE("[win-vbo] glColorPointer bound=%u ptr=%p→%p\n",
          s_bound_array, ptr, resolved);
    real_glColorPointer(sz, type, stride, resolved);
}
static void hook_glNormalPointer(GLenum type, GLsizei stride, const void *ptr) {
    real_glNormalPointer(type, stride, resolve_array_ptr(ptr));
}
static void hook_glTexCoordPointer(GLint sz, GLenum type, GLsizei stride,
                                   const void *ptr) {
    const void *resolved = resolve_array_ptr(ptr);
    TRACE("[win-vbo] glTexCoordPointer bound=%u ptr=%p→%p\n",
          s_bound_array, ptr, resolved);
    real_glTexCoordPointer(sz, type, stride, resolved);
}
static void hook_glDrawElements(GLenum mode, GLsizei count, GLenum type,
                                const void *indices) {
    const void *resolved = resolve_elem_ptr(indices);
    TRACE("[win-vbo] glDrawElements(mode=0x%x, count=%d, type=0x%x, idx=%p) "
          "bound_elem=%u → %p\n", mode, count, type, indices,
          s_bound_elem, resolved);
    real_glDrawElements(mode, count, type, resolved);
}

/* ── Install: patch GL slots after install_gl_redirect ───────────── */

void install_win_vbo(void) {
    /* Capture the real (host) function pointers before we overwrite the
     * slots with our hooks, so the hooks can forward correctly AND so
     * try_promote_to_real_vbo can restore the un-hooked versions once
     * Mesa's real VBOs take over.  Slots populated by
     * install_gl_redirect() in loader_sdl_gl.c. */
    real_glVertexPointer   = (void *)*SLOT_glVertexPointer;
    real_glColorPointer    = (void *)*SLOT_glColorPointer;
    real_glTexCoordPointer = (void *)*SLOT_glTexCoordPointer;
    real_glDrawElements    = (void *)*SLOT_glDrawElements;

    /* Cache wglGetProcAddress for post-context VBO resolution.  Pulled
     * from Mesa's opengl32.dll (already loaded by install_gl_redirect).
     * NULL if for some reason opengl32 didn't load — we'll stay on the
     * software emulator forever. */
    HMODULE opengl32 = GetModuleHandleA("opengl32.dll");
    if (opengl32) {
        s_wgl_get_proc = (wgl_get_proc_t)GetProcAddress(opengl32, "wglGetProcAddress");
    }

    /* glNormalPointer isn't in the dom6 GL slot table — skip its hook.
     * If dom6 ever calls it with a VBO bound the offset would leak
     * through, but install_gl_redirect's "missed" count tells us this
     * symbol isn't reached by dom6 anyway. */

    *SLOT_glBindBufferARB    = (uint64_t)(void *)vbo_glBindBufferARB;
    *SLOT_glBufferDataARB    = (uint64_t)(void *)vbo_glBufferDataARB;
    *SLOT_glDeleteBuffersARB = (uint64_t)(void *)vbo_glDeleteBuffersARB;
    *SLOT_glGenBuffersARB    = (uint64_t)(void *)vbo_glGenBuffersARB;

    *SLOT_glVertexPointer    = (uint64_t)(void *)hook_glVertexPointer;
    *SLOT_glColorPointer     = (uint64_t)(void *)hook_glColorPointer;
    *SLOT_glTexCoordPointer  = (uint64_t)(void *)hook_glTexCoordPointer;
    *SLOT_glDrawElements     = (uint64_t)(void *)hook_glDrawElements;

    fprintf(stderr,
            "[win-vbo] installed: VBO emulator armed, will try to hand "
            "control to Mesa on first glGenBuffers (wgl=%s)\n",
            s_wgl_get_proc ? "ok" : "missing");
}

#else  /* !_WIN32 */
void install_win_vbo(void) { /* no-op on POSIX (real VBOs via libGL) */ }
#endif

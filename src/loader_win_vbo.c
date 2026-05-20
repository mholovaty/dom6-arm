/* loader_win_vbo.c — software ARB_vertex_buffer_object for Win.
 *
 * Windows' opengl32.dll exports only OpenGL 1.1 statically; anything
 * beyond (including the VBO functions glBindBufferARB et al.) is only
 * reachable via wglGetProcAddress on a current GL context.  The
 * loader resolves GL symbols at startup via GetProcAddress, before
 * any context exists, so those 4 slots come back NULL.
 *
 * This file implements the 4 VBO functions in software (Gen/Bind/
 * BufferData/Delete, backing each ID with a heap buffer) and
 * intercepts glVertexPointer/ColorPointer/TexCoordPointer/DrawElements
 * to translate "offset into VBO" arguments back to CPU pointers when
 * a VBO is bound — the rest of the draw goes through opengl32.dll's
 * 1.1 client-side-arrays path, which works.
 *
 * Wired up by install_win_vbo(), called from loader_main.c right
 * after install_gl_redirect() so the host glVertexPointer etc.
 * pointers are captured before the slots get overwritten.
 *
 * Future cleanup: defer GL symbol resolution to post-SDL_GL_CreateContext
 * and use wglGetProcAddress for the missed ARB slots — that would make
 * this file unnecessary.
 *
 * Win-only.  Compiled out on POSIX (libGL has real VBOs). */

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

#define MAX_VBO  1024

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

/* ── Fake VBO API ────────────────────────────────────────────────── */

#define TRACE(...) do { if (getenv("DOM6_VBO_TRACE")) \
    fprintf(stderr, __VA_ARGS__); } while (0)

static void vbo_glGenBuffersARB(GLsizei n, GLuint *ids) {
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
     * slots with our hooks, so the hooks can forward correctly.  The
     * slots are populated by install_gl_redirect() in loader_sdl_gl.c. */
    real_glVertexPointer   = (void *)*SLOT_glVertexPointer;
    real_glColorPointer    = (void *)*SLOT_glColorPointer;
    real_glTexCoordPointer = (void *)*SLOT_glTexCoordPointer;
    real_glDrawElements    = (void *)*SLOT_glDrawElements;

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
            "[win-vbo] installed: ARB_vertex_buffer_object emulation "
            "via client-side arrays\n");
}

#else  /* !_WIN32 */
void install_win_vbo(void) { /* no-op on POSIX (real VBOs via libGL) */ }
#endif

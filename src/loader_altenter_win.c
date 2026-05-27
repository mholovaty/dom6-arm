/* Alt+Enter fullscreen fix — see loader_altenter.h for the full rationale.
 * Windows-only logic; empty stubs elsewhere so it links into every build. */
#include "loader_altenter.h"
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32) && !defined(DOM6_ALTENTER_FIX_DISABLED)

#include <windows.h>
#include <string.h>
#include <stdint.h>

static int       g_enabled = 1;
static void     *g_window;          /* SDL_Window* */
static HWND      g_hwnd;
static unsigned  g_window_id;
static HHOOK     g_hook;
static int       g_alt_down;
static int       g_enter_down;      /* de-bounce auto-repeat: one toggle per press */

/* Resolved directly from the host SDL2 (dom6 may never call some of these). */
static int      (*p_GetWindowWMInfo)(void *, void *);
static void     (*p_GetVersion)(void *);
static int      (*p_PushEvent)(void *);
static unsigned (*p_GetWindowID)(void *);

/* SDL_SysWMinfo: version@0 (must be set), subsystem@4, then the union; on
 * Windows the HWND (info.win.window) is the first union member, at offset 8. */
static HWND resolve_hwnd(void) {
    if (g_hwnd || !g_window || !p_GetWindowWMInfo || !p_GetVersion) return g_hwnd;
    unsigned char wm[128];
    memset(wm, 0, sizeof wm);
    p_GetVersion(wm);
    if (p_GetWindowWMInfo(g_window, wm)) g_hwnd = *(HWND *)(wm + 8);
    return g_hwnd;
}

/* SDL_KeyboardEvent (ABI-stable across SDL2): type@0, windowID@8, state@12,
 * repeat@13, keysym{ scancode@16, sym@20, mod@24 }. */
static void push_synthetic_alt_enter(void) {
    if (!p_PushEvent) return;
    unsigned char ev[64];
    for (int up = 0; up < 2; up++) {
        memset(ev, 0, sizeof ev);
        *(uint32_t *)(ev + 0)  = up ? 0x301u : 0x300u;  /* SDL_KEYUP : SDL_KEYDOWN */
        *(uint32_t *)(ev + 8)  = g_window_id;
        ev[12] = up ? 0 : 1;                            /* RELEASED : PRESSED */
        *(int32_t *)(ev + 16)  = 40;                    /* SDL_SCANCODE_RETURN */
        *(int32_t *)(ev + 20)  = 13;                    /* SDLK_RETURN */
        *(uint16_t *)(ev + 24) = 0x0100;                /* KMOD_LALT */
        p_PushEvent(ev);
    }
}

static LRESULT CALLBACK ll_kbd(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        const KBDLLHOOKSTRUCT *k = (const KBDLLHOOKSTRUCT *)lp;
        DWORD vk = k->vkCode;
        int down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU) g_alt_down = down;
        if (vk == VK_RETURN && g_alt_down) {
            HWND hwnd = resolve_hwnd();
            if (hwnd && GetForegroundWindow() == hwnd) {
                if (down && !g_enter_down) {            /* one toggle per physical press */
                    g_enter_down = 1;
                    push_synthetic_alt_enter();
                } else if (!down) {
                    g_enter_down = 0;
                }
                return 1;   /* swallow before DXGI's pump-level Alt+Enter trap */
            }
        }
    }
    return CallNextHookEx(g_hook, code, wp, lp);
}

static void altenter_shutdown(void) {
    if (g_hook) { UnhookWindowsHookEx(g_hook); g_hook = NULL; }
}

void altenter_fix_init(os_lib_t sdl) {
    const char *e = getenv("DOM6_ALTENTER_FIX");
    g_enabled = !(e && e[0] == '0');               /* on unless explicitly "0" */
    if (!g_enabled || !sdl) return;
    *(void **)&p_GetWindowWMInfo = os_lib_sym(sdl, "SDL_GetWindowWMInfo");
    *(void **)&p_GetVersion      = os_lib_sym(sdl, "SDL_GetVersion");
    *(void **)&p_PushEvent       = os_lib_sym(sdl, "SDL_PushEvent");
    *(void **)&p_GetWindowID     = os_lib_sym(sdl, "SDL_GetWindowID");
}

void altenter_fix_on_window(void *sdl_window) {
    if (!g_enabled || g_hook || !sdl_window) return;
    g_window = sdl_window;
    resolve_hwnd();
    if (p_GetWindowID) g_window_id = p_GetWindowID(sdl_window);
    g_hook = SetWindowsHookExW(WH_KEYBOARD_LL, ll_kbd, GetModuleHandleW(NULL), 0);
    atexit(altenter_shutdown);
    fprintf(stderr, "[altenter] DXGI Alt+Enter fix active (hook=%p hwnd=%p id=%u)\n",
            (void *)g_hook, (void *)g_hwnd, g_window_id);
}

#else  /* non-Windows, or compiled out: no DXGI, no bug */

void altenter_fix_init(os_lib_t sdl)        { (void)sdl; }
void altenter_fix_on_window(void *window)   { (void)window; }

#endif

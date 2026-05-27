/* Alt+Enter fullscreen fix for the Windows-on-ARM loader.  Self-contained and
 * removable: delete this file + loader_altenter_win.c and drop the two calls in
 * loader_sdl_gl.c (altenter_fix_init + altenter_fix_on_window).
 *
 * Why it exists: on Windows-ARM dom6's GL present runs Mesa-zink -> Vulkan ->
 * Adreno WSI -> DXGI.  DXGI's *documented default* traps hardware Alt+Enter and
 * forces the swapchain into EXCLUSIVE fullscreen (the WSI never opts out via
 * MakeWindowAssociation(NO_ALT_ENTER)).  That exclusive switch desyncs the
 * Vulkan-WSI swapchain and wedges the present -> hard freeze.  dom6's own
 * borderless Alt+Enter toggle is fine; the freeze is purely DXGI's switch.
 *
 * The fix: a WH_KEYBOARD_LL hook (runs before the key is queued, hence before
 * DXGI's pump-level trap) swallows hardware Alt+Enter while dom6 is foreground,
 * then pushes a synthetic SDL Alt+Enter so dom6 runs its own borderless toggle.
 * DXGI never sees an Enter *message*, so it never fires.  This mirrors why a
 * PostMessage'd Alt+Enter (no kernel key-state) always worked.
 *
 * Switch: ON by default on Windows.  DOM6_ALTENTER_FIX=0 disables at runtime;
 * -DDOM6_ALTENTER_FIX_DISABLED compiles it out.  Non-Windows: no-op (no DXGI). */
#ifndef LOADER_ALTENTER_H
#define LOADER_ALTENTER_H

#include "loader_os.h"

/* Resolve the few SDL entry points the fix needs + read the on/off switch.
 * Pass the already-open host SDL2 handle. */
void altenter_fix_init(os_lib_t sdl);

/* Arm the fix for dom6's window.  Call once, right after SDL_CreateWindow. */
void altenter_fix_on_window(void *sdl_window);

#endif /* LOADER_ALTENTER_H */

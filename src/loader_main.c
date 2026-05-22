/* loader_main.c — process entry point + boot orchestration.
 *
 * Boot sequence:
 *   1. install crash handler (loader_crash.c)
 *   2. install SIGUSR2 / atexit counter-dump (loader_counters.c)
 *   3. SIG_IGN SIGPIPE so server sockets don't kill the process
 *   4. resolve absolute Mac binary path, chdir into virtual MacOS/ dir
 *   5. mmap each Mach-O segment at its native VA (0x100000000 base)
 *   6. fill GOT / __la_symbol_ptr slots → mac_* shims + nop_X thunks
 *      (loader_install_got, defined in loader_shims.c next to its targets)
 *   7. install SDL dynapi redirect → host libSDL2 (loader_sdl_gl.c)
 *   8. install gl/glu GOT redirect → host libGL/libGLU (loader_sdl_gl.c)
 *   9. jump to MAC_ENTRYPOINT (Mac binary's `_main`) */
#include "loader_common.h"
#include "loader_counters.h"
#include "loader_os.h"

/* Symbols defined in other translation units. */
extern void install_crash_handler(void);
extern void loader_install_got(void);   /* loader_shims.c — calls fill_got */
extern void install_sdl_redirect(void); /* loader_sdl_gl.c */
extern void install_gl_redirect(void);  /* loader_sdl_gl.c */

/* Mac entry point address — generated from the binary's LC_MAIN/LC_UNIXTHREAD. */
typedef int (*mac_main_fn)(int, char**, char**);
#include "entry.inc"

#ifdef _WIN32
static void loader_atexit_marker(void) {
    fprintf(stderr, "[dom6-loader] atexit marker fired\n");
    fflush(stderr);
}
#endif

/* ── mmap_segments: load Mac binary segments at their native VAs ──
 * Body is a sequence of mmap() calls generated from the binary's
 * LC_SEGMENT_64 load commands.  Run once at startup. */
static int mmap_segments(const char *mac_path) {
    int fd = open(mac_path, O_RDONLY);
    if (fd < 0) { perror("open mac binary"); return -1; }
#include "segments.inc"
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    extern char **environ;

#ifdef _WIN32
    /* Unbuffer stderr early so trace output isn't lost when dom6 calls
     * _exit() (which bypasses atexit + libc flush). */
    setvbuf(stderr, NULL, _IONBF, 0);
    atexit(loader_atexit_marker);
#endif
    /* OS-specific early setup (Win: DLL search path + GALLIUM_DRIVER). */
    os_early_init();
    install_crash_handler();
    install_shim_dump_handler();
    /* macOS ignores SIGPIPE on sockets by default; Linux terminates.
     * Windows sockets don't raise SIGPIPE at all (returns WSAECONNRESET). */
    os_ignore_broken_pipe();

#ifdef _WIN32
    /* Winsock requires explicit initialisation before any socket() call.
     * Without this, mac_socket/bind/listen all silently fail and the
     * tcpserver exits before binding. */
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            fprintf(stderr, "[dom6-loader] WSAStartup failed (%d)\n",
                    WSAGetLastError());
    }

    /* Drop-in compatibility with the native Dominions6.exe Steam build:
     * use the same %APPDATA%\Dominions6 directory.  dom6 honors five
     * env vars as explicit dir overrides (literal strings DOM6_CONF /
     * DOM6_SAVE / DOM6_DATA / DOM6_LOCALMAPS / DOM6_MODS in __cstring),
     * bypassing the binary's `~/.dominions6` tilde-expansion path —
     * which produces mojibake on Win32 because dom6's home-dir builder
     * relies on POSIX getpwuid/HOME conventions our loader can't fully
     * recreate.  Setting these all to %APPDATA%\Dominions6 lands saves
     * in the same dir as the native Steam build. */
    {
        const char *appdata = getenv("APPDATA");
        if (!appdata) appdata = "C:\\";
        /* If the caller already set DOM6_CONF (e.g. for isolated tests
         * that don't want to inherit the user's saved settings), respect
         * it and use it as the base — otherwise fall back to the native
         * Dominions6.exe location.  Same for DOM6_SAVE/LOCALMAPS/MODS. */
        const char *user_conf = getenv("DOM6_CONF");
        char default_base[MAX_PATH];
        snprintf(default_base, sizeof default_base, "%s\\Dominions6", appdata);
        const char *base = user_conf ? user_conf : default_base;
        CreateDirectoryA(base, NULL);                      /* OK if exists */
        char sub[MAX_PATH];
        snprintf(sub, sizeof sub, "%s\\savedgames", base);  CreateDirectoryA(sub, NULL);
        snprintf(sub, sizeof sub, "%s\\maps",       base);  CreateDirectoryA(sub, NULL);
        snprintf(sub, sizeof sub, "%s\\mods",       base);  CreateDirectoryA(sub, NULL);
        fprintf(stderr, "[dom6-loader] conf dir: %s%s\n", base,
                user_conf ? " (DOM6_CONF override)" : "");
        if (!user_conf) _putenv_s("DOM6_CONF", base);
        if (!getenv("DOM6_SAVE"))      _putenv_s("DOM6_SAVE",      base);
        if (!getenv("DOM6_LOCALMAPS")) _putenv_s("DOM6_LOCALMAPS", base);
        if (!getenv("DOM6_MODS"))      _putenv_s("DOM6_MODS",      base);
        if (!getenv("HOME"))           _putenv_s("HOME",           appdata);
        /* DOM6_DATA intentionally unset — let dom6 fall back to the
         * bundle's `data/` dir alongside the .exe.  Deployment requires
         * copying origin/data/ next to dom6_aarch64.exe. */
    }
#endif

    const char *mac_path = getenv("DOM6_MAC_PATH");
    if (!mac_path) mac_path = DOM6_MAC_PATH;

    /* Resolve to absolute so it stays valid after chdir. */
    char abs_mac_path[4096];
#ifdef _WIN32
    if (!_fullpath(abs_mac_path, mac_path, sizeof(abs_mac_path))) {
#else
    if (!realpath(mac_path, abs_mac_path)) {
#endif
        strncpy(abs_mac_path, mac_path, sizeof(abs_mac_path)-1);
        abs_mac_path[sizeof(abs_mac_path)-1] = '\0';
    }
    mac_path = abs_mac_path;
#ifdef _WIN32
    _putenv_s("DOM6_MAC_PATH", abs_mac_path);
#else
    setenv("DOM6_MAC_PATH", abs_mac_path, 1);
#endif

    /* chdir to <dirname(mac_path)>/MacOS (virtual app-bundle subdir) so the
     * binary's hardcoded "../data/<file>" paths resolve to <dirname>/data/. */
    {
#ifdef _WIN32
        /* _fullpath returns backslashes; pick whichever separator wins. */
        const char *fwd = strrchr(abs_mac_path, '/');
        const char *bwd = strrchr(abs_mac_path, '\\');
        const char *slash = (fwd > bwd) ? fwd : bwd;
#else
        const char *slash = strrchr(abs_mac_path, '/');
#endif
        if (slash && slash > abs_mac_path) {
            char bundle_dir[4096];
            snprintf(bundle_dir, sizeof(bundle_dir),
                     "%.*s/MacOS", (int)(slash - abs_mac_path), abs_mac_path);
#ifdef _WIN32
            mkdir(bundle_dir);          /* Win32 mkdir takes 1 arg */
#else
            mkdir(bundle_dir, 0755);
#endif
            if (chdir(bundle_dir) != 0)
                perror("[dom6-loader] chdir to bundle MacOS dir");
            else
                fprintf(stderr, "[dom6-loader] cwd -> %s\n", bundle_dir);
        }
    }

    if (mmap_segments(mac_path) != 0) {
        fprintf(stderr, "[dom6-loader] Failed to map Mac binary: %s\n", mac_path);
        return 1;
    }

    /* Mac binary's stdio expects FILE** indirection — wire to host libc FILE*. */
    mac_stderr_val = stderr;
    mac_stdout_val = stdout;
    mac_stdin_val  = stdin;

    loader_install_got();      /* libc + Mac framework shims */
    install_sdl_redirect();    /* SDL dynapi → host libSDL2 */
    install_gl_redirect();     /* gl/glu GOT → host libGL/libGLU */
    /* MUST run after install_gl_redirect — captures the real host
     * glVertexPointer/glColorPointer/etc. pointers before overwriting
     * the slots with VBO-translation hooks.  No-op on POSIX. */
    extern void install_win_vbo(void);
    install_win_vbo();

#ifdef _WIN32
    /* dom6's bgload_init (texture preload background threads) crashes on
     * Win ARM64 when SDL_CreateThread runs its thread proc — the thread
     * proc dispatches through a heap-resident SDL trampoline that doesn't
     * survive the Mac ABI handoff.  --nothread doesn't suppress it.  Patch
     * bgload_init's first instruction to `ret` (0xD65F03C0) so dom6 skips
     * background loading entirely.  In server / textonly mode this only
     * means save-file loads happen on the main thread — no functional loss.
     * mmap'd __TEXT segment is RX — VirtualProtect to RWX for the write. */
    /* bgload_init used to crash because SDL_CreateThread's thread proc
     * trampoline didn't survive the Mac→Win ABI handoff.  We now stub
     * SDL_CreateThread entirely (see install_sdl_redirect), so this
     * patch is no longer needed.  Set DOM6_BGLOAD_PATCH=1 to re-enable
     * the `mov w0,#0; ret` patch for debugging. */
    if (getenv("DOM6_BGLOAD_PATCH")) {
        void *bgload_init = (void *)0x10072c1bcULL;
        DWORD old_prot;
        if (VirtualProtect(bgload_init, 8, PAGE_EXECUTE_READWRITE, &old_prot)) {
            ((uint32_t *)bgload_init)[0] = 0x52800000;  /* movz w0, #0 */
            ((uint32_t *)bgload_init)[1] = 0xD65F03C0;  /* ret */
            FlushInstructionCache(GetCurrentProcess(), bgload_init, 8);
            VirtualProtect(bgload_init, 8, old_prot, &old_prot);
        }
    }

    /* Pre-mark dom6's SDL_DYNAPI init-done flag so the per-symbol
     * dispatch trampolines (0x100016400, 0x10001641c, …) skip the
     * resolver at 0x1000202dc.  If the resolver runs, it calls dom6's
     * INTERNAL SDL_DYNAPI_entry (bl 0x100013060) which overwrites the
     * 0x100ae6000+ vtable — and our install_sdl_redirect's host libSDL2
     * pointers — with dom6_mac's built-in SDL stubs.  Skipping the
     * init keeps our redirect intact. */
    {
        uint8_t *init_done_flag = (uint8_t *)0x104cb8caaULL;
        *init_done_flag = 1;
    }
#endif

    /* Transfer control to the Mac binary. */
    mac_main_fn mac_main = (mac_main_fn)MAC_ENTRYPOINT;
#ifdef _WIN32
    /* Also write a marker to a dedicated trace file so we know whether
     * mac_main returns even if stderr was closed/redirected mid-run. */
    HANDLE trace_h = CreateFileA("C:\\msys64\\tmp\\dom6run\\boot.trace",
                                 GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (trace_h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(trace_h, "ENTER mac_main\n", 15, &w, NULL);
        CloseHandle(trace_h);
    }
#endif
    fprintf(stderr, "[dom6-loader] entering mac_main @ %p\n", (void*)mac_main);
    fflush(stderr);
    int rc = mac_main(argc, argv, environ);
#ifdef _WIN32
    trace_h = CreateFileA("C:\\msys64\\tmp\\dom6run\\boot.trace",
                          GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (trace_h != INVALID_HANDLE_VALUE) {
        SetFilePointer(trace_h, 0, NULL, FILE_END);
        char buf[64];
        DWORD w;
        int n = snprintf(buf, sizeof buf, "RETURNED rc=%d\n", rc);
        WriteFile(trace_h, buf, n, &w, NULL);
        CloseHandle(trace_h);
    }
#endif
    fprintf(stderr, "[dom6-loader] mac_main returned %d\n", rc);
    fflush(stderr);
    return rc;
}

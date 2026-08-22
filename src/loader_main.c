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

/* ── check_binary: refuse a dom6_mac this loader was not built for ──
 *
 * Every generated table here — GOT bindings, segment map, SDL jump table,
 * entry point — describes ONE upstream build.  Run it against another and
 * nothing announces itself: the loader jumps to whatever now lives at the old
 * entry point and the failure surfaces later, elsewhere, as an unreadable
 * crash.  The binary states its own entry point in LC_MAIN, so the two are
 * compared.  Costs one read of the Mach-O header at startup. */
static int check_binary(const char *mac_path) {
    unsigned char head[32];
    FILE *f = fopen(mac_path, "rb");
    if (!f) return 0;                                      /* unreadable: let the mapper complain */
    if (fread(head, 1, sizeof head, f) != sizeof head) { fclose(f); return 0; }
    uint32_t magic = *(uint32_t *)head;
    uint32_t ncmds = *(uint32_t *)(head + 16);
    uint32_t sizeofcmds = *(uint32_t *)(head + 20);
    if (magic != 0xFEEDFACFu || ncmds > 4096 || sizeofcmds > (1u << 20)) {
        fclose(f);                                         /* not a 64-bit Mach-O: not ours to judge */
        return 0;
    }
    unsigned char *cmds = (unsigned char *)malloc(sizeofcmds);
    if (!cmds) { fclose(f); return 0; }
    int verdict = 0;
    if (fread(cmds, 1, sizeofcmds, f) == sizeofcmds) {
        uint32_t off = 0;
        for (uint32_t i = 0; i < ncmds && off + 8 <= sizeofcmds; i++) {
            uint32_t cmd = *(uint32_t *)(cmds + off);
            uint32_t csz = *(uint32_t *)(cmds + off + 4);
            if (csz < 8 || off + csz > sizeofcmds) break;
            if (cmd == 0x80000028u && csz >= 16) {         /* LC_MAIN */
                uint64_t entryoff = *(uint64_t *)(cmds + off + 8);
                uint64_t entry_va = 0x100000000ULL + entryoff;
                if (entry_va != (uint64_t)MAC_ENTRYPOINT) {
                    fprintf(stderr,
                        "[dom6-loader] REFUSING TO RUN: this loader was built for Dominions 6 v%s,\n"
                        "              whose entry point is 0x%llx, and %s says 0x%llx.\n"
                        "              Every generated table here — GOT bindings, segment map, SDL\n"
                        "              jump table — belongs to the other build, so running it would\n"
                        "              fail somewhere else, later, as a crash nobody can read.\n"
                        "              Build the loader for this game: make DOM6_VERSION=<ver>\n"
                        "              MAC_BIN=%s regen-data && make DOM6_VERSION=<ver> build\n",
#ifdef DOM6_VERSION_STR
                        DOM6_VERSION_STR,
#else
                        "(unrecorded)",
#endif
                        (unsigned long long)MAC_ENTRYPOINT, mac_path,
                        (unsigned long long)entry_va, mac_path);
                    verdict = -1;
                }
                break;
            }
            off += csz;
        }
    }
    free(cmds);
    fclose(f);
    return verdict;
}

/* ── mmap_segments: load Mac binary segments at their native VAs ──
 * Body is a sequence of mmap() calls generated from the binary's
 * LC_SEGMENT_64 load commands.  Run once at startup. */
static int mmap_segments(const char *mac_path) {
    int fd = open(mac_path, O_RDONLY);
    if (fd < 0) { perror("open mac binary"); return -1; }
    if (check_binary(mac_path) != 0) { close(fd); return -1; }
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

    /* Identify which Dominions 6 binary this build was compiled against
     * (the .inc tables under data/<DOM6_VERSION>).  If the installed dom6_mac is
     * a different upstream version the GOT layout won't match and things
     * fail in confusing ways — having the version in every log makes
     * that mismatch obvious. */
#ifdef DOM6_VERSION_STR
    fprintf(stderr, "[dom6-loader] built for Dominions 6 v%s\n",
            DOM6_VERSION_STR);
#endif

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
        /* Each of these names a directory outright — dom6 uses the value as-is rather than
         * appending anything to it, so DOM6_SAVE must be the savedgames dir itself.  Pointing
         * it at `base` created every game one level too high, beside dom6config, where the
         * Steam build's game list does not look for them. */
        char saves[MAX_PATH], maps[MAX_PATH], mods[MAX_PATH];
        snprintf(saves, sizeof saves, "%s\\savedgames", base);  CreateDirectoryA(saves, NULL);
        snprintf(maps,  sizeof maps,  "%s\\maps",       base);  CreateDirectoryA(maps,  NULL);
        snprintf(mods,  sizeof mods,  "%s\\mods",       base);  CreateDirectoryA(mods,  NULL);
        fprintf(stderr, "[dom6-loader] conf dir: %s%s\n", base,
                user_conf ? " (DOM6_CONF override)" : "");
        if (!user_conf) _putenv_s("DOM6_CONF", base);
        if (!getenv("DOM6_SAVE"))      _putenv_s("DOM6_SAVE",      saves);
        if (!getenv("DOM6_LOCALMAPS")) _putenv_s("DOM6_LOCALMAPS", maps);
        if (!getenv("DOM6_MODS"))      _putenv_s("DOM6_MODS",      mods);
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
    /* Nothing patches dom6's bgload_init here.  Its background texture threads only start
     * through SDL_CreateThread, which install_sdl_redirect stubs on this platform, so there
     * is nothing to suppress.
     *
     * Patching engine CODE needs the function located in the build at hand, never an address
     * written down here: __TEXT changes size between releases, so no arithmetic carries such
     * an address forward and a stale one lands mid-instruction.
     */

    /* Nothing pre-marks dom6's SDL_DYNAPI init-done flag here.  The redirect
     * install_sdl_redirect writes survives without it.
     *
     * If it ever does need marking — the engine's own dynapi resolver calls its INTERNAL
     * SDL_DYNAPI_entry, which fills the jump table with dom6's built-in stubs over the host
     * pointers — the flag has to be located in the build at hand.  A byte address written
     * down here is a silent write into whatever occupies it, which is worse than not
     * marking the flag at all.
     */

#endif

    /* Transfer control to the Mac binary. */
    mac_main_fn mac_main = (mac_main_fn)MAC_ENTRYPOINT;
#ifdef _WIN32
    /* Also write a marker to a dedicated trace file so we know whether
     * mac_main returns even if stderr was closed/redirected mid-run. */
    /* DOM6_BOOT_TRACE names a file that records whether mac_main was entered and what it
     * returned — the one thing stderr cannot tell you when it has been closed or redirected
     * mid-run.  Unset by default: a fixed path is one developer's machine, not a feature. */
    const char *trace_path = getenv("DOM6_BOOT_TRACE");
    HANDLE trace_h = trace_path
        ? CreateFileA(trace_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
        : INVALID_HANDLE_VALUE;
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
    trace_h = trace_path
        ? CreateFileA(trace_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
        : INVALID_HANDLE_VALUE;
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

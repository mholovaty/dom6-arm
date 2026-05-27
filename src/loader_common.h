/* loader_common.h — runtime includes + globals shared by all loader sources.
 *
 * Splits headers into "portable" (always included) and "POSIX-only"
 * (wrapped in #ifndef _WIN32).  Win32 backend (loader_os_win32.c + the
 * Win32 shim stubs) doesn't need most POSIX headers because:
 *   - the OS abstraction layer hides mmap/dlopen/sigaction/etc.
 *   - the socket/dispatch/dlopen mac_* shims compile out on Win32
 *     (they'd be reimplemented via Winsock/CreateThread/LoadLibrary
 *      if we want full server-mode portability later)
 *
 * Per-OS abstractions live in loader_os.h.
 */
#ifndef LOADER_COMMON_H
#define LOADER_COMMON_H

/* sincos(), strlcpy(), atomic intrinsics, MAP_ANONYMOUS etc. are glibc
 * extensions enabled by _GNU_SOURCE.  Must be set before any libc include.
 * Harmless on Win32 / UCRT (just ignored). */
#define _GNU_SOURCE

/* Portable C / UCRT-available — present on POSIX and Win32 + UCRT. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <ctype.h>
#include <wchar.h>
#include <locale.h>
#include <setjmp.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <zlib.h>
#include <bzlib.h>
#include <GL/gl.h>
#include <GL/glu.h>

/* pthread.h is available on both POSIX (system) and MSYS2 mingw-w64
 * (via winpthreads).  fill_got needs the function names for symbol
 * resolution. */
#include <pthread.h>
#include <dirent.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
/* mingw-w64 supplies sys/time.h (for gettimeofday) and sys/wait.h. */
#include <sys/time.h>
#include <io.h>          /* _open, _read, _write, _close, _get_osfhandle */
#endif

#ifndef _WIN32
/* True POSIX-only: socket APIs, mmap, signals, dynamic linking.
 * The Win32 path provides equivalents via loader_os.h + Winsock /
 * CreateThread / LoadLibrary inside the win32-shim stubs file. */
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <dlfcn.h>
#include <netdb.h>
#include <sys/wait.h>
#include <GL/glext.h>
#endif  /* _WIN32 */

/* Default path to the Mac binary, looked up relative to cwd.
 * Matches the Dominions 6 Steam install layout: dom6_mac sits next to
 * Dominions6.exe / dom6_amd64 in the install root.  Override at runtime
 * with the DOM6_MAC_PATH env var. */
#ifndef DOM6_MAC_PATH
#define DOM6_MAC_PATH "dom6_mac"
#endif

extern FILE *mac_stderr_val;
extern FILE *mac_stdout_val;
extern FILE *mac_stdin_val;
extern FILE **mac_stderrp_ptr;
extern FILE **mac_stdoutp_ptr;
extern FILE **mac_stdinp_ptr;

#endif /* LOADER_COMMON_H */

# dom6-arm loader build driver.
#
# `make build` compiles src/*.c against the committed data/<DOM6_VERSION>/*.inc
# tables — no dom6_mac binary required.  `make regen-data` regenerates those
# tables from a dom6_mac binary; maintainer-only path.
#
# Portable across GNU make on Linux and MSYS2 (MinGW/CLANGARM64) on
# Windows-on-ARM.

.PHONY: build clean regen-data help

# ── Toolchain ────────────────────────────────────────────────────────
CC          ?= cc
PYTHON      ?= python3
CFLAGS      ?= -O2 -march=armv8-a -fPIC \
               -Wall -Wno-incompatible-pointer-types \
               -Wno-implicit-function-declaration \
               -Wno-int-conversion -Wno-attributes \
               -Wno-unknown-warning-option \
               -Wno-builtin-declaration-mismatch

# STATIC=1 → link zlib + bzip2 + pthread (and on Win the gcc runtime)
# into the executable, so it runs without those shared libraries.
STATIC      ?=

# ── Per-OS link libraries ────────────────────────────────────────────
LOADER_OS   ?= posix
ifeq ($(LOADER_OS),posix)
  # SDL2 + libGL + libGLU are dlopened at runtime by install_sdl_redirect
  # / install_gl_redirect — intentionally NOT in LDLIBS.  See the win32
  # block below for why static-linking opengl32 would break the Mesa
  # zink override on Windows; on Linux it's a symmetry/portability win
  # (binary runs on any glibc with libGL.so.1 present, no -dev pkgs).
  DYN_LIBS  := -lm -ldl
  STA_LIBS  := -lz -lbz2 -lpthread
endif
ifeq ($(LOADER_OS),win32)
  # SDL2 + opengl32 + glu32 are all dlopened at runtime — intentionally
  # NOT in LDLIBS.  Static-importing opengl32 would force the PE loader
  # to resolve it at process start, before main() can narrow the DLL
  # search to <exe-dir>\arm64.  That binds the early opengl32 import
  # to Microsoft's GDI software GL 1.1 and prevents our bundled Mesa
  # from taking over later.
  DYN_LIBS  := -lpsapi -lws2_32 -lbcrypt
  STA_LIBS  := -lz -lbz2 -lpthread
  ifeq ($(STATIC),1)
    LDFLAGS += -static-libgcc
  endif
  # dom6_mac has a function whose stack frame is ~1 MB; bump the default
  # 1 MB PE stack reserve.
  LDFLAGS   += -Wl,--stack,16777216
  CFLAGS    += -D_WIN32_WINNT=0x0601
endif
ifeq ($(STATIC),1)
  LDLIBS    ?= $(DYN_LIBS) -Wl,-Bstatic $(STA_LIBS) -Wl,-Bdynamic
else
  LDLIBS    ?= $(DYN_LIBS) $(STA_LIBS)
endif

# ── Paths ────────────────────────────────────────────────────────────
# The NEWEST tables we carry, so a plain `make build` targets the current game rather than
# whichever release was current when this line was last edited. Override to build an older one:
# `make DOM6_VERSION=6.35 build`.
DOM6_VERSION ?= $(lastword $(sort $(notdir $(wildcard data/*))))
SRC_DIR      := src
DATA_DIR     := data/$(DOM6_VERSION)

# Surface the upstream Dominions 6 version inside the loader so users
# (and bug reports) can confirm which game version a given build targets.
CFLAGS      += -DDOM6_VERSION_STR=\"$(DOM6_VERSION)\"
BUILD_DIR    := build/loader
ifeq ($(LOADER_OS),win32)
LOADER_BIN   := $(BUILD_DIR)/dom6_arm64.exe
else
LOADER_BIN   := $(BUILD_DIR)/dom6_aarch64
endif

MAC_BIN      ?= origin/dom6_mac

# ── Sources ──────────────────────────────────────────────────────────
COMMON_SRC  := $(SRC_DIR)/loader_main.c       \
               $(SRC_DIR)/loader_shims.c      \
               $(SRC_DIR)/loader_counters.c   \
               $(SRC_DIR)/loader_crash.c      \
               $(SRC_DIR)/loader_sdl_gl.c     \
               $(SRC_DIR)/loader_altenter_win.c \
               $(SRC_DIR)/loader_win_vbo.c

OS_SRC      := $(SRC_DIR)/loader_os_$(LOADER_OS).c
LOADER_SRC  := $(COMMON_SRC) $(OS_SRC)

# ── Targets ──────────────────────────────────────────────────────────

help:
	@echo "Targets:"
	@echo "  build         build the loader binary ($(LOADER_BIN))"
	@echo "                  for DOM6_VERSION=$(DOM6_VERSION) (data/$(DOM6_VERSION)/)"
	@echo "  regen-data    regenerate data/<DOM6_VERSION>/*.inc from \$$(MAC_BIN)"
	@echo "                  — only needed when adding support for a new dom6 release"
	@echo "  clean         remove $(LOADER_BIN)"
	@echo ""
	@echo "Override on the command line:  CC, CFLAGS, LDLIBS, PYTHON, MAC_BIN, DOM6_VERSION"
	@echo "Cross-build for Windows:       make LOADER_OS=win32 CC=clang"
	@echo "Pick a different game version: make DOM6_VERSION=6.36"
	@echo "Static-link zlib/bzip2/pthread:make STATIC=1"

build: $(LOADER_BIN) $(BUILD_DIR)/DOM6_VERSION.txt

$(LOADER_BIN): $(LOADER_SRC) | $(BUILD_DIR) data-check
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(DATA_DIR) \
	    -o $@ $(LOADER_SRC) $(LDFLAGS) $(LDLIBS)

# Surfaces the upstream Dominions 6 version this build targets — shipped
# next to the binary in CI artifacts so users can confirm at a glance
# which dom6_mac their downloaded loader matches.
# ALWAYS rewritten: it records a VALUE, not a file, so depending on the Makefile let the stamp
# survive a version change and report the wrong game.
.PHONY: $(BUILD_DIR)/DOM6_VERSION.txt
$(BUILD_DIR)/DOM6_VERSION.txt: | $(BUILD_DIR)
	@echo "$(DOM6_VERSION)" > $@

.PHONY: data-check
data-check:
	@if [ ! -d "$(DATA_DIR)" ]; then \
	    echo "make: data/$(DOM6_VERSION)/ not found."; \
	    echo "      Supported DOM6_VERSION values: $$(ls data 2>/dev/null | tr '\n' ' ')"; \
	    echo "      To add a new release: make regen-data DOM6_VERSION=$(DOM6_VERSION) MAC_BIN=path/to/dom6_mac"; \
	    exit 1; \
	fi

$(BUILD_DIR):
	mkdir -p $@

# See doc/regenerating-data.md.
regen-data: | $(DATA_DIR)
	@if [ -z "$(SDL_ARCHIVE)" ]; then \
	    echo "make: SDL_ARCHIVE is unset.  See doc/regenerating-data.md."; \
	    exit 1; \
	fi
	$(PYTHON) tools/sdl_lookup.py  --mac-bin $(MAC_BIN) \
	                               --sdl-archive $(SDL_ARCHIVE) \
	                               --out $(DATA_DIR)/sdl_map.json
	$(PYTHON) tools/build_loader.py --mac-bin $(MAC_BIN) --out $(DATA_DIR)

$(DATA_DIR):
	mkdir -p $@

clean:
	rm -rf $(LOADER_BIN)

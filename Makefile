# dom6-arm loader build driver.
#
# Build is two-step:
#  1. (one-time per dom6 release, by maintainer) tools/build_loader.py reads
#     a Mach-O dom6_mac and writes binary-dependent data tables into
#     data/<dom6_version>/*.inc — these are then committed.
#  2. (every build) $(CC) compiles src/*.c against the committed .inc files
#     for the requested DOM6_VERSION.
#
# Default behavior: build for DOM6_VERSION=6.35 using data/6.35/.  No game
# binary required — CI can build any supported version without origin/.
#
# Portable across GNU make on Linux and MSYS2 (MinGW/CLANGARM64) on
# Windows-on-ARM: uses only POSIX make features, forward slashes, and
# never spawns Linux-specific shell utilities.

.PHONY: build clean regen-data help

# ── Toolchain (override on the make command line for cross-builds) ───
CC          ?= cc
PYTHON      ?= python3
CFLAGS      ?= -O2 -march=armv8-a -fPIC \
               -Wall -Wno-incompatible-pointer-types \
               -Wno-implicit-function-declaration \
               -Wno-int-conversion -Wno-attributes \
               -Wno-unknown-warning-option \
               -Wno-builtin-declaration-mismatch

# OS-specific link libraries.  Override LDLIBS on the command line for
# anything exotic.
LOADER_OS   ?= posix
ifeq ($(LOADER_OS),posix)
  LDLIBS    ?= -lm -lz -lbz2 -lpthread -ldl -lGL -lGLU
endif
ifeq ($(LOADER_OS),win32)
  # MSYS2 clangarm64.  zlib + bzip2 come from mingw-w64 packages; pthread
  # is winpthread; psapi for EnumProcessModules in os_print_memory_map.
  LDLIBS    ?= -lSDL2 -lopengl32 -lglu32 -lpsapi -lz -lbz2 -lpthread -lws2_32 -lbcrypt
  # macOS gives the main thread 8 MB stack; Win32 default is 1 MB and
  # dom6 has at least one function that does a ~1 MB single-frame
  # allocation that blows the default Win stack.  Bump PE stack reserve.
  LDFLAGS   += -Wl,--stack,16777216
  CFLAGS    += -D_WIN32_WINNT=0x0601
endif

# ── Paths ────────────────────────────────────────────────────────────
DOM6_VERSION ?= 6.35
SRC_DIR      := src
DATA_DIR     := data/$(DOM6_VERSION)
BUILD_DIR    := build/loader
ifeq ($(LOADER_OS),win32)
LOADER_BIN   := $(BUILD_DIR)/dom6_aarch64.exe
else
LOADER_BIN   := $(BUILD_DIR)/dom6_aarch64
endif

MAC_BIN      ?= origin/dom6_mac

# ── Source partition ─────────────────────────────────────────────────
# OS-specific impl picked by OS_SRC below.
COMMON_SRC  := $(SRC_DIR)/loader_main.c       \
               $(SRC_DIR)/loader_shims.c      \
               $(SRC_DIR)/loader_counters.c   \
               $(SRC_DIR)/loader_crash.c      \
               $(SRC_DIR)/loader_sdl_gl.c     \
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
	@echo "  clean         remove build/loader/{dom6_aarch64,dom6_aarch64.exe}"
	@echo ""
	@echo "Override on the command line:  CC, CFLAGS, LDLIBS, PYTHON, MAC_BIN, DOM6_VERSION"
	@echo "Cross-build for Windows:       make LOADER_OS=win32 CC=clang"
	@echo "Pick a different game version: make DOM6_VERSION=6.36"

build: $(LOADER_BIN)

# Single compile + link.  The .inc files at data/$(DOM6_VERSION)/ are
# committed; -I$(DATA_DIR) lets src/*.c #include them by short name.
# No per-object intermediates: the .inc files are #included inline by
# .c files, so any data change is a whole-binary rebuild anyway.
$(LOADER_BIN): $(LOADER_SRC) | $(BUILD_DIR) data-check
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(DATA_DIR) \
	    -o $@ $(LOADER_SRC) $(LDFLAGS) $(LDLIBS)

# Fail fast with a clear message if the requested DOM6_VERSION isn't
# present.  Lists known versions so the user can pick one.
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

# Regenerate the committed data tables for one dom6 version.  Maintainer
# target — run once per dom6 release.  Two inputs are required:
#   MAC_BIN       — path to dom6_mac (the Mach-O ARM64 binary)
#   SDL_ARCHIVE   — path to a libSDL2.a built from the SDL2 version dom6
#                   was linked against.  The script validates the version.
#                   Source the archive however your environment prefers
#                   (Homebrew bottle, locally compiled, CI Docker image,
#                   …) — this project does not download anything.
# See doc/regenerating-data.md for the maintainer workflow.
regen-data: | $(DATA_DIR)
	@if [ -z "$(SDL_ARCHIVE)" ]; then \
	    echo "make: SDL_ARCHIVE is unset."; \
	    echo "      Provide the path to libSDL2.a for the SDL2 version dom6 needs."; \
	    echo "      See doc/regenerating-data.md."; \
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

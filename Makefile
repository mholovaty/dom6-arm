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
  DYN_LIBS  := -lm -ldl -lGL -lGLU
  STA_LIBS  := -lz -lbz2 -lpthread
endif
ifeq ($(LOADER_OS),win32)
  # SDL2 is dlopened at runtime — intentionally not in LDLIBS.
  DYN_LIBS  := -lopengl32 -lglu32 -lpsapi -lws2_32 -lbcrypt
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
DOM6_VERSION ?= 6.35
SRC_DIR      := src
DATA_DIR     := data/$(DOM6_VERSION)
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

build: $(LOADER_BIN)

$(LOADER_BIN): $(LOADER_SRC) | $(BUILD_DIR) data-check
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(DATA_DIR) \
	    -o $@ $(LOADER_SRC) $(LDFLAGS) $(LDLIBS)

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

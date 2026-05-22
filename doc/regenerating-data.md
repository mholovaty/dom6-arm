# Regenerating `data/<dom6_version>/`

The committed `data/<version>/` directory holds binary-derived tables for
one dom6 release.  Building the loader needs only these files — no game
binary, no SDL2 archive.  The tables themselves are produced by inspecting
a `dom6_mac` binary, so adding support for a new dom6 release means
running the regeneration pipeline once.

## Inputs

Two file-system paths.  This project does not download anything — provide
the inputs however the calling environment prefers.

| Input | What it is | Examples |
|---|---|---|
| `dom6_mac` | The Mach-O ARM64 binary from the Mac Steam install (~80 MB) | local Steam install; `steamcmd` download; checked-in fixture; CI secret |
| `libSDL2.a` | A static-archive build of the *exact* SDL2 version dom6 was linked against | `brew install sdl2`; from-source build; bottle download; CI image |

The script verifies that the SDL2 version in the archive matches the
version string embedded in `dom6_mac` (`SDL2-X.Y.Z/...` paths inside the
binary).  Mismatch is a loud, immediate error.

## Command

```bash
make regen-data \
    DOM6_VERSION=6.36 \
    MAC_BIN=/path/to/dom6_mac \
    SDL_ARCHIVE=/path/to/libSDL2.a
```

This runs two scripts in sequence:

1. **`tools/sdl_lookup.py`** — extracts SDL2's dynapi jump-table layout
   from `libSDL2.a` (the slot order), scans `dom6_mac` for the
   jump-table address, writes `data/6.36/sdl_map.json`.
2. **`tools/build_loader.py`** — reads `dom6_mac` (segments, GOT
   bindings, imports), classifies every imported symbol, and writes the
   8 `.inc` files (`entry.inc`, `segments.inc`, `got_bindings.inc`,
   `shim_enum.inc`, `shim_table.inc`, `shim_thunks.inc`,
   `gl_redirect.inc`, `sdl_redirect.inc`) into `data/6.36/`.

Total runtime: a few seconds.  Total output: ~280 KB per release.

The pipeline is deterministic — re-running with the same inputs produces
byte-identical output, so the result can be compared against committed
`data/<version>/` to detect upstream drift.

A typical dom6 release moves every address but the symbol *list* is
mostly stable: small changes in `slots` are normal; a regeneration that
loses or doubles ~200 GOT entries usually indicates a wrong input.

## Adding support for a new dom6 release

1. Stage the new `dom6_mac` at a known path.
2. Identify the SDL2 version it needs:
   `strings dom6_mac | grep -oE 'SDL2-[0-9.]+' | head -1`
3. Stage a matching `libSDL2.a` (Homebrew bottle, from-source build, …).
4. `make regen-data DOM6_VERSION=<X.Y> MAC_BIN=… SDL_ARCHIVE=…`
5. Diff against the previous version: `git diff data/`.
6. Commit `data/<X.Y>/`.

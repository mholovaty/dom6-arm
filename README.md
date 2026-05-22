# Dominions 6 ARM64 Loader (`dom6-arm`)

Native **ARM64 executables** of
[Dominions 6](https://www.illwinter.com/dom6/) for **Windows** and
**Linux** — no x86 emulation.

## Download

Pre-built loaders from the latest `main` branch:

- **Windows ARM64**:
  [dom6_arm64-windows.zip](https://nightly.link/mholovaty/dom6-arm/workflows/build/main/dom6_arm64-windows.zip)
- **Linux ARM64**:
  [dom6_aarch64-linux.zip](https://nightly.link/mholovaty/dom6-arm/workflows/build/main/dom6_aarch64-linux.zip)

These are just the loader — you still need a legitimate copy of
Dominions 6 (Steam, GOG, direct purchase from Illwinter).  The loader
reuses the **macOS** game binary that already ships with your install.

## Install

### Windows ARM64

You need: Dominions 6 installed via Steam, Snapdragon X (or other
Windows-on-ARM) laptop, and a recent **Adreno graphics driver** —
**31.0.148.0 or later**.  Older Adreno drivers have a Vulkan sync bug
that randomly hangs the game; grab the latest from the
[Qualcomm Software Center](https://softwarecenter.qualcomm.com/catalog/item/Windows_Graphics_Driver)
if you haven't recently.

1. Download
   [`dom6_arm64-windows.zip`](https://nightly.link/mholovaty/dom6-arm/workflows/build/main/dom6_arm64-windows.zip).
2. Extract the contents directly into your Dominions 6 install folder
   (default:
   `C:\Program Files (x86)\Steam\steamapps\common\Dominions6\`).
   You should end up with `dom6_arm64.exe` next to the existing
   `Dominions6.exe`, and a new `arm64\` subfolder containing bundled
   SDL2 + Mesa runtime DLLs.
3. Double-click `dom6_arm64.exe`.  The game launches natively, no
   x86 emulation.

To launch through Steam ("Play" button), replace `Dominions6.exe` with
a copy of `dom6_arm64.exe` (rename our exe).  Steam will then run the
ARM64 build by default.

### Linux ARM64

You need: a legitimately licensed copy of Dominions 6 with the macOS
binary (`dom6_mac`) accessible to the box, plus host Mesa/SDL2
packages.

1. Download
   [`dom6_aarch64-linux.zip`](https://nightly.link/mholovaty/dom6-arm/workflows/build/main/dom6_aarch64-linux.zip)
   and extract it (it contains a single `dom6_aarch64` binary).
2. Install runtime dependencies (Debian/Ubuntu):
   ```
   sudo apt install libgl1 libglu1-mesa libsdl2-2.0-0
   ```
3. Put `dom6_aarch64` somewhere convenient.  Point it at your
   `dom6_mac` via the `DOM6_MAC_PATH` env var, or just place it in the
   same directory as `dom6_mac`:
   ```
   DOM6_MAC_PATH=/path/to/dom6_mac ./dom6_aarch64
   ```

That's it — the loader handles the rest.

## Why

The official Dominions 6 distribution ships only **x86_64** binaries
for Windows and Linux.  ARM64 users on those OSes are stuck running
the x86_64 build through emulation (qemu on Linux, Microsoft Prism on
Windows) — which isn't always reliable and carries a noticeable
performance penalty.

`dom6-arm` runs Dominions 6's native ARM64 game code on those OSes
directly, translating only the OS-boundary calls (libc, SDL, GL,
sockets).  No emulation, no x86 in the loop.

- **Linux ARM64** users (Raspberry Pi 5, Rockchip RK3588 SBCs like
  Orange Pi 5, Apple Silicon under Asahi Linux, Ampere / AWS Graviton
  servers, etc.) get a native build where there wasn't one.
- **Windows ARM64** users (Snapdragon X / 8cx Gen 2+, etc.) get the
  same.
- **One loader across OSes**, no separate ports to track and no
  game-side modifications.

The ARM64 game code itself comes from Dominions 6's macOS build, which
the loader reuses unchanged — an implementation detail invisible to
users.

## Verified configurations

See [`doc/hardware.md`](doc/hardware.md) for the current test matrix
(hardware, driver versions, OS builds).

## Note

The project's goal is to broaden ARM64 platform coverage, not to
circumvent copy protection or redistribute game content.  It loads
your legitimately licensed `dom6_mac` binary unchanged — no DRM
removal, no license-check bypass, no game-content modification.
All rights to Dominions 6 remain with Illwinter Game Design; this
project is not affiliated with or endorsed by them.

## License

MIT — see [`LICENSE`](LICENSE).  Covers the loader code only; the
Dominions 6 binary remains under Illwinter's licensing.

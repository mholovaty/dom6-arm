# Hardware and drivers tested

A factual log of the hardware, OS builds, toolchains, and graphics drivers
the loader has been verified against.  Updated as the matrix grows; the
list is not exhaustive of supported configurations, only of *tested*
ones.

## Targets

### Windows ARM64

|               |                                                                                                                                                           |
|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Machine       | ASUS Snapdragon X laptop                                                                                                                                  |
| SoC           | Qualcomm Snapdragon X (8-core Oryon)                                                                                                                      |
| GPU           | Qualcomm Adreno X1-45 (`ACPI\VEN_QCOM&DEV_0D17`)                                                                                                          |
| OS            | Windows 11 24H2 (ARM64)                                                                                                                                   |
| Build env     | MSYS2 CLANGARM64, clang 21.x / 22.x, lld, mingw-w64-clang-aarch64-*                                                                                       |
| Mesa runtime  | mingw-w64-clang-aarch64-mesa, latest (pacman -Syuu in CI)                                                                                                 |
| Adreno driver | 31.0.148.0 (2026-03-18) — passing.  Earlier 31.0.96.0 (2025-02) sporadically hung; see [`snapdragon_adreno_drivers.md`](../snapdragon_adreno_drivers.md). |
| Launch path   | Steam install dir; loader auto-detects `dom6_mac` next to `dom6_arm64.exe`.                                                                               |
| Vulkan loader | System `vulkan-1.dll`; ICD discovery via `qcvk_icd_arm64x.json` in DriverStore.                                                                           |

### Linux ARM64

|              |                                                                                                                                                                                            |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Machine      | Same ASUS Snapdragon X laptop, WSL2                                                                                                                                                        |
| Distro       | Ubuntu 24.04 LTS (ARM64)                                                                                                                                                                   |
| Build env    | gcc 13, make, libgl1-mesa-dev, libglu1-mesa-dev, libbz2-dev, zlib1g-dev                                                                                                                    |
| Verification | `make build` + headless smoke run (GLX context creation fails under WSL2 X server but loader otherwise initialises correctly: SDL 836/836, GL 73/73 redirects, dom6_mac mac_main entered). |

### Raspberry Pi 4 (via qemu-aarch64-static, server mode)

|              |                                                                                                                                                                      |
|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Machine      | Raspberry Pi 4                                                                                                                                                       |
| SoC          | BCM2711 (Cortex-A72, ARMv8.0-A — *below* the native ARMv8.2 floor)                                                                                                   |
| OS           | Raspberry Pi OS 64-bit                                                                                                                                               |
| Tooling      | `qemu-user-static` (`qemu-aarch64-static`)                                                                                                                           |
| Verified     | Server mode only: `--tcpserver --textonly --nosound --nosteam`, Dom6 v6.35, 2026-06-03.                                                                              |
| Mechanism    | qemu's TCG lowers SDOT/UDOT and LSE atomics to ARMv8.0-only host sequences on the fly; no binary patching needed. Without qemu the binary SIGILLs natively on `sdot` |
| Not verified | GUI mode                                                                                                                                                             |

## CI matrix

GitHub Actions, defined in `.github/workflows/build.yml`:

| Job           | Runner             | Builds                                                                               |
|---------------|--------------------|--------------------------------------------------------------------------------------|
| Linux ARM64   | `ubuntu-24.04-arm` | `build/loader/dom6_aarch64`                                                          |
| Windows ARM64 | `windows-11-arm`   | `dist/dom6_arm64.exe` + `dist/arm64/` (SDL2, Mesa zink, libLLVM-22, transitive deps) |

CI's MSYS2 install line uses `update: true` so `pacman -Syuu` runs each
build — keeps Mesa+LLVM moving with upstream and avoids the 2025
incident where a stale cached Mesa package shipped to users and tripped
an Adreno Vulkan bug.

## Not yet tested (target ports of interest)

These platforms should work — the loader is portable ARM64 — but have
no on-record verification run as of writing:

- Raspberry Pi 5 (BCM2712, Cortex-A76, ARMv8.2-A LSE).
- Rockchip RK3588 SBCs (Orange Pi 5, Radxa Rock 5, etc.).
- Other Snapdragon X laptops (Surface, Dell, HP, Samsung) — same GPU
  driver family as the test box, so the Windows-ARM64 build should
  apply unchanged.

CPU floor is **ARMv8.2-A** (LSE atomics + dot-product) for *native*
execution — Pi 3/4 and Jetson Nano fall below.  Hosts below the floor
can still run server-mode under `qemu-aarch64-static`, which lowers the
missing opcodes on the fly (verified on a Pi 4, see entry above).  See
`tools/check-arch` for the native-run runtime check the loader performs.

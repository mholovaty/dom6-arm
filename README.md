# Dominions 6 ARM64 Loader (`dom6-arm`)

Native **ARM64 executables** of
[Dominions 6](https://www.illwinter.com/dom6/) for **Windows** and
**Linux** — no x86 emulation.

## Why

The official Dominions 6 distribution ships only **x86_64** binaries for
Windows and Linux.  ARM64 users on those OSes are stuck running the
x86_64 build through emulation (qemu on Linux, Microsoft Prism on
Windows) — which isn't always reliable and carries a noticeable
performance penalty.

`dom6-arm` is a small loader that runs Dominions 6's native ARM64 game
code on those OSes directly, translating only the OS-boundary calls
(libc, SDL, GL, sockets).  No emulation, no x86 in the loop.

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

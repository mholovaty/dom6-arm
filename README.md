# dom6-arm

Run the Mac ARM64 build of [Dominions 6](https://www.illwinter.com/dom6/)
natively on **Linux ARM64** and **Windows ARM64** — no x86 emulation.

## Why

The official Dominions 6 distribution ships only **x86_64** binaries for
Windows and Linux.  ARM64 users on those OSes are stuck running the
x86_64 build through emulation (qemu on Linux, Microsoft Prism on
Windows) — which isn't always reliable and carries a noticeable
performance penalty.

But the same release also ships a **native ARM64** binary for macOS.
This project reuses that Mac binary on Linux and Windows by mmapping
its segments at their original virtual addresses and substituting only
the OS-boundary calls (libc, SDL, GL, sockets).  All ARM64 game code
runs unchanged, so:

- **Linux ARM64** users get a native build where there wasn't one.
- **Windows ARM64** users (Snapdragon X / 8cx Gen 2+, etc.) get the
  same.
- **One binary across OSes**: no separate Mac and Windows ports to
  track, no game-side modifications.

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

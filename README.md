# Ghidra Emotion Engine: Reloaded [![run tests](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml)
An extension for Ghidra that adds support for the PlayStation 2.

This extension is based on the original [ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) project, with a number of changes.

## Features

- Disassemble and decompile EE-specific instruction sets (MMI, VU0 macro mode, etc).
- Recover data types, functions and global variables from ELF files with `.mdebug` sections with the included STABS Analyzer.
- Import PCSX2 save states.
- Fix references to global variables with the MIPS-R5900 Constant Reference Analyzer.

## Installation

Release builds are available on the [releases](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases) page. Unstable builds, generated whenever there is a push to the main branch, are available [here](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases/tag/unstable). To install the package, follow the instructions in the [Ghidra documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md#extensions).

## Building

If you want to build the extension yourself, install `gradle` and run:
 
```
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

`buildExtension` also runs `prepareStdump` to provision the pinned,
SHA-256-verified **ccc v1.2.1** native `stdump` executables (Windows, Linux,
and macOS) in `os/`. The STABS analyzer requires this helper. A fresh source
checkout therefore needs internet access for its first build unless the
executables were supplied manually beforehand. The packaged extension must
contain `os/win_x86_64/stdump.exe` for Windows; a normal Java-only build
without this file cannot import STABS symbols.

For an **already installed** extension missing `stdump.exe`, rebuild and
reinstall the extension, or copy the prepared
`os/win_x86_64/stdump.exe` into the installed extension's
`os/win_x86_64/` directory and restart Ghidra.

## STABS and Metrowerks ELF files

STABS metadata is read from an ELF `.mdebug` section. Metrowerks CATS
metadata (`.mwcats`) and an ordinary ELF `.symtab` are **not** STABS. The
analyzer skips files without `.mdebug` unless an external ELF or stdump JSON
override is configured. Those files do not need `stdump` merely to disassemble
or analyze their ordinary ELF symbols.

## Common Issues

### 7-Zip returned unsupported method

Modern versions of PCSX2 store save states using zstd compression by default, which Ghidra's zip implementation doesn't support. To work around this, if you are using PCSX2 v2.1.178 or higher you should make sure that `Tools -> Show Advanced Settings` is checked, then navigate to `File -> Settings -> Advanced -> Savestate Settings` and change the `Compression Method` option to `Deflate64`. If you are using an older version, you will have to change `SavestateZstdCompression` to `false` in the `EmuCore` section of your `PCSX2.ini` file.

### Decompilation fails for some functions

Try disabling the `Decompiler Parameter ID` analyzer.

### Symbols aren't being demangled

Enable the `Use Deprecated Demangler` option in the settings for the `Demangler GNU` analyzer.

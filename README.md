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

buildExtension also runs prepareStdump to install native CCC v2.1 stdump
executables for Windows, Linux and Apple Silicon macOS. The symbol analyzer
now understands CCC 2.x JSON (format versions 13 through 15). For the full
native binary locations, architecture limitations, offline builds, and
optional archive SHA-256 verification, see [os/README.md](os/README.md).

## CCC 2.x symbols and Metrowerks ELF files

The CCC 2.x analyzer imports symbol metadata from supported ELF sections
including .mdebug (STABS), .symtab, .sndata and, in compatible CCC builds,
.debug (DWARF 1). It can also accept an external CCC 2.x JSON document via
the analysis options. Ordinary ELF symbols may already be imported by
Ghidra; the analyzer avoids clearing defined code and user metadata.
Metrowerks .mwcats is **not** handled by CCC and remains separate work.

## Common Issues

### 7-Zip returned unsupported method

Modern versions of PCSX2 store save states using zstd compression by default, which Ghidra's zip implementation doesn't support. To work around this, if you are using PCSX2 v2.1.178 or higher you should make sure that `Tools -> Show Advanced Settings` is checked, then navigate to `File -> Settings -> Advanced -> Savestate Settings` and change the `Compression Method` option to `Deflate64`. If you are using an older version, you will have to change `SavestateZstdCompression` to `false` in the `EmuCore` section of your `PCSX2.ini` file.

### Decompilation fails for some functions

Try disabling the `Decompiler Parameter ID` analyzer.

### Symbols aren't being demangled

Enable the `Use Deprecated Demangler` option in the settings for the `Demangler GNU` analyzer.

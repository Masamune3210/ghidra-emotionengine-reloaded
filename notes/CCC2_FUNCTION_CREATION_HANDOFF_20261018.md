# CCC 2.x function creation regression

Branch: `note-working/ccc2-function-creation-20261018`  
Base: `testing` at `450e76e45830e181d057e5a71bf2d23dc5d13142`  
Scope: Fix CCC v13-v15 JSON importer function creation in the Emotion Engine Ghidra extension without weakening EE/IOP detection or overwriting existing Ghidra database state.

## Background and evidence

The separate PSBBN cloud analysis is in `Masamune3210/ps2bbndecomp`, branch `note-working/psbbn-ghidra-analysis-20261018`; consult its `docs/GHIDRA_IMPORT_AUDIT.md` and `docs/VERIFICATION.md`. It independently reproduced a serious importer bug:

```java
CreateFunctionCmd cmd = new CreateFunctionCmd(body, SourceType.ANALYSIS);
```

Ghidra's two-argument overload treats `body` as a set of **entry points**, not an intended function body. It attempts to create functions at every byte in the reported range. In the preserved PSBBN vmlinux database, 18,384 one-byte functions were identified among 23,089 total. The original cloud investigation demonstrated a 56-byte rolled-back fixture: incorrect overload creates 56 functions; the explicit-body overload creates one. A separately compiled patched extension ran a clean original vmlinux import and produced 4,802 functions, no one-byte/nonaligned functions, no mapped LOAD byte differences and 28 passed extension tests. Those validations were on an external analysis workspace, **not on this branch**.

## Implemented

- In `src/main/java/ghidra/emotionengine/symboltable/Ccc2SymbolImporter.java`, use `CreateFunctionCmd(name, address, body, SourceType.ANALYSIS)` with a source comment documenting why its overload matters.
- Existing import options, existing function signature source checks, and parameter/local metadata are unchanged.

## Next

1. Add a safe regression reproducer or automated test to make accidentally reintroducing the wrong overload harder.
2. Compile/test extension with matching Ghidra installation and existing CCC2 fixture. If Ghidra is unavailable, report that limitation rather than implying that tests ran.
3. Inspect mapped CCC symbols that disagree with native ELF `.symtab` and decide separately whether a conservative opt-in conflict filter is warranted. Do not globally discard legitimate CCC-only symbols or disable CCC's fake-function heuristic.
4. Consider a **separate migration**, not automatic deletion, for existing saved databases already polluted with byte-sized function bodies. Preserve analyst-owned names/types/annotations and old archive baselines.
5. Keep this branch isolated until a matching clean import is verified. No PCSX2 source changes are required for this importer defect.

## Verification and constraints

The exact constructor change is independently cloud-tested in `ps2bbndecomp`; this branch's code is not yet rebuilt against a local Ghidra runtime. No proprietary ELF or `.gzf` content is committed. Ghidra memory bytes and user-defined metadata must not be silently rewritten.

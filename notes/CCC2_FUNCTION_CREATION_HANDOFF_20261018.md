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

## Confirmed additional imported-symbol protection

The original kernel's `.mdebug` is frequently pre-link/stale for `.text.init` records (for example `name_to_kdev_t` has CCC address `0x80018038`, linked ELF `0x801D0038`). The PSBBN audit recorded **142 mapped CCC name/address disagreements** beyond the 161 candidates CCC discarded. Conflicting metadata can be even more serious than an extra function: if the stale address belongs to a *different* correctly linked native function, CCC may attach the wrong return/parameter/stack information to it.

The importer now consults Ghidra's independently imported `SourceType.IMPORTED` FUNCTION/LABEL symbols for the CCC name:
- Native symbol at the CCC entry: allow, including multiply-defined same-named symbols.
- Name only at a different mapped imported address: skip that CCC function record.
- No imported symbol but a **different imported function already at the CCC address**: skip, protecting its signature/locals.
- No independently imported symbol conflict: preserve CCC's existing behavior, including for stripped ELF/CCC-only records.

These tests cover the policy in `Ccc2FunctionAddressGuardTest.java`. The importer *does not* alter the native ELF symbol, delete a user function, guess an alternate CCC address, or disable upstream CCC fake-function disambiguation.

## Regression coverage

- `ghidra_scripts/VerifyCcc2FunctionBody_20261018_v1.java` uses the original PSBBN vmlinux's 56-byte undefined `rest_init` prefix. Requires the preserved original baseline; it rejects wrong hashes, architecture, image base or occupied range. The explicit-body mode expects one created function, legacy mode expects 56; both roll back the entire Ghidra transaction. The underlying same test was previously executed in the separate `ps2bbndecomp` cloud environment, but **this branch's script itself has not been executed in a live Ghidra program**.
- `build.gradle` includes the script in `compileCccAuditScripts`; Java compilation therefore runs under `gradle test` as well as `buildExtension`.
- `.github/workflows/ccc2-symbol-validation.yml` now runs for this branch on Ghidra 12.1.3 and 12.1.4.

**Actual GitHub Actions:** [run 39137400101](https://github.com/Masamune3210/ghidra-emotionengine-reloaded/actions/runs/39137400101) completed successfully in **both** Ghidra versions, including all extension unit tests and regression script compilation, at source commit `f9978a983f4b86ed7a75086838b13f7074bf7648`. No user testing was required.

### Verification limits

- No full import of `vmlinux` with the *new* imported-symbol guards was performed here, and no existing `.gzf` database was migrated. The earlier cloud's clean import with only the constructor fix (4,802 functions, zero byte-sized function artifacts) is independent corroboration of the original constructor correction, **not** validation of this branch's extra guard.
- This execution environment has no Ghidra or Gradle installation. CI verifies Java/unit behavior; imported-symbol provenance and end-to-end clean ELF import should still be checked on a disposable Ghidra project before merging into `testing`.
- Do not bulk-clear old Ghidra one-byte artifacts as a side effect of reimporting; a separate migration requires safeguarding existing names, signatures, datatypes and body overlaps.

## Next

1. **Done:** add rollback-only Ghidra constructor regression probe and JUnit source-guard tests.
2. **CI verified:** both Ghidra 12.1.3 and 12.1.4 unit builds pass. Next validate a new **full** original PSBBN ELF import using a disposable Ghidra project and compare linked symbol preservation.
3. **Implemented conservative guard:** reject CCC candidates contradicted by imported linked function names/locations. Check its effects on a disposable full-ELF import before merging.
4. Consider a **separate migration**, not automatic deletion, for existing saved databases already polluted with byte-sized function bodies. Preserve analyst-owned names/types/annotations and old archive baselines.
5. Keep this branch isolated until a matching clean import is verified. No PCSX2 source changes are required for this importer defect.

## Verification and constraints

The constructor was independently cloud-tested in `ps2bbndecomp`; this branch passed Ghidra 12.1.3 and 12.1.4 CI unit builds and regression-script compilation. Full-ELF integration testing of its additional symbol guard is pending. No proprietary ELF or `.gzf` content is committed. Ghidra memory bytes and user-defined metadata must not be silently rewritten.

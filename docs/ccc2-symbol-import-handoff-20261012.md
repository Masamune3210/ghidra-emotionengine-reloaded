# CCC 2.x symbol importer branch

## Purpose
Implement the Chaos Compiler Collection 2.x symbol-database JSON (versions 13–15) in the Ghidra PS2 extension on top of `testing`. This is a direct migration, not a repair of the legacy CCC 1.2.1/v7 parser.

## Decisions
- Route the existing STABS analyzer entry point through a new CCC 2.x importer; retain old source only as inert reference during migration.
- Use the 2.x `stdump json <ELF>` command and parse flat symbol tables (data_types, functions, parameter_variables, local_variables, global_variables, labels).
- Support v13, v14 and v15 with version validation. Prefer verified type information; preserve user-defined Ghidra metadata and avoid destructive data clearing.
- Target stable CCC v2.1 packaging initially; v2.2 development JSON v15 should be accepted by the new reader when compatible binaries are supplied.
- Detect .mdebug, .debug, .symtab and .sndata, not .mwcats; do not claim Metrowerks CATS support.

## State
Branch created from `testing` on 2026-10-12. Implementation is in progress.

## Next steps and verification
- Implement importer, analyzer routing and native-tool provisioning; inspect diffs.
- Compile/test against Ghidra 12.1.x and sample PS2 ELFs with .mdebug, .debug and .symtab when a Ghidra install and sample binaries are available.
- Record tested CCC executable version and JSON version. Do not interpret source inspection as runtime validation.

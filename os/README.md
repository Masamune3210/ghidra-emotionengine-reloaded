# CCC 2.x native symbol importer

The symbol analyzer now uses CCC 2.x, not the v1.2.1 STABS-only JSON model.
CCC v2.1 emits JSON schema v14; the new importer accepts schemas v13-v15
and the newer development builds can additionally read DWARF 1.

The Gradle buildExtension task runs prepareStdump to download CCC v2.1.
The release artifacts available in upstream's v2.1 release include Windows,
Linux-musl and Apple Silicon macOS builds. Native helper locations:

- os/linux_x86_64/stdump
- os/mac_arm_64/stdump
- os/win_x86_64/stdump.exe

**Integrity note:** The v2.1 release API does not provide SHA-256 digests for
its existing assets. The provisioner prints the downloaded archive's digest
but cannot verify it against an upstream-published checksum by default.
For trusted reproducible provisioning provide the relevant SHA-256 as
-PcccStdumpSha256Linux=..., -PcccStdumpSha256Mac=..., or
-PcccStdumpSha256Windows=.... These are archive checksums, not executable
checksums. To use preinstalled trusted v2.x binaries without downloading,
pass -PuseLocalCcc2Stdump to Gradle.

macOS Intel requires a separately built compatible CCC 2.x executable, or
a newer upstream release that supplies one. The tagged v2.1 mac archive is
for Apple Silicon; do not copy it to mac_x86_64.

If updating an installed extension, reinstall the built ZIP. Do not leave a
v1.2.1 stdump executable in its os/ platform directory; v1.x does not
support the v2.x json subcommand or schema.

CCC recognizes .mdebug, .debug (DWARF 1 in supported builds), .symtab, and
.sndata symbol sections. It does not implement Metrowerks .mwcats parsing.

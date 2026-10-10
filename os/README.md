The STABS analyzer uses the native [ccc/stdump](https://github.com/chaoticgd/ccc)
v1.2.1 executable. It does not build from the Java sources.

The normal Gradle `buildExtension` task automatically runs `prepareStdump`,
which downloads and SHA-256-verifies the pinned v1.2.1 release archives for
Linux, macOS, and Windows. Native binaries are ignored by Git.

Native helper locations:

- `os/linux_x86_64/stdump`
- `os/mac_x86_64/stdump`
- `os/win_x86_64/stdump.exe`

For an offline build, place the corresponding v1.2.1 executables in these
locations before running `buildExtension`. The release CI also supports
`bash os/download.sh` for explicit provisioning.

An extension that was **already installed** without its Windows helper needs
either a reinstall of a complete ZIP or a copy of `stdump.exe` into the
installed extension's `os/win_x86_64` directory, then a Ghidra restart.

No `.mdebug` section means there is no STABS input. Metrowerks `.mwcats`
is a different symbol/debug metadata format.

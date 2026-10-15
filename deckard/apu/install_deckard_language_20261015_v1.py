#!/usr/bin/env python3
"""Install standalone Sony DECKARD PowerPC SLEIGH variant into an existing Ghidra install.

Never overwrites any file, or touches generic PPC/R5900/IOP processor specs.
Creates only: deckard.ldefs, ppc_32_deckard_be.slaspec, deckard_apu.sinc,
ppc_32_deckard_be.sla.  The last is compiled by the target Ghidra's sleigh.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil
import subprocess
import sys

SOURCES = ('ppc_32_deckard_be.slaspec','deckard_apu.sinc','deckard.ldefs')
OUTPUT = 'ppc_32_deckard_be.sla'
DEPENDENCIES = ('ppc_common.sinc','4xx.sinc','ppc_32.pspec','ppc_32.cspec')

def locate_compiler(base: Path, explicit: str | None) -> Path:
    if explicit:
        p=Path(explicit)
        if not p.is_file(): raise RuntimeError(f'Sleigh compiler not found: {p}')
        return p
    possibles=[base/'support'/'sleigh.bat',base/'support'/'sleigh',base/'support'/'sleigh.cmd',base/'support'/'sleigh.sh',base/'Ghidra'/'Features'/'Decompiler'/'os'/'win_x86_64'/'sleigh.exe',base/'Ghidra'/'Features'/'Decompiler'/'os'/'linux_x86_64'/'sleigh']
    for p in possibles:
        if p.is_file(): return p
    raise RuntimeError('Cannot locate sleigh compiler. Use --sleigh with its exact path (commonly Ghidra/support/sleigh.bat).')

def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('ghidra',help='Ghidra installation directory')
    ap.add_argument('--install',action='store_true',help='Copy and compile (otherwise check-only)')
    ap.add_argument('--sleigh',help='Optional path to Ghidra Sleigh compiler launcher')
    args=ap.parse_args()
    base=Path(args.ghidra).resolve()
    languages=base/'Ghidra'/'Processors'/'PowerPC'/'data'/'languages'
    if not languages.is_dir(): raise RuntimeError(f'Ghidra PowerPC language directory missing: {languages}')
    for dep in DEPENDENCIES:
        if not (languages/dep).is_file(): raise RuntimeError(f'Required stock PowerPC file missing: {dep}')
    compiler=locate_compiler(base,args.sleigh)
    source_dir=Path(__file__).resolve().parent
    for f in SOURCES:
        if not (source_dir/f).is_file(): raise RuntimeError(f'Missing package file: {f}')
    for f in (*SOURCES,OUTPUT):
        if (languages/f).exists(): raise RuntimeError(f'WILL NOT OVERWRITE: {languages/f}; uninstall or compare existing DECKARD files manually')
    print('Stock PowerPC 4xx language and build dependencies: present')
    print('Sleigh compiler:',compiler)
    print('Target: PowerPC:BE:32:DECKARD')
    if not args.install:
        print('CHECK ONLY: no files were changed. Run with --install to compile/install.')
        return 0
    created=[]
    try:
        for f in SOURCES:
            dest=languages/f
            shutil.copy2(source_dir/f,dest)
            created.append(dest)
        slaspec=languages/SOURCES[0]
        outfile=languages/OUTPUT
        # Use target Ghidra's compiler to avoid mismatched compiled SLA versions.
        command=[str(compiler),str(slaspec),str(outfile)]
        print('Compiling:', ' '.join(command))
        p=subprocess.run(command,cwd=languages,check=False)
        if p.returncode != 0 or not outfile.is_file() or outfile.stat().st_size < 1024:
            raise RuntimeError('DECKARD Sleigh compilation did not produce a valid-sized SLA; see errors above')
        created.append(outfile)
        print('INSTALLED:',outfile)
        print('Restart Ghidra; choose PowerPC:BE:32:DECKARD on a fresh firmware import.')
        return 0
    except BaseException:
        # Do not damage unrelated files: remove ONLY names created by this script.
        for dest in created:
            try: dest.unlink(missing_ok=True)
            except OSError: pass
        # The compiler may have written a partial .sla before failing.
        if (languages/OUTPUT).exists():
            try: (languages/OUTPUT).unlink()
            except OSError: pass
        print('ROLLED BACK: newly created DECKARD files removed; stock PPC untouched',file=sys.stderr)
        raise

if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, RuntimeError) as e:
        print('ERROR:',e,file=sys.stderr);sys.exit(1)

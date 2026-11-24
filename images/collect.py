#!/usr/bin/env python3
"""Copy results off the (read-only mounted) Windows volume after the VM stops.
usage: collect.py <mountpoint> <outdir>"""
import os, re, shutil, sys

MNT, OUT = sys.argv[1], sys.argv[2]


def ci(rel):
    cur = MNT
    for comp in rel.replace('\\', '/').split('/'):
        if not comp:
            continue
        try:
            hit = next((n for n in os.listdir(cur) if n.lower() == comp.lower()), None)
        except OSError:
            return None
        if hit is None:
            return None
        cur = os.path.join(cur, hit)
    return cur


g = ci('cptest/out')
if g:
    shutil.copytree(g, os.path.join(OUT, 'guest'), dirs_exist_ok=True)
    print(f'collected {sum(len(f) for _, _, f in os.walk(g))} guest files')
else:
    print('C:\\cptest\\out does not exist - the boot hook never ran')
st = ci('cptest/state.txt')
print('guest state:', open(st).read().strip() if st else 'none')

# final copies of the score report files the host found before boot
cand = ci('cptest/report-candidates.txt')
if cand:
    dst = os.path.join(OUT, 'score-disk-final')
    os.makedirs(dst, exist_ok=True)
    for i, line in enumerate(open(cand, encoding='utf-8-sig').read().splitlines()):
        p = ci(re.sub(r'(?i)^c:\\', '', line.strip())) if line.strip() else None
        if p and os.path.isfile(p):
            shutil.copy2(p, os.path.join(dst, f'{i:02d}_{os.path.basename(p)}'))

# Harden backup folder (secedit export, auditpol, reg exports, harden-log.txt)
for d in ('Windows/System32/config/systemprofile/Desktop', 'Users/Public/Desktop', 'Windows/System32'):
    sp = ci(d)
    if sp:
        for n in os.listdir(sp):
            if n.startswith('CP-Backup-') and os.path.isdir(os.path.join(sp, n)):
                shutil.copytree(os.path.join(sp, n), os.path.join(OUT, 'harden-backup', n), dirs_exist_ok=True)

# If nothing ran, keep the System event log for diagnosis.
if not g:
    ev = ci('Windows/System32/winevt/Logs/System.evtx')
    if ev:
        shutil.copy2(ev, OUT)

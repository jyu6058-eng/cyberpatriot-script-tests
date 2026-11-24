#!/usr/bin/env python3
"""Markdown summary of one image run. usage: summarize.py <outdir> <title>"""
import glob, html.parser, os, re, sys

OUT, TITLE = sys.argv[1], sys.argv[2]


class T(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.p, self.skip = [], 0

    def handle_starttag(self, t, a):
        if t in ('script', 'style'):
            self.skip += 1
        elif t in ('br', 'p', 'div', 'li', 'tr', 'h1', 'h2', 'h3', 'h4', 'title'):
            self.p.append('\n')

    def handle_endtag(self, t):
        if t in ('script', 'style'):
            self.skip -= 1

    def handle_data(self, d):
        if not self.skip:
            self.p.append(d)


def text(path):
    raw = open(path, 'rb').read()
    s = raw.decode('utf-16') if raw[:2] in (b'\xff\xfe', b'\xfe\xff') else raw.decode('utf-8', 'replace')
    if re.search(r'\.html?$', path, re.I):
        t = T(); t.feed(s); s = ''.join(t.p)
    return '\n'.join(l.strip() for l in s.splitlines() if l.strip())


def readlines(p):
    if not os.path.exists(p):
        return []
    raw = open(p, 'rb').read()
    s = raw.decode('utf-16') if raw[:2] in (b'\xff\xfe', b'\xfe\xff') else raw.decode('utf-8-sig', 'replace')
    return s.splitlines()


print(f'### {TITLE}\n')
d = readlines(os.path.join(OUT, 'discovery.txt'))
for l in d:
    if re.match(r'(OS|Computer name|hive SYSTEM|Winlogon):', l) or 'scoring engine folder' in l or l.startswith('README found'):
        print(f'- {l}')
print()

run = readlines(os.path.join(OUT, 'guest', 'run.log'))
if run:
    print('<details><summary>guest run.log</summary>\n\n```')
    print('\n'.join(run[-80:]))
    print('```\n</details>\n')
else:
    print('**Guest runner produced no log** (boot failed or hook did not run). See shots/ and host.log.\n')

for tag in ('shipped', 'boot', 'after-audit', 'after-harden', 'after-reboot', 'final'):
    files = sorted(glob.glob(os.path.join(OUT, 'guest', f'score-{tag}', '*.htm*'))) or \
            sorted(glob.glob(os.path.join(OUT, f'score-{tag}', '*.htm*')))
    for f in files[:1]:
        t = text(f)
        keep = [l for l in t.splitlines() if re.search(r'(?i)points|out of|penalt|score|issues|\bpts\b', l)][:6]
        print(f'**score {tag}** ({os.path.basename(f)}): ' + ' | '.join(keep) + '\n')
        with open(os.path.join(OUT, f'score-{tag}.txt'), 'w') as fh:
            fh.write(t)

for tag in ('audit-before', 'audit-after'):
    lines = readlines(os.path.join(OUT, 'guest', f'{tag}.txt'))
    if lines:
        flags = sum(1 for l in lines if l.startswith('[!]'))
        checks = sum(1 for l in lines if l.startswith('[?]'))
        print(f'- {tag}: {flags} [!] and {checks} [?]')
h = readlines(os.path.join(OUT, 'guest', 'harden.console.txt'))
if h:
    fails = [l.strip() for l in h if 'FAILED' in l or 'exit code' in l]
    print(f'- harden: {len(h)} output lines, {len(fails)} failures')
    for l in fails[:15]:
        print(f'  - `{l}`')

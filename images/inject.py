#!/usr/bin/env python3
"""Offline prep of a mounted Windows volume (run as root on the host).

usage: inject.py <mountpoint> <outdir> <repo> [--scoring-dat FILE]

1. Discovery: what the image contains (OS, users, desktops, scoring engine,
   README, installed programs) -> <outdir>/discovery.txt, copies of README and
   initial scoring report files.
2. Copies the test scripts to C:\\cptest.
3. SYSTEM hive: adds a one-shot boot service that starts C:\\cptest\\run.ps1
   (run.ps1 deletes it first thing), and makes storahci boot-start so the
   disk works on QEMU's AHCI controller.
"""
import base64, hashlib, html.parser, os, re, shutil, struct, sys, urllib.parse, urllib.request

MNT, OUT, REPO = sys.argv[1], sys.argv[2], sys.argv[3]
SCORING_DAT = sys.argv[sys.argv.index('--scoring-dat') + 1] if '--scoring-dat' in sys.argv else None
os.makedirs(OUT, exist_ok=True)
disc = open(os.path.join(OUT, 'discovery.txt'), 'w', encoding='utf-8')


def say(*a):
    s = ' '.join(str(x) for x in a)
    print(s)
    disc.write(s + '\n')


def ci(*parts):
    """Case-insensitive path lookup under MNT. Returns real path or None."""
    cur = MNT
    for comp in '/'.join(parts).replace('\\', '/').split('/'):
        if not comp:
            continue
        try:
            names = os.listdir(cur)
        except OSError:
            return None
        hit = next((n for n in names if n.lower() == comp.lower()), None)
        if hit is None:
            return None
        cur = os.path.join(cur, hit)
    return cur


def winpath(p):
    return 'C:\\' + os.path.relpath(p, MNT).replace('/', '\\')


def tree(p, depth, indent='  ', maxn=60):
    try:
        names = sorted(os.listdir(p))
    except OSError:
        return
    for n in names[:maxn]:
        fp = os.path.join(p, n)
        if os.path.isdir(fp):
            say(f'{indent}{n}/')
            if depth > 1:
                tree(fp, depth - 1, indent + '  ', maxn)
        else:
            try:
                sz = os.path.getsize(fp)
            except OSError:
                sz = -1
            say(f'{indent}{n}  ({sz} B)')
    if len(names) > maxn:
        say(f'{indent}... {len(names) - maxn} more')


class Text(html.parser.HTMLParser):
    BREAK = {'br', 'p', 'div', 'li', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'pre', 'table', 'ul', 'ol', 'title'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.skip += 1
        elif tag in self.BREAK:
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.skip = max(0, self.skip - 1)
        elif tag in self.BREAK:
            self.parts.append('\n')

    def handle_data(self, d):
        if not self.skip:
            self.parts.append(d)


def html_to_text(raw):
    p = Text()
    p.feed(raw)
    t = ''.join(p.parts).replace('\r', '')
    t = re.sub(r'[ \t\xa0]+\n', '\n', t)
    return re.sub(r'\n{3,}', '\n\n', t).strip()


def read_text(path):
    raw = open(path, 'rb').read()
    for enc in ('utf-8-sig', 'utf-16', 'cp1252'):
        try:
            s = raw.decode(enc)
            if enc == 'utf-16' and not raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
                continue
            return s
        except UnicodeDecodeError:
            pass
    return raw.decode('latin-1')


# ------------------------------------------------------------------ hives
import hivex  # noqa: E402

REG_SZ, REG_EXPAND_SZ, REG_DWORD = 1, 2, 4


def child(h, node, name):
    for c in h.node_children(node):
        if h.node_name(c).lower() == name.lower():
            return c
    return None


def path_node(h, path):
    n = h.root()
    for comp in path.split('\\'):
        n = child(h, n, comp)
        if not n:
            return None
    return n


def val(h, node, name):
    if not node:
        return None
    for v in h.node_values(node):
        if h.value_key(v).lower() == name.lower():
            t, data = h.value_value(v)
            if t in (REG_SZ, REG_EXPAND_SZ):
                return data.decode('utf-16-le', 'replace').rstrip('\x00')
            if t == REG_DWORD:
                return struct.unpack('<I', data[:4])[0]
            return data
    return None


def sz(s, t=REG_SZ):
    return {'key': None, 't': t, 'value': (s + '\x00').encode('utf-16-le')}


def dword(n):
    return {'key': None, 't': REG_DWORD, 'value': struct.pack('<I', n)}


def fix_regf_checksum(path):
    """Recompute the regf header checksum: XOR of the first 127 dwords, stored at 0x1FC."""
    with open(path, 'r+b') as f:
        hdr = f.read(512)
        x = 0
        for i in range(0, 0x1FC, 4):
            x ^= int.from_bytes(hdr[i:i + 4], 'little')
        if x == 0xFFFFFFFF:
            x = 0xFFFFFFFE
        elif x == 0:
            x = 1
        f.seek(0x1FC)
        f.write(x.to_bytes(4, 'little'))


def hive_dirty(path):
    with open(path, 'rb') as f:
        hdr = f.read(12)
    s1, s2 = struct.unpack('<II', hdr[4:12])
    return s1 != s2, s1, s2


cfg = ci('Windows/System32/config')
say('=' * 70)
say('IMAGE DISCOVERY')
say('=' * 70)
for hv in ('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY'):
    p = ci('Windows/System32/config', hv)
    if p:
        d, s1, s2 = hive_dirty(p)
        say(f'hive {hv}: {"DIRTY" if d else "clean"} (seq {s1}/{s2})')

ifeo_hijacked = set()
sw = ci('Windows/System32/config/SOFTWARE')
if sw:
    h = hivex.Hivex(sw)
    cv = path_node(h, r'Microsoft\Windows NT\CurrentVersion')
    say(f"OS: {val(h, cv, 'ProductName')} | {val(h, cv, 'EditionID')} | build {val(h, cv, 'CurrentBuild')}.{val(h, cv, 'UBR')} | {val(h, cv, 'DisplayVersion')}")
    say(f"Registered owner: {val(h, cv, 'RegisteredOwner')}")
    wl = path_node(h, r'Microsoft\Windows NT\CurrentVersion\Winlogon')
    default_user = val(h, wl, 'DefaultUserName') or ''
    say(f"Winlogon: DefaultUserName={val(h, wl, 'DefaultUserName')} DefaultDomainName={val(h, wl, 'DefaultDomainName')} AutoAdminLogon={val(h, wl, 'AutoAdminLogon')} DefaultPassword={'SET' if val(h, wl, 'DefaultPassword') else 'none'}")
    progs = set()
    for base in (r'Microsoft\Windows\CurrentVersion\Uninstall', r'WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'):
        n = path_node(h, base)
        if n:
            for c in h.node_children(n):
                dn = val(h, c, 'DisplayName')
                if dn and not val(h, c, 'SystemComponent'):
                    progs.add(f"{dn} {val(h, c, 'DisplayVersion') or ''}".strip())
    say(f'Installed programs ({len(progs)}):')
    for p in sorted(progs):
        say('  ' + p)
    # Tool health: plants that stop PowerShell/cmd (and so this test's boot hook) from working
    ifeo = path_node(h, r'Microsoft\Windows NT\CurrentVersion\Image File Execution Options')
    dbg = []
    if ifeo:
        for c in h.node_children(ifeo):
            d = val(h, c, 'Debugger')
            if d:
                dbg.append(f'{h.node_name(c)} -> {d}')
                ifeo_hijacked.add(h.node_name(c).lower())
    say(f'Tool health: IFEO debuggers ({len(dbg)}): ' + ('; '.join(dbg) if dbg else 'none'))
    psp = path_node(h, r'Policies\Microsoft\Windows\PowerShell')
    srp = 'present' if path_node(h, r'Policies\Microsoft\Windows\Safer\CodeIdentifiers') else 'none'
    say(f"Tool health: PowerShell policy ExecutionPolicy={val(h, psp, 'ExecutionPolicy')} EnableScripts={val(h, psp, 'EnableScripts')}; Software Restriction Policies: {srp}")
    for app in ('cmd', 'powershell'):
        n = path_node(h, 'Microsoft\\Windows\\CurrentVersion\\App Paths\\' + app + '.exe')
        if n:
            say(f"Tool health: App Paths {app}.exe -> {val(h, n, '')}")
    del h

sysh = ci('Windows/System32/config/SYSTEM')
h = hivex.Hivex(sysh)
cur = val(h, path_node(h, 'Select'), 'Current') or 1
cs = f'ControlSet{cur:03d}'
cn = path_node(h, cs + r'\Control\ComputerName\ComputerName')
say(f"Computer name: {val(h, cn, 'ComputerName')}   (current control set {cs})")
svcs = path_node(h, cs + r'\Services')
interesting = []
for c in h.node_children(svcs):
    ip = val(h, c, 'ImagePath')
    st = val(h, c, 'Start')
    if isinstance(ip, str) and st in (2, 3) and not re.search(r'(?i)\\windows\\|system32|syswow64|^\\systemroot|^system32|%systemroot%|%windir%', ip):
        interesting.append(f'  {h.node_name(c)}  start={st}  {ip}')
say(f'Non-Windows services ({len(interesting)}):')
for s in sorted(interesting):
    say(s)
env = path_node(h, cs + r'\Control\Session Manager\Environment')
say(f"Tool health: ComSpec={val(h, env, 'ComSpec')} PATHEXT={val(h, env, 'PATHEXT')} __PSLockdownPolicy={val(h, env, '__PSLockdownPolicy')}")
say(f"Tool health: PATH={val(h, env, 'Path')}")
for svc in ('EventLog', 'Schedule', 'Winmgmt', 'LanmanServer', 'RpcSs'):
    n = child(h, svcs, svc)
    say(f"Tool health: service {svc} Start={val(h, n, 'Start') if n else 'MISSING'}")
for exe in ('Windows/System32/cmd.exe', 'Windows/System32/WindowsPowerShell/v1.0/powershell.exe', 'Windows/System32/conhost.exe'):
    q = ci(exe)
    say(f"Tool health: {exe}: {os.path.getsize(q) if q else 'MISSING'} bytes")
del h

say('')
say('Top of C:\\')
tree(MNT, 1)
for d in ('aeacus', 'CyberPatriot', 'scoring', 'CCS'):
    p = ci(d)
    if p:
        say(f'\nC:\\{os.path.basename(p)}  (scoring engine folder?)')
        tree(p, 3)

users = ci('Users')
desk_files = []
if users:
    for u in sorted(os.listdir(users)):
        dp = os.path.join(users, u, 'Desktop')
        if os.path.isdir(dp):
            names = sorted(os.listdir(dp))
            say(f'\nDesktop of {u}: {", ".join(names) if names else "(empty)"}')
            desk_files += [os.path.join(dp, n) for n in names]

# scoring-ish files anywhere outside Windows
cands = []
skip = re.compile(r'(?i)^/(windows|program files/windowsapps|\$recycle\.bin|system volume information|programdata/microsoft|recovery)(/|$)')
for root, dirs, files in os.walk(MNT):
    rel = '/' + os.path.relpath(root, MNT).replace('\\', '/')
    if rel == '/.':
        rel = '/'
    if skip.search(rel) or rel.count('/') > 7:
        dirs[:] = []
        continue
    for f in files:
        if re.search(r'(?i)scor(e|ing)', f) and re.search(r'(?i)\.(html?|txt|json|xml|log|lnk|url|dat|conf|cfg|ini)$', f):
            cands.append(os.path.join(root, f))
say(f'\nScoring-related files ({len(cands)}):')
for c in cands[:80]:
    say(f'  {winpath(c)}  ({os.path.getsize(c)} B)')

# ------------------------------------------------------------------ README
readme_text = ''
rdir = os.path.join(OUT, 'readme')
os.makedirs(rdir, exist_ok=True)
rcands = [f for f in desk_files if re.search(r'(?i)read ?me', os.path.basename(f))]
for d in ('aeacus', 'CyberPatriot'):
    p = ci(d)
    if p:
        for root, _, files in os.walk(p):
            rcands += [os.path.join(root, f) for f in files if re.search(r'(?i)read ?me', f)]
for f in rcands:
    base = os.path.basename(f)
    try:
        if os.path.getsize(f) > 5_000_000:
            continue
        shutil.copy2(f, os.path.join(rdir, base))
        raw = read_text(f)
        text = ''
        if f.lower().endswith('.url'):
            m = re.search(r'(?im)^URL=(.+)$', raw)
            target = m.group(1).strip() if m else ''
            say(f'README shortcut {base} -> {target}')
            if target.lower().startswith('file:'):
                t = re.sub(r'(?i)^file:/*', '', urllib.parse.unquote(target))
                lp = ci(re.sub(r'(?i)^[a-z]:[\\/]', '', t))
                if lp:
                    text = html_to_text(read_text(lp))
            elif target.lower().startswith('http'):
                try:
                    req = urllib.request.Request(target, headers={'User-Agent': 'Mozilla/5.0'})
                    text = html_to_text(urllib.request.urlopen(req, timeout=20).read().decode('utf-8', 'replace'))
                    say(f'  fetched README from the web ({len(text)} chars)')
                except Exception as e:  # noqa: BLE001
                    say(f'  could not fetch README: {e}')
        elif re.search(r'(?i)\.html?$', f):
            text = html_to_text(raw)
        elif f.lower().endswith('.txt'):
            text = raw
        if text:
            open(os.path.join(rdir, base + '.txt'), 'w', encoding='utf-8').write(text)
            if 'authorized' in text.lower() and len(text) > len(readme_text):
                readme_text = text
    except Exception as e:  # noqa: BLE001
        say(f'README read error {base}: {e}')

# Pull out just the user list block, the way a student would paste it into users.txt
userlist = ''
if readme_text:
    lines = readme_text.splitlines()
    start = next((i for i, l in enumerate(lines) if re.search(r'(?i)authorized\s+admin', l)), None)
    if start is not None:
        block, seen_users, n_users = [], False, 0
        for l in lines[start:]:
            t = l.strip()
            if re.search(r'(?i)authorized\s+users?\b', t) and not re.search(r'(?i)admin', t):
                seen_users = True
                block.append(l)
                continue
            if seen_users:
                if not t:
                    if n_users:
                        break      # first blank line after the users list ends it
                    continue
                n_users += 1
            block.append(l)
        userlist = '\n'.join(block).strip()
say(f'\nREADME found: {"yes" if readme_text else "no"};  user list block: {len(userlist.splitlines())} lines')
if userlist:
    say(userlist)

# ------------------------------------------------------------------ copy scripts
dst = os.path.join(MNT, 'cptest')
os.makedirs(dst, exist_ok=True)
for f in ('Audit.ps1', 'Harden.ps1', 'Users.ps1'):
    shutil.copy2(os.path.join(REPO, 'scripts', f), dst)
shutil.copy2(os.path.join(REPO, 'images', 'guest', 'run.ps1'), dst)
with open(os.path.join(dst, 'report-candidates.txt'), 'w', encoding='utf-8-sig') as f:
    f.write('\r\n'.join(winpath(c) for c in cands if re.search(r'(?i)\.(html?|txt|json|xml)$', c)))
if userlist:
    open(os.path.join(dst, 'users.txt'), 'w', encoding='utf-8-sig').write(userlist.replace('\n', '\r\n'))
if readme_text:
    open(os.path.join(dst, 'readme.txt'), 'w', encoding='utf-8-sig').write(readme_text.replace('\n', '\r\n'))
m = re.search(r'(?im)^\s*([^\s(][^(\n]*?)\s*\(you\)', readme_text or '')
main_user = m.group(1).strip() if m else (default_user if sw else '')
say(f'Main user (logged-in account in a real round): {main_user or "unknown"}')
if main_user:
    open(os.path.join(dst, 'mainuser.txt'), 'w', encoding='utf-8').write(main_user)

# initial copies of score reports (as shipped)
sdir = os.path.join(OUT, 'score-shipped')
os.makedirs(sdir, exist_ok=True)
for i, c in enumerate(cands):
    if re.search(r'(?i)\.(html?|txt|json)$', c) and os.path.getsize(c) < 5_000_000:
        shutil.copy2(c, os.path.join(sdir, f'{i:02d}_{os.path.basename(c)}'))

if SCORING_DAT:
    target = ci('aeacus/scoring.dat')
    if target:
        old = hashlib.md5(open(target, 'rb').read()).hexdigest()
        new = hashlib.md5(open(SCORING_DAT, 'rb').read()).hexdigest()
        if old != new:
            shutil.copy2(target, os.path.join(dst, 'scoring.dat.shipped'))
            shutil.copy2(SCORING_DAT, target)
            say(f'Replaced C:\\aeacus\\scoring.dat with the separate download ({old} -> {new})')
        else:
            say('Separate scoring.dat is identical to the one in the image')
    else:
        say('Separate scoring.dat given but C:\\aeacus\\scoring.dat not found; not copied')

# ------------------------------------------------------------------ boot hook
dirty, s1, s2 = hive_dirty(sysh)
if dirty:
    say(f'SYSTEM hive is dirty (seq {s1}/{s2}); applying its transaction logs first')
    try:
        from regipy.recovery import apply_transaction_logs
        log1 = ci('Windows/System32/config/SYSTEM.LOG1')
        log2 = ci('Windows/System32/config/SYSTEM.LOG2')
        restored = os.path.join(OUT, 'SYSTEM.restored')
        r = apply_transaction_logs(sysh, log1, secondary_log_path=log2, restored_hive_path=restored)
        say(f'  regipy: {r}')
        # regipy rewrites the sequence numbers and hbins size but not the header checksum,
        # and hivex refuses a hive whose checksum is wrong (King Arthur's Castle).
        fix_regf_checksum(restored)
        try:
            hivex.Hivex(restored)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f'replayed hive still does not open in hivex ({e})')
        orig = os.path.join(OUT, 'SYSTEM.dirty-original')
        shutil.copy2(sysh, orig)
        shutil.copy2(restored, sysh)
        os.remove(restored)
        hl = os.path.join(dst, 'hivelogs')
        os.makedirs(hl, exist_ok=True)
        for lg in (log1, log2):
            if lg:
                shutil.move(lg, hl)
        say('  transaction logs applied; the original logs were moved to C:\\cptest\\hivelogs')
    except Exception as e:  # noqa: BLE001
        say(f'  could not apply logs ({e}); editing the hive without them (its last unsaved changes are lost)')

boot = r"& ([scriptblock]::Create([IO.File]::ReadAllText('C:\cptest\run.ps1')))"
enc = base64.b64encode(boot.encode('utf-16-le')).decode()
# A "broken" image can hijack cmd.exe/powershell.exe with an IFEO debugger, which only matches the file name:
# start them through a hard link with another name instead (the image's own state is left as it is).
launch = {}
for name, folder in (('cmd.exe', 'Windows/System32'), ('powershell.exe', 'Windows/System32/WindowsPowerShell/v1.0')):
    win = '%SystemRoot%\\' + folder.split('/', 1)[1].replace('/', '\\') + '\\'
    launch[name] = win + name
    if name in ifeo_hijacked:
        src, d = ci(folder + '/' + name), ci(folder)
        if src and d:
            try:
                os.link(src, os.path.join(d, 'cptest-' + name))
            except FileExistsError:
                pass
            launch[name] = win + 'cptest-' + name
            say(f'{name} has an IFEO debugger: the boot hook starts it as cptest-{name} so the hijack does not apply')
# "set __PSLockdownPolicy=" clears a planted constrained-language switch for this hook only.
image_path = (launch['cmd.exe'] + ' /c set __PSLockdownPolicy=& start "" ' + launch['powershell.exe'] + ' '
              r'-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ' + enc)
open(os.path.join(dst, 'imagepath.txt'), 'w', encoding='utf-8').write(image_path)

h = hivex.Hivex(sysh, write=True)
svcs = path_node(h, cs + r'\Services')
node = child(h, svcs, 'CPTestRunner') or h.node_add_child(svcs, 'CPTestRunner')
vals = [('Type', dword(0x10)), ('Start', dword(2)), ('ErrorControl', dword(0)),
        ('ImagePath', sz(image_path, REG_EXPAND_SZ)), ('ObjectName', sz('LocalSystem')),
        ('DisplayName', sz('CP test runner (one-shot)'))]
h.node_set_values(node, [dict(v, key=k) for k, v in vals])
sa = child(h, svcs, 'storahci')
if sa:
    h.node_set_value(sa, dict(dword(0), key='Start'))
    so = child(h, sa, 'StartOverride')
    if so:
        h.node_delete_child(so)
    say('storahci set to boot-start')
h.commit(None)
say(f'Boot hook added to {cs}\\Services\\CPTestRunner')
disc.close()

#!/usr/bin/env bash
# Host side of the practice-image test. Runs on an ubuntu-latest GitHub runner.
#   download -> extract -> read .vmx -> qcow2 overlay -> offline inject
#   -> boot under QEMU/KVM (guest runs images/guest/run.ps1) -> collect results
set -uo pipefail

KEY=${KEY:?}; DRIVE_ID=${DRIVE_ID:?}; TITLE=${TITLE:-$KEY}
REPO=$(cd "$(dirname "$0")/.." && pwd); cd "$REPO"
OUT=$REPO/out/$KEY
W=/var/tmp/cpimg
VM_MINUTES=${VM_MINUTES:-150}
mkdir -p "$OUT/shots"
: > "$OUT/host.log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/host.log"; }
die() { log "FATAL: $*"; summary "FAILED: $*"; exit 1; }
summary() { { echo "### $TITLE"; echo; echo "$*"; echo; } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"; }
url() { echo "https://drive.usercontent.google.com/download?id=$1&export=download&confirm=t"; }

[ -z "${ONLY:-}" ] && [ -f "$REPO/images/only.txt" ] && ONLY=$(tr -d ' \n' < "$REPO/images/only.txt")
if [ -n "${ONLY:-}" ] && [[ ",${ONLY// /}," != *",$KEY,"* ]]; then log "skipped (only=$ONLY)"; exit 0; fi

# fail fast on PowerShell syntax errors
if command -v pwsh >/dev/null; then
    pwsh -NoProfile -Command '$bad=0; foreach ($f in Get-ChildItem images/guest/*.ps1, scripts/*.ps1) { $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$null,[ref]$e); if ($e) { $bad++; $e | % { "$($f.Name): $_" } } }; exit $bad' \
        || die "PowerShell parse errors"
    log "PowerShell parse OK"
fi

# ------------------------------------------------------------ tools + disk
log "freeing disk and installing tools"
( sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc /usr/local/.ghcup \
    /opt/hostedtoolcache/CodeQL /usr/local/share/boost /usr/share/swift 2>/dev/null ) &
sudo apt-get update -qq >/dev/null 2>&1
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-x86 qemu-utils ovmf \
    python3-hivex python3-venv ntfs-3g 7zip aria2 socat dislocker >/dev/null 2>&1 || die "apt install failed"
python3 -m venv --system-site-packages /var/tmp/venv && /var/tmp/venv/bin/pip -q install regipy >/dev/null 2>&1 \
    || log "regipy not installed (only needed if a hive is dirty)"
PY=/var/tmp/venv/bin/python3; [ -x "$PY" ] || PY=python3
wait
sudo mkdir -p "$W" /mnt/w && sudo chown "$USER" "$W"
sudo chmod 666 /dev/kvm
df -h / | tail -1 | tee -a "$OUT/host.log"

# ------------------------------------------------------------ download
cd "$W"
log "downloading $TITLE ($EXPECT_SIZE bytes)"
t0=$(date +%s)
# When Drive's quota is used up it answers with a ~2 KB HTML page instead of the file; aria2c then
# "succeeds" once and the size check below stops the run. (Ranged requests can still return 206 while
# plain ones are refused, so a ranged probe is not a valid availability check.)
ok=0
for try in 1 2 3; do
    aria2c -q -x 8 -s 8 -k 64M --file-allocation=none --max-tries=8 --retry-wait=10 \
        --auto-file-renaming=false --allow-overwrite=true -d "$W" -o archive "$(url "$DRIVE_ID")" && { ok=1; break; }
    log "aria2c attempt $try failed"
done
if [ $ok = 0 ]; then
    rm -f archive archive.aria2
    curl -sSL --retry 10 --retry-delay 10 -o archive "$(url "$DRIVE_ID")" || die "download failed"
fi
got=$(stat -c %s archive)
log "downloaded $got bytes in $(( $(date +%s) - t0 ))s"
if [ -n "${EXPECT_SIZE:-}" ] && [ "$got" != "$EXPECT_SIZE" ]; then
    if [ "$got" -lt 1000000 ] && grep -qiE 'quota|too many users|<html' archive 2>/dev/null; then
        die "Google Drive refused the download (too many downloads of this file recently). Try again in a few hours."
    fi
    die "size mismatch: got $got, expected $EXPECT_SIZE"
fi

if [ -n "${EXTRA_SCORING_ID:-}" ]; then
    curl -sSL --retry 5 -o "$W/scoring.dat" "$(url "$EXTRA_SCORING_ID")" && log "extra scoring.dat: $(stat -c %s "$W/scoring.dat") bytes"
fi

# ------------------------------------------------------------ extract
log "extracting"
t0=$(date +%s)
7z x -y -bd -p- -o"$W/ex" archive > "$OUT/extract.log" 2>&1 || { tail -20 "$OUT/extract.log"; die "extract failed"; }
rm -f archive
log "extracted in $(( $(date +%s) - t0 ))s: $(du -sh "$W/ex" | cut -f1)"
find "$W/ex" -type f -not -path '*/caches/*' -printf '%12s  %P\n' | sort -k2 > "$OUT/files.txt"
df -h / | tail -1 | tee -a "$OUT/host.log"

# ------------------------------------------------------------ read the .vmx
VMX=$(find "$W/ex" -name '*.vmx' | head -1)
[ -n "$VMX" ] || die "no .vmx in archive"
VMDIR=$(dirname "$VMX")
tr -d '\r' < "$VMX" > "$OUT/vm.vmx"
vget() { grep -iE "^$1 *=" "$OUT/vm.vmx" | head -1 | sed -E 's/^[^=]*= *"(.*)".*/\1/'; }
grep -qiE '^(encryption\.|.*keySafe)' "$OUT/vm.vmx" && die "VM is encrypted"
FW=$(vget firmware); MEM=$(vget memsize); NICDEV=$(vget 'ethernet0\.virtualDev'); GOS=$(vget guestOS)
SB=$(vget 'uefi\.secureBoot\.enabled')
DISKS=()
while IFS= read -r line; do
    dev=${line%%.fileName*}; dev=${dev,,}
    f=$(sed -E 's/^[^=]*= *"(.*)".*/\1/' <<<"$line")
    pres=$(vget "${dev}\.present"); dt=$(vget "${dev}\.deviceType")
    [ "${pres,,}" = "false" ] && continue
    [[ "${dt,,}" == cdrom* ]] && continue
    f=${f//\\//}; f=$VMDIR/$(basename "$f")
    [ -f "$f" ] || { log "disk listed in vmx but missing: $f"; continue; }
    DISKS+=("$f"); log "disk: $dev -> $(basename "$f")  [$(vget "${dev%%:*}\.virtualDev")]"
done < <(grep -iE '^(scsi|sata|nvme|ide)[0-9]+:[0-9]+\.fileName *= *".*\.vmdk"' "$OUT/vm.vmx")
[ ${#DISKS[@]} -gt 0 ] || die "no disks found in vmx"
log "vmx: guestOS=$GOS firmware=${FW:-bios} secureBoot=${SB:-no} memsize=$MEM nic=$NICDEV disks=${#DISKS[@]}"
ls "$VMDIR"/*.vmss "$VMDIR"/*.vmem >/dev/null 2>&1 && log "note: VM was saved SUSPENDED; booting cold from disk"

i=0
for f in "${DISKS[@]}"; do
    qemu-img info --backing-chain "$f" > "$OUT/disk$i-info.txt" 2>&1 || { cat "$OUT/disk$i-info.txt"; die "qemu-img cannot read $(basename "$f")"; }
    qemu-img create -q -f qcow2 -b "$(realpath "$f")" -F vmdk "$W/disk$i.qcow2" || die "overlay failed"
    i=$((i+1))
done
NDISK=$i

# ------------------------------------------------------------ offline inject
sudo modprobe nbd max_part=16 || die "no nbd module"
nbd_up()   { sudo qemu-nbd ${3:-} --connect="/dev/nbd$1" -f qcow2 "$2" && sleep 2 && sudo partprobe "/dev/nbd$1" 2>/dev/null; sleep 1; }
nbd_down() { for j in $(seq 0 $((NDISK-1))); do sudo qemu-nbd --disconnect "/dev/nbd$j" >/dev/null 2>&1; done; }

# Mount a partition at /mnt/w. BitLocker volumes are opened with dislocker's clear key (protection suspended);
# a volume locked with a TPM or password cannot be opened outside VMware.
mount_win() {   # $1 partition, $2 ro|rw
    local p=$1 mode=$2 src=$1
    if [ "$(sudo blkid -o value -s TYPE "$p" 2>/dev/null)" = BitLocker ]; then
        sudo mkdir -p /mnt/bl
        local ro=""; [ "$mode" = ro ] && ro="-r"
        if ! sudo dislocker -V "$p" --clearkey $ro -- /mnt/bl 2>>"$OUT/host.log"; then
            log "BitLocker on $p has no clear key (locked with TPM/password) - cannot open it. Protectors:"
            sudo dislocker-metadata -V "$p" 2>&1 | grep -iE 'datum value type|protect|entry type' | sort | uniq -c | head -20 | tee -a "$OUT/host.log"
            return 1
        fi
        src=/mnt/bl/dislocker-file; BITLOCKER=1
    fi
    if [ "$mode" = ro ]; then sudo mount -t ntfs-3g -o ro "$src" /mnt/w 2>/dev/null; return $?; fi
    sudo mount -t ntfs-3g -o rw,remove_hiberfile "$src" /mnt/w 2>>"$OUT/host.log" && return 0
    log "NTFS not clean; running ntfsfix -d on the overlay copy"
    sudo ntfsfix -d "$src" >> "$OUT/host.log" 2>&1
    sudo mount -t ntfs-3g -o rw,remove_hiberfile "$src" /mnt/w
}
# The dislocker FUSE mount belongs to root, so check and unmount it as root (a plain `mountpoint` cannot see it).
umount_win() { sudo umount /mnt/w 2>/dev/null; sudo umount /mnt/bl 2>/dev/null; sleep 1; true; }
BITLOCKER=0
WINPART=""; WINDISK=""
for j in $(seq 0 $((NDISK-1))); do
    nbd_up "$j" "$W/disk$j.qcow2"
    lsblk -o NAME,SIZE,FSTYPE,LABEL "/dev/nbd$j" | tee -a "$OUT/host.log"
    for p in /dev/nbd${j}p*; do
        case "$(sudo blkid -o value -s TYPE "$p" 2>/dev/null)" in ntfs|BitLocker) ;; *) continue;; esac
        mount_win "$p" ro || continue
        if [ -n "$(sudo find /mnt/w -maxdepth 4 -ipath '/mnt/w/windows/system32/config/system' -print -quit 2>/dev/null)" ]; then
            WINPART=$p; WINDISK=$j
        fi
        umount_win
        [ -n "$WINPART" ] && break
    done
    [ -n "$WINPART" ] && break
done
[ -n "$WINPART" ] || { nbd_down; die "no Windows partition found"; }
WINPNUM=${WINPART##*p}
log "Windows is on disk$WINDISK partition $WINPNUM$( [ $BITLOCKER = 1 ] && echo ' (BitLocker, clear key)')"
mount_win "$WINPART" rw || { nbd_down; die "cannot mount Windows read-write"; }
extra=(); [ -s "$W/scoring.dat" ] && extra=(--scoring-dat "$W/scoring.dat")
sudo "$PY" "$REPO/images/inject.py" /mnt/w "$OUT" "$REPO" "${extra[@]}" 2>&1 | tee -a "$OUT/host.log"
rc=${PIPESTATUS[0]}
umount_win; nbd_down
[ "$rc" = 0 ] || die "inject failed"

# ------------------------------------------------------------ boot
case "${NICDEV,,}" in vmxnet3) NIC=vmxnet3;; e1000) NIC=e1000;; *) NIC=e1000e;; esac
MEMQ=$(( ${MEM:-8192} < 6144 ? 6144 : ( ${MEM:-8192} > 10240 ? 10240 : ${MEM:-8192} ) ))
QARGS=(-name cp -machine q35,accel=kvm,vmport=off
       -cpu host,-vmx,-svm,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time
       -smp 4,sockets=1,cores=4 -m "$MEMQ" -rtc base=localtime,clock=host
       -vga std -display none -usb -device usb-tablet
       -monitor "unix:$W/mon.sock,server,nowait" -serial "file:$OUT/serial.log"
       -netdev user,id=n0,restrict=on -device "$NIC,netdev=n0")
if [ "${FW,,}" = efi ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "$W/vars.fd"
    QARGS+=(-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
            -drive "if=pflash,format=raw,file=$W/vars.fd")
fi
# Windows disk first, all on the q35 AHCI controller (storahci was set to boot-start).
order=("$WINDISK"); for j in $(seq 0 $((NDISK-1))); do [ "$j" != "$WINDISK" ] && order+=("$j"); done
bus=0
for j in "${order[@]}"; do
    QARGS+=(-drive "file=$W/disk$j.qcow2,if=none,id=d$j,format=qcow2,cache=unsafe" -device "ide-hd,drive=d$j,bus=ide.$bus")
    bus=$((bus+1))
done
echo "qemu-system-x86_64 ${QARGS[*]}" >> "$OUT/host.log"
log "booting (nic=$NIC mem=${MEMQ}M firmware=${FW:-bios}); limit ${VM_MINUTES} min"
qemu-system-x86_64 "${QARGS[@]}" > "$OUT/qemu.log" 2>&1 &
QPID=$!
start=$(date +%s); n=0; seen=0; done_at=0
last_shot_hash=""; same_since=0; resets=0
mon() { echo "$1" | socat - "UNIX-CONNECT:$W/mon.sock" >/dev/null 2>&1; }
while kill -0 "$QPID" 2>/dev/null; do
    sleep 30; n=$((n+1))
    el=$(( $(date +%s) - start ))
    if (( n % 2 == 0 )); then
        shot="$OUT/shots/$(printf '%03d' $((el/60))).png"
        mon "screendump $shot -f png"; sleep 2
        # Freeze watchdog: the lock screen's clock changes every minute, so a non-blank screen that stays
        # identical for 15 minutes means Windows hung (seen once on Beyond Journey's End before any script ran).
        # A blank display (screen turned off, PNG of a few KB) is normal and never counts.
        if [ -s "$shot" ]; then
            h=$(md5sum < "$shot" | cut -c1-32); sz=$(stat -c %s "$shot")
            if [ "$h" != "$last_shot_hash" ] || (( sz < 20000 )); then
                last_shot_hash=$h; same_since=$el
            elif (( el - same_since >= 900 && resets < 2 )); then
                log "screen unchanged for $(( (el - same_since) / 60 )) min and not blank: guest looks frozen; resetting the VM (the guest steps resume after a reboot)"
                mon system_reset; resets=$((resets+1)); same_since=$el; last_shot_hash=""
            fi
        fi
    fi
    if [ -f "$OUT/serial.log" ]; then
        total=$(wc -l < "$OUT/serial.log")
        if (( total > seen )); then sed -n "$((seen+1)),${total}p" "$OUT/serial.log" | tr -d '\r' | sed 's/^/  guest: /'; seen=$total; fi
        if (( done_at == 0 )) && grep -q 'ALL DONE' "$OUT/serial.log"; then done_at=$el; fi
    fi
    if (( done_at > 0 && el - done_at > 300 )); then log "guest said ALL DONE but did not power off; stopping VM"; mon quit; break; fi
    if (( el > VM_MINUTES * 60 )); then log "time limit reached; stopping VM"; mon "screendump $OUT/shots/final.png -f png"; sleep 3; mon quit; break; fi
done
wait "$QPID" 2>/dev/null
log "VM stopped after $(( ($(date +%s) - start) / 60 )) min"
cat "$OUT/qemu.log" >> "$OUT/host.log"

# ------------------------------------------------------------ collect
nbd_up "$WINDISK" "$W/disk$WINDISK.qcow2" -r
mount_win "/dev/nbd${WINDISK}p$WINPNUM" ro || log "could not mount Windows to collect results"
if mountpoint -q /mnt/w; then
    sudo "$PY" "$REPO/images/collect.py" /mnt/w "$OUT" 2>&1 | tee -a "$OUT/host.log"
fi
umount_win
nbd_down
sudo chown -R "$USER" "$OUT"
"$PY" "$REPO/images/summarize.py" "$OUT" "$TITLE" | tee "$OUT/summary.md" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
cat "$OUT/summary.md"
log "done"

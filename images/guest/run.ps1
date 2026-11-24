# Guest side of the practice-image test. Started as SYSTEM at boot by a
# one-shot service that inject.py adds offline; that service is deleted first
# thing so the audit never sees it.
#
# Phase 1: wait for boot -> score snapshot -> Audit (full) -> Users dry run
#          -> score snapshot -> Harden -> wait -> score snapshot -> reboot
# Phase 2: wait for boot -> score snapshot -> Audit -Quick -> power off
# Progress goes to C:\cptest\out\run.log and to COM1 (the host shows it live).

$ErrorActionPreference = 'Continue'
$base  = 'C:\cptest'
$out   = Join-Path $base 'out'
$state = Join-Path $base 'state.txt'
New-Item -ItemType Directory -Path $out -Force | Out-Null
$logFile = Join-Path $out 'run.log'

$port = $null
try { $port = New-Object System.IO.Ports.SerialPort 'COM1', 115200, 'None', 8, 'One'; $port.Open() } catch { $port = $null }
function Log([string]$m) {
    $l = '[{0:HH:mm:ss}] {1}' -f (Get-Date), $m
    Add-Content -Path $logFile -Value $l
    if ($port) { try { $port.WriteLine($l) } catch {} }
}

$phase = if (Test-Path $state) { (Get-Content $state -Raw).Trim() } else { 'phase1' }
Log "=== $phase start as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) on $env:COMPUTERNAME (COM1 $(if ($port) {'ok'} else {'missing'}))"

# Remove the boot hook before anything looks at services.
& sc.exe delete CPTestRunner | Out-Null
Start-Sleep 2
Log "boot hook removed: $(if (Get-Service CPTestRunner -ErrorAction SilentlyContinue) { 'NO - still present' } else { 'yes' })"

$os = Get-CimInstance Win32_OperatingSystem
Log "OS: $($os.Caption) build $($os.BuildNumber), ProductType $($os.ProductType), booted $($os.LastBootUpTime)"

function Wait-Ready {
    $t0 = Get-Date
    if ($os.ProductType -eq 2) {
        $ok = $false
        do {
            try { Import-Module ActiveDirectory -ErrorAction Stop; $null = Get-ADDomain -ErrorAction Stop; $ok = $true }
            catch { Start-Sleep 20 }
        } until ($ok -or ((Get-Date) - $t0).TotalMinutes -gt 15)
        Log "Active Directory ready: $ok after $([int]((Get-Date) - $t0).TotalSeconds)s"
    }
    # let the scoring engine finish a pass after boot
    Start-Sleep 240
}

$sysDesk = [Environment]::GetFolderPath('Desktop')
New-Item -ItemType Directory -Path $sysDesk -Force | Out-Null
$empty = Join-Path $base 'empty.txt'
if (-not (Test-Path $empty)) { Set-Content -Path $empty -Value '' }

function Get-ScoreCandidates {
    $c = New-Object System.Collections.Generic.List[string]
    if (Test-Path "$base\report-candidates.txt") { Get-Content "$base\report-candidates.txt" | Where-Object { $_ } | ForEach-Object { $c.Add($_) } }
    $roots = @('C:\aeacus', 'C:\CyberPatriot', 'C:\Users\Public\Desktop') + @(Get-ChildItem 'C:\Users\*\Desktop' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object FullName)
    foreach ($r in $roots) {
        Get-ChildItem -LiteralPath $r -Recurse -Depth 3 -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'scor(e|ing)' -and $_.Extension -match '^\.(html?|txt|json|xml)$' } |
            ForEach-Object { if (-not $c.Contains($_.FullName)) { $c.Add($_.FullName) } }
    }
    return $c
}

function Snap([string]$tag) {
    $dir = Join-Path $out "score-$tag"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $i = 0
    foreach ($f in Get-ScoreCandidates) {
        if (Test-Path -LiteralPath $f -PathType Leaf) {
            $i++
            Copy-Item -LiteralPath $f -Destination (Join-Path $dir ('{0:00}_{1}' -f $i, (Split-Path $f -Leaf))) -Force
            if ($f -match '\.html?$') {
                $t = [regex]::Replace((Get-Content -LiteralPath $f -Raw), '<[^>]+>', "`n")
                $lines = $t -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '(?i)points|out of|penalt|score|issues' } | Select-Object -First 4
                foreach ($l in $lines) { Log "  [$tag] $l" }
            }
        }
    }
    Log "score snapshot '$tag': $i file(s)"
    Get-Process | Where-Object { $_.Name -match '(?i)phocus|aeacus|scor|ccs|minos' } | ForEach-Object { Log "  engine process: $($_.Name) pid $($_.Id)" }
}

function Run-Script([string]$tag, [string]$script, [string]$scriptArgs, [int]$minutes) {
    $code = "& ([scriptblock]::Create([IO.File]::ReadAllText('$base\$script'))) $scriptArgs"
    $enc  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $t0 = Get-Date
    Log "running $script $scriptArgs (limit $minutes min)"
    $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $enc" `
        -RedirectStandardOutput "$out\$tag.console.txt" -RedirectStandardError "$out\$tag.err.txt" `
        -RedirectStandardInput $empty -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit($minutes * 60000)) {
        Log "$tag TIMED OUT after $minutes min - killing"
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    Log ('{0} finished in {1:n1} min, exit code {2}' -f $tag, ((Get-Date) - $t0).TotalMinutes, $p.ExitCode)
    $err = Get-Content "$out\$tag.err.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match '\S' } | Select-Object -First 3
    foreach ($e in $err) { Log "  stderr: $e" }
    $done = Select-String -Path "$out\$tag.console.txt" -Pattern 'DONE:|findings|Finished|errors?' -ErrorAction SilentlyContinue | Select-Object -Last 2
    foreach ($d in $done) { Log "  $($d.Line.Trim())" }
}

function Save-Services([string]$tag) {
    Get-Service | Sort-Object Name | Select-Object Name, Status, StartType, DisplayName |
        Format-Table -AutoSize | Out-String -Width 200 | Set-Content "$out\services-$tag.txt"
}

if ($phase -eq 'phase1') {
    Wait-Ready
    Save-Services 'boot'
    Snap 'boot'

    Run-Script 'audit-before' 'Audit.ps1' '' 35
    $r = Get-ChildItem $sysDesk -Filter 'CP-Audit-*.txt' | Sort-Object LastWriteTime | Select-Object -Last 1
    if ($r) { Move-Item $r.FullName "$out\audit-before.txt" -Force }

    if (Test-Path "$base\users.txt") {
        Run-Script 'users-dryrun' 'Users.ps1' "-ListFile '$base\users.txt'" 10
    } else { Log 'no README user list found - Users.ps1 dry run skipped' }

    Start-Sleep 90
    Snap 'after-audit'          # Audit is read-only: the score must not change here

    Run-Script 'harden' 'Harden.ps1' '' 30
    Get-ChildItem $sysDesk -Directory -Filter 'CP-Backup-*' | ForEach-Object { Log "Harden backup: $($_.FullName) ($(@(Get-ChildItem $_.FullName -Recurse -File).Count) files)" }
    Save-Services 'after-harden'
    Start-Sleep 300
    Snap 'after-harden'

    # Come back after the reboot.
    Set-Content -Path $state -Value 'phase2'
    $ip = (Get-Content "$base\imagepath.txt" -Raw).Trim()
    New-Service -Name CPTestRunner -BinaryPathName $ip -StartupType Automatic -DisplayName 'CP test runner (one-shot)' | Out-Null
    Log 'rebooting (Harden asks for a reboot)'
    Restart-Computer -Force
    exit
}

if ($phase -eq 'phase2') {
    Wait-Ready
    Save-Services 'after-reboot'
    Snap 'after-reboot'
    Run-Script 'audit-after' 'Audit.ps1' '-Quick' 25
    $r = Get-ChildItem $sysDesk -Filter 'CP-Audit-*.txt' | Sort-Object LastWriteTime | Select-Object -Last 1
    if ($r) { Move-Item $r.FullName "$out\audit-after.txt" -Force }
    Snap 'final'
    Set-Content -Path $state -Value 'done'
    Log 'ALL DONE - powering off'
    Stop-Computer -Force
}

# Guest side of the practice-image test. Started as SYSTEM at every boot by a
# service that inject.py adds offline (CPTestRunner). It is a step machine:
# C:\cptest\state.txt holds the next step, so the run resumes after the
# planned reboot and after crashes (some images blue-screen on a timer).
# The hook is removed in the last step. Audit will list CPTestRunner while the
# test runs; that one entry is ours.
#
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

$os = Get-CimInstance Win32_OperatingSystem
Log "=== boot at $($os.LastBootUpTime) | $($os.Caption) build $($os.BuildNumber) type $($os.ProductType) | as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) | COM1 $(if ($port) {'ok'} else {'missing'})"
$bugcheck = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting' } -MaxEvents 3 -ErrorAction SilentlyContinue
foreach ($b in $bugcheck) { Log "  earlier BLUE SCREEN: $($b.TimeCreated) $($b.Message -replace '\s+', ' ' | Select-Object -First 1)" }

$sysDesk = [Environment]::GetFolderPath('Desktop')
if (-not $sysDesk -or -not (Test-Path $sysDesk)) { $sysDesk = Join-Path $env:PUBLIC 'Desktop' }   # same fallback the scripts use as SYSTEM
$empty = Join-Path $base 'empty.txt'
if (-not (Test-Path $empty)) { Set-Content -Path $empty -Value '' }

# In a real round the README user is logged in, so their registry hive (HKCU) is loaded and both the
# scoring engine and Audit can see per-user settings. Nobody logs in here, so load that hive by hand.
$script:hiveSid = $null
function Mount-UserHive {
    $u = if (Test-Path "$base\mainuser.txt") { (Get-Content "$base\mainuser.txt" -Raw).Trim() } else { '' }
    if (-not $u) { Log 'main user unknown - per-user registry not loaded'; return }
    $prof = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
        ForEach-Object { [pscustomobject]@{ Sid = $_.PSChildName; Path = [string]$_.GetValue('ProfileImagePath') } } |
        Where-Object { $_.Path -and (Split-Path $_.Path -Leaf) -match ('^' + [regex]::Escape($u) + '(\..*)?$') } | Select-Object -First 1
    if (-not $prof) { Log "no profile folder for '$u' - per-user registry not loaded"; return }
    if (Test-Path "Registry::HKEY_USERS\$($prof.Sid)") { Log "registry hive of $u already loaded"; return }
    $r = & reg.exe load "HKU\$($prof.Sid)" "$($prof.Path)\NTUSER.DAT" 2>&1
    Log "loaded registry hive of $u ($($prof.Sid)) from $($prof.Path): exit $LASTEXITCODE $r"
    if ($LASTEXITCODE -eq 0) { $script:hiveSid = $prof.Sid }
}
function Dismount-UserHive {
    if (-not $script:hiveSid) { return }
    [gc]::Collect(); [gc]::WaitForPendingFinalizers(); Start-Sleep 2
    $r = & reg.exe unload "HKU\$script:hiveSid" 2>&1
    Log "unloaded user hive: exit $LASTEXITCODE $r"
}

# QEMU gives the VM a new network adapter, so a static IP the image had (servers and DCs) stays on the old,
# now-missing adapter and services like DNS or a website look "down" to the scoring engine. Copy it over.
function Restore-StaticIP {
    $cur = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    if (-not $cur) { $cur = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $cur) { Log 'network: no adapter'; return }
    $manual = @(Get-NetIPAddress -InterfaceIndex $cur.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -eq 'Manual' })
    if ($manual.Count) { Log "network: $($cur.Name) already has static $($manual[0].IPAddress)"; return }
    foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction SilentlyContinue) {
        if ($k.PSChildName -ieq $cur.InterfaceGuid) { continue }
        $ip = @($k.GetValue('IPAddress')) | Where-Object { $_ -and $_ -ne '0.0.0.0' } | Select-Object -First 1
        if ($k.GetValue('EnableDHCP') -ne 0 -or -not $ip) { continue }
        $mask = @($k.GetValue('SubnetMask'))[0]
        $prefix = (($mask -split '\.') | ForEach-Object { [Convert]::ToString([int]$_, 2) } | ForEach-Object { ($_ -replace '0', '').Length } | Measure-Object -Sum).Sum
        $gw = @($k.GetValue('DefaultGateway')) | Where-Object { $_ } | Select-Object -First 1
        $dns = @(([string]$k.GetValue('NameServer')) -split '[, ]+' | Where-Object { $_ })
        try {
            Set-NetIPInterface -InterfaceIndex $cur.ifIndex -Dhcp Disabled -ErrorAction Stop
            Get-NetIPAddress -InterfaceIndex $cur.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            Remove-NetRoute -InterfaceIndex $cur.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
            $a = @{ InterfaceIndex = $cur.ifIndex; IPAddress = $ip; PrefixLength = $prefix; ErrorAction = 'Stop' }
            if ($gw) { $a.DefaultGateway = $gw }
            New-NetIPAddress @a | Out-Null
            if ($dns.Count) { Set-DnsClientServerAddress -InterfaceIndex $cur.ifIndex -ServerAddresses $dns -ErrorAction Stop }
            Log "network: copied the image's static IP $ip/$prefix gw $gw dns $($dns -join ',') to $($cur.Name)"
        } catch { Log "network: could not copy static IP $ip ($($_.Exception.Message))" }
        return
    }
    Log "network: image had no static IPv4 address; keeping DHCP on $($cur.Name)"
}

function Save-ScmErrors([string]$tag) {
    # In a job with a time limit: with the Event Log service broken, reading the log must not stall the run.
    $j = Start-Job -ArgumentList $os.LastBootUpTime -ScriptBlock { param($since) Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Level = 2; StartTime = $since } -ErrorAction SilentlyContinue }
    $ev = @()
    if (Wait-Job $j -Timeout 90) { $ev = @(Receive-Job $j) } else { Log 'reading the System log timed out (Event Log service broken?)' }
    Remove-Job $j -Force -ErrorAction SilentlyContinue
    $ev | ForEach-Object { '{0:HH:mm:ss} {1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') } | Set-Content "$out\scm-errors-$tag.txt"
    Log "service start errors since boot: $(@($ev).Count)"
    $ev | Where-Object { $_.Message -match '(?i)firewall|defender|mpssvc|bfe' } | Select-Object -First 3 | ForEach-Object { Log ("  SCM {0}: {1}" -f $_.Id, ($_.Message -replace '\s+', ' ')) }
}

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
    Log 'waiting 4 min so the scoring engine finishes a pass after boot'
    Start-Sleep 240      # let the scoring engine finish a pass after boot
}

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
                $t -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '(?i)points|out of|penalt|issues' } |
                    Select-Object -First 4 | ForEach-Object { Log "  [$tag] $_" }
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
    # Same executable as this process: cptest-powershell.exe when the image hijacks powershell.exe with an IFEO debugger
    $p = Start-Process -FilePath ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) `
        -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $enc" `
        -RedirectStandardOutput "$out\$tag.console.txt" -RedirectStandardError "$out\$tag.err.txt" `
        -RedirectStandardInput $empty -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit($minutes * 60000)) {
        Log "$tag TIMED OUT after $minutes min - killing"
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    Log ('{0} finished in {1:n1} min, exit code {2}' -f $tag, ((Get-Date) - $t0).TotalMinutes, $p.ExitCode)
    # Child PowerShell writes its streams to stderr as CLIXML; keep only the real errors.
    $raw = Get-Content "$out\$tag.err.txt" -Raw -ErrorAction SilentlyContinue
    if ($raw -and $raw.StartsWith('#< CLIXML')) {
        $errs = [regex]::Matches($raw, '<S S="Error">(.*?)</S>') | ForEach-Object { $_.Groups[1].Value -replace '_x000D_', '' -replace '_x000A_', ' ' }
        Set-Content "$out\$tag.err.txt" ($errs -join "`r`n")
    }
    Get-Content "$out\$tag.err.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match '\S' } | Select-Object -First 3 | ForEach-Object { Log "  stderr: $_" }
    Select-String -Path "$out\$tag.console.txt" -Pattern 'DONE:|README:' -ErrorAction SilentlyContinue | Select-Object -Last 2 | ForEach-Object { Log "  $($_.Line.Trim())" }
}

function Save-Audit([string]$name) {
    $r = Get-ChildItem $sysDesk, "$env:PUBLIC\Desktop", "$env:SystemRoot\System32" -Filter 'CP-Audit-*.txt' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
    if ($r) { Move-Item $r.FullName "$out\$name.txt" -Force; Log "saved $name.txt" }
    else { Copy-Item "$out\$name.console.txt" "$out\$name.txt" -ErrorAction SilentlyContinue; Log "report file not found - using the console output as $name.txt" }
}

function Save-Services([string]$tag) {
    Get-Service | Sort-Object Name | Select-Object Name, Status, StartType, DisplayName |
        Format-Table -AutoSize | Out-String -Width 200 | Set-Content "$out\services-$tag.txt"
}

$steps = @(
    @{ n = 'snap-boot';     a = { Save-Services 'boot'; Snap 'boot' } }
    @{ n = 'audit-before';  a = { Run-Script 'audit-before' 'Audit.ps1' '' 35; Save-Audit 'audit-before' } }
    @{ n = 'users-dryrun';  a = { if (Test-Path "$base\users.txt") { Run-Script 'users-dryrun' 'Users.ps1' "-ListFile '$base\users.txt'" 10 } else { Log 'no README user list - Users.ps1 dry run skipped' } } }
    @{ n = 'snap-audit';    a = { Start-Sleep 90; Snap 'after-audit' } }        # Audit is read-only; score must not move
    @{ n = 'harden';        a = { Run-Script 'harden' 'Harden.ps1' '' 30; Save-Services 'after-harden' } }
    @{ n = 'snap-harden';   a = { Start-Sleep 300; Snap 'after-harden' } }
    @{ n = 'reboot';        a = { Log 'rebooting (Harden asks for a reboot)'; $script:rebooting = $true } }
    @{ n = 'snap-reboot';   a = { Save-Services 'after-reboot'; Snap 'after-reboot' } }
    @{ n = 'audit-after';   a = { Run-Script 'audit-after' 'Audit.ps1' '-Quick' 25; Save-Audit 'audit-after' } }
    @{ n = 'finish';        a = { Snap 'final'; & sc.exe delete CPTestRunner | Out-Null; Log "boot hook removed: $(-not (Get-Service CPTestRunner -ErrorAction SilentlyContinue))"; $script:finished = $true } }
)

# state: "<next step index> <attempts at that step>"
$idx = 0; $tries = 0
if (Test-Path $state) { $p = (Get-Content $state -Raw).Trim() -split '\s+'; $idx = [int]$p[0]; $tries = [int]$p[1] }
if ($idx -ge $steps.Count) { Log 'state says finished; removing hook'; & sc.exe delete CPTestRunner | Out-Null; Stop-Computer -Force; exit }
if ($tries -ge 2) { Log "step $($steps[$idx].n) was interrupted twice - skipping it"; $idx++; $tries = 0 }
if ($idx -gt 0 -and $tries -gt 0) { Log "resuming: step $($steps[$idx].n) was interrupted (crash or reboot), retrying" }

Mount-UserHive
Restore-StaticIP
Wait-Ready
Save-ScmErrors ("boot{0:HHmm}" -f $os.LastBootUpTime)
$script:rebooting = $false; $script:finished = $false
while ($idx -lt $steps.Count) {
    $s = $steps[$idx]
    Set-Content -Path $state -Value "$idx $($tries + 1)"
    Log "--- step $($idx + 1)/$($steps.Count): $($s.n)"
    & $s.a
    $idx++; $tries = 0
    Set-Content -Path $state -Value "$idx 0"
    if ($script:rebooting) { Dismount-UserHive; & shutdown.exe /a 2>$null; Restart-Computer -Force; exit }   # /a: cancel a countdown a planted task started (Among the Reindeer)
}
Dismount-UserHive
Log 'ALL DONE - powering off'
Stop-Computer -Force

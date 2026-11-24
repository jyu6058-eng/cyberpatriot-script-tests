<#
.SYNOPSIS
  Compare the machine's users and admins with the README. Dry run by default.

.DESCRIPTION
  1. Make a text file (for example users.txt) and paste the README lists in it.
     The README's own headers work as-is ("Authorized Administrators:" and
     "Authorized Users:"), or use [admins] / [users]:

        [admins]
        jsmith (you)
        password: Hunter2!      <- lines starting with "password" are ignored
        mlee
        [users]
        akim
        bwong

  2. Run:   .\Users.ps1 -ListFile .\users.txt
     It prints: unauthorized users, missing users, people who are admins but
     should not be, authorized admins who are not admins, disabled authorized users.

  3. Run:   .\Users.ps1 -ListFile .\users.txt -Apply
     Same report, but it asks y/N before EACH change (delete user, remove from
     admin groups, add to Administrators, create a missing user, enable a user).

  Optional: -ResetPasswords  gives every authorized user except you a new random
  password and saves the list to a file on your Desktop (so nobody is locked out).

  Works on workstations/member servers (local accounts) and on domain
  controllers (AD accounts; admin = Administrators / Domain Admins /
  Enterprise Admins / Schema Admins). Never touches you, krbtgt, the built-in
  Administrator, Guest, DefaultAccount or WDAGUtilityAccount.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ListFile,
    [switch]$Apply,
    [switch]$ResetPasswords
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an ELEVATED PowerShell.' -ForegroundColor Red; exit 1 }
if (-not (Test-Path $ListFile)) { Write-Host "List file not found: $ListFile" -ForegroundColor Red; exit 1 }

$isDC  = ([int](Get-CimInstance Win32_OperatingSystem).ProductType -eq 2)
$me    = $env:USERNAME
$meSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# ---------------------------------------------------------------- parse README list
$admins = New-Object System.Collections.Generic.List[string]
$users  = New-Object System.Collections.Generic.List[string]
$mode = ''
$listText = Get-Content $ListFile -Raw
foreach ($raw in Get-Content $ListFile) {
    $line = $raw.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }
    # Headers: [admins] / [users], or the README's own "Authorized Administrators:" / "Authorized Users:" lines.
    # The section title "Authorized Administrators and Users" is not a header.
    if ($line -match '^(?i)(\[(admins?|administrators?)\]|authorized\s+admin(istrator)?s?\s*:?)$') { $mode = 'admins'; continue }
    if ($line -match '^(?i)(\[users?\]|authorized\s+users?\s*:?)$') { $mode = 'users'; continue }
    if ($line -match '^(?i)authorized\s+admin') { continue }
    if ($line -match '^(?i)password') { continue }
    # READMEs put notes in the list: "saturnalorbit (Hey, that's not...", "(I had to change it again - Ian)".
    # Keep the name before any comment; skip lines that cannot be an account name.
    $name = ($line -replace '\(you\)', '').Trim()
    if ($name -match '^[\(\[]') { continue }
    $name = ($name -split '\s*[\(\[]', 2)[0].Trim()
    if (-not $name) { continue }
    if ($name -match '["/\\\[\]:;|=,+*?<>]' -or ($name -split '\s+').Count -gt 3) {
        Write-Host "Line '$line' does not look like an account name - ignored" -ForegroundColor Yellow; continue
    }
    if ($mode -eq 'admins') { $admins.Add($name) } elseif ($mode -eq 'users') { $users.Add($name) }
    else { Write-Host "Line '$line' is above any [admins]/[users] header - ignored" -ForegroundColor Yellow }
}
$authorized = @($admins) + @($users)
Write-Host "README: $($admins.Count) admins, $($users.Count) standard users" -ForegroundColor Cyan
if ($admins.Count -eq 0) { Write-Host 'No [admins] section found - stopping so nobody gets demoted by mistake.' -ForegroundColor Red; exit 1 }

function In-List([string]$n, $list) { return @($list | Where-Object { $_ -ieq $n }).Count -gt 0 }
# Safety net: an account named anywhere in the README text is never offered for deletion, even if parsing missed it.
# A README name that is missing, and an extra account that shares a name part with it (stanley.stevenson vs
# mr.stevenson), may be one person renamed. Report both and let a human decide instead of delete + create.
function Get-LookAlike([string]$acct, [string]$display, $missing) {
    foreach ($n in $missing) {
        foreach ($t in @($n -split '[._\- ]' | Where-Object { $_.Length -ge 4 })) {
            if ($acct -match [regex]::Escape($t) -or $display -match [regex]::Escape($t)) { return $n }
        }
    }
    return $null
}
function In-ReadmeText([string]$n) { return $listText -match ('(?im)(^|[\s,])' + [regex]::Escape($n) + '($|[\s,(\[])') }
function Ask([string]$q) {
    if (-not $Apply) { return $false }
    $a = Read-Host "$q [y/N]"
    return ($a -match '^(y|yes)$')
}
function New-StrongPassword {
    $up = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $lo = 'abcdefghijkmnopqrstuvwxyz'; $di = '23456789'; $sy = '!#%+=?@'
    $all = $up + $lo + $di + $sy
    $chars = @($up[(Get-Random -Maximum $up.Length)], $lo[(Get-Random -Maximum $lo.Length)], $di[(Get-Random -Maximum $di.Length)], $sy[(Get-Random -Maximum $sy.Length)])
    $chars += 1..12 | ForEach-Object { $all[(Get-Random -Maximum $all.Length)] }
    return -join ($chars | Sort-Object { Get-Random })
}
$skipRid = '-(500|501|502|503|504)$'   # Administrator, Guest, krbtgt, DefaultAccount, WDAGUtilityAccount
$changes = 0
$deleted = New-Object 'System.Collections.Generic.HashSet[string]'   # SIDs deleted in this run
$created = New-Object 'System.Collections.Generic.List[string]'      # names created in this run
$listFailed = $false
$deskDir = [Environment]::GetFolderPath('Desktop')
if (-not $deskDir -or -not (Test-Path $deskDir)) { $deskDir = Join-Path $env:PUBLIC 'Desktop' }   # e.g. running as SYSTEM
$pwFile = Join-Path $deskDir ("CP-new-passwords-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

if (-not $isDC) {
    # ============================================================ LOCAL ACCOUNTS
    $local = Get-LocalUser
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $adminMembers = @()
    try { $adminMembers = Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop }
    catch { Write-Host 'Get-LocalGroupMember failed (orphaned SID in Administrators?). Check with: net localgroup Administrators' -ForegroundColor Yellow }

    Write-Host "`n--- Users on this machine that are NOT in the README" -ForegroundColor Cyan
    $missingNames = @($authorized | Where-Object { $n = $_; -not ($local | Where-Object { $_.Name -ieq $n }) })
    foreach ($u in $local) {
        if ($u.SID.Value -match $skipRid -or $u.SID.Value -eq $meSid) { continue }
        if (-not (In-List $u.Name $authorized)) {
            $la = Get-LookAlike $u.Name $u.FullName $missingNames
            if ($la) { Write-Host "[?] $($u.Name) may be README user '$la' under another name - check before deleting or creating anyone" -ForegroundColor Yellow; continue }
            if (In-ReadmeText $u.Name) { Write-Host "[?] $($u.Name) is not in the parsed lists but its name is in the README text - check by hand (not offered for deletion)" -ForegroundColor Yellow; continue }
            Write-Host "[!] $($u.Name)  (enabled: $($u.Enabled))" -ForegroundColor Red
            if (Ask "    Delete local user '$($u.Name)'?") { Remove-LocalUser -SID $u.SID; [void]$deleted.Add($u.SID.Value); Write-Host '    deleted' -ForegroundColor Green; $changes++ }
        }
    }

    Write-Host "`n--- README users missing from this machine" -ForegroundColor Cyan
    foreach ($n in $authorized) {
        if (-not ($local | Where-Object { $_.Name -ieq $n })) {
            $twin = $local | Where-Object { -not (In-List $_.Name $authorized) -and (Get-LookAlike $_.Name $_.FullName @($n)) } | Select-Object -First 1
            if ($twin) { Write-Host "[?] $n does not exist, but '$($twin.Name)' looks like the same person - decide by hand" -ForegroundColor Yellow; continue }
            Write-Host "[?] $n does not exist (README sometimes asks you to create users)" -ForegroundColor Yellow
            if (Ask "    Create '$n' with a random password (saved to Desktop)?") {
                $pw = New-StrongPassword
                New-LocalUser -Name $n -Password (ConvertTo-SecureString $pw -AsPlainText -Force) | Out-Null
                net user "$n" /passwordreq:yes | Out-Null   # New-LocalUser leaves 'password not required' set
                Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $n -ErrorAction SilentlyContinue   # usually already a member
                "$n`t$pw" | Out-File $pwFile -Append -Encoding UTF8
                $created.Add($n)
                Write-Host '    created' -ForegroundColor Green; $changes++
            }
        }
    }

    Write-Host "`n--- Administrators group" -ForegroundColor Cyan
    foreach ($m in $adminMembers) {
        $short = ($m.Name -split '\\')[-1]
        if ($m.SID.Value -match '-500$' -or $m.SID.Value -eq $meSid -or $deleted.Contains($m.SID.Value)) { continue }
        if ($m.PrincipalSource -ne 'Local' -and $m.ObjectClass -eq 'Group') { Write-Host "    group $($m.Name) is in Administrators (domain group - check it)" -ForegroundColor Yellow; continue }
        if (-not (In-List $short $admins)) {
            Write-Host "[!] $($m.Name) is an administrator but not a README admin" -ForegroundColor Red
            if (Ask "    Remove '$($m.Name)' from Administrators?") {
                Remove-LocalGroupMember -Group $adminGroup -Member $m
                if ((In-List $short $users) -and -not (Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.SID -eq $m.SID })) { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $m.SID }
                Write-Host '    removed' -ForegroundColor Green; $changes++
            }
        }
    }
    foreach ($n in $admins) {
        $acct = $local | Where-Object { $_.Name -ieq $n }
        if ($acct -and -not ($adminMembers | Where-Object { $_.SID -eq $acct.SID })) {
            Write-Host "[!] README admin '$n' is not in Administrators" -ForegroundColor Red
            if (Ask "    Add '$n' to Administrators?") { Add-LocalGroupMember -Group $adminGroup -Member $acct; Write-Host '    added' -ForegroundColor Green; $changes++ }
        }
    }

    Write-Host "`n--- Authorized users that are disabled" -ForegroundColor Cyan
    foreach ($u in $local | Where-Object { -not $_.Enabled -and $_.SID.Value -notmatch $skipRid }) {
        if (In-List $u.Name $authorized) {
            Write-Host "[?] $($u.Name) is disabled" -ForegroundColor Yellow
            if (Ask "    Enable '$($u.Name)'?") { Enable-LocalUser -SID $u.SID; Write-Host '    enabled' -ForegroundColor Green; $changes++ }
        }
    }

    Write-Host "`n--- Other groups that grant power (review by hand)" -ForegroundColor Cyan
    foreach ($g in 'S-1-5-32-555','S-1-5-32-551','S-1-5-32-580','S-1-5-32-578','S-1-5-32-556','S-1-5-32-547') {
        $grp = Get-LocalGroup -SID $g -ErrorAction SilentlyContinue
        if (-not $grp) { continue }
        $mem = Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue
        if ($mem) { Write-Host ("    {0,-32} {1}" -f $grp.Name, (($mem.Name) -join ', ')) -ForegroundColor Yellow }
    }

    if ($ResetPasswords) {
        Write-Host "`n--- Reset passwords" -ForegroundColor Cyan
        if (Ask "Give every authorized user except '$me' a new random password (saved to $pwFile)?") {
            foreach ($u in Get-LocalUser | Where-Object { $_.SID.Value -notmatch $skipRid -and $_.SID.Value -ne $meSid -and (In-List $_.Name $authorized) -and -not (In-List $_.Name $created) }) {
                $pw = New-StrongPassword
                Set-LocalUser -SID $u.SID -Password (ConvertTo-SecureString $pw -AsPlainText -Force)
                "$($u.Name)`t$pw" | Out-File $pwFile -Append -Encoding UTF8
                Write-Host "    $($u.Name) changed" -ForegroundColor Green; $changes++
            }
        } elseif (-not $Apply) { Write-Host '    (add -Apply to actually reset)' -ForegroundColor Yellow }
    }
}
else {
    # ============================================================ ACTIVE DIRECTORY
    Import-Module ActiveDirectory
    $adUsers = Get-ADUser -Filter * -Properties Enabled
    $adminGroups = 'Administrators','Domain Admins','Enterprise Admins','Schema Admins'

    Write-Host "`n--- AD users NOT in the README" -ForegroundColor Cyan
    $missingNames = @($authorized | Where-Object { $n = $_; -not ($adUsers | Where-Object { $_.SamAccountName -ieq $n }) })
    foreach ($u in $adUsers) {
        if ($u.SID.Value -match $skipRid -or $u.SID.Value -eq $meSid -or $u.SamAccountName -ieq $me) { continue }
        if (-not (In-List $u.SamAccountName $authorized)) {
            $la = Get-LookAlike $u.SamAccountName $u.Name $missingNames
            if ($la) { Write-Host "[?] $($u.SamAccountName) ($($u.Name)) may be README user '$la' under another logon name - check before deleting or creating anyone" -ForegroundColor Yellow; continue }
            if (In-ReadmeText $u.SamAccountName) { Write-Host "[?] $($u.SamAccountName) is not in the parsed lists but its name is in the README text - check by hand (not offered for deletion)" -ForegroundColor Yellow; continue }
            if ($u.SamAccountName.EndsWith('$')) { Write-Host "[?] $($u.SamAccountName) ends in `$ - a trust account or a user disguised as one. Check in dsa.msc (Advanced Features) before deleting." -ForegroundColor Yellow; continue }
            Write-Host "[!] $($u.SamAccountName)  ($($u.Name), enabled: $($u.Enabled))" -ForegroundColor Red
            if (Ask "    Delete AD user '$($u.SamAccountName)'?") { Remove-ADUser -Identity $u -Confirm:$false; [void]$deleted.Add($u.SID.Value); Write-Host '    deleted' -ForegroundColor Green; $changes++ }
        }
    }

    Write-Host "`n--- README users missing from AD" -ForegroundColor Cyan
    foreach ($n in $authorized) {
        if (-not ($adUsers | Where-Object { $_.SamAccountName -ieq $n })) {
            $twin = $adUsers | Where-Object { -not (In-List $_.SamAccountName $authorized) -and (Get-LookAlike $_.SamAccountName $_.Name @($n)) } | Select-Object -First 1
            if ($twin) { Write-Host "[?] $n does not exist in AD, but '$($twin.SamAccountName)' ($($twin.Name)) looks like the same person - decide by hand" -ForegroundColor Yellow; continue }
            Write-Host "[?] $n does not exist in AD" -ForegroundColor Yellow
            if (Ask "    Create AD user '$n' with a random password (saved to Desktop)?") {
                $pw = New-StrongPassword
                New-ADUser -Name $n -SamAccountName $n -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true
                "$n`t$pw" | Out-File $pwFile -Append -Encoding UTF8
                $created.Add($n)
                Write-Host '    created' -ForegroundColor Green; $changes++
            }
        }
    }

    Write-Host "`n--- Admin group membership" -ForegroundColor Cyan
    foreach ($gName in $adminGroups) {
        $members = @()
        try { $members = Get-ADGroupMember -Identity $gName -ErrorAction Stop }
        catch { $listFailed = $true; Write-Host "    could not list $gName ($($_.Exception.Message)) - check it in dsa.msc" -ForegroundColor Yellow; continue }
        foreach ($m in $members) {
            if ($m.objectClass -eq 'group') { Write-Host "    $gName contains GROUP '$($m.SamAccountName)' - check who is inside it" -ForegroundColor Yellow; continue }
            if ($m.objectClass -ne 'user') { Write-Host "    $gName contains $($m.objectClass) '$($m.Name)'" -ForegroundColor Yellow; continue }
            if ($m.SID.Value -match '-500$' -or $m.SID.Value -eq $meSid -or $m.SamAccountName -ieq $me -or $deleted.Contains($m.SID.Value)) { continue }
            if (-not (In-List $m.SamAccountName $admins)) {
                Write-Host "[!] $($m.SamAccountName) is in $gName but is not a README admin" -ForegroundColor Red
                if (Ask "    Remove '$($m.SamAccountName)' from ${gName}?") { Remove-ADGroupMember -Identity $gName -Members $m -Confirm:$false; Write-Host '    removed' -ForegroundColor Green; $changes++ }
            }
        }
    }
    $da = @(); try { $da = Get-ADGroupMember 'Domain Admins' -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName } catch { $listFailed = $true }
    $ba = @(); try { $ba = Get-ADGroupMember 'Administrators' -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName } catch { $listFailed = $true }
    if ($listFailed) { Write-Host '    Skipping the "missing admin" check because a group could not be read. Check Domain Admins in dsa.msc.' -ForegroundColor Yellow }
    foreach ($n in $(if ($listFailed) { @() } else { $admins })) {
        if ($n -ieq $me) { continue }
        if (($adUsers | Where-Object { $_.SamAccountName -ieq $n }) -and -not (In-List $n (@($da) + @($ba)))) {
            Write-Host "[!] README admin '$n' is not in Domain Admins or Administrators" -ForegroundColor Red
            if (Ask "    Add '$n' to Domain Admins?") { Add-ADGroupMember -Identity 'Domain Admins' -Members $n; $changes++ }
        }
    }

    Write-Host "`n--- Authorized users that are disabled" -ForegroundColor Cyan
    $disAuth = @($adUsers | Where-Object { -not $_.Enabled -and $_.SID.Value -notmatch $skipRid -and (In-List $_.SamAccountName $authorized) })
    if ($authorized.Count -gt 3 -and $disAuth.Count -gt $authorized.Count / 2) {
        Write-Host "    $($disAuth.Count) of $($authorized.Count) README users are disabled. That is usually how the image was built (accounts made without passwords), not a vulnerability. Enable only the ones the README says must work." -ForegroundColor Yellow
    }
    foreach ($u in $adUsers | Where-Object { -not $_.Enabled -and $_.SID.Value -notmatch $skipRid }) {
        if (In-List $u.SamAccountName $authorized) {
            Write-Host "[?] $($u.SamAccountName) is disabled" -ForegroundColor Yellow
            if (Ask "    Enable '$($u.SamAccountName)'?") { Enable-ADAccount -Identity $u; Write-Host '    enabled' -ForegroundColor Green; $changes++ }
        }
    }

    Write-Host "`n--- Other powerful AD groups (review by hand)" -ForegroundColor Cyan
    foreach ($g in 'Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Remote Desktop Users','Remote Management Users') {
        $mem = $null; try { $mem = Get-ADGroupMember $g -ErrorAction Stop } catch {}
        if ($mem) { Write-Host ("    {0,-30} {1}" -f $g, (($mem.SamAccountName) -join ', ')) -ForegroundColor Yellow }
    }

    if ($ResetPasswords) {
        Write-Host "`n--- Reset passwords" -ForegroundColor Cyan
        if (Ask "Give every authorized AD user except '$me' a new random password (saved to $pwFile)?") {
            foreach ($u in $adUsers | Where-Object { $_.SID.Value -notmatch $skipRid -and $_.SamAccountName -ine $me -and (In-List $_.SamAccountName $authorized) -and -not (In-List $_.SamAccountName $created) }) {
                $pw = New-StrongPassword
                Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
                "$($u.SamAccountName)`t$pw" | Out-File $pwFile -Append -Encoding UTF8
                Write-Host "    $($u.SamAccountName) changed" -ForegroundColor Green; $changes++
            }
        } elseif (-not $Apply) { Write-Host '    (add -Apply to actually reset)' -ForegroundColor Yellow }
    }
}

Write-Host ''
if ($Apply) { Write-Host "$changes change(s) made. Check the score report." -ForegroundColor Cyan }
else { Write-Host 'Dry run: nothing changed. Re-run with -Apply to fix items one by one.' -ForegroundColor Cyan }
if (Test-Path $pwFile) { Write-Host "New passwords saved in $pwFile (delete this file before the round ends if the README treats it as sensitive)." -ForegroundColor Yellow }

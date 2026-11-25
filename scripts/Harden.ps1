<#
.SYNOPSIS
  CyberPatriot Windows HARDEN script: account policy, audit policy, security
  options, firewall, Defender, SMB, RDP security, updates, risky features.

.DESCRIPTION
  Designed around one rule: never break something the README might need.
  So this script does NOT:
    - stop or disable any service (that is a README decision - use Audit.ps1)
    - delete users, change passwords or remove group members (use Users.ps1)
    - turn Remote Desktop on or off (it only secures RDP if RDP is already on)
    - block ports or import a firewall rule set (it only turns the firewall on)
    - remove Defender exclusions (practice images may need one for the scorer)
    - touch SMBv2/v3 (disabling the SMB client has been a 5-point penalty)

  Before changing anything it saves a backup folder on the Desktop with your
  old security policy, audit policy, firewall and the registry keys it edits.

.USAGE
  Elevated PowerShell:
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Harden.ps1 -DryRun      # show what would change, change nothing
    .\Harden.ps1              # apply
  Optional switches:
    -SkipFeatures   do not disable SMB1 / PowerShell 2.0 / Telnet / TFTP
    -SkipUserFlags  do not touch per-user flags (password expiry, etc.)
    -ExploitProtection  also turn on system DEP (OptOut), CFG, SEHOP and ASLR.
                    Test first: very old README apps can crash with these on.

  Do the Forensics Questions first. Snapshot the VM first when practicing.
  Reboot when it finishes (LSA protection and feature removal need it).
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SkipFeatures,
    [switch]$SkipUserFlags,
    [switch]$ExploitProtection
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an ELEVATED PowerShell (Run as administrator).' -ForegroundColor Red; exit 1 }

$productType = [int](Get-CimInstance Win32_OperatingSystem).ProductType   # 1 workstation, 2 DC, 3 server
$isDC        = ($productType -eq 2)
$meSid       = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$meName      = $env:USERNAME
$engineUserRx = '^(?i)(magistrate|aeacus|cyberpatriot|ccsclient)$'   # accounts a scoring engine runs as (Mushroom Kingdom: AD user MAGISTRATE)
$stamp       = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop     = [Environment]::GetFolderPath('Desktop')
if (-not $desktop -or -not (Test-Path $desktop)) { $desktop = Join-Path $env:PUBLIC 'Desktop' }   # e.g. running as SYSTEM
$backup      = Join-Path $desktop "CP-Backup-$stamp"
$log         = New-Object System.Collections.Generic.List[string]

function Say([string]$t, [string]$c = 'Gray') { Write-Host $t -ForegroundColor $c; $log.Add($t) }
function Step([string]$t) { Say ''; Say "== $t" 'Cyan' }

$script:Desired = @{}   # HKLM values Harden wants; on a DC, domain GPOs that set them differently are fixed too
function Set-Reg([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
    if ($Path -like 'HKLM:\*') { $script:Desired[(($Path -replace '^HKLM:\\', 'MACHINE\') + '\' + $Name).ToLower()] = @($Value, $Type, "$Path\$Name") }
    $old = $null
    $k = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($k) { $old = $k.GetValue($Name, $null) }
    if ($null -ne $old -and [string]$old -eq [string]$Value) { return }
    $show = { param($x) if ($null -eq $x) { '(not set)' } elseif ($x -is [array]) { if ($x.Count) { '(' + ($x -join ', ') + ')' } else { '(empty)' } } else { $x } }
    $msg = "{0}\{1}: {2} -> {3}" -f $Path, $Name, (& $show $old), (& $show $Value)
    if ($DryRun) { Say "  would set $msg" 'Yellow'; return }
    if (-not $k) { New-Item -Path $Path -Force | Out-Null }   # only when the key is missing (New-Item -Force on an existing key wipes it)
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Say "  set $msg" 'Green'
}
function Remove-RegValue([string]$Path, [string]$Name) {
    $k = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $k -or $null -eq $k.GetValue($Name, $null)) { return }
    if ($DryRun) { Say "  would remove $Path\$Name (currently $($k.GetValue($Name)))" 'Yellow'; return }
    Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
    Say "  removed $Path\$Name" 'Green'
}
function Run([string]$what, [scriptblock]$action) {
    if ($DryRun) { Say "  would $what" 'Yellow'; return }
    try { & $action; Say "  $what" 'Green' } catch { Say "  FAILED: $what - $($_.Exception.Message)" 'Red' }
}

Say "CyberPatriot Harden.ps1  $(if ($DryRun) {'(DRY RUN - nothing will change)'})" 'Cyan'
Say "Role: $(switch ($productType) { 1 {'Workstation'} 2 {'Domain Controller'} 3 {'Server'} })   User: $meName"

# ------------------------------------------------------------------ 0. backup
Step 'Backup current settings'
if (-not $DryRun) {
    New-Item -ItemType Directory -Path $backup -Force | Out-Null
    secedit /export /cfg "$backup\secpol-before.inf" /quiet | Out-Null
    auditpol /backup /file:"$backup\auditpol-before.csv" | Out-Null
    netsh advfirewall export "$backup\firewall-before.wfw" | Out-Null
    $keys = @{
        'lsa'          = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
        'lanmanserver' = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        'lanmanwks'    = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        'policies-sys' = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
        'policies'     = 'HKLM\SOFTWARE\Policies'
        'terminal'     = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
    }
    foreach ($n in $keys.Keys) { reg export $keys[$n] "$backup\$n.reg" /y | Out-Null }
    Say "  saved to $backup" 'Green'
    Say '  To undo security policy: secedit /configure /db undo.sdb /cfg "<backup>\secpol-before.inf"' 'DarkGray'
    Say '  To undo audit policy:    auditpol /restore /file:"<backup>\auditpol-before.csv"' 'DarkGray'
    Say '  To undo a registry key:  reg import "<backup>\<name>.reg"' 'DarkGray'
} else { Say '  (skipped in dry run)' 'Yellow' }

# ------------------------------------------------------------------ 1. account policy + user rights
Step 'Account policy (password + lockout) and dangerous user rights'
if ($isDC) {
    # The domain's password/lockout/Kerberos policy comes from the Default Domain Policy GPO: its GptTmpl.inf in SYSVOL.
    # Edit that file, then raise the GPO version in BOTH GPT.INI and the AD object, or the change is never applied.
    $ddp = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
    $want = [ordered]@{
        'System Access'   = [ordered]@{ MinimumPasswordAge = 1; MaximumPasswordAge = 60; MinimumPasswordLength = 14; PasswordComplexity = 1; PasswordHistorySize = 24; ClearTextPassword = 0; LockoutBadCount = 10; ResetLockoutCount = 30; LockoutDuration = 30 }
        'Kerberos Policy' = [ordered]@{ MaxTicketAge = 10; MaxRenewAge = 7; MaxServiceAge = 600; MaxClockSkew = 5; TicketValidateClient = 1 }
    }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domObj = Get-ADDomain -ErrorAction Stop
        $gpoDN  = "CN=$ddp,CN=Policies,CN=System,$($domObj.DistinguishedName)"
        $gpoAD  = Get-ADObject -Identity $gpoDN -Properties versionNumber -ErrorAction Stop
        $sysvol = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction Stop).SysVol
        $gpoDir = Join-Path $sysvol "$($domObj.DNSRoot)\Policies\$ddp"
        $tmpl   = Join-Path $gpoDir 'MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        $gptIni = Join-Path $gpoDir 'GPT.INI'
        if (-not (Test-Path $tmpl)) { throw "not found: $tmpl" }
        $text  = [IO.File]::ReadAllText($tmpl)          # usually UTF-16 with a BOM; ReadAllText detects it
        $lines = New-Object System.Collections.Generic.List[string]
        $text -split "`r?`n" | ForEach-Object { $lines.Add($_) }
        $changed = @()
        foreach ($sec in $want.Keys) {
            $hdr = -1; for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -ieq "[$sec]") { $hdr = $i; break } }
            if ($hdr -lt 0) { $lines.Add("[$sec]"); $hdr = $lines.Count - 1 }
            $end = $lines.Count; for ($i = $hdr + 1; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim().StartsWith('[')) { $end = $i; break } }
            foreach ($k in $want[$sec].Keys) {
                $v = $want[$sec][$k]; $found = $false
                for ($i = $hdr + 1; $i -lt $end; $i++) {
                    if ($lines[$i] -match "^\s*$k\s*=\s*(.*)$") {
                        $found = $true
                        if ($Matches[1].Trim() -ne "$v") { $changed += "$k $($Matches[1].Trim()) -> $v"; $lines[$i] = "$k = $v" }
                        break
                    }
                }
                if (-not $found) { $lines.Insert($end, "$k = $v"); $end++; $changed += "$k (not set) -> $v" }
            }
        }
        if ($changed.Count -eq 0) { Say '  Default Domain Policy already has the recommended password, lockout and Kerberos values' 'Green' }
        elseif ($DryRun) { foreach ($c in $changed) { Say "  would set Default Domain Policy $c" 'Yellow' } }
        else {
            Copy-Item $tmpl (Join-Path $backup 'DefaultDomainPolicy-GptTmpl.inf') -Force
            Copy-Item $gptIni (Join-Path $backup 'DefaultDomainPolicy-GPT.INI') -Force
            [IO.File]::WriteAllText($tmpl, ($lines -join "`r`n"), [Text.Encoding]::Unicode)
            $ini = [IO.File]::ReadAllText($gptIni)
            $fileVer = if ($ini -match '(?im)^\s*Version\s*=\s*(\d+)') { [int]$Matches[1] } else { 0 }
            $newVer = [Math]::Max($fileVer, [int]$gpoAD.versionNumber) + 1      # +1 = computer-side version
            if ($ini -match '(?im)^\s*Version\s*=') { $ini = [regex]::Replace($ini, '(?im)^(\s*Version\s*=\s*)\d+', "`${1}$newVer") } else { $ini = $ini.TrimEnd() + "`r`nVersion=$newVer`r`n" }
            [IO.File]::WriteAllText($gptIni, $ini, [Text.Encoding]::ASCII)
            Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVer } -ErrorAction Stop
            foreach ($c in $changed) { Say "  Default Domain Policy: $c" 'Green' }
            Say "  GPO version $fileVer -> $newVer (GPT.INI and AD). gpupdate /force at the end applies it; check with: net accounts" 'Green'
        }
    } catch {
        Say "  FAILED to edit the Default Domain Policy automatically: $($_.Exception.Message)" 'Red'
        Say '  Do it by hand: gpmc.msc > Default Domain Policy > Edit > Computer Configuration > Policies > Windows Settings >' 'Yellow'
        Say '    Security Settings > Account Policies (Password Policy, Account Lockout Policy, Kerberos Policy), then gpupdate /force' 'Yellow'
    }
    Say '  User Rights on a DC live in GPOs (Default Domain Controllers Policy). The "Domain GPOs" step near the end removes Everyone, Users and single users from the dangerous ones.' 'Yellow'
} else {
    $delegation = ''   # workstations and member servers: nobody
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
LockoutBadCount = 10
LockoutDuration = 30
ResetLockoutCount = 30
EnableGuestAccount = 0
LSAAnonymousNameLookup = 0
[Privilege Rights]
SeTrustedCredManAccessPrivilege =
SeTcbPrivilege =
SeCreateTokenPrivilege =
SeCreatePermanentPrivilege =
SeLockMemoryPrivilege =
SeRelabelPrivilege =
SeEnableDelegationPrivilege = $delegation
SeDebugPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeLoadDriverPrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeSecurityPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
"@
    Say '  Password: min age 1, max age 60, length 14, history 24, complexity on, reversible off'
    Say '  Lockout:  10 attempts, 30 min duration, 30 min reset   (below 5 has been scored as a PENALTY)'
    Say '  Rights:   Act as OS / Credential Manager / Create token / Delegation = nobody; Debug, Take ownership, Load driver = Administrators; Guests denied logon'
    if (-not $DryRun) {
        $infPath = Join-Path $backup 'cp-hardened.inf'
        $dbPath  = Join-Path $backup 'cp-hardened.sdb'
        $inf | Set-Content -Path $infPath -Encoding Unicode
        $out = secedit /configure /db $dbPath /cfg $infPath /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
        if ($LASTEXITCODE -eq 0) { Say '  secedit applied OK' 'Green' } else { Say "  secedit exit code $LASTEXITCODE (check %windir%\security\logs\scesrv.log): $out" 'Red' }
    } else { Say '  would apply the template above with secedit' 'Yellow' }
}

# ------------------------------------------------------------------ 2. audit policy
Step 'Audit policy'
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'String'
Run 'enable Success+Failure auditing on every subcategory (auditpol)' {
    auditpol /set /category:* /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # fallback: the nine audit categories by GUID (works on any language of Windows)
        $cats = '{69979848-797A-11D9-BED3-505054503030},{69979849-797A-11D9-BED3-505054503030},{6997984A-797A-11D9-BED3-505054503030},{6997984B-797A-11D9-BED3-505054503030},{6997984C-797A-11D9-BED3-505054503030},{6997984D-797A-11D9-BED3-505054503030},{6997984E-797A-11D9-BED3-505054503030},{6997984F-797A-11D9-BED3-505054503030},{69979850-797A-11D9-BED3-505054503030}'
        auditpol /set /category:$cats /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol exit $LASTEXITCODE" }
    }
}

# ------------------------------------------------------------------ 3. security options
Step 'Security options (Local Policies > Security Options)'
$L  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$LS = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$LW = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$SY = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-Reg $L 'RestrictAnonymousSAM' 1        # Do not allow anonymous enumeration of SAM accounts
Set-Reg $L 'RestrictAnonymous' 1           # ...of SAM accounts and shares
Set-Reg $L 'EveryoneIncludesAnonymous' 0
Set-Reg $L 'NoLMHash' 1
Set-Reg $L 'LmCompatibilityLevel' 5        # NTLMv2 only, refuse LM & NTLM
Set-Reg $L 'LimitBlankPasswordUse' 1
Set-Reg $L 'DisableDomainCreds' 1          # do not store network credentials
Set-Reg "$L\MSV1_0" 'NTLMMinClientSec' 537395200   # require NTLMv2 session security + 128-bit
Set-Reg "$L\MSV1_0" 'NTLMMinServerSec' 537395200
Set-Reg "$L\MSV1_0" 'allownullsessionfallback' 0
Set-Reg $LS 'RequireSecuritySignature' 1
Set-Reg $LS 'EnableSecuritySignature' 1
Set-Reg $LS 'RestrictNullSessAccess' 1
Set-Reg $LS 'EnableForcedLogOff' 1
Set-Reg $LW 'RequireSecuritySignature' 1
Set-Reg $LW 'EnableSecuritySignature' 1
Set-Reg $LW 'EnablePlainTextPassword' 0
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireSignOrSeal' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SealSecureChannel' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SignSecureChannel' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireStrongKey' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'ClearPageFileAtShutdown' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 0   # SEHOP (CIS MSS)
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'ObCaseInsensitive' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode' 1
Set-Reg $LS 'autodisconnect' 15                # SMB server idle session timeout (minutes)
$psShellKey = 'Registry::HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell'
if ((Get-Item -LiteralPath $psShellKey -ErrorAction SilentlyContinue).GetValue('') -eq '0') {
    Run '.ps1 double-click opens Notepad again instead of running the script' { Set-ItemProperty -LiteralPath $psShellKey -Name '(default)' -Value 'Open' -ErrorAction Stop }
}
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AllocateCDRoms' '1' 'String'   # CD-ROM access for the local user only
# UAC + logon screen
Set-Reg $SY 'EnableLUA' 1
Set-Reg $SY 'ConsentPromptBehaviorAdmin' 2     # prompt for consent on the secure desktop
Set-Reg $SY 'ConsentPromptBehaviorUser' 0      # standard users: automatically deny elevation
Set-Reg $SY 'PromptOnSecureDesktop' 1
Set-Reg $SY 'FilterAdministratorToken' 1
Set-Reg $SY 'EnableInstallerDetection' 1
Set-Reg $SY 'EnableSecureUIAPaths' 1
Set-Reg $SY 'EnableVirtualization' 1
Set-Reg $SY 'DisableCAD' 0                     # require CTRL+ALT+DEL
Set-Reg $SY 'DontDisplayLastUserName' 1
Set-Reg $SY 'InactivityTimeoutSecs' 900
Set-Reg $SY 'ShutdownWithoutLogon' 0
# Values Windows keeps secure by default; images plant the opposite (from CIS and the CyberPatriot-Toolkit checklists)
$LSA = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Set-Reg $LSA 'ForceGuest' 0                                   # sharing model: Classic, not Guest only
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'DisablePasswordChange' 0
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'EnableUserControl' 0
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth' 0
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionShares' ([string[]]@()) 'MultiString'
if (-not $isDC) {
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionPipes' ([string[]]@()) 'MultiString'
    Set-Reg $LSA 'RestrictRemoteSAM' 'O:BAG:BAD:(A;;RC;;;BA)' 'String'   # remote SAM calls: Administrators only
}
# PrintNightmare: only admins install printer drivers, and Point and Print always warns and elevates
$PNP = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
Set-Reg $PNP 'RestrictDriverInstallationToAdministrators' 1
Set-Reg $PNP 'NoWarningNoElevationOnInstall' 0
Set-Reg $PNP 'UpdatePromptSettings' 0
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0   # LLMNR off (name-poisoning attacks)
# Network stack (MSS settings in the CIS benchmark)
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 2
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 2
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NoNameReleaseOnDemand' 1
if ($isDC) {
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity' 2   # require LDAP signing
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RefusePasswordChange' 0
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'FullSecureChannelProtection' 1   # Zerologon enforcement
}

# ------------------------------------------------------------------ 4. credential theft protection
Step 'Credential protection'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$wlKey = Get-Item -LiteralPath $wl -ErrorAction SilentlyContinue
if ($wlKey -and $wlKey.GetValue('DefaultPassword', $null)) { Say "  Winlogon stored a plain-text password for '$($wlKey.GetValue('DefaultUserName', ''))' (write it down if a forensics question asks)" 'Yellow' }
Remove-RegValue $wl 'DefaultPassword'
if ($wlKey -and [string]$wlKey.GetValue('AutoAdminLogon', '') -eq '1') { Set-Reg $wl 'AutoAdminLogon' '0' 'String' }
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
Set-Reg $L 'RunAsPPL' 1                            # LSA protection, needs reboot
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0
Set-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0

# ------------------------------------------------------------------ 5. firewall
Step 'Windows Firewall (turn on; no ports are blocked)'
# Planted trick (Beyond Journey's End): MpsSvc made to depend on a service that never starts (Sense), so the
# firewall cannot start. Windows' own dependencies are mpsdrv, bfe and (Server 2022) nsi. sc.exe config is
# denied for this protected service even to admins, so fix the registry value; the change applies after a reboot.
$mpsKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc'
$dep = @((Get-Item $mpsKey -ErrorAction SilentlyContinue).GetValue('DependOnService', $null)) | Where-Object { $_ }
$extra = @($dep | Where-Object { $_ -notin 'mpsdrv', 'bfe', 'nsi' })
if ($extra.Count) {
    $keep = @($dep | Where-Object { $_ -in 'mpsdrv', 'bfe', 'nsi' }); foreach ($need in 'mpsdrv', 'bfe') { if ($keep -notcontains $need) { $keep += $need } }
    Run "MpsSvc dependencies: removed $($extra -join ', ') (planted), kept $($keep -join ', ') - REBOOT, then the firewall can start" {
        Set-ItemProperty -LiteralPath $mpsKey -Name DependOnService -Value ([string[]]$keep) -Type MultiString -ErrorAction Stop
    }
}
foreach ($fs in 'BFE','MpsSvc') {
    $svc = Get-Service $fs -ErrorAction SilentlyContinue
    if ($svc -and ($svc.StartType -ne 'Automatic' -or $svc.Status -ne 'Running')) {
        Run "$fs -> Automatic and started (the firewall needs it; was $($svc.StartType)/$($svc.Status))" { Set-Service $fs -StartupType Automatic -ErrorAction Stop; Start-Service $fs -ErrorAction Stop }
    }
}
Run 'enable Domain/Private/Public profiles' { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogMaxSizeKilobytes 16384 }
foreach ($pp in 'DomainProfile','PrivateProfile','PublicProfile') {
    $k = Get-Item -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$pp" -ErrorAction SilentlyContinue
    if ($k -and $null -ne $k.GetValue('EnableFirewall', $null)) { Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$pp" 'EnableFirewall' 1 }
    if ($k -and $k.GetValue('DefaultInboundAction', $null) -eq 0) { Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$pp" 'DefaultInboundAction' 1 }   # policy said allow
}

# ------------------------------------------------------------------ 6. Defender
Step 'Microsoft Defender'
$dp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
Remove-RegValue $dp 'DisableAntiSpyware'
Remove-RegValue $dp 'DisableAntiVirus'
foreach ($n in 'DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableOnAccessProtection','DisableScanOnRealtimeEnable','DisableIOAVProtection','DisableScriptScanning') { Remove-RegValue "$dp\Real-Time Protection" $n }
# Policy that makes Defender ignore (6) or take no action (9) on threats of a given alert level
$tsda = Get-Item -LiteralPath "$dp\Threats\ThreatSeverityDefaultAction" -ErrorAction SilentlyContinue
if ($tsda) { foreach ($lvl in $tsda.GetValueNames()) { if ([string]$tsda.GetValue($lvl) -in '6','9') { Remove-RegValue "$dp\Threats\ThreatSeverityDefaultAction" $lvl } } }
# Settings below need the Defender service running (error 0x800106ba otherwise), so start it first.
$wd = Get-Service WinDefend -ErrorAction SilentlyContinue
if ($wd -and $wd.Status -ne 'Running' -and -not $DryRun) {
    Run 'start the Defender service' { Start-Service WinDefend -ErrorAction Stop }
}
# After a disabled-by-policy Defender is started, it can stay half-off (AMServiceEnabled False) until a reboot,
# and every Set-MpPreference fails with 0x800106ba. Wait a little, then say so plainly instead of failing.
$defReady = $DryRun
for ($i = 0; $i -lt 30 -and -not $defReady; $i++) { $st = Get-MpComputerStatus -ErrorAction SilentlyContinue; if ($st -and $st.AMServiceEnabled) { $defReady = $true } else { Start-Sleep 2 } }
if (-not $defReady) {
    Say '  Defender is not fully running yet (it was disabled). REBOOT, then run Harden.ps1 again to finish the Defender settings (real-time, cloud, PUA, ASR).' 'Red'
}
$mpp = Get-MpPreference -ErrorAction SilentlyContinue
foreach ($lv in 'Severe','High','Moderate','Low') {
    if ($defReady -and $mpp -and $mpp."${lv}ThreatDefaultAction" -in 6, 9) {
        $splat = @{ "${lv}ThreatDefaultAction" = 'Quarantine'; ErrorAction = 'Stop' }
        Run "Defender default action for $lv threats -> Quarantine (was $($mpp."${lv}ThreatDefaultAction"))" { Set-MpPreference @splat }
    }
}
if ($defReady) {
    Run 'turn on real-time, behavior, download and script scanning + PUA blocking' {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -PUAProtection Enabled -ErrorAction Stop
    }
    Remove-RegValue "$dp\Spynet" 'SpynetReporting'
    Run 'cloud-delivered protection on, send safe samples automatically' { Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop }
    # Attack Surface Reduction rules that do not interfere with normal admin work or the scoring engine.
    # Left out on purpose: PSExec/WMI process creation, prevalence/age check, ransomware heuristic (can block README apps or tools).
    $asr = [ordered]@{
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    }
    Run "enable $($asr.Count) Attack Surface Reduction rules in Block mode" {
        Add-MpPreference -AttackSurfaceReductionRules_Ids @($asr.Keys) -AttackSurfaceReductionRules_Actions @($asr.Keys | ForEach-Object { 'Enabled' }) -ErrorAction Stop
    }
}
$ex = Get-MpPreference
# An extension exclusion for a program or script type makes Defender ignore every such file (KaliPatriot's
# Windows 10 image excluded .exe). No scoring engine needs one, so these go; path exclusions stay for you to judge.
foreach ($e in @($ex.ExclusionExtension) | Where-Object { $_ -and $_.TrimStart('.') -match '^(?i)(exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|scr|com|msi|sys|cpl|lnk|jar)$' }) {
    $e2 = $e
    Run "remove Defender exclusion for every '$e2' file" { Remove-MpPreference -ExclusionExtension $e2 -ErrorAction Stop }
}
$ex = Get-MpPreference
if ($ex.ExclusionPath -or $ex.ExclusionProcess -or $ex.ExclusionExtension) {
    Say "  Other Defender exclusions NOT removed automatically - review them: $((@($ex.ExclusionPath) + @($ex.ExclusionProcess) + @($ex.ExclusionExtension) | Where-Object { $_ }) -join '; ')" 'Yellow'
    Say '  Remove one with: Remove-MpPreference -ExclusionPath "C:\path"  (or -ExclusionProcess / -ExclusionExtension)' 'Yellow'
}

# ------------------------------------------------------------------ 7. system settings that are almost always scored safe
Step 'AutoPlay, SmartScreen, attachments, Remote Assistance, hardened UNC paths'
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' 2   # 2 = keep zone info ("Do not preserve zone information" = Disabled)
Set-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' 2
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited' 0   # no unsolicited Remote Assistance offers
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' 0
# WinRM: no Basic auth, no unencrypted traffic (does not turn WinRM on or off)
foreach ($side in 'Service','Client') {
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\$side" 'AllowBasic' 0
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\$side" 'AllowUnencryptedTraffic' 0
}
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowDigest' 0
$hp = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
foreach ($share in '\\*\SYSVOL','\\*\NETLOGON') {
    # reg.exe because the value name contains * (PowerShell would treat it as a wildcard)
    Run "hardened UNC path $share" { reg add $hp /v $share /t REG_SZ /d 'RequireMutualAuthentication=1, RequireIntegrity=1' /f | Out-Null }
}

# ------------------------------------------------------------------ 8. SMB
Step 'SMB (SMBv1 off, signing on; SMBv2/3 left alone)'
Run 'disable SMBv1 on the SMB server, require signing, encrypt SMB traffic' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -EnableSecuritySignature $true -EncryptData $true -Force -ErrorAction Stop }
$mrx = (Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb20' -ErrorAction SilentlyContinue)
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'DisableCompression' 1   # SMBGhost workaround (scored on Mushroom Kingdom)
if ($mrx -and $mrx.GetValue('Start', $null) -eq 4) { Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb20' 'Start' 2; Say '  SMBv2/3 client driver was disabled (a past 5-point penalty) - re-enabled, reboot needed' 'Yellow' }

# ------------------------------------------------------------------ 9. RDP (never turned on or off here; always secured)
Step 'Remote Desktop'
# The secure settings are applied whether RDP is on or off: they change nothing until RDP is used, and images score
# them even with RDP off (PPTH: "RDP SSL security", "Require secure RPC"). Turning RDP on or off is the README's call.
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpOn = ((Get-ItemProperty -LiteralPath $ts -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0)
if ($rdpOn) { Say '  RDP is ON - leaving it on (README decides). Securing it:' }
else        { Say '  RDP is OFF - leaving it off. If the README lists RDP, turn it on in System Properties > Remote. Applying the secure settings anyway:' 'Yellow' }
Set-Reg "$ts\WinStations\RDP-Tcp" 'UserAuthentication' 1   # Network Level Authentication
Set-Reg "$ts\WinStations\RDP-Tcp" 'SecurityLayer' 2        # TLS
Set-Reg "$ts\WinStations\RDP-Tcp" 'MinEncryptionLevel' 3   # High
$tsp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
Set-Reg $tsp 'DisablePasswordSaving' 1   # do not allow passwords to be saved
Set-Reg $tsp 'fPromptForPassword' 1      # always prompt for password on connection
Set-Reg $tsp 'fDisableCdm' 1             # no drive redirection
Set-Reg $tsp 'fEncryptRPCTraffic' 1
Set-Reg $tsp 'MinEncryptionLevel' 3      # High (policy copy, so a planted policy cannot lower it)
Set-Reg $tsp 'UserAuthentication' 1      # NLA (policy copy)
Set-Reg $tsp 'SecurityLayer' 2
if ($rdpOn) { Say '  Also decide who may use RDP: Remote Desktop Users group / "Allow log on through Remote Desktop Services".' 'Yellow' }

# ------------------------------------------------------------------ 10. updates
Step 'Windows Update'
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
Set-Reg "$wu\AU" 'NoAutoUpdate' 0
Set-Reg "$wu\AU" 'AUOptions' 4      # auto download and schedule the install
Remove-RegValue $wu 'DisableWindowsUpdateAccess'
Remove-RegValue $wu 'DoNotConnectToWindowsUpdateInternetLocations'
foreach ($svc in 'wuauserv','UsoSvc','BITS') {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s -and $s.StartType -eq 'Disabled') { Run "set $svc to Manual (it was Disabled)" { Set-Service $svc -StartupType Manual -ErrorAction Stop } }
}
$auKey = Get-Item -LiteralPath "$wu\AU" -ErrorAction SilentlyContinue
if ($auKey -and $auKey.GetValue('UseWUServer', 0) -eq 1) {
    Say "  WARNING: updates point to a WSUS server ($((Get-Item -LiteralPath $wu).GetValue('WUServer'))). If that is not legit, delete WUServer/UseWUServer." 'Yellow'
}
Say '  Now open Settings > Windows Update and click Check for updates (start it early; it is slow).' 'Yellow'

# ------------------------------------------------------------------ 11. features
if (-not $SkipFeatures) {
    Step 'Remove risky optional features'
    foreach ($f in 'SMB1Protocol','MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2','TelnetClient','TFTP') {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue
        if ($feat -and $feat.State -eq 'Enabled') {
            Run "disable feature $f" { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null }
        }
    }
}

# ------------------------------------------------------------------ 12. DC-only application security
if ($isDC) {
    Step 'Domain controller: DNS'
    foreach ($z in Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' -and $_.ZoneType -eq 'Primary' }) {
        if ($z.SecureSecondaries -eq 'TransferAnyServer') {
            Run "zone $($z.ZoneName): zone transfers only to name servers" { Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries TransferToZoneNameServer -ErrorAction Stop }
        }
        if ($z.IsDsIntegrated -and $z.DynamicUpdate -eq 'NonsecureAndSecure') {
            Run "zone $($z.ZoneName): secure dynamic updates only" { Set-DnsServerPrimaryZone -Name $z.ZoneName -DynamicUpdate Secure -ErrorAction Stop }
        }
    }
    $c = Get-DnsServerCache -ErrorAction SilentlyContinue
    if ($c -and -not $c.EnablePollutionProtection) { Run 'turn on DNS cache pollution protection' { Set-DnsServerCache -PollutionProtection $true -ErrorAction Stop } }
}
if (Get-Service DNS -ErrorAction SilentlyContinue) {
    Step 'DNS server: SIGRed workaround and plugin DLL'
    $dnsPar = 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters'
    Set-Reg $dnsPar 'TcpReceivePacketSize' 65280   # 0xFF00, the CVE-2020-1350 (SIGRed) workaround; takes effect when DNS restarts
    $plugin = (Get-ItemProperty -LiteralPath $dnsPar -ErrorAction SilentlyContinue).ServerLevelPluginDll
    if ($plugin) { Say "  WARNING: the DNS server loads a plugin DLL: $plugin - the DnsAdmins attack (not removed here; it may be forensics evidence). Remove: Remove-ItemProperty '$dnsPar' ServerLevelPluginDll; Restart-Service DNS" 'Yellow' }
}

# ------------------------------------------------------------------ 12a. boot options
# Kernel debugging / test signing / no integrity checks let unsigned or attacker drivers load. Off is the Windows default.
Step 'Boot options'
$bcd = bcdedit /enum '{current}' 2>$null
foreach ($bk in 'debug','bootdebug','testsigning','nointegritychecks') {
    if ($bcd | Select-String -Pattern "^\s*$bk\s+Yes") {
        Run "boot option $bk -> off (reboot needed)" { bcdedit /set '{current}' $bk off | Out-Null; if ($LASTEXITCODE -ne 0) { throw "bcdedit exit $LASTEXITCODE" } }
    }
}

# ------------------------------------------------------------------ 12b. exploit protection (opt-in)
if ($ExploitProtection) {
    Step 'Exploit protection and DEP'
    Run 'system exploit protection: DEP, CFG, SEHOP, bottom-up and high-entropy ASLR on' { Set-ProcessMitigation -System -Enable DEP,CFG,SEHOP,BottomUp,HighEntropy -ErrorAction Stop }
    $nxLine = bcdedit /enum '{current}' 2>$null | Select-String -Pattern '^\s*nx\s+(\S+)'
    $nx = if ($nxLine) { $nxLine.Matches[0].Groups[1].Value } else { '' }
    if ($nx -in 'OptIn','AlwaysOff') {
        Run "DEP $nx -> OptOut (all programs except listed exceptions; reboot needed)" { bcdedit /set '{current}' nx OptOut | Out-Null; if ($LASTEXITCODE -ne 0) { throw "bcdedit exit $LASTEXITCODE" } }
    } else { Say "  DEP (nx) already $nx" }
} else {
    Say ''; Say '== Exploit protection skipped (run with -ExploitProtection after testing the README apps)' 'DarkGray'
}

# ------------------------------------------------------------------ 12c. services that must run
Step 'Services that must not be off'
$must = [ordered]@{ 'EventLog'='Automatic'; 'MpsSvc'='Automatic'; 'BFE'='Automatic'; 'LanmanWorkstation'='Automatic' }
if ($isDC) {
    foreach ($n in 'NTDS','ADWS','Kdc','Netlogon','LanmanServer','W32Time','DFSR','DNS') { if (Get-Service $n -ErrorAction SilentlyContinue) { $must[$n] = 'Automatic' } }
}
foreach ($n in @($must.Keys)) {
    $s = Get-Service $n -ErrorAction SilentlyContinue
    if (-not $s -or ($s.StartType -ne 'Disabled' -and $s.Status -eq 'Running')) { continue }
    $mode = $must[$n]
    Run "$n -> $mode and started (was $($s.StartType)/$($s.Status))" {
        try { Set-Service $n -StartupType $mode -ErrorAction Stop }
        catch { Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$n" -Name Start -Value 2 -ErrorAction Stop }
        Start-Service $n -ErrorAction Stop
    }
}
foreach ($n in 'W32Time','CryptSvc') {
    $s = Get-Service $n -ErrorAction SilentlyContinue
    if ($s -and $s.StartType -eq 'Disabled' -and -not $must.Contains($n)) { Run "$n -> Manual (was Disabled)" { Set-Service $n -StartupType Manual -ErrorAction Stop } }
}

# ------------------------------------------------------------------ 12d. IIS
if (Get-Service W3SVC -ErrorAction SilentlyContinue) {
    Step 'IIS: directory browsing, error pages, logging'
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    foreach ($site in Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue) {
        $ps = "IIS:\Sites\$($site.Name)"
        $isWeb = ($site.Bindings.Collection | Where-Object { $_.protocol -like 'http*' })
        if ($isWeb) {
            $db = Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $ps -ErrorAction SilentlyContinue
            if ($null -ne $db -and $db.PSObject.Properties['Value']) { $db = $db.Value }
            if ($db -eq $true) { Run "site $($site.Name): directory browsing off" { Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath $ps -ErrorAction Stop } }
            $em = Get-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -PSPath $ps -ErrorAction SilentlyContinue
            if ($null -ne $em -and $em.PSObject.Properties['Value']) { $em = $em.Value }
            # Custom, not DetailedLocalOnly: Mushroom Kingdom's guide scores "Custom error pages"
            if ([string]$em -match '^Detailed') { Run "site $($site.Name): custom error pages (no detailed errors)" { Set-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -Value 'Custom' -PSPath $ps -ErrorAction Stop } }
        }
        if (-not $site.logFile.enabled) { Run "site $($site.Name): logging on" { Set-ItemProperty $ps -Name logFile.enabled -Value $true -ErrorAction Stop } }
    }
    if (Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue) {
        $srv = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter /system.webServer/httpErrors -Name errorMode -ErrorAction SilentlyContinue
        if ($null -ne $srv -and $srv.PSObject.Properties['Value']) { $srv = $srv.Value }
        if ($srv -and [string]$srv -ne 'Custom') { Run 'IIS server level: custom error pages' { Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter /system.webServer/httpErrors -Name errorMode -Value 'Custom' -ErrorAction Stop } }
    }
    foreach ($ap in Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue) {
        if ([string]$ap.processModel.identityType -eq 'LocalSystem') { Say "  App pool '$($ap.Name)' runs as LocalSystem. Change it in IIS Manager > Application Pools > Advanced Settings > Identity = ApplicationPoolIdentity, then test the site." 'Yellow' }
    }
    Say '  Still manual: HTTPS binding with a certificate, anonymous auth per README, FTP anonymous login + SSL, webroot permissions, web shells.' 'Yellow'
}

# ------------------------------------------------------------------ 12e. browsers
$chromeExe = @('C:\Program Files\Google\Chrome\Application\chrome.exe','C:\Program Files (x86)\Google\Chrome\Application\chrome.exe') | Where-Object { Test-Path $_ }
if ($chromeExe) {
    Step 'Google Chrome policies (chrome://policy to confirm)'
    $cp = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    Set-Reg $cp 'AdsSettingForIntrusiveAdsSites' 2   # block intrusive ads (scored on a past semifinal)
    Set-Reg $cp 'DefaultPopupsSetting' 2             # block pop-ups
    Set-Reg $cp 'SafeBrowsingProtectionLevel' 1      # standard Safe Browsing
    Set-Reg $cp 'DownloadRestrictions' 1             # block dangerous downloads
    Set-Reg $cp 'BlockThirdPartyCookies' 1
    Set-Reg $cp 'NetworkPredictionOptions' 2         # no network prediction
    Set-Reg $cp 'MetricsReportingEnabled' 0
    Set-Reg $cp 'BackgroundModeEnabled' 0
    Set-Reg $cp 'SSLVersionMin' 'tls1.2' 'String'
    if (Test-Path "$cp\ExtensionInstallForcelist") { Say "  WARNING: Chrome force-installs extensions ($cp\ExtensionInstallForcelist) - check them" 'Yellow' }
    Say '  Left alone (README may need them): incognito, password manager, sync.' 'DarkGray'
}
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenPuaEnabled' 1
Say '  Firefox: change settings inside the browser (Settings > Privacy & Security). User settings live in prefs.js, which Firefox policies do not rewrite.' 'DarkGray'

# ------------------------------------------------------------------ 13. accounts
Step 'Built-in accounts and per-user flags'
if (-not $isDC) {
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
    if ($guest -and $guest.Enabled) { Run "disable Guest account '$($guest.Name)'" { Disable-LocalUser -SID $guest.SID -ErrorAction Stop } }
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
    if ($admin -and $admin.Enabled) {
        if ($meSid -like '*-500') { Say "  You are logged in as the built-in Administrator - leaving it enabled." 'Yellow' }
        else { Say "  Built-in Administrator '$($admin.Name)' is enabled. Disable it yourself if the README allows: Disable-LocalUser -Name '$($admin.Name)'" 'Yellow' }
    }
    if (-not $SkipUserFlags) {
        foreach ($u in Get-LocalUser | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(500|501|503|504)$' -and $_.Name -notmatch $engineUserRx }) {
            if (-not $u.PasswordExpires -or -not $u.UserMayChangePassword) {
                Run "user $($u.Name): password expires, user may change password" { Set-LocalUser -SID $u.SID -PasswordNeverExpires $false -UserMayChangePassword $true -ErrorAction Stop }
            }
            if (-not $u.PasswordRequired) {
                Run "user $($u.Name): password required" { net user "$($u.Name)" /passwordreq:yes | Out-Null; if ($LASTEXITCODE -ne 0) { throw "net user exit $LASTEXITCODE" } }
            }
        }
        Say '  Note: if your own password is now past the 60-day max age, Windows will ask you to change it at next sign-in.' 'DarkGray'
    }
} else {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    $g = Get-ADUser -Filter * -Properties Enabled | Where-Object { $_.SID.Value -like '*-501' }
    if ($g -and $g.Enabled) { Run 'disable AD Guest account' { Disable-ADAccount -Identity $g -ErrorAction Stop } }
    if (-not $SkipUserFlags) {
        foreach ($u in Get-ADUser -Filter * -Properties PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption, PasswordNeverExpires, ServicePrincipalName) {
            if ($u.SamAccountName -eq 'krbtgt' -or $u.SamAccountName -match $engineUserRx) { continue }   # never touch a scoring engine's account
            if ($u.PasswordNotRequired)               { Run "AD $($u.SamAccountName): require a password"           { Set-ADUser $u -PasswordNotRequired $false -ErrorAction Stop
                                                            if ((Get-ADUser $u -Properties PasswordNotRequired).PasswordNotRequired) { throw 'still set after the change - the account probably has a blank password; give it a strong password, then try again' } } }
            if ($u.DoesNotRequirePreAuth)             { Run "AD $($u.SamAccountName): require Kerberos pre-auth"    { Set-ADAccountControl $u -DoesNotRequirePreAuth $false -ErrorAction Stop } }
            if ($u.AllowReversiblePasswordEncryption) { Run "AD $($u.SamAccountName): no reversible encryption"     { Set-ADUser $u -AllowReversiblePasswordEncryption $false -ErrorAction Stop } }
            if ($u.PasswordNeverExpires -and -not $u.ServicePrincipalName) { Run "AD $($u.SamAccountName): password expires" { Set-ADUser $u -PasswordNeverExpires $false -ErrorAction Stop } }
            elseif ($u.PasswordNeverExpires) { Say "  AD $($u.SamAccountName) has an SPN (service account?) - left PasswordNeverExpires alone, decide yourself" 'Yellow' }
        }
    }
}

if ($isDC) {
    # On a DC, a security option that a domain GPO also defines (GptTmpl.inf [Registry Values]) is put back at the
    # next refresh - e.g. Default Domain Controllers Policy sets LDAP server signing to 1. Make those GPOs agree.
    Step 'Domain GPOs that would undo these settings'
    try {
        $domObj = Get-ADDomain -ErrorAction Stop
        $sysvol = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction Stop).SysVol
        $typeCode = @{ DWord = '4'; String = '1'; ExpandString = '2'; MultiString = '7' }
        # User rights on a DC come from GPOs (normally Default Domain Controllers Policy). Mushroom Kingdom planted
        # Everyone in "Enable ... trusted for delegation" and "Allow log on locally" there. Only these rights are edited.
        $rightsNobody = 'SeTcbPrivilege', 'SeCreateTokenPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeCreatePermanentPrivilege', 'SeLockMemoryPrivilege', 'SeRelabelPrivilege'
        $rightsAdmins = 'SeDebugPrivilege', 'SeEnableDelegationPrivilege'
        $rightsClean  = 'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeSecurityPrivilege', 'SeSystemEnvironmentPrivilege', 'SeRemoteShutdownPrivilege', 'SeShutdownPrivilege', 'SeSystemtimePrivilege', 'SeManageVolumePrivilege', 'SeSyncAgentPrivilege'
        $broadRx = '^(S-1-1-0|S-1-5-11|S-1-5-32-545|S-1-5-32-546|S-1-5-7|S-1-5-4|S-1-5-21-[\d-]+-(513|514|515))$'   # Everyone, Authenticated Users, Users, Guests, Anonymous, Interactive, Domain Users/Guests/Computers
        $userSid = @{}
        $toSid = { param($t) if ($t.StartsWith('*')) { $t.Substring(1) } else { try { ([Security.Principal.NTAccount]$t).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null } } }
        $isUser = { param($sid)
            if ($sid -notmatch '^S-1-5-21-[\d-]+-(\d+)$' -or [int64]$Matches[1] -lt 1000) { return $false }
            if (-not $userSid.ContainsKey($sid)) { $userSid[$sid] = $false; try { $null = Get-ADUser -Identity $sid -ErrorAction Stop; $userSid[$sid] = $true } catch {} }
            $userSid[$sid] }
        foreach ($gdir in Get-ChildItem (Join-Path $sysvol "$($domObj.DNSRoot)\Policies") -Directory -ErrorAction Stop) {
            $tmpl = Join-Path $gdir.FullName 'MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            if (-not (Test-Path $tmpl)) { continue }
            $lines = @([IO.File]::ReadAllText($tmpl) -split "`r?`n")
            $inReg = $false; $inRights = $false; $fixed = @()
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $l = $lines[$i].Trim()
                if ($l.StartsWith('[')) { $inReg = ($l -ieq '[Registry Values]'); $inRights = ($l -ieq '[Privilege Rights]'); continue }
                if ($inRights -and $l -match '^(Se\w+)\s*=\s*(.*)$') {
                    $right = $Matches[1]; $orig = $Matches[2].Trim()
                    $toks = @($orig -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    if ($rightsNobody -contains $right) { $newToks = @() }
                    elseif ($rightsAdmins -contains $right) { $newToks = @('*S-1-5-32-544') }
                    elseif ($rightsClean -contains $right) {
                        $newToks = @($toks | Where-Object { $sid = & $toSid $_; -not ($sid -and $sid -ne $meSid -and ($sid -match $broadRx -or (& $isUser $sid))) })
                        if ($newToks.Count -eq 0) { $newToks = @('*S-1-5-32-544') }   # never leave a logon right empty
                    } else { continue }
                    $newVal = $newToks -join ','
                    if ($newVal -ne ($toks -join ',')) { $fixed += "user right $($right): '$orig' -> '$(if ($newVal) { $newVal } else { 'nobody' })'"; $lines[$i] = "$right = $newVal".TrimEnd() }
                    continue
                }
                if (-not $inReg -or $l -notmatch '^([^=]+)=(\d+),(.*)$') { continue }
                $key = $Matches[1].Trim().ToLower(); $gType = $Matches[2]; $gData = $Matches[3].Trim('"')
                if (-not $script:Desired.ContainsKey($key)) { continue }
                $want = $script:Desired[$key]
                $wantData = [string]$want[0]
                if ($gData -eq $wantData) { continue }
                $code = if ($typeCode.ContainsKey($want[1])) { $typeCode[$want[1]] } else { $gType }
                $dataOut = if ($code -eq '1' -or $code -eq '2') { '"' + $wantData + '"' } else { $wantData }
                $fixed += "$($want[2]): GPO had $gData, now $wantData"
                $lines[$i] = "$($Matches[1].Trim())=$code,$dataOut"
            }
            if ($fixed.Count -eq 0) { continue }
            $gname = try { (Get-GPO -Guid $gdir.Name.Trim('{}') -ErrorAction Stop).DisplayName } catch { $gdir.Name }
            if ($DryRun) { foreach ($f in $fixed) { Say "  would change GPO '$gname': $f" 'Yellow' }; continue }
            Copy-Item $tmpl (Join-Path $backup "GptTmpl-$($gdir.Name).inf") -Force
            [IO.File]::WriteAllText($tmpl, ($lines -join "`r`n"), [Text.Encoding]::Unicode)
            $gptIni = Join-Path $gdir.FullName 'GPT.INI'
            $gpoDN = "CN=$($gdir.Name),CN=Policies,CN=System,$($domObj.DistinguishedName)"
            $adVer = [int](Get-ADObject -Identity $gpoDN -Properties versionNumber -ErrorAction Stop).versionNumber
            $ini = [IO.File]::ReadAllText($gptIni)
            $fileVer = if ($ini -match '(?im)^\s*Version\s*=\s*(\d+)') { [int]$Matches[1] } else { 0 }
            $newVer = [Math]::Max($fileVer, $adVer) + 1
            $ini = [regex]::Replace($ini, '(?im)^(\s*Version\s*=\s*)\d+', "`${1}$newVer")
            [IO.File]::WriteAllText($gptIni, $ini, [Text.Encoding]::ASCII)
            Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVer } -ErrorAction Stop
            foreach ($f in $fixed) { Say "  GPO '$gname': $f" 'Green' }
        }
    } catch { Say "  FAILED to check domain GPOs: $($_.Exception.Message) - check Default Domain Controllers Policy > Security Options by hand" 'Red' }
}

# ------------------------------------------------------------------ done
Step 'Finish'
if (-not $DryRun) {
    Run 'gpupdate /force' { gpupdate /force | Out-Null }
    $log | Out-File (Join-Path $backup 'harden-log.txt') -Encoding UTF8
    Say "Log and backups: $backup" 'Cyan'
}
Say 'Next steps (manual, README-driven): services, users (Users.ps1), unwanted software, prohibited files, app updates, persistence found by Audit.ps1.' 'Cyan'
Say 'Check the score report now. If points went DOWN, compare with the backup and undo the last section.' 'Cyan'
Say 'Reboot when convenient (LSA protection and feature removal finish on reboot).' 'Cyan'

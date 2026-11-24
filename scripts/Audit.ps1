<#
.SYNOPSIS
  CyberPatriot Windows AUDIT script. READ-ONLY: it changes nothing.

.DESCRIPTION
  Walks the same categories the scoring engine uses (User Auditing, Account/Local
  Policy, Defensive Countermeasures, Service Auditing, Malware/persistence,
  Prohibited Files, Unwanted Software, Updates, Application Security) and prints
  anything that looks wrong as a [!] line. Everything is also saved to a report
  on the Desktop so you can work through it.

  [!]  = probably a vulnerability, look at it
  [?]  = needs a human decision (check against the README)
  Plain lines are information.

.USAGE
  Right-click PowerShell > Run as administrator, then:
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Audit.ps1            # normal run (about 1-3 minutes)
    .\Audit.ps1 -Deep      # also checks signatures of System32 executables (slow)
    .\Audit.ps1 -Quick     # skip the slow disk-wide file searches (good for re-checks)

  Answer the Forensics Questions BEFORE running anything that changes the system.
  This script is read-only, so it is safe to run first.
#>
[CmdletBinding()]
param(
    [switch]$Deep,
    [switch]$Quick
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Report = New-Object System.Collections.Generic.List[string]
$script:FlagCount = 0

function Out-Line([string]$text, [string]$color = 'Gray') {
    Write-Host $text -ForegroundColor $color
    $script:Report.Add($text)
}
function Section([string]$title) {
    Out-Line ''
    Out-Line ('=' * 78) 'DarkCyan'
    Out-Line "  $title" 'Cyan'
    Out-Line ('=' * 78) 'DarkCyan'
}
function Flag([string]$text)  { $script:FlagCount++; Out-Line "[!] $text" 'Red' }
function Check([string]$text) { Out-Line "[?] $text" 'Yellow' }
function Info([string]$text)  { Out-Line "    $text" 'Gray' }
function Good([string]$text)  { Out-Line "[ok] $text" 'Green' }
function Out-Table($obj) {
    if ($null -eq $obj) { return }
    $s = ($obj | Format-Table -AutoSize -Wrap | Out-String -Width 220).TrimEnd()
    foreach ($l in ($s -split "`r?`n")) { Out-Line $l 'Gray' }
}
function Get-RegValue([string]$path, [string]$name) {
    $k = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($k) { return $k.GetValue($name, $null) }
    return $null
}

# The CyberPatriot scoring client and community engines (aeacus) look like malware to a scanner. Never touch them.
$mimiRx = '(?i)mimikatz|mimidrv|mimilib|gentilkiwi|benjamin delpy'   # survives renaming: it is in the file's version info
$engineRx = '(?i)\\(aeacus|CyberPatriot|CCS)\\|\\(phocus|CCSClient)\.exe'
function Is-Engine([string]$p) { return ($p -match $engineRx) }

# ---------------------------------------------------------------- preflight
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an ELEVATED PowerShell (Run as administrator).' -ForegroundColor Red; exit 1 }

$os          = Get-CimInstance Win32_OperatingSystem
$productType = [int]$os.ProductType          # 1 = workstation, 2 = domain controller, 3 = member/standalone server
$isDC        = ($productType -eq 2)
$me          = [Security.Principal.WindowsIdentity]::GetCurrent()
$stamp       = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop     = [Environment]::GetFolderPath('Desktop')
if (-not $desktop -or -not (Test-Path $desktop)) { $desktop = Join-Path $env:PUBLIC 'Desktop' }   # e.g. running as SYSTEM
$reportPath  = Join-Path $desktop "CP-Audit-$stamp.txt"

Section 'SYSTEM'
Info "OS:            $($os.Caption)  build $($os.BuildNumber).$(Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR')"
Info "Role:          $(switch ($productType) { 1 {'Workstation'} 2 {'DOMAIN CONTROLLER'} 3 {'Server'} })"
Info "Computer:      $env:COMPUTERNAME   Domain: $((Get-CimInstance Win32_ComputerSystem).Domain)"
Info "Running as:    $($me.Name)  ($($me.User.Value))"
Info "Remember: the README decides what is 'required'. Nothing here is a reason to remove a critical service."

# ---------------------------------------------------------------- USER AUDITING
Section 'USER AUDITING  (compare every name below with the README)'
if (-not $isDC) {
    $users = Get-LocalUser
    Out-Table ($users | Select-Object Name, Enabled,
        @{n='RID';e={$_.SID.Value.Split('-')[-1]}},
        PasswordRequired, UserMayChangePassword,
        @{n='PwdExpires';e={ if ($_.PasswordExpires) { $_.PasswordExpires.ToString('yyyy-MM-dd') } else { 'NEVER' } }},
        @{n='LastLogon';e={ if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { '' } }},
        Description)
    foreach ($u in $users) {
        $rid = $u.SID.Value.Split('-')[-1]
        if ($u.Name.EndsWith('$'))                 { Flag "User '$($u.Name)' ends in `$ - 'net user' hides these. Is it in the README?" }
        if ($rid -eq '501' -and $u.Enabled)        { Flag "Guest account (renamed or not: '$($u.Name)') is ENABLED" }
        if ($rid -eq '500' -and $u.Enabled -and $me.User.Value -notlike '*-500') { Check "Built-in Administrator '$($u.Name)' is enabled (disable it unless README says otherwise)" }
        if ($u.Enabled -and -not $u.PasswordRequired) { Flag "User '$($u.Name)' does not require a password" }
        if ($u.Enabled -and -not $u.PasswordExpires -and $rid -notin '500','501','503','504') { Check "User '$($u.Name)' password never expires" }
        if ($u.Enabled -and -not $u.UserMayChangePassword -and $rid -notin '501','503','504') { Check "User '$($u.Name)' cannot change their password" }
    }

    Out-Line ''
    Info 'Local group membership (only non-empty groups shown):'
    foreach ($g in Get-LocalGroup) {
        $members = $null
        try { $members = Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | Select-Object -ExpandProperty Name }
        catch {
            # Get-LocalGroupMember breaks on orphaned SIDs; fall back to net.exe
            $raw = net localgroup "$($g.Name)" 2>$null
            if ($raw) { $members = $raw | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' } }
        }
        if ($members) {
            $line = "{0,-35} {1}" -f $g.Name, ($members -join ', ')
            if ($g.Name -in 'Administrators','Remote Desktop Users','Backup Operators','Remote Management Users','Hyper-V Administrators','Network Configuration Operators','Event Log Readers','Power Users') { Check $line } else { Info $line }
        }
    }
}
else {
    Import-Module ActiveDirectory
    $adUsers = Get-ADUser -Filter * -Properties Enabled, PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption, TrustedForDelegation, ServicePrincipalName, Description, LastLogonDate
    Out-Table ($adUsers | Select-Object SamAccountName, Enabled, PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption, @{n='SPN';e={($_.ServicePrincipalName -join ';')}}, Description)
    foreach ($u in $adUsers) {
        if ($u.SamAccountName -eq 'krbtgt') { continue }
        if ($u.DoesNotRequirePreAuth)            { Flag "AD user '$($u.SamAccountName)' has Kerberos pre-auth DISABLED (AS-REP roastable)" }
        if ($u.PasswordNotRequired)              { Flag "AD user '$($u.SamAccountName)' has PasswordNotRequired" }
        if ($u.AllowReversiblePasswordEncryption){ Flag "AD user '$($u.SamAccountName)' stores password with reversible encryption" }
        if ($u.TrustedForDelegation)             { Flag "AD user '$($u.SamAccountName)' is trusted for unconstrained delegation" }
        if ($u.Enabled -and $u.PasswordNeverExpires) { Check "AD user '$($u.SamAccountName)' password never expires" }
        if ($u.SID.Value -like '*-501' -and $u.Enabled) { Flag "AD Guest account ('$($u.SamAccountName)') is enabled" }
    }

    Out-Line ''
    Info 'Privileged AD groups (direct members, read from the member attribute so nothing is skipped):'
    $priv = 'Administrators','Domain Admins','Enterprise Admins','Schema Admins','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Remote Desktop Users','Pre-Windows 2000 Compatible Access','Remote Management Users'
    foreach ($g in $priv) {
        $grp = Get-ADGroup -Identity $g -Properties member -ErrorAction SilentlyContinue
        if (-not $grp) { continue }
        $names = $grp.member | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }
        if ($names) { Check ("{0,-35} {1}" -f $g, ($names -join ', ')) }
        if ($g -eq 'Pre-Windows 2000 Compatible Access' -and ($names -contains 'S-1-1-0' -or $names -contains 'S-1-5-7')) {
            Flag 'Everyone/Anonymous is in Pre-Windows 2000 Compatible Access'
        }
    }

    Out-Line ''
    Info 'Who can DCSync (Replicating Directory Changes / Changes All on the domain root):'
    $domainDN = (Get-ADDomain).DistinguishedName
    $replGuids = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
    $acl = Get-Acl -Path "AD:$domainDN"
    foreach ($ace in $acl.Access) {
        if ($replGuids -contains $ace.ObjectType.ToString() -and $ace.AccessControlType -eq 'Allow') {
            $who = $ace.IdentityReference.Value
            if ($who -match 'Domain Controllers|Enterprise Domain Controllers|Enterprise Read-only Domain Controllers|BUILTIN\\Administrators|Read-only Domain Controllers') { Info "    $who" }
            else { Flag "$who has replication (DCSync) rights on the domain" }
        }
    }

    Out-Line ''
    Info 'Computer objects with a ManagedBy owner or delegation:'
    Get-ADComputer -Filter * -Properties ManagedBy, TrustedForDelegation, 'msDS-AllowedToDelegateTo', PrimaryGroupID | ForEach-Object {
        if ($_.ManagedBy) { Flag "Computer $($_.Name) is managed by $(($_.ManagedBy -split ',')[0] -replace '^CN=')" }
        if ($_.TrustedForDelegation -and $_.PrimaryGroupID -ne 516) { Flag "Computer $($_.Name) (not a DC) has unconstrained delegation" }
    }

    $dsh = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -Properties dsHeuristics).dsHeuristics
    if ($dsh -and $dsh.Length -ge 7 -and $dsh[6] -eq '2') { Flag "dsHeuristics = '$dsh' (7th character 2 = anonymous LDAP operations allowed)" } else { Info "dsHeuristics: '$dsh'" }

    Out-Line ''
    Info 'Group Policy startup/logon scripts in SYSVOL (malicious GP scripts are a known scored item):'
    $gpScripts = Get-ChildItem "$env:SystemRoot\SYSVOL\sysvol\*\Policies\*\*\Scripts" -Recurse -File -ErrorAction SilentlyContinue
    if ($gpScripts) { foreach ($f in $gpScripts) { Check $f.FullName } } else { Info '    none' }

    Out-Line ''
    Info 'Dangerous permissions on privileged AD objects (dsa.msc > View > Advanced Features > Security tab):'
    $domain = Get-ADDomain
    $targets = @($domain.DistinguishedName, "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)") +
               @('Domain Admins','Enterprise Admins','Schema Admins','Administrators' | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).DistinguishedName })
    $adOk = '\\(Domain Admins|Enterprise Admins|Administrators|Key Admins|Enterprise Key Admins|Domain Controllers|Enterprise Domain Controllers|Enterprise Read-only Domain Controllers|Cert Publishers|Terminal Server License Servers|Windows Authorization Access Group|Pre-Windows 2000 Compatible Access|SYSTEM|SELF|ENTERPRISE DOMAIN CONTROLLERS)$|^CREATOR OWNER$'
    $memberGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    foreach ($dn in $targets | Where-Object { $_ }) {
        foreach ($ace in (Get-Acl -Path "AD:$dn").Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $id = $ace.IdentityReference.Value
            if ($id -match $adOk) { continue }
            $r  = [string]$ace.ActiveDirectoryRights
            $og = $ace.ObjectType.ToString()
            $danger = ($r -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') -or ($r -match 'WriteProperty' -and ($og -eq '00000000-0000-0000-0000-000000000000' -or $og -eq $memberGuid))
            if ($danger) { Flag "$id has $r on $(($dn -split ',')[0])" }
        }
    }

    Out-Line ''
    Info 'Fine-grained password policies (a weak one silently overrides the Default Domain Policy for its members):'
    foreach ($pso in Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue) {
        $to = ($pso.AppliesTo | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join ', '
        $line = "PSO '{0}' (precedence {1}) min length {2}, complexity {3}, reversible {4}, lockout {5}, applies to: {6}" -f $pso.Name, $pso.Precedence, $pso.MinPasswordLength, $pso.ComplexityEnabled, $pso.ReversibleEncryptionEnabled, $pso.LockoutThreshold, $to
        if ($pso.MinPasswordLength -lt 12 -or -not $pso.ComplexityEnabled -or $pso.ReversibleEncryptionEnabled -or $pso.LockoutThreshold -lt 5) { Flag $line } else { Check $line }
    }
    $maq = (Get-ADObject (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
    if ($maq -gt 0) { Check "ms-DS-MachineAccountQuota = $maq (any user can join $maq computers to the domain; CIS recommends 0)" }
    $nlp = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    if (Get-RegValue $nlp 'VulnerableChannelAllowList') { Flag "Netlogon VulnerableChannelAllowList is set (re-opens Zerologon for: $(Get-RegValue $nlp 'VulnerableChannelAllowList'))" }
    if ((Get-RegValue $nlp 'FullSecureChannelProtection') -eq 0) { Flag 'Netlogon FullSecureChannelProtection = 0 (Zerologon enforcement off)' }
    $cb = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
    if ($cb -ne 2) { Check "LDAP channel binding (LdapEnforceChannelBinding) = $(if ($null -eq $cb) {'not set'} else {$cb}) (2 = always)" }

    Out-Line ''
    Info 'Group Policy Objects and who can edit them (gpmc.msc > GPO > Delegation):'
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    foreach ($gpo in Get-GPO -All -ErrorAction SilentlyContinue) {
        Info ("GPO '{0}'  status {1}  modified {2}" -f $gpo.DisplayName, $gpo.GpoStatus, $gpo.ModificationTime)
        foreach ($perm in Get-GPPermission -Guid $gpo.Id -All -ErrorAction SilentlyContinue) {
            if ([string]$perm.Permission -in 'GpoEdit','GpoEditDeleteModifySecurity' -and $perm.Trustee.Name -notin 'Domain Admins','Enterprise Admins','SYSTEM') {
                Flag "GPO '$($gpo.DisplayName)' can be edited by $($perm.Trustee.Name) ($($perm.Permission))"
            }
        }
    }
}

# ---------------------------------------------------------------- ACCOUNT + LOCAL POLICY
Section 'ACCOUNT POLICY + LOCAL POLICY (secedit export)'
$tmpInf = Join-Path $env:TEMP "cp-audit-$stamp.inf"
secedit /export /cfg $tmpInf /quiet | Out-Null
$sec = @{}
$section = ''
foreach ($line in (Get-Content $tmpInf)) {
    if ($line -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
    if ($line -match '^\s*([^=]+?)\s*=\s*(.*)$') { $sec["$section|$($Matches[1])"] = $Matches[2].Trim() }
}
if ($isDC) { Check 'Domain controller: account policy shown here is the effective DOMAIN policy. Fix it in gpmc.msc > Default Domain Policy, not secpol.msc.' }

$acct = @(
    @{k='MinimumPasswordAge';   want='>=1';  test={ param($v) [int]$v -ge 1 }}
    @{k='MaximumPasswordAge';   want='1-90'; test={ param($v) [int]$v -ge 1 -and [int]$v -le 90 }}
    @{k='MinimumPasswordLength';want='>=12'; test={ param($v) [int]$v -ge 12 }}
    @{k='PasswordComplexity';   want='1';    test={ param($v) $v -eq '1' }}
    @{k='PasswordHistorySize';  want='>=5';  test={ param($v) [int]$v -ge 5 }}
    @{k='ClearTextPassword';    want='0';    test={ param($v) $v -eq '0' }}
    @{k='LockoutBadCount';      want='5-10 (below 5 has been a PENALTY)'; test={ param($v) [int]$v -ge 5 -and [int]$v -le 10 }}
    @{k='LockoutDuration';      want='>=15'; test={ param($v) [int]$v -ge 15 }}
    @{k='ResetLockoutCount';    want='>=15'; test={ param($v) [int]$v -ge 15 }}
    @{k='LSAAnonymousNameLookup'; want='0';  test={ param($v) $v -eq '0' }}
)
foreach ($a in $acct) {
    $v = $sec["System Access|$($a.k)"]
    if ($null -eq $v) { Check ("{0,-24} not set   (want {1})" -f $a.k, $a.want); continue }
    if (& $a.test $v) { Good ("{0,-24} = {1}" -f $a.k, $v) } else { Flag ("{0,-24} = {1}   (want {2})" -f $a.k, $v, $a.want) }
}
foreach ($k in 'MaxTicketAge','MaxRenewAge','MaxServiceAge','MaxClockSkew') {
    $v = $sec["Kerberos Policy|$k"]
    if ($v) { Info ("Kerberos {0,-15} = {1}  (defaults: 10h, 7d, 600min, 5min)" -f $k, $v) }
}

Out-Line ''
Info 'User Rights Assignment - risky principals in sensitive rights:'
function Resolve-Sid([string]$entry) {
    $e = $entry.Trim()
    if ($e.StartsWith('*')) {
        try { return (New-Object Security.Principal.SecurityIdentifier($e.TrimStart('*'))).Translate([Security.Principal.NTAccount]).Value } catch { return $e }
    }
    return $e
}
$sensitive = 'SeTcbPrivilege','SeDebugPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeLoadDriverPrivilege',
             'SeCreateTokenPrivilege','SeTrustedCredManAccessPrivilege','SeEnableDelegationPrivilege','SeImpersonatePrivilege',
             'SeAssignPrimaryTokenPrivilege','SeSecurityPrivilege','SeSystemEnvironmentPrivilege','SeManageVolumePrivilege',
             'SeRemoteShutdownPrivilege','SeRemoteInteractiveLogonRight','SeLockMemoryPrivilege','SeCreatePermanentPrivilege',
             'SeRelabelPrivilege','SeSystemtimePrivilege','SeCreateSymbolicLinkPrivilege','SeBatchLogonRight','SeServiceLogonRight','SeNetworkLogonRight','SeInteractiveLogonRight'
$normal = @{ 'SeNetworkLogonRight'='Everyone|Users|Authenticated Users'; 'SeInteractiveLogonRight'='^Users$' }
$broad = @{ '*S-1-1-0'='Everyone'; '*S-1-5-32-546'='Guests'; '*S-1-5-7'='ANONYMOUS LOGON'; '*S-1-5-11'='Authenticated Users'; '*S-1-5-32-545'='Users' }
foreach ($key in ($sec.Keys | Where-Object { $_ -like 'Privilege Rights|*' } | Sort-Object)) {
    $right = $key.Split('|')[1]
    $entries = $sec[$key] -split ','
    $names = ($entries | ForEach-Object { Resolve-Sid $_ }) -join ', '
    $bad = @()
    foreach ($e in $entries) {
        $e = $e.Trim()
        if ($broad.ContainsKey($e)) { $bad += $broad[$e] }
        elseif ($e -match '-501$') { $bad += 'Guest' }
        elseif ($e -match '-513$') { $bad += 'Domain Users' }
        elseif ($e -match '^\*S-1-5-21-.*-(\d{4,})$') { $bad += (Resolve-Sid $e) }   # RID >= 1000 = an account/group someone created
    }
    if ($right -like 'SeDeny*') {
        if ($entries -contains '*S-1-5-32-544') { Flag "$right includes Administrators - this can lock you out" } else { Info ("{0,-38} {1}" -f $right, $names) }
        continue
    }
    if ($right -in $sensitive -and $bad.Count -gt 0) {
        if ($normal.ContainsKey($right) -and ($bad | Where-Object { $_ -notmatch $normal[$right] }).Count -eq 0) { Check ("{0,-38} {1}   (default on workstations, CIS removes broad groups)" -f $right, $names) }
        else { Flag ("{0,-38} {1}" -f $right, $names) }
    }
}
foreach ($r in 'SeTcbPrivilege','SeTrustedCredManAccessPrivilege','SeCreateTokenPrivilege') {
    if ($sec["Privilege Rights|$r"]) { Flag "$r should be assigned to NO ONE (has: $((($sec["Privilege Rights|$r"] -split ',') | ForEach-Object { Resolve-Sid $_ }) -join ', '))" }
}

Out-Line ''
Info 'Audit policy (auditpol) - subcategories with No Auditing:'
$ap = auditpol /get /category:* 2>$null
$noAudit = $ap | Where-Object { $_ -match '\s{2,}No Auditing\s*$' } | ForEach-Object { $_.Trim() -replace '\s{2,}No Auditing$','' }
if ($noAudit.Count -gt 0) { Flag "$($noAudit.Count) audit subcategories have No Auditing: $(($noAudit | Select-Object -First 12) -join ', ')..." } else { Good 'Every audit subcategory audits something' }

Out-Line ''
Info 'Security Options (registry) - compared with hardened values:'
$opts = @(
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RestrictAnonymousSAM',1,'Do not allow anonymous enumeration of SAM accounts')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RestrictAnonymous',1,'Do not allow anonymous enumeration of SAM accounts and shares')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','EveryoneIncludesAnonymous',0,'Let Everyone permissions apply to anonymous users = Disabled')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','NoLMHash',1,'Do not store LAN Manager hash')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel',5,'LAN Manager auth level = NTLMv2 only, refuse LM & NTLM')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','LimitBlankPasswordUse',1,'Limit blank passwords to console logon only')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','SCENoApplyLegacyAuditPolicy',1,'Force audit policy subcategory settings')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL',1,'LSA protection (RunAsPPL)')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RequireSecuritySignature',1,'SMB server: digitally sign communications (always)')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RestrictNullSessAccess',1,'Restrict anonymous access to Named Pipes and Shares')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters','RequireSecuritySignature',1,'SMB client: digitally sign communications (always)')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters','EnablePlainTextPassword',0,'Send unencrypted password to third-party SMB servers = Disabled')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA',1,'UAC: Run all administrators in Admin Approval Mode')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','ConsentPromptBehaviorAdmin',2,'UAC: prompt for consent on the secure desktop')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','PromptOnSecureDesktop',1,'UAC: switch to the secure desktop')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','FilterAdministratorToken',1,'UAC: Admin Approval Mode for built-in Administrator')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','DisableCAD',0,'Interactive logon: Do not require CTRL+ALT+DEL = Disabled')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','DontDisplayLastUserName',1,"Interactive logon: Don't display last signed-in")
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','ShutdownWithoutLogon',0,'Shutdown: allow without logon = Disabled')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','ProcessCreationIncludeCmdLine_Enabled',1,'Include command line in process creation events')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0,'WDigest does not keep plaintext passwords')
    ,@('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0,'AlwaysInstallElevated is off (classic privilege escalation)')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance','fAllowToGetHelp',0,'Remote Assistance is off')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoDriveTypeAutoRun',255,'AutoPlay off for all drives')
    ,@('HKLM:\SOFTWARE\Policies\Microsoft\Windows\System','EnableSmartScreen',1,'SmartScreen on')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','AllocateCDRoms','1','Restrict CD-ROM access to locally logged-on user')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers','AddPrinterDrivers',1,'Prevent users from installing printer drivers')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','DisableDomainCreds',1,'Do not allow storage of passwords for network authentication')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0','NTLMMinClientSec',537395200,'NTLM clients: require NTLMv2 session security + 128-bit')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0','NTLMMinServerSec',537395200,'NTLM servers: require NTLMv2 session security + 128-bit')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','EnableForcedLogOff',1,'Disconnect clients when logon hours expire')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','ConsentPromptBehaviorUser',0,'UAC: automatically deny elevation for standard users')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableInstallerDetection',1,'UAC: detect application installations')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableSecureUIAPaths',1,'UAC: only elevate UIAccess apps in secure locations')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableVirtualization',1,'UAC: virtualize file and registry write failures')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters','RequireSignOrSeal',1,'Domain member: encrypt or sign secure channel (always)')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters','RequireStrongKey',1,'Domain member: require strong session key')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\LDAP','LDAPClientIntegrity',1,'LDAP client signing = Negotiate signing')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutorun',1,'Turn off Autorun')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0','allownullsessionfallback',0,'Network security: allow LocalSystem NULL session fallback = off')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel','DisableExceptionChainValidation',0,'SEHOP on (MSS: DisableExceptionChainValidation = 0)')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel','ObCaseInsensitive',1,'System objects: require case insensitivity')
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager','ProtectionMode',1,'System objects: strengthen default permissions')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments','SaveZoneInformation',2,'Do not preserve zone information = Disabled (keep Mark of the Web)')
)
foreach ($o in $opts) {
    $v = Get-RegValue $o[0] $o[1]
    if ($null -eq $v) { Check ("{0,-62} not set (want {1})" -f $o[3], $o[2]) }
    elseif ([string]$v -eq [string]$o[2]) { Good ("{0,-62} = {1}" -f $o[3], $v) }
    else { Flag ("{0,-62} = {1}  (want {2})" -f $o[3], $v, $o[2]) }
}
$ad = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'autodisconnect'
if ($null -ne $ad -and ($ad -gt 15 -or $ad -lt 0)) { Flag ("{0,-62} = {1}  (want 1-15)" -f 'SMB server: idle minutes before disconnecting a session', $ad) }
$psShell = Get-RegValue 'Registry::HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell' ''
if ($psShell -eq '0') { Flag 'Double-clicking a .ps1 file RUNS it (HKCR\Microsoft.PowerShellScript.1\Shell default = 0; normal is Open = Notepad)' }
$psl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' '__PSLockdownPolicy'
if ($null -ne $psl) { Check "__PSLockdownPolicy = $psl (4 = PowerShell constrained language for everyone; scored on one practice image, but it breaks most scripts, so set it last)" }
$vbs = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity'
if ($vbs -ne 1) { Check 'Virtualization-based security not enabled (DeviceGuard\EnableVirtualizationBasedSecurity; scored on a practice image)' }
$idle = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
if ($null -eq $idle) { Check ("{0,-62} not set (want 1-900)" -f 'Interactive logon: machine inactivity limit (seconds)') }
elseif ($idle -ge 1 -and $idle -le 900) { Good ("{0,-62} = {1}" -f 'Interactive logon: machine inactivity limit (seconds)', $idle) }
else { Flag ("{0,-62} = {1}  (want 1-900)" -f 'Interactive logon: machine inactivity limit (seconds)', $idle) }
$hku = Get-RegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
if ($hku -eq 1) { Flag 'HKCU AlwaysInstallElevated = 1' }

# ---------------------------------------------------------------- GROUP POLICY (Administrative Templates)
Section 'GROUP POLICY: every configured Administrative Template setting (Registry.pol)'
Info 'Same list as gpedit.msc > Administrative Templates > All Settings, sorted by State. Compare each with a baseline:'
Info 'many are legitimate, but planted ones (firewall off, Defender off, updates off, RDP without NLA...) hide here.'
function Read-PolString([byte[]]$b, [ref]$pos) {
    $start = $pos.Value
    while ($pos.Value + 1 -lt $b.Length -and ($b[$pos.Value] -ne 0 -or $b[$pos.Value + 1] -ne 0)) { $pos.Value += 2 }
    $s = [Text.Encoding]::Unicode.GetString($b, $start, $pos.Value - $start)
    $pos.Value += 2
    return $s
}
function Read-PolFile([string]$path) {
    # Registry.pol format: 'PReg' + version, then entries [key;value;type;size;data] in UTF-16
    $b = [IO.File]::ReadAllBytes($path)
    if ($b.Length -lt 8 -or [Text.Encoding]::ASCII.GetString($b, 0, 4) -ne 'PReg') { return @() }
    $p = 8
    $out = @()
    while ($p + 2 -le $b.Length -and $b[$p] -eq 0x5B) {
        $p += 2
        $key  = Read-PolString $b ([ref]$p); $p += 2
        $name = Read-PolString $b ([ref]$p); $p += 2
        $type = [BitConverter]::ToUInt32($b, $p); $p += 6
        $size = [BitConverter]::ToUInt32($b, $p); $p += 6
        $data = [byte[]]@()
        if ($size -gt 0) { $data = [byte[]]$b[$p..($p + $size - 1)] }
        $p += $size + 2
        $val = switch ($type) {
            1       { [Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }
            2       { [Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }
            7       { ([Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0)) -replace "`0", ' | ' }
            4       { if ($size -ge 4) { [BitConverter]::ToUInt32($data, 0) } }
            11      { if ($size -ge 8) { [BitConverter]::ToUInt64($data, 0) } }
            default { ($data | ForEach-Object { $_.ToString('X2') }) -join '' }
        }
        $out += [pscustomobject]@{ Key = $key; Name = $name; Value = $val }
    }
    return $out
}
$polFiles = @(Get-ChildItem "$env:windir\System32\GroupPolicy\Machine\Registry.pol","$env:windir\System32\GroupPolicy\User\Registry.pol","$env:windir\System32\GroupPolicyUsers\*\User\Registry.pol" -Force -ErrorAction SilentlyContinue)
if ($isDC) { $polFiles += @(Get-ChildItem "$env:SystemRoot\SYSVOL\sysvol\*\Policies\*\*\Registry.pol" -Force -ErrorAction SilentlyContinue) }
if ($polFiles.Count -eq 0) { Good 'No Registry.pol files: no Administrative Template settings are configured locally' }
foreach ($pf in $polFiles) {
    $label = $pf.FullName
    if ($isDC -and $pf.FullName -match '\{([0-9A-Fa-f-]{36})\}') { $g = Get-GPO -Guid $Matches[1] -ErrorAction SilentlyContinue; if ($g) { $label = "GPO '$($g.DisplayName)'  $($pf.FullName)" } }
    Out-Line ''
    Info $label
    foreach ($e in Read-PolFile $pf.FullName) { Check ("{0} \ {1} = {2}" -f $e.Key, $e.Name, $e.Value) }
}
Info 'Local Group Policy scripts (startup/shutdown/logon/logoff):'
$lgpScripts = Get-ChildItem "$env:windir\System32\GroupPolicy\*\Scripts" -Recurse -File -Force -ErrorAction SilentlyContinue
if ($lgpScripts) { foreach ($f in $lgpScripts) { Flag "$($f.FullName)"; if ($f.Extension -eq '.ini') { Get-Content $f.FullName | Where-Object { $_.Trim() } | ForEach-Object { Info "        $_" } } } } else { Info '    none' }

# ---------------------------------------------------------------- DEFENSIVE COUNTERMEASURES
Section 'DEFENSIVE COUNTERMEASURES (firewall, Defender, SMB, RDP)'
$mps = Get-Service MpsSvc
if ($mps -and $mps.Status -ne 'Running') { Flag "The firewall service (MpsSvc) is $($mps.Status) / $($mps.StartType) - the firewall is not filtering anything, whatever the profiles say" }
$mpsDep = @((Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc').GetValue('DependOnService', $null)) | Where-Object { $_ }
if (@($mpsDep | Where-Object { $_ -notin 'mpsdrv', 'bfe' }).Count) { Flag "MpsSvc depends on $($mpsDep -join ', ') (Windows default: mpsdrv, bfe). A planted dependency that never starts keeps the firewall off: sc.exe config MpsSvc depend= mpsdrv/bfe" }
foreach ($p in Get-NetFirewallProfile) {
    if ($p.Enabled -eq 'True' -or $p.Enabled -eq $true) { Good "Firewall $($p.Name) profile enabled (inbound default: $($p.DefaultInboundAction))" } else { Flag "Firewall $($p.Name) profile is OFF" }
    if ([string]$p.DefaultInboundAction -eq 'Allow') { Flag "Firewall $($p.Name) profile ALLOWS inbound connections that match no rule (should be Block)" }
}
foreach ($pp in 'DomainProfile','PrivateProfile','PublicProfile') {
    if ((Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$pp" 'DefaultInboundAction') -eq 0) { Flag "Group Policy makes the $pp firewall ALLOW unmatched inbound connections (WindowsFirewall\$pp DefaultInboundAction=0)" }
}
foreach ($pp in 'DomainProfile','PrivateProfile','PublicProfile') {
    $v = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$pp" 'EnableFirewall'
    if ($v -eq 0) { Flag "Group Policy turns the firewall OFF for $pp (HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$pp EnableFirewall=0)" }
}
Info 'Enabled inbound ALLOW rules that are not built-in Windows groups (review against README):'
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { -not $_.Group -or $_.Group -notlike '@*' } |
    Select-Object -First 40 DisplayName, Profile, @{n='Program';e={($_ | Get-NetFirewallApplicationFilter).Program}}, @{n='Port';e={($_ | Get-NetFirewallPortFilter).LocalPort}} |
    ForEach-Object { Check ("{0,-45} {1,-18} port {2,-10} {3}" -f $_.DisplayName, $_.Profile, ($_.Port -join ','), $_.Program) }

$mp = Get-MpComputerStatus
if ($mp) {
    if ($mp.AntivirusEnabled)          { Good 'Defender antivirus enabled' } else { Flag 'Defender antivirus is DISABLED' }
    if ($mp.RealTimeProtectionEnabled) { Good 'Defender real-time protection on' } else { Flag 'Defender real-time protection is OFF' }
    Info "Tamper protection: $($mp.IsTamperProtected)   Signatures: $($mp.AntivirusSignatureLastUpdated)"
} else { Flag 'Could not query Defender (service stopped or removed?)' }
$pref = Get-MpPreference
foreach ($n in 'ExclusionPath','ExclusionProcess','ExclusionExtension','ExclusionIpAddress') {
    if ($pref.$n) { Check "Defender $n : $($pref.$n -join '; ')   (remove unless it is the scoring engine, e.g. C:\aeacus on some practice images)" }
}
foreach ($x in @($pref.ExclusionPath) | Where-Object { $_ -match '^[A-Za-z]:\\?$' }) { Flag "Defender excludes the whole $x drive" }
foreach ($x in @(@($pref.ExclusionPath) + @($pref.ExclusionProcess)) | Where-Object { $_ -match '(?i)\.(exe|dll|ps1|bat|cmd|vbs|js|scr|sys)$' -and $_ -notmatch '(?i)\\aeacus\\' } | Select-Object -Unique) {
    Flag "Defender excludes one specific program: $x  (malware often whitelists itself - look at that file)"
}
$defPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
foreach ($n in 'DisableAntiSpyware','DisableAntiVirus') { if ((Get-RegValue $defPol $n) -eq 1) { Flag "Policy $n = 1 (Defender disabled by policy)" } }
foreach ($n in 'DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableOnAccessProtection','DisableScanOnRealtimeEnable','DisableIOAVProtection','DisableScriptScanning') {
    if ((Get-RegValue "$defPol\Real-Time Protection" $n) -eq 1) { Flag "Policy Real-Time Protection\$n = 1" }
}
# 'Specify threat alert levels at which default action should not be taken': value name = level (4 high, 5 severe), data 6 = ignore/allow
$tsda = Get-Item -LiteralPath "$defPol\Threats\ThreatSeverityDefaultAction" -ErrorAction SilentlyContinue
if ($tsda) {
    foreach ($lvl in $tsda.GetValueNames()) {
        $lvlName = switch ($lvl) { '1' {'low'} '2' {'moderate'} '4' {'high'} '5' {'severe'} default { $lvl } }
        if ([string]$tsda.GetValue($lvl) -in '6','9') { Flag "Policy tells Defender to IGNORE $lvlName threats (Threats\ThreatSeverityDefaultAction\$lvl = $($tsda.GetValue($lvl)))" }
    }
}
if ((Get-RegValue "$defPol\Spynet" 'SpynetReporting') -eq 0) { Flag 'Policy turns off cloud-delivered protection (Spynet\SpynetReporting = 0)' }
if ($pref) {
    if ($pref.MAPSReporting -eq 0) { Check 'Cloud-delivered protection (MAPS) is off' }
    if ($pref.PUAProtection -ne 1) { Check 'Potentially unwanted app (PUA) blocking is off' }
    foreach ($n in 'DisableScriptScanning','DisableBehaviorMonitoring','DisableIOAVProtection','DisableRealtimeMonitoring','DisableBlockAtFirstSeen') {
        if ($pref.$n -eq $true) { Flag "Defender setting $n = True" }
    }
    foreach ($lv in 'Severe','High','Moderate','Low') {
        $a = $pref."${lv}ThreatDefaultAction"
        if ($a -in 6, 9) { $txt = "Defender default action for $lv threats = $(if ($a -eq 6) {'Allow'} else {'NoAction'})"; if ($lv -in 'Severe','High') { Flag $txt } else { Check $txt } }
    }
    if ($pref.EnableControlledFolderAccess -ne 1) { Check 'Controlled folder access is off (test before enabling: it can stop README apps from saving to Documents)' }
    $asrIds = @(@($pref.AttackSurfaceReductionRules_Ids) | Where-Object { $_ })   # @() keeps a single rule as a list
    $asrAct = @($pref.AttackSurfaceReductionRules_Actions)
    if ($asrIds.Count -eq 0) { Check 'No Attack Surface Reduction (ASR) rules configured' }
    for ($i = 0; $i -lt $asrIds.Count; $i++) {
        $act = switch ([int]$asrAct[$i]) { 0 {'Disabled'} 1 {'Block'} 2 {'Audit'} 6 {'Warn'} default { $asrAct[$i] } }
        if ($act -eq 'Disabled') { Check "ASR rule $($asrIds[$i]) is set to Disabled" } else { Info "ASR rule $($asrIds[$i]) = $act" }
    }
    if ($pref.AttackSurfaceReductionOnlyExclusions) { Check "ASR exclusions: $($pref.AttackSurfaceReductionOnlyExclusions -join '; ')" }
}

$bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
if ($bl) { if ($bl.ProtectionStatus -ne 'On') { Check "BitLocker on C: is $($bl.VolumeStatus) / protection $($bl.ProtectionStatus) (some images score turning it on - only if the README allows)" } else { Good 'BitLocker protects C:' } }
else {
    $mb = (manage-bde -status C: 2>$null) -join ' '
    if ($mb -match 'Protection Status:\s+Protection (On|Off)') { if ($Matches[1] -ne 'On') { Check 'BitLocker protection on C: is OFF (some images score turning it on - only if the README allows)' } }
    else { Info 'BitLocker: not available on this system (feature not installed)' }
}

Info 'Exploit protection (Windows Security > App & browser control > Exploit protection):'
$sysMit = Get-ProcessMitigation -System
if ($sysMit) {
    $pairs = @(@('DEP', $sysMit.Dep.Enable), @('CFG', $sysMit.Cfg.Enable), @('SEHOP', $sysMit.SEHOP.Enable),
               @('Bottom-up ASLR', $sysMit.Aslr.BottomUp), @('High-entropy ASLR', $sysMit.Aslr.HighEntropy), @('Mandatory ASLR', $sysMit.Aslr.ForceRelocateImages))
    foreach ($pr in $pairs) { if ([string]$pr[1] -eq 'OFF') { Flag "System exploit protection: $($pr[0]) is OFF" } else { Info ("    {0,-18} {1}" -f $pr[0], $pr[1]) } }
}
foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue) {
    if ($null -eq $k.GetValue('MitigationOptions', $null)) { continue }
    $m = Get-ProcessMitigation -Name $k.PSChildName
    if (-not $m) { continue }
    $off = @()
    if ([string]$m.Dep.Enable -eq 'OFF') { $off += 'DEP' }
    if ([string]$m.Cfg.Enable -eq 'OFF') { $off += 'CFG' }
    if ([string]$m.Aslr.BottomUp -eq 'OFF') { $off += 'BottomUp ASLR' }
    if ([string]$m.Aslr.HighEntropy -eq 'OFF') { $off += 'HighEntropy ASLR' }
    if ([string]$m.SEHOP.Enable -eq 'OFF') { $off += 'SEHOP' }
    if ($off) { Check "Exploit protection override for $($k.PSChildName): $($off -join ', ') OFF" }
}
$bcd = bcdedit /enum '{current}' 2>$null
foreach ($bk in 'debug','bootdebug','testsigning','nointegritychecks') {
    if ($bcd | Select-String -Pattern "^\s*$bk\s+Yes") { Flag "Boot option '$bk' is ON (bcdedit /set {current} $bk off)" }
}
$nxLine = $bcd | Select-String -Pattern '^\s*nx\s+(\S+)'
if ($nxLine) {
    $nx = $nxLine.Matches[0].Groups[1].Value
    if ($nx -eq 'AlwaysOff') { Flag 'DEP is AlwaysOff (bcdedit nx)' } elseif ($nx -eq 'OptIn') { Check 'DEP is OptIn (Windows client default). The guide recommends OptOut: sysdm.cpl > Advanced > Performance > Data Execution Prevention' } else { Info "    DEP (bcdedit nx): $nx" }
}
foreach ($lp in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers','HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers') {
    $lk = Get-Item -LiteralPath $lp -ErrorAction SilentlyContinue
    if ($lk) { foreach ($n in $lk.GetValueNames()) { if ([string]$lk.GetValue($n) -match 'DisableNX') { Flag "DEP exception for $n" } } }
}
$hvci = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled'
Info "    Memory integrity (HVCI) registry value: $(if ($null -eq $hvci) {'not set'} else {$hvci})  (may not be supported inside a VM)"

Info 'Firewall rules pushed by Group Policy (these override local rules):'
$gpRules = @(Get-NetFirewallRule -PolicyStore RSOP -ErrorAction SilentlyContinue)
if ($gpRules.Count -gt 0) { foreach ($r in $gpRules) { Check ("GP firewall rule: {0}  {1} {2} enabled={3}" -f $r.DisplayName, $r.Direction, $r.Action, $r.Enabled) } } else { Info '    none' }

$smb = Get-SmbServerConfiguration
if ($smb) {
    if ($smb.EnableSMB1Protocol) { Flag 'SMBv1 is enabled on the SMB server' } else { Good 'SMBv1 server disabled' }
    if (-not $smb.RequireSecuritySignature) { Check 'SMB server does not require signing' }
    if (-not $smb.EnableSMB2Protocol) { Flag 'SMBv2/3 server is DISABLED (this has been a penalty when SMB is needed)' }
    if (-not $smb.EncryptData) { Check 'SMB encryption (EncryptData) is off' }
    Info ("    SMB server: SMB1={0} SMB2={1} RequireSigning={2} EncryptData={3} RejectUnencrypted={4}" -f $smb.EnableSMB1Protocol, $smb.EnableSMB2Protocol, $smb.RequireSecuritySignature, $smb.EncryptData, $smb.RejectUnencryptedAccess)
}
if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb20' 'Start') -eq 4) { Flag 'SMBv2/3 CLIENT driver (mrxsmb20) is disabled - this was a 5-point penalty' }
$lw = Get-Service LanmanWorkstation
if ($lw -and $lw.StartType -eq 'Disabled') { Flag 'Workstation service (SMB client) is Disabled' }
$rdpOff = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
if ($rdpOff -eq 0) {
    Check 'Remote Desktop is ON. Keep it only if the README needs it.'
    $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($nla -ne 1) { Flag 'RDP does not require Network Level Authentication' }
    $lvl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer'
    if ($lvl -ne 2) { Check "RDP SecurityLayer = $lvl (2 = TLS)" }
    $tsp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    if ((Get-RegValue $tsp 'fEncryptRPCTraffic') -ne 1) { Check 'RDP: "Require secure RPC communication" is not enabled (Terminal Services\fEncryptRPCTraffic)' }
    if ((Get-RegValue $tsp 'MinEncryptionLevel') -lt 3) { Check 'RDP: client connection encryption level is not High (Terminal Services\MinEncryptionLevel = 3)' }
} else { Info 'Remote Desktop is off' }
$tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
if ((Get-RegValue $tsPol 'UserAuthentication') -eq 0) { Flag 'Group Policy turns OFF RDP Network Level Authentication (Terminal Services\UserAuthentication = 0)' }
if ((Get-RegValue $tsPol 'fDenyTSConnections') -eq 0) { Check 'Group Policy forces Remote Desktop ON (Terminal Services\fDenyTSConnections = 0)' }
$wrm = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM'
foreach ($side in 'Service','Client') {
    if ((Get-RegValue "$wrm\$side" 'AllowBasic') -eq 1) { Flag "WinRM $side allows Basic authentication" }
    if ((Get-RegValue "$wrm\$side" 'AllowUnencryptedTraffic') -eq 1) { Flag "WinRM $side allows unencrypted traffic" }
}

Info 'Optional features that are usually unwanted:'
foreach ($f in 'SMB1Protocol','MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2','TelnetClient','TFTP','IIS-FTPServer','SimpleTCP','Printing-Foundation-LPDPrintService') {
    $feat = Get-WindowsOptionalFeature -Online -FeatureName $f
    if ($feat -and $feat.State -eq 'Enabled') { if ($f -like 'IIS-*') { Check "$f is enabled (fine only if README needs FTP)" } else { Flag "Optional feature $f is enabled" } }
}
if ($productType -ne 1) {
    Info 'Installed server roles/features:'
    Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object { Info "    $($_.Name)  ($($_.DisplayName))" }
}

# ---------------------------------------------------------------- SERVICES
Section 'SERVICE AUDITING'
$svcs = Get-CimInstance Win32_Service
$review = @{ 'TlntSvr'='Telnet server'; 'RemoteRegistry'='Remote Registry'; 'SNMP'='SNMP'; 'SNMPTRAP'='SNMP Trap'; 'SSDPSRV'='SSDP Discovery'; 'upnphost'='UPnP Device Host';
             'ftpsvc'='IIS FTP'; 'W3SVC'='IIS web'; 'TermService'='Remote Desktop'; 'Spooler'='Print Spooler'; 'simptcp'='Simple TCP/IP'; 'iprip'='RIP Listener';
             'WebClient'='WebDAV client'; 'RemoteAccess'='Routing and Remote Access'; 'SharedAccess'='Internet Connection Sharing'; 'Fax'='Fax';
             'sshd'='OpenSSH server'; 'FileZilla Server'='FileZilla FTP'; 'MSSQLSERVER'='SQL Server'; 'MySQL'='MySQL'; 'CertSvc'='AD Certificate Services';
             'WinRM'='Windows Remote Management'; 'XblGameSave'='Xbox'; 'lfsvc'='Geolocation'; 'NetTcpPortSharing'='Net.Tcp Port Sharing'; 'TapiSrv'='Telephony';
             'Browser'='Computer Browser'; 'p2psvc'='Peer Networking'; 'icssvc'='Mobile hotspot'; 'WMSVC'='IIS Web Management'; 'MSFTPSVC'='old IIS FTP' }
Info 'Services worth a README decision (state / start mode):'
foreach ($s in $svcs) {
    if ($review.ContainsKey($s.Name)) { Check ("{0,-22} {1,-28} {2,-8} {3}" -f $s.Name, $review[$s.Name], $s.State, $s.StartMode) }
}
Out-Line ''
Info 'Services whose binary is NOT under C:\Windows or Program Files (look closely at each):'
foreach ($s in $svcs) {
    $p = [string]$s.PathName
    if (-not $p) { continue }
    $exe = if ($p -match '^"?([^"]+?\.(exe|com|bat|cmd))') { $Matches[1] } elseif ($p.StartsWith('"')) { $p.Split('"')[1] } else { $p.Split(' ')[0] }
    if ($exe -notmatch '^(?i)(C:\\Windows\\|C:\\Program Files|C:\\ProgramData\\Microsoft\\Windows Defender)' -and $exe -notmatch '^(?i)\\SystemRoot\\|^system32\\') {
        if (Is-Engine $p) { Info ("    {0,-22} {1,-8} {2}   <- scoring engine: leave it alone" -f $s.Name, $s.State, $p) }
        else { Flag ("{0,-22} {1,-8} {2}" -f $s.Name, $s.State, $p) }
    }
    if (-not $p.StartsWith('"') -and $p -match '^[A-Za-z]:\\[^"]* [^"]*\.exe' -and $p -notmatch '^(?i)C:\\Windows\\') {
        Check "Unquoted service path with a space: $($s.Name) -> $p"
    }
}
# Malware swapped into a built-in service: the service still has a ServiceDll (it belongs in svchost) but runs some other exe,
# or its exe sits in an unusual folder under C:\Windows (e.g. C:\Windows\Globalization\Sorting\...).
foreach ($s in $svcs) {
    $p = [string]$s.PathName
    if (-not $p) { continue }
    $sdll = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" 'ServiceDll'
    if ($sdll -and $p -notmatch '(?i)\\(svchost|lsass)\.exe') { Flag "Service $($s.Name) has a ServiceDll (normally runs in svchost) but runs: $p" }   # EFS, KeyIso, Netlogon, VaultSvc run in lsass
    $exe = if ($p -match '^"?([^"]+?\.(exe|com|bat|cmd))') { $Matches[1] } else { $p.Split(' ')[0] }
    if ($exe -match '^(?i)C:\\Windows\\' -and $exe -notmatch '^(?i)C:\\Windows\\(System32|SysWOW64|Microsoft\.NET|servicing|ADWS|WinSxS|PSSDNSvc|vss|CCM|ccmsetup|SystemApps|ImmersiveControlPanel|explorer\.exe)') {
        Check "Service $($s.Name) runs from an unusual Windows folder: $p"
    }
}
foreach ($s in $svcs | Where-Object { $_.PathName -match '(?i)\\(cmd|powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|nc|ncat)\.exe' -and $_.Name -notmatch '^(?i)(WinDefend|Sense)$' }) {
    Flag "Service $($s.Name) runs a shell/LOLBin: $($s.PathName)"
}

Out-Line ''
Info 'Services that should be running (a stopped one may be the vulnerability, or will break things):'
$mustRun = 'EventLog','MpsSvc','BFE','WinDefend','RpcSs','Dnscache'
if ($isDC) { $mustRun += 'NTDS','ADWS','Kdc','Netlogon','LanmanServer','LanmanWorkstation','W32Time','DFSR'; if (Get-Service DNS) { $mustRun += 'DNS' } }
foreach ($n in $mustRun) {
    $s = Get-Service $n
    if (-not $s) { if ($n -ne 'WinDefend') { Flag "Service $n is missing" } else { Check 'Defender service (WinDefend) not present' }; continue }
    if ($s.StartType -eq 'Disabled' -or $s.Status -ne 'Running') {
        Flag ("{0,-18} {1} / {2}  <- should be running{3}" -f $n, $s.Status, $s.StartType, $(if ($isDC -and $n -in 'NTDS','ADWS','Kdc','Netlogon','DNS','DFSR') {' (Active Directory needs it)'} else {''}))
        # The Service Control Manager logs why a start failed (7000/7001/7023/7024); show the latest one for this service.
        $why = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000, 7001, 7003, 7023, 7024 } -MaxEvents 300 -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match [regex]::Escape($s.DisplayName) } | Select-Object -First 1
        if ($why) { Info ("        last start error ({0:g}): {1}" -f $why.TimeCreated, ($why.Message -replace '\s+', ' ')) }
        foreach ($dep in @($s.ServicesDependedOn)) { if ($dep.Status -ne 'Running') { Info "        depends on $($dep.Name), which is $($dep.Status) / $($dep.StartType)" } }
        $img = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$n" 'ImagePath'
        Info "        ImagePath: $img"
    }
}
if ($isDC) { $sp = Get-Service Spooler; if ($sp -and $sp.Status -eq 'Running') { Flag 'Print Spooler is running on a domain controller (PrintNightmare). Disable it unless the README needs printing.' } }
foreach ($n in 'wuauserv','W32Time','BITS','CryptSvc','LanmanWorkstation') { $s = Get-Service $n; if ($s -and $s.StartType -eq 'Disabled') { Flag "$n is Disabled (should not be)" } }

Info 'Hidden services (in the registry but invisible to services.msc / Get-Service):'
$scm = @{}
foreach ($s in Get-Service) { $scm[$s.Name.ToLower()] = $true }
$hiddenFound = $false
foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services') {
    $t = $k.GetValue('Type', $null); $img = $k.GetValue('ImagePath', $null)
    if ($null -eq $t -or -not $img) { continue }
    if (($t -band 0x30) -and -not ($t -band 0xC0) -and -not $scm.ContainsKey($k.PSChildName.ToLower())) { Flag "Hidden service: $($k.PSChildName) -> $img"; $hiddenFound = $true }
}
if (-not $hiddenFound) { Info '    none' }

Info 'Kernel drivers outside the Windows driver folders, or known attack drivers (mimikatz mimidrv, vulnerable-driver kits):'
$drvFound = $false
foreach ($drv in Get-CimInstance Win32_SystemDriver) {
    $drvPath = [string]$drv.PathName
    $drvBad = ($drv.Name -match '(?i)^(mimidrv|mimikatz|kprocesshacker|rtcore64|gdrv|dbutil_2_3|winring0|capcom|iqvw64e|asrdrv)') -or ($drvPath -match '(?i)mimidrv|mimikatz')
    $drvFile = $drvPath -replace '^\\\?\?\\', '' -replace '^(?i)\\SystemRoot\\', "$env:SystemRoot\"
    if (-not $drvBad -and $drvFile -and [IO.File]::Exists($drvFile)) {
        $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($drvFile)
        if ("$($vi.CompanyName) $($vi.ProductName) $($vi.OriginalFilename) $($vi.InternalName)" -match $mimiRx) { $drvBad = $true }
    }
    $drvOdd = $drvPath -and $drvPath -notmatch '(?i)^(\\\?\?\\)?(C:\\Windows\\(System32|SysWOW64)\\(drivers|DriverStore)\\|C:\\Windows\\System32\\[^\\]+\.sys$|C:\\ProgramData\\Microsoft\\Windows Defender\\)'
    if ($drvBad) { Flag "Attack driver: $($drv.Name) ($($drv.State), $($drv.StartMode)) -> $drvPath"; $drvFound = $true }
    elseif ($drvOdd -and $drv.StartMode -ne 'Disabled') { Check ("Driver {0,-20} {1,-8} {2,-7} {3}" -f $drv.Name, $drv.State, $drv.StartMode, $drvPath); $drvFound = $true }
}
if (-not $drvFound) { Info '    none' }

Info 'Services with a DENY entry in their permissions (locked services, sc sdshow):'
foreach ($s in Get-Service) {
    $sd = (sc.exe sdshow $s.Name 2>$null) -join ''
    if ($sd -match '\(D;') { Check "$($s.Name): $sd" }
}

# ---------------------------------------------------------------- PERSISTENCE / MALWARE
Section 'MALWARE + PERSISTENCE'
Info 'Accessibility-binary backdoors (sticky keys etc.):'
$ref = @{}
foreach ($r in 'System32\cmd.exe','System32\WindowsPowerShell\v1.0\powershell.exe','explorer.exe','System32\taskmgr.exe') { $h = (Get-FileHash "$env:windir\$r").Hash; if ($h) { $ref[$h] = $r } }
foreach ($b in 'sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe','EaseOfAccessDialog.exe') {
    $path = "$env:windir\System32\$b"
    if (-not (Test-Path $path)) { continue }
    $h = (Get-FileHash $path).Hash
    if ($ref.ContainsKey($h)) { Flag "$b is really $($ref[$h]) - BACKDOOR" }
    $sig = Get-AuthenticodeSignature $path
    if ($sig.Status -ne 'Valid') { Flag "$b signature status: $($sig.Status)" }
}
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($k in Get-ChildItem $ifeo) {
    $dbg = $k.GetValue('Debugger', $null)
    if ($dbg) { Flag "IFEO debugger: $($k.PSChildName) -> $dbg" }
    $gf = $k.GetValue('GlobalFlag', $null)
    if ($gf -eq 512) { Flag "IFEO GlobalFlag 0x200 (SilentProcessExit hook) on $($k.PSChildName)" }
}
foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') {
    Flag "SilentProcessExit monitor: $($k.PSChildName) -> $($k.GetValue('MonitorProcess',''))"
}

$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$shell = Get-RegValue $wl 'Shell'; $uinit = Get-RegValue $wl 'Userinit'
if ($shell -and $shell -notmatch '^(?i)explorer\.exe$') { Flag "Winlogon Shell = '$shell' (should be explorer.exe)" }
if ($uinit -and $uinit -notmatch '^(?i)C:\\Windows\\system32\\userinit\.exe,?$') { Flag "Winlogon Userinit = '$uinit' (should be C:\Windows\system32\userinit.exe,)" }
if ((Get-RegValue $wl 'AutoAdminLogon') -eq '1') { Flag "AutoAdminLogon = 1: Windows signs in automatically as '$(Get-RegValue $wl 'DefaultUserName')'" }
$dpw = Get-RegValue $wl 'DefaultPassword'
if ($dpw) { Flag "Winlogon DefaultPassword stores a password in plain text: '$dpw' (could also be a forensics answer)" }
$appinit = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs'
if ($appinit) { Flag "AppInit_DLLs = '$appinit'" }
$notif = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'Notification Packages'
$odd = $notif | Where-Object { $_ -and $_ -notin 'scecli','rassfm' }
if ($odd) { Flag "LSA Notification Packages contains '$($odd -join ', ')' (password-filter backdoor?)" }

Out-Line ''
Info 'Run / RunOnce keys (every program here starts at logon):'
$runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
foreach ($sid in (Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }).PSChildName) {
    $runKeys += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
    $runKeys += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
}
foreach ($rk in $runKeys) {
    $k = Get-Item -LiteralPath $rk -ErrorAction SilentlyContinue
    if (-not $k) { continue }
    foreach ($n in $k.GetValueNames()) { Check ("{0}`n        {1} = {2}" -f $rk, $n, $k.GetValue($n)) }
}
Info 'Control Panel items registered as CPL files (a .cpl is a DLL that runs when Control Panel opens):'
$cplKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Cpls', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Control Panel\Cpls') +
           @((Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }).PSChildName | ForEach-Object { "Registry::HKEY_USERS\$_\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" })
$cplFound = $false
foreach ($ck in $cplKeys) {
    $k = Get-Item -LiteralPath $ck -ErrorAction SilentlyContinue
    if (-not $k) { continue }
    foreach ($n in $k.GetValueNames()) { $v = [string]$k.GetValue($n); $cplFound = $true; if ($v -match '(?i)^(%SystemRoot%|C:\\Windows)\\System32\\') { Info "    $n = $v" } else { Flag "CPL item $n = $v  ($ck)" } }
}
if (-not $cplFound) { Info '    none' }
Info 'Startup folders:'
$startup = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") + (Get-ChildItem 'C:\Users' -Directory | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
$wsh = New-Object -ComObject WScript.Shell
foreach ($sf in $startup) {
    Get-ChildItem $sf -File -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
        if ($_.Extension -eq '.lnk') {
            $lnk = $wsh.CreateShortcut($_.FullName)
            $tgt = "$($lnk.TargetPath) $($lnk.Arguments)".Trim()
            $tp = [string]$lnk.TargetPath
            $excluded = @(@($pref.ExclusionPath) + @($pref.ExclusionProcess) | Where-Object { $_ -and $tp -and $tp -ieq $_ }).Count -gt 0
            $unsignedWin = $tp -match '(?i)^C:\\Windows\\' -and ((-not (Test-Path -LiteralPath $tp)) -or (Get-AuthenticodeSignature -LiteralPath $tp).Status -ne 'Valid')
            if ($excluded -or $unsignedWin -or $tp -match '(?i)\\(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)\.exe$') {
                Flag "$($_.FullName) -> $tgt"
            } else { Check "$($_.FullName) -> $tgt" }
        } else { Check $_.FullName }
    }
}

Out-Line ''
Info 'Scheduled tasks outside \Microsoft\ (with what they run):'
$allTasks = @(Get-ScheduledTask)
$coreRx  = '(?i)(^|\\)(wininit|csrss|smss|lsass|services|winlogon|svchost)(\.exe)?$'   # never launched by a task; wininit = instant blue screen
$shellRx = '(?i)(^|\\)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)(\.exe)?$'
foreach ($t in $allTasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }) {
    $acts = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
    $line = "{0}{1}  [{2}]  -> {3}" -f $t.TaskPath, $t.TaskName, $t.State, $acts
    if (Is-Engine $acts) { Info "    $line   <- scoring engine" }
    elseif (@($t.Actions | Where-Object { $_.Execute -and [Environment]::ExpandEnvironmentVariables($_.Execute).Trim('"') -match $coreRx }).Count) { Flag "$line   (a task should never start a core Windows process; wininit.exe here means a blue screen)" }
    elseif ($t.TaskName -match '^(?i)Microsoft|OneDrive|Google|Adobe' -and @($t.Actions | Where-Object { $_.Execute -match $shellRx }).Count) { Flag "$line   (vendor-looking name, but it runs a shell)" }
    else { Check $line }
}
Info 'Tasks inside \Microsoft\ that run a shell or script (Microsoft''s own tasks almost never do - malware hides here):'
$msFound = $false
foreach ($t in $allTasks | Where-Object { $_.TaskPath -like '\Microsoft\*' }) {
    foreach ($a in @($t.Actions | Where-Object { $_.Execute })) {
        $exe = [Environment]::ExpandEnvironmentVariables($a.Execute).Trim('"')
        # rundll32/cscript are left out on purpose: several built-in tasks use them (Autochk Proxy, SystemRestore SR, CleanupOldPerfLogs).
        # Built-in tasks that run a .cmd from System32 through cmd (Software Inventory Logging: silcollector.cmd) are normal too.
        if ($exe -match '(?i)(^|\\)cmd(\.exe)?$' -and $a.Arguments -match '(?i)^(/d\s+)?/c\s+(%systemroot%|%windir%|C:\\Windows)\\system32\\[\w-]+\.cmd(\s+\w+)*\s*$') { continue }
        if ($exe -match '(?i)(^|\\)(powershell|pwsh|cmd|mshta|wscript|bitsadmin|certutil)(\.exe)?$' -or $exe -match $coreRx -or
            $a.Arguments -match '(?i)\.ps1\b|-enc(odedcommand)?\b|\s-e\s|frombase64string|downloadstring|downloadfile|\biex\b|invoke-expression|invoke-webrequest') {
            Flag ("{0}{1}  [{2}]  -> {3} {4}" -f $t.TaskPath, $t.TaskName, $t.State, $a.Execute, $a.Arguments); $msFound = $true
        }
    }
}
if (-not $msFound) { Info '    none' }
Info 'Hidden scheduled tasks (registry entry with no security descriptor):'
foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' -Recurse) {
    if ($k.GetValue('Id', $null) -and -not $k.GetValue('SD', $null)) { Flag "Hidden task: $($k.Name -replace '^.*\\Tree','')" }
}

Out-Line ''
Info 'WMI event subscriptions (fileless persistence):'
$wmiF = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
$wmiC = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
$wmiS = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer
foreach ($f in $wmiF | Where-Object { $_.Name -ne 'SCM Event Log Filter' }) { Flag "WMI filter '$($f.Name)': $($f.Query)" }
foreach ($c in $wmiC) { Flag "WMI command consumer '$($c.Name)': $($c.CommandLineTemplate)" }
foreach ($c in $wmiS) { Flag "WMI script consumer '$($c.Name)'" }

Info 'BITS jobs:'
Get-BitsTransfer -AllUsers | ForEach-Object { Check "BITS job '$($_.DisplayName)' owner $($_.OwnerAccount) state $($_.JobState)" }
Info 'Port proxies (netsh interface portproxy):'
$pp = netsh interface portproxy show all
$ppRules = @($pp | Where-Object { $_ -match '^\s*(\d+\.\d+\.\d+\.\d+|\*|[0-9a-f:]+)\s+\d+\s+' })
if ($ppRules.Count -gt 0) { foreach ($l in $ppRules) { Flag "portproxy: $($l.Trim())" } } else { Info '    none' }
Info 'PowerShell profile scripts (run every time PowerShell starts):'
foreach ($pf in "$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1","$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1") { if (Test-Path $pf) { Flag "Profile exists: $pf" } }
Get-ChildItem 'C:\Users\*\Documents\WindowsPowerShell\*profile.ps1' -Force | ForEach-Object { Check "User profile script: $($_.FullName)" }

Out-Line ''
Info 'Listening ports and the program behind each:'
Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess
    Info ("TCP {0,-6} pid {1,-6} {2,-22} {3}" -f $_.LocalPort, $_.OwningProcess, $proc.ProcessName, $proc.Path)
}
Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -in '0.0.0.0','::' } | Sort-Object LocalPort -Unique | Select-Object -First 25 | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess
    Info ("UDP {0,-6} pid {1,-6} {2}" -f $_.LocalPort, $_.OwningProcess, $proc.ProcessName)
}
foreach ($c in Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80)' }) {
    Check ("Outbound to {0}:{1} from {2}" -f $c.RemoteAddress, $c.RemotePort, (Get-Process -Id $c.OwningProcess).Path)
}

$hosts = Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -match '^\s*[^#\s]' }
if ($hosts) { foreach ($h in $hosts) { Flag "hosts file entry: $h" } } else { Good 'hosts file has no active entries' }

Info 'Shares:'
foreach ($sh in Get-SmbShare) {
    $default = $sh.Name -match '^(ADMIN\$|IPC\$|[A-Z]\$|print\$|SYSVOL|NETLOGON)$'
    $acc = Get-SmbShareAccess -Name $sh.Name | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }
    $line = "{0,-12} {1,-30} {2}" -f $sh.Name, $sh.Path, ($acc -join ', ')
    if ($default) { Info $line } else { Check $line }
    $broadRx = if ($default) { '^(Everyone|BUILTIN\\Guests|.*\\Guest|.*\\Domain Users)$' } else { '^(Everyone|BUILTIN\\Users|BUILTIN\\Guests|NT AUTHORITY\\Authenticated Users|.*\\Guest|.*\\Domain Users)$' }
    foreach ($a in Get-SmbShareAccess -Name $sh.Name | Where-Object { "$($_.AccessControlType)" -eq 'Allow' -and "$($_.AccessRight)" -in 'Full','Change' -and $_.AccountName -match $broadRx }) {
        Flag ("Share {0} gives {1} {2} access" -f $sh.Name, $a.AccountName, "$($a.AccessRight)".ToUpper())
    }
}

Info 'Executables in places they should not be:'
Get-ChildItem "$env:windir\System32\drivers\*" -File -Include *.exe,*.ps1,*.bat,*.vbs,*.cmd -Force | Where-Object { $_.Directory.Name -eq 'drivers' -and $_.Directory.Parent.Name -eq 'System32' } | ForEach-Object { Flag "Not a driver: $($_.FullName)" }
foreach ($dir in "$env:windir\Temp","C:\Users\Public","C:\PerfLogs","$env:ProgramData") {
    Get-ChildItem "$dir\*" -File -Include *.exe,*.ps1,*.bat,*.vbs,*.js,*.hta,*.scr -Force | ForEach-Object { Check $_.FullName }
}
Get-ChildItem 'C:\Users\*\AppData\Local\Temp\*','C:\Users\*\AppData\Roaming\*' -File -Include *.exe,*.ps1,*.bat,*.vbs,*.hta,*.scr -Force | Select-Object -First 40 | ForEach-Object { Check $_.FullName }

Out-Line ''
Info 'Running processes (what Process Explorer would show you):'
$procs = @(Get-CimInstance Win32_Process)
$byId = @{}
foreach ($p in $procs) { $byId[[int]$p.ProcessId] = $p }
$mine = @{}; $cur = [int]$PID
while ($cur -and $byId.ContainsKey($cur) -and -not $mine.ContainsKey($cur)) { $mine[$cur] = $true; $cur = [int]$byId[$cur].ParentProcessId }
foreach ($p in $procs) {
    if ($mine.ContainsKey([int]$p.ProcessId)) { continue }
    $parent = $byId[[int]$p.ParentProcessId]
    $pn = if ($parent) { $parent.Name } else { '(exited)' }
    if ($p.Name -match '^(?i)(cmd|powershell|pwsh|nc|nc64|ncat|cryptcat|python|pythonw|wscript|cscript|mshta)\.exe$') {
        Check ("Shell/script process {0} (pid {1}, parent {2}): {3}" -f $p.Name, $p.ProcessId, $pn, $p.CommandLine)
    }
    if ($p.ExecutablePath -match '(?i)\\(Temp|AppData|Users\\Public|PerfLogs)\\' -and $p.ExecutablePath -notmatch '(?i)\\AppData\\Local\\Microsoft\\|\\WindowsApps\\') { Check "Process running from a user/temp folder: $($p.ExecutablePath)" }
}
$procPaths = $procs | Where-Object { $_.ExecutablePath } | Select-Object -ExpandProperty ExecutablePath -Unique
foreach ($x in $procPaths) {
    if (Is-Engine $x) { continue }
    $sig = Get-AuthenticodeSignature -LiteralPath $x
    if ($sig.Status -ne 'Valid') {
        if ($x -match '^(?i)C:\\Windows\\') { Flag "Running from Windows folder but not validly signed ($($sig.Status)): $x" } else { Check "Running, not validly signed ($($sig.Status)): $x" }
    }
}

if ($Deep) {
    Info 'Unsigned executables in System32 / SysWOW64 (slow):'
    foreach ($dir in "$env:windir\System32","$env:windir\SysWOW64") {
        Get-ChildItem $dir -File -Filter *.exe | ForEach-Object {
            $s = Get-AuthenticodeSignature $_.FullName
            if ($s.Status -eq 'NotSigned' -or $s.Status -eq 'HashMismatch') { Flag "$($s.Status): $($_.FullName)" }
        }
    }
}

# ---------------------------------------------------------------- SOFTWARE + FILES
Section 'UNWANTED SOFTWARE + PROHIBITED FILES'
$uninstall = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
foreach ($sid in (Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }).PSChildName) { $uninstall += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }
$apps = Get-ItemProperty $uninstall | Where-Object { $_.DisplayName } | Sort-Object DisplayName -Unique
$badWords = 'wireshark|nmap|zenmap|\bcain\b|\babel\b|john the|hashcat|mimikatz|netcat|ncat|cryptcat|metasploit|burp|hydra|aircrack|angry ?ip|ophcrack|l0pht|sharphound|bloodhound|rubeus|lazagne|keylog|spy|teamviewer|anydesk|ammyy|vnc|radmin|utorrent|bittorrent|bitcomet|frostwire|limewire|tor browser|steam|epic games|minecraft|roblox|game|solitaire|pong|npcap|winpcap|ccleaner|driver ?booster|advanced ?systemcare|wise care|mcafee webadvisor|ask toolbar|babylon|conduit|cheat ?engine|shareaza|vuze|deluge|tixati|emule|kazaa|ettercap|kismet|netbus|back ?orifice|darkcomet|njrat|nikto|sqlmap|openvas'
Info 'Installed programs (name / version / publisher):'
foreach ($a in $apps) {
    $line = "{0,-55} {1,-18} {2}" -f $a.DisplayName, $a.DisplayVersion, $a.Publisher
    if ($a.DisplayName -match "(?i)$badWords") { Flag $line } else { Info $line }
}
Out-Line ''
Info 'Store apps (these never appear in Control Panel; remove with Get-AppxPackage <name> -AllUsers | Remove-AppxPackage -AllUsers):'
foreach ($ax in Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { -not $_.IsFramework -and "$($_.SignatureKind)" -ne 'System' } | Sort-Object Name -Unique) {
    $line = "{0,-50} {1,-16} {2}" -f $ax.Name, $ax.Version, (($ax.Publisher -split ',')[0] -replace '^CN=')
    $junk = $ax.Name -match "(?i)$badWords|candy|bubble|king\.com|zynga|roblox|minecraft|asphalt|farm|disney|tiktok|torrent"
    if ($ax.Publisher -notmatch 'Microsoft') { if ($junk) { Flag "Store app: $line" } else { Check "Store app (not Microsoft): $line" } }
    elseif ($junk) { Check "Store app from Microsoft (game?): $line" }
}
Out-Line ''
if (-not $Quick) {
    Info 'Hacking tools, media, archives and password-looking files (one fast pass, stops after 6 minutes):'
    $toolRx    = [regex]'(?i)^(nc|nc64|ncat|nmap|zenmap|wireshark)\.exe$|^(netcat|cryptcat|mimikatz|lazagne|hashcat|hydra|sharphound|rubeus|keylog)|^(procdump|psexec|john).*\.exe$|\.torrent$|crack|keygen'
    $mediaRx   = [regex]'(?i)\.(mp3|mp4|wav|flac|m4a|aac|ogg|wma|avi|mkv|mov|wmv|flv|webm|m4v|mpg|mpeg)$|\.(zip|7z|rar|tar|gz|iso|kdbx|pcap|pcapng)$|pass.*\.txt$|password|cred.*\.txt$|secret'
    $noMediaRx = [regex]'(?i)^C:\\(Program Files|Program Files \(x86\)|ProgramData)\\|\\AppData\\Local\\(Microsoft|Packages|Temp)\\|\\WindowsApps\\|\\CP-Audit'
    $skipDirRx = [regex]'(?i)\\SysinternalsSuite$|\\WinSxS$'
    $roots = @('C:\Users','C:\Program Files','C:\Program Files (x86)','C:\ProgramData') + @(Get-ChildItem C:\ -Directory -Force | Where-Object { $_.Name -notin 'Windows','Users','Program Files','Program Files (x86)','ProgramData','$Recycle.Bin','System Volume Information','Recovery','Boot','PerfLogs','Documents and Settings','$WinREAgent','Config.Msi','MSOCache' } | ForEach-Object { $_.FullName })
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $limit = [TimeSpan]::FromMinutes(6)
    $stack = New-Object System.Collections.Generic.Stack[string]
    [array]::Reverse($roots)   # a stack pops the last item first, so this searches C:\Users first
    foreach ($r in $roots) { if ([IO.Directory]::Exists($r)) { $stack.Push($r) } }
    $stack.Push('C:\')         # files sitting directly in C:\ (its folders are already in the list)
    $tools = 0; $mediaHits = 0; $scanned = 0
    while ($stack.Count -gt 0) {
        if ($clock.Elapsed -gt $limit) { Check ("File scan stopped after {0} minutes ({1:N0} files checked). Search the rest with Everything (voidtools)." -f [int]$limit.TotalMinutes, $scanned); break }
        $dir = $stack.Pop()
        try {
            foreach ($f in [IO.Directory]::EnumerateFiles($dir)) {
                $scanned++
                $name = [IO.Path]::GetFileName($f)
                $ext = [IO.Path]::GetExtension($name)
                if ($ext -in '.sys', '.exe', '.dll' -and ($ext -eq '.sys' -or -not $noMediaRx.IsMatch($f))) {
                    $vi = $null; try { $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($f) } catch { }
                    if ($vi -and "$($vi.CompanyName) $($vi.ProductName) $($vi.OriginalFilename) $($vi.InternalName)" -match $mimiRx) { $tools++; Flag "mimikatz file (found by its version info, whatever it is named): $f"; continue }
                    if ($ext -eq '.sys' -and -not $noMediaRx.IsMatch($f)) { Check "Driver file outside Windows: $f" }
                }
                if ($tools -lt 40 -and $toolRx.IsMatch($name)) { $tools++; Flag $f }
                elseif ($mediaHits -lt 80 -and $mediaRx.IsMatch($name) -and -not $noMediaRx.IsMatch($f)) {
                    $mediaHits++
                    Check ("{0,8:N0} KB  {1}" -f ((New-Object IO.FileInfo $f).Length / 1KB), $f)
                }
            }
            if ($dir -eq 'C:\') { continue }
            foreach ($d in [IO.Directory]::EnumerateDirectories($dir)) {
                if ($skipDirRx.IsMatch($d)) { continue }
                if (([IO.File]::GetAttributes($d) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                $stack.Push($d)
            }
        } catch { }   # access denied or path too long: skip that folder
    }
    Info ("    checked {0:N0} files in {1:N0} seconds" -f $scanned, $clock.Elapsed.TotalSeconds)
} else { Info 'Skipped the tool-name and media file searches (-Quick)' }

$webRoots = 'C:\inetpub','C:\xampp\htdocs','C:\wamp64\www','C:\nginx\html','C:\Apache24\htdocs'
foreach ($w in $webRoots | Where-Object { Test-Path $_ }) {
    Info "Web root $w :"
    $shown = 0
    Get-ChildItem $w -Recurse -File -Include *.php,*.asp,*.aspx,*.ashx,*.jsp,*.cfm -Force | ForEach-Object {
        $txt = Get-Content $_.FullName -Raw
        if ($txt -match 'phpinfo\s*\(') { Flag "phpinfo page (prohibited file): $($_.FullName)" }
        if ($shown -lt 25 -and $txt -match '(eval\s*\(|base64_decode|shell_exec|passthru|cmd\.exe|Process\.Start|WScript\.Shell)') { $shown++; Check "Possible web shell, read it: $($_.FullName)" }
    }
}

Out-Line ''
Info 'Per-user installs (AppData\Local\Programs) - these do not always show in Control Panel:'
Get-ChildItem 'C:\Users\*\AppData\Local\Programs' -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'Common' } | ForEach-Object { Check $_.FullName }
Info 'Hidden folders in Program Files / ProgramData and hidden files in user folders:'
foreach ($pf in 'C:\Program Files','C:\Program Files (x86)','C:\ProgramData') {
    Get-ChildItem $pf -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::Hidden) -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $_.Name -notin 'WindowsApps','Uninstall Information','ModifiableWindowsApps','Packages' } |
        ForEach-Object { Check "Hidden folder: $($_.FullName)" }
}
if (-not $Quick) {
    Get-ChildItem 'C:\Users\*\Desktop','C:\Users\*\Documents','C:\Users\*\Downloads','C:\Users\*\Music','C:\Users\*\Pictures','C:\Users\*\Videos' -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::Hidden) -and $_.Name -ne 'desktop.ini' -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
        Select-Object -First 40 | ForEach-Object { if ($_.Name -match $badWords) { Flag "Hidden item that looks like a tool or game: $($_.FullName)" } else { Check "Hidden item: $($_.FullName)" } }

    Info 'Alternate data streams (data hidden inside another file; Zone.Identifier is normal):'
    $adsRoots = @('C:\Users') + @($webRoots | Where-Object { Test-Path $_ })
    $adsFound = 0
    foreach ($r in $adsRoots) {
        Get-ChildItem $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\AppData\\' } | Select-Object -First 8000 | ForEach-Object {
            Get-Item -LiteralPath $_.FullName -Stream * -ErrorAction SilentlyContinue |
                Where-Object { $_.Stream -notin ':$DATA','Zone.Identifier','SmartScreen','{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}' } |
                ForEach-Object { $adsFound++; Flag ("ADS {0}:{1}  ({2} bytes)  read: Get-Content -LiteralPath '{0}' -Stream '{1}'" -f $_.FileName, $_.Stream, $_.Length) }
        }
    }
    if ($adsFound -eq 0) { Info '    none found in C:\Users or web roots (use streams.exe -s for other folders)' }
} else { Info 'Skipped hidden-file and alternate-data-stream searches (-Quick)' }

# ---------------------------------------------------------------- PERMISSIONS
Section 'PERMISSIONS (who can write where they should not)'
$okId    = '^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|NT SERVICE\\TrustedInstaller|CREATOR OWNER|APPLICATION PACKAGE AUTHORITY\\.*|.*\\Domain Admins|.*\\Enterprise Admins)$'
$writeRx = 'FullControl|Modify|Write|ChangePermissions|TakeOwnership|^268435456$|^1073741824$'
function Show-WriteAces([string]$path, [string]$skipRx) {
    if (Is-Engine $path) { return }
    $acl = Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $acl) { return }
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $id = $ace.IdentityReference.Value
        if ($id -match $okId) { continue }
        if ($skipRx -and $id -match $skipRx) { continue }
        if ([string]$ace.FileSystemRights -match $writeRx) { Flag ("{0}: {1} has {2}" -f $path, $id, $ace.FileSystemRights) }
    }
}
Show-WriteAces 'C:\' '^(BUILTIN\\Users|NT AUTHORITY\\Authenticated Users)$'
foreach ($p in 'C:\Program Files','C:\Program Files (x86)','C:\Windows','C:\Windows\System32','C:\Windows\SysWOW64') { Show-WriteAces $p '' }
foreach ($w in $webRoots + @('C:\inetpub\wwwroot','C:\inetpub\ftproot') | Select-Object -Unique) { if (Test-Path $w) { Show-WriteAces $w '' } }
Info 'Service programs outside C:\Windows that non-admins can overwrite (privilege escalation):'
foreach ($s in $svcs) {
    $p = [string]$s.PathName
    if (-not $p) { continue }
    $exe = if ($p -match '^"?([^"]+?\.(exe|com|bat|cmd))') { $Matches[1] } elseif ($p.StartsWith('"')) { $p.Split('"')[1] } else { $p.Split(' ')[0] }
    if ($exe -match '^(?i)C:\\Windows\\' -or -not (Test-Path -LiteralPath $exe)) { continue }
    Show-WriteAces $exe ''
}
Info 'User profile folders other people can open:'
foreach ($d in Get-ChildItem 'C:\Users' -Directory -Force | Where-Object { $_.Name -notin 'Public','Default','Default User','All Users' -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }) {
    $acl = Get-Acl -LiteralPath $d.FullName -ErrorAction SilentlyContinue
    if (-not $acl) { continue }
    $ownerName = $d.Name.Split('.')[0]
    foreach ($ace in $acl.Access) {
        $id = $ace.IdentityReference.Value
        if ($ace.AccessControlType -ne 'Allow' -or $id -match $okId -or ($id -split '\\')[-1] -ieq $ownerName) { continue }
        Check ("{0}: {1} has {2}" -f $d.FullName, $id, $ace.FileSystemRights)
    }
}

# ---------------------------------------------------------------- APPLICATION SECURITY
Section 'APPLICATION SECURITY: OpenSSH, IIS, browsers'
$sshd = "$env:ProgramData\ssh\sshd_config"
if (Test-Path $sshd) {
    Info "sshd_config ($sshd) active lines:"
    $cfg = @(Get-Content $sshd | Where-Object { $_ -match '^\s*[^#\s]' })
    foreach ($l in $cfg) { Info "    $l" }
    if ($cfg -match '^\s*PermitEmptyPasswords\s+yes') { Flag 'sshd: PermitEmptyPasswords yes' }
    if ($cfg -match '^\s*StrictModes\s+no') { Flag 'sshd: StrictModes no' }
    if (-not ($cfg -match '^\s*(AllowUsers|AllowGroups)\s')) { Check 'sshd: no AllowUsers/AllowGroups line, so every account can try to log in' }
    if ($cfg -match '^\s*PasswordAuthentication\s+yes') { Check 'sshd: password logins allowed (fine unless the README wants keys only)' }
    if ($cfg -match '^\s*(AllowTcpForwarding|GatewayPorts|PermitTunnel)\s+yes') { Check 'sshd: forwarding/tunnelling allowed' }
    Info '    (Server settings live in sshd_config. ssh_config is the client file.)'
} else { Info 'OpenSSH server not configured' }
$keyFiles = @("$env:ProgramData\ssh\administrators_authorized_keys") + @(Get-ChildItem 'C:\Users\*\.ssh\authorized_keys' -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
foreach ($kf in $keyFiles) {
    if (-not (Test-Path -LiteralPath $kf)) { continue }
    $keys = @(Get-Content -LiteralPath $kf | Where-Object { $_ -match '^\s*(ssh-|ecdsa-|sk-)' })
    Check ("SSH keys that can log in: {0} ({1} key(s): {2})" -f $kf, $keys.Count, (($keys | ForEach-Object { ($_ -split '\s+')[-1] }) -join ', '))
}

if (Get-Service W3SVC) {
    Out-Line ''
    Info 'IIS sites and app pools:'
    Import-Module WebAdministration
    function Get-IISVal($v) { if ($null -ne $v -and $v.PSObject.Properties['Value']) { return $v.Value } else { return $v } }
    foreach ($ap in Get-ChildItem IIS:\AppPools) {
        $idt = [string]$ap.processModel.identityType
        if ($idt -eq 'LocalSystem') { Flag "App pool '$($ap.Name)' runs as LocalSystem (a web shell would run as SYSTEM)" } else { Info "    App pool '$($ap.Name)': $idt" }
    }
    foreach ($site in Get-ChildItem IIS:\Sites) {
        $n = $site.Name; $ps = "IIS:\Sites\$n"
        $bind = ($site.Bindings.Collection | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) -join '; '
        Info "    Site '$n' -> $($site.PhysicalPath)  [$bind]"
        if ($bind -match 'http') {
            if (Get-IISVal (Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $ps)) { Flag "Site '$n': directory browsing is ON" }
            if ([string](Get-IISVal (Get-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -PSPath $ps)) -eq 'Detailed') { Flag "Site '$n': detailed error pages are shown to everyone" }
            if ($bind -notmatch 'https') { Check "Site '$n' has no HTTPS binding" }
        }
        if (-not (Get-IISVal (Get-ItemProperty $ps -Name logFile.enabled))) { Flag "Site '$n': logging is off" }
        if ($bind -match 'ftp') {
            if (Get-IISVal (Get-ItemProperty $ps -Name ftpServer.security.authentication.anonymousAuthentication.enabled)) { Flag "FTP site '$n' allows anonymous login" }
            $ssl = [string](Get-IISVal (Get-ItemProperty $ps -Name ftpServer.security.ssl.controlChannelPolicy))
            if ($ssl -ne 'SslRequire') { Check "FTP site '$n' SSL policy = $ssl (SslRequire is strongest)" }
        }
    }
}

Out-Line ''
Info 'Browsers:'
$cpol = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue
if ($cpol) {
    foreach ($n in $cpol.GetValueNames()) { Info "    Chrome policy $n = $($cpol.GetValue($n))" }
    foreach ($sub in Get-ChildItem $cpol.PSPath) {
        $vals = ($sub.GetValueNames() | ForEach-Object { $sub.GetValue($_) }) -join '; '
        if ($sub.PSChildName -eq 'ExtensionInstallForcelist') { Flag "Chrome FORCE-INSTALLS extensions: $vals" } else { Info "    Chrome policy list $($sub.PSChildName): $vals" }
    }
    if ($cpol.GetValue('SafeBrowsingProtectionLevel', $null) -eq 0) { Flag 'Chrome Safe Browsing turned off by policy' }
}
if ((Test-Path 'C:\Program Files\Google\Chrome\Application\chrome.exe') -or (Test-Path 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe')) {
    if (-not $cpol -or $cpol.GetValue('AdsSettingForIntrusiveAdsSites', $null) -ne 2) { Check 'Chrome does not block intrusive ads by policy (AdsSettingForIntrusiveAdsSites=2 was scored)' }
}
foreach ($pj in 'C:\Program Files\Mozilla Firefox\distribution\policies.json','C:\Program Files (x86)\Mozilla Firefox\distribution\policies.json') { if (Test-Path $pj) { Check "Firefox policies.json present - read it: $pj" } }
foreach ($ffDir in 'C:\Program Files\Mozilla Firefox','C:\Program Files (x86)\Mozilla Firefox') {
    if (-not (Test-Path "$ffDir\firefox.exe")) { continue }
    # AutoConfig can lock bad prefs or crash Firefox on start (mozilla.cfg + a defaults\pref\*.js that points at it)
    foreach ($ac in Get-ChildItem "$ffDir\defaults\pref\*.js", "$ffDir\*.cfg" -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'channel-prefs.js' }) { Flag "Firefox AutoConfig file: $($ac.FullName) - read it (locked prefs, startup crash)" }
    $ffPol = Get-Item 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' -ErrorAction SilentlyContinue
    if ($ffPol) { foreach ($n in $ffPol.GetValueNames()) { Info "    Firefox policy $n = $($ffPol.GetValue($n))" } }
    if (-not $ffPol -or $ffPol.GetValue('DisableFirefoxAccounts', $null) -ne 1) { Check 'Firefox: no policy disabling Firefox Accounts (DisableFirefoxAccounts was scored on a practice image)' }
}
$ffBad = [ordered]@{
    'dom.disable_open_during_load", false'          = 'pop-up blocker OFF'
    'browser.safebrowsing.malware.enabled", false'  = 'malware protection OFF'
    'browser.safebrowsing.phishing.enabled", false' = 'phishing protection OFF'
    'browser.safebrowsing.downloads.enabled", false'= 'dangerous download blocking OFF'
    'xpinstall.whitelist.required", false'          = 'no warning when sites install add-ons'
    'security.OCSP.enabled", 0'                     = 'OCSP certificate checking OFF'
}
foreach ($pjs in Get-ChildItem 'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\prefs.js','C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\user.js' -Force -ErrorAction SilentlyContinue) {
    if ($pjs.Name -eq 'user.js') { Check "Firefox user.js overrides prefs: $($pjs.FullName)" }
    $txt = Get-Content -LiteralPath $pjs.FullName -Raw
    foreach ($k in $ffBad.Keys) { if ($txt -match [regex]::Escape($k)) { Flag "Firefox $($ffBad[$k]) in $($pjs.FullName)" } }
}

# ---------------------------------------------------------------- UPDATES
Section 'OPERATING SYSTEM + APPLICATION UPDATES'
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
if ((Get-RegValue "$wu\AU" 'NoAutoUpdate') -eq 1) { Flag 'Automatic updates disabled by policy (AU\NoAutoUpdate=1)' }
$auo = Get-RegValue "$wu\AU" 'AUOptions'; if ($auo) { Info "AUOptions = $auo (4 = auto download and schedule install)" }
if ((Get-RegValue $wu 'DisableWindowsUpdateAccess') -eq 1) { Flag 'DisableWindowsUpdateAccess = 1' }
if ((Get-RegValue $wu 'DoNotConnectToWindowsUpdateInternetLocations') -eq 1) { Flag 'DoNotConnectToWindowsUpdateInternetLocations = 1' }
if ((Get-RegValue "$wu\AU" 'UseWUServer') -eq 1) { Check "Updates come from WSUS server '$(Get-RegValue $wu 'WUServer')' - is that legitimate?" }
foreach ($n in 'wuauserv','UsoSvc','BITS') { $s = Get-Service $n; if ($s.StartType -eq 'Disabled') { Flag "$n service is Disabled" } }
Info 'Last installed hotfixes:'
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 | ForEach-Object { Info "    $($_.HotFixID)  $($_.InstalledOn)" }
Info 'Application versions to update are in the Installed programs list above (Firefox, Chrome, Notepad++, 7-Zip, Thunderbird, etc.).'

if ($isDC -or (Get-Service DNS)) {
    Section 'APPLICATION SECURITY: DNS'
    foreach ($z in Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' }) {
        if ($z.SecureSecondaries -eq 'TransferAnyServer') { Flag "Zone $($z.ZoneName) allows zone transfers to ANY server" }
        if ($z.DynamicUpdate -eq 'NonsecureAndSecure') { Flag "Zone $($z.ZoneName) allows NON-secure dynamic updates" }
        Info ("{0,-30} type {1,-10} AD {2,-5} updates {3,-18} transfers {4}" -f $z.ZoneName, $z.ZoneType, $z.IsDsIntegrated, $z.DynamicUpdate, $z.SecureSecondaries)
    }
    $cache = Get-DnsServerCache
    if ($cache -and -not $cache.EnablePollutionProtection) { Flag 'DNS cache pollution protection is OFF' }
    $ldapSign = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
    if ($isDC -and $ldapSign -ne 2) { Flag "LDAP server signing = $ldapSign (2 = require signing)" }
}

# ---------------------------------------------------------------- done
Section "DONE: $script:FlagCount [!] findings"
Info "Full report saved to: $reportPath"
Info 'Next: fix what matches the README, re-check the score report after each change, and write down what you changed.'
$script:Report | Out-File -FilePath $reportPath -Encoding UTF8
Remove-Item $tmpInf -Force

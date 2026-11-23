# Runs Users.ps1 non-interactively. Answers "y" only for the accounts this test planted,
# and "n" for anything else, so stock accounts on the CI image are reported but left alone.
param([switch]$Apply)
function global:Read-Host {
    param([string]$Prompt)
    $yes = ($Prompt -match "'(?:[^'\\]*\\)?(hacker|svc\$|akim|mlee|bwong|carol)'") -or ($Prompt -like 'Give every authorized*')
    Write-Host ("{0} -> {1}" -f $Prompt, $(if ($yes) { 'y' } else { 'n  (not a planted account, left alone)' })) -ForegroundColor DarkGray
    if ($yes) { 'y' } else { 'n' }
}
if ($Apply) { & "$PSScriptRoot\..\scripts\Users.ps1" -ListFile "$PSScriptRoot\users.txt" -Apply -ResetPasswords }
else        { & "$PSScriptRoot\..\scripts\Users.ps1" -ListFile "$PSScriptRoot\users.txt" }

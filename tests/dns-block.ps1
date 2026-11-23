# Harden.ps1 only runs its DNS fixes on a domain controller, and a CI VM cannot become one.
# This pulls that exact block (and the helper functions it uses) out of Harden.ps1 and runs it here.
$path = Join-Path $PSScriptRoot '..\scripts\Harden.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path), [ref]$null, [ref]$null)
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in 'Say','Step','Run' }, $true)
$blk = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$isDC' -and $n.Extent.Text -match 'Get-DnsServerZone' }, $true) | Select-Object -First 1
if (-not $blk) { throw 'DNS block not found in Harden.ps1' }
$DryRun = $false
$log = New-Object System.Collections.Generic.List[string]
foreach ($f in $fns) { . ([scriptblock]::Create($f.Extent.Text)) }
$body = $blk.Clauses[0].Item2.Extent.Text
. ([scriptblock]::Create($body.Substring(1, $body.Length - 2)))

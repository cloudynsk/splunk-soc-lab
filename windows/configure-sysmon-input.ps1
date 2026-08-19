[CmdletBinding()]
param(
    [string]$SplunkHome = "C:\Program Files\SplunkUniversalForwarder"
)

$ErrorActionPreference = "Stop"

$channel = "Microsoft-Windows-Sysmon/Operational"
$log = Get-WinEvent -ListLog $channel -ErrorAction Stop
if (-not $log.IsEnabled) {
    throw "Sysmon Operational channel exists but is disabled. Enable Sysmon before configuring the forwarder."
}

Write-Host "Sysmon channel enabled with $($log.RecordCount) records."

$inputs = Join-Path $SplunkHome "etc\system\local\inputs.conf"
$directory = Split-Path $inputs -Parent
New-Item -ItemType Directory -Path $directory -Force | Out-Null

$stanzaHeader = "[WinEventLog://$channel]"
$stanza = @"

$stanzaHeader
disabled = 0
renderXml = true
"@

if (Test-Path $inputs) {
    $content = Get-Content $inputs -Raw
    if ($content -match [regex]::Escape($stanzaHeader)) {
        Write-Host "Sysmon stanza already exists in $inputs; leaving it in place."
        Write-Host "Use btool below to verify the effective disabled/renderXml values."
    }
    else {
        Add-Content -Path $inputs -Value $stanza -Encoding ASCII
        Write-Host "Added Sysmon input stanza to $inputs"
    }
}
else {
    Set-Content -Path $inputs -Value $stanza.TrimStart() -Encoding ASCII
    Write-Host "Created $inputs with the Sysmon input stanza."
}

Restart-Service SplunkForwarder
Start-Sleep -Seconds 3
Get-Service SplunkForwarder | Format-Table Status, Name, DisplayName

Write-Host "`nEffective Sysmon input configuration:"
& "$SplunkHome\bin\splunk.exe" btool inputs list --debug |
    Select-String -Pattern "Microsoft-Windows-Sysmon|Sysmon" -Context 2,6

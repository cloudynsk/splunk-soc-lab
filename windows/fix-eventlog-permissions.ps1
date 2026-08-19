[CmdletBinding()]
param(
    [string]$ServiceIdentity = "NT SERVICE\SplunkForwarder"
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from PowerShell as Administrator."
}

$channel = "Microsoft-Windows-Sysmon/Operational"
$acl = (& wevtutil gl $channel) -join "`n"

if ($acl -notmatch "S-1-5-32-573") {
    throw "The Sysmon channel ACL does not grant Event Log Readers access. This script refuses to rewrite the channel ACL automatically."
}

Write-Host "Sysmon channel ACL grants Event Log Readers access."

$targetSid = ([System.Security.Principal.NTAccount]$ServiceIdentity).Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value

$members = Get-LocalGroupMember -Group "Event Log Readers" -ErrorAction Stop
$alreadyMember = $members | Where-Object { $_.SID.Value -eq $targetSid }

if ($alreadyMember) {
    Write-Host "$ServiceIdentity is already a member of Event Log Readers."
}
else {
    Add-LocalGroupMember -Group "Event Log Readers" -Member $ServiceIdentity
    Write-Host "Added $ServiceIdentity to Event Log Readers."
}

Restart-Service SplunkForwarder
Start-Sleep -Seconds 5
Get-Service SplunkForwarder | Format-Table Status, Name, DisplayName

$ufLog = "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log"
if (Test-Path $ufLog) {
    Write-Host "`nNewest Sysmon/access/forwarding log lines:"
    Get-Content $ufLog -Tail 150 |
        Select-String -Pattern "Sysmon|errorCode=5|Connected to idx"
}

Write-Host "`nIf a new errorCode=5 appears after this restart, inspect the channel-specific ACL and service token before changing unrelated networking or reinstalling Splunk."

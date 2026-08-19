[CmdletBinding()]
param(
    [string]$Indexer = "192.168.56.102",
    [int]$Port = 9997,
    [string]$SplunkHome = "C:\Program Files\SplunkUniversalForwarder"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Network ==="
$tcp = Test-NetConnection $Indexer -Port $Port -WarningAction SilentlyContinue
[pscustomobject]@{
    Destination = "$Indexer`:$Port"
    Source       = $tcp.SourceAddress
    Reachable    = $tcp.TcpTestSucceeded
} | Format-List

Write-Host "=== SplunkForwarder service ==="
$service = Get-Service SplunkForwarder -ErrorAction Stop
$service | Format-Table Status, Name, DisplayName

Write-Host "=== Sysmon channel ==="
$sysmon = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
[pscustomobject]@{
    LogName     = $sysmon.LogName
    Enabled     = $sysmon.IsEnabled
    RecordCount = $sysmon.RecordCount
} | Format-List

Write-Host "=== Newest Sysmon events ==="
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Select-Object TimeCreated, Id, ProviderName |
    Format-Table -AutoSize

Write-Host "=== Windows time ==="
Get-Date
w32tm /query /source
w32tm /query /status

Write-Host "=== Effective Sysmon input ==="
& "$SplunkHome\bin\splunk.exe" btool inputs list --debug |
    Select-String -Pattern "Microsoft-Windows-Sysmon|Sysmon" -Context 2,6

Write-Host "=== Recent Universal Forwarder evidence ==="
$log = Join-Path $SplunkHome "var\log\splunk\splunkd.log"
if (Test-Path $log) {
    Get-Content $log -Tail 250 |
        Select-String -Pattern "Connected to idx|Sysmon|errorCode=5" |
        Select-Object -Last 30
}
else {
    Write-Warning "splunkd.log not found at $log"
}

Write-Host "=== Result guide ==="
Write-Host "Expected healthy state:"
Write-Host "  - TCP $Indexer`:$Port reachable"
Write-Host "  - SplunkForwarder Running"
Write-Host "  - Sysmon channel enabled with records"
Write-Host "  - Current system time synchronized"
Write-Host "  - Effective Sysmon input disabled = 0"
Write-Host "  - Recent 'Connected to idx=$Indexer`:$Port' evidence"
Write-Host "  - No new Sysmon errorCode=5 after the latest service restart"

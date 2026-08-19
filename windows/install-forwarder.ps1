[CmdletBinding()]
param(
    [string]$Indexer = "192.168.56.102",
    [int]$Port = 9997,
    [string]$Version = "10.4.2",
    [string]$Build = "33c3bf42cd73"
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

$destination = "$Indexer`:$Port"
Write-Host "Testing receiver $destination ..."
$tcp = Test-NetConnection $Indexer -Port $Port -WarningAction SilentlyContinue
if (-not $tcp.TcpTestSucceeded) {
    throw "Cannot reach $destination. Fix networking or the Splunk receiving port before installing the forwarder."
}

$filename = "splunkforwarder-$Version-$Build-windows-x64.msi"
$msi = Join-Path $env:TEMP $filename
$url = "https://download.splunk.com/products/universalforwarder/releases/$Version/windows/$filename"
$log = Join-Path $env:TEMP "splunk-uf-install.log"

if (-not (Test-Path $msi)) {
    Write-Host "Downloading Universal Forwarder $Version ..."
    Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
}
else {
    Write-Host "Using existing installer: $msi"
}

Write-Host "Enter a local Splunk UF admin password. It is read securely and is not written to PowerShell history."
$securePassword = Read-Host "Splunk UF admin password" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

try {
    if ($plainPassword.Length -lt 8) {
        throw "Splunk requires at least 8 printable ASCII characters for this lab configuration."
    }

    if ($plainPassword -match '[^\x20-\x7E]') {
        throw "Use printable ASCII characters for the lab password."
    }

    $arguments = @(
        "/i", "`"$msi`"",
        "RECEIVING_INDEXER=`"$destination`"",
        "WINEVENTLOG_APP_ENABLE=1",
        "WINEVENTLOG_SEC_ENABLE=1",
        "WINEVENTLOG_SYS_ENABLE=1",
        "SPLUNKUSERNAME=admin",
        "SPLUNKPASSWORD=`"$plainPassword`"",
        "GROUPPERFORMANCEMONITORUSERS=0",
        "AGREETOLICENSE=Yes",
        "/quiet",
        "/L*v", "`"$log`""
    )

    Write-Host "Installing Universal Forwarder silently ..."
    $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList $arguments
    if ($process.ExitCode -ne 0) {
        throw "MSI failed with exit code $($process.ExitCode). Inspect $log before retrying."
    }
}
finally {
    if ($bstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    $plainPassword = $null
    $securePassword = $null
}

$service = Get-Service SplunkForwarder -ErrorAction Stop
if ($service.Status -ne "Running") {
    Start-Service SplunkForwarder
    $service = Get-Service SplunkForwarder
}

Write-Host "Universal Forwarder installed successfully."
$service | Format-Table Status, Name, DisplayName
Write-Host "Receiver configured for $destination"
Write-Host "For interactive verification:"
Write-Host '  cd "C:\Program Files\SplunkUniversalForwarder\bin"'
Write-Host '  .\splunk.exe list forward-server'

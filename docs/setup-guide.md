# Setup Guide

This guide reconstructs the validated lab rather than redesigning it.

## 1. Create the Splunk VM

Create an Ubuntu Server 24.04.4 LTS VM named `Splunk-SIEM` with approximately:

- 4 vCPU
- 8 GB RAM
- 60 GB disk
- Adapter 1: NAT
- Adapter 2: Host-only

The validated Linux user was `splunkadmin`.

### Netplan

The validated guest used DHCP on both adapters:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
      optional: true
    enp0s8:
      dhcp4: true
      optional: true
```

Apply and verify:

```bash
sudo chmod 600 /etc/netplan/60-hostonly.yaml
sudo netplan generate
sudo netplan apply
ip -br a
ip route
```

Expected shape:

```text
enp0s3  UP  10.0.2.15/24
 enp0s8  UP  192.168.56.102/24
 default via 10.0.2.2 dev enp0s3
```

If the NAT interface is up but loses its DHCPv4 lease after applying Netplan, renew it without rewriting the configuration:

```bash
sudo networkctl renew enp0s3
```

## 2. Enable SSH

```bash
sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
```

Once Host-only networking works, connect from the Windows host with:

```powershell
ssh splunkadmin@192.168.56.102
```

## 3. Install Splunk Enterprise 10.4.2

Download the Linux AMD64 `.deb` from Splunk and install it:

```bash
sudo dpkg -i splunk-10.4.2-33c3bf42cd73-linux-amd64.deb
```

Start Splunk and accept the license:

```bash
/opt/splunk/bin/splunk start --accept-license
```

Open Splunk Web from the host:

```text
http://192.168.56.102:8000
```

## 4. Enable the forwarder receiver

In Splunk Web:

```text
Settings
  -> Forwarding and receiving
  -> Configure receiving
  -> New Receiving Port
  -> 9997
```

If Splunk says configuration for port 9997 already exists, do not create it again.

Optional Linux verification:

```bash
sudo ss -lntp | grep 9997
```

## 5. Prepare WIN11-LAB networking

The validated Windows endpoint used:

```text
Host-only: 192.168.56.20/24
NAT:       10.0.2.15/24
```

Verify the route to Splunk from the Windows VM:

```powershell
Test-NetConnection 192.168.56.102 -Port 9997
```

Expected:

```text
TcpTestSucceeded : True
```

## 6. Install the Splunk Universal Forwarder

Run PowerShell as Administrator and use:

```powershell
.\windows\install-forwarder.ps1 -Indexer 192.168.56.102 -Port 9997
```

The script downloads the pinned 10.4.2 x64 MSI, prompts for a local Universal Forwarder admin password, enables Application/Security/System event-log inputs, and points the forwarder to the receiver.

Verify:

```powershell
Get-Service SplunkForwarder
```

Expected status: `Running`.

Interactive forwarder verification:

```powershell
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe list forward-server
```

Expected:

```text
Active forwards:
    192.168.56.102:9997
Configured but inactive forwards:
    None
```

## 7. Enable Sysmon forwarding

Sysmon must already be installed and its Operational channel enabled.

Verify:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" |
    Select-Object LogName, IsEnabled, RecordCount
```

Then run:

```powershell
.\windows\configure-sysmon-input.ps1
```

The effective stanza is:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
```

Confirm effective Splunk configuration:

```powershell
$uf = "C:\Program Files\SplunkUniversalForwarder"
& "$uf\bin\splunk.exe" btool inputs list --debug |
    Select-String -Pattern "Microsoft-Windows-Sysmon|Sysmon" -Context 2,6
```

## 8. Repair Sysmon read permissions if needed

If `splunkd.log` contains:

```text
Could not subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational'
errorCode=5
```

run:

```powershell
.\windows\fix-eventlog-permissions.ps1
```

The script checks the Sysmon channel ACL, adds `NT SERVICE\SplunkForwarder` to Event Log Readers when appropriate, and restarts the forwarder.

## 9. Verify Windows time

Bad endpoint time makes healthy ingestion look broken.

```powershell
Get-Date
Get-TimeZone
w32tm /query /status
```

The validated VM initially reported `Source: Local CMOS Clock` and was three days behind.

A repaired standalone configuration used:

```powershell
Set-Service w32time -StartupType Automatic
w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /update
Restart-Service w32time
w32tm /resync /rediscover
```

Validate offset:

```powershell
w32tm /stripchart /computer:time.windows.com /dataonly /samples:5
```

The completed lab was within a few milliseconds of the NTP source.

## 10. Verify ingestion in Splunk

Use **All time** while initial historical backlog is still draining.

Check recent index-time arrivals:

```spl
index=main host=WIN11-LAB _index_earliest=-5m
| stats count by source sourcetype
| sort - count
```

Expected sources include Security and Sysmon.

For Sysmon specifically:

```spl
index=main host=WIN11-LAB sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort - count
```

## 11. Generate and find a live test event

On WIN11-LAB:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SPLUNK_LIVE_TEST_20260819'"
```

In Splunk:

```spl
index=main host=WIN11-LAB sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-5m "SPLUNK_LIVE_TEST_20260819"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| table _time User Image CommandLine ParentImage
```

A matching event proves the process-to-Splunk pipeline end to end.

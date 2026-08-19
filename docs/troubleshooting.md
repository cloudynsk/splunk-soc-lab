# Troubleshooting

This document preserves the failures encountered during the validated build and the evidence that separated them from unrelated problems.

## 1. Host-only adapter has no IPv4 address

### Symptom

Ubuntu showed:

```text
enp0s8  UP  fe80::.../64
```

but no `192.168.56.x` address.

### Evidence

```bash
sudo netplan get
ip -br a
```

The Host-only interface existed but was not configured for DHCP.

### Fix

Add the interface to Netplan:

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

If the Host-only interface remains up without IPv4, inspect VirtualBox Host-only DHCP before randomly rewriting Linux networking.

## 2. NAT IPv4 disappears after applying Netplan

### Symptom

The Host-only interface worked but `enp0s3` lost `10.0.2.15` and retained only link-local IPv6.

### Fix

Renew the existing DHCP configuration rather than redesigning Netplan:

```bash
sudo networkctl renew enp0s3
```

Verify:

```bash
ip -br a
ip route
```

## 3. Splunk says receiving port 9997 already exists

This is not a failure. It means the receiver is already configured.

Verify on Linux:

```bash
sudo ss -lntp | grep 9997
```

Verify from WIN11-LAB:

```powershell
Test-NetConnection 192.168.56.102 -Port 9997
```

## 4. Universal Forwarder MSI exits with 1603

### Symptom

The service did not exist after a silent installation attempt.

### Evidence

The verbose MSI log contained:

```text
ValidatePassword: ERROR: Password must contain at a minimum 8 total printable ASCII characters.
CustomAction ValidatePassword returned actual error code 1603
```

The generic MSI `1603` was only the wrapper. The actual cause was password validation.

The log also showed:

```text
USE_VIRTUAL_ACCOUNT = 1
GROUPPERFORMANCEMONITORUSERS = 1
```

For the validated 10.4.2 install, the corrected command explicitly used:

```text
GROUPPERFORMANCEMONITORUSERS=0
```

### Lesson

Always search the verbose MSI log around `Return value 3` and custom-action errors before reinstalling.

## 5. Universal Forwarder local login fails

### Symptom

`admin` plus the expected password failed even though the service was running.

### Evidence

`etc\passwd` existed and was non-empty, so the issue was not simply a missing credential store.

### Recovery used in the lab

The existing `passwd` file was preserved, a new password hash was generated with `splunk.exe hash-passwd`, and `user-seed.conf` was used while `passwd` was temporarily absent. After restart, Splunk recreated `etc\passwd` and the credential worked.

Do not delete the original credential file without preserving a backup.

## 6. Sysmon is configured but nothing appears in Splunk

### Source-side checks

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" |
    Select-Object LogName, IsEnabled, RecordCount
```

The validated endpoint showed the channel enabled with more than 60,000 records.

Check effective Splunk configuration:

```powershell
$uf = "C:\Program Files\SplunkUniversalForwarder"
& "$uf\bin\splunk.exe" btool inputs list --debug |
    Select-String -Pattern "Microsoft-Windows-Sysmon|Sysmon" -Context 2,6
```

The validated stanza existed and had `disabled = 0`.

### Runtime evidence

The decisive log lines were:

```text
WinEventLogChannel::subscribeToEvtChannel: Could not subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational'
WinEventLogChannel::init: Init failed ... errorCode=5
```

Seconds later, the same `splunkd.log` showed:

```text
Connected to idx=192.168.56.102:9997
```

That proved forwarding/networking worked while the Sysmon reader failed locally.

### Root cause

Windows error code 5 means access denied.

The Sysmon channel ACL already contained:

```text
(A;;0x1;;;S-1-5-32-573)
```

`S-1-5-32-573` is the built-in Event Log Readers group.

### Fix

Add only the least-privileged Splunk service identity to that group:

```powershell
net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
Restart-Service SplunkForwarder
```

Do not switch to LocalSystem merely to make the error disappear.

## 7. Splunk is ingesting now, but searches for the last 30 minutes show zero events

### Symptom

A normal search such as:

```spl
index=main host=WIN11-LAB earliest=-30m
```

returned zero even though forwarder telemetry indicated ingestion.

### Diagnosis

Check host metadata:

```spl
| metadata type=hosts index=main
| convert ctime(firstTime) ctime(lastTime) ctime(recentTime)
| table host totalCount firstTime lastTime recentTime
```

Then inspect index time rather than event time:

```spl
index=main host=WIN11-LAB _index_earliest=-15m
| eval EventTime=strftime(_time,"%Y-%m-%d %H:%M:%S")
| eval IndexedTime=strftime(_indextime,"%Y-%m-%d %H:%M:%S")
| table IndexedTime EventTime source sourcetype
| sort - IndexedTime
```

The validated lab was ingesting a large historical Windows Security backlog. `_indextime` was current while `_time` was several days old.

### Lesson

`earliest=` filters event time. `_index_earliest=` filters when Splunk indexed the event. During backlog ingestion, they answer different questions.

## 8. Fresh Sysmon events still appear several days old

### Symptom

Splunk was caught up enough to ingest new records, but their event timestamps were still three days behind.

### Source-side evidence

```powershell
Get-Date
w32tm /query /status
```

The endpoint reported:

```text
Source: Local CMOS Clock
Leap Indicator: 3(not synchronized)
Last Successful Sync Time: unspecified
```

`Get-WinEvent` confirmed new Sysmon records were stamped with the wrong date.

### Repair

The standalone VM was moved close to the correct date, then configured to use Windows NTP:

```powershell
Set-Service w32time -StartupType Automatic
w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /update
Restart-Service w32time
w32tm /resync /rediscover
```

Validate with:

```powershell
w32tm /stripchart /computer:time.windows.com /dataonly /samples:5
w32tm /query /peers
w32tm /resync
```

The completed VM synchronized successfully and showed millisecond-scale offset.

## 9. `EventCode` is empty for Sysmon XML events

With `renderXml = true`, the validated lab received Sysmon events under:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

The official Sysmon add-on was not installed in the baseline, so fields such as `EventCode`, `Image`, and `CommandLine` were not automatically extracted.

Use `rex` against the raw XML:

```spl
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
```

and extract individual `<Data Name='...'>` fields as needed.

Installing the Splunk Add-on for Sysmon is a sensible future improvement, but it is not required to reproduce the baseline.

## 10. Suspicious PowerShell rule returns zero

Zero can be the correct result.

The lab first searched for patterns such as:

- `-enc`
- `EncodedCommand`
- `DownloadString`
- `Invoke-WebRequest`

No existing process event matched the stricter rule.

A controlled synthetic command was then generated and the rule was expected to match exactly once. This validated the detection path without treating ordinary PowerShell usage as automatically malicious.

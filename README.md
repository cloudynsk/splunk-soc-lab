# Splunk SOC Lab

A reproducible home SOC lab built with **Splunk Enterprise**, a **Windows 11 endpoint**, **Sysmon**, and the **Splunk Universal Forwarder**.

This repository reconstructs the working lab that was built and validated on 2026-08-19. The goal is not merely to show that Splunk can be installed. It documents the actual endpoint-to-SIEM pipeline, the failure modes encountered, the fixes applied, and several small SOC-style investigations performed against live telemetry.

## What this lab demonstrates

- Splunk Enterprise running on a dedicated Ubuntu VM.
- A Windows 11 SOC endpoint with Sysmon.
- A Splunk Universal Forwarder sending Windows telemetry to the Splunk indexer over TCP/9997.
- A two-interface VirtualBox design: NAT for internet access and Host-only networking for lab traffic.
- Windows Security, System, Application, and Sysmon ingestion.
- Diagnosis of a least-privilege Sysmon access failure (`errorCode=5`).
- Repair by granting the Splunk service identity membership in **Event Log Readers**.
- Diagnosis and repair of a badly skewed Windows VM clock using `w32tm`.
- Distinguishing event time (`_time`) from index time (`_indextime`) while Splunk drained a historical backlog.
- SPL searches for Sysmon process creation, network connections, PowerShell activity, and controlled detection validation.
- Negative and positive testing of a simple suspicious-PowerShell rule.

## Validated topology

```text
Windows 11 SOC VM (WIN11-LAB)
  Host-only: 192.168.56.20
  NAT:       10.0.2.15
  Sysmon + Splunk Universal Forwarder
               |
               | TCP/9997
               v
Splunk-SIEM Ubuntu VM
  Host-only: 192.168.56.102
  NAT:       10.0.2.15
  Splunk Enterprise 10.4.2
               |
               v
        index=main / SPL searches
```

The host-only adapter carries lab traffic. NAT remains available on each VM for internet access. The host-only adapter intentionally has no default gateway.

## Software used

- VirtualBox
- Ubuntu Server 24.04.4 LTS
- Splunk Enterprise 10.4.2
- Windows 11
- Splunk Universal Forwarder 10.4.2
- Sysmon
- PowerShell

The Windows endpoint also had a Wazuh agent installed. Wazuh is not required for this Splunk lab, but its activity appears in some Sysmon process events and is useful context during triage.

## Repository layout

```text
.
├── AGENTS.md
├── README.md
├── docs/
│   ├── architecture.md
│   ├── setup-guide.md
│   ├── troubleshooting.md
│   └── investigation-walkthrough.md
├── splunk/
│   ├── configs/
│   │   └── inputs.conf.example
│   └── searches/
│       ├── network-connections.spl
│       ├── process-creation.spl
│       ├── suspicious-powershell.spl
│       └── sysmon-event-summary.spl
└── windows/
    ├── configure-sysmon-input.ps1
    ├── fix-eventlog-permissions.ps1
    ├── install-forwarder.ps1
    └── verify-lab.ps1
```

## Fast reconstruction path

1. Create the Splunk Ubuntu VM with NAT plus a Host-only adapter.
2. Give the Host-only adapter an address on `192.168.56.0/24`; the validated Splunk VM used `192.168.56.102`.
3. Install Splunk Enterprise and enable receiving on TCP/9997.
4. Give the Windows SOC VM a Host-only address on the same subnet; the validated endpoint used `192.168.56.20`.
5. Verify from Windows:

   ```powershell
   Test-NetConnection 192.168.56.102 -Port 9997
   ```

6. Install the Universal Forwarder with `windows/install-forwarder.ps1`.
7. Enable the Sysmon channel with `windows/configure-sysmon-input.ps1`.
8. If Sysmon ingestion reports access denied, run `windows/fix-eventlog-permissions.ps1`.
9. Run `windows/verify-lab.ps1`.
10. Use the searches under `splunk/searches/` to validate live telemetry.

See [docs/setup-guide.md](docs/setup-guide.md) for the full path.

## Important lessons from the build

### `errorCode=5` was permissions, not networking

The forwarder successfully connected to `192.168.56.102:9997`, but its log reported:

```text
Could not subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational'
errorCode=5
```

Windows error 5 is access denied. Sysmon already granted read access to the built-in Event Log Readers group, so the correct fix was to add the least-privileged Splunk service account to that group rather than run the forwarder as LocalSystem or rewrite the Sysmon channel ACL.

### Fresh ingestion can contain old event timestamps

The first live searches appeared empty because Splunk was ingesting historical Windows events. `_time` represented when those events occurred, while `_indextime` represented when Splunk received them. Searching with `_index_earliest` proved that ingestion was active even though `_time` was several days old.

### Endpoint time matters

The Windows VM was three days behind and `w32tm` reported it was unsynchronized. That produced fresh Sysmon records with old timestamps. After repairing Windows Time, live Sysmon ingestion was approximately one second behind the event source.

### A keyword hit is not automatically malicious

A controlled PowerShell test containing the text `Invoke-WebRequest` triggered a simple string-based rule even though it did not perform a web request. A stricter rule requiring both `Invoke-WebRequest` and an HTTP-looking string reduced that false-positive case. Detection logic still requires analyst context.

## Example validated live event

A controlled command:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SPLUNK_LIVE_TEST_20260819'"
```

was observed in Splunk as a Sysmon Event ID 1 with the user, process image, command line, and parent image available for triage.

## Portfolio / interview summary

> Built and troubleshot a Splunk Enterprise SOC lab with Windows Sysmon telemetry, Universal Forwarder ingestion, network isolation, SPL-based investigation, detection validation, and least-privilege event log access. Diagnosed forwarding, permissions, backlog/timestamp, and Windows time-synchronization issues and validated live process and network telemetry end-to-end.

## Scope

This repository reproduces the completed lab. It intentionally does not pretend that optional hardening or polish was part of the original validated state. Items such as installing the Splunk Add-on for Sysmon, replacing default Splunk certificates, changing `pass4SymmKey`, and building dashboards are useful future improvements, not prerequisites for the completed lab documented here.

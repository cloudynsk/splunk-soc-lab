# Investigation Walkthrough

This walkthrough reproduces the small analyst exercises used to validate the lab after ingestion was healthy.

## 1. Confirm Sysmon event coverage

```spl
index=main host=WIN11-LAB sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort - count
```

The validated lab observed event IDs including:

- 1: Process creation
- 3: Network connection
- 5: Process terminated
- 7: Image loaded
- 10: Process accessed
- 11: File created
- 12/13: Registry events
- 15, 16, 17, 22, 26, 29

The exact distribution is workload-dependent.

## 2. Investigate process creation

```spl
index=main host=WIN11-LAB sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| table _time User ParentImage Image CommandLine
| sort - _time
```

Questions to ask:

- Which user launched the process?
- Is the executable path expected?
- What parent process launched it?
- Does the command line match normal administrative activity?
- Is the same parent producing several unusual children?

## 3. Hunt PowerShell activity

```spl
index=main host=WIN11-LAB sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "powershell.exe"
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| table _time User ParentImage Image CommandLine
| sort - _time
```

A useful baseline observation from this lab was a PowerShell process launched by the Wazuh agent to export and inspect local security policy. The presence of PowerShell alone was not enough to classify that activity as malicious.

## 4. Review network connections

```spl
index=main host=WIN11-LAB sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| search EventID=3
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| rex field=_raw "<Data Name='Protocol'>(?<Protocol>[^<]+)</Data>"
| table _time User Image DestinationIp DestinationPort Protocol
| sort - _time
```

The validated endpoint showed ordinary examples such as OneDrive and Microsoft Defender using TCP/443 and local discovery traffic using UDP/5353.

## 5. Build a simple suspicious-PowerShell rule

```spl
index=main host=WIN11-LAB sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| search Image="*powershell.exe"
| eval cmd=lower(CommandLine)
| eval suspicious=if(
    like(cmd,"%encodedcommand%")
    OR like(cmd,"%-enc %")
    OR like(cmd,"%downloadstring(%")
    OR (like(cmd,"%invoke-webrequest%") AND like(cmd,"%http%")),
    1,0
)
| where suspicious=1
| table _time User ParentImage Image CommandLine
| sort - _time
```

This is intentionally a teaching rule, not a production-grade detector.

## 6. Negative test

Generate a command line that contains `Invoke-WebRequest` but no URL:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SOC_TEST_Invoke-WebRequest'"
```

The stricter rule should return zero because it requires both the keyword and an HTTP-like string.

That zero-result case is useful evidence: the rule did not fire merely because the phrase appeared somewhere in the command line.

## 7. Positive synthetic test

Generate harmless text that matches both conditions:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Invoke-WebRequest http://example.invalid'"
```

This command **does not make a web request**. It only creates a process command line containing the strings used by the rule.

The validated rule returned exactly one event showing:

- user: `WIN11-LAB\danru`
- parent image: PowerShell
- image: PowerShell
- command line containing `Invoke-WebRequest http://example.invalid`

## 8. Pivot to network evidence

After a suspicious-looking PowerShell command line, ask whether PowerShell actually opened a network connection:

```spl
index=main host=WIN11-LAB sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-15m
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| search EventID=3
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| rex field=_raw "<Data Name='Protocol'>(?<Protocol>[^<]+)</Data>"
| search Image="*powershell.exe"
| table _time User Image DestinationIp DestinationPort Protocol
| sort - _time
```

For the synthetic text-only test, the result was zero. That was expected because the command did not perform network activity.

## 9. Analyst conclusion pattern

A simple Tier-1 reasoning chain for this exercise is:

```text
Alert-like command line
    -> inspect process image
    -> inspect parent
    -> inspect user
    -> inspect full command line
    -> pivot to network events
    -> compare behavior with the detection hypothesis
    -> classify as test/benign, suspicious, or escalation-worthy
```

The main lesson is that a string match is the start of triage, not the conclusion.

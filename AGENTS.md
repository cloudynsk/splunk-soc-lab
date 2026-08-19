# AGENTS.md

## Purpose

This repository documents and reproduces a small Splunk SOC lab. Treat it as a learning, troubleshooting, and portfolio project, not as production infrastructure.

## Preserve the validated architecture

- Splunk Enterprise runs on a dedicated Ubuntu VM.
- The monitored endpoint is a Windows 11 VM named `WIN11-LAB`.
- Sysmon and the Splunk Universal Forwarder run on the Windows endpoint.
- The Universal Forwarder sends to the Splunk VM on TCP/9997.
- The validated Host-only addresses were:
  - Windows endpoint: `192.168.56.20`
  - Splunk VM: `192.168.56.102`
- NAT remains enabled separately for internet access.

Do not silently replace this topology with Splunk Cloud, Wazuh-only collection, Docker, or an unrelated SIEM design.

## Safety and reproducibility

- Never commit passwords, tokens, private keys, cookies, session data, or generated credential files.
- Scripts must prompt for credentials at runtime or use documented environment/secret mechanisms.
- Prefer least privilege. Do not switch the Universal Forwarder to LocalSystem merely to bypass a permissions problem.
- Do not rewrite Windows Event Log channel ACLs when membership in `Event Log Readers` is sufficient.
- Avoid destructive cleanup of Splunk checkpoints or indexes unless a task explicitly requires it and the consequence is documented.
- Keep scripts idempotent where practical.
- Verify a failure with logs or effective configuration before changing unrelated layers.

## Evidence-first troubleshooting

Useful evidence sources include:

- `splunkd.log` on the Universal Forwarder.
- `splunk.exe btool inputs list --debug` for effective input configuration.
- `Get-WinEvent` for source-channel state and record counts.
- `wevtutil gl` for Event Log channel ACLs.
- `w32tm` for endpoint time synchronization.
- `_time` versus `_indextime` in Splunk for backlog/timestamp diagnosis.

Do not recommend reinstalling the forwarder as a first response to collection failures.

## Lab state versus future improvements

The validated lab did **not** require:

- Splunk Add-on for Sysmon.
- Custom TLS certificates.
- Dashboard creation.
- Multiple endpoints.
- A deployment server.

Those are valid future improvements, but keep them clearly separated from the reconstructed baseline.

## Documentation style

- Prefer exact commands and observable success criteria.
- Explain why a change is needed, not only what command to run.
- Preserve troubleshooting lessons that would help a junior SOC analyst understand the failure.
- Distinguish synthetic detection tests from actual malicious behavior.

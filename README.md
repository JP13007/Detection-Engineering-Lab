# Detection Engineering Lab: Sigma Rule Development & Validation

Building detection rules for common attack techniques. This lab demonstrates how to write Sigma detection rules, validate them against real attack telemetry, and tune them to reduce false positives.

## Project Overview

**What is Detection Engineering?**

Detection Engineering is the practice of building rules that alert on attacker behavior automatically, rather than relying solely on manual threat hunting. The skill is not just writing a rule that fires — it is tuning that rule so it catches malicious activity without drowning analysts in false positives.

This lab demonstrates the complete workflow:
1. **Identify an attack technique** — drawn from my SOC Investigation Lab
2. **Write a Sigma detection rule** — in the industry-standard YAML format
3. **Validate against captured telemetry** — using real Sysmon event data from the lab
4. **Tune for false positives** — add context, whitelist known-good behavior, adjust thresholds
5. **Document findings** — rule logic, tuning decisions, and lessons learned

## Sigma Rules Included

Five detection rules targeting techniques from the SOC Investigation Lab:

| # | Technique | MITRE ID | Sigma Rule |
|---|-----------|----------|-----------|
| 1 | Suspicious Download & Execution | T1204.002 | rule_1_suspicious_download_execution.yml |
| 2 | C2 Callback Detection | T1071.001 | rule_2_c2_callback.yml |
| 3 | Failed Privilege Escalation | T1548.002 | rule_3_failed_privilege_escalation.yml |
| 4 | User/System Enumeration | T1033 | rule_4_user_enumeration.yml |
| 5 | Suspicious Process Parent-Child | T1059.003 | rule_5_suspicious_process_parent.yml |

## Rule Details

### Rule 1: Suspicious Download & Execution (T1204.002)

**What it detects:** A file downloaded to the Downloads folder, then executed by the user.

**Why it matters:** Phishing and watering-hole attacks use this pattern — attacker delivers a malicious file, user runs it.

**Sigma logic:** Image ends with `.exe`, parent is `explorer.exe`, path contains `Downloads`.

**False positives:** Legitimate software installers downloaded and run (e.g., Slack, Discord setup.exe).

**Tuning:** Add a time threshold — if the file was downloaded well before execution, it is more likely legitimate. Whitelist Microsoft-signed binaries.

### Rule 2: C2 Callback Detection (T1071.001)

**What it detects:** A process connecting to an external IP on an uncommon port (e.g., 4444).

**Why it matters:** Reverse shells and C2 beacons establish outbound connections to attacker infrastructure.

**Sigma logic:** EventID 3 (network connection), DestinationPort 4444, DestinationIp is external.

**False positives:** Legitimate development tools (testing frameworks, remote debugging) on localhost or internal IPs.

**Tuning:** Filter out internal/private IP ranges; whitelist known-good ports (443, 80) and destinations.

### Rule 3: Failed Privilege Escalation (T1548.002)

**What it detects:** Multiple `net user` or `net localgroup` commands in quick succession, especially failed attempts.

**Why it matters:** Attackers attempt account creation and group membership changes for persistence.

**Sigma logic:** CommandLine contains `net user` or `net localgroup`, multiple events within 60 seconds.

**False positives:** System administrators running bulk user-management scripts.

**Tuning:** Filter on exit code (failed vs. successful), exclude SYSTEM/admin context, baseline expected command frequency for the environment.

### Rule 4: User/System Enumeration (T1033)

**What it detects:** Multiple discovery commands executed in sequence (`whoami /all`, `net user`, `systeminfo`).

**Why it matters:** After gaining access, attackers enumerate the system to plan next steps.

**Sigma logic:** CommandLine matches enumeration patterns, multiple commands from the same parent process.

**False positives:** Legitimate troubleshooting scripts, compliance scanning tools.

**Tuning:** Add parent-process context; whitelist system-management tools (SCCM, Puppet) and known scanners.

### Rule 5: Suspicious Process Parent-Child (T1059.003)

**What it detects:** Uncommon parent-child process relationships (e.g., notepad.exe spawning cmd.exe).

**Why it matters:** Attackers use legitimate programs as launchers to blend in and evade detection.

**Sigma logic:** ParentImage is an office/utility app (notepad.exe, calc.exe, etc.); child is `cmd.exe` or `powershell.exe`.

**False positives:** Some software legitimately spawns cmd/PowerShell from unexpected parents.

**Tuning:** Add command-line context (encoded PowerShell, enumeration commands raise priority); verify the child process is Microsoft-signed.

## Validation & Tuning Method

Each rule was validated against real Sysmon telemetry captured during the SOC Investigation Lab — the same attack chain (reverse shell delivery, execution, C2 callback, enumeration, failed escalation) was used as the source data. The `test_results/` folder documents, per rule:

- The Sysmon events used as test input
- Whether the rule fired on the malicious activity
- Which benign scenarios produced false positives
- The tuning adjustments applied to suppress those false positives

This is lab validation against simulated attack data, not a measurement of production detection rates. The value of the exercise is in the tuning methodology — distinguishing malicious behavior from benign activity that looks similar.

## How to Use These Rules

### In Splunk

1. Use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) to convert the YAML rules to Splunk SPL.
2. Import as saved searches or correlation searches.
3. Configure alerts to fire on match.

### In Other SIEMs

Sigma is SIEM-agnostic:
- **Elastic/ELK** — native Sigma support
- **Microsoft Sentinel** — convert to KQL
- **Splunk** — convert to SPL via sigma-cli
- **QRadar / ArcSight** — community converters available

### Local Testing

1. Export Sysmon events from a Windows target (EventIDs 1, 3, etc.).
2. Import into Splunk or Elastic.
3. Run each rule as an SPL/KQL query.
4. Compare results against expected detections.

## Key Lessons Learned

1. **Context is everything** — the same command (`net user`) is malicious in one context (attacker post-exploitation) and routine in another (admin automation). A rule without context is a rule that cries wolf.
2. **False positives kill detections** — a rule that fires constantly on benign activity gets ignored (alert fatigue). Tuning is the real work.
3. **Whitelist known-good, don't blacklist** — alert on *unknown* binaries running enumeration, not on all enumeration.
4. **Detections are environment-specific** — a rule tuned for one organization's baseline will misfire in another. Tuning is never "done."

## Repository Structure

```
Detection-Engineering-Lab/
├── README.md
├── sigma_rules/
│   ├── rule_1_suspicious_download_execution.yml
│   ├── rule_2_c2_callback.yml
│   ├── rule_3_failed_privilege_escalation.yml
│   ├── rule_4_user_enumeration.yml
│   └── rule_5_suspicious_process_parent.yml
└── test_results/
    ├── rule_1_test_results.md
    ├── rule_2_test_results.md
    ├── rule_3_test_results.md
    ├── rule_4_test_results.md
    └── rule_5_test_results.md
```

## Linked to SOC Investigation Lab

This project builds on the attack techniques identified in my [SOC Investigation Lab](https://github.com/JP13007/SOC-Investigation-Lab). Each rule targets a technique observed in that incident:

- **Rule 1** — malware delivery via download (T1204)
- **Rule 2** — reverse shell callback to the attacker host (T1071)
- **Rule 3** — failed persistence attempts (T1548)
- **Rule 4** — post-compromise enumeration (T1033)
- **Rule 5** — suspicious process execution (T1059)

## References

- [Sigma Documentation](https://sigma.readthedocs.io/)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma/tree/master/rules)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## Skills Demonstrated

- Sigma detection rule authoring
- MITRE ATT&CK technique mapping
- False-positive tuning and baseline reasoning
- Log analysis and detection validation
- Cross-SIEM rule conversion (Splunk SPL, Microsoft KQL)
- Technical documentation

---

**Author:** JP13007
**Status:** 5 rules written and validated against lab telemetry
**Validated Against:** Sysmon and Windows Security logs from the SOC Investigation Lab

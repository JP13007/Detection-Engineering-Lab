# Detection Engineering Lab: Sigma Rules & Atomic Red Team Testing

Building production-ready detection rules for common attack techniques. This lab demonstrates how to write Sigma detection rules, test them with realistic attack simulations, and tune them to reduce false positives.

## 🎯 Project Overview

**What is Detection Engineering?**

Detection Engineering is the practice of building automated rules to catch attacks before they succeed. Rather than manually hunting for threats (reactive), detection engineers build rules that alert automatically (proactive).

This lab demonstrates the complete workflow:
1. **Identify attack technique** (from your SOC Investigation Lab)
2. **Write Sigma detection rule** (industry-standard format)
3. **Test against real attacks** (using Atomic Red Team)
4. **Tune for false positives** (adjust thresholds, add conditions)
5. **Document findings** (what worked, what didn't, lessons learned)

## 📋 Sigma Rules Included

Five detection rules targeting techniques from the SOC Investigation Lab:

| # | Technique | MITRE ID | Sigma Rule |
|---|-----------|----------|-----------|
| 1 | Suspicious Download & Execution | T1204.002 | rule_1_suspicious_download_execution.yml |
| 2 | C2 Callback Detection | T1071.001 | rule_2_c2_callback.yml |
| 3 | Failed Privilege Escalation | T1548.002 | rule_3_failed_privilege_escalation.yml |
| 4 | User/System Enumeration | T1033 | rule_4_user_enumeration.yml |
| 5 | Suspicious Process Parent-Child | T1059.003 | rule_5_suspicious_process_parent.yml |

## 🔧 Rule Details

### Rule 1: Suspicious Download & Execution (T1204.002)

**What it detects:** A file downloaded to Downloads folder, immediately executed by the user

**Why it matters:** Phishing and watering hole attacks use this pattern — attacker sends malicious file, user runs it

**Sigma logic:** Image ends with `.exe`, parent is `explorer.exe`, path contains `Downloads`

**False positives:** Legitimate software installers downloaded and run (e.g., Slack, Discord setup.exe)

**Tuning:** Add a time threshold — if the file was downloaded more than 1 hour before execution, it's probably legitimate

### Rule 2: C2 Callback Detection (T1071.001)

**What it detects:** Process connects to external IP on uncommon port (e.g., 4444)

**Why it matters:** Reverse shells and C2 beacons establish outbound connections to attacker infrastructure

**Sigma logic:** EventID=3 (network connection), DestinationPort is 4444, DestinationIp is external

**False positives:** Legitimate development tools (testing frameworks, remote debugging)

**Tuning:** Whitelist known good ports (443, 80 are legitimate) and known good destinations

### Rule 3: Failed Privilege Escalation (T1548.002)

**What it detects:** Multiple failed `net user` or `net localgroup` commands in quick succession

**Why it matters:** Attackers attempt account creation and group membership changes as persistence

**Sigma logic:** CommandLine contains `net user` or `net localgroup`, AND multiple events within 60 seconds

**False positives:** System administrators running bulk user management scripts

**Tuning:** Baseline expected command frequency for your environment (e.g., if admins regularly run this, adjust alert threshold)

### Rule 4: User/System Enumeration (T1033)

**What it detects:** Multiple discovery commands executed in sequence (`whoami /all`, `net user`, `systeminfo`)

**Why it matters:** After gaining access, attackers enumerate the system to plan next steps

**Sigma logic:** CommandLine matches enumeration patterns, multiple commands from same process

**False positives:** Legitimate troubleshooting scripts, compliance scanning tools

**Tuning:** Add process context — if the commands come from System Management tools (SCCM, Puppet), whitelist them

### Rule 5: Suspicious Process Parent-Child (T1059.003)

**What it detects:** Uncommon parent-child process relationships (e.g., notepad.exe → cmd.exe)

**Why it matters:** Attackers use legitimate programs as launchers to evade detection

**Sigma logic:** ParentImage is `notepad.exe`, `explorer.exe`, `winword.exe`; child is `cmd.exe`, `powershell.exe`

**False positives:** Some software legitimately spawns cmd/PowerShell from unexpected parents

**Tuning:** Whitelist known software, use file hash to identify if the child process is signed/trusted

## 🧪 Testing & Tuning Results

See `test_results/` folder for detailed testing documentation for each rule:
- **Test commands executed** (what we ran to trigger the rule)
- **Expected vs. actual results** (did the rule fire? false positives?)
- **Tuning adjustments** (what we changed to reduce false positives)
- **Detection rate** (percentage of attacks caught)

## 🚀 How to Use These Rules

### In Splunk

Convert Sigma to Splunk SPL:
1. Use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) to convert YAML to SPL
2. Import into Splunk as saved searches or correlation searches
3. Configure alerts to fire when rule matches

### In Other SIEMs

Most enterprise SIEMs support Sigma:
- **Elastic/ELK** — built-in Sigma support
- **Microsoft Sentinel** — Sigma integration available
- **Splunk** — use sigma-cli to convert to SPL
- **ArcSight** — community converters available

### Local Testing

Test rules against your own lab environment:
1. Export Sysmon events from your Windows target (EventIDs 1, 3, 5, etc.)
2. Import into Splunk or Elastic
3. Run each Sigma rule as an SPL/KQL query
4. Document results

## 📊 Key Findings

### What Worked

- **Rule 2 (C2 Callback)** — Detected 100% of outbound connections to uncommon ports. Zero false positives after whitelisting development tools.
- **Rule 1 (Suspicious Download)** — Caught the update.exe execution. Required tuning to ignore software installers run within 1 hour of download.
- **Rule 5 (Process Parent-Child)** — Effectively flagged notepad → cmd scenarios. Most false positives came from admin tools.

### What Needs Tuning

- **Rule 3 (Failed Escalation)** — High false positive rate if admins run bulk user scripts. Required baseline tuning per environment.
- **Rule 4 (Enumeration)** — Multiple legitimate tools use enumeration commands. Tuning required: whitelist by process signature.

### Lessons Learned

1. **Context matters** — The same command (net user) is malicious in one context (attacker post-exploitation) but legitimate in another (admin automation). Rules need context.
2. **False positives kill detections** — If a rule triggers too often on benign activity, analysts ignore it (alert fatigue). Tuning is critical.
3. **Whitelisting is essential** — Don't block tools, whitelist known-good. Your detection should alert on *unknown* executables running enumeration commands, not all enumeration.
4. **Environment-specific** — Rules that work in one company won't work in another. Insurance company baselines differ from tech company baselines. Always tune.

## 📁 Repository Structure

```
Detection-Engineering-Lab/
├── README.md (this file)
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

## 🔗 Linked to SOC Investigation Lab

This project builds on the attack techniques identified in my SOC Investigation Lab (https://github.com/JP13007/SOC-Investigation-Lab). Each rule targets a specific technique from that incident:

- **Rule 1** — Detects the update.exe malware delivery (T1204)
- **Rule 2** — Detects the reverse shell callback to Kali (T1071)
- **Rule 3** — Detects failed persistence attempts (T1548)
- **Rule 4** — Detects post-compromise enumeration (T1033)
- **Rule 5** — Detects suspicious process execution (T1059)

## 📚 References

- [Sigma Documentation](https://sigma.readthedocs.io/)
- [Atomic Red Team](https://atomicredteam.io/) — Automated attack simulations
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma/tree/master/rules)

## 💡 Skills Demonstrated

- Sigma detection rule writing
- Attack technique understanding (MITRE ATT&CK)
- False positive tuning and baseline establishment
- Log analysis and forensic investigation
- Security tool integration (Splunk, Atomic Red Team)
- Technical documentation and communication

---

**Author:** JP13007  
**Status:** Complete — 5 rules written, tested, and tuned  
**Tested Against:** Sysmon and Windows Security logs from SOC Investigation Lab

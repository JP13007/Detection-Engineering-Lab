# Detection Engineering Lab: Sigma Rule Development & Validation

Writing Sigma detection rules for common attack techniques, validating them against real captured telemetry, finding and fixing logic errors, and tuning for false positives. This lab demonstrates the full detection-engineering loop — including the parts where rules failed their own validation and had to be corrected.

## Project Overview

Detection Engineering is the practice of building rules that alert on attacker behavior automatically. The skill is not just writing a rule that *looks* right — it is validating that the rule actually fires on real telemetry, and tuning it so it catches malicious activity without drowning analysts in false positives.

This lab demonstrates the complete workflow:
1. **Identify an attack technique** — drawn from my [SOC Investigation Lab](https://github.com/JP13007/SOC-Investigation-Lab)
2. **Write a Sigma detection rule** — in the industry-standard YAML format
3. **Validate against real telemetry** — using Atomic Red Team to generate attacker behavior, plus manual reproduction where atomics did not fit
4. **Find and fix rule errors** — several rules did not fire on their own captured data and were corrected
5. **Tune for false positives** — reasoned tuning strategy, documented honestly as anticipated vs. tested

## Validation Method (Important — Read This)

Each rule was validated against **real Sysmon telemetry captured in the lab**, not against assumed or invented results. Two approaches were used depending on what fit the rule:

- **Atomic Red Team** for rules where an atomic reproduces the behavior:
  - Rule 4 (enumeration) — Atomic **T1033-7** (net users from cmd.exe)
  - Rule 3 (account creation) — Atomic **T1136.001-4** (net user /add from cmd.exe)
- **Manual reproduction** for rules whose specific conditions no atomic reproduces:
  - Rule 1 (exe launched from Downloads by Explorer) — reproduced with a renamed benign file
  - Rule 5 (unusual parent spawning a shell) — reproduced explorer->cmd; stronger patterns documented as anticipated
- **Existing lab telemetry** for Rule 2 (the real Meterpreter callback), with an honest note on the lab's internal-only limitation

Full per-rule write-ups, including exact captured events and SPL queries, are in `test_results/`.

## Sigma Rules Included

| # | Rule | MITRE ID | Validation |
|---|------|----------|-----------|
| 1 | Suspicious Executable Execution from Downloads | T1204.002 | Manual reproduction (real event captured) |
| 2 | Outbound Connection to Non-Standard Port (C2) | T1071.001 | Real lab callback; external path noted as not exercised |
| 3 | Local Account Creation/Modification via net.exe | T1136.001 | Atomic Red Team T1136.001-4 |
| 4 | System/User Enumeration via Command-Line Tools | T1033 | Atomic Red Team T1033-7 |
| 5 | Suspicious Process Parent-Child (LOLBin) | T1059.003 | Manual reproduction (explorer->cmd) |

## What I Found by Validating (Not Assuming)

The most valuable part of this project was discovering that several rules **did not work as written** once tested against real data:

- **Rule 4** originally required `whoami` AND `net` AND `systeminfo` to all occur together. Real telemetry showed only `net users` ran, so the rule would not have fired despite genuine enumeration. Fixed to match any single enumeration command from a shell, with multi-command correlation moved to the tuning layer.
- **Rule 2** originally matched only *internal* IP ranges (10./172./192.) — the exact opposite of detecting external C2 — and hardcoded the lab attacker's IP. Fixed to exclude private ranges and target external destinations.
- **Rule 1** hardcoded a single filename (`update.exe`), so it would miss any other malicious download. Generalized to match the pattern (exe + Explorer parent + Downloads).
- **Rule 3** relied on EventID 5 (process termination), an unreliable signal. Fixed to match the process-creation event with `/add`, and pair with Windows Security EventID 4720 to confirm successful creation.
- **net.exe -> net1.exe delegation** — discovered that a single `net` command produces two process-creation events (Windows delegates to net1.exe), which rules must account for to avoid missing or double-counting.

These corrections are documented in each rule file and its test result.

## Scope & Honest Limitations

This is a single-VM home lab, and the write-ups are explicit about what that means:

- Validation is against **simulated attack telemetry in a lab**, not a production environment. No production false-positive rates are claimed.
- False-positive scenarios (legitimate installers, admin scripts, scanners) are documented as **anticipated tuning considerations**, reasoned but not separately executed as tests.
- **Rule 2's external-C2 path was not exercised** — the lab is internal-only, so a genuine external callback could not be safely generated. The port/connection logic was validated against the real internal callback; the external-destination path is logic-reviewed only.
- **Rule 5's high-value patterns** (notepad->powershell, calc->cmd) were not reproduced, as forcing them requires offensive tooling beyond this lab's scope. They are documented as anticipated detections.

## How to Use These Rules

### In Splunk
1. Convert the YAML rules to SPL with [sigma-cli](https://github.com/SigmaHQ/sigma-cli), or use the SPL provided in each rule's tuning notes.
2. Import as saved/correlation searches.
3. Configure alerts on match.

### In Other SIEMs
Sigma is SIEM-agnostic — each rule includes a Microsoft KQL conversion, and the rules convert to Elastic, QRadar, etc. via community converters.

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
    ├── test_results_rule_1.md
    ├── test_results_rule_2.md
    ├── test_results_rule_3.md
    ├── test_results_rule_4.md
    └── test_results_rule_5.md
```

## Linked to SOC Investigation Lab

This project builds on the techniques observed in my [SOC Investigation Lab](https://github.com/JP13007/SOC-Investigation-Lab):

- Rule 1 — malware delivery via download (T1204)
- Rule 2 — reverse shell callback (T1071)
- Rule 3 — account creation for persistence (T1136)
- Rule 4 — post-compromise enumeration (T1033)
- Rule 5 — suspicious process execution (T1059)

## References

- [Sigma Documentation](https://sigma.readthedocs.io/)
- [Atomic Red Team](https://atomicredteam.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma/tree/master/rules)

## Skills Demonstrated

- Sigma detection rule authoring
- Validation against real telemetry using Atomic Red Team and manual reproduction
- Finding and fixing detection logic errors (the core of detection engineering)
- MITRE ATT&CK technique mapping
- False-positive tuning and baseline reasoning
- Cross-SIEM rule conversion (Splunk SPL, Microsoft KQL)
- Honest technical documentation, including limitations

---

**Author:** JP13007
**Status:** 5 rules written, validated against real captured telemetry, corrected where validation revealed logic errors
**Validated With:** Atomic Red Team (T1033, T1136) + manual reproduction; Sysmon telemetry via Splunk"# Detection-Engineering-Lab" 

# Rule 3 Test Results: Account Creation via net user /add

**Rule ID:** detection-003
**Technique:** T1136.001 — Create Account: Local Account
**Test Method:** Atomic Red Team (T1136.001-4), validated against captured Sysmon telemetry
**Tester:** JP13007

---

## Test Scenario

**Behavior tested:** Creation of a local user account using `net user /add` from a command prompt — a common persistence and privilege-escalation step.

**Tooling:** Atomic Red Team test T1136.001-4 ("Create a new user in a command prompt"), executed on the Windows 10 lab VM (DESKTOP-9BB4HVN) with Sysmon forwarding to Splunk. The test account was removed afterward via the atomic's cleanup command.

---

## Important Context: Success vs. Failure

Rule 3 was originally built around a **failed** account-creation attempt captured in the SOC Investigation Lab — Meterpreter ran `net user hacker /add` under a restricted (Medium-integrity) token and it was blocked with "Access is denied" (exit code 5).

This atomic test runs in an **elevated/admin** context, so the same command pattern **succeeds** (the account is actually created, exit code 0). The command pattern is identical; the outcome differs because of privilege level.

This is the honest, important finding: **Rule 3 detects the `net user /add` command pattern regardless of whether it succeeds or fails.** A rule that only fired on failures would miss successful malicious account creation, which is arguably the more dangerous case. Both the lab's failed attempt and this successful creation match the rule.

---

## Test Execution

### What the atomic ran

```
net user /add "T1136.001_CMD" "T1136.001_CMD!"
```

Reported "The command completed successfully" — the account was created (admin context).

### Captured Sysmon events (EventID 1)

Confirmed in Splunk (`index=win_logs host=DESKTOP-9BB4HVN`, Last 24 hours):

| _time | CommandLine | ParentImage |
|-------|-------------|-------------|
| 2026-06-30 19:56:33.602 | "cmd.exe" /c net user /add "T1136.001_CMD" "T1136.001_CMD!" | C:\System32\WindowsPowerShell\v1.0\powershell.exe |
| 2026-06-30 19:56:33.781 | net user /add "T1136.001_CMD" "T1136.001_CMD!" | C:\Windows\System32\cmd.exe |
| 2026-06-30 19:56:33.817 | C:\Windows\system32\net1 user /add "T1136.001_CMD" "T1136.001_CMD!" | C:\Windows\System32\net.exe |

The middle event — `net user /add` with parent **cmd.exe** — is the event Rule 3 targets.

### Search used to confirm

```spl
index=win_logs host=DESKTOP-9BB4HVN
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="1"
| search "T1136"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| table _time, CommandLine, ParentImage
| sort -_time
```

### Cleanup

```
net user /del "T1136.001_CMD"
```
The test account was removed after capture.

---

## Full Process Chain Observed

The capture shows the complete execution chain:
1. **powershell.exe** (Atomic Red Team executor) spawned **cmd.exe**
2. **cmd.exe** ran `net user /add`
3. **net.exe** delegated to **net1.exe** (Windows' standard net -> net1 handoff)

The `net.exe -> net1.exe` delegation is the same behavior observed in the Rule 4 test. Any rule matching `net`-based commands must account for both Image values and de-duplicate, or it will either miss events or double-count one logical action.

---

## What This Validates

- Rule 3's detection pattern (`net user /add` from a command shell) matches real captured telemetry.
- The pattern fires whether the attempt succeeds (this test) or fails (the original lab event), which is the correct behavior.

## What This Does NOT Establish

- This is lab validation of the detection pattern, not a production false-positive rate.
- Legitimate-administration false positives are reasoned below, not separately executed.

---

## Note on Rule 3 YAML

The current rule uses EventID 5 (process termination) in `selection2`, which is not a reliable signal for account-creation attempts. The more robust approach is:
- Match the **process-creation** event (EventID 1) for `net.exe`/`net1.exe` with `user`/`localgroup` + `/add` in the command line (validated above).
- Pair with **Windows Security EventID 4720** (a user account was created) to confirm *successful* creation, vs. the Sysmon command event which captures the *attempt*.

This pairing distinguishes attempt from success and is the recommended production form.

---

## Anticipated False Positives & Tuning Strategy

Reasoned tuning, not executed test cases:

- **Legitimate admin / onboarding scripts** that create accounts → whitelist known admin service accounts and management tooling (SCCM, automation agents) by parent process.
- **Help desk automation** → baseline expected account-creation frequency; alert on deviations or on creation from unusual parents.
- **Context** → `net user /add` from a freshly spawned shell under an unusual parent is higher-signal than the same command in an admin's interactive session.

---

**Status:** Detection pattern validated against real captured Sysmon telemetry for T1136.001-4 (net user /add, parent cmd.exe). Documented the honest success-vs-failure distinction from the original lab event, the net->net1 delegation, and a recommended YAML improvement (EventID 1 + pairing with Security 4720). False-positive behavior reasoned but not separately tested.
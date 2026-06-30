# Rule 4 Test Results: System and User Enumeration

**Rule ID:** detection-004
**Technique:** T1033 — System Owner/User Discovery
**Test Method:** Atomic Red Team (T1033-7), validated against captured Sysmon telemetry
**Tester:** JP13007

---

## Test Scenario

**Behavior tested:** Enumeration commands run from a command prompt (`net users`), characteristic of post-compromise reconnaissance.

**Tooling:** Atomic Red Team test T1033-7 ("System Owner/User Discovery Using Command Prompt"), executed on the Windows 10 lab VM (DESKTOP-9BB4HVN) with Sysmon forwarding to Splunk.

---

## Test Execution

### What the atomic ran

T1033-7 executes the following from `cmd.exe`:
```
echo Username: %USERNAME%
echo User Domain: %USERDOMAIN%
net users
query user
```

### Actual result

The test executed and reported **Exit code: 1**, because `query user` is not available on this Windows 10 build:
```
'query' is not recognized as an internal or external command,
operable program or batch file.
Exit code: 1
Done executing test: T1033-7 System Owner/User Discovery Using Command Prompt
```

This is an honest finding, not a clean pass: one of the four commands (`query`) was unavailable on the host, so it did not run. The commands before it — including `net users` — did execute and were captured.

### Captured Sysmon events (EventID 1)

Confirmed in Splunk (`index=win_logs host=DESKTOP-9BB4HVN`, Last 24 hours):

| _time | CommandLine | ParentImage |
|-------|-------------|-------------|
| 2026-06-30 19:17:21.958 | C:\Windows\system32\net1 users | C:\Windows\System32\net.exe |
| 2026-06-30 19:17:21.923 | net users | C:\Windows\System32\cmd.exe |

The `net users` command was captured with **cmd.exe as the parent process**, which is exactly the pattern Rule 4 keys on.

### Search used to confirm

```spl
index=win_logs host=DESKTOP-9BB4HVN
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="1"
| search "net.exe"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| table _time, CommandLine, ParentImage
| sort -_time
```

---

## Key Technical Finding: net.exe -> net1.exe delegation

Each `net` command produced **two** process-creation events:
- `net users` with parent **cmd.exe**
- `net1 users` with parent **net.exe**

This is because Windows `net.exe` automatically delegates execution to `net1.exe`. Any detection rule for `net`-based enumeration must account for this, or it risks either missing events (if it only looks for `net1.exe`) or double-counting (if it counts both as separate enumeration actions). Rule 4 includes both Image names but notes that downstream correlation should de-duplicate.

---

## What This Validates

- Rule 4's detection logic (enumeration command spawned from cmd.exe) matches real captured telemetry from a known enumeration technique.
- The rule would fire on this event.

## What This Does NOT Establish

- This is **lab validation against a single simulated technique**, not a production false-positive rate. No claim is made about how often this rule would fire on benign activity in a real environment.
- Anticipated false positives (legitimate troubleshooting scripts, inventory tools, vulnerability scanners running enumeration) are documented in the rule's tuning notes as *expected* behavior to tune for — they were not executed as separate tests in this lab.

---

## Anticipated False Positives & Tuning Strategy

In a production environment, this rule would also fire on legitimate enumeration. These are reasoned tuning considerations, not executed test cases:

- **Help desk / troubleshooting scripts** running whoami/ipconfig/systeminfo → tune by whitelisting known script paths and service accounts.
- **Vulnerability scanners / inventory tools** (Nessus, SCCM, etc.) → whitelist by parent process.
- **Timing/context** → enumeration from a freshly spawned cmd.exe under an unusual parent is higher-signal than the same command from an admin's interactive session.

---

**Status:** Detection logic validated against real captured Sysmon telemetry for T1033-7 (net users). `query user` sub-command unavailable on host (exit code 1). False-positive behavior reasoned but not separately tested in lab.
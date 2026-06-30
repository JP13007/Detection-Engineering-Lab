# Rule 5 Test Results: Suspicious Process Parent-Child (LOLBin / Unusual Shell Parent)

**Rule ID:** detection-005
**Technique:** T1059.003 — Command and Scripting Interpreter: Windows Command Shell
**Test Method:** Manual reproduction of the lowest-risk rule pattern (explorer -> cmd), validated against captured Sysmon telemetry. Higher-risk patterns documented as anticipated detections (see limitations).
**Tester:** JP13007

---

## Test Scenario

**Behavior tested:** A command interpreter (cmd.exe) spawned by a GUI/utility parent process. Rule 5 targets the "unusual parent launches a shell" pattern used in Living-off-the-Land (LOLBin) execution, where attackers use legitimate programs as launchers to blend in.

**Why manual reproduction rather than Atomic Red Team:** The Atomic Red Team T1059.003 tests (batch scripts, command-shell execution, etc.) all run commands *inside* cmd.exe with the atomic's own executor as the parent. Rule 5 keys on the **launcher** (the parent process), not on what runs inside the shell. None of the available atomics reproduce an office/utility app spawning a shell, so they do not exercise this rule. The detectable portion was reproduced manually.

---

## Test Execution

### What was run

cmd.exe was launched from Windows Explorer (typing `cmd` into the File Explorer address bar), producing a process-creation event with **explorer.exe as the parent** — one of the parent processes in Rule 5's selection list.

### Captured Sysmon event (EventID 1)

Confirmed in Splunk (`index=win_logs host=DESKTOP-9BB4HVN`, Last 24 hours):

| _time | Image | ParentImage |
|-------|-------|-------------|
| 2026-06-30 20:10:36.533 | C:\Windows\System32\cmd.exe | C:\Windows\explorer.exe |

(Additional explorer -> cmd events from earlier in the session are also present, e.g. 19:13:48, 18:56:23, consistent with the same pattern.)

### Search used to confirm

```spl
index=win_logs host=DESKTOP-9BB4HVN
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="1"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| where like(Image,"%cmd.exe") AND like(ParentImage,"%explorer.exe")
| table _time, Image, ParentImage
| sort -_time
```

---

## Honest Assessment: This Validates the Rule's WEAKEST Pattern

The captured event (explorer -> cmd) matches Rule 5, but it is deliberately the rule's **lowest-priority** pattern, and this is the most important point in this document:

- **explorer.exe -> cmd.exe is frequently legitimate.** Users open command prompts from Explorer routinely (address bar, context menu, Shift+right-click). On its own it is a high-false-positive signal, which is exactly why Rule 5's own tuning notes rank it as MEDIUM/low priority and require additional command-line context to be actionable.
- Validating against this pattern proves the rule's parent-child matching *mechanism* works, but it does **not** demonstrate detection of the genuinely suspicious cases.

### The strong patterns were NOT reproduced (and why)

Rule 5's high-value detections are combinations that are almost never legitimate:
- **notepad.exe -> powershell.exe**
- **calc.exe -> cmd.exe**
- **mspaint.exe -> cmd.exe**

These were **not** reproduced in this lab. Forcing a text editor or calculator to spawn a shell does not happen through normal use — it requires offensive techniques (e.g. IFEO/debugger hijack, process injection, or a malicious document/macro acting as the launcher), which were outside the scope and tooling of this lab. Rather than fabricate these results, they are documented here as **anticipated detections**: the rule is written to catch them, and the matching logic is validated by the explorer->cmd case, but the high-risk pairs themselves were not executed.

This is an honest limitation. A production validation of this rule would use a malicious-document or injection technique to generate a true notepad->powershell event; that is a logical next step for this lab.

---

## What This Validates

- Rule 5's parent-child matching logic fires correctly against real telemetry (explorer -> cmd captured).

## What This Does NOT Establish

- The rule's high-value detections (notepad/calc -> shell) were not reproduced and are documented as anticipated, not tested.
- No production false-positive rate is claimed. The explorer->cmd pattern in particular is expected to be high-FP and should not be alerted on without additional command-line context.

---

## Recommended Rule Improvement

Given that explorer->cmd is high-FP, the rule is materially stronger if the parent-child match is combined with suspicious command-line content (the rule already proposes this as an enhancement). Recommended production form:

- **Tier 1 (high confidence, alert):** notepad/calc/mspaint/wordpad -> cmd/powershell — almost never legitimate, alert regardless of command line.
- **Tier 2 (needs context):** explorer/taskmgr -> cmd/powershell — only alert when the child command line contains enumeration/encoded-command indicators (whoami, net user, `-enc`, IEX).

This two-tier approach keeps the strong signals high-priority while suppressing the explorer->cmd noise that this test demonstrated.

---

**Status:** Parent-child matching logic validated against real captured telemetry (explorer -> cmd). Honestly documented that this is the rule's weakest, highest-FP pattern; the high-value patterns (notepad/calc -> shell) were not reproduced and are recorded as anticipated detections with the reason why. Recommended a two-tier refinement to separate strong signals from noisy ones.
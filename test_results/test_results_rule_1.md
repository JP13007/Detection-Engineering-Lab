# Rule 1 Test Results: Suspicious Executable Download and Execution

**Rule ID:** detection-001
**Technique:** T1204.002 — User Execution: Malicious File
**Test Method:** Manual reproduction of the detection scenario, validated against captured Sysmon telemetry
**Tester:** JP13007

---

## Test Scenario

**Behavior tested:** An executable located in the Downloads folder is launched by the user via Windows Explorer (double-click). This is the core pattern Rule 1 detects — the user-execution step of a phishing or drive-by-download attack.

**Why manual reproduction rather than Atomic Red Team:** The available Atomic Red Team T1204.002 tests are predominantly Office-macro and document-based execution (OSTap, maldocs, Excel 4 macros), or download executables to %TEMP% under a PowerShell parent. None reproduce Rule 1's specific conditions (an .exe in Downloads, launched by explorer.exe). To validate the rule's actual detection logic, the exact scenario was reproduced by hand using a benign file.

---

## Test Execution

### What was run

A benign copy of the Windows Calculator binary was placed in the Downloads folder under a download-style name, then launched from Windows Explorer:

```powershell
Copy-Item "C:\Windows\System32\calc.exe" "$env:USERPROFILE\Downloads\update_test.exe"
# then double-clicked update_test.exe in File Explorer
```

Using a renamed copy of calc.exe keeps the test completely benign while still producing a process-creation event with the parent/path characteristics the rule targets.

### Captured Sysmon event (EventID 1)

Confirmed in Splunk (`index=win_logs host=DESKTOP-9BB4HVN`, Last 24 hours):

| _time | Image | ParentImage | CurrentDirectory |
|-------|-------|-------------|------------------|
| 2026-06-30 19:43:59.219 | C:\Users\admin\Downloads\update_test.exe | C:\Windows\explorer.exe | C:\Users\admin\Downloads\ |

### Search used to confirm

```spl
index=win_logs host=DESKTOP-9BB4HVN
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="1"
| search "update_test"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='CurrentDirectory'>(?<CurrentDirectory>[^<]+)</Data>"
| table _time, Image, ParentImage, CurrentDirectory
| sort -_time
```

---

## Detection Pattern Validation

The captured event satisfies all three of Rule 1's selection conditions:

| Rule condition | Required | Captured event | Match |
|----------------|----------|----------------|-------|
| Image is an .exe in Downloads | Image ends with .exe, path contains Downloads | C:\Users\admin\Downloads\update_test.exe | Yes |
| Parent is Explorer | ParentImage ends with \explorer.exe | C:\Windows\explorer.exe | Yes |
| Executed from Downloads | CurrentDirectory contains Downloads | C:\Users\admin\Downloads\ | Yes |

The detection pattern (executable launched from Downloads by Explorer) is validated against real telemetry.

---

## Honest Finding: Rule Is Too Narrow As Written

The current rule YAML hardcodes the filename:
```yaml
Image|endswith: '\update.exe'
```

This means the rule would match the original lab artifact (`update.exe`) but would NOT match this test file (`update_test.exe`), nor any other malicious download with a different name. The filename hardcoding makes the rule brittle.

**Recommended fix:** Match the *pattern*, not a specific filename — i.e. any `.exe` whose ParentImage is explorer.exe and whose path is in Downloads — and then reduce false positives through tuning (signature checks, known-installer exclusions) rather than by pinning to one filename.

```yaml
detection:
  selection:
    EventID: 1
    Image|endswith: '.exe'
    ParentImage|endswith: '\explorer.exe'
    CurrentDirectory|contains: 'Downloads'
  condition: selection
```

This is the more realistic production form of the rule. The narrow `update.exe` version was an artifact of the original lab and is a genuine weakness, documented here rather than hidden.

---

## What This Validates

- The detection pattern (Explorer-launched executable in Downloads) fires correctly against real captured telemetry.

## What This Does NOT Establish

- This is lab validation of the detection pattern, not a production false-positive measurement.
- Anticipated false positives (legitimate installers, updaters) are reasoned below as tuning strategy, not executed as separate tests.

---

## Anticipated False Positives & Tuning Strategy

The broadened (pattern-based) rule would also fire on legitimate downloaded executables. Reasoned tuning, not executed test cases:

- **Legitimate installers** (setup.exe, application installers) launched from Downloads → whitelist Microsoft/trusted-publisher-signed binaries; the highest-value tuning lever is signature verification.
- **Software updaters** that drop and run executables → exclude by signature or known hash.
- **Time gap** → a file that sat in Downloads for hours before execution is lower-signal than one downloaded and immediately run.

---

**Status:** Detection pattern validated against real captured Sysmon telemetry (Explorer-launched exe in Downloads). Identified and documented a real rule weakness (hardcoded filename) with a recommended pattern-based fix. False-positive behavior reasoned but not separately tested in lab.
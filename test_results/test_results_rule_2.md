# Rule 2 Test Results: Outbound Connection to Non-Standard Port (Possible C2 Callback)

**Rule ID:** detection-002
**Technique:** T1071.001 — Application Layer Protocol / C2 Callback
**Test Method:** Validated against the real reverse-shell callback captured in the SOC Investigation Lab. External-destination path documented as a known limitation (see below).
**Tester:** JP13007

---

## Test Scenario

**Behavior tested:** A process establishing an outbound connection to a non-standard port (4444) used by reverse shells and C2 frameworks.

**Source data:** The genuine Meterpreter reverse-shell callback captured during the SOC Investigation Lab — the malware (`update.exe`) connecting back to the Kali attacker on port 4444.

---

## Real Captured Event (from SOC Investigation Lab)

This is genuine telemetry from the original lab attack, captured by Sysmon (EventID 3 — Network Connection):

```
Image:           C:\Users\admin\Downloads\update.exe
SourceIp:        192.168.1.21   (Windows 10 victim VM)
SourcePort:      49919
DestinationIp:   192.168.1.18   (Kali attacker)
DestinationPort: 4444
Protocol:        tcp
Initiated:       true
```

This is a real reverse-shell callback: the executed malware reaching out to the attacker's listener on the classic Metasploit default port 4444. The port and the outbound-initiated connection are exactly the indicators Rule 2 is built around.

---

## The Honest Limitation: Internal-Only Lab

This is the single most important point in this document, and it is a real constraint, not a failure:

**The lab is internal-only.** The attacker (Kali) sits at 192.168.1.18 — a private RFC1918 address on the same LAN as the victim. The real captured callback therefore goes to a **private IP**.

Rule 2 is designed to detect C2 to **external** infrastructure, and deliberately excludes private ranges via its `filter_private` block (so it does not alert on normal internal traffic). This creates an unavoidable tension in the lab:

- The rule's **port logic** (outbound to 4444) is validated by the real captured event above.
- The rule's **external-destination logic** (`not filter_private`) means the rule, as written for production, would **exclude** this lab's callback because the destination is private.

In other words: the real event proves the *port/connection* detection works, but the lab cannot produce a genuine *external* C2 callback to exercise the full rule end-to-end. Generating real external C2 traffic would require attacker infrastructure outside the lab (a VPS listener), which was out of scope.

**This was not faked.** Rather than invent an external connection or fabricate Docker/database false-positive scenarios (as an earlier draft did), the limitation is stated plainly. The honest position is: port-level detection validated against real telemetry; external-destination path validated by logic/SPL review but not by live external traffic.

---

## How the Rule Behaves on the Real Event

If `filter_private` is **temporarily removed** (to test the port logic against the lab data), the rule matches the real callback:

```spl
index=win_logs host=DESKTOP-9BB4HVN
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="3"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| where DestinationPort="4444"
| table _time, DestinationIp, DestinationPort
```

This confirms the port/connection portion of the rule fires on the real event. With `filter_private` in place (production form), the same event is correctly excluded as internal — which is the intended behavior for a rule hunting external C2.

---

## What This Validates

- The port-based detection (outbound connection to 4444) matches real captured reverse-shell telemetry.
- The `filter_private` logic correctly classifies the lab's callback as internal.

## What This Does NOT Establish

- The full external-C2 detection path was **not** exercised with live external traffic, because the lab is internal-only.
- No production false-positive rate is claimed.

---

## Recommended Next Step (Honest Path to Full Validation)

To validate this rule end-to-end against a genuine external callback:
- Stand up a cloud listener (a VPS running a Metasploit/netcat listener on 4444) outside the lab network.
- Generate a callback from the victim to that external IP.
- Confirm the rule fires *with* `filter_private` in place.

This is documented as the logical next step rather than simulated. It was not performed because it requires external attacker infrastructure beyond the current lab.

---

## Anticipated False Positives & Tuning Strategy

Reasoned tuning, not executed test cases:

- **Legitimate software using these ports to external services** (rare) → whitelist by process.
- **Remote-debugging / dev tools** configured on non-standard ports → whitelist by process and destination.
- **Timing** → a connection from a process created moments earlier is higher-signal (immediate callback) than a long-running process making an occasional connection.

---

**Status:** Port/connection detection validated against the real captured Meterpreter callback (192.168.1.21 -> 192.168.1.18:4444). External-destination path documented honestly as not exercised, because the internal-only lab cannot produce genuine external C2 traffic. No fabricated scenarios; recommended external-listener test documented as the next step.
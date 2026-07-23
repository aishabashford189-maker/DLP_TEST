# SentinelOne Analyst Tabletop Exercises

**Document type:** Facilitated tabletop exercises  
**Based on:** Anonymised historical SOC Security Events tickets (Critical severity, last 6 months)  
**Sessions:** 3 independent scenarios, 10–15 min each, ~30–45 min total  
**Target audience:** SOC Analysts (all levels)

---

# SCENARIO 1 — Ghost in the Installer

## Scenario Overview

| Field | Detail |
|---|---|
| **Title** | Ghost in the Installer |
| **Learning objective** | Triage a macOS SentinelOne alert where key context fields are absent; distinguish legitimate Apple system processes from genuine threats using path, signature, and hash analysis |
| **Expected outcome** | False positive — no action required |
| **Difficulty** | Easy |
| **Estimated time** | 10–12 minutes |

---

## Initial Alert

> Give the analyst ONLY the information below. Do not reveal anything else until they ask.

```
Alert Source:    SentinelOne (via Splunk)
Alert Name:      SOC-Alert-Sentinelone-Same malware detected on multiple computers
Severity:        Critical
Timestamp:       08 Jul 2026, 10:15 UTC
Detection Name:  package_script_service
Threat Class:    Malware
Confidence:      Suspicious

Affected hosts:  MACZOPA-01, MACZOPA-02  (2 endpoints)
Username:        [none]
OS:              [none]
IP address:      [none]

Threat description:
  "Threat with confidence level suspicious detected: package_script_service."

MITRE ATT&CK:    [none mapped]
Mitigation:      [not populated]
```

---

## Facilitator Guide

**Ground rule:** Reveal nothing proactively. Every data point must be in response to a specific investigative question or described action. If the analyst jumps to a conclusion without evidence, ask: *"What evidence leads you to that conclusion?"*

---

**IF the analyst asks about the SentinelOne console / threat details page:**

Reveal:
```
File path:   /System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/
             XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service
Hash (SHA1): 3e49604948e51d526257c16013f1cacaf77e20c5
Publisher:   Not shown in this alert type
Arguments:   None
Parent:      Not available for this alert type
```

---

**IF the analyst asks why no user, OS, or IP is shown:**

Reveal:
> This is consistent with macOS SentinelOne agents in this environment. The alert ingestion pipeline does not always populate these fields for macOS detections. The absence of user/IP context is a known gap for this alert type — it is not evidence of evasion.

---

**IF the analyst checks VirusTotal for the hash:**

Reveal:
> `3e49604948e51d526257c16013f1cacaf77e20c5` — **0 / 72 vendors flag this as malicious.** The file is identified by multiple vendors as a legitimate Apple macOS system binary.

---

**IF the analyst researches the file path:**

Reveal:
> `/System/Library/PrivateFrameworks/PackageKit.framework/` is Apple's macOS package management framework. `package_script_service` is an Apple-signed XPC service that executes pre/post-install scripts during software updates. It runs with elevated privileges as part of the macOS software update mechanism.
>
> This path is under `/System/Library/` — Apple's protected system volume, which is not writeable by third-party software or user processes on modern macOS.

---

**IF the analyst asks about both endpoints triggering simultaneously:**

Reveal:
> Both MACZOPA-01 and MACZOPA-02 triggered within 36 seconds of each other (10:15:58 and 10:16:34 UTC). Both are macOS. This timing is consistent with a coordinated system event — for example, a simultaneous macOS software update rollout or an MDM-pushed package installation running on both devices at the same time.

---

**IF the analyst checks for historical detections on these endpoints:**

Reveal:
> No previous detections on MACZOPA-01 or MACZOPA-02. No other active threats. No network connections recorded in the alert. No lateral movement indicators.

---

**IF the analyst asks about the "Critical" severity rating:**

Reveal:
> SentinelOne assigns severity based on the detection rule that fired ("Same malware detected on multiple computers"), not on a per-file analysis. Critical reflects the rule logic (multiple endpoints = potential spread), not the file's actual maliciousness. This is a known characteristic of this alert type.

---

**IF the analyst asks whether to raise an incident:**

Prompt first: *"What evidence do you have that supports raising an incident? What would you need to decide not to?"*

If they have reviewed path, hash, and timing — reveal:
> Legitimate Apple system binary, clean VT, protected system path, coordinated timing consistent with a software update. Historical closure for this case: **Closure Code: No incident found.** No IR actions required.

---

## Expected Investigation Flow

1. Receive alert — note Critical severity, no user/IP context
2. Open SentinelOne console — retrieve file path and hash
3. Recognise absent user/IP as a macOS pipeline gap, not a red flag
4. Research the file path — identify as an Apple system framework under `/System/Library/`
5. Check hash on VirusTotal — clean (0/72)
6. Note both machines triggered within seconds — consistent with a simultaneous update
7. Conclude: legitimate macOS system process, no malicious activity
8. Close: **No incident found**

---

## Decision Points

| Moment | Good reasoning looks like |
|---|---|
| No user / IP in alert | "This is likely a macOS pipeline limitation. I'll use the file path and hash for context instead of treating absence as evasion." |
| File under `/System/Library/` | "This is Apple's protected system partition. Third-party malware should not live here. My confidence in legitimacy increases." |
| VT clean | "Combined with the system path, this is strong evidence for a false positive." |
| Two machines at the same time | "Simultaneous hits are more consistent with a managed update event than an infection spreading between hosts." |
| Should I quarantine? | "No — I have no evidence of malicious code execution. Quarantining a clean system creates disruption without security benefit." |

---

## Expected Outcome

- **Classification:** False positive
- **IR actions:** None
- **Escalation:** None required
- **Ticket closure:** Closure Code — **No incident found**

---

## Debrief Questions

- What was the single most important piece of evidence? *(Expected: file path — `/System/Library/` is Apple's protected volume)*
- Would you have felt more confident with a username and IP? What does their absence tell you about macOS SentinelOne integration?
- At what point were you confident enough to close? What would have changed your decision?
- If VT had shown 1–2 detections rather than 0, would your conclusion change? What threshold would prompt further investigation?
- Was the Critical severity rating appropriate? What is the risk of over-alerting at Critical for this rule type?
- Could this detection be tuned or suppressed for Apple system binaries? What would you need to verify first?

---
---

# SCENARIO 2 — Six Alarms, One Inbox

## Scenario Overview

| Field | Detail |
|---|---|
| **Title** | Six Alarms, One Inbox |
| **Learning objective** | Triage a Windows alert with `agentInfected: true` and mixed mitigation status; correctly identify Outlook WebView2 cache artifacts as benign without prematurely quarantining a production endpoint |
| **Expected outcome** | False positive — additional investigation required; no quarantine; no incident raised |
| **Difficulty** | Medium |
| **Estimated time** | 12–15 minutes |

---

## Initial Alert

> Give the analyst ONLY the information below.

```
Alert Source:    SentinelOne (via Splunk)
Alert Name:      SOC-Alert-Sentinelone-Multiple malware detected on a single computer
Severity:        Critical
Timestamp:       18 Jun 2026, 07:27 UTC
Detection Name:  Multiple threats (6 total)
Threat Class:    General

Affected host:   WINZOPA-14
Username:        c.nicholls
OS:              Windows 11 Enterprise
Internal IP:     192.168.1.75
External IP:     83.105.93.8

Agent Infected:  true
Mitigation:      Mixed (some Mitigated / some Not mitigated)

MITRE ATT&CK:    [none mapped]
Threat description: [none]
```

---

## Facilitator Guide

---

**IF the analyst asks for the SentinelOne threat list / process tree:**

Reveal:
> Six threats detected, all within a 60-second window (07:27:09–07:27:10 UTC):

| # | Threat name | File path | Mitigation |
|---|---|---|---|
| 1 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `\...\Olk\Attachments\ooa-11fbc19d-...\6845844e...\e3b0c44...` | Mitigated |
| 2 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `\...\Olk\Attachments\ooa-11fbc19d-...\bb2a23be...\e3b0c44...` | Mitigated |
| 3 | `f_000052` | `\...\Olk\EBWebView\Default\Cache\Cache_Data\f_000052` | **Not mitigated** |
| 4 | `f_000053` | `\...\Olk\EBWebView\Default\Cache\Cache_Data\f_000053` | **Not mitigated** |
| 5–6 | (duplicate variants) | Same `Olk\Attachments` directory | Mitigated |

> Full paths: `\Device\HarddiskVolume3\Users\c.nicholls\AppData\Local\Microsoft\Olk\...`
>
> No process tree available. No parent process or command-line arguments captured.

---

**IF the analyst looks up the hash `e3b0c44...`:**

Reveal:
> `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` is the SHA-256 hash of an **empty file (0 bytes)**. This is a mathematically fixed value — every zero-byte file on every system in the world has this hash. It cannot represent a uniquely malicious file. VirusTotal: clean.

---

**IF the analyst asks about `f_000052` / `f_000053`:**

Reveal:
> These are Chromium-format disk cache files. The path `\Olk\EBWebView\Default\Cache\Cache_Data\` indicates they are part of Microsoft Outlook's embedded WebView2 browser cache — `Olk` is the new Outlook for Windows app. Files named `f_000052`, `f_000053` etc. are sequentially numbered cache data blocks (standard Chromium cache naming), holding cached web content from emails rendered inside Outlook — HTML emails, embedded images, tracking pixels.

---

**IF the analyst asks about the `Olk\Attachments` path:**

Reveal:
> `\AppData\Local\Microsoft\Olk\Attachments\` is the local attachment staging directory for new Outlook for Windows. When a user opens or previews an email attachment, Outlook writes it here temporarily. Files named `e3b0c44...` (the empty-file hash) indicate Outlook wrote zero-byte placeholder files — a known behaviour when attachments are staged but not fully downloaded, or when email content is pre-cached.

---

**IF the analyst asks whether `agentInfected: true` means the endpoint is actively compromised:**

Reveal:
> `agentInfected: true` is set by the SentinelOne agent when it classifies at least one active threat as present. In this case the flag was set because Outlook cache files were classified as threats. The flag does not confirm execution of malicious code — it reflects the agent's local classification. You must review the specific files before treating this as an active compromise.

---

**IF the analyst asks about the "Not mitigated" threats:**

Reveal:
> Threats 3 and 4 (`f_000052`, `f_000053`) were not quarantined — either because the mitigation policy for this detection type does not auto-quarantine, or because the files were locked by the Outlook process at detection time. "Not mitigated" does not mean the threats are actively executing; it means the agent did not automatically remove them.

---

**IF the analyst asks whether to isolate / quarantine the endpoint:**

Prompt first: *"What is your confidence level that malicious code executed on this endpoint? What evidence do you have either way?"*

If they have reviewed file paths and hashes — reveal:
> The files are Outlook WebView2 browser cache blocks and zero-byte attachment placeholders. No code execution, no process tree, no external network connections, no persistence mechanisms. Isolating a production endpoint based on cached email content would cause significant disruption without any security benefit.

---

**IF the analyst checks the user's activity or contacts the user:**

Reveal:
> c.nicholls is a current Zopa employee in the Lending team. She was at her desk and working normally when the alert fired. She was using Outlook and had been previewing several external emails that morning. No unusual activity. No recent travel or VPN from unusual locations.

---

**IF the analyst checks for other detections on WINZOPA-14:**

Reveal:
> No other SentinelOne detections on WINZOPA-14 in the past 30 days. No related alerts in the SOC queue. Last endpoint scan was clean.

---

**IF the analyst checks the external IP 83.105.93.8:**

Reveal:
> This is the endpoint's corporate egress IP (NAT/proxy). Not a suspicious destination — it is the office internet egress. No suspicious outbound connections in firewall or proxy logs around the time of the alert.

---

**IF the analyst asks whether to raise an incident:**

Reveal:
> Six detections, all attributable to Outlook WebView2 cache files and zero-byte attachment placeholders. No code execution. No network indicators. User activity consistent with normal email use. Historical closure: **Closure Code: False positive.** No incident required. The `agentInfected: true` flag was set by the detection of cache files, not an active compromise.

---

## Expected Investigation Flow

1. Receive alert — note `agentInfected: true` and mixed mitigation; resist immediate isolation
2. Open SentinelOne — retrieve all six file paths and names
3. Recognise `e3b0c44...` as the SHA-256 of an empty file — lowers concern immediately
4. Identify `Olk\EBWebView\Cache_Data\` as Outlook WebView2 browser cache
5. Identify `Olk\Attachments\` as Outlook's local attachment staging directory
6. Check for process tree, command-line arguments, network connections — none
7. Contact user or review activity — normal email use confirmed
8. Check for other detections on endpoint — none
9. Assess: all detections are Outlook cache artifacts; no execution; no network indicators
10. Close: **False positive**

---

## Decision Points

| Moment | Good reasoning looks like |
|---|---|
| `agentInfected: true` on arrival | "This flag is set by the agent's classification. I need to review the specific files before deciding if the endpoint is truly compromised." |
| `e3b0c44...` hash | "This is the hash of an empty file. It cannot be uniquely malicious. Every zero-byte file has this hash." |
| "Not mitigated" status | "This means SentinelOne didn't auto-quarantine, not that the threat is executing. I need to understand why before escalating." |
| Should I isolate? | "I have no evidence of code execution or active malicious behaviour. Isolating a production user's endpoint now would be premature and disruptive." |
| Should I raise an incident? | "No — Outlook WebView2 cache files flagged during normal email use is a false positive pattern. No escalation needed." |

---

## Expected Outcome

- **Classification:** False positive
- **IR actions:** None — no quarantine, no isolation
- **Escalation:** None required
- **Ticket closure:** Closure Code — **False positive**

---

## Debrief Questions

- What was the significance of `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`? Would you have known this without looking it up?
- Did `agentInfected: true` affect your initial response? How did you recalibrate?
- At what point did you consider contacting the user? Was that the right moment?
- What would you have done differently if VT had flagged one of the cache files?
- Is "Not mitigated" always a reason to escalate? What questions should you ask first?
- How would you document this closure to help a future analyst who sees the same pattern?

---
---

# SCENARIO 3 — Trusted But Noisy

## Scenario Overview

| Field | Detail |
|---|---|
| **Title** | Trusted But Noisy |
| **Learning objective** | Triage a Windows alert with an extremely high MITRE ATT&CK mapping and alarming behaviours; correctly identify HP Sure Click (Bromium) virtualisation software as the source; reach a confident verdict using publisher verification, hash reputation, and contextual reasoning |
| **Expected outcome** | Investigation completed — legitimate enterprise security software; no IR action required |
| **Difficulty** | Hard |
| **Estimated time** | 15 minutes |

---

## Initial Alert

> Give the analyst ONLY the information below.

```
Alert Source:    SentinelOne (via Splunk)
Alert Name:      SOC-Alert-Sentinelone-Malware detected
Severity:        Critical
Timestamp:       12 Jan 2026, 01:40 UTC
Detection Name:  BrLauncher.exe
Threat Class:    Malware

Affected host:   WINZOPA-09
Username:        f.grasty
OS:              Windows 11 Enterprise
Internal IP:     192.168.1.111
External IP:     193.221.129.90
Domain:          WORKGROUP

Agent Infected:  false
Mitigation:      Not mitigated

MITRE ATT&CK:    Multiple techniques mapped (count not shown)
```

---

## Facilitator Guide

---

**IF the analyst opens the SentinelOne threat details / behavioural indicators:**

Reveal (in batches — do NOT read the full list at once):

```
File:       BrLauncher.exe
Full path:  \Device\HarddiskVolume3\PROGRAM FILES\HP\Sure Click\servers\BrLauncher.exe
Arguments:  vSentry start
Publisher:  BROMIUM UK LIMITED
Agent infected: false
Mitigation: Not mitigated
```

*First batch of behavioural indicators:*
- Process wrote to a hidden file section
- Code injection to other process memory space via Reflection
- A new root certificate was added
- Microsoft Edge's private memory was accessed
- Application registered itself to become persistent via an autorun

*If analyst asks for more:*
- Attempt to duplicate thread pool object from remote process (injection indicator)
- Suspicious hard link was created
- Identified attempt to access a raw volume
- Process executed shellcode in another process
- Process executed with PE file embedded in resource
- A PPL process was executed by a non-PPL process
- Suspicious WMI query identified

*Total MITRE ATT&CK techniques:* **75 technique instances** across Process Injection, Defense Evasion, Privilege Escalation, Persistence, Discovery, Credential Access, and Execution.

---

**IF the analyst says "this looks very suspicious" and wants to quarantine / isolate immediately:**

Do NOT reveal the outcome. Instead ask:
> *"Before taking any containment action — what do you know about BrLauncher.exe? What does the file path tell you? What does the publisher field say?"*

---

**IF the analyst looks up BrLauncher.exe:**

Reveal:
> `BrLauncher.exe` is the launcher process for **HP Sure Click** (formerly Bromium vSentry). HP Sure Click is an enterprise endpoint security product that uses hardware-enforced micro-virtualisation to isolate potentially malicious web content and documents inside disposable micro-VMs. The argument `vSentry start` confirms it is launching the virtualisation engine.
>
> The path `C:\Program Files\HP\Sure Click\` is the standard installation location for this product.

---

**IF the analyst checks the digital signature / publisher:**

Reveal:
> The binary is signed by **BROMIUM UK LIMITED** — the original developer of vSentry before HP acquired the product. The certificate is valid. This is the expected publisher for HP Sure Click components.

---

**IF the analyst checks VirusTotal for the hash:**

Reveal:
> The file hash is **clean on VirusTotal — 0 malicious detections.** Multiple AV vendors identify it as `HP Sure Click` or `Bromium vSentry`. No malicious classification from any major vendor.

---

**IF the analyst asks why so many MITRE ATT&CK techniques are mapped:**

Reveal:
> HP Sure Click operates by creating isolated micro-virtual machines at the hardware level. To do this, it deliberately performs many of the same low-level operations that malware uses: code injection into processes (to intercept browser content), kernel-level hooking, and access to raw volumes. These are not malicious behaviours — they are the intended operation of a security product that works by emulating the techniques it is designed to defend against.
>
> High MITRE technique counts are characteristic of virtualisation and security software, not malware.

---

**IF the analyst asks why mitigation shows "Not mitigated":**

Reveal:
> SentinelOne detected the behavioural signatures but did not auto-quarantine because detection confidence was set to `suspicious` rather than `malicious`. The agent flagged it for analyst review rather than automatic remediation. This is correct behaviour — the agent is surfacing the detection rather than blindly quarantining a signed enterprise binary.

---

**IF the analyst asks whether HP Sure Click is deployed / approved at Zopa:**

Reveal *(label as simulated):*
> [SIMULATED] HP Sure Click / Bromium vSentry is deployed to a subset of endpoints as an approved enterprise security control. The presence of the binary in `C:\Program Files\HP\Sure Click\` on a Zopa-managed Windows 11 endpoint is consistent with an approved deployment. Confirm with IT Asset Management if you need to verify specific endpoint deployment status.

---

**IF the analyst checks other endpoint activity / SIEM:**

Reveal:
> No other suspicious activity on WINZOPA-09 in the 24 hours surrounding the alert. No unusual network connections, no lateral movement, no credential access events outside of normal user activity. f.grasty logged in at approximately 01:35 UTC — the Sure Click service initialised at 01:40 UTC as part of the user session startup.

---

**IF the analyst asks about `agentInfected: false`:**

Reveal:
> Unlike Scenario 2 where `agentInfected: true` was set by cache file detections, this alert shows `agentInfected: false` — meaning SentinelOne's own verdict is that the endpoint is **not infected**. The threat was flagged for analyst review but the agent itself did not conclude the endpoint was compromised.

---

**IF the analyst asks whether to raise an incident:**

Prompt first: *"Summarise your confidence level and your reasoning."*

If they have verified publisher, VT, file path, and Sure Click identity — reveal:
> Historical closure: **Closure Code: Investigation completed.** Documented reasoning: `BrLauncher.exe` is HP Sure Click. Binary signed and verified by BROMIUM UK LIMITED. Hash clean on VirusTotal. `agentInfected: false`. The endpoint agent appears to have been decommissioned or reimaged shortly after this event (no further detections). No IR actions required.

---

## Expected Investigation Flow

1. Receive alert — note alarming behavioural indicators and 75 MITRE techniques
2. Resist immediate quarantine — check file path and publisher first
3. Identify `C:\Program Files\HP\Sure Click\BrLauncher.exe` — standard HP Sure Click installation path
4. Check publisher: BROMIUM UK LIMITED — signed enterprise security product
5. Check VT: clean, identified as HP Sure Click by multiple vendors
6. Understand why MITRE count is high — virtualisation security software performs injection-like operations by design
7. Note `agentInfected: false` — SentinelOne's own verdict is no infection
8. Check for other endpoint activity — none suspicious
9. Confirm Sure Click is an approved enterprise control
10. Close: **Investigation completed** — legitimate enterprise security software

---

## Decision Points

| Moment | Good reasoning looks like |
|---|---|
| 75 MITRE techniques | "High technique count can indicate noisy security tooling, not just malware. I need to identify what the process actually is before treating this as an attack." |
| `vSentry start` argument | "This is a service start command. The argument name suggests virtualisation software." |
| Publisher: BROMIUM UK LIMITED | "This is a signed binary from a known vendor. This significantly changes my assessment." |
| VT clean | "Combined with signed publisher and legitimate path, this is strong evidence for a false positive." |
| `agentInfected: false` | "The SentinelOne agent itself doesn't believe this endpoint is infected — that's meaningful context." |
| Should I raise an incident? | "No — all evidence points to legitimate enterprise security software behaving as designed." |

---

## Expected Outcome

- **Classification:** Investigation completed — legitimate enterprise security software (HP Sure Click / Bromium vSentry)
- **IR actions:** None
- **Escalation:** None required
- **Ticket closure:** Closure Code — **Investigation completed**

---

## Debrief Questions

- What was the single piece of evidence that most changed your assessment? *(Expected: publisher signature — BROMIUM UK LIMITED, or VT reputation)*
- How did you feel when you first saw 75 MITRE ATT&CK techniques? Did that influence your initial thinking?
- At what point would the evidence have led you to quarantine the endpoint instead? What would that threshold look like?
- How does `agentInfected: false` affect your interpretation of a SentinelOne alert? When is this field trustworthy?
- What is the risk of building a suppression rule for Sure Click behaviours? What attacker technique would that suppress alongside the legitimate tool?
- Would your approach differ if the binary was unsigned? If it was in `C:\Users\f.grasty\AppData\` instead of `C:\Program Files\`?
- How would you document this to prevent future analysts spending 15 minutes reaching the same conclusion?

---
---

# PHASE 4 — FACILITATOR NOTES

---

## Skills Being Assessed

| Skill | Assessed in |
|---|---|
| Alert triage and prioritisation | All scenarios |
| SentinelOne console proficiency | All scenarios |
| File path and process context analysis | All scenarios |
| Hash / VirusTotal reputation checking | Scenarios 1, 3 |
| Digital signature verification | Scenario 3 |
| Understanding of EDR detection logic (`agentInfected`, confidence levels) | Scenarios 2, 3 |
| Knowledge of enterprise tooling (macOS pipelines, Outlook WebView2, HP Sure Click) | All scenarios |
| Evidence-based decision making (not alert-driven panic) | Scenarios 2, 3 |
| Communication and reasoning articulation | All scenarios |
| Correct application of escalation and IR thresholds | All scenarios |
| Ticket documentation and closure | All scenarios |

---

## Scoring Matrix

Score each dimension 1–5.

| Dimension | 1 — Needs Development | 3 — Competent | 5 — Excellent |
|---|---|---|---|
| **Investigation methodology** | Skipped steps, jumped to conclusions | Followed a logical sequence with minor gaps | Systematic, prioritised highest-value evidence first |
| **Appropriate tool usage** | Did not identify which tool to use, or used the wrong tool | Identified correct tools; some prompting needed | Named correct tools unprompted; described what to look for |
| **Investigative questions** | Asked few or vague questions | Asked relevant questions; some gaps | Precise, targeted questions covering all key evidence sources |
| **Evidence gathering** | Acted on incomplete evidence | Gathered sufficient evidence to reach a verdict | Evidence proportionate to risk; knew when to stop |
| **Risk assessment accuracy** | Incorrect verdict (closed a TP or escalated an FP) | Correct verdict; reasoning partially articulated | Correct verdict; clear, well-reasoned justification |
| **IR action recommendation** | Disproportionate or incorrect response | Correct response type; some uncertainty | Correct, proportionate response with explicit justification |
| **Communication clarity** | Difficult to follow reasoning | Understandable with some prompting | Concise, structured; could be relayed directly to a manager |

**Guidance:** Use half-points if needed. A score of 3 across all dimensions = competent analyst. Scores of 4–5 indicate readiness for senior/lead responsibilities. Scores of 1–2 on risk assessment or IR actions warrant immediate follow-up coaching.

---

## Facilitator Tips

**How much to reveal**  
Reveal nothing proactively. Every data point must be earned through a specific investigative question or described action. If the analyst says "I would check SentinelOne," ask: *"What specifically would you look at, and what would you be looking for?"*

**When to prompt**  
If the analyst is silent for more than 60 seconds or appears stuck, use neutral prompts:
- *"What's your current hypothesis?"*
- *"What evidence would change your assessment?"*
- *"What tools haven't you checked yet?"*

Never use leading questions like *"Have you considered looking at the publisher?"* — that hands them the answer.

**Avoid confirming hunches**  
If an analyst says *"I think this is HP Sure Click"* before checking the publisher, respond: *"Interesting hypothesis. What evidence are you going to use to confirm or refute that?"* Make them earn the conclusion.

**Assess reasoning over correctness**  
An analyst who reaches the correct verdict through flawed reasoning scores lower than one who reaches it through systematic evidence review. The scoring matrix separates evidence gathering from verdict accuracy.

**For group sessions**  
Nominate one lead analyst who asks questions and calls decisions. Others can offer suggestions but the lead makes the call. The debrief should invite the group to challenge the lead's reasoning — this surfaces different mental models.

**Managing time**

- *Scenario 1:* Aim to close in ≤10 min. If still undecided at 10 min, ask: *"You have two minutes to make a decision — what would you do right now?"*
- *Scenario 2:* The `agentInfected: true` flag usually causes the most hesitation. If stuck on quarantine vs. no-quarantine, ask the analyst to articulate what evidence they would need to make that call.
- *Scenario 3:* The 75 MITRE techniques are deliberately overwhelming. Give time to work through them — but if the analyst is cataloguing individual techniques rather than identifying the process, prompt: *"What does the file path and publisher tell you before you look at the MITRE list?"*

**After the session**  
Collect the scoring matrix before the debrief. The debrief questions are designed to surface reasoning gaps not visible during the exercise. Pay particular attention to how analysts would document their findings — this reveals whether they think about knowledge transfer to future analysts, not just resolving the current ticket.

---

*Document prepared from anonymised historical SOC Security Events tickets (Jira project: SOC, Critical priority, Jan–Jul 2026). All hostnames, usernames, and IP addresses have been modified. Technical details (file paths, hashes, publisher names, MITRE mappings) are preserved from real cases to maintain investigative realism.*

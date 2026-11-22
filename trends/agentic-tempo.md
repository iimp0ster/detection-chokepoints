---
layout: default
title: Agentic Offensive Tempo
description: "Incident evidence and a synthetic test for how agentic pacing, retries, parallelism and ordering affect detection and response."
permalink: /trends/agentic-tempo/
---

<article class="ac-prose" style="max-width: 800px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem;" markdown="1">

[Back to Trends]({{ '/trends/' | relative_url }})

# Agentic Offensive Tempo

An agent can queue independent actions in parallel, retry a failed tool call, or change which action it takes next. When the action stays the same, the target still applies the same environmental checks. An AWS service still makes an authorization decision and a Windows remote service still needs to accept a request before the target runs anything. The practical question for defenders is whether the same telemetry still produces a useful alert when actions arrive in a different order or the response window shrinks.

## What incident investigators observed

**Anthropic, September 2025 campaign.** Anthropic reported that humans chose targets and intervened at key decisions while a Claude Code-based system performed much of the tactical work. The provider reported successful intrusions in a small subset of targeted organizations. It also documented reports of credentials that failed verification and public information presented as a sensitive discovery. An agent's claimed result needs confirmation from the affected environment. [Anthropic campaign write-up](https://www.anthropic.com/news/disrupting-AI-espionage), [technical report, pp. 3–4 and 7](https://assets.claude.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf).

**GTIG and Mandiant, ARTEX.** The investigators reported bursts interspersed with longer pauses. One AWS permissions-probing burst produced 27 events in 23 seconds of active time. In a separate case, investigators saw repeated execution attempts and errors that they judged could reflect sub-agents interfering with one another. The burst count describes a single observed interval. [GTIG and Mandiant, *ARTEX and Friends*, “Observations in the Wild”](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks).

**GTIG, CAIRN and PentAGI.** GTIG reported CAIRN use in intrusion activity and separately tracked reconnaissance and vulnerability scanning with a customized platform based on PentAGI. The public CAIRN summary leaves the individual victim-side steps unspecified. The cited PentAGI case establishes reconnaissance and scanning. [GTIG, November 2026 *AI Threat Tracker*, “Multi-Agent Frameworks in Cyber Intrusions”](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold).

## Framework capabilities and incident evidence

GTIG describes CAIRN coordinating agents through shared state and PentAGI dividing work among specialized agents. Those designs make parallel work and feedback-driven sequencing plausible. For a particular intrusion, simultaneous activity needs timestamps or overlapping request intervals. A retry needs evidence that a subsequent attempt followed the earlier result. A framework description or demonstration establishes capability under its own conditions. A tool mention, configuration artifact or agent transcript can guide an investigation, with victim-side logs needed to confirm the action and its effect. [GTIG and Mandiant framework analysis](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks), [GTIG November tracker](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold).

## Existing chokepoints to use

- [AWS Stolen Credential Permission Enumeration]({{ '/chokepoints/aws-credential-permission-enumeration/' | relative_url }}) applies when an operator tests permissions by issuing AWS requests. The service still produces an authorization outcome. CloudTrail visibility depends on operation support and logging configuration. A multi-service denial burst is a hunt heuristic, and GTIG's ARTEX example provides a reason to test its sensitivity to pacing.
- [Remote Execution Tools]({{ '/chokepoints/remote-execution-tools/' | relative_url }}) covers Windows remote-management mechanisms including WinRM. GTIG reported ARTEX attempting lateral movement with WinRM among other methods and endpoint protection blocking execution. Correlate authentication or service access with a target-side process or service effect to establish successful execution. [GTIG and Mandiant, “Move Laterally” in the ARTEX lifecycle table](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks).
- [Web Shell Persistence]({{ '/chokepoints/web-shells/' | relative_url }}) looks for a web server spawning a child interpreter. GTIG observed repeated ARTEX web-shell attempts followed by returned command output. Treat the public report as evidence of web-mediated execution and verify the child-process lineage separately before applying that analytic. [GTIG and Mandiant, “Observations in the Wild”](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks).
- [C2 Service Relationship Correlation]({{ '/chokepoints/c2-service-relationship-correlation/' | relative_url }}) applies when tasking or results cross a remote client-to-service path. Use direction, service role and time-bounded endpoint or network evidence. A shared destination or rotating service identity is weak evidence by itself.

These mappings apply to the actions that occur. Orchestration can choose a different action and cross a different boundary. Fast activity is also common in ordinary administration, scheduled jobs and legitimate agents. Map the observed behavior to its existing technique and use independent evidence for any claim about the controller.

## Correlation windows and time to respond

A short event-time window can catch a tight burst and miss the same sequence when a pause divides it. Wider windows can recover those joins and increase unrelated matches. Parallel work and reordered steps can break a strict sequence even when all events fit the window. Independent collectors may also deliver events out of order. Preserve both event and arrival times, and test how late records, retries and deduplication affect the join.

Measure response against the action the team wants to interrupt. A correlation that fires on the final state change can confirm the outcome. An earlier detection based on an authorization or execution signal may provide lead time for containment. Include collection, rule scheduling, queueing, triage and containment latency when measuring that margin.

## Proposed synthetic replay

Use only generated event records from a mock service. In each positive run, use one synthetic principal and session, an initial identity record, two independent permission checks (A denied, B allowed), one retry of A that is also denied, and a final harmless marker write authorized by B. Give every attempt a unique event ID and give both A attempts the same logical request ID. Keep the records, outcomes and objective fixed across the three runs. Vary their timestamps and the order of independent checks while keeping B before the marker and A before its retry.

- **Paced serial** — Identity at 0 seconds, A at 15, retry at 45, B at 100, marker at 140.
- **Compressed serial** — Identity at 0, A at 1, retry at 2, B at 4, marker at 8.
- **Compressed reordered** — Identity at 0, B at 1, A at 2, retry at 3, marker at 8.

First use event times as arrival times. Compare a same-principal and same-session ordered join (A denied → B allowed → marker) with a join that accepts either order for A and B and still requires both before the marker. Sweep illustrative windows of 10 and 180 seconds from the first matched check to the marker. With complete delivery, both joins should match the compressed serial run in either window. Only the wider window should match the paced run, and only the join that accepts either order should match the reordered run. Emit one match per principal, session and marker ID so the A retry cannot duplicate the alert.

For an early-warning comparison, alert as soon as the first same-session A denial and B allow are both available and within the selected window, in either order. Compare that alert with the marker even if the alert arrives later. With immediate processing and complete delivery, the 180-second setting should surface both compressed runs at 4 and 2 seconds respectively, and the paced run at 100 seconds. Apply the same illustrative 5-second triage delay after each alert and record whether triage begins before the marker. This measures an assumed response delay against a fixture timeline.

Stress one variable at a time on the compressed serial run:

- **Concurrency.** Let A run from 0.5 to 1 second and B from 0.75 to 4 seconds. Timestamp the results at completion. The result-based joins should behave as before even though the requests overlap.
- **Late delivery and retention.** Deliver the two A results at 12 and 13 seconds while preserving their event times of 1 and 2. Keep the session's partial match state for either 2 or 10 seconds after the marker arrives. The longer retention should recover the confirmation at 12 seconds, after the objective. The shorter retention should miss it.
- **Collection limit.** Accept only the first event per principal in each fixed 2-second arrival bucket starting at time 0. The identity record takes the first slot and the original A denial is dropped. The retry still allows a match, even though the collector lost one attempt.

Use two controls. A benign batch with similar check volume and the same A and B results but no marker can trigger the early alert and should never trigger confirmation. When the matching records are split across sessions, neither join nor the early alert should match. Record expected versus observed matches, alert volume, false joins, dropped events, event-to-alert delay, and alert-to-marker lead time. Count attempts by event ID and logical requests by request ID. These are fixture expectations to compare with detector behavior.

## Limits and measurements still needed

This proposed test measures the behavior of a specific correlation over generated records. It supplies no real-world detection rate, escalation outcome, or attribution to an AI controller. The incident reports cover selected cases with different visibility. Neither supplies matched human-directed, scripted and agent-driven traces for the same task and environment.

To compare orchestration methods, collect attributable paired traces with equivalent actions and objectives, plus routine administrative baselines. Record sample size, unfinished runs, event-clock skew, late arrivals, collection gaps and dropped or rate-limited events. Measure inter-action and inter-stage gaps, retries per logical request, overlap and fan-out, time to objective, false joins and time to triage or contain. Where possible, verify successful actions against the target's audit trail and state changes. Those observations are needed before recommending production thresholds or claiming a change in coverage.

</article>

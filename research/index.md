---
layout: default
title: Research Studies
description: Evidence, scope and limitations for Detection Lens Explorer studies.
---

<link rel="stylesheet" href="{{ '/assets/css/detection-lens-explorer.css' | relative_url }}" />

<section class="ac-index-hero lens-research">
  <div class="ac-index-hero-inner">
    <h1>Research Studies</h1>
    <p>Controlled studies of behavior, telemetry and evidence. Each study has its own cohort, evidence contract and limitations.</p>
  </div>
</section>

<section class="max-w-[1100px] mx-auto px-6 py-8 ac-prose lens-research" markdown="1">

[Open the Detection Lens Explorer]({{ '/lens-explorer/' | relative_url }}) · [Read the framework]({{ '/framework/' | relative_url }})

## Study findings

<div class="table-wrapper overflow-x-auto" role="region" aria-label="Study findings" tabindex="0" markdown="1">

| Study | Claim supported by its evidence | Limit |
| --- | --- | --- |
| Windows PR #49 | The controlled event-driven cohort matched 11 of 11 expected child starts using Sysmon and explicit instance binding. WMI in the separate workstation comparison observed 4 of 11 and supported 0 of 11 exact confirmations. | This is process creation in an instrumented application. It does not measure production coverage or a later command effect. |
| PHP PR #51 | Child and in-process paths completed a read of the same designated canary. Seven of seven research reads were confirmed. An approved route completed the same read. | Authorization and attribution are separate from a completed read. Delegated and in-process computations require different proof. The trace does not prove disclosure of real data. |
| Gate B | The synthetic full set confirmed all four primary positive effects. W/K/H qualified for the direct path and W/D/H for the delegated path. | The fixture supplies modeled identity, operation and outcome binding. These counts cover modeled input. |
| Gate C | Complete research instrumentation confirmed eight of eight primary delegated effects and zero of eight primary direct effects. W/D/H qualified for the delegated path. | Two delayed positive controls are outside the primary denominator. The scenario assessed fixed canary writes and authorization under an instrumented helper. |
| Gate C.2 | Final augmented replay confirmed 24/39 downstream effects, 7/19 boundary-policy violations, 12/19 downstream authorization violations and 7/14 causal edges. Downstream effects could persist when the upstream node or edge lacked evidence. | C2-01 was incomplete. Inert account, trust, schedule and service records did not realize adversary objectives. The measured result describes bounded canary scenarios. |
| C.2 operation diagnostic | Both two-run reference groups for the vectored variants observed completion. The selected runtime hook observed neither. Scalar and positional controls were seen in both groups for their own variants. | The reference and runtime rows are separate invocations. The result isolates a gap in the selected hook and capture configuration. |
| Gate C.3 | The synthetic A/B replay shows 10/16 downstream effects under the original modeled observer and 16/16 under the complementary observer. Delayed upstream evidence can leave the edge coverage limited while the downstream effect is confirmed. | Runtime attachment, recovery, and collection overhead are unmeasured. No C.3 live coverage claim is supported. |

</div>

## Interpreting the evidence

- **Measured** describes observations from a controlled lab cohort. **Synthetic** describes replay over modeled evidence. **Source-reported** behavior supplies context for possible paths and stays outside lab denominators.
- **Native evidence** comes from the tested collectors. Supplemental profiles add explicit bindings, applicable policy, transaction records, or independent outcome witnesses, as defined by each study.
- **Operation, effect, authorization and causality** have separate verdicts. A downstream effect can remain confirmed when its upstream cause is unresolved.
- The sanitized projection contains 1,746 replay and reporting rows across six studies. Each denominator applies to its study, cohort, cutoff, and claim. Coverage gaps and incomplete trials remain visible.

## Research boundaries

The container studies assess scoped canaries and inert records. They establish no universal observable container-escape chokepoint. Gate C.3 remains synthetic, with live capture recovery and collection overhead unmeasured. The studies provide no production coverage or false-positive estimates. The container-escape research candidate remains unresolved.

</section>

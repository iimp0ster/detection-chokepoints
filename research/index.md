---
layout: default
title: Research Studies
description: Detection lab results, synthetic comparisons, and the limits of what each telemetry source can confirm.
---

<link rel="stylesheet" href="{{ '/assets/css/detection-lens-explorer.css' | relative_url }}" />

<section class="ac-index-hero lens-research">
  <div class="ac-index-hero-inner">
    <h1>Research Studies</h1>
    <p>These studies cover child-process starts, file reads, and host effects. Compare what the collectors saw with what the lab could confirm.</p>
  </div>
</section>

<section class="max-w-[1100px] mx-auto px-6 py-8 ac-prose lens-research" markdown="1">

[Compare telemetry in the Lens Explorer]({{ '/lens-explorer/' | relative_url }}) · [Read the framework]({{ '/framework/' | relative_url }})

## Lab results and synthetic replays

<div class="table-wrapper overflow-x-auto" role="region" aria-label="Lab results and synthetic replays" tabindex="0" markdown="1">

| Study | Result | Scope |
| --- | --- | --- |
| Windows child-process starts | Sysmon events, tied to the exact request and process instance, confirmed 11 of 11 expected child starts. In a separate workstation run, WMI polling produced four observations across 11 expected starts and supported 0 of 11 exact confirmations. | The lab measured process creation. It did not measure a later command effect or production coverage. |
| PHP file reads | A child process and an in-process PHP worker read the same canary. The study confirmed 7 of 7 research reads. An approved route also read the file. | Check policy and attribution separately from read completion. The delegated test used a job key and an independent destination result. The reads used a test file and establish no disclosure of real data. |
| Host-write attribution (Gate B, synthetic) | With all lenses on, the replay confirmed all four primary positive effects. W/K/H qualified for direct writes and W/D/H for delegated writes. | The fixtures modeled the identity, operation, and outcome evidence needed to tie a write to its effect. These are fixture results. |
| Host writes (Gate C, measured) | The full evidence profile confirmed all 8 primary delegated effects. It could not confirm any of the 8 primary direct effects. W/D/H qualified for delegated writes. | The test used a fixed canary and an instrumented helper. The primary counts exclude two delayed positive controls. |
| Downstream host effects (Gate C.2, measured) | The final replay with supplemental evidence confirmed 24/39 downstream effects, 7/19 boundary-policy violations, 12/19 downstream authorization violations, and 7/14 causal links. The replay could confirm an effect while the boundary-policy violation or the causal link remained unresolved. | The scored cohort excludes incomplete trial C2-01. The lab used inert account, trust, schedule, and service records. It did not establish functioning persistence or completion of an attacker objective. |
| Linux write capture (Gate C.2, measured diagnostic) | Reference tracing recorded 2 of 2 completed writes for each vectored variant. In separate runs, the selected Tetragon hook captured 0 of 2 for each. Both observers captured the scalar and positional controls. | The gap applies to the selected hook and collection settings. |
| Linux write capture (Gate C.3, synthetic A/B) | The replay confirmed 10/16 downstream effects with the original modeled observer and 16/16 with the complementary observer. Late upstream evidence can leave the causal link open after the effect is confirmed. | Live hook attachment, capture recovery, and collection overhead still need a lab test. |

</div>

## Read the results

- **Measured** comes from a controlled lab. **Synthetic** comes from replaying modeled evidence. **Source-reported** tradecraft gives attack paths context and stays out of the lab counts.
- **Native evidence** comes from the collectors under test. Supplemental evidence can add actor or object identity, the applicable policy, a transaction record, or independent proof of an outcome.
- Check the verdict for the claim you want to make. A destination receipt can confirm a canary result while the link to the initiating workload remains unresolved.
- The dataset contains 1,746 replay and reporting rows across six studies. Each count uses its own study, cohort, receipt cutoff, and claim. The explorer shows missing evidence and records incomplete trials in the study notes.

## Where the evidence stops

The container studies used canaries and inert records to test specific attack paths. The proposed universal container-escape chokepoint remains unresolved. The lab supports claims about specific canary effects and test-policy violations. Exploitation, production detection coverage, and production false-positive rates are outside the study scope.

</section>

---
layout: default
title: "Container Escapes: Detecting Isolation Boundary Abuse"
description: "Follow host data access, host execution, and SSH trust through different container isolation boundaries."
---

<link rel="stylesheet" href="{{ '/assets/css/detection-lens-explorer.css' | relative_url }}" />

<section class="ac-index-hero lens-research">
  <div class="ac-index-hero-inner">
    <h1>Container Escapes: Detecting Isolation Boundary Abuse</h1>
    <p>Follow the operation from workload to host or destination, then check what the evidence can confirm.</p>
  </div>
</section>

<section class="max-w-[1100px] mx-auto px-6 py-8 ac-prose lens-research" markdown="1">

A workload sends a request to a container runtime. The runtime starts another container. A host file is read and its contents come back. Each step answers a different question. Who sent the request? Which process read the file? Did the data reach the requester? In 2026, Sysdig reported that an attacker used Docker management access from a workload and recovered host-file contents. It also reported reads from the Kubernetes API. Those API reads belong to a separate control-plane path. [Sysdig, Phase 1 and Phase 2](https://www.sysdig.com/blog/agentic-threat-actor-hits-the-orchestration-plane-ai-agent-driven-container-escape)

Start with the result you need to explain. Use the host or destination evidence to establish what happened, then work back to the workload, management principal, or host actor that caused it.

[Follow the three paths in the Lens Explorer]({{ '/lens-explorer/container-escape/' | relative_url }}) · [Container Escape Variations in the catalog]({{ '/chokepoints/container-escape-variations/' | relative_url }})

## Did the workload obtain host data?

1. **Find the protected object.** A host mount or namespace transition tells you which resources might be reachable. For a completed read, resolve the object to determine whether it belongs to the host. Bind the source version when you need to establish acquisition of designated data. An approved diagnostic or backup can touch the same file.
2. **Follow the bytes through the runtime.** A daemon can read on behalf of a workload. containerd also disclosed a path that made a read-only copy available in a workload. A completed local read supports access to that copy. To establish host provenance, find the copy or job record that binds the original version to what was delivered.
3. **Check the recipient and policy.** Confirm who received the data and which policy applied. A successful Kubernetes Secret request can explain how a workload obtained credential material. Check whether the data actually came from the designated node object before making a host-data claim.

[containerd advisory, Impact](https://github.com/containerd/containerd/security/advisories/GHSA-crp2-qrr5-8pq7#impact) · [Kubernetes, hostPath](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath) · [Container credential access lesson]({{ '/lens-explorer/' | relative_url }}?lesson=resilience)

## Did attacker-controlled code execute under host authority?

1. **Qualify the execution context.** A namespace operation can explain the route. Record the namespace type and target, the result, and the relevant process instance. PID namespace reassociation affects later children. A namespace event by itself leaves host execution open.
2. **Check what the runtime actually did.** Bind a daemon or shim request to the instance or operation it created. Distinguish a workload-originated request from an external API caller deploying a new container.
3. **Follow the later launch.** A runtime binary change can precede execution by a normal operator. Check that the launch consumed the affected generation. A nearby process start could have consumed a clean binary or come from an unrelated maintenance job.

[runc disclosure, Overview](https://www.openwall.com/lists/oss-security/2019/02/11/2) · [containerd shim advisory, Impact](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4#impact) · [Linux setns, PID namespaces](https://man7.org/linux/man-pages/man2/setns.2.html#DESCRIPTION)

When a downstream execution uses shared-writable file staging, the existing Land and Run entry covers that interaction. Check the staging evidence before applying it. [Linux Shared-Writable Staging to Execution]({{ '/chokepoints/ssh-land-and-run/' | relative_url }})

## Would the server accept a new key?

1. **Find the change.** A local trust file can change through direct host access, a delegated job, or approved rotation. Identify the affected account and the exact change before assigning a cause.
2. **Check effective trust.** Resolve which key sources the server uses for that account and whether the new key would be eligible under the effective account and connection policy. A write can be ineffective. A configured central publisher can change effective trust without a node escape.
3. **Check for later use.** An authenticated session answers a separate question. Start with the destination account and credential evidence, then work back to the authorized change or originating workload.

[OpenSSH, key lookup and trust directives](https://man.openbsd.org/sshd_config) · [Datadog, SSH persistence and campaign impact](https://securitylabs.datadoghq.com/articles/analysis-of-teamtnt-doppelganger/) · [Docker SSH backdoors lesson]({{ '/lens-explorer/' | relative_url }}?lesson=minimum)

## Where to look first

<div class="table-wrapper overflow-x-auto" role="region" aria-label="Defensive observation points" tabindex="0" markdown="1">

| What you have | What it can establish | What to look for next |
|---|---|---|
| Admission or API audit | Who requested a deployment or operation and the recorded disposition at the retained audit stage | Runtime instance, accepted job, completed operation |
| Endpoint or kernel event | A resolved host operation or process context, if the sensor captured it | Boot-scoped workload identity, exact object or code generation, applicable authorization |
| Host integrity record | A runtime file or trust source changed | Which actor did it, whether the change took effect, what later consumed it |
| Destination or off-node evidence | Data reached a recipient, trust became effective, or a host action occurred, within the scope of the witness | Exact lineage to the initiating actor and a check for an authorized alternative |

</div>

Without runtime telemetry, start from the evidence you have. A host integrity change and a destination authentication record can justify investigation even while workload origin remains open. A read-only disclosure can remain invisible if neither the host read nor the recipient is observable.

## What the studies checked

<div class="table-wrapper overflow-x-auto" role="region" aria-label="Study findings" tabindex="0" markdown="1">

| Study | Finding | Scope |
|---|---|---|
| Gate B, synthetic | 4/4 primary positive canary writes confirmed with the full modeled evidence set | Direct and delegated paths used different evidence combinations. |
| Gate C, measured | 8/8 primary delegated effects and 0/8 primary direct effects confirmed with full instrumentation | Two delayed positive controls are outside the primary counts. The study used a fixed canary and an instrumented helper. |
| Gate C.2, measured | 24/39 downstream effects and 7/14 causal links confirmed with supplemental evidence | The study used inert records and a fake read marker. These were distinct claims with different denominators. |
| Gate C.3, synthetic | The complementary observation model confirmed 16/16 downstream effects compared with 10/16 in the original model | Replay of modeled observations. |

</div>

Use the studies to compare what evidence adds to a claim. The graphs show proposed routes and simulated placements. The lab rows measure or model specific canary behavior, with their own scope and evidence labels. [Published research studies]({{ '/research/' | relative_url }})

## What remains open

The strongest next boundary question is whether a defender can connect a workload's authenticated runtime request to the exact job and destination effect across retries, restarts, and delayed receipts. Copy provenance and effective trust are separate questions. The evidence supports scoped candidates for each. Container escape remains an open research topic.

</section>

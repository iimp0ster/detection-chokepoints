---
layout: chokepoint
title: Container Escape Variations
description: "Follow the routes from a Linux workload to host data, host execution, or persistent SSH trust."
permalink: /chokepoints/container-escape-variations/
catalog_kind: research-profile
profile_maturity: Research
mitre_ids: [T1611]
research_url: /research/container-escape/
explorer_url: /lens-explorer/container-escape/
threat_summary: "Sysdig reported Docker management access from a workload, recovery of host files, and an nsenter fallback. The same report describes a separate Kubernetes API read. Start with the result you can establish."
threat_source: "https://www.sysdig.com/blog/agentic-threat-actor-hits-the-orchestration-plane-ai-agent-driven-container-escape"
threat_source_label: "Sysdig, Phase 1 and Phase 2"
scope_note: "The research has not established a universal observable container escape chokepoint."
related_entries:
  - slug: ssh-land-and-run
    relationship: Execution
    scope: "Follow when host code is staged in a shared-writable location and then consumed."
  - slug: web-shells
    relationship: Persistence
    scope: "Follow when a web shell provides foothold or persistence. Effective SSH trust has a separate evidence contract."
  - slug: browser-credential-theft
    relationship: Credential Access
    scope: "Follow when the protected target is a browser credential store and the downstream activity meets the entry's mechanism."
  - slug: edr-bypass-techniques
    relationship: Defense Evasion
    scope: "Compare separately evidenced security-tool impairment within the entry's platform scope. Container escape alone establishes no impairment."
---

<section class="cp-section-card" id="attack-chokepoints" markdown="1">
<div class="cp-section-heading-row">
  <div class="cp-section-icon" aria-hidden="true">
    <img class="cp-section-pixel" src="{{ '/assets/img/pixel/chokepoint.png' | relative_url }}" alt="" width="22" height="22" />
  </div>
  <h2 class="cp-section-heading">Attack Chokepoints <span class="section-sub">Research candidates</span></h2>
</div>

<div id="boundaries" markdown="1">

### Isolation boundaries
{: #isolation-boundaries }

For an escape claim, identify the starting workload, the intended isolation and the host-scoped resource or authority it reached. T1611 applies to the crossing from the workload. T1610 describes deployment activity. An external manager, a newly provisioned workload and a host-native actor are different possible origins. A Kubernetes Secret response or cloud action can meet an objective without crossing node isolation. [ATT&CK T1610, Deploy Container](https://attack.mitre.org/techniques/T1610/)

**Prerequisites.** Establish the starting identity, node, expected policy and available bridge. Configuration, effective permissions, version and lifecycle determine which routes are possible. A mount, shared namespace or management grant can predate compromise.

**What changes by route.** A process can use a mapping, enter a namespace or rely on a controller. A runtime can materialize a copy before the workload reads it. A new process, namespace transition, host write or distinct grant depends on the route.

</div>

<div id="candidates" markdown="1">

### Candidates by objective
{: #candidates-by-objective }

<div class="table-wrapper" role="region" aria-label="Candidates by objective" tabindex="0" markdown="1">

| Objective | Necessary interaction for the candidate | What else can explain the result |
| --- | --- | --- |
| Host action through delegation | A privileged controller performs the host-enabled operation. This is the highest-priority candidate. Bind the authenticated requester and completed job to the exact host result. | A direct host grant, a different controller, deployment by an external principal, or approved administration. |
| Acquisition of protected host data | A recipient acquires a representation derived from the protected version. Establish whether that recipient was outside the intended policy. Observe direct read, delegated delivery, or copy materialization and receipt as appropriate. | Approved backup or projection, a stale copy, or a different management-plane source. |
| Execution under host authority | A qualified host action must occur. For runtime binary replacement, a later invocation has to consume the affected generation. Scope this candidate to that mechanism. | A valid package update or unrelated launch. Namespace, daemon, or scheduler execution can avoid runtime replacement. |
| Persistent SSH trust | The applicable server resolution accepts the exact key as eligible for the named account and connection context. A local trust input is one scoped candidate. | Key rotation, authorized administration, or a configured publisher. Authentication and additional factors are later claims. |

</div>

Later effects can include credential access, execution, persistent trust, integrity change or service disruption. Compare routes and prevention cuts in the Lens Explorer for [protected host data]({{ '/lens-explorer/container-escape/' | relative_url }}?objective=data), [host execution]({{ '/lens-explorer/container-escape/' | relative_url }}?objective=execution), or [persistent SSH trust]({{ '/lens-explorer/container-escape/' | relative_url }}?objective=trust).

</div>
</section>

<section class="cp-section-card" id="variations" aria-labelledby="variations-title" markdown="1">

<div class="cp-section-heading-row">
  <div class="cp-section-icon" aria-hidden="true">
    <img class="cp-section-pixel" src="{{ '/assets/img/pixel/sec-variations.png' | relative_url }}" alt="" width="22" height="22" />
  </div>
  <h2 class="cp-section-heading" id="variations-title">Variations</h2>
</div>

Compare what grants access, who can use it, and which records show that the operation completed.

<details class="chokepoint-item" open>
<summary class="chokepoint-header"><span class="cp-title">Namespace abuse</span><span aria-hidden="true" class="cp-chevron">▸</span></summary>
<div class="chokepoint-body" markdown="1">

Sysdig describes an `nsenter` fallback. Reassociation requires usable target context and applicable authority. Resolve the namespace type, identity and operation result, then follow the relevant process. With PID reassociation, inspect the later child. Approved node debugging and runtime housekeeping can use the same facilities. The report does not tie every transition to its own confirmed effect. [Sysdig, Phase 1](https://www.sysdig.com/blog/agentic-threat-actor-hits-the-orchestration-plane-ai-agent-driven-container-escape) · [Linux setns, PID namespaces](https://man7.org/linux/man-pages/man2/setns.2.html#DESCRIPTION) · [Kubernetes node debugging](https://kubernetes.io/docs/tasks/debug/debug-cluster/kubectl-node-debug/)

</div>
</details>

<details class="chokepoint-item">
<summary class="chokepoint-header"><span class="cp-title">Host filesystem exposure</span><span aria-hidden="true" class="cp-chevron">▸</span></summary>
<div class="chokepoint-body" markdown="1">

A usable host mapping can expose a host object before a workload is compromised. Aqua reported a host filesystem path followed by cron changes and execution, with limited per-operation lineage in the public report. Check the resolved object, completed operation and applicable policy. Backup and node agents are administrative equivalents. [Aqua, “Using rootkits in the wild,” steps 1–4](https://www.aquasec.com/blog/advanced-persistent-threat-techniques-container-attacks/) · [Kubernetes hostPath](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath)

</div>
</details>

<details class="chokepoint-item">
<summary class="chokepoint-header"><span class="cp-title">Runtime management abuse</span><span aria-hidden="true" class="cp-chevron">▸</span></summary>
<div class="chokepoint-body" markdown="1">

A reachable daemon can perform a host-enabled job for a workload. An external caller can also direct the daemon to provision a privileged workload. The affected containerd shim in CVE-2020-15257 exposed an abstract endpoint under specific network-namespace and UID conditions. A mounted socket is only one way to reach a controller. Distinguish the authenticated caller, request disposition, completed job, and actual target. [Sysdig, Phase 1](https://www.sysdig.com/blog/agentic-threat-actor-hits-the-orchestration-plane-ai-agent-driven-container-escape) · [Datadog, “Malicious payload deployment”](https://securitylabs.datadoghq.com/articles/analysis-of-teamtnt-doppelganger/) · [containerd shim advisory, Impact](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4#impact)

</div>
</details>

<details class="chokepoint-item">
<summary class="chokepoint-header"><span class="cp-title">Kernel and runtime vulnerabilities</span><span aria-hidden="true" class="cp-chevron">▸</span></summary>
<div class="chokepoint-body" markdown="1">

The cgroup v1 research distinguishes a host control-setting change and a later host action. The shared-kernel study demonstrates a separate memory corruption route. Runtime disclosures describe leaked host references, host binary replacement, and redirected privileged writes during setup. Compare the affected component and starting conditions. Prove later execution by linking it to the affected generation or exact earlier action. [Unit 42, CVE-2022-0492, Figures 7–9](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) · [CVE-2022-0185, kCTF full-chain discussion](https://www.willsroot.io/2022/01/cve-2022-0185.html) · [runc reference advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv#impact) · [runc original lifecycle disclosure](https://www.openwall.com/lists/oss-security/2019/02/11/2) · [runc write-redirection advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm#impact)

</div>
</details>

<details class="chokepoint-item">
<summary class="chokepoint-header"><span class="cp-title">Runtime-mediated disclosure</span><span aria-hidden="true" class="cp-chevron">▸</span></summary>
<div class="chokepoint-body" markdown="1">

The containerd CRI advisory describes read-only copies of host data made available at provisioning. A later read can stay inside the workload. Link the original source version to the copied object and the recipient. A same-value copy can be stale or unrelated. [containerd CRI advisory, Impact](https://github.com/containerd/containerd/security/advisories/GHSA-crp2-qrr5-8pq7#impact)

</div>
</details>

<details class="chokepoint-item">
<summary class="chokepoint-header"><span class="cp-title">Composed boundary interactions</span><span aria-hidden="true" class="cp-chevron">▸</span></summary>
<div class="chokepoint-body" markdown="1">

In Wiz's NVIDIA Container Toolkit research, an unintended read-only host mapping still exposed a Unix socket. A separate daemon job then created a privileged workload. The mapping and the job authorization are different controls. The documented composition establishes reach and broader access in the demonstration. Exact protected-data delivery or qualifying host execution needs separate evidence. [Wiz, “Privilege escalation & RCE”](https://www.wiz.io/blog/nvidia-ai-vulnerability-deep-dive-cve-2024-0132)

</div>
</details>

</section>

<section class="cp-section-card" id="detection-strategy" aria-labelledby="detection" markdown="1">
<div class="cp-section-heading-row">
  <div class="cp-section-icon" aria-hidden="true">
    <img class="cp-section-pixel" src="{{ '/assets/img/pixel/sec-detection.png' | relative_url }}" alt="" width="22" height="22" />
  </div>
  <h2 class="cp-section-heading" id="detection">Detection Strategy</h2>
</div>

<!-- defensive-coverage -->

<details class="research-field-notes" id="detection-notes" markdown="1">
<summary>Field and correlation notes</summary>

An exposure or request is a lead. Join the authenticated requester, runtime task and terminal operation to the resolved host target. Compare the intended authorization for that workload and time. Confirm the outcome with independent evidence before attributing it. A shared host or a nearby timestamp alone can join unrelated work.

For a copied resource, bind the original version to the recipient. For runtime integrity, use the same executable generation. For SSH, verify the actual trust source and named account. [ATT&CK DET0219](https://attack.mitre.org/detectionstrategies/DET0219/)

</details>

<div class="catalog-research-note" id="limits" markdown="1">

### Research limits
{: #research-limits }

Gate B and Gate C.3 are synthetic. Gates C and C.2 measured inert fixtures with scoped attribution. The source reports and modeled routes carry separate evidence. Field performance and false positives remain unmeasured. The open question is whether ordinary runtime records can resolve workload lifetime, completed actions, late terminals and competing causes. [Published Research Studies]({{ '/research/#lab-results-and-synthetic-replays' | relative_url }})

</div>

</section>

<section class="cp-section-card" id="prevention" aria-labelledby="prevention-and-deception" markdown="1">
<div class="cp-section-heading-row" id="controls">
  <div class="cp-section-icon" aria-hidden="true">
    <img class="cp-section-pixel" src="{{ '/assets/img/pixel/sec-prevention.png' | relative_url }}" alt="" width="22" height="22" />
  </div>
  <h2 class="cp-section-heading" id="prevention-and-deception">Prevention and Deception</h2>
</div>

- **Limit exposure.** Restrict grants, workload privileges, and host resources to authorized scope. Check runtime, kernel, shim, and device integration lifecycle before crediting remediation.
- **Restrict the completed job.** Apply job authorization at the controller where eligible. Validate it independently of socket reach. The copied version and any earlier effects require separate handling.
- **Protect destination inputs.** Enforce policy at the actual host service, executable, or trust provider. Verify the effective policy and the relevant route before claiming coverage.
- **Use inert decoys.** A nonfunctional management endpoint or labeled nonsecret object can reveal unexpected contact. Keep the decoy isolated from real runtime authority. Bind the signal to the decoy and actor. Decoy contact establishes interest or access to that surface.

</section>

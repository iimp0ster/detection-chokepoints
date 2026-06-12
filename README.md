# Detection Chokepoints

<p align="center">
  <img src="assets/img/detection-chokepoints-logo.png" alt="Detection Chokepoints — 16-bit arcade fighting-game scene of a jiu-jitsu rear naked choke with body triangle: the fighter in red has back control and strangles the fighter in blue, with health bars and a match timer overhead" width="512" />
</p>

> **TTPs evolve. Chokepoints don't.**

A community detection engineering resource organized around invariant prerequisites. Every chokepoint here is a condition the attacker cannot avoid, no matter which tool they pick or how they obfuscate it. Detect the prerequisite, catch every variant that needs it.

Live site: [iimp0ster.github.io/detection-chokepoints](https://iimp0ster.github.io/detection-chokepoints/)

---

## Why This Exists

Kaspersky analyzed eight major ransomware operations in 2022 and found they all share the same core kill chain. External Remote Services, command and scripting interpreters, WMI, and LSASS credential dumping show up in every single group. Shadow copy deletion and service stopping appear in 7 of 8. The tools rotate constantly. The requirements don't.

That pattern is not ransomware-specific. We rebuilt the TTP overlap analysis across 5 attack chains using [Kitsune](https://github.com/christina23/kitsune), an AI-driven threat intelligence pipeline, correlating procedure-level data from 60+ vendor and government reports sourced via [ORKL](https://orkl.eu/). Every chain converges on a handful of unavoidable chokepoints. The framework is the same every time.

Meanwhile dwell time keeps compressing. Mandiant M-Trends 2025 puts the median Time to Ransom under 24 hours. That's down from 21 days in 2020. There is no time to chase tool signatures. You need detections that survive tool rotation on the first try.

---

## Chokepoint Index

9 chokepoints tracked. Each has a canonical YAML entry, Sigma rules at three maturity levels, and emulation scripts for validation.

| Chokepoint | Tactic | Priority | Prevalence | Difficulty |
|------------|--------|----------|------------|------------|
| [LSASS Credential Dumping](chokepoints/credential-access/lsass-credential-dumping.yml) | Credential Access | CRITICAL | VERY HIGH | MEDIUM |
| [Browser Credential Theft](chokepoints/credential-access/browser-credential-theft.yml) | Credential Access | CRITICAL | HIGH | MEDIUM |
| [Ransomware Service Manipulation](chokepoints/defense-evasion/ransomware-service-manipulation.yml) | Defense Evasion / Impact | CRITICAL | HIGH | LOW |
| [EDR Bypass Techniques](chokepoints/defense-evasion/edr-bypass-techniques.yml) | Defense Evasion | CRITICAL | HIGH | HIGH |
| [Web Shell Persistence](chokepoints/persistence/web-shells.yml) | Persistence / Initial Access | CRITICAL | HIGH | MEDIUM |
| [ClickFix Techniques](chokepoints/initial-access/clickfix-techniques.yml) | Initial Access | HIGH | HIGH | LOW |
| [Renamed RMM Tools](chokepoints/initial-access/renamed-rmm-tools.yml) | Initial Access / C2 | HIGH | HIGH | MEDIUM |
| [Remote Execution Tools](chokepoints/lateral-movement/remote-execution-tools.yml) | Lateral Movement | HIGH | HIGH | MEDIUM |
| [BYOSI Scripting Interpreters](chokepoints/defense-evasion/byosi-scripting-interpreters.yml) | Defense Evasion | HIGH | EMERGING | HIGH |

---

## Attack Chains

Each chain maps 5 actors against the same kill chain to show where every group converges. Research-backed TTP data via Kitsune + ORKL.

| Chain | Actors Tracked | Shared Techniques |
|-------|----------------|-------------------|
| [Ransomware](attack-chains/ransomware.md) | BlackBasta, LockBit 3.0, Akira, Alphv/BlackCat, Play | See page |
| [Infostealers](attack-chains/infostealers.md) | RedLine, LummaC2, Vidar, StealC, Raccoon | 28 shared |
| [AiTM / Phishing Kits](attack-chains/aitm.md) | Tycoon 2FA, Evilginx, EvilProxy, Sneaky 2FA, Device Code | 12 shared |
| [Hypervisor Compromise](attack-chains/hypervisor-compromise.md) | BRICKSTORM/UNC5221, UNC3886, Scattered Spider, Play, Alphv | 22 shared |
| [AD / Identity Domination](attack-chains/identity-domination.md) | APT29, Storm-0501, Storm-2372, Scattered Spider, Ransomware ops | 23 shared |

---

## The Framework

Adapted from [Matt Graeber's threat research methodology at Red Canary](https://redcanary.com/blog/threat-detection/threat-research-questions/). For every technique, ask six questions in order:

1. What is this technique at a technical level?
2. What must be true for it to succeed?
3. What does the attacker control?
4. **What can't the attacker control?** ← the chokepoint
5. Can we observe it independent of intent?
6. What are all the possible variations?

Steps 1-3 build understanding. Step 4 identifies the chokepoint. Steps 5-6 turn it into a detection.

Full walkthrough with worked examples, the relationship graph, and the maturity model: [Framework page](https://iimp0ster.github.io/detection-chokepoints/framework/).

---

## Detection Maturity Model

Every chokepoint ships with Sigma rules at three levels. Don't skip ahead.

| Level | Goal | FP Rate | Use Case |
|-------|------|---------|----------|
| **Research** | Establish visibility, baseline behavior | High | Threat research, log source validation |
| **Hunt** | Reduce noise, keep coverage | Medium | Active hunting, campaign detection |
| **Analyst** | Production SOC alerting | Low | Automated alerting, IR escalation |

Start with Research to learn what's in your environment. Tune to Hunt. Harden to Analyst. Each level feeds the next.

---

## Trends

Data-driven analysis of shifts in the chokepoint landscape. What cradles dominate, which evasion techniques are rising, what infrastructure actors reuse.

- [ClickFix Delivery Chain](trends/clickgrab.md): 10 months of MHaggis ClickGrab data across 20K+ malicious sites. Tracks cradle family evolution, evasion acceleration, self-delete emergence, and CDN staging.
- [Edge Device Exploit Trends](trends/edge-exploits/): Defused Cyber honeypot telemetry across 25 decoy types. CitrixBleed 2 proliferation, CVE-2022-22536 SAP burst, multi-stage kill chains, self-replicating worms.

---

## Repository Structure

```
chokepoints/      # Canonical YAML entries, one file per chokepoint, organized by tactic
sigma-rules/      # Sigma rules at three maturity levels (research / hunt / analyst)
iok-rules/        # Indicator of Knowledge rules for lure/phishing page detection
emulation/        # PowerShell scripts to validate detections in a lab
attack-chains/    # Full kill chain documentation with actor convergence matrices
trends/           # Threat trend analyses and chokepoint evolution tracking
intel/            # Free intelligence resources tied to specific chokepoints
templates/        # Templates for contributors (chokepoint YAML, quick-add, evolution tracker)
scripts/          # Data ingestion and overlap-builder scripts (Kitsune + ORKL pipeline artifacts)
schema/           # Field definitions and valid values for chokepoint entries
_data/            # Jekyll data files (chokepoints, TTP overlap per attack chain)
```

---

## How to Use This Repository

### Threat hunters

1. Browse [chokepoints/](chokepoints/) by tactic
2. Grab the Sigma rule at your target maturity level from [sigma-rules/](sigma-rules/)
3. Check [trends/](trends/) for current telemetry on what's actually in the wild

### Detection engineers

1. Deploy the Research rule to baseline behavior in your environment
2. Tune the Hunt rule against your baseline
3. Promote to Analyst once false positives are acceptable
4. Validate with the PowerShell emulation scripts in [emulation/](emulation/) in an isolated lab

### Phishing and lure detection

1. Check [iok-rules/](iok-rules/) for Indicator of Knowledge rules at the web proxy or phish.report layer
2. IOK rules detect invariant page-side behaviors (clipboard seeding + execution instruction) regardless of visual design or obfuscation

### Tracking threat evolution

- New tool variant on an existing chokepoint: use [templates/quick-add.md](templates/quick-add.md)
- New technique entirely: start from [templates/chokepoint-template.yml](templates/chokepoint-template.yml)
- Complete worked example: [templates/EXAMPLE-WORKFLOW.md](templates/EXAMPLE-WORKFLOW.md)

---

## Contributing

You don't need to submit a complete chokepoint page to contribute. Every empty field on an existing page is an open contribution. Pick what you can fill in.

**Ask yourself before submitting:** if the attacker switches tools tomorrow, does this detection still fire? If yes, it's a chokepoint. If no, it may be a useful IOC, but it isn't a chokepoint entry.

**Paths that need help:**
- Missing Sigma rules at any tier (research, hunt, analyst)
- OSINT pivot queries for platforms not yet covered
- Log samples for stages with empty `RawLogs`
- Emulation scripts for chokepoints that don't have one
- EvolutionTimeline entries for newly reported variants
- BypassNote entries documenting known evasion paths

Full contribution guide, schema reference, and PR checklist: [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Resources

| Resource | Used for |
|----------|----------|
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique taxonomy for all chokepoint mappings |
| [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) | Rule format across all detection levels |
| [Kitsune](https://github.com/christina23/kitsune) | AI-driven threat intelligence pipeline used to extract and correlate procedure-level data |
| [ORKL](https://orkl.eu/) | Open Repository of Knowledge on Libraries, source corpus for attack chain analysis |
| [Kaspersky: Common TTPs of Modern Ransomware (2022)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf) | Empirical foundation for the chokepoint approach |
| [Mandiant M-Trends](https://www.mandiant.com/m-trends) | Source for TTR compression data |
| [Red Canary: The Why, What, and How of Threat Research](https://redcanary.com/blog/threat-detection/threat-research-questions/) | Matt Graeber's research methodology that this framework adapts |
| [MHaggis ClickGrab](https://mhaggis.github.io/ClickGrab/) | Live ClickFix crawl data feeding the trends analysis |
| [Defused Cyber](https://defusedcyber.com/) | Honeypot telemetry feeding the edge-exploit trends analysis |
| [Huntress: Don't Sweat the ClickFix Techniques](https://huntress.com/blog/dont-sweat-clickfix-techniques) | In-the-wild ClickFix variant breakdown |

---

> *Detection is a game of economics. Make it expensive for attackers to avoid your detections.*

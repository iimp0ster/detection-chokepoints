---
layout: default
title: ClickFix Delivery Chain — Trend Analysis
description: "10 months of MHaggis ClickGrab data analyzed through the Detection Chokepoint Framework. Tracks cradle family evolution, evasion technique shifts, and staging infrastructure from April 2025 to March 2026."
---

<style>
/* ── Page layout ────────────────────────────────────────────────────────── */
.cg-page { max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
.cg-page h1 { font-size: 1.6rem; font-weight: 700; color: var(--color-fg-default, #c9d1d9); margin-bottom: .25rem; }
.cg-page h2 { font-size: 1.15rem; font-weight: 600; color: var(--color-fg-default, #c9d1d9); margin: 2.5rem 0 .75rem; border-bottom: 1px solid #30363d; padding-bottom: .4rem; }
.cg-page h3 { font-size: 1rem; font-weight: 600; color: #c9d1d9; margin: 1.5rem 0 .5rem; }
.cg-page p, .cg-page li { color: #8b949e; font-size: .9rem; line-height: 1.7; }
.cg-page a { color: #58a6ff; }
.cg-meta { color: #8b949e; font-size: .8rem; margin-bottom: 1.75rem; }

/* ── Stats row ──────────────────────────────────────────────────────────── */
.cg-stats { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.25rem 0 2rem; }
.cg-stat  { flex: 1 1 140px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: .85rem 1rem; }
.cg-stat-val { font-size: 1.5rem; font-weight: 700; color: #c9d1d9; font-family: ui-monospace, monospace; line-height: 1.2; }
.cg-stat-lbl { font-size: .72rem; color: #8b949e; margin-top: .2rem; text-transform: uppercase; letter-spacing: .04em; }

/* ── Framework chain map ────────────────────────────────────────────────── */
.cg-chain { display: flex; align-items: flex-start; gap: 0; flex-wrap: wrap; margin: 1.5rem 0 2rem; }
.cg-chain-stage {
  flex: 1 1 90px; min-width: 80px;
  border: 1px solid #30363d; border-radius: 6px;
  padding: .6rem .5rem; text-align: center; background: #161b22;
  position: relative;
}
.cg-chain-stage + .cg-chain-stage { margin-left: -1px; border-radius: 0; }
.cg-chain-stage:first-child { border-radius: 6px 0 0 6px; }
.cg-chain-stage:last-child  { border-radius: 0 6px 6px 0; }
.cg-chain-stage--blind  { border-top: 3px solid #30363d; }
.cg-chain-stage--t1     { border-top: 3px solid #e3b341; }
.cg-chain-stage--t2     { border-top: 3px solid #f0883e; }
.cg-chain-stage--t3     { border-top: 3px solid #da3633; }
.cg-chain-label { font-size: .72rem; font-weight: 600; color: #c9d1d9; line-height: 1.3; display: block; }
.cg-chain-sub   { font-size: .62rem; color: #8b949e; margin-top: .25rem; display: block; }
.cg-tier-badge  { display: inline-block; font-size: .6rem; font-weight: 700; padding: .1rem .35rem; border-radius: 3px; margin-top: .35rem; letter-spacing: .03em; }
.cg-tier-blind  { background: #21262d; color: #8b949e; }
.cg-tier-t1     { background: rgba(227,179,65,.15);  color: #e3b341; }
.cg-tier-t2     { background: rgba(240,136,62,.15);  color: #f0883e; }
.cg-tier-t3     { background: rgba(218, 54, 51,.15); color: #da3633; }
.cg-chain-arrow {
  align-self: center; flex: 0 0 auto;
  color: #30363d; font-size: 1.2rem; padding: 0 .1rem; margin-top: -2px;
}

/* ── Chart containers ───────────────────────────────────────────────────── */
.cg-chart-wrap { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1rem .5rem; margin: 1rem 0 1.75rem; overflow-x: auto; }
.cg-chart-title { font-size: .75rem; font-weight: 600; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; margin-bottom: .5rem; }

/* ── Callout boxes ──────────────────────────────────────────────────────── */
.cg-callout { border-radius: 6px; padding: .85rem 1rem; margin: .75rem 0; font-size: .875rem; border-left: 3px solid; }
.cg-callout--warn  { background: rgba(227,179,65,.08);  border-color: #e3b341; color: #c9d1d9; }
.cg-callout--alert { background: rgba(218,54,51,.08);   border-color: #da3633; color: #c9d1d9; }
.cg-callout--info  { background: rgba(56,139,253,.08);  border-color: #388bfd; color: #c9d1d9; }
.cg-callout--tip   { background: rgba(63,185,80,.08);   border-color: #3fb950; color: #c9d1d9; }
.cg-callout strong { color: #c9d1d9; }

/* ── Staging domain table ───────────────────────────────────────────────── */
.cg-table { width: 100%; border-collapse: collapse; font-size: .85rem; margin: .75rem 0 1.5rem; }
.cg-table th { text-align: left; color: #8b949e; font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; border-bottom: 1px solid #30363d; padding: .4rem .6rem; font-weight: 600; }
.cg-table td { padding: .45rem .6rem; border-bottom: 1px solid #21262d; color: #c9d1d9; font-family: ui-monospace, monospace; font-size: .82rem; }
.cg-table tr:last-child td { border-bottom: none; }
.cg-badge-cdn  { display: inline-block; background: rgba(227,179,65,.15); color: #e3b341; font-size: .65rem; font-weight: 700; padding: .1rem .3rem; border-radius: 3px; letter-spacing: .03em; }
.cg-badge-ip   { display: inline-block; background: rgba(240,136,62,.15); color: #f0883e; font-size: .65rem; font-weight: 700; padding: .1rem .3rem; border-radius: 3px; letter-spacing: .03em; }

/* ── Recommendation list ────────────────────────────────────────────────── */
.cg-rec { display: flex; gap: .75rem; align-items: flex-start; padding: .6rem 0; border-bottom: 1px solid #21262d; }
.cg-rec:last-child { border-bottom: none; }
.cg-rec-tier { flex: 0 0 62px; }
.cg-rec-body { flex: 1; font-size: .875rem; color: #8b949e; }
.cg-rec-body strong { color: #c9d1d9; display: block; margin-bottom: .2rem; }
</style>

<div class="cg-page">

<h1>ClickFix Delivery Chain — Trend Analysis</h1>
<p class="cg-meta">
  Data: <a href="https://github.com/mhaggis/ClickGrab" target="_blank" rel="noopener">MHaggis ClickGrab</a>
  &nbsp;·&nbsp; Period: Apr 2025 – Mar 2026
  &nbsp;·&nbsp; {{ site.data.clickgrab_trends.meta.total_reports }} nightly reports
  &nbsp;·&nbsp; Generated: {{ site.data.clickgrab_trends.meta.generated }}
</p>

<!-- ── Dataset Overview ──────────────────────────────────────────────── -->
<div class="cg-stats">
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.meta.total_sites_crawled | divided_by: 1000 }}k+</div>
    <div class="cg-stat-lbl">Sites crawled</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.meta.total_malicious | divided_by: 1000 }}k+</div>
    <div class="cg-stat-lbl">Malicious confirmed</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.cradles_total.iwr_iex }}</div>
    <div class="cg-stat-lbl">IWR/IEX cradles</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.evasion_totals.base64 }}</div>
    <div class="cg-stat-lbl">Base64 obfuscated</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.evasion_totals.self_delete }}</div>
    <div class="cg-stat-lbl">Self-delete</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{{ site.data.clickgrab_trends.evasion_totals.cdn_staging }}</div>
    <div class="cg-stat-lbl">CDN-staged payloads</div>
  </div>
</div>

<!-- ── Framework Chain Map ───────────────────────────────────────────── -->
<h2>Detection Chokepoint Framework</h2>
<p>Five stages of the ClickFix delivery chain. Not all stages are equally detectable — Tier 1 are unavoidable adversary actions regardless of how the lure evolves.</p>

<div class="cg-chain" role="list" aria-label="ClickFix delivery chain stages">
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">Browser renders lure</span>
    <span class="cg-chain-sub">Fake CAPTCHA / reCAPTCHA page</span>
    <span class="cg-tier-badge cg-tier-blind">NOT DETECTABLE</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">JS → clipboard</span>
    <span class="cg-chain-sub">execCommand("copy") writes cmd</span>
    <span class="cg-tier-badge cg-tier-blind">PRE-EXEC</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t1" role="listitem">
    <span class="cg-chain-label">Process spawn</span>
    <span class="cg-chain-sub">Run dialog → cmd.exe → PowerShell</span>
    <span class="cg-tier-badge cg-tier-t1">TIER 1</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t1" role="listitem">
    <span class="cg-chain-label">Network fetch</span>
    <span class="cg-chain-sub">IWR / IRM / WebClient / Curl</span>
    <span class="cg-tier-badge cg-tier-t1">TIER 1</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t2" role="listitem">
    <span class="cg-chain-label">Payload write</span>
    <span class="cg-chain-sub">Script dropped to %TEMP%</span>
    <span class="cg-tier-badge cg-tier-t2">TIER 2</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t3" role="listitem">
    <span class="cg-chain-label">Execute + cleanup</span>
    <span class="cg-chain-sub">Payload runs, then self-deletes</span>
    <span class="cg-tier-badge cg-tier-t3">TIER 2/3</span>
  </div>
</div>

<p>The <strong>Tier 1 chokepoints are process spawn and network fetch</strong> — every cradle family must touch the network to retrieve the payload, and the unusual parent→PowerShell spawn is unavoidable because the user manually triggers execution from a Run dialog. These are the detection bets that pay off regardless of lure evolution. See the <a href="{{ '/chokepoints/clickfix-techniques/' | relative_url }}">ClickFix Techniques chokepoint</a> for detection logic.</p>

<!-- ── Chart A: Monthly Volume ───────────────────────────────────────── -->
<h2>Monthly Volume — Malicious Sites Detected</h2>
<p>Total sites crawled vs. confirmed malicious per month across {{ site.data.clickgrab_trends.meta.total_reports }} nightly ClickGrab scans.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Sites crawled vs. malicious by month</div>
  <div id="cg-chart-volume"></div>
</div>

<!-- ── Chart B: Cradle Family Evolution ──────────────────────────────── -->
<h2>Tier 1 Chokepoint: Cradle Family Evolution</h2>
<p>The network fetch is the unavoidable action. This chart shows <em>how</em> adversaries are fetching payloads — and how that method has shifted as defenders tuned IWR/IEX detections.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Monthly cradle family distribution (PowerShell download method)</div>
  <div id="cg-chart-cradles"></div>
</div>

<div class="cg-callout cg-callout--warn">
  <strong>Dec 2025 pivot:</strong> IWR/IEX drops sharply as WebClient (.NET) and Curl/Bash surge simultaneously — a clear signal that IWR-specific detections were effective and adversaries rotated to alternatives. If your detection logic is <code>iwr|Invoke-WebRequest</code> pattern matching, coverage dropped significantly in Q4 2025.
</div>

<div class="cg-callout cg-callout--info">
  <strong>Why this is still Tier 1:</strong> The network fetch method changed from IWR to Curl/WebClient, but the chokepoint didn't move. Any outbound connection to a staging URL from a PowerShell process spawned by an unusual parent (explorer.exe, cmd.exe from Run dialog) remains the detection signal. Behavioral rules survive cradle rotation; method-specific string matching does not.
</div>

<!-- ── Chart C: Evasion Technique Trends ─────────────────────────────── -->
<h2>Evasion Technique Trends — Where Adversaries Are Adapting</h2>
<p>These are the adversary adaptation signals in the trend data. Rising lines indicate where defenders got effective and adversaries responded. Flat lines with spikes indicate campaign surges.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Monthly evasion technique prevalence (count of sites using each technique)</div>
  <div id="cg-chart-evasion"></div>
</div>

<div class="cg-callout cg-callout--alert">
  <strong>Self-delete: zero → hundreds in one month.</strong> From April–November 2025, zero recorded self-delete instances. Starting December 2025, self-delete appeared in hundreds of sites per month ({{ site.data.clickgrab_trends.evasion_totals.self_delete }} total across the campaign). This defeats forensic artifact detection — any rule that relies on finding dropped script files will see nothing after execution. Correlate process execution with file-system events <em>before</em> cleanup completes.
</div>

<div class="cg-callout cg-callout--warn">
  <strong>Base64 explosion Jan 2026:</strong> Base64-encoded payloads increased ~18× vs. the April 2025 baseline. This defeats plaintext command inspection. IDS/SIEM rules matching raw PowerShell strings like <code>iwr https://</code> are seeing the encoded version, not the decoded cradle. Detection must decode or detect the encoding act itself.
</div>

<div class="cg-callout cg-callout--warn">
  <strong>Mixed-case PowerShell declining:</strong> Mixed-case variants (POWerShEll, PowErsHeLL) peaked in mid-2025 then trended down as Base64 encoding became the primary obfuscation method. If you added case-insensitive PowerShell regex, you caught the technique as adversaries were already moving away from it.
</div>

<!-- ── Staging Infrastructure ────────────────────────────────────────── -->
<h2>Staging Infrastructure</h2>
<p>Domains serving the actual payloads (from PowerShell download commands). CDN-hosted payloads defeat domain-reputation blocking — the infrastructure looks like legitimate web hosting.</p>

<table class="cg-table">
  <thead>
    <tr>
      <th>Domain</th>
      <th>Payload count</th>
      <th>Type</th>
      <th>Blind spot</th>
    </tr>
  </thead>
  <tbody>
    {% for d in site.data.clickgrab_trends.staging_domains %}
    <tr>
      <td>{{ d.domain }}</td>
      <td>{{ d.count }}</td>
      <td>
        {% if d.cdn %}<span class="cg-badge-cdn">CDN</span>{% else %}—{% endif %}
      </td>
      <td style="color:#8b949e;font-family:inherit;">
        {% if d.cdn %}Domain reputation blocklists ineffective (legitimate CDN provider)
        {% elsif d.domain contains "wpengine.com" %}Managed WP hosting — likely compromised; blocklist removes legitimate sites
        {% elsif d.domain contains "blogspot.com" or d.domain contains "blogger.com" %}Google-hosted; domain blocking would block all of Blogger
        {% else %}—{% endif %}
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<div class="cg-callout cg-callout--alert">
  <strong>CDN-hosted staging defeats domain blocking.</strong> <code>irp.cdn-website.com</code> appeared in {{ site.data.clickgrab_trends.evasion_totals.cdn_staging }} payload fetches. This is a legitimate CDN used by website builders — blocking it would impact legitimate sites. Detection must shift to behavioral signals (PowerShell → network → unusual domain path) rather than domain-reputation lookup.
</div>

<!-- ── Detection Recommendations ────────────────────────────────────── -->
<h2>Detection Recommendations</h2>
<p>Prioritized by chokepoint tier. Tier 1 recommendations survive lure evolution, cradle rotation, and obfuscation changes.</p>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t1" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 1</span></div>
  <div class="cg-rec-body">
    <strong>Detect unusual parent → PowerShell spawn</strong>
    Correlate <code>explorer.exe</code> or <code>cmd.exe</code> (from Run dialog) spawning <code>powershell.exe</code> with a window-hidden flag. This signal is constant regardless of cradle family rotation. See <a href="{{ '/sigma-rules/clickfix/' | relative_url }}">sigma-rules/clickfix/hunt.yml</a>.
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t1" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 1</span></div>
  <div class="cg-rec-body">
    <strong>Cradle-agnostic network fetch detection</strong>
    Move from IWR/IRM string matching to: <em>PowerShell process → outbound HTTP/HTTPS to non-Microsoft, non-CDN domain → path ends in .ps1/.txt/.hta</em>. This catches IWR, Curl, WebClient, and any future cradle. Update Sigma rules to use process+network correlation, not command-string pattern matching.
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t2" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 2</span></div>
  <div class="cg-rec-body">
    <strong>Detect Base64 decode + execute</strong>
    <code>[Convert]::FromBase64String</code> or <code>[Text.Encoding]::UTF8.GetString</code> followed immediately by <code>iex</code> / <code>Invoke-Expression</code>. The encoding act itself is detectable even when the decoded content is not. This covers the 18× Base64 increase seen in Jan 2026.
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t2" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 2</span></div>
  <div class="cg-rec-body">
    <strong>File write → execute → delete correlation (new Dec 2025)</strong>
    Self-delete appeared at scale in December 2025. Correlate: script written to <code>%TEMP%</code> → process execution from that path → file deletion within seconds. If artifact-based rules are your only coverage, they're now blind after execution completes. Use process execution telemetry, not file presence.
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-blind" style="display:block;text-align:center;padding:.25rem .5rem;background:#21262d;color:#8b949e;">INFRA</span></div>
  <div class="cg-rec-body">
    <strong>CDN staging: pivot from domain blocking to path-pattern detection</strong>
    <code>irp.cdn-website.com</code> is a legitimate CDN. Block it and you break legitimate sites. Instead, alert on PowerShell fetching from <code>*.cdn-website.com</code> paths matching <code>/files/uploaded/*.ps1</code>. Or use JA4/TLS fingerprinting on the outbound connection rather than the destination hostname.
  </div>
</div>

</div><!-- /.cg-page -->

<!-- ── Data injection + chart init ──────────────────────────────────── -->
<script>
window.CLICKGRAB_TRENDS = {{ site.data.clickgrab_trends | jsonify }};
</script>
<script src="{{ '/assets/js/clickgrab-trends.js' | relative_url }}"></script>

---
layout: default
title: Software Impersonation Infrastructure
description: "How to fingerprint masquerading software infrastructure — domain patterns, favicon clusters, delivery chains, campaign clustering, and the detection chokepoints that survive perfect visual impersonation."
permalink: /trends/masq-infra/
---

<style>
/* ── Page layout ────────────────────────────────────────────────────────── */
.cg-page { max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
.cg-page h1 { font-size: 1.6rem; font-weight: 700; color: var(--text); margin-bottom: .25rem; }
.cg-page h2 { font-size: 1.15rem; font-weight: 600; color: var(--text); margin: 2.5rem 0 .75rem; border-bottom: 1px solid var(--border); padding-bottom: .4rem; }
.cg-page h3 { font-size: 1rem; font-weight: 600; color: var(--text); margin: 1.5rem 0 .5rem; }
.cg-page p, .cg-page li { color: var(--text-muted); font-size: .9rem; line-height: 1.7; }
.cg-page a { color: var(--link); }
.cg-page strong { color: var(--text); }
.cg-page code { font-family: ui-monospace, monospace; font-size: .85rem; background: var(--bg-card); border: 1px solid var(--border); border-radius: 3px; padding: .1rem .3rem; color: var(--text); }
.cg-page pre { background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; overflow-x: auto; margin: .75rem 0 1.25rem; }
.cg-page pre code { background: none; border: none; padding: 0; font-size: .82rem; }
.cg-page hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }
.cg-meta { color: var(--text-muted); font-size: .8rem; margin-bottom: 1.75rem; }

/* ── Stats row ──────────────────────────────────────────────────────────── */
.cg-stats { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.25rem 0 2rem; }
.cg-stat  { flex: 1 1 140px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: .85rem 1rem; }
.cg-stat-val { font-size: 1.5rem; font-weight: 700; color: var(--text); font-family: ui-monospace, monospace; line-height: 1.2; }
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
.cg-chain-stage--blind { border-top: 3px solid var(--border); }
.cg-chain-stage--t1    { border-top: 3px solid var(--high); }
.cg-chain-stage--t2    { border-top: 3px solid var(--accent); }
.cg-chain-stage--t3    { border-top: 3px solid var(--critical); }
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

/* ── Callout boxes ──────────────────────────────────────────────────────── */
.cg-callout { border-radius: 6px; padding: .85rem 1rem; margin: .75rem 0; font-size: .875rem; border-left: 3px solid; }
.cg-callout--warn  { background: rgba(227,179,65,.08);  border-color: var(--high);     color: var(--text); }
.cg-callout--alert { background: rgba(218,54,51,.08);   border-color: var(--critical); color: var(--text); }
.cg-callout--info  { background: rgba(56,139,253,.08);  border-color: var(--low);      color: var(--text); }
.cg-callout--tip   { background: rgba(63,185,80,.08);   border-color: var(--medium);   color: var(--text); }
.cg-callout strong { color: var(--text); }

/* ── Tables ─────────────────────────────────────────────────────────────── */
.cg-table { width: 100%; border-collapse: collapse; font-size: .85rem; margin: .75rem 0 1.5rem; }
.cg-table th { text-align: left; color: var(--text-muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; border-bottom: 1px solid var(--border); padding: .4rem .6rem; font-weight: 600; }
.cg-table td { padding: .45rem .6rem; border-bottom: 1px solid var(--border); color: var(--text); font-size: .85rem; }
.cg-table tr:last-child td { border-bottom: none; }
.cg-table td.mono { font-family: ui-monospace, monospace; font-size: .82rem; }
.cg-table td.muted { color: var(--text-muted); font-family: inherit; }

/* ── Recommendation list ────────────────────────────────────────────────── */
.cg-rec { display: flex; gap: .75rem; align-items: flex-start; padding: .6rem 0; border-bottom: 1px solid var(--border); }
.cg-rec:last-child { border-bottom: none; }
.cg-rec-tier { flex: 0 0 62px; }
.cg-rec-body { flex: 1; font-size: .875rem; color: var(--text-muted); }
.cg-rec-body strong { color: var(--text); display: block; margin-bottom: .2rem; }

/* ── Favicon hash example ───────────────────────────────────────────────── */
.cg-fav-demo {
  display: flex; gap: 1rem; flex-wrap: wrap;
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px;
  padding: 1rem 1.25rem; margin: 1rem 0 1.5rem; align-items: flex-start;
}
.cg-fav-hash {
  font-family: ui-monospace, monospace; font-size: .78rem; color: var(--text-muted);
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 4px;
  padding: .5rem .75rem; flex: 1 1 280px; word-break: break-all;
}
.cg-fav-hash strong { color: var(--accent); display: block; font-size: .65rem; letter-spacing: .05em; text-transform: uppercase; margin-bottom: .35rem; }

/* ── Delivery chain diagram ──────────────────────────────────────────────── */
.cg-delivery { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0 1.5rem; font-family: ui-monospace, monospace; font-size: .82rem; color: var(--text-muted); line-height: 2; }
.cg-delivery span.node { color: var(--text); font-weight: 600; }
.cg-delivery span.label { color: var(--accent); font-size: .75rem; }
</style>

<div class="cg-page">

<h1>Software Impersonation Infrastructure</h1>
<p class="cg-meta">
  Coverage: T1036 Masquerading · T1583.001 Domains · T1608.001 Upload Malware
  &nbsp;·&nbsp; Updated: {{ site.data.masq_infra.meta.last_updated }}{% if site.data.masq_infra.meta.sample_size > 0 %} &nbsp;·&nbsp; n={{ site.data.masq_infra.meta.sample_size }}, {{ site.data.masq_infra.meta.lookback_days }}-day lookback{% endif %}
</p>

<div class="cg-callout cg-callout--info">
  <strong>Page focus:</strong> Software impersonation is always the lure. A user must believe they are downloading legitimate software — the voluntary execution is required for the attack to succeed. This constraint makes the infrastructure fingerprint consistent and detectable. This page documents how to identify, cluster, and hunt that infrastructure, and what payloads it delivers.
</div>

<!-- ── Stats ─────────────────────────────────────────────────────────── -->
<div class="cg-stats">
  <div class="cg-stat">
    <div class="cg-stat-val">{% if site.data.masq_infra.stats.tls_lets_encrypt_pct > 0 %}{{ site.data.masq_infra.stats.tls_lets_encrypt_pct }}%{% else %}99%+{% endif %}</div>
    <div class="cg-stat-lbl">Sites with Let's Encrypt TLS</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{% if site.data.masq_infra.stats.domain_to_resolution_hours_median > 0 %}{{ site.data.masq_infra.stats.domain_to_resolution_hours_median }}h{% else %}&lt;48h{% endif %}</div>
    <div class="cg-stat-lbl">Cert issuance → live domain (median)</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{% if site.data.masq_infra.stats.favicon_clusters_found > 0 %}{{ site.data.masq_infra.stats.favicon_clusters_found }}{% else %}—{% endif %}</div>
    <div class="cg-stat-lbl">Brand favicon clusters found (Shodan)</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">T1036.005</div>
    <div class="cg-stat-lbl">PE OriginalFilename mismatch — primary chokepoint</div>
  </div>
</div>

<!-- ── The Lure ───────────────────────────────────────────────────────── -->
<h2>The Lure</h2>
<p>Software impersonation is uniquely suited to drive-by malware delivery because the user must voluntarily execute the payload. That requirement means the attacker must maintain the illusion long enough for the user to click through a download prompt and run a file. No other lure type — phishing pages, document macros, browser exploits — imposes the same constraint. The result is a consistent infrastructure pattern: a convincing download page, a real-looking binary, and an execution moment the attacker can count on.</p>

<p>Other lure types exist but use different infrastructure patterns and are out of scope here. Document/macro lures and phishing pages don't need the download-page illusion. This page covers only software-impersonation download infrastructure.</p>

<h3>Lure Taxonomy</h3>
<table class="cg-table">
  <thead>
    <tr><th>Category</th><th>Targets</th><th>Typical payload</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>fake_software</strong></td>
      <td class="muted">7-Zip, WinRAR, VLC, Notepad++, Audacity, GIMP, LibreOffice</td>
      <td class="muted">Lumma, Vidar, RedLine, StealC — general-purpose infostealers</td>
    </tr>
    <tr>
      <td><strong>fake_ai_tool</strong></td>
      <td class="muted">ChatGPT, Midjourney, Claude, Gemini desktop apps</td>
      <td class="muted">Lumma, AMOS (macOS) — credential + crypto theft focus</td>
    </tr>
    <tr>
      <td><strong>crypto_wallet</strong></td>
      <td class="muted">MetaMask, Ledger Live, Exodus, Phantom, Electrum</td>
      <td class="muted">Atomic Stealer, MetaStealer, Clipbanker — wallet seed theft</td>
    </tr>
    <tr>
      <td><strong>vpn_tool</strong></td>
      <td class="muted">NordVPN, ProtonVPN, Mullvad, ExpressVPN</td>
      <td class="muted">AsyncRAT, Remcos — persistent access; privacy-seeking targets</td>
    </tr>
    <tr>
      <td><strong>remote_work</strong></td>
      <td class="muted">Zoom, Slack, Teams, Webex</td>
      <td class="muted">CobaltStrike, AsyncRAT — corporate targeting</td>
    </tr>
    <tr>
      <td><strong>fake_update</strong></td>
      <td class="muted">Browser update prompts, Windows update lures</td>
      <td class="muted">Varied; often paired with ClickFix delivery chains</td>
    </tr>
    <tr>
      <td><strong>game_crack</strong></td>
      <td class="muted">Steam, Roblox, Minecraft — cheat tools, "free" versions</td>
      <td class="muted">RedLine, Raccoon — credential theft from younger user base</td>
    </tr>
  </tbody>
</table>

{% if site.data.masq_infra.lure_types.size > 0 %}
<h3>Observed Lure Types ({{ site.data.masq_infra.meta.lookback_days }}-day window)</h3>
<table class="cg-table">
  <thead>
    <tr><th>Category</th><th>Domains</th><th>Share</th></tr>
  </thead>
  <tbody>
    {% for lure in site.data.masq_infra.lure_types %}
    <tr>
      <td>{{ lure.tag | replace: "_", " " }}</td>
      <td>{{ lure.count }}</td>
      <td class="muted">{{ lure.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── How Users Arrive ───────────────────────────────────────────────── -->
<h2>How Users Arrive: Traffic Sources</h2>
<p>Understanding how users reach lure pages determines which detection layer can intercept them. The same fake download page may be delivered via four distinct vectors, each with different detection surface.</p>

<table class="cg-table">
  <thead>
    <tr><th>Vector</th><th>Mechanism</th><th>Domain pattern</th><th>Detection surface</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>combosquat</strong></td>
      <td class="muted">Brand name + action word in domain; ranks well for "download X free" queries</td>
      <td class="mono">7zip-download.com · get-vlc.net</td>
      <td class="muted">DNS / crt.sh monitoring for brand + action-word combos</td>
    </tr>
    <tr>
      <td><strong>typosquat</strong></td>
      <td class="muted">User mistyped URL or clicked near-miss from autocomplete</td>
      <td class="mono">7-z1p.org · vIc-media.org</td>
      <td class="muted">Unicode normalization check; edit-distance alerting on cert transparency</td>
    </tr>
    <tr>
      <td><strong>seo_bait</strong></td>
      <td class="muted">Brand buried in longer domain string; SEO-optimised content</td>
      <td class="mono">free-discord-nitro24.top · best7zipalternative.click</td>
      <td class="muted">URLScan / passive DNS monitoring for brand-substring domains with generic TLDs</td>
    </tr>
    <tr>
      <td><strong>redirected</strong></td>
      <td class="muted">Malvertising via Google/Bing Ads; submitted URL is ad-tracker, landing is lure</td>
      <td class="muted">Landing domain differs from submitted URL (ad tracking redirect)</td>
      <td class="muted">Browser proxy logs; URLScan task.url vs page.url mismatch</td>
    </tr>
  </tbody>
</table>

{% if site.data.masq_infra.traffic_sources.size > 0 %}
<h3>Observed Traffic Source Distribution</h3>
<table class="cg-table">
  <thead>
    <tr><th>Source</th><th>Domains</th><th>Share</th></tr>
  </thead>
  <tbody>
    {% for src in site.data.masq_infra.traffic_sources %}
    <tr>
      <td>{{ src.source }}</td>
      <td>{{ src.count }}</td>
      <td class="muted">{{ src.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── Infrastructure Fingerprinting ─────────────────────────────────── -->
<h2>Infrastructure Fingerprinting</h2>
<p>Because the attacker's operational constraints don't change — fast deployment, low cost, abuse-resistant hosting — the infrastructure patterns are remarkably consistent across campaigns and operators. These signals survive tool rotation and can be queried proactively.</p>

<!-- 3a. Domain naming patterns -->
<h3>Domain Naming Patterns</h3>
<p>Three naming strategies dominate. Combosquatting (brand + action word) is the most common because it satisfies the user's search intent — the extra keyword is not a mistake, it's SEO strategy.</p>

<table class="cg-table">
  <thead>
    <tr><th>Strategy</th><th>Example (target: 7-zip.org)</th><th>Detection angle</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Typosquatting</strong></td>
      <td class="mono">7-z1p.org · 7ziip.org · 7-zip.net</td>
      <td class="muted">crt.sh substring query; edit-distance ≤ 2 from official domain</td>
    </tr>
    <tr>
      <td><strong>Combosquatting</strong></td>
      <td class="mono">7zip-download.com · get-7zip.org · 7zip-free.net</td>
      <td class="muted">Brand + {download, get, free, install, setup, official, latest} pattern</td>
    </tr>
    <tr>
      <td><strong>Homoglyph substitution</strong></td>
      <td class="mono">7‑zip.org (en-dash) · vlc-mediа.org (Cyrillic а)</td>
      <td class="muted">Unicode normalization check — visually identical but distinct bytes</td>
    </tr>
  </tbody>
</table>

{% if site.data.masq_infra.domain_patterns.size > 0 %}
<h3>Observed Naming Patterns (live data)</h3>
<p>Recurring structural skeletons across collected samples. <code>{brand}</code> = brand name substituted; <code>{N}</code> = digit sequence.</p>
<table class="cg-table">
  <thead>
    <tr><th>Pattern</th><th>Count</th><th>Example</th></tr>
  </thead>
  <tbody>
    {% for pat in site.data.masq_infra.domain_patterns %}
    <tr>
      <td class="mono">{{ pat.pattern }}</td>
      <td>{{ pat.count }}</td>
      <td class="mono muted">{{ pat.example }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<p><strong>URLScan hunting queries{% if site.data.masq_infra.chokepoints.urlscan_hunt_queries.size > 0 %} (derived from observed patterns){% endif %}:</strong></p>
<pre><code>{% if site.data.masq_infra.chokepoints.urlscan_hunt_queries.size > 0 %}{% for q in site.data.masq_infra.chokepoints.urlscan_hunt_queries -%}
{{ q }}
{% endfor %}{% else %}page.domain:*7-zip*download* AND date:&gt;now-30d
page.domain:*vlc*install* AND date:&gt;now-30d{% endif %}</code></pre>
{% endif %}

<!-- 3b. TLS / Certificate signals -->
<h3>TLS &amp; Certificate Signals</h3>
<p>Let's Encrypt certificates appear on effectively all active delivery sites. The HTTPS padlock no longer signals trust — it signals only that TLS is configured, which is free and automated. Certificate transparency gives defenders a detection window: new impersonation infrastructure almost always acquires a certificate within hours of domain registration, before the site is weaponized or before users encounter it.</p>

<p><strong>crt.sh monitoring query:</strong></p>
<pre><code># New certificates containing brand name — run on a schedule
https://crt.sh/?q=%25.7-zip.%25&amp;output=json
https://crt.sh/?q=%25discord%25download%25&amp;output=json

# CertStream filter (Python)
# Alert: domain matches /(7-?zip|winrar|vlc|discord|telegram)/i
#        AND issuer == "Let's Encrypt"
#        AND not_before within last 48h</code></pre>

<!-- 3c. Hosting -->
<h3>Hosting &amp; ASN Clustering</h3>
<p>Adversaries prefer hosting where domain reputation is initially clean and abuse reports take days to process. Cloudflare's infrastructure is particularly common — not because of Cloudflare abuse specifically, but because legitimate sites use Cloudflare, so <code>pages.dev</code> and Cloudflare-proxied domains inherit clean reputation signals that bypass many filters.</p>

{% if site.data.masq_infra.meta.sample_size > 0 %}
<table class="cg-table">
  <thead>
    <tr><th>Provider / ASN</th><th>Domains</th><th>Share</th></tr>
  </thead>
  <tbody>
    {% for provider in site.data.masq_infra.hosting_providers %}
    <tr>
      <td>{{ provider.name }}</td>
      <td>{{ provider.count }}</td>
      <td class="muted">{{ provider.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- 3d. Favicon hash pivoting -->
<h3>Favicon Hash Pivoting</h3>
<p>Favicons are trivially stolen — a single HTTP request retrieves the bytes that brand a fake site with a recognizable logo. What makes this useful for defenders: <strong>the same bytes hash to the same value across all infrastructure reusing that favicon</strong>. Shodan indexes HTTP response favicon hashes, enabling bulk infrastructure discovery from a single known-malicious domain.</p>

<div class="cg-fav-demo">
  <div class="cg-fav-hash">
    <strong>Shodan query format</strong>
    http.favicon.hash:&lt;murmur3_int32&gt;
  </div>
  <div class="cg-fav-hash">
    <strong>Censys query format</strong>
    services.http.response.favicons.md5_hash:&lt;md5hex&gt;
  </div>
  <div class="cg-fav-hash">
    <strong>Compute hash locally (Python)</strong>
    import mmh3, requests, base64<br>
    r = requests.get('https://target.com/favicon.ico')<br>
    h = mmh3.hash(base64.encodebytes(r.content))<br>
    print(h)  # paste into Shodan
  </div>
</div>

{% if site.data.masq_infra.favicon_clusters.size > 0 %}
<h3>Active Favicon Clusters (Shodan)</h3>
<table class="cg-table">
  <thead>
    <tr><th>Brand</th><th>Hash</th><th>Impersonator hosts</th><th>Sample host</th></tr>
  </thead>
  <tbody>
    {% for cluster in site.data.masq_infra.favicon_clusters %}
    <tr>
      <td>{{ cluster.brand }}</td>
      <td class="mono">{{ cluster.hash }}</td>
      <td>{{ cluster.count }}</td>
      <td class="mono muted">{{ cluster.sample_hosts | first }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── IOK Rules ───────────────────────────────────────────────────────── -->
<h2>IOK Rules — Lure Page Fingerprinting</h2>
<p>Indicators of Kit (IOK) rules identify lure pages by their structural patterns — URL shape, HTML content, and TLS signals — before a binary is ever downloaded. These rules can be applied to URLScan results, proxy logs, or crawl pipelines.</p>

<pre><code># IOK rule: fake software download page (generic)
rule: fake_software_download_lure
meta:
  description: Masquerading software download page with brand impersonation
  mitre: [T1036, T1583.001, T1608.001]
  author: detection-chokepoints
indicators:
  url:
    - pattern: "(7zip|winrar|vlc|notepad|discord|telegram|chatgpt|zoom|nordvpn).*(download|install|setup|free|get)"
    - pattern: "(get|download|free)-(7zip|vlc|discord|telegram|chatgpt)\\.(com|net|org|top|click)"
  html:
    - pattern: "&lt;title&gt;.*(?:download|free|official).*(?:7-?zip|winrar|vlc|discord|telegram).*&lt;/title&gt;"
    - pattern: "(?:btn-download|download-btn|dl-button|downloadNow)"
  tls:
    - issuer_cn_contains: "Let's Encrypt"</code></pre>

<pre><code># IOK rule: crypto wallet impersonation
rule: crypto_wallet_lure
meta:
  description: Fake crypto wallet installer — wallet seed theft
  mitre: [T1036, T1583.001]
indicators:
  url:
    - pattern: "(metamask|ledger|exodus|phantom|electrum).*(download|install|desktop|app|wallet)"
    - pattern: "(get|install|official)-(metamask|ledger|exodus|phantom)\\."
  html:
    - pattern: "&lt;title&gt;.*(?:metamask|ledger live|exodus|phantom).*(?:download|wallet|app).*&lt;/title&gt;"
    - pattern: "(?:connect-wallet|wallet-connect|seed-phrase)"
  tls:
    - not_before_age_hours_max: 72</code></pre>

<pre><code># IOK rule: fast-deployed brand typosquat (infrastructure signal)
rule: fast_deploy_brand_typosquat
meta:
  description: Brand-name domain with Let's Encrypt cert issued &lt;48h ago
  note: High-signal for newly weaponized infrastructure before URLScan coverage
indicators:
  tls:
    - issuer_cn_contains: "Let's Encrypt"
    - not_before_age_hours_max: 48
  url:
    - pattern: "(7-?zip|winrar|vlc|notepad|discord|telegram|chatgpt|zoom|nordvpn)"
    - tld_in: [".top", ".click", ".xyz", ".pw", ".cam", ".life", ".shop"]</code></pre>

<!-- ── Delivery Chain ──────────────────────────────────────────────────── -->
<h2>Delivery Chain</h2>
<p>Where does the payload actually come from? The binary is often <strong>not</strong> hosted on the same domain as the lure page. Single-domain blocklisting misses the binary when it's staged on a CDN or separate bulletproof host.</p>

<div class="cg-delivery">
  <span class="node">[Lure page]</span> ──direct──▶ <span class="node">[Payload download]</span> <span class="label">  ← most common</span><br>
  <span class="node">[Lure page]</span> ──302──▶ <span class="node">[CDN / file host]</span> ──▶ <span class="node">[Payload]</span> <span class="label">  ← off-domain staging</span><br>
  <span class="node">[Ad link]</span> ──▶ <span class="node">[Tracker redirect]</span> ──▶ <span class="node">[Lure page]</span> ──▶ <span class="node">[Payload]</span> <span class="label">  ← malvertising</span>
</div>

{% if site.data.masq_infra.payload_hosting.offhost_count > 0 %}
<p>In the current dataset: <strong>{{ site.data.masq_infra.payload_hosting.offhost_count }} payloads ({{ site.data.masq_infra.payload_hosting.offhost_pct }}%)</strong> are hosted on a different domain than the lure page.</p>

{% if site.data.masq_infra.payload_hosting.top_payload_hosts.size > 0 %}
<h3>Top Off-Domain Payload Hosts</h3>
<table class="cg-table">
  <thead>
    <tr><th>Host</th><th>Payloads</th><th>Share of off-host</th></tr>
  </thead>
  <tbody>
    {% for host in site.data.masq_infra.payload_hosting.top_payload_hosts %}
    <tr>
      <td class="mono">{{ host.name }}</td>
      <td>{{ host.count }}</td>
      <td class="muted">{{ host.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}
{% endif %}

{% if site.data.masq_infra.delivery_chains.size > 0 %}
<h3>Sample Delivery Chains</h3>
<table class="cg-table">
  <thead>
    <tr><th>Lure domain</th><th>Payload host</th><th>Off-host?</th><th>File type</th><th>Family</th></tr>
  </thead>
  <tbody>
    {% for chain in site.data.masq_infra.delivery_chains %}
    <tr>
      <td class="mono">{{ chain.lure_domain }}</td>
      <td class="mono">{{ chain.payload_host }}</td>
      <td class="muted">{% if chain.offhost %}yes{% else %}same domain{% endif %}</td>
      <td class="muted">{{ chain.file_type | default: "—" }}</td>
      <td>{{ chain.malware_family | default: "—" }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── Campaign Clustering ─────────────────────────────────────────────── -->
<h2>Campaign Clustering</h2>
<p>Shared observable signals link multiple lure domains to the same operator or campaign. Two signals are tracked:</p>
<ul>
  <li><strong>shared_payload</strong> — two or more domains serving the exact same binary (SHA256 match). Same operator reusing a compiled binary without recompiling between deployments.</li>
  <li><strong>asn_cohort</strong> — three or more domains appearing on the same ASN within the same calendar month. Consistent with batch domain registration and bulk hosting account abuse.</li>
</ul>

{% if site.data.masq_infra.campaign_clusters.size > 0 %}
<table class="cg-table">
  <thead>
    <tr><th>Type</th><th>Signal</th><th>Brand</th><th>Domains</th><th>Payloads</th><th>Date range</th></tr>
  </thead>
  <tbody>
    {% for cluster in site.data.masq_infra.campaign_clusters limit:10 %}
    <tr>
      <td>{{ cluster.cluster_type | replace: "_", " " }}</td>
      <td class="mono muted">{{ cluster.signal }}</td>
      <td>{{ cluster.brand }}</td>
      <td>{{ cluster.domain_count }}</td>
      <td class="muted">{{ cluster.payload_families | join: ", " | default: "—" }}</td>
      <td class="muted">{% if cluster.date_range.first %}{{ cluster.date_range.first | date: "%Y-%m-%d" }}{% endif %}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="cg-callout cg-callout--info">Campaign clustering data will populate after the next pipeline run collects payload SHA256 values or identifies ASN cohorts. Requires MalwareBazaar enrichment and at least 3 samples per ASN/month bucket.</div>
{% endif %}

<!-- ── Payload Inventory ───────────────────────────────────────────────── -->
<h2>Payload Inventory</h2>
<p>Software impersonation infrastructure almost exclusively delivers infostealers and RATs — malware families designed to extract credentials, crypto wallet seeds, session tokens, and system access without visible symptoms. The lure type strongly predicts the payload family.</p>

{% if site.data.masq_infra.payload_families.size > 0 %}
<h3>Payload Families</h3>
<table class="cg-table">
  <thead>
    <tr><th>Family</th><th>Samples</th><th>Share</th></tr>
  </thead>
  <tbody>
    {% for fam in site.data.masq_infra.payload_families %}
    <tr>
      <td>{{ fam.family }}</td>
      <td>{{ fam.count }}</td>
      <td class="muted">{{ fam.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

{% if site.data.masq_infra.payload_file_types.size > 0 %}
<h3>Payload File Types</h3>
<table class="cg-table">
  <thead>
    <tr><th>Type</th><th>Count</th><th>Share</th></tr>
  </thead>
  <tbody>
    {% for ft in site.data.masq_infra.payload_file_types %}
    <tr>
      <td class="mono">{{ ft.type }}</td>
      <td>{{ ft.count }}</td>
      <td class="muted">{{ ft.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

{% if site.data.masq_infra.urlhaus_tags.size > 0 %}
<h3>URLHaus Threat Tags</h3>
<table class="cg-table">
  <thead>
    <tr><th>Tag</th><th>URLs</th></tr>
  </thead>
  <tbody>
    {% for tag in site.data.masq_infra.urlhaus_tags limit:10 %}
    <tr>
      <td>{{ tag.tag }}</td>
      <td>{{ tag.count }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── Detection Chokepoints ──────────────────────────────────────────── -->
<h2>Detection Chokepoints</h2>
<p>Perfect visual impersonation neutralizes every user-facing trust signal. These are the stages where adversaries run out of room to maintain the illusion, with concrete rule examples and matched payload observations.</p>

<div class="cg-chain" role="list" aria-label="Software impersonation delivery chain">
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">SEO / ad delivers user</span>
    <span class="cg-chain-sub">Search or malvertising</span>
    <span class="cg-tier-badge cg-tier-blind">NOT DETECTABLE</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">Visual trust satisfied</span>
    <span class="cg-chain-sub">TLS, favicon, cloned UI</span>
    <span class="cg-tier-badge cg-tier-blind">PRE-EXEC</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t1" role="listitem">
    <span class="cg-chain-label">Browser download</span>
    <span class="cg-chain-sub">File lands in %Downloads%; MotW applied</span>
    <span class="cg-tier-badge cg-tier-t1">TIER 1</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t1" role="listitem">
    <span class="cg-chain-label">User execution</span>
    <span class="cg-chain-sub">Installer runs from Downloads / Temp</span>
    <span class="cg-tier-badge cg-tier-t1">TIER 1</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t2" role="listitem">
    <span class="cg-chain-label">PE metadata exposed</span>
    <span class="cg-chain-sub">OriginalFilename ≠ displayed name</span>
    <span class="cg-tier-badge cg-tier-t2">TIER 2</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t2" role="listitem">
    <span class="cg-chain-label">C2 / staging callback</span>
    <span class="cg-chain-sub">Payload fetches stage 2 or phones home</span>
    <span class="cg-tier-badge cg-tier-t2">TIER 2</span>
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t1" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 1</span></div>
  <div class="cg-rec-body">
    <strong>PE OriginalFilename mismatch at execution (T1036.005)</strong>
    <p>Alert when a process's <code>OriginalFilename</code> (from PE version resource) does not match its running filename. Adversaries rename existing malicious binaries — they rarely recompile with matching resources. This is one of the most reliable signals in the framework.</p>
<pre><code># Sigma — PE OriginalFilename mismatch from download path
detection:
  selection:
    Image|endswith:
      - '\7-Zip.exe'
      - '\VLC.exe'
      - '\DiscordSetup.exe'
      - '\NordVPN.exe'
      - '\ZoomInstaller.exe'
    CurrentDirectory|contains:
      - '\Downloads\'
      - '\AppData\Local\Temp\'
  filter_legit:
    OriginalFileName|contains:
      - '7-Zip'
      - 'VLC'
      - 'Discord'
      - 'NordVPN'
      - 'Zoom'
condition: selection and not filter_legit

{% if site.data.masq_infra.chokepoints.matched_example %}# Matched: {{ site.data.masq_infra.chokepoints.matched_example.domain }} → {{ site.data.masq_infra.chokepoints.matched_example.filename }}
#   OriginalFileName: {{ site.data.masq_infra.chokepoints.matched_example.family }}.exe  → ALERT{% else %}# Matched example: 7zip-download.com → 7-Zip.exe
#   OriginalFileName: LummaC.exe  → ALERT{% endif %}</code></pre>
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t1" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 1</span></div>
  <div class="cg-rec-body">
    <strong>Signed binary executing from user download path</strong>
    <p>Adversaries increasingly code-sign malware to bypass reputation checks. A <em>signed</em> binary running from <code>%Downloads%</code> is more anomalous than an unsigned one in managed environments — legitimate signed software is deployed via package manager or IT tooling, not user download directories.</p>
<pre><code># Sigma — signed binary spawned by browser from Downloads
detection:
  selection:
    ParentImage|contains:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
    Image|endswith:
      - '\setup.exe'
      - '\installer.exe'
      - '\install.exe'
    CurrentDirectory|contains: '\Downloads\'
    Signed: 'true'
condition: selection</code></pre>
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t2" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 2</span></div>
  <div class="cg-rec-body">
    <strong>Certificate transparency monitoring for brand typosquats</strong>
    <p>Subscribe to crt.sh or CertStream and alert on certificates issued for domains containing monitored brand names. New impersonation infrastructure acquires a TLS certificate within hours of registration — cert transparency gives you a detection window before users encounter the site.</p>
<pre><code># CertStream monitor (Python — certstream library)
# Alert on: domain matches brand pattern AND Let's Encrypt AND issued &lt;48h

WATCH_BRANDS = re.compile(
    r'({% if site.data.masq_infra.chokepoints.certstream_regex != "" %}{{ site.data.masq_infra.chokepoints.certstream_regex }}{% else %}7-?zip|winrar|vlc|notepad|discord|telegram|chatgpt|zoom|nordvpn{% endif %})',
    re.IGNORECASE
)
def on_cert(message, context):
    domains = message['data']['leaf_cert']['all_domains']
    for domain in domains:
        if WATCH_BRANDS.search(domain):
            alert(domain, message['data']['leaf_cert']['subject']['CN'])</code></pre>
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t2" style="display:block;text-align:center;padding:.25rem .5rem;">INFRA</span></div>
  <div class="cg-rec-body">
    <strong>Favicon hash pivoting for infrastructure clustering</strong>
    <p>From one confirmed fake domain: fetch favicon → compute Murmur3 hash → query Shodan. Campaigns reusing the same stolen favicon across dozens of domains will surface immediately. Blocklist the entire cluster, not just the single known URL.</p>
<pre><code># Known impersonator favicon hashes (Shodan)
{% if site.data.masq_infra.chokepoints.favicon_hashes.size > 0 %}{% for fh in site.data.masq_infra.chokepoints.favicon_hashes -%}
http.favicon.hash:{{ fh.hash }}   # {{ fh.brand }} favicon ({{ fh.count }} impersonators)
{% endfor %}{% else %}http.favicon.hash:-469815234   # Telegram favicon on non-Telegram infrastructure
http.favicon.hash:991727625    # 7-Zip favicon
http.favicon.hash:9732861      # VLC favicon
http.favicon.hash:-1899664115  # Notepad++ favicon
{% endif %}</code></pre>
  </div>
</div>

<!-- ── Recent Samples ─────────────────────────────────────────────────── -->
{% if site.data.masq_infra.meta.sample_size > 0 and site.data.masq_infra.recent_samples.size > 0 %}
<h2>Recent Samples</h2>
<table class="cg-table">
  <thead>
    <tr><th>First seen</th><th>Domain</th><th>Lure type</th><th>Traffic source</th><th>Payload host</th><th>Family</th></tr>
  </thead>
  <tbody>
    {% for sample in site.data.masq_infra.recent_samples %}
    <tr>
      <td class="muted">{{ sample.first_seen | date: "%Y-%m-%d" }}</td>
      <td class="mono">{{ sample.domain }}</td>
      <td>{{ sample.lure_type | replace: "_", " " }}</td>
      <td class="muted">{{ sample.traffic_source | default: "—" }}</td>
      <td class="mono muted">{{ sample.payload_host | default: "—" }}</td>
      <td>{{ sample.malware_family | default: "—" }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

</div><!-- /.cg-page -->

---
layout: default
title: Trends
description: "Data-driven trend analysis for detection engineers. Tracks payload prevalence, command-line patterns, evasion technique shifts, and malicious infrastructure over time."
permalink: /trends/
---

<style>
/* ── Page layout ────────────────────────────────────────────────────────── */
.tr-hero {
  position: relative;
  padding: 5.5rem 1.5rem 5rem;
  background: var(--bg);
  overflow: hidden;
  text-align: center;
}
.tr-hero-inner { max-width: 680px; margin: 0 auto; }
.tr-hero::before {
  content: "";
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse 80% 55% at 50% -5%, rgba(240,136,62,.18) 0%, transparent 65%);
  pointer-events: none;
}
.tr-hero::after {
  content: "";
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 1px;
  background: linear-gradient(to right, transparent, var(--border) 20%, var(--border) 80%, transparent);
}
.tr-hero > * { position: relative; }
.tr-hero h1 {
  font-size: 2.75rem;
  font-weight: 800;
  color: var(--text);
  margin-bottom: .75rem;
  letter-spacing: -.02em;
}
.tr-hero p { font-size: 1rem; color: var(--text-muted); max-width: 560px; line-height: 1.8; margin: 0 auto; }

/* ── What lives here ────────────────────────────────────────────────────── */
.tr-pillars {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: .75rem;
  margin: 2.5rem 0 2.75rem;
}
.tr-pillar {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.1rem 1.25rem;
  box-shadow: 0 4px 16px rgba(0,0,0,0.2), inset 0 1px 0 rgba(255,255,255,0.04);
  transition: border-color .15s, box-shadow .15s;
}
.tr-pillar:hover {
  border-color: rgba(240,136,62,0.35);
  box-shadow: 0 6px 20px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.06);
}
.tr-pillar-icon {
  width: 36px; height: 36px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 8px;
  background: linear-gradient(135deg, rgba(240,136,62,0.22) 0%, rgba(240,136,62,0.07) 100%);
  border: 1px solid rgba(240,136,62,0.2);
  color: var(--accent);
  margin-bottom: .75rem;
}
.tr-pillar-icon svg { width: 18px; height: 18px; }
.tr-pillar-title {
  font-size: .78rem;
  font-weight: 700;
  color: var(--text);
  text-transform: uppercase;
  letter-spacing: .06em;
  margin-bottom: .35rem;
}
.tr-pillar-desc { font-size: .8rem; color: var(--text-muted); line-height: 1.6; }

/* ── Section header ─────────────────────────────────────────────────────── */
.tr-section-header {
  display: flex;
  align-items: baseline;
  gap: .75rem;
  margin-bottom: 1.25rem;
}
.tr-section-header h2 {
  font-size: .72rem;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: .12em;
  margin: 0;
}
.tr-section-header-line {
  flex: 1;
  height: 1px;
  background: linear-gradient(to right, var(--border) 0%, transparent 100%);
}

/* ── Analysis cards ─────────────────────────────────────────────────────── */
.tr-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 1rem;
  margin-bottom: 3rem;
}
.tr-card {
  display: flex;
  flex-direction: column;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem 1.4rem;
  text-decoration: none;
  color: inherit;
  transition: border-color .2s, box-shadow .2s, transform .2s;
  box-shadow: 0 4px 16px rgba(0,0,0,0.2), inset 0 1px 0 rgba(255,255,255,0.04);
}
.tr-card:hover {
  border-color: var(--accent);
  box-shadow: 0 0 0 1px var(--accent), 0 12px 32px rgba(0,0,0,.3), inset 0 1px 0 rgba(255,255,255,0.06);
  transform: translateY(-2px);
  text-decoration: none;
  color: inherit;
}
.tr-card-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: .75rem;
  margin-bottom: .6rem;
}
.tr-card-badge {
  display: inline-block;
  font-size: .65rem;
  font-weight: 700;
  letter-spacing: .06em;
  text-transform: uppercase;
  padding: .2rem .5rem;
  border-radius: 4px;
  white-space: nowrap;
  flex-shrink: 0;
}
.tr-card-badge.live      { background: rgba(63,185,80,.15);  color: #3fb950; border: 1px solid rgba(63,185,80,.35); }
.tr-card-badge.analysis  { background: rgba(88,166,255,.15); color: #58a6ff; border: 1px solid rgba(88,166,255,.35); }
.tr-card-badge.reference { background: rgba(188,140,255,.15);color: #bc8cff; border: 1px solid rgba(188,140,255,.35); }
.tr-card-title {
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: .35rem;
}
.tr-card-desc {
  font-size: .875rem;
  color: var(--text-muted);
  line-height: 1.6;
  flex: 1;
  margin-bottom: 1rem;
}
.tr-card-stats {
  display: flex;
  flex-wrap: wrap;
  gap: .4rem;
  margin-bottom: .9rem;
}
.tr-stat-chip {
  font-size: .72rem;
  font-weight: 600;
  color: var(--text-muted);
  background: var(--bg-sidebar, rgba(255,255,255,.04));
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: .2rem .5rem;
}
.tr-stat-chip strong { color: var(--text); }
.tr-card-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-top: 1px solid var(--border);
  padding-top: .75rem;
  margin-top: auto;
  font-size: .75rem;
  color: var(--text-muted);
}
.tr-card-cta {
  display: flex;
  align-items: center;
  gap: .25rem;
  color: var(--accent);
  font-weight: 600;
  font-size: .8rem;
}

/* ── Stub cards ─────────────────────────────────────────────────────────── */
.tr-card.stub {
  opacity: .55;
  cursor: default;
  pointer-events: none;
}
.tr-card.stub:hover {
  transform: none;
  box-shadow: none;
  border-color: var(--border);
}
.tr-card-badge.soon { background: rgba(240,136,62,.12); color: #f0883e; border: 1px solid rgba(240,136,62,.3); }
</style>

<section class="tr-hero">
  <div class="tr-hero-inner">
    <h1>Trends</h1>
    <p>Chokepoints stay stable; the techniques around them shift. Track what's actually prevalent - payloads, evasion, infrastructure.</p>
  </div>
</section>

<div style="max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem 4rem;">

  <!-- What lives here -->
  <div class="tr-pillars">
    <div class="tr-pillar">
      <div class="tr-pillar-icon" aria-hidden="true" title="Telemetry">
        <img class="tr-pillar-pixel" src="{{ '/assets/img/pixel/tr-prevalence.png' | relative_url }}" alt="" width="24" height="24" />
      </div>
      <div class="tr-pillar-title">Payload Prevalence</div>
      <div class="tr-pillar-desc">Which command lines, scripts, and file types are most common vs. rare across real-world campaigns</div>
    </div>
    <div class="tr-pillar">
      <div class="tr-pillar-icon" aria-hidden="true" title="Technique pivot">
        <img class="tr-pillar-pixel" src="{{ '/assets/img/pixel/tr-shifts.png' | relative_url }}" alt="" width="24" height="24" />
      </div>
      <div class="tr-pillar-title">Technique Shifts</div>
      <div class="tr-pillar-desc">When adversaries pivot. New evasion methods emerging, old ones dying as defenders catch up.</div>
    </div>
    <div class="tr-pillar">
      <div class="tr-pillar-icon" aria-hidden="true" title="Adversary infrastructure">
        <img class="tr-pillar-pixel" src="{{ '/assets/img/pixel/tr-infra.png' | relative_url }}" alt="" width="24" height="24" />
      </div>
      <div class="tr-pillar-title">Malicious Infrastructure</div>
      <div class="tr-pillar-desc">Staging domains, CDN abuse, C2 hosting patterns, and reused infrastructure clusters</div>
    </div>
    <div class="tr-pillar">
      <div class="tr-pillar-icon" aria-hidden="true" title="Time-series trend">
        <img class="tr-pillar-pixel" src="{{ '/assets/img/pixel/tr-timeseries.png' | relative_url }}" alt="" width="24" height="24" />
      </div>
      <div class="tr-pillar-title">Time-Series Intel</div>
      <div class="tr-pillar-desc">Monthly aggregations showing acceleration, plateau, or decline, not just point-in-time snapshots</div>
    </div>
  </div>

  <!-- Live analyses -->
  <div class="tr-section-header">
    <h2>Analyses</h2>
    <div class="tr-section-header-line"></div>
  </div>

  <div class="tr-grid">

    <a class="tr-card" href="{{ '/trends/clickgrab/' | relative_url }}">
      <div class="tr-card-header">
        <div class="tr-card-title">ClickFix Delivery Chain</div>
        <span class="tr-card-badge live">Live Data</span>
      </div>
      <p class="tr-card-desc">
        10 months of MHaggis ClickGrab crawl data mapped through the Detection Chokepoint Framework.
        Tracks cradle family evolution (IWR→Curl pivot), evasion technique acceleration (Base64 18×),
        self-delete emergence, and CDN staging infrastructure across 20K+ malicious sites.
      </p>
      <div class="tr-card-stats">
        <span class="tr-stat-chip"><strong>{{ site.data.clickgrab_trends.meta.total_sites_crawled | number_with_delimiter }}</strong> sites crawled</span>
        <span class="tr-stat-chip"><strong>{{ site.data.clickgrab_trends.meta.total_malicious | number_with_delimiter }}</strong> malicious</span>
        <span class="tr-stat-chip"><strong>{{ site.data.clickgrab_trends.meta.total_reports }}</strong> daily reports</span>
        <span class="tr-stat-chip"><strong>{{ site.data.clickgrab_trends.meta.date_range }}</strong></span>
      </div>
      <div class="tr-card-footer">
        <span>Updated {{ site.data.clickgrab_trends.meta.generated }}</span>
        <span class="tr-card-cta">
          View analysis
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

    <a class="tr-card" href="{{ '/trends/edge-exploits/' | relative_url }}">
      <div class="tr-card-header">
        <div class="tr-card-title">Edge Device Exploit Trends</div>
        <span class="tr-card-badge live">Live Data</span>
      </div>
      <p class="tr-card-desc">
        Defused Cyber honeypot telemetry across 25 edge device decoy types mapped through the Detection Chokepoint Framework. Tracks CitrixBleed 2 toolkit proliferation (54% of traffic), the CVE-2022-22536 SAP burst, CVE-2026-20127 (Cisco SD-WAN) full kill chain, and self-replicating worm campaigns.
      </p>
      <div class="tr-card-stats">
        <span class="tr-stat-chip"><strong>15,001</strong> exploit attempts</span>
        <span class="tr-stat-chip"><strong>25</strong> decoy types</span>
        <span class="tr-stat-chip"><strong>40+</strong> CVEs</span>
        <span class="tr-stat-chip"><strong>Mar 14 – Apr 13, 2026</strong></span>
      </div>
      <div class="tr-card-footer">
        <span>Updated 2026-04-13</span>
        <span class="tr-card-cta">
          View analysis
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

    <a class="tr-card" href="{{ '/trends/masq-infra/' | relative_url }}">
      <div class="tr-card-header">
        <div class="tr-card-title">Software Impersonation Infrastructure</div>
        <span class="tr-card-badge live">Live Data</span>
      </div>
      <p class="tr-card-desc">
        Validated de-intel-pipeline hunts plus aggregate IOC pipeline data. Tracks favicon-pivot discovery,
        JS-gated EXE delivery (MROScanner OU cert), ClickFix install modals targeting AI developer tools,
        and post-launch domain squatting against Codex CLI and LM Studio.
      </p>
      <div class="tr-card-stats">
        {% if site.data.masq_infra_hunts %}
        <span class="tr-stat-chip"><strong>{{ site.data.masq_infra_hunts.meta.hunt_count }}</strong> validated hunts</span>
        <span class="tr-stat-chip"><strong>{{ site.data.masq_infra_hunts.meta.brands_targeted | size }}</strong> brands</span>
        <span class="tr-stat-chip"><strong>{{ site.data.masq_infra_hunts.meta.confirmed_delivery_count }}</strong> confirmed delivery</span>
        {% endif %}
        {% if site.data.masq_infra.meta.record_count %}
        <span class="tr-stat-chip"><strong>{{ site.data.masq_infra.meta.record_count }}</strong> pipeline records</span>
        {% endif %}
        {% if site.data.masq_infra_hunts.meta.date_range %}
        <span class="tr-stat-chip"><strong>{{ site.data.masq_infra_hunts.meta.date_range }}</strong></span>
        {% endif %}
      </div>
      <div class="tr-card-footer">
        <span>Updated {% if site.data.masq_infra_hunts %}{{ site.data.masq_infra_hunts.meta.generated }}{% else %}{{ site.data.masq_infra.meta.last_updated | default: "-" }}{% endif %}</span>
        <span class="tr-card-cta">
          View analysis
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

  </div>


  <div class="mt-4 p-5 rounded-lg" style="background:var(--bg-card);border:1px solid var(--border);">
    <p style="font-size:.875rem;color:var(--text-muted);margin:0;">
      <strong style="color:var(--text);">Have data worth analyzing?</strong>
      Trends analyses are sourced from crawled infrastructure, public incident reports, and open datasets.
      If you have a dataset that maps well to detection chokepoints, see
      <a href="https://github.com/{{ site.github_username }}/{{ site.github_repo }}/blob/main/CONTRIBUTING.md">CONTRIBUTING.md</a>
      or open an issue to discuss.
    </p>
  </div>

</div>

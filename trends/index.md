---
layout: default
title: Trends
description: "Data-driven trend analysis for detection engineers — tracking payload prevalence, command-line patterns, evasion technique shifts, and malicious infrastructure over time."
permalink: /trends/
---

<style>
/* ── Page layout ────────────────────────────────────────────────────────── */
.tr-hero {
  padding: 3rem 0 2rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 2.5rem;
}
.tr-hero h1 {
  font-size: 2.25rem;
  font-weight: 800;
  color: var(--color-fg-default, #c9d1d9);
  margin-bottom: .6rem;
}
.tr-hero p { font-size: 1rem; color: var(--text-muted); max-width: 640px; line-height: 1.7; }

/* ── What lives here ────────────────────────────────────────────────────── */
.tr-pillars {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: .75rem;
  margin: 2rem 0 3rem;
}
.tr-pillar {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.1rem;
}
.tr-pillar-icon {
  font-size: 1.25rem;
  margin-bottom: .4rem;
}
.tr-pillar-title {
  font-size: .8rem;
  font-weight: 700;
  color: var(--text);
  text-transform: uppercase;
  letter-spacing: .05em;
  margin-bottom: .3rem;
}
.tr-pillar-desc { font-size: .8rem; color: var(--text-muted); line-height: 1.55; }

/* ── Section header ─────────────────────────────────────────────────────── */
.tr-section-header {
  display: flex;
  align-items: baseline;
  gap: .75rem;
  margin-bottom: 1.25rem;
}
.tr-section-header h2 {
  font-size: 1rem;
  font-weight: 700;
  color: var(--text);
  text-transform: uppercase;
  letter-spacing: .08em;
  margin: 0;
}
.tr-section-header-line {
  flex: 1;
  height: 1px;
  background: var(--border);
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
  transition: border-color .15s, box-shadow .15s, transform .15s;
}
.tr-card:hover {
  border-color: var(--accent);
  box-shadow: 0 0 0 1px var(--accent), 0 8px 24px rgba(0,0,0,.15);
  transform: translateY(-1px);
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

<div class="max-w-[1280px] mx-auto px-6 py-10">

  <div class="tr-hero">
    <h1>Trends</h1>
    <p>
      Chokepoints stay stable — but the techniques layered around them shift constantly.
      These analyses track what adversaries are actually doing: which payloads and cradle families dominate,
      which evasion techniques are rising or dying, and what infrastructure they keep coming back to.
      Data-driven signal for prioritizing detection work.
    </p>
  </div>

  <!-- What lives here -->
  <div class="tr-pillars">
    <div class="tr-pillar">
      <div class="tr-pillar-icon">📊</div>
      <div class="tr-pillar-title">Payload Prevalence</div>
      <div class="tr-pillar-desc">Which command lines, scripts, and file types are most common vs. rare across real-world campaigns</div>
    </div>
    <div class="tr-pillar">
      <div class="tr-pillar-icon">🔀</div>
      <div class="tr-pillar-title">Technique Shifts</div>
      <div class="tr-pillar-desc">When adversaries pivot — new evasion methods emerging, old ones dying as defenders catch up</div>
    </div>
    <div class="tr-pillar">
      <div class="tr-pillar-icon">🏗️</div>
      <div class="tr-pillar-title">Malicious Infrastructure</div>
      <div class="tr-pillar-desc">Staging domains, CDN abuse, C2 hosting patterns, and reused infrastructure clusters</div>
    </div>
    <div class="tr-pillar">
      <div class="tr-pillar-icon">📅</div>
      <div class="tr-pillar-title">Time-Series Intel</div>
      <div class="tr-pillar-desc">Monthly aggregations showing acceleration, plateau, or decline — not just point-in-time snapshots</div>
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

    <a class="tr-card" href="{{ '/trends/chokepoint-shifts/' | relative_url }}">
      <div class="tr-card-header">
        <div class="tr-card-title">Chokepoint Shifts</div>
        <span class="tr-card-badge analysis">Analysis</span>
      </div>
      <p class="tr-card-desc">
        When defensive improvements force adversaries to abandon one chokepoint for another — covering
        macro deprecation, LSASS protection responses, RDP brute-force decline, and predicted shifts
        through 2026. Distinguishes true chokepoint shifts from simple tool rotation.
      </p>
      <div class="tr-card-stats">
        <span class="tr-stat-chip"><strong>3</strong> active shifts</span>
        <span class="tr-stat-chip"><strong>3</strong> historical shifts</span>
        <span class="tr-stat-chip"><strong>2</strong> predicted shifts</span>
      </div>
      <div class="tr-card-footer">
        <span>Updated 2025-01-15</span>
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

    <a class="tr-card" href="{{ '/trends/2025-q1/' | relative_url }}">
      <div class="tr-card-header">
        <div class="tr-card-title">2025 Threat Trends — Q1</div>
        <span class="tr-card-badge reference">Reference</span>
      </div>
      <p class="tr-card-desc">
        Q1 2025 snapshot covering hot chokepoints (renamed RMM tools, ClickFix variants, infostealer
        credential harvesting), declining techniques, and predictions through Q4 2025.
        Sourced from Mandiant M-Trends, HudsonRock, RedCanary, and Cyberint.
      </p>
      <div class="tr-card-stats">
        <span class="tr-stat-chip"><strong>4</strong> hot chokepoints</span>
        <span class="tr-stat-chip"><strong>2</strong> declining</span>
        <span class="tr-stat-chip"><strong>Jan–Mar 2025</strong></span>
      </div>
      <div class="tr-card-footer">
        <span>Updated 2025-01-15</span>
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

  <!-- Coming soon stubs -->
  <div class="tr-section-header">
    <h2>In Development</h2>
    <div class="tr-section-header-line"></div>
  </div>

  <div class="tr-grid">

    <div class="tr-card stub">
      <div class="tr-card-header">
        <div class="tr-card-title">Infostealer Payload Prevalence</div>
        <span class="tr-card-badge soon">Coming Soon</span>
      </div>
      <p class="tr-card-desc">
        Command-line argument frequency, string patterns, and target file paths across RedLine, LummaC2,
        Vidar, and StealC — ranked by prevalence to prioritize detection coverage.
      </p>
      <div class="tr-card-footer">
        <span>In development</span>
      </div>
    </div>

    <div class="tr-card stub">
      <div class="tr-card-header">
        <div class="tr-card-title">RMM Tool Infrastructure Tracking</div>
        <span class="tr-card-badge soon">Coming Soon</span>
      </div>
      <p class="tr-card-desc">
        ASN distribution, certificate reuse, and domain registration patterns across
        AnyDesk, ScreenConnect, RustDesk, and MeshCentral deployments observed in
        incident response data.
      </p>
      <div class="tr-card-footer">
        <span>In development</span>
      </div>
    </div>

    <div class="tr-card stub">
      <div class="tr-card-header">
        <div class="tr-card-title">LOLBin Usage Frequency</div>
        <span class="tr-card-badge soon">Coming Soon</span>
      </div>
      <p class="tr-card-desc">
        Which living-off-the-land binaries appear most in real campaigns vs. red team exercises —
        certutil, mshta, regsvr32, wscript, cscript, rundll32 tracked across public incident data.
      </p>
      <div class="tr-card-footer">
        <span>In development</span>
      </div>
    </div>

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

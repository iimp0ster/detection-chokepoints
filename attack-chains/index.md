---
layout: default
title: Attack Chains
description: "Mapped attack chains for ransomware and infostealer operators — showing how every actor converges on the same prerequisite chokepoints regardless of tooling."
permalink: /attack-chains/
---

<div class="max-w-[1280px] mx-auto px-6 py-10">

  <div class="ac-index-hero">
    <h1>Attack Chains</h1>
    <p>
      Threat actors change their tools constantly — loaders, C2 frameworks, ransomware brands, stealer families.
      But the <strong>prerequisite conditions</strong> they must satisfy at each stage never change.
      These mapped attack chains show how every actor, regardless of affiliation or toolset,
      converges on the same chokepoints. Detect the chokepoint; catch any actor.
    </p>
  </div>

  <div class="ac-index-grid">

    <a class="ac-index-card" href="{{ '/attack-chains/ransomware/' | relative_url }}">
      <span class="ac-card-badge ransomware">Ransomware</span>
      <div class="ac-card-title">Ransomware Attack Chain</div>
      <p class="ac-card-desc">
        Initial Access → Credential Access → Lateral Movement → Defense Evasion → Impact.
        Covers BlackBasta, LockBit 3.0, Akira, Alphv/BlackCat, and Play with a convergence
        matrix showing how each group hits the same five chokepoints.
      </p>
      <div class="ac-card-meta">
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          5 actors tracked
        </span>
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          5 chokepoints
        </span>
        <span class="ac-card-meta-item">Avg TTR &lt;24 hrs</span>
        <span class="ac-card-cta">
          View chain
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

    <a class="ac-index-card" href="{{ '/attack-chains/infostealers/' | relative_url }}">
      <span class="ac-card-badge infostealer">Infostealer</span>
      <div class="ac-card-title">Infostealer Attack Chain</div>
      <p class="ac-card-desc">
        Distribution → Execution → Collection → Exfiltration → Monetization.
        Covers RedLine, LummaC2, Vidar, StealC, and Raccoon — including how
        infostealer-harvested credentials fuel the RaaS ecosystem downstream.
      </p>
      <div class="ac-card-meta">
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          5 families tracked
        </span>
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          5 chokepoints
        </span>
        <span class="ac-card-meta-item">15M+ infections/yr</span>
        <span class="ac-card-cta">
          View chain
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

  </div>

  <div class="mt-12 p-5 rounded-lg" style="background:var(--bg-card);border:1px solid var(--border);">
    <p style="font-size:.875rem;color:var(--text-muted);margin:0;">
      <strong style="color:var(--text);">More attack chains coming soon.</strong>
      BEC / business email compromise, initial access broker (IAB) operations, and supply chain compromise
      chains are in development. See <a href="https://github.com/{{ site.github_username }}/{{ site.github_repo }}/blob/main/CONTRIBUTING.md">CONTRIBUTING.md</a> to propose or draft a new chain.
    </p>
  </div>

</div>

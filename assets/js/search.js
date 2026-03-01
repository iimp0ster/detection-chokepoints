/* Detection Chokepoints — client-side search & filter
 * Depends on: fuse.min.js loaded before this script
 * Data: window.CHOKEPOINTS_DATA (injected by Jekyll from site.data.chokepoints)
 */

(function () {
  'use strict';

  // ── DOM refs ──────────────────────────────────────────────────────────────
  const searchInput  = document.getElementById('search-input');
  const grid         = document.getElementById('chokepoints-grid');
  const noResults    = document.getElementById('no-results');
  const clearBtn     = document.getElementById('clear-search');
  const resultCount  = document.getElementById('results-count');
  const tacticChips  = document.querySelectorAll('[data-filter="tactic"]');
  const priorityChips= document.querySelectorAll('[data-filter="priority"]');
  const cards        = Array.from(grid ? grid.querySelectorAll('.chokepoint-card') : []);

  if (!grid) return; // not on index page

  // ── State ─────────────────────────────────────────────────────────────────
  let activeTactic   = 'all';
  let activePriority = 'all';
  let fuseResults    = null; // null = no text query active

  // ── Fuse.js setup ─────────────────────────────────────────────────────────
  const data = window.CHOKEPOINTS_DATA || [];
  const fuse = new Fuse(data, {
    threshold: 0.35,
    distance:  200,
    minMatchCharLength: 2,
    keys: [
      { name: 'Name',         weight: 3 },
      { name: 'MitreIds',     weight: 2.5 },
      { name: 'Description',  weight: 2 },
      { name: 'TheConstant',  weight: 1.5 },
      { name: 'Tactic',       weight: 1.5 },
      { name: 'Prerequisites',weight: 1 },
      { name: 'Variations.Name',       weight: 1 },
      { name: 'Variations.Description',weight: 0.8 },
    ],
  });

  // Slug → card map for fast lookups
  const slugToCard = {};
  cards.forEach(card => {
    // Cards have data-* but we need the slug; extract from the card link
    const link = card.querySelector('.card-link');
    if (!link) return;
    const href = link.getAttribute('href') || '';
    const parts = href.replace(/\/+$/, '').split('/');
    const slug = parts[parts.length - 1];
    if (slug) slugToCard[slug] = card;
  });

  // ── Helpers ───────────────────────────────────────────────────────────────
  function updateCount(visible) {
    const total = cards.length;
    if (visible === total) {
      resultCount.textContent = `${total} chokepoint${total !== 1 ? 's' : ''}`;
    } else {
      resultCount.textContent = `${visible} of ${total} chokepoint${total !== 1 ? 's' : ''}`;
    }
  }

  function normalise(str) {
    return (str || '').toLowerCase().replace(/\s+/g, '-');
  }

  function applyFilters() {
    // Build allowed slug set from fuse results (if search active)
    let allowedSlugs = null;
    if (fuseResults !== null) {
      allowedSlugs = new Set(fuseResults.map(r => r.item._slug));
    }

    let visible = 0;
    cards.forEach(card => {
      const tactic   = normalise(card.dataset.tactic || '');
      const priority = (card.dataset.priority || '').toUpperCase();

      // Get slug from card link
      const link = card.querySelector('.card-link');
      const href = link ? link.getAttribute('href') || '' : '';
      const parts = href.replace(/\/+$/, '').split('/');
      const slug = parts[parts.length - 1];

      const passesSearch   = allowedSlugs === null || allowedSlugs.has(slug);
      const passesTactic   = activeTactic   === 'all' || tactic   === activeTactic;
      const passesPriority = activePriority === 'all' || priority === activePriority;

      const show = passesSearch && passesTactic && passesPriority;
      card.classList.toggle('hidden', !show);
      if (show) visible++;
    });

    const hasResults = visible > 0;
    noResults.hidden = hasResults;
    updateCount(visible);

    // Sync URL query string
    const params = new URLSearchParams();
    if (searchInput.value)   params.set('q', searchInput.value);
    if (activeTactic   !== 'all') params.set('tactic',   activeTactic);
    if (activePriority !== 'all') params.set('priority', activePriority);
    const qs = params.toString();
    const newUrl = qs ? `${location.pathname}?${qs}` : location.pathname;
    history.replaceState(null, '', newUrl);
  }

  // ── Search ────────────────────────────────────────────────────────────────
  let debounceTimer;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const q = searchInput.value.trim();
      fuseResults = q.length >= 2 ? fuse.search(q) : null;
      applyFilters();
    }, 150);
  });

  // Keyboard shortcut: press "/" to focus search (unless already in an input)
  document.addEventListener('keydown', e => {
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
    if (e.key === 'Escape' && document.activeElement === searchInput) {
      searchInput.blur();
    }
  });

  // ── Filter chips ──────────────────────────────────────────────────────────
  function setActiveChip(chips, value) {
    chips.forEach(chip => {
      const isActive = chip.dataset.value === value;
      chip.classList.toggle('active', isActive);
      chip.setAttribute('aria-pressed', isActive ? 'true' : 'false');
    });
  }

  tacticChips.forEach(chip => {
    chip.addEventListener('click', () => {
      activeTactic = chip.dataset.value;
      setActiveChip(tacticChips, activeTactic);
      applyFilters();
    });
  });

  priorityChips.forEach(chip => {
    chip.addEventListener('click', () => {
      activePriority = chip.dataset.value;
      setActiveChip(priorityChips, activePriority);
      applyFilters();
    });
  });

  // Clear button (no-results state)
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      searchInput.value = '';
      fuseResults = null;
      activeTactic = 'all';
      activePriority = 'all';
      setActiveChip(tacticChips, 'all');
      setActiveChip(priorityChips, 'all');
      applyFilters();
    });
  }

  // ── Restore state from URL ────────────────────────────────────────────────
  (function restoreFromUrl() {
    const params = new URLSearchParams(location.search);
    const q = params.get('q') || '';
    const tactic   = params.get('tactic')   || 'all';
    const priority = params.get('priority') || 'all';

    if (q) {
      searchInput.value = q;
      fuseResults = q.length >= 2 ? fuse.search(q) : null;
    }
    activeTactic   = tactic;
    activePriority = priority;
    setActiveChip(tacticChips, tactic);
    setActiveChip(priorityChips, priority);
    applyFilters();
  })();

})();

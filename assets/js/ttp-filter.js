/**
 * ttp-filter.js
 * Interactive actor filter for the vertical TTP overlap diagram.
 * Reads window.TTP_FILTER_GROUPS (injected by _includes/ttp-vertical-diagram.html).
 */
(function () {
  'use strict';

  var selected = new Set();
  var actorColors = {};
  var actorNames = {};

  function init() {
    // Build actor → color map from injected data
    var groups = window.TTP_FILTER_GROUPS;
    if (!groups) return;
    groups.forEach(function (g) { actorColors[g.id] = g.color; actorNames[g.id] = g.name; });

    // Wire filter buttons
    document.querySelectorAll('.ttp-filter-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var actor = btn.dataset.actor;
        if (selected.has(actor)) {
          selected.delete(actor);
        } else {
          selected.add(actor);
        }
        renderFilter();
      });
    });

    // Wire clear button
    var clearBtn = document.getElementById('ttp-clear');
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        selected.clear();
        renderFilter();
      });
    }
  }

  function renderFilter() {
    var cells        = document.querySelectorAll('.ttp-cell');
    var connectors   = document.querySelectorAll('.stage-connector');
    var filterBtns   = document.querySelectorAll('.ttp-filter-btn');
    var clearBtn     = document.getElementById('ttp-clear');

    // ── Reset all states ────────────────────────────────────────────────
    cells.forEach(function (c) {
      c.classList.remove('state-dim', 'state-lit', 'state-converge', 'state-partial');
      c.style.removeProperty('--lit-color');
    });
    connectors.forEach(function (c) { c.classList.remove('connector-dim'); });
    filterBtns.forEach(function (b) {
      b.classList.remove('faded', 'active');
      b.setAttribute('aria-pressed', 'false');
    });
    document.querySelectorAll('.ttp-cell-dots .dot').forEach(function (d) {
      d.classList.remove('dot-active');
      d.style.removeProperty('--dot-ring');
    });
    document.querySelectorAll('.ac-matrix tbody tr').forEach(function (row) {
      row.classList.remove('matrix-row-lit', 'matrix-row-dim');
      row.style.removeProperty('--row-color');
    });

    // ── Show / hide clear button ────────────────────────────────────────
    if (clearBtn) {
      if (selected.size > 0) {
        clearBtn.classList.add('visible');
      } else {
        clearBtn.classList.remove('visible');
      }
    }

    // ── Neutral state — nothing selected ───────────────────────────────
    if (selected.size === 0) return;

    // ── Update legend button states ─────────────────────────────────────
    filterBtns.forEach(function (b) {
      if (selected.has(b.dataset.actor)) {
        b.classList.add('active');
        b.setAttribute('aria-pressed', 'true');
      } else {
        b.classList.add('faded');
      }
    });

    // ── Process each TTP cell ───────────────────────────────────────────
    cells.forEach(function (cell) {
      var actors  = (cell.dataset.actors || '').split(',').filter(Boolean);
      var matched = actors.filter(function (a) { return selected.has(a); });

      if (matched.length === 0) {
        cell.classList.add('state-dim');
        return;
      }

      cell.classList.add('state-lit');
      cell.style.setProperty('--lit-color', actorColors[matched[0]] || '#f0883e');

      // When 2+ actors are selected, separate convergence (used by ALL of them)
      // from partial overlap (used by some). The shared cells get the strong
      // highlight so the reader sees the convergence without inspecting dots.
      if (selected.size >= 2) {
        cell.classList.add(matched.length === selected.size ? 'state-converge' : 'state-partial');
      }

      // Ring the matching actor dots inside this cell
      cell.querySelectorAll('.ttp-cell-dots .dot[data-actor]').forEach(function (dot) {
        if (selected.has(dot.dataset.actor)) {
          dot.classList.add('dot-active');
          dot.style.setProperty('--dot-ring', actorColors[dot.dataset.actor] || '');
        }
      });
    });

    // ── Mirror the selection onto the convergence matrix below ──────────
    // Light the selected actors' rows in their own colour and dim the rest.
    // The chokepoint (tfoot) row is left untouched — the invariant holds
    // regardless of which actors you compare.
    var selectedNames = {};
    selected.forEach(function (id) {
      if (actorNames[id]) selectedNames[actorNames[id]] = actorColors[id];
    });
    document.querySelectorAll('.ac-matrix tbody tr').forEach(function (row) {
      var nameCell = row.querySelector('.ac-actor-name');
      var name = (nameCell && nameCell.childNodes[0]) ? nameCell.childNodes[0].textContent.trim() : '';
      if (selectedNames.hasOwnProperty(name)) {
        row.classList.add('matrix-row-lit');
        row.style.setProperty('--row-color', selectedNames[name]);
      } else {
        row.classList.add('matrix-row-dim');
      }
    });

    // ── Dim connectors between stages where neither side has lit cells ──
    var stageRows = document.querySelectorAll('.ttp-stage-row');
    connectors.forEach(function (connector, i) {
      var prevRow = stageRows[i];
      var nextRow = stageRows[i + 1];
      if (!prevRow || !nextRow) return;
      var prevLit = prevRow.querySelectorAll('.ttp-cell.state-lit').length;
      var nextLit = nextRow.querySelectorAll('.ttp-cell.state-lit').length;
      if (prevLit === 0 && nextLit === 0) {
        connector.classList.add('connector-dim');
      }
    });
  }

  // ── Boot ────────────────────────────────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();

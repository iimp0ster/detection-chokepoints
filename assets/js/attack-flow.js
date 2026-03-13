/**
 * attack-flow.js
 * Tooltip and keyboard interaction for the SVG swimlane attack-flow diagram.
 * Vanilla JS, no dependencies, ~1.5 KB.
 */
(function () {
  'use strict';

  var tip = document.getElementById('af-tooltip');
  if (!tip) return;

  var stages = document.querySelectorAll('.af-stage');
  if (!stages.length) return;

  /* ── Helpers ──────────────────────────────────────────────────────── */

  function escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function buildTipHtml(g) {
    var label      = g.dataset.label      || '';
    var tactic     = g.dataset.tactic     || '';
    var techsRaw   = g.dataset.techniques || '';
    var status     = g.dataset.status     || 'unknown';
    var statusLbl  = g.dataset.statusLabel || 'Unknown';
    var sigsRaw    = g.dataset.signals    || '';

    var techs = techsRaw ? techsRaw.split('||') : [];
    var sigs  = sigsRaw  ? sigsRaw.split('||')  : [];

    var statusClass = 'af-tip-status--' + status;

    var html = '<strong class="af-tip-title">' + escHtml(label) + '</strong>';

    if (tactic) {
      html += '<div class="af-tip-tactic">' + escHtml(tactic) + '</div>';
    }

    if (techs.length) {
      html += '<ul class="af-tip-techs">';
      techs.forEach(function (t) {
        html += '<li>' + escHtml(t.trim()) + '</li>';
      });
      html += '</ul>';
    }

    html += '<div class="af-tip-status ' + statusClass + '">' + escHtml(statusLbl) + '</div>';

    if (sigs.length) {
      html += '<div class="af-tip-sigs-label">Detection signals</div>';
      html += '<ul class="af-tip-sigs">';
      sigs.forEach(function (s) {
        html += '<li>' + escHtml(s.trim()) + '</li>';
      });
      html += '</ul>';
    }

    return html;
  }

  /* ── Positioning ──────────────────────────────────────────────────── */

  function positionTip(clientX, clientY) {
    var maxX = window.innerWidth  - 250;
    var maxY = window.innerHeight - 220;
    tip.style.left = Math.min(clientX + 12, maxX) + 'px';
    tip.style.top  = Math.min(clientY + 12, maxY) + 'px';
  }

  /* ── Show / hide ──────────────────────────────────────────────────── */

  function showTip(g, clientX, clientY) {
    tip.innerHTML = buildTipHtml(g);
    tip.setAttribute('aria-hidden', 'false');
    positionTip(clientX, clientY);
  }

  function hideTip() {
    tip.setAttribute('aria-hidden', 'true');
    tip.innerHTML = '';
  }

  /* ── Event wiring ─────────────────────────────────────────────────── */

  stages.forEach(function (g) {

    /* Mouse hover */
    g.addEventListener('mouseenter', function (e) {
      showTip(g, e.clientX, e.clientY);
    });
    g.addEventListener('mousemove', function (e) {
      positionTip(e.clientX, e.clientY);
    });
    g.addEventListener('mouseleave', hideTip);

    /* Keyboard / focus */
    g.addEventListener('focusin', function () {
      var r = g.getBoundingClientRect();
      showTip(g, r.left + r.width / 2, r.bottom);
    });
    g.addEventListener('focusout', hideTip);
    g.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { hideTip(); g.blur(); }
    });

    /* Touch (tap to toggle) */
    g.addEventListener('touchstart', function (e) {
      if (tip.getAttribute('aria-hidden') === 'false' &&
          tip.dataset.activeStage === g.dataset.label) {
        hideTip();
      } else {
        var touch = e.touches[0];
        showTip(g, touch.clientX, touch.clientY);
        tip.dataset.activeStage = g.dataset.label;
      }
      e.preventDefault();
    }, { passive: false });
  });

  /* Close tooltip when clicking outside */
  document.addEventListener('click', function (e) {
    if (!e.target.closest('.af-stage') && !e.target.closest('#af-tooltip')) {
      hideTip();
    }
  });

  /* Reposition on scroll (fixed positioning tracks viewport) */
  window.addEventListener('scroll', hideTip, { passive: true });

}());

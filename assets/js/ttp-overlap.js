/**
 * ttp-overlap.js
 * Renders the Kaspersky-style TTP overlap flow diagram into #ttp-overlap-svg.
 * Reads window.TTP_OVERLAP_DATA injected by _includes/ttp-overlap-diagram.html.
 */
(function () {
  'use strict';

  // ── Helpers ──────────────────────────────────────────────────────────

  var NS = 'http://www.w3.org/2000/svg';

  function svgEl(tag, attrs) {
    var e = document.createElementNS(NS, tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    }
    return e;
  }

  function svgText(content, attrs) {
    var e = svgEl('text', attrs);
    e.textContent = content;
    return e;
  }

  /**
   * Wrap text into at most 2 lines of maxChars each.
   */
  function wrapText(text, maxChars) {
    if (text.length <= maxChars) return [text];
    var words = text.split(' ');
    var lines = [];
    var current = '';
    for (var i = 0; i < words.length; i++) {
      var w = words[i];
      var candidate = current ? current + ' ' + w : w;
      if (candidate.length <= maxChars) {
        current = candidate;
      } else {
        if (current) lines.push(current);
        current = w;
      }
    }
    if (current) lines.push(current);
    return lines.slice(0, 2);
  }

  // ── Main render ───────────────────────────────────────────────────────

  function render() {
    var data = window.TTP_OVERLAP_DATA;
    if (!data || !data.groups || !data.phases) return;

    var svg = document.getElementById('ttp-overlap-svg');
    if (!svg) return;

    var tooltip = document.getElementById('ttp-overlap-tooltip');

    // ── Layout constants ──────────────────────────────────────────────
    var NW      = 170;  // node width
    var NH      = 74;   // node height
    var HG      = 16;   // horizontal gap between nodes in the same row
    var PLH     = 26;   // phase label height (space above nodes in each row)
    var PG      = 70;   // total gap between consecutive phase rows (arrow + label)
    var PAD_X   = 28;   // left/right padding
    var PAD_TOP = 20;   // top padding

    // ── Group lookup ──────────────────────────────────────────────────
    var groupById = {};
    data.groups.forEach(function (g) { groupById[g.id] = g; });

    // ── Compute canvas size ───────────────────────────────────────────
    var maxN = 0;
    data.phases.forEach(function (p) {
      if (p.techniques.length > maxN) maxN = p.techniques.length;
    });

    var maxRowW  = maxN * NW + (maxN - 1) * HG;
    var totalW   = maxRowW + PAD_X * 2;
    var nPhases  = data.phases.length;
    // Each phase occupies PLH + NH; between phases there is PG of space.
    var totalH   = PAD_TOP + nPhases * (PLH + NH) + (nPhases - 1) * PG + PAD_TOP;

    svg.setAttribute('viewBox', '0 0 ' + totalW + ' ' + totalH);
    svg.setAttribute('width',   totalW);
    svg.setAttribute('height',  totalH);

    // ── Defs: arrowhead marker ────────────────────────────────────────
    var defs   = svgEl('defs', {});
    var marker = svgEl('marker', {
      id: 'ttp-arr',
      markerWidth: 8, markerHeight: 6,
      refX: 8, refY: 3,
      orient: 'auto',
      markerUnits: 'userSpaceOnUse'
    });
    marker.appendChild(svgEl('polygon', { points: '0 0,8 3,0 6', fill: '#444d56' }));
    defs.appendChild(marker);
    svg.appendChild(defs);

    // ── Draw phases ───────────────────────────────────────────────────
    var curY = PAD_TOP;

    data.phases.forEach(function (phase, pi) {
      var n      = phase.techniques.length;
      var rowW   = n * NW + (n - 1) * HG;
      var rowX   = (totalW - rowW) / 2;
      var nodesY = curY + PLH;

      // Phase label
      svg.appendChild(svgText(phase.label, {
        x: totalW / 2,
        y: curY + 18,
        'text-anchor': 'middle',
        class: 'ttp-phase-label'
      }));

      // ── Technique nodes ───────────────────────────────────────────
      phase.techniques.forEach(function (tech, ti) {
        var nx      = rowX + ti * (NW + HG);
        var ny      = nodesY;
        var cx      = nx + NW / 2;

        var usedIds = tech.groups || [];
        var coverage = usedIds.length / data.groups.length;

        // Border highlight based on convergence
        var strokeColor = coverage >= 1.0
          ? '#f0883e'
          : coverage >= 0.6
            ? 'rgba(240,136,62,0.5)'
            : '#30363d';
        var strokeW = coverage >= 1.0 ? 2 : 1;

        var g = svgEl('g', {
          class: 'ttp-node',
          tabindex: 0,
          role: 'button',
          'aria-label': tech.name + ' (' + tech.id + ')'
        });

        // Node background rect
        g.appendChild(svgEl('rect', {
          x: nx, y: ny,
          width: NW, height: NH,
          rx: 6,
          fill: '#161b22',
          stroke: strokeColor,
          'stroke-width': strokeW
        }));

        // ── Group dots ────────────────────────────────────────────
        var nG          = data.groups.length;
        var dotR        = 4.5;
        var dotSpacing  = 11;            // center-to-center
        var totalDotW   = (nG - 1) * dotSpacing;
        var dotStartX   = cx - totalDotW / 2;
        var dotY        = ny + 15;

        data.groups.forEach(function (group, gi) {
          var dx   = dotStartX + gi * dotSpacing;
          var used = usedIds.indexOf(group.id) !== -1;
          g.appendChild(svgEl('circle', {
            cx: dx, cy: dotY, r: dotR,
            fill:           used ? group.color : 'none',
            stroke:         used ? group.color : '#444d56',
            'stroke-width': 1.5,
            opacity:        used ? 1 : 0.35
          }));
        });

        // ── Technique name (wrapped to 2 lines) ───────────────────
        var lines = wrapText(tech.name, 22);
        if (lines.length === 1) {
          g.appendChild(svgText(lines[0], {
            x: cx, y: ny + 38,
            'text-anchor': 'middle',
            class: 'ttp-node-name'
          }));
          g.appendChild(svgText(tech.id, {
            x: cx, y: ny + 55,
            'text-anchor': 'middle',
            class: 'ttp-node-id'
          }));
        } else {
          g.appendChild(svgText(lines[0], {
            x: cx, y: ny + 34,
            'text-anchor': 'middle',
            class: 'ttp-node-name'
          }));
          g.appendChild(svgText(lines[1] || '', {
            x: cx, y: ny + 47,
            'text-anchor': 'middle',
            class: 'ttp-node-name'
          }));
          g.appendChild(svgText(tech.id, {
            x: cx, y: ny + 62,
            'text-anchor': 'middle',
            class: 'ttp-node-id'
          }));
        }

        // ── Hover / focus tooltip ─────────────────────────────────
        g.addEventListener('mouseenter', makeShowHandler(tech, usedIds));
        g.addEventListener('mouseleave', hideTooltip);
        g.addEventListener('focus',      makeShowHandler(tech, usedIds));
        g.addEventListener('blur',       hideTooltip);

        svg.appendChild(g);
      });

      // ── Arrow to next phase ───────────────────────────────────────
      if (pi < nPhases - 1) {
        var ax  = totalW / 2;
        var ay1 = nodesY + NH + 5;
        var ay2 = nodesY + NH + PG - PLH - 6;
        svg.appendChild(svgEl('line', {
          x1: ax, y1: ay1,
          x2: ax, y2: ay2,
          stroke: '#444d56',
          'stroke-width': 1.5,
          'marker-end': 'url(#ttp-arr)'
        }));
      }

      curY += PLH + NH + PG;
    });

    // ── Tooltip repositioning on mouse move ───────────────────────────
    if (tooltip) {
      svg.parentElement.addEventListener('mousemove', function (e) {
        if (tooltip.classList.contains('ttp-tooltip--visible')) {
          positionTooltip(e.clientX, e.clientY);
        }
      });
    }

    // ── Tooltip helpers ───────────────────────────────────────────────

    function makeShowHandler(tech, usedIds) {
      return function (e) {
        if (!tooltip) return;
        var names = usedIds.map(function (id) {
          return groupById[id] ? groupById[id].name : id;
        });
        tooltip.innerHTML =
          '<strong>' + escHtml(tech.name) + '</strong><br>' +
          '<span class="ttp-tt-id">' + escHtml(tech.id) + '</span><br>' +
          '<span class="ttp-tt-groups">Used by: ' + names.map(escHtml).join(', ') + '</span>';
        tooltip.setAttribute('aria-hidden', 'false');
        tooltip.classList.add('ttp-tooltip--visible');
        var cx = e.type === 'focus' ? e.target.getBoundingClientRect().left : e.clientX;
        var cy = e.type === 'focus' ? e.target.getBoundingClientRect().top  : e.clientY;
        positionTooltip(cx, cy);
      };
    }

    function hideTooltip() {
      if (!tooltip) return;
      tooltip.classList.remove('ttp-tooltip--visible');
      tooltip.setAttribute('aria-hidden', 'true');
    }

    function positionTooltip(cx, cy) {
      if (!tooltip) return;
      var tw   = tooltip.offsetWidth  || 240;
      var th   = tooltip.offsetHeight || 80;
      var x    = cx + 14;
      var y    = cy - 10;
      if (x + tw > window.innerWidth  - 8) x = cx - tw - 14;
      if (y + th > window.innerHeight - 8) y = cy - th - 10;
      tooltip.style.left = x + 'px';
      tooltip.style.top  = y + 'px';
    }

    function escHtml(str) {
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }
  }

  // ── Boot ──────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', render);
  } else {
    render();
  }

})();

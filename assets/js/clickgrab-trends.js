/**
 * clickgrab-trends.js
 * Renders three SVG charts for the ClickFix delivery-chain trend analysis page.
 * Reads from window.CLICKGRAB_TRENDS (injected by the Jekyll page via | jsonify).
 * Vanilla JS + SVG, no external dependencies.
 */
(function () {
  'use strict';

  var DATA = window.CLICKGRAB_TRENDS;
  if (!DATA) return;

  var monthly = DATA.monthly || [];
  if (!monthly.length) return;

  /* ── Palette (matches project CSS vars) ─────────────────────────────── */
  var C = {
    bg:       'transparent',
    grid:     'rgba(255,255,255,0.08)',
    text:     '#8b949e',
    label:    '#c9d1d9',
    blue:     '#388bfd',
    red:      '#da3633',
    yellow:   '#e3b341',
    orange:   '#f0883e',
    green:    '#3fb950',
    purple:   '#bc8cff',
    cyan:     '#39c5cf',
    pink:     '#f778ba',
  };

  /* ── SVG helpers ─────────────────────────────────────────────────────── */

  function svgEl(tag, attrs) {
    var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (var k in attrs) el.setAttribute(k, attrs[k]);
    return el;
  }

  function makeSvg(w, h) {
    return svgEl('svg', {
      viewBox: '0 0 ' + w + ' ' + h,
      width: '100%',
      role: 'img',
      'aria-label': 'Chart',
    });
  }

  function text(x, y, str, opts) {
    var el = svgEl('text', Object.assign({
      x: x, y: y,
      fill: C.text,
      'font-size': '11',
      'font-family': 'ui-monospace, SFMono-Regular, monospace',
      'text-anchor': 'middle',
    }, opts || {}));
    el.textContent = str;
    return el;
  }

  /* ── Shared axes ─────────────────────────────────────────────────────── */

  function drawAxes(svg, pad, W, H, yMax, labels, ySteps) {
    // Grid lines + Y labels
    for (var i = 0; i <= ySteps; i++) {
      var val = Math.round((yMax / ySteps) * i);
      var yy  = pad.top + (H - pad.top - pad.bottom) * (1 - i / ySteps);
      svg.appendChild(svgEl('line', {
        x1: pad.left, y1: yy, x2: W - pad.right, y2: yy,
        stroke: C.grid, 'stroke-width': '1',
      }));
      svg.appendChild(text(pad.left - 6, yy + 4, val, { 'text-anchor': 'end', fill: C.text }));
    }
    // X labels
    var chartW = W - pad.left - pad.right;
    labels.forEach(function (lbl, i) {
      var x = pad.left + (i / (labels.length - 1)) * chartW;
      svg.appendChild(text(x, H - pad.bottom + 16, lbl, { 'font-size': '10' }));
    });
    // Axes borders
    svg.appendChild(svgEl('line', {
      x1: pad.left, y1: pad.top, x2: pad.left, y2: H - pad.bottom,
      stroke: C.grid, 'stroke-width': '1',
    }));
  }

  /* ── Tooltip ─────────────────────────────────────────────────────────── */

  var tip = (function () {
    var el = document.createElement('div');
    el.id = 'cg-tooltip';
    el.setAttribute('aria-hidden', 'true');
    el.style.cssText = [
      'position:fixed;pointer-events:none;z-index:1000;',
      'background:#161b22;border:1px solid #30363d;border-radius:6px;',
      'padding:8px 10px;font-size:12px;font-family:ui-monospace,monospace;',
      'color:#c9d1d9;max-width:240px;line-height:1.5;',
      'opacity:0;transition:opacity .15s;',
    ].join('');
    document.body.appendChild(el);

    function show(html, cx, cy) {
      el.innerHTML = html;
      el.setAttribute('aria-hidden', 'false');
      el.style.opacity = '1';
      var mx = window.innerWidth  - 260;
      var my = window.innerHeight - 180;
      el.style.left = Math.min(cx + 12, mx) + 'px';
      el.style.top  = Math.min(cy + 12, my) + 'px';
    }
    function hide() {
      el.style.opacity = '0';
      el.setAttribute('aria-hidden', 'true');
    }
    return { show: show, hide: hide };
  }());

  function hitZone(svg, x, y, w, h, html) {
    var rect = svgEl('rect', {
      x: x - w / 2, y: y - h / 2, width: w, height: h,
      fill: 'transparent', cursor: 'crosshair',
    });
    rect.addEventListener('mouseenter', function (e) { tip.show(html, e.clientX, e.clientY); });
    rect.addEventListener('mousemove',  function (e) {
      var mx = window.innerWidth  - 260;
      var my = window.innerHeight - 180;
      var t = document.getElementById('cg-tooltip');
      if (t) {
        t.style.left = Math.min(e.clientX + 12, mx) + 'px';
        t.style.top  = Math.min(e.clientY + 12, my) + 'px';
      }
    });
    rect.addEventListener('mouseleave', tip.hide);
    svg.appendChild(rect);
  }

  /* ════════════════════════════════════════════════════════════════════════
   * Chart A — Monthly malicious-site volume (grouped bar chart)
   * ════════════════════════════════════════════════════════════════════════ */

  function renderChartA(containerId) {
    var el = document.getElementById(containerId);
    if (!el) return;

    var W = 760, H = 240;
    var pad = { top: 20, right: 20, bottom: 40, left: 48 };
    var svg = makeSvg(W, H);
    svg.setAttribute('aria-label', 'Monthly malicious site volume');

    var labels   = monthly.map(function (m) { return m.month.slice(5); }); // 'MM'
    var totals   = monthly.map(function (m) { return m.total_sites; });
    var malicious = monthly.map(function (m) { return m.malicious; });
    var yMax     = Math.max.apply(null, totals);
    var yMaxR    = Math.ceil(yMax / 500) * 500 || 500;

    drawAxes(svg, pad, W, H, yMaxR, labels, 5);

    var n       = monthly.length;
    var chartW  = W - pad.left - pad.right;
    var chartH  = H - pad.top - pad.bottom;
    var slotW   = chartW / n;
    var barW    = Math.max(4, slotW * 0.35);

    monthly.forEach(function (m, i) {
      var cx   = pad.left + slotW * (i + 0.5);
      var tot  = m.total_sites;
      var mal  = m.malicious;

      // Total bar (back)
      var hTot = (tot / yMaxR) * chartH;
      var yTot = pad.top + chartH - hTot;
      svg.appendChild(svgEl('rect', {
        x: cx - barW, y: yTot, width: barW - 1, height: hTot,
        fill: C.blue, opacity: '0.55',
      }));

      // Malicious bar (front)
      var hMal = (mal / yMaxR) * chartH;
      var yMal = pad.top + chartH - hMal;
      svg.appendChild(svgEl('rect', {
        x: cx + 1, y: yMal, width: barW - 1, height: hMal,
        fill: C.red, opacity: '0.85',
      }));

      // Hit zone
      var html = '<strong style="color:#c9d1d9">' + m.month + '</strong><br>'
               + '<span style="color:' + C.blue + '">&#9646; Total crawled: ' + tot + '</span><br>'
               + '<span style="color:' + C.red  + '">&#9646; Malicious: ' + mal + ' (' + Math.round(mal/tot*100) + '%)</span>';
      hitZone(svg, cx, pad.top + chartH / 2, slotW, chartH, html);
    });

    // Legend
    var lx = W - pad.right - 200;
    var ly = pad.top + 8;
    [[C.blue, 'Total crawled'], [C.red, 'Malicious']].forEach(function (item, i) {
      svg.appendChild(svgEl('rect', { x: lx, y: ly + i * 18, width: 10, height: 10, fill: item[0], rx: '2' }));
      svg.appendChild(text(lx + 14, ly + i * 18 + 9, item[1], { 'text-anchor': 'start', fill: C.label }));
    });

    el.appendChild(svg);
  }

  /* ════════════════════════════════════════════════════════════════════════
   * Chart B — Cradle family evolution (stacked area / line chart)
   * ════════════════════════════════════════════════════════════════════════ */

  function renderChartB(containerId) {
    var el = document.getElementById(containerId);
    if (!el) return;

    var W = 760, H = 260;
    var pad = { top: 20, right: 20, bottom: 40, left: 52 };
    var svg = makeSvg(W, H);
    svg.setAttribute('aria-label', 'Cradle family monthly distribution');

    var series = [
      { key: 'iwr_iex',   label: 'IWR/IEX',   color: C.yellow  },
      { key: 'webclient', label: 'WebClient',  color: C.orange  },
      { key: 'curl',      label: 'Curl/Bash',  color: C.purple  },
      { key: 'irm_iex',   label: 'IRM/IEX',   color: C.cyan    },
    ];

    var labels = monthly.map(function (m) { return m.month.slice(5); });
    var allVals = monthly.map(function (m) {
      return series.reduce(function (s, sr) { return s + (m.cradles[sr.key] || 0); }, 0);
    });
    var yMax  = Math.max.apply(null, allVals);
    var yMaxR = Math.ceil(yMax / 100) * 100 || 100;

    drawAxes(svg, pad, W, H, yMaxR, labels, 5);

    var n      = monthly.length;
    var chartW = W - pad.left - pad.right;
    var chartH = H - pad.top - pad.bottom;

    function xOf(i) { return pad.left + (i / (n - 1)) * chartW; }
    function yOf(v) { return pad.top + chartH - (v / yMaxR) * chartH; }

    // Draw a line per series
    series.forEach(function (sr) {
      var pts = monthly.map(function (m) { return m.cradles[sr.key] || 0; });

      // Area fill
      var areaPath = 'M ' + xOf(0) + ',' + yOf(0);
      pts.forEach(function (v, i) { areaPath += ' L ' + xOf(i) + ',' + yOf(v); });
      areaPath += ' L ' + xOf(n - 1) + ',' + yOf(0) + ' Z';
      svg.appendChild(svgEl('path', {
        d: areaPath, fill: sr.color, opacity: '0.12', stroke: 'none',
      }));

      // Line
      var linePath = pts.map(function (v, i) {
        return (i === 0 ? 'M' : 'L') + ' ' + xOf(i) + ',' + yOf(v);
      }).join(' ');
      svg.appendChild(svgEl('path', {
        d: linePath, fill: 'none', stroke: sr.color,
        'stroke-width': '2', 'stroke-linejoin': 'round', 'stroke-linecap': 'round',
      }));

      // Dots + hit zones
      pts.forEach(function (v, i) {
        if (v === 0) return;
        svg.appendChild(svgEl('circle', {
          cx: xOf(i), cy: yOf(v), r: '3', fill: sr.color,
        }));
        var m = monthly[i];
        var html = '<strong style="color:#c9d1d9">' + m.month + '</strong><br>'
                 + '<span style="color:' + sr.color + '">&#9646; ' + sr.label + ': ' + v + '</span><br>'
                 + '<span style="color:' + C.text + '">Malicious sites: ' + m.malicious + '</span>';
        hitZone(svg, xOf(i), yOf(v), 20, 20, html);
      });
    });

    // Legend (right side)
    var lx = W - pad.right - 88;
    var ly = pad.top;
    series.forEach(function (sr, i) {
      svg.appendChild(svgEl('line', {
        x1: lx, y1: ly + i * 18 + 5, x2: lx + 14, y2: ly + i * 18 + 5,
        stroke: sr.color, 'stroke-width': '2',
      }));
      svg.appendChild(text(lx + 18, ly + i * 18 + 9, sr.label, { 'text-anchor': 'start', fill: C.label, 'font-size': '10' }));
    });

    el.appendChild(svg);
  }

  /* ════════════════════════════════════════════════════════════════════════
   * Chart C — Evasion technique trends over time (multi-line)
   * ════════════════════════════════════════════════════════════════════════ */

  function renderChartC(containerId) {
    var el = document.getElementById(containerId);
    if (!el) return;

    var W = 760, H = 280;
    var pad = { top: 20, right: 20, bottom: 40, left: 52 };
    var svg = makeSvg(W, H);
    svg.setAttribute('aria-label', 'Evasion technique monthly trends');

    var series = [
      { key: 'base64',       label: 'Base64 encoding',      color: C.yellow },
      { key: 'hidden_window',label: 'Hidden window',         color: C.blue   },
      { key: 'mixed_case',   label: 'Mixed-case PS',         color: C.orange },
      { key: 'cdn_staging',  label: 'CDN staging',           color: C.cyan   },
      { key: 'self_delete',  label: 'Self-delete',           color: C.red    },
      { key: 'start_sleep',  label: 'Start-Sleep',           color: C.purple },
    ];

    var labels = monthly.map(function (m) { return m.month.slice(5); });
    var allVals = [];
    monthly.forEach(function (m) {
      series.forEach(function (sr) { allVals.push(m.evasion[sr.key] || 0); });
    });
    var yMax  = Math.max.apply(null, allVals);
    var yMaxR = Math.ceil(yMax / 500) * 500 || 500;

    drawAxes(svg, pad, W, H, yMaxR, labels, 5);

    var n      = monthly.length;
    var chartW = W - pad.left - pad.right;
    var chartH = H - pad.top - pad.bottom;

    function xOf(i) { return pad.left + (i / (n - 1)) * chartW; }
    function yOf(v) { return pad.top + chartH - (v / yMaxR) * chartH; }

    series.forEach(function (sr) {
      var pts = monthly.map(function (m) { return m.evasion[sr.key] || 0; });

      var linePath = pts.map(function (v, i) {
        return (i === 0 ? 'M' : 'L') + ' ' + xOf(i) + ',' + yOf(v);
      }).join(' ');
      svg.appendChild(svgEl('path', {
        d: linePath, fill: 'none', stroke: sr.color,
        'stroke-width': '2', 'stroke-linejoin': 'round', 'stroke-linecap': 'round',
      }));

      // Dots + hit zones
      pts.forEach(function (v, i) {
        svg.appendChild(svgEl('circle', {
          cx: xOf(i), cy: yOf(v), r: '3', fill: sr.color,
        }));
        var m = monthly[i];
        var html = '<strong style="color:#c9d1d9">' + m.month + '</strong><br>'
                 + '<span style="color:' + sr.color + '">&#9646; ' + sr.label + ': ' + v + '</span><br>'
                 + '<span style="color:' + C.text + '">Malicious sites: ' + m.malicious + '</span>';
        hitZone(svg, xOf(i), yOf(v), 20, 20, html);
      });
    });

    // Legend (two columns)
    var lx = pad.left + 10;
    var ly = pad.top + 4;
    series.forEach(function (sr, i) {
      var col = i < 3 ? 0 : 1;
      var row = i < 3 ? i : i - 3;
      var x = lx + col * 175;
      var y = ly + row * 18;
      svg.appendChild(svgEl('line', {
        x1: x, y1: y + 5, x2: x + 14, y2: y + 5,
        stroke: sr.color, 'stroke-width': '2',
      }));
      svg.appendChild(text(x + 18, y + 9, sr.label, { 'text-anchor': 'start', fill: C.label, 'font-size': '10' }));
    });

    el.appendChild(svg);
  }

  /* ── Init ────────────────────────────────────────────────────────────── */

  function init() {
    renderChartA('cg-chart-volume');
    renderChartB('cg-chart-cradles');
    renderChartC('cg-chart-evasion');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

}());

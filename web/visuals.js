// Server side drawings: Lucide icons and maps made from real world geography
// (geo.json was built from Natural Earth data via the world-atlas package).
const fs = require('fs');
const path = require('path');

const ICON_DIR = path.join(__dirname, '..', 'node_modules', 'lucide-static', 'icons');
const iconCache = {};

// icon('radar', 'extra-class') returns an inline <svg>
function icon(name, cls = '') {
  if (!iconCache[name]) {
    let svg = '';
    try {
      svg = fs.readFileSync(path.join(ICON_DIR, `${name}.svg`), 'utf8');
    } catch (e) {
      return '';
    }
    iconCache[name] = svg
      .replace(/<!--.*?-->/s, '')
      .replace(/class="[^"]*"/, 'class="ico __CLS__" aria-hidden="true"')
      .replace(/\s(width|height)="24"/g, '')
      .replace(/\n\s*/g, ' ')
      .trim();
  }
  return iconCache[name].replace('__CLS__', cls);
}

const GEO = JSON.parse(fs.readFileSync(path.join(__dirname, 'geo.json'), 'utf8'));

// Names in the logs that differ from the map data
const ALIAS = { 'United States': 'United States of America' };
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// World map with an arc from every attacking country to Pakistan.
// origins: [{ country, count }]
function attackMap(origins, opts = {}) {
  const { W, H, countries, sites } = GEO.world;
  const max = Math.max(1, ...origins.map((o) => o.count));
  const target = sites.LHR;
  const hit = new Map(origins.map((o) => [ALIAS[o.country] || o.country, o.count]));

  let shapes = '';
  for (const [name, c] of Object.entries(countries)) {
    let cls = 'land';
    let style = '';
    if (name === 'Pakistan') cls = 'land home';
    else if (hit.has(name)) {
      cls = 'land hit';
      style = ` style="fill-opacity:${(0.25 + 0.6 * (hit.get(name) / max)).toFixed(2)}"`;
    }
    shapes += `<path class="${cls}"${style} d="${c.d}"><title>${esc(name)}${hit.has(name) ? `: ${hit.get(name).toLocaleString('en-US')} events` : ''}</title></path>`;
  }

  let arcs = '';
  let dots = '';
  origins.forEach((o, i) => {
    const c = countries[ALIAS[o.country] || o.country];
    if (!c || o.country === 'Pakistan') return;
    const [x1, y1] = c.c;
    const [x2, y2] = target;
    const mx = (x1 + x2) / 2;
    const my = Math.min(y1, y2) - Math.abs(x2 - x1) * 0.28 - 12;
    const w = (1 + 3 * (o.count / max)).toFixed(1);
    arcs += `<path class="arc" style="animation-delay:${i * 0.18}s" stroke-width="${w}" d="M${x1},${y1} Q${mx},${my} ${x2},${y2}"/>`;
    dots += `<circle class="origin" cx="${x1}" cy="${y1}" r="${(3 + 7 * (o.count / max)).toFixed(1)}"><title>${esc(o.country)}: ${o.count.toLocaleString('en-US')} events</title></circle>`;
    if (opts.labels !== false && i < 5) {
      dots += `<text class="origin-label" x="${x1}" y="${y1 - 12}">${esc(o.country)}</text>`;
    }
  });

  const pins = Object.entries(sites).map(([code, [x, y]]) =>
    `<circle class="site-ring" cx="${x}" cy="${y}" r="9"/><circle class="site-dot" cx="${x}" cy="${y}" r="3"/>`).join('');

  return `<svg class="worldmap ${opts.cls || ''}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Map of countries attacking our sites">
    <g>${shapes}</g><g>${arcs}</g><g>${dots}</g><g>${pins}</g></svg>`;
}

// Pakistan close up with the three sites. stats: { KHI: {events, open}, ... }
function siteMap(stats) {
  const { W, H, d, sites } = GEO.pakistan;
  const names = { KHI: 'Karachi', LHR: 'Lahore', ISB: 'Islamabad' };
  const max = Math.max(1, ...Object.values(stats).map((s) => s.events || 0));
  const offset = { KHI: [14, 18], LHR: [16, 4], ISB: [-18, -2] };
  let pins = '';
  for (const [code, [x, y]] of Object.entries(sites)) {
    const s = stats[code] || { events: 0, open: 0 };
    const r = 8 + 16 * ((s.events || 0) / max);
    const [dx, dy] = offset[code];
    const anchor = dx < 0 ? 'end' : 'start';
    pins += `<circle class="pk-halo" cx="${x}" cy="${y}" r="${r.toFixed(1)}"/><circle class="pk-dot" cx="${x}" cy="${y}" r="4"/>
      <text class="pk-name" x="${x + dx}" y="${y + dy}" text-anchor="${anchor}">${names[code]}</text>
      <text class="pk-num" x="${x + dx}" y="${y + dy + 15}" text-anchor="${anchor}">${s.open} open</text>`;
  }
  return `<svg class="pkmap" viewBox="0 0 ${W} ${H}" role="img" aria-label="Map of Pakistan with the three sites">
    <path class="pk-land" d="${d}"/>${pins}</svg>`;
}

module.exports = { icon, attackMap, siteMap };

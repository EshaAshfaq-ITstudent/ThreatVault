// ============================================================
// ThreatVault sample log generator
// Creates data/logs_KHI.csv, data/logs_LHR.csv, data/logs_ISB.csv
// Normal traffic plus planted attacks so detection has something to find.
//
// Usage:  node tools/generate-logs.js [days] [rowsPerSite]
//         default: 14 days ending today, about 33,000 rows per site
// ============================================================
const fs = require('fs');
const path = require('path');

const DAYS = parseInt(process.argv[2] || '14', 10);
const ROWS_PER_SITE = parseInt(process.argv[3] || '33000', 10);
const OUT_DIR = path.join(__dirname, '..', 'data');

// Small seeded random generator so every member gets the same data
let seed = 20261106;
function rand() {
  seed = (seed * 1664525 + 1013904223) % 4294967296;
  return seed / 4294967296;
}
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const between = (a, b) => a + Math.floor(rand() * (b - a + 1));

const SITES = [
  { code: 'KHI', assetBase: 100 },
  { code: 'LHR', assetBase: 200 },
  { code: 'ISB', assetBase: 300 },
];

// Countries with weights for normal traffic
const NORMAL_COUNTRIES = [
  ['Pakistan', 70], ['United Arab Emirates', 8], ['Saudi Arabia', 6],
  ['United States', 6], ['United Kingdom', 5], ['Germany', 5],
];
const ATTACK_COUNTRIES = ['China', 'Russia', 'North Korea', 'Iran', 'Brazil', 'Vietnam', 'Ukraine', 'Romania'];
const USERS = ['ali.khan', 'sara.ahmed', 'bilal.r', 'hina.s', 'usman.t', 'ayesha.m', 'fahad.q', 'zara.n'];
const BRUTE_USERS = ['admin', 'root', 'administrator', 'test', 'oracle', 'sa'];
const PHISH_SENDERS = ['security@paypa1-verify.com', 'hr@bahria-portal.net', 'it-support@micros0ft-login.com',
  'billing@k-electric-pay.org', 'noreply@dhl-track-parcel.info'];

function weightedCountry() {
  const total = NORMAL_COUNTRIES.reduce((s, c) => s + c[1], 0);
  let r = rand() * total;
  for (const [name, w] of NORMAL_COUNTRIES) { if ((r -= w) <= 0) return name; }
  return 'Pakistan';
}

function publicIp() {
  return `${between(11, 223)}.${between(0, 255)}.${between(0, 255)}.${between(1, 254)}`;
}

// Pools: normal visitors and attackers
const normalIps = Array.from({ length: 4000 }, () => ({ ip: publicIp(), country: weightedCountry() }));
const sharedAttackers = Array.from({ length: 3 }, () => ({ ip: publicIp(), country: pick(ATTACK_COUNTRIES) }));

const pad = (n) => String(n).padStart(2, '0');
function fmt(d) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function hexHash() {
  let h = '';
  for (let i = 0; i < 64; i++) h += '0123456789abcdef'[Math.floor(rand() * 16)];
  return h;
}

const now = new Date();
const endDay = new Date(now.getFullYear(), now.getMonth(), now.getDate()); // today 00:00
const startDay = new Date(endDay.getTime() - (DAYS - 1) * 86400000);

function randomTime() {
  const dayIdx = between(0, DAYS - 1);
  const d = new Date(startDay.getTime() + dayIdx * 86400000);
  // more traffic during office hours
  const hour = rand() < 0.7 ? between(8, 19) : between(0, 23);
  d.setHours(hour, between(0, 59), between(0, 59));
  return d;
}
function randomHourSlot() {
  const d = new Date(startDay.getTime() + between(0, DAYS - 1) * 86400000);
  d.setHours(between(0, 23), 0, 0);
  return d;
}
function inSameHour(slot) {
  const d = new Date(slot);
  d.setMinutes(between(0, 59), between(0, 59));
  return d;
}

function csvValue(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function generateSite(site) {
  const rows = [];
  const asset = () => site.assetBase + between(1, 20);
  const webAsset = () => site.assetBase + pick([1, 6, 11, 16]);     // web servers
  const firewall = () => site.assetBase + pick([4, 9, 14, 19]);     // firewalls
  const workstation = () => site.assetBase + pick([5, 10, 15, 20]); // workstations
  const add = (t, assetId, src, type, action, user, detail, port) =>
    rows.push([site.code, fmt(t), assetId, src.ip, src.country, port, type, action, user || '', detail || '']);

  // ---------- planted attacks ----------
  // Brute force: 6 bursts, plus the 3 shared attackers hit every site
  const bruteAttackers = [
    ...Array.from({ length: 6 }, () => ({ ip: publicIp(), country: pick(ATTACK_COUNTRIES) })),
    ...sharedAttackers,
  ];
  for (const a of bruteAttackers) {
    const slot = randomHourSlot();
    const target = asset();
    const tries = between(25, 90);
    for (let i = 0; i < tries; i++) {
      add(inSameHour(slot), target, a, 'LOGIN_FAIL', 'DENIED', pick(BRUTE_USERS), null, 22);
    }
  }
  // DDoS: 3 floods of 350 to 700 web requests in one hour
  for (let k = 0; k < 3; k++) {
    const a = { ip: publicIp(), country: pick(ATTACK_COUNTRIES) };
    const slot = randomHourSlot();
    const target = webAsset();
    const hits = between(350, 700);
    for (let i = 0; i < hits; i++) add(inSameHour(slot), target, a, 'HTTP_REQ', 'ALLOWED', null, 'GET /login', 443);
  }
  // Malware alerts
  for (let k = 0; k < 4; k++) {
    const t = randomTime();
    add(t, workstation(), { ip: `10.${SITES.indexOf(site) + 1}.0.${pick([5, 10, 15, 20])}`, country: 'Pakistan' },
        'MALWARE_ALERT', 'QUARANTINE', pick(USERS), hexHash(), null);
  }
  // Phishing clicks
  for (let k = 0; k < 4; k++) {
    const t = randomTime();
    add(t, workstation(), { ip: `10.${SITES.indexOf(site) + 1}.0.${pick([5, 10, 15, 20])}`, country: 'Pakistan' },
        'PHISH_CLICK', 'ALLOWED', pick(USERS), pick(PHISH_SENDERS), 80);
  }
  // Port scans (noise, shown in reports)
  for (let k = 0; k < 5; k++) {
    const a = { ip: publicIp(), country: pick(ATTACK_COUNTRIES) };
    const slot = randomHourSlot();
    for (let i = 0; i < between(30, 60); i++) {
      add(inSameHour(slot), firewall(), a, 'PORT_SCAN', 'BLOCKED', null, null, between(1, 1024));
    }
  }

  // ---------- normal traffic fills the rest ----------
  while (rows.length < ROWS_PER_SITE) {
    const src = pick(normalIps);
    const t = randomTime();
    const r = rand();
    if (r < 0.55) add(t, webAsset(), src, 'HTTP_REQ', 'ALLOWED', null, pick(['GET /', 'GET /products', 'POST /api/order', 'GET /about']), 443);
    else if (r < 0.83) add(t, asset(), src, 'LOGIN_OK', 'ALLOWED', pick(USERS), null, 22);
    else if (r < 0.90) add(t, asset(), src, 'LOGIN_FAIL', 'DENIED', pick(USERS), 'wrong password', 22);
    else add(t, firewall(), { ip: publicIp(), country: pick([...ATTACK_COUNTRIES, 'Pakistan']) }, 'FW_BLOCK', 'BLOCKED', null, null, pick([23, 445, 3389, 1433, 8080]));
  }

  rows.sort((a, b) => (a[1] < b[1] ? -1 : 1));
  return rows;
}

fs.mkdirSync(OUT_DIR, { recursive: true });
const header = 'site_code,event_time,asset_id,src_ip,src_country,dst_port,event_type,action,username,detail';
let total = 0;
for (const site of SITES) {
  const rows = generateSite(site);
  const file = path.join(OUT_DIR, `logs_${site.code}.csv`);
  fs.writeFileSync(file, header + '\n' + rows.map((r) => r.map(csvValue).join(',')).join('\n') + '\n');
  total += rows.length;
  console.log(`${file}  ${rows.length} rows`);
}
console.log(`Done. ${total} rows from ${fmt(startDay).slice(0, 10)} to ${fmt(endDay).slice(0, 10)}.`);
console.log(`Shared attackers (show up in INTERSECT report): ${sharedAttackers.map((a) => a.ip).join(', ')}`);

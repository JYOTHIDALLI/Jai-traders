// Godown Ledger server. It serves the app (public/index.html) and talks to MongoDB Atlas.
// The Atlas URL lives only in the ".env" file on the server, never in the app.
//   owner : read, add, change, delete everything
//   staff : read, and ADD new customers/sales/payments/stock. Cannot change or delete existing ones.
//   view  : read only
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns');

// tiny .env loader (so "npm start" works on any Node version)
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && !l.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch (e) { /* no .env file: use real environment variables */ }

const nodeDnsServers = dns.getServers();
if (nodeDnsServers.includes('127.0.0.1') || nodeDnsServers.includes('::1')) {
  try {
    dns.setServers(['1.1.1.1', '8.8.8.8']);
  } catch (e) {
    console.warn('Could not set the fallback DNS servers:', e.message);
  }
}

const { MongoClient } = require('mongodb');
const { MONGODB_URI, PORT = 3000 } = process.env;
const hasDatabaseConfig = !!MONGODB_URI && !MONGODB_URI.includes('<db_password>');

// A key still set to the .env.example placeholder is public, so it counts as not set.
const keyFrom = name => {
  const v = process.env[name] || '';
  if (!/^replace-with-/.test(v)) return v;
  console.warn(name + ' is still the example placeholder, so it is ignored. Set your own long random key.');
  return '';
};
const OWNER_KEY = keyFrom('OWNER_KEY'), STAFF_KEY = keyFrom('STAFF_KEY'), VIEW_KEY = keyFrom('VIEW_KEY');
// The built-in "local-owner" key only works while there is no database, for trying the app on your own computer.
const effectiveOwnerKey = OWNER_KEY || (hasDatabaseConfig ? '' : 'local-owner');
if (hasDatabaseConfig && !OWNER_KEY) console.warn('OWNER_KEY is not set, so nobody can use the owner role. Add OWNER_KEY to .env (or to the host\'s environment variables) and restart.');

const DATA = ['cust', 'moves', 'sales', 'pays'];
const COLS = [...DATA, 'cfg', 'backup', 'auditlog'];
const ID = /^[A-Za-z0-9_-]{1,80}$/;
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
// A missing or empty key is no role at all, never the owner.
const roleOf = k => {
  if (!k) return null;
  return (effectiveOwnerKey && same(k, effectiveOwnerKey)) ? 'owner' : (STAFF_KEY && same(k, STAFF_KEY)) ? 'staff' : (VIEW_KEY && same(k, VIEW_KEY)) ? 'view' : null;
};

// The visitor's address, for counting wrong keys. On Vercel, requests reach the function through Vercel's proxy,
// so the connection address is not the visitor's. Vercel writes the visitor's address into x-forwarded-for and
// overwrites any value the visitor sent, so the header is trusted there. Anywhere else a visitor could fake it.
const clientIp = req => {
  if (process.env.VERCEL) {
    const first = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (first) return first;
  }
  return req.socket.remoteAddress;
};

// slow down key guessing: 30 wrong keys per 10 minutes per address
const bad = new Map();
const blocked = ip => { const r = bad.get(ip); return r && r.n >= 30 && Date.now() - r.t < 600000; };
const fail = ip => { const r = bad.get(ip); if (!r || Date.now() - r.t > 600000) bad.set(ip, { n: 1, t: Date.now() }); else r.n++; };

const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(obj)); };

// Returns the caller's role, or sends 429/401 and returns null.
function authorize(req, res) {
  const ip = clientIp(req);
  if (blocked(ip)) { json(res, 429, { error: 'Too many wrong keys. Try again later.' }); return null; }
  const role = roleOf(req.headers['x-api-key'] || '');
  if (!role) { fail(ip); json(res, 401, { error: 'Invalid key' }); return null; }
  return role;
}
const readBody = req => new Promise((ok, no) => {
  let d = ''; req.on('data', c => { d += c; if (d.length > 400000) { no(new Error('Too big')); req.destroy(); } });
  req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { no(e); } });
});

const client = hasDatabaseConfig ? new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 8000 }) : null;
let db;
const audit = (role, action, col, id) => db.collection('audit').insertOne({ t: new Date(), role, action, col, id }).catch(() => {});
const out = d => { const { _id, ...x } = d; return { ...x, id: _id }; };

function allowedRead(role, col) { return col === 'cfg' || DATA.includes(col) || role === 'owner'; }
function allowedWrite(role, col) {
  if (role === 'owner') return true;
  if (role === 'staff') return DATA.includes(col) || col === 'auditlog';
  return false;
}

// ---- What a saved record may contain. Anything else is refused with 400 and a plain-language reason, which the
// app shows as "Sync problem (...)". The rules match the fields the app itself writes.
const GRADES = ['AAAA', 'AAA', 'AA', 'A', 'Kali'], MOVE_TYPES = ['dispatch', 'return', 'inward'], PAY_MODES = ['Cash', 'UPI'];
const DAYS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
const MAX_KG = 1e6, MAX_RATE = 1e5, MAX_RUPEES = 1e8, MAX_TIME = 1e13;
const NAMES = { cust: 'Customer', moves: 'Stock entry', sales: 'Sale', pays: 'Payment', cfg: 'Settings', backup: 'Backup', auditlog: 'Log entry' };
const LABELS = { qty: 'quantity', price: 'price per kg', paid: 'paid amount', amt: 'amount', cid: 'customer', open: 'old pending',
  cost: 'cost per kg', loc: 'place', addr: 'address', mode: 'payment mode', v: 'schedule', t: 'time', a: 'text', l: 'line name', o: 'starting credit' };

const isNum = v => typeof v === 'number' && Number.isFinite(v);
const isObj = v => !!v && typeof v === 'object' && !Array.isArray(v);
const inr = n => n.toLocaleString('en-IN');
const missing = v => v === undefined || v === null;
// Each rule returns '' when the value is fine, otherwise the problem.
const text = (max, required) => v => missing(v) || v === '' ? (required ? 'is required' : '')
  : typeof v !== 'string' ? 'must be text' : required && !v.trim() ? 'is required'
  : v.length > max ? `must be ${max} characters or fewer` : /[\u0000-\u001f\u007f]/.test(v) ? 'has invalid characters' : '';
const num = (min, max, above) => v => missing(v) ? 'is required' : !isNum(v) ? 'must be a number'
  : above ? (v > min ? (v <= max ? '' : `must be ${inr(max)} or less`) : `must be above ${inr(min)}`)
  : v < min ? `must be at least ${inr(min)}` : v > max ? `must be ${inr(max)} or less` : '';
const optional = rule => v => missing(v) ? '' : rule(v);
const oneOf = list => v => missing(v) ? 'is required' : list.includes(v) ? '' : 'must be one of ' + list.join(', ');
const date = v => {
  if (missing(v) || v === '') return 'is required';
  const d = typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) ? new Date(v + 'T00:00:00Z') : null;
  if (!d || isNaN(d) || d.toISOString().slice(0, 10) !== v || v < '2000-01-01') return 'must be a real date (YYYY-MM-DD)';
  return d.getTime() > Date.now() + 366 * 864e5 ? 'is more than a year ahead' : '';
};
const phone = v => text(30)(v) || (v && !/^[0-9+\-\s()\/,.]*$/.test(v) ? 'may only contain digits, spaces and + - ( ) / , .' : '');
const custId = v => missing(v) || v === '' ? 'is required' : typeof v === 'string' && ID.test(v) ? '' : 'is not a valid customer';
const schedule = v => {
  if (!isObj(v)) return 'must be an object';
  for (const [day, x] of Object.entries(v)) {
    if (!DAYS.includes(day)) return `has an unknown day ${JSON.stringify(day.slice(0, 20))}`;
    if (!isObj(x) || Object.keys(x).some(k => k !== 'l' && k !== 'o')) return `for ${day} must have only a line name and starting credit`;
    const p = text(50)(x.l) || (missing(x.l) ? 'is required' : '');
    if (p) return `line name for ${day} ${p}`;
    const q = num(-MAX_RUPEES, MAX_RUPEES)(x.o);
    if (q) return `starting credit for ${day} ${q}`;
  }
  return '';
};
const SYNC_FIELDS = { ts: optional(num(0, MAX_TIME)), by: text(40), h: text(40) }; // added by the app when it syncs
const SHAPES = {
  cust: { name: text(100, true), route: text(50, true), loc: text(100), addr: text(300), phone, open: optional(num(-MAX_RUPEES, MAX_RUPEES)), ...SYNC_FIELDS },
  moves: { type: oneOf(MOVE_TYPES), date, grade: oneOf(GRADES), qty: num(0, MAX_KG, true), route: text(50), cost: optional(num(0, MAX_RATE)), ...SYNC_FIELDS },
  sales: { date, cid: custId, grade: oneOf(GRADES), qty: num(0, MAX_KG, true), price: num(0, MAX_RATE, true), paid: num(0, MAX_RUPEES), mode: oneOf(PAY_MODES), ...SYNC_FIELDS },
  pays: { date, cid: custId, amt: num(0, MAX_RUPEES, true), mode: oneOf(PAY_MODES), ...SYNC_FIELDS },
  auditlog: { t: num(0, MAX_TIME), a: text(300, true), w: optional(oneOf([0, 1])), u: text(40) },
};
function shapeOf(col, id) {
  if (col === 'cfg') return id === 'sched' ? { v: schedule } : id === 'meta' ? { t: num(0, MAX_TIME) } : null;
  if (col === 'backup') {
    if (id === 'meta') return { n: v => Number.isInteger(v) && v >= 1 && v <= 1000 ? '' : 'must be a whole number from 1 to 1000', t: num(0, MAX_TIME), by: text(40) };
    const part = /^c(\d{1,4})$/.exec(id);
    return part ? { i: v => v === Number(part[1]) ? '' : 'must match the part number', d: v => typeof v === 'string' && v.length <= 60000 ? '' : 'must be text of at most 60000 characters' } : null;
  }
  return SHAPES[col];
}
// Returns null when the record may be saved, otherwise the reason it cannot.
async function invalid(col, id, body) {
  const name = NAMES[col], shape = shapeOf(col, id);
  if (!shape) return `${name}: unknown record ${JSON.stringify(id)}`;
  for (const k of Object.keys(body)) if (!(k in shape)) return `${name}: unknown field ${JSON.stringify(k.slice(0, 40))}`;
  for (const [k, rule] of Object.entries(shape)) { const p = rule(body[k]); if (p) return `${name}: ${LABELS[k] || k} ${p}`; }
  if (col === 'moves' && body.type !== 'inward' && !(body.route || '').trim()) return `${name}: route is required for a dispatch or return`;
  if ((col === 'sales' || col === 'pays') && !(await db.collection('cust').findOne({ _id: body.cid }, { projection: { _id: 1 } }))) return `${name}: customer not found`;
  return null;
}

async function api(req, res, parts) {
  const role = authorize(req, res);
  if (!role) return;
  if (parts[1] === 'whoami') return json(res, 200, { role });
  if (parts[1] === 'audit') {
    if (role !== 'owner') return json(res, 403, { error: 'Only the owner can read the server log' });
    return json(res, 200, await db.collection('audit').find({}).sort({ t: -1 }).limit(1000).toArray());
  }
  // Several collections in one request (the app's live refresh), e.g. /api/sync?c=cust,moves,sales.
  // The ETag lets the app ask "changed since?" and get an empty 304 when nothing has.
  if (parts[1] === 'sync') {
    if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' });
    const cols = [...new Set((new URL(req.url, 'http://x').searchParams.get('c') || '').split(',').filter(Boolean))];
    if (!cols.length || cols.some(c => !COLS.includes(c))) return json(res, 400, { error: 'Bad collection list' });
    if (cols.some(c => !allowedRead(role, c))) return json(res, 403, { error: 'Not allowed' });
    const lists = await Promise.all(cols.map(c => db.collection(c).find({}).limit(100000).toArray()));
    const data = {};
    cols.forEach((c, i) => { data[c] = lists[i].map(out); });
    const body = JSON.stringify(data);
    const etag = '"' + crypto.createHash('sha1').update(body).digest('base64url') + '"';
    if (req.headers['if-none-match'] === etag) { res.writeHead(304, { etag, 'cache-control': 'no-store' }); return res.end(); }
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', etag });
    return res.end(body);
  }
  if (parts[1] !== 'data' || !COLS.includes(parts[2])) return json(res, 404, { error: 'Not found' });
  const col = parts[2], id = parts[3], c = db.collection(col);
  if (id !== undefined && !ID.test(id)) return json(res, 400, { error: 'Bad id' });

  if (req.method === 'GET') {
    if (!allowedRead(role, col)) return json(res, 403, { error: 'Not allowed' });
    if (id === undefined) return json(res, 200, (await c.find({}).limit(100000).toArray()).map(out));
    const d = await c.findOne({ _id: id });
    return d ? json(res, 200, out(d)) : json(res, 404, { error: 'Not found' });
  }
  if (req.method === 'PUT' && id !== undefined) {
    if (!allowedWrite(role, col)) return json(res, 403, { error: 'Your key cannot write here' });
    let doc;
    try { doc = await readBody(req); } catch (e) { return json(res, 400, { error: 'Body must be valid JSON' }); }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return json(res, 400, { error: 'Body must be an object' });
    if (DATA.includes(col) && doc.id !== id) return json(res, 400, { error: 'id mismatch' });
    const body = { ...doc }; delete body.id; delete body._id;
    const problem = await invalid(col, id, body);
    if (problem) return json(res, 400, { error: problem });
    if (col === 'auditlog' || role === 'staff') {
      try { await c.insertOne({ ...body, _id: id }); } catch (e) {
        if (e && e.code === 11000) return json(res, 409, { error: 'Already exists. Existing entries cannot be changed with this key.' });
        throw e;
      }
      audit(role, 'add', col, id);
      return json(res, 200, { ok: true });
    }
    const old = await c.findOne({ _id: id });
    await c.replaceOne({ _id: id }, { ...body, _id: id }, { upsert: true });
    if (old && DATA.includes(col)) await db.collection('history').insertOne({ t: new Date(), col, id, before: old }).catch(() => {});
    audit(role, old ? 'change' : 'add', col, id);
    return json(res, 200, { ok: true });
  }
  if (req.method === 'DELETE' && id !== undefined) {
    if (role !== 'owner' || col === 'auditlog') return json(res, 403, { error: 'Only the owner can delete, and the log can never be deleted' });
    const old = await c.findOne({ _id: id });
    if (old) { await db.collection('deleted').insertOne({ t: new Date(), col, id, doc: old }); await c.deleteOne({ _id: id }); }
    audit('owner', 'delete', col, id);
    return json(res, 200, { ok: true });
  }
  return json(res, 405, { error: 'Method not allowed' });
}

function serve(req, res, pathname) {
  let p = path.normalize(decodeURIComponent(pathname)).replace(/^([/\\])+/, '');
  if (!p || p.endsWith('/')) p += 'index.html';
  const file = path.join(__dirname, 'public', p);
  if (!file.startsWith(path.join(__dirname, 'public'))) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, data) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'x-content-type-options': 'nosniff', 'cache-control': 'no-cache' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x'), parts = u.pathname.split('/').filter(Boolean);
    if (parts[0] === 'api') return await api(req, res, parts);
    return serve(req, res, u.pathname);
  } catch (e) { console.error(e); if (!res.headersSent) json(res, 500, { error: 'Server error' }); }
});

let dbReady;
async function ensureDatabase() {
  if (!client) throw new Error('MongoDB is not configured');
  if (!dbReady) {
    dbReady = client.connect().then(() => {
      db = client.db();
    }).catch(e => {
      dbReady = null;
      throw e;
    });
  }
  return dbReady;
}

async function handler(req, res) {
  try {
    const u = new URL(req.url, 'http://x'), parts = u.pathname.split('/').filter(Boolean);
    if (parts[0] === 'api') {
      // whoami answers before the database connects, so the app can check a key even when Atlas is down.
      if (parts[1] === 'whoami') { const role = authorize(req, res); if (role) json(res, 200, { role }); return; }
      try {
        await ensureDatabase();
        return await api(req, res, parts);
      } catch (e) {
        console.error('Could not connect to MongoDB Atlas:', e.message);
        return json(res, 503, { error: 'Database connection failed' });
      }
    }
    return serve(req, res, u.pathname);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) json(res, 500, { error: 'Server error' });
  }
}

if (require.main === module) {
  http.createServer(handler).listen(PORT, '0.0.0.0', () => {
    console.log('Godown is running: open http://localhost:' + PORT);
    if (!hasDatabaseConfig) {
      console.warn('MongoDB is not configured. The app will run with browser-local storage.');
    } else {
      console.warn('MongoDB may be unavailable. The app can still run with browser-local storage.');
    }
  });
}

module.exports = handler;

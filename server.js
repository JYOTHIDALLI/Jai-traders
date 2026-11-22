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
const { MONGODB_URI, OWNER_KEY, STAFF_KEY, VIEW_KEY, PORT = 3000 } = process.env;
const effectiveOwnerKey = OWNER_KEY || 'local-owner';
const hasDatabaseConfig = !!MONGODB_URI && !MONGODB_URI.includes('<db_password>');

const DATA = ['cust', 'moves', 'sales', 'pays'];
const COLS = [...DATA, 'cfg', 'backup', 'auditlog'];
const ID = /^[A-Za-z0-9_-]{1,80}$/;
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const roleOf = k => {
  if (!k) return 'owner';
  return same(k, effectiveOwnerKey) ? 'owner' : (STAFF_KEY && same(k, STAFF_KEY)) ? 'staff' : (VIEW_KEY && same(k, VIEW_KEY)) ? 'view' : null;
};

// slow down key guessing: 30 wrong keys per 10 minutes per address
const bad = new Map();
const blocked = ip => { const r = bad.get(ip); return r && r.n >= 30 && Date.now() - r.t < 600000; };
const fail = ip => { const r = bad.get(ip); if (!r || Date.now() - r.t > 600000) bad.set(ip, { n: 1, t: Date.now() }); else r.n++; };

const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(obj)); };
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

async function api(req, res, parts) {
  const ip = req.socket.remoteAddress;
  if (blocked(ip)) return json(res, 429, { error: 'Too many wrong keys. Try again later.' });
  const role = roleOf(req.headers['x-api-key'] || '');
  if (!role) { fail(ip); return json(res, 401, { error: 'Invalid key' }); }
  if (parts[1] === 'whoami') return json(res, 200, { role });
  if (parts[1] === 'audit') {
    if (role !== 'owner') return json(res, 403, { error: 'Only the owner can read the server log' });
    return json(res, 200, await db.collection('audit').find({}).sort({ t: -1 }).limit(1000).toArray());
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
    const doc = await readBody(req);
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return json(res, 400, { error: 'Body must be an object' });
    if (DATA.includes(col) && doc.id !== id) return json(res, 400, { error: 'id mismatch' });
    const body = { ...doc }; delete body.id; delete body._id;
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
      if (parts[1] === 'whoami') return json(res, 200, { role: roleOf(req.headers['x-api-key'] || '') || 'owner' });
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

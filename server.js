/**
 * SupplyOps — Office Supplies & Admin Asset Inventory
 * Local network server: Express + JSON-file database.
 *
 * Security model:
 *  - Passwords are hashed (scrypt + per-user salt), never stored or sent in plaintext.
 *  - Login issues a session token; all data endpoints require it.
 *  - User management & audit access require the Admin role (enforced server-side).
 *  - All shared data lives on the SERVER machine, so every PC on the LAN sees the same inventory.
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const PORT = process.env.PORT || 3001;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

/* ---------------- Database (JSON file) ---------------- */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = String(stored).split(':');
    const test = crypto.scryptSync(String(password), salt, 64);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), test);
  } catch (e) {
    return false;
  }
}

function defaultDb() {
  return {
    items: [
      { id: 'o1', category: 'Paper & Filing Supplies', sku: 'PPR-001', brand: 'Hard Copy Bond Paper', size: 'A4 (8.27 x 11.69 in)', type: '80 GSM Premium Sub70', color: 'Bright White', qty: 120, unit: 'reams', location: 'Supply Room Shelf 1', remarks: 'Standard printing paper for all departments', poNo: 'PO-2026-001', unitCost: 4.5, totalCost: 540 },
      { id: 'o2', category: 'Paper & Filing Supplies', sku: 'PPR-002', brand: 'Long Expandable Folders', size: 'Legal / Long', type: 'Tagboard Heavy Duty', color: 'Kraft / Beige', qty: 350, unit: 'pcs', location: 'Supply Room Shelf 3', remarks: 'For accounting & HR documentation', poNo: 'PO-2026-001', unitCost: 0.6, totalCost: 210 },
      { id: 'o3', category: 'Pens & Desk Accessories', sku: 'DSK-101', description: 'Pilot Gel Pen 0.7mm', brand: 'Pilot Super Gel', size: '0.7mm Fine', color: 'Black Ink', qty: 40, unit: 'boxes (12s)', location: 'Cabinet C Drawer 1', totalCost: 320, poNo: 'PO-2026-002' },
      { id: 'o4', category: 'Pens & Desk Accessories', sku: 'DSK-102', description: 'Gem Clips & Binder Clips Set', brand: 'Joy Office', size: 'Assorted Sizes', color: 'Silver Steel', qty: 75, unit: 'tubs', location: 'Cabinet C Drawer 2', totalCost: 112.5, poNo: 'PO-2026-002' },
      { id: 'o5', category: 'Admin Office Furniture', sku: 'AST-001', name: 'Ergonomic High-Back Executive Mesh Chair', brand: 'Steelcase Series', spec: 'Adjustable Lumbar & Armrests, Black/Rose Frame', qty: 25, unit: 'units', location: 'Main Office Floor & Executive Rooms', condition: 'Brand New', poNo: 'PO-2026-003', totalCost: 4375 },
      { id: 'o6', category: 'Admin Office Furniture', sku: 'AST-002', name: '4-Drawer Lateral Steel Filing Cabinet', brand: 'ModernOffice Heavy Duty', spec: 'Anti-tilt mechanism, Central Key Lock, Cold-rolled steel', qty: 12, unit: 'units', location: 'Finance & HR Dep', condition: 'Good Condition' }
    ],
    suppliers: [
      { id: 's1', name: 'National Office Depot', contact: 'Mark Reyes', email: 'sales@officedepot.com', phone: '+63 917 888 9900' },
      { id: 's2', name: 'Executive Modern Furniture', contact: 'Sarah Chen', email: 'orders@modfurniture.com', phone: '+63 918 333 4455' }
    ],
    pos: [
      { id: 'p1', poNumber: 'PO-2026-001', supplierId: 's1', supplierName: 'National Office Depot', itemCode: 'Hard Copy Bond Paper', qty: 120, status: 'Completed' }
    ],
    users: [
      { id: 'u1', username: 'admin', passwordHash: hashPassword('adminpassword'), name: 'Clara Oswald (Admin Manager)', email: 'coswald@company.com', role: 'Admin' },
      { id: 'u2', username: 'staff_john', passwordHash: hashPassword('userpassword'), name: 'John Doe (Admin Assistant)', email: 'jdoe@company.com', role: 'Standard User' }
    ],
    audit: [{ id: 'a1', timestamp: new Date().toISOString(), user: 'System', action: 'SupplyOps Office System Initialized' }]
  };
}

function loadDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    const db = defaultDb();
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    console.log('[db] Created new database at ' + DB_FILE);
    return db;
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    console.error('[db] Corrupt db.json, starting fresh:', e.message);
    const db = defaultDb();
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    return db;
  }
}

let db = loadDb();

// Simple write queue so concurrent requests don't clobber each other
let savePending = false;
function saveDb() {
  if (savePending) return;
  savePending = true;
  setImmediate(function () {
    savePending = false;
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    } catch (e) {
      console.error('[db] Save failed:', e.message);
    }
  });
}

/* ---------------- Auth & sessions ---------------- */

const sessions = new Map(); // token -> userId
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId, expires: Date.now() + TOKEN_TTL_MS });
  return token;
}

function sanitizeUser(u) {
  if (!u) return null;
  const { passwordHash, ...rest } = u;
  return rest;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const session = sessions.get(token);
  if (Date.now() > session.expires) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
  req.user = db.users.find((u) => u.id === session.userId) || null;
  if (!req.user) {
    sessions.delete(token);
    return res.status(401).json({ error: 'User no longer exists' });
  }
  next();
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin role required' });
  }
  next();
}

function audit(action, user) {
  db.audit.unshift({
    id: crypto.randomBytes(6).toString('hex'),
    timestamp: new Date().toISOString(),
    user: user ? user.username : 'System',
    action: action
  });
  // Keep log bounded
  if (db.audit.length > 5000) db.audit.length = 5000;
}

/* ---------------- App ---------------- */

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.users.find((u) => u.username.toLowerCase() === String(username).toLowerCase());
  if (!user || !verifyPassword(password, user.passwordHash)) {
    audit('Failed login attempt for "' + username + '"', null);
    saveDb();
    return res.status(401).json({ error: 'Invalid Username or Password' });
  }

  const token = createSession(user.id);
  audit('User logged in (' + user.role + ')', user);
  saveDb();
  res.json({ token, user: sanitizeUser(user) });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  const token = (req.headers.authorization || '').slice(7);
  sessions.delete(token);
  audit('User logged out', req.user);
  saveDb();
  res.json({ ok: true });
});

// Full state snapshot (users sanitized)
app.get('/api/state', authMiddleware, (req, res) => {
  res.json({
    items: db.items,
    suppliers: db.suppliers,
    pos: db.pos,
    users: db.users.map(sanitizeUser),
    audit: req.user.role === 'Admin' ? db.audit : []
  });
});

/* ---- Generic CRUD factory for items / suppliers / pos ---- */

function crudRoutes(name, label) {
  const r = express.Router();
  r.use(authMiddleware);

  r.post('/', (req, res) => {
    const data = req.body || {};
    data.id = crypto.randomBytes(8).toString('hex');
    db[name].push(data);
    audit('Added new ' + label, req.user);
    saveDb();
    res.json(data);
  });

  r.put('/:id', (req, res) => {
    const idx = db[name].findIndex((x) => x.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    const updated = Object.assign({}, db[name][idx], req.body, { id: req.params.id });
    db[name][idx] = updated;
    audit('Updated ' + label, req.user);
    saveDb();
    res.json(updated);
  });

  r.delete('/:id', (req, res) => {
    const before = db[name].length;
    db[name] = db[name].filter((x) => x.id !== req.params.id);
    if (db[name].length === before) return res.status(404).json({ error: 'Not found' });
    audit('Deleted ' + label, req.user);
    saveDb();
    res.json({ ok: true });
  });

  return r;
}

app.use('/api/items', crudRoutes('items', 'supply/asset item'));
app.use('/api/suppliers', crudRoutes('suppliers', 'supplier'));
app.use('/api/pos', crudRoutes('pos', 'purchase order'));

/* ---- Users (Admin only) ---- */

const usersRouter = express.Router();
usersRouter.use(authMiddleware, adminOnly);

usersRouter.post('/', (req, res) => {
  const { username, password, name, email, role } = req.body || {};
  if (!username || !password || !name) return res.status(400).json({ error: 'Username, Password and Full Name are required' });
  if (db.users.some((u) => u.username.toLowerCase() === String(username).toLowerCase())) {
    return res.status(409).json({ error: 'Username already exists' });
  }
  const user = {
    id: crypto.randomBytes(8).toString('hex'),
    username,
    name,
    email: email || '',
    role: role === 'Admin' ? 'Admin' : 'Standard User',
    passwordHash: hashPassword(password)
  };
  db.users.push(user);
  audit('Created user: ' + username, req.user);
  saveDb();
  res.json(sanitizeUser(user));
});

usersRouter.put('/:id', (req, res) => {
  const idx = db.users.findIndex((u) => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const existing = db.users[idx];
  const { username, password, name, email, role } = req.body || {};
  const newUsername = (username || existing.username).trim();
  if (db.users.some((u) => u.username.toLowerCase() === newUsername.toLowerCase() && u.id !== req.params.id)) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  const updated = Object.assign({}, existing, {
    username: newUsername,
    name: name || existing.name,
    email: email != null ? email : existing.email,
    role: role === 'Admin' ? 'Admin' : 'Standard User'
  });
  if (password) updated.passwordHash = hashPassword(password); // re-hash only if changed

  // Safety: never demote or lock out the last Admin
  const admins = db.users.filter((u) => u.role === 'Admin');
  if (existing.role === 'Admin' && (updated.role !== 'Admin') && admins.length <= 1) {
    return res.status(400).json({ error: 'Cannot demote the last remaining Admin' });
  }

  db.users[idx] = updated;
  audit('Updated user: ' + updated.username, req.user);

  // Kill that user's other sessions if their credentials/role changed materially
  if (password || existing.role !== updated.role || existing.username !== updated.username) {
    for (const [tok, s] of sessions) if (s.userId === updated.id) sessions.delete(tok);
  }
  saveDb();
  res.json(sanitizeUser(updated));
});

usersRouter.delete('/:id', (req, res) => {
  const target = db.users.find((u) => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own logged-in user' });
  if (target.role === 'Admin' && db.users.filter((u) => u.role === 'Admin').length <= 1) {
    return res.status(400).json({ error: 'Cannot delete the last remaining Admin' });
  }
  db.users = db.users.filter((u) => u.id !== req.params.id);
  for (const [tok, s] of sessions) if (s.userId === target.id) sessions.delete(tok);
  audit('Deleted user profile: ' + target.username, req.user);
  saveDb();
  res.json({ ok: true });
});

app.use('/api/users', usersRouter);

/* ---- Audit (append allowed for any logged-in user; read/clear admin only) ---- */

app.post('/api/audit', authMiddleware, (req, res) => {
  const action = String((req.body && req.body.action) || '').slice(0, 300);
  if (!action) return res.status(400).json({ error: 'Action text required' });
  audit(action, req.user);
  saveDb();
  res.json({ ok: true });
});

app.get('/api/audit', authMiddleware, adminOnly, (req, res) => {
  res.json(db.audit);
});

app.delete('/api/audit', authMiddleware, adminOnly, (req, res) => {
  db.audit = [];
  audit('Cleared the Audit Trail', req.user);
  saveDb();
  res.json({ ok: true });
});

/* ---- Server-side JSON backup / restore (Admin only) ---- */

app.get('/api/backup', authMiddleware, adminOnly, (req, res) => {
  res.json({
    exportedAt: new Date().toISOString(),
    items: db.items,
    suppliers: db.suppliers,
    pos: db.pos,
    users: db.users.map(sanitizeUser),
    audit: db.audit
  });
});

app.post('/api/restore', authMiddleware, adminOnly, (req, res) => {
  const d = req.body || {};
  let restored = [];
  if (Array.isArray(d.items)) { db.items = d.items; restored.push('items'); }
  if (Array.isArray(d.suppliers)) { db.suppliers = d.suppliers; restored.push('suppliers'); }
  if (Array.isArray(d.pos)) { db.pos = d.pos; restored.push('pos'); }
  if (Array.isArray(d.audit)) { db.audit = d.audit; restored.push('audit'); }
  // NOTE: users are NOT restored from file — passwords in old exports were plaintext
  // and importing them would break hashing. Manage users via the User Profiles page.
  audit('Restored JSON backup (' + (restored.join(', ') || 'nothing valid found') + ')', req.user);
  saveDb();
  res.json({ ok: true, restored });
});

/* ---- Start ---- */

app.listen(PORT, '0.0.0.0', () => {
  console.log('==========================================================');
  console.log('  SupplyOps server running');
  console.log('  On this PC:   http://localhost:' + PORT);
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        console.log('  On your LAN:  http://' + net.address + ':' + PORT);
      }
    }
  }
  console.log('  Default login: admin / adminpassword  (CHANGE IT after first login!)');
  console.log('==========================================================');
});

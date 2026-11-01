// I'm at 1% — Live Battery Assistance (v4). Express + WebSocket + encrypted free persistence (GitHub Gist) or local file.
"use strict";
const express = require("express"), http = require("http"), path = require("path"), fs = require("fs");
const crypto = require("crypto"), bcrypt = require("bcryptjs"), jwt = require("jsonwebtoken");
const { WebSocketServer } = require("ws");
const { createStorage } = require("./storage");

const PORT = process.env.PORT || 3000;
const ADMINS = (process.env.ADMIN_EMAIL || "").toLowerCase().split(",").map((x) => x.trim()).filter(Boolean);
const DATA_DIR = process.env.DATA_DIR || __dirname;
const STALE_MS = 90e3, REQUEST_TTL = 6 * 3600e3;
const uuid = () => crypto.randomUUID();
fs.mkdirSync(DATA_DIR, { recursive: true });

// Secret: env var, else generated once next to the data. In Gist mode it MUST be set (it also encrypts the stored data).
const GIST_MODE = !!(process.env.GIST_ID && process.env.GITHUB_TOKEN);
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  if (GIST_MODE) { console.error("JWT_SECRET must be set when using GIST_ID/GITHUB_TOKEN (it encrypts your data)."); process.exit(1); }
  const f = path.join(DATA_DIR, ".jwt_secret");
  try { return fs.readFileSync(f, "utf8").trim(); } catch (_) {}
  const s = crypto.randomBytes(48).toString("hex");
  try { fs.writeFileSync(f, s, { mode: 0o600 }); } catch (_) {}
  return s;
})();
const storage = createStorage({ dataDir: DATA_DIR, gistId: process.env.GIST_ID, token: process.env.GITHUB_TOKEN, secret: process.env.STORAGE_KEY || JWT_SECRET });

// ---------- in-memory db, saved through the storage layer (debounced) ----------
let db = { users: {}, requests: {}, messages: {}, reports: [], banned: [] };
const presence = new Map(), locations = new Map(); // presence & location are memory-only, never saved
const byPair = new Map(); // pair -> messages[] (index)
function indexMessages() { byPair.clear(); Object.values(db.messages).sort((a, b) => a.createdAt - b.createdAt).forEach((m) => { if (!byPair.has(m.pair)) byPair.set(m.pair, []); byPair.get(m.pair).push(m); }); }
let saveTimer = null;
function persist() { if (!saveTimer) saveTimer = setTimeout(flush, storage.remote ? 15000 : 400); }
async function flush() { saveTimer = null; try { await storage.save(db); } catch (e) { console.error("Save failed (will retry):", e.message); persist(); } }
async function flushFinal() { clearTimeout(saveTimer); saveTimer = null; try { await storage.save(db); } catch (e) { console.error("Final save failed:", e.message); } }

// ---------- helpers ----------
const isLive = (id) => Date.now() - (presence.get(id) || 0) < STALE_MS;
const touch = (id) => presence.set(id, Date.now());
const blockedEither = (a, b) => !!(db.users[a]?.blocked.includes(b) || db.users[b]?.blocked.includes(a));
function removeUser(id) {
  delete db.users[id]; for (const x of Object.values(db.users)) x.blocked = (x.blocked || []).filter((i) => i !== id);
  presence.delete(id); locations.delete(id);
  for (const r of Object.values(db.requests)) if (r.userId === id) delete db.requests[r.id];
  for (const m of Object.values(db.messages)) if (m.from === id || m.to === id) delete db.messages[m.id];
  db.reports = db.reports.filter((r) => r.reporter !== id && r.reported !== id);
  indexMessages(); persist(); usersChanged(); broadcast({ type: "requests:update" });
  for (const ws of sockets.get(id) || []) ws.close(4001, "removed");
}
const isAdmin = (u) => ADMINS.includes(u.email);
const pairOf = (a, b) => [a, b].sort().join("_");
const num = (v, lo, hi) => typeof v === "number" && Number.isFinite(v) && v >= lo && v <= hi;
const clean = (s, n) => String(s ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n);
function publicUser(u) {
  const live = isLive(u.id), loc = live && locations.get(u.id);
  return { id: u.id, name: u.name, role: u.role, helperAvailable: u.helperAvailable, online: live, lat: loc ? loc.lat : null, lng: loc ? loc.lng : null, updatedAt: presence.get(u.id) || null };
}
const sign = (u) => jwt.sign({ uid: u.id, tv: u.tv }, JWT_SECRET, { expiresIn: "30d" });
function verify(token) {
  const { uid, tv } = jwt.verify(token, JWT_SECRET), u = db.users[uid];
  if (!u || (u.tv || 0) !== (tv || 0)) throw new Error("invalid");
  return u;
}

// ---------- realtime ----------
const app = express(), server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws", maxPayload: 4096 });
const sockets = new Map(); // uid -> Set<ws>
function sendTo(uid, payload) { const m = JSON.stringify(payload); for (const ws of sockets.get(uid) || []) if (ws.readyState === 1) ws.send(m); }
function broadcast(payload) { const m = JSON.stringify(payload); for (const set of sockets.values()) for (const ws of set) if (ws.readyState === 1) ws.send(m); }
let usersTimer = null; // coalesce bursts of presence/location changes into one push
function usersChanged() { if (usersTimer) return; usersTimer = setTimeout(() => { usersTimer = null; broadcast({ type: "users:update" }); }, 700); }

wss.on("connection", (ws, req) => {
  let u; try { u = verify(new URL(req.url, "http://x").searchParams.get("token")); } catch (_) { return ws.close(4001, "bad token"); }
  const set = sockets.get(u.id) || sockets.set(u.id, new Set()).get(u.id);
  if (set.size >= 5) set.values().next().value.close(4002, "too many connections");
  set.add(ws); ws.alive = true; touch(u.id); usersChanged();
  ws.on("pong", () => { ws.alive = true; });
  ws.on("message", (raw) => { // typing indicator relay
    try { const m = JSON.parse(raw); if (m.type === "typing" && db.users[m.to]) sendTo(m.to, { type: "typing", from: u.id }); } catch (_) {}
  });
  ws.on("close", () => { set.delete(ws); if (!set.size) sockets.delete(u.id); });
});
setInterval(() => wss.clients.forEach((ws) => { if (!ws.alive) return ws.terminate(); ws.alive = false; ws.ping(); }), 30e3).unref();
setInterval(() => { // sweeper: expire stale presence & old pending requests
  let changed = false;
  for (const [id, t] of presence) if (Date.now() - t >= STALE_MS && locations.delete(id)) changed = true;
  for (const r of Object.values(db.requests)) if (r.status === "Pending" && Date.now() - r.createdAt > REQUEST_TTL) { r.status = "Expired"; changed = true; persist(); broadcast({ type: "requests:update" }); }
  if (changed) usersChanged();
}, 30e3).unref();
setInterval(() => { // retention: keep the stored data (and the free Gist) small
  const now = Date.now(); let changed = false;
  for (const r of Object.values(db.requests)) if (r.status !== "Pending" && r.status !== "Accepted" && now - (r.closedAt || r.createdAt) > 30 * 864e5) { delete db.requests[r.id]; changed = true; }
  for (const m of Object.values(db.messages)) if (now - m.createdAt > 90 * 864e5) { delete db.messages[m.id]; changed = true; }
  const n = db.reports.length; db.reports = db.reports.filter((r) => now - r.createdAt < 180 * 864e5); if (db.reports.length !== n) changed = true;
  if (changed) { indexMessages(); persist(); }
}, 3600e3).unref();

// ---------- middleware ----------
const CDN = "https://unpkg.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net";
const CSP = `default-src 'self'; script-src 'self' 'unsafe-inline' ${CDN}; style-src 'self' 'unsafe-inline' ${CDN}; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self' ws: wss: https://router.project-osrm.org; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`;
app.disable("x-powered-by"); app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.set({ "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin", "Permissions-Policy": "geolocation=(self)" });
  if (req.secure) res.set("Strict-Transport-Security", "max-age=15552000");
  next();
});
app.use(express.json({ limit: "10kb" }), express.text({ type: "text/plain", limit: "2kb" }));
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
function limiter(max, windowMs, keyFn = (r) => r.ip) {
  const hits = new Map(); setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, windowMs).unref();
  return (req, res, next) => {
    const k = keyFn(req), n = Date.now(); let h = hits.get(k);
    if (!h || h.reset < n) hits.set(k, (h = { c: 0, reset: n + windowMs }));
    if (++h.c > max) return res.set("Retry-After", Math.ceil((h.reset - n) / 1000)).status(429).json({ error: "Too many attempts. Please slow down and try again shortly." });
    next();
  };
}
const authLimit = limiter(15, 15 * 60e3);
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "Not signed in." });
  try { req.user = verify(h.slice(7)); req.uid = req.user.id; next(); }
  catch (_) { res.status(401).json({ error: "Session expired. Please log in again." }); }
}
const apiLimit = limiter(240, 60e3, (r) => r.uid || r.ip);
app.get("/healthz", (req, res) => res.json({ ok: true, storage: storage.mode, users: Object.keys(db.users).length, online: [...presence.keys()].filter(isLive).length }));

// ---------- auth ----------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const DUMMY_HASH = bcrypt.hashSync("dummy-password", 10);
app.post("/api/auth/register", authLimit, ah(async (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase(), password = String(req.body.password || "");
  const name = clean(req.body.name, 60) || email.split("@")[0];
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "Please enter a valid email address." });
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: "Password must be 8–72 characters." });
  if (db.banned.includes(email)) return res.status(403).json({ error: "This email can't be used to register." });
  if (Object.values(db.users).some((u) => u.email === email)) return res.status(409).json({ error: "That account already exists. Log in instead." });
  const id = uuid();
  db.users[id] = { id, email, passwordHash: await bcrypt.hash(password, 11), name, role: "Student", helperAvailable: false, tv: 0, blocked: [], createdAt: Date.now() };
  touch(id); persist(); usersChanged();
  res.json({ token: sign(db.users[id]), user: publicUser(db.users[id]) });
}));
app.post("/api/auth/login", authLimit, ah(async (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase(), password = String(req.body.password || "").slice(0, 72);
  const u = Object.values(db.users).find((x) => x.email === email);
  const ok = await bcrypt.compare(password, u ? u.passwordHash : DUMMY_HASH); // constant-ish time: no user enumeration
  if (!u || !ok) return res.status(401).json({ error: "Account not found or password is incorrect." });
  touch(u.id); usersChanged();
  res.json({ token: sign(u), user: publicUser(u) });
}));

// ---------- profile / presence ----------
app.use("/api", (req, res, next) => (req.path.startsWith("/auth/") || req.path === "/offline" ? next() : auth(req, res, () => apiLimit(req, res, next))));
const me = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, helperAvailable: u.helperAvailable, admin: isAdmin(u) });
app.get("/api/me", (req, res) => res.json(me(req.user)));
app.put("/api/me", (req, res) => {
  const u = req.user, b = req.body;
  if (clean(b.name, 60)) u.name = clean(b.name, 60);
  if (["Student", "Helper", "Both"].includes(b.role)) u.role = b.role;
  if (typeof b.helperAvailable === "boolean") u.helperAvailable = b.helperAvailable;
  touch(u.id); persist(); usersChanged(); res.json(me(u));
});
app.post("/api/me/password", ah(async (req, res) => {
  const u = req.user, next = String(req.body.newPassword || "");
  if (!(await bcrypt.compare(String(req.body.password || ""), u.passwordHash))) return res.status(403).json({ error: "Current password is incorrect." });
  if (next.length < 8 || next.length > 72) return res.status(400).json({ error: "New password must be 8–72 characters." });
  u.passwordHash = await bcrypt.hash(next, 11); u.tv++; persist(); // invalidates all other sessions
  res.json({ token: sign(u) });
}));
app.delete("/api/me", ah(async (req, res) => {
  const u = req.user;
  if (!(await bcrypt.compare(String(req.body.password || ""), u.passwordHash))) return res.status(403).json({ error: "Password is incorrect." });
  removeUser(u.id);
  res.json({ ok: true });
}));
app.post("/api/location", (req, res) => {
  const { lat, lng } = req.body;
  if (lat === null && lng === null) locations.delete(req.uid);
  else if (num(lat, -90, 90) && num(lng, -180, 180)) locations.set(req.uid, { lat, lng });
  else return res.status(400).json({ error: "Invalid coordinates." });
  touch(req.uid); usersChanged(); res.json({ ok: true });
});
app.post("/api/heartbeat", (req, res) => { const was = isLive(req.uid); touch(req.uid); if (!was) usersChanged(); res.json({ ok: true }); });
app.post("/api/offline", (req, res) => { // sendBeacon: token in text/plain body (or ?token= for older clients)
  try {
    const raw = typeof req.body === "string" ? req.body : req.body && req.body.token;
    const u = verify(req.query.token || raw);
    presence.delete(u.id); locations.delete(u.id); usersChanged();
  } catch (_) {}
  res.json({ ok: true });
});
app.get("/api/blocked", (req, res) => res.json(req.user.blocked.filter((id) => db.users[id]).map((id) => ({ id, name: db.users[id].name }))));
app.post("/api/block", (req, res) => {
  const id = String(req.body.id || ""); if (!db.users[id] || id === req.uid) return res.status(400).json({ error: "Invalid user." });
  const b = req.user.blocked, i = b.indexOf(id);
  if (req.body.block === false) { if (i >= 0) b.splice(i, 1); } else if (i < 0) b.push(id);
  persist(); usersChanged(); broadcast({ type: "requests:update" }); res.json({ ok: true });
});
app.post("/api/report", limiter(10, 3600e3, (r) => r.uid), (req, res) => {
  const id = String(req.body.id || ""); if (!db.users[id] || id === req.uid) return res.status(400).json({ error: "Invalid user." });
  db.reports.push({ id: uuid(), reporter: req.uid, reported: id, reason: clean(req.body.reason, 500), createdAt: Date.now() }); persist();
  console.log(`[report] ${req.uid} reported ${id}`); res.json({ ok: true });
});
const adminOnly = (req, res, next) => (isAdmin(req.user) ? next() : res.status(403).json({ error: "Admins only." }));
app.get("/api/admin/reports", adminOnly, (req, res) => res.json(db.reports.slice(-100).reverse().map((r) => ({ id: r.id, reason: r.reason, createdAt: r.createdAt, reported: { id: r.reported, name: db.users[r.reported]?.name || "(deleted)" }, reporter: db.users[r.reporter]?.name || "(deleted)" }))));
app.post("/api/admin/dismiss", adminOnly, (req, res) => { db.reports = db.reports.filter((r) => r.id !== req.body.id); persist(); res.json({ ok: true }); });
app.post("/api/admin/remove", adminOnly, (req, res) => {
  const t = db.users[String(req.body.id || "")]; if (!t || isAdmin(t)) return res.status(400).json({ error: "Can't remove that user." });
  db.banned.push(t.email); removeUser(t.id); res.json({ ok: true });
});
app.get("/api/users", (req, res) => res.json(Object.values(db.users).filter((u) => u.id !== req.uid && !blockedEither(u.id, req.uid)).map(publicUser)));

// ---------- requests ----------
const canSee = (r, u) => !blockedEither(r.userId, u.id) && (r.userId === u.id || r.helperId === u.id || (u.helperAvailable && r.status === "Pending"));
app.get("/api/requests", (req, res) => res.json(Object.values(db.requests).filter((r) => canSee(r, req.user)).sort((a, b) => b.createdAt - a.createdAt).slice(0, 200)));
app.post("/api/requests", (req, res) => {
  const open = Object.values(db.requests).find((r) => r.userId === req.uid && (r.status === "Pending" || r.status === "Accepted"));
  if (open) return res.status(409).json({ error: "You already have an open request. Resolve or cancel it first." });
  const allowedResources = ["Power Bank", "Charger", "Laptop Charger", "USB-C Cable", "Lightning Cable", "Micro-USB Cable", "Wall Charger", "Charging Adapter", "Universal Travel Adapter", "Charging Outlet"];
  const resource = allowedResources.includes(req.body.resource) ? req.body.resource : "Power Bank";
  const r = { id: uuid(), userId: req.uid, battery: Math.max(1, Math.min(100, Math.round(Number(req.body.battery)) || 1)), resource, note: clean(req.body.note, 300), status: "Pending", helperId: null, createdAt: Date.now() };
  db.requests[r.id] = r; persist(); broadcast({ type: "requests:update" });
  for (const u of Object.values(db.users)) if (u.helperAvailable && u.id !== req.uid && !blockedEither(u.id, req.uid)) sendTo(u.id, { type: "request:new", name: req.user.name, battery: r.battery, resource });
  res.json(r);
});
function loadReq(req, res) { const r = db.requests[req.params.id]; if (!r || !canSee(r, req.user)) { res.status(404).json({ error: "Request not found." }); return null; } return r; }
app.post("/api/requests/:id/accept", (req, res) => {
  const r = loadReq(req, res); if (!r) return;
  if (r.userId === req.uid) return res.status(400).json({ error: "You can't accept your own request." });
  if (!req.user.helperAvailable) return res.status(403).json({ error: "Turn on “Available as helper” in your profile first." });
  if (r.status !== "Pending") return res.status(409).json({ error: "Someone else already accepted this request." });
  r.status = "Accepted"; r.helperId = req.uid; r.acceptedAt = Date.now();
  addMessage(req.uid, r.userId, `Hi! I can help with your ${r.resource}.`);
  persist(); broadcast({ type: "requests:update" }); res.json(r);
});
const finish = (status) => (req, res) => {
  const r = loadReq(req, res); if (!r) return;
  if (r.userId !== req.uid && !(status === "Resolved" && r.helperId === req.uid)) return res.status(403).json({ error: "Not allowed." });
  if (r.status !== "Pending" && r.status !== "Accepted") return res.status(409).json({ error: `Request is already ${r.status.toLowerCase()}.` });
  r.status = status; r.closedAt = Date.now(); persist(); broadcast({ type: "requests:update" }); res.json(r);
};
app.post("/api/requests/:id/resolve", finish("Resolved"));
app.post("/api/requests/:id/cancel", finish("Cancelled"));

// ---------- messages ----------
function addMessage(from, to, text) {
  const pair = pairOf(from, to), m = { id: uuid(), from, to, pair, text, createdAt: Date.now(), readAt: null };
  db.messages[m.id] = m; if (!byPair.has(pair)) byPair.set(pair, []); byPair.get(pair).push(m);
  sendTo(to, { type: "message:new", pair, from }); sendTo(from, { type: "message:new", pair, from });
  return m;
}
app.get("/api/conversations", (req, res) => { // last message + unread count per person
  const out = [];
  for (const [pair, list] of byPair) {
    if (!pair.split("_").includes(req.uid) || !list.length) continue;
    const last = list[list.length - 1], other = last.from === req.uid ? last.to : last.from;
    out.push({ with: other, last: { text: last.text, from: last.from, createdAt: last.createdAt }, unread: list.filter((m) => m.to === req.uid && !m.readAt).length });
  }
  res.json(out.sort((a, b) => b.last.createdAt - a.last.createdAt));
});
app.get("/api/messages", (req, res) => {
  const w = String(req.query.with || ""); if (!db.users[w]) return res.status(400).json({ error: "Unknown user." });
  res.json((byPair.get(pairOf(req.uid, w)) || []).slice(-200));
});
app.post("/api/messages/read", (req, res) => {
  const w = String(req.body.with || ""), now = Date.now(); let n = 0;
  for (const m of byPair.get(pairOf(req.uid, w)) || []) if (m.to === req.uid && !m.readAt) { m.readAt = now; n++; }
  if (n) { persist(); sendTo(w, { type: "message:read", by: req.uid }); }
  res.json({ ok: true });
});
app.post("/api/messages", limiter(60, 60e3, (r) => r.uid), (req, res) => {
  const to = String(req.body.to || ""), text = clean(req.body.text, 1000);
  if (!db.users[to] || to === req.uid || !text || blockedEither(req.uid, to)) return res.status(400).json({ error: "Invalid message." });
  persist(); res.json(addMessage(req.uid, to, text));
});

// ---------- static / errors ----------
app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h", setHeaders: (res, p) => { if (/\.(html|js)$/.test(p)) res.setHeader("Cache-Control", "no-cache"); } }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err.type === "entity.parse.failed" || err.type === "entity.too.large") return res.status(400).json({ error: "Bad request body." });
  console.error(err); res.status(500).json({ error: "Something went wrong on the server." });
});

async function boot() {
  let loaded = null;
  for (let i = 1; ; i++) { // never start with an empty db if the stored one exists but couldn't be read — that would overwrite it
    try { loaded = await storage.load(); break; } catch (e) { console.error(`Storage load failed (${i}/4):`, e.message); if (i >= 4) process.exit(1); await new Promise((r) => setTimeout(r, 1500 * i)); }
  }
  db = { ...db, ...(loaded || {}) };
  for (const u of Object.values(db.users)) { u.tv = u.tv || 0; u.blocked = u.blocked || []; delete u.online; delete u.lat; delete u.lng; }
  indexMessages();
  server.listen(PORT, () => console.log(`I'm at 1% listening on http://localhost:${PORT} — storage: ${storage.mode}${ADMINS.length ? " — admin: " + ADMINS.join(",") : ""}`));
}
boot();

async function shutdown() { await Promise.race([flushFinal(), new Promise((r) => setTimeout(r, 5000))]); process.exit(0); } // Render sends SIGTERM before sleeping/redeploying
process.on("SIGINT", shutdown); process.on("SIGTERM", shutdown);

// مسواک سولیماکس — سێرڤەری لیستی ماددە تەواوبووەکان
// Zero-dependency Node.js server (Node 18+). Data is kept in data/db.json.
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const PUBLIC_DIR = __dirname;
const ALLOWED = new Set(["/index.html","/sw.js","/manifest.webmanifest","/icon-192.png","/icon-512.png","/icon-maskable-512.png","/apple-touch-icon.png"]);
const SESSION_DAYS = 90;

// ---------- storage ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { users: [], items: [], sessions: [] };
if (fs.existsSync(DB_FILE)) {
  db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = DB_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(db, null, 1));
    fs.renameSync(tmp, DB_FILE);
  }, 50);
}
function saveNow() { clearTimeout(saveTimer); const tmp = DB_FILE + ".tmp"; fs.writeFileSync(tmp, JSON.stringify(db, null, 1)); fs.renameSync(tmp, DB_FILE); }

const newId = () => crypto.randomBytes(9).toString("base64url");
function hashPassword(pw, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(pw), salt, 64).toString("hex");
  return { salt, hash };
}
function checkPassword(pw, user) {
  const { hash } = hashPassword(pw, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.hash, "hex"));
}

// First run: create the admin (committee) account.
if (!db.users.length) {
  const username = (process.env.ADMIN_USER || "admin").toLowerCase();
  const password = process.env.ADMIN_PASS || "solimax123";
  db.users.push({ id: newId(), username, name: "لیژنە", role: "admin", ...hashPassword(password), createdAt: Date.now() });
  saveNow();
  console.log(`Admin account created → username: ${username}  password: ${password}  (change it after first login)`);
}

// ---------- helpers ----------
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json", ".webmanifest": "application/manifest+json", ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon" };

function send(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(data);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > 100000) { reject(new Error("too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}
const clean = (s, max) => String(s ?? "").trim().slice(0, max);
const publicUser = u => ({ id: u.id, username: u.username, name: u.name, role: u.role });

function auth(req) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return null;
  const s = db.sessions.find(x => x.token === token);
  if (!s || s.expires < Date.now()) return null;
  return db.users.find(u => u.id === s.userId) || null;
}

// simple login rate limit per IP
const attempts = new Map();
function limited(ip) {
  const now = Date.now(), a = attempts.get(ip) || { n: 0, t: now };
  if (now - a.t > 15 * 60 * 1000) { a.n = 0; a.t = now; }
  a.n++; attempts.set(ip, a);
  return a.n > 20;
}

// ---------- API ----------
async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  let body = {};
  if (m === "POST" || m === "PATCH") {
    try { body = await readBody(req); } catch { return send(res, 400, { error: "داواکارییەکە هەڵەیە" }); }
  }

  if (p === "/api/login" && m === "POST") {
    const ip = req.socket.remoteAddress;
    if (limited(ip)) return send(res, 429, { error: "هەوڵی زۆرت دا، ١٥ خولەک چاوەڕێ بکە" });
    const u = db.users.find(x => x.username === clean(body.username, 40).toLowerCase());
    if (!u || !checkPassword(body.password || "", u)) return send(res, 401, { error: "ناوی بەکارهێنەر یان وشەی نهێنی هەڵەیە" });
    const token = crypto.randomBytes(32).toString("base64url");
    db.sessions = db.sessions.filter(s => s.expires > Date.now());
    db.sessions.push({ token, userId: u.id, expires: Date.now() + SESSION_DAYS * 864e5 });
    save();
    return send(res, 200, { token, user: publicUser(u) });
  }

  const me = auth(req);
  if (!me) return send(res, 401, { error: "پێویستە سەرەتا بچیتە ژوورەوە" });
  const isAdmin = me.role === "admin";

  if (p === "/api/logout" && m === "POST") {
    const token = (req.headers.authorization || "").slice(7);
    db.sessions = db.sessions.filter(s => s.token !== token); save();
    return send(res, 200, { ok: true });
  }
  if (p === "/api/me" && m === "GET") return send(res, 200, { user: publicUser(me) });

  if (p === "/api/me/password" && m === "POST") {
    if (!checkPassword(body.old || "", me)) return send(res, 400, { error: "وشەی نهێنیی ئێستا هەڵەیە" });
    const np = String(body.new || "");
    if (np.length < 4) return send(res, 400, { error: "وشەی نهێنی دەبێت لانیکەم ٤ پیت بێت" });
    Object.assign(me, hashPassword(np)); save();
    return send(res, 200, { ok: true });
  }

  // items
  if (p === "/api/items" && m === "GET") {
    const names = Object.fromEntries(db.users.map(u => [u.id, u.name]));
    const items = db.items.slice().sort((a, b) => b.at - a.at).map(i => ({ ...i, byName: names[i.by] || "بەکارهێنەری سڕاوە", doneByName: i.doneBy ? (names[i.doneBy] || "") : "" }));
    return send(res, 200, { items, version: db.version || 0 });
  }
  if (p === "/api/items" && m === "POST") {
    const name = clean(body.name, 80), note = clean(body.note, 120);
    if (!name) return send(res, 400, { error: "ناوی ماددە بنووسە" });
    const item = { id: newId(), name, note, by: me.id, at: Date.now(), done: false, doneAt: null, doneBy: null };
    db.items.push(item); db.version = (db.version || 0) + 1; save();
    return send(res, 201, { item });
  }
  let mm = p.match(/^\/api\/items\/([\w-]+)$/);
  if (mm) {
    const item = db.items.find(i => i.id === mm[1]);
    if (!item) return send(res, 404, { error: "ماددەکە نەدۆزرایەوە" });
    if (m === "PATCH") {
      if (typeof body.done === "boolean") { item.done = body.done; item.doneAt = body.done ? Date.now() : null; item.doneBy = body.done ? me.id : null; }
      if ((item.by === me.id || isAdmin) && body.name !== undefined) { const n = clean(body.name, 80); if (n) item.name = n; }
      if ((item.by === me.id || isAdmin) && body.note !== undefined) item.note = clean(body.note, 120);
      db.version = (db.version || 0) + 1; save();
      return send(res, 200, { item });
    }
    if (m === "DELETE") {
      if (item.by !== me.id && !isAdmin) return send(res, 403, { error: "تەنها نووسەر یان لیژنە دەتوانێت بیسڕێتەوە" });
      db.items = db.items.filter(i => i !== item); db.version = (db.version || 0) + 1; save();
      return send(res, 200, { ok: true });
    }
  }

  // users (admin only)
  if (p.startsWith("/api/users")) {
    if (!isAdmin) return send(res, 403, { error: "تەنها لیژنە دەتوانێت بەکارهێنەران بەڕێوەببات" });
    if (p === "/api/users" && m === "GET") return send(res, 200, { users: db.users.map(publicUser) });
    if (p === "/api/users" && m === "POST") {
      const username = clean(body.username, 40).toLowerCase(), name = clean(body.name, 40), pw = String(body.password || "");
      if (!/^[a-z0-9_.-]{2,40}$/.test(username)) return send(res, 400, { error: "ناوی بەکارهێنەر تەنها پیتی ئینگلیزی و ژمارە بێت (لانیکەم ٢ پیت)" });
      if (!name) return send(res, 400, { error: "ناوی تەواو بنووسە" });
      if (pw.length < 4) return send(res, 400, { error: "وشەی نهێنی دەبێت لانیکەم ٤ پیت بێت" });
      if (db.users.some(u => u.username === username)) return send(res, 400, { error: "ئەم ناوی بەکارهێنەرە پێشتر هەیە" });
      const u = { id: newId(), username, name, role: body.role === "admin" ? "admin" : "user", ...hashPassword(pw), createdAt: Date.now() };
      db.users.push(u); save();
      return send(res, 201, { user: publicUser(u) });
    }
    mm = p.match(/^\/api\/users\/([\w-]+)$/);
    if (mm) {
      const u = db.users.find(x => x.id === mm[1]);
      if (!u) return send(res, 404, { error: "بەکارهێنەر نەدۆزرایەوە" });
      const admins = db.users.filter(x => x.role === "admin").length;
      if (m === "PATCH") {
        if (body.name !== undefined) { const n = clean(body.name, 40); if (n) u.name = n; }
        if (body.role !== undefined) {
          const r = body.role === "admin" ? "admin" : "user";
          if (u.role === "admin" && r === "user" && admins <= 1) return send(res, 400, { error: "دەبێت لانیکەم یەک ئەندامی لیژنە بمێنێت" });
          u.role = r;
        }
        if (body.password) {
          if (String(body.password).length < 4) return send(res, 400, { error: "وشەی نهێنی دەبێت لانیکەم ٤ پیت بێت" });
          Object.assign(u, hashPassword(body.password));
          db.sessions = db.sessions.filter(s => s.userId !== u.id || u.id === me.id);
        }
        save();
        return send(res, 200, { user: publicUser(u) });
      }
      if (m === "DELETE") {
        if (u.id === me.id) return send(res, 400, { error: "ناتوانیت خۆت بسڕیتەوە" });
        if (u.role === "admin" && admins <= 1) return send(res, 400, { error: "دەبێت لانیکەم یەک ئەندامی لیژنە بمێنێت" });
        db.users = db.users.filter(x => x !== u);
        db.sessions = db.sessions.filter(s => s.userId !== u.id); save();
        return send(res, 200, { ok: true });
      }
    }
  }
  return send(res, 404, { error: "نەدۆزرایەوە" });
}

// ---------- static ----------
function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);
  if (p === "/" || !ALLOWED.has(p)) p = "/index.html";
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (!file.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) {
      // single-page fallback
      return fs.readFile(path.join(PUBLIC_DIR, "index.html"), (e2, html) => {
        res.writeHead(e2 ? 404 : 200, { "Content-Type": MIME[".html"] }); res.end(e2 ? "Not found" : html);
      });
    }
    const ext = path.extname(file);
    const headers = { "Content-Type": MIME[ext] || "application/octet-stream" };
    headers["Cache-Control"] = (ext === ".html" || p === "/sw.js" || ext === ".webmanifest") ? "no-cache" : "public, max-age=604800";
    res.writeHead(200, headers); res.end(data);
  });
}

http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (url.pathname.startsWith("/api/")) {
    api(req, res, url).catch(err => { console.error(err); send(res, 500, { error: "هەڵەیەک لە سێرڤەر ڕوویدا" }); });
  } else serveStatic(req, res, url);
}).listen(PORT, () => console.log(`Solimax server running on http://localhost:${PORT}`));

process.on("SIGINT", () => { saveNow(); process.exit(0); });
process.on("SIGTERM", () => { saveNow(); process.exit(0); });

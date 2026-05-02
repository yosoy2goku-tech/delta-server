const http = require("http");
const fs   = require("fs");

const PORT       = process.env.PORT || 3000;
const KEYS_FILE  = "./keys.json";
const ADMIN_PASS = "delta2026";

function loadKeys() {
  if (!fs.existsSync(KEYS_FILE))
    fs.writeFileSync(KEYS_FILE, JSON.stringify({}, null, 2));
  return JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
}
function saveKeys(data) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(data, null, 2));
}

const CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function rand(n) {
  let s = "";
  for (let i = 0; i < n; i++)
    s += CHARS[Math.floor(Math.random() * CHARS.length)];
  return s;
}
function buildKey() {
  return `DELTA-${rand(4)}-${rand(4)}-${rand(4)}-${rand(4)}`;
}
function parseBody(req) {
  return new Promise(resolve => {
    let b = "";
    req.on("data", c => b += c);
    req.on("end", () => { try { resolve(JSON.parse(b)); } catch { resolve({}); } });
  });
}
function parseQuery(url) {
  const q = {}, idx = url.indexOf("?");
  if (idx === -1) return q;
  url.slice(idx + 1).split("&").forEach(p => {
    const [k, v] = p.split("=");
    q[decodeURIComponent(k)] = decodeURIComponent(v || "");
  });
  return q;
}
function respond(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Password"
  });
  res.end(JSON.stringify(data));
}
function isExpired(entry) {
  if (!entry.expiry) return false;
  return new Date() > new Date(entry.expiry);
}

http.createServer(async (req, res) => {
  const path   = req.url.split("?")[0];
  const query  = parseQuery(req.url);
  const method = req.method;

  if (method === "OPTIONS") {
    res.writeHead(204, { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type, X-Admin-Password" });
    return res.end();
  }

  if (method === "GET" && path === "/verify") {
    const key  = (query.key || "").toUpperCase().trim();
    const keys = loadKeys();
    if (!key) return respond(res, 400, { status: "ERROR", message: "Falta la key" });
    const entry = keys[key];
    if (!entry) return respond(res, 200, { status: "NOT_FOUND", message: "Key no existe" });
    if (isExpired(entry)) return respond(res, 200, { status: "EXPIRED", message: "Key expirada", expiry: entry.expiry });
    keys[key].last_used = new Date().toISOString();
    keys[key].uses = (keys[key].uses || 0) + 1;
    saveKeys(keys);
    return respond(res, 200, { status: "VALID", message: "Key activa", type: entry.type, expiry: entry.expiry || "Lifetime", uses: keys[key].uses });
  }

  if (method === "POST" && path === "/getkey") {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
    const keys = loadKeys();
    const existing = Object.entries(keys).find(([k, v]) => {
      return v.ip === ip && v.type === "USER" && !isExpired(v);
    });
    if (existing) {
      return respond(res, 200, { key: existing[0], expiry: existing[1].expiry, cached: true });
    }
    const key    = buildKey();
    const expiry = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
    keys[key] = { type: "USER", created: new Date().toISOString(), expiry, uses: 0, last_used: null, ip };
    saveKeys(keys);
    return respond(res, 200, { key, expiry, cached: false });
  }

  if (method === "POST" && path === "/generate") {
    if (req.headers["x-admin-password"] !== ADMIN_PASS) return respond(res, 403, { error: "Contrasena incorrecta" });
    const body   = await parseBody(req);
    const type   = body.type || "BASIC";
    const days   = parseInt(body.days ?? 30);
    const key    = buildKey();
    const expiry = days === 0 ? null : (() => { const d = new Date(); d.setDate(d.getDate() + days); return d.toISOString(); })();
    const keys   = loadKeys();
    keys[key]    = { type, created: new Date().toISOString(), expiry, uses: 0, last_used: null };
    saveKeys(keys);
    return respond(res, 200, { key, type, expiry: expiry || "Lifetime" });
  }

  if (method === "GET" && path === "/list") {
    if (req.headers["x-admin-password"] !== ADMIN_PASS) return respond(res, 403, { error: "Contrasena incorrecta" });
    const keys = loadKeys();
    const list = Object.entries(keys).map(([k, v]) => ({ key: k, ...v, expired: isExpired(v) }));
    return respond(res, 200, { total: list.length, keys: list });
  }

  if (method === "DELETE" && path === "/delete") {
    if (req.headers["x-admin-password"] !== ADMIN_PASS) return respond(res, 403, { error: "Contrasena incorrecta" });
    const key  = (query.key || "").toUpperCase().trim();
    const keys = loadKeys();
    if (!keys[key]) return respond(res, 404, { error: "Key no encontrada" });
    delete keys[key];
    saveKeys(keys);
    return respond(res, 200, { message: "Key eliminada" });
  }

  respond(res, 404, { error: "Ruta no existe" });

}).listen(PORT, "0.0.0.0", () => {
  console.log("DELTA Key Server corriendo en puerto " + PORT);
});

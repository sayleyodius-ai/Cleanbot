require("dotenv").config();
const express = require("express");
const session = require("express-session");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const QRCode = require("qrcode");
const { Server } = require("socket.io");
const { Client, LocalAuth } = require("whatsapp-web.js");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));
const PORT = Number(process.env.PORT || 3000);
const PASSWORD = process.env.DASHBOARD_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const AUTH_PATH = process.env.AUTH_PATH || path.join(__dirname, "..", "data", "whatsapp-auth");
const MIN_DELAY = Math.max(120, Number(process.env.MIN_DELAY_SECONDS || 120));
const HOURLY_LIMIT = Math.min(10, Math.max(1, Number(process.env.HOURLY_LIMIT || 10)));
const DAILY_LIMIT = Math.min(30, Math.max(1, Number(process.env.DAILY_LIMIT || 30)));

if (!PASSWORD || PASSWORD.length < 12) console.warn("WARNING: Set DASHBOARD_PASSWORD to a unique password of at least 12 characters.");
if (!SESSION_SECRET || SESSION_SECRET.length < 32) console.warn("WARNING: Set SESSION_SECRET to a random secret of at least 32 characters.");
fs.mkdirSync(AUTH_PATH, { recursive: true });
const GUARD_FILE = path.join(AUTH_PATH, "guard-state.json");
function loadGuardState() {
  try {
    const raw = JSON.parse(fs.readFileSync(GUARD_FILE, "utf8"));
    return {
      blacklisted: new Set(Array.isArray(raw.blacklisted) ? raw.blacklisted : []),
      sendTimes: Array.isArray(raw.sendTimes) ? raw.sendTimes.filter(t => Number.isFinite(t) && Date.now() - t < 24*60*60*1000) : [],
      lastSendAt: Number(raw.lastSendAt) || 0,
      recentHashes: new Map(Array.isArray(raw.recentHashes) ? raw.recentHashes.filter(([h,t]) => typeof h === "string" && Number.isFinite(t) && Date.now()-t < 24*60*60*1000) : [])
    };
  } catch (_) {
    return { blacklisted: new Set(), sendTimes: [], lastSendAt: 0, recentHashes: new Map() };
  }
}
const persistedGuards = loadGuardState();
function saveGuardState() {
  const temp = GUARD_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify({
    blacklisted: [...state.blacklisted],
    sendTimes: state.sendTimes,
    lastSendAt: state.lastSendAt,
    recentHashes: [...state.recentHashes.entries()]
  }), { mode: 0o600 });
  fs.renameSync(temp, GUARD_FILE);
}

const state = {
  status: "disconnected",
  qrDataUrl: null,
  phone: null,
  lastError: "",
  startedAt: null,
  client: null,
  queue: Promise.resolve(),
  sendTimes: persistedGuards.sendTimes,
  lastSendAt: persistedGuards.lastSendAt,
  blacklisted: persistedGuards.blacklisted,
  recentHashes: persistedGuards.recentHashes,
  logs: []
};
const log = (level, message) => {
  const item = { level, message: String(message).slice(0, 400), at: new Date().toISOString() };
  state.logs.unshift(item);
  state.logs = state.logs.slice(0, 100);
  console.log(`[${level}] ${item.message}`);
  io.emit("activity", item);
  io.emit("state", publicState());
};
const publicState = () => ({
  status: state.status,
  phone: state.phone,
  qrDataUrl: state.qrDataUrl,
  lastError: state.lastError,
  startedAt: state.startedAt,
  rate: rateState(),
  blacklist: [...state.blacklisted],
  logs: state.logs.slice(0, 30),
  connected: state.status === "connected"
});
function rateState() {
  const now = Date.now();
  state.sendTimes = state.sendTimes.filter(t => now - t < 24 * 60 * 60 * 1000);
  const hour = state.sendTimes.filter(t => now - t < 60 * 60 * 1000).length;
  const day = state.sendTimes.length;
  const wait = state.lastSendAt ? Math.max(0, MIN_DELAY - Math.floor((now - state.lastSendAt) / 1000)) : 0;
  return { hourlyUsed: hour, hourlyLimit: HOURLY_LIMIT, dailyUsed: day, dailyLimit: DAILY_LIMIT, delaySeconds: MIN_DELAY, secondsUntilNext: wait };
}
const sessionMiddleware = session({
  name: "waadmin.sid",
  secret: SESSION_SECRET || crypto.randomBytes(48).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000 }
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);
function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  if (req.path === "/login" || req.path === "/health") return next();
  return res.status(401).json({ error: "Konekte sou dashboard la an premye." });
}
app.get("/health", (req, res) => res.json({ ok: true, status: state.status }));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.post("/login", (req, res) => {
  const supplied = Buffer.from(String(req.body.password || ""));
  const expected = Buffer.from(PASSWORD);
  if (!PASSWORD || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    log("warn", "Echèk koneksyon dashboard.");
    return res.status(401).json({ error: "Modpas pa kòrèk." });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Pa kapab kreye sesyon." });
    req.session.authed = true;
    res.json({ ok: true });
  });
});
app.post("/logout", requireAuth, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.use("/api", requireAuth);
app.use("/", (req, res, next) => {
  if (req.path.startsWith("/api") || req.path === "/login" || req.path === "/health") return next();
  if (!req.session?.authed) return res.redirect("/login");
  next();
});
app.use(express.static(path.join(__dirname, "public")));

function emitState() { io.emit("state", publicState()); }
async function createClient() {
  if (state.client) return;
  state.status = "starting";
  state.lastError = "";
  state.qrDataUrl = null;
  emitState();
  const client = new Client({
    authStrategy: new LocalAuth({ clientId: "main", dataPath: AUTH_PATH }),
    puppeteer: {
      headless: true,
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium",
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
    },
    takeoverOnConflict: false,
    qrMaxRetries: 5
  });
  state.client = client;
  client.on("qr", async qr => {
    try {
      state.qrDataUrl = await QRCode.toDataURL(qr, { width: 300, margin: 2 });
      state.status = "qr";
      log("info", "QR Code pare. Eskane li nan WhatsApp > Aparèy ki konekte.");
      emitState();
    } catch (e) { state.lastError = e.message; log("error", "Pa kapab kreye QR: " + e.message); }
  });
  client.on("authenticated", () => {
    state.status = "authenticated";
    state.qrDataUrl = null;
    log("success", "WhatsApp otantifye; n ap tann koneksyon an fini.");
    emitState();
  });
  client.on("ready", () => {
    state.status = "connected";
    state.qrDataUrl = null;
    state.lastError = "";
    state.phone = client.info?.wid?.user || null;
    state.startedAt = new Date().toISOString();
    log("success", "WhatsApp konekte.");
    emitState();
  });
  client.on("auth_failure", msg => {
    state.status = "error";
    state.lastError = String(msg || "WhatsApp authentication failure");
    log("error", "Otantifikasyon echwe: " + state.lastError);
    emitState();
  });
  client.on("disconnected", reason => {
    state.status = "disconnected";
    state.phone = null;
    state.qrDataUrl = null;
    log("warn", "WhatsApp dekonekte: " + reason);
    emitState();
    // Fail closed: don't auto-retry endless connection loops.
  });
  try {
    await client.initialize();
  } catch (e) {
    state.status = "error";
    state.lastError = e.message;
    log("error", "Inisyalizasyon echwe: " + e.message);
    emitState();
  }
}
async function disconnectClient() {
  const client = state.client;
  state.client = null;
  state.status = "disconnected";
  state.phone = null;
  state.qrDataUrl = null;
  emitState();
  if (client) {
    try { await client.logout(); } catch (_) {}
    try { await client.destroy(); } catch (_) {}
  }
  log("info", "Bot la dekonekte sou demann admin.");
}
function normalizePhone(value) { return String(value || "").replace(/[^\d]/g, ""); }
function hashMessage(phone, text) {
  return crypto.createHash("sha256").update(phone + "\n" + text.trim()).digest("hex");
}
function guardMessage(phone, body) {
  if (state.status !== "connected" || !state.client) throw new Error("WhatsApp pa konekte.");
  if (!/^\d{8,15}$/.test(phone)) throw new Error("Mete nimewo entènasyonal la ak kòd peyi a, chif sèlman (8–15 chif).");
  if (state.blacklisted.has(phone)) throw new Error("Kontak sa a sou lis nwa.");
  if (!body || body.length > 4000) throw new Error("Mesaj la vid oswa li twò long.");
  const rate = rateState();
  if (rate.secondsUntilNext > 0) throw new Error(`Anti-spam: tann ${rate.secondsUntilNext} segonn.`);
  if (rate.hourlyUsed >= HOURLY_LIMIT) throw new Error("Limit pa èdtan rive.");
  if (rate.dailyUsed >= DAILY_LIMIT) throw new Error("Limit pa jou rive.");
  const hash = hashMessage(phone, body);
  const seen = state.recentHashes.get(hash);
  if (seen && Date.now() - seen < 24 * 60 * 60 * 1000) throw new Error("Menm mesaj la deja voye bay nimewo sa a nan 24 èdtan.");
  return hash;
}
function queueSend(phone, body) {
  const operation = async () => {
    const hash = guardMessage(phone, body);
    // Reserve the rate slot before sending to avoid concurrent sends bypassing limits.
    const now = Date.now();
    state.sendTimes.push(now);
    state.lastSendAt = now;
    state.recentHashes.set(hash, now);
    saveGuardState();
    try {
      const chatId = phone + "@c.us";
      await state.client.sendMessage(chatId, body, { sendSeen: false });
      log("success", `Mesaj voye bay ${phone}.`);
      return { ok: true };
    } catch (e) {
      state.recentHashes.delete(hash);
      state.sendTimes = state.sendTimes.filter(t => t !== now);
      saveGuardState();
      state.status = "error";
      state.lastError = e.message;
      log("error", "Voye mesaj echwe; bot la mete an poz: " + e.message);
      // Fail closed: disconnect to prevent further automated activity after send error.
      const client = state.client;
      state.client = null;
      try { if (client) await client.destroy(); } catch (_) {}
      throw new Error("Voye mesaj echwe. Bot la kanpe pou sekirite: " + e.message);
    } finally { saveGuardState(); emitState(); }
  };
  const result = state.queue.then(operation, operation);
  state.queue = result.catch(() => {});
  return result;
}

app.get("/api/state", (req, res) => res.json(publicState()));
app.post("/api/connect", async (req, res) => {
  if (state.client && ["starting", "qr", "authenticated", "connected"].includes(state.status)) {
    return res.json({ ok: true, status: state.status });
  }
  createClient().catch(e => log("error", e.message));
  res.json({ ok: true, status: "starting" });
});
app.post("/api/disconnect", async (req, res) => {
  await disconnectClient();
  res.json({ ok: true });
});
app.post("/api/send", async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const body = String(req.body.body || "").trim();
  try { res.json(await queueSend(phone, body)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.post("/api/blacklist", (req, res) => {
  const phone = normalizePhone(req.body.phone);
  if (!/^\d{8,15}$/.test(phone)) return res.status(400).json({ error: "Nimewo a dwe gen 8–15 chif ak kòd peyi." });
  state.blacklisted.add(phone);
  saveGuardState();
  log("info", `Kontak ajoute sou lis nwa: ${phone}`);
  res.json({ ok: true, blacklist: [...state.blacklisted] });
});
app.delete("/api/blacklist/:phone", (req, res) => {
  const phone = normalizePhone(req.params.phone);
  state.blacklisted.delete(phone);
  saveGuardState();
  log("info", `Kontak retire nan lis nwa: ${phone}`);
  res.json({ ok: true, blacklist: [...state.blacklisted] });
});
io.use((socket, next) => {
  if (socket.request.session?.authed) return next();
  next(new Error("Unauthorized"));
});
io.on("connection", socket => socket.emit("state", publicState()));

server.listen(PORT, () => {
  log("info", `Dashboard demare sou pò ${PORT}. Peze Konekte pou montre QR Code.`);
});

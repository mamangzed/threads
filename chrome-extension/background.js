// Threads Session Sync — background service worker.
// Memantau cookie sessionid Instagram; setiap kali berubah (login ulang /
// ganti akun / rotasi), kirim otomatis ke aplikasi Threads supaya sesi di
// sana selalu segar tanpa salin manual.
// Auth: API key pengguna (diisi di popup) diutamakan — sesi masuk ke akun
// milik pemilik key. Tanpa API key, pakai password gate (khusus admin).
// Sessionid HANYA dikirim ke threads.wandalo.dev (server Sophie sendiri),
// tidak ke tempat lain.

const SERVER = "https://threads.wandalo.dev";
// Sessionid diambil dari Threads dulu (yang dipakai Sophie saat salin
// manual), Instagram sebagai cadangan. Keduanya dicoba berurutan.
const COOKIE_URLS = [
  "https://www.threads.net/",
  "https://www.threads.com/",
  "https://www.instagram.com/",
];

async function getSetting(key, fallback) {
  const r = await chrome.storage.local.get(key);
  return r[key] !== undefined ? r[key] : fallback;
}

async function setStatus(obj) {
  const prev = await chrome.storage.local.get("syncStatus");
  const cur = prev.syncStatus || {};
  await chrome.storage.local.set({ syncStatus: { ...cur, ...obj } });
}

// Login gate web — cookie sesi berlaku 24 jam.
async function ensureGate() {
  const pass = await getSetting("gatePassword", "");
  const res = await fetch(SERVER + "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ password: pass }),
  });
  if (!res.ok) throw new Error("Gate login gagal (" + res.status + ")");
  return true;
}

// Username dari tab Threads yang sedang dibuka (ide Sophie): kalau lagi
// di halaman profil, URL-nya threads.net/@username — kirim sekalian
// supaya server tidak perlu menebak username.
async function usernameFromActiveTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = (tabs && tabs[0] && tabs[0].url) || "";
    const m = url.match(/threads\.(?:net|com)\/@([A-Za-z0-9_.]+)/);
    return m ? m[1] : "";
  } catch (e) {
    return "";
  }
}

async function syncSessionid(reason) {
  let cookie = null;
  let cookieSource = "";
  // Cek SEMUA cookie store: biasa ("0") + incognito ("1") bila extension
  // diizinkan di Incognito. Tanpa storeId, chrome.cookies.get hanya
  // membaca store biasa — itu sebabnya login di incognito tidak terbaca.
  let stores = [{ id: "0" }];
  try {
    const all = await chrome.cookies.getAllCookieStores();
    if (all && all.length) stores = all;
  } catch (e) { /* fallback: store biasa saja */ }
  outer:
  for (const s of stores) {
    for (const u of COOKIE_URLS) {
      const c = await chrome.cookies.get({ url: u, name: "sessionid", storeId: s.id });
      if (c && c.value) { cookie = c; cookieSource = u + " (store " + s.id + ")"; break outer; }
    }
  }
  if (!cookie || !cookie.value) {
    await setStatus({
      lastCheck: new Date().toISOString(),
      lastResult: "no-cookie",
      lastError: "Tidak login Threads/Instagram di Chrome ini (dicek biasa + incognito).",
    });
    return { ok: false, error: "Tidak login Threads/Instagram di Chrome ini (dicek biasa + incognito)." };
  }
  const sessionid = cookie.value;
  const last = await getSetting("lastSessionid", "");
  if (sessionid === last && reason !== "manual") {
    await setStatus({ lastCheck: new Date().toISOString(), lastResult: "unchanged" });
    return { ok: true, unchanged: true };
  }
  try {
    // Auth: API key (pengguna) diutamakan — sesi masuk ke akun milik
    // pemilik key. Tanpa key, pakai login gate (khusus admin).
    // Dengan key, cookie TIDAK dikirim (credentials "omit") supaya cookie
    // sesi lain (mis. admin) tidak mengalahkan key.
    const apiKey = await getSetting("apiKey", "");
    const headers = { "Content-Type": "application/json" };
    let credentials = "include";
    if (apiKey) {
      headers["X-API-Key"] = apiKey;
      credentials = "omit";
    } else {
      await ensureGate();
    }
    const tabUsername = await usernameFromActiveTab();
    const res = await fetch(SERVER + "/api/accounts", {
      method: "POST",
      headers,
      credentials,
      body: JSON.stringify({ sessionid, username: tabUsername || undefined, source: "extension" }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) {
      if (apiKey && res.status === 401) {
        throw new Error("API key tidak valid (401) — periksa kolom API key di popup.");
      }
      throw new Error(data.error || ("Server balas " + res.status));
    }
    const username = (data.account && data.account.username) || "";
    await chrome.storage.local.set({ lastSessionid: sessionid, lastCookieSource: cookieSource });
    await setStatus({
      lastCheck: new Date().toISOString(),
      lastResult: "ok",
      lastError: "",
      lastUsername: username,
      lastSync: new Date().toISOString(),
    });
    return { ok: true, username };
  } catch (e) {
    await setStatus({
      lastCheck: new Date().toISOString(),
      lastResult: "error",
      lastError: String(e && e.message ? e.message : e),
    });
    return { ok: false, error: String(e && e.message ? e.message : e) };
  }
}

// Cookie sessionid berubah (login ulang / ganti akun / rotasi) -> sync.
chrome.cookies.onChanged.addListener((change) => {
  const c = change.cookie;
  if (c.name !== "sessionid") return;
  if (!c.domain) return;
  const d = c.domain;
  if (!d.includes("threads.net") && !d.includes("threads.com") && !d.includes("instagram.com")) return;
  if (change.removed) return; // logout: tidak ada sesi untuk disinkronkan
  syncSessionid("cookie");
});

// Cek berkala (jaga-jaga bila event cookie terlewat) + saat browser dibuka.
chrome.alarms.create("sync-check", { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "sync-check") syncSessionid("alarm");
});
chrome.runtime.onStartup.addListener(() => syncSessionid("startup"));
chrome.runtime.onInstalled.addListener(() => syncSessionid("install"));

// Popup minta sync manual / minta status.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "sync-now") {
    syncSessionid("manual").then(sendResponse);
    return true; // jawab async
  }
  if (msg && msg.type === "get-status") {
    chrome.storage.local.get(["syncStatus", "lastSessionid"]).then(sendResponse);
    return true;
  }
});

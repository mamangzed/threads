// Popup Threads Session Sync.
const $ = (id) => document.getElementById(id);

function maskSid(sid) {
  if (!sid) return "—";
  if (sid.length <= 10) return sid.slice(0, 4) + "…";
  return sid.slice(0, 4) + "…" + sid.slice(-4);
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("id-ID", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

async function refresh() {
  const st = await chrome.runtime.sendMessage({ type: "get-status" });
  const s = (st && st.syncStatus) || {};
  const sid = (st && st.lastSessionid) || "";
  $("sid").textContent = maskSid(sid);
  $("username").textContent = s.lastUsername ? "@" + s.lastUsername : "—";
  $("lastSync").textContent = fmtTime(s.lastSync);
  const el = $("status");
  if (s.lastResult === "ok") {
    el.textContent = "Tersinkron";
    el.className = "ok";
  } else if (s.lastResult === "unchanged") {
    el.textContent = "Sudah sinkron";
    el.className = "ok";
  } else if (s.lastResult === "no-cookie") {
    el.textContent = "Belum login Instagram";
    el.className = "err";
    const hint = document.getElementById("hint");
    if (hint) hint.style.display = "block";
  } else if (s.lastResult === "error") {
    el.textContent = "Gagal: " + (s.lastError || "").slice(0, 80);
    el.className = "err";
  } else {
    el.textContent = "Belum pernah sync";
    el.className = "";
  }
  const saved = await chrome.storage.local.get("gatePassword");
  $("gatePass").value = saved.gatePassword || "";
  $("gatePass").placeholder = "password gate";
}

$("syncBtn").addEventListener("click", async () => {
  const btn = $("syncBtn");
  btn.disabled = true;
  btn.textContent = "Menyinkronkan…";
  try {
    const r = await chrome.runtime.sendMessage({ type: "sync-now" });
    if (r && !r.ok && r.error) alert("Sync gagal: " + r.error);
  } catch (e) {
    alert("Sync gagal: " + e);
  }
  btn.disabled = false;
  btn.textContent = "Sync Sekarang";
  refresh();
});

$("gatePass").addEventListener("change", async (e) => {
  await chrome.storage.local.set({ gatePassword: e.target.value.trim() });
});

refresh();

#!/usr/bin/env node
/**
 * Browser login for Instagram — returns a web sessionid for the app.
 *
 * Why a browser: the API (CAA/Bloks) login succeeds but Instagram
 * rejects the resulting session on the Threads feed endpoint
 * (logout_reason 37), while a session created by a real browser login
 * works fine. So the app logs in through headless Chromium instead.
 *
 * Usage:  node browser_login.js < /tmp/input.json
 * Input (stdin, one JSON object):
 *   { username, password, totp_key, proxy, code }
 *   totp_key: 2FA secret key (base32) — the 6-digit code is generated
 *             at the moment the 2FA field appears. A bare 6-digit
 *             `code` is also accepted (used as-is, may expire).
 *   proxy:    optional http://user:pass@host:port, used for the
 *             browser only, never stored.
 * Output (stdout, exactly one JSON line):
 *   {"ok": true, "sessionid": "...", "user_id": "..."}
 *   {"ok": false, "need_2fa": true, "error": "..."}
 *   {"ok": false, "error": "..."}
 * Everything else goes to stderr. Credentials travel via stdin only
 * and are never logged or written anywhere.
 */
const crypto = require("crypto");
const { chromium } = require("/root/kai-bot/node_modules/playwright-core");

function log(...args) {
  console.error("[browser_login]", new Date().toISOString().slice(11, 19), ...args);
}

function out(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

// --- TOTP (RFC 6238, SHA1, 30s step) --------------------------------------
function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(str || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const ch of clean) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totp(secret, windowOffset = 0) {
  const key = base32Decode(secret);
  if (!key.length) throw new Error("kunci 2FA tidak valid");
  const counter = Math.floor(Date.now() / 1000 / 30) + windowOffset;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[off] & 0x7f) << 24) |
    ((hmac[off + 1] & 0xff) << 16) |
    ((hmac[off + 2] & 0xff) << 8) |
    (hmac[off + 3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}

// --- proxy -----------------------------------------------------------------
function parseProxy(url) {
  if (!url) return null;
  const m = String(url).match(/^https?:\/\/(?:([^:@]+)(?::([^@]*))?@)?([^:/]+)(?::(\d+))?/);
  if (!m) return null;
  const proxy = { server: `http://${m[3]}${m[4] ? ":" + m[4] : ""}` };
  if (m[1]) proxy.username = decodeURIComponent(m[1]);
  if (m[2] !== undefined) proxy.password = decodeURIComponent(m[2]);
  return proxy;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf-8") || "{}");
}

async function getCookies(context) {
  const all = await context.cookies("https://www.instagram.com");
  const map = {};
  for (const c of all) map[c.name] = c.value;
  return map;
}

async function main() {
  const input = await readStdin();
  const username = (input.username || "").trim();
  const password = input.password || "";
  const totpKey = (input.totp_key || "").trim();
  const manualCode = (input.code || "").trim();
  const proxy = parseProxy(input.proxy);
  if (!username || !password) {
    out({ ok: false, error: "username dan password wajib diisi" });
    return;
  }

  let browser = null;
  try {
    browser = await chromium.launch({
      headless: true,
      // Pakai Chromium LENGKAP, bukan headless-shell (lebih mudah terdeteksi bot).
      channel: "chromium",
      args: [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=IsolateOrigins,site-per-process",
      ],
      proxy: proxy || undefined,
    });
    const context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
      locale: "id-ID",
      timezoneId: "Asia/Jakarta",
    });
    const page = await context.newPage();
    // Stealth: samarkan tanda browser otomatis agar login tidak ditolak
    // sebagai bot. (navigator.webdriver, chrome runtime, plugin, bahasa.)
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "webdriver", { get: () => false });
      window.chrome = { runtime: {}, loadTimes: () => ({}), csi: () => ({}) };
      Object.defineProperty(navigator, "plugins", {
        get: () => [1, 2, 3, 4, 5],
      });
      Object.defineProperty(navigator, "languages", {
        get: () => ["id-ID", "id", "en-US", "en"],
      });
      Object.defineProperty(navigator, "platform", { get: () => "Linux armv8l" });
      const origQuery = window.navigator.permissions.query;
      window.navigator.permissions.query = (params) =>
        params.name === "notifications"
          ? Promise.resolve({ state: Notification.permission })
          : origQuery(params);
    });

    log("goto login page");
    // The residential proxy's exit IP rotates per connection and some
    // are slow to Instagram — retry the page load instead of failing
    // on the first slow one. waitUntil "commit" returns as soon as the
    // response headers arrive; the selector wait below covers parsing.
    let loaded = false;
    for (let attempt = 0; attempt < 3 && !loaded; attempt++) {
      try {
        log(`goto attempt ${attempt + 1} start`);
        await page.goto("https://www.instagram.com/accounts/login/", {
          waitUntil: "commit",
          timeout: 30000,
        });
        loaded = true;
        log(`goto attempt ${attempt + 1} commit ok, url=`, page.url());
      } catch (e) {
        log(`goto attempt ${attempt + 1} failed:`, String((e && e.message) || e).slice(0, 120));
        if (attempt === 2) throw e;
        await sleep(2000);
      }
    }
    log("waiting for email input");
    // NOTE: the live web login form uses name="email" / name="pass"
    // (not "username" / "password") and an <input type="submit">.
    // The inputs exist in the DOM before they are visible/editable
    // (entrance animation), so wait for "visible" — "attached" returns
    // too early and fill() then waits 30s for editability and times out.
    try {
      await page.waitForSelector('input[name="email"]', { timeout: 60000, state: "visible" });
      log("form found");
    } catch (e) {
      const title = await page.title().catch(() => "?");
      const bodyText = (await page.evaluate(() => document.body.innerText).catch(() => "")) || "";
      const inputs = await page.evaluate(() =>
        Array.from(document.querySelectorAll("input")).map((el) => ({
          type: el.type, name: el.name, id: el.id,
          placeholder: el.placeholder, aria: el.getAttribute("aria-label"),
        }))
      ).catch(() => []);
      log("login form not found. url=", page.url(), "title=", title);
      log("body=", bodyText.slice(0, 300));
      log("inputs=", JSON.stringify(inputs));
      await page.screenshot({ path: "/tmp/blogin-debug.png" }).catch(() => {});
      throw e;
    }

    log("filling credentials");
    await page.fill('input[name="email"]', username, { timeout: 20000 });
    log("email filled");
    await sleep(600 + Math.floor(Math.random() * 800));
    await page.fill('input[name="pass"]', password, { timeout: 20000 });
    log("password filled");
    // The submit <input> is not clickable via Playwright's actionability
    // checks (covered/styled) — press Enter in the password field to
    // submit the form, falling back to a forced click.
    await sleep(800 + Math.floor(Math.random() * 1200));
    try {
      await page.locator('input[name="pass"]').press("Enter", { timeout: 10000 });
    } catch (e) {
      log("enter submit failed, force-clicking:", String(e.message).slice(0, 100));
      const submitBtn = page.locator('input[type="submit"], button[type="submit"]').first();
      await submitBtn.click({ force: true, timeout: 10000 });
    }
    log("submitted login form");

    let tried2fa = false;
    let tried2faAt = 0;
    const deadline = Date.now() + 90000;
    let iter = 0;
    while (Date.now() < deadline) {
      await sleep(2000);
      iter++;
      const cookies = await getCookies(context);
      if (cookies.sessionid && cookies.ds_user_id) {
        out({ ok: true, sessionid: cookies.sessionid, user_id: String(cookies.ds_user_id) });
        return;
      }
      const url = page.url();
      const bodyText = (await page.evaluate(() => document.body.innerText).catch(() => "")) || "";
      if (iter <= 3 || iter % 10 === 0) {
        log(`poll #${iter} url=`, url, "body=", bodyText.replace(/\s+/g, " ").slice(0, 200));
      }

      // 2FA step — checked FIRST: the 2FA page can also show a
      // "Not Now" button (trust-device prompt), and dismissing that
      // before filling the code would loop forever.
      const on2faPage =
        url.includes("two_step_verification") ||
        /two-factor|two factor|authentication app/i.test(bodyText) ||
        /Periksa email Anda|Check your email|Masukkan kode yang kami kirim|Enter the code we sent/i.test(bodyText);
      if (on2faPage) {
        // The code field renders seconds AFTER the 2FA page loads, and
        // the login form's email/pass inputs linger in the DOM (and
        // report visible) meanwhile — typing into those fills the wrong
        // field. Wait for a NEW input (not email/pass) to appear.
        const codeBoxes = page.locator(
          'input:not([type="hidden"]):not([type="checkbox"]):not([type="submit"]):not([type="button"]):not([name="email"]):not([name="pass"]):visible'
        );
        if ((await codeBoxes.count()) === 0) {
          log("2FA page seen, code field not rendered yet — waiting");
          continue;
        }
        if (tried2fa) {
          // IG needs a few seconds to validate the code — do not call
          // it wrong just because the 2FA page is still showing. Only
          // conclude failure when IG shows an error, or after 20s with
          // no verdict at all.
          if (/incorrect|wrong|not valid|try again|coba lagi/i.test(bodyText)) {
            out({ ok: false, error: "Kode 2FA salah atau sudah kedaluwarsa — coba lagi." });
            return;
          }
          if (Date.now() - tried2faAt < 20000) {
            log("waiting for IG to validate the 2FA code");
            continue;
          }
          out({ ok: false, error: "Kode 2FA tidak diterima Instagram — coba lagi." });
          return;
        }
        let code = manualCode;
        if (!code && totpKey) {
          try {
            // Generate the code fresh, at the last moment — and never
            // in the last 5s of a 30s window, or it can expire before
            // Instagram validates it.
            const msLeft = 30000 - (Date.now() % 30000);
            if (msLeft < 5000) {
              log("near end of TOTP window, waiting for the next one");
              await sleep(msLeft + 500);
            }
            code = totp(totpKey);
          } catch (e) {
            out({ ok: false, error: "Kunci 2FA tidak valid." });
            return;
          }
        }
        if (!code) {
          const isEmailCode = /Periksa email Anda|Check your email|Masukkan kode yang kami kirim|Enter the code we sent/i.test(bodyText);
          out({
            ok: false,
            need_2fa: true,
            error: isEmailCode
              ? "Instagram mengirim kode verifikasi ke email akun ini — cek inbox email dan masukkan kode 6 digit itu di sini."
              : "Akun ini memakai 2FA — masukkan kunci 2FA (secret key dari aplikasi Authenticator).",
          });
          return;
        }
        const nBoxes = await codeBoxes.count();
        log("filling 2FA code, visible code inputs:", nBoxes);
        // Type the code with real key events into the first code box:
        // works for a single 6-digit field and for six single-digit
        // boxes (auto-advance).
        await codeBoxes.first().click({ timeout: 10000 });
        await page.keyboard.type(code, { delay: 60 });
        const codeVal = await codeBoxes.first().inputValue().catch(() => "?");
        log("code field value after typing:", codeVal);
        // The submit button is labelled "Continue" on this page. Use
        // a role selector so the hidden login form's submit input
        // (still in the DOM) is never picked instead.
        const confirmBtn = page.getByRole("button", { name: /Continue|Confirm/i }).first();
        if ((await confirmBtn.count()) > 0) {
          log("clicking Continue/Confirm button");
          await confirmBtn.click({ timeout: 15000 }).catch((e) => log("continue click failed:", String(e.message).slice(0, 120)));
        } else {
          log("no Continue button found, pressing Enter");
          await page.keyboard.press("Enter");
        }
        tried2fa = true;
        tried2faAt = Date.now();
        continue;
      }
      // Fallback 2FA detection for any other 2FA layout.
      const codeBoxes = page.locator(
        'input[name="verificationCode"], input[inputmode="numeric"], input[name*="verif" i], input[aria-label*="code" i]'
      );
      if ((await codeBoxes.count()) > 0 && (await codeBoxes.first().isVisible().catch(() => false))) {
        if (tried2fa) {
          if (/incorrect|wrong|not valid|try again|coba lagi/i.test(bodyText)) {
            out({ ok: false, error: "Kode 2FA salah atau sudah kedaluwarsa — coba lagi." });
            return;
          }
          if (Date.now() - tried2faAt < 20000) {
            log("waiting for IG to validate the 2FA code");
            continue;
          }
          out({ ok: false, error: "Kode 2FA tidak diterima Instagram — coba lagi." });
          return;
        }
        let code = manualCode;
        if (!code && totpKey) {
          try {
            const msLeft = 30000 - (Date.now() % 30000);
            if (msLeft < 5000) {
              log("near end of TOTP window, waiting for the next one");
              await sleep(msLeft + 500);
            }
            code = totp(totpKey);
          } catch (e) {
            out({ ok: false, error: "Kunci 2FA tidak valid." });
            return;
          }
        }
        if (!code) {
          out({
            ok: false,
            need_2fa: true,
            error: "Akun ini memakai 2FA — masukkan kunci 2FA (secret key dari aplikasi Authenticator).",
          });
          return;
        }
        log("filling 2FA code (fallback)");
        await codeBoxes.first().click({ timeout: 10000 });
        await page.keyboard.type(code, { delay: 60 });
        const codeValFb = await codeBoxes.first().inputValue().catch(() => "?");
        log("code field value after typing:", codeValFb);
        const confirmBtnFb = page.getByRole("button", { name: /Continue|Confirm/i }).first();
        if ((await confirmBtnFb.count()) > 0) {
          await confirmBtnFb.click({ timeout: 15000 }).catch((e) => log("continue click failed:", String(e.message).slice(0, 120)));
        } else {
          await page.keyboard.press("Enter");
        }
        tried2fa = true;
        tried2faAt = Date.now();
        continue;
      }

      // Dismiss post-login dialogs ("Save your login info" / "Turn on
      // Notifications") if they appear. Only act when the "Not Now"
      // button is actually visible — the dialog text can sit hidden in
      // the DOM on the login page itself, and matching on text alone
      // would skip every other check forever.
      const notNowBtn = page.getByText("Not Now", { exact: true }).first();
      if ((await notNowBtn.count()) > 0) {
        const notNowVisible = await notNowBtn.isVisible().catch(() => false);
        if (notNowVisible) {
          await notNowBtn.click().catch(() => {});
          continue;
        }
      }

      // Challenge / checkpoint page — TAPI halaman kode email sudah
      // ditangani di atas sebagai 2FA, jangan sampai jatuh ke sini.
      if (
        /Periksa email Anda|Check your email|Masukkan kode yang kami kirim|Enter the code we sent/i.test(bodyText)
      ) {
        // Seharusnya sudah ditangani sebagai on2faPage; kalau sampai sini,
        // beri sinyal need_2fa agar UI minta kode email.
        out({
          ok: false,
          need_2fa: true,
          error: "Instagram mengirim kode verifikasi ke email akun ini — cek inbox email dan masukkan kode 6 digit itu di sini.",
        });
        return;
      }
      if (
        url.includes("/challenge/") ||
        /unusual login attempt|Confirm your identity|challenge_required|Suspicious login/i.test(bodyText)
      ) {
        out({
          ok: false,
          error:
            "Instagram minta konfirmasi login ini (dideteksi sebagai login tidak biasa). Buka Instagram di HP dan konfirmasi bahwa ini kamu, lalu coba lagi.",
        });
        return;
      }

      // Plain login errors. (Live wording, Nov 2026: "The login
      // information you entered is incorrect.")
      if (/your password was incorrect|login information you entered is incorrect|password you entered is incorrect|Informasi login yang Anda masukkan salah|Kata sandi salah/i.test(bodyText)) {
        out({ ok: false, error: "Username atau password salah." });
        return;
      }
      if (/username you entered doesn't belong/i.test(bodyText)) {
        out({ ok: false, error: "Username tidak ditemukan." });
        return;
      }
      if (/Please wait a few minutes/i.test(bodyText)) {
        out({
          ok: false,
          error: "Instagram meminta menunggu beberapa menit sebelum mencoba lagi (terlalu banyak percobaan login). Coba lagi nanti.",
        });
        return;
      }
      if (/suspended|disabled/i.test(bodyText) && /account/i.test(bodyText)) {
        out({ ok: false, error: "Akun ini dibatasi/dinonaktifkan oleh Instagram." });
        return;
      }
    }
    await page.screenshot({ path: "/tmp/blogin-debug.png" }).catch(() => {});
    log("poll loop ended without a match; screenshot saved");
    out({ ok: false, error: "Login timeout — halaman Instagram tidak merespons seperti yang diharapkan." });
  } catch (e) {
    const msg = String((e && e.message) || e);
    if (/proxy|ERR_PROXY|net::ERR/i.test(msg)) {
      out({ ok: false, error: "Proxy tidak bisa dihubungi: " + msg.slice(0, 200) });
    } else if (/Timeout|timeout/i.test(msg)) {
      out({ ok: false, error: "Instagram tidak merespons (timeout) — coba lagi." });
    } else {
      out({ ok: false, error: "Gagal: " + msg.slice(0, 200) });
    }
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

main();

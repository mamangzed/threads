#!/usr/bin/env python3
"""Registrasi akun Instagram baru via alur Bloks CAA (instagrapi 3.2.11).

Dua fase (OTP dimasukkan manual oleh Sophie di UI aplikasi Threads):
  start:   {"phase":"start","username","password","contact_type":"phone"|"email",
            "contact": nomor HP atau email, "full_name",
            "day","month","year","proxy"|null,"state_dir"}
           -> aymh -> expose_ntm -> prefill -> contactpoint_phone
           -> phone: contactpoint_phone.async (submit nomor) -> coba kirim SMS
           -> email: contactpoint_email -> contactpoint_email_new
                     -> send_confirmation_email (kode ke email)
           -> simpan state CAA ke <state_dir>/<username>.json (0600)
           -> {"ok": true, "waiting_otp": true, "contact": ...,
               "contact_type": ..., "sms_send"/"email_send": ...}
           Status kirim: "requested" = panggilan dieksekusi tanpa error,
           BUKAN bukti kode terkirim (respons server kosong); "failed" =
           semua percobaan gagal. UI TIDAK BOLEH mengklaim "berhasil
           dikirim" — hanya "permintaan dikirim, cek inbox/SMS".
  confirm: {"phase":"confirm","username","code","password","proxy"|null,"state_dir"}
           -> confirmation -> password -> birthday -> name -> username
              -> create.account -> sessionid + user_id + settings
           -> {"ok": true, "sessionid": ..., "user_id": ..., "settings": {...}}
  resend:  {"phase":"resend","username","proxy"|null,"state_dir"}
           -> coba kirim ulang SMS -> {"ok": true, "sms_send": ...}

Protocol (stdin JSON -> stdout SATU baris JSON, tidak ada yang lain di stdout).
Password hanya transit via stdin, tidak pernah dicetak atau disimpan.
State file TIDAK menyimpan password maupun proxy (keduanya dikirim ulang
di tiap fase dari UI).
"""
import hashlib
import json
import os
import random
import re
import sys
import time
from uuid import uuid4

BLOKS_VERSION_ID = "8f5ec0abc5f3dbbd823773bbd39ae9703d2a92f63e9189c89ee878de00fb866a"

# Perangkat modern (sama seperti daftar di aplikasi Threads) — dipilih
# stabil per username supaya tiap akun baru punya device berbeda.
DEVICES = [
    {"android_version": 33, "android_release": "13.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "samsung", "device": "dm3q", "model": "SM-S918B", "cpu": "qcom"},
    {"android_version": 34, "android_release": "14.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "samsung", "device": "e3q", "model": "SM-S921B", "cpu": "qcom"},
    {"android_version": 34, "android_release": "14.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "samsung", "device": "a54x", "model": "SM-A546E", "cpu": "exynos"},
    {"android_version": 34, "android_release": "14.0.0", "dpi": "420dpi", "resolution": "1080x2400", "manufacturer": "Google", "device": "husky", "model": "Pixel 8 Pro", "cpu": "google"},
    {"android_version": 34, "android_release": "14.0.0", "dpi": "420dpi", "resolution": "1080x2400", "manufacturer": "Google", "device": "panther", "model": "Pixel 7", "cpu": "google"},
    {"android_version": 34, "android_release": "14.0.0", "dpi": "440dpi", "resolution": "1080x2400", "manufacturer": "Xiaomi", "device": "houji", "model": "23127PN0CG", "cpu": "qcom"},
    {"android_version": 33, "android_release": "13.0.0", "dpi": "440dpi", "resolution": "1080x2400", "manufacturer": "Xiaomi", "device": "garnet", "model": "2312DRA50G", "cpu": "qcom"},
    {"android_version": 34, "android_release": "14.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "OPPO", "device": "CPH2599", "model": "CPH2599", "cpu": "mtk"},
    {"android_version": 33, "android_release": "13.0.0", "dpi": "440dpi", "resolution": "1080x2400", "manufacturer": "vivo", "device": "V2250", "model": "V2250", "cpu": "qcom"},
    {"android_version": 34, "android_release": "14.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "OnePlus", "device": "CPH2449", "model": "CPH2449", "cpu": "qcom"},
]

PHONE_ASYNC = "com.bloks.www.bloks.caa.reg.async.contactpoint_phone.async"
EMAIL_ASYNC = "com.bloks.www.bloks.caa.reg.async.contactpoint_email.async"
SEND_EMAIL_ASYNC = "com.bloks.www.bloks.caa.reg.send_confirmation_email.async"
CONFIRM_ASYNC = "com.bloks.www.bloks.caa.reg.confirmation.async"
SEND_SMS_CANDIDATES = [
    "com.bloks.www.bloks.caa.reg.send_confirmation_sms.async",
    "com.bloks.www.bloks.caa.reg.async.send_confirmation_sms.async",
]


def _device_for(username: str) -> dict:
    idx = int(hashlib.md5(("aa" + (username or "")).encode()).hexdigest(), 16) % len(DEVICES)
    return dict(DEVICES[idx])


def _clean(msg: str) -> str:
    low = (msg or "").lower()
    if "nomor ponsel atau email diperlukan" in low or "phone number or email" in low:
        return ("Instagram menolak kontak ini (dianggap kosong/tidak valid). "
                "Coba kontak lain.")
    if "too many" in low or "429" in low or "throttled" in low:
        return "Instagram membatasi permintaan (429). Tunggu beberapa menit lalu coba lagi."
    if "challenge" in low or "checkpoint" in low:
        return ("Instagram meminta verifikasi tambahan (challenge). "
                "Coba lagi nanti atau daftar manual dulu lewat aplikasi Instagram.")
    if "not eligible" in low or "age" in low:
        return "Tanggal lahir tidak memenuhi syarat umur Instagram."
    if "username" in low and ("taken" in low or "taken" in low or "not available" in low or "unavailable" in low):
        return "Username sudah dipakai orang lain. Pilih username lain."
    if "invalid" in low and "code" in low:
        return "Kode konfirmasi salah. Periksa lagi kodenya."
    if "expired" in low and "code" in low:
        return "Kode konfirmasi kedaluwarsa. Minta kirim ulang kode."
    if "field_exception" in low or "payload returned is null" in low:
        return ("Instagram menolak langkah ini (field_exception). "
                "Kemungkinan alur registrasi berubah — laporkan ke JONO.")
    return (msg or "Pendaftaran gagal.")[:300]


def _norm_phone(raw: str):
    """Kembalikan (internasional +62..., nasional tanpa kode negara)."""
    p = re.sub(r"[\s\-()]", "", (raw or "").strip())
    if p.startswith("+62"):
        return p, p[3:]
    if p.startswith("62"):
        return "+" + p, p[2:]
    if p.startswith("08"):
        return "+62" + p[1:], p[1:]
    if p.startswith("8"):
        return "+62" + p, p
    return p, p


def _field_id_from_screen(resp) -> str:
    """Ambil text_input_id dari bundle layar.
    Pola di bundle: dn3 "nyffcd:43" (dn3 diikuti field id dikutip).
    Kemunculan dn3 pertama sering token panjang dn3xxx... tanpa ':',
    jadi iterasi SEMUA kemunculan dn3 sampai ketemu yang diikuti field id dikutip.
    """
    raw = json.dumps(resp, default=str)
    needle = "dn3"
    pos = 0
    while True:
        i = raw.find(needle, pos)
        if i < 0:
            break
        # Lihat 40 karakter sesudah dn3; cari pola "xxx:NNN"
        window = raw[i:i + 40]
        # Cari tanda kutip lalu id:angka lalu kutip (toleran backslash)
        q1 = window.find('"')
        if q1 >= 0:
            q2 = window.find('"', q1 + 1)
            if q2 > q1 + 1:
                cand = window[q1 + 1:q2].replace("\\", "")
                if ":" in cand and len(cand) < 20:
                    parts = cand.split(":")
                    if len(parts) == 2 and parts[0].isalnum() and parts[1].isdigit():
                        return cand
        pos = i + len(needle)
    return str(random.randint(100000000000000, 999999999999999))


def _setup_client(proxy, username):
    from instagrapi import Client

    cl = Client()
    if proxy:
        cl.set_proxy(proxy)
    try:
        cl.set_device(_device_for(username))
    except Exception:
        pass
    try:
        cl.set_locale("id_ID")
        cl.set_country_code(62)
        cl.timezone_offset = 420
    except Exception:
        pass
    try:
        cl.bloks_versioning_id = BLOKS_VERSION_ID
    except Exception:
        pass
    return cl


def _initial_state(cl, contact, contact_type):
    state = cl._caa_initial_state()
    ri = json.loads(state["reg_info"])
    if contact_type == "email":
        ri["contactpoint"] = contact
        ri["ar_contactpoint"] = None
        ri["contactpoint_type"] = "email"
    else:
        ri["contactpoint"] = contact
        ri["ar_contactpoint"] = contact
        ri["contactpoint_type"] = "phone"
    state["reg_info"] = json.dumps(ri)
    return state


def _opening_steps(cl, state):
    from instagrapi.mixins.signup import CAA_REG_CONTACTPOINT_DOC_ID  # noqa: F401 (dipakai di submit)
    r = cl.caa_reg_graphql(
        "com.bloks.www.bloks.caa.reg.aymh_create_account_button.async",
        state=state, current_step=0,
        client_input_params={"accounts_list": [], "device_emails": [], "device_phone_numbers": []},
        server_params={"reg_flow_source": "login_home_native_integration_point", "entrypoint": "login_home"},
    )
    cl._caa_update_state(state, r)
    r = cl.caa_reg_async_action(
        "com.bloks.www.bloks.caa.reg.async.expose_ntm_experiment.async",
        state=state, current_step=0,
        client_input_params={"si_device_param_network_info": ""},
    )
    cl._caa_update_state(state, r)
    r = cl.caa_reg_graphql(
        "com.bloks.www.bloks.caa.reg.async.contactpoint_prefill.async",
        state=state, current_step=0,
        client_input_params={"accounts_list": [], "si_device_param_network_info": ""},
    )
    cl._caa_update_state(state, r)
    r = cl.caa_reg_graphql(
        "com.bloks.www.bloks.caa.reg.contactpoint_phone",
        state=state, current_step=0,
        server_params={"INTERNAL_INFRA_screen_id": str(uuid4())},
    )
    cl._caa_update_state(state, r)
    return r


def _phone_submit(cl, state, phone_intl, phone_nat, field_id):
    from instagrapi.mixins.signup import CAA_REG_CONTACTPOINT_DOC_ID
    r = cl.caa_reg_graphql(
        PHONE_ASYNC, state=state, current_step=0,
        client_doc_id=CAA_REG_CONTACTPOINT_DOC_ID,
        client_input_params={
            "phone": phone_nat,
            "accounts_list": [],
            "build_type": "release",
            "encrypted_msisdn": "",
            "headers_infra_flow_id": "",
            "was_headers_prefill_available": False,
            "was_headers_prefill_used": False,
            "fb_ig_device_id": [],
            "whatsapp_installed_on_client": False,
            "confirmed_cp_and_code": {},
            "msg_previous_cp": "",
            "switch_cp_first_time_loading": False,
            "switch_cp_have_seen_suma": False,
            "has_rejected_rel": False,
            "login_upsell_phone_list": [],
            "country_code": "62",
            "prefill_attempted_silent_auth": False,
            "device_network_info": cl._caa_network_info(),
            "seen_login_upsell": False,
            "block_store_machine_id": "",
        },
        server_params={
            "cp_funnel": 0,
            "cp_source": 0,
            "text_input_id": field_id,
            "is_from_confirmation_sheet": False,
        },
    )
    cl._caa_update_state(state, r)
    return r


def _try_send_sms(cl, state, phone_nat):
    """Coba kirim SMS kode. Kembalikan (status, detail).
    Status: 'requested' bila satu percobaan dieksekusi tanpa error —
    itu BUKAN bukti SMS terkirim (respons server kosong, tidak ada
    konfirmasi pengiriman); 'failed' bila semua gagal.
    Best-effort: pemanggil yang memutuskan (kode bisa jadi sudah terkirim
    oleh langkah submit nomor)."""
    last_err = ""
    for action in SEND_SMS_CANDIDATES:
        for via_graphql in (False, True):
            try:
                if via_graphql:
                    r = cl.caa_reg_graphql(
                        action, state=state, current_step=0,
                        client_input_params={"phone": phone_nat},
                        server_params={"is_from_unified_cp_screen": False, "is_direct_from_conf": False, "accounts_list": []},
                    )
                else:
                    r = cl.caa_reg_async_action(
                        action, state=state, current_step=0,
                        client_input_params={"phone": phone_nat},
                        server_params={"is_from_unified_cp_screen": False, "is_direct_from_conf": False, "accounts_list": []},
                    )
                cl._caa_update_state(state, r)
                return "requested", action
            except Exception as e:
                last_err = str(e)[:200]
                continue
    return "failed", last_err


def _email_submit(cl, state, email):
    """Alur email (terbukti dari bundle layar, 14 Nov):
    contactpoint_email (layar) -> contactpoint_email.async via GRAPHQL
    dengan doc id yang sama seperti submit nomor.
    Nama library `contactpoint_email_new.async` 404 — JANGAN dipakai.
    Field id WAJIB dari bundle layar email (seperti nomor HP)."""
    from instagrapi.mixins.signup import CAA_REG_CONTACTPOINT_DOC_ID
    r = cl.caa_reg_graphql(
        "com.bloks.www.bloks.caa.reg.contactpoint_email",
        state=state, current_step=0,
        server_params={
            "root_screen_id": "CAA_REG_CONTACT_POINT_PHONE",
            "INTERNAL_INFRA_screen_id": str(uuid4()),
            "reg_context": None,
        },
    )
    cl._caa_update_state(state, r)
    field_id = _field_id_from_screen(r)
    r = cl.caa_reg_graphql(
        EMAIL_ASYNC,
        state=state, current_step=0,
        client_doc_id=CAA_REG_CONTACTPOINT_DOC_ID,
        client_input_params={
            "accounts_list": [],
            "email": email,
            "email_prefilled": 0,
            "confirmed_cp_and_code": {},
            "is_from_device_emails": 0,
            "prefetch_version": 11,
            "si_device_param_network_info": cl._caa_network_info(),
            "block_store_machine_id": "",
            "fb_ig_device_id": [],
        },
        server_params={
            "cp_funnel": 0,
            "cp_source": 0,
            "prefetch_on_field": 1,
            "text_input_id": field_id,
            "reg_context": None,
        },
    )
    cl._caa_update_state(state, r)
    return r


def _try_send_email(cl, state):
    """Kirim kode konfirmasi ke email. Kembalikan (status, detail).
    Status: 'requested' bila panggilan dieksekusi tanpa error — itu BUKAN
    bukti email terkirim (respons server kosong, tidak ada token maupun
    konfirmasi pengiriman); 'failed' bila gagal.
    Best-effort seperti SMS: pemanggil yang memutuskan."""
    last_err = ""
    for via_graphql in (False, True):
        try:
            params = {
                "client_input_params": {"email_token": state.get("email_token", "")},
                "server_params": {"is_from_unified_cp_screen": False, "is_direct_from_conf": False, "accounts_list": []},
            }
            if via_graphql:
                r = cl.caa_reg_graphql(SEND_EMAIL_ASYNC, state=state, current_step=0, **params)
            else:
                r = cl.caa_reg_async_action(SEND_EMAIL_ASYNC, state=state, current_step=0, **params)
            cl._caa_update_state(state, r)
            return "requested", SEND_EMAIL_ASYNC
        except Exception as e:
            last_err = str(e)[:200]
            continue
    return "failed", last_err


def _state_path(state_dir, username):
    return os.path.join(state_dir, re.sub(r"[^A-Za-z0-9_.\-]", "_", username) + ".json")


def _save_state(state_dir, username, state, settings, form):
    os.makedirs(state_dir, exist_ok=True)
    path = _state_path(state_dir, username)
    data = {"state": state, "settings": settings, "form": form, "saved_at": int(time.time())}
    with open(path, "w") as f:
        json.dump(data, f)
    os.chmod(path, 0o600)
    return path


def _load_state(state_dir, username):
    path = _state_path(state_dir, username)
    with open(path) as f:
        return json.load(f), path


def _restore_client_ids(cl, state, settings):
    try:
        if settings:
            cl.set_settings(settings)
    except Exception:
        pass
    try:
        cl.android_device_id = state.get("device_id", "") or getattr(cl, "android_device_id", "")
        cl.phone_id = state.get("family_device_id", "") or getattr(cl, "phone_id", "")
        cl.uuid = state.get("qe_device_id", "") or getattr(cl, "uuid", "")
        cl.waterfall_id = state.get("waterfall_id", "") or getattr(cl, "waterfall_id", "")
        if state.get("machine_id"):
            cl.mid = state["machine_id"]
    except Exception:
        pass


def _do_start(req):
    from instagrapi.mixins.signup import CAA_REG_CONTACTPOINT_DOC_ID  # noqa: F401
    username = (req.get("username") or "").strip().lstrip("@")
    password = req.get("password") or ""
    # Kontak: "contact_type"+"contact" baru; "phone" lama tetap didukung.
    contact_type = (req.get("contact_type") or "").strip().lower()
    contact = (req.get("contact") or "").strip()
    phone_raw = (req.get("phone") or "").strip()
    email_raw = (req.get("email") or "").strip()
    if not contact_type:
        if email_raw:
            contact_type, contact = "email", email_raw
        elif phone_raw:
            contact_type, contact = "phone", phone_raw
    if contact_type == "email" and not contact:
        contact = email_raw
    if contact_type == "phone" and not contact:
        contact = phone_raw
    full_name = (req.get("full_name") or "").strip()
    day = int(req.get("day") or 0)
    month = int(req.get("month") or 0)
    year = int(req.get("year") or 0)
    proxy = (req.get("proxy") or "").strip() or None
    state_dir = req.get("state_dir") or "/root/threads-app/data/reg_pending"
    if not username or not password or not contact:
        return {"ok": False, "error": "username, password, dan nomor HP / email wajib diisi.", "step": "validasi"}
    if len(password) < 6:
        return {"ok": False, "error": "Kata sandi minimal 6 karakter.", "step": "validasi"}
    if not (1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2015):
        return {"ok": False, "error": "Tanggal lahir tidak valid.", "step": "validasi"}
    phone_intl, phone_nat = "", ""
    email = ""
    if contact_type == "email":
        email = contact
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return {"ok": False, "error": "Alamat email tidak valid.", "step": "validasi"}
    elif contact_type == "phone":
        phone_intl, phone_nat = _norm_phone(contact)
        if not re.match(r"^\+62[8][0-9]{7,11}$", phone_intl):
            return {"ok": False, "error": "Nomor HP tidak valid (format Indonesia +62 8xx).", "step": "validasi"}
    else:
        return {"ok": False, "error": "Jenis kontak tidak dikenal (phone/email).", "step": "validasi"}
    step = "setup"
    try:
        cl = _setup_client(proxy, username)
        state = _initial_state(cl, contact if contact_type == "email" else phone_intl, contact_type)
        step = "aymh_create_account_button"
        screen = _opening_steps(cl, state)
        if contact_type == "phone":
            field_id = _field_id_from_screen(screen)
            step = "contactpoint_phone.async"
            _phone_submit(cl, state, phone_intl, phone_nat, field_id)
            step = "send_sms"
            send_status, send_detail = _try_send_sms(cl, state, phone_nat)
        else:
            step = "contactpoint_email.async"
            _email_submit(cl, state, email)
            step = "send_confirmation_email"
            send_status, send_detail = _try_send_email(cl, state)
        try:
            settings = cl.get_settings()
        except Exception:
            settings = {}
        _save_state(state_dir, username, state, settings, {
            "username": username, "contact": contact, "contact_type": contact_type,
            "phone": phone_intl, "email": email, "full_name": full_name,
            "day": day, "month": month, "year": year,
        })
        res = {"ok": True, "waiting_otp": True, "contact": contact, "contact_type": contact_type,
               "phone": phone_intl, "email": email}
        if contact_type == "phone":
            res["sms_send"] = send_status
            res["sms_detail"] = send_detail[:200]
        else:
            res["email_send"] = send_status
            res["email_detail"] = send_detail[:200]
        return res
    except Exception as e:
        rej = ""
        try:
            rej = cl._caa_extract_rejection_message(locals().get("r")) or ""
        except Exception:
            pass
        return {"ok": False, "error": _clean(rej or str(e) or type(e).__name__), "step": step}


def _do_confirm(req):
    username = (req.get("username") or "").strip().lstrip("@")
    code = (req.get("code") or "").strip()
    password = req.get("password") or ""
    proxy = (req.get("proxy") or "").strip() or None
    state_dir = req.get("state_dir") or "/root/threads-app/data/reg_pending"
    if not username or not code or not password:
        return {"ok": False, "error": "username, kode OTP, dan password wajib diisi.", "step": "validasi"}
    try:
        saved, path = _load_state(state_dir, username)
    except Exception:
        return {"ok": False, "error": "Sesi pendaftaran tidak ditemukan (mungkin sudah kedaluwarsa). Mulai lagi dari awal.", "step": "load_state"}
    state = saved.get("state") or {}
    settings = saved.get("settings") or {}
    form = saved.get("form") or {}
    # Kontak dari state (file lama: hanya "phone", dianggap phone).
    contact = form.get("contact") or form.get("phone") or ""
    contact_type = form.get("contact_type") or ("email" if "@" in contact else "phone")
    full_name = form.get("full_name") or ""
    day = int(form.get("day") or 0)
    month = int(form.get("month") or 0)
    year = int(form.get("year") or 0)
    step = "setup"
    try:
        cl = _setup_client(proxy, username)
        _restore_client_ids(cl, state, settings)
        step = "confirmation"
        r = cl.caa_reg_graphql(
            CONFIRM_ASYNC, state=state, current_step=3,
            client_input_params={"code": code, "confirmed_cp_and_code": {"contactpoint": contact, "code": code}},
            server_params={"text_input_id": str(uuid4()), "wa_timer_id": str(uuid4())},
        )
        cl._caa_update_state(state, r)
        step = "password"
        r = cl.caa_reg_graphql(
            "com.bloks.www.bloks.caa.reg.password.async",
            state=state, current_step=4,
            client_input_params={
                "encrypted_password": cl._caa_password(password),
                "spi_action": 1,
                "whatsapp_installed_on_client": False,
                "safetynet_token": cl._caa_reg_info_value(state, "safetynet_token", ""),
                "safetynet_response": cl._caa_reg_info_value(state, "safetynet_response", "GOOGLE_PLAY_UNAVAILABLE: SERVICE_INVALID"),
                "system_permissions_status": {"READ_CONTACTS": "DENIED", "GET_ACCOUNTS": "DENIED", "READ_PHONE_STATE": "DENIED", "READ_PHONE_NUMBERS": "DENIED"},
            },
            server_params={"flow_modifier": state["flow_info"], "si_device_param_network_info": ""},
        )
        cl._caa_update_state(state, r)
        birthday = f"{day:02d}-{month:02d}-{year:04d}"
        step = "birthday"
        r = cl.caa_reg_graphql(
            "com.bloks.www.bloks.caa.reg.birthday.async",
            state=state, current_step=6,
            client_input_params={
                "accounts_list": [],
                "client_timezone": getattr(cl, "timezone_offset", 0),
                "birthday_or_current_date_string": birthday,
                "birthday_timestamp": int(time.time()),
                "os_age_range": "o18",
                "should_skip_youth_tos": False,
                "is_youth_regulation_flow_complete": False,
            },
            server_params={"si_device_param_network_info": ""},
        )
        cl._caa_update_state(state, r)
        step = "name"
        r = cl.caa_reg_async_action(
            "com.bloks.www.bloks.caa.reg.name_vtwo.async",
            state=state, current_step=7,
            client_input_params={"accounts_list": [], "name": full_name or username},
            server_params={"si_device_param_network_info": ""},
        )
        cl._caa_update_state(state, r)
        step = "username"
        r = cl.caa_reg_graphql(
            "com.bloks.www.bloks.caa.reg.username.async",
            state=state, current_step=8,
            client_input_params={"validation_text": username},
            server_params={
                "action": 1, "post_tos": 0,
                "text_input_id": random.randint(100000000000000, 999999999999999),
                "suggestions_container_id": random.randint(100000000000000, 999999999999999),
                "screen_id": random.randint(100000000000000, 999999999999999),
                "input_id": random.randint(100000000000000, 999999999999999),
            },
        )
        cl._caa_update_state(state, r)
        step = "create.account"
        r = cl.caa_reg_graphql(
            "com.bloks.www.bloks.caa.reg.create.account.async",
            state=state, current_step=9,
            client_input_params={
                "passkey_eligible_device": 0, "ck_error": "", "failed_birthday_year_count": "",
                "headers_last_infra_flow_id": "", "ig_partially_created_account_nonce_expiry": 0,
                "should_ignore_existing_login": 0, "reached_from_tos_screen": 1,
                "ig_partially_created_account_nonce": "", "has_dismissed_suma_pre_conf": 0,
                "ck_nonce": "", "force_sessionless_nux_experience": 0,
                "ig_partially_created_account_user_id": 0, "ck_id": "",
                "no_contact_perm_email_oauth_token": "", "encrypted_msisdn": "",
            },
            server_params={
                "sa_prefetch_callback_id": "", "should_ignore_suma_check": 0,
                "bloks_controller_source": "bk_caa_reg_tos_screen", "app_id": 0,
            },
        )
        cl._caa_update_state(state, r)
        reg = state.get("registration_response") or {}
        if not reg.get("created_user"):
            rej = cl._caa_extract_rejection_message(r) or ""
            if rej:
                return {"ok": False, "error": _clean(rej), "step": step}
            return {"ok": False, "error": "Instagram tidak mengembalikan akun yang dibuat.", "step": step}
        if reg.get("account_created") is False:
            return {"ok": False, "error": "Instagram tidak membuat akun.", "step": step}
        try:
            cookies = {c.name: c.value for c in cl.private.cookies}
        except Exception:
            cookies = {}
        sid = cookies.get("sessionid")
        uid = cookies.get("ds_user_id") or str(getattr(cl, "user_id", "") or "")
        if not sid or not uid:
            return {"ok": False, "error": "Akun dibuat tapi sessionid tidak didapat.", "step": "session"}
        account_check = ""
        try:
            cl.account_info()
        except Exception as e:
            account_check = _clean(str(e) or type(e).__name__)
        try:
            settings = cl.get_settings()
        except Exception:
            settings = {}
        try:
            os.unlink(path)
        except Exception:
            pass
        return {"ok": True, "sessionid": sid, "user_id": uid, "settings": settings,
                "username": username, "account_check": account_check}
    except Exception as e:
        return {"ok": False, "error": _clean(str(e) or type(e).__name__), "step": step}


def _do_resend(req):
    username = (req.get("username") or "").strip().lstrip("@")
    proxy = (req.get("proxy") or "").strip() or None
    state_dir = req.get("state_dir") or "/root/threads-app/data/reg_pending"
    if not username:
        return {"ok": False, "error": "username wajib diisi.", "step": "validasi"}
    try:
        saved, _ = _load_state(state_dir, username)
    except Exception:
        return {"ok": False, "error": "Sesi pendaftaran tidak ditemukan. Mulai lagi dari awal.", "step": "load_state"}
    state = saved.get("state") or {}
    settings = saved.get("settings") or {}
    form = saved.get("form") or {}
    contact = form.get("contact") or form.get("phone") or ""
    contact_type = form.get("contact_type") or ("email" if "@" in contact else "phone")
    _, phone_nat = _norm_phone(form.get("phone") or contact)
    try:
        cl = _setup_client(proxy, username)
        _restore_client_ids(cl, state, settings)
        if contact_type == "email":
            status, detail = _try_send_email(cl, state)
        else:
            status, detail = _try_send_sms(cl, state, phone_nat)
        _save_state(state_dir, username, state, settings, form)
        return {"ok": True, "sms_send": status, "email_send": status,
                "sms_detail": detail[:200], "email_detail": detail[:200]}
    except Exception as e:
        return {"ok": False, "error": _clean(str(e) or type(e).__name__), "step": "resend"}


def main() -> None:
    try:
        req = json.load(sys.stdin)
    except Exception:
        print(json.dumps({"ok": False, "error": "Input helper tidak valid."}))
        return
    phase = (req.get("phase") or "").strip()
    try:
        if phase == "start":
            res = _do_start(req)
        elif phase == "confirm":
            res = _do_confirm(req)
        elif phase == "resend":
            res = _do_resend(req)
        else:
            res = {"ok": False, "error": "Fase tidak dikenal."}
    except Exception as e:
        res = {"ok": False, "error": _clean(str(e) or type(e).__name__)}
    print(json.dumps(res, default=str))


if __name__ == "__main__":
    main()

"""kor - backend for the "קור" AC remote.

One HTTPS function with two ways to reach the AC through Tuya:
  share - QR login from the Smart Life app (no developer account)
  dev   - the official Tuya IoT developer API (Access ID + Secret)

Both create a session whose random key the app keeps; Tuya tokens never
leave the server. Sessions live in Firestore (kor_sessions/{sha256(key)}),
which client rules never expose - only this function (admin SDK) reads it.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import os
import secrets
import time
import uuid
from zoneinfo import ZoneInfo

import requests
from firebase_admin import firestore, initialize_app
from firebase_functions import https_fn, options
from tuya_sharing import LoginControl
from tuya_sharing.customerapi import CustomerApi, CustomerTokenInfo, SharingTokenListener

initialize_app()

# Public client id of the Smart Life "device sharing" login (same one Home Assistant uses).
SHARE_CLIENT_ID = "HA_3y9q4ak7g4ephrvke"
SHARE_SCHEMA = "haauthorize"

DEV_REGIONS = {
    "eu": "https://openapi.tuyaeu.com",
    "weu": "https://openapi-weaz.tuyaeu.com",
    "us": "https://openapi.tuyaus.com",
    "use": "https://openapi-ueaz.tuyaus.com",
    "in": "https://openapi.tuyain.com",
    "cn": "https://openapi.tuyacn.com",
}

ALLOWED_ORIGINS = {"https://elior-sasi.github.io", "http://localhost:8080", "http://127.0.0.1:8080"}
AC_CATEGORIES = {"kt", "ktkzq", "kts"}
TZ = ZoneInfo("Asia/Jerusalem")


def _db():
    return firestore.client()


def _sess_ref(key: str):
    return _db().collection("kor_sessions").document(hashlib.sha256(key.encode()).hexdigest())


def _new_session(data: dict) -> str:
    key = secrets.token_urlsafe(32)
    data["created"] = int(time.time())
    _sess_ref(key).set(data)
    return key


class ApiError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


# ---------------------------------------------------------------- share mode
class _SaveToken(SharingTokenListener):
    def __init__(self, ref):
        self.ref = ref

    def update_token(self, token_info):
        self.ref.update({"share.token_info": token_info})


def _share_api(sess: dict, ref) -> CustomerApi:
    s = sess["share"]
    return CustomerApi(CustomerTokenInfo(s["token_info"]), SHARE_CLIENT_ID, s["user_code"], s["endpoint"], _SaveToken(ref))


def _share_ok(resp):
    if not resp or not resp.get("success"):
        raise ApiError((resp or {}).get("msg") or "Tuya לא ענתה", 502)
    return resp.get("result")


def _share_devices(api: CustomerApi, only_id: str | None = None):
    out = []
    if only_id:
        items = _share_ok(api.get("/v1.0/m/life/ha/devices/detail", {"devIds": only_id})) or []
    else:
        items = []
        for home in _share_ok(api.get("/v1.0/m/life/users/homes")) or []:
            items += _share_ok(api.get("/v1.0/m/life/ha/home/devices", {"homeId": str(home["ownerId"])})) or []
    for it in items:
        spec = _share_ok(api.get(f"/v1.1/m/life/{it['id']}/specifications")) or {}
        out.append({
            "id": it["id"], "name": it.get("name", ""), "category": it.get("category", ""),
            "online": bool(it.get("online", True)),
            "status": {x["code"]: x["value"] for x in it.get("status", []) if "code" in x},
            "functions": [_fn(f) for f in spec.get("functions", [])],
            "statusRange": [_fn(f) for f in spec.get("status", [])],
        })
    return out


# ---------------------------------------------------------------- dev mode
_dev_tokens: dict[str, tuple[str, float]] = {}


def _dev_sign(cid, secret, t, nonce, method, path, body, token=""):
    body_hash = hashlib.sha256((body or "").encode()).hexdigest()
    string_to_sign = f"{method}\n{body_hash}\n\n{path}"
    msg = cid + token + t + nonce + string_to_sign
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest().upper()


def _dev_call(d: dict, method: str, path: str, body: dict | None = None, token: str | None = None):
    cid, secret, base = d["access_id"], d["access_secret"], d["endpoint"]
    if token is None:
        token = _dev_token(d)
    t, nonce = str(int(time.time() * 1000)), uuid.uuid4().hex
    raw = json.dumps(body, separators=(",", ":")) if body is not None else ""
    headers = {
        "client_id": cid, "t": t, "nonce": nonce, "sign_method": "HMAC-SHA256",
        "sign": _dev_sign(cid, secret, t, nonce, method, path, raw, token),
        "Content-Type": "application/json",
    }
    if token:
        headers["access_token"] = token
    r = requests.request(method, base + path, data=raw or None, headers=headers, timeout=20).json()
    if not r.get("success"):
        raise ApiError(f"Tuya: {r.get('msg', 'שגיאה')} ({r.get('code', '')})", 502)
    return r.get("result")


def _dev_token(d: dict) -> str:
    cached = _dev_tokens.get(d["access_id"])
    if cached and cached[1] > time.time() + 60:
        return cached[0]
    res = _dev_call(d, "GET", "/v1.0/token?grant_type=1", token="")
    _dev_tokens[d["access_id"]] = (res["access_token"], time.time() + int(res.get("expire_time", 3600)))
    return res["access_token"]


def _dev_devices(d: dict, only_id: str | None = None):
    if only_id:
        items = [_dev_call(d, "GET", f"/v1.0/devices/{only_id}")]
    else:
        items = _dev_call(d, "GET", "/v2.0/cloud/thing/device?page_size=20") or []
    out = []
    for it in items:
        did = it["id"]
        fns = (_dev_call(d, "GET", f"/v1.0/iot-03/devices/{did}/functions") or {}).get("functions", [])
        st = _dev_call(d, "GET", f"/v1.0/iot-03/devices/{did}/status") or []
        out.append({
            "id": did, "name": it.get("name") or it.get("customName", ""), "category": it.get("category", ""),
            "online": bool(it.get("isOnline", it.get("online", True))),
            "status": {x["code"]: x["value"] for x in st},
            "functions": [_fn(f) for f in fns], "statusRange": [],
        })
    return out


# ---------------------------------------------------------------- shared helpers
def _fn(f: dict) -> dict:
    vals = f.get("values")
    try:
        vals = json.loads(vals) if isinstance(vals, str) else vals
    except ValueError:
        pass
    return {"code": f.get("code"), "type": f.get("type"), "name": f.get("name", ""), "values": vals}


def _load(req) -> tuple[dict, object]:
    key = req.headers.get("X-Kor-Key", "")
    if len(key) < 20:
        raise ApiError("לא מחובר", 401)
    ref = _sess_ref(key)
    snap = ref.get()
    if not snap.exists:
        raise ApiError("החיבור פג - התחבר מחדש", 401)
    return snap.to_dict(), ref


def _devices(sess, ref, only_id=None):
    if sess["mode"] == "share":
        devs = _share_devices(_share_api(sess, ref), only_id)
    else:
        devs = _dev_devices(sess["dev"], only_id)
    devs.sort(key=lambda x: (x["category"] not in AC_CATEGORIES, x["name"]))
    return devs


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _send(sess, ref, did, cmds):
    if sess["mode"] == "share":
        _share_ok(_share_api(sess, ref).post(f"/v1.1/m/thing/{did}/commands", None, {"commands": cmds}))
    else:
        _dev_call(sess["dev"], "POST", f"/v1.0/iot-03/devices/{did}/commands", {"commands": cmds})


def _status(sess, ref, did) -> dict:
    if sess["mode"] == "share":
        items = _share_ok(_share_api(sess, ref).get("/v1.0/m/life/ha/devices/detail", {"devIds": did})) or []
        return {x["code"]: x["value"] for x in (items[0].get("status", []) if items else []) if "code" in x}
    st = _dev_call(sess["dev"], "GET", f"/v1.0/iot-03/devices/{did}/status") or []
    return {x["code"]: x["value"] for x in st}


def _sess_by_hash(h):
    ref = _db().collection("kor_sessions").document(h)
    snap = ref.get()
    return (snap.to_dict(), ref) if snap.exists else (None, ref)


def _tick():
    now = dt.datetime.now(TZ)
    hm, today, wd = now.strftime("%H:%M"), now.strftime("%Y-%m-%d"), (now.weekday() + 1) % 7
    ran, errs = 0, 0
    for snap in _db().collection("kor_schedules").where("enabled", "==", True).stream():
        sc = snap.to_dict()
        due = False
        if sc.get("once_at"):
            due = sc["once_at"] <= time.time()
        elif sc.get("time") == hm and wd in sc.get("days", []) and sc.get("last") != today + " " + hm:
            due = True
        if not due:
            continue
        try:
            sess, ref = _sess_by_hash(sc["sess"])
            if sess:
                _send(sess, ref, sc["device"], sc["cmds"])
                ran += 1
        except Exception:  # noqa: BLE001
            errs += 1
        if sc.get("once_at"):
            snap.reference.delete()
        else:
            snap.reference.update({"last": today + " " + hm})
    if now.minute % 2 == 0:
        for snap in _db().collection("kor_sessions").where("track", "==", True).stream():
            sess = snap.to_dict()
            did = sess.get("device")
            if not did:
                continue
            try:
                st = _status(sess, snap.reference, did)
            except Exception:  # noqa: BLE001
                continue
            on = st.get("switch", st.get("power", st.get("switch_1")))
            mode = str(st.get("mode", st.get("work_mode", "other")))
            if on:
                _db().collection("kor_stats").document(f"{snap.id}_{today}").set(
                    {"sess": snap.id, "date": today, "minutes": firestore.Increment(2),
                     "modes": {mode: firestore.Increment(2)}}, merge=True)
            try:
                _watch(snap, sess, did, st, bool(on), mode, now, today)
            except Exception:  # noqa: BLE001
                pass
    return {"ran": ran, "errors": errs}


FAULTS = ["E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "P8", "P9", "P10", "P11", "P12", "P13", "P14"]


def _fault_codes(v) -> list:
    try:
        v = int(v or 0)
    except (TypeError, ValueError):
        return []
    return [c for i, c in enumerate(FAULTS) if v >> i & 1]


def _notify(sess_id: str, msg: dict) -> int:
    n = 0
    for snap in _db().collection("toaster_push").where("sess", "==", sess_id).stream():
        try:
            code = _webpush(snap.to_dict()["sub"], msg)
            if code in (404, 410):
                snap.reference.delete()
            else:
                n += 1
        except Exception:  # noqa: BLE001
            pass
    return n


def _watch(snap, sess, did, st, on, mode, now, today):
    """Per tracked session, every 2 minutes: temperature log, fault alerts, thermostat."""
    temp = st.get("temp_current")
    if isinstance(temp, (int, float)):
        _db().collection("kor_temps").document(f"{snap.id}_{today}").set(
            {"sess": snap.id, "date": today, "t": {now.strftime("%H%M"): [temp, 1 if on else 0]}}, merge=True)
    f = int(st.get("fault") or 0) if str(st.get("fault", 0)).lstrip("-").isdigit() else 0
    if f != int(sess.get("fault") or 0):
        snap.reference.update({"fault": f})
        if f:
            _notify(snap.id, {"title": "תקלה במזגן", "body": "קוד " + ", ".join(_fault_codes(f) or [str(f)])})
    th = sess.get("thermo") or {}
    if not isinstance(temp, (int, float)) or time.time() - float(th.get("last") or 0) < 600:
        return
    stop, start = th.get("stop") or {}, th.get("start") or {}
    act, msg = None, ""
    if on and stop.get("en") and stop.get("t") is not None:
        t = float(stop["t"])
        if (mode == "hot" and temp >= t) or (mode in ("cold", "wet") and temp <= t):
            act, msg = [{"code": "switch", "value": False}], f"המזגן כובה - החדר הגיע ל-{temp:g}°"
    if not on and start.get("en") and start.get("t") is not None and start.get("cmds"):
        t = float(start["t"])
        if (start.get("dir") == "below" and temp <= t) or (start.get("dir") != "below" and temp >= t):
            act, msg = start["cmds"], f"המזגן הודלק - בחדר {temp:g}°"
    if act:
        _send(sess, snap.reference, did, act)
        snap.reference.update({"thermo.last": time.time()})
        if th.get("notify", True):
            _notify(snap.id, {"title": "תרמוסטט", "body": msg})


def _state(req):
    """Read-only status for home-screen widgets, authorized by the Siri link token."""
    k = req.args.get("k", "")
    tok = _db().collection("kor_actions").document(_h(k)).get() if len(k) > 10 else None
    if not tok or not tok.exists:
        raise ApiError("קישור לא תקף", 401)
    sid = tok.to_dict()["sess"]
    sess, ref = _sess_by_hash(sid)
    if not sess:
        raise ApiError("החיבור פג", 401)
    did = req.args.get("d") or sess.get("device")
    st = _status(sess, ref, did)
    timer, nxt = None, None
    now = dt.datetime.now(TZ)
    best = None
    for snap in _db().collection("kor_schedules").where("sess", "==", sid).stream():
        d = snap.to_dict()
        if d.get("once_at"):
            on = bool(d["cmds"][0].get("value")) if d.get("cmds") else False
            timer = {"at": d["once_at"], "power": on}
            continue
        if not d.get("enabled") or not d.get("time"):
            continue
        hh, mm = map(int, d["time"].split(":"))
        for add in range(8):
            day = now + dt.timedelta(days=add)
            if (day.weekday() + 1) % 7 not in (d.get("days") or []):
                continue
            at = day.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if at <= now:
                continue
            on = any(c.get("value") is True for c in d.get("cmds") or [] if c.get("code") == "switch")
            if best is None or at < best[0]:
                best = (at, on)
            break
    if best:
        nxt = {"at": best[0].timestamp(), "power": best[1]}
    return {"status": st, "timer": timer, "next": nxt, "fault": _fault_codes(st.get("fault")), "t": time.time()}


def _act(req):
    k = req.args.get("k", "")
    tok = _db().collection("kor_actions").document(_h(k)).get() if len(k) > 10 else None
    if not tok or not tok.exists:
        raise ApiError("קישור לא תקף - צור קישור חדש באפליקציה", 401)
    sess, ref = _sess_by_hash(tok.to_dict()["sess"])
    if not sess:
        raise ApiError("החיבור למזגן פג - התחבר מחדש באפליקציה", 401)
    raw = req.args.get("c", "")
    cmds = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode())
    _send(sess, ref, req.args.get("d") or sess.get("device"), cmds)
    if req.args.get("tm") is not None:  # optional auto-off in minutes
        _set_once(ref.id, req.args.get("d") or sess.get("device"), int(req.args["tm"]), [{"code": req.args.get("pc", "switch"), "value": False}])
    return req.args.get("s") or "בוצע"


def _set_once(sess_id, did, minutes, cmds):
    _db().collection("kor_schedules").document(sess_id + "_once").set({
        "sess": sess_id, "device": did, "enabled": True, "once_at": time.time() + minutes * 60, "cmds": cmds})


# ---------------------------------------------------------------- web push (toaster)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_vapid_cache = {}


def _vapid():
    if "k" not in _vapid_cache:
        raw = os.environ.get("VAPID_PEM", "")
        if not raw:
            raise ApiError("התראות עוד לא הותקנו בשרת - הרץ עדכון", 503)
        priv = serialization.load_pem_private_key(_unb64u(raw), None)
        pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        _vapid_cache["k"] = (priv, pub)
    return _vapid_cache["k"]


def _hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def _encrypt(sub: dict, payload: bytes) -> bytes:
    """RFC 8291 aes128gcm."""
    ua_pub = _unb64u(sub["keys"]["p256dh"])
    auth = _unb64u(sub["keys"]["auth"])
    as_priv = ec.generate_private_key(ec.SECP256R1())
    as_pub = as_priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    shared = as_priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_pub))
    ikm = _hmac(_hmac(auth, shared), b"WebPush: info\x00" + ua_pub + as_pub + b"\x01")
    salt = secrets.token_bytes(16)
    prk = _hmac(salt, ikm)
    cek = _hmac(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]
    nonce = _hmac(prk, b"Content-Encoding: nonce\x00\x01")[:12]
    ct = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    return salt + (4096).to_bytes(4, "big") + bytes([len(as_pub)]) + as_pub + ct


def _vapid_header(endpoint: str) -> str:
    priv, pub = _vapid()
    from urllib.parse import urlparse
    u = urlparse(endpoint)
    head = _b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = _b64u(json.dumps({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 12 * 3600,
                               "sub": "mailto:nmkhj5@gmail.com"}, separators=(",", ":")).encode())
    r, s_ = decode_dss_signature(priv.sign(f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256())))
    sig = _b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big"))
    return f"vapid t={head}.{claims}.{sig}, k={_b64u(pub)}"


def _webpush(sub: dict, data: dict) -> int:
    body = _encrypt(sub, json.dumps(data, ensure_ascii=False).encode())
    r = requests.post(sub["endpoint"], data=body, timeout=15, headers={
        "Authorization": _vapid_header(sub["endpoint"]), "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream", "TTL": "300", "Urgency": "high"})
    return r.status_code


def _push_due():
    """Called from each minute tick: send every alert due in the next ~58s at its exact second."""
    now = time.time()
    jobs = []
    for snap in _db().collection("toaster_push").where("at", ">", 0).stream():
        d = snap.to_dict()
        if d.get("at", 0) <= now + 55:
            # claim it first so an overlapping tick can't send it twice
            snap.reference.update({"at": 0})
            jobs.append((d["at"], snap.reference, d))
    sent = 0
    for at, ref, d in sorted(jobs, key=lambda x: x[0]):
        wait = at - time.time()
        if wait > 0:
            time.sleep(wait)
        try:
            code = _webpush(d["sub"], d.get("msg") or {"title": "הטוסט מוכן", "body": "החשמל נותק"})
            if code in (404, 410):
                ref.delete()
            else:
                sent += 1
        except Exception:  # noqa: BLE001
            pass
    return sent


def _push_route(path, body, ref):
    col = _db().collection("toaster_push")
    if path == "/push/key":
        return {"key": _b64u(_vapid()[1])}
    if path == "/push/subscribe":
        sub = body.get("sub") or {}
        if not sub.get("endpoint") or not (sub.get("keys") or {}).get("p256dh"):
            raise ApiError("מנוי התראות לא תקין")
        col.document(_h(sub["endpoint"])).set({"sess": ref.id, "sub": sub, "at": 0})
        return {"subscribed": True}
    if path == "/push/at":
        at = float(body.get("at") or 0)
        msg = {"title": str(body.get("title") or "הטוסט מוכן")[:60], "body": str(body.get("body") or "")[:120]}
        n = 0
        for snap in col.where("sess", "==", ref.id).stream():
            snap.reference.update({"at": at, "msg": msg})
            n += 1
        return {"armed": n}
    if path == "/push/cancel":
        for snap in col.where("sess", "==", ref.id).stream():
            snap.reference.update({"at": 0})
        return {"cancelled": True}
    if path == "/push/test":
        n = 0
        for snap in col.where("sess", "==", ref.id).stream():
            _webpush(snap.to_dict()["sub"], {"title": "בדיקה", "body": "ככה תיראה ההתראה כשהטוסט מוכן"})
            n += 1
        return {"sent": n}
    return None


def _route(req, path: str, body: dict):
    if path == "/share/qr":
        code = (body.get("userCode") or "").strip()
        if not code:
            raise ApiError("חסר User Code")
        r = LoginControl().qr_code(SHARE_CLIENT_ID, SHARE_SCHEMA, code)
        if not r.get("success"):
            raise ApiError(f"Tuya: {r.get('msg', 'הקוד לא התקבל')}")
        tok = r["result"]["qrcode"]
        return {"token": tok, "qr": f"tuyaSmart--qrLogin?token={tok}"}

    if path == "/share/poll":
        code, tok = (body.get("userCode") or "").strip(), body.get("token") or ""
        ok, info = LoginControl().login_result(tok, SHARE_CLIENT_ID, code)
        if not ok:
            return {"linked": False}
        key = _new_session({"mode": "share", "share": {
            "user_code": code, "terminal_id": info["terminal_id"], "endpoint": info["endpoint"],
            "token_info": {k: info[k] for k in ("t", "uid", "expire_time", "access_token", "refresh_token")},
        }})
        return {"linked": True, "key": key, "username": info.get("username", "")}

    if path == "/dev/link":
        region = body.get("region", "eu")
        d = {"access_id": (body.get("accessId") or "").strip(),
             "access_secret": (body.get("accessSecret") or "").strip(),
             "endpoint": DEV_REGIONS.get(region, DEV_REGIONS["eu"])}
        if not d["access_id"] or not d["access_secret"]:
            raise ApiError("חסרים Access ID או Secret")
        _dev_token(d)  # validates the credentials
        return {"linked": True, "key": _new_session({"mode": "dev", "dev": d})}

    if path == "/tick":
        if not os.environ.get("TICK_SECRET") or req.headers.get("X-Tick") != os.environ["TICK_SECRET"]:
            raise ApiError("forbidden", 403)
        out = _tick()
        try:
            out["pushed"] = _push_due()
        except Exception as e:  # noqa: BLE001
            out["push_error"] = str(e)
        return out

    if path == "/state":
        return _state(req)
    sess, ref = _load(req)
    if path.startswith("/push/"):
        res = _push_route(path, body, ref)
        if res is not None:
            return res
    if path == "/prefs":
        ref.update({"device": body.get("device"), "track": True})
        return {"saved": True}
    if path == "/token":
        tok = sess.get("act_token")
        if body.get("renew") and tok:
            _db().collection("kor_actions").document(_h(tok)).delete()
            tok = None
        if not tok:
            tok = secrets.token_urlsafe(18)
            _db().collection("kor_actions").document(_h(tok)).set({"sess": ref.id})
            ref.update({"act_token": tok})
        return {"token": tok}
    if path == "/schedules":
        out, timer = [], None
        for snap in _db().collection("kor_schedules").where("sess", "==", ref.id).stream():
            d = snap.to_dict()
            if d.get("once_at"):
                timer = {"at": d["once_at"], "power": bool(d["cmds"][0].get("value")) if d.get("cmds") else False}
            else:
                out.append({"id": snap.id, **{k: d.get(k) for k in ("time", "days", "label", "enabled", "cmds")}})
        out.sort(key=lambda x: x["time"] or "")
        return {"schedules": out, "timer": timer}
    if path == "/schedules/save":
        sid = body.get("id") or (ref.id + "_" + secrets.token_hex(4))
        if not sid.startswith(ref.id):
            raise ApiError("לא מורשה", 403)
        _db().collection("kor_schedules").document(sid).set({
            "sess": ref.id, "device": body.get("device"), "time": body.get("time"), "days": body.get("days") or [],
            "cmds": body.get("cmds") or [], "label": body.get("label", ""), "enabled": bool(body.get("enabled", True))})
        return {"id": sid}
    if path == "/schedules/delete":
        sid = body.get("id", "")
        if sid.startswith(ref.id):
            _db().collection("kor_schedules").document(sid).delete()
        return {"deleted": True}
    if path == "/timer/set":
        _set_once(ref.id, body.get("device"), int(body.get("minutes", 0)), body.get("cmds") or [])
        return {"set": True}
    if path == "/timer/clear":
        _db().collection("kor_schedules").document(ref.id + "_once").delete()
        return {"cleared": True}
    if path == "/stats":
        days = [s2.to_dict() for s2 in _db().collection("kor_stats").where("sess", "==", ref.id).stream()]
        days.sort(key=lambda x: x.get("date", ""), reverse=True)
        return {"days": days[:31]}
    if path == "/temps":
        out = []
        for s2 in _db().collection("kor_temps").where("sess", "==", ref.id).stream():
            d = s2.to_dict()
            out.append({"date": d.get("date"), "t": d.get("t") or {}})
        out.sort(key=lambda x: x.get("date", ""), reverse=True)
        return {"days": out[:7]}
    if path == "/thermo":
        return {"thermo": sess.get("thermo") or {}, "fault": _fault_codes(sess.get("fault")),
                "push": len(list(_db().collection("toaster_push").where("sess", "==", ref.id).stream()))}
    if path == "/thermo/save":
        th = body.get("thermo") or {}
        clean = {"stop": {"en": bool((th.get("stop") or {}).get("en")), "t": (th.get("stop") or {}).get("t")},
                 "start": {k: (th.get("start") or {}).get(k) for k in ("en", "t", "dir", "cmds", "label")},
                 "notify": bool(th.get("notify", True)), "last": 0}
        ref.update({"thermo": clean, "track": True, "device": body.get("device") or sess.get("device")})
        return {"saved": True}
    if path == "/notify/test":
        return {"sent": _notify(ref.id, {"title": "Breeze", "body": "ככה ייראו ההתראות מהמזגן"})}
    if path == "/push/off":
        for s2 in _db().collection("toaster_push").where("sess", "==", ref.id).stream():
            s2.reference.delete()
        return {"off": True}
    if path == "/debug":
        did = body.get("id", "")
        out = {"mode": sess["mode"]}
        def tryget(name, fn):
            try:
                out[name] = fn()
            except Exception as e:  # noqa: BLE001
                out[name] = "ERR " + str(e)[:300]
        if sess["mode"] == "share":
            api = _share_api(sess, ref)
            g = lambda p, q=None: api.get(p, q)  # noqa: E731
            tryget("detail", lambda: g("/v1.0/m/life/ha/devices/detail", {"devIds": did}))
            tryget("spec", lambda: g(f"/v1.1/m/life/{did}/specifications"))
            tryget("model", lambda: g(f"/v1.0/m/thing/{did}/model"))
            tryget("model2", lambda: g(f"/v2.0/m/thing/{did}/model"))
            tryget("props", lambda: g(f"/v2.0/m/thing/{did}/shadow/properties"))
            tryget("props1", lambda: g(f"/v1.0/m/thing/{did}/shadow/properties"))
        else:
            d = sess["dev"]
            tryget("info", lambda: _dev_call(d, "GET", f"/v1.0/devices/{did}"))
            tryget("spec", lambda: _dev_call(d, "GET", f"/v1.0/iot-03/devices/{did}/specification"))
            tryget("model", lambda: _dev_call(d, "GET", f"/v2.0/cloud/thing/{did}/model"))
            tryget("props", lambda: _dev_call(d, "GET", f"/v2.0/cloud/thing/{did}/shadow/properties"))
        txt = json.dumps(out, ensure_ascii=False)
        for k in ("local_key", "localKey", "uuid", "ip", "lat", "lon"):
            txt = re.sub(r'"%s"\s*:\s*"[^"]*"' % k, '"%s":"-"' % k, txt)
        return json.loads(txt)
    if path == "/probe":
        did = body.get("id", "")
        try:
            if body.get("props") is not None:
                props = json.dumps(body["props"])
                if sess["mode"] == "share":
                    r = _share_api(sess, ref).post(f"/v2.0/m/thing/{did}/shadow/properties/issue", None, {"properties": props})
                else:
                    r = _dev_call(sess["dev"], "POST", f"/v2.0/cloud/thing/{did}/shadow/properties/issue", {"properties": props})
            else:
                cmds = body.get("commands") or []
                if sess["mode"] == "share":
                    r = _share_api(sess, ref).post(f"/v1.1/m/thing/{did}/commands", None, {"commands": cmds})
                else:
                    r = _dev_call(sess["dev"], "POST", f"/v1.0/iot-03/devices/{did}/commands", {"commands": cmds})
            return {"resp": r}
        except Exception as e:  # noqa: BLE001
            return {"resp": "ERR " + str(e)[:300]}
    if path == "/devices":
        return {"mode": sess["mode"], "devices": _devices(sess, ref)}
    if path == "/device":
        did = body.get("id") or req.args.get("id", "")
        devs = _devices(sess, ref, did)
        return {"device": devs[0] if devs else None}
    if path == "/command":
        did, cmds = body.get("id"), body.get("commands") or []
        if not did or not cmds:
            raise ApiError("פקודה ריקה")
        _send(sess, ref, did, cmds)
        return {"sent": True}
    if path == "/logout":
        ref.delete()
        return {"loggedOut": True}
    raise ApiError("נתיב לא מוכר", 404)


@https_fn.on_request(region="europe-west1", memory=options.MemoryOption.MB_256, timeout_sec=120)
def kor(req: https_fn.Request) -> https_fn.Response:
    origin = req.headers.get("Origin", "")
    cors = {
        "Access-Control-Allow-Origin": origin if origin in ALLOWED_ORIGINS else "https://elior-sasi.github.io",
        "Access-Control-Allow-Headers": "Content-Type, X-Kor-Key",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Vary": "Origin",
    }
    if req.method == "OPTIONS":
        return https_fn.Response("", status=204, headers=cors)
    path = "/" + req.path.strip("/").split("/", 1)[-1] if req.path.strip("/").startswith("kor") else req.path
    path = "/" + path.strip("/")
    if path == "/act":
        try:
            txt, st = _act(req), 200
        except ApiError as e:
            txt, st = str(e), e.status
        except Exception as e:  # noqa: BLE001
            txt, st = f"שגיאה: {e}", 500
        return https_fn.Response(txt, status=st, headers={**cors, "Content-Type": "text/plain; charset=utf-8"})
    try:
        body = req.get_json(silent=True) or {}
        out = {"ok": True, **_route(req, path, body)}
        status = 200
    except ApiError as e:
        out, status = {"ok": False, "error": str(e)}, e.status
    except Exception as e:  # noqa: BLE001
        out, status = {"ok": False, "error": f"שגיאת שרת: {e}"}, 500
    return https_fn.Response(json.dumps(out, ensure_ascii=False), status=status,
                             headers={**cors, "Content-Type": "application/json; charset=utf-8"})

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
            if on:
                mode = str(st.get("mode", st.get("work_mode", "other")))
                _db().collection("kor_stats").document(f"{snap.id}_{today}").set(
                    {"sess": snap.id, "date": today, "minutes": firestore.Increment(2),
                     "modes": {mode: firestore.Increment(2)}}, merge=True)
    return {"ran": ran, "errors": errs}


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
        return _tick()

    sess, ref = _load(req)
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


@https_fn.on_request(region="europe-west1", memory=options.MemoryOption.MB_256, timeout_sec=60)
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

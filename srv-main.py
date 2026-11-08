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


def _homes(sess, ref):
    """Smart Life homes + the room of every device, for Unplug's home/room tabs."""
    homes, where = [], {}
    if sess["mode"] == "share":
        api = _share_api(sess, ref)
        for home in _share_ok(api.get("/v1.0/m/life/users/homes")) or []:
            hid = str(home.get("ownerId") or home.get("homeId") or home.get("id"))
            homes.append({"id": hid, "name": home.get("name", "")})
            for it in _share_ok(api.get("/v1.0/m/life/ha/home/devices", {"homeId": hid})) or []:
                room = None
                try:
                    r = api.get(f"/v1.0/m/thing/ha/{it['id']}/room")
                    if r and r.get("success") and r.get("result"):
                        room = {"id": str(r["result"].get("roomId") or r["result"].get("id") or ""), "name": r["result"].get("name", "")}
                except Exception:  # noqa: BLE001
                    pass
                where[it["id"]] = {"home": hid, "room": room}
    else:
        d = sess["dev"]
        uid = (_dev_call(d, "GET", "/v2.0/cloud/thing/device?page_size=1") or [{}])[0].get("uid", "")
        for home in (_dev_call(d, "GET", f"/v1.0/users/{uid}/homes") or []) if uid else []:
            hid = str(home.get("home_id"))
            homes.append({"id": hid, "name": home.get("name", "")})
            rooms = {}
            for rm in (_dev_call(d, "GET", f"/v1.0/homes/{hid}/rooms") or {}).get("rooms", []):
                rooms[str(rm.get("room_id"))] = rm.get("name", "")
                for dv in _dev_call(d, "GET", f"/v1.0/homes/{hid}/rooms/{rm.get('room_id')}/devices") or []:
                    where[dv.get("id")] = {"home": hid, "room": {"id": str(rm.get("room_id")), "name": rm.get("name", "")}}
            for dv in _dev_call(d, "GET", f"/v1.0/homes/{hid}/devices") or []:
                where.setdefault(dv.get("id"), {"home": hid, "room": None})
    return {"homes": homes, "where": where}


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
        t = str(sc.get("time") or "")
        if sc.get("once_at"):
            due = sc["once_at"] <= time.time()
        elif wd in sc.get("days", []) and t and t <= hm and sc.get("last") != today + " " + t:
            # catch up if a tick was late or skipped (up to 5 minutes), instead of losing the day's run
            try:
                at = now.replace(hour=int(t[:2]), minute=int(t[3:5]), second=0, microsecond=0)
                late = (now - at).total_seconds()
            except ValueError:
                at, late = now, 999
            # a schedule saved after its time today (e.g. 07:00 saved at 07:02) starts tomorrow, not now
            due = 0 <= late < 5 * 60 and float(sc.get("saved") or 0) < at.timestamp()
        if not due:
            continue
        ok = False
        try:
            sess, ref = _sess_by_hash(sc["sess"])
            if sess and sc.get("device") == "mova-e30-ultra":
                # the vacuum: start cleaning (whole home or chosen rooms) through the MOVAhome cloud
                V, d = _mova_dev(ref, sess.get("mova") or {})
                for c in sc.get("cmds") or []:
                    v = c.get("value") if isinstance(c.get("value"), dict) else {}
                    V.act(d, str(v.get("a") or "start"), v)
                V._quiet(d)
                ran += 1
                ok = True
            elif sess:
                _send(sess, ref, sc["device"], sc["cmds"])
                ran += 1
                ok = True
        except Exception:  # noqa: BLE001
            errs += 1
        if sc.get("once_at") or sc.get("once"):
            # a one-time timer that failed (device or cloud hiccup) gets two more tries a minute apart
            tries = int(sc.get("tries") or 0) + 1
            if ok or tries >= 3:
                snap.reference.delete()
            else:
                snap.reference.update({"tries": tries})
        else:
            snap.reference.update({"last": today + " " + (t or hm)})
    if now.minute % 2 == 0:
        # the vacuum: tell the phone when it finished or got stuck
        for snap in _db().collection("kor_sessions").where("mova_notify", "==", True).stream():
            sess = snap.to_dict()
            mv = sess.get("mova") or {}
            if not mv.get("did"):
                continue
            try:
                V, d = _mova_dev(snap.reference, mv)
                msgs, new = V.notice(V.snapshot(d)["state"], sess.get("mova_last") or {})
                snap.reference.update({"mova_last": new})
                for m in msgs:
                    _notify(snap.id, dict(m, url="./#dev=mova-e30-ultra"))
            except Exception:  # noqa: BLE001
                pass
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
    if now.minute % 2 == 1:
        for snap in _db().collection("kor_sessions").where("guard_on", "==", True).stream():
            sd = snap.to_dict()
            try:
                if (sd.get("guard") or {}).get("rules"):
                    _guard(snap, sd)
            except Exception:  # noqa: BLE001
                pass
            try:
                if sd.get("home"):
                    _home(snap, _sess_by_hash(snap.id)[0] or sd, now)
            except Exception:  # noqa: BLE001
                pass
    return {"ran": ran, "errors": errs}


POWER_CODES = ("switch", "switch_1", "switch_led", "power")


def _guard(snap, sess):
    """House guard, every 2 minutes: device left on too long, or a machine finished (power dropped)."""
    rules = [r for r in (sess.get("guard") or {}).get("rules", []) if r.get("enabled", True)]
    state = dict(sess.get("guard_state") or {})
    now = time.time()
    cache = {}
    for r in rules:
        did = r["device"]
        if did not in cache:
            try:
                cache[did] = _status(sess, snap.reference, did)
            except Exception:  # noqa: BLE001
                cache[did] = None
        st = cache[did]
        if st is None:
            continue
        g = dict(state.get(r["id"]) or {})
        name = r.get("name") or "מכשיר"
        if r["kind"] == "on_long":
            pc = r.get("pcode") or next((c for c in POWER_CODES if isinstance(st.get(c), bool)), None)
            if pc and st.get(pc) is True:
                g.setdefault("since", now)
                if not g.get("sent") and now - g["since"] >= r["minutes"] * 60:
                    mins = int((now - g["since"]) // 60)
                    _notify(snap.id, {"title": f"{name} עדיין דלוק", "body": f"דלוק כבר {mins} דקות. הקש כדי לכבות.", "tag": "guard-" + r["id"], "url": "./#dev=" + did})
                    g["sent"] = True
            else:
                g = {}
        else:
            raw = st.get("cur_power")
            if not isinstance(raw, (int, float)):
                continue
            w = raw / (10 ** int(r.get("scale") or 0))
            if w >= 8:
                if g.get("end"):
                    g = {}
                g.setdefault("run", now)
                g["low"] = 0
                g["w"] = round(w)
            elif g.get("run"):
                g["low"] = int(g.get("low") or 0) + 1
                g["w"] = round(w)
                if g["low"] >= 2 and now - g["run"] >= r["minutes"] * 60:
                    mins = int((now - g["run"]) // 60)
                    exp = int(r.get("expect") or 0)
                    if exp and mins < exp * 0.6:
                        _notify(snap.id, {"title": f"{name} עצרה באמצע?", "body": f"הצריכה ירדה אחרי {mins} דק׳, מוקדם מהצפוי. כדאי לבדוק.", "tag": "guard-" + r["id"], "url": "./#dev=" + did})
                    else:
                        _notify(snap.id, {"title": f"{name} סיים", "body": "הצריכה ירדה - נראה שהתוכנית נגמרה.", "tag": "guard-" + r["id"], "url": "./#dev=" + did})
                    g = {"end": now, "began": g["run"]}
                elif g["low"] >= 6:
                    g = {}
            elif g.get("end") and r.get("remind") and not g.get("rem") and now - g["end"] >= 30 * 60:
                _notify(snap.id, {"title": f"{name}: הכביסה מחכה", "body": "סיימה לפני חצי שעה. לא לשכוח לפרוק.", "tag": "guard-" + r["id"], "url": "./#dev=" + did})
                g["rem"] = True
        state[r["id"]] = g
    snap.reference.update({"guard_state": state})


def _bulk(sess, ref, ids):
    """Status + online for many devices in as few calls as possible."""
    out = {}
    ids = [i for i in dict.fromkeys(ids) if i]
    if not ids:
        return out
    if sess["mode"] == "share":
        api = _share_api(sess, ref)
        for i in range(0, len(ids), 20):
            for it in _share_ok(api.get("/v1.0/m/life/ha/devices/detail", {"devIds": ",".join(ids[i:i + 20])})) or []:
                out[it["id"]] = {"online": bool(it.get("online", True)),
                                 "status": {x["code"]: x["value"] for x in it.get("status", []) if "code" in x}}
    else:
        for d in ids:
            try:
                out[d] = {"online": True, "status": _status(sess, ref, d)}
            except Exception:  # noqa: BLE001
                pass
    return out


def _num(st, code, scale):
    v = st.get(code)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return v / (10 ** int(scale or 0))


def _weather(loc):
    """Outdoor temperature now and today's max/min at the home location (Open-Meteo, no key)."""
    try:
        r = requests.get("https://api.open-meteo.com/v1/forecast", timeout=8, params={
            "latitude": loc["lat"], "longitude": loc["lon"], "current": "temperature_2m",
            "daily": "temperature_2m_max,temperature_2m_min", "timezone": "Asia/Jerusalem", "forecast_days": 1})
        j = r.json()
        return {"now": j["current"]["temperature_2m"], "max": j["daily"]["temperature_2m_max"][0], "min": j["daily"]["temperature_2m_min"][0]}
    except Exception:  # noqa: BLE001
        return None


def _hebcal(sh, hs, now):
    """Shabbat and holiday times for the next 3 weeks (Hebcal), refreshed once a day.
    Returns (ins, outs): when each Shabbat/holiday block starts (first candle lighting) and ends (havdalah)."""
    c = hs.get("hc") or {}
    key = f"{now.strftime('%Y-%m-%d')}|{sh.get('lat')}|{sh.get('lon')}|{sh.get('candle')}"
    if c.get("k") != key:
        try:
            r = requests.get("https://www.hebcal.com/hebcal", timeout=10, params={
                "v": 1, "cfg": "json", "maj": "on", "c": "on", "i": "on", "M": "on", "geo": "pos",
                "latitude": sh["lat"], "longitude": sh["lon"], "tzid": "Asia/Jerusalem", "b": int(sh.get("candle") or 30),
                "start": (now - dt.timedelta(days=1)).strftime("%Y-%m-%d"), "end": (now + dt.timedelta(days=21)).strftime("%Y-%m-%d")})
            ev = []
            for it in r.json().get("items", []):
                if it.get("category") in ("candles", "havdalah") and "T" in it.get("date", ""):
                    ev.append([dt.datetime.fromisoformat(it["date"]).timestamp(), it["category"]])
            ev.sort()
            c = {"k": key, "ev": ev}
            hs["hc"] = c
        except Exception:  # noqa: BLE001
            return [], []
    ins, outs, prev = [], [], None
    for t, cat in c.get("ev", []):
        if cat == "candles" and prev != "candles":
            ins.append(t)
        elif cat == "havdalah":
            outs.append(t)
        prev = cat
    return ins, outs


WX_KINDS = ("out_above", "out_below", "fc_above", "fc_below")


def _home(snap, sess, now):
    """HomeOn, every 2 minutes: energy use, offline alerts and if-then automations."""
    h = sess.get("home") or {}
    en, off, autos = h.get("energy") or {}, h.get("offline") or {}, [a for a in (h.get("autos") or []) if a.get("enabled", True)]
    ids = []
    if en.get("on"):
        ids += [d["id"] for d in en.get("devs", [])]
    if off.get("on"):
        ids += [d["id"] for d in off.get("devs", [])]
    for a in autos:
        ids += [a.get("if", {}).get("device"), a.get("then", {}).get("device")]
    sh = h.get("shabbat") or {}
    if not ids and not sh.get("on"):
        return
    data = _bulk(sess, snap.reference, ids)
    hs = dict(sess.get("home_state") or {})
    sid = snap.id
    t = time.time()
    wx = _weather(h["loc"]) if h.get("loc") and any((a.get("if") or {}).get("kind") in WX_KINDS for a in autos) else None
    # energy: watt-hours per device per day
    if en.get("on"):
        add = {}
        for d in en.get("devs", []):
            st = (data.get(d["id"]) or {}).get("status") or {}
            w = _num(st, "cur_power", d.get("scale", 1))
            if w and w > 0.5:
                add[d["id"]] = firestore.Increment(round(w * 2 / 60, 3))
        if add:
            _db().collection("kor_energy").document(f"{sid}_{now.strftime('%Y-%m-%d')}").set(
                {"sess": sid, "date": now.strftime("%Y-%m-%d"), "wh": add}, merge=True)
    # offline / back online
    if off.get("on"):
        for d in off.get("devs", []):
            info = data.get(d["id"])
            if not info:
                continue
            k = "o_" + d["id"]
            g = dict(hs.get(k) or {})
            if not info["online"]:
                g["n"] = int(g.get("n") or 0) + 1
                if g["n"] >= 3 and not g.get("sent"):
                    _notify(sid, {"title": f"{d.get('name') or 'מכשיר'} התנתק", "body": "כבר כמה דקות בלי חיבור. אולי הפסקת חשמל או בעיה ב-WiFi.", "tag": k, "url": "./#dev=" + d["id"]})
                    g["sent"] = t
            else:
                if g.get("sent"):
                    mins = int((t - g["sent"]) // 60) + 6
                    _notify(sid, {"title": f"{d.get('name') or 'מכשיר'} חזר לרשת", "body": f"היה מנותק בערך {mins} דקות.", "tag": k, "url": "./#dev=" + d["id"]})
                g = {}
            hs[k] = g
    # if-then automations, fired when the condition becomes true
    for a in autos:
        c, th = a.get("if") or {}, a.get("then") or {}
        kind, ok = c.get("kind"), None
        if kind in WX_KINDS:
            info = {"status": {}}
        else:
            info = data.get(c.get("device"))
        if not info:
            continue
        st = info["status"]
        if kind in WX_KINDS:
            if wx:
                v = float(c.get("value", 0))
                if kind == "out_above":
                    ok = wx["now"] > v
                elif kind == "out_below":
                    ok = wx["now"] < v
                else:  # forecast, checked from a set time of day: false before it, so it fires once a day
                    at = c.get("at") or "07:00"
                    ok = now.strftime("%H:%M") >= at and (wx["max"] > v if kind == "fc_above" else wx["min"] < v)
        elif kind in ("temp_above", "temp_below"):
            v = _num(st, c.get("code") or "temp_current", c.get("scale", 0))
            if v is not None:
                ok = v > float(c.get("value", 0)) if kind == "temp_above" else v < float(c.get("value", 0))
        elif kind in ("turns_on", "turns_off"):
            v = st.get(c.get("code") or "switch")
            if isinstance(v, bool):
                ok = v if kind == "turns_on" else not v
        elif kind in ("power_above", "power_below"):
            v = _num(st, "cur_power", c.get("scale", 1))
            if v is not None:
                ok = v > float(c.get("value", 0)) if kind == "power_above" else v < float(c.get("value", 0))
        if ok is None:
            continue
        k = "a_" + str(a.get("id"))
        g = dict(hs.get(k) or {})
        prev = g.get("ok")
        if ok and prev is False and t - float(g.get("at") or 0) > 60 * int(a.get("cool", 10)):
            try:
                _send(sess, snap.reference, th["device"], th["cmds"])
                g["at"] = t
                if a.get("notify"):
                    _notify(sid, {"title": a.get("name") or "אוטומציה", "body": a.get("text") or "הופעלה", "tag": k, "url": "./#dev=" + th["device"]})
            except Exception:  # noqa: BLE001
                pass
        g["ok"] = ok
        hs[k] = g
    # Shabbat and holidays: actions around candle lighting / havdalah, run by the server every week
    if sh.get("on") and sh.get("lat") is not None:
        ins, outs = _hebcal(sh, hs, now)
        done = list(hs.get("shb") or [])
        for i, a in enumerate(sh.get("acts") or []):
            for base in (ins if a.get("when") == "in" else outs):
                at = base + 60 * int(a.get("off") or 0)
                tag = f"{i}@{int(at)}"
                if 0 <= t - at < 20 * 60 and tag not in done:
                    try:
                        _send(sess, snap.reference, a["device"], [{"code": a.get("pcode") or "switch", "value": a.get("to") == "on"}])
                    except Exception:  # noqa: BLE001
                        pass
                    done.append(tag)
        hs["shb"] = done[-60:]
    snap.reference.update({"home_state": hs})


def _home_on(h):
    h = h or {}
    return bool((h.get("energy") or {}).get("on") or (h.get("offline") or {}).get("on") or (h.get("shabbat") or {}).get("on")
                or any(a.get("enabled", True) for a in h.get("autos") or []))


def _clean_home(h):
    def devs(lst):
        return [{"id": str(d.get("id")), "name": str(d.get("name") or "")[:60], "scale": int(d.get("scale") or 0)} for d in (lst or [])[:60] if d.get("id")]
    en, off = h.get("energy") or {}, h.get("offline") or {}
    autos = []
    for a in (h.get("autos") or [])[:30]:
        c, th = a.get("if") or {}, a.get("then") or {}
        wxk = c.get("kind") in WX_KINDS
        if (not c.get("device") and not wxk) or not th.get("device") or not isinstance(th.get("cmds"), list):
            continue
        autos.append({"id": str(a.get("id") or secrets.token_hex(4)), "name": str(a.get("name") or "")[:80], "text": str(a.get("text") or "")[:120],
                      "enabled": bool(a.get("enabled", True)), "notify": bool(a.get("notify")), "cool": max(1, min(1440, int(a.get("cool") or 10))),
                      "if": {"device": str(c.get("device") or ""), "kind": str(c.get("kind") or ""), "code": str(c.get("code") or ""), "scale": int(c.get("scale") or 0),
                             "value": float(c.get("value") or 0), "at": str(c.get("at") or "07:00")[:5]},
                      "then": {"device": str(th["device"]), "cmds": th["cmds"][:5]}})
    out = {"energy": {"on": bool(en.get("on")), "price": float(en.get("price") or 0.64), "devs": devs(en.get("devs"))},
           "offline": {"on": bool(off.get("on")), "devs": devs(off.get("devs"))}, "autos": autos}
    loc = h.get("loc") or {}
    if loc.get("lat") is not None and loc.get("lon") is not None:
        out["loc"] = {"lat": float(loc["lat"]), "lon": float(loc["lon"]), "name": str(loc.get("name") or "")[:40]}
    sh = h.get("shabbat") or {}
    if sh:
        out["shabbat"] = {"on": bool(sh.get("on")), "lat": float(sh.get("lat") or 32.085), "lon": float(sh.get("lon") or 34.782),
                          "candle": max(0, min(60, int(sh.get("candle") or 21))), "city": str(sh.get("city") or "")[:10],
                          "acts": [{"device": str(a["device"]), "pcode": str(a.get("pcode") or "switch"), "to": "on" if a.get("to") == "on" else "off",
                                    "when": "out" if a.get("when") == "out" else "in", "off": max(-600, min(600, int(a.get("off") or 0)))}
                                   for a in (sh.get("acts") or [])[:30] if a.get("device")]}
    return out


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
    if req.args.get("m"):  # several devices in one link: [{"d": id, "c": [commands]}, ...]
        raw = req.args["m"]
        items = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode())
        ok = 0
        for it in items[:40]:
            try:
                _send(sess, ref, it["d"], it["c"])
                ok += 1
            except Exception:  # noqa: BLE001
                pass
        return req.args.get("s") or f"בוצע ({ok})"
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


# ---------------- MOVA E30 Ultra (MOVAhome cloud, like the MOVAhome app) ----------------
# The cloud protocol is vendored from Tasshack/dreame-vacuum (MIT) as mova.py next to this file.
# The password is used once to log in and is never stored; only the account e-mail, region,
# the vacuum id and the refresh token are kept in the session.
_VAC = None
MOVA_REGIONS = ("eu", "us", "sg", "ru", "cn")


def _vac():
    """The vacuum module and the vendored dreame-vacuum library load only when the vacuum is used."""
    global _VAC
    if _VAC is None:
        import importlib.util
        import sys
        here = os.path.dirname(os.path.abspath(__file__))
        if not os.path.exists(os.path.join(here, "vac.py")) or not os.path.isdir(os.path.join(here, "dreame")):
            raise ApiError("השרת צריך עדכון כדי לחבר את השואב")
        if here not in sys.path:
            sys.path.insert(0, here)
        spec = importlib.util.spec_from_file_location("homeon_vac", os.path.join(here, "vac.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _VAC = mod
    return _VAC


def _mova_login(user, pw, country):
    _vac()
    from dreame.protocol import DreameVacuumDreameHomeCloudProtocol
    c = DreameVacuumDreameHomeCloudProtocol(user, pw, "mova", country, None, None)
    if not c.login():
        return None
    return c


def _mova_dev(ref, mv, fresh=True):
    V = _vac()
    try:
        d, new_auth = V.device(ref.id, mv, fresh)
    except V.VacError as e:
        raise ApiError(str(e), 409 if e.status == 409 else 400) from None
    if new_auth:
        mv = dict(mv, auth=new_auth)
        ref.update({"mova": mv})
    return V, d


def _mova_route(path, body, sess, ref):
    mv = sess.get("mova") or {}
    if path == "/mova/login":
        user, pw = str(body.get("email") or "").strip(), str(body.get("password") or "")
        if not user or not pw:
            raise ApiError("צריך אימייל וסיסמה של MOVAhome")
        regions = [body["country"]] if body.get("country") in MOVA_REGIONS else list(MOVA_REGIONS)
        last = None
        for country in regions:
            c = _mova_login(user, pw, country)
            if c is None:
                last = ApiError("האימייל או הסיסמה של MOVAhome לא נכונים", 409)
                continue
            data = c.get_devices() or {}
            recs = ((data.get("page") or {}).get("records")) or []
            vac = [r for r in recs if ".vacuum." in str(r.get("model", ""))]
            if not vac:
                last = ApiError("החשבון מחובר, אבל לא נמצא בו שואב")
                continue
            r = vac[0]
            name = r.get("customName") or (r.get("deviceInfo") or {}).get("displayName") or "MOVA"
            mv = {"user": user, "country": country, "did": str(r["did"]), "model": r.get("model", ""), "name": name,
                  "mac": r.get("mac") or "", "bind": r.get("bindDomain") or "", "auth": c.auth_key}
            ref.update({"mova": mv})
            _vac().forget(ref.id)
            return {"mova": {"name": name, "model": mv["model"]}}
        raise last or ApiError("לא הצלחתי להתחבר ל-MOVAhome")
    if path == "/mova/logout":
        ref.update({"mova": firestore.DELETE_FIELD})
        try:
            _vac().forget(ref.id)
        except ApiError:
            pass
        return {"done": True}
    if path == "/mova/notify":
        ref.update({"mova_notify": bool(body.get("on")), "mova_last": {}})
        return {"on": bool(body.get("on"))}
    if not mv.get("did"):
        raise ApiError("השואב לא מחובר", 404)
    V, d = _mova_dev(ref, mv, path not in ("/mova/move", "/mova/obstacle", "/mova/hmap"))
    try:
        if path == "/mova/state":
            out = V.snapshot(d)
            out["name"] = mv.get("name") or out.get("name") or "MOVA"
            out["notify"] = bool(sess.get("mova_notify"))
            return out
        if path == "/mova/map":
            m = V.render_map(ref.id, d)
            if not m:
                return {"map": None}
            return {"map": m}
        if path == "/mova/act":
            V.act(d, str(body.get("a") or ""), body, ref.id)
            V._quiet(d)
            return {"sent": True, **V.snapshot(d)}
        if path == "/mova/hmap":
            return {"png": V.history_png(ref.id, d, int(body.get("i") or 0))}
        if path == "/mova/obstacle":
            return {"img": V.obstacle_image(d, body.get("i"))}
        if path == "/mova/move":
            V.act(d, "move", body, ref.id)
            return {"sent": True}
        if path == "/mova/edit":
            V.edit(ref.id, d, body)
            V._quiet(d)
            m = V.render_map(ref.id, d)
            return {"sent": True, "map": m, **V.snapshot(d)}
        if path == "/mova/set":
            V.set_value(d, str(body.get("k") or ""), body.get("v"))
            V._quiet(d)
            return {"sent": True, **V.snapshot(d)}
    except V.VacError as e:
        raise ApiError(str(e)) from None
    except ApiError:
        raise
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if not msg or not any("\u0590" <= ch <= "\u05ff" for ch in msg):
            msg = "השואב לא קיבל את הפקודה"
        raise ApiError(msg) from None
    raise ApiError("לא נמצא", 404)


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
    if path == "/recover":
        code = re.sub(r"[^A-Z0-9]", "", str(body.get("code", "")).upper())
        if len(code) != 10:
            raise ApiError("הקוד צריך להיות 10 תווים")
        snap = _db().collection("kor_recover").document(_h(code)).get()
        if not snap.exists:
            raise ApiError("קוד לא נכון")
        d = snap.to_dict()
        try:
            raw = _unb64u(d["enc"])
            key = AESGCM(hashlib.sha256(("rk:" + code).encode()).digest()).decrypt(raw[:12], raw[12:], None).decode()
        except Exception:  # noqa: BLE001
            raise ApiError("קוד לא נכון")
        if not _sess_ref(key).get().exists:
            raise ApiError("החיבור הזה כבר לא קיים - התחבר מחדש עם QR")
        return {"key": key}
    sess, ref = _load(req)
    if path.startswith("/push/"):
        res = _push_route(path, body, ref)
        if res is not None:
            return res
    if path == "/meta":
        return {"meta": sess.get("ui_meta")}
    if path == "/meta/save":
        m = body.get("meta")
        if isinstance(m, dict) and len(json.dumps(m)) < 400_000:
            ref.update({"ui_meta": m})
            return {"saved": True}
        return {"saved": False}
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
                out.append({"id": snap.id, **{k: d.get(k) for k in ("device", "time", "days", "label", "enabled", "cmds", "once")}})
        out.sort(key=lambda x: x["time"] or "")
        return {"schedules": out, "timer": timer, "once": True}
    if path == "/schedules/save":
        sid = body.get("id") or (ref.id + "_" + secrets.token_hex(4))
        if not sid.startswith(ref.id):
            raise ApiError("לא מורשה", 403)
        _db().collection("kor_schedules").document(sid).set({
            "sess": ref.id, "device": body.get("device"), "time": body.get("time"), "days": body.get("days") or [],
            "cmds": body.get("cmds") or [], "label": body.get("label", ""), "enabled": bool(body.get("enabled", True)),
            "once": bool(body.get("once")), "saved": time.time()})
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
    if path == "/recover/create":
        old = sess.get("recover")
        if old and not body.get("renew"):
            return {"code": old}
        abc = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        code = "".join(secrets.choice(abc) for _ in range(10))
        if old:
            _db().collection("kor_recover").document(_h(re.sub(r"[^A-Z0-9]", "", old))).delete()
        key = req.headers.get("X-Kor-Key", "")
        nonce = secrets.token_bytes(12)
        enc = nonce + AESGCM(hashlib.sha256(("rk:" + code).encode()).digest()).encrypt(nonce, key.encode(), None)
        _db().collection("kor_recover").document(_h(code)).set({"enc": _b64u(enc), "sess": ref.id, "at": time.time()})
        pretty = code[:5] + "-" + code[5:]
        ref.update({"recover": pretty})
        return {"code": pretty}
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
    if path == "/homes":
        return _homes(sess, ref)
    if path == "/home":
        return {"home": sess.get("home") or {}}
    if path == "/home/save":
        hm_ = _clean_home(body.get("home") or {})
        ref.update({"home": hm_, "guard_on": _home_on(hm_) or any(r.get("enabled", True) for r in (sess.get("guard") or {}).get("rules", []))})
        return {"saved": True}
    if path.startswith("/mova/"):
        return _mova_route(path, body, sess, ref)
    if path == "/states":  # light on/off + online for the widget and Siri
        ids = [str(i) for i in (body.get("ids") or [])][:40]
        out = {}
        for did, info in _bulk(sess, ref, ids).items():
            st = info.get("status") or {}
            on = next((st[c] for c in POWER_CODES if isinstance(st.get(c), bool)), None)
            out[did] = {"online": info.get("online", True), "on": on}
        return {"states": out}
    if path == "/weather":
        loc = body.get("loc") or (sess.get("home") or {}).get("loc")
        return {"weather": _weather(loc) if loc else None}
    if path == "/energy":
        days = max(1, min(62, int(body.get("days") or 31)))
        today_ = dt.datetime.now(TZ).date()
        refs = [_db().collection("kor_energy").document(f"{ref.id}_{(today_ - dt.timedelta(days=i)).isoformat()}") for i in range(days)]
        out = {}
        for d in _db().get_all(refs):
            if d.exists:
                x = d.to_dict()
                out[x["date"]] = x.get("wh", {})
        return {"days": out}
    if path == "/guard":
        return {"guard": sess.get("guard") or {"rules": []}, "state": sess.get("guard_state") or {}}
    if path == "/guard/save":
        rules = []
        for r in (body.get("rules") or [])[:30]:
            if r.get("device") and r.get("kind") in ("on_long", "done"):
                rules.append({"id": str(r.get("id") or secrets.token_hex(4)), "device": str(r["device"]), "kind": r["kind"],
                              "minutes": max(1, min(24 * 60, int(r.get("minutes") or 20))), "name": str(r.get("name") or "")[:60],
                              "pcode": str(r.get("pcode") or ""), "scale": int(r.get("scale") or 0), "enabled": bool(r.get("enabled", True)),
                              "expect": max(0, min(600, int(r.get("expect") or 0))), "remind": bool(r.get("remind"))})
        old = sess.get("guard_state") or {}
        ref.update({"guard": {"rules": rules}, "guard_on": any(r["enabled"] for r in rules) or _home_on(sess.get("home")),
                    "guard_state": {r["id"]: old[r["id"]] for r in rules if r["id"] in old}})
        return {"saved": True, "count": len(rules)}
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
        if sess.get("recover"):
            _db().collection("kor_recover").document(_h(re.sub(r"[^A-Z0-9]", "", sess["recover"]))).delete()
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

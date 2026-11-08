"""HomeOn - full MOVA / Dreame robot vacuum control through the MOVAhome cloud.

Runs the open-source dreame-vacuum library (MIT, github.com/Tasshack/dreame-vacuum, vendored in ./dreame)
the same way Home Assistant does, but on demand: one device object per HomeOn account, kept warm while the
server instance lives, refreshed on every request. Everything the MOVAhome app shows - state, rooms and map,
room cleaning, the base station, consumables, settings, do-not-disturb, schedules and history - is exposed
as plain JSON for the HomeOn page.
"""
import base64
import io
import threading
import time

from dreame import DreameVacuumDevice
from dreame.exceptions import DeviceException
from dreame.types import (
    DreameVacuumAction as A,
    DreameVacuumProperty as P,
    DreameVacuumAutoSwitchProperty as AS,
    DreameVacuumAIProperty as AI,
)


# On a server a background thread may never get CPU after the response is sent, so the library's
# "async" cloud calls (settings, map edits) run inline instead.
from dreame.protocol import DreameVacuumDreameHomeCloudProtocol as _Cloud


def _send_now(self, callback, method, parameters=None, retry_count=2):
    try:
        r = self.send(method, parameters, retry_count)
    except Exception:  # noqa: BLE001
        r = None
    if callback:
        callback(r)


_Cloud.send_async = _send_now


class VacError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


# ---------- Hebrew ----------
HE_ERRORS = {
    "device_unavailable": "השואב לא זמין כרגע. בדוק שהוא דולק ומחובר ל-WiFi",
    "unavailable_while_running": "אי אפשר לשנות את זה בזמן שהשואב עובד",
    "unavailable_on_current_map": "צריך מפה שמורה כדי לנקות חדרים",
    "unavailable_without_map": "אין עדיין מפה. צריך ניקוי מלא ראשון כדי ליצור מפה",
    "unavailable_with_temporary_map": "יש מפה זמנית. צריך לשמור אותה קודם",
    "unavailable_while_draining": "אי אפשר בזמן ניקוז",
    "unavailable_while_self_wash": "אי אפשר בזמן שטיפת המגבים",
    "unavailable_with_customized_cleaning": "כשיש הגדרות נפרדות לכל חדר, משנים את זה בחלון של החדר",
    "fast_mapping_mop_installed": "קודם מסירים את המגבים",
    "unavailable_while_fast_mapping": "אי אפשר בזמן מיפוי",
    "cloud_required": "צריך חיבור לענן",
    "low_battery": "הסוללה חלשה מדי",
    "start_failed": "השואב לא התחיל",
    "invalid_value": "ערך לא תקין",
    "invalid_option": "אפשרות לא תקינה",
    "command_failed": "השואב לא קיבל את הפקודה",
    "not_supported": "השואב לא תומך בזה",
    "unavailable": "לא זמין כרגע",
    "max_rooms_reached": "נבחרו יותר מדי חדרים",
    "property_not_updated": "השואב לא אישר את השינוי",
}
DeviceException.localize = lambda key: HE_ERRORS.get(key.split(".")[1]) if key.count(".") >= 1 else None

SEGMENT_HE = {
    0: "חדר", 1: "סלון", 2: "חדר שינה", 3: "חדר עבודה", 4: "מטבח", 5: "פינת אוכל", 6: "שירותים",
    7: "מרפסת", 8: "מסדרון", 9: "חדר שירות", 10: "ארון", 11: "חדר ישיבות", 12: "משרד",
    13: "חדר כושר", 14: "חדר משחקים", 15: "חדר שינה נוסף",
}

ERR_HE = {1: "גלגל באוויר. הנח את השואב על הרצפה",2: "חיישני המדרגות מלוכלכים או שהשואב על קצה",3: "הפגוש תקוע",5: "הפגוש תקוע",6: "גלגל באוויר",8: "מיכל האבק לא מותקן",9: "מיכל המים לא מותקן",10: "מיכל המים ריק",11: "מיכל האבק מלא",12: "המברשת הראשית תקועה",13: "מברשת הצד תקועה",14: "המאוורר תקוע",15: "הגלגל השמאלי תקוע",16: "הגלגל הימני תקוע",17: "השואב תקוע",18: "השואב תקוע",19: "לא מוצא את העמדה",20: "הסוללה חלשה",21: "בעיית טעינה",22: "הסוללה חלשה",29: "תקלה בסוללה",47: "הדרך חסומה",48: "תקלה בחיישן הלייזר",49: "פגוש הלייזר תקוע",51: "הפילטר חסום",54: "חיישן הקיר מלוכלך",57: "חיישן הקיר מלוכלך",59: "השואב באזור אסור",61: "לא מצליח להגיע ליעד",62: "לא מצליח להגיע ליעד",63: "הדרך חסומה",64: "הדרך חסומה",68: "צריך להסיר את המגבים",69: "המגבים נפלו",70: "המגבים נפלו",71: "המגבים לא מסתובבים",72: "המגבים לא מסתובבים",74: "התקנת המגבים נכשלה",75: "הסוללה נגמרה",76: "מיכל המים המלוכלכים לא מותקן",80: "השואב תקוע",81: "השואב תקוע",82: "רצפה חלקה",85: "בדוק שהמגבים מותקנים",86: "מיכל המים המלוכלכים מלא",90: "השואב תקוע",101: "מיכל האבק בעמדה מלא",102: "מכסה העמדה פתוח",103: "מכסה העמדה פתוח",104: "מיכל האבק בעמדה מלא",105: "מיכל המים הנקיים לא מותקן",106: "מיכל המים המלוכלכים לא מותקן או מלא",107: "מיכל המים הנקיים ריק",108: "מיכל המים המלוכלכים מלא",109: "מיכל המים המלוכלכים חסום",111: "המגבים לא מותקנים",112: "המגבים רטובים מדי",114: "צריך לנקות את המגבים",116: "מיכל המים הנקיים ריק",117: "העמדה לא מחוברת לחשמל",118: "מיכל המים המלוכלכים מלא",119: "צריך לנקות את משטח השטיפה",120: "אין מגבים בעמדה",121: "שקית האבק מלאה",125: "הניקוז נכשל",126: "המגבים לא זוהו",128: "תקלה בעמדה",129: "שטיפת המגבים נכשלה",1000: "החזרה לעמדה נכשלה"}
BUSY_STATES = {1, 5, 7, 9, 10, 11, 12, 15, 17, 18, 25, 27, 28, 30, 37, 38, 101, 103, 104, 105}


def notice(st, last):
    """What to tell the phone after the 2-minute check: finished cleaning, or a new error."""
    busy = bool(st.get("running")) or st.get("state") in BUSY_STATES
    msgs = []
    err = int(st.get("error") or 0)
    if err and err != int(last.get("err") or 0):
        msgs.append({"title": "השואב צריך עזרה", "body": ERR_HE.get(err, f"תקלה (קוד {err})"), "tag": "mova-err"})
    if last.get("busy") and not busy and not st.get("paused") and not err:
        a, t = last.get("area"), last.get("time")
        body = " · ".join(x for x in [f"{a} מ״ר" if a else "", f"{t} דק׳" if t else ""] if x) or "חזר לעמדה"
        msgs.append({"title": "השואב סיים לנקות", "body": body, "tag": "mova-done"})
    new = {"busy": busy, "err": err, "area": st.get("area") or (last.get("area") if busy else None),
           "time": st.get("time") or (last.get("time") if busy else None)}
    return msgs, new


# ---------- device cache ----------
_DEVS = {}
_LOCK = threading.Lock()


def _quiet(d):
    """The library schedules its own background refreshes; on a server we refresh on request instead."""
    try:
        d.schedule_update(-1)
        if d._map_manager:
            d._map_manager.schedule_update(-1)
        if getattr(d, "_keep_alive_timer", None):
            d._keep_alive_timer.cancel()
    except Exception:  # noqa: BLE001
        pass


def _close(d):
    try:
        d.disconnect()
    except Exception:  # noqa: BLE001
        pass


def device(key, mv, fresh=True):
    """Returns (device, new_auth_key or None)."""
    with _LOCK:
        e = _DEVS.get(key)
        if e and e["did"] == str(mv.get("did")) and time.time() - e["t"] < 1800 and e["d"].available:
            d = e["d"]
            if fresh and time.time() - e["t"] > 2:
                try:
                    d.update(True)
                except Exception:  # noqa: BLE001
                    _close(d)
                    e = None
        else:
            if e:
                _close(e["d"])
            e = None
        if e is None:
            d = DreameVacuumDevice(
                # no local host (cloud only); the password is never stored - the saved refresh token logs in
                mv.get("name") or "MOVA", "", "", mv.get("mac") or None,
                mv.get("user"), "-", mv.get("country") or "eu", True, "mova", str(mv.get("did")), mv.get("auth"))
            try:
                d.update()
            except Exception as ex:  # noqa: BLE001
                _close(d)
                if getattr(d, "auth_failed", False) or not (d._protocol.cloud and d._protocol.cloud.logged_in):
                    raise VacError("החיבור ל-MOVAhome פג. צריך להתחבר מחדש", 409) from None
                raise VacError(str(ex) if isinstance(ex, DeviceException) else "השואב לא ענה. בדוק שהוא מחובר ל-WiFi", 502) from None
            e = {"d": d, "did": str(mv.get("did"))}
            _DEVS[key] = e
        e["t"] = time.time()
        _quiet(d)
        new_auth = None
        try:
            a = d._protocol.cloud.auth_key
            if a and a != mv.get("auth"):
                new_auth = a
        except Exception:  # noqa: BLE001
            pass
        return d, new_auth


def forget(key):
    with _LOCK:
        e = _DEVS.pop(key, None)
        if e:
            _close(e["d"])


# ---------- reading ----------
def _g(obj, name, default=None):
    try:
        v = getattr(obj, name)
        return default if v is None else v
    except Exception:  # noqa: BLE001
        return default


def _iv(v):
    try:
        return int(v.value if hasattr(v, "value") else v)
    except Exception:  # noqa: BLE001
        return None


def _name(v):
    if v is None:
        return None
    return str(v).lower().replace(" ", "_")


CONSUMABLES = [  # (status attr, reset action, Hebrew)
    ("main_brush_life", "RESET_MAIN_BRUSH", "מברשת ראשית"),
    ("side_brush_life", "RESET_SIDE_BRUSH", "מברשת צד"),
    ("filter_life", "RESET_FILTER", "פילטר"),
    ("sensor_dirty_life", "RESET_SENSOR", "חיישנים"),
    ("mop_life", "RESET_MOP_PAD", "מגבים"),
    ("tank_filter_life", "RESET_TANK_FILTER", "פילטר מיכל המים"),
    ("silver_ion_life", "RESET_SILVER_ION", "יוני כסף"),
    ("detergent_life", "RESET_DETERGENT", "נוזל ניקוי"),
    ("squeegee_life", "RESET_SQUEEGEE", "מגב הגומי"),
    ("dirty_water_channel_dirty_life", "RESET_DIRTY_WATER_CHANNEL", "תעלת המים המלוכלכים"),
    ("onboard_dirty_water_tank_life", "RESET_ONBOARD_DIRTY_WATER_TANK", "מיכל מים מלוכלכים בשואב"),
    ("deodorizer_life", "RESET_DEODORIZER", "מנטרל ריחות"),
    ("wheel_dirty_life", "RESET_WHEEL", "גלגלים"),
    ("scale_inhibitor_life", "RESET_SCALE_INHIBITOR", "מונע אבנית"),
    ("water_outlet_filter_dirty_life", "RESET_WATER_OUTLET_FILTER", "פילטר יציאת המים"),
    ("washboard_cleaning_life", "RESET_WASHBOARD_CLEANING", "משטח השטיפה"),
]

# switches: key -> (property, Hebrew, hint)
SWITCHES = [
    ("CARPET_BOOST", P, "הגברת שאיבה על שטיחים", ""),
    ("RESUME_CLEANING", P, "המשך ניקוי אחרי טעינה", "אם הסוללה נגמרת באמצע"),
    ("CHILD_LOCK", P, "נעילת ילדים", "הכפתורים על השואב לא יעבדו"),
    ("OBSTACLE_AVOIDANCE", P, "הימנעות ממכשולים", ""),
    ("AUTO_DUST_COLLECTING", P, "ריקון אבק אוטומטי", "בכל חזרה לעמדה"),
    ("CARPET_RECOGNITION", P, "זיהוי שטיחים", ""),
    ("AUTO_ADD_DETERGENT", P, "הוספת נוזל ניקוי אוטומטית", ""),
    ("AUTO_WATER_REFILLING", P, "מילוי מים אוטומטי", ""),
    ("TIGHT_MOPPING", P, "שטיפה צפופה", ""),
    ("CUSTOMIZED_CLEANING", P, "הגדרות נפרדות לכל חדר", ""),
    ("MULTI_FLOOR_MAP", P, "כמה מפות (קומות)", ""),
    ("AUTO_MOUNT_MOP", P, "הסרת מגבים אוטומטית לשאיבה", ""),
    ("SELF_CLEAN", P, "שטיפת מגבים אוטומטית", ""),
    ("VOICE_ASSISTANT", P, "עוזר קולי", ""),
    ("DND_DISABLE_RESUME_CLEANING", P, "בשעות שקטות: לא להמשיך ניקוי", ""),
    ("DND_DISABLE_AUTO_EMPTY", P, "בשעות שקטות: בלי ריקון אבק", ""),
    ("DND_REDUCE_VOLUME", P, "בשעות שקטות: עוצמה נמוכה", ""),
    ("AUTO_DRYING", AS, "ייבוש מגבים אוטומטי", ""),
    ("COLLISION_AVOIDANCE", AS, "מניעת התנגשויות", "נוסע בעדינות ליד רהיטים"),
    ("FLOOR_DIRECTION_CLEANING", AS, "שטיפה לאורך כיוון הפרקט", ""),
    ("PET_FOCUSED_CLEANING", AS, "ניקוי ממוקד לחיות מחמד", ""),
    ("INTENSIVE_CARPET_CLEANING", AS, "ניקוי שטיחים אינטנסיבי", ""),
    ("SIDE_REACH", AS, "הגעה לפינות", ""),
    ("MOP_EXTEND", AS, "הרחבת מגב לקצוות", ""),
    ("GAP_CLEANING_EXTENSION", AS, "ניקוי רווחים", ""),
    ("MOPPING_UNDER_FURNITURES", AS, "שטיפה מתחת לרהיטים", ""),
    ("AUTO_CHARGING", AS, "טעינה חכמה", ""),
    ("FILL_LIGHT", AS, "תאורת עזר", ""),
    ("STAIN_AVOIDANCE", AS, "הימנעות מכתמים רטובים", ""),
    ("AI_OBSTACLE_DETECTION", AI, "זיהוי מכשולים חכם", ""),
    ("AI_PET_DETECTION", AI, "זיהוי חיות מחמד", ""),
    ("AI_FURNITURE_DETECTION", AI, "זיהוי רהיטים", ""),
    ("AI_FLUID_DETECTION", AI, "זיהוי נוזלים", ""),
]
SWITCH_FORMAT = {"STAIN_AVOIDANCE": lambda on: 2 if on else 1}
SWITCH_VALUE = {"STAIN_AVOIDANCE": lambda v: v == 2, "WIDER_CORNER_COVERAGE": lambda v: v is not None and v > 0}

# selects: key (status attr base) -> Hebrew
SELECTS = [
    ("cleaning_mode", "מצב ניקוי"),
    ("suction_level", "עוצמת שאיבה"),
    ("water_volume", "כמות מים"),
    ("mop_pad_humidity", "לחות המגבים"),
    ("cleangenius", "CleanGenius"),
    ("cleangenius_mode", "מצב CleanGenius"),
    ("cleaning_route", "מסלול ניקוי"),
    ("mop_wash_level", "רמת שטיפת המגבים"),
    ("mop_clean_frequency", "כל כמה זמן לשטוף מגבים"),
    ("self_clean_frequency", "תדירות שטיפת מגבים"),
    ("washing_mode", "מצב שטיפה"),
    ("water_temperature", "טמפרטורת מים"),
    ("auto_empty_mode", "ריקון אבק"),
    ("carpet_sensitivity", "רגישות לשטיחים"),
    ("carpet_cleaning", "התנהגות על שטיחים"),
    ("mopping_type", "סוג שטיפה"),
    ("wider_corner_coverage", "כיסוי פינות"),
    ("mop_pad_swing", "תנועת המגב"),
    ("mop_extend_frequency", "תדירות הרחבת המגב"),
    ("auto_recleaning", "ניקוי חוזר אוטומטי"),
    ("auto_rewashing", "שטיפה חוזרת אוטומטית"),
    ("custom_mopping_route", "מסלול שטיפה"),
    ("mop_pressure", "לחץ המגב"),
    ("mop_temperature", "חום המגב"),
    ("low_lying_area_frequency", "ניקוי מתחת לרהיטים נמוכים"),
    ("scraper_frequency", "תדירות ניקוי המגרד"),
    ("auto_lds_coverage", "כיסוי הלייזר"),
    ("voice_assistant_language", "שפת הפקודות הקוליות"),
]
SELECT_OPTIONS_ATTR = {"auto_recleaning": "second_cleaning_list", "auto_rewashing": "second_cleaning_list"}

OPT_HE = {
    "quiet": "שקט", "standard": "רגיל", "strong": "חזק", "turbo": "טורבו", "max": "מקסימום",
    "low": "נמוך", "medium": "בינוני", "high": "גבוה", "ultra": "מקסימלי",
    "sweeping": "שאיבה", "mopping": "שטיפה", "sweeping_and_mopping": "שאיבה ושטיפה",
    "mopping_after_sweeping": "שאיבה ואז שטיפה", "routine_cleaning": "ניקוי רגיל", "deep_cleaning": "ניקוי יסודי",
    "slightly_dry": "כמעט יבש", "moist": "לח", "wet": "רטוב", "dry": "יבש",
    "water_saving": "חיסכון במים", "daily": "יומי", "deep": "יסודי", "light": "קל",
    "normal": "רגיל", "off": "כבוי", "on": "פעיל", "smart": "חכם", "auto": "אוטומטי", "standard_mode": "רגיל",
    "by_area": "לפי שטח", "by_time": "לפי זמן", "by_room": "לפי חדר", "intelligent": "חכם",
    "avoidance": "להימנע", "adaptation": "להתאים", "remove_mop": "להסיר מגבים", "ignore": "להתעלם", "cross": "לעבור",
    "vacuum_and_mop": "שאיבה ושטיפה", "in_deep_mode": "במצב יסודי", "in_all_modes": "בכל המצבים",
    "every_time": "כל פעם", "frequent": "לעיתים קרובות", "infrequent": "לעיתים רחוקות",
    "normal_water": "מים רגילים", "mild": "פושר", "warm": "חמים", "hot": "חם",
    "quick": "מהיר", "intensive": "אינטנסיבי", "s_shape": "בצורת S", "x_shape": "בצורת X",
    "english": "אנגלית", "german": "גרמנית", "russian": "רוסית", "italian": "איטלקית", "french": "צרפתית",
    "korean": "קוריאנית", "chinese": "סינית", "default": "ברירת מחדל",
    "lower": "נמוך", "higher": "גבוה", "disabled": "כבוי", "enabled": "פעיל",
}


def _opt_he(name):
    if name is None:
        return None
    k = str(name).lower().replace(" ", "_")
    return OPT_HE.get(k) or str(name).replace("_", " ").capitalize()


def _settings(d):
    s = d.status
    sw = []
    for key, enum, he, hint in SWITCHES:
        try:
            prop = enum[key]
        except KeyError:
            continue
        v = d.get_property(prop)
        if v is None:
            continue
        on = SWITCH_VALUE.get(key, lambda x: bool(x))(v)
        sw.append({"k": key, "t": he, "h": hint, "on": bool(on)})
    sel = []
    for key, he in SELECTS:
        lst = _g(s, SELECT_OPTIONS_ATTR.get(key, key + "_list"))
        cur = _g(s, key + "_name")
        if not lst or cur is None or str(cur).lower() in ("unknown", "none"):
            continue
        opts = [{"v": n, "t": _opt_he(n)} for n in lst.keys()]
        if len(opts) < 2:
            continue
        sel.append({"k": key, "t": he, "cur": _name(cur), "o": opts})
    num = []
    vol = d.get_property(P.VOLUME)
    if vol is not None:
        num.append({"k": "volume", "t": "עוצמת קול", "v": int(vol), "min": 0, "max": 100, "step": 10, "u": "%"})
    dt = d.get_property(P.DRYING_TIME)
    if dt is not None and _g(d.capability, "self_wash_base"):
        num.append({"k": "drying_time", "t": "זמן ייבוש מגבים", "v": int(dt), "min": 2, "max": 4 if not _g(d.capability, "long_drying_time") else 12, "step": 1, "u": "שעות"})
    aef = d.get_property(P.AUTO_EMPTY_FREQUENCY)
    if aef is not None and not _g(d.capability, "auto_empty_mode"):
        num.append({"k": "auto_empty_frequency", "t": "ריקון אבק כל", "v": int(aef), "min": 1, "max": 3, "step": 1, "u": "ניקויים"})
    return sw, sel, num


def _rooms(d):
    out = []
    segs = _g(d.status, "segments") or {}
    for sid, seg in sorted(segs.items(), key=lambda kv: (_g(kv[1], "order") or 99, kv[0])):
        name = _g(seg, "custom_name")
        if not name:
            t = _g(seg, "type", 0)
            name = SEGMENT_HE.get(t, "חדר")
            idx = _g(seg, "index", 0)
            if t == 0:
                name = f"חדר {sid}"
            elif idx:
                name = f"{name} {idx + 1}"
        out.append({"id": int(sid), "name": name, "x": _g(seg, "x"), "y": _g(seg, "y"), "type": _g(seg, "type", 0),
                    "suction": _iv(_g(seg, "suction_level")), "water": _iv(_g(seg, "water_volume")),
                    "times": _iv(_g(seg, "cleaning_times")), "mode": _iv(_g(seg, "cleaning_mode"))})
    return out


def _history(d):
    out = []
    for h in (_g(d.status, "_cleaning_history") or [])[:20]:
        try:
            out.append({"t": int(h.date.timestamp()), "min": h.cleaning_time, "m2": h.cleaned_area,
                        "done": h.completed, "status": _iv(h.status)})
        except Exception:  # noqa: BLE001
            pass
    return out


def _schedules(d):
    out = []
    for t in (_g(d.status, "schedule") or []):
        out.append({"id": t.id, "on": bool(t.enabled), "time": t.time, "days": t.repeats, "once": bool(t.once),
                    "suction": t.suction_level, "water": t.water_volume})
    return out


def _opts(lst):
    out = []
    for n, v in (lst or {}).items():
        v = _iv(v)
        if v is None or str(n).lower() in ("unknown", "none"):
            continue
        out.append({"v": int(v), "t": _opt_he(n)})
    return out


def _room_opts(d):
    s = d.status
    wet = _g(d.capability, "self_wash_base")
    return {"suction": _opts(_g(s, "suction_level_list")),
            "water": _opts(_g(s, "mop_pad_humidity_list" if wet else "water_volume_list")),
            "water_t": "לחות המגבים" if wet else "כמות מים",
            "mode": _opts(_g(s, "cleaning_mode_list"))}


def snapshot(d):
    s = d.status
    err = _iv(_g(s, "error"))
    st = {
        "state": _iv(_g(s, "state")), "state_en": _name(_g(s, "state_name")),
        "status": _iv(_g(s, "status")), "task": _iv(_g(s, "task_status")),
        "battery": d.get_property(P.BATTERY_LEVEL), "charging": _iv(_g(s, "charging_status")),
        "error": err if err not in (None, 0, -1) else 0,
        "error_en": _g(s, "error_name") if err not in (None, 0, -1) else None,
        "warning": bool(_g(s, "has_warning", False)), "has_error": bool(_g(s, "has_error", False)),
        "area": d.get_property(P.CLEANED_AREA), "time": d.get_property(P.CLEANING_TIME),
        "progress": d.get_property(P.CLEANING_PROGRESS),
        "running": bool(_g(s, "running", False)), "paused": bool(_g(s, "paused", False)),
        "docked": bool(_g(s, "docked", False)), "returning": bool(_g(s, "returning", False)),
        "started": bool(_g(s, "started", False)),
        "washing": bool(_g(s, "washing", False)), "drying": bool(_g(s, "drying", False)),
        "emptying": bool(_g(s, "auto_emptying", False)),
        "drying_left": _g(s, "drying_left_time"),
        "station": _iv(_g(s, "self_wash_base_status")),
        "clean_tank": _name(_g(s, "clean_water_tank_status_name")),
        "dirty_tank": _name(_g(s, "dirty_water_tank_status_name")),
        "dust_bag": _name(_g(s, "dust_bag_status_name")),
        "detergent": _name(_g(s, "detergent_status_name")),
        "segment_cleaning": bool(_g(s, "segment_cleaning", False)),
        "room": None,
        "offpeak": {"on": bool(_g(s, "off_peak_charging")), "start": _g(s, "off_peak_charging_start"), "end": _g(s, "off_peak_charging_end")} if _g(d.capability, "off_peak_charging") else None,
        "dnd": {"on": bool(_g(s, "dnd", False)), "start": _g(s, "dnd_start"), "end": _g(s, "dnd_end")} if d.get_property(P.DND_TASK) is not None or d.get_property(P.DND) is not None else None,
        "totals": {"count": d.get_property(P.CLEANING_COUNT), "minutes": d.get_property(P.TOTAL_CLEANING_TIME),
                   "m2": d.get_property(P.TOTAL_CLEANED_AREA), "first": d.get_property(P.FIRST_CLEANING_DATE)},
    }
    cr = _g(s, "current_room")
    if cr is not None:
        st["room"] = int(_g(cr, "id", 0)) or None
    cons = []
    for attr, act, he in CONSUMABLES:
        v = _g(s, attr)
        if v is None:
            continue
        cons.append({"k": attr, "t": he, "pct": int(v), "reset": act in A.__members__})
    sw, sel, num = _settings(d)
    caps = d.capability
    return {
        "state": st, "rooms": _rooms(d), "consumables": cons, "switches": sw, "selects": sel, "numbers": num,
        "history": _history(d), "schedules": _schedules(d),
        "can": {
            "station": bool(_g(caps, "self_wash_base")), "empty": bool(_g(caps, "auto_empty_base")),
            "drying": bool(_g(s, "drying_available", False) or _g(caps, "self_wash_base")),
            "washing": bool(_g(s, "washing_available", False) or _g(caps, "self_wash_base")),
            "map": bool(_g(s, "current_map") is not None),
            "zone": bool(_g(caps, "map", True)),
            "drain": bool(_g(s, "water_tank_draining_available", False)),
            "station_clean": bool(_g(caps, "station_cleaning", False)),
            "reclean": bool(_g(caps, "auto_recleaning", False)),
            "fast_map": bool(_g(caps, "lidar_navigation", True)),
            "carpets": bool(_g(caps, "carpet_recognition", False) or _g(caps, "carpet_material", False) or _g(caps, "map", False)),
            "obstacles": bool(_g(caps, "ai_detection", False)),
        },
        "room_opts": _room_opts(d),
        "custom": bool(_g(s, "customized_cleaning", False)),
        "mapping": bool(_g(s, "fast_mapping", False)),
        "model": _g(d.info, "model") if d.info else None,
        "fw": _g(d.info, "firmware_version") if d.info else None,
        "name": d.name if hasattr(d, "name") else None,
    }


# ---------- map ----------
_RENDERERS = {}


def render_map(key, d):
    from dreame.map import DreameVacuumMapRenderer
    try:
        mm = d._map_manager
        if mm:
            mm.set_device_running(d.status.running, d.status.docked and not d.status.started)
            mm.update()
    except Exception:  # noqa: BLE001
        pass
    md = d.get_map(0)
    if md is None or md.empty_map:
        return None
    r = _RENDERERS.get(key)
    if r is None:
        r = DreameVacuumMapRenderer(
            "Dreame Dark", 0,
            ["icon", "name", "name_background", "order", "suction_level", "water_volume", "cleaning_times",
             "cleaning_mode", "mopping_mode", "no_go", "no_mop", "virtual_wall"],
            _g(d.capability, "robot_type", 0), False, False, segment_names=SEGMENT_HE)
        _RENDERERS[key] = r
    png = r.render_map(d.get_map_for_render(md), d.status.robot_status, d.status.station_status)
    cal = r.calibration_points
    w = h = None
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(png))
        w, h = im.size
    except Exception:  # noqa: BLE001
        pass
    rooms = []
    if cal and w and h:
        p0, p1, p2 = [(c["map"]["x"], c["map"]["y"]) for c in cal[:3]]

        def px(x, y):
            return (p0[0] + x / 1000 * (p1[0] - p0[0]) + y / 1000 * (p2[0] - p0[0]),
                    p0[1] + x / 1000 * (p1[1] - p0[1]) + y / 1000 * (p2[1] - p0[1]))
        for rm in _rooms(d):
            if rm["x"] is None or rm["y"] is None:
                continue
            X, Y = px(rm["x"], rm["y"])
            rooms.append({"id": rm["id"], "name": rm["name"], "px": round(X / w * 100, 2), "py": round(Y / h * 100, 2)})
    zones = {"walls": [], "nogo": [], "nomop": []}
    maps = []
    if cal and w and h:
        _CAL[key] = {"cal": cal, "w": w, "h": h}

        def pc(x, y):
            X, Y = px(x, y)
            return [round(X / w * 100, 2), round(Y / h * 100, 2)]
        for wl in (getattr(md, "virtual_walls", None) or []):
            zones["walls"].append(pc(wl.x0, wl.y0) + pc(wl.x1, wl.y1))
        for k, attr in (("nogo", "no_go_areas"), ("nomop", "no_mopping_areas")):
            for a in (getattr(md, attr, None) or []):
                zones[k].append(pc(a.x0, a.y0) + pc(a.x2, a.y2))
        try:
            zones["carpets"] = [{"id": c.id, "q": pc(c.x0, c.y0) + pc(c.x2, c.y2)}
                                for c in (getattr(md, "carpets", None) or []) if not getattr(c, "hidden", False)]
        except Exception:  # noqa: BLE001
            zones["carpets"] = []
        obs = []
        ob = getattr(md, "obstacles", None) or {}
        for idx, o in (ob.items() if hasattr(ob, "items") else enumerate(ob)):
            try:
                t = int(o.type.value)
                if t in (200, 214, 216, 217, 228) or (o.x == 0 and o.y == 0):
                    continue
                ign = o.ignore_status.value if o.ignore_status is not None else -1
                obs.append({"i": str(idx), "x": o.x, "y": o.y, "p": pc(o.x, o.y), "t": OBST_HE.get(t, "מכשול"),
                            "pic": bool(o.file_name) and (o.picture_status is None or o.picture_status.value == 2),
                            "ign": ign == 1, "can_ign": ign in (0, 1)})
            except Exception:  # noqa: BLE001
                pass
        zones["obstacles"] = obs[:40]
    try:
        sel = d.status.selected_map
        for mid, m in (d.status.map_data_list or {}).items():
            maps.append({"id": int(mid), "name": getattr(m, "custom_name", None) or f"מפה {mid}",
                         "current": bool(sel and sel.map_id == mid)})
    except Exception:  # noqa: BLE001
        pass
    return {"png": base64.b64encode(png).decode(), "w": w, "h": h, "rooms": rooms, "zones": zones, "maps": maps,
            "map_id": getattr(md, "map_id", None)}


_CAL = {}


def history_png(key, d, i):
    from dreame.map import DreameVacuumMapRenderer
    md = d.history_map(str(int(i) + 1))
    if md is None:
        raise VacError("אין מפה לניקוי הזה")
    r = _RENDERERS.get(("h", key))
    if r is None:
        r = DreameVacuumMapRenderer(
            "Dreame Dark", 0,
            ["icon", "name", "name_background", "order", "suction_level", "water_volume", "cleaning_times",
             "cleaning_mode", "mopping_mode"],
            _g(d.capability, "robot_type", 0), False, False, segment_names=SEGMENT_HE)
        _RENDERERS[("h", key)] = r
    png = r.render_map(md, d.status.robot_status, d.status.station_status)
    return base64.b64encode(png).decode()

OBST_HE = {128: "בסיס של רהיט", 129: "משקל", 130: "חוט", 131: "כבל", 132: "צעצוע", 133: "נעליים", 134: "גרב",
           135: "צואה של חיה", 136: "פח", 137: "בד", 138: "מפצל חשמל", 139: "כתם נוזל", 142: "מכשול", 158: "חיית מחמד",
           163: "כלי ניקוי", 169: "כתם", 201: "רהיט שקל להיתקע בו", 202: "כתם שלא יורד", 204: "רגל של רהיט",
           205: "פירורים גדולים", 206: "כתם יבש", 209: "קערת אוכל של חיה", 210: "מיטה של חיה", 215: "כתם שדולג",
           225: "שיער", 226: "נייר", 229: "חפצים קטנים"}


def obstacle_image(d, i):
    img, _o = d.obstacle_image(str(i))
    if not img:
        raise VacError("אין תמונה למכשול הזה")
    return base64.b64encode(img).decode()


def _to_map(key, xp, yp):
    """A point on the picture (percent) back to vacuum map coordinates."""
    c = _CAL.get(key)
    if not c:
        raise VacError("צריך לטעון את המפה קודם")
    cal, w, h = c["cal"], c["w"], c["h"]
    p0, p1, p2 = [(q["map"]["x"], q["map"]["y"]) for q in cal[:3]]
    X, Y = float(xp) / 100 * w, float(yp) / 100 * h
    ax, ay = (p1[0] - p0[0]) / 1000, (p1[1] - p0[1]) / 1000
    bx, by = (p2[0] - p0[0]) / 1000, (p2[1] - p0[1]) / 1000
    det = ax * by - bx * ay
    if not det:
        raise VacError("המפה לא מוכנה")
    dx, dy = X - p0[0], Y - p0[1]
    return [int(round((dx * by - bx * dy) / det)), int(round((ax * dy - dx * ay) / det))]


def _seg4(key, q):
    if not isinstance(q, (list, tuple)) or len(q) != 4:
        raise VacError("קואורדינטות לא תקינות")
    return _to_map(key, q[0], q[1]) + _to_map(key, q[2], q[3])


def edit(key, d, body):
    op = str(body.get("op") or "")
    segs = _g(d.status, "segments") or {}
    if op == "rename":
        sid = int(body.get("id"))
        name = str(body.get("name") or "").strip()[:24]
        if sid not in segs:
            raise VacError("החדר לא נמצא")
        t = body.get("type")
        t = int(t) if t not in (None, "") else int(_g(segs[sid], "type", 0) or 0)
        if not name and t == 0:
            raise VacError("צריך שם לחדר")
        return d.set_segment_name(sid, t, name or None)
    if op == "merge":
        ids = [int(x) for x in body.get("ids") or []]
        if len(ids) != 2:
            raise VacError("בוחרים שני חדרים צמודים")
        return d.merge_segments(None, ids)
    if op == "split":
        sid = int(body.get("id"))
        return d.split_segments(None, sid, _seg4(key, body.get("line")))
    if op == "zones":
        z = body.get("zones") or {}
        walls = [_seg4(key, q) for q in z.get("walls") or []]
        nogo = [_seg4(key, q) for q in z.get("nogo") or []]
        nomop = [_seg4(key, q) for q in z.get("nomop") or []]
        return d.set_restricted_zone(walls, nogo, nomop)
    if op == "order":
        return d.set_cleaning_sequence([int(x) for x in body.get("ids") or []])
    if op == "room_set":
        sid, k, v = int(body.get("id")), str(body.get("k")), int(body.get("v"))
        if k == "water" and _g(d.capability, "self_wash_base"):
            return d.set_segment_mop_pad_humidity(sid, v)
        fn = {"suction": d.set_segment_suction_level, "water": d.set_segment_water_volume,
              "times": d.set_segment_cleaning_times, "mode": d.set_segment_cleaning_mode}.get(k)
        if not fn:
            raise VacError("הגדרה לא מוכרת")
        return fn(sid, v)
    if op == "carpets":
        md = d.status.current_map
        keep = {int(c.id): c for c in (getattr(md, "carpets", None) or []) if c.id is not None}
        out = []
        for c in body.get("carpets") or []:
            cid = c.get("id")
            if cid is not None and int(cid) in keep:
                k = keep[int(cid)]
                out.append([int(k.x0), int(k.y0), int(k.x2), int(k.y2), int(cid)])
            else:
                q = _seg4(key, c.get("q"))
                out.append([min(q[0], q[2]), min(q[1], q[3]), max(q[0], q[2]), max(q[1], q[3])])
        return d.set_carpet_area(out, [])
    if op == "obstacle_ignore":
        return d.set_obstacle_ignore(body.get("x"), body.get("y"), bool(body.get("on", True)))
    if op == "select_map":
        return d.set_selected_map(int(body.get("id")))
    if op == "rename_map":
        return d.rename_map(int(body.get("id")), str(body.get("name") or "")[:24])
    raise VacError("פעולה לא מוכרת")


# ---------- commands ----------
def act(d, a, body, key=None):
    s = d.status
    if a == "zone":
        zs = [_seg4(key, q) for q in (body.get("zones") or [])][:5]
        if not zs:
            raise VacError("לא סומן אזור")
        zs = [[min(q[0], q[2]), min(q[1], q[3]), max(q[0], q[2]), max(q[1], q[3])] for q in zs]
        times = max(1, min(3, int(body.get("times") or 1)))
        return d.clean_zone(zs, times, None, None)
    if a == "spot":
        pts = [_to_map(key, p[0], p[1]) for p in (body.get("points") or [])][:5]
        if not pts:
            raise VacError("לא סומנה נקודה")
        times = max(1, min(3, int(body.get("times") or 1)))
        return d.clean_spot(pts, times, None, None)
    if a == "preset":
        for k in ("cleaning_mode", "suction_level"):
            if body.get(k):
                try:
                    set_value(d, k, body[k])
                except Exception:  # noqa: BLE001
                    pass
        ids = [int(x) for x in (body.get("rooms") or [])]
        if ids:
            return d.clean_segment(ids, max(1, min(3, int(body.get("times") or 1))))
        return d.start()
    if a == "station_clean":
        return d.start_station_cleaning()
    if a == "reclean":
        try:
            d.history_map(1)
        except Exception:  # noqa: BLE001
            pass
        r = d.start_recleaning()
        if r is None:
            raise VacError("אין מה להשלים מהניקוי האחרון")
        return r
    if a == "map_new":
        if bool(body.get("fast")):
            return d.start_fast_mapping()
        return d.start_mapping()
    if a == "move":
        r = max(-128, min(128, int(body.get("r") or 0)))
        v = max(-300, min(300, int(body.get("v") or 0)))
        return d.remote_control_move_step(r, v, False)
    if a == "start":
        return d.start()
    if a == "pause":
        return d.pause()
    if a == "stop":
        return d.stop()
    if a == "dock":
        return d.return_to_base()
    if a == "locate":
        return d.locate()
    if a == "rooms":
        ids = [int(x) for x in (body.get("rooms") or []) if str(x).lstrip("-").isdigit()]
        if not ids:
            raise VacError("לא נבחרו חדרים")
        times = max(1, min(3, int(body.get("times") or 1)))
        return d.clean_segment(ids, times)
    if a == "wash":
        return d.pause_washing() if _g(s, "washing") else d.start_washing()
    if a == "dry":
        return d.stop_drying() if _g(s, "drying") else d.start_drying()
    if a == "empty":
        return d.call_action(A.START_AUTO_EMPTY)
    if a == "clear":
        return d.clear_warning()
    if a == "drain":
        return d.start_draining()
    if a.startswith("reset:"):
        attr = a[6:]
        for c_attr, c_act, _ in CONSUMABLES:
            if c_attr == attr and c_act in A.__members__:
                return d.call_action(A[c_act])
        raise VacError("פריט לא מוכר")
    raise VacError("פעולה לא מוכרת")


def set_value(d, k, v):
    for key, enum, _, _ in SWITCHES:
        if key == k:
            on = bool(v)
            val = SWITCH_FORMAT.get(key, lambda x: int(x))(on)
            setter = getattr(d, f"set_{key.lower()}", None)
            return setter(val) if setter else d.set_property(enum[key], val)
    if k == "voice_assistant_language":
        lst = _g(d.status, "voice_assistant_language_list") or {}
        if v not in lst:
            raise VacError("אפשרות לא תקינה")
        val = lst[v]
        return d.set_voice_assistant_language(str(val.value if hasattr(val, "value") else val))
    if k == "offpeak":
        return d.set_off_peak_charging_config(bool(v.get("on")), str(v.get("start") or "22:00"), str(v.get("end") or "08:00"))
    for key, _ in SELECTS:
        if key == k:
            lst = _g(d.status, SELECT_OPTIONS_ATTR.get(key, key + "_list")) or {}
            if v not in lst:
                raise VacError("אפשרות לא תקינה")
            val = lst[v]
            val = int(val.value if hasattr(val, "value") else val)
            setter = getattr(d, f"set_{key}", None)
            if setter:
                return setter(val)
            return d.set_property(P[key.upper()] if key.upper() in P.__members__ else AS[key.upper()], val)
    if k == "volume":
        return d.set_volume(max(0, min(100, int(v))))
    if k == "drying_time":
        return d.set_drying_time(int(v))
    if k == "auto_empty_frequency":
        return d.set_property(P.AUTO_EMPTY_FREQUENCY, max(1, min(3, int(v))))
    if k == "dnd":
        on, st, en = bool(v.get("on")), str(v.get("start") or "22:00"), str(v.get("end") or "08:00")
        if d.get_property(P.DND_TASK) is not None:
            return d.set_dnd_tasks(on, st, en)
        d.set_dnd(on)
        d.set_dnd_start(st)
        return d.set_dnd_end(en)
    if k == "schedule_on":
        return _schedule_toggle(d, str(v.get("id")), bool(v.get("on")))
    if k == "schedule_delete":
        return d.delete_scheduled_task(str(v))
    raise VacError("הגדרה לא מוכרת")


def _schedule_toggle(d, sid, on):
    raw = d.get_property(P.SCHEDULE) or ""
    tasks = []
    for t in raw.split(";"):
        p = t.split("-")
        if p and p[0] == sid and len(p) > 1:
            p[1] = "1" if on else "0"
        tasks.append("-".join(p))
    return d.set_property(P.SCHEDULE, ";".join(tasks))

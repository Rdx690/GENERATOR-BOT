# t.me/RishantAPIs
# t.me/RishantAPIs
# t.me/RishantAPIs
# t.me/RishantAPIs
#
#
#
from flask import Flask, request, jsonify, make_response
import os, sys, time, threading, json, random, requests, re, codecs, base64, hmac, hashlib, string, logging
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import concurrent.futures
import uuid
import ipaddress

urllib3.disable_warnings()

# ========== LOG ==========
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stdout)
log = logging.getLogger("ffgen")

# ========== DEBUG SYSTEM ==========
_thread_local = threading.local()

def _safe(v):
    if v is None or isinstance(v, (str, int, float, bool)): return v
    if isinstance(v, (bytes, bytearray)):
        try: return v.decode("utf-8")
        except Exception: return bytes(v).hex()
    if isinstance(v, dict): return {str(k): _safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)): return [_safe(x) for x in v]
    return str(v)

def _is_debug(): return bool(getattr(_thread_local, "debug_enabled", False))

def dbg(tag, **fields):
    if not _is_debug(): return
    payload = {"ts": datetime.now().isoformat()}
    payload.update({k: _safe(v) for k, v in fields.items()})
    try: line = json.dumps(payload, ensure_ascii=False)
    except Exception: line = str(payload)
    print(f"[DEBUG] {tag} :: {line}", flush=True)

def _dbg_resp_raw(tag, resp):
    if resp is None:
        dbg(f"{tag}.resp_raw", len=0, raw=None, utf8=None, hex=None); return
    try: content = resp.content
    except Exception: content = b""
    try: text = resp.text
    except Exception:
        try: text = content.decode("utf-8", errors="replace")
        except Exception: text = ""
    dbg(f"{tag}.resp_raw", len=len(content), raw=repr(content), utf8=text, hex=content.hex() if content else "")

# ========== CONFIG ==========
REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn","PK":"ur","TW":"zh","CIS":"ru","SAC":"es","BR":"pt"}
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
HEX_KEY_STR = HEX_KEY.decode()

# Timeout pendek, NO RETRY
OPT = {'timeout': (3, 5), 'retries': 0}
RARITY_SCORE_THRESHOLD = 8

# HARDCODED — 150 worker, target 100 acc/s
FIXED_WORKERS      = 150
TARGET_ACC_PER_SEC = 100.0
RELEASE_VER        = "OB55"
GAME_VERSION       = "2.132.4"

# ========== IP SPOOFING ==========
def _build_ip_pool():
    pool = set()
    ranges = [
        ("1.",400),("5.",400),("14.",400),("27.",400),("31.",400),("36.",400),("37.",400),("39.",400),
        ("41.",400),("42.",400),("43.",400),("45.",400),("46.",400),("47.",400),("49.",400),("58.",400),
        ("59.",400),("60.",400),("61.",400),("62.",400),("77.",400),("78.",400),("79.",400),("80.",400),
        ("81.",400),("82.",400),("83.",400),("84.",400),("85.",400),("86.",400),("87.",400),("88.",400),
        ("89.",400),("90.",400),("91.",400),("92.",400),("93.",400),("94.",400),("95.",400),("101.",400),
        ("102.",400),("103.",400),("104.",400),("105.",400),("106.",400),("107.",400),("108.",400),("109.",400),
        ("110.",400),("111.",400),("112.",400),("113.",400),("114.",400),("115.",400),("116.",400),("117.",400),
        ("118.",400),("119.",400),("120.",400),("121.",400),("122.",400),("123.",400),("124.",400),("125.",400),
        ("126.",400),("128.",400),("129.",400),("130.",400),("131.",400),("132.",400),("133.",400),("134.",400),
        ("135.",400),("136.",400),("137.",400),("138.",400),("139.",400),("140.",400),("141.",400),("142.",400),
        ("143.",400),("144.",400),("145.",400),("146.",400),("147.",400),("148.",400),("149.",400),("150.",400),
        ("151.",400),("152.",400),("153.",400),("154.",400),("155.",400),("156.",400),("157.",400),("158.",400),
        ("159.",400),("160.",400),("161.",400),("162.",400),("163.",400),("164.",400),("165.",400),("166.",400),
        ("167.",400),("168.",400),("169.",400),("170.",400),("171.",400),("172.",400),("173.",400),("174.",400),
        ("175.",400),("176.",400),("177.",400),("178.",400),("179.",400),("180.",400),("181.",400),("182.",400),
        ("183.",400),("184.",400),("185.",400),("186.",400),("187.",400),("188.",400),("189.",400),("190.",400),
        ("191.",400),("192.",400),("193.",400),("194.",400),("195.",400),("196.",400),("197.",400),("198.",400),
        ("199.",400),("200.",400),("201.",400),("202.",400),("203.",400),("204.",400),("205.",400),("206.",400),
        ("207.",400),("208.",400),("209.",400),("210.",400),("211.",400),("212.",400),("213.",400),("214.",400),
        ("215.",400),("216.",400),("217.",400),("218.",400),("219.",400),("220.",400),("221.",400),("222.",400),
        ("223.",400),
    ]
    private_ranges = [
        ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
    ]
    for pfx, cnt in ranges:
        for _ in range(cnt):
            ip_str = f"{pfx}{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if any(ip_obj in net for net in private_ranges): continue
                pool.add(ip_str)
            except Exception: continue
    pl = list(pool); random.shuffle(pl); return pl

print("[*] Building IP pool...")
IP_POOL = _build_ip_pool()
print(f"[+] IP pool ready: {len(IP_POOL)} IPs")

def pick_ip():
    if not IP_POOL:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return IP_POOL[random.randint(0, len(IP_POOL) - 1)]

def ip_headers():
    real = pick_ip()
    chain = [real]
    for _ in range(random.randint(1, 3)): chain.append(pick_ip())
    return {
        "X-Forwarded-For": ", ".join(chain),
        "X-Real-IP": real, "X-Client-IP": real, "X-Originating-IP": real,
        "X-Remote-IP": real, "X-Remote-Addr": real,
        "Forwarded": f"for={real};proto=https", "CF-Connecting-IP": real,
    }

# ========== DEVICE POOL ==========
class DevicePool:
    _devices, _index, _lock = [], 0, threading.Lock()
    DEVICE_MODELS = [
        ("Asus ASUS_I005DA", "ARMv7 VFPv3 NEON VMH | 2400 | 2", "Adreno (TM) 640"),
        ("SM-A525F", "ARMv8 VFPv4 NEON VMH | 2200 | 8", "Adreno (TM) 618"),
        ("SM-A325M", "ARMv8 VFPv4 NEON VMH | 2000 | 8", "Mali-G52"),
        ("SM-S918B", "ARMv8 VFPv4 NEON VMH | 3200 | 8", "Adreno (TM) 740"),
        ("Redmi Note 10","ARMv8 VFPv4 NEON VMH | 2200 | 8","Adreno (TM) 619"),
        ("Redmi Note 11","ARMv8 VFPv4 NEON VMH | 2400 | 8","Adreno (TM) 610"),
        ("Poco X3","ARMv8 VFPv4 NEON VMH | 2300 | 8","Adreno (TM) 618"),
        ("Poco M4 Pro","ARMv8 VFPv4 NEON VMH | 2200 | 8","Mali-G57"),
        ("Pixel 6","ARMv8 VFPv4 NEON VMH | 2800 | 8","Mali-G78"),
        ("Pixel 7 Pro","ARMv8 VFPv4 NEON VMH | 2800 | 8","Mali-G710"),
        ("OnePlus 9","ARMv8 VFPv4 NEON VMH | 2800 | 8","Adreno (TM) 660"),
        ("OnePlus 11","ARMv8 VFPv4 NEON VMH | 3200 | 8","Adreno (TM) 740"),
        ("Xiaomi 13 Pro","ARMv8 VFPv4 NEON VMH | 3200 | 8","Adreno (TM) 740"),
        ("Infinix X6819","ARMv8 VFPv4 NEON VMH | 2400 | 8","Mali-G57"),
        ("vivo 1906","ARMv8 VFPv4 NEON VMH | 2000 | 8","Adreno (TM) 610"),
        ("OPPO CPH2211","ARMv8 VFPv4 NEON VMH | 2200 | 8","Adreno (TM) 619"),
        ("realme RMX3363","ARMv8 VFPv4 NEON VMH | 2400 | 8","Adreno (TM) 642"),
        ("TECNO KI5","ARMv8 VFPv4 NEON VMH | 2000 | 8","Mali-G52"),
    ]
    ANDROID_VERSIONS = [
        ("Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)","9","28"),
        ("Android OS 10 / API-29 (QKQ1.200114.002)","10","29"),
        ("Android OS 11 / API-30 (RP1A.201005.001)","11","30"),
        ("Android OS 12 / API-31 (SP1A.210812.016)","12","31"),
        ("Android OS 12L / API-32 (SP2A.220505.002)","12","32"),
        ("Android OS 13 / API-33 (TQ3A.230805.001)","13","33"),
        ("Android OS 14 / API-34 (UP1A.231005.007)","14","34"),
    ]
    NETWORKS  = ["WIFI","4G","5G"]
    OPERATORS = ["ATM Mobils","Telkomsel","Indosat","XL Axiata","Airtel","Jio","Vodafone","Globe","Smart","Viettel","Mobifone","Claro","Vivo"]
    SDK_VER   = ["4.0.38","4.0.39","4.0.40","4.0.41","4.0.42"]

    @classmethod
    def _rh(cls, n): return ''.join(random.choices("0123456789abcdef", k=n))
    @classmethod
    def _uuid(cls): return f"{cls._rh(8)}-{cls._rh(4)}-{cls._rh(4)}-{cls._rh(4)}-{cls._rh(12)}"
    @classmethod
    def _mac(cls):  return "02:" + ":".join(cls._rh(2) for _ in range(5))

    @classmethod
    def init_pool(cls, count=2500):
        if cls._devices: return
        for _ in range(count):
            model, cpu, gpu = random.choice(cls.DEVICE_MODELS)
            android_full, android_ver, api = random.choice(cls.ANDROID_VERSIONS)
            dev = {
                "model": model, "brand": model.split()[0], "cpu": cpu, "gpu": gpu,
                "android_full": android_full, "android_version": android_ver, "api_level": api,
                "operator": random.choice(cls.OPERATORS), "network": random.choice(cls.NETWORKS),
                "sdk": random.choice(cls.SDK_VER), "mac": cls._mac(),
                "device_id": cls._rh(32), "android_id": cls._rh(16), "uuid": cls._uuid(),
                "imei": cls._rh(15), "fingerprint": cls._rh(40), "gl_renderer": "OpenGL ES 3.2",
                "lang_code": random.choice(["en","in","ar","hi","vi","th","pt","ru","es","bn","ur","zh"]),
            }
            dev["_hdr"] = {
                "X-Device-Id": dev["device_id"], "X-Android-Id": dev["android_id"],
                "X-Device-Model": dev["model"],  "X-Device-Brand": dev["brand"],
                "X-OS-Version": dev["android_version"], "X-API-Level": dev["api_level"],
                "X-SDK-Version": dev["sdk"], "X-Network-Type": dev["network"],
                "X-Operator": dev["operator"], "X-IMEI": dev["imei"],
                "X-Mac": dev["mac"], "X-Client-Uuid": dev["uuid"],
            }
            dev["_gpu_full"] = f"{gpu}|OpenGL ES 3.2"
            cls._devices.append(dev)

    @classmethod
    def get(cls):
        with cls._lock:
            dev = cls._devices[cls._index % len(cls._devices)]
            cls._index += 1
            return dev

    @classmethod
    def headers(cls, device=None):
        d = device or cls.get()
        return d.get("_hdr") or {}

DevicePool.init_pool(2500)
print(f"[+] Device pool ready: {len(DevicePool._devices)} devices")

# ---- Thread-local ----
def get_thread_device():
    if not hasattr(_thread_local, "device"):
        _thread_local.device = DevicePool.get()
        _thread_local.dev_headers = _thread_local.device["_hdr"]
    return _thread_local.device

def get_thread_dev_headers():
    if not hasattr(_thread_local, "dev_headers"):
        _thread_local.device = DevicePool.get()
        _thread_local.dev_headers = _thread_local.device["_hdr"]
    return _thread_local.dev_headers

def reset_thread_session():
    """ HANYA clear cookie, TIDAK rotate device."""
    s = getattr(_thread_local, "session", None)
    if s is not None: s.cookies.clear()

def get_thread_session():
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=8, pool_maxsize=8,     
            max_retries=0, pool_block=False
        )
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.verify = False
        s.headers.update({
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        _thread_local.session = s
    return s

def encode_f14(s):
    ks = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,
          0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
          0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,
          0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    return bytes(ord(c) ^ ks[i % len(ks)] for i, c in enumerate(s))

FIELD_22 = bytes.fromhex(
    "4747524501010100620200001052aa0d669c6a368f08338060d2ee0690053af84a41edcd3558556ec10f24f4"
    "6c93ac64ca41a16732c46a2cb071246a79b8929032f9e1b6f4ef331bd53cabf29b09b97349a46e9863c0314e"
    "1a0d80819fef8aabf03876b3d037db354a7ccb5c1bce96411fb3753f6f50e44c69c4ed617fa30efb8ffc0517"
    "ff2f636739be1f304d999cfd6fd48bf69454199794c3dc88f55a4bdbd66534d5a061359cdfd1fb680cd37918"
    "df9fdb3cf7d80067b0a3506c90063cf62b2ccec11e23913a2fd7c4ef091331967bb518a5ad1e551146b90821"
    "be800883abadde39d6c80a5d798611466c748f075481806c5842ce45e6bd4e3368ec08fe2ec41ceb880cd862"
    "49eb71693f79f0bccf9e590c3fae12519fe08c7a1905d0927690109e0df28574bb14847225db1a59230e6662"
    "ed7730e15ff9a6c815cb41b420edeada735a4b03e181037c37c2c850257311df2f07b0a56e759372cbd0268e"
    "3f13a292ee4373e38ab5096e0342a5e0d7fec6da2bbc265d74baadd2b24ee4f74862f82c21d6694bac53f8ce"
    "80312a30068a6276a641c19b11d0305c6fe2f531ac7de578b29f543697f5c73663e6f23aa15277b6122dcd4d"
    "4171e38f9ac0b173f39c58416a16c5c1f4a35acd065ce78f449cf538a249339e763272d458e4ed86c976591a"
    "9c066b3a37111e44091eb6b5a795249f3e5145db022a6055f2cc675936391312f688f89627845df222a91156"
    "555225be36f9714a0ba50246d0f003bda3c9c1292ab73b4f79635ddd023218eda93a302d79e023404c143965"
    "44a930b98ed54771aca7fec10d095587685b473e81a9619764fad9256529dcd6e911f4f4629612287d4ee3ec"
    "5389f6ec4ec020b0e2aac017232a9197be9e46239ce690fe5d4872b2e98e651510c971667f3aca8b59f3e9d5"
    "0e43"
)

# ========== UA POOL BESAR ==========
USER_AGENTS_POOL = [
    "GarenaMSDK/4.0.39(SM-A325M;Android 13;en;HK;)",
    "GarenaMSDK/4.0.38(Redmi Note 10;Android 12;en;ID;)",
    "GarenaMSDK/4.0.40(Poco X3;Android 11;en;SG;)",
    "GarenaMSDK/4.0.41(SM-S918B;Android 14;en;IN;)",
    "GarenaMSDK/4.0.42(OnePlus 11;Android 13;en;US;)",
    "GarenaMSDK/4.0.39(Xiaomi 13 Pro;Android 13;pt;BR;)",
    "GarenaMSDK/4.0.40(Pixel 7 Pro;Android 14;en;US;)",
    "GarenaMSDK/4.0.38(ASUS ROG Phone 7;Android 13;id;ID;)",
    "GarenaMSDK/4.0.41(Infinix Note 12;Android 12;th;TH;)",
    "GarenaMSDK/4.0.43(SM-G998B;Android 13;ar;EG;)",
    "GarenaMSDK/4.0.37(Redmi Note 11;Android 11;es;MX;)",
    "GarenaMSDK/4.0.40(Poco F5;Android 13;en;VN;)",
    "GarenaMSDK/4.0.42(Realme GT 3;Android 13;hi;IN;)",
    "GarenaMSDK/4.0.39(Vivo V27;Android 13;en;PH;)",
    "GarenaMSDK/4.0.41(OPPO Reno 10;Android 13;id;ID;)",
    "GarenaMSDK/4.0.38(Tecno Camon 20;Android 13;fr;FR;)",
    "GarenaMSDK/4.0.40(Huawei P50;Android 11;ar;SA;)",
    "GarenaMSDK/4.0.42(Lenovo Legion Y70;Android 12;zh;TW;)",
    "GarenaMSDK/4.0.39(Zuck Z5 Pro;Android 11;en;US;)",
    "GarenaMSDK/4.0.44(SM-S928B;Android 14;en;SG;)",
    "GarenaMSDK/4.0.42(Xiaomi 14;Android 14;id;ID;)",
    "GarenaMSDK/4.0.40(Poco X5 Pro;Android 12;en;MY;)",
    "GarenaMSDK/4.0.41(Oppo Find X5;Android 13;th;TH;)",
    "GarenaMSDK/4.0.39(Vivo X80;Android 12;vi;VN;)",
    "GarenaMSDK/4.0.43(Realme 11 Pro;Android 13;hi;IN;)",
    "GarenaMSDK/4.0.38(Infinix Zero 30;Android 13;ar;SA;)",
    "GarenaMSDK/4.0.40(Tecno Phantom V;Android 13;pt;BR;)",
    "GarenaMSDK/4.0.42(Samsung A54;Android 13;es;MX;)",
    "GarenaMSDK/4.0.39(Samsung A34;Android 13;en;PH;)",
]

_SAMSUNG_MODELS = [
    ("SM-A325M","13"),("SM-A525F","13"),("SM-A725F","13"),("SM-A127F","12"),
    ("SM-A037F","11"),("SM-A546E","14"),("SM-A346E","14"),("SM-A146P","13"),
    ("SM-M236B","13"),("SM-M536B","14"),("SM-S901E","13"),("SM-S908E","13"),
    ("SM-S918B","14"),("SM-G998B","13"),("SM-G991B","13"),("SM-A135F","13"),
    ("SM-A226B","13"),("SM-A536B","14"),("SM-M135F","13"),("SM-A045F","13"),
]
_SAMSUNG_REGS = ["HK","ID","SG","MY","PH","TH","VN"]
for _model, _osv in _SAMSUNG_MODELS:
    for _reg in _SAMSUNG_REGS:
        USER_AGENTS_POOL.append(f"GarenaMSDK/4.0.39({_model};Android {_osv};en;{_reg};)")

_XIAOMI_MODELS = ["Poco X3","Poco X3 Pro","Poco F3","Poco F4","Poco F5","Poco M4 Pro","Poco M5",
                  "Xiaomi 12","Xiaomi 12 Pro","Xiaomi 13 Pro","Xiaomi 14","Xiaomi 14 Pro",
                  "Xiaomi 11T","Xiaomi 11T Pro","Redmi Note 10","Redmi Note 11","Redmi Note 12",
                  "Redmi Note 13","Redmi 9","Redmi 10","Redmi 12"]
for _model in _XIAOMI_MODELS:
    for _osv in ["11","12","13","14"]:
        for _reg in _SAMSUNG_REGS:
            USER_AGENTS_POOL.append(f"GarenaMSDK/4.0.40({_model};Android {_osv};en;{_reg};)")

_OPPO_MODELS = ["CPH2025","CPH2219","CPH2345","CPH2449","CPH2557","CPH2509","CPH2601"]
for _model in _OPPO_MODELS:
    for _osv in ["12","13","14"]:
        for _reg in _SAMSUNG_REGS:
            USER_AGENTS_POOL.append(f"GarenaMSDK/4.0.39({_model};Android {_osv};en;{_reg};)")

_VIVO_MODELS = ["V2024","V2048","V2120","V2146","V2229","V2307"]
for _model in _VIVO_MODELS:
    for _osv in ["12","13","14"]:
        for _reg in _SAMSUNG_REGS:
            USER_AGENTS_POOL.append(f"GarenaMSDK/4.0.39({_model};Android {_osv};en;{_reg};)")

_REALME_MODELS = ["RMX2020","RMX3360","RMX3363","RMX3630","RMX3700","RMX3686","RMX3636","RMX3624"]
for _model in _REALME_MODELS:
    for _osv in ["11","12","13","14"]:
        for _reg in _SAMSUNG_REGS:
            USER_AGENTS_POOL.append(f"GarenaMSDK/4.0.39({_model};Android {_osv};en;{_reg};)")

_ONEPLUS_MODELS = ["CPH2411","CPH2451","CPH2477","CPH2487","CPH2493"]
for _model in _ONEPLUS_MODELS:
    for _osv in ["13","14"]:
        for _reg in _SAMSUNG_REGS:
            USER_AGENTS_POOL.append(f"GarenaMSDK/4.0.39({_model};Android {_osv};en;{_reg};)")

USER_AGENTS_POOL = list(dict.fromkeys(USER_AGENTS_POOL))
print(f"[+] UA pool ready: {len(USER_AGENTS_POOL)} UAs")

def random_ua(): return random.choice(USER_AGENTS_POOL)

# ========== HTTP — NO RETRY ==========
_IP_HEADER_KEYS = ("X-Forwarded-For","X-Real-IP","X-Client-IP","CF-Connecting-IP","X-Originating-IP")

def _merge_headers(headers, device=None, rotate_ip=False):
    if headers is None: headers = {}
    merged = dict(headers)
    dev_h = DevicePool.headers(device) if device is not None else get_thread_dev_headers()
    for k, v in dev_h.items():
        merged.setdefault(k, v)
    if rotate_ip or "X-Forwarded-For" not in merged:
        iph = ip_headers()
        merged.update(iph)
    return merged

def request_retry(method, url, tag="HTTP", **kwargs):
    """ NO retry, fail-fast."""
    sess = get_thread_session()
    try:
        kwargs.setdefault('timeout', OPT['timeout'])
        kwargs['headers'] = _merge_headers(kwargs.get('headers'), rotate_ip=False)
        kwargs['verify'] = False
        if _is_debug():
            dbg(f"{tag}.request", method=method, url=url,
                device=get_thread_device().get("model"))
        resp = sess.request(method, url, **kwargs)
        if _is_debug():
            dbg(f"{tag}.status", value=str(resp.status_code))
            _dbg_resp_raw(tag, resp)
        return resp
    except Exception as e:
        if _is_debug(): dbg(f"{tag}.error", raw=str(e))
        return None

# ========== ENCRYPTION ==========
def encode_varint(n):
    if n < 0: return b''
    result = []
    while True:
        byte = n & 0x7F; n >>= 7
        if n: byte |= 0x80
        result.append(byte)
        if not n: break
    return bytes(result)

def create_proto_field(field_num, value):
    if isinstance(value, dict):
        nested = create_proto_field(field_num, value)
        return encode_varint((field_num << 3) | 2) + encode_varint(len(nested)) + nested
    elif isinstance(value, int):
        return encode_varint((field_num << 3) | 0) + encode_varint(value)
    elif isinstance(value, (str, bytes)):
        ev = value.encode() if isinstance(value, str) else value
        return encode_varint((field_num << 3) | 2) + encode_varint(len(ev)) + ev
    return b''

def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())

_AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
_AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

def aes_encrypt(hex_data):
    data = bytes.fromhex(hex_data)
    return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(pad(data, AES.block_size))

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(pad(plain, AES.block_size)).hex()

# ========== CREATE ACCOUNT ==========
def create_account(region, account_name, password_prefix):
    try:
        reset_thread_session()   # ⚡ cuma clear cookie
        rand_part = "".join(random.choices("0123456789ABCDEF", k=16))
        password = f"{password_prefix}_{rand_part}"
        url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
        payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
        body_json = json.dumps(payload, separators=(",", ":"))
        signature = hmac.new(HEX_KEY, body_json.encode("utf-8"), hashlib.sha256).hexdigest()

        dev = get_thread_device()
        headers = _merge_headers({
            "User-Agent": random_ua(),
            "Connection": "Keep-Alive",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Authorization": f"Signature {signature}",
            "Content-Type": "application/json; charset=utf-8",
            "Host": "100067.connect.garena.com",
        }, device=dev)

        resp = request_retry('POST', url, tag="Register", headers=headers, data=body_json)
        if resp and resp.status_code == 200:
            res = resp.json()
            if "data" in res and "uid" in res["data"]:
                uid = str(res["data"]["uid"])
                return get_token(uid, password, region, account_name, password_prefix)
        return None
    except Exception:
        return None

def get_token(uid, password, region, account_name, password_prefix):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        dev = get_thread_device()
        headers = _merge_headers({
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": random_ua(),
        }, device=dev)
        body = {"uid": uid, "password": password, "response_type": "token",
                "client_type": "2", "client_secret": HEX_KEY_STR, "client_id": "100067"}

        resp = request_retry('POST', url, tag="Token", headers=headers, data=body)
        if resp and resp.status_code == 200 and 'open_id' in resp.json():
            j = resp.json()
            open_id = j['open_id']
            access_token = j["access_token"]

            keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            encoded = "".join(chr(ord(open_id[i]) ^ keystream[i % len(keystream)]) for i in range(len(open_id)))
            field = codecs.decode(
                ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded),
                'unicode_escape'
            ).encode('latin1')
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix)
        return None
    except Exception:
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix):
    try:
        url = ("https://loginbp.ppmainecoonghj.com/MajorRegister"
               if region.upper() not in ["ME","TH"]
               else "https://loginbp.common.ggbluefox.com/MajorRegister")
        name = generate_random_name(account_name)
        dev = get_thread_device()
        headers = _merge_headers({
            'Host': 'loginbp.ppmainecoonghj.com',
            'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Accept': '*/*', 'Accept-Encoding': 'deflate, gzip',
            'Authorization': 'Bearer', 'X-GA': 'v1 1',
            'ReleaseVersion': RELEASE_VER,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Unity-Version': '2018.4.12f1',
        }, device=dev)
        lang = REGION_LANG.get(region.upper(), "en")
        reg_msg = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1,
                    14: encode_f14(open_id), 15: lang, 16: 2, 20: GAME_VERSION, 21: 1, 22: FIELD_22}
        encrypted = aes_encrypt(build_proto(reg_msg).hex())

        request_retry('POST', url, tag="MajorRegister", headers=headers, data=encrypted)
        login_result = major_login(uid, password, access_token, open_id, region)
        account_id = login_result.get("account_id", "N/A")
        jwt_token  = login_result.get("jwt_token", "")
        if account_id != "N/A":
            if jwt_token and region.upper() != "BR":
                try: force_region_bind(region, jwt_token)
                except: pass
            return {
                "uid": uid, "password": password, "name": name, "region": region,
                "account_id": account_id, "jwt_token": jwt_token,
                "device_model": dev["model"], "device_id": dev["device_id"],
                "created_at": datetime.now().isoformat()
            }
        return None
    except Exception:
        return None

def major_login(uid, password, access_token, open_id, region):
    try:
        lang = REGION_LANG.get(region.upper(), "en")
        dev  = get_thread_device()
        gpu_full, gpu, model = dev["_gpu_full"], dev["gpu"], dev["model"]
        os_str, operator, network = dev["android_full"], dev["operator"], dev["network"]
        device_uuid, cpu = dev["uuid"], dev["cpu"]
        ip_addr = pick_ip()

        open_id_b = open_id.encode() if isinstance(open_id, str) else open_id
        access_token_b = access_token.encode() if isinstance(access_token, str) else access_token

        payload_dict = {
            3:  datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            4:  b'free fire', 5: 1, 7: GAME_VERSION, 8: os_str, 9: b'Handheld',
            10: operator, 11: network, 12: 1280, 13: 720, 14: b'240', 15: cpu,
            16: random.choice([5951, 6000, 6100, 5500]), 17: gpu, 18: gpu_full,
            19: f'Google|{device_uuid}', 20: ip_addr, 21: lang, 22: open_id_b,
            23: b'4', 24: b'Handheld', 25: model, 26: lang, 29: access_token_b,
            30: 1, 41: operator, 42: network,
            57: b'1ac4b80ecf0478a44203bf8fac6120f5',
            60: 30000, 61: 30000, 62: 2519, 63: 243,
            64: 32357, 65: 34308, 66: 32357, 67: 34308, 73: 1,
            74: b'/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/lib/arm',
            76: 2,
            77: b'428775ab8c8845bd341b5357ec61d15e|/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/base.apk',
            78: 2, 79: 1, 81: b'32', 83: b'2019118525', 85: 3,
            86: b'OpenGLES3', 87: 4095, 88: 4,
            92: random.choice([19788, 20000, 21000]),
            93: b'android_max',
            94: b'KqsHT2gyPt7vUCc9SCjv2ioi3WEZSEL86ErvXB38suVVK/Z4IVt78ESl/r2S15C1pqu/j6ZmgFL7HbwoFiiVconX08ooKiisQffvEAPCo/C+Lahr',
            96: b'{"cur_rate":null,"support_etc2":true}',
            97: 1, 98: 1, 99: b'4', 100: b'4', 102: b'', 104: 77149, 105: 1,
            106: b'https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462',
            107: b'c8e41b7a93f02d56e1a94c7b8203f5d1',
        }
        data = build_proto(payload_dict)

        url = ("https://loginbp.ppmainecoonghj.com/MajorLogin"
               if region.upper() not in ["ME", "TH"]
               else "https://loginbp.common.ggbluefox.com/MajorLogin")

        headers = _merge_headers({
            'Host': 'loginbp.ppmainecoonghj.com',
            'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Accept': '*/*', 'Accept-Encoding': 'deflate, gzip',
            'Authorization': 'Bearer', 'X-GA': 'v1 1',
            'X-Ga-Sv': '1789534056',
            'ReleaseVersion': RELEASE_VER,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Unity-Version': '2018.4.12f1',
        }, device=dev)

        enc_hex = encrypt_api(data.hex())
        resp = request_retry('POST', url, tag="MajorLogin",
                             headers=headers, data=bytes.fromhex(enc_hex))

        if resp and resp.status_code == 200 and len(resp.text) > 10:
            jwt_start = resp.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = resp.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            pp = parts[1]
                            padding = 4 - len(pp) % 4
                            if padding != 4: pp += '=' * padding
                            claims = json.loads(base64.urlsafe_b64decode(pp))
                            account_id = claims.get('account_id') or claims.get('external_id')
                            if account_id:
                                return {"account_id": str(account_id), "jwt_token": jwt_token}
                    except Exception:
                        pass
        return {"account_id": "N/A", "jwt_token": ""}
    except Exception:
        return {"account_id": "N/A", "jwt_token": ""}

def force_region_bind(region, jwt_token):
    try:
        url = ("https://loginbp.common.ggbluefox.com/ChooseRegion"
               if region.upper() in ["ME","TH"]
               else "https://loginbp.ppmainecoonghj.com/ChooseRegion")
        region_code = "RU" if region.upper() == "CIS" else region.upper()
        encrypted = encrypt_api(build_proto({1: region_code}).hex())
        dev = get_thread_device()
        headers = _merge_headers({
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
            "X-Ga-Sv": "1789534056",
            "Authorization": f"Bearer {jwt_token}",
            "X-Ga": "v1 1", "Releaseversion": RELEASE_VER,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.12f1"
        }, device=dev)
        request_retry('POST', url, tag="ForceRegionBind", data=bytes.fromhex(encrypted), headers=headers)
    except Exception:
        pass

# ========== RANDOM NAME ==========
def generate_random_name(name_prefix):
    return name_prefix + ''.join(random.choices(string.ascii_letters + string.digits, k=6)).upper()

# ========== RARITY ==========
PATTERNS = {
    "R4": [r"(\d)\1{3,}", 5], "R3": [r"(\d)\1\1(\d)\2\2", 4],
    "S5": [r"(12345|23456|34567|45678|56789)", 6],
    "S4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 5],
    "P6": [r"^(\d)(\d)(\d)\3\2\1$", 7], "P4": [r"^(\d)(\d)\2\1$", 5],
    "SPH": [r"(69|420|1337|007)", 6],
    "SPM": [r"(100|200|300|400|500|666|777|888|999)", 4],
    "QD": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 6],
    "MH": [r"^(\d{2,3})\1$", 5], "MM": [r"(\d{2})0\1", 4],
    "GD": [r"1618|0618", 5],
    "ULTRA_R4": [r"(\d)\1{5,}", 10], "ULTRA_PAL": [r"^(\d)(\d)(\d)\2\1$", 8],
    "ULTRA_MIRROR": [r"^(\d{3})(\d{3})\1$", 9],
    "ULTRA_SEQ": [r"(012345|123456|234567|345678|456789|987654|876543|765432|654321)", 8],
    "ULTRA_QUAD": [r"(\d{4})\1", 8], "ULTRA_BINARY": [r"^[01]+$", 7],
    "ULTRA_REPEAT": [r"(\d{2})\1\1", 7],
}
COMPILED_PATTERNS = {k: (re.compile(p), pts) for k, (p, pts) in PATTERNS.items()}

def check_rarity(account_data):
    account_id = account_data.get("account_id", "")
    if not account_id or account_id == "N/A": return False, None, None, 0
    score = 0; patterns_found = []
    for ptype, (pattern, pts) in COMPILED_PATTERNS.items():
        if pattern.search(account_id):
            score += pts; patterns_found.append(ptype)
    digits = [int(d) for d in account_id if d.isdigit()]
    digit_count = len(digits)
    if len(set(digits)) == 1 and digit_count >= 4:
        bonus = min(digit_count * 2, 12); score += bonus
        patterns_found.append(f"UNIFORM(+{bonus})")
    if digit_count >= 4:
        diffs = [digits[i+1] - digits[i] for i in range(len(digits)-1)]
        if len(set(diffs)) == 1:
            bonus = min(abs(diffs[0]) * 2, 10); score += bonus
            patterns_found.append(f"ARITHMETIC(+{bonus})")
    if len(account_id) <= 8 and account_id.isdigit():
        n = int(account_id)
        if n < 1000000: score += 8; patterns_found.append("LOW_ID(<1M)")
        elif n < 10000000: score += 5; patterns_found.append("LOW_ID(<10M)")
        elif n < 100000000: score += 3; patterns_found.append("LOW_ID(<100M)")
    if account_id.isdigit() and len(account_id) > 0:
        score += 2; patterns_found.append("CLEAN_DIGIT")
    if len(account_id) >= 3 and account_id == account_id[::-1]:
        score += 6; patterns_found.append("PALINDROME")
    if "888" in account_id or "999" in account_id:
        score += 5; patterns_found.append("TRIPLE_EIGHT_NINE")
    if "0000" in account_id:
        score += 7; patterns_found.append("QUAD_ZUY")
    if len(account_id) >= 4:
        rising = all(digits[i] < digits[i+1] for i in range(len(digits)-1))
        sinking = all(digits[i] > digits[i+1] for i in range(len(digits)-1))
        if rising or sinking:
            bonus = min(len(digits) * 2, 10); score += bonus
            patterns_found.append(f"RISING_SINKING(+{bonus})")
    if score >= RARITY_SCORE_THRESHOLD:
        rtype = "LEGENDARY" if score >= 20 else "MYTHIC" if score >= 16 else "EPIC" if score >= 12 else "RARE"
        return True, rtype, ",".join(patterns_found[:10]), score
    return False, None, None, score

# ========== GENERATE SINGLE ==========
def generate_single_account(region, name_prefix, password_prefix):
    account_result = create_account(region, name_prefix, password_prefix)
    if not account_result or account_result.get("account_id", "N/A") == "N/A":
        return None
    is_rare, rtype, reason, rscore = check_rarity(account_result)
    account_result["rarity"] = rtype if is_rare else "NORMAL"
    account_result["rarity_score"] = rscore if is_rare else 0
    account_result["patterns"] = reason.split(",") if is_rare else []
    account_result["rarity_reason"] = reason if is_rare else ""
    return account_result

# ========== FLASK ==========
app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
    return response

@app.route('/', methods=['GET', 'OPTIONS'])
def index():
    if request.method == 'OPTIONS': return make_response('', 200)
    return jsonify({
        "message": "Free Fire Account Generator API — FAST",
        "endpoint": "/v3/generate?count=1000&name=User&password=Pass&region=ID&debug=0",
        "workers": FIXED_WORKERS,
        "target_acc_per_sec": TARGET_ACC_PER_SEC,
        "ip_pool_size": len(IP_POOL),
        "ua_pool_size": len(USER_AGENTS_POOL),
        "device_pool_size": len(DevicePool._devices),
    })

@app.route('/v3/generate', methods=['GET', 'OPTIONS'])
def generate_endpoint():
    if request.method == 'OPTIONS': return make_response('', 200)

    count    = request.args.get('count', default=1, type=int)
    name     = request.args.get('name', default='User', type=str)
    password = request.args.get('password', default='Pass', type=str)
    region   = request.args.get('region', default='ID', type=str).upper()
    debug    = request.args.get('debug', default=0, type=int) == 1

    if count < 1 or count > 2000:
        return jsonify({"error": "count must be between 1 and 2000"}), 400
    if not name or not password:
        return jsonify({"error": "name and password are required"}), 400
    if region not in REGION_LANG:
        return jsonify({"error": f"invalid region, allowed: {list(REGION_LANG.keys())}"}), 400

    _thread_local.debug_enabled = debug

    max_workers = min(FIXED_WORKERS, count)
    est_seconds  = count / TARGET_ACC_PER_SEC
    deadline     = time.time() + max(est_seconds * 3, 60)
    max_attempts = count * 4    

    accounts   = []
    attempts   = 0
    lock       = threading.Lock()
    stop_flag  = threading.Event()

    def worker():
        nonlocal attempts
        _thread_local.debug_enabled = debug
        while not stop_flag.is_set():
            with lock:
                if len(accounts) >= count or attempts >= max_attempts \
                        or time.time() > deadline:
                    stop_flag.set(); return
                attempts += 1
            try:
                acc = generate_single_account(region, name, password)
            except Exception:
                acc = None
            if acc:
                with lock:
                    if len(accounts) < count:
                        accounts.append(acc)
                        if len(accounts) >= count:
                            stop_flag.set()

    t_start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for _ in range(max_workers):
            ex.submit(worker)
        # Polling cepat, exit langsung
        while not stop_flag.is_set() and time.time() < deadline:
            time.sleep(0.02)
        stop_flag.set()

    elapsed = time.time() - t_start

    return jsonify({
        "success": True,
        "total_requested": count,
        "total_created": len(accounts),
        "accounts": accounts,
        "attempts_made": attempts,
        "device_pool_size": len(DevicePool._devices),
        "ip_pool_size": len(IP_POOL),
        "ua_pool_size": len(USER_AGENTS_POOL),
        "workers": max_workers,
        "elapsed_seconds": round(elapsed, 2),
        "throughput_acc_per_sec": round(len(accounts) / elapsed, 2) if elapsed > 0 else 0,
        "target_acc_per_sec": TARGET_ACC_PER_SEC,
        "debug": debug,
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "release_version": RELEASE_VER,
        "game_version": GAME_VERSION,
        "pools": {
            "ip_pool_size": len(IP_POOL),
            "ua_pool_size": len(USER_AGENTS_POOL),
            "device_models": len(DevicePool._devices),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

if __name__ == "__main__":
    app.run(debug=False, threaded=True, host="0.0.0.0", port=3000)
#
#
#
# t.me/RishantAPIs
# t.me/RishantAPIs
# t.me/RishantAPIs
# t.me/RishantAPIs
# I THINK I AM THE FIRST WHO LEAK KA GUEST GENERATOR API SOURCE CODE 
# Regards t.me/PeakCalumny
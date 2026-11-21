"""DCOC·데이터센터 화면 로컬 개발 서버(설치 대상 아님).

- Core의 page.html과 정적 파일을 실제 경로(/core/, /core/assets/<이름>)로 내보낸다.
  자산 이름은 views.py의 허용 목록을 그대로 읽어 검사한다. 목록에 없으면 404다.
- /core/api/facility, /core/api/facility/requests, /core/api/datacenter[/floors/<층>]는
  Core의 facility.py·datacenter.py 코드를 그대로 불러 실행한다(Django 대신 작은 대역).
- 시설 상태는 이 프로세스 안에서 실제로 도는 M4 시뮬레이터(Service)가 만든다.
  훈련 시작, 운영 조치, 장애 넣기, 배속 변경이 실제로 반영된다.
- 세션·레지스트리 등 나머지 Core API는 레포 코드(구성요소 선언, 권한 표)를 바탕으로 만든 최소 고정값이다.

    python tools/dcoc-dev/server.py [--port 8765] [--tick 2] [--livefire <경로>]

개발용 조작 페이지: http://127.0.0.1:8765/dev  (권한·라이선스 바꾸기, 강사 반 전체 장애 흉내)
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import queue
import re
import secrets
import sys
import tempfile
import threading
import time
import traceback
import types
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.dont_write_bytecode = True          # 구성요소 폴더에 __pycache__가 생기면 설치가 거절된다
_read_text = Path.read_text
# Windows 기본 인코딩(cp949) 대신 설치본(Linux)처럼 UTF-8로 읽는다(datacenter.py가 카탈로그를 read_text()로 읽는다)
Path.read_text = lambda self, encoding=None, errors=None, **kw: _read_text(self, encoding=encoding or "utf-8", errors=errors, **kw)

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CONTROL = REPO / "components" / "platform" / "control"
BRANDING = REPO / "assets" / "branding"

DEV = {"role": "admin", "license": "active"}          # /dev 페이지에서 바꾼다


def _roles() -> dict:
    """security.py의 권한 표를 그대로 읽는다(그 파일은 Django 모델을 불러서 통째로 import하지 않는다)."""
    text = (CONTROL / "security.py").read_text(encoding="utf-8")
    block = text[text.index("ROLES = {"):text.index("\n\n\ndef ")]
    space: dict = {}
    exec(block, space)
    return space["ROLES"]


ROLES = _roles()
READ_ACTIONS = {"read", "export", "stop"}             # entitlements.py와 같다


def log(message: str) -> None:
    print(time.strftime("%H:%M:%S"), message, flush=True)


# ── Django 대역 ────────────────────────────────────────────────────────
class JsonResponse:
    def __init__(self, data, status=200):
        self.data, self.status_code = data, status


class ValidationError(Exception):
    pass


class Denied(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def module(name: str, **values) -> types.ModuleType:
    m = types.ModuleType(name)
    m.__dict__.update(values)
    sys.modules[name] = m
    return m


def install_stubs(state_dir: Path, request_dir: Path):
    settings = types.SimpleNamespace(FACILITY_STATE_DIR=str(state_dir), FACILITY_REQUEST_DIR=str(request_dir),
                                     CONFIG={"public_host": "127.0.0.1", "ssh_username": "ccc", "siem_available": True})
    module("django")
    module("django.conf", settings=settings)
    module("django.core")
    module("django.core.exceptions", ValidationError=ValidationError)
    module("django.http", JsonResponse=JsonResponse)
    module("django.views")
    module("django.views.decorators")
    module("django.views.decorators.http", require_GET=lambda f: f, require_POST=lambda f: f)

    package = module("control")
    package.__path__ = [str(CONTROL)]

    def protected(permission=None):
        def decorate(function):
            def wrapped(request, *args, **kwargs):
                if permission and permission not in ROLES.get(request.user.profile.role, set()):
                    return JsonResponse({"error": "permission_denied"}, status=403)
                return function(request, *args, **kwargs)
            return wrapped
        return decorate

    def audit(request, action, outcome, target="", before=None, after=None):
        log(f"감사 기록: {action} {outcome} {target} {json.dumps(after or {}, ensure_ascii=False)}")

    module("control.security", protected=protected, audit=audit, ROLES=ROLES)
    module("control.entitlements", Denied=Denied)

    def access(component, action="register", **resource):
        paid = component.get("commercial") or component.get("minimum_tier", "community") != "community"
        if not paid:
            return {"tier": "community", "mode": "community"}
        if DEV["license"] == "none":
            raise Denied("commercial_unavailable")
        if DEV["license"] == "expired" and action not in READ_ACTIONS:
            raise Denied("entitlement_expired")
        return {"tier": "live-fire", "mode": "read-only" if DEV["license"] == "expired" else "licensed",
                "expires_at": "2027-03-01T00:00:00Z"}

    def edition():
        if DEV["license"] == "none":
            return {"tier": "community", "label": "Community", "state": "none"}
        return {"tier": "live-fire", "label": "Live Fire", "state": "expired" if DEV["license"] == "expired" else "active",
                "expires_at": "2027-03-01T00:00:00Z"}

    def panels(data, role):
        selected, allowed = {c["id"] for c in data["components"]}, set()
        for component in data["components"]:
            try:
                access(component)
                allowed.add(component["id"])
            except (OSError, ValueError, KeyError, TypeError):
                pass
        return [p for p in data["panels"] if p["component_id"] in selected & allowed and p["permission"] in ROLES.get(role, set())]

    def snapshot(data):
        now = datetime.now(timezone.utc)
        assets = [dict(a, health={"state": "running", "restarts": 0, "started_at": "2026-11-21T00:00:00+00:00"}) for a in data["assets"]]
        return {"assets": assets, "observation": {"fresh": True, "observed_at": now.isoformat(), "age_seconds": 3,
                                                  "max_age_seconds": 45, "scope": "container_state"},
                "served_at": now.isoformat(), "edition": edition()}

    def document(name, default):
        raise OSError("개발 서버에는 관측 파일이 없다")

    module("control.workspace", registry=lambda: REGISTRY, access=access, panels=panels, snapshot=snapshot,
           document=document, edition=edition)

    def data(request, required, optional=()):     # views.data와 같다
        def unique(pairs):
            out = {}
            for k, v in pairs:
                if k in out:
                    raise ValueError()
                out[k] = v
            return out
        try:
            value = json.loads(request.body, object_pairs_hook=unique)
            if not isinstance(value, dict) or not set(required) <= value.keys() or not value.keys() <= set(required) | set(optional):
                raise ValueError()
            return value
        except (ValueError, UnicodeError, RecursionError):
            raise ValidationError("invalid_body")

    module("control.views", data=data)
    return settings, edition, panels, snapshot


# ── 레포 선언으로 만든 레지스트리 ─────────────────────────────────────
def asset(service, title, kind, component, zones):
    ident = hashlib.sha1((component + "/" + service).encode()).hexdigest()
    return {"schema_version": "xoc.asset/0.1.0", "asset_id": "asset-" + ident[:32], "component_id": component,
            "service": service, "title": title, "kind": kind, "floor": "2F", "zones": zones,
            "tenant_id": "community", "range_id": "local"}


def build_registry(livefire: Path) -> dict:
    import yaml
    components, panels = [], []
    for name in ("noc", "portal", "siem-ui"):
        manifest = yaml.safe_load((REPO / "components" / name / "component.yaml").read_text(encoding="utf-8"))
        components.append({k: manifest.get(k) for k in ("id", "title", "version", "commercial", "minimum_tier", "requires", "provides")})
        panels += [dict(p, component_id=name) for p in manifest.get("ui") or []]
    m4 = yaml.safe_load((livefire / "modules" / "m4-facility" / "module.yaml").read_text(encoding="utf-8"))
    components.append({k: m4.get(k) for k in ("id", "title", "version", "commercial", "minimum_tier", "requires", "provides")})
    panels += [dict(p, component_id=m4["id"]) for p in m4.get("ui") or []]
    assets = [asset("ingress", "HTTPS 진입점", "proxy", "security-path", ["ext"]),
              asset("fw", "방화벽", "firewall", "security-path", ["ext", "pipe"]),
              asset("ips", "침입 방지(IPS)", "ips", "security-path", ["dmz", "office", "pipe"]),
              asset("web", "웹 방화벽(WAF)", "waf", "security-path", ["dmz", "int"]),
              asset("siem", "SIEM 매니저", "siem", "siem", ["mgmt"]),
              asset("indexer", "SIEM 인덱서", "siem", "siem", ["mgmt"]),
              asset("dashboard", "SIEM 대시보드", "dashboard", "siem-ui", ["mgmt"]),
              asset("platform", "Core 관리 서비스", "platform", "portal", ["mgmt"])]
    return {"schema_version": "xoc.registry/0.1.0", "plan_id": "dev-plan", "installation_id": "dev",
            "components": components, "panels": sorted(panels, key=lambda p: p.get("order", 0)), "assets": assets}


REGISTRY: dict = {}


# ── 시뮬레이터 ────────────────────────────────────────────────────────
class FakeLink:
    """Range Control 대신 강사 반 전체 장애(drills.py 형식)를 넣는 통로."""

    def __init__(self):
        self.inbox, self.outbox, self.answered = queue.Queue(), queue.Queue(), threading.Event()


def start_simulator(livefire: Path, state_dir: Path, request_dir: Path, tick: float):
    m4 = livefire / "modules" / "m4-facility"
    sys.path.insert(0, str(m4))
    if not hasattr(os, "fchmod"):                  # Windows의 Python 3.12에는 없다
        os.fchmod = lambda fd, mode: None
    sim = importlib.import_module("facility")
    service = sim.Service(state_dir, request_dir, sim.load_assets(m4 / "assets.yaml"), tick_sec=tick,
                          trainings=sim.load_trainings(m4 / "drills.yaml"))
    service.link = FakeLink()
    lock = threading.Lock()

    def loop():
        while True:
            try:
                with lock:
                    service.step()
            except OSError as exc:              # Windows에서 읽는 중인 파일은 바꾸지 못할 때가 있다
                log(f"시뮬레이터 쓰기 재시도: {exc.__class__.__name__}")
            except Exception:
                traceback.print_exc()
            time.sleep(0.25)

    threading.Thread(target=loop, daemon=True).start()
    return service, lock


# ── HTTP ──────────────────────────────────────────────────────────────
def allowed_assets() -> tuple:
    text = (CONTROL / "views.py").read_text(encoding="utf-8")
    match = re.search(r"def asset\(request, name\):\s*\n\s*if name not in \(([^)]*)\)", text)
    return tuple(re.findall(r"'([^']+)'", match.group(1)))


class User:
    is_authenticated = True

    def __init__(self):
        self.username = "dev-" + DEV["role"]
        self.profile = types.SimpleNamespace(role=DEV["role"], must_change_password=False, generation=1)


class Request:
    def __init__(self, method, body=b""):
        self.method, self.body, self.user, self.session, self.request_id = method, body, User(), {"generation": 1}, secrets.token_hex(8)


SIEM_PAGE = """<!doctype html><meta charset=utf-8><title>SIEM 대역</title><body style="font:16px system-ui;background:#141022;color:#e6dcf5;padding:40px">
<h1>SIEM(Wazuh Dashboard) 대역 — 개발 서버</h1><p>설치본에서는 이 주소가 Wazuh Discover를 엽니다.</p><pre id=u style="white-space:pre-wrap;background:#221a36;padding:16px;border-radius:8px"></pre>
<script>document.getElementById('u').textContent=decodeURIComponent(location.href)</script>"""

DEV_PAGE = """<!doctype html><meta charset=utf-8><title>개발 조작</title><body style="font:16px system-ui;background:#141022;color:#e6dcf5;padding:40px;line-height:2">
<h1>DCOC 개발 서버 조작</h1><p>현재: 권한 <b>{role}</b> · 라이선스 <b>{license}</b></p>
<p>권한: <a href=/dev?role=admin>관리자</a> · <a href=/dev?role=operator>운영자</a> · <a href=/dev?role=viewer>조회자</a></p>
<p>라이선스: <a href=/dev?license=active>유효</a> · <a href=/dev?license=expired>만료(읽기 전용)</a> · <a href=/dev?license=none>없음</a></p>
<p>강사 반 전체 장애(drills.py 흉내): <a href=/dev/class-drill?hidden=1>원인 숨김으로 시작</a> · <a href=/dev/class-drill?hidden=0>원인 공개로 시작</a> · <a href=/dev/class-drill?stop=1>종료</a></p>
<p><a href=/core/#datacenter>데이터센터</a> · <a href=/core/#module/m4-facility>DCOC 설비 운영</a></p>
<style>a{{color:#7ee8e1}}</style>"""

CLASS_DRILL = {"batch": None}


class Handler(BaseHTTPRequestHandler):
    server_version = "dcoc-dev"

    def log_message(self, fmt, *args):
        if "/core/api/facility " in (args[0] if args else "") or "POST" in (args[0] if args else ""):
            log(fmt % args)

    def send(self, status, body: bytes, kind: str, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Cache-Control", "no-store")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json(self, value, status=200):
        if isinstance(value, JsonResponse):
            value, status = value.data, value.status_code
        self.send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        try:
            if path in ("/", "/core"):
                return self.send(302, b"", "text/plain", [("Location", "/core/")])
            if path == "/core/":
                return self.send(200, (CONTROL / "page.html").read_bytes(), "text/html; charset=utf-8")
            if path.startswith("/core/assets/"):
                name = path.rsplit("/", 1)[1]
                if name not in allowed_assets():   # views.py를 고치면 바로 반영된다
                    return self.json({"error": "not_found"}, 404)
                kind = "text/javascript" if name.endswith(".js") else "text/css"
                return self.send(200, (CONTROL / name).read_bytes(), kind + "; charset=utf-8")
            if path.startswith("/assets/") and (BRANDING / path.rsplit("/", 1)[1]).is_file():
                return self.send(200, (BRANDING / path.rsplit("/", 1)[1]).read_bytes(), "image/png")
            if path.startswith("/siem"):
                return self.send(200, SIEM_PAGE.encode("utf-8"), "text/html; charset=utf-8")
            if path == "/dev":
                for key in ("role", "license"):
                    if query.get(key, [""])[0] in {"role": ROLES, "license": ("active", "expired", "none")}[key]:
                        DEV[key] = query[key][0]
                return self.send(200, DEV_PAGE.format(**DEV).encode("utf-8"), "text/html; charset=utf-8")
            if path == "/dev/class-drill":
                return self.class_drill(query)
            if path.startswith("/core/api/"):
                return self.api_get(path[len("/core/api/"):])
            return self.json({"error": "not_found"}, 404)
        except Exception:
            traceback.print_exc()
            return self.json({"error": "dev_server_error"}, 500)

    def class_drill(self, query):
        import random
        if query.get("stop"):
            if CLASS_DRILL["batch"]:
                SERVICE.link.inbox.put({"drill_id": secrets.token_hex(16), "batch_id": CLASS_DRILL["batch"], "action": "stop",
                                        "title": "강사 반 전체 장애", "requested_by": "instructor", "hidden": True, "faults": []})
                CLASS_DRILL["batch"] = None
        else:
            CLASS_DRILL["batch"] = secrets.token_hex(16)
            fault = random.choice([("chiller_fail", "chiller-01"), ("crac_fail", "crac-02"), ("pump_fail", "pump-pcw-01")])
            SERVICE.link.inbox.put({"drill_id": secrets.token_hex(16), "batch_id": CLASS_DRILL["batch"], "action": "start",
                                    "title": "3주차 반 전체 냉방 장애", "requested_by": "instructor", "hidden": query.get("hidden", ["1"])[0] == "1",
                                    "faults": [{"fault": fault[0], "target": fault[1], "minutes": 30}]})
        return self.send(302, b"", "text/plain", [("Location", "/dev")])

    def api_get(self, name):
        request = Request("GET")
        if name == "session":
            role = DEV["role"]
            return self.json({"csrf_token": "dev", "authenticated": True, "siem_available": True, "consoles": [],
                              "username": request.user.username, "role": role, "must_change_password": False,
                              "navigation": PANELS(REGISTRY, role), "edition": EDITION(), "lab_domain": "lab.local",
                              "public_host": "127.0.0.1"})
        if name in ("registry", "noc"):
            value = {k: REGISTRY[k] for k in ("schema_version", "plan_id", "components")}
            value.update(SNAPSHOT(REGISTRY), panels=PANELS(REGISTRY, DEV["role"]), floor="2F")
            return self.json(value)
        if name == "facility":
            with LOCK:
                return self.json(FACILITY.state(request))
        if name == "datacenter":
            with LOCK:
                return self.json(DATACENTER.endpoint(request))
        if name.startswith("datacenter/floors/"):
            with LOCK:
                return self.json(DATACENTER.endpoint(request, name.rsplit("/", 1)[1]))
        if name.startswith("datacenter/design/"):
            return self.json(DATACENTER.design(request, name.rsplit("/", 1)[1]))
        if name.startswith("modules/"):
            return self.json({"error": "component_not_installed"}, 404)
        return self.json({"error": "not_found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            if path == "/core/api/facility/requests":
                with LOCK:
                    return self.json(FACILITY.request_change(Request("POST", body)))
            if path == "/core/api/logout":
                return self.json({"ok": True})
            return self.json({"error": "permission_denied"}, 403)
        except Exception:
            traceback.print_exc()
            return self.json({"error": "dev_server_error"}, 500)


def main() -> int:
    global REGISTRY, ALLOWED, SERVICE, LOCK, FACILITY, DATACENTER, PANELS, SNAPSHOT, EDITION
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--tick", type=float, default=2.0, help="시뮬레이터 상태 쓰기 간격(초). 설치본은 5초")
    parser.add_argument("--livefire", type=Path, default=REPO.parent / "xocrange_livefire")
    parser.add_argument("--state", type=Path, default=None, help="시뮬레이터 상태 폴더(기본: 임시 폴더)")
    args = parser.parse_args()
    root = args.state or Path(tempfile.mkdtemp(prefix="dcoc-dev-"))
    state_dir, request_dir = root / "state", root / "requests"
    state_dir.mkdir(parents=True, exist_ok=True)
    request_dir.mkdir(parents=True, exist_ok=True)
    _, EDITION, PANELS, SNAPSHOT = install_stubs(state_dir, request_dir)
    REGISTRY = build_registry(args.livefire)
    ALLOWED = allowed_assets()
    FACILITY = importlib.import_module("control.facility")
    DATACENTER = importlib.import_module("control.datacenter")
    SERVICE, LOCK = start_simulator(args.livefire, state_dir, request_dir, args.tick)
    log(f"시뮬레이터 상태 폴더: {root}")
    log(f"http://127.0.0.1:{args.port}/core/#module/m4-facility  ·  조작: http://127.0.0.1:{args.port}/dev")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    return 0


ALLOWED: tuple = ()
SERVICE = LOCK = FACILITY = DATACENTER = PANELS = SNAPSHOT = EDITION = None

if __name__ == "__main__":
    sys.exit(main())

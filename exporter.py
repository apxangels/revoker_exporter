#!/usr/bin/env python3
"""
TLS certificate revocation Prometheus exporter.

Active OCSP/CRL checks with per-module configuration (mode + insecure).
The /probe endpoint blocks on first check and reads from cache thereafter.
"""

import os
import ssl
import socket
import time
import logging
import threading
import concurrent.futures
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

import yaml
import requests
from flask import Flask, request as flask_request, Response
from prometheus_client import CollectorRegistry, Gauge, generate_latest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, NameOID
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.x509.ocsp import OCSPCertStatus, OCSPResponseStatus

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("revoker")

# ── Config ────────────────────────────────────────────────────────────────────

CONFIG_PATH = os.environ.get("REVOKER_CONFIG", "revoker.yaml")


@dataclass
class ModuleConfig:
    mode: str = "both"      # "ocsp" | "crl" | "both"
    insecure: bool = False


@dataclass
class AppConfig:
    refresh_ocsp_seconds: int = 3600
    refresh_crl_seconds: int = 21600
    refresh_error_seconds: int = 300
    connect_timeout: int = 10
    http_timeout: int = 15
    max_workers: int = 10
    port: int = 9969
    probe_wait_timeout: int = 120
    modules: Dict[str, ModuleConfig] = field(default_factory=dict)


def _load_raw(path: str) -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.info("%s not found, using defaults", path)
        return {}


def _parse_config(raw: dict) -> AppConfig:
    modules: Dict[str, ModuleConfig] = {}
    for name, mc in (raw.get("modules") or {}).items():
        mc = mc or {}
        modules[name] = ModuleConfig(
            mode=str(mc.get("mode", "both")),
            insecure=bool(mc.get("insecure", False)),
        )
    if "default" not in modules:
        modules["default"] = ModuleConfig()

    return AppConfig(
        refresh_ocsp_seconds  = int(raw.get("refresh_ocsp_seconds",  3600)),
        refresh_crl_seconds   = int(raw.get("refresh_crl_seconds",  21600)),
        refresh_error_seconds = int(raw.get("refresh_error_seconds",   300)),
        connect_timeout       = int(raw.get("connect_timeout",          10)),
        http_timeout          = int(raw.get("http_timeout",             15)),
        max_workers           = int(raw.get("max_workers",              10)),
        port                  = int(raw.get("port",                   9969)),
        probe_wait_timeout    = int(raw.get("probe_wait_timeout",      120)),
        modules               = modules,
    )


_config_lock: threading.Lock = threading.Lock()
_config: AppConfig = _parse_config(_load_raw(CONFIG_PATH))
logger.info("Loaded config from %s", CONFIG_PATH)


def _cfg() -> AppConfig:
    with _config_lock:
        return _config


def reload_config() -> str:
    global _config
    raw = _load_raw(CONFIG_PATH)
    new_cfg = _parse_config(raw)
    with _config_lock:
        _config = new_cfg
    names = ", ".join(sorted(new_cfg.modules))
    logger.info("Config reloaded: %d module(s): %s", len(new_cfg.modules), names)
    return f"reloaded {len(new_cfg.modules)} module(s): {names}"


# ── Status codes ──────────────────────────────────────────────────────────────

class RevStatus(IntEnum):
    GOOD        = 0  # certificate is valid
    REVOKED     = 1  # certificate is revoked
    UNKNOWN     = 2  # OCSP responder returned "unknown"
    UNAVAILABLE = 3  # no OCSP or CRL URLs in certificate
    UNREACHABLE = 4  # responder/CRL server unreachable
    ERROR       = 5  # parse or validation error
    PENDING     = 6  # first check not yet complete


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class RevResult:
    status: RevStatus
    method: str                              # "ocsp" | "crl" | "none"
    revoked: bool
    ocsp_latency: Optional[float] = None
    crl_next_update: Optional[datetime] = None
    crl_issuer: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CertInfo:
    not_after: datetime
    subject: str
    serial: int
    ocsp_urls: List[str]
    crl_urls: List[str]
    issuer_url: Optional[str]
    stapled: bool
    chain: List[x509.Certificate] = field(default_factory=list)  # leaf first


@dataclass
class TargetState:
    instance: str
    module_name: str
    last_checked: Optional[float] = None
    next_refresh_at: float = 0.0
    cert_info: Optional[CertInfo] = None
    result: Optional[RevResult] = None
    running: bool = False
    failures: Dict[str, int] = field(default_factory=dict)
    ready: threading.Event = field(default_factory=threading.Event)


# ── Global state ──────────────────────────────────────────────────────────────

_lock: threading.Lock = threading.Lock()
_state: Dict[str, TargetState] = {}

_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=_config.max_workers,
    thread_name_prefix="checker",
)

# In-memory CRL cache: url -> (crl_object, expiry_unix_timestamp)
_crl_cache: Dict[str, Tuple[x509.CertificateRevocationList, float]] = {}
_crl_cache_lock = threading.Lock()


# ── Datetime helpers ──────────────────────────────────────────────────────────

def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _cert_not_after(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_after_utc      # cryptography >= 42
    except AttributeError:
        return _utc(cert.not_valid_after)    # type: ignore[attr-defined]


def _cert_not_before(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_before_utc     # cryptography >= 42
    except AttributeError:
        return _utc(cert.not_valid_before)   # type: ignore[attr-defined]


def _crl_next_update(crl: x509.CertificateRevocationList) -> Optional[datetime]:
    try:
        return crl.next_update_utc           # cryptography >= 42
    except AttributeError:
        nu = crl.next_update                 # type: ignore[attr-defined]
        return _utc(nu) if nu else None


# ── Certificate / chain helpers ───────────────────────────────────────────────

def fetch_leaf_cert(
    host: str,
    port: int,
    insecure: bool = False,
) -> Tuple[x509.Certificate, bool]:
    """Connect via TLS and return (leaf_cert, ocsp_stapled).

    When insecure=True the SSL chain is not verified — useful for targets
    whose issuer certificate is absent from the local CA bundle.
    """
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

    timeout = _cfg().connect_timeout
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            stapled = False  # Python ssl does not expose raw stapled bytes

    cert = x509.load_der_x509_certificate(der, default_backend())
    logger.debug("[%s:%s] leaf cert: %s", host, port, cert.subject.rfc4514_string())
    return cert, stapled


def get_aia_urls(cert: x509.Certificate) -> Tuple[List[str], Optional[str]]:
    """Return (ocsp_urls, ca_issuers_url) from the AIA extension."""
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return [], None

    ocsp_urls = [
        a.access_location.value
        for a in aia
        if a.access_method == AuthorityInformationAccessOID.OCSP
    ]
    issuer_urls = [
        a.access_location.value
        for a in aia
        if a.access_method == AuthorityInformationAccessOID.CA_ISSUERS
    ]
    return ocsp_urls, (issuer_urls[0] if issuer_urls else None)


def get_crl_urls(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return []

    urls = []
    for dp in ext:
        if dp.full_name:
            for name in dp.full_name:
                val = getattr(name, "value", "")
                if val.startswith("http"):
                    urls.append(val)
    return urls


def fetch_issuer_cert(url: str) -> Optional[x509.Certificate]:
    """Download the CA Issuers certificate (DER or PEM) from an AIA URL."""
    try:
        r = requests.get(url, timeout=_cfg().http_timeout, allow_redirects=True)
        r.raise_for_status()
        try:
            return x509.load_der_x509_certificate(r.content, default_backend())
        except Exception:
            return x509.load_pem_x509_certificate(r.content, default_backend())
    except Exception as e:
        logger.warning("issuer cert fetch failed (%s): %s", url, e)
        return None


def build_cert_chain(leaf_cert: x509.Certificate) -> List[x509.Certificate]:
    """Walk AIA CA Issuers links upward from the leaf to build the full chain."""
    chain = [leaf_cert]
    cert = leaf_cert
    seen = {leaf_cert.serial_number}

    for _ in range(8):  # guard against loops
        _, issuer_url = get_aia_urls(cert)
        if not issuer_url:
            break
        issuer = fetch_issuer_cert(issuer_url)
        if issuer is None or issuer.serial_number in seen:
            break
        chain.append(issuer)
        seen.add(issuer.serial_number)
        if issuer.subject == issuer.issuer:  # self-signed root
            break
        cert = issuer

    return chain


def _cert_chain_labels(cert: x509.Certificate, chain_no: int, instance: str) -> dict:
    """Extract Prometheus label values from a certificate (ssl_exporter format)."""
    def _get(name: x509.Name, oid) -> str:
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else ""

    cn        = _get(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _get(cert.issuer,  NameOID.COMMON_NAME)

    ou_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    ou = ("," + ",".join(a.value for a in ou_attrs) + ",") if ou_attrs else ""

    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        dns_list   = san.get_values_for_type(x509.DNSName)
        email_list = san.get_values_for_type(x509.RFC822Name)
        ip_list    = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        dnsnames = ("," + ",".join(dns_list)   + ",") if dns_list   else ""
        emails   = ("," + ",".join(email_list) + ",") if email_list else ""
        ips      = ("," + ",".join(ip_list)    + ",") if ip_list    else ""
    except x509.ExtensionNotFound:
        dnsnames = emails = ips = ""

    return {
        "instance":  instance,
        "chain_no":  str(chain_no),
        "cn":        cn,
        "issuer_cn": issuer_cn,
        "ou":        ou,
        "serial_no": str(cert.serial_number),
        "dnsnames":  dnsnames,
        "emails":    emails,
        "ips":       ips,
    }


# ── OCSP ──────────────────────────────────────────────────────────────────────

def check_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    ocsp_url: str,
    instance: str,
) -> RevResult:
    """Perform an active OCSP check via HTTP POST."""
    t0 = time.monotonic()
    try:
        req = (
            crypto_ocsp.OCSPRequestBuilder()
            .add_certificate(cert, issuer, hashes.SHA256())
            .build()
        )
        req_der = req.public_bytes(serialization.Encoding.DER)

        r = requests.post(
            ocsp_url,
            data=req_der,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=_cfg().http_timeout,
        )
        latency = time.monotonic() - t0
        r.raise_for_status()

        resp = crypto_ocsp.load_der_ocsp_response(r.content)

        if resp.response_status != OCSPResponseStatus.SUCCESSFUL:
            logger.warning("[%s] OCSP non-successful: %s", instance, resp.response_status)
            return RevResult(
                status=RevStatus.UNKNOWN,
                method="ocsp",
                revoked=False,
                ocsp_latency=latency,
                error=f"OCSP response_status={resp.response_status}",
            )

        if resp.serial_number != cert.serial_number:
            return RevResult(
                status=RevStatus.ERROR,
                method="ocsp",
                revoked=False,
                ocsp_latency=latency,
                error="OCSP serial number mismatch",
            )

        now = datetime.now(timezone.utc)
        this_update = _utc(resp.this_update) if resp.this_update else None
        next_update = _utc(resp.next_update) if resp.next_update else None

        if this_update and this_update > now:
            logger.warning("[%s] OCSP this_update is in the future", instance)
        if next_update and next_update < now:
            logger.warning("[%s] OCSP response is stale (next_update=%s)", instance, next_update)

        cert_status = resp.certificate_status
        if cert_status == OCSPCertStatus.GOOD:
            logger.info("[%s] OCSP: GOOD (latency=%.3fs)", instance, latency)
            return RevResult(status=RevStatus.GOOD, method="ocsp", revoked=False, ocsp_latency=latency)
        elif cert_status == OCSPCertStatus.REVOKED:
            logger.warning("[%s] OCSP: REVOKED", instance)
            return RevResult(status=RevStatus.REVOKED, method="ocsp", revoked=True, ocsp_latency=latency)
        else:
            logger.warning("[%s] OCSP: UNKNOWN status", instance)
            return RevResult(status=RevStatus.UNKNOWN, method="ocsp", revoked=False, ocsp_latency=latency)

    except Exception as e:
        latency = time.monotonic() - t0
        logger.warning("[%s] OCSP failed (%s): %s", instance, ocsp_url, e)
        return RevResult(
            status=RevStatus.UNREACHABLE,
            method="ocsp",
            revoked=False,
            ocsp_latency=latency,
            error=str(e),
        )


# ── CRL ───────────────────────────────────────────────────────────────────────

def _load_crl(data: bytes) -> x509.CertificateRevocationList:
    try:
        return x509.load_der_x509_crl(data, default_backend())
    except Exception:
        return x509.load_pem_x509_crl(data, default_backend())


def _fetch_crl(url: str, instance: str) -> Optional[x509.CertificateRevocationList]:
    """Return a CRL from in-memory cache or download it."""
    now_ts = time.time()

    with _crl_cache_lock:
        entry = _crl_cache.get(url)

    if entry is not None:
        crl, expiry_ts = entry
        if now_ts < expiry_ts:
            logger.debug("[%s] CRL cache hit: %s", instance, url)
            return crl
        logger.debug("[%s] CRL cache expired: %s", instance, url)

    logger.info("[%s] downloading CRL: %s", instance, url)
    try:
        r = requests.get(url, timeout=_cfg().http_timeout, allow_redirects=True)
        r.raise_for_status()
        crl = _load_crl(r.content)

        next_update = _crl_next_update(crl)
        refresh_crl = _cfg().refresh_crl_seconds
        expiry_ts = next_update.timestamp() if next_update else (now_ts + refresh_crl)

        with _crl_cache_lock:
            _crl_cache[url] = (crl, expiry_ts)
        return crl
    except Exception as e:
        logger.warning("[%s] CRL download failed (%s): %s", instance, url, e)
        return None


def check_crl(
    cert: x509.Certificate,
    crl_urls: List[str],
    instance: str,
) -> RevResult:
    if not crl_urls:
        return RevResult(
            status=RevStatus.UNAVAILABLE,
            method="crl",
            revoked=False,
            error="no CRL URLs in certificate",
        )

    now = datetime.now(timezone.utc)
    serial = cert.serial_number

    for url in crl_urls:
        crl = _fetch_crl(url, instance)
        if crl is None:
            continue

        next_update = _crl_next_update(crl)
        if next_update and next_update < now:
            logger.warning("[%s] CRL is stale (next_update=%s)", instance, next_update)

        revoked_entry = crl.get_revoked_certificate_by_serial_number(serial)
        if revoked_entry:
            logger.warning("[%s] CRL: REVOKED", instance)
            return RevResult(
                status=RevStatus.REVOKED,
                method="crl",
                revoked=True,
                crl_next_update=next_update,
                crl_issuer=crl.issuer.rfc4514_string(),
            )

        logger.info("[%s] CRL: GOOD", instance)
        return RevResult(
            status=RevStatus.GOOD,
            method="crl",
            revoked=False,
            crl_next_update=next_update,
            crl_issuer=crl.issuer.rfc4514_string(),
        )

    return RevResult(
        status=RevStatus.UNREACHABLE,
        method="crl",
        revoked=False,
        error="all CRL URLs failed",
    )


# ── Full check ────────────────────────────────────────────────────────────────

def _next_refresh(result: RevResult) -> float:
    now = time.time()
    c = _cfg()
    if result.status in (RevStatus.UNREACHABLE, RevStatus.ERROR):
        return now + c.refresh_error_seconds
    if result.method == "crl" and result.crl_next_update:
        valid_for = (result.crl_next_update - datetime.now(timezone.utc)).total_seconds()
        return now + max(c.refresh_crl_seconds, valid_for / 2)
    return now + c.refresh_ocsp_seconds


def run_check(state_key: str) -> None:
    """Full revocation check for one target+module. Runs in the thread pool."""
    with _lock:
        st = _state.get(state_key)
        if st is None:
            return
        instance    = st.instance
        module_name = st.module_name

    module = _cfg().modules.get(module_name, ModuleConfig())
    host, _, port_str = instance.rpartition(":")
    port = int(port_str)

    logger.info(
        "[%s] starting check (module=%s mode=%s insecure=%s)",
        instance, module_name, module.mode, module.insecure,
    )
    ready_event: Optional[threading.Event] = None

    try:
        cert, stapled = fetch_leaf_cert(host, port, insecure=module.insecure)

        ocsp_urls, issuer_url = get_aia_urls(cert)
        crl_urls = get_crl_urls(cert)
        chain = build_cert_chain(cert)

        cert_info = CertInfo(
            not_after=_cert_not_after(cert),
            subject=cert.subject.rfc4514_string(),
            serial=cert.serial_number,
            ocsp_urls=ocsp_urls,
            crl_urls=crl_urls,
            issuer_url=issuer_url,
            stapled=stapled,
            chain=chain,
        )

        result: Optional[RevResult] = None
        mode = module.mode

        # ── OCSP (primary for mode=ocsp or mode=both) ─────────────────────
        if mode in ("ocsp", "both"):
            if ocsp_urls:
                issuer = chain[1] if len(chain) > 1 else None
                if issuer is None and issuer_url:
                    issuer = fetch_issuer_cert(issuer_url)
                if issuer is None:
                    logger.warning("[%s] no issuer cert; OCSP skipped", instance)
                else:
                    for url in ocsp_urls:
                        result = check_ocsp(cert, issuer, url, instance)
                        if result.status not in (RevStatus.UNREACHABLE, RevStatus.ERROR):
                            break
            else:
                logger.info("[%s] no OCSP URLs in certificate", instance)

        # ── CRL (primary for mode=crl, fallback for mode=both) ────────────
        if mode in ("crl", "both"):
            need_crl = (
                mode == "crl"
                or result is None
                or result.status in (RevStatus.UNREACHABLE, RevStatus.UNKNOWN, RevStatus.ERROR)
            )
            if need_crl and crl_urls:
                crl_result = check_crl(cert, crl_urls, instance)
                if result is None or crl_result.status in (RevStatus.GOOD, RevStatus.REVOKED):
                    result = crl_result

        if result is None:
            result = RevResult(
                status=RevStatus.UNAVAILABLE,
                method="none",
                revoked=False,
                error="no OCSP or CRL URLs found in certificate",
            )

        with _lock:
            st = _state.get(state_key)
            if st:
                st.cert_info = cert_info
                st.result = result
                st.last_checked = time.time()
                st.next_refresh_at = _next_refresh(result)
                st.running = False
                if result.status in (RevStatus.UNREACHABLE, RevStatus.ERROR):
                    st.failures[result.method] = st.failures.get(result.method, 0) + 1
                ready_event = st.ready

        logger.info(
            "[%s] done: status=%s method=%s revoked=%s",
            instance, result.status.name, result.method, result.revoked,
        )

    except Exception as e:
        logger.exception("[%s] check failed: %s", instance, e)
        with _lock:
            st = _state.get(state_key)
            if st:
                st.result = RevResult(
                    status=RevStatus.ERROR,
                    method="none",
                    revoked=False,
                    error=str(e),
                )
                st.last_checked = time.time()
                st.next_refresh_at = time.time() + _cfg().refresh_error_seconds
                st.running = False
                st.failures["connect"] = st.failures.get("connect", 0) + 1
                ready_event = st.ready

    if ready_event is not None:
        ready_event.set()


def _ensure_target(instance: str, module_name: str) -> Tuple[str, threading.Event]:
    """Register target+module, schedule a check if due, return (state_key, ready_event)."""
    state_key = f"{module_name}:{instance}"
    with _lock:
        if state_key not in _state:
            _state[state_key] = TargetState(instance=instance, module_name=module_name)

        st = _state[state_key]
        if not st.running and time.time() >= st.next_refresh_at:
            st.running = True
            _pool.submit(run_check, state_key)

        return state_key, st.ready


# ── Background scheduler ──────────────────────────────────────────────────────

def _scheduler_loop() -> None:
    while True:
        time.sleep(30)
        with _lock:
            items = list(_state.items())

        now = time.time()
        to_run: List[str] = []
        for state_key, st in items:
            if not st.running and now >= st.next_refresh_at:
                with _lock:
                    st2 = _state.get(state_key)
                    if st2 and not st2.running and now >= st2.next_refresh_at:
                        st2.running = True
                        to_run.append(state_key)

        for state_key in to_run:
            _pool.submit(run_check, state_key)


threading.Thread(target=_scheduler_loop, daemon=True, name="scheduler").start()


# ── Flask application ─────────────────────────────────────────────────────────

app = Flask(__name__)

_INDEX_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Revoker Exporter</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 720px; color: #222; }}
    h1 {{ margin-bottom: 1.2rem; }}
    label {{ display: block; margin: 0.4rem 0; }}
    input[type=text] {{ width: 360px; padding: 0.3em 0.5em; font-size: 1em; }}
    select {{ padding: 0.3em 0.5em; font-size: 1em; }}
    #links {{ margin-top: 1.2rem; line-height: 2; }}
    #links a {{ display: block; }}
    hr {{ margin: 1.5rem 0; border: none; border-top: 1px solid #ccc; }}
    .nav a {{ margin-right: 1.2rem; }}
  </style>
</head>
<body>
<h1>Revoker Exporter</h1>
<form onsubmit="return false;">
  <label>Target: <input type="text" id="target" value="prometheus.io:443" oninput="update()"></label>
  <label>Module:
    <select id="module" onchange="update()">
      {module_options}
    </select>
  </label>
</form>
<div id="links">
  <a id="probe-link" href="#">Probe …</a>
  <a id="debug-link" href="#">Debug probe …</a>
</div>
<hr>
<p class="nav">
  <a href="/targets">Active targets</a>
  <a href="/config">Configuration</a>
</p>
<script>
  function update() {{
    var t = document.getElementById('target').value.trim() || 'prometheus.io:443';
    var m = document.getElementById('module').value;
    var base = '/probe?target=' + encodeURIComponent(t) + '&module=' + encodeURIComponent(m);
    document.getElementById('probe-link').href = base;
    document.getElementById('probe-link').textContent = 'Probe ' + t + ' with ' + m;
    document.getElementById('debug-link').href = base + '&debug=true';
    document.getElementById('debug-link').textContent = 'Debug probe ' + t + ' with ' + m;
  }}
  update();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    modules = sorted(_cfg().modules.keys())
    opts = "\n      ".join(
        f'<option value="{m}"{" selected" if m == "default" else ""}>{m}</option>'
        for m in modules
    )
    return Response(_INDEX_HTML.format(module_options=opts), mimetype="text/html")


@app.route("/config")
def config_page():
    try:
        with open(CONFIG_PATH) as f:
            content = f.read()
    except Exception as e:
        content = f"# error reading {CONFIG_PATH}: {e}\n"
    return Response(content, mimetype="text/plain; charset=utf-8")


@app.route("/reload", methods=["POST"])
def do_reload():
    msg = reload_config()
    return Response(msg + "\n", mimetype="text/plain")


@app.route("/probe")
def probe():
    target = flask_request.args.get("target", "").strip()
    if not target:
        return Response("missing ?target= parameter\n", status=400)

    module_name = flask_request.args.get("module", "default").strip()
    debug = flask_request.args.get("debug", "").lower() in ("1", "true", "yes")

    # Strip scheme if provided (e.g. https://ya.ru → ya.ru)
    for scheme in ("https://", "http://"):
        if target.startswith(scheme):
            target = target[len(scheme):]
            break
    target = target.rstrip("/")

    # Parse host:port
    if target.startswith("["):
        bracket_end = target.find("]")
        if bracket_end == -1:
            return Response("invalid IPv6 target\n", status=400)
        host = target[1:bracket_end]
        rest = target[bracket_end + 1:]
        port = int(rest.lstrip(":")) if rest.startswith(":") else 443
    elif ":" in target:
        host, _, port_str = target.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            return Response("invalid port\n", status=400)
    else:
        host = target
        port = 443

    instance = f"{host}:{port}"

    c = _cfg()
    if module_name not in c.modules:
        return Response(f"unknown module {module_name!r}\n", status=400)

    state_key, ready_event = _ensure_target(instance, module_name)

    # Block until the first check completes (avoids returning PENDING to Prometheus)
    probe_wait = c.probe_wait_timeout
    if probe_wait > 0 and not ready_event.is_set():
        ready_event.wait(timeout=probe_wait)

    # Snapshot cached state — no I/O under lock
    with _lock:
        st = _state[state_key]
        cert_info    = st.cert_info
        result       = st.result
        last_checked = st.last_checked
        failures     = dict(st.failures)

    registry = CollectorRegistry()

    def g(name, doc, *label_names):
        return Gauge(name, doc, list(label_names), registry=registry)

    g_revoked   = g("tls_cert_revoked",
                    "1 if certificate is currently revoked",
                    "instance")
    g_status    = g("tls_revocation_status",
                    "Revocation status: 0=good 1=revoked 2=unknown "
                    "3=unavailable 4=unreachable 5=error 6=pending",
                    "instance", "method")
    g_ocsp_lat  = g("tls_ocsp_latency_seconds",
                    "OCSP request round-trip latency in seconds",
                    "instance")
    g_cache_age = g("tls_cache_age_seconds",
                    "Seconds elapsed since the last completed check",
                    "instance")
    g_not_after = g("tls_cert_not_after_timestamp_seconds",
                    "Unix timestamp of certificate not-after (expiry)",
                    "instance")
    g_days      = g("tls_cert_days_remaining",
                    "Calendar days until certificate expiry",
                    "instance")
    g_stapled   = g("tls_ocsp_stapled",
                    "1 if the TLS server sent a stapled OCSP response",
                    "instance")
    g_crl_next  = g("tls_crl_next_update_timestamp_seconds",
                    "Unix timestamp of CRL next-update field",
                    "instance")
    g_failures  = g("tls_responder_failures_total",
                    "Cumulative responder / CRL fetch failures since start",
                    "instance", "method")
    g_success   = g("tls_probe_success",
                    "1 if the last probe produced a definitive revocation answer",
                    "instance")

    # Per-certificate chain metrics (leaf first, then intermediates, then root)
    g_chain_not_after  = g(
        "tls_cert_chain_not_after",
        "NotAfter Unix timestamp for each certificate in the verified chain",
        "instance", "chain_no", "cn", "issuer_cn", "ou",
        "serial_no", "dnsnames", "emails", "ips",
    )
    g_chain_not_before = g(
        "tls_cert_chain_not_before",
        "NotBefore Unix timestamp for each certificate in the verified chain",
        "instance", "chain_no", "cn", "issuer_cn", "ou",
        "serial_no", "dnsnames", "emails", "ips",
    )

    lbl = {"instance": instance}

    if result is not None:
        g_revoked.labels(**lbl).set(1 if result.revoked else 0)
        g_status.labels(instance=instance, method=result.method).set(int(result.status))

        if result.ocsp_latency is not None:
            g_ocsp_lat.labels(**lbl).set(result.ocsp_latency)

        if result.crl_next_update is not None:
            g_crl_next.labels(**lbl).set(result.crl_next_update.timestamp())

        definitive = result.status in (RevStatus.GOOD, RevStatus.REVOKED)
        g_success.labels(**lbl).set(1 if definitive else 0)
    else:
        g_revoked.labels(**lbl).set(0)
        g_status.labels(instance=instance, method="none").set(int(RevStatus.PENDING))
        g_success.labels(**lbl).set(0)

    if cert_info is not None:
        g_not_after.labels(**lbl).set(cert_info.not_after.timestamp())
        days = (cert_info.not_after - datetime.now(timezone.utc)).days
        g_days.labels(**lbl).set(days)
        g_stapled.labels(**lbl).set(1 if cert_info.stapled else 0)

        for i, cert_obj in enumerate(cert_info.chain):
            chain_labels = _cert_chain_labels(cert_obj, i, instance)
            g_chain_not_after.labels(**chain_labels).set(_cert_not_after(cert_obj).timestamp())
            g_chain_not_before.labels(**chain_labels).set(_cert_not_before(cert_obj).timestamp())

    if last_checked is not None:
        g_cache_age.labels(**lbl).set(time.time() - last_checked)

    for method, count in failures.items():
        g_failures.labels(instance=instance, method=method).set(count)

    metrics_bytes = generate_latest(registry)

    if debug:
        module = c.modules.get(module_name, ModuleConfig())
        lines = [
            f"# module:      {module_name} (mode={module.mode}, insecure={module.insecure})",
            f"# instance:    {instance}",
        ]
        if result:
            lines.append(f"# status:      {result.status.name}")
            lines.append(f"# method:      {result.method}")
            lines.append(f"# revoked:     {result.revoked}")
            if result.error:
                lines.append(f"# error:       {result.error}")
        if cert_info:
            lines.append(f"# subject:     {cert_info.subject}")
            lines.append(f"# not_after:   {cert_info.not_after.isoformat()}")
            lines.append(f"# ocsp_urls:   {cert_info.ocsp_urls}")
            lines.append(f"# crl_urls:    {cert_info.crl_urls}")
        if last_checked:
            ts = datetime.fromtimestamp(last_checked, tz=timezone.utc).isoformat()
            lines.append(f"# last_checked:{ts}")
        lines.append("")
        debug_prefix = ("\n".join(lines) + "\n").encode()
        return Response(
            debug_prefix + metrics_bytes,
            mimetype="text/plain; version=0.0.4",
        )

    return Response(metrics_bytes, mimetype="text/plain; version=0.0.4")


@app.route("/healthz")
def healthz():
    return Response("ok\n", mimetype="text/plain")


@app.route("/targets")
def targets():
    """Debug endpoint: list registered targets and their current status."""
    with _lock:
        rows = []
        for state_key, st in sorted(_state.items()):
            status = st.result.status.name if st.result else "PENDING"
            checked = (
                datetime.fromtimestamp(st.last_checked, tz=timezone.utc).isoformat()
                if st.last_checked else "never"
            )
            rows.append(f"{st.instance}\t{st.module_name}\t{status}\t{checked}")
    return Response("\n".join(rows) + "\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=_config.port, threaded=True)

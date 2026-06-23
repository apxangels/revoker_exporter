#!/usr/bin/env python3
"""
TLS certificate revocation Prometheus exporter.

Active OCSP checks with CRL fallback. All network I/O happens in background
workers; the /probe endpoint blocks on first check and reads from cache thereafter.
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

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("revoker")

# ── Config ─────────────────────────────────────────────────────────────────────

def _load_config(path: str = "revoker.yaml") -> dict:
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        logger.info(f"Loaded config from {path}")
        return cfg
    except FileNotFoundError:
        logger.info(f"{path} not found, using defaults")
        return {}

_cfg = _load_config()

REFRESH_OCSP_SECONDS  = int(_cfg.get("refresh_ocsp_seconds",  3600))
REFRESH_CRL_SECONDS   = int(_cfg.get("refresh_crl_seconds",  21600))
REFRESH_ERROR_SECONDS = int(_cfg.get("refresh_error_seconds",   300))
CONNECT_TIMEOUT       = int(_cfg.get("connect_timeout",          10))
HTTP_TIMEOUT          = int(_cfg.get("http_timeout",             15))
MAX_WORKERS           = int(_cfg.get("max_workers",              10))
PORT                  = int(_cfg.get("port",                   9969))
PROBE_WAIT_TIMEOUT    = int(_cfg.get("probe_wait_timeout",      120))

# ── Status codes ───────────────────────────────────────────────────────────────

class RevStatus(IntEnum):
    GOOD        = 0  # certificate is valid
    REVOKED     = 1  # certificate is revoked
    UNKNOWN     = 2  # OCSP responder returned "unknown"
    UNAVAILABLE = 3  # no OCSP or CRL URLs in certificate
    UNREACHABLE = 4  # responder/CRL server unreachable
    ERROR       = 5  # parse or validation error
    PENDING     = 6  # first check not yet complete

# ── Data classes ───────────────────────────────────────────────────────────────

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
    last_checked: Optional[float] = None
    next_refresh_at: float = 0.0
    cert_info: Optional[CertInfo] = None
    result: Optional[RevResult] = None
    running: bool = False
    failures: Dict[str, int] = field(default_factory=dict)
    ready: threading.Event = field(default_factory=threading.Event)


# ── Global state ───────────────────────────────────────────────────────────────

_lock: threading.Lock = threading.Lock()
_state: Dict[str, TargetState] = {}
_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_WORKERS,
    thread_name_prefix="checker",
)

# In-memory CRL cache: url -> (crl_object, expiry_unix_timestamp)
_crl_cache: Dict[str, Tuple[x509.CertificateRevocationList, float]] = {}
_crl_cache_lock = threading.Lock()

# ── Datetime helpers ───────────────────────────────────────────────────────────

def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


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

# ── Certificate / chain helpers ────────────────────────────────────────────────

def fetch_leaf_cert(host: str, port: int) -> Tuple[x509.Certificate, bool]:
    """Connect via TLS and return (leaf_cert, ocsp_stapled)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            stapled = False  # Python ssl does not expose raw stapled bytes

    cert = x509.load_der_x509_certificate(der, default_backend())
    logger.debug(f"[{host}:{port}] leaf cert: {cert.subject.rfc4514_string()}")
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
        r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        try:
            return x509.load_der_x509_certificate(r.content, default_backend())
        except Exception:
            return x509.load_pem_x509_certificate(r.content, default_backend())
    except Exception as e:
        logger.warning(f"issuer cert fetch failed ({url}): {e}")
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

# ── OCSP ───────────────────────────────────────────────────────────────────────

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
            timeout=HTTP_TIMEOUT,
        )
        latency = time.monotonic() - t0
        r.raise_for_status()

        resp = crypto_ocsp.load_der_ocsp_response(r.content)

        if resp.response_status != OCSPResponseStatus.SUCCESSFUL:
            logger.warning(f"[{instance}] OCSP non-successful: {resp.response_status}")
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
            logger.warning(f"[{instance}] OCSP this_update is in the future")
        if next_update and next_update < now:
            logger.warning(f"[{instance}] OCSP response is stale (next_update={next_update})")

        cert_status = resp.certificate_status
        if cert_status == OCSPCertStatus.GOOD:
            logger.info(f"[{instance}] OCSP: GOOD (latency={latency:.3f}s)")
            return RevResult(
                status=RevStatus.GOOD,
                method="ocsp",
                revoked=False,
                ocsp_latency=latency,
            )
        elif cert_status == OCSPCertStatus.REVOKED:
            logger.warning(f"[{instance}] OCSP: REVOKED")
            return RevResult(
                status=RevStatus.REVOKED,
                method="ocsp",
                revoked=True,
                ocsp_latency=latency,
            )
        else:
            logger.warning(f"[{instance}] OCSP: UNKNOWN status")
            return RevResult(
                status=RevStatus.UNKNOWN,
                method="ocsp",
                revoked=False,
                ocsp_latency=latency,
            )

    except Exception as e:
        latency = time.monotonic() - t0
        logger.warning(f"[{instance}] OCSP failed ({ocsp_url}): {e}")
        return RevResult(
            status=RevStatus.UNREACHABLE,
            method="ocsp",
            revoked=False,
            ocsp_latency=latency,
            error=str(e),
        )

# ── CRL ────────────────────────────────────────────────────────────────────────

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
            logger.debug(f"[{instance}] CRL cache hit: {url}")
            return crl
        logger.debug(f"[{instance}] CRL cache expired: {url}")

    logger.info(f"[{instance}] downloading CRL: {url}")
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        crl = _load_crl(r.content)

        next_update = _crl_next_update(crl)
        expiry_ts = next_update.timestamp() if next_update else (now_ts + REFRESH_CRL_SECONDS)

        with _crl_cache_lock:
            _crl_cache[url] = (crl, expiry_ts)

        return crl
    except Exception as e:
        logger.warning(f"[{instance}] CRL download failed ({url}): {e}")
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
            logger.warning(f"[{instance}] CRL is stale (next_update={next_update})")

        revoked_entry = crl.get_revoked_certificate_by_serial_number(serial)
        if revoked_entry:
            logger.warning(f"[{instance}] CRL: REVOKED")
            return RevResult(
                status=RevStatus.REVOKED,
                method="crl",
                revoked=True,
                crl_next_update=next_update,
                crl_issuer=crl.issuer.rfc4514_string(),
            )

        logger.info(f"[{instance}] CRL: GOOD")
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

# ── Full check ─────────────────────────────────────────────────────────────────

def _next_refresh(result: RevResult) -> float:
    now = time.time()
    if result.status in (RevStatus.UNREACHABLE, RevStatus.ERROR):
        return now + REFRESH_ERROR_SECONDS
    if result.method == "crl" and result.crl_next_update:
        valid_for = (result.crl_next_update - datetime.now(timezone.utc)).total_seconds()
        return now + max(REFRESH_CRL_SECONDS, valid_for / 2)
    return now + REFRESH_OCSP_SECONDS


def run_check(instance: str) -> None:
    """Full revocation check for one target. Runs in the thread pool."""
    host, _, port_str = instance.rpartition(":")
    port = int(port_str)

    logger.info(f"[{instance}] starting check")
    ready_event: Optional[threading.Event] = None

    try:
        cert, stapled = fetch_leaf_cert(host, port)

        ocsp_urls, issuer_url = get_aia_urls(cert)
        crl_urls = get_crl_urls(cert)

        # Build the full chain via AIA CA Issuers (leaf → intermediate → root)
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

        # ── OCSP (primary) ─────────────────────────────────────────────────
        if ocsp_urls:
            # Reuse chain[1] as the issuer if we have it; avoids a second fetch
            issuer = chain[1] if len(chain) > 1 else None
            if issuer is None:
                if issuer_url:
                    issuer = fetch_issuer_cert(issuer_url)
                else:
                    logger.warning(f"[{instance}] no CA Issuers URL; OCSP skipped")

            if issuer:
                for url in ocsp_urls:
                    result = check_ocsp(cert, issuer, url, instance)
                    if result.status not in (RevStatus.UNREACHABLE, RevStatus.ERROR):
                        break
        else:
            logger.info(f"[{instance}] no OCSP URLs in certificate")

        # ── CRL (fallback) ─────────────────────────────────────────────────
        if result is None or result.status in (
            RevStatus.UNREACHABLE, RevStatus.UNKNOWN, RevStatus.ERROR
        ):
            if crl_urls:
                crl_result = check_crl(cert, crl_urls, instance)
                if result is None or crl_result.status in (
                    RevStatus.GOOD, RevStatus.REVOKED
                ):
                    result = crl_result

        if result is None:
            result = RevResult(
                status=RevStatus.UNAVAILABLE,
                method="none",
                revoked=False,
                error="no OCSP or CRL URLs found in certificate",
            )

        with _lock:
            st = _state.get(instance)
            if st:
                st.cert_info = cert_info
                st.result = result
                st.last_checked = time.time()
                st.next_refresh_at = _next_refresh(result)
                st.running = False
                if result.status in (RevStatus.UNREACHABLE, RevStatus.ERROR):
                    st.failures[result.method] = (
                        st.failures.get(result.method, 0) + 1
                    )
                ready_event = st.ready

        logger.info(
            f"[{instance}] done: status={result.status.name} "
            f"method={result.method} revoked={result.revoked}"
        )

    except Exception as e:
        logger.exception(f"[{instance}] check failed: {e}")
        with _lock:
            st = _state.get(instance)
            if st:
                st.result = RevResult(
                    status=RevStatus.ERROR,
                    method="none",
                    revoked=False,
                    error=str(e),
                )
                st.last_checked = time.time()
                st.next_refresh_at = time.time() + REFRESH_ERROR_SECONDS
                st.running = False
                st.failures["connect"] = st.failures.get("connect", 0) + 1
                ready_event = st.ready

    if ready_event is not None:
        ready_event.set()


def _ensure_target(instance: str) -> threading.Event:
    """Register target, schedule a check if due, and return its ready event."""
    with _lock:
        if instance not in _state:
            _state[instance] = TargetState(instance=instance)

        st = _state[instance]
        if not st.running and time.time() >= st.next_refresh_at:
            st.running = True
            _pool.submit(run_check, instance)

        return st.ready

# ── Background scheduler ───────────────────────────────────────────────────────

def _scheduler_loop() -> None:
    while True:
        time.sleep(30)
        with _lock:
            items = list(_state.items())

        now = time.time()
        for instance, st in items:
            if not st.running and now >= st.next_refresh_at:
                with _lock:
                    _state[instance].running = True
                _pool.submit(run_check, instance)


threading.Thread(target=_scheduler_loop, daemon=True, name="scheduler").start()

# ── Flask application ──────────────────────────────────────────────────────────

app = Flask(__name__)


@app.route("/probe")
def probe():
    target = flask_request.args.get("target", "").strip()
    if not target:
        return Response("missing ?target= parameter\n", status=400)

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
    ready_event = _ensure_target(instance)

    # Block until the first check completes (avoids returning PENDING to Prometheus)
    if PROBE_WAIT_TIMEOUT > 0 and not ready_event.is_set():
        ready_event.wait(timeout=PROBE_WAIT_TIMEOUT)

    # Snapshot cached state — no I/O under lock
    with _lock:
        st = _state[instance]
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

        for cert_obj in cert_info.chain:
            chain_labels = _cert_chain_labels(cert_obj, 0, instance)
            g_chain_not_after.labels(**chain_labels).set(
                _cert_not_after(cert_obj).timestamp()
            )
            g_chain_not_before.labels(**chain_labels).set(
                _cert_not_before(cert_obj).timestamp()
            )

    if last_checked is not None:
        g_cache_age.labels(**lbl).set(time.time() - last_checked)

    for method, count in failures.items():
        g_failures.labels(instance=instance, method=method).set(count)

    return Response(
        generate_latest(registry),
        mimetype="text/plain; version=0.0.4",
    )


@app.route("/healthz")
def healthz():
    return Response("ok\n", mimetype="text/plain")


@app.route("/targets")
def targets():
    """Debug endpoint: list registered targets and their current status."""
    with _lock:
        rows = []
        for inst, st in sorted(_state.items()):
            status = st.result.status.name if st.result else "PENDING"
            checked = (
                datetime.fromtimestamp(st.last_checked, tz=timezone.utc).isoformat()
                if st.last_checked else "never"
            )
            rows.append(f"{inst}\t{status}\t{checked}")
    return Response("\n".join(rows) + "\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, threaded=True)

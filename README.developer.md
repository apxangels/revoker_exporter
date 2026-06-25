# Developer notes

This document explains how the exporter is structured internally, what happens at each stage, and where to look when something breaks.

## File layout

```
exporter.py      single-file application: config, data model, check logic, HTTP server
revoker.yaml     runtime configuration
requirements.txt Python dependencies
Dockerfile       single-worker gunicorn container
docker-compose.yml
```

Everything lives in `exporter.py`. There are no separate modules.

---

## Threading model

The process runs three kinds of threads:

```
main thread         gunicorn worker thread, handles HTTP requests
scheduler thread    wakes every 30 s, re-queues stale targets
checker threads     ThreadPoolExecutor (default 10), one per active check
```

The `_state` dict and `_crl_cache` dict are the only shared mutable state. Both are protected by their own locks (`_lock` and `_crl_cache_lock`). Checks never hold a lock while doing network I/O; they acquire the lock only to write results back.

---

## Global state

```python
_state: Dict[str, TargetState]
```

One `TargetState` entry per target (e.g. `"ya.ru:443"`). Contains:

- `cert_info` — parsed certificate data and the full chain
- `result` — winning `RevResult` used for `tls_cert_revoked` and `tls_probe_success`
- `per_method` — `Dict[str, RevResult]` with one entry per method that was actually checked (keys: `"ocsp"`, `"crl"`); used to emit per-method `tls_revocation_status` rows
- `last_checked` — unix timestamp of the last completed check
- `next_refresh_at` — when the next check should run
- `running` — True while a checker thread is active for this target
- `failures` — cumulative failure counters by method
- `ready` — `threading.Event`, set once the first check completes

```python
_crl_cache: Dict[str, Tuple[CRL, expiry_timestamp]]
```

In-memory CRL cache keyed by download URL. Entries expire when the CRL's own `next_update` field passes.

---

## Request lifecycle

### First request for a new target

```
HTTP GET /probe?target=ya.ru:443
  |
  v
probe()
  strips scheme, parses host:port
  calls _ensure_target("ya.ru:443")
    creates TargetState with ready=Event()
    sets running=True
    submits run_check("ya.ru:443") to thread pool
    returns the Event
  calls ready_event.wait(timeout=probe_wait_timeout)
    blocks until run_check signals the event
  reads snapshot from _state under lock
  builds CollectorRegistry, fills gauges
  returns Prometheus text format
```

### Subsequent requests (cache hit)

```
HTTP GET /probe?target=ya.ru:443
  |
  v
probe()
  calls _ensure_target()
    running=False, next_refresh_at is in the future -> does nothing
    returns the already-set Event
  ready_event.is_set() == True -> wait() returns immediately
  reads snapshot, returns metrics
```

### Background refresh

```
_scheduler_loop() wakes every 30 s
  for each target: if not running and now >= next_refresh_at
    sets running=True
    submits run_check() to thread pool
```

---

## What run_check does

```
run_check(instance)
  fetch_leaf_cert()           TLS connect, getpeercert(binary_form=True)
  — or —
  fetch_leaf_cert_smtp()      SMTP STARTTLS connect (proto=smtp modules)

  get_aia_urls(cert)          parse AIA extension: OCSP URLs, CA Issuers URL
  get_crl_urls(cert)          parse CDP extension: CRL distribution point URLs
  build_cert_chain(cert)      walk AIA CA Issuers upward: leaf -> intermediates -> root
                              stores results in a list of x509.Certificate objects

  if mode in (ocsp, both) and OCSP URLs exist:
    issuer = chain[1] if available, else fetch from CA Issuers URL
    for each OCSP URL:
      check_ocsp(cert, issuer, url)  -> ocsp_result
      stop on GOOD or REVOKED; retry next URL on UNREACHABLE/ERROR

  if mode in (crl, both) and CRL URLs exist:
    check_crl(cert, crl_urls)        -> crl_result
    (always runs in mode=both, not just as a fallback)

  pick winning result (mode=both: CRL definitive > OCSP definitive > CRL non-error > OCSP)
  build per_method dict from ocsp_result / crl_result
  write result and per_method into _state under lock
  call ready_event.set()
```

If any exception escapes (TLS connect failure, DNS error, etc.), the catch block writes `RevStatus.ERROR` into `_state` and still calls `ready_event.set()` so the waiting probe thread is unblocked.

---

## OCSP check (check_ocsp)

1. Build an OCSP request with `OCSPRequestBuilder`, SHA-256 hash, DER encoding.
2. HTTP POST to the OCSP URL with `Content-Type: application/ocsp-request`.
3. Parse the response with `load_der_ocsp_response`.
4. Check `response_status == SUCCESSFUL`; anything else is `UNKNOWN`.
5. Verify `resp.serial_number == cert.serial_number`; mismatch is `ERROR`.
6. Log warnings if `this_update` is in the future or `next_update` is in the past.
7. Map `OCSPCertStatus` to `RevStatus`: GOOD -> 0, REVOKED -> 1, else UNKNOWN -> 2.

OCSP response signatures are not verified by the library call. If you need signature verification, you must check that the responder certificate is either the issuer or a certificate signed by the issuer with the `id-kp-OCSPSigning` extended key usage.

---

## CRL check (check_crl)

1. For each CRL URL, call `_fetch_crl(url)`.
2. `_fetch_crl` checks `_crl_cache` first. If the cached entry has not expired, returns it without a network call.
3. Otherwise downloads the CRL (DER or PEM), parses it, stores it in `_crl_cache` with expiry = CRL `next_update`.
4. Calls `crl.get_revoked_certificate_by_serial_number(serial)`. If found: REVOKED. If not found: GOOD.
5. Tries the next URL only if the current one fails to download; does not try multiple URLs on a successful parse.

---

## Certificate chain building (build_cert_chain)

Starts with the leaf certificate. At each step:
- Reads the CA Issuers URL from the current certificate's AIA extension.
- Downloads and parses that certificate (`fetch_issuer_cert`).
- Appends it to the chain.
- Stops if the certificate is self-signed (`subject == issuer`) or if there is no CA Issuers URL.
- A guard of 8 iterations prevents infinite loops.

The issuer at `chain[1]` is reused directly by the OCSP check, so no extra network call is needed for the issuer fetch.

---

## Refresh scheduling

After each completed check, `_next_refresh` sets the next deadline:

- Error or unreachable: `now + refresh_error_seconds` (default 5 min)
- CRL result with a known `next_update`: `now + max(refresh_crl_seconds, next_update_in / 2)`
- Everything else: `now + refresh_ocsp_seconds` (default 1 hour)

The scheduler thread checks every 30 seconds and re-submits any target that is past its deadline and not already running.

---

## Metrics emission

`probe()` creates a fresh `CollectorRegistry` per request (not the global default registry). This allows per-target label sets without cross-contamination between simultaneous requests for different targets.

All gauges are filled from the `_state` snapshot taken under lock. No network calls happen inside `probe()`.

`tls_revocation_status` emits one time series per entry in `per_method`, so in `mode=both` you get separate `method="ocsp"` and `method="crl"` rows (only for methods that were actually checked). `tls_ocsp_latency_seconds` is read from `per_method["ocsp"]` and `tls_crl_next_update_timestamp_seconds` from `per_method["crl"]`, so they are correct regardless of which method won.

Chain metrics (`tls_cert_chain_not_after`, `tls_cert_chain_not_before`) are emitted by iterating `cert_info.chain` and calling `_cert_chain_labels()` on each `x509.Certificate` object. The chain is stored as live Python objects (not serialized), which is fine since `x509.Certificate` is immutable.

---

## Adding a new metric

1. Add a field to `RevResult` or `CertInfo` if the value comes from the check.
2. Populate the field in `check_ocsp`, `check_crl`, or `run_check`.
3. In `probe()`, declare the gauge with `g(name, doc, *label_names)` and call `.set()` inside the relevant `if result is not None` or `if cert_info is not None` block.

---

## Adding a new config key

Add it to `revoker.yaml` with a comment. Read it in the config section at module level:

```python
MY_SETTING = int(_cfg.get("my_setting", default_value))
```

Config is read once at startup. There is no hot-reload; restart the process to pick up changes.

---

## Common failure modes

**Target stuck in PENDING**

The checker thread is either still running or encountered an exception that did not set `ready`. Check logs for `[instance] check failed`. If `run_check` raises an unhandled exception before reaching the `except` block, `ready` will never be set and the probe will wait until `probe_wait_timeout`.

**Only one method appears in tls_revocation_status**

`per_method` only contains entries for methods that were actually run. If the certificate has no OCSP URLs, `ocsp_result` is never set and `method="ocsp"` will not appear. Check `# ocsp_urls:` and `# crl_urls:` in `?debug=1` output.

**OCSP skipped, CRL used instead**

The leaf certificate has an OCSP URL but no CA Issuers URL, so the issuer certificate cannot be obtained and OCSP is skipped. Look for `no issuer cert; OCSP skipped` in logs. The certificate chain will contain only the leaf.

**CRL always re-downloaded**

CRL `next_update` is in the past. The cache entry is treated as expired on every check. Look for `CRL is stale` in logs; the CRL server is not rotating the CRL on schedule.

**gunicorn timeout on first scrape**

The gunicorn `--timeout` (default 30 s in the Dockerfile) is shorter than `probe_wait_timeout` (default 120 s). Increase `--timeout` in the gunicorn command, or reduce `probe_wait_timeout`. Also increase Prometheus `scrape_timeout` for this job.

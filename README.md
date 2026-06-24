# Revoker exporter

A Prometheus exporter that performs active TLS certificate revocation checks via OCSP and CRL. All network I/O runs in background workers; the `/probe` endpoint only reads from an in-memory cache and blocks on the first request until the initial check completes.

## How it works

On the first `/probe` request for a target, the exporter:

1. Opens a TLS connection and retrieves the leaf certificate.
2. Walks the AIA CA Issuers chain upward (leaf -> intermediates -> root) by fetching each issuer certificate from the URL embedded in the certificate's Authority Information Access extension.
3. Sends an active OCSP request (HTTP POST, RFC 6960) to the OCSP responder URL from the same AIA extension, using SHA-256 as the hash algorithm.
4. If OCSP is unavailable or returns a non-definitive status, falls back to downloading and parsing the CRL from the CDP extension.
5. Stores the result and the full certificate chain in memory.
6. Schedules the next refresh based on the result: OCSP interval, CRL next_update, or error retry interval.

The `/probe` endpoint blocks until the first check completes (configurable via `probe_wait_timeout`). Subsequent requests return the cached result immediately.

CRLs are cached in memory until the `next_update` field in the CRL itself, so the same CRL is not downloaded redundantly across multiple targets that share a distribution point.

The background scheduler wakes every 30 seconds and re-queues any target whose refresh deadline has passed.

## Revocation status codes

| Value | Name        | Meaning                                          |
|-------|-------------|--------------------------------------------------|
| 0     | GOOD        | OCSP or CRL confirmed the certificate is valid   |
| 1     | REVOKED     | OCSP or CRL confirmed the certificate is revoked |
| 2     | UNKNOWN     | OCSP responder returned "unknown" status         |
| 3     | UNAVAILABLE | No OCSP or CRL URLs found in the certificate     |
| 4     | UNREACHABLE | Responder or CRL server could not be contacted   |
| 5     | ERROR       | Parse or validation error                        |
| 6     | PENDING     | First check has not completed yet                |

The exporter never treats a missing or unreachable OCSP response as GOOD.

## Metrics

| Metric                                  | Labels                                                              | Description                                      |
|-----------------------------------------|---------------------------------------------------------------------|--------------------------------------------------|
| `tls_cert_revoked`                      | instance                                                            | 1 if revoked, 0 otherwise                        |
| `tls_revocation_status`                 | instance, method                                                    | Status code from the table above                 |
| `tls_ocsp_latency_seconds`              | instance                                                            | OCSP round-trip time                             |
| `tls_cache_age_seconds`                 | instance                                                            | Seconds since last completed check               |
| `tls_cert_not_after_timestamp_seconds`  | instance                                                            | Leaf certificate expiry as Unix timestamp        |
| `tls_cert_days_remaining`               | instance                                                            | Calendar days until leaf certificate expiry      |
| `tls_ocsp_stapled`                      | instance                                                            | 1 if server sent a stapled OCSP response         |
| `tls_crl_next_update_timestamp_seconds` | instance                                                            | CRL next_update as Unix timestamp                |
| `tls_responder_failures_total`          | instance, method                                                    | Cumulative responder or CRL fetch failures       |
| `tls_probe_success`                     | instance                                                            | 1 if the last check produced a definitive result |
| `tls_cert_chain_not_after`              | instance, chain_no, cn, issuer_cn, ou, serial_no, dnsnames, emails, ips | NotAfter for each certificate in the chain  |
| `tls_cert_chain_not_before`             | instance, chain_no, cn, issuer_cn, ou, serial_no, dnsnames, emails, ips | NotBefore for each certificate in the chain |

## Endpoints

| Path       | Description                                      |
|------------|--------------------------------------------------|
| `/probe`   | Run or return cached check for `?target=host:port` or `?target=https://host` |
| `/healthz` | Returns 200 OK                                   |
| `/targets` | Lists all registered targets with status and last check time |

## Configuration

Edit `revoker.yaml` before starting the exporter. All fields are optional; defaults are shown.

```yaml
port: 9969
max_workers: 10

refresh_ocsp_seconds: 3600    # re-check interval after a successful OCSP result
refresh_crl_seconds: 21600    # minimum re-check interval after a CRL result
refresh_error_seconds: 300    # re-check interval after any failure

connect_timeout: 10           # TLS connect timeout in seconds
http_timeout: 15              # OCSP / CRL / AIA fetch timeout in seconds

probe_wait_timeout: 120       # how long /probe blocks waiting for the first result

# Modules define check behaviour. Select via ?module=<name> in /probe requests.
#
# mode:
#   both  — OCSP primary, CRL fallback (default)
#   ocsp  — OCSP only, no CRL fallback
#   crl   — CRL only, no OCSP
#
# insecure:
#   false — verify TLS certificate chain (default)
#   true  — skip chain verification (use when issuer CA is absent from local bundle)
modules:
  default:
    mode: both
    insecure: false

```

## Running

Local:

```
pip install -r requirements.txt
python exporter.py
```

Docker:

```
docker run -d --name revoker_exporter --restart unless-stopped -p 9969:9969 -e TZ=Europe/Moscow -v $(pwd)/revoker.yaml:/app/revoker.yaml:ro --health-cmd="python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:9969/healthz')\"" --health-interval=30s --health-timeout=5s --health-retries=3 --health-start-period=10s apxangels/revoker_exporter:latest
```
Or Docker compose:
```
services:
  revoker_exporter:
    image: apxangels/revoker_exporter:1.0
    container_name: revoker_exporter
    ports:
      - "9969:9969"

    restart: unless-stopped

    volumes:
      - ./revoker.yaml:/app/revoker.yaml:ro

    environment:
      TZ: Europe/Moscow

    healthcheck:
      test: ["CMD", "python", "-c",
             "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9969/healthz')"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```


The container image copies `revoker.yaml` as the default configuration. Mount your own file to override it:

```yaml
volumes:
  - ./revoker.yaml:/app/revoker.yaml:ro
```

## Prometheus scrape configuration

```yaml
scrape_configs:
  - job_name: tls_revocation
    metrics_path: /probe
    params:
      module: ["default"]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9969
    static_configs:
      - targets:
          - ya.ru:443
```

Set `scrape_timeout` in the job to a value larger than `probe_wait_timeout` to avoid Prometheus timing out on first scrape of a new target.

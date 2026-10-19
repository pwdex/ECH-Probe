# ECH Probe

A lightweight Python command-line tool for discovering **Encrypted ClientHello (ECH)** signals across a list of hostnames. It checks DNS HTTPS (type 65) records for advertised ECH configuration and performs a low-level TLS GREASE ClientHello probe to observe server behavior.

> **Important:** This is an observational scanner, not proof that ordinary client connections use ECH. A DNS ECH configuration indicates that ECH is advertised in DNS. The active probe sends a GREASE ClientHello and does **not** validate ECH acceptance. A negative or failed probe does not prove that a service lacks ECH support.

## Features

- Queries DNS HTTPS/SVCB records (type 65) and detects ECH configuration parameters.
- Follows relevant DNS CNAME and HTTPS AliasMode chains, with depth limits and loop detection.
- Uses configurable DNS resolvers, with UDP queries and TCP fallback for truncated responses.
- Sends a GREASE ECH ClientHello and records observable TLS response signals.
- Supports concurrent scanning of multiple hostnames.
- Accepts optional per-host ports in the input file.
- Exports results to CSV and optionally JSON Lines (JSONL).
- Reports progress and prints domains for which ECH is advertised in DNS.
- Includes timeouts and error details to help interpret incomplete probes.

## Requirements

- Python 3.10 or newer (the code uses modern type annotations such as `X | None`).
- Network access to the configured DNS resolvers and target hosts.
- Outbound DNS (UDP/TCP port 53) and TLS probe connectivity to the target port (443 by default).

The tool uses Python's standard library; no third-party Python packages are required.

## Getting started

### 1. Clone the repository

After you push this project to GitHub, clone it with:

```bash
git clone https://github.com/<YOUR-USERNAME>/<YOUR-REPOSITORY>.git
cd <YOUR-REPOSITORY>
```

Replace the placeholders with your GitHub username and repository name.

### 2. Prepare a domain list

Create a file named `domains.txt`, with one hostname per line:

```text
# Example targets
example.com
cloudflare.com
www.example.org
example.net:443
```

Blank lines and lines beginning with `#` are ignored. Duplicate hostname/port entries are removed. An optional `:port` suffix can be used for a hostname; otherwise, the default port applies.

Use hostnames, not IP addresses or full URLs. For example, use `example.com`, not `https://example.com/path`.

### 3. Run a scan

```bash
python3 ech_probe.py domains.txt
```

By default, the tool writes results to `ech_results.csv`, uses up to 20 concurrent workers, probes TLS port 443, uses a 5-second TLS timeout, and uses a 4-second DNS timeout per resolver.

## Usage

### Basic scan

```bash
python3 ech_probe.py domains.txt
```

### Choose an output CSV file

```bash
python3 ech_probe.py domains.txt --output results.csv
```

### Increase or reduce concurrency

```bash
python3 ech_probe.py domains.txt --jobs 30
```

### Configure timeouts

```bash
python3 ech_probe.py domains.txt --dns-timeout 3 --timeout 5
```

### Use specific DNS resolvers

```bash
python3 ech_probe.py domains.txt --dns-servers 1.1.1.1,8.8.8.8
```

Resolver entries may be IPv4 addresses, IPv6 addresses, or resolver hostnames.

### Change the default TLS port

```bash
python3 ech_probe.py domains.txt --port 8443
```

A port specified directly in `domains.txt` overrides this default for that hostname.

### Also write JSON Lines output

```bash
python3 ech_probe.py domains.txt --output results.csv --jsonl results.jsonl
```

Each line in the JSONL file contains one JSON object for a scanned hostname.

## Command-line options

| Option | Default | Description |
|---|---:|---|
| `domains_file` | Required | Input file containing hostnames and optional ports |
| `-o`, `--output` | `ech_results.csv` | CSV output path |
| `-j`, `--jobs` | `20` | Maximum number of concurrent worker threads; must be at least 1 |
| `-t`, `--timeout` | `5.0` seconds | TLS probe timeout; must be greater than 0 |
| `--dns-timeout` | `4.0` seconds | DNS timeout per resolver; must be greater than 0 |
| `--dns-servers` | `1.1.1.1,8.8.8.8` | Comma-separated DNS resolvers |
| `--port` | `443` | Default TLS port; must be between 1 and 65535 |
| `--jsonl` | Not enabled | Optional path for JSON Lines output |

Run `python3 ech_probe.py --help` to see the command-line help.

## Understanding the results

### Verdicts

| Verdict | Meaning |
|---|---|
| `positive` | An ECH configuration was found in a relevant DNS HTTPS/SVCB response. This means ECH is advertised in DNS; it does not prove a client can or will complete ECH. |
| `not_observed` | The DNS lookup completed, but no ECH configuration was observed in the relevant records. This is not proof that the service cannot support ECH. |
| `inconclusive` | The DNS lookup did not complete sufficiently to make a reliable determination. Review the error fields and retry if appropriate. |

### Important fields

| Field | Meaning |
|---|---|
| `domain` | Normalized hostname that was scanned |
| `port` | TLS port used for the active probe |
| `ech_advertised` | Whether an ECH configuration was observed in DNS |
| `ech_supported` | Legacy compatibility alias for `ech_advertised`; prefer `ech_advertised` |
| `verdict` | Overall DNS-based verdict |
| `dns_https` | Whether relevant HTTPS records were observed |
| `dns_lookup_complete` | Whether the DNS lookup reached a conclusive lookup state |
| `dns_ech` | Whether an ECH parameter was found in relevant HTTPS records |
| `dns_ech_b64` | JSON-encoded list of Base64 ECH configuration values found in DNS |
| `dns_resolver` | Resolver that supplied the successful DNS response |
| `dns_record_count` | Number of relevant HTTPS records observed |
| `active_sh` | Whether a ServerHello was observed during the active probe |
| `active_hrr_ech_extension` | Whether an ECH extension was observed in a HelloRetryRequest |
| `active_hrr_ech_extension_len` | Length of the observed HRR ECH extension, if present |
| `active_ech_acceptance_validated` | Whether ECH acceptance was cryptographically validated; this probe reports `false` |
| `active_hrr` | Whether the observed ServerHello was a HelloRetryRequest |
| `active_address` | Target IP address used for the observed response |
| `latency_ms` | Elapsed time for the active TLS probe, in milliseconds |
| `error` | DNS and/or active-probe error details |
| `dns_raw` | Concise summary of relevant DNS records and alias-chain observations |
| `active_info` | Summary of observed TLS handshake messages or alerts |

The CSV also contains the corresponding raw ECH configuration data and active-probe metadata. JSONL preserves the complete result objects.

## How it works

1. **Normalize input:** validates and normalizes each hostname and removes duplicate hostname/port entries.
2. **Query DNS:** requests HTTPS records (DNS type 65), using EDNS(0) and falling back to TCP when a UDP response is truncated.
3. **Follow aliases:** follows relevant CNAME and HTTPS AliasMode chains within configured depth limits.
4. **Inspect ECH configuration:** checks ServiceMode HTTPS parameters for a non-empty ECH parameter.
5. **Probe TLS:** sends a GREASE ECH ClientHello to the target and parses observable TLS records, ServerHello/HelloRetryRequest messages, and alerts.
6. **Save results:** writes a sorted CSV and, if requested, a JSONL file using temporary files and atomic replacement.

## Limitations and interpretation

- **GREASE is not a real ECH handshake.** The active probe does not have the target's real ECH configuration, an HPKE context, or the inner-handshake transcript required to validate ECH acceptance.
- **A ServerHello is not proof of ECH acceptance.** The tool explicitly does not infer acceptance from the presence of an observed extension.
- **DNS results are time- and resolver-dependent.** Different resolvers, DNS changes, network policies, and caching can affect results.
- **A failed probe is inconclusive about ECH support.** Firewalls, rate limits, routing problems, server behavior, and timeouts can prevent a response.
- **Results describe observations at scan time.** They should not be treated as a guarantee about every browser, client, network path, or future connection.
- **Scanning has an external network impact.** Only scan systems you own or are authorized to assess, and use reasonable concurrency and timeouts.

## Troubleshooting

- **`DNS timeout` or resolver errors:** check network access to the selected resolver and try a different resolver with `--dns-servers`.
- **TLS timeout or connection refused:** confirm that the hostname and port are reachable from your network. A failed active probe does not establish that ECH is unavailable.
- **`not_observed`:** verify that the hostname is correct and review `dns_lookup_complete`, `dns_https`, and `error` before drawing conclusions.
- **No output file:** check that the destination directory is writable and that the command completed without a file-writing error.

## Security and responsible use

This tool sends DNS queries and TLS ClientHello probes to the specified targets. Use it only for legitimate research, troubleshooting, or assessments you are authorized to perform. Avoid excessive concurrency against services you do not operate.

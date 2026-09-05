# vela-blocklist

The malicious-domain list behind Vela's **Scan** feature ("Ask before you click").

The app ships a bundled copy as an asset and refreshes it from:

```
https://raw.githubusercontent.com/vpnvela-del/vela-blocklist/main/blocklist.txt
```

## Format

One hostname per line, lowercased, sorted, deduplicated. The first line is a
comment carrying source/date/count:

```
# source abuse.ch URLhaus (hostfile, Tranco-filtered, malware only) | date 2026-09-05 | count 4380
0022a601.pphost.net
00pq7d1j.1xboropartners.com
...
```

The app's loader (`ScanRepository`) skips blank lines and any line starting with
`#`, so extra comments are safe to add.

## The two rules that must not be broken

1. **Full hostnames, never eTLD+1.** The feeds are full of `*.vercel.app`,
   `*.blogspot.com`, `*.amazonaws.com`. Collapsing an entry to its registrable
   domain would blocklist the entire provider. `ScanRepository` walks parent
   domains at lookup time, stopping at two labels, so a subdomain entry still
   catches deeper subdomains without over-blocking the apex.
2. **The `NEVER_BLOCK` guard.** A hardcoded set of shared-hosting / CDN / major
   apexes is dropped outright. On the seed run it caught 1,233 entries — malware
   hosted *on* `google.com`, `github.com`, `dropbox.com`, `drive.google.com`,
   `sites.google.com`. Without it the app blocklists Google and GitHub wholesale.

Bare IPs are dropped; this is a domain list.

## Refresh pipeline

`.github/workflows/refresh.yml` runs daily at 04:17 UTC and on manual dispatch.

- **Primary source:** the abuse.ch URLhaus **hostfile**,
  `https://urlhaus.abuse.ch/downloads/hostfile/`, with the Auth-Key sent in the
  `Auth-Key` request header from the `ABUSECH_AUTH_KEY` repository secret. This
  variant is domains-only and pre-filtered against the Tranco Top 1M, which cuts
  false positives.
- **Fallback:** if the secret is absent — or the authenticated fetch does not
  yield a usable list — the run logs a warning and falls back to the public
  plain-text URL feed, `https://urlhaus.abuse.ch/downloads/text/`. That is the
  feed the verified 4,911-domain seed was built from.
- **Safety valve:** `tools/build_blocklist.py` fails the run, writing nothing, if
  the body looks like HTML rather than a list, or if it yields fewer than
  **1,000** domains. A broken or empty fetch can never overwrite the good list.
  The workflow then re-checks the written file and asserts the `NEVER_BLOCK`
  apexes are absent.
- **Commit only on material change:** the generator compares domain bodies, not
  whole files, so the header's date does not churn a commit every day.

### Regenerating by hand

```sh
curl -sSL -H "Auth-Key: $ABUSECH_AUTH_KEY" \
  https://urlhaus.abuse.ch/downloads/hostfile/ -o feed.txt
python3 tools/build_blocklist.py --input feed.txt --output blocklist.txt \
  --source-label 'abuse.ch URLhaus (hostfile, Tranco-filtered, malware only)'
```

## Licensing

URLhaus is a fair-use community feed; abuse.ch notes that commercial or
for-profit use *may* require their paid commercial API. URLhaus is **malware
only** — it explicitly refuses phishing submissions, so this list carries no
phishing coverage. OpenPhish and PhishTank were both ruled out: their terms bar
commercial use and redistribution.

## Provenance

The first commit is the verified 4,911-domain seed copied verbatim from
`vela-android`'s `app/src/main/assets/scan/blocklist.txt` (Scan Phase 1.1,
on-device verified `loaded=4911`). `tools/build_blocklist.py` is a verbatim port
of the extractor that produced it — re-running it over the same 2026-09-04
URLhaus snapshot reproduces that file byte for byte.

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
# source abuse.ch URLhaus (plain-text URL feed + authenticated hostfile, malware only) | date 2026-09-05 | count 4840
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

- **Authenticated source:** the abuse.ch URLhaus **hostfile**, via the current
  v2 API — `https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/hostfile.txt`,
  with the key from the `ABUSECH_AUTH_KEY` repository secret. The key travels in
  the **URL path**: the legacy `Auth-Key:` request header is accepted but
  ignored (the old `urlhaus.abuse.ch/downloads/hostfile/` endpoint returns the
  same anonymous body with the header, without it, and with a bogus key —
  verified 2026-09-05). The header is still sent for forward compatibility.
  This feed is deliberately narrow: only hostnames currently serving a payload
  or added in the last 48 hours, pre-filtered against the Tranco Top 1M. That
  was **386 domains** on 2026-09-05, so it is a supplement, never the whole
  list. If the secret is missing or the fetch fails, the run logs a warning and
  carries on without it.
- **Public source:** the plain-text URL list,
  `https://urlhaus.abuse.ch/downloads/text/` — active malware URLs plus
  everything added in the last 90 days. No auth. This is the feed the verified
  4,911-domain seed was built from and it carries the bulk of the coverage. If
  *this* one fails, the run fails.
- **The two are unioned**, then put through the shared normalisation above.
- **Safety valve:** `tools/build_blocklist.py` fails the run, writing nothing, if
  any body looks like HTML rather than a list, or if the merged result yields
  fewer than **1,000** domains. A broken or empty fetch can never overwrite the
  good list. The workflow then re-checks the written file and asserts the
  `NEVER_BLOCK` apexes are absent.
- **Commit only on material change:** the generator compares domain bodies, not
  whole files, so the header's date does not churn a commit every day.

### Regenerating by hand

```sh
curl -sSL https://urlhaus.abuse.ch/downloads/text/ -o feed_public.txt
curl -sSL "https://urlhaus-api.abuse.ch/v2/files/exports/$ABUSECH_AUTH_KEY/hostfile.txt" \
  -o feed_auth.txt
python3 tools/build_blocklist.py \
  --input feed_public.txt --input feed_auth.txt --output blocklist.txt \
  --source-label 'abuse.ch URLhaus (plain-text URL feed + authenticated hostfile, malware only)'
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

#!/usr/bin/env python3
"""Regenerate blocklist.txt from an abuse.ch URLhaus feed.

The normalisation rules here are a verbatim port of the extractor that built the
verified 4,911-domain seed list (vela-android, Scan Phase 1.1). Two of them are
load-bearing and must not be "simplified":

  1. Entries are kept as FULL hostnames, never reduced to eTLD+1. The feeds are
     full of *.vercel.app / *.blogspot.com / *.amazonaws.com; collapsing those
     to the registrable domain would blocklist the whole provider.
  2. The NEVER_BLOCK guard drops shared-hosting / CDN / major apexes. On the
     2026-09-04 seed run it caught 1,233 entries -- malware hosted *on*
     google.com, github.com, dropbox.com, drive.google.com, sites.google.com.
     Without it the app blocklists Google and GitHub wholesale.

Bare IPs are dropped (this is a domain list). The single leading `#` header line
carries source/date/count and is skipped by the app's loader, which ignores any
line starting with `#`.
"""

import argparse
import datetime
import ipaddress
import re
import sys

# Shared-hosting / CDN / major apexes that must NEVER end up as a bare entry:
# a single malware page on one of these would otherwise blocklist the whole
# provider. We keep FULL hostnames (not eTLD+1) precisely to avoid this, but
# guard anyway in case a feed lists a bare apex.
NEVER_BLOCK = set("""
google.com googleapis.com gstatic.com youtube.com blogspot.com blogger.com
amazonaws.com s3.amazonaws.com cloudfront.net azurewebsites.net windows.net
vercel.app netlify.app pages.dev workers.dev firebaseapp.com web.app
github.io githubusercontent.com github.com gitlab.io glitch.me repl.co
weebly.com wixsite.com squarespace.com wordpress.com sharepoint.com
herokuapp.com onrender.com fly.dev surge.sh 000webhostapp.com
microsoft.com live.com office.com apple.com icloud.com dropbox.com
facebook.com fbcdn.net instagram.com twitter.com x.com t.me telegram.org
cloudflare.com discord.com discordapp.com paypal.com bit.ly tinyurl.com
r2.dev b-cdn.net jsdelivr.net unpkg.com sites.google.com drive.google.com
""".split())

VALID = re.compile(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$')

# Hosts-file lines look like "127.0.0.1\tevil.example". Only the URLhaus
# hostfile variant produces these; plain-text URL lines contain no whitespace,
# so this pre-step is inert on that feed.
HOSTS_PREFIX = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+')

# Markers that mean we were handed an error/landing page instead of a feed.
HTML_MARKERS = ('<html', '<!doctype', '<head', '<body', '<script')


def host_of(raw):
    s = raw.strip()
    if not s or s.startswith('#'):
        return None
    s = HOSTS_PREFIX.sub('', s, count=1).strip()
    s = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', '', s)   # scheme
    s = re.split(r'[/?#]', s, 1)[0]                       # path/query/fragment
    if '@' in s:                                          # userinfo
        s = s.rsplit('@', 1)[1]
    if s.startswith('['):                                 # bracketed IPv6
        return None
    s = s.split(':', 1)[0]                                # port
    s = s.strip().strip('.').lower()
    if not s:
        return None
    if s.startswith('www.'):
        s = s[4:]
    return s or None


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def read_feed(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read()


def looks_like_html(text):
    head = text[:4096].lower()
    return any(m in head for m in HTML_MARKERS)


def extract(text):
    domains = set()
    stats = {'lines': 0, 'comments': 0, 'ips': 0, 'invalid': 0, 'guarded': 0}
    guarded_hits = set()
    for line in text.splitlines():
        stats['lines'] += 1
        if not line.strip() or line.lstrip().startswith('#'):
            stats['comments'] += 1
            continue
        h = host_of(line)
        if h is None:
            stats['invalid'] += 1
            continue
        if is_ip(h):
            stats['ips'] += 1
            continue
        if not VALID.match(h) or len(h) > 253:
            stats['invalid'] += 1
            continue
        if h in NEVER_BLOCK:
            stats['guarded'] += 1
            guarded_hits.add(h)
            continue
        domains.add(h)
    return sorted(domains), stats, sorted(guarded_hits)


def existing_domains(path):
    """The domain body of an existing list, ignoring the header comment."""
    try:
        with open(path, encoding='utf-8') as f:
            return [l.strip() for l in f
                    if l.strip() and not l.lstrip().startswith('#')]
    except FileNotFoundError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True, help='raw feed file')
    ap.add_argument('--output', help='blocklist.txt to (re)write')
    ap.add_argument('--source-label', default='abuse.ch URLhaus')
    ap.add_argument('--min-domains', type=int, default=1000)
    ap.add_argument('--date', help='override header date (testing)')
    ap.add_argument('--check-only', action='store_true',
                    help='validate the feed and report the count; write nothing')
    args = ap.parse_args()

    text = read_feed(args.input)

    # --- Safety valve, part 1: an HTML/error body is never a feed. ----------
    if looks_like_html(text):
        print('FAIL: feed body looks like HTML, not a domain list', file=sys.stderr)
        print(text[:300], file=sys.stderr)
        return 2

    out, stats, guarded = extract(text)

    for k, v in stats.items():
        print('%-9s %d' % (k, v))
    print('domains   %d' % len(out))
    print('guarded_hits: %s' % (guarded or 'none'))

    # --- Safety valve, part 2: never overwrite a good list with a thin one. -
    if len(out) < args.min_domains:
        print('FAIL: only %d domains, below the %d minimum'
              % (len(out), args.min_domains), file=sys.stderr)
        return 2

    if args.check_only or not args.output:
        return 0

    # Compare domain bodies only -- the header carries a date, so comparing
    # whole files would report a change every single day.
    if existing_domains(args.output) == out:
        print('UNCHANGED: domain set is identical, leaving the file alone')
        return 0

    today = args.date or datetime.date.today().isoformat()
    with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
        f.write('# source %s | date %s | count %d\n'
                % (args.source_label, today, len(out)))
        for d in out:
            f.write(d + '\n')
    print('CHANGED: wrote %d domains to %s' % (len(out), args.output))
    return 0


if __name__ == '__main__':
    sys.exit(main())

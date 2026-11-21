"""Domain registration expiry lookups: RDAP where the TLD has it, raw whois (port 43) where it does not.

Only the standard library and `requests` (already a dependency) are used.

Data sources:
  - .ru / .su / .рф (xn--p1ai) second-level domains: whois.tcinet.ru (the TCI registry),
    fields `paid-till:`, `state:`, `free-date:`.
  - third-level domains in org.ru / net.ru / pp.ru: whois.nic.net.ru (MSK-IX), same format as TCI.
  - any other third-level .ru / .su domain (spb.ru, msk.ru, com.ru, ...): whois.flexireg.net,
    ICANN-style `Registry Expiry Date:`.
  - every other TLD: RDAP, the server is found through the IANA bootstrap file.
A per-domain `whois_server` overrides all of that.
"""
import json
import os
import re
import socket
import time
from datetime import datetime, timedelta, timezone

import requests

RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'
RDAP_BOOTSTRAP_CACHE_PATH = '/tmp/self-hosted-tg-alert-sites-monitoring-tool-rdap-dns.json'
RDAP_BOOTSTRAP_MAX_AGE = 24 * 3600  # IANA publishes it about once a day

TCI_WHOIS = 'whois.tcinet.ru'
MSKIX_WHOIS = 'whois.nic.net.ru'
FLEXIREG_WHOIS = 'whois.flexireg.net'
TCI_TLDS = {'ru', 'su', 'xn--p1ai'}
MSKIX_ZONES = {'org.ru', 'net.ru', 'pp.ru'}

WHOIS_MAX_BYTES = 1024 * 1024

LABEL_RE = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')
HOST_RE = re.compile(r'^[a-z0-9.-]+$')

NOT_FOUND_MARKERS = (
    'no entries found',
    'domain not found',
    'no match for',
    'not found',
    'no data found',
    'status: free',
)
# Checked in this order: the first key that is present wins.
EXPIRY_KEYS = (
    'paid-till',
    'registry expiry date',
    'registrar registration expiration date',
    'expiration date',
    'expiry date',
    'expires',
)
# Status words (RDAP status / EPP "Domain Status") that mean the domain is not working.
PROBLEM_STATUSES = ('hold', 'inactive', 'redemption', 'pending delete', 'pendingdelete')

_lookup_cache = {}


def to_ascii(domain) -> str:
    """Normalise a domain to lowercase punycode. Raises ValueError for anything that is not a domain."""
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError('must be a non-empty string')

    name = domain.strip().rstrip('.').lower()

    if '://' in name or '/' in name or ' ' in name:
        raise ValueError(f"'{domain}' is not a bare domain name")

    try:
        ascii_name = name.encode('idna').decode('ascii')
    except UnicodeError as e:
        raise ValueError(f"'{domain}' is not a valid domain name ({e})")

    labels = ascii_name.split('.')

    if len(labels) < 2 or len(ascii_name) > 253 or not all(LABEL_RE.match(label) for label in labels):
        raise ValueError(f"'{domain}' is not a valid domain name")

    if labels[-1].isdigit():
        raise ValueError(f"'{domain}' looks like an IP address, not a domain")

    return ascii_name


def to_unicode(ascii_name: str) -> str:
    try:
        return ascii_name.encode('ascii').decode('idna')
    except UnicodeError:
        return ascii_name


def pick_whois_server(ascii_name: str) -> str | None:
    """The whois server for zones without RDAP, or None when RDAP should be used."""
    labels = ascii_name.split('.')

    if labels[-1] not in TCI_TLDS:
        return None

    if len(labels) == 2:
        return TCI_WHOIS

    if '.'.join(labels[-2:]) in MSKIX_ZONES:
        return MSKIX_WHOIS

    return FLEXIREG_WHOIS


def describe_source(ascii_name: str, whois_server: str | None = None) -> str:
    """Where a domain's data will come from, without any network access (for --check-config)."""
    server = whois_server or pick_whois_server(ascii_name)

    return f"whois {server}" if server else 'RDAP (server from the IANA bootstrap)'


def parse_datetime(value: str) -> datetime | None:
    """Parse the date formats registries use: 2026-11-16T10:15:25Z, 2027-04-29, 2026.11.21T13:20:52Z, ...

    The result is always timezone-aware (UTC when the source gives no zone).
    """
    if not value:
        return None

    match = re.search(r'(\d{4})[-./](\d{2})[-./](\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?'
                      r'\s*(Z|[+-]\d{2}:?\d{2})?', value.strip())

    if not match:
        return None

    year, month, day, hour, minute, second, zone = match.groups()

    try:
        moment = datetime(int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0))
    except ValueError:
        return None

    if zone and zone != 'Z':
        digits = zone[1:].replace(':', '')
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))

        return moment.replace(tzinfo=timezone(offset if zone[0] == '+' else -offset)).astimezone(timezone.utc)

    return moment.replace(tzinfo=timezone.utc)


def _empty_result(ascii_name: str, source: str) -> dict:
    return {
        'domain': ascii_name,
        'source': source,
        'registered': None,
        'expires': None,
        'delegated': None,
        'state': None,
        'statuses': [],
        'free_date': None,
        'error': None,
    }


def parse_whois(text: str, ascii_name: str, source: str) -> dict:
    """Parse a whois answer: TCI/MSK-IX (`paid-till:`, `state:`) or ICANN-style (`Registry Expiry Date:`)."""
    result = _empty_result(ascii_name, source)
    fields = {}
    statuses = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith('%') or line.startswith('#') or ':' not in line:
            continue

        key, _, value = line.partition(':')
        key = key.strip().lower()
        value = value.strip()

        if key in ('domain status', 'status'):
            statuses.append(value)

        fields.setdefault(key, value)

    expiry_raw = next((fields[key] for key in EXPIRY_KEYS if fields.get(key)), None)

    if expiry_raw is None:
        lowered = text.lower()

        if any(marker in lowered for marker in NOT_FOUND_MARKERS):
            result['registered'] = False

            return result

        first_line = next((ln.strip() for ln in text.splitlines()
                           if ln.strip() and not ln.strip().startswith(('%', '#', '>>>'))), '')
        result['error'] = f"no expiry date in the whois answer: '{first_line[:150]}'" if first_line \
            else 'empty whois answer'

        return result

    result['registered'] = True
    result['expires'] = parse_datetime(expiry_raw)

    if result['expires'] is None:
        result['error'] = f"cannot parse the expiry date '{expiry_raw}'"

    state = fields.get('state')

    if state:
        upper = state.upper()
        result['state'] = state

        if 'NOT DELEGATED' in upper:
            result['delegated'] = False
        elif 'DELEGATED' in upper:
            result['delegated'] = True
        else:
            result['delegated'] = False

    result['statuses'] = statuses
    result['free_date'] = fields.get('free-date') or None

    return result


def parse_rdap(data, ascii_name: str, source: str) -> dict:
    """Parse an RDAP domain object: the expiry is the `expiration` event."""
    result = _empty_result(ascii_name, source)

    if not isinstance(data, dict):
        result['error'] = 'RDAP answer is not a JSON object'

        return result

    if data.get('errorCode') == 404:
        result['registered'] = False

        return result

    result['registered'] = True
    result['statuses'] = [str(s) for s in data.get('status', []) if s]

    for event in data.get('events', []) or []:
        if isinstance(event, dict) and str(event.get('eventAction', '')).lower() == 'expiration':
            result['expires'] = parse_datetime(str(event.get('eventDate', '')))

            break

    if result['expires'] is None:
        result['error'] = 'RDAP answer has no expiration event'

    return result


def whois_query(server: str, query: str, timeout: float) -> str:
    deadline = time.time() + timeout
    chunks = []
    size = 0

    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + '\r\n').encode('ascii'))

        while size < WHOIS_MAX_BYTES:
            remaining = deadline - time.time()

            if remaining <= 0:
                raise TimeoutError(f"whois {server} did not finish answering in {timeout}s")

            sock.settimeout(remaining)
            chunk = sock.recv(4096)

            if not chunk:
                break

            chunks.append(chunk)
            size += len(chunk)

    return b''.join(chunks).decode('utf-8', 'replace')


def load_rdap_bootstrap(timeout: float, cache_path: str = RDAP_BOOTSTRAP_CACHE_PATH) -> dict:
    """The IANA RDAP bootstrap file, refreshed at most once a day; a stale copy beats no copy."""
    cached = None

    if os.path.isfile(cache_path):
        # noinspection PyBroadException
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cached = json.load(f)

            if time.time() - os.path.getmtime(cache_path) < RDAP_BOOTSTRAP_MAX_AGE:
                return cached
        except Exception:
            cached = None

    try:
        response = requests.get(RDAP_BOOTSTRAP_URL, timeout=timeout)
        response.raise_for_status()
        data = response.json()

        if not isinstance(data.get('services'), list):
            raise ValueError('unexpected bootstrap format')
    except Exception:
        if cached is not None:
            return cached

        raise

    # noinspection PyBroadException
    try:
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    except Exception:
        pass

    return data


def find_rdap_base(bootstrap: dict, ascii_name: str) -> str | None:
    """Longest matching TLD entry wins, as RFC 9224 asks."""
    labels = ascii_name.split('.')
    best, best_len = None, 0

    for service in bootstrap.get('services', []):
        if not isinstance(service, list) or len(service) < 2 or not service[1]:
            continue

        for suffix in service[0]:
            suffix = str(suffix).lower()
            suffix_len = len(suffix.split('.'))

            if suffix_len > best_len and '.'.join(labels[-suffix_len:]) == suffix:
                urls = service[1]
                best = next((u for u in urls if u.startswith('https://')), urls[0])
                best_len = suffix_len

    return best


def lookup_rdap(ascii_name: str, timeout: float) -> dict:
    try:
        bootstrap = load_rdap_bootstrap(timeout)
    except Exception as e:
        return {**_empty_result(ascii_name, 'RDAP'), 'error': f"cannot load the IANA RDAP bootstrap: {e}"}

    base = find_rdap_base(bootstrap, ascii_name)

    if base is None:
        tld = ascii_name.rsplit('.', 1)[-1]

        return {**_empty_result(ascii_name, 'RDAP'),
                'error': f"no RDAP service for '.{tld}'; set whois_server for this domain"}

    url = base.rstrip('/') + '/domain/' + ascii_name
    source = f"RDAP {url}"

    try:
        response = requests.get(url, timeout=timeout, headers={'Accept': 'application/rdap+json'})
    except requests.exceptions.RequestException as e:
        return {**_empty_result(ascii_name, source), 'error': str(e)}

    if response.status_code == 404:
        return {**_empty_result(ascii_name, source), 'registered': False}

    if response.status_code != 200:
        return {**_empty_result(ascii_name, source), 'error': f"HTTP {response.status_code}"}

    try:
        data = response.json()
    except ValueError:
        return {**_empty_result(ascii_name, source), 'error': 'RDAP answer is not JSON'}

    return parse_rdap(data, ascii_name, source)


def lookup_whois(ascii_name: str, server: str, timeout: float) -> dict:
    source = f"whois {server}"

    try:
        text = whois_query(server, ascii_name, timeout)
    except (OSError, UnicodeError) as e:
        return {**_empty_result(ascii_name, source), 'error': str(e) or e.__class__.__name__}

    return parse_whois(text, ascii_name, source)


def get_domain_expiry(ascii_name: str, timeout: float = 10.0, whois_server: str | None = None) -> dict:
    """One lookup per domain per run, however many checks mention it."""
    server = whois_server or pick_whois_server(ascii_name)
    cache_key = (ascii_name, server)

    if cache_key not in _lookup_cache:
        _lookup_cache[cache_key] = lookup_whois(ascii_name, server, timeout) if server \
            else lookup_rdap(ascii_name, timeout)

    return _lookup_cache[cache_key]


def days_left(expires: datetime, now: datetime) -> int:
    return int((expires - now).total_seconds() // 86400)


def evaluate(info: dict, warn_days: int, now: datetime | None = None) -> str | None:
    """Turn a lookup result into an alert message, or None when all is well."""
    now = now or datetime.now(tz=timezone.utc)
    shown = to_unicode(info['domain'])

    if shown != info['domain']:
        shown = f"{shown} ({info['domain']})"

    if info['registered'] is False:
        return f"Domain {shown} is not registered (according to {info['source']})"

    if info['error'] or info['expires'] is None:
        return f"Domain lookup failed ({info['source']}): {info['error'] or 'no expiry date'}"

    expires = info['expires']
    left = days_left(expires, now)
    free = f"; it becomes free for anyone to register on {info['free_date']}" if info.get('free_date') else ''
    state = f"; registry state: {info['state']}" if info.get('state') else ''

    if expires <= now:
        ago = int((now - expires).total_seconds() // 86400)

        return f"Domain {shown} EXPIRED on {expires:%Y-%m-%d} ({ago} days ago){state}{free}"

    if info['delegated'] is False:
        return f"Domain {shown} is not delegated (registry state: {info['state']})"

    problems = [s for s in info.get('statuses', []) if any(p in s.lower() for p in PROBLEM_STATUSES)]

    if problems:
        return f"Domain {shown} has registry status {', '.join(problems)}"

    if left < warn_days:
        return f"Domain {shown} expires in {left} days, on {expires:%Y-%m-%d} (warn_days: {warn_days}){free}"

    return None

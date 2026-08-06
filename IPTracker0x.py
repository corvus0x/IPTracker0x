#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPTracker0x - Bulk IP enrichment and triage for security investigations.
by corvus0x

Runs on a stock Python 3.8+ interpreter. No pip install required.
"""

import base64
import csv
import ipaddress
import json
import os
import re
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Input file containing the IPs (one per line)
input_file = "ips.txt"

# API token for ipinfo.io (Replace with your own token)      ------- important! -------
api_token = "YOUR_API_KEY"

# Number of IPs fetched in parallel
max_workers = 10

# Output files
csv_output = "results_IPTracker0x.csv"
html_output = "report_IPTracker0x.html"

# Where downloaded threat-intel feeds are cached, and for how long (seconds).
# Spamhaus asks for no more than one download per day, so keep this at 24h.
cache_dir = ".iptracker_cache"
cache_ttl = 24 * 3600

# Optional: enrich with ip-api.com proxy/VPN, hosting and mobile flags.
# Disabled by default on purpose: the free tier of ip-api.com is HTTP only,
# so turning this on sends the IPs you are investigating over the network in
# clear text. Enable it only if that trade-off is acceptable to you.
ENABLE_IPAPI_FLAGS = False

# Corporate proxies re-sign HTTPS traffic with their own CA, which Python does
# not trust, so certificate verification is disabled here to let the tool run on
# those networks.
VERIFY_TLS = False

REQUEST_TIMEOUT = 10
USER_AGENT = "IPTracker0x/2.0 (+https://github.com/corvus0x)"

# ---------------------------------------------------------------------------
# Threat intelligence feeds (all HTTPS, none require an API key)
# ---------------------------------------------------------------------------

FEEDS = {
    # ASNs belonging to cloud, managed hosting and colo facilities.
    # NOTE: this is *not* a list of malicious networks. It tells you the IP is
    # infrastructure rather than a residential/mobile subscriber, which is
    # context, not a verdict.
    "hosting_asn": {
        "url": "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv",
        "file": "hosting-asn-list.csv",
        "label": "bad-asn-list (cloud/hosting/colo ASNs)",
    },
    # IPs aggregated from 30+ public blocklists, with a hit counter.
    "ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "file": "ipsum.txt",
        "label": "IPsum (30+ aggregated blocklists)",
    },
    # Current Tor exit nodes.
    "tor": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "file": "tor-exit-nodes.txt",
        "label": "Tor Project bulk exit list",
    },
    # Netblocks hijacked or leased by criminal operations.
    "spamhaus": {
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "file": "spamhaus-drop-v4.json",
        "label": "Spamhaus DROP (do not route or peer)",
    },
}

# Scoring weights. Every point added to an IP is traceable back to one of these.
WEIGHT_SPAMHAUS = 50
WEIGHT_IPSUM_HIGH = 40      # listed on 5+ blocklists
WEIGHT_IPSUM_MEDIUM = 30    # listed on 3-4 blocklists
WEIGHT_IPSUM_LOW = 15       # listed on 1-2 blocklists
WEIGHT_TOR = 25
WEIGHT_HOSTING_ASN = 10
WEIGHT_PROXY = 20           # ip-api.com only, when explicitly enabled

BANDS = ("Clean", "Low", "Medium", "High", "Critical")

# Ranges are derived from risk_band() below; keep the two in step.
BAND_RANGES = [
    ("Clean", "0", "Nothing matched. The address is only geolocation data."),
    ("Low", "1-24", "Context worth knowing, but not an accusation on its own."),
    ("Medium", "25-49", "At least one real reputation hit. Worth a look."),
    ("High", "50-74", "Listed by a source with a low false-positive rate."),
    ("Critical", "75+", "Several independent sources agree."),
]

# What each signal means, in plain language, next to what it costs. The report
# renders this table, so the explanation can never drift from the weights.
SIGNAL_CATALOG = [
    {
        "label": "Spamhaus DROP",
        "points": "+%d" % WEIGHT_SPAMHAUS,
        "source": "Spamhaus",
        "means": "The address falls inside a netblock Spamhaus publishes as hijacked "
                 "or leased outright by a criminal operation. Whole ranges, not single IPs.",
    },
    {
        "label": "IPsum",
        "points": "+%d / +%d / +%d" % (WEIGHT_IPSUM_LOW, WEIGHT_IPSUM_MEDIUM, WEIGHT_IPSUM_HIGH),
        "source": "IPsum",
        "means": "The address appears on public blocklists that IPsum aggregates from 30+ "
                 "sources. Weighted by how many lists agree: 1-2, 3-4, or 5 and above.",
    },
    {
        "label": "Tor exit node",
        "points": "+%d" % WEIGHT_TOR,
        "source": "Tor Project",
        "means": "The address is a current Tor exit relay, so the traffic left the Tor "
                 "network here. It says nothing about who sent it.",
    },
    {
        "label": "Hosting/Cloud ASN",
        "points": "+%d" % WEIGHT_HOSTING_ASN,
        "source": "bad-asn-list",
        "means": "The network is a datacenter, cloud or colo provider rather than a home "
                 "or mobile ISP. Context, not a verdict - AWS and Cloudflare are on this list.",
    },
    {
        "label": "Proxy/VPN/Tor",
        "points": "+%d" % WEIGHT_PROXY,
        "source": "ip-api.com",
        "means": "Flagged as an anonymising service. Only present when ENABLE_IPAPI_FLAGS "
                 "is turned on in the script.",
    },
    {
        "label": "Anycast",
        "points": "0",
        "source": "ipinfo.io",
        "means": "The address is announced from many places at once, so its location is "
                 "the nearest node, not a single place. Informational only.",
    },
    {
        "label": "Mobile carrier",
        "points": "0",
        "source": "ip-api.com",
        "means": "A cellular network address. Informational only.",
    },
    {
        "label": "Non-routable",
        "points": "0",
        "source": "local",
        "means": "A private, reserved or special-use address. Never sent to the API, and "
                 "it has no public location.",
    },
]

# ---------------------------------------------------------------------------
# ISO 3166-1 alpha-2 country names (replaces the pycountry dependency)
# ---------------------------------------------------------------------------

COUNTRIES = {
    'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AF': 'Afghanistan',
    'AG': 'Antigua and Barbuda', 'AI': 'Anguilla', 'AL': 'Albania', 'AM': 'Armenia',
    'AO': 'Angola', 'AQ': 'Antarctica', 'AR': 'Argentina', 'AS': 'American Samoa',
    'AT': 'Austria', 'AU': 'Australia', 'AW': 'Aruba', 'AX': 'Åland Islands', 'AZ': 'Azerbaijan',
    'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados', 'BD': 'Bangladesh', 'BE': 'Belgium',
    'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BH': 'Bahrain', 'BI': 'Burundi', 'BJ': 'Benin',
    'BL': 'Saint Barthélemy', 'BM': 'Bermuda', 'BN': 'Brunei Darussalam', 'BO': 'Bolivia',
    'BQ': 'Bonaire, Sint Eustatius and Saba', 'BR': 'Brazil', 'BS': 'Bahamas', 'BT': 'Bhutan',
    'BV': 'Bouvet Island', 'BW': 'Botswana', 'BY': 'Belarus', 'BZ': 'Belize', 'CA': 'Canada',
    'CC': 'Cocos (Keeling) Islands', 'CD': 'Congo, The Democratic Republic of the',
    'CF': 'Central African Republic', 'CG': 'Congo', 'CH': 'Switzerland', 'CI': 'Côte d\'Ivoire',
    'CK': 'Cook Islands', 'CL': 'Chile', 'CM': 'Cameroon', 'CN': 'China', 'CO': 'Colombia',
    'CR': 'Costa Rica', 'CU': 'Cuba', 'CV': 'Cabo Verde', 'CW': 'Curaçao',
    'CX': 'Christmas Island', 'CY': 'Cyprus', 'CZ': 'Czechia', 'DE': 'Germany', 'DJ': 'Djibouti',
    'DK': 'Denmark', 'DM': 'Dominica', 'DO': 'Dominican Republic', 'DZ': 'Algeria',
    'EC': 'Ecuador', 'EE': 'Estonia', 'EG': 'Egypt', 'EH': 'Western Sahara', 'ER': 'Eritrea',
    'ES': 'Spain', 'ET': 'Ethiopia', 'FI': 'Finland', 'FJ': 'Fiji',
    'FK': 'Falkland Islands (Malvinas)', 'FM': 'Micronesia, Federated States of',
    'FO': 'Faroe Islands', 'FR': 'France', 'GA': 'Gabon', 'GB': 'United Kingdom', 'GD': 'Grenada',
    'GE': 'Georgia', 'GF': 'French Guiana', 'GG': 'Guernsey', 'GH': 'Ghana', 'GI': 'Gibraltar',
    'GL': 'Greenland', 'GM': 'Gambia', 'GN': 'Guinea', 'GP': 'Guadeloupe',
    'GQ': 'Equatorial Guinea', 'GR': 'Greece',
    'GS': 'South Georgia and the South Sandwich Islands', 'GT': 'Guatemala', 'GU': 'Guam',
    'GW': 'Guinea-Bissau', 'GY': 'Guyana', 'HK': 'Hong Kong',
    'HM': 'Heard Island and McDonald Islands', 'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti',
    'HU': 'Hungary', 'ID': 'Indonesia', 'IE': 'Ireland', 'IL': 'Israel', 'IM': 'Isle of Man',
    'IN': 'India', 'IO': 'British Indian Ocean Territory', 'IQ': 'Iraq', 'IR': 'Iran',
    'IS': 'Iceland', 'IT': 'Italy', 'JE': 'Jersey', 'JM': 'Jamaica', 'JO': 'Jordan',
    'JP': 'Japan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia', 'KI': 'Kiribati',
    'KM': 'Comoros', 'KN': 'Saint Kitts and Nevis', 'KP': 'North Korea', 'KR': 'South Korea',
    'KW': 'Kuwait', 'KY': 'Cayman Islands', 'KZ': 'Kazakhstan', 'LA': 'Laos', 'LB': 'Lebanon',
    'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LR': 'Liberia',
    'LS': 'Lesotho', 'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'LY': 'Libya',
    'MA': 'Morocco', 'MC': 'Monaco', 'MD': 'Moldova', 'ME': 'Montenegro',
    'MF': 'Saint Martin (French part)', 'MG': 'Madagascar', 'MH': 'Marshall Islands',
    'MK': 'North Macedonia', 'ML': 'Mali', 'MM': 'Myanmar', 'MN': 'Mongolia', 'MO': 'Macao',
    'MP': 'Northern Mariana Islands', 'MQ': 'Martinique', 'MR': 'Mauritania', 'MS': 'Montserrat',
    'MT': 'Malta', 'MU': 'Mauritius', 'MV': 'Maldives', 'MW': 'Malawi', 'MX': 'Mexico',
    'MY': 'Malaysia', 'MZ': 'Mozambique', 'NA': 'Namibia', 'NC': 'New Caledonia', 'NE': 'Niger',
    'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NI': 'Nicaragua', 'NL': 'Netherlands',
    'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru', 'NU': 'Niue', 'NZ': 'New Zealand', 'OM': 'Oman',
    'PA': 'Panama', 'PE': 'Peru', 'PF': 'French Polynesia', 'PG': 'Papua New Guinea',
    'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland', 'PM': 'Saint Pierre and Miquelon',
    'PN': 'Pitcairn', 'PR': 'Puerto Rico', 'PS': 'Palestine, State of', 'PT': 'Portugal',
    'PW': 'Palau', 'PY': 'Paraguay', 'QA': 'Qatar', 'RE': 'Réunion', 'RO': 'Romania',
    'RS': 'Serbia', 'RU': 'Russian Federation', 'RW': 'Rwanda', 'SA': 'Saudi Arabia',
    'SB': 'Solomon Islands', 'SC': 'Seychelles', 'SD': 'Sudan', 'SE': 'Sweden', 'SG': 'Singapore',
    'SH': 'Saint Helena, Ascension and Tristan da Cunha', 'SI': 'Slovenia',
    'SJ': 'Svalbard and Jan Mayen', 'SK': 'Slovakia', 'SL': 'Sierra Leone', 'SM': 'San Marino',
    'SN': 'Senegal', 'SO': 'Somalia', 'SR': 'Suriname', 'SS': 'South Sudan',
    'ST': 'Sao Tome and Principe', 'SV': 'El Salvador', 'SX': 'Sint Maarten (Dutch part)',
    'SY': 'Syria', 'SZ': 'Eswatini', 'TC': 'Turks and Caicos Islands', 'TD': 'Chad',
    'TF': 'French Southern Territories', 'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan',
    'TK': 'Tokelau', 'TL': 'Timor-Leste', 'TM': 'Turkmenistan', 'TN': 'Tunisia', 'TO': 'Tonga',
    'TR': 'Türkiye', 'TT': 'Trinidad and Tobago', 'TV': 'Tuvalu', 'TW': 'Taiwan',
    'TZ': 'Tanzania', 'UA': 'Ukraine', 'UG': 'Uganda',
    'UM': 'United States Minor Outlying Islands', 'US': 'United States', 'UY': 'Uruguay',
    'UZ': 'Uzbekistan', 'VA': 'Holy See (Vatican City State)',
    'VC': 'Saint Vincent and the Grenadines', 'VE': 'Venezuela', 'VG': 'Virgin Islands, British',
    'VI': 'Virgin Islands, U.S.', 'VN': 'Vietnam', 'VU': 'Vanuatu', 'WF': 'Wallis and Futuna',
    'WS': 'Samoa', 'YE': 'Yemen', 'YT': 'Mayotte', 'ZA': 'South Africa', 'ZM': 'Zambia',
    'ZW': 'Zimbabwe',
}

# User-assigned code that geolocation providers return but ISO does not define.
COUNTRIES["XK"] = "Kosovo"


def country_name(code):
    """Country name for an alpha-2 code, falling back to the code itself.

    pycountry raised AttributeError here for any code it did not know, which
    killed the whole run through future.result().
    """
    if not code:
        return ""
    return COUNTRIES.get(code.upper(), code.upper())


def flag_emoji(code):
    """Regional indicator pair for an alpha-2 code, e.g. 'AR' -> the flag."""
    if not code or len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())






# ---------------------------------------------------------------------------
# World map raster
# ---------------------------------------------------------------------------

# Country outlines are fetched at run time rather than shipped inside this
# file: the tool already needs the network for ipinfo and the reputation
# feeds, and downloading them keeps the script small. Natural Earth is public
# domain.
GEOMETRY = {
    "url": "https://raw.githubusercontent.com/nvkelso/natural-earth-vector"
           "/master/geojson/ne_50m_admin_0_countries.geojson",
    "file": "ne_50m_countries.geojson",
    "label": "Natural Earth 1:50m boundaries",
}

# Equirectangular, cropped to the inhabited band.
MAP_LAT_TOP, MAP_LAT_BOTTOM = 84.0, -56.0
MAP_WIDTH = 1800
MAP_HEIGHT = int(round(MAP_WIDTH * (MAP_LAT_TOP - MAP_LAT_BOTTOM) / 360.0))

# Index 0 ocean, 1 land with no data, 2-6 the sequential ramp, 7 border.
MAP_PALETTE = [
    (0x3D, 0x3D, 0x3D), (0x0E, 0x0E, 0x0E),
    (0x18, 0x4F, 0x95), (0x25, 0x6A, 0xBF), (0x39, 0x87, 0xE5),
    (0x6D, 0xA7, 0xEC), (0x9E, 0xC5, 0xF4),
    (0x2B, 0x2B, 0x2B),
]


def map_project(lon, lat):
    lat = max(min(lat, MAP_LAT_TOP), MAP_LAT_BOTTOM)
    return ((lon + 180.0) * (MAP_WIDTH / 360.0),
            (MAP_LAT_TOP - lat) * (MAP_WIDTH / 360.0))


def _rings_of(geom):
    kind = geom.get("type")
    if kind == "Polygon":
        return geom.get("coordinates", [])
    if kind == "MultiPolygon":
        return [r for poly in geom.get("coordinates", []) for r in poly]
    return []


def load_shapes(text):
    """(iso2, edges, bbox) per territory, already in pixel space."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    shapes = []
    for feat in data.get("features", []):
        props = feat.get("properties", {})
        code = props.get("ISO_A2_EH") or props.get("ISO_A2") or ""
        if code in ("-99", "", None):
            code = props.get("ISO_A2") or ""
        if code in ("-99", "", None):
            continue
        edges = []
        minx = miny = 1e9
        maxx = maxy = -1e9
        for ring in _rings_of(feat.get("geometry", {})):
            pts = [map_project(lon, lat) for lon, lat in ring]
            if len(pts) < 3:
                continue
            for i in range(len(pts)):
                ax, ay = pts[i]
                bx, by = pts[(i + 1) % len(pts)]
                if ay != by:
                    edges.append((ax, ay, bx, by))
                minx = min(minx, ax); maxx = max(maxx, ax)
                miny = min(miny, ay); maxy = max(maxy, ay)
        if edges:
            shapes.append((code, edges, (minx, miny, maxx, maxy)))
    return shapes


def _fill_shape(buf, edges, bbox, index):
    """Even-odd scanline fill, sampling at pixel centres."""
    y0 = max(0, int(bbox[1]))
    y1 = min(MAP_HEIGHT - 1, int(bbox[3]) + 1)
    run = bytes([index])
    for y in range(y0, y1 + 1):
        yc = y + 0.5
        xs = []
        for (ax, ay, bx, by) in edges:
            if (ay <= yc < by) or (by <= yc < ay):
                xs.append(ax + (yc - ay) * (bx - ax) / (by - ay))
        if not xs:
            continue
        xs.sort()
        row = y * MAP_WIDTH
        for i in range(0, len(xs) - 1, 2):
            sx = max(0, int(xs[i] + 0.5))
            ex = min(MAP_WIDTH, int(xs[i + 1] + 0.5))
            if ex > sx:
                buf[row + sx:row + ex] = run * (ex - sx)


def _stroke_shape(buf, edges, index):
    """Hairline outline, so two shaded neighbours never merge into one blob."""
    for (ax, ay, bx, by) in edges:
        steps = int(max(abs(bx - ax), abs(by - ay))) + 1
        dx = (bx - ax) / steps
        dy = (by - ay) / steps
        x, y = ax, ay
        for _ in range(steps + 1):
            xi = int(x)
            yi = int(y)
            if 0 <= xi < MAP_WIDTH and 0 <= yi < MAP_HEIGHT:
                buf[yi * MAP_WIDTH + xi] = index
            x += dx
            y += dy


def encode_png(buf, palette, width, height):
    """Indexed-colour PNG. Flat map fills compress to a few tens of KB."""
    def chunk(tag, payload):
        body = tag + payload
        return (struct.pack(">I", len(payload)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    raw = bytearray()
    for y in range(height):
        raw.append(0)  # no per-row filter
        raw += buf[y * width:(y + 1) * width]

    signature = bytes([137, 80, 78, 71, 13, 10, 26, 10])
    return (signature
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 3, 0, 0, 0))
            + chunk(b"PLTE", b"".join(bytes(c) for c in palette))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def render_map_png(records, shapes):
    """Choropleth as a data URI, ready to drop into an <img> tag."""
    if not shapes:
        return "", {}

    counts = Counter(r["country_code"] for r in records if r["country_code"])
    peak = max(counts.values()) if counts else 0
    edges = bucket_edges(peak)

    buf = bytearray([0]) * (MAP_WIDTH * MAP_HEIGHT)
    for code, shape_edges, bbox in shapes:
        n = counts.get(code, 0)
        _fill_shape(buf, shape_edges, bbox, 1 + bucket_of(n, edges) if n else 1)
    for code, shape_edges, bbox in shapes:
        _stroke_shape(buf, shape_edges, 7)

    png = encode_png(buf, MAP_PALETTE, MAP_WIDTH, MAP_HEIGHT)
    uri = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
    return uri, {"bytes": len(png), "edges": edges, "peak": peak}


def bucket_edges(peak):
    """Five steps; below six addresses each step is a single count."""
    if peak <= 5:
        return list(range(1, peak + 1))
    seen, out = set(), []
    for k in range(1, 6):
        v = max(1, int(round(peak * k / 5.0)))
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def bucket_of(count, edges):
    for i, edge in enumerate(edges):
        if count <= edge:
            return i + 1
    return len(edges)


# ---------------------------------------------------------------------------
# Terminal output (replaces the colorama dependency)
# ---------------------------------------------------------------------------


def _prepare_stdout():
    """Make stdout tolerate non-ASCII, and report whether it renders it.

    Redirecting output to a pipe or file on Windows hands us a cp1252 stream,
    which cannot encode the banner or the bar glyphs. Without this the tool
    dies on a UnicodeEncodeError before doing any work.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "█░—".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


UNICODE_OK = _prepare_stdout()


def _enable_ansi():
    """Turn on ANSI escape handling, and report whether colour is usable."""
    if not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class _Palette:
    """ANSI codes, or empty strings when the terminal cannot render them."""

    NAMES = {
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
        "RED": "\033[31m",
        "GREEN": "\033[32m",
        "YELLOW": "\033[33m",
        "BLUE": "\033[34m",
        "MAGENTA": "\033[35m",
        "CYAN": "\033[36m",
        "GREY": "\033[90m",
    }

    def __init__(self, enabled):
        for name, code in self.NAMES.items():
            setattr(self, name, code if enabled else "")


C = _Palette(_enable_ansi())


class ProgressBar:
    """Minimal thread-safe progress bar (replaces the tqdm dependency)."""

    def __init__(self, total, desc="Working", width=32):
        self.total = max(total, 1)
        self.desc = desc
        self.width = width
        self.count = 0
        self.start = time.time()
        self._lock = threading.Lock()
        self._active = sys.stdout.isatty()
        self.render()

    def update(self, step=1):
        with self._lock:
            self.count += step
            self.render()

    def render(self):
        if not self._active:
            return
        done = self.count / self.total
        filled = int(self.width * done)
        full, empty = ("█", "░") if UNICODE_OK else ("#", "-")
        bar = full * filled + empty * (self.width - filled)
        elapsed = time.time() - self.start
        rate = self.count / elapsed if elapsed > 0 else 0
        remaining = (self.total - self.count) / rate if rate > 0 else 0
        sys.stdout.write(
            "\r%s%s%s |%s%s%s| %d/%d  %.1f/s  eta %s   "
            % (
                C.CYAN,
                self.desc,
                C.RESET,
                C.GREEN,
                bar,
                C.RESET,
                self.count,
                self.total,
                rate,
                _fmt_seconds(remaining),
            )
        )
        sys.stdout.flush()

    def close(self):
        if self._active:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _fmt_seconds(seconds):
    seconds = int(max(seconds, 0))
    if seconds < 60:
        return "%ds" % seconds
    return "%dm%02ds" % (seconds // 60, seconds % 60)


def info(message):
    print("%s[*]%s %s" % (C.BLUE, C.RESET, message))


def ok(message):
    print("%s[+]%s %s" % (C.GREEN, C.RESET, message))


def warn(message):
    print("%s[!]%s %s" % (C.YELLOW, C.RESET, message))


def fail(message):
    print("%s[-]%s %s" % (C.RED, C.RESET, message))


def print_logo():
    logo = r"""
██╗██████╗ ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗  ██████╗ ██╗  ██╗
██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔═████╗╚██╗██╔╝
██║██████╔╝   ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝██║██╔██║ ╚███╔╝
██║██╔═══╝    ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗████╔╝██║ ██╔██╗
██║██║        ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║╚██████╔╝██╔╝ ██╗
╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
"""
    ascii_logo = r"""
 ___ ___ _____             _           ___
|_ _| _ \_   _| _ __ _ __ | |_____ _ _/ _ \__ __
 | ||  _/ | || '_/ _` / _|| / / -_) '_| | | \ \ /
|___|_|   |_||_| \__,_\__||_\_\___|_|  \___//_\_\
"""
    print(C.CYAN + (logo if UNICODE_OK else ascii_logo) + C.RESET)
    print("    %sby corvus0x%s\n" % (C.GREY, C.RESET))


# ---------------------------------------------------------------------------
# HTTP (replaces the requests dependency)
# ---------------------------------------------------------------------------


class FetchError(Exception):
    """A request failed after exhausting retries."""


def _build_ssl_context():
    context = ssl.create_default_context()
    if not VERIFY_TLS:
        # check_hostname must be cleared first; CERT_NONE is refused while it is on.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


SSL_CONTEXT = _build_ssl_context()


def http_get(url, timeout=REQUEST_TIMEOUT, retries=3, data=None, content_type=None):
    """GET (or POST when data is given) a URL and return the response bytes.

    Retries on network errors, 429 and 5xx with exponential backoff. Honours
    Retry-After when the server sends it. Other 4xx responses fail straight
    away, since retrying them never helps.
    """
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    if content_type:
        headers["Content-Type"] = content_type

    last_error = None
    for attempt in range(retries):
        request = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout,
                                        context=SSL_CONTEXT) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            last_error = "HTTP %s" % exc.code
            if exc.code == 429:
                wait = _retry_after(exc.headers) or (2 ** attempt)
            elif 500 <= exc.code < 600:
                wait = 2 ** attempt
            else:
                raise FetchError(last_error)
        except urllib.error.URLError as exc:
            last_error = str(exc.reason)
            wait = 2 ** attempt
        except (OSError, ValueError) as exc:
            last_error = str(exc)
            wait = 2 ** attempt

        if attempt < retries - 1:
            time.sleep(wait)

    raise FetchError(last_error or "unknown error")


def _retry_after(headers):
    try:
        return max(0, min(int(headers.get("Retry-After", "")), 60))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Feed cache
# ---------------------------------------------------------------------------


def cached_feed(key):
    """Return (text, age_label) for a feed, downloading it only when stale.

    Falls back to an expired cache copy if the download fails, so a report can
    still be produced without connectivity.
    """
    feed = FEEDS[key]
    path = os.path.join(cache_dir, feed["file"])
    fresh = os.path.exists(path) and (time.time() - os.path.getmtime(path)) < cache_ttl

    if fresh:
        return _read_cache(path), _cache_age(path)

    try:
        body = http_get(feed["url"], timeout=30)
        os.makedirs(cache_dir, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(body)
        return body.decode("utf-8", "replace"), "downloaded now"
    except (FetchError, OSError) as exc:
        if os.path.exists(path):
            warn("%s unavailable (%s); using cached copy" % (feed["label"], exc))
            return _read_cache(path), _cache_age(path) + " (stale)"
        warn("%s unavailable (%s); this signal will be missing" % (feed["label"], exc))
        return None, "unavailable"


def cached_geometry():
    """Country boundaries, downloaded once a day and cached like the feeds."""
    path = os.path.join(cache_dir, GEOMETRY["file"])
    fresh = os.path.exists(path) and (time.time() - os.path.getmtime(path)) < cache_ttl
    if fresh:
        return _read_cache(path)
    try:
        body = http_get(GEOMETRY["url"], timeout=90)
        os.makedirs(cache_dir, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(body)
        return body.decode("utf-8", "replace")
    except (FetchError, OSError) as exc:
        if os.path.exists(path):
            warn("%s unavailable (%s); using cached copy" % (GEOMETRY["label"], exc))
            return _read_cache(path)
        warn("%s unavailable (%s); the report will have no map" % (GEOMETRY["label"], exc))
        return None


def _read_cache(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", "replace")


def _cache_age(path):
    hours = (time.time() - os.path.getmtime(path)) / 3600
    if hours < 1:
        return "cached %dm ago" % int(hours * 60)
    return "cached %dh ago" % int(hours)


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------


class ThreatIntel:
    """Loads the feeds once, then answers per-IP lookups from memory."""

    def __init__(self):
        self.hosting_asns = set()
        self.ipsum = {}
        self.tor_exits = set()
        self.drop_nets = defaultdict(list)  # first octet -> [IPv4Network]
        self.provenance = {}

    def load(self):
        loaders = (
            ("hosting_asn", self._load_hosting_asns),
            ("ipsum", self._load_ipsum),
            ("tor", self._load_tor),
            ("spamhaus", self._load_spamhaus),
        )
        for key, loader in loaders:
            text, age = cached_feed(key)
            count = loader(text) if text else 0
            self.provenance[key] = {
                "label": FEEDS[key]["label"],
                "url": FEEDS[key]["url"],
                "age": age,
                "entries": count,
                "available": text is not None,
            }
        return self

    def _load_hosting_asns(self, text):
        reader = csv.reader(text.splitlines())
        for row in reader:
            if not row:
                continue
            value = row[0].strip().upper().lstrip("AS")
            if value.isdigit():  # skips the header row without StopIteration
                self.hosting_asns.add(value)
        return len(self.hosting_asns)

    def _load_ipsum(self, text):
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                self.ipsum[parts[0]] = int(parts[1])
        return len(self.ipsum)

    def _load_tor(self, text):
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                self.tor_exits.add(line)
        return len(self.tor_exits)

    def _load_spamhaus(self, text):
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            cidr = entry.get("cidr")
            if not cidr:
                continue  # metadata records carry no cidr
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            # Bucket by first octet so lookups stay cheap on large inputs.
            self.drop_nets[int(network.network_address) >> 24].append(
                (network, entry.get("sblid", ""))
            )
            count += 1
        return count

    def signals_for(self, ip_text, asn):
        """Every reputation signal that applies to this IP, with its evidence."""
        signals = []
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            address = None

        if address is not None and address.version == 4:
            bucket = self.drop_nets.get(int(address) >> 24, ())
            for network, sblid in bucket:
                if address in network:
                    signals.append(
                        _signal(
                            "Spamhaus DROP",
                            WEIGHT_SPAMHAUS,
                            "spamhaus",
                            "Inside %s%s" % (network, ", " + sblid if sblid else ""),
                        )
                    )
                    break

        hits = self.ipsum.get(ip_text)
        if hits:
            if hits >= 5:
                weight = WEIGHT_IPSUM_HIGH
            elif hits >= 3:
                weight = WEIGHT_IPSUM_MEDIUM
            else:
                weight = WEIGHT_IPSUM_LOW
            signals.append(
                _signal(
                    "IPsum",
                    weight,
                    "ipsum",
                    "Listed on %d public blocklist%s" % (hits, "" if hits == 1 else "s"),
                )
            )

        if ip_text in self.tor_exits:
            signals.append(
                _signal("Tor exit node", WEIGHT_TOR, "tor", "Current Tor exit relay")
            )

        if asn and asn in self.hosting_asns:
            signals.append(
                _signal(
                    "Hosting/Cloud ASN",
                    WEIGHT_HOSTING_ASN,
                    "hosting_asn",
                    "AS%s is a cloud, managed hosting or colo network" % asn,
                )
            )

        return signals


def _signal(label, weight, source, detail):
    return {"label": label, "weight": weight, "source": source, "detail": detail}


def risk_band(score):
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    if score >= 1:
        return "Low"
    return "Clean"


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------


def read_ips(file_path):
    """Parse the input file into (queryable, local, invalid).

    Deduplicates, normalises, and separates addresses that cannot be looked up
    so they neither burn API quota nor silently vanish from the report.
    """
    try:
        with open(file_path, "r", encoding="utf-8-sig") as handle:
            raw_lines = [line.strip() for line in handle]
    except OSError as exc:
        fail("Cannot read %s: %s" % (file_path, exc))
        sys.exit(1)

    queryable, local, invalid = [], [], []
    seen = set()

    for line in raw_lines:
        if not line or line.startswith("#"):
            continue
        # Tolerate log-style lines: take the first whitespace/comma field.
        candidate = re.split(r"[\s,;]+", line)[0].strip().strip('"\'')
        if not candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            if line not in [item["ip"] for item in invalid]:
                invalid.append({"ip": line, "reason": "Not a valid IP address"})
            continue

        normalised = str(address)
        if normalised in seen:
            continue
        seen.add(normalised)

        reason = _non_routable_reason(address)
        if reason:
            local.append({"ip": normalised, "reason": reason})
        else:
            queryable.append(normalised)

    return queryable, local, invalid


RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


def _non_routable_reason(address):
    if address.is_loopback:
        return "Loopback address"
    if address.is_link_local:
        return "Link-local address"
    if address.is_multicast:
        return "Multicast address"
    if address.is_unspecified:
        return "Unspecified address"
    if address.is_reserved:
        return "Reserved address"
    if address.is_private:
        # is_private also covers documentation, benchmarking and carrier-grade
        # NAT ranges, so only claim RFC 1918 when it really is one.
        for network in RFC1918:
            if address.version == network.version and address in network:
                return "Private (RFC 1918) address"
        return "Special-use address"
    return None


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

ASN_PATTERN = re.compile(r"^AS(\d+)\s*(.*)$")


def blank_record(ip, status, note=""):
    return {
        "ip": ip,
        "status": status,
        "note": note,
        "hostname": "",
        "city": "",
        "region": "",
        "country": "",
        "country_code": "",
        "flag": "",
        "loc": "",
        "postal": "",
        "timezone": "",
        "org": "",
        "asn": "",
        "asn_org": "",
        "asn_type": "",
        "anycast": False,
        "risk_score": 0,
        "risk_band": "Clean",
        "signals": [],
    }


def get_ip_info(ip, token):
    """Fetch one IP from ipinfo.io. Network failures are recorded, not hidden."""
    url = "https://ipinfo.io/%s/json" % ip
    if token and token != "YOUR_API_KEY":
        url += "?token=%s" % token

    try:
        payload = json.loads(http_get(url).decode("utf-8", "replace"))
    except FetchError as exc:
        return blank_record(ip, "error", "Lookup failed: %s" % exc)
    except ValueError:
        return blank_record(ip, "error", "Lookup failed: malformed response")

    if payload.get("bogon"):
        return blank_record(ip, "local", "Bogon address")

    record = blank_record(ip, "ok")
    org = payload.get("org", "") or ""
    match = ASN_PATTERN.match(org)
    code = (payload.get("country", "") or "").upper()

    record.update(
        {
            "ip": payload.get("ip", ip),
            "hostname": payload.get("hostname", "") or "",
            "city": payload.get("city", "") or "",
            "region": payload.get("region", "") or "",
            "country_code": code,
            "country": country_name(code),
            "flag": flag_emoji(code),
            "loc": payload.get("loc", "") or "",
            "postal": payload.get("postal", "") or "",
            "timezone": payload.get("timezone", "") or "",
            "org": org,
            "asn": match.group(1) if match else "",
            "asn_org": match.group(2).strip() if match else org,
            "anycast": bool(payload.get("anycast")),
        }
    )
    return record


def fetch_ipapi_flags(ips):
    """Optional proxy/hosting/mobile flags from ip-api.com (100 IPs per call).

    Only reached when ENABLE_IPAPI_FLAGS is on. See the note at the top of the
    file: this endpoint is plain HTTP on the free tier.
    """
    flags = {}
    for start in range(0, len(ips), 100):
        chunk = ips[start : start + 100]
        body = json.dumps(
            [{"query": ip, "fields": "query,status,proxy,hosting,mobile"} for ip in chunk]
        ).encode("utf-8")
        try:
            response = http_get(
                "http://ip-api.com/batch",
                data=body,
                content_type="application/json",
                timeout=20,
            )
            for entry in json.loads(response.decode("utf-8", "replace")):
                if entry.get("status") == "success":
                    flags[entry.get("query")] = {
                        "proxy": bool(entry.get("proxy")),
                        "hosting": bool(entry.get("hosting")),
                        "mobile": bool(entry.get("mobile")),
                    }
        except (FetchError, ValueError) as exc:
            warn("ip-api.com batch failed: %s" % exc)
            break
        if start + 100 < len(ips):
            time.sleep(4)  # free tier allows 15 requests per minute
    return flags


def apply_scoring(record, intel, ipapi_flags):
    """Attach signals and the resulting score to one record."""
    signals = []

    if record["status"] == "ok":
        signals.extend(intel.signals_for(record["ip"], record["asn"]))

        extra = ipapi_flags.get(record["ip"])
        if extra:
            if extra["proxy"]:
                signals.append(
                    _signal(
                        "Proxy/VPN/Tor",
                        WEIGHT_PROXY,
                        "ipapi",
                        "ip-api.com flags this as an anonymising service",
                    )
                )
            if extra["hosting"] and not any(s["source"] == "hosting_asn" for s in signals):
                signals.append(
                    _signal(
                        "Hosting/Cloud",
                        WEIGHT_HOSTING_ASN,
                        "ipapi",
                        "ip-api.com flags this as a datacenter address",
                    )
                )
            if extra["mobile"]:
                signals.append(
                    _signal("Mobile carrier", 0, "ipapi", "Cellular network address")
                )

        if record["anycast"]:
            signals.append(
                _signal("Anycast", 0, "ipinfo", "Address is announced from many locations")
            )

        record["asn_type"] = (
            "Hosting/Cloud"
            if any(s["source"] in ("hosting_asn", "ipapi") and s["weight"] for s in signals)
            else "ISP/Other"
        )
    elif record["status"] == "local":
        signals.append(_signal("Non-routable", 0, "local", record["note"]))

    record["signals"] = signals
    record["risk_score"] = min(100, sum(s["weight"] for s in signals))
    record["risk_band"] = risk_band(record["risk_score"])
    return record


# ---------------------------------------------------------------------------
# Output: CSV and JSON
# ---------------------------------------------------------------------------

# Geolocation first: it is what this tool is for. The reputation columns are
# an add-on and sit at the end, next to the status/note pair.
CSV_FIELDS = [
    "ip",
    "hostname",
    "city",
    "region",
    "country",
    "country_code",
    "loc",
    "postal",
    "timezone",
    "org",
    "asn",
    "asn_org",
    "asn_type",
    "risk_score",
    "risk_band",
    "signals",
    "status",
    "note",
]

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralise spreadsheet formula injection.

    Fields here come from PTR records and WHOIS strings, which the owner of the
    IP controls. A leading '=' would otherwise be evaluated by Excel when the
    analyst opens the results.
    """
    text = "" if value is None else str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def save_to_csv(records, file_path):
    with open(file_path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row = {field: _csv_safe(record.get(field, "")) for field in CSV_FIELDS}
            row["signals"] = _csv_safe(
                "; ".join("%s (%s)" % (s["label"], s["detail"]) for s in record["signals"])
            )
            writer.writerow(row)


def build_summary(records, intel, elapsed):
    countries = Counter(r["country"] for r in records if r["country"])
    cities = Counter(
        "%s, %s" % (r["city"], r["country_code"])
        for r in records
        if r["city"] and r["country_code"]
    )
    regions = Counter(
        "%s, %s" % (r["region"], r["country_code"])
        for r in records
        if r["region"] and r["country_code"]
    )
    asns = Counter(
        "AS%s %s" % (r["asn"], r["asn_org"]) for r in records if r["asn"]
    )
    bands = Counter(r["risk_band"] for r in records)
    sources = Counter(
        s["source"] for r in records for s in r["signals"] if s["weight"] > 0
    )

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "elapsed_seconds": round(elapsed, 1),
        "total": len(records),
        "resolved": sum(1 for r in records if r["status"] == "ok"),
        "errors": sum(1 for r in records if r["status"] == "error"),
        "non_routable": sum(1 for r in records if r["status"] == "local"),
        "invalid": sum(1 for r in records if r["status"] == "invalid"),
        "unique_countries": len(countries),
        "unique_cities": len(cities),
        "unique_asns": len(asns),
        "located": sum(1 for r in records if r["loc"]),
        "flagged": sum(1 for r in records if r["risk_score"] > 0),
        "bands": {band: bands.get(band, 0) for band in BANDS},
        "top_countries": countries.most_common(10),
        "top_cities": cities.most_common(10),
        "top_regions": regions.most_common(10),
        "top_asns": asns.most_common(10),
        "signal_sources": dict(sources),
        "signal_catalog": SIGNAL_CATALOG,
        "band_ranges": BAND_RANGES,
        "feeds": intel.provenance,
    }


# ---------------------------------------------------------------------------
# Output: HTML dashboard
# ---------------------------------------------------------------------------

# The report is a single self-contained file: no CDN, no external fonts, no
# network calls. It has to open on an isolated analysis machine.
#
# Every value coming from the network is delivered inside a JSON island and
# written to the DOM with textContent, never by string-concatenating markup.
# Hostnames come from PTR records the investigated party controls, so treating
# them as markup would let a target inject script into the analyst's report.

HTML_HEAD = """<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPTracker0x Report</title>
<style>
:root {
  --bg: #f5f6fa; --panel: #ffffff; --panel-2: #fafbfd; --ink: #1b1f2a;
  --muted: #626b7d; --line: #e2e5ec; --accent: #2563eb; --accent-ink: #ffffff;
  --clean: #64748b; --low: #2563eb; --medium: #b45309; --high: #c2410c; --critical: #b91c1c;
  --clean-bg: #f1f5f9; --low-bg: #e6efff; --medium-bg: #fdf3e3; --high-bg: #ffedd5; --critical-bg: #fee2e2;
  /* The map is dark in both themes, the way an embedded Grafana panel is, so
     these do not change with the theme. Ocean sits lighter than land, as in
     CartoDB Dark Matter. The ramp runs light-on-dark: q1 measures 29.8 dE from
     the land colour, so one address never reads as none. */
  --ocean: #3d3d3d; --land: #0e0e0e; --border: #2b2b2b; --marker: #d94a52;
  --marker-hi: #f4767c; --mapink: #f0f0f0;
  --q1: #184f95; --q2: #256abf; --q3: #3987e5; --q4: #6da7ec; --q5: #9ec5f4;
  --shadow: 0 1px 2px rgba(16,24,40,.06), 0 4px 12px rgba(16,24,40,.05);
}
html[data-theme="dark"] {
  --bg: #0f1218; --panel: #161b24; --panel-2: #1b212c; --ink: #e6e9ef;
  --muted: #98a2b3; --line: #262e3b; --accent: #3b82f6; --accent-ink: #ffffff;
  --clean: #94a3b8; --low: #60a5fa; --medium: #fbbf24; --high: #fb923c; --critical: #f87171;
  --clean-bg: #1e2430; --low-bg: #17263f; --medium-bg: #2e2513; --high-bg: #32210f; --critical-bg: #331717;
  --shadow: 0 1px 2px rgba(0,0,0,.3), 0 4px 12px rgba(0,0,0,.25);
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 clamp(12px, 3vw, 32px) 64px;
  font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--ink); font-size: 14px; line-height: 1.5;
}
a { color: var(--accent); }
header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 12px; padding: 28px 0 18px; }
h1 { margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -.01em; }
h1 span { color: var(--accent); }
.sub { color: var(--muted); font-size: 12.5px; }
.spacer { flex: 1; }
button, select, input {
  font: inherit; color: var(--ink); background: var(--panel);
  border: 1px solid var(--line); border-radius: 8px; padding: 7px 11px;
}
button { cursor: pointer; }
button:hover { border-color: var(--accent); }
button.primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
.kpi {
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 13px 15px; box-shadow: var(--shadow); text-align: left;
}
.kpi .n { font-size: 24px; font-weight: 700; letter-spacing: -.02em; }
.kpi .l { color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em; }
.kpi.band { cursor: pointer; }
.kpi.band.on { outline: 2px solid var(--accent); outline-offset: -1px; }
.kpi.band[data-band="Clean"] .n { color: var(--clean); }
.kpi.band[data-band="Low"] .n { color: var(--low); }
.kpi.band[data-band="Medium"] .n { color: var(--medium); }
.kpi.band[data-band="High"] .n { color: var(--high); }
.kpi.band[data-band="Critical"] .n { color: var(--critical); }
.mapwrap { margin-top: 10px; padding-bottom: 8px; }
.maphead { display: flex; flex-wrap: wrap; gap: 10px 20px; align-items: baseline; justify-content: space-between; }
.mapbox {
  position: relative; margin-top: 8px; border-radius: 8px; overflow: hidden;
  background: var(--ocean); line-height: 0;
}
#mapimg { width: 100%; height: auto; display: block; }
/* The pins ride on top of the raster in the same coordinate space. */
#pinlayer { position: absolute; inset: 0; width: 100%; height: 100%; }
/* Proportional circles: area scales with the count and the translucent fill
   turns overlapping places into a denser patch instead of a solid mass. */
#markers .dot { cursor: pointer; }
#markers .dot .body {
  /* Low fill opacity on purpose: where places pile up the overlap darkens
     gradually instead of flooding to solid red at the first collision. */
  fill: var(--marker); fill-opacity: .34;
  stroke: var(--marker-hi); stroke-opacity: .5; stroke-width: .7;
  vector-effect: non-scaling-stroke;
}
#markers .dot .hit { fill: transparent; }
#markers .dot:hover .body { fill-opacity: .85; stroke: var(--mapink); stroke-width: 1.5; }
#markers .dot.sel .body { fill-opacity: .9; stroke: var(--mapink); stroke-width: 1.8; }
.legend { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 10px; font-size: 11.5px; color: var(--muted); }
.legend .steps { display: flex; align-items: center; gap: 2px; }
.legend .sw { width: 26px; height: 10px; border-radius: 2px; display: block; }
.legend .lbl { margin: 0 2px; }
.legend .sizes { display: inline-flex; align-items: flex-end; gap: 5px; }
.legend .sizes svg { display: block; overflow: visible; }
.legend .sizes circle {
  fill: var(--marker); fill-opacity: .34; stroke: var(--marker-hi); stroke-opacity: .5; stroke-width: .7;
}
.tip {
  position: absolute; pointer-events: none; opacity: 0; transition: opacity .1s;
  background: var(--panel); color: var(--ink); border: 1px solid var(--line);
  border-radius: 7px; padding: 6px 9px; font-size: 12.5px; box-shadow: var(--shadow);
  white-space: nowrap; z-index: 5;
  /* .mapbox zeroes line-height to kill the gap under the <img>; the tooltip
     must undo it or its two lines print on top of each other. */
  line-height: 1.35;
}
.tip.on { opacity: 1; }
.tip b { display: block; font-size: 13px; }
.dist { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; margin-top: 10px; }
.panel {
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 14px 16px; box-shadow: var(--shadow);
}
.panel h2 {
  margin: 0 0 10px; font-size: 11.5px; font-weight: 600; color: var(--muted);
  text-transform: uppercase; letter-spacing: .04em;
}
.bars { display: flex; flex-direction: column; gap: 5px; }
.bar {
  display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: center;
  position: relative; padding: 4px 8px; border: 0; border-radius: 6px;
  background: transparent; text-align: left; cursor: pointer; width: 100%;
}
.bar:hover { background: var(--panel-2); }
.bar.on { outline: 1px solid var(--accent); }
.bar .fill {
  position: absolute; left: 0; top: 0; bottom: 0; border-radius: 6px;
  background: var(--accent); opacity: .16; pointer-events: none;
}
.bar .name { position: relative; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar .val { position: relative; color: var(--muted); font-variant-numeric: tabular-nums; font-size: 12.5px; }
.toolbar {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  margin: 20px 0 12px; padding: 12px; background: var(--panel);
  border: 1px solid var(--line); border-radius: 10px; box-shadow: var(--shadow);
}
#q { flex: 1 1 240px; min-width: 200px; }
.count { color: var(--muted); font-size: 12.5px; white-space: nowrap; }
.explain {
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  box-shadow: var(--shadow); margin-bottom: 12px;
}
.explain > summary {
  cursor: pointer; padding: 11px 14px; font-size: 12.5px; font-weight: 600;
  color: var(--accent); list-style: none;
}
.explain > summary::-webkit-details-marker { display: none; }
.explain > summary::before { content: "▸"; display: inline-block; margin-right: 7px; transition: transform .15s; }
.explain[open] > summary::before { transform: rotate(90deg); }
.explain-body { padding: 0 14px 14px; border-top: 1px solid var(--line); }
.explain .lede { max-width: 78ch; color: var(--ink); font-size: 13px; margin: 12px 0 16px; }
.explain-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px 28px; }
.explain h3 {
  margin: 0 0 6px; font-size: 11.5px; font-weight: 600; color: var(--muted);
  text-transform: uppercase; letter-spacing: .04em;
}
table.ref { width: 100%; border-collapse: collapse; }
table.ref td { border: 0; border-bottom: 1px solid var(--line); padding: 7px 10px 7px 0; vertical-align: top; font-size: 12.5px; }
table.ref tr:last-child td { border-bottom: 0; }
table.ref td:first-child { white-space: nowrap; padding-right: 16px; width: 1%; }
table.ref td.pts { text-align: right; white-space: nowrap; color: var(--muted); font-variant-numeric: tabular-nums; padding-left: 12px; }
table.ref td.what { color: var(--muted); }
table.ref .src { color: var(--muted); font-size: 11.5px; }
.foot-note { color: var(--muted); font-size: 12px; margin: 12px 0 0; }
.wrap { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; box-shadow: var(--shadow); overflow-x: auto; }
/* Fixed layout is what keeps the table inside the viewport: every column gets
   the width declared in COLUMNS and long values are clipped, instead of the
   browser widening the table until it needs a horizontal scrollbar. */
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
th, td {
  padding: 9px 12px; text-align: left; border-bottom: 1px solid var(--line);
  vertical-align: top; overflow: hidden; text-overflow: ellipsis;
}
th {
  position: sticky; top: 0; z-index: 2; background: var(--panel-2);
  font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em;
  color: var(--muted); cursor: pointer; white-space: nowrap; user-select: none;
}
th:hover { color: var(--accent); }
th .arrow { opacity: .45; font-size: 10px; }
tbody tr:hover { background: var(--panel-2); }
tr.row { cursor: pointer; }
td.ip { font-family: 'Cascadia Mono', Consolas, monospace; white-space: nowrap; }
/* IPv6 is far wider than the column; clip it and keep the full value in the
   title and the expanded row. */
td.ip span { display: block; overflow: hidden; text-overflow: ellipsis; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); }
.trunc { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.badge {
  display: inline-block; padding: 2px 9px; border-radius: 999px;
  font-size: 11.5px; font-weight: 600; white-space: nowrap;
}
.badge[data-band="Clean"] { color: var(--clean); background: var(--clean-bg); }
.badge[data-band="Low"] { color: var(--low); background: var(--low-bg); }
.badge[data-band="Medium"] { color: var(--medium); background: var(--medium-bg); }
.badge[data-band="High"] { color: var(--high); background: var(--high-bg); }
.badge[data-band="Critical"] { color: var(--critical); background: var(--critical-bg); }
.chips { display: flex; flex-wrap: wrap; gap: 4px; }
.chip {
  padding: 1px 7px; border-radius: 5px; font-size: 11px; white-space: nowrap;
  background: var(--panel-2); border: 1px solid var(--line); color: var(--muted);
}
.chip.w { color: var(--ink); border-color: var(--accent); }
.detail td { background: var(--panel-2); padding: 0; overflow: visible; white-space: normal; }
/* The table scrolls sideways; without this the expanded detail sits off-screen
   whenever the reader has scrolled right. */
.detail .inner { position: sticky; left: 0; display: inline-block; padding: 12px 14px; }
.detail dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0 0 12px; }
.detail dt { color: var(--muted); font-size: 12px; }
.detail dd { margin: 0; font-size: 12.5px; word-break: break-word; }
.ev { border-left: 3px solid var(--line); padding: 3px 0 3px 10px; margin-bottom: 6px; }
.ev b { font-weight: 600; }
.ev .src { color: var(--muted); font-size: 11.5px; }
tr.group td { background: var(--panel-2); border-top: 1px solid var(--line); }
tr.group .meta { font-weight: 400; color: var(--muted); font-size: 12.5px; margin-left: 8px; }
tr.group .badge { margin-left: 6px; }
.nowrap { white-space: nowrap; }
.empty { padding: 48px 16px; text-align: center; color: var(--muted); }
footer { margin-top: 20px; color: var(--muted); font-size: 12px; }
footer table { width: auto; }
footer td { border: 0; padding: 3px 14px 3px 0; font-size: 12px; }
@media print {
  .toolbar, .kpi.band { break-inside: avoid; }
  body { background: #fff; }
}
</style>
</head>
<body>
<header>
  <div>
    <h1>IPTracker<span>0x</span> Report</h1>
    <div class="sub" id="meta"></div>
  </div>
  <div class="spacer"></div>
  <button id="theme" title="Toggle light/dark">Theme</button>
</header>

<div class="kpis" id="kpis"></div>

<section class="panel mapwrap">
  <div class="maphead">
    <h2>Where these addresses are</h2>
    <div class="legend" id="legend"></div>
  </div>
  <div class="mapbox" id="mapbox">
    <img id="mapimg" src="__MAP_PNG__" alt="World map, each country shaded by how many of the analysed addresses are located there">
    <svg id="pinlayer" viewBox="__VIEWBOX__" aria-hidden="true">
      <g id="markers"></g>
    </svg>
    <div class="tip" id="tip" role="status" aria-live="polite"></div>
  </div>
</section>

<section class="dist" id="dist"></section>

<div class="toolbar">
  <input id="q" type="search" placeholder="Search IP, hostname, city, region, country, ASN...">
  <select id="fCountry"></select>
  <select id="fCity"></select>
  <select id="fAsn"></select>
  <select id="fRisk"></select>
  <select id="fSignal"></select>
  <button id="group">Group by</button>
  <button id="reset">Reset</button>
  <span class="spacer"></span>
  <span class="count" id="count"></span>
  <button id="copy">Copy IPs</button>
  <button id="csv" class="primary">CSV</button>
</div>

<details class="explain" id="explain">
  <summary>What are signals and risk bands?</summary>
  <div class="explain-body">
    <p class="lede">
      This is a geolocation report. Beyond location, every address is also checked
      against a few public reputation feeds. Each match is a <b>signal</b>: a named
      fact from a named source, worth a fixed number of points. The points add up to
      a score out of 100, and the score falls into a <b>band</b>. An address with no
      matches scores zero and is simply <b>Clean</b>.
    </p>
    <div class="explain-cols">
      <div>
        <h3>Signals</h3>
        <table class="ref" id="sigRef"></table>
      </div>
      <div>
        <h3>Bands</h3>
        <table class="ref" id="bandRef"></table>
        <p class="foot-note">
          Hover any chip in the Signals column to see why that address matched.
          Click a row to open the full evidence.
        </p>
      </div>
    </div>
  </div>
</details>

<div class="wrap" id="wrap"></div>

<footer id="foot"></footer>
"""


HTML_SCRIPT = """
<script type="application/json" id="payload">__DATA__</script>
<script>
(function () {
  "use strict";

  var DATA = JSON.parse(document.getElementById("payload").textContent);
  var ROWS = DATA.results;
  var SUM = DATA.summary;
  var BANDS = ["Critical", "High", "Medium", "Low", "Clean"];
  var BAND_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Clean: 0 };

  var state = {
    q: "", country: "", city: "", asn: "", signal: "", risk: "", flagged: false,
    // Default order is geographic, not by risk.
    sort: { key: "location", dir: 1 }, groupBy: "", open: {}
  };

  // Build every node with textContent so hostile PTR/WHOIS strings stay text.
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function asnLabel(r) {
    if (!r.asn) return "";
    return "AS" + r.asn + (r.asn_org ? " " + r.asn_org : "");
  }

  // Compact form for the table: "Kingston, JM". ipinfo often repeats the city
  // as the region, and the full name is one click away in the detail row.
  function place(r) {
    var parts = [];
    if (r.city) parts.push(r.city);
    if (r.region && r.region !== r.city) parts.push(r.region);
    if (r.country_code) parts.push(r.country_code);
    return parts.join(", ");
  }

  function placeFull(r) {
    var parts = [];
    if (r.city) parts.push(r.city);
    if (r.region && r.region !== r.city) parts.push(r.region);
    if (r.country) parts.push(r.country);
    return parts.join(", ");
  }

  function haystack(r) {
    return [r.ip, r.hostname, r.org, r.country, r.city, r.region, asnLabel(r), r.note]
      .filter(Boolean).join(" ").toLowerCase();
  }
  ROWS.forEach(function (r) { r._hay = haystack(r); });

  // ---- filtering -----------------------------------------------------------

  function cityLabel(r) {
    return r.city && r.country_code ? r.city + ", " + r.country_code : "";
  }

  function visible() {
    var q = state.q.trim().toLowerCase();
    var terms = q ? q.split(/\\s+/) : [];
    return ROWS.filter(function (r) {
      if (state.flagged && !r.risk_score) return false;
      if (state.risk && r.risk_band !== state.risk) return false;
      if (state.country && r.country !== state.country) return false;
      if (state.city && cityLabel(r) !== state.city) return false;
      if (state.asn && asnLabel(r) !== state.asn) return false;
      if (state.signal && !r.signals.some(function (s) { return s.label === state.signal; })) return false;
      for (var i = 0; i < terms.length; i++) {
        if (r._hay.indexOf(terms[i]) === -1) return false;
      }
      return true;
    });
  }

  function sorted(rows) {
    var key = state.sort.key, dir = state.sort.dir;
    return rows.slice().sort(function (a, b) {
      var x, y;
      if (key === "risk_score") { x = a.risk_score; y = b.risk_score; }
      else if (key === "ip") { x = ipKey(a.ip); y = ipKey(b.ip); }
      else if (key === "asn") { x = asnLabel(a).toLowerCase(); y = asnLabel(b).toLowerCase(); }
      else if (key === "location") {
        // Group by country first, and park the unlocatable ones at the end
        // rather than letting an empty string sort above every country.
        x = ((a.country || "zzzz") + " " + a.city).toLowerCase();
        y = ((b.country || "zzzz") + " " + b.city).toLowerCase();
      }
      else { x = String(a[key] || "").toLowerCase(); y = String(b[key] || "").toLowerCase(); }
      if (x < y) return -dir;
      if (x > y) return dir;
      return ipKey(a.ip) - ipKey(b.ip);
    });
  }

  function ipKey(ip) {
    var parts = String(ip).split(".");
    if (parts.length !== 4) return 0;
    return (((+parts[0] * 256 + +parts[1]) * 256 + +parts[2]) * 256 + +parts[3]);
  }

  // ---- KPIs ----------------------------------------------------------------

  function buildKpis() {
    var box = document.getElementById("kpis");
    box.textContent = "";
    // Geolocation coverage first -- that is what this report is about.
    var stats = [
      ["Total IPs", SUM.total],
      ["Geolocated", SUM.located],
      ["Countries", SUM.unique_countries],
      ["Cities", SUM.unique_cities],
      ["ASNs", SUM.unique_asns]
    ];
    stats.forEach(function (st) {
      var card = el("div", "kpi");
      card.appendChild(el("div", "n", st[1]));
      card.appendChild(el("div", "l", st[0]));
      box.appendChild(card);
    });

    // Reputation is an add-on: one card, not the whole header.
    var flagged = el("button", "kpi band" + (state.flagged ? " on" : ""));
    flagged.setAttribute("data-band", worstBand());
    flagged.setAttribute("title", "Show only addresses with a reputation signal");
    flagged.setAttribute("aria-pressed", state.flagged ? "true" : "false");
    flagged.appendChild(el("div", "n", SUM.flagged));
    flagged.appendChild(el("div", "l", "Flagged"));
    flagged.addEventListener("click", function () {
      state.flagged = !state.flagged;
      render();
    });
    box.appendChild(flagged);
  }

  function worstBand() {
    for (var i = 0; i < BANDS.length; i++) {
      if (SUM.bands[BANDS[i]]) return BANDS[i];
    }
    return "Clean";
  }

  // ---- world map -----------------------------------------------------------

  var MAP = document.getElementById("pinlayer");
  var TIP = document.getElementById("tip");
  // Same projection the geometry was baked with (equirectangular, cropped).
  var PIN_VIEW = (document.getElementById("pinlayer").getAttribute("viewBox") || "0 0 1000 389")
    .split(" ").map(Number);
  var PROJ = { top: 84, bottom: -56, scale: PIN_VIEW[2] / 360 };
  // Sizes are expressed against a 1000-unit-wide canvas, then scaled to
  // whatever the raster actually is.
  var UNIT = PIN_VIEW[2] / 1000;
  var MIN_R = 2.6 * UNIT, MAX_R = 16 * UNIT, MIN_HIT = 6 * UNIT;

  // Area-proportional: radius follows the square root, so a circle twice as
  // wide really does stand for four times as many addresses.
  function dotRadius(n, peak) {
    if (peak <= 1) return MIN_R * 1.6;
    return Math.max(MIN_R, MAX_R * Math.sqrt(n / peak));
  }
  var SVGNS = "http://www.w3.org/2000/svg";
  function svgEl(tag, attrs) {
    var node = document.createElementNS(SVGNS, tag);
    Object.keys(attrs).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    return node;
  }

  function projectPoint(lat, lon) {
    var y = (PROJ.top - Math.max(Math.min(lat, PROJ.top), PROJ.bottom)) * PROJ.scale;
    return [(lon + 180) * PROJ.scale, y];
  }

  function showTip(event, title, detail) {
    TIP.textContent = "";
    TIP.appendChild(el("b", null, title));
    TIP.appendChild(document.createTextNode(detail));
    TIP.classList.add("on");
    var box = MAP.getBoundingClientRect();
    var x = event.clientX - box.left;
    var y = event.clientY - box.top;
    TIP.style.left = Math.min(Math.max(x + 12, 0), box.width - TIP.offsetWidth - 4) + "px";
    TIP.style.top = Math.max(y - TIP.offsetHeight - 10, 0) + "px";
  }

  function hideTip() { TIP.classList.remove("on"); }

  function plural(n) { return n + (n === 1 ? " address" : " addresses"); }

  function buildMap() {
    // Rows that are visible under every filter except the geographic one, so
    // clicking a country reads as "narrow to here", not "empty the map".
    var scope = ROWS.filter(function (r) {
      if (state.flagged && !r.risk_score) return false;
      if (state.risk && r.risk_band !== state.risk) return false;
      if (state.asn && asnLabel(r) !== state.asn) return false;
      if (state.signal && !r.signals.some(function (x) { return x.label === state.signal; })) return false;
      return true;
    });

    var byCode = {}, names = {}, places = {};
    scope.forEach(function (r) {
      if (r.country_code) {
        byCode[r.country_code] = (byCode[r.country_code] || 0) + 1;
        names[r.country_code] = r.country || r.country_code;
      }
      if (r.loc) {
        var key = r.loc;
        if (!places[key]) {
          places[key] = { n: 0, label: cityLabel(r) || r.country || r.ip, loc: r.loc, city: cityLabel(r) };
        }
        places[key].n++;
      }
    });

    var layer = document.getElementById("markers");
    layer.textContent = "";
    var peak = 1;
    Object.keys(places).forEach(function (k) { if (places[k].n > peak) peak = places[k].n; });
    MAP_PEAK = peak;

    // Biggest first, so a large circle never buries a small one that sits
    // inside it -- the small one has to stay hoverable.
    var ordered = Object.keys(places)
      .map(function (key) {
        var parts = places[key].loc.split(",");
        return { place: places[key], lat: parseFloat(parts[0]), lon: parseFloat(parts[1]) };
      })
      .filter(function (p) { return !isNaN(p.lat) && !isNaN(p.lon); })
      .sort(function (a, b) { return b.place.n - a.place.n; });

    ordered.forEach(function (item) {
      var place = item.place;
      var xy = projectPoint(item.lat, item.lon);
      var r = dotRadius(place.n, peak);

      var dot = svgEl("g", { "class": "dot" + (state.city && state.city === place.city ? " sel" : "") });
      dot.appendChild(svgEl("circle", { "class": "body", cx: xy[0].toFixed(1), cy: xy[1].toFixed(1), r: r.toFixed(1) }));
      // Keep a usable target even where the circle is only a few pixels wide.
      dot.appendChild(svgEl("circle", { "class": "hit", cx: xy[0].toFixed(1), cy: xy[1].toFixed(1),
                                        r: Math.max(r, MIN_HIT).toFixed(1) }));

      dot.addEventListener("mousemove", function (e) { showTip(e, place.label, plural(place.n)); });
      dot.addEventListener("mouseleave", hideTip);
      dot.addEventListener("click", function () {
        if (place.city) {
          state.city = state.city === place.city ? "" : place.city;
          state.country = "";
          hideTip();
          render();
        }
      });
      layer.appendChild(dot);
    });

    // Legend mirrors the breaks Python used for the raster, so the swatches
    // always describe the image actually on screen.
    buildLegend((SUM.map || {}).edges || [], (SUM.map || {}).peak || 0);
  }

  // Three reference circles: smallest, midpoint, largest.
  function sizeKey() {
    var wrap = el("div", "sizes");
    var peak = MAP_PEAK || 1;
    // Never offer a reference circle larger than anything actually drawn:
    // with peak 1 the midpoint would otherwise invent a "2".
    var stops = [1, Math.max(2, Math.round(peak / 4)), peak];
    var seen = {};
    stops.forEach(function (n) {
      if (n < 1 || n > peak || seen[n]) return;
      seen[n] = 1;
      var r = dotRadius(n, peak) / UNIT;      // back to 1000-space for display
      var size = Math.max(6, r * 1.6);
      var svg = svgEl("svg", { width: size, height: size,
                               viewBox: (-size / 2) + " " + (-size / 2) + " " + size + " " + size });
      svg.appendChild(svgEl("circle", { cx: 0, cy: 0, r: (r * 0.8).toFixed(1) }));
      wrap.appendChild(svg);
      wrap.appendChild(el("span", "lbl", String(n)));
    });
    return wrap;
  }

  var MAP_PEAK = 1;

  function buildLegend(edges, max) {
    var box = document.getElementById("legend");
    box.textContent = "";
    if (!max) {
      box.appendChild(el("span", null, "No address could be placed on the map"));
      return;
    }

    box.appendChild(el("span", "lbl", "Addresses per country"));
    // Numbers flank the ramp so the reader sees the range, not just the hues.
    box.appendChild(el("span", "lbl", "1"));
    var steps = el("div", "steps");
    var low = 1;
    edges.forEach(function (edge, i) {
      var sw = el("span", "sw");
      sw.style.background = "var(--q" + (i + 1) + ")";
      sw.title = (low === edge ? String(low) : low + " to " + edge);
      steps.appendChild(sw);
      low = edge + 1;
    });
    box.appendChild(steps);
    box.appendChild(el("span", "lbl", String(max)));

    box.appendChild(el("span", "lbl", "Addresses per city"));
    box.appendChild(sizeKey());
  }


  // ---- geographic distribution --------------------------------------------

  function panel(title, entries, key) {
    var box = el("div", "panel");
    box.appendChild(el("h2", null, title));
    if (!entries.length) {
      box.appendChild(el("div", "muted", "No data"));
      return box;
    }
    var top = entries[0][1];
    var bars = el("div", "bars");
    entries.forEach(function (entry) {
      var name = entry[0], count = entry[1];
      var active = state[key] === name;
      var bar = el("button", "bar" + (active ? " on" : ""));
      bar.setAttribute("aria-pressed", active ? "true" : "false");
      var fill = el("span", "fill");
      fill.style.width = Math.max(3, (count / top) * 100) + "%";
      bar.appendChild(fill);
      bar.appendChild(el("span", "name", name));
      bar.appendChild(el("span", "val", count));
      bar.addEventListener("click", function () {
        state[key] = active ? "" : name;
        render();
      });
      bars.appendChild(bar);
    });
    box.appendChild(bars);
    return box;
  }

  function buildDistribution() {
    var box = document.getElementById("dist");
    box.textContent = "";
    box.appendChild(panel("Top countries", SUM.top_countries, "country"));
    box.appendChild(panel("Top cities", SUM.top_cities, "city"));
    box.appendChild(panel("Top networks", SUM.top_asns, "asn"));
  }

  // ---- select filters ------------------------------------------------------

  function fillSelect(id, placeholder, values, current) {
    var sel = document.getElementById(id);
    sel.textContent = "";
    sel.appendChild(new Option(placeholder, ""));
    values.forEach(function (v) { sel.appendChild(new Option(v[0] + " (" + v[1] + ")", v[0])); });
    sel.value = current;
  }

  function tally(fn) {
    var map = {};
    ROWS.forEach(function (r) {
      var keys = fn(r);
      (Array.isArray(keys) ? keys : [keys]).forEach(function (k) {
        if (k) map[k] = (map[k] || 0) + 1;
      });
    });
    return Object.keys(map).map(function (k) { return [k, map[k]]; })
      .sort(function (a, b) { return b[1] - a[1] || a[0].localeCompare(b[0]); });
  }

  function buildSelects() {
    fillSelect("fCountry", "All countries", tally(function (r) { return r.country; }), state.country);
    fillSelect("fCity", "All cities", tally(cityLabel), state.city);
    fillSelect("fAsn", "All networks", tally(asnLabel), state.asn);
    fillSelect("fRisk", "All risk levels",
      BANDS.filter(function (b) { return SUM.bands[b]; })
        .map(function (b) { return [b, SUM.bands[b]]; }), state.risk);
    fillSelect("fSignal", "All signals",
      tally(function (r) { return r.signals.map(function (s) { return s.label; }); }), state.signal);
  }

  // ---- table ---------------------------------------------------------------

  // Geolocation leads; the reputation columns close the row. Widths are fixed
  // so the whole table fits a laptop screen instead of scrolling sideways --
  // the two flexible columns share what is left.
  var COLUMNS = [
    { key: "ip", label: "IP", w: "148px" },
    { key: "location", label: "Location", w: "23%" },
    { key: "hostname", label: "Hostname", w: "26%" },
    { key: "asn", label: "Network / ASN", w: "26%" },
    { key: "risk_score", label: "Risk", num: true, w: "96px" },
    { key: "signals", label: "Signals", nosort: true, w: "180px" }
  ];

  function headRow() {
    var tr = document.createElement("tr");
    COLUMNS.forEach(function (col) {
      var th = el("th", null, col.label);
      if (!col.nosort) {
        if (state.sort.key === col.key) {
          th.appendChild(el("span", "arrow", state.sort.dir > 0 ? " \\u25B2" : " \\u25BC"));
        }
        th.addEventListener("click", function () {
          if (state.sort.key === col.key) state.sort.dir *= -1;
          else state.sort = { key: col.key, dir: col.num ? -1 : 1 };
          render();
        });
      }
      tr.appendChild(th);
    });
    return tr;
  }

  function dataRow(r) {
    var tr = el("tr", "row");
    // Anything that can outgrow its column carries the full value in a title.
    var ipCell = el("td", "ip");
    ipCell.title = r.ip;
    ipCell.appendChild(el("span", null, r.ip));
    tr.appendChild(ipCell);

    var loc = el("td", "nowrap" + (placeFull(r) ? "" : " muted"));
    loc.textContent = (r.flag ? r.flag + " " : "") + (placeFull(r) || "\\u2014");
    loc.title = placeFull(r);
    tr.appendChild(loc);

    var host = el("td");
    host.title = r.hostname;
    host.appendChild(el("span", "trunc" + (r.hostname ? "" : " muted"), r.hostname || "\\u2014"));
    tr.appendChild(host);

    var org = el("td");
    org.title = asnLabel(r) || r.org;
    org.appendChild(el("span", "trunc" + (r.asn ? "" : " muted"), asnLabel(r) || r.org || "\\u2014"));
    tr.appendChild(org);

    var risk = el("td");
    var badge = el("span", "badge",
      r.risk_band + (r.risk_score ? " \\u00B7 " + r.risk_score : ""));
    badge.setAttribute("data-band", r.risk_band);
    badge.title = bandHint(r.risk_band);
    risk.appendChild(badge);
    tr.appendChild(risk);

    var sig = el("td");
    var chips = el("div", "chips");
    r.signals.forEach(function (s) {
      var chip = el("span", "chip" + (s.weight > 0 ? " w" : ""), s.label);
      chip.title = signalHint(s);
      chips.appendChild(chip);
    });
    if (!r.signals.length) chips.appendChild(el("span", "muted", "\\u2014"));
    sig.appendChild(chips);
    tr.appendChild(sig);

    tr.addEventListener("click", function () {
      state.open[r.ip] = !state.open[r.ip];
      render();
    });
    return tr;
  }

  function detailRow(r) {
    var tr = el("tr", "detail");
    var cell = document.createElement("td");
    cell.colSpan = COLUMNS.length;
    var td = el("div", "inner");
    cell.appendChild(td);

    var dl = document.createElement("dl");
    [["City", r.city || "\\u2014"],
     ["Region", r.region || "\\u2014"],
     ["Country", r.country ? r.country + " (" + r.country_code + ")" : "\\u2014"],
     ["Postal code", r.postal || "\\u2014"],
     ["Time zone", r.timezone || "\\u2014"],
     ["Hostname", r.hostname || "\\u2014"],
     ["Network", r.org || "\\u2014"],
     ["Network type", r.asn_type || "\\u2014"],
     ["Anycast", r.anycast ? "yes" : "no"],
     ["Status", r.status + (r.note ? " \\u2014 " + r.note : "")]].forEach(function (pair) {
      dl.appendChild(el("dt", null, pair[0]));
      dl.appendChild(el("dd", null, pair[1]));
    });

    if (r.loc) {
      dl.appendChild(el("dt", null, "Coordinates"));
      var dd = document.createElement("dd");
      dd.appendChild(document.createTextNode(r.loc + " "));
      // Plain link: nothing is requested unless the analyst clicks it, so the
      // report stays usable offline.
      var map = el("a", null, "open map");
      map.href = "https://www.openstreetmap.org/?mlat=" +
        encodeURIComponent(r.loc.split(",")[0]) + "&mlon=" +
        encodeURIComponent(r.loc.split(",")[1]) + "#map=10/" +
        encodeURIComponent(r.loc.split(",")[0]) + "/" +
        encodeURIComponent(r.loc.split(",")[1]);
      map.target = "_blank";
      map.rel = "noopener noreferrer";
      dd.appendChild(map);
      dl.appendChild(dd);
    }
    td.appendChild(dl);

    if (r.signals.length) {
      td.appendChild(el("div", "l muted", r.risk_score
        ? "Reputation signals - why this address is flagged"
        : "Notes - nothing here adds to the score"));
      r.signals.forEach(function (s) {
        var box = el("div", "ev");
        box.appendChild(el("b", null, s.label + (s.weight ? " (+" + s.weight + ")" : " (informational)")));
        box.appendChild(el("div", null, s.detail));
        box.appendChild(el("div", "src", "source: " + s.source));
        td.appendChild(box);
      });
    } else {
      td.appendChild(el("div", "muted",
        "No reputation feed matched this address. It is geolocation data only."));
    }

    tr.appendChild(cell);
    return tr;
  }

  function render() {
    buildKpis();
    buildMap();
    buildDistribution();
    buildSelects();
    var groupBtn = document.getElementById("group");
    groupBtn.textContent = state.groupBy === "country" ? "Grouped by country"
                         : state.groupBy === "asn" ? "Grouped by network"
                         : "Group by";
    groupBtn.classList.toggle("primary", !!state.groupBy);
    var rows = sorted(visible());
    document.getElementById("count").textContent =
      rows.length + " of " + ROWS.length + " shown";

    var wrap = document.getElementById("wrap");
    wrap.textContent = "";

    if (!rows.length) {
      wrap.appendChild(el("div", "empty", "No IP matches the current filters."));
      return;
    }

    var table = document.createElement("table");
    var group = document.createElement("colgroup");
    COLUMNS.forEach(function (col) {
      var c = document.createElement("col");
      if (col.w) c.style.width = col.w;
      group.appendChild(c);
    });
    table.appendChild(group);
    var thead = document.createElement("thead");
    thead.appendChild(headRow());
    table.appendChild(thead);

    if (state.groupBy) {
      renderGrouped(table, rows);
    } else {
      var tbody = document.createElement("tbody");
      rows.forEach(function (r) {
        tbody.appendChild(dataRow(r));
        if (state.open[r.ip]) tbody.appendChild(detailRow(r));
      });
      table.appendChild(tbody);
    }
    wrap.appendChild(table);
  }

  // One single table, with group headers as full-width rows. Separate tables
  // per ASN would each size their columns independently and stop lining up.
  function renderGrouped(table, rows) {
    var tbody = document.createElement("tbody");
    var groups = {};
    var byCountry = state.groupBy === "country";
    rows.forEach(function (r) {
      var key = byCountry
        ? ((r.flag ? r.flag + " " : "") + (r.country || "Unknown location"))
        : (asnLabel(r) || "Unknown network");
      (groups[key] = groups[key] || []).push(r);
    });

    Object.keys(groups)
      .sort(function (a, b) {
        var d = groups[b].length - groups[a].length;
        return d || a.localeCompare(b);
      })
      .forEach(function (key) {
        var members = groups[key];
        var worst = members.reduce(function (m, r) {
          return BAND_RANK[r.risk_band] > BAND_RANK[m.risk_band] ? r : m;
        }, members[0]);

        var head = el("tr", "group");
        var cell = document.createElement("td");
        cell.colSpan = COLUMNS.length;
        cell.appendChild(el("b", null, key));
        cell.appendChild(document.createTextNode(" "));
        var badge = el("span", "badge", worst.risk_band);
        badge.setAttribute("data-band", worst.risk_band);
        cell.appendChild(badge);
        cell.appendChild(el("span", "meta",
          members.length + (members.length === 1 ? " address" : " addresses")));
        head.appendChild(cell);
        tbody.appendChild(head);

        members.forEach(function (r) {
          tbody.appendChild(dataRow(r));
          if (state.open[r.ip]) tbody.appendChild(detailRow(r));
        });
      });

    table.appendChild(tbody);
  }

  // ---- exports -------------------------------------------------------------

  function csvCell(value) {
    var text = value === null || value === undefined ? "" : String(value);
    if (/^[=+\\-@\\t\\r]/.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
  }

  function exportCsv() {
    var cols = ["ip", "status", "risk_score", "risk_band", "hostname", "city",
                "region", "country", "loc", "org", "asn", "asn_org", "asn_type"];
    var lines = [cols.concat(["signals"]).join(",")];
    sorted(visible()).forEach(function (r) {
      var cells = cols.map(function (c) { return csvCell(r[c]); });
      cells.push(csvCell(r.signals.map(function (s) {
        return s.label + " (" + s.detail + ")";
      }).join("; ")));
      lines.push(cells.join(","));
    });
    download("iptracker0x-filtered.csv", "\\uFEFF" + lines.join("\\r\\n"), "text/csv");
  }

  function download(name, text, type) {
    var blob = new Blob([text], { type: type + ";charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function copyIps(button) {
    var text = sorted(visible()).map(function (r) { return r.ip; }).join("\\n");
    var done = function () {
      var label = button.textContent;
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = label; }, 1200);
    };
    // navigator.clipboard is unavailable on file:// in some browsers.
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text, done); });
    } else {
      legacyCopy(text, done);
    }
  }

  function legacyCopy(text, done) {
    var area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); done(); } catch (e) { /* clipboard blocked */ }
    document.body.removeChild(area);
  }

  // ---- chrome --------------------------------------------------------------

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try { localStorage.setItem("iptracker0x-theme", theme); } catch (e) { /* private mode */ }
  }

  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem("iptracker0x-theme"); } catch (e) { /* private mode */ }
    var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(saved || (dark ? "dark" : "light"));
  }

  function buildReference() {
    var sig = document.getElementById("sigRef");
    (SUM.signal_catalog || []).forEach(function (entry) {
      var tr = document.createElement("tr");
      var name = document.createElement("td");
      name.appendChild(el("b", null, entry.label));
      name.appendChild(el("div", "src", entry.source));
      tr.appendChild(name);
      tr.appendChild(el("td", "what", entry.means));
      tr.appendChild(el("td", "pts", entry.points));
      sig.appendChild(tr);
    });

    var bands = document.getElementById("bandRef");
    (SUM.band_ranges || []).forEach(function (row) {
      var tr = document.createElement("tr");
      var cell = document.createElement("td");
      var badge = el("span", "badge", row[0]);
      badge.setAttribute("data-band", row[0]);
      cell.appendChild(badge);
      tr.appendChild(cell);
      tr.appendChild(el("td", "pts", row[1]));
      tr.appendChild(el("td", "what", row[2]));
      bands.appendChild(tr);
    });
  }

  function bandHint(band) {
    var found = "";
    (SUM.band_ranges || []).forEach(function (row) {
      if (row[0] === band) found = band + " (" + row[1] + ") - " + row[2];
    });
    return found;
  }

  function signalHint(s) {
    return s.source + " - "
      + (s.weight > 0 ? "+" + s.weight + " points" : "informational")
      + "\\n" + s.detail;
  }

  function buildFooter() {
    var foot = document.getElementById("foot");
    foot.appendChild(el("div", null, "Reputation feeds used in this report:"));
    var table = document.createElement("table");
    Object.keys(SUM.feeds).forEach(function (key) {
      var feed = SUM.feeds[key];
      var tr = document.createElement("tr");
      tr.appendChild(el("td", null, feed.label));
      tr.appendChild(el("td", null, feed.available ? feed.entries + " entries" : "unavailable"));
      tr.appendChild(el("td", null, feed.age));
      table.appendChild(tr);
    });
    foot.appendChild(table);
    foot.appendChild(el("div", null,
      "Hosting/Cloud marks infrastructure networks. It is context, not a verdict: " +
      "legitimate services run there too."));
    foot.appendChild(el("div", null,
      "Map boundaries: Natural Earth 1:50m (public domain), simplified. " +
      "City markers use the coordinates reported for each address; they are an " +
      "approximation, not a precise position."));
  }

  function init() {
    initTheme();
    document.getElementById("meta").textContent =
      SUM.total + " addresses \\u00B7 generated " + SUM.generated +
      " \\u00B7 " + SUM.elapsed_seconds + "s" +
      (SUM.errors ? " \\u00B7 " + SUM.errors + " lookup errors" : "");

    document.getElementById("q").addEventListener("input", function (e) {
      state.q = e.target.value; render();
    });
    document.getElementById("fCountry").addEventListener("change", function (e) {
      state.country = e.target.value; render();
    });
    document.getElementById("fAsn").addEventListener("change", function (e) {
      state.asn = e.target.value; render();
    });
    document.getElementById("fSignal").addEventListener("change", function (e) {
      state.signal = e.target.value; render();
    });
    document.getElementById("fCity").addEventListener("change", function (e) {
      state.city = e.target.value; render();
    });
    document.getElementById("fRisk").addEventListener("change", function (e) {
      state.risk = e.target.value; render();
    });
    // Off -> country -> network -> off. Country comes first: this is a
    // geolocation report, and "which countries is this traffic from" is the
    // question people open it with.
    document.getElementById("group").addEventListener("click", function () {
      state.groupBy = state.groupBy === "" ? "country"
                    : state.groupBy === "country" ? "asn" : "";
      render();
    });
    document.getElementById("reset").addEventListener("click", function () {
      state.q = ""; state.country = ""; state.city = ""; state.asn = "";
      state.signal = ""; state.risk = ""; state.flagged = false; state.open = {};
      document.getElementById("q").value = "";
      render();
    });
    document.getElementById("copy").addEventListener("click", function (e) { copyIps(e.target); });
    document.getElementById("csv").addEventListener("click", exportCsv);
    document.getElementById("theme").addEventListener("click", function () {
      applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
    });

    buildReference();
    buildFooter();
    render();
  }

  init();
})();
</script>
</body>
</html>
"""


def generate_html_report(records, summary, file_path, map_uri=""):
    # ensure_ascii escapes every non-ASCII character, which includes U+2028 and
    # U+2029 -- valid in JSON but line terminators in JavaScript.
    payload = json.dumps({"summary": summary, "results": records})
    # Stop the JSON island from ending the script element early.
    payload = payload.replace("<", "\\u003c")
    view_box = "0 0 %d %d" % (MAP_WIDTH, MAP_HEIGHT)
    document = (
        HTML_HEAD.replace("__VIEWBOX__", view_box).replace("__MAP_PNG__", map_uri)
        + HTML_SCRIPT.replace("__DATA__", payload)
    )
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(document)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    print_logo()
    started = time.time()

    queryable, local, invalid = read_ips(input_file)
    total_input = len(queryable) + len(local) + len(invalid)
    if not total_input:
        fail("No IP addresses found in %s" % input_file)
        return 1

    info("%d unique addresses to process" % total_input)
    if local:
        info("%d non-routable address(es) flagged locally, no API call spent" % len(local))
    if invalid:
        warn("%d line(s) could not be parsed as an IP address" % len(invalid))
    if api_token in ("", "YOUR_API_KEY"):
        warn("No ipinfo.io token set - falling back to the anonymous rate limit")

    info("Loading reputation feeds...")
    intel = ThreatIntel().load()
    for feed in intel.provenance.values():
        if feed["available"]:
            ok("%s: %s entries (%s)" % (feed["label"], feed["entries"], feed["age"]))

    records = []
    if queryable:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(get_ip_info, ip, api_token): ip for ip in queryable
            }
            with ProgressBar(len(queryable), desc="Fetching IPs") as progress:
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        records.append(future.result())
                    except Exception as exc:  # never let one IP abort the run
                        records.append(
                            blank_record(ip, "error", "Unexpected failure: %s" % exc)
                        )
                    progress.update()

    for entry in local:
        records.append(blank_record(entry["ip"], "local", entry["reason"]))
    for entry in invalid:
        records.append(blank_record(entry["ip"], "invalid", entry["reason"]))

    ipapi_flags = {}
    if ENABLE_IPAPI_FLAGS and queryable:
        info("Fetching ip-api.com flags over plain HTTP (ENABLE_IPAPI_FLAGS is on)")
        ipapi_flags = fetch_ipapi_flags(queryable)

    for record in records:
        apply_scoring(record, intel, ipapi_flags)

    records.sort(key=lambda r: (r["country"] or "zz", r["city"], r["ip"]))
    summary = build_summary(records, intel, time.time() - started)

    info("Drawing the map...")
    geometry = cached_geometry()
    shapes = load_shapes(geometry) if geometry else []
    map_uri, map_meta = render_map_png(records, shapes)
    if map_meta:
        summary["map"] = {"edges": map_meta["edges"], "peak": map_meta["peak"]}
        ok("Map rendered: %d territories, %.0f KB"
           % (len(shapes), map_meta["bytes"] / 1024.0))
    else:
        summary["map"] = {"edges": [], "peak": 0}
        warn("No map in this report")

    save_to_csv(records, csv_output)
    generate_html_report(records, summary, html_output, map_uri)

    print()
    print("  %sAnalysed%s     %d addresses in %ss"
          % (C.BOLD, C.RESET, summary["total"], summary["elapsed_seconds"]))
    print("  %sGeolocated%s   %d addresses across %d countries and %d cities"
          % (C.BOLD, C.RESET, summary["located"], summary["unique_countries"],
             summary["unique_cities"]))
    print("  %sNetworks%s     %d distinct ASNs"
          % (C.BOLD, C.RESET, summary["unique_asns"]))

    if summary["top_countries"]:
        print()
        print("  %sTop countries%s" % (C.BOLD, C.RESET))
        widest = max(len(name) for name, _ in summary["top_countries"])
        peak = summary["top_countries"][0][1]
        glyph = "█" if UNICODE_OK else "#"
        for name, count in summary["top_countries"]:
            bar = glyph * max(1, int(round(20.0 * count / peak)))
            print("    %-*s  %s%s%s %d"
                  % (widest, name, C.CYAN, bar, C.RESET, count))

    if summary["flagged"]:
        band_colours = {
            "Critical": C.RED, "High": C.MAGENTA, "Medium": C.YELLOW,
            "Low": C.BLUE, "Clean": C.GREY,
        }
        parts = [
            "%s%s %d%s" % (band_colours[band], band, summary["bands"][band], C.RESET)
            for band in BANDS
            if summary["bands"][band] and band != "Clean"
        ]
        print()
        print("  %sReputation%s   %d address(es) matched a feed: %s"
              % (C.BOLD, C.RESET, summary["flagged"], "  ".join(parts)))
    if summary["errors"]:
        print("  %sErrors%s       %d lookup(s) failed - see the status column"
              % (C.BOLD, C.RESET, summary["errors"]))
    print()

    ok("Saved %s and %s" % (csv_output, html_output))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        fail("Interrupted")
        sys.exit(130)

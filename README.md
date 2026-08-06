# IPTracker0x

IPTracker0x is a bulk IP geolocation tool. It takes a list of IP addresses, resolves where each one is and what network it belongs to using the [ipinfo.io](https://ipinfo.io) API, and produces a self-contained HTML report along with a CSV.

As an add-on, each address is also checked against a handful of public reputation feeds, so you can tell at a glance whether any of them is worth a second look.

It runs on a stock Python 3.8+ interpreter. **There is nothing to install.**

<p align="center">
<img src="https://i.imgur.com/ouksnLX.png" alt="IPTracker0x running in the terminal">
</p>

## Features

- **No dependencies.** Standard library only — nothing to `pip install`. It does need network access, the same as any IP lookup tool.
- **Geolocation for every address**: city, region, country, coordinates, postal code, time zone, hostname, organisation and ASN.
- **World map**, drawn to a PNG by the script and embedded in the report — countries shaded by how many addresses are in them, plus a proportional circle per city. Hover for counts, click to filter.
- **Distribution at a glance**: top countries, top cities and top networks, ranked and clickable as filters.
- **Interactive report.** One HTML file with live search, combinable filters, column sorting, grouping by country or by network, and CSV export of whatever is on screen. No CDN, no external fonts, no network calls — it opens offline.
- **Input hygiene.** Addresses are validated, normalised and deduplicated. Private, reserved and special-use ranges are labelled locally without spending an API call.
- **Parallel lookups** with retries, backoff and explicit rate-limit handling.
- **Reputation check** against four public feeds, as a secondary signal.

## Usage

1. Put the addresses you want to analyse in `ips.txt`, one per line. Blank lines and `#` comments are ignored, and log-style lines are tolerated (the first field is used).
2. Run:

```bash
python IPTracker0x.py
```

3. Open `report_IPTracker0x.html` in a browser.

## Configuration

All settings live at the top of `IPTracker0x.py`.

### API key

ipinfo.io works without a token at a lower anonymous rate limit. With a free token you get 50,000 lookups per month:

```python
api_token = "YOUR_API_KEY"
```

> The token lives in the script itself, so replace it with the placeholder before committing.

### Threads

```python
max_workers = 10
```

## Output

### `report_IPTracker0x.html`

A single self-contained file:

- Coverage summary: addresses processed, geolocated, distinct countries, cities and ASNs.
- A world map with a dark palette: grey ocean, near-black land, countries shaded on a five-step scale by how many addresses sit there. The map is rendered to a PNG by the script itself — no imaging library, just `zlib` — and embedded in the report as a data URI, so it stays a single file. Each city is marked with a translucent red circle whose **area** is proportional to how many addresses sit there, so a circle twice as wide stands for four times as many. The translucency is the point: where places pile up the overlaps darken gradually and dense regions read as dense, instead of the map disappearing under a wall of markers — which is exactly what happened with pins at 10,000 addresses. A size key in the legend gives the scale.
- The map keeps its dark palette in both themes, the way an embedded panel does.
- Ranked distribution panels for countries, cities and networks — click any bar to filter.
- A sortable table led by location, with an expandable row per address showing the full geolocation detail (city, region, country, postal code, time zone, coordinates with an optional map link, hostname and network).
- A built-in **"What are signals and risk bands?"** panel explaining every signal, its source and its weight, plus what each band means. It is generated from the script's own weights, so it can never fall out of step with the code. Hovering a chip explains that specific match; expanding a row shows the full evidence.
- Grouping by country or by network, for answering "where is this traffic coming from" in one click.

Values coming from the network are delivered as a JSON island and written to the DOM as text, never as markup — hostnames come from PTR records the owner of the IP controls.

### `results_IPTracker0x.csv`

`ip, hostname, city, region, country, country_code, loc, postal, timezone, org, asn, asn_org, asn_type, risk_score, risk_band, signals, status, note`

Fields that begin with a spreadsheet formula character are prefixed with `'` so Excel does not evaluate attacker-controlled strings.

The `status` column distinguishes `ok`, `error` (the lookup failed — the reason is in `note`), `local` (non-routable) and `invalid` (unparseable input), so a failed lookup is never mistaken for an address with no data.

<p align="center">
<img src="https://i.imgur.com/5Pxz43L.png" alt="HTML report: world map and distribution panels">
<img src="https://i.imgur.com/xx6Qp3M.png" alt="HTML report: the address table with risk signals">
</p>

## The reputation add-on

Beyond geolocation, each address is checked against four public feeds. None of them needs an API key.

A **signal** is one match: a named fact from a named source, worth a fixed number of points. Points add up to a score out of 100, and the score falls into a **band**. An address that matches nothing scores zero and is simply `Clean`. Every point is traceable to a feed, so the report shows *why* something was flagged rather than a bare yes/no — and the report carries this same table inside it, so whoever opens it does not need the README.

| Signal | Points | Source |
|---|---|---|
| Address inside a Spamhaus DROP netblock | +50 | [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| Listed on 5 or more public blocklists | +40 | [IPsum](https://github.com/stamparm/ipsum) |
| Listed on 3–4 public blocklists | +30 | IPsum |
| Listed on 1–2 public blocklists | +15 | IPsum |
| Current Tor exit node | +25 | [Tor Project](https://check.torproject.org/torbulkexitlist) |
| Belongs to a cloud/hosting/colo ASN | +10 | [bad-asn-list](https://github.com/brianhama/bad-asn-list) |
| Anycast, mobile carrier, non-routable | 0 | ipinfo.io / local |

Bands: `Clean` 0 · `Low` 1–24 · `Medium` 25–49 · `High` 50–74 · `Critical` 75+.

### A note on the hosting/cloud ASN list

The list this project uses is named "bad-asn-list", but its author describes it as *ASNs known to belong to cloud, managed hosting and colo facilities* — it is not a list of malicious networks. AWS, Google Cloud and Cloudflare are all on it.

That is why it contributes only 10 points here and is labelled **Hosting/Cloud**, not "bad". It tells you the address is infrastructure rather than a residential or mobile subscriber, which is useful geolocation context: a datacenter address does not tell you where the person behind it actually is.

Feeds are cached in `.iptracker_cache/` for 24 hours, which also respects Spamhaus's request of no more than one download per day. If a feed cannot be reached, the run continues using the cached copy and the report says so.

The country boundaries the map is drawn from are fetched the same way, rather than shipped inside the script. If they cannot be downloaded and no cached copy exists, the report is still produced — just without the map.

### Optional ip-api.com flags

`ENABLE_IPAPI_FLAGS` adds proxy/VPN, hosting and mobile-carrier flags from ip-api.com. It is **off by default**: the free tier of that service is HTTP only, so enabling it sends the addresses you are looking up over the network in clear text. Turn it on only if that trade-off is acceptable for your work.

## Credits

- [ipinfo.io](https://ipinfo.io) for IP geolocation and ASN data.
- [Natural Earth](https://www.naturalearthdata.com/) for the public-domain 1:50m country boundaries the map is drawn from.
- [brianhama](https://github.com/brianhama/bad-asn-list) for **bad-asn-list**.
- [stamparm](https://github.com/stamparm/ipsum) for **IPsum**.
- [The Spamhaus Project](https://www.spamhaus.org/) for the **DROP** list.
- [The Tor Project](https://www.torproject.org/) for the bulk exit list.

Each feed is distributed under its own terms; review them before using this tool commercially.

## License

This project is open source and distributed under the MIT license.

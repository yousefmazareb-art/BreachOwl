# BreachOwl

A small Flask web app that checks whether common ports are open on a target host. Built as a learning project for network and web security.

> **Legal notice:** only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal where you live.

## What it does

- Resolves a hostname (or accepts an IP address).
- Checks six common ports with a 1 second timeout each: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 3389 (RDP).
- Shows which ones are open, in a simple results table.

## Run it locally

```bash
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000.

To scan machines on your own network (for example a home lab), start it with:

```bash
BREACHOWL_ALLOW_PRIVATE=1 python app.py
```

By default, private and internal addresses are blocked.

## Security hardening

The first version had problems, which I found and fixed in a review:

| Problem | Fix |
| --- | --- |
| `debug=True` exposes Flask's interactive debugger | Debug is off unless `FLASK_DEBUG=1` is set |
| User input was placed straight into the HTML response (reflected XSS) | Output goes through Jinja templates, which escape it automatically |
| Any input was accepted as a target | Only valid hostnames and IP addresses are allowed |
| The server could be used to probe internal networks | Private, loopback and link-local addresses are blocked by default |
| DNS could change between the check and the scan | The scan uses the exact IP that was checked |
| No consent step | The form requires confirming permission to scan |

## Known limitations

- Scans ports one at a time, so it is slow.
- Only TCP connect scans, with no service detection.
- No rate limiting or login, so do not expose it publicly.

## Ideas for next versions

- Concurrent scanning with a thread pool.
- Custom port ranges.
- Banner grabbing for service detection.
- Rate limiting and CSRF protection.
- Export results to JSON.

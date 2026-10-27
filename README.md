# Email address checker

A small Flask web app. Paste a list of email addresses and each one is reported as
**Likely delivered**, **Likely to bounce**, or **Unknown**, with a plain-language reason.

- **Live app:** `<ADD RENDER URL>`
- **Source:** `<ADD GITHUB URL>`

## How it works

Each address goes through up to three stages (`verifier.py`):

1. **Syntax.** Checks for one `@`, valid characters, length limits (64 / 254), and a well-formed domain.
   Failure means *likely to bounce*.
2. **DNS.** Looks up the domain's MX records, falling back to its A/AAAA record as RFC 5321 requires.
   Non-existent domain, no mail server, or a "null MX" (`.`) means *likely to bounce*.
   Common typo domains (`gmial.com`, `gmail.con`, ...) are flagged with a suggestion.
3. **SMTP probe.** Connects to the domain's mail server on port 25 and runs `MAIL FROM:<>` then
   `RCPT TO:<address>`, then `RSET`/close. **`DATA` is never sent, so no message is delivered to anyone.**
   The server's reply decides the result:

| Server reply | Result |
|---|---|
| `250` accepted | Likely delivered |
| `550/551/553` "no such user" | Likely to bounce |
| Accepts a random made-up address too (catch-all) | Unknown |
| `4xx` temporary / greylisting, policy or reputation blocks (`5.7.x`), mailbox full, timeout, connection refused | Unknown |

Addresses are grouped by domain, so each mail server gets one connection at a time, and one
connection is reused for all addresses on that domain. Input is capped at 50 addresses per request.

### Why "Unknown" is common

Many providers (and most corporate gateways) accept every `RCPT` to avoid leaking which mailboxes
exist, or refuse to answer verification probes from unknown IPs. A "likely delivered" result is a
strong signal, not a guarantee, and "unknown" means exactly that: the tool could not tell.

## What the deployed version can and cannot check

Many hosts, including free tiers of Render, Railway and PythonAnywhere, block outbound connections
to port 25. The app tests this on startup (and every 10 minutes) by trying to reach a public mail
server, and shows a banner in the UI saying which mode it is in:

| Mode | Syntax | Domain exists / has mail server | Mailbox exists |
|---|---|---|---|
| **Full** (port 25 open) | yes | yes | yes, via SMTP probe |
| **DNS-only** (port 25 blocked) | yes | yes | **no**: valid addresses on real domains show as Unknown |

In DNS-only mode the tool can still confidently flag malformed addresses, typos, and dead domains
as likely to bounce. To get full checks, run it locally from a home or office network that allows
port 25, or on a VPS that permits outbound SMTP. Set `SMTP_PROBE=off` to force DNS-only mode.

> Update this section after deploying with the mode your live link actually shows.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py          # http://127.0.0.1:5000
pytest                 # unit tests (no network needed)
```

Optional environment variables: `SMTP_PROBE=off|auto` (default `auto`), `HELO_HOST` (name sent in
`EHLO`; set this to a real hostname for better results from strict servers).

## Deploy on Render (free)

1. Push this repo to GitHub.
2. In Render: **New > Web Service**, connect the repo. It reads `render.yaml`
   (build: `pip install -r requirements.txt`, start: `gunicorn app:app`).
3. Open the `onrender.com` URL and read the banner to see which mode you got.

## Responsible use

Only the mail server of each address's domain is contacted, and only to ask whether it would accept
the recipient. No message body is ever transmitted. Even so, don't run large lists against domains
you don't own: repeated probes can get your IP rate-limited or listed. This tool is a hygiene check,
not a guarantee of delivery.

## Files

`app.py` (routes) · `verifier.py` (all checking logic) · `templates/index.html` (UI) · `tests/` · `render.yaml` / `Procfile` (deploy)

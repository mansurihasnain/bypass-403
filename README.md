# bypass-403.sh

An enhanced **403 / access-control bypass** tester with an important twist: it first tells
you **whether your 403 is application-layer or web-server-layer**, because that determines
whether path/method/header bypass tricks are even the right tool.

> Original concept by **Iam_J0ker** — this is the "Enhanced v2" continuation.

```
  ___                           _ _   __ ____
 | _ )_  _ _ __  __ _ _________| | | /  \__ /
 | _ \ || | '_ \/ _` (_-<_-<___|  _  | () |_ \
 |___/\_, | .__/\__,_/__/__/    |_|  \__/___/
      |__/|_|
```

---

## Why the "layer" matters

A `403` can come from two very different places:

| Layer | Who sent it | Example | Do bypass tricks help? |
|-------|-------------|---------|------------------------|
| **WEB-SERVER** | nginx/Apache/IIS/WAF/ACL in front of the app | default nginx `403 Forbidden` page, F5 "Request rejected" | **Yes** — path/header/method tricks can bypass sloppy proxy rules |
| **APPLICATION** | the app itself (auth/permission check) | Django/DRF `{"error":...}`, a branded login/denied page | **No** — needs a real auth flaw or a valid session |

The tool fetches the response, classifies it, and warns you before you waste time fuzzing
an app-layer auth check.

---

## Features

- **403 layer detection** — APPLICATION vs WEB-SERVER (with the matching evidence).
- **Classify-only mode (`-c`)** — quickly triage the 403 type for a whole list of URLs.
- **Flexible input** — single target, a `.txt` list (`-l`), or piped via **STDIN**.
- **Batch mode** — many targets in one run, with a combined layer breakdown.
- **~200 bypass techniques** — path manipulation, HTTP methods, IP/proxy headers,
  URL-encoding, unicode/normalization, protocol/port, case, double headers, Wayback.
- **False-positive guard** — flags results whose size equals the baseline 403.
- **Redirect-following is OFF by default** — avoids the SPA-catch-all "302 → /app" being
  reported as a bogus `200` bypass (`-r` to re-enable).
- **Colored, tee'd output** that's both screen-readable and saved to a file.

---

## Requirements

- `bash` 4+ (uses arrays, `read`, process substitution)
- `curl`
- `jq` *(optional)* — for the Wayback Machine lookup
- `figlet` *(optional)* — for the banner

No Python required.

---

## Installation

```bash
chmod +x bypass-403.sh
# optional: put it on your PATH
sudo cp bypass-403.sh /usr/local/bin/
```

---

## Quick start

```bash
# Single target + path
./bypass-403.sh https://target.com admin

# Full URL form
./bypass-403.sh https://target.com/admin

# Is this 403 app-layer or web-server? (just classify)
./bypass-403.sh -c https://target.com/admin

# A whole list, from a file
./bypass-403.sh -l targets.txt

# A whole list, piped
cat targets.txt | ./bypass-403.sh
waybackurls target.com | ./bypass-403.sh -l -
```

---

## Usage

```
./bypass-403.sh [options] https://target.com path
./bypass-403.sh [options] https://target.com/path
./bypass-403.sh [options] -l targets.txt
cat targets.txt | ./bypass-403.sh [options]
some-cmd | ./bypass-403.sh -
```

### Input

| Flag | Description |
|------|-------------|
| `-l, --list <file>` | Read targets from a file (one per line). A FIFO/process substitution also works. |
| `-` | Read targets from STDIN (also auto-detected when the tool is piped). |

### Options

| Flag | Description |
|------|-------------|
| `-t, --threads <num>` | Parallel jobs (default: `10`) |
| `-T, --timeout <sec>` | Per-request timeout (default: `10`) |
| `-f, --filter <codes>` | Only show these status codes (e.g. `200,301,302`) |
| `-o, --output <file>` | Output file (default: auto-named) |
| `-a, --all` | Show everything, including `403`/`404`/`000` |
| `-c, --classify-only` | Classify the response layer only — no fuzzing |
| `-r, --follow-redirects` | Follow redirects (default: **off**) |
| `-h, --help` | Help |
| `--version` | Show version |

Every long option also accepts the `=` form, e.g. `--timeout=15 --filter=200,302`.

### Target line formats

Each line in a list / on STDIN can be:

```
https://target.com path        # URL + path (space or tab separated)
https://target.com/path        # full URL — path is split automatically
target.com/path                # scheme defaults to https
# comment lines and blank lines are ignored (CRLF is handled)
```

---

## Understanding the output

A normal run starts with a baseline classification:

```
Baseline: HTTP 403  size: 61 bytes  ctype: application/json  server: none
Baseline layer: APPLICATION  (json/structured error body)
!! APPLICATION-layer 403 (auth/permission), not a web-server ACL.
   Path/method/header 403-bypass tricks below mostly defeat WEB-SERVER 403s.
   App-layer 403 usually needs a real auth flaw or a valid session.
```

Then each result line:

```
  [200] size:1337     time:0.121s   https://target.com/admin/..;/     [possible FP — same size as baseline]
  [403] size:61       time:0.098s   https://target.com/admin [-X PUT] [layer:APPLICATION]
```

- **`size`** — response body size in bytes.
- **`[possible FP — same size as baseline]`** — the response matches the baseline 403 size;
  treat with suspicion (often a catch-all).
- **`[layer:...]`** — shown on `401`/`403` results, using the baseline's layer.
- Colors: green `200`, yellow `301/302/307`, red `401/403`, magenta `5xx`.

### Classify-only mode

```console
$ cat urls.txt | ./bypass-403.sh -c
  [403] https://target.com/admin/api/   layer=APPLICATION size=61    ctype=application/json
  [403] https://target.com/secret       layer=WEB-SERVER  size=153   ctype=text/html
  [200] https://target.com/             layer=n/a         size=2270  ctype=text/html

Layer breakdown (app vs web-server):
  1 x layer=APPLICATION
  1 x layer=WEB-SERVER
```

### How the classifier decides

Checked in this order:

1. `application/json` or a structured `{"error|detail|status_code|message": ...}` body → **APPLICATION**
2. WAF/block-page signatures (F5 "The requested URL was rejected", "Support ID",
   Imperva, ModSecurity, Barracuda, …) → **WEB-SERVER**
3. Stock server error pages (`<center>nginx</center>`, `Apache/2.x`, `Microsoft-IIS`,
   `<title>403 Forbidden</title>`, openresty, LiteSpeed) → **WEB-SERVER**
4. App-framework markers (Django, DRF, CSRF, `Log in`, ASP.NET, app brand) → **APPLICATION**
5. Full HTML "app chrome" pages (`<html`/`<script`/`stylesheet`/`<form`/`StatusCode:`/`Request ID:`) → **APPLICATION**
6. `Server:` header of a known server + a generic "Forbidden" body → **WEB-SERVER**
7. otherwise → **UNKNOWN**

The classifier only runs for `401`/`403` responses; other codes show `layer=n/a`.

---

## What it tests (the fuzzing sections)

| # | Section | Examples |
|---|---------|----------|
| 1 | Path manipulation | `/path/.`, `//path//`, `/path..;/`, `/path%20` |
| 2 | HTTP method bypass | `PUT PATCH DELETE OPTIONS TRACE HEAD CONNECT PROPFIND`, POST + `Content-Length: 0` |
| 3 | Header bypasses | `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization`, `Forwarded`, ~58 variants |
| 4 | Encoded path payloads | `%2e%2e`, `%2f`, `..;`, `%00`, double-encoding |
| 5 | Unicode / normalization | fullwidth slash, overlong UTF-8, `%u2215` |
| 6 | Protocol / port variation | `http`/`https` on `80,443,8080,8443,8000,8888` |
| 7 | Case variation | `/ADMIN`, `/Admin` |
| 8 | Double header / combination | `X-Forwarded-For` + `X-Original-URL`, `CF-Connecting-IP` + `X-Real-Ip` |
| 9 | Wayback Machine | checks `archive.org` for a snapshot |

> Note: **`-c` classify-only** runs none of these — it makes exactly one request per target.

---

## Examples

```bash
# Fuzz, only show genuine 2xx/3xx hits, save to a file
./bypass-403.sh -t 20 -f 200,301,302,307 -o out.txt https://target.com admin

# Show everything including 403/404 (to eyeball behavior)
./bypass-403.sh -a https://target.com admin

# Triage 500 URLs to see which 403s are app-layer vs web-server
cat urls.txt | ./bypass-403.sh -c -o triage.txt

# Bulk fuzz every URL that returned a web-server 403
grep 'layer=WEB-SERVER' triage.txt | awk '{print $NF}' | ./bypass-403.sh -f 200,302

# Follow redirects if the app relies on them
./bypass-403.sh -r https://target.com admin
```

---

## Notes & gotchas

- **Redirects are not followed by default.** Many apps have a catch-all that redirects
  unknown paths to a SPA/login page; following it turns every `302` into a fake `200`.
  Use `-r` only when you actually need redirect-following.
- **User-Agent matters.** Some targets render a different 403 (HTML portal page vs JSON)
  depending on the client. The tool sends browser-like UAs by default; if you suspect a
  WAF/proxy is keying off the UA, test manually with a couple of UAs.
- **Rate limiting / WAF.** A full run is ~200 requests per target. Use a lower `-t` and a
  higher `-T` against sensitive or rate-limited hosts.
- **`403` vs `404`.** The tool hides both by default (use `-a`); a `302 → login` is often
  the real "denied" signal.
- **Multiple targets** are processed sequentially; each target runs the full suite.

---

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| Every result is a fake `200` | The app has a SPA catch-all — keep redirect-following **off** (default) and filter by size |
| `layer=UNKNOWN` everywhere | Neither signature matched; inspect manually with `curl -D -` |
| `no target supplied` | Give `URL path`, use `-l <file>`, or pipe input |
| `jq not found` | Install `jq` (only affects the Wayback section) |
| Timeouts on `8080/8888` | Normal — those ports are usually closed; raise `-T` or ignore |

---

## Legal

For **authorized** security testing only — bug-bounty scopes, pentests, or systems you own.
Unauthorized use is illegal. You are responsible for staying within scope.

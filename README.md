# cfscan

A friendly, beginner-friendly terminal app that wraps the scanner you already
have: **[XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest)**
(`cfst`). cfscan does not re-implement scanning - it builds safe argument lists
for `cfst`, hides its Chinese output behind a short English progress line,
parses the CSV it produces, and ranks the results.

* Standard library only (Python 3.9+), no TUI framework, no dependencies
* English everywhere: interface, messages, errors and comments
* Never uses a shell for the scanner, never stores secrets, never touches your
  DNS or VPN settings

---

## Installation

Requirements: macOS with `cfst` installed (for example
`brew install cloudflare-speedtest` or the release binary from the upstream
project) and Python 3.9 or newer.

```sh
cd /path/to/cfscan
./install.sh
```

The installer copies the package to `~/.local/share/cfscan/lib` and creates the
launcher `~/.local/bin/cfscan`. If `~/.local/bin` is not on your `PATH`, the
installer prints the one line to add to your shell profile.

### Working on the code: the live link

While you are editing cfscan, a copied install is in the way - every change
would need a copy step before the terminal saw it. Link the command to this
folder once instead:

```sh
./dev-link.sh
```

It rewrites `~/.local/bin/cfscan` so the command imports the package straight
from this folder. From then on every edit is live on the very next `cfscan`
run: no copy, no update step, nothing to remember. `cfscan --version` prints
the folder it is running from, so "is my change live?" is a question the
output answers:

```
cfscan 1.4.0
dev link: /path/to/cfscan/cfscan (edits are live)
```

The link writes no `__pycache__` folders into the sources, and it refuses to
run (with a clear message) if the project folder is ever moved or deleted
rather than silently running old code.

### Going back to a copied install

`./install.sh` replaces the link with a normal copied install at any time.
After that, changes need the copy step again:

```sh
./update.sh
```

It removes the previous install, installs the current files, checks that the
installed package matches this folder byte for byte and prints the version. Your
configuration and results are never touched.

To install with pip/pipx instead:

```sh
pipx install .
# or
python3 -m pip install --user .
```

## Usage

```sh
cfscan                       # interactive menu (recommended)
cfscan --quick --yes         # scan with the active profile right away
cfscan --quick --dry-run     # print the exact cfst argument list, run nothing
cfscan --quick --no-verify-top  # scan without the strict check of the best ten
cfscan --verify 104.16.0.1  # strict 20-attempt check of one address
cfscan --profile office      # use another saved profile (menu or one-shot run)
cfscan --show-last           # show the newest saved result
cfscan --list-profiles       # list saved profiles
cfscan --make-pool 2000      # fix the candidate list every carrier round shares
cfscan --isp mci             # measure one carrier against that list
cfscan --multi-isp           # print the multi-carrier report of the session
cfscan --colo FRA,AMS        # keep only those datacentres, for this run only
cfscan --colo any            # ignore the profile's filter, measure everything
cfscan --update-ranges       # download Cloudflare's current IP range lists
cfscan --edges               # rank the datacentres from what you measured
cfscan --no-preflight        # skip the one-address check made before a scan
cfscan --direct              # ignore proxy variables (cfst and the new probes)
cfscan --quick --download    # second pass: download a large file through each address
cfscan --quick --upload      # POST an upload sample through each address
cfscan --quick --no-jitter   # latency and loss only, no jitter samples
cfscan --isp mci --note 4g   # label a carrier round with the access type
cfscan --multi-isp --session FILE   # report a specific stored session
cfscan --no-color            # plain output
cfscan --version
cfscan --help
```

One command per run: combining two of them is refused instead of silently
running whichever comes first.

### The menu

```
==================================================================
  cfscan 1.4.0  clean Cloudflare IP finder
==================================================================
  Profile   node.example.com
  Target    node.example.com   port 443  IPv4  HTTPing/https  only FRA,AMS
  Ready     cfst ready  ip.txt 14 ranges, 2026-09-17
  Last run  104.16.142.237  16 Sep 12:21  (7 saved IP(s) in menu 3)
------------------------------------------------------------------
  Scan
    1. Quick Scan            scan the range with the active profile
    2. Custom Scan           ask for every setting, then scan
   10. Multi-carrier scan    compare carriers on one fixed candidate list
  Check one address
    3. Verify an IP          re-check a saved address, or any address you type
  Results
    4. Show Last Results     the newest saved result file
    8. Open Results Folder   reveal the CSV and log files in Finder
  Setup
    5. Show Saved Profiles   what is stored and which one is active
    6. Add or Edit Profile   add, edit, activate or delete a profile
    7. Switch IPv4 / IPv6    switch the active profile's address family
   11. Update IP ranges      download Cloudflare's current range lists
   12. Edge locations        rank the datacentres, or clear the filter
    9. Help                  what every setting means
    0. Exit
------------------------------------------------------------------
```

The block above the list is the state a scan depends on, so a missing scanner,
a missing range file or a range file that is years old is visible **before**
anything is chosen rather than seconds into a run.

**Quick Scan** shows the active profile, asks for confirmation, runs `cfst`,
then prints a ranked table:

```
#  IP address       Sent  Received  Loss  Latency    Colo
-- ---------------- ---- --------- ----- ---------- ----
 1  104.16.0.1 * 4    4         0%    438.32 ms  -
 2  172.67.213.151   4    3         25%   512.10 ms  SJC
```

Then the ten best addresses are **re-measured before you see them**: one extra
scanner run pings those ten addresses with 20 attempts each and cfscan marks
every line with the result of that check:

```
Top 10 IPs you can use
----------------------
  1. PASS 104.19.10.61     146.09 ms   0%  FRA  Port 2087  SNI/Host node.example.com  *
  2. PASS 104.18.210.173   149.02 ms   0%  FRA  Port 2087  SNI/Host node.example.com
  3. FAIL 162.159.206.2    149.74 ms  15%  FRA  Port 2087  SNI/Host node.example.com
  4. DEAD 104.20.126.138          -     -  -    Port 2087  SNI/Host node.example.com
 10. PASS 104.25.79.140    154.96 ms   0%  FRA  Port 2087  SNI/Host node.example.com
```

* **PASS** - every one of the 20 attempts was answered, 0% packet loss. Safe to
  use right now.
* **FAIL** - packets were lost; the line shows how many answered.
* **DEAD** - not one attempt came back, so the address belongs to a bad moment.

If *every* line comes back DEAD, the check happened while your connection was
busy (a scan saturates the link for a moment) or the origin stopped answering;
the scanner log next to the check records the reason, and menu 3 re-measures a
single address in seconds.

Every line is complete, so any of them can be pasted into a client without
cross-checking the profile: put the IP in **Address**, keep the port shown, and
set **SNI** and **Host** to the domain. The fastest **PASS** line is marked with
`*` and repeated above the list as the recommended address - a measurement from
seconds ago, not a guess. `Ctrl+C` during the check skips it and leaves the scan
view untouched; `--no-verify-top`, or `"verify_top_ips": false` in a profile,
turns the whole step off.

The scanner is asked for at least ten results (a profile with a smaller
`results_limit` still gets `-p 10`), so ten candidates are on offer whenever ten
of them pass the filters. Menu 4 lists every row of the saved file. Change how
many are offered with `top_ips` in the profile.

**Verify an IP** runs `cfst` against a single address with 20 attempts and a
generous latency cap, and the address passes only when every attempt is answered
(0% packet loss). The scanner is asked to report the address even when it is
lossy (`-tlr 1`), so cfscan judges the numbers itself - a failure comes with its
measurements (`Replies 17/20, packet loss 15%`, `HTTP status 520 observed while
400 was required`, ...) instead of the scanner silently dropping the address.

**Multi-carrier scan** (menu 10) answers a different question: *which address
works on several networks?* A clean address is a property of the line, not of
the address - MCI, Irancell and Mokhaberat filter ranges and ports differently -
so one scan on one connection cannot tell you that. The wizard asks how many
carriers you have and what to call each, then runs one round per carrier and
**waits between rounds** so you can switch the connection:

```
How many carriers do you want to measure? [2]:
Name of carrier 1 [mci]:
Name of carrier 2 [irancell]:
Candidate list: pool-ea0244573a2f45c6.txt (168 addresses over 21 prefixes)

Round 1 of 2 - mci
Switch this Mac to mci (hotspot, SIM or router) now.
Press Enter to start the mci round:
+ 7 address(es) verified on mci - fastest 104.21.171.224 (132 ms).

Round 2 of 2 - irancell
...
```

Every round measures **the same addresses**: the scanner draws a fresh random
sample from the range file on each run (measured: 5,955 of 1,524,480 addresses,
and two runs of the same profile shared no address at all), so two carriers
would otherwise measure different candidates and nothing could be compared. The
wizard therefore fixes one candidate list once - a deterministic sample spread
over many `/24` prefixes, with its seed kept in the session - and reuses it.

The report has three sections:

* **1. Best on every carrier** - addresses that passed the strict check on *all*
  of them, ranked by **worst-case** latency, not average. An address that is
  150 ms on one carrier and 600 ms on another loses to one that is 200 ms on
  both, even though its average is better.
* **2. Fastest verified address per carrier** - for whoever is on that line.
* **3. Partial coverage** - when nothing passed everywhere: the addresses that
  reach the most carriers.

Then one line says what to use, with the client fields. Rounds are stored as
they finish under `~/Documents/Cloudflare Scanner Results/multi-isp/<domain>/`,
so a dropped hotspot costs one round and not the session; `cfscan --multi-isp`
prints the report again from the stored file, and a CSV copy of it sits next to
it. Re-measuring a carrier replaces its round and keeps the others.

The same thing step by step, for scripting: `cfscan --make-pool 2000` writes the
candidate list, `cfscan --isp mci --pool <file>` measures one carrier, and any
further `--isp NAME --pool <file>` continues the same session.

### What happens after a test

Every flow (quick scan, custom scan, verify, last results) prints its full
output and then repeats the verdict in one short block, so the result is what
you see last:

```
----------------------------------------------------------------
[PASS] Verify 104.16.0.1 - PASS
  104.16.0.1 answered 20/20 attempts, 0% packet loss
  Average latency 431.07 ms    Colo FRA
  Client fields - Address 104.16.0.1, Port 2087, SNI node.example.com,
  Host node.example.com

Press Enter to return to the menu:
```

Press Enter and the menu comes back, so you can rank another round, verify the
winner, or look at the saved file without restarting cfscan. When the output is
piped (no terminal), the pause is skipped so scripts behave exactly as before.

`Ctrl+C` cancels the step you are in and returns to the menu - it no longer
closes cfscan. Pressing it at the menu prompt itself (or choosing `0`) is what
leaves the program. One-shot commands (`cfscan --quick`, `cfscan --verify IP`)
print their result and exit, which is what a script wants.

### Picking the datacentre

Cloudflare answers from the datacentre nearest to your line, and which one that
is decides the latency far more than the address does. A region filter keeps
only the addresses whose datacentre you name:

```sh
cfscan --colo FRA,AMS --quick --yes     # this run only
```

Menu 2 asks for it as well, and stores it on the profile. Measured on one line
here:

| Scan | Result |
| --- | --- |
| no filter | 1,385 addresses in GYD (Baku), 190 in SOF, 53 in ARN, **2 in FRA** |
| `-cfcolo FRA,AMS,LHR` | **36 addresses, all FRA or LHR**, 138-150 ms |

**Which datacentres to name is not a question of distance.** On the line above,
the nearest datacentre of all is the slowest:

| colo | samples | min | median |
| --- | --- | --- | --- |
| SOF (Sofia) | 299 | 155 ms | **172 ms** |
| FRA (Frankfurt) | 1,707 | **134 ms** | 176 ms |
| MUC (Munich) | 791 | 147 ms | 186 ms |
| **GYD (Baku)** | 2,771 | 214 ms | **232 ms** |
| IAD (Washington) | 5 | 304 ms | 363 ms |

What decides the number is the route the carrier takes, not the kilometres. So
cfscan does not guess the filter from a map - see **Ranking the edge locations**
below.

The filter needs HTTPing with `scheme: https`, because it reads the datacentre
out of the edge's `CF-RAY` header. TCPing never reads a header, and plain HTTP
to an HTTPS port makes the edge answer its own 400, whose `CF-RAY` is empty
(measured: `CF-RAY: -`) - so in both cases the filter would silently drop every
address. cfscan refuses to set up that combination and says why instead.

Verification is never filtered. The question there is whether one address still
answers, so an address that moved to another datacentre is reported as having
moved rather than as dead.

**Turning it off is always one choice away.** Menu 2 and menu 12 both offer
*"measure every datacentre"* as a choice on screen, menu 6 edits it without
running a scan, and one run can ignore a saved filter entirely:

```sh
cfscan --colo any --quick --yes     # the saved profile is not touched
```

### When no address can work: a missing certificate

A hostname the edge has no certificate for fails in a way that looks exactly
like a dead network. The scanner cannot tell them apart - its Go client wraps
the TLS alert in its own timeout, so the log says `context deadline exceeded`
for both - so cfscan asks the question a second way. Plain HTTP to an HTTPS
port is answered by Cloudflare itself and needs no certificate, so an address
that answers *that* while failing the TLS probe settles it:

```
x The edge answers for ws.node.example.com over plain HTTP but refuses TLS for
  it, so this is a certificate problem, not an address problem.
  - No clean IP can fix it. ...
```

The usual cause is depth. A TLS wildcard matches **exactly one label**, and
Cloudflare's Universal SSL issues only the zone and `*.zone`:

| hostname | labels below the zone | covered by `*.example.com` |
| --- | --- | --- |
| `node.example.com` | 1 | yes |
| `edge.example.com` | 1 | yes |
| `ws.node.example.com` | **2** | **no** |

The ways out are a hostname one level below the zone, Cloudflare's Advanced
Certificate Manager / Total TLS, or a certificate you install on the zone
yourself. Setting `scheme: http` is **not** one of them:
it makes the scan produce rows again while the client still cannot connect, so
cfscan says so rather than letting it look like a fix.

### Ranking the edge locations

Every scan records which datacentres answered and how fast. Menu 12 (or
`cfscan --edges`) turns that history into an order, and offers the filter that
follows from it:

```
 #  Colo  Typical    Best  Loss-free  Addresses  Scans  Note
--  ----  -------  ------  ---------  ---------  -----  -------
 1  SOF    171 ms  155 ms       100%        299      2
 2  FRA    190 ms  134 ms       100%        156      2
 3  GYD    233 ms  214 ms       100%       2771      2
 4  LHR    331 ms  324 ms       100%          2      1  too few

Suggested region filter: SOF,FRA
```

*Typical* is the median of each scan's median, so one bad scan cannot move it.
A row marked *too few* has not been measured enough to mean anything and never
wins, so two lucky addresses cannot outrank a datacentre measured a thousand
times. On a profile with no history yet, the scoreboard is built from the
result files already in the results folder.

Two things keep it honest rather than merely convenient:

**A score belongs to the line that measured it.** A scan taken through a tunnel
describes the tunnel's path, not this machine's own connection, and mixing the
two produces a ranking that is true of neither. Every entry is labelled with
the line it came from, and the screen says which line it is describing.
Tunnels are grouped by kind rather than by number, because macOS hands out
`utun18` today and `utun19` tomorrow for the same tunnel.

**A filter narrows what can be learned.** Once one is applied, later scans only
ever see the datacentres it allows, so a colo that becomes good can never be
discovered again. Entries record the filter they ran under, and the screen
warns when the picture has stopped refreshing.

### Scanning through a tunnel

When this Mac's default route is a tunnel, the scanner measures the path
through it and out of its exit - so the address it recommends is the best one
*for that tunnel*, which is rarely what a clean IP is wanted for. cfscan says
so before the first scan of a session:

```
! This Mac's default route is a tunnel (utun19), so the scan measures the path
  through it and out of its exit - not this machine's own connection.
```

`--direct` does not help here: it clears this shell's proxy variables and
cannot change a system route. Turn the tunnel off to measure the real line.

TCPing is meaningless while a tunnel is up, because a TUN-mode client answers
the TCP handshake locally. Measured on one such line: the handshake came back
in **0.4 ms** while the TLS handshake to the same address took **920 ms**.

### Addresses you already proved

A full scan measures thousands of addresses to offer ten. Those ten are the
cheapest candidates tomorrow, so every address that passes the strict check is
saved on its profile, and menu 3 offers the list before it asks you to type
anything:

```
Saved good IPs for node.example.com
#  IP address       Latency  Colo  Proven
-- ---------------- -------- ----- --------
 1  104.16.142.237    134 ms  FRA   2 h ago
 2  172.64.78.249     149 ms  FRA   2 h ago

Number from the list, 'all' to re-check every saved address, or an IPv4 address:
```

`all` re-measures the whole list in **one** scanner run - seconds, where
finding those addresses cost a full scan. An address that fails today is kept
rather than dropped: the same address is often the fastest one an hour later.

### Keeping the IP ranges current

A range that is missing from the range file is never scanned, so that file
decides which part of Cloudflare's edge can be found at all. The list shipped
with the scanner is a snapshot - the one on this Mac was written in January
2023. Menu 11 (or `cfscan --update-ranges`) downloads what Cloudflare publishes
today.

It **merges** rather than replaces, because neither list contains the other:

| | Covers |
| --- | --- |
| shipped file (2023) | `104.16.0.0/12`, so 104.28-104.31 - which Cloudflare does not publish, and which answers today (`104.28.173.174`, FRA, 140 ms) |
| published list | `172.64.0.0/13`, so 172.68-172.71 - which the shipped file never had |
| merged | 14 entries, 1,786,880 addresses (+262,400) |

Keeping a range Cloudflare no longer publishes costs a little scanning time;
dropping a live one means never finding the address behind it. The previous
file is kept beside the new one as `<name>.previous`.

A candidate list built earlier for a carrier comparison still holds the old
addresses - rebuild it with `cfscan --make-pool` after an update.

## Configuration

Everything lives in one file: `~/.config/cfscan/config.json` (mode `0600`,
written atomically).

```json
{
  "version": 1,
  "cfst_path": "/opt/homebrew/bin/cfst",
  "active_profile": "example",
  "profiles": {
    "example": {
      "domain": "node.example.com",
      "port": 2087,
      "mode": "httping",
      "scheme": "https",
      "url_path": "/",
      "http_status": 400,
      "colo": "FRA,AMS",
      "ip_version": 4,
      "ip_file": "/Users/you/.local/share/cloudflare-speedtest/ip.txt",
      "ipv6_file": "/Users/you/.local/share/cloudflare-speedtest/ipv6.txt",
      "attempts": 4,
      "concurrency": 200,
      "max_latency_ms": 1000,
      "max_loss": 0.25,
      "results_limit": 20,
      "top_ips": 10,
      "download_test": false,
      "download_url": "",
      "download_count": 10,
      "download_seconds": 10,
      "upload_test": false,
      "upload_url": "",
      "upload_seconds": 8,
      "jitter_test": true,
      "jitter_samples": 6,
      "jitter_count": 0,
      "recommended_ip": "104.16.0.1",
      "verify_attempts": 20,
      "favourites": []
    }
  }
}
```

| Field | Meaning |
| --- | --- |
| `domain` | The site you scan through (`-url`, and the SNI/Host you configure in your client) |
| `port` | Scan port, `1`-`65535` (`-tp`) |
| `mode` | `httping` (HTTP/S request, matches a status code) or `tcp` (plain TCP connect) |
| `scheme` | `https` for a real TLS request, `http` to send a plain request to the HTTPS port (menu 6 asks for this too) |
| `url_path` | Path used in the test URL, default `/` |
| `http_status` | The status code that counts as a good answer in HTTPing mode |
| `ip_version` | `4` or `6`, picks between `ip_file` and `ipv6_file` |
| `attempts` | Pings per address (`-t`) |
| `concurrency` | Parallel workers (`-n`, 1-1000) |
| `max_latency_ms` | Addresses slower than this are dropped (`-tl`) |
| `max_loss` | Fraction `0.0`-`1.0`, e.g. `0.25` for 25% (`-tlr`) |
| `colo` | Cloudflare datacentres to keep, e.g. `"FRA,AMS"` (`-cfcolo`); empty means the whole edge. Needs `mode: httping` with `scheme: https` |
| `results_limit` | Legacy. It only ever became the scanner's `-p`, which caps the scanner's own console listing - output cfscan hides, because it reads the result file instead. Measured: `-p 1` over five addresses still wrote all five rows. `top_ips` is the setting that decides what you see |
| `top_ips` | How many of the best addresses are listed **and verified** after a scan (default `10`). Menu 2 asks for this one |
| `favourites` | Addresses this profile has proven, newest first. Menu 3 offers them before asking you to type an address |
| `edge_history` | One summary per scan of which datacentres answered and how fast, labelled with the line it was measured on. Menu 12 ranks the edge locations from it |
| `verify_top_ips` | `true` (default) re-measures those addresses with 20 attempts each before they are listed; `false` skips that step |
| `download_test` | `false` adds `-dd` (no cfst download test). `true` measures download speed; see below |
| `download_url` | File URL for a second cfst pass. Empty means "download the profile test URL", which only works when that URL returns HTTP 200 and a large body |
| `download_count` | How many of the fastest addresses are download-tested (`-dn`, default 10) |
| `download_seconds` | Seconds cfst spends on each download (`-dt`, default 10) |
| `upload_test` | `false` (default). cfst cannot upload; cfscan measures this itself |
| `upload_url` | Where the upload POST goes. Required when `upload_test` is true |
| `upload_seconds` | How long to keep uploading to each address (default 8) |
| `jitter_test` | `true` (default). TCP-handshake jitter on the best addresses, in milliseconds |
| `jitter_samples` | Handshakes per address (default 6, at least 2) |
| `jitter_count` | How many addresses to sample. `0` means `top_ips` |
| `recommended_ip` | Your verified IP; highlighted when it appears in a scan, and rewritten whenever a verification passes. Custom Scan clears it automatically when you change the domain or port, because the IP was verified against the old target |

Profiles can also be created and edited from the menu (option 6). The built-in
`example` profile cannot be deleted, so a working fallback always
exists. Editing the JSON by hand is safe: missing fields are filled in with
defaults and unknown fields are preserved.

### The command cfscan runs

For the default profile, a Quick Scan is exactly equivalent to:

```sh
cfst -f ~/.local/share/cloudflare-speedtest/ip.txt \
     -tp 2087 -httping -httping-code 400 \
     -url https://node.example.com:2087/ \
     -dd -t 4 -n 200 -tl 1000 -tlr 0.25 -p 20 \
     -o "$HOME/Documents/Cloudflare Scanner Results/cfscan-example-<timestamp>.csv"
```

Use `cfscan --quick --dry-run` (or the `--dry-run` flag with any scan) to print
the argument list without running anything. Arguments are always passed as a
list - never as a shell string - so no value you type can become a command.

### Jitter, download and upload

cfst v2.3.5 writes IP, sent, received, loss, average latency, download MB/s
and colo. It has no jitter column and no upload flag, so those two are
measured by cfscan after the scan, on the best addresses only. Download keeps
using cfst.

**Jitter** is on by default (`jitter_test`, or `--no-jitter` to skip a run).
Each chosen address gets `jitter_samples` TCP handshakes (default 6) on the
profile port. The number shown is the average gap between consecutive
round-trips, in milliseconds. Ranking still prefers lower packet loss, then
lower latency. Jitter only reorders addresses whose latency falls in the same
20 ms band, so a steady 150 ms beats a swinging 155 ms, and a steady 300 ms
does not beat a steady 150 ms. A latency-only file (no jitter column) sorts
exactly as before.

**Download** stays off until you enable it (menu 2 / menu 6, or
`cfscan --quick --download`). cfst has a single `-url`, used both for the
latency check and for the download, and it records **0.00 MB/s** unless that
URL returns HTTP 200 and a body large enough to fill `-dt` seconds. A short
body that finishes early is reported as 0.00. So is HTTP 403: on
`speed.cloudflare.com`, `bytes=100000000` and `bytes=200000000` are rejected,
and cfst writes 0.00 for that rejection. The profile test URL is a latency
check, so enabling download without another URL does not produce a useful
speed.

Set `download_url` (or pass `--download-url`). cfscan then keeps `-dd` on the
latency scan and runs a **second** `cfst` pass over the fastest addresses:
`-url` is the file, `-tp` is that URL's port (not the profile port), `-dn` /
`-dt` come from `download_count` / `download_seconds`, and `-debug` is on so
the log contains the HTTP status. `--download` with no URL saved uses
`https://speed.cloudflare.com/__down?bytes=50000000` (50 MB), which returns
HTTP 200 on that host. When every speed is 0.00 and the log shows
`HTTP 状态码: 403` (or the English `HTTP status code: 403`), cfscan prints
that Cloudflare rejected the URL and points at a smaller file. When a
download was measured, ranking prefers higher speed. Speeds in the same 1 MB/s
band still fall back to
latency and jitter, and any loss-free address still outranks one that dropped
packets.

**Upload** is opt-in (`upload_test`, or `cfscan --quick --upload`) because it
needs a URL that accepts a POST. The default when you pass `--upload` and the
profile has no URL is `https://speed.cloudflare.com/__up`. cfscan opens **one**
connection to the **candidate address** on the URL's port (TLS when the URL is
https, with that URL's hostname as SNI and Host) and POSTs about 1 MiB at a
time with HTTP/1.1 keep-alive for `upload_seconds` (default 8). The
result is MB/s and should sit in the same range as a curl POST of `__up`
through that address. When download was not measured, upload ranks in the same
1 MB/s bands. When both were measured, upload only breaks a remaining tie.

`cfscan --direct` applies to these probes as well as to cfst. Proxy variables
(`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, including `socks5://`) are ignored,
so a test of the real ISP does not go out through a VPN proxy exported in the
shell. Without `--direct`, those variables are honoured, which is what cfst
does.

### Results

* CSV files: `~/Documents/Cloudflare Scanner Results/cfscan-<profile>-<timestamp>.csv`
* Raw scanner output: the matching `.log` file next to it
* Multi-carrier work: `~/Documents/Cloudflare Scanner Results/multi-isp/<domain>/`
  (one session JSON per run, one report CSV per report, and the candidate lists
  in its `pools/` folder)
* A pointer to the newest result is kept in the configuration (`last_result`),
  so option 4 reopens it later
* Existing files are never overwritten - a `-2`, `-3`, ... suffix is added
* Option 8 opens the folder in Finder

## Troubleshooting

**"No IP passed the filters"** - the scanner found nothing. Common causes:

1. The expected status code does not match what the site returns. In HTTPing
   mode with `scheme=https`, `cfst` performs a real TLS request, so a down or
   misconfigured origin makes Cloudflare answer `520`/`522` and every candidate
   is filtered out. Open the site in a browser first; if it answers `200`, set
   the expected status to `200` (menu 6).
2. **Scheme trick:** with `scheme=http` the scanner sends a *plain* HTTP request
   to your HTTPS port, and Cloudflare itself answers `400 Bad Request` ("The
   plain HTTP request was sent to HTTPS port"). That makes a fast, origin
   independent port-liveness probe, which is why an expected status of `400`
   with an `http://` URL is a useful setup. Pick it in menu 6 -> Edit Profile
   ("URL scheme used for the test request") or set `"scheme": "http"` in
   `~/.config/cfscan/config.json`.
3. Filters are too tight: raise `max_latency_ms`, or raise `max_loss`.
4. The IP range file is missing or empty - check `ip_file` in the profile.

**`ParseCIDR err invalid CIDR address` and the scanner exits with code 1** - the
file handed to `-f` contains a line the scanner cannot parse (a comment, a
header, any text). The scanner parses that file as a CIDR list and abandons the
whole run, writing no CSV. Keep such a file to one address or CIDR per line,
without `#`. cfscan writes its own candidate lists that way.

**A multi-carrier round measures nothing** - usually the connection was not
switched yet, but the round now prints the scanner's own translated messages, so
a real reason (an unparseable list, a missing binary) is visible instead of
looking like a forgotten switch. Menu 10 asks whether to measure that carrier
again, continue, or stop and show what was measured so far.

**`cfscan: command not found`** - `~/.local/bin` is not on your `PATH`. Add
`export PATH="$HOME/.local/bin:$PATH"` to `~/.zshrc` and open a new terminal, or
run `~/.local/bin/cfscan` directly.

**"The scanner binary was not found"** - install `cfst`
(`brew install cloudflare-speedtest`) or point `cfst_path` in the config file at
the binary you already have.

**Verification fails with a status number** - the address answered, but with a
different status than the profile expects. cfscan prints the observed status;
fix `http_status`, or pick another address.

**Scan is interrupted or the network drops** - press `Ctrl+C`; cfscan stops the
scanner, keeps whatever partial result file exists and drops you back at the
menu. Nothing is left running.

**A scan feels slow** - lower `concurrency`, or leave download and upload off
(`download_test` / `upload_test` false, which passes `-dd` and skips the
upload). A download pass transfers a large file through each of the best
addresses for `download_seconds` each. Jitter is a few TCP handshakes and is
much cheaper; turn it off with `--no-jitter` if you want the latency scan
alone.

**Download speed is 0.00** - cfst only records a speed for HTTP 200 with a
body that lasts the whole download window. HTTP 403, which
`speed.cloudflare.com` returns for an oversized `bytes=` (100 MB and 200 MB),
is stored as 0.00 as well. When the download log shows that 403, cfscan says
the URL was rejected and suggests the 50 MB default,
`https://speed.cloudflare.com/__down?bytes=50000000`. The profile test URL is
not a speed-test file. Set `download_url` (menu 2, or `--download-url`) and
run again.

## What this depends on, and what you may ship

cfscan is **MIT licensed** (see `LICENSE`) and has **no Python dependencies**:
it imports only the standard library, which the test suite checks.

It does not contain, bundle or link any third-party code. It *runs* one
external program, which you install yourself:

| Program | Role | Licence |
| --- | --- | --- |
| [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) (`cfst`) | does the measuring | GPL-3.0 |

cfscan starts `cfst` as a separate process with an argument list - it never
links against it and never copies its code - so distributing cfscan does not
distribute `cfst`, and the MIT licence above covers everything in this
repository. If you redistribute the `cfst` **binary** alongside it, GPL-3.0
applies to that binary and its terms are yours to meet; the simplest route is
what this README already tells users to do, which is to install it themselves.

The names in this repository (`example.com`, `node.example.com`) are reserved
for documentation by RFC 2606 and resolve to nothing. There is no real domain,
address or credential anywhere in the source, and a test guards against one
creeping back in.

## Supported platforms

Written for and tested on **macOS**. Three things are macOS-specific and
degrade rather than crash elsewhere:

| What | Where | Off macOS |
| --- | --- | --- |
| `open` to reveal the results folder | menu 8 | prints the path instead |
| `route -n get default` to detect a tunnel | menu 12, scan notices | the line is labelled `unknown`, ranking still works |
| `/opt/homebrew/bin/cfst` as the fallback path | first run | `cfst` is found on `PATH` first, so set `cfst_path` if it is elsewhere |

Everything else - the scanning, parsing, ranking, profiles and result files -
is plain Python and portable. Linux support is a small change in those three
places if you want it.

## Safety

* The scanner is started with an argument list and `shell=False`; there is no
  string interpolation and no shell involved anywhere.
* Inputs are validated: domains, IP addresses (via `ipaddress`), ports
  (`1`-`65535`), numbers, packet loss (`0`-`1` or a percentage) and filenames
  (no path separators, no shell metacharacters, `.csv` only).
* cfscan never asks for or stores UUIDs, passwords, private keys or
  subscription links, and rejects values that look like them.
* cfscan never changes Cloudflare DNS records, your VPN configuration, or any
  other system setting. You paste the verified IP into your client yourself.
* Configuration writes are atomic (`os.replace`), so a crash cannot corrupt the
  file.
* Colours appear only when the terminal supports them (`NO_COLOR` is honoured);
  every screen stays readable without colour.

## Development

```sh
python3 -m unittest discover -s tests -t . -v
```

589 tests, on Python 3.9 and newer.

Run `./dev-link.sh` once and the `cfscan` command reads this folder, so every
edit is live on the next run (see **Working on the code: the live link**
above). Without it, the launcher reads the copy in `~/.local/share/cfscan/lib`
and an old version keeps answering until `./update.sh` is run.

The suite uses temporary directories only - it never touches your real
configuration or results - and fakes exactly one boundary: the execution of the
external `cfst` binary. It covers validation, argument construction, log
translation, CSV parsing, profile persistence, atomic writes, menu flows,
dry-run behaviour, error handling, the first-run defaults and the region
filter.

## Uninstall

```sh
./uninstall.sh            # removes the launcher and package, keeps your config
./uninstall.sh --purge    # also removes ~/.config/cfscan
./update.sh               # uninstall + reinstall from this folder (keeps both)
```

Your results in `~/Documents/Cloudflare Scanner Results` are never deleted
automatically.

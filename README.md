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

After changing anything in the package, replace the installed copy with:

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
cfscan --verify 104.21.54.105  # strict 20-attempt check of one address
cfscan --profile office      # use another saved profile (menu or one-shot run)
cfscan --show-last           # show the newest saved result
cfscan --list-profiles       # list saved profiles
cfscan --make-pool 2000      # fix the candidate list every carrier round shares
cfscan --isp mci             # measure one carrier against that list
cfscan --multi-isp           # print the multi-carrier report of the session
cfscan --no-color            # plain output
cfscan --version
cfscan --help
```

One command per run: combining two of them is refused instead of silently
running whichever comes first.

### The menu

```
1. Quick Scan             7. Switch IPv4 / IPv6
2. Custom Scan            8. Open Results Folder
3. Verify an IP           9. Help
4. Show Last Results      10. Multi-carrier scan
5. Show Saved Profiles    0. Exit
6. Add or Edit Profile
```

**Quick Scan** shows the active profile, asks for confirmation, runs `cfst`,
then prints a ranked table:

```
#  IP address       Sent  Received  Loss  Latency    Colo
-- ---------------- ---- --------- ----- ---------- ----
 1  104.21.54.105 * 4    4         0%    438.32 ms  -
 2  172.67.213.151   4    3         25%   512.10 ms  SJC
```

Then the ten best addresses are **re-measured before you see them**: one extra
scanner run pings those ten addresses with 20 attempts each and cfscan marks
every line with the result of that check:

```
Top 10 IPs you can use
----------------------
  1. PASS 104.19.10.61     146.09 ms   0%  FRA  Port 2087  SNI/Host gerr.yasin-ai-54.ir  *
  2. PASS 104.18.210.173   149.02 ms   0%  FRA  Port 2087  SNI/Host gerr.yasin-ai-54.ir
  3. FAIL 162.159.206.2    149.74 ms  15%  FRA  Port 2087  SNI/Host gerr.yasin-ai-54.ir
  4. DEAD 104.20.126.138          -     -  -    Port 2087  SNI/Host gerr.yasin-ai-54.ir
 10. PASS 104.25.79.140    154.96 ms   0%  FRA  Port 2087  SNI/Host gerr.yasin-ai-54.ir
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
[PASS] Verify 104.21.54.105 - PASS
  104.21.54.105 answered 20/20 attempts, 0% packet loss
  Average latency 431.07 ms    Colo FRA
  Client fields - Address 104.21.54.105, Port 2087, SNI gerr.yasin-ai-54.ir,
  Host gerr.yasin-ai-54.ir

Press Enter to return to the menu:
```

Press Enter and the menu comes back, so you can rank another round, verify the
winner, or look at the saved file without restarting cfscan. When the output is
piped (no terminal), the pause is skipped so scripts behave exactly as before.

`Ctrl+C` cancels the step you are in and returns to the menu - it no longer
closes cfscan. Pressing it at the menu prompt itself (or choosing `0`) is what
leaves the program. One-shot commands (`cfscan --quick`, `cfscan --verify IP`)
print their result and exit, which is what a script wants.

## Configuration

Everything lives in one file: `~/.config/cfscan/config.json` (mode `0600`,
written atomically).

```json
{
  "version": 1,
  "cfst_path": "/opt/homebrew/bin/cfst",
  "active_profile": "gerr-yasin-ai-54",
  "profiles": {
    "gerr-yasin-ai-54": {
      "domain": "gerr.yasin-ai-54.ir",
      "port": 2087,
      "mode": "httping",
      "scheme": "https",
      "url_path": "/",
      "http_status": 400,
      "ip_version": 4,
      "ip_file": "/Users/you/.local/share/cloudflare-speedtest/ip.txt",
      "ipv6_file": "/Users/you/.local/share/cloudflare-speedtest/ipv6.txt",
      "attempts": 4,
      "concurrency": 200,
      "max_latency_ms": 1000,
      "max_loss": 0.25,
      "results_limit": 20,
      "download_test": false,
      "recommended_ip": "104.21.54.105",
      "verify_attempts": 20
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
| `results_limit` | Rows written by the scanner (`-p`); cfscan always asks for at least 10 so ten addresses can be offered |
| `top_ips` | How many of the best addresses are listed after a scan (default `10`) |
| `verify_top_ips` | `true` (default) re-measures those addresses with 20 attempts each before they are listed; `false` skips that step |
| `download_test` | `false` adds `-dd` (faster scans) |
| `recommended_ip` | Your verified IP; highlighted when it appears in a scan. Custom Scan clears it automatically when you change the domain or port, because the IP was verified against the old target |

Profiles can also be created and edited from the menu (option 6). The built-in
`gerr-yasin-ai-54` profile cannot be deleted, so a working fallback always
exists. Editing the JSON by hand is safe: missing fields are filled in with
defaults and unknown fields are preserved.

### The command cfscan runs

For the default profile, a Quick Scan is exactly equivalent to:

```sh
cfst -f ~/.local/share/cloudflare-speedtest/ip.txt \
     -tp 2087 -httping -httping-code 400 \
     -url https://gerr.yasin-ai-54.ir:2087/ \
     -dd -t 4 -n 200 -tl 1000 -tlr 0.25 -p 20 \
     -o "$HOME/Documents/Cloudflare Scanner Results/cfscan-gerr-yasin-ai-54-<timestamp>.csv"
```

Use `cfscan --quick --dry-run` (or the `--dry-run` flag with any scan) to print
the argument list without running anything. Arguments are always passed as a
list - never as a shell string - so no value you type can become a command.

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

**A scan feels slow** - lower `concurrency`, raise it, or keep the download test
disabled (`download_test: false`, `-dd`). Enabling the download test is much
slower because every candidate is downloaded from.

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

After a change, run `./update.sh` before trying `cfscan` again: the launcher reads
the installed copy in `~/.local/share/cfscan/lib`, not this folder, so an old
version would otherwise keep answering.

The suite uses temporary directories only - it never touches your real
configuration or results - and fakes exactly one boundary: the execution of the
external `cfst` binary. It covers validation, argument construction, log
translation, CSV parsing, profile persistence, atomic writes, menu flows,
dry-run behaviour and error handling.

## Uninstall

```sh
./uninstall.sh            # removes the launcher and package, keeps your config
./uninstall.sh --purge    # also removes ~/.config/cfscan
./update.sh               # uninstall + reinstall from this folder (keeps both)
```

Your results in `~/Documents/Cloudflare Scanner Results` are never deleted
automatically.

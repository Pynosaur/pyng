# pyng

Pure Python network ping with colorized output and rich statistics.

Reimagines `ping` for the [Pynosaur](https://github.com/pynosaur) ecosystem.

## Features

- **Color-coded RTT** — green (<50ms), yellow (<150ms), red (>=150ms or lost)
- **Jitter stats** — min/avg/max/jitter in the summary
- **DNS info** — shows IP and reverse DNS upfront
- **TCP connect mode** — ping any port without root (`-T`)
- **Clean UX** — Ctrl+C prints summary, clear exit codes
- **Pure Python** — stdlib only, no dependencies
- **Cross-platform** — Linux, macOS, Windows

## Installation

```bash
pget install pyng
```

Or from source:

```bash
python app/main.py example.com
```

## Usage

```bash
# ICMP ping (continuous)
pyng example.com

# Send 5 pings
pyng -c 5 8.8.8.8

# TCP connect ping on HTTPS port (no root needed)
pyng -T -p 443 example.com

# Fast interval, short timeout
pyng -i 0.5 -t 1 example.com

# Quiet mode — only summary
pyng -q -c 10 example.com

# Large payload
pyng -s 1024 example.com

# ICMP on Linux (needs root)
sudo pyng example.com
```

## Example Output

```
PYNG example.com (93.184.215.14) — 56 data bytes
56 bytes from 93.184.215.14: seq=0 ttl=56 time=12.34 ms
56 bytes from 93.184.215.14: seq=1 ttl=56 time=11.87 ms
56 bytes from 93.184.215.14: seq=2 ttl=56 time=13.02 ms
^C
--- example.com ping statistics ---
3 transmitted, 3 received, 0.0% packet loss
rtt min/avg/max/jitter = 11.87/12.41/13.02/0.47 ms
```

## Options

```
-h, --help             Show help message
-v, --version          Show version information
-c COUNT               Number of pings to send (default: infinite)
-i INTERVAL            Seconds between pings (default: 1.0)
-t TIMEOUT             Timeout per ping in seconds (default: 2.0)
-s SIZE                Payload size in bytes (default: 56)
-T, --tcp              Use TCP connect mode (no root required)
-p PORT                TCP port to ping (default: 80)
-q, --quiet            Quiet mode — only show summary at the end
--no-color             Disable colored output
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | All pings successful |
| 1    | Any packet loss or privilege error |
| 2    | DNS resolution failure |

## ICMP vs TCP Mode

**ICMP** (default) sends standard ICMP Echo Request packets — the same
as system `ping`. On macOS this works without root; on Linux it requires
`sudo` or the `cap_net_raw` capability.

**TCP** (`-T`) measures the TCP three-way handshake to a specific port.
No special privileges are needed. Useful for testing if a service is
reachable through firewalls that block ICMP.

## Requirements

- Python 3.8+
- No external dependencies

## Tests

```bash
python test/test_main.py
```

## License

MIT

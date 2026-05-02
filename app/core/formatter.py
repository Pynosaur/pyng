#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys


# ANSI color codes
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
CYAN = '\033[36m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

RTT_FAST = 50.0    # ms — green threshold
RTT_MEDIUM = 150.0  # ms — yellow threshold


def supports_color():
    """Check if terminal supports color output."""
    if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
        return False
    return True


def _c(text, code, color_enabled):
    if not color_enabled:
        return text
    return f"{code}{text}{RESET}"


def rtt_color(rtt_ms, color_enabled):
    """Return colored RTT string based on latency thresholds."""
    text = f"{rtt_ms:.2f} ms"
    if not color_enabled:
        return text
    if rtt_ms < RTT_FAST:
        return f"{GREEN}{text}{RESET}"
    if rtt_ms < RTT_MEDIUM:
        return f"{YELLOW}{text}{RESET}"
    return f"{RED}{text}{RESET}"


def loss_color(loss_pct, color_enabled):
    """Return colored packet loss string."""
    text = f"{loss_pct:.1f}%"
    if not color_enabled:
        return text
    if loss_pct == 0.0:
        return f"{GREEN}{text}{RESET}"
    if loss_pct < 25.0:
        return f"{YELLOW}{text}{RESET}"
    return f"{RED}{text}{RESET}"


def format_header(
    host, ip, rdns, mode='icmp', port=None, payload_size=56, color=True,
):
    """Format the ping session header."""
    lines = []

    if mode == 'tcp':
        target = f"{host} ({ip})" if host != ip else ip
        lines.append(
            f"{_c('PYNG', BOLD, color)} {target} port {_c(str(port), CYAN, color)}"
            f" — TCP connect"
        )
    else:
        target = f"{host} ({ip})" if host != ip else ip
        lines.append(
            f"{_c('PYNG', BOLD, color)} {target}"
            f" — {payload_size} data bytes"
        )

    if rdns and rdns != ip and rdns != host:
        lines.append(f"  {_c('rDNS:', DIM, color)} {rdns}")

    return '\n'.join(lines)


def format_reply(result, ip, color=True):
    """Format a single ping reply line."""
    seq = result['seq']

    if result['success']:
        rtt = rtt_color(result['rtt_ms'], color)
        parts = [f"{result.get('nbytes', '?')} bytes from {ip}:"]
        parts.append(f"seq={seq}")
        if result.get('ttl') is not None:
            parts.append(f"ttl={result['ttl']}")
        parts.append(f"time={rtt}")
        return ' '.join(parts)

    error = result.get('error', 'unknown error')
    if error == 'timeout':
        return _c(f"seq={seq} — Request timed out", RED, color)
    return _c(f"seq={seq} — {error}", RED, color)


def format_tcp_reply(result, ip, port, color=True):
    """Format a single TCP ping reply line."""
    seq = result['seq']

    if result['success']:
        rtt = rtt_color(result['rtt_ms'], color)
        return f"Connected to {ip}:{port}: seq={seq} time={rtt}"

    error = result.get('error', 'unknown error')
    if error == 'timeout':
        return _c(f"seq={seq} — Connection timed out", RED, color)
    return _c(f"seq={seq} — {error}", RED, color)


def format_stats(stats, host, color=True):
    """Format the final statistics summary."""
    lines = []
    lines.append('')
    lines.append(f"--- {host} ping statistics ---")

    loss = loss_color(stats.loss_pct, color)
    lines.append(
        f"{stats.sent} transmitted, {stats.received} received,"
        f" {loss} packet loss"
    )

    if stats.rtts:
        max_color = RED if stats.rtt_max >= RTT_MEDIUM else YELLOW
        lines.append(
            f"rtt min/avg/max/jitter ="
            f" {_c(f'{stats.rtt_min:.2f}', GREEN, color)}"
            f"/{_c(f'{stats.rtt_avg:.2f}', CYAN, color)}"
            f"/{_c(f'{stats.rtt_max:.2f}', max_color, color)}"
            f"/{_c(f'{stats.rtt_jitter:.2f}', DIM, color)}"
            f" ms"
        )

    return '\n'.join(lines)


def format_privilege_error(color=True):
    """Format a helpful error when ICMP requires elevated privileges."""
    lines = [
        _c("Error: ICMP ping requires elevated privileges", RED, color),
        "",
        "Options:",
        f"  1. {_c('sudo pyng <host>', BOLD, color)}"
        "              Run with elevated privileges",
        f"  2. {_c('pyng -T <host>', BOLD, color)}"
        "               Use TCP connect mode (no root needed)",
        f"  3. {_c('pyng -T -p 443 <host>', BOLD, color)}"
        "        TCP ping on a specific port",
    ]
    return '\n'.join(lines)

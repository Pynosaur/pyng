#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.append(str(Path(__file__).resolve().parent.parent))
    __package__ = "app"

from app import __version__
from app.core.pinger import resolve_host, icmp_ping, tcp_ping, PingStats
from app.core.formatter import (
    format_header,
    format_reply,
    format_tcp_reply,
    format_stats,
    format_privilege_error,
    supports_color,
)
from app.utils.doc_reader import read_app_doc


def print_help():
    doc = read_app_doc("pyng")
    desc = doc.get("description", "Pure Python network ping with better UX")

    print(f"pyng - {desc}")
    print()
    print("USAGE:")
    print("    pyng [OPTIONS] HOST")
    print("    pyng -T [-p PORT] HOST")
    print()
    print("OPTIONS:")
    print("    -h, --help             Show help message")
    print("    -v, --version          Show version information")
    print("    -c COUNT               Number of pings to send (default: infinite)")
    print("    -i INTERVAL            Seconds between pings (default: 1.0)")
    print("    -t TIMEOUT             Timeout per ping in seconds (default: 2.0)")
    print("    -s SIZE                Payload size in bytes (default: 56)")
    print("    -T, --tcp              Use TCP connect mode (no root required)")
    print("    -p PORT                TCP port to ping (default: 80)")
    print("    -q, --quiet            Quiet mode — only show summary at the end")
    print("    --no-color             Disable colored output")
    print()
    print("EXAMPLES:")
    print("    pyng example.com")
    print("    pyng -c 5 8.8.8.8")
    print("    pyng -T -p 443 example.com")
    print("    pyng -i 0.5 -t 1 example.com")
    print("    pyng -q -c 10 example.com")


def print_version():
    doc = read_app_doc("pyng")
    print(doc.get("version", __version__))


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    if args[0] in ("-v", "--version"):
        print_version()
        return 0

    # Parse arguments
    host = None
    count = 0       # 0 = infinite
    interval = 1.0
    timeout = 2.0
    payload_size = 56
    tcp_mode = False
    tcp_port = 80
    quiet = False
    color = supports_color()

    i = 0
    while i < len(args):
        arg = args[i]

        if arg in ('-c',) and i + 1 < len(args):
            try:
                count = int(args[i + 1])
                if count < 1:
                    print("Error: count must be >= 1", file=sys.stderr)
                    return 1
            except ValueError:
                print(f"Error: invalid count: {args[i + 1]}", file=sys.stderr)
                return 1
            i += 2
        elif arg in ('-i',) and i + 1 < len(args):
            try:
                interval = float(args[i + 1])
                if interval <= 0:
                    print("Error: interval must be > 0", file=sys.stderr)
                    return 1
            except ValueError:
                print(f"Error: invalid interval: {args[i + 1]}", file=sys.stderr)
                return 1
            i += 2
        elif arg in ('-t',) and i + 1 < len(args):
            try:
                timeout = float(args[i + 1])
                if timeout <= 0:
                    print("Error: timeout must be > 0", file=sys.stderr)
                    return 1
            except ValueError:
                print(f"Error: invalid timeout: {args[i + 1]}", file=sys.stderr)
                return 1
            i += 2
        elif arg in ('-s',) and i + 1 < len(args):
            try:
                payload_size = int(args[i + 1])
                if payload_size < 0:
                    print("Error: size must be >= 0", file=sys.stderr)
                    return 1
            except ValueError:
                print(f"Error: invalid size: {args[i + 1]}", file=sys.stderr)
                return 1
            i += 2
        elif arg in ('-p',) and i + 1 < len(args):
            try:
                tcp_port = int(args[i + 1])
                if not (1 <= tcp_port <= 65535):
                    print("Error: port must be 1-65535", file=sys.stderr)
                    return 1
            except ValueError:
                print(f"Error: invalid port: {args[i + 1]}", file=sys.stderr)
                return 1
            i += 2
        elif arg in ('-T', '--tcp'):
            tcp_mode = True
            i += 1
        elif arg in ('-q', '--quiet'):
            quiet = True
            i += 1
        elif arg == '--no-color':
            color = False
            i += 1
        elif arg.startswith('-'):
            print(f"Error: unknown option: {arg}", file=sys.stderr)
            return 1
        else:
            host = arg
            i += 1

    if not host:
        print("Error: no host specified", file=sys.stderr)
        print("Usage: pyng [OPTIONS] HOST", file=sys.stderr)
        return 1

    # Resolve host
    ip, rdns = resolve_host(host)
    if ip is None:
        print(f"pyng: cannot resolve {host}: Unknown host", file=sys.stderr)
        return 2

    # Print header
    if not quiet:
        mode = 'tcp' if tcp_mode else 'icmp'
        header = format_header(
            host, ip, rdns, mode=mode, port=tcp_port,
            payload_size=payload_size, color=color,
        )
        print(header)

    # Ping loop
    stats = PingStats()
    ident = os.getpid() & 0xFFFF
    seq = 0

    try:
        while True:
            if count > 0 and seq >= count:
                break

            if tcp_mode:
                result = tcp_ping(ip, tcp_port, timeout=timeout)
                result['seq'] = seq
                stats.record(result)
                if not quiet:
                    print(format_tcp_reply(result, ip, tcp_port, color=color))
            else:
                result = icmp_ping(
                    ip, seq, ident,
                    timeout=timeout,
                    payload_size=payload_size,
                )
                stats.record(result)

                if result.get('error') == 'privilege':
                    print(format_privilege_error(color=color))
                    return 1

                if not quiet:
                    print(format_reply(result, ip, color=color))

            seq += 1

            if count > 0 and seq >= count:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        pass

    # Print statistics
    print(format_stats(stats, host, color=color))

    if stats.received == 0:
        return 1
    if stats.lost > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

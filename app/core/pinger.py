#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import struct
import time
import math


def _checksum(data):
    """Compute ICMP checksum per RFC 1071."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def resolve_host(host):
    """Resolve hostname to IP and reverse-DNS name.

    Returns (ip, rdns) where rdns may equal ip if reverse lookup fails.
    """
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None, None

    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        rdns = ip

    return ip, rdns


def _build_icmp_packet(seq, ident, payload_size):
    """Build an ICMP echo request packet."""
    icmp_type = 8  # Echo Request
    code = 0
    checksum_placeholder = 0
    padding = b'\x42' * max(0, payload_size - 8)

    ts = struct.pack('!d', time.time())
    header = struct.pack(
        '!BBHHH',
        icmp_type,
        code,
        checksum_placeholder,
        ident,
        seq,
    )
    packet = header + ts + padding
    chk = _checksum(packet)
    header = struct.pack('!BBHHH', icmp_type, code, chk, ident, seq)
    return header + ts + padding


def _open_icmp_socket(timeout):
    """Try to open an ICMP socket. Prefers DGRAM (macOS unprivileged), falls
    back to RAW."""
    for sock_type in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            sock = socket.socket(socket.AF_INET, sock_type, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            return sock, sock_type
        except PermissionError:
            continue
        except OSError:
            continue
    return None, None


def icmp_ping(ip, seq, ident, timeout=2.0, payload_size=56):
    """Send a single ICMP echo request and wait for reply.

    Returns dict with keys: success, rtt_ms, seq, ttl, nbytes, error.
    """
    result = {
        'success': False,
        'rtt_ms': None,
        'seq': seq,
        'ttl': None,
        'nbytes': None,
        'error': None,
    }

    sock, sock_type = _open_icmp_socket(timeout)
    if sock is None:
        result['error'] = 'privilege'
        return result

    try:
        packet = _build_icmp_packet(seq, ident, payload_size)
        send_time = time.monotonic()

        if sock_type == socket.SOCK_DGRAM:
            sock.sendto(packet, (ip, 0))
        else:
            sock.sendto(packet, (ip, 0))

        while True:
            elapsed = time.monotonic() - send_time
            if elapsed >= timeout:
                result['error'] = 'timeout'
                return result

            sock.settimeout(max(0.001, timeout - elapsed))
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                result['error'] = 'timeout'
                return result

            # Both RAW and DGRAM sockets on macOS return the
            # IP header.  Detect it via the version nibble.
            if len(data) >= 20 and (data[0] >> 4) == 4:
                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 8:
                    continue
                ttl = data[8]
                icmp_data = data[ihl:]
            elif len(data) >= 8:
                ttl = None
                icmp_data = data
            else:
                continue

            icmp_type = icmp_data[0]
            icmp_code = icmp_data[1]
            recv_ident = struct.unpack('!H', icmp_data[4:6])[0]
            recv_seq = struct.unpack('!H', icmp_data[6:8])[0]

            # Type 0 = Echo Reply
            # On DGRAM sockets the kernel rewrites ident and
            # filters replies for us, so only check seq.
            ident_ok = (
                sock_type == socket.SOCK_DGRAM or recv_ident == ident
            )
            if icmp_type == 0 and ident_ok and recv_seq == seq:
                rtt = (time.monotonic() - send_time) * 1000.0
                result['success'] = True
                result['rtt_ms'] = rtt
                result['ttl'] = ttl
                result['nbytes'] = len(data)
                return result

            # Type 3 = Destination Unreachable
            if icmp_type == 3:
                codes = {
                    0: 'Network unreachable',
                    1: 'Host unreachable',
                    2: 'Protocol unreachable',
                    3: 'Port unreachable',
                    13: 'Administratively prohibited',
                }
                msg = f'Unreachable (code {icmp_code})'
                result['error'] = codes.get(icmp_code, msg)
                return result

    except OSError as e:
        result['error'] = str(e)
    finally:
        sock.close()

    return result


def tcp_ping(ip, port, timeout=2.0):
    """TCP connect ping — no root required. Measures TCP handshake time."""
    result = {
        'success': False,
        'rtt_ms': None,
        'seq': 0,
        'ttl': None,
        'nbytes': None,
        'error': None,
        'port': port,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        start = time.monotonic()
        sock.connect((ip, port))
        rtt = (time.monotonic() - start) * 1000.0
        result['success'] = True
        result['rtt_ms'] = rtt
    except socket.timeout:
        result['error'] = 'timeout'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused'
    except OSError as e:
        result['error'] = str(e)
    finally:
        sock.close()

    return result


class PingStats:
    """Accumulates ping statistics."""

    def __init__(self):
        self.sent = 0
        self.received = 0
        self.rtts = []
        self.errors = []

    def record(self, result):
        self.sent += 1
        if result['success']:
            self.received += 1
            self.rtts.append(result['rtt_ms'])
        elif result.get('error'):
            self.errors.append(result['error'])

    @property
    def lost(self):
        return self.sent - self.received

    @property
    def loss_pct(self):
        if self.sent == 0:
            return 0.0
        return (self.lost / self.sent) * 100.0

    @property
    def rtt_min(self):
        return min(self.rtts) if self.rtts else 0.0

    @property
    def rtt_max(self):
        return max(self.rtts) if self.rtts else 0.0

    @property
    def rtt_avg(self):
        return sum(self.rtts) / len(self.rtts) if self.rtts else 0.0

    @property
    def rtt_jitter(self):
        """Standard deviation of RTTs."""
        if len(self.rtts) < 2:
            return 0.0
        avg = self.rtt_avg
        variance = sum((r - avg) ** 2 for r in self.rtts) / len(self.rtts)
        return math.sqrt(variance)

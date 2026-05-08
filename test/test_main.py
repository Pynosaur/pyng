#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent

from app.core.pinger import resolve_host, PingStats, _checksum, _build_icmp_packet
from app.core.formatter import (
    rtt_color,
    loss_color,
    format_header,
    format_stats,
    supports_color,
)


class TestResolve(unittest.TestCase):
    """Test DNS resolution."""

    def test_resolve_localhost(self):
        ip, rdns = resolve_host("localhost")
        self.assertIn(ip, ("127.0.0.1", "::1"))

    def test_resolve_invalid(self):
        ip, rdns = resolve_host("this.host.definitely.does.not.exist.invalid")
        self.assertIsNone(ip)
        self.assertIsNone(rdns)

    def test_resolve_ip(self):
        ip, rdns = resolve_host("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")


class TestChecksum(unittest.TestCase):
    """Test ICMP checksum computation."""

    def test_zero_data(self):
        cs = _checksum(b'\x00\x00')
        self.assertEqual(cs, 0xFFFF)

    def test_known_value(self):
        data = b'\x08\x00\x00\x00\x00\x01\x00\x01'
        cs = _checksum(data)
        self.assertIsInstance(cs, int)
        self.assertGreaterEqual(cs, 0)
        self.assertLessEqual(cs, 0xFFFF)

    def test_odd_length(self):
        cs = _checksum(b'\x01\x02\x03')
        self.assertIsInstance(cs, int)


class TestBuildPacket(unittest.TestCase):
    """Test ICMP packet building."""

    def test_packet_length(self):
        pkt = _build_icmp_packet(seq=1, ident=1234, payload_size=56)
        self.assertGreaterEqual(len(pkt), 8)

    def test_packet_type(self):
        pkt = _build_icmp_packet(seq=0, ident=0, payload_size=56)
        self.assertEqual(pkt[0], 8)  # ICMP Echo Request


class TestPingStats(unittest.TestCase):
    """Test statistics accumulator."""

    def test_empty_stats(self):
        stats = PingStats()
        self.assertEqual(stats.sent, 0)
        self.assertEqual(stats.received, 0)
        self.assertEqual(stats.loss_pct, 0.0)

    def test_all_success(self):
        stats = PingStats()
        for rtt in [10.0, 20.0, 30.0]:
            stats.record({'success': True, 'rtt_ms': rtt})
        self.assertEqual(stats.sent, 3)
        self.assertEqual(stats.received, 3)
        self.assertAlmostEqual(stats.rtt_avg, 20.0)
        self.assertAlmostEqual(stats.rtt_min, 10.0)
        self.assertAlmostEqual(stats.rtt_max, 30.0)
        self.assertAlmostEqual(stats.loss_pct, 0.0)

    def test_partial_loss(self):
        stats = PingStats()
        stats.record({'success': True, 'rtt_ms': 15.0})
        stats.record({'success': False, 'error': 'timeout'})
        self.assertEqual(stats.sent, 2)
        self.assertEqual(stats.received, 1)
        self.assertAlmostEqual(stats.loss_pct, 50.0)

    def test_jitter(self):
        stats = PingStats()
        for rtt in [10.0, 10.0, 10.0]:
            stats.record({'success': True, 'rtt_ms': rtt})
        self.assertAlmostEqual(stats.rtt_jitter, 0.0)


class TestFormatter(unittest.TestCase):
    """Test output formatting."""

    def test_rtt_color_no_color(self):
        result = rtt_color(42.5, False)
        self.assertEqual(result, "42.50 ms")

    def test_loss_color_no_color(self):
        result = loss_color(0.0, False)
        self.assertEqual(result, "0.0%")

    def test_format_header_icmp(self):
        header = format_header(
            "example.com", "93.184.215.14", "example.com",
            color=False,
        )
        self.assertIn("PYNG", header)
        self.assertIn("example.com", header)

    def test_format_header_tcp(self):
        header = format_header(
            "example.com", "93.184.215.14", "example.com",
            mode='tcp', port=443, color=False,
        )
        self.assertIn("TCP", header)
        self.assertIn("443", header)

    def test_format_stats_output(self):
        stats = PingStats()
        stats.record({'success': True, 'rtt_ms': 25.0})
        output = format_stats(stats, "example.com", color=False)
        self.assertIn("1 transmitted", output)
        self.assertIn("1 received", output)
        self.assertIn("0.0%", output)


class TestVersionConsistency(unittest.TestCase):
    """All version references must match. CI catches drift."""

    def _read_program_version(self):
        text = (REPO_ROOT / ".program").read_text()
        for line in text.splitlines():
            if line.startswith("version:"):
                return line.split(":", 1)[1].strip()
        self.fail(".program has no version field")

    def _read_doc_version(self):
        doc_file = REPO_ROOT / "doc" / "pyng.yaml"
        text = doc_file.read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.upper().startswith("VERSION:"):
                val = stripped.split(":", 1)[1].strip()
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                return val
        self.fail("doc/pyng.yaml has no VERSION field")

    def _read_readme_version(self):
        readme = REPO_ROOT / "README.md"
        if not readme.exists():
            return None
        text = readme.read_text()
        match = re.search(r'^Version:\s*(.+)$', text, re.MULTILINE)
        return match.group(1).strip() if match else None

    def test_all_versions_match(self):
        program_v = self._read_program_version()
        doc_v = self._read_doc_version()
        readme_v = self._read_readme_version()
        init_v = __version__

        self.assertEqual(
            init_v, program_v,
            f"__init__.py ({init_v}) != .program ({program_v})",
        )
        self.assertEqual(
            init_v, doc_v,
            f"__init__.py ({init_v}) != doc yaml ({doc_v})",
        )
        if readme_v is not None:
            self.assertEqual(
                init_v, readme_v,
                f"__init__.py ({init_v}) != README.md ({readme_v})",
            )


if __name__ == "__main__":
    unittest.main()

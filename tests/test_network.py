"""Tests for network.py."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from wgpeer.network import _get_allowed_ips, next_ip


def make_proc(stdout="", returncode=0):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.stdout = stdout
    proc.returncode = returncode
    return proc


WG_OUTPUT_TWO_PEERS = "pubkeyAAA\t10.0.0.2/32\npubkeyBBB\t10.0.0.3/32\n"

WG_OUTPUT_WITH_IPV6 = "pubkeyAAA\t10.0.0.2/32 fd00::2/128\n"

WG_OUTPUT_NONSEQUENTIAL = "pubkeyAAA\t10.0.0.5/32\npubkeyBBB\t10.0.0.10/32\n"


class TestGetAllowedIps:
    def test_returns_ips_from_output(self):
        proc = make_proc(stdout=WG_OUTPUT_TWO_PEERS)
        with patch("subprocess.run", return_value=proc):
            ips = _get_allowed_ips()
        assert "10.0.0.2" in ips
        assert "10.0.0.3" in ips

    def test_returns_empty_on_failure(self):
        proc = make_proc(returncode=1)
        with patch("subprocess.run", return_value=proc):
            ips = _get_allowed_ips()
        assert ips == []

    def test_strips_prefix_length(self):
        proc = make_proc(stdout="pubkey\t10.0.0.2/32\n")
        with patch("subprocess.run", return_value=proc):
            ips = _get_allowed_ips()
        assert ips == ["10.0.0.2"]

    def test_handles_multiple_addresses_per_peer(self):
        proc = make_proc(stdout=WG_OUTPUT_WITH_IPV6)
        with patch("subprocess.run", return_value=proc):
            ips = _get_allowed_ips()
        assert "10.0.0.2" in ips
        assert "fd00::2" in ips


class TestNextIp:
    def test_falls_back_to_second_host_when_no_peers(self):
        proc = make_proc(stdout="")
        with patch("subprocess.run", return_value=proc):
            ip = next_ip()
        assert ip == "10.0.0.2"

    def test_falls_back_when_wg_fails(self):
        proc = make_proc(returncode=1)
        with patch("subprocess.run", return_value=proc):
            ip = next_ip()
        assert ip == "10.0.0.2"

    def test_increments_highest_address(self):
        proc = make_proc(stdout=WG_OUTPUT_TWO_PEERS)
        with patch("subprocess.run", return_value=proc):
            ip = next_ip()
        assert ip == "10.0.0.4"

    def test_uses_highest_not_sequential(self):
        proc = make_proc(stdout=WG_OUTPUT_NONSEQUENTIAL)
        with patch("subprocess.run", return_value=proc):
            ip = next_ip()
        assert ip == "10.0.0.11"

    def test_custom_subnet_cidr(self):
        proc = make_proc(stdout="pubkey\t192.168.1.5/32\n")
        with patch("subprocess.run", return_value=proc):
            ip = next_ip(subnet="192.168.1.0/24")
        assert ip == "192.168.1.6"

    def test_ignores_ips_from_different_subnet(self):
        proc = make_proc(stdout="pubkey\t172.16.0.5/32\n")
        with patch("subprocess.run", return_value=proc):
            ip = next_ip(subnet="10.0.0.0/24")
        assert ip == "10.0.0.2"

    def test_exits_when_subnet_full(self):
        lines = "\n".join(f"pubkey{i}\t10.0.0.{i}/32" for i in range(2, 255))
        proc = make_proc(stdout=lines)
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(SystemExit):
                next_ip()

    def test_exactly_at_limit_254_exits(self):
        proc = make_proc(stdout="pubkey\t10.0.0.254/32\n")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(SystemExit):
                next_ip()

    def test_exits_when_subnet_too_small(self):
        proc = make_proc(stdout="")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(SystemExit):
                next_ip(subnet="10.0.0.1/32")

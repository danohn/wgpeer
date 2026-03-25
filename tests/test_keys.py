"""Tests for keys.py."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from wgpeer.keys import gen_keypair, genkey, pubkey, run


def make_proc(stdout="", returncode=0, stderr=""):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


class TestRun:
    def test_returns_completed_process_on_success(self):
        proc = make_proc(stdout="output\n")
        with patch("subprocess.run", return_value=proc) as mock_run:
            result = run(["wg", "genkey"])
        mock_run.assert_called_once_with(
            ["wg", "genkey"], input=None, capture_output=True, text=True
        )
        assert result is proc

    def test_exits_on_nonzero_returncode(self):
        proc = make_proc(returncode=1, stderr="command failed")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(SystemExit):
                run(["wg", "genkey"])

    def test_passes_input_to_subprocess(self):
        proc = make_proc(stdout="pubkey\n")
        with patch("subprocess.run", return_value=proc) as mock_run:
            run(["wg", "pubkey"], input="privkey")
        mock_run.assert_called_once_with(
            ["wg", "pubkey"], input="privkey", capture_output=True, text=True
        )


class TestGenkey:
    def test_returns_stripped_private_key(self):
        proc = make_proc(stdout="abc123privatekey\n")
        with patch("subprocess.run", return_value=proc):
            result = genkey()
        assert result == "abc123privatekey"

    def test_calls_wg_genkey(self):
        proc = make_proc(stdout="key\n")
        with patch("subprocess.run", return_value=proc) as mock_run:
            genkey()
        args = mock_run.call_args[0][0]
        assert args == ["wg", "genkey"]


class TestPubkey:
    def test_returns_stripped_public_key(self):
        proc = make_proc(stdout="pubkeyABC\n")
        with patch("subprocess.run", return_value=proc):
            result = pubkey("myprivatekey")
        assert result == "pubkeyABC"

    def test_passes_private_key_as_input(self):
        proc = make_proc(stdout="pub\n")
        with patch("subprocess.run", return_value=proc) as mock_run:
            pubkey("myprivatekey")
        _, kwargs = mock_run.call_args
        # input is passed positionally via run() helper
        assert mock_run.call_args[1]["input"] == "myprivatekey"


class TestGenKeypair:
    def test_returns_private_and_public_key(self):
        priv_proc = make_proc(stdout="privatekey\n")
        pub_proc = make_proc(stdout="publickey\n")
        with patch("subprocess.run", side_effect=[priv_proc, pub_proc]):
            priv, pub = gen_keypair()
        assert priv == "privatekey"
        assert pub == "publickey"

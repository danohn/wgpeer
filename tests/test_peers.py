"""Tests for peers.py."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wgpeer.peers import (
    _fmt_bytes,
    _fmt_handshake,
    _pubkey_from_conf,
    add_peer,
    list_peers,
    peer_status,
    remove_peer,
    show_qr,
    validate_name,
)

SAMPLE_CFG = {
    "server_ip": "1.2.3.4",
    "server_port": 51820,
    "wg_interface": "wg0",
    "wg_dir": "/etc/wireguard",
    "subnet": "10.0.0.0/24",
    "dns": "10.0.0.1",
    "keepalive": 25,
}

SAMPLE_CONF = """\
[Interface]
PrivateKey = PRIVKEYABC
Address = 10.0.0.2/24
DNS = 10.0.0.1

[Peer]
PublicKey = SERVERPUB
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""


def make_proc(stdout="", returncode=0, stderr=""):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


class TestValidateName:
    def test_accepts_alphanumeric(self):
        validate_name("alice123")  # no exception

    def test_accepts_hyphens_and_underscores(self):
        validate_name("my-peer_01")  # no exception

    def test_rejects_spaces(self):
        with pytest.raises(SystemExit):
            validate_name("my peer")

    def test_rejects_dots(self):
        with pytest.raises(SystemExit):
            validate_name("peer.name")

    def test_rejects_empty_string(self):
        with pytest.raises(SystemExit):
            validate_name("")

    def test_rejects_slash(self):
        with pytest.raises(SystemExit):
            validate_name("../../etc/passwd")


class TestPubkeyFromConf:
    def test_extracts_and_derives_public_key(self):
        pub_proc = make_proc(stdout="DERIVEDPUB\n")
        conf = MagicMock(spec=Path)
        conf.read_text.return_value = SAMPLE_CONF
        with patch("subprocess.run", return_value=pub_proc):
            pub = _pubkey_from_conf(conf)
        assert pub == "DERIVEDPUB"

    def test_exits_if_no_private_key(self):
        conf = MagicMock(spec=Path)
        conf.read_text.return_value = "[Interface]\nAddress = 10.0.0.2/24\n"
        with pytest.raises(SystemExit):
            _pubkey_from_conf(conf)

    def test_exits_if_wg_pubkey_fails(self):
        proc = make_proc(returncode=1)
        conf = MagicMock(spec=Path)
        conf.read_text.return_value = SAMPLE_CONF
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(SystemExit):
                _pubkey_from_conf(conf)


class TestAddPeer:
    def _patch_all(self, conf_exists=False):
        """Return a context manager stack for patching add_peer dependencies."""
        patches = [
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("wgpeer.peers.next_ip", return_value="10.0.0.2"),
            patch("wgpeer.peers.gen_keypair", return_value=("PRIV", "PUB")),
            patch("wgpeer.peers._server_pubkey", return_value="SERVERPUB"),
            patch("wgpeer.peers.render_client_config", return_value=SAMPLE_CONF),
            patch(
                "wgpeer.peers._conf_path",
                return_value=MagicMock(
                    exists=MagicMock(return_value=conf_exists),
                    write_text=MagicMock(),
                    chmod=MagicMock(),
                ),
            ),
            patch("wgpeer.peers.run"),
            patch("wgpeer.peers._setup_logger", return_value=MagicMock()),
            patch("segno.make", return_value=MagicMock(terminal=MagicMock())),
        ]
        return patches

    def test_exits_on_duplicate(self):
        patches = self._patch_all(conf_exists=True)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7],
            patches[8],
        ):
            with pytest.raises(SystemExit):
                add_peer("alice")

    def test_calls_wg_set_and_save(self):
        mock_run = MagicMock()
        patches = self._patch_all(conf_exists=False)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patch("wgpeer.peers.run", mock_run),
            patches[7],
            patches[8],
        ):
            add_peer("alice")
        calls = mock_run.call_args_list
        assert any("wg" in str(c) and "set" in str(c) for c in calls)
        assert any("wg-quick" in str(c) and "save" in str(c) for c in calls)

    def test_writes_config_file(self):
        conf_mock = MagicMock(
            exists=MagicMock(return_value=False),
            write_text=MagicMock(),
            chmod=MagicMock(),
        )
        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("wgpeer.peers.next_ip", return_value="10.0.0.2"),
            patch("wgpeer.peers.gen_keypair", return_value=("PRIV", "PUB")),
            patch("wgpeer.peers._server_pubkey", return_value="SERVERPUB"),
            patch("wgpeer.peers.render_client_config", return_value=SAMPLE_CONF),
            patch("wgpeer.peers._conf_path", return_value=conf_mock),
            patch("wgpeer.peers.run"),
            patch("wgpeer.peers._setup_logger", return_value=MagicMock()),
            patch("segno.make", return_value=MagicMock(terminal=MagicMock())),
        ):
            add_peer("alice")
        conf_mock.write_text.assert_called_once_with(SAMPLE_CONF)
        conf_mock.chmod.assert_called_once_with(0o600)

    def test_rejects_invalid_name(self):
        with pytest.raises(SystemExit):
            add_peer("bad name!")


class TestRemovePeer:
    def test_exits_if_conf_not_found(self):
        conf_mock = MagicMock(exists=MagicMock(return_value=False))
        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("wgpeer.peers._conf_path", return_value=conf_mock),
        ):
            with pytest.raises(SystemExit):
                remove_peer("alice")

    def test_calls_wg_set_remove_and_save(self):
        conf_mock = MagicMock(
            exists=MagicMock(return_value=True),
            unlink=MagicMock(),
        )
        mock_run = MagicMock()
        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("wgpeer.peers._conf_path", return_value=conf_mock),
            patch("wgpeer.peers._pubkey_from_conf", return_value="PUBKEY"),
            patch("wgpeer.peers.run", mock_run),
            patch("wgpeer.peers._setup_logger", return_value=MagicMock()),
        ):
            remove_peer("alice")
        calls = mock_run.call_args_list
        assert any("remove" in str(c) for c in calls)
        assert any("wg-quick" in str(c) for c in calls)

    def test_deletes_conf_file(self):
        conf_mock = MagicMock(
            exists=MagicMock(return_value=True),
            unlink=MagicMock(),
        )
        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("wgpeer.peers._conf_path", return_value=conf_mock),
            patch("wgpeer.peers._pubkey_from_conf", return_value="PUBKEY"),
            patch("wgpeer.peers.run"),
            patch("wgpeer.peers._setup_logger", return_value=MagicMock()),
        ):
            remove_peer("alice")
        conf_mock.unlink.assert_called_once()

    def test_rejects_invalid_name(self):
        with pytest.raises(SystemExit):
            remove_peer("bad name!")


class TestListPeers:
    def test_shows_table_with_peers(self, capsys):
        wg_output = "PUBKEYAAA\t10.0.0.2/32\n"
        proc = make_proc(stdout=wg_output)
        conf_mock = MagicMock(stem="alice")

        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
            patch("pathlib.Path.glob", return_value=[conf_mock]),
            patch("wgpeer.peers._pubkey_from_conf", return_value="PUBKEYAAA"),
            patch("rich.get_console") as mock_console,
        ):
            list_peers()
        mock_console.return_value.print.assert_called_once()

    def test_skips_interface_conf_file(self):
        wg_output = "PUBKEYAAA\t10.0.0.2/32\n"
        proc = make_proc(stdout=wg_output)
        # wg0.conf should be skipped; only alice.conf should be considered
        wg0_conf = MagicMock(stem="wg0")
        alice_conf = MagicMock(stem="alice")

        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
            patch("pathlib.Path.glob", return_value=[wg0_conf, alice_conf]),
            patch("wgpeer.peers._pubkey_from_conf", return_value="PUBKEYAAA"),
            patch("rich.get_console") as mock_console,
        ):
            list_peers()
        # _pubkey_from_conf should only be called for alice, not wg0
        table = mock_console.return_value.print.call_args[0][0]
        assert wg0_conf.stem not in str(table.columns)

    def test_shows_peers_without_conf_as_no_config(self):
        wg_output = "PUBKEYORPHAN\t10.0.0.5/32\n"
        proc = make_proc(stdout=wg_output)

        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
            patch("pathlib.Path.glob", return_value=[]),
            patch("rich.get_console"),
            patch("rich.table.Table.add_row") as mock_add_row,
        ):
            list_peers()
        assert any("no config" in str(c) for c in mock_add_row.call_args_list)

    def test_exits_on_wg_failure(self):
        proc = make_proc(returncode=1)
        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
        ):
            with pytest.raises(SystemExit):
                list_peers()


class TestShowQr:
    def test_renders_qr_from_conf(self):
        conf_mock = MagicMock(
            exists=MagicMock(return_value=True),
            read_text=MagicMock(return_value=SAMPLE_CONF),
        )
        qr_mock = MagicMock()
        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("wgpeer.peers._conf_path", return_value=conf_mock),
            patch("segno.make", return_value=qr_mock),
        ):
            show_qr("alice")
        qr_mock.terminal.assert_called_once()

    def test_exits_if_conf_not_found(self):
        conf_mock = MagicMock(exists=MagicMock(return_value=False))
        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("wgpeer.peers._conf_path", return_value=conf_mock),
        ):
            with pytest.raises(SystemExit):
                show_qr("alice")

    def test_rejects_invalid_name(self):
        with pytest.raises(SystemExit):
            show_qr("bad name!")


# Dump format: interface line + peer lines (tab-separated)
# Interface: pubkey  privkey  listen-port  fwmark
# Peer:      pubkey  preshared  endpoint  allowed-ips  handshake-ts  rx  tx  keepalive
SAMPLE_DUMP = (
    "SERVERPUB\t(none)\t51820\toff\n"
    "PUBKEYAAA\t(none)\t1.1.1.1:12345\t10.0.0.2/32\t1700000100\t1024\t2048\t25\n"
    "PUBKEYBBB\t(none)\t2.2.2.2:12345\t10.0.0.3/32\t1700000000\t512\t256\t25\n"
)


class TestFmtBytes:
    def test_bytes(self):
        assert _fmt_bytes(512) == "512.0 B"

    def test_kilobytes(self):
        assert _fmt_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        assert _fmt_bytes(1024 * 1024) == "1.0 MB"

    def test_gigabytes(self):
        assert _fmt_bytes(1024**3) == "1.0 GB"

    def test_terabytes(self):
        assert _fmt_bytes(1024**4) == "1.0 TB"


class TestFmtHandshake:
    def test_never_when_zero(self):
        label, status = _fmt_handshake(0)
        assert label == "never"
        assert status == "offline"

    def test_online_within_3_minutes(self):
        import time

        now = int(time.time())
        _, status = _fmt_handshake(now - 60)
        assert status == "online"

    def test_idle_between_3_and_15_minutes(self):
        import time

        now = int(time.time())
        _, status = _fmt_handshake(now - 300)
        assert status == "idle"

    def test_offline_after_15_minutes(self):
        import time

        now = int(time.time())
        _, status = _fmt_handshake(now - 1000)
        assert status == "offline"

    def test_label_seconds(self):
        import time

        now = int(time.time())
        label, _ = _fmt_handshake(now - 30)
        assert label.endswith("s ago")

    def test_label_minutes(self):
        import time

        now = int(time.time())
        label, _ = _fmt_handshake(now - 300)
        assert label.endswith("m ago")

    def test_label_hours(self):
        import time

        now = int(time.time())
        label, _ = _fmt_handshake(now - 7200)
        assert label == "2h ago"

    def test_label_days(self):
        import time

        now = int(time.time())
        label, _ = _fmt_handshake(now - 172800)
        assert label == "2d ago"


class TestPeerStatus:
    def test_shows_table(self):
        proc = make_proc(stdout=SAMPLE_DUMP)
        alice_conf = MagicMock(stem="alice")

        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
            patch("pathlib.Path.glob", return_value=[alice_conf]),
            patch("wgpeer.peers._pubkey_from_conf", return_value="PUBKEYAAA"),
            patch("rich.get_console") as mock_console,
        ):
            peer_status()
        mock_console.return_value.print.assert_called_once()

    def test_exits_on_wg_failure(self):
        proc = make_proc(returncode=1)
        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
        ):
            with pytest.raises(SystemExit):
                peer_status()

    def test_peers_without_conf_shown_as_no_config(self):
        proc = make_proc(stdout=SAMPLE_DUMP)

        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
            patch("pathlib.Path.glob", return_value=[]),
            patch("rich.get_console"),
            patch("rich.table.Table.add_row") as mock_add_row,
        ):
            peer_status()
        assert any("no config" in str(c) for c in mock_add_row.call_args_list)

    def test_skips_interface_line_in_dump(self):
        proc = make_proc(stdout=SAMPLE_DUMP)

        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
            patch("pathlib.Path.glob", return_value=[]),
            patch("rich.get_console"),
            patch("rich.table.Table.add_row") as mock_add_row,
        ):
            peer_status()
        # Should have exactly 2 rows (PUBKEYAAA and PUBKEYBBB), not 3
        assert mock_add_row.call_count == 2

    def test_displays_transfer_bytes(self):
        proc = make_proc(stdout=SAMPLE_DUMP)

        with (
            patch("wgpeer.peers.load_config", return_value=SAMPLE_CFG),
            patch("subprocess.run", return_value=proc),
            patch("pathlib.Path.glob", return_value=[]),
            patch("rich.get_console"),
            patch("rich.table.Table.add_row") as mock_add_row,
        ):
            peer_status()
        all_args = str(mock_add_row.call_args_list)
        assert "1.0 KB" in all_args  # rx for PUBKEYAAA = 1024
        assert "2.0 KB" in all_args  # tx for PUBKEYAAA = 2048

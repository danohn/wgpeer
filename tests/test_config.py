"""Tests for config.py."""

from pathlib import Path
from unittest.mock import mock_open, patch

from wgpeer.config import DEFAULTS, load_config, render_client_config


class TestLoadConfig:
    def test_returns_defaults_when_no_config_file(self):
        with patch.object(Path, "exists", return_value=False):
            cfg = load_config()
        assert cfg["server_port"] == DEFAULTS["server_port"]
        assert cfg["subnet"] == DEFAULTS["subnet"]
        assert cfg["dns"] == DEFAULTS["dns"]

    def test_overrides_defaults_with_config_file(self):
        toml_content = b'server_ip = "1.2.3.4"\nserver_port = 12345\n'
        with patch.object(Path, "exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=toml_content)):
                cfg = load_config()
        assert cfg["server_ip"] == "1.2.3.4"
        assert cfg["server_port"] == 12345
        # Non-overridden defaults remain
        assert cfg["subnet"] == DEFAULTS["subnet"]

    def test_defaults_have_all_required_keys(self):
        required = {
            "server_ip",
            "server_port",
            "wg_interface",
            "wg_dir",
            "subnet",
            "dns",
            "keepalive",
        }  # noqa: E501
        assert required.issubset(set(DEFAULTS.keys()))


class TestRenderClientConfig:
    CFG = {
        "server_ip": "1.2.3.4",
        "server_port": 51820,
        "dns": "10.0.0.1",
        "keepalive": 25,
    }

    def _render(self, **kwargs):
        defaults = dict(
            private_key="PRIVKEY",
            ip="10.0.0.2",
            server_pub="PUBKEY",
            cfg=self.CFG,
        )
        defaults.update(kwargs)
        # Use the package template (no override)
        with patch.object(Path, "exists", return_value=False):
            return render_client_config(**defaults)

    def test_contains_private_key(self):
        out = self._render(private_key="MYPRIVKEY")
        assert "MYPRIVKEY" in out

    def test_contains_ip_address(self):
        out = self._render(ip="10.0.0.5")
        assert "10.0.0.5/24" in out

    def test_contains_server_public_key(self):
        out = self._render(server_pub="SERVERPUB")
        assert "SERVERPUB" in out

    def test_contains_endpoint(self):
        out = self._render()
        assert "1.2.3.4:51820" in out

    def test_contains_dns(self):
        out = self._render()
        assert "10.0.0.1" in out

    def test_contains_keepalive(self):
        out = self._render()
        assert "25" in out

    def test_contains_allowed_ips(self):
        out = self._render()
        assert "0.0.0.0/0" in out

    def test_interface_section_present(self):
        out = self._render()
        assert "[Interface]" in out

    def test_peer_section_present(self):
        out = self._render()
        assert "[Peer]" in out

    def test_uses_override_template_when_present(self):
        override_content = "OVERRIDE={{ private_key }}"
        with patch.object(Path, "exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=override_content)):
                # Patch FileSystemLoader to return the override template
                with patch("wgpeer.config.FileSystemLoader") as mock_loader_cls:
                    from jinja2 import BaseLoader

                    class _Ldr(BaseLoader):
                        def get_source(self, env, tmpl):
                            return override_content, None, lambda: True

                    mock_loader_cls.return_value = _Ldr()
                    out = render_client_config(
                        private_key="MYKEY",
                        ip="10.0.0.2",
                        server_pub="PUB",
                        cfg=self.CFG,
                    )
        assert "OVERRIDE=MYKEY" in out

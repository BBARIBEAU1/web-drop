"""One-liners have to be pasteable, with the lab address filled in."""

from __future__ import annotations

import ipaddress

import pytest

from web_drop.netinfo import choose_ip, detect_ip
from web_drop.oneliners import render_oneliners


def _render(**overrides: object) -> str:
    values = {
        "ip": "10.10.14.5",
        "port": 8000,
        "https": False,
        "filename": "notes.txt",
        "password": None,
        "ip_source": "explicit",
    }
    values.update(overrides)
    return render_oneliners(**values)  # type: ignore[arg-type]


def test_download_and_upload_commands_cover_each_client() -> None:
    text = _render()
    for needle in (
        "Invoke-WebRequest",
        "Net.WebClient",
        "Invoke-RestMethod",
        "certutil",
        "bitsadmin",
        "curl",
        "wget",
        "python3",
        "base64",
        "-Method PUT",
        "-Method POST",
        "http://10.10.14.5:8000/notes.txt",
        "%CD%\\notes.txt",
        "# ip source: explicit",
    ):
        assert needle in text
    assert "token=" not in text
    assert "WEB_DROP_B64" in text


def test_https_commands_skip_certificate_checks() -> None:
    text = _render(https=True, port=8443)
    assert "https://10.10.14.5:8443/notes.txt" in text
    assert "curl -k" in text
    assert "--no-check-certificate" in text
    assert "ServerCertificateValidationCallback" in text
    assert "-SkipCertificateCheck" in text


def test_password_is_percent_encoded_in_the_query() -> None:
    text = _render(password="p@ss&word", filename="a b.txt")
    assert "token=p%40ss%26word" in text
    assert "a%20b.txt" in text
    assert "OutFile 'a b.txt'" in text
    assert "p@ss&word" not in text.split("token=", 1)[1]


def test_small_file_is_embedded_as_base64() -> None:
    text = _render(embed=b"hello")
    assert "aGVsbG8=" in text
    assert "not embedded" not in text


def test_large_file_is_not_embedded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("web_drop.oneliners.EMBED_LIMIT", 4)
    text = _render(embed=None, embed_skipped=True, filename="notes.txt")
    assert "not embedded" in text
    assert "aGVsbG8=" not in text


def test_ipv6_address_is_bracketed() -> None:
    text = _render(ip="2001:db8::5")
    assert "[2001:db8::5]:8000" in text


def test_choose_ip_prefers_tun0_then_the_primary_interface() -> None:
    explicit = choose_ip("10.1.2.3", tun0="10.10.14.5", primary="192.168.1.9")
    assert explicit == ("10.1.2.3", "explicit")
    assert choose_ip("auto", tun0="10.10.14.5", primary="192.168.1.9") == ("10.10.14.5", "tun0")
    assert choose_ip("auto", tun0=None, primary="192.168.1.9") == ("192.168.1.9", "primary")
    assert choose_ip("auto", tun0=None, primary=None) == ("127.0.0.1", "loopback")


def test_choose_ip_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        choose_ip("not-an-ip", tun0=None, primary=None)


def test_detect_ip_returns_an_address() -> None:
    ip, source = detect_ip()
    ipaddress.ip_address(ip)
    assert source in {"tun0", "primary", "loopback"}

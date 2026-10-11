"""
`scrutics oui update` downloads the IEEE OUI database and installs it only when it is complete and
valid.

The HTTP layer is mocked; any real connection attempt fails the test. A successful download is
installed. A refused request (for example HTTP 418, which the IEEE server returns to some client
User-Agents), a network failure, an incomplete body, or a file the validator rejects gives a clear
message and leaves the installed database untouched.
"""

import email.message
import http.client
import importlib.util
import io
import json
import os
import socket
import urllib.error
from unittest.mock import patch

import pytest

from scrutics.classifier import oui
from scrutics.cli import build_parser, run_oui

PREVIOUS = "00-00-01   (hex)\t\tPrevious Vendor\n"
# The page the IEEE firewall returns with HTTP 418
REJECTED_PAGE = (b"<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. "
                 b"Please consult with your administrator.</body></html>")


def _ieee_text(entries=1100):
    return "".join(f"{(i >> 16) & 0xFF:02X}-{(i >> 8) & 0xFF:02X}-{i & 0xFF:02X}   (hex)\t\tVendor {i}\n"
                   for i in range(entries)).encode("utf-8")


class _Response:
    def __init__(self, body, status=200, headers=None, read_error=None):
        self.status = status
        self._body = body
        self._read_error = read_error
        self.headers = email.message.Message()
        for k, v in (headers or {"Content-Length": str(len(body)),
                                 "Last-Modified": "Sun, 11 Oct 2026 04:01:20 GMT"}).items():
            self.headers[k] = v

    def read(self):
        if self._read_error is not None:
            raise self._read_error
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a test tried to open a network connection")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.fixture
def user_db(tmp_path, monkeypatch):
    """An installed user database with one entry, in tmp_path."""
    user_dir = tmp_path / ".scrutics"
    user_dir.mkdir()
    monkeypatch.setattr(oui, "OUI_USER_DIR", str(user_dir))
    monkeypatch.setattr(oui, "OUI_USER_PATH", str(user_dir / "oui.txt"))
    monkeypatch.setattr(oui, "OUI_USER_BAK_PATH", str(user_dir / "oui.txt.bak"))
    monkeypatch.setattr(oui, "OUI_META_PATH", str(user_dir / "oui_meta.json"))
    (user_dir / "oui.txt").write_text(PREVIOUS, encoding="utf-8")
    (user_dir / "oui_meta.json").write_text('{"source": "previous"}', encoding="utf-8")
    return user_dir


def _unchanged(user_db):
    assert (user_db / "oui.txt").read_text(encoding="utf-8") == PREVIOUS
    assert (user_db / "oui_meta.json").read_text(encoding="utf-8") == '{"source": "previous"}'
    assert not (user_db / "oui.txt.bak").exists()
    assert [p.name for p in user_db.iterdir() if ".tmp" in p.name] == []


def test_a_complete_download_is_installed(user_db):
    sent = []

    def urlopen(req, timeout):
        sent.append(req)
        return _Response(_ieee_text())

    with patch("urllib.request.urlopen", urlopen):
        ok, msg, report = oui.download_ieee_oui()
    assert ok, msg
    assert report["entry_count"] == 1100
    assert (user_db / "oui.txt").read_bytes() == _ieee_text()
    assert (user_db / "oui.txt.bak").read_text(encoding="utf-8") == PREVIOUS
    assert json.loads((user_db / "oui_meta.json").read_text(encoding="utf-8"))["source_date"] == "2026-10-11"
    [req] = sent
    assert req.full_url == oui.IEEE_OUI_URL
    assert req.get_header("User-agent").startswith("Scrutics/")


def _http_error(code, reason, body=b""):
    return urllib.error.HTTPError(oui.IEEE_OUI_URL, code, reason, email.message.Message(), io.BytesIO(body))


@pytest.mark.parametrize("outcome, expected", [
    (_http_error(418, "I'm a Teapot", REJECTED_PAGE), "the server refused the download (HTTP 418 I'm a Teapot)"),
    (_http_error(503, "Service Unavailable"), "the server refused the download (HTTP 503 Service Unavailable)"),
    (urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")), "network error"),
    (TimeoutError("timed out"), "network error: timed out"),
    (_Response(b"partial", status=206), "the server answered HTTP 206 instead of the file"),
    (_Response(_ieee_text()[:5000], headers={"Content-Length": str(len(_ieee_text()))}), "the download is incomplete"),
    (_Response(b"", read_error=http.client.IncompleteRead(b"x" * 4000, 10000)), "the download is incomplete (4,000 bytes received)"),
], ids=["http-418", "http-503", "refused", "timeout", "http-206", "short-body", "incomplete-read"])
def test_a_failed_download_is_reported_and_changes_nothing(user_db, outcome, expected):
    def urlopen(req, timeout):
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    with patch("urllib.request.urlopen", urlopen):
        ok, msg, report = oui.download_ieee_oui()
    assert not ok and report is None
    assert expected in msg
    assert f"{oui.OUI_USER_PATH} was not changed" in msg
    assert "scrutics oui import" in msg
    _unchanged(user_db)


@pytest.mark.parametrize("body", [
    REJECTED_PAGE,                       # an error page served with HTTP 200
    _ieee_text(1100)[:20000],            # truncated: too few entries, last line cut
    b"\x00\xff" * 4000,                  # not text
], ids=["html-page", "truncated", "binary"])
def test_a_response_the_validator_rejects_is_not_installed(user_db, body):
    with patch("urllib.request.urlopen", lambda req, timeout: _Response(body)):
        ok, msg, report = oui.download_ieee_oui()
    assert not ok
    assert msg.startswith("Validation failed")
    assert f"{oui.OUI_USER_PATH} was not changed" in msg
    _unchanged(user_db)


def test_command_reports_a_refused_download(user_db, capsys):
    with patch("urllib.request.urlopen", side_effect=_http_error(418, "I'm a Teapot", REJECTED_PAGE)):
        assert run_oui(build_parser().parse_args(["oui", "update"])) == 1
    out = capsys.readouterr().out
    assert "[✗] Update failed: Could not download the OUI database: the server refused the download (HTTP 418" in out
    _unchanged(user_db)


def test_developer_download_script_keeps_the_existing_file_on_failure(tmp_path, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location(
        "download_oui", os.path.join(os.path.dirname(__file__), "..", "scripts", "download_oui.py"))
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    dest = tmp_path / "oui.txt"
    dest.write_text(PREVIOUS, encoding="utf-8")
    monkeypatch.setattr(script, "DEST", str(dest))
    with patch("urllib.request.urlopen", side_effect=_http_error(418, "I'm a Teapot", REJECTED_PAGE)):
        assert script.main() == 1
    assert "HTTP 418" in capsys.readouterr().out
    with patch("urllib.request.urlopen", lambda req, timeout: _Response(REJECTED_PAGE)):
        assert script.main() == 1
    assert dest.read_text(encoding="utf-8") == PREVIOUS
    with patch("urllib.request.urlopen", lambda req, timeout: _Response(_ieee_text())):
        assert script.main() == 0
    assert dest.read_bytes() == _ieee_text()
    assert [p.name for p in tmp_path.iterdir()] == ["oui.txt"]


def test_a_response_without_content_length_is_installed(user_db):
    # A chunked response carries no Content-Length; there is nothing to compare, so no length check
    response = _Response(_ieee_text(), headers={"Transfer-Encoding": "chunked"})
    assert response.headers.get("Content-Length") is None
    with patch("urllib.request.urlopen", lambda req, timeout: response):
        ok, msg, report = oui.download_ieee_oui()
    assert ok, msg
    assert report["entry_count"] == 1100
    assert (user_db / "oui.txt").read_bytes() == _ieee_text()

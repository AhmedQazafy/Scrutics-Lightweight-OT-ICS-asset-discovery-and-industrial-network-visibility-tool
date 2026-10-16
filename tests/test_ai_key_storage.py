"""AI setup stores keys in a private Scrutics file and adds one marked ~/.bashrc line, nothing more."""

from __future__ import annotations

import io
import os
import shutil
import stat
import subprocess
import sys
from contextlib import redirect_stdout
from unittest import mock

import pytest

from scrutics.ai import key_store
from scrutics.ai.key_store import MARKER, SOURCE_LINE, KeyStoreError, save_key, store_for_setup

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes and ~/.bashrc")

KEY = "sk-test-key-111"


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _keys_file(home):
    return os.path.join(home, ".scrutics", "ai_keys.sh")


def _sourced(home, var):
    """The value bash gets for var after loading the keys file."""
    result = subprocess.run(["bash", "-c", f'. "$1"; printf %s "${var}"', "bash", _keys_file(home)],
                            capture_output=True, text=True, check=True)
    return result.stdout


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in key_store.KEY_VARS:
        monkeypatch.delenv(var, raising=False)


def test_the_key_goes_to_a_private_file_and_bashrc_gets_one_marked_line(tmp_path):
    home = str(tmp_path)
    result = save_key("GEMINI_API_KEY", KEY, home)
    assert _mode(_keys_file(home)) == 0o600
    assert _mode(os.path.join(home, ".scrutics")) == 0o700
    assert _sourced(home, "GEMINI_API_KEY") == KEY
    assert (tmp_path / ".bashrc").read_text() == SOURCE_LINE + "\n"
    assert result.line_added and os.environ["GEMINI_API_KEY"] == KEY


def test_the_marked_line_is_added_once(tmp_path):
    home = str(tmp_path)
    save_key("GEMINI_API_KEY", KEY, home)
    second = save_key("OPENAI_API_KEY", "sk-openai-222", home)
    save_key("GEMINI_API_KEY", "sk-new-333", home)
    assert not second.line_added
    assert (tmp_path / ".bashrc").read_text().count(MARKER) == 1


def test_the_file_is_rewritten_whole_and_keeps_other_providers(tmp_path):
    home = str(tmp_path)
    save_key("GEMINI_API_KEY", "sk-old-gemini", home)
    save_key("OPENAI_API_KEY", "sk-openai-222", home)
    save_key("GEMINI_API_KEY", "sk-new-gemini", home)
    content = open(_keys_file(home)).read()
    assert "sk-old-gemini" not in content
    assert _sourced(home, "GEMINI_API_KEY") == "sk-new-gemini"
    assert _sourced(home, "OPENAI_API_KEY") == "sk-openai-222"
    assert [line for line in content.splitlines() if line.startswith("export")] == [
        "export GEMINI_API_KEY='sk-new-gemini'", "export OPENAI_API_KEY='sk-openai-222'"]


def test_a_loose_existing_file_ends_with_mode_0600_whatever_the_umask(tmp_path):
    home = str(tmp_path)
    os.makedirs(tmp_path / ".scrutics")
    (tmp_path / ".scrutics" / "ai_keys.sh").write_text("export GEMINI_API_KEY='x'\n")
    os.chmod(_keys_file(home), 0o644)
    old = os.umask(0)
    try:
        save_key("GEMINI_API_KEY", KEY, home)
    finally:
        os.umask(old)
    assert _mode(_keys_file(home)) == 0o600
    leftovers = [n for n in os.listdir(tmp_path / ".scrutics") if n.startswith(".ai_keys.")]
    assert leftovers == []


def test_unmarked_export_lines_are_reported_and_never_changed(tmp_path):
    original = ("# my settings\n"
                "export GEMINI_API_KEY=\"old-key-from-2025\"\n"
                "alias ll='ls -l'\n"
                "  export OPENAI_API_KEY=old-openai\n"
                "export GEMINI_API_KEY_BACKUP=keep\n")
    (tmp_path / ".bashrc").write_text(original)
    result = save_key("GEMINI_API_KEY", KEY, str(tmp_path))
    assert (tmp_path / ".bashrc").read_text() == original + SOURCE_LINE + "\n"
    assert result.other_exports == [(2, "GEMINI_API_KEY", False), (4, "OPENAI_API_KEY", False)]
    messages = result.messages("GEMINI_API_KEY")
    assert any("~/.bashrc line 2 also sets GEMINI_API_KEY (possibly an old key); Scrutics did not change it"
               in m for m in messages)
    assert not any("old-key-from-2025" in m or KEY in m for m in messages)


def test_an_export_after_the_marked_line_is_reported_as_overriding(tmp_path):
    (tmp_path / ".bashrc").write_text(SOURCE_LINE + "\nexport GEMINI_API_KEY=later\n")
    result = save_key("GEMINI_API_KEY", KEY, str(tmp_path))
    assert result.other_exports == [(2, "GEMINI_API_KEY", True)]
    assert "replaces the key just saved" in result.messages("GEMINI_API_KEY")[-1]


def test_a_bashrc_without_a_final_newline_is_only_appended_to(tmp_path):
    (tmp_path / ".bashrc").write_text("export PATH=$PATH:/opt/bin")
    save_key("ANTHROPIC_API_KEY", KEY, str(tmp_path))
    assert (tmp_path / ".bashrc").read_text() == "export PATH=$PATH:/opt/bin\n" + SOURCE_LINE + "\n"


@pytest.mark.parametrize("key", ["sk-a'b", "sk-$(touch pwned)", "sk-`id`-\\x", 'sk-"q";rm -rf ~'])
def test_any_key_text_is_stored_verbatim_and_never_runs(tmp_path, key):
    save_key("OPENAI_API_KEY", key, str(tmp_path))
    assert _sourced(str(tmp_path), "OPENAI_API_KEY") == key
    assert not (tmp_path / "pwned").exists()


@pytest.mark.parametrize("key", ["", "   ", "sk-a\nexport X=1", "sk-\x07"])
def test_an_empty_or_control_character_key_is_refused_and_nothing_written(tmp_path, key):
    with pytest.raises(KeyStoreError):
        save_key("GEMINI_API_KEY", key, str(tmp_path))
    assert not (tmp_path / ".scrutics").exists() and not (tmp_path / ".bashrc").exists()


def test_an_unknown_variable_is_refused(tmp_path):
    with pytest.raises(KeyStoreError):
        save_key("PATH", KEY, str(tmp_path))


def test_a_write_failure_is_reported(tmp_path):
    (tmp_path / ".scrutics").write_text("not a directory")
    with pytest.raises(KeyStoreError, match="Could not store the key"):
        save_key("GEMINI_API_KEY", KEY, str(tmp_path))


def test_the_module_reads_the_key_from_standard_input(tmp_path):
    root = os.path.dirname(os.path.dirname(os.path.abspath(key_store.__file__)))
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env.update(HOME=str(tmp_path), PYTHONPATH=os.path.dirname(root))
    result = subprocess.run([sys.executable, "-m", "scrutics.ai.key_store", "set", "GEMINI_API_KEY"],
                            input=KEY + "\n", capture_output=True, text=True, env=env, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "Key saved to ~/.scrutics/ai_keys.sh" in result.stdout and KEY not in result.stdout
    assert _sourced(str(tmp_path), "GEMINI_API_KEY") == KEY


def test_on_windows_the_key_is_kept_for_the_session_and_the_bat_is_named(tmp_path, monkeypatch):
    monkeypatch.setattr(key_store.os, "name", "nt")
    monkeypatch.setenv("HOME", str(tmp_path))
    lines = store_for_setup("GEMINI_API_KEY", KEY)
    assert os.environ["GEMINI_API_KEY"] == KEY
    assert "scrutics_ai_setup.bat" in lines[0]
    assert list(tmp_path.iterdir()) == []


def test_cli_onboarding_uses_the_key_store(tmp_path, monkeypatch):
    from scrutics import cli

    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".bashrc").write_text("export ANTHROPIC_API_KEY=old\n")
    replies = iter(["3", ""])
    out = io.StringIO()
    with mock.patch("builtins.input", lambda prompt="": next(replies)), \
         mock.patch("getpass.getpass", return_value=KEY), \
         mock.patch("requests.get", side_effect=AssertionError("blocked")), redirect_stdout(out):
        cfg = cli._run_ai_onboarding_cli()
    assert cfg["api_key"] == "${ANTHROPIC_API_KEY}"
    assert (tmp_path / ".bashrc").read_text() == "export ANTHROPIC_API_KEY=old\n" + SOURCE_LINE + "\n"
    assert _sourced(str(tmp_path), "ANTHROPIC_API_KEY") == KEY
    assert "line 1 also sets ANTHROPIC_API_KEY" in out.getvalue() and KEY not in out.getvalue()


def test_cli_onboarding_stops_when_the_key_cannot_be_stored(tmp_path, monkeypatch):
    from scrutics import cli

    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".scrutics").write_text("not a directory")
    replies = iter(["3", ""])
    out = io.StringIO()
    with mock.patch("builtins.input", lambda prompt="": next(replies)), \
         mock.patch("getpass.getpass", return_value=KEY), redirect_stdout(out):
        assert cli._run_ai_onboarding_cli() is None
    assert "Key not saved: Could not store the key" in out.getvalue()


def test_tui_onboarding_uses_the_key_store(tmp_path, monkeypatch):
    import asyncio
    from scrutics.ui.tui import AIModelSelectionModal, ScruticsApp

    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".bashrc").write_text("export OPENAI_API_KEY=old\n")
    notes = []

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            step1 = {"provider_id": "openai", "var_name": "OPENAI_API_KEY", "api_key": KEY,
                     "default_model": "gpt-6-luna", "model_source": "live"}
            screen = AIModelSelectionModal(step1, ["gpt-6-luna"])
            await app.push_screen(screen)
            await pilot.pause()
            with mock.patch.object(screen, "notify", lambda message, **kw: notes.append(message)):
                screen.confirm()
            await pilot.pause()

    asyncio.run(run())
    assert (tmp_path / ".bashrc").read_text() == "export OPENAI_API_KEY=old\n" + SOURCE_LINE + "\n"
    assert _sourced(str(tmp_path), "OPENAI_API_KEY") == KEY
    assert any("line 1 also sets OPENAI_API_KEY" in n for n in notes)
    assert "api_key: ${OPENAI_API_KEY}" in (tmp_path / ".scrutics" / "ai.yaml").read_text()

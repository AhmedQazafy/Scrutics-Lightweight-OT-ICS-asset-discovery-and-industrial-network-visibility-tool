"""The setup scripts never put a key on a command line or into code, and the .sh labels a fallback list."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys

import pytest

import scrutics
from scrutics.ai.key_store import SOURCE_LINE
from scrutics.ai.model_rules import FALLBACK_LABEL

CONFIG = os.path.join(os.path.dirname(os.path.abspath(scrutics.__file__)), "config")
SETUP_SH = os.path.join(CONFIG, "scrutics_ai_setup.sh")
SETUP_BAT = os.path.join(CONFIG, "scrutics_ai_setup.bat")
KEY_PS1 = os.path.join(CONFIG, "scrutics_ai_key.ps1")
WINDOWS_POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"


def run_setup_sh(home, answers, extra_env=None):
    """Run the .sh setup with a temporary HOME. Every python3 started by the script goes through a
    shim that records its arguments; requests go to a closed local proxy, so nothing leaves the host."""
    bindir = os.path.join(home, "_bin")
    os.makedirs(bindir, exist_ok=True)
    argv_log = os.path.join(home, "_python_argv.log")
    shim = os.path.join(bindir, "python3")
    with open(shim, "w") as f:
        f.write('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a" >> "$ARGV_LOG"; done\n'
                'printf -- "----\\n" >> "$ARGV_LOG"\n'
                f'exec "{sys.executable}" "$@"\n')
    os.chmod(shim, 0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON") and "proxy" not in k.lower()}
    env.update(HOME=home, ARGV_LOG=argv_log, PATH=bindir + os.pathsep + env.get("PATH", ""),
               HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9", NO_PROXY="")
    env.update(extra_env or {})
    result = subprocess.run(["bash", SETUP_SH], input=answers, capture_output=True, text=True,
                            env=env, timeout=120)
    argv = open(argv_log).read() if os.path.exists(argv_log) else ""
    return result, argv


def _sourced(home, var):
    result = subprocess.run(["bash", "-c", f'. "$1"; printf %s "${var}"', "bash",
                             os.path.join(home, ".scrutics", "ai_keys.sh")],
                            capture_output=True, text=True, check=True)
    return result.stdout


posix_only = pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="needs bash")


@posix_only
def test_sh_setup_stores_the_key_privately_and_labels_the_fallback(tmp_path):
    key = "sk-ant-script-777"
    (tmp_path / ".bashrc").write_text('export ANTHROPIC_API_KEY="old"\n')
    result, argv = run_setup_sh(str(tmp_path), f"3\n{key}\n\n")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    keys_file = tmp_path / ".scrutics" / "ai_keys.sh"
    assert stat.S_IMODE(os.stat(keys_file).st_mode) == 0o600
    assert _sourced(str(tmp_path), "ANTHROPIC_API_KEY") == key
    assert (tmp_path / ".bashrc").read_text() == 'export ANTHROPIC_API_KEY="old"\n' + SOURCE_LINE + "\n"
    assert "line 1 also sets ANTHROPIC_API_KEY" in out
    assert FALLBACK_LABEL in out and "Could not list models (" in out
    yaml_text = (tmp_path / ".scrutics" / "ai.yaml").read_text()
    assert "model: claude-haiku-5-5" in yaml_text and "api_key: ${ANTHROPIC_API_KEY}" in yaml_text
    assert key not in out
    assert argv and key not in argv


@posix_only
def test_sh_setup_never_runs_text_from_the_key(tmp_path):
    key = "sk-'$(touch pwned)'\"; touch pwned2; \"`touch pwned3`"
    result, argv = run_setup_sh(str(tmp_path), f"2\n{key}\n\n")
    assert result.returncode == 0, result.stderr
    assert _sourced(str(tmp_path), "OPENAI_API_KEY") == key
    assert not list(tmp_path.glob("pwned*")) and not list(tmp_path.parent.glob("pwned*"))
    assert key not in argv


@posix_only
def test_sh_setup_for_ollama_asks_for_no_key_and_writes_no_bashrc_line(tmp_path):
    result, argv = run_setup_sh(str(tmp_path), "4\n\n")
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / ".bashrc").exists() and not (tmp_path / ".scrutics" / "ai_keys.sh").exists()
    assert "provider: ollama" in (tmp_path / ".scrutics" / "ai.yaml").read_text()


@posix_only
def test_sh_setup_with_no_key_changes_nothing(tmp_path):
    result, _argv = run_setup_sh(str(tmp_path), "1\n\n")
    assert result.returncode == 0
    assert "No key entered. Nothing was changed." in result.stdout
    assert not (tmp_path / ".bashrc").exists() and not (tmp_path / ".scrutics" / "ai_keys.sh").exists()


def test_sh_script_has_no_key_on_a_command_line_or_in_code():
    text = open(SETUP_SH, encoding="utf-8").read()
    uses = [line.strip() for line in text.splitlines() if "USER_KEY" in line and not line.strip().startswith("#")]
    # Allowed: the hidden read, the empty check, the builtin printf piped to Python, the builtin export
    allowed = (re.compile(r'^read -rsp .* USER_KEY$'), re.compile(r'^if \[\[ -z "\$USER_KEY" \]\]; then$'),
               re.compile(r'^USER_KEY=""'),
               re.compile(r'^if ! printf \'%s\\n\' "\$USER_KEY" \| python3 -m scrutics\.ai\.key_store set "\$VAR_NAME"; then$'),
               re.compile(r'^export "\$\{VAR_NAME\}=\$\{USER_KEY\}"$'))
    assert uses and all(any(p.match(u) for p in allowed) for u in uses), uses
    assert not re.search(r"(sed -i|>>)[^\n]*(BASHRC|bashrc)", text)
    assert "python3 -c" not in text


def test_bat_script_never_handles_the_key():
    raw = open(SETUP_BAT, "rb").read()
    assert b"\r\n" in raw
    text = raw.decode("utf-8")
    assert "USER_KEY" not in text and "set /p USER_KEY" not in text
    calls = [line.strip() for line in text.splitlines()
             if "powershell" in line.lower() and not line.strip().startswith(("::", "echo"))]
    assert calls == ['powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scrutics_ai_key.ps1" -Name "!VAR_NAME!"']
    assert "export !VAR_NAME!=" not in text and "your key is visible" not in text.lower()


def test_ps1_reads_the_key_hidden_stores_it_per_user_and_asks_before_replacing():
    text = open(KEY_PS1, encoding="utf-8").read()
    assert 'Read-Host -AsSecureString' in text
    assert '[Environment]::SetEnvironmentVariable($Name, $key, "User")' in text
    assert '[Environment]::GetEnvironmentVariable($Name, "User")' in text
    assert re.search(r'Read-Host ".*already set for your Windows account\. Replace it\? \[y/N\]"', text)
    for line in text.splitlines():
        if "Write-Host" in line:
            assert "$key" not in line and "$existing" not in line


def test_the_ps1_ships_with_the_package():
    root = os.path.dirname(os.path.dirname(os.path.abspath(scrutics.__file__)))
    assert '"config/*.ps1"' in open(os.path.join(root, "pyproject.toml")).read()
    manifest = os.path.join(root, "MANIFEST.in")
    if os.path.exists(manifest):
        assert "*.ps1" in open(manifest).read()


@pytest.mark.skipif(not os.path.exists(WINDOWS_POWERSHELL) or shutil.which("wslpath") is None,
                    reason="Windows PowerShell not reachable")
def test_ps1_parses_in_windows_powershell():
    path = subprocess.run(["wslpath", "-w", KEY_PS1], capture_output=True, text=True, check=True).stdout.strip()
    command = ("$t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("
               f"'{path}', [ref]$t, [ref]$e); if ($e.Count) {{ $e | ForEach-Object {{ $_.ToString() }} }} "
               "else { 'parse ok' }")
    result = subprocess.run([WINDOWS_POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, text=True, timeout=120)
    assert result.stdout.replace("\r", "").strip() == "parse ok", result.stdout + result.stderr


def test_bat_explains_the_manual_alternative_when_the_key_is_not_saved():
    text = open(SETUP_BAT, "rb").read().decode("utf-8").replace("\r\n", "\n")
    # Any exit code other than 0 (stored), 2 (no key) or 3 (kept), negative ones included, is a failure
    assert 'if "!KEY_RESULT!"=="0" goto :key_ready' in text
    assert 'if "!KEY_RESULT!"=="2" goto :done\ngoto :key_not_saved' in text
    handling = text.split(":key_not_saved", 1)[0].split("scrutics_ai_key.ps1", 1)[1]
    assert not any(line.startswith("if errorlevel") for line in handling.splitlines())
    section = text.split("\n:key_not_saved\n", 1)[1].split("\ngoto :done\n", 1)[0]
    echoed = [line for line in section.splitlines() if line.startswith("echo")]
    message = " ".join(echoed)
    assert "The key was not saved" in message
    assert "may block PowerShell scripts" in message
    assert "System Properties ^> Environment Variables" in message
    assert "add !VAR_NAME! under \"User variables" in message
    assert "ask your administrator" in message
    # Outside any ( ) block; a bare > would redirect the echo into a file
    for line in echoed:
        assert ">" not in line.replace("^>", "")

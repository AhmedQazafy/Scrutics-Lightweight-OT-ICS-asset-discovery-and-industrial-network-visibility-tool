"""Where AI setup keeps API keys on Linux, macOS and WSL.

The keys live in ~/.scrutics/ai_keys.sh, a file Scrutics owns: mode 0600, rewritten whole on every
save, one `export VAR='key'` line per provider. ~/.bashrc gets one marked line that loads it, added
once. Scrutics never edits or removes any other line of ~/.bashrc; `export` lines for the provider
variables that it did not write are reported to the user, since they may hold an old key.

Run as `python3 -m scrutics.ai.key_store set VAR` the key is read from standard input, so it never
appears on a command line.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass, field

KEY_VARS = ("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")
KEYS_FILENAME = "ai_keys.sh"
MARKER = "# Scrutics AI keys"
SOURCE_LINE = f'[ -f "$HOME/.scrutics/{KEYS_FILENAME}" ] && . "$HOME/.scrutics/{KEYS_FILENAME}"  {MARKER}'

_EXPORT_RE = re.compile(r"^\s*export\s+(" + "|".join(KEY_VARS) + r")=")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class KeyStoreError(Exception):
    """The key could not be stored; the message says why."""


@dataclass
class SaveResult:
    keys_file: str
    bashrc: str
    line_added: bool
    # (line number, variable, comes after the Scrutics line) for export lines Scrutics did not write
    other_exports: list[tuple[int, str, bool]] = field(default_factory=list)

    def messages(self, var_name: str) -> list[str]:
        lines = [f"Key saved to ~/.scrutics/{KEYS_FILENAME} (readable only by you)."]
        if self.line_added:
            lines.append("Added one line to ~/.bashrc that loads it in new terminals.")
        else:
            lines.append("~/.bashrc already loads it.")
        for number, name, after in self.other_exports:
            note = f"~/.bashrc line {number} also sets {name} (possibly an old key); Scrutics did not change it."
            if after and name == var_name:
                note += " It comes after the Scrutics line, so it replaces the key just saved in new terminals."
            lines.append(note + " Remove it if it is no longer needed.")
        return lines


def _quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _read_keys(path: str) -> dict[str, str]:
    """The keys in a file Scrutics wrote; lines it cannot read are dropped."""
    keys: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    parts = shlex.split(line, comments=True)
                except ValueError:
                    continue
                if len(parts) == 2 and parts[0] == "export" and "=" in parts[1]:
                    name, value = parts[1].split("=", 1)
                    if name in KEY_VARS and value:
                        keys[name] = value
    except FileNotFoundError:
        pass
    return keys


def _write_private(path: str, content: str) -> None:
    """Replace path with content through a new file created with mode 0600 in the same directory."""
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".ai_keys.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def save_key(var_name: str, key: str, home: str | None = None) -> SaveResult:
    """Store key for var_name and make new shells load it. Raises KeyStoreError with a reason."""
    if var_name not in KEY_VARS:
        raise KeyStoreError(f"Unknown key variable {var_name!r}.")
    key = (key or "").strip()
    if not key:
        raise KeyStoreError("No key entered.")
    if _CONTROL_RE.search(key):
        raise KeyStoreError("The key contains a line break or another control character; paste it again.")

    home = home or os.path.expanduser("~")
    directory = os.path.join(home, ".scrutics")
    keys_file = os.path.join(directory, KEYS_FILENAME)
    bashrc = os.path.join(home, ".bashrc")
    try:
        if not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
        keys = _read_keys(keys_file)
        keys[var_name] = key
        content = "\n".join(
            [f"{MARKER}. Written by Scrutics AI setup; rewritten whole on every setup.",
             *(f"export {name}={_quote(keys[name])}" for name in KEY_VARS if name in keys)]
        ) + "\n"
        _write_private(keys_file, content)

        existing = ""
        if os.path.exists(bashrc):
            with open(bashrc, encoding="utf-8", errors="replace") as f:
                existing = f.read()
        lines = existing.splitlines()
        marked = [i for i, line in enumerate(lines) if MARKER in line and KEYS_FILENAME in line]
        line_added = not marked
        if line_added:
            # Appended, never rewritten: the rest of the file stays exactly as it was
            with open(bashrc, "a", encoding="utf-8") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                f.write(SOURCE_LINE + "\n")
            marked_at = len(lines)
        else:
            marked_at = marked[0]
    except OSError as e:
        raise KeyStoreError(f"Could not store the key: {type(e).__name__}: {e.strerror or e}") from None

    others = []
    for number, line in enumerate(lines, start=1):
        match = _EXPORT_RE.match(line)
        if match:
            others.append((number, match.group(1), number - 1 > marked_at))
    os.environ[var_name] = key
    return SaveResult(keys_file, bashrc, line_added, others)


def store_for_setup(var_name: str, key: str) -> list[str]:
    """Store a key entered during setup and return the lines to show the user.

    On Windows there is no ~/.bashrc to load a file from: the key is kept for this session only and
    the user is pointed to scrutics_ai_setup.bat, which stores it as a per-user variable.
    """
    if os.name == "nt":
        key = (key or "").strip()
        if not key or _CONTROL_RE.search(key):
            raise KeyStoreError("The key is empty or contains a control character; paste it again.")
        os.environ[var_name] = key
        return [f"Key kept for this session only. To keep it, run scrutics_ai_setup.bat, which stores "
                f"{var_name} for your Windows account without showing the key."]
    return save_key(var_name, key).messages(var_name)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "set" or argv[1] not in KEY_VARS:
        sys.stderr.write(f"usage: python3 -m scrutics.ai.key_store set {{{'|'.join(KEY_VARS)}}} < key\n")
        return 2
    try:
        result = save_key(argv[1], sys.stdin.readline())
    except KeyStoreError as e:
        sys.stderr.write(f" {e}\n")
        return 1
    for line in result.messages(argv[1]):
        print(f" {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

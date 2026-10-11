"""
Download the full IEEE OUI database and place it next to the classifier.
Run this once on a machine with internet access.

Usage:
    python scripts/download_oui.py

The downloaded oui.txt will be used automatically by Scrutics
in preference to the bundled ics_oui.txt. The file is validated before it replaces an
existing one; a failed download or an invalid file leaves the existing file unchanged.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scrutics.classifier.oui import (  # noqa: E402
    IEEE_OUI_URL, OUIDownloadError, fetch_oui_database, validate_oui_file,
)

OUI_URL = IEEE_OUI_URL
DEST = os.path.join(
    os.path.dirname(__file__),
    "..", "scrutics", "classifier", "oui.txt"
)


def main():
    print(f"[*] Downloading OUI database from {OUI_URL}")
    try:
        data, _ = fetch_oui_database(OUI_URL)
    except OUIDownloadError as e:
        print(f"[!] Could not download the OUI database: {e}. {os.path.abspath(DEST)} was not changed.")
        print("[!] Download it in a browser instead and save it as scrutics/classifier/oui.txt:")
        print(f"    {OUI_URL}")
        return 1
    temp = DEST + ".tmp"
    with open(temp, "wb") as f:
        f.write(data)
    report = validate_oui_file(temp)
    if not report["valid"] or report["entry_count"] < 1000:
        os.remove(temp)
        print(f"[!] The downloaded file is not a valid OUI database ({report.get('error') or str(report['entry_count']) + ' entries'}); "
              f"{os.path.abspath(DEST)} was not changed.")
        return 1
    os.replace(temp, DEST)
    print(f"[+] Done. {report['entry_count']} OUI entries saved to {os.path.abspath(DEST)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

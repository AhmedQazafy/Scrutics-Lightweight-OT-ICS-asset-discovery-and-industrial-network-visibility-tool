"""
Startup dependency checker.
Delegates to scrutics.diagnostics so the logic lives in one place.
"""

from scrutics.diagnostics import check_dependencies as _check


def check_dependencies(headless: bool = False) -> bool:
    """
    Check required dependencies. Print clear errors if any are missing.
    Returns True if all required deps are present, False otherwise.
    """
    results = _check(headless=headless)
    missing = [r for r in results if not r["ok"]]
    if not missing:
        return True
    print("\n  [!] Scrutics: missing required dependencies\n")
    for r in missing:
        print(f"  Missing : {r['name']}")
        print(f"  Install : {r['install_cmd']}\n")
    return False

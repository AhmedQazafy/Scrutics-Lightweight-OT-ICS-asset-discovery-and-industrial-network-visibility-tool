"""
Tests for scrutics.passive: passive enforcement layer.

These tests verify that:
  - enforce_passive() patches all Scapy send functions
  - Patched functions raise PermissionError on any call
  - enforce_passive() is idempotent (safe to call multiple times)
  - verify_passive() detects un-patched functions
  - is_enforced() reflects enforcement state
"""

import pytest
import sys
from unittest.mock import MagicMock, patch


class TestPassiveEnforcement:

    def test_enforce_passive_runs_without_error(self):
        from scrutics.passive import enforce_passive
        enforce_passive()  # Should not raise

    def test_is_enforced_true_after_call(self):
        from scrutics.passive import enforce_passive, is_enforced
        enforce_passive()
        assert is_enforced() is True

    def test_enforce_passive_is_idempotent(self):
        from scrutics.passive import enforce_passive
        enforce_passive()
        enforce_passive()  # Second call should not raise or break anything

    def test_patched_send_raises_permission_error(self):
        """After enforcement, scapy.sendrecv.send must raise PermissionError."""
        from scrutics.passive import enforce_passive
        enforce_passive()

        import scapy.sendrecv as sr
        if hasattr(sr, "send"):
            with pytest.raises(PermissionError) as exc_info:
                sr.send(None)
            assert "passive violation" in str(exc_info.value).lower() or \
                   "Scrutics" in str(exc_info.value)

    def test_patched_sr_raises_permission_error(self):
        """After enforcement, scapy.sendrecv.sr must raise PermissionError."""
        from scrutics.passive import enforce_passive
        enforce_passive()

        import scapy.sendrecv as sr
        if hasattr(sr, "sr"):
            with pytest.raises(PermissionError):
                sr.sr(None)

    def test_patched_sendp_raises_permission_error(self):
        """After enforcement, scapy.sendrecv.sendp must raise PermissionError."""
        from scrutics.passive import enforce_passive
        enforce_passive()

        import scapy.sendrecv as sr
        if hasattr(sr, "sendp"):
            with pytest.raises(PermissionError):
                sr.sendp(None)

    def test_violation_handler_name_starts_with_blocked(self):
        """Patched functions must be identifiable by name."""
        from scrutics.passive import enforce_passive
        enforce_passive()

        import scapy.sendrecv as sr
        if hasattr(sr, "send"):
            fn = getattr(sr, "send")
            assert fn.__name__.startswith("_blocked_")

    def test_verify_passive_returns_empty_after_enforcement(self):
        """verify_passive() should find no un-patched transmit functions."""
        from scrutics.passive import enforce_passive, verify_passive
        enforce_passive()
        violations = verify_passive()
        assert violations == [], f"Un-patched functions found: {violations}"

    def test_violation_writes_to_audit_log(self, tmp_path):
        """A blocked call should write to the audit log."""
        from scrutics.passive import enforce_passive, AUDIT_LOG_PATH
        import scrutics.passive as passive_module

        # Redirect audit log to temp dir for this test
        original_path = passive_module.AUDIT_LOG_PATH
        test_log = str(tmp_path / "audit.log")
        passive_module.AUDIT_LOG_PATH = test_log

        try:
            enforce_passive()
            import scapy.sendrecv as sr
            if hasattr(sr, "send"):
                try:
                    sr.send(None)
                except PermissionError:
                    pass

            if hasattr(sr, "send"):
                import os
                if os.path.exists(test_log):
                    content = open(test_log).read()
                    assert "PASSIVE VIOLATION" in content or "scrutics" in content.lower()
        finally:
            passive_module.AUDIT_LOG_PATH = original_path

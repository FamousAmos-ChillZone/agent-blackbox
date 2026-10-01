"""kernel.redaction — THE redaction implementation (G1).

Regression for KI-178 (2026-10-01): the private-key rule matched only the
BEGIN header, so redaction replaced the header and left the key body in the
local audit log (and in what the opt-in LLM reviewer sends out); secret
assignments like ``DB_PASSWORD=...`` were not redacted in the audit log at all.
"""

from __future__ import annotations

from plugins.blackbox.audit import redaction as audit_redaction
from plugins.blackbox.detection import content_scanners
from plugins.blackbox.kernel.redaction import redact_secret_values

KEY_BODY = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"
PEM = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----"


def test_private_key_block_is_removed_whole():
    out = redact_secret_values(f"cat id_rsa\n{PEM}\nafter")
    assert KEY_BODY not in out
    assert out == "cat id_rsa\n[REDACTED_PRIVATE_KEY]\nafter"


def test_private_key_block_cut_off_is_removed_to_the_end():
    out = redact_secret_values(f"before\n-----BEGIN PRIVATE KEY-----\n{KEY_BODY}")
    assert out == "before\n[REDACTED_PRIVATE_KEY]"


def test_secret_assignment_keeps_key_drops_value():
    assert redact_secret_values("export DB_PASSWORD=hunter2secret") == "export DB_PASSWORD=[REDACTED]"
    assert redact_secret_values('{"api_key": "abcd1234efgh"}') == '{"api_key": "[REDACTED]"}'


def test_known_key_inside_an_assignment_keeps_its_typed_marker():
    out = redact_secret_values("ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz")
    assert out == "ANTHROPIC_API_KEY=[REDACTED_ANTHROPIC_API_KEY]"


def test_bearer_token_is_redacted():
    assert redact_secret_values("Authorization: Bearer abc.def.ghi") == "Authorization: Bearer [REDACTED]"


def test_ordinary_prose_about_secrets_is_untouched():
    for text in ("the token generation process", "password reset link sent", "rotate the api key soon"):
        assert redact_secret_values(text) == text


def test_audit_log_text_drops_key_body_and_assignments():
    out = audit_redaction.sanitize_text(f"{PEM}\nDB_PASSWORD=hunter2secret")
    assert KEY_BODY not in out
    assert "hunter2secret" not in out


def test_audit_redacts_before_truncating():
    out = audit_redaction.sanitize_text(f"x{PEM}", max_len=40)
    assert "MIIEow" not in out


def test_detection_still_flags_a_private_key_header():
    hits = content_scanners.scan_secret_values(f"echo {PEM[:40]}")
    assert {"type": "private-key", "severity": "critical"} in hits

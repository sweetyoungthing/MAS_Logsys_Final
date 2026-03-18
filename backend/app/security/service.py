"""Helpers for enforcing security policy on service outputs."""

from __future__ import annotations

from typing import Any

from .analyzer import get_security_analyzer
from .exceptions import SecurityInterceptionError


def ensure_safe_response(payload: Any, *, source: str, policy_name: str) -> None:
    """Analyze an outbound payload and raise if it should be blocked."""
    analyzer = get_security_analyzer()
    assessment = analyzer.assess_payload(
        payload,
        source=source,
        direction="response",
        policy_name=policy_name,
    )
    if assessment.blocked:
        raise SecurityInterceptionError(assessment)

"""FastAPI security dependencies for request inspection."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict

from fastapi import Request

from .analyzer import get_security_analyzer
from .exceptions import SecurityInterceptionError


async def _extract_request_payload(request: Request) -> Dict[str, Any]:
    """Extract a normalized request payload for security analysis."""
    payload: Dict[str, Any] = {
        "path": request.url.path,
        "method": request.method,
        "query": dict(request.query_params),
    }

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            payload["body"] = await request.json()
        except Exception:
            payload["body"] = {}
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form = await request.form()
            payload["body"] = dict(form)
        except Exception:
            payload["body"] = {}

    return payload


def security_guard(policy_name: str) -> Callable[[Request], Awaitable[None]]:
    """Create a dependency that blocks high-risk inbound payloads."""

    async def dependency(request: Request) -> None:
        analyzer = get_security_analyzer()
        payload = await _extract_request_payload(request)
        assessment = analyzer.assess_payload(
            payload,
            source=request.url.path,
            direction="request",
            policy_name=policy_name,
        )
        request.state.security_assessment = assessment
        if assessment.blocked:
            raise SecurityInterceptionError(assessment)

    return dependency

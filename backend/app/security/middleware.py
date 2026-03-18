"""FastAPI middleware for translating security exceptions into API responses."""

from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .exceptions import SecurityInterceptionError
from .models import SecurityErrorResponse

logger = logging.getLogger(__name__)


class SecurityExceptionMiddleware(BaseHTTPMiddleware):
    """Convert intercepted security errors into a standardized JSON response."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        """Execute the next middleware and catch security interception errors."""
        try:
            return await call_next(request)
        except SecurityInterceptionError as exc:
            assessment = exc.assessment
            logger.warning(
                "Security request blocked",
                extra={
                    "path": request.url.path,
                    "method": request.method,
                    "risk_level": assessment.risk_level,
                    "risk_score": assessment.risk_score,
                    "policy_name": assessment.metadata.get("policy_name"),
                },
            )
            body = SecurityErrorResponse(
                message=assessment.message,
                risk_level=assessment.risk_level,
                risk_score=assessment.risk_score,
                findings=assessment.findings,
            )
            return JSONResponse(status_code=403, content=body.model_dump())

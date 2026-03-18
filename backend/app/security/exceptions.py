"""Custom exceptions for the backend security layer."""

from .models import SecurityAssessment


class SecurityInterceptionError(Exception):
    """Raised when a request or response is blocked by security policy."""

    def __init__(self, assessment: SecurityAssessment):
        """Initialize the exception with the triggering assessment."""
        super().__init__(assessment.message)
        self.assessment = assessment

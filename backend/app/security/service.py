"""Helpers for enforcing security policy on service outputs."""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from .analyzer import get_security_analyzer
from .exceptions import SecurityInterceptionError
from .models import SecurityAssessment, SecurityFinding


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


def _to_risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _collect_cata_log_findings(events: Sequence[Dict[str, Any]]) -> List[SecurityFinding]:
    ranked = sorted(
        (
            ev for ev in events
            if isinstance(ev, dict) and isinstance((ev.get("security") or {}).get("findings"), list)
        ),
        key=lambda ev: int((ev.get("security") or {}).get("risk_score") or 0),
        reverse=True,
    )

    out: List[SecurityFinding] = []
    seen: set[tuple[str, str]] = set()
    for event in ranked[:5]:
        for finding in (event.get("security") or {}).get("findings", [])[:5]:
            category = str(finding.get("category") or "Unknown")
            evidence = str(finding.get("evidence") or "")[:240]
            key = (category, evidence)
            if not evidence or key in seen:
                continue
            seen.add(key)
            out.append(
                SecurityFinding(
                    category=category,
                    severity=max(1, min(5, int(finding.get("severity") or 3))),
                    confidence=max(0.0, min(1.0, float(finding.get("confidence") or 0.5))),
                    evidence=evidence,
                )
            )
            if len(out) >= 8:
                return out
    return out


def ensure_safe_mas_execution(
    summary: Dict[str, Any],
    *,
    source: str,
    policy_name: str,
    events: Sequence[Dict[str, Any]] | None = None,
) -> None:
    """Block final output when CATA-Log finds a successful or compromised MAS attack chain."""
    findings_by_category = dict(summary.get("findings_by_category") or {})
    successful_attack_chains = int(summary.get("successful_attack_chain_count") or 0)
    attempted_attack_chains = int(summary.get("attempted_attack_chain_count") or 0)
    max_risk_score = int(summary.get("max_risk_score") or 0)
    compromised_decisions = int(findings_by_category.get("CompromisedDecision") or 0)
    blocked = successful_attack_chains > 0 or compromised_decisions > 0

    if not blocked:
        return

    findings = _collect_cata_log_findings(list(events or ()))
    assessment = SecurityAssessment(
        blocked=True,
        risk_level=_to_risk_level(max_risk_score),
        risk_score=max_risk_score,
        message="MAS运行链路检测到高风险攻击传播，已阻止返回结果。",
        findings=findings,
        metadata={
            "source": source,
            "direction": "response",
            "policy_name": policy_name,
            "method": "CATA-Log",
            "successful_attack_chain_count": successful_attack_chains,
            "attempted_attack_chain_count": attempted_attack_chains,
            "attack_chains": list(summary.get("attack_chains") or [])[:5],
            "findings_by_category": findings_by_category,
        },
    )
    raise SecurityInterceptionError(assessment)

"""Heuristic security analyzer adapted from the project's MAS security research."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Sequence

from .models import SecurityAssessment, SecurityFinding


INJECTION_PATTERNS: Sequence[str] = (
    r"ignore (all|any|the)?\s*(previous|prior|above)\s*instructions",
    r"forget (all|any|the)?\s*(previous|prior)\s*(instructions|rules|policies)?",
    r"(reveal|show|print|output).{0,24}(system prompt|developer prompt|hidden prompt)",
    r"bypass (policy|safety|guardrail)",
    r"you must obey|must follow this only|override all rules",
    r"忽略(之前|此前|以上|前文).{0,14}(提示|指令|规则|约束)",
    r"无视(之前|此前|以上|前文).{0,14}(提示|指令|规则|约束)",
    r"忘记(之前|此前|以上|前文).{0,14}(提示|指令|规则|约束)",
    r"(泄露|输出|展示).{0,24}(系统提示词|开发者提示词|隐藏提示词)",
)

COMM_SABOTAGE_PATTERNS: Sequence[str] = (
    r"ignore messages? from",
    r"do not trust",
    r"stop communicating with",
    r"replace (their|the) answer",
    r"disable (verification|validation|guardrails?)",
    r"忽略.+(消息|结果|回复)",
    r"(不要|停止).{0,16}(与|和).{0,40}(通信|沟通)",
    r"(覆盖|替换).+(计划|答案|结果)",
)

EXFIL_PATTERNS: Sequence[str] = (
    r"(send|share|reveal|export|leak).{0,30}(api[-_ ]?key|token|password|secret|private key|credential)",
    r"(upload|post).{0,30}(chat history|conversation|logs?)",
    r"(发送|分享|泄露|导出).{0,24}(api[-_ ]?key|密钥|token|密码|凭证|私钥)",
    r"(上传|发送).{0,24}(对话记录|聊天记录|日志)",
)

SECRET_TOKEN_PATTERNS: Sequence[str] = (
    r"sk-[A-Za-z0-9_-]{16,}",
    r"tvly-[A-Za-z0-9_-]{16,}",
    r"AKIA[0-9A-Z]{16}",
    r"Bearer\s+[A-Za-z0-9._-]{20,}",
)

IMPERATIVE_CUES: Sequence[str] = (
    "must",
    "obey",
    "ignore",
    "bypass",
    "reveal",
    "override",
    "replace",
    "disable",
    "send",
    "upload",
    "必须",
    "务必",
    "立刻",
    "马上",
    "忽略",
    "无视",
    "服从",
    "覆盖",
    "替换",
    "禁用",
    "发送",
    "上传",
)


class SecurityAnalyzer:
    """Analyze inbound or outbound payloads for prompt injection style risks."""

    def __init__(self, request_block_threshold: int = 65, response_block_threshold: int = 65):
        """Create a security analyzer with separate thresholds for requests and responses."""
        self.request_block_threshold = request_block_threshold
        self.response_block_threshold = response_block_threshold

    def assess_payload(
        self,
        payload: Any,
        *,
        source: str,
        direction: str,
        policy_name: str,
    ) -> SecurityAssessment:
        """Assess a request/response payload and return a structured decision."""
        texts = self._extract_texts(payload)
        findings: List[SecurityFinding] = []
        matched_categories: Dict[str, int] = {
            "PromptInjection": 0,
            "CommunicationSabotage": 0,
            "DataExfiltrationAttempt": 0,
        }

        imperative_hits = 0
        evidence_samples: List[str] = []
        contains_secret_token = False

        for text in texts:
            normalized = self._normalize_text(text)
            if not normalized:
                continue

            imperative_hits += sum(1 for cue in IMPERATIVE_CUES if cue in normalized)
            contains_secret_token = contains_secret_token or any(
                re.search(pattern, text, flags=re.IGNORECASE) for pattern in SECRET_TOKEN_PATTERNS
            )

            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    matched_categories["PromptInjection"] += 1
                    evidence_samples.append(text[:180])
                    findings.append(
                        SecurityFinding(
                            category="PromptInjection",
                            severity=4,
                            confidence=0.86,
                            evidence=text[:180],
                        )
                    )
                    break

            for pattern in COMM_SABOTAGE_PATTERNS:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    matched_categories["CommunicationSabotage"] += 1
                    evidence_samples.append(text[:180])
                    findings.append(
                        SecurityFinding(
                            category="CommunicationSabotage",
                            severity=4,
                            confidence=0.8,
                            evidence=text[:180],
                        )
                    )
                    break

            for pattern in EXFIL_PATTERNS:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    matched_categories["DataExfiltrationAttempt"] += 1
                    evidence_samples.append(text[:180])
                    findings.append(
                        SecurityFinding(
                            category="DataExfiltrationAttempt",
                            severity=5,
                            confidence=0.9,
                            evidence=text[:180],
                        )
                    )
                    break

        if contains_secret_token:
            findings.append(
                SecurityFinding(
                    category="SecretTokenLeakage",
                    severity=5,
                    confidence=0.98,
                    evidence="payload contains a token-like secret",
                )
            )

        risk_score = self._compute_risk_score(matched_categories, imperative_hits, contains_secret_token)
        risk_level = self._to_risk_level(risk_score)
        threshold = self.response_block_threshold if direction == "response" else self.request_block_threshold
        blocked = risk_score >= threshold

        if blocked:
            message = "请求包含高风险指令，已被安全策略拦截。" if direction == "request" else "响应内容命中安全策略，已阻止返回。"
        elif risk_score >= 30:
            message = "检测到潜在风险内容，请谨慎处理。"
        else:
            message = "未检测到需要拦截的风险。"

        unique_findings = self._dedupe_findings(findings)
        return SecurityAssessment(
            blocked=blocked,
            risk_level=risk_level,
            risk_score=risk_score,
            message=message,
            findings=unique_findings,
            metadata={
                "source": source,
                "direction": direction,
                "policy_name": policy_name,
                "text_count": len(texts),
                "matched_categories": matched_categories,
                "imperative_hits": imperative_hits,
                "contains_secret_token": contains_secret_token,
                "evidence_samples": evidence_samples[:5],
            },
        )

    def _extract_texts(self, payload: Any) -> List[str]:
        """Flatten a payload into candidate text fragments."""
        texts: List[str] = []

        def visit(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, str):
                stripped = value.strip()
                if stripped:
                    texts.append(stripped)
                return
            if hasattr(value, "model_dump"):
                visit(value.model_dump())
                return
            if isinstance(value, dict):
                for item in value.values():
                    visit(item)
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    visit(item)
                return
            if isinstance(value, (int, float, bool)):
                return
            try:
                visit(json.loads(json.dumps(value, ensure_ascii=False, default=str)))
            except Exception:
                visit(str(value))

        visit(payload)
        return texts

    @staticmethod
    def _normalize_text(text: str) -> str:
        """Normalize text for lightweight keyword matching."""
        return re.sub(r"\s+", " ", text).strip().lower()

    @staticmethod
    def _compute_risk_score(
        matched_categories: Dict[str, int],
        imperative_hits: int,
        contains_secret_token: bool,
    ) -> int:
        """Compute a coarse risk score from matched categories and intent cues."""
        score = 0
        score += min(70, matched_categories["PromptInjection"] * 60)
        score += min(60, matched_categories["CommunicationSabotage"] * 45)
        score += min(75, matched_categories["DataExfiltrationAttempt"] * 55)
        score += min(20, imperative_hits * 3)
        if contains_secret_token:
            score = max(score, 90)
        return min(100, score)

    @staticmethod
    def _to_risk_level(score: int) -> str:
        """Map numeric risk scores to risk levels."""
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "none"

    @staticmethod
    def _dedupe_findings(findings: Iterable[SecurityFinding]) -> List[SecurityFinding]:
        """Remove duplicate findings while preserving order."""
        deduped: List[SecurityFinding] = []
        seen: set[tuple[str, str]] = set()
        for finding in findings:
            key = (finding.category, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped


_SECURITY_ANALYZER = SecurityAnalyzer()


def get_security_analyzer() -> SecurityAnalyzer:
    """Return the shared security analyzer instance."""
    return _SECURITY_ANALYZER

from dataclasses import dataclass, field
from typing import Dict, List

from core.cookie_utils import CookieObservation, is_auth_cookie
from core.entropy import shannon_entropy
from config import ENTROPY_CRITICAL_THRESHOLD, ENTROPY_WARNING_THRESHOLD, MIN_SESSION_TOKEN_LENGTH


@dataclass
class Finding:
    cookie_name: str
    issue: str
    severity: str
    details: str


@dataclass
class AnalysisResult:
    target: str
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)


def analyze_cookies(target: str, cookies: List[CookieObservation]) -> AnalysisResult:
    findings: List[Finding] = []
    for cookie in cookies:
        if not is_auth_cookie(cookie):
            continue
        if not cookie.secure:
            findings.append(
                Finding(
                    cookie_name=cookie.name,
                    issue="Missing Secure flag",
                    severity="High",
                    details="Authentication cookie is not marked Secure and could be sent over HTTP.",
                )
            )
        if not cookie.http_only:
            findings.append(
                Finding(
                    cookie_name=cookie.name,
                    issue="Missing HttpOnly flag",
                    severity="Medium",
                    details="Authentication cookie is accessible to client-side scripts.",
                )
            )
        if not cookie.same_site:
            findings.append(
                Finding(
                    cookie_name=cookie.name,
                    issue="Missing SameSite attribute",
                    severity="Medium",
                    details="Authentication cookie lacks SameSite and may be exposed to CSRF.",
                )
            )
        if len(cookie.value) < MIN_SESSION_TOKEN_LENGTH:
            findings.append(
                Finding(
                    cookie_name=cookie.name,
                    issue="Short session token",
                    severity="High",
                    details=f"Token length is {len(cookie.value)} characters which is below recommended minimum.",
                )
            )
        entropy = shannon_entropy(cookie.value)
        if entropy and entropy < ENTROPY_WARNING_THRESHOLD:
            severity = "Critical" if entropy < ENTROPY_CRITICAL_THRESHOLD else "High"
            findings.append(
                Finding(
                    cookie_name=cookie.name,
                    issue="Low session token entropy",
                    severity=severity,
                    details=f"Shannon entropy is {entropy:.2f} bits per character.",
                )
            )
    summary = {"total_findings": len(findings)}
    return AnalysisResult(target=target, findings=findings, summary=summary)

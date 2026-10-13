"""Deterministic evidence scoring engine for false-positive reduction."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from api.models import FindingClassification


@dataclass
class EvidenceScoreCard:
    total_score: int
    classification: FindingClassification
    confidence_label: str  # "Confirmed", "Probable", "Tentative", "Informational", "Rejected"
    reasons: list[str] = field(default_factory=list)
    deductions: list[str] = field(default_factory=list)
    false_positive_indicators: list[str] = field(default_factory=list)


def calculate_evidence_score(
    has_exact_target_and_param: bool = False,
    is_reproducible: bool = False,
    has_meaningful_difference: bool = False,
    has_direct_security_impact: bool = False,
    has_browser_confirmation: bool = False,
    has_independent_detector_agreement: bool = False,
    is_generic_error_or_custom_404: bool = False,
    is_login_redirect_or_waf: bool = False,
    is_unstable_response: bool = False,
    is_observation_only: bool = False,
    has_persisted_evidence: bool = False,
    is_duplicate_or_rejected: bool = False,
) -> EvidenceScoreCard:
    """
    Computes deterministic evidence score based on strict additive/subtractive rules:
    +2 exact target and parameter match
    +2 reproducible across repeated requests
    +2 meaningful baseline/candidate difference
    +2 direct evidence of security impact
    +1 browser confirmation
    +1 independent detector agreement
    -2 generic error or custom 404 response
    -2 login redirect or WAF block
    -2 unstable/dynamic response
    -2 observation-only signal
    -3 no persisted evidence
    -3 duplicate or already rejected candidate
    """
    score = 0
    reasons: list[str] = []
    deductions: list[str] = []
    fp_indicators: list[str] = []

    # Positive additions
    if has_exact_target_and_param:
        score += 2
        reasons.append("+2 Exact target and parameter verified.")
    if is_reproducible:
        score += 2
        reasons.append("+2 Behavior verified across repeated requests.")
    if has_meaningful_difference:
        score += 2
        reasons.append("+2 Meaningful baseline/candidate difference confirmed.")
    if has_direct_security_impact:
        score += 2
        reasons.append("+2 Direct evidence of security impact present.")
    if has_browser_confirmation:
        score += 1
        reasons.append("+1 Browser DOM / execution confirmation verified.")
    if has_independent_detector_agreement:
        score += 1
        reasons.append("+1 Agreement confirmed across independent detector modules.")

    # Deductions
    if is_generic_error_or_custom_404:
        score -= 2
        deductions.append("-2 Candidate response is generic error or custom 404.")
        fp_indicators.append("Generic error / custom 404 response.")
    if is_login_redirect_or_waf:
        score -= 2
        deductions.append("-2 Candidate redirected to login or hit WAF challenge.")
        fp_indicators.append("Login redirect or WAF challenge block.")
    if is_unstable_response:
        score -= 2
        deductions.append("-2 Unstable or volatile dynamic response behavior.")
        fp_indicators.append("Response content fluctuates dynamically across safe requests.")
    if is_observation_only:
        score -= 2
        deductions.append("-2 Finding is an observation-only signal (surface discovery, header, banner).")
        fp_indicators.append("Observation-only telemetry signal.")
    if not has_persisted_evidence:
        score -= 3
        deductions.append("-3 No persisted evidence artifact linked to finding.")
        fp_indicators.append("Lacks persisted raw request/response evidence.")
    if is_duplicate_or_rejected:
        score -= 3
        deductions.append("-3 Duplicate or previously rejected candidate.")
        fp_indicators.append("Duplicate candidate or previously rejected pattern.")

    # Clamp score to 0 minimum
    score = max(0, score)

    # Classification mapping:
    # 0-2: Rejected or Informational
    # 3-4: Tentative
    # 5-7: Probable
    # 8+: Confirmed (only if persisted evidence exists and not observation only)
    if is_observation_only:
        classification = FindingClassification.informational
        confidence_label = "Informational"
    elif score <= 2:
        classification = FindingClassification.rejected if (is_generic_error_or_custom_404 or is_login_redirect_or_waf or is_duplicate_or_rejected) else FindingClassification.informational
        confidence_label = classification.value
    elif 3 <= score <= 4:
        classification = FindingClassification.tentative
        confidence_label = "Tentative"
    elif 5 <= score <= 7:
        classification = FindingClassification.probable
        confidence_label = "Probable"
    else:
        # Score >= 8
        if has_persisted_evidence and not is_observation_only:
            classification = FindingClassification.confirmed
            confidence_label = "Confirmed"
        else:
            classification = FindingClassification.probable
            confidence_label = "Probable"
            reasons.append("Capped at Probable: Confirmed status strictly requires verified evidence artifact.")

    return EvidenceScoreCard(
        total_score=score,
        classification=classification,
        confidence_label=confidence_label,
        reasons=reasons,
        deductions=deductions,
        false_positive_indicators=fp_indicators,
    )

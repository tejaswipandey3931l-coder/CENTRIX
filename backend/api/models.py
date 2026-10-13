"""Pydantic v2 models shared across API and scanner."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


# ── Enums ─────────────────────────────────────────────────────────
class ScanProfile(str, Enum):
    quick = "quick"
    full = "full"
    api = "api"
    custom = "custom"


class SafetyLevel(str, Enum):
    passive = "passive"
    standard = "standard"
    aggressive = "aggressive"


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    paused = "paused"
    completed = "completed"
    stopped = "stopped"
    error = "error"


class ScanStage(str, Enum):
    # Durable State Machine stages
    created = "created"
    authorization_pending = "authorization_pending"
    planning = "planning"
    discovering = "discovering"
    crawling = "crawling"
    browser_testing = "browser_testing"
    passive_analysis = "passive_analysis"
    active_testing = "active_testing"
    validating = "validating"
    adjudicating = "adjudicating"
    reporting = "reporting"
    completed = "completed"

    # Legacy aliases for compatibility
    validate = "validate"
    discover = "discover"
    crawl = "crawl"
    probe = "probe"
    analyze = "analyze"
    report = "report"
    done = "done"


class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    info = "Info"


class FindingStatus(str, Enum):
    open = "Open"
    in_review = "In Review"
    fixed = "Fixed"
    accepted = "Accepted"
    still_open = "Still Open"
    needs_review = "Needs Review"


class FindingClassification(str, Enum):
    confirmed = "Confirmed"
    probable = "Probable"
    tentative = "Tentative"
    informational = "Informational"
    rejected = "Rejected"


# ── Scan Configuration ────────────────────────────────────────────
class ScanConfig(BaseModel):
    target: str = Field(..., description="Primary target URL")
    scope: list[str] = Field(default_factory=list, description="Scope rules / URL patterns")
    imported_urls: list[str] = Field(default_factory=list, description="Endpoints imported from OpenAPI, Postman, HAR, or GraphQL")
    imported_requests: list[dict] = Field(default_factory=list, description="Full imported API requests including method, headers, and sample body")
    sequence_workflows: list[dict] = Field(default_factory=list, description="Stateful API sequence workflows to run before crawling/probing")
    browser_workflows: list[dict] = Field(default_factory=list, description="Browser macro workflows to run before crawling/probing")
    authorized: bool = Field(False, description="Operator confirms authorization to test this target")
    profile: ScanProfile = ScanProfile.full
    safety: SafetyLevel = SafetyLevel.standard
    depth: int = Field(default=3, ge=1, le=10)
    timeout: int = Field(default=30, ge=5, le=120)
    concurrency: int = Field(default=10, ge=1, le=25)
    max_requests: int = Field(default=500, ge=10, le=10_000)
    respect_robots: bool = False
    auth_token: Optional[str] = None
    label: Optional[str] = None
    environment: str = "Production"
    retest_finding_id: Optional[str] = None
    base_scan_id: Optional[str] = None


# ── Scan State ────────────────────────────────────────────────────
class ScanState(BaseModel):
    id: str
    config: ScanConfig
    status: ScanStatus = ScanStatus.pending
    stage: ScanStage = ScanStage.validate
    progress: int = 0            # 0-100
    findings_count: int = 0
    requests_sent: int = 0
    urls_discovered: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_msg: Optional[str] = None
    duration_s: Optional[float] = None
    checkpoint_stage: Optional[str] = None
    can_resume: bool = False


# ── Finding ───────────────────────────────────────────────────────
class Finding(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: Severity
    category: str
    target: str
    parameter: str = ""
    confidence: Literal["Confirmed", "Probable", "Tentative", "Informational", "Rejected"] = "Tentative"
    classification: FindingClassification = FindingClassification.tentative
    status: FindingStatus = FindingStatus.open
    found_at: datetime = Field(default_factory=datetime.utcnow)
    description: str = ""
    recommendation: str = ""
    evidence: str = ""
    cwe: Optional[str] = None
    cvss: Optional[float] = None

    # Evidence-based pipeline fields
    vuln_type: str = "unknown"
    detection_source: str = "dast_engine"
    detection_rule: Optional[str] = None
    evidence_artifact_ids: list[str] = Field(default_factory=list)
    request_response_refs: list[str] = Field(default_factory=list)
    reproduction_status: str = "untested"  # reproduced, untested, failed
    confidence_score: int = 4              # deterministic score 0-10
    confidence_reasons: list[str] = Field(default_factory=list)
    false_positive_indicators: list[str] = Field(default_factory=list)
    validation_status: str = "pending"     # validated, pending, rejected
    model_review_status: str = "unreviewed"# adjudicated, unreviewed
    human_review_status: str = "unreviewed"# unreviewed, approved, rejected
    why_false_positive_risk: Optional[str] = None
    affected_urls_count: int = 1
    example_urls: list[str] = Field(default_factory=list)
    request_method: str = "GET"
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    reproduction_curl: Optional[str] = None

    @model_validator(mode="after")
    def enforce_evidence_for_confirmation(self) -> "Finding":
        """Safety invariant: A finding cannot be Confirmed without evidence."""
        if self.classification == FindingClassification.confirmed:
            if not self.evidence_artifact_ids:
                self.classification = FindingClassification.tentative
                self.confidence = "Tentative"
                self.confidence_reasons.append("Downgraded from Confirmed: Missing persisted evidence artifact.")
                if not self.why_false_positive_risk:
                    self.why_false_positive_risk = "Finding lacked direct verifiable evidence artifact."
        return self


class EvidenceArtifact(BaseModel):
    id: str
    scan_id: str
    url: str
    method: str = "GET"
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    status_code: int
    content_type: str = ""
    response_length: int = 0
    response_excerpt: str = ""
    response_headers: dict[str, str] = Field(default_factory=dict)
    captured_at: datetime = Field(default_factory=datetime.utcnow)


# ── Report ────────────────────────────────────────────────────────
class ReportConfig(BaseModel):
    scan_id: str
    format: Literal["json", "html", "pdf", "sarif", "junit", "evidence", "github_issues", "jira"] = "json"
    report_type: Literal["technical", "executive", "compliance"] = "technical"
    target_scope: Optional[str] = None


class Report(BaseModel):
    id: str
    scan_id: str
    name: str
    report_type: str
    target: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    status: Literal["Pending", "Ready"] = "Pending"
    findings_count: int = 0
    size: str = "—"
    format: str = "json"
    content: Optional[str] = None   # rendered HTML/JSON string


class ManualRequest(BaseModel):
    scan_id: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None


class ResponseComparison(BaseModel):
    left_status: int
    right_status: int
    left_length: int
    right_length: int
    status_changed: bool
    length_delta: int


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class ApiImport(BaseModel):
    format: Literal["openapi", "postman", "har", "graphql"]
    document: dict
    base_url: Optional[str] = None


class AuthProfile(BaseModel):
    id: str
    name: str
    role: str = "user"
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    notes: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuthProfileInput(BaseModel):
    name: str
    role: str = "user"
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    notes: str = ""


class AuthMatrixRunRequest(BaseModel):
    scan_id: str
    request_ids: list[str] = Field(default_factory=list, max_length=30)
    profile_ids: list[str] = Field(default_factory=list, max_length=6)


# ── Differential Scanning Models ──────────────────────────────────
class FindingDiffItem(BaseModel):
    finding_id: str
    title: str
    severity: Severity
    target: str
    parameter: str = ""
    cwe: Optional[str] = None


class DifferentialScanResult(BaseModel):
    base_scan_id: str
    target_scan_id: str
    new_findings: list[FindingDiffItem] = Field(default_factory=list)
    resolved_findings: list[FindingDiffItem] = Field(default_factory=list)
    recurrent_findings: list[FindingDiffItem] = Field(default_factory=list)
    total_new: int = 0
    total_resolved: int = 0
    total_recurrent: int = 0


# ── API Responses ──────────────────────────────────────────────────
class StartScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    stage: ScanStage
    progress: int
    findings_count: int
    requests_sent: int
    urls_discovered: int
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    duration_s: Optional[float]
    checkpoint_stage: Optional[str] = None
    can_resume: bool = False

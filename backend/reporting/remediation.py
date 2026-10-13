"""Multi-language, actionable developer remediation engine for CENTRIX.

Generates framework-specific code patches, web server / edge configuration snippets,
defense-in-depth guidance, and verification unit tests across Python, Node.js,
Java, Go, PHP, Nginx, and Cloudflare.
"""
from __future__ import annotations

from typing import Any, Optional


REMEDIATION_KNOWLEDGE_BASE: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "title": "SQL Injection (CWE-89)",
        "summary": "Untrusted user input is directly concatenated into a dynamic SQL query, allowing database manipulation.",
        "code_fixes": {
            "python_fastapi": """# Safe: Use SQLAlchemy / parameterized ORM
from sqlalchemy.orm import Session
from models import User

def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()
""",
            "python_django": """# Safe: Django ORM parameterizes queries automatically
from myapp.models import User

def get_user(request, user_id):
    return User.objects.filter(id=user_id).first()
""",
            "nodejs_express": """// Safe: Parameterized query with pg / mysql2
const query = 'SELECT * FROM users WHERE id = $1';
const result = await pool.query(query, [userId]);
""",
            "java_spring": """// Safe: Spring Data JPA or PreparedStatement
@Query("SELECT u FROM User u WHERE u.id = :id")
User findByUserId(@Param("id") Long id);
""",
            "go": """// Safe: Database/sql parameterized query
var user User
err := db.QueryRowContext(ctx, "SELECT id, name FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Name)
""",
            "php": """// Safe: PDO prepared statement
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch();
""",
        },
        "server_configs": {
            "cloudflare": "Enable Cloudflare OWASP Core Ruleset (CRS) rule: 942100 (SQLi Detection).",
            "nginx": "# Block basic SQL injection keywords in query strings\nif ($query_string ~* \"union.*select|insert.*into|drop.*table\") {\n    return 403;\n}",
        },
        "prevention_checklist": [
            "Always use parameterized queries, prepared statements, or an ORM.",
            "Never construct SQL statements via string concatenation or format strings.",
            "Apply principle of least privilege to database connection credentials.",
            "Enable database query logging and anomaly detection.",
        ],
        "verification_test": """# Pytest verification: verify parameterized safety
def test_sqli_protection(client):
    response = client.get("/api/users?id=1' OR '1'='1")
    assert response.status_code in [400, 404, 422]
""",
    },

    "cross_site_scripting": {
        "title": "Cross-Site Scripting / XSS (CWE-79)",
        "summary": "Unsanitized user data is included in HTML/DOM output, enabling arbitrary JavaScript execution in user browsers.",
        "code_fixes": {
            "python_fastapi": """# Safe: Let Jinja2 or modern JSON serialization handle escaping
from fastapi.responses import HTMLResponse
import html

@app.get("/search")
def search(q: str):
    safe_q = html.escape(q)
    return HTMLResponse(f"<h1>Results for {safe_q}</h1>")
""",
            "nodejs_express": """// Safe: Use DOMPurify or sanitize-html for HTML output
import DOMPurify from 'isomorphic-dompurify';

app.post('/comment', (req, res) => {
    const cleanHTML = DOMPurify.sanitize(req.body.comment);
    res.json({ comment: cleanHTML });
});
""",
            "java_spring": """// Safe: Thymeleaf or OWASP Java HTML Sanitizer
PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
String safeHtml = policy.sanitize(untrustedHtml);
""",
            "go": """// Safe: Use html/template (context-aware escaping)
import "html/template"

tmpl := template.Must(template.New("view").Parse("<h1>Hello, {{.}}</h1>"))
tmpl.Execute(w, untrustedInput)
""",
            "php": """// Safe: htmlspecialchars with ENT_QUOTES and UTF-8
echo htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');
""",
        },
        "server_configs": {
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;",
            "cloudflare": "Add Transform Rule to set Content-Security-Policy header enforcing script-src 'self'.",
        },
        "prevention_checklist": [
            "Use context-aware output encoding (HTML body, attributes, JavaScript, CSS).",
            "Deploy a strict Content-Security-Policy (CSP) without 'unsafe-inline'.",
            "Mark sensitive session cookies as HttpOnly and Secure.",
            "Use modern frontend frameworks (React, Angular, Vue) that escape data by default.",
        ],
        "verification_test": """# Verification: ensure script tags are escaped in response
def test_xss_protection(client):
    response = client.get('/search?q=<script>alert(1)</script>')
    assert '<script>alert(1)</script>' not in response.text
    assert '&lt;script&gt;' in response.text or 'alert(1)' not in response.text
""",
    },

    "cross_site_request_forgery": {
        "title": "Cross-Site Request Forgery / CSRF (CWE-352)",
        "summary": "State-changing actions accept requests without validating an anti-CSRF token or verifying request origin.",
        "code_fixes": {
            "python_fastapi": """# Safe: Use SameSite cookies and custom header validation
response.set_cookie(
    key="session_id",
    value=token,
    httponly=True,
    secure=True,
    samesite="lax"  # or "strict"
)
""",
            "nodejs_express": """// Safe: csurf middleware or SameSite cookies
import csurf from 'csurf';
app.use(csurf({ cookie: { httpOnly: true, secure: true, sameSite: 'strict' } }));
""",
            "java_spring": """// Safe: Spring Security enables CSRF protection by default
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
    return http.build();
}
""",
            "go": """// Safe: gorilla/csrf
CSRF := csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(true), csrf.SameSite(csrf.SameSiteStrictMode))
http.ListenAndServe(":8000", CSRF(r))
""",
            "php": """// Safe: Synchronizer token pattern
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    die('Invalid CSRF token');
}
""",
        },
        "server_configs": {
            "nginx": "# Block cross-origin state changes via Sec-Fetch-Site header\nif ($http_sec_fetch_site = \"cross-site\") {\n    return 403;\n}",
            "cloudflare": "Enable Cloudflare Managed Rules for CSRF protection and check Sec-Fetch-Site header.",
        },
        "prevention_checklist": [
            "Use SameSite=Lax or SameSite=Strict on all authentication cookies.",
            "Verify anti-CSRF synchronizer tokens on all state-changing endpoints (POST/PUT/PATCH/DELETE).",
            "Validate Sec-Fetch-Site and Origin/Referer request headers.",
        ],
        "verification_test": """# Verification: confirm POST without CSRF token fails with 403
def test_csrf_token_required(client):
    response = client.post("/api/profile/update", json={"email": "attacker@evil.com"})
    assert response.status_code in [401, 403]
""",
    },

    "missing_security_headers": {
        "title": "Missing Security Headers (CWE-693)",
        "summary": "Application is missing defense-in-depth HTTP headers such as CSP, HSTS, X-Content-Type-Options, or X-Frame-Options.",
        "code_fixes": {
            "python_fastapi": """# Safe: Middleware adding security headers
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    return response
""",
            "nodejs_express": """// Safe: Use Helmet.js
import helmet from 'helmet';
app.use(helmet());
""",
            "java_spring": """// Safe: Spring Security headers configuration
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
    .frameOptions(frame -> frame.deny())
    .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
);
""",
            "go": """// Safe: Security middleware
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        next.ServeHTTP(w, r)
    })
}
""",
            "php": """// Safe: Header function calls before output
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("Content-Security-Policy: default-src 'self'");
""",
        },
        "server_configs": {
            "nginx": """# Add security headers globally
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self';" always;
""",
            "cloudflare": "Add an Edge Transform Rule to attach HSTS, X-Content-Type-Options: nosniff, and X-Frame-Options: DENY to all responses.",
        },
        "prevention_checklist": [
            "Enable HSTS with at least 1 year duration and includeSubDomains.",
            "Set X-Content-Type-Options: nosniff to prevent MIME confusion attacks.",
            "Configure a tight Content-Security-Policy restricting script and style origins.",
            "Disallow iframe embedding using X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        ],
        "verification_test": """# Verification: verify headers are present on responses
def test_security_headers_present(client):
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") in ["DENY", "SAMEORIGIN"]
    assert "Strict-Transport-Security" in response.headers
""",
    },
}


def get_remediation_guide(category_or_type: str) -> dict[str, Any]:
    """Retrieve structured multi-language remediation recommendations for a finding."""
    key = category_or_type.lower().replace(" ", "_").replace("-", "_")
    
    # Direct match or fuzzy match
    for k, data in REMEDIATION_KNOWLEDGE_BASE.items():
        if k in key or key in k:
            return data
    
    # Generic fallback
    return {
        "title": f"Security Remediation Guide: {category_or_type}",
        "summary": "Review application logic to enforce input validation, output encoding, and principle of least privilege.",
        "code_fixes": {
            "python_fastapi": "# Enforce strict input validation using Pydantic models\nclass InputModel(BaseModel):\n    field: str = Field(..., max_length=100)",
            "nodejs_express": "// Enforce input validation using express-validator or Zod\nimport { z } from 'zod';",
            "java_spring": "// Enforce Bean Validation (@NotNull, @Size)\n@Valid @RequestBody RequestDto dto",
            "go": "// Enforce structural validation\nif err := validator.Validate(req); err != nil { ... }",
            "php": "// Validate input types and boundaries\n$safe = filter_input(INPUT_POST, 'data', FILTER_SANITIZE_SPECIAL_CHARS);",
        },
        "server_configs": {
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "cloudflare": "Apply WAF managed ruleset and rate limiting policy.",
        },
        "prevention_checklist": [
            "Validate all input on arrival (type, length, format, allowed characters).",
            "Implement defense-in-depth with server and network layer controls.",
            "Write automated unit tests to verify access control and validation constraints.",
        ],
        "verification_test": "# Run test suite after applying fix\npytest tests/",
    }

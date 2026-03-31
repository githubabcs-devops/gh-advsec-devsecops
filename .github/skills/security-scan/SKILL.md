---
name: security-scan
description: "Security scanning domain knowledge — OWASP Top 10, CWE mappings, IaC hardening, CI/CD pipeline security, supply chain controls, and SARIF output format"
---

# Security Scan Skill

Domain knowledge for security scanning agents. Agents load this skill to understand vulnerability categories, severity classification, compliance mappings, and SARIF output requirements.

## OWASP Top 10 Vulnerability Categories

The following table maps OWASP Top 10 (2021) categories to their primary CWE identifiers for automated detection and SARIF enrichment.

| # | OWASP Category | Primary CWEs | Detection Approach |
|---|---|---|---|
| A01 | Broken Access Control | CWE-200, CWE-201, CWE-352, CWE-639, CWE-862, CWE-863 | SAST (authorization checks), code review (RBAC patterns) |
| A02 | Cryptographic Failures | CWE-259, CWE-261, CWE-327, CWE-328, CWE-330, CWE-522 | SAST (weak algorithms), secret scanning |
| A03 | Injection | CWE-20, CWE-77, CWE-78, CWE-79, CWE-89, CWE-94 | SAST (taint analysis), DAST (fuzzing) |
| A04 | Insecure Design | CWE-209, CWE-256, CWE-501, CWE-522 | Architecture review, threat modeling |
| A05 | Security Misconfiguration | CWE-2, CWE-11, CWE-16, CWE-611 | IaC scanning, configuration audit |
| A06 | Vulnerable and Outdated Components | CWE-1104 | SCA (Dependabot, Dependency Review), SBOM |
| A07 | Identification and Authentication Failures | CWE-255, CWE-287, CWE-384, CWE-613 | SAST (session management), DAST (auth flows) |
| A08 | Software and Data Integrity Failures | CWE-345, CWE-426, CWE-494, CWE-502, CWE-829 | CI/CD integrity checks, artifact attestations |
| A09 | Security Logging and Monitoring Failures | CWE-117, CWE-223, CWE-532, CWE-778 | Code review (logging patterns), monitoring audit |
| A10 | Server-Side Request Forgery (SSRF) | CWE-918 | SAST (URL construction), DAST (SSRF payloads) |

### OWASP LLM Top 10 (AI/LLM-Specific)

| # | Category | CWEs | Relevance |
|---|---|---|---|
| LLM01 | Prompt Injection | CWE-77, CWE-94 | Agent configuration files, user input to LLM |
| LLM02 | Insecure Output Handling | CWE-79, CWE-94 | LLM-generated code execution |
| LLM03 | Training Data Poisoning | CWE-506 | Model supply chain |
| LLM04 | Model Denial of Service | CWE-400 | Resource exhaustion |
| LLM05 | Supply Chain Vulnerabilities | CWE-829, CWE-494 | Agent packages, prompt files |
| LLM06 | Sensitive Information Disclosure | CWE-200 | PII in training data or outputs |
| LLM07 | Insecure Plugin Design | CWE-862 | MCP tools, agent tool permissions |
| LLM08 | Excessive Agency | CWE-269 | Agent tool access scope |
| LLM09 | Overreliance | N/A | Trust calibration |
| LLM10 | Model Theft | CWE-200 | Model exfiltration |

## ASP.NET Core Security Patterns

### Authentication and Authorization

| Pattern | Implementation | Risk if Missing |
|---|---|---|
| JWT validation | `AddAuthentication().AddJwtBearer()` with issuer/audience validation | A07 — Auth bypass |
| Role-based authorization | `[Authorize(Roles = "Admin")]` or policy-based `[Authorize(Policy = "...")]` | A01 — Broken access control |
| CORS configuration | `AddCors()` with explicit origins, never `AllowAnyOrigin()` with credentials | A01 — Cross-origin abuse |
| Anti-forgery tokens | `[ValidateAntiForgeryToken]` on state-changing actions | A01 — CSRF (CWE-352) |
| Rate limiting | `AddRateLimiter()` with fixed/sliding/token bucket policies | A04 — Abuse prevention |

### Input Validation

| Pattern | Implementation | Risk if Missing |
|---|---|---|
| Model validation | Data annotations + `[ApiController]` automatic 400 responses | A03 — Injection |
| Parameterized queries | EF Core LINQ or Dapper with parameters, never string concatenation | A03 — SQL injection (CWE-89) |
| Output encoding | Razor auto-encodes by default; use `HtmlEncoder` for raw output | A03 — XSS (CWE-79) |
| File upload validation | Validate content type, size, and extension; store outside web root | A04 — Arbitrary file upload |

### Secrets Management

| Pattern | Implementation | Risk if Missing |
|---|---|---|
| User Secrets (dev) | `dotnet user-secrets` for local development | A02 — Secrets in source |
| Azure Key Vault (prod) | `AddAzureKeyVault()` configuration provider | A02 — Hardcoded secrets |
| Managed Identity | `DefaultAzureCredential` with no connection strings in config | A02 — Credential exposure |

### Security Headers

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Prevent clickjacking |
| `Content-Security-Policy` | Strict CSP with nonce/hash | Prevent XSS, injection |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer leakage |

## IaC Security Checklist

### Terraform

| Check | Rule | CWE |
|---|---|---|
| No hardcoded secrets in `.tf` files | Scan for `password`, `secret`, `key` in plain text | CWE-259 |
| Encryption at rest enabled | `azurerm_storage_account.enable_https_traffic_only = true` | CWE-311 |
| Network segmentation | No `0.0.0.0/0` in NSG rules or firewall exceptions | CWE-284 |
| Logging enabled | Diagnostic settings on all resources | CWE-778 |
| TLS 1.2+ enforced | `min_tls_version = "TLS1_2"` on all services | CWE-327 |
| Managed Identity over keys | Use `identity {}` block, avoid `access_key` references | CWE-522 |
| State file encryption | Remote backend with encryption, never local state in CI | CWE-312 |

### Bicep

| Check | Rule | CWE |
|---|---|---|
| Secure parameters | `@secure()` decorator on secrets, never `@description` with default values | CWE-259 |
| Resource locks | `Microsoft.Authorization/locks` on production resources | CWE-284 |
| Diagnostic settings | Deploy `Microsoft.Insights/diagnosticSettings` with all resources | CWE-778 |
| Private endpoints | Use `Microsoft.Network/privateEndpoints` for data services | CWE-284 |
| Key Vault references | `reference(keyVaultId).getSecret('name')` instead of inline secrets | CWE-522 |

### Kubernetes / Helm

| Check | Rule | CWE |
|---|---|---|
| No privileged containers | `securityContext.privileged: false` | CWE-250 |
| Read-only root filesystem | `securityContext.readOnlyRootFilesystem: true` | CWE-732 |
| Resource limits | CPU and memory `limits` set on all containers | CWE-400 |
| Network policies | Default-deny `NetworkPolicy` with explicit allow rules | CWE-284 |
| No latest tag | Pin image tags to specific digests or versions | CWE-829 |
| Secrets from external store | Use CSI Secret Store driver or sealed secrets, never `kind: Secret` | CWE-312 |
| Pod Security Standards | Enforce `restricted` profile via `PodSecurity` admission | CWE-250 |

## CI/CD Pipeline Hardening Checklist

| Domain | Check | Implementation |
|---|---|---|
| Secrets | No secrets in workflow files | Use `${{ secrets.NAME }}`, never inline values |
| Secrets | Rotate secrets regularly | Automated rotation via Key Vault or GitHub secret scanning |
| Permissions | Least-privilege `permissions` | Set `permissions: read-all` at workflow level, escalate per job |
| Dependencies | Pin actions to SHA | `uses: actions/checkout@abcdef1` not `@v4` |
| Dependencies | Enable Dependabot for actions | `dependabot.yml` with `package-ecosystem: github-actions` |
| Isolation | Use ephemeral runners | GitHub-hosted or self-hosted with clean images per run |
| Artifacts | Sign and attest artifacts | `actions/attest-build-provenance` for SLSA provenance |
| Artifacts | Verify artifact integrity | Check SHA256 digests before deployment |
| Branch protection | Require status checks | Branch rules enforce CI pass before merge |
| Branch protection | Require code review | Minimum 1 approval, dismiss stale reviews |
| SARIF upload | Upload all scanner results | `github/codeql-action/upload-sarif@v4` per domain |
| Audit | Log all workflow runs | GitHub audit log + Defender for Cloud integration |

## Supply Chain Security Controls

| Control | Tool | Purpose |
|---|---|---|
| Secret scanning | GitHub Secret Protection + custom patterns | Prevent credential leaks in commits |
| Dependency scanning | Dependabot + Dependency Review | Detect vulnerable dependencies before merge |
| SBOM generation | Anchore Syft, Microsoft SBOM Tool | Inventory all components |
| Container scanning | Trivy, Grype, MSDO | Detect vulnerabilities in container images |
| Artifact attestation | `actions/attest-build-provenance` | SLSA Build Level 2+ provenance |
| Code signing | Sigstore / Cosign | Verify artifact authenticity |
| Agent config scanning | APM `apm audit` | Detect hidden Unicode in agent files |
| Lock files | `package-lock.json`, `requirements.txt` with hashes | Prevent dependency confusion |

## SARIF Output Format for Security Findings

Security agents produce SARIF v2.1.0 compliant output with the following conventions.

### Required Fields

| Field | Value |
|---|---|
| `$schema` | `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json` |
| `version` | `2.1.0` |
| `tool.driver.name` | Agent name (e.g., `SecurityReviewerAgent`) |
| `automationDetails.id` | Category prefix (e.g., `security/owasp/`, `security/iac/`) |
| `partialFingerprints` | Hash of `ruleId:filePath:lineNumber` for deduplication |
| `results[].ruleId` | Unique rule identifier (e.g., `sql-injection`, `hardcoded-secret`) |
| `results[].level` | Mapped from severity (see below) |
| `results[].message.text` | Human-readable finding description |

### SARIF Enrichment

| Field | Purpose |
|---|---|
| `help.markdown` | Rule description, CWE mapping, remediation guidance, and learn-more links |
| `properties.tags` | Includes `security` plus OWASP/CWE tags for GitHub filtering |
| `properties.precision` | `very-high`, `high`, `medium`, or `low` based on detection confidence |
| `properties.security-severity` | Numeric score (0.0–10.0) for GitHub severity display |

## Severity Classification

All security findings use the following severity levels, mapped to SARIF and numeric scores.

| Severity | SARIF Level | `security-severity` | Description |
|---|---|---|---|
| CRITICAL | `error` | 9.0–10.0 | Immediate risk — active exploitation possible, data exposure |
| HIGH | `error` | 7.0–8.9 | Significant risk — must remediate before merge |
| MEDIUM | `warning` | 4.0–6.9 | Moderate risk — address in current sprint |
| LOW | `note` | 0.1–3.9 | Minor risk — track for future improvement |

### Compliance Framework Mapping

When applicable, map findings to the following frameworks:

| Framework | Use Case |
|---|---|
| CWE IDs | All code-level vulnerabilities |
| OWASP Top 10 | Application security findings |
| OWASP LLM Top 10 | AI/LLM-related findings |
| CIS Azure Benchmarks | Azure resource configuration |
| NIST 800-53 | Federal compliance requirements |
| PCI-DSS | Payment card data handling |
| Azure Security Benchmark | Azure-native security controls |

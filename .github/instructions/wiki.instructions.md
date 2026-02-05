# Wiki Maintenance Instructions

This document provides comprehensive instructions for maintaining the [gh-advsec-devsecops wiki](https://github.com/devopsabcs-engineering/gh-advsec-devsecops/wiki). The wiki documents custom GitHub Copilot agents for DevSecOps workflows, focusing on shift-left security practices in Visual Studio Code.

---

## Wiki Purpose and Scope

This wiki serves as the primary documentation hub for the [devopsabcs-engineering/gh-advsec-devsecops](https://github.com/devopsabcs-engineering/gh-advsec-devsecops) repository, which demonstrates:

- **Agentic AI for DevSecOps** - Using GitHub Copilot custom agents to automate security workflows
- **GitHub Advanced Security (GHAS)** integration with development workflows
- **Shift-left security practices** through custom agents in VS Code
- **Practical examples** with sample prompts, screenshots, and outputs

---

## Repository Custom Agents Overview

The repository contains **5 custom Copilot agents** in the `.github/agents/` directory. Each agent should have its own dedicated section in the wiki with consistent documentation structure.

| Agent | File | Primary Purpose |
| ----- | ---- | --------------- |
| **Security Agent** | `security-agent.md` | Comprehensive security review of ASP.NET Core apps, IaC, and CI/CD configurations |
| **Security Reviewer Agent** | `security-reviewer-agent.md` | Security-focused code review identifying OWASP Top 10 vulnerabilities |
| **Pipeline Security Agent** | `pipeline-security-agent.md` | GitHub Actions and Azure DevOps pipeline hardening |
| **IaC Security Agent** | `iac-security-agent.md` | Terraform, Bicep, ARM, Kubernetes, and Helm security scanning |
| **Supply Chain Security Agent** | `supply-chain-security-agent.md` | Secrets detection, dependency hygiene, SBOM, and repository governance |

---

## Documentation Standards

### Page Structure Template

Each custom agent section MUST follow this consistent structure:

```markdown
## [Agent Name]

Brief description of the agent's purpose and specialization.

### Agent Capabilities

Bullet list of what the agent can analyze and detect.

### Core Responsibilities

Key responsibilities from the agent definition.

### Sample Prompts

Organized by category with practical examples users can copy-paste.

### Example Output

Screenshot or code block showing typical agent response.

### Integration with VS Code

How to activate and use the agent in the Copilot Chat interface.

### Screenshot Gallery

Visual demonstrations with descriptive alt text.
```

### Screenshot Requirements

All screenshots MUST include:

1. **Descriptive alt text** - Explain what the screenshot shows for accessibility
2. **Context caption** - Brief explanation of what users should observe
3. **Consistent naming** - Use format: `agent-name-action-description.png`

Example:

```markdown
The screenshot below shows the IaC Security Agent scanning a Terraform file and identifying misconfigured storage account settings:

![IaC Security Agent analyzing Terraform code and highlighting public access misconfiguration with severity CRITICAL](https://github.com/user-attachments/assets/example-guid)
```

### Sample Prompt Guidelines

Organize prompts by **use case category** and provide context for each:

```markdown
#### Terraform Security

- "Scan this Terraform file for security misconfigurations"
- "Check if this storage account configuration follows Azure security baselines"
- "Review my azurerm_network_security_group for overly permissive rules"

#### Kubernetes Security

- "Analyze this deployment manifest for container security issues"
- "Is this pod configuration following security best practices?"
- "Check for privilege escalation risks in this Kubernetes spec"
```

### Writing Style

- **Be direct and actionable** - Avoid filler phrases
- **Use active voice** - "The agent scans..." not "The code is scanned by..."
- **Include severity levels** - Reference CRITICAL, HIGH, MEDIUM, LOW consistently
- **Provide code examples** - Show before/after patterns where applicable
- **Link to reference standards** - OWASP, CIS, NIST, Azure Security Benchmark

---

## Agent-Specific Documentation Guidelines

### Security Agent (`security-agent.md`)

**Focus Areas:**

- ASP.NET Core Razor Pages application review (`src/webapp01`)
- Authentication/authorization configuration
- Input handling and CSRF protections
- Infrastructure-as-code posture assessment
- CI/CD pipeline security review

**Required Sections:**

- Scope definition (which directories/files it prioritizes)
- Security scanning capabilities (SAST, SCA, IaC, CI/CD)
- Report structure explanation
- Example security assessment report output

**Sample Prompts to Document:**

```markdown
- "Perform a security review of this repository"
- "Scan src/webapp01 for OWASP Top 10 vulnerabilities"
- "Review the authentication configuration in this ASP.NET app"
- "Check for secrets in configuration files"
- "Analyze the GitHub Actions workflows for security issues"
```

---

### Security Reviewer Agent (`security-reviewer-agent.md`)

**Focus Areas:**

- Code-level vulnerability detection
- OWASP Top 10 vulnerability scanning
- Input validation and sanitization review
- Authentication and authorization logic
- Cryptographic implementation assessment

**Required Sections:**

- Review approach (high-risk areas first)
- Communication style (severity levels)
- Example finding format
- Common vulnerability categories

**Sample Prompts to Document:**

```markdown
- "Review this authentication function for security issues"
- "Check this API endpoint for injection vulnerabilities"
- "Is this password hashing implementation secure?"
- "Scan this file for XSS vulnerabilities"
- "Identify potential SQL injection points in this code"
```

---

### Pipeline Security Agent (`pipeline-security-agent.md`)

**Focus Areas:**

- GitHub Actions workflow hardening
- Azure DevOps pipeline security
- Permission least privilege enforcement
- Action/task version pinning (SHA vs tags)
- Script injection prevention
- Secrets handling review

**Required Sections:**

- Security focus areas with severity classifications
- GitHub Actions specific checks
- Azure DevOps specific checks
- Hardened workflow diff examples
- Change justification checklist format

**Sample Prompts to Document:**

```markdown
#### Workflow Hardening
- "Help me harden this GitHub Actions workflow"
- "What permissions should I remove from this workflow?"
- "Is this workflow vulnerable to script injection attacks?"

#### Secrets Management
- "Check this pipeline for secrets exposure risks"
- "Are my secrets being handled securely in this workflow?"

#### Action Pinning
- "Are my action dependencies pinned to specific versions?"
- "Convert this workflow to use SHA-pinned actions"

#### Pull Request Security
- "Is this workflow safe to run on pull_request_target?"
- "Check for pwn request vulnerabilities"
```

---

### IaC Security Agent (`iac-security-agent.md`)

**Focus Areas:**

- Terraform security scanning
- Bicep/ARM template analysis
- Kubernetes manifest review
- Helm chart security assessment
- Dockerfile security best practices
- Compliance framework mapping (CIS, NIST, Azure Security Benchmark)

**Required Sections:**

- Supported IaC technologies table
- Security categories (IAM, Network, Data Protection, Logging, Container Security, Backup/DR)
- MSDO analyzer integration examples
- Output format (findings report, fix pack, control mapping)
- Reference standards links

**Sample Prompts to Document:**

```markdown
#### Terraform Security
- "Scan this Terraform directory for security misconfigurations"
- "Check if this azurerm_storage_account follows security baselines"
- "Review IAM role assignments for least privilege"

#### Bicep Security
- "Analyze this Bicep template for Azure security issues"
- "Is this Key Vault configuration secure?"
- "Check network security settings in this Bicep file"

#### Kubernetes Security
- "Review this Kubernetes deployment for security issues"
- "Is this pod running as non-root?"
- "Check for missing security context in this manifest"

#### Compliance Mapping
- "Map findings to CIS Azure benchmarks"
- "What NIST 800-53 controls does this violate?"
```

---

### Supply Chain Security Agent (`supply-chain-security-agent.md`)

**Focus Areas:**

- Secrets detection and containment
- Dependency vulnerability analysis (SCA)
- SBOM generation and provenance guidance
- Repository governance (branch protection, CODEOWNERS)
- Dependabot configuration
- SLSA framework alignment

**Required Sections:**

- Secrets detection patterns table
- Dependency manifest file coverage by ecosystem
- SBOM and provenance approaches
- Repository governance baseline audit format
- Integration with GHAS features

**Sample Prompts to Document:**

```markdown
#### Secrets Detection
- "Scan this repository for exposed secrets"
- "Check configuration files for hardcoded credentials"
- "Review this workflow for secrets handling issues"

#### Dependency Security
- "Analyze package.json for vulnerable dependencies"
- "Check if dependencies are properly pinned"
- "Review this requirements.txt for security issues"

#### Repository Governance
- "Audit branch protection rules for this repository"
- "Generate a CODEOWNERS file for security-sensitive paths"
- "Check if required status checks are configured"

#### SBOM and Provenance
- "Help me set up SBOM generation in CI"
- "What SLSA level does this release process achieve?"
- "Add artifact attestation to this release workflow"
```

---

## Adding New Screenshots

When adding screenshots for sample prompts and agent outputs:

### Capture Guidelines

1. **Use VS Code with Copilot Chat panel visible**
2. **Show the agent picker with the relevant agent selected**
3. **Include both the prompt and the response**
4. **Highlight key findings with annotations if helpful**
5. **Use consistent VS Code theme (recommend Dark+ for readability)**

### Upload Process

1. Take screenshot with descriptive content visible
2. Upload to GitHub issue/PR to get asset URL
3. Reference using the format:

```markdown
![Alt text description](https://github.com/user-attachments/assets/guid)
```

### Required Screenshots per Agent

Each agent section should include screenshots demonstrating:

- [ ] Agent selection in the VS Code Copilot Chat picker
- [ ] Sample prompt being entered
- [ ] Agent response with findings (showing severity levels)
- [ ] Example remediation code suggestions
- [ ] (Optional) Comparison of before/after code

---

## Consistency Checklist

Before publishing wiki updates, verify:

### Structure

- [ ] Agent section follows the standard template
- [ ] All 5 agents are documented with equal depth
- [ ] Sample prompts are categorized by use case
- [ ] Screenshots have descriptive alt text

### Content

- [ ] Agent capabilities match the source `.md` files in the repository
- [ ] Reference standards are linked (OWASP, CIS, NIST, etc.)
- [ ] Severity levels use consistent terminology (CRITICAL/HIGH/MEDIUM/LOW)
- [ ] Code examples are properly formatted with syntax highlighting

### Links

- [ ] Repository links point to `devopsabcs-engineering/gh-advsec-devsecops`
- [ ] Agent source files are linked
- [ ] External documentation links are valid

---

## Quick Reference: Agent Source Files

Always refer to the latest agent definitions when updating documentation:

| Agent | Source URL |
| ----- | ---------- |
| Security Agent | [`.github/agents/security-agent.md`](https://github.com/devopsabcs-engineering/gh-advsec-devsecops/blob/main/.github/agents/security-agent.md) |
| Security Reviewer Agent | [`.github/agents/security-reviewer-agent.md`](https://github.com/devopsabcs-engineering/gh-advsec-devsecops/blob/main/.github/agents/security-reviewer-agent.md) |
| Pipeline Security Agent | [`.github/agents/pipeline-security-agent.md`](https://github.com/devopsabcs-engineering/gh-advsec-devsecops/blob/main/.github/agents/pipeline-security-agent.md) |
| IaC Security Agent | [`.github/agents/iac-security-agent.md`](https://github.com/devopsabcs-engineering/gh-advsec-devsecops/blob/main/.github/agents/iac-security-agent.md) |
| Supply Chain Security Agent | [`.github/agents/supply-chain-security-agent.md`](https://github.com/devopsabcs-engineering/gh-advsec-devsecops/blob/main/.github/agents/supply-chain-security-agent.md) |

---

## Contribution Workflow

1. **Review current agent definitions** - Check the source files for any updates
2. **Follow documentation standards** - Use the templates and guidelines above
3. **Add screenshots** - Demonstrate prompts and outputs visually
4. **Verify consistency** - Run through the checklist
5. **Commit with descriptive message** - Reference the agent or section updated

Example commit messages:

```text
docs: Add IaC Security Agent section with sample prompts and screenshots
docs: Update Pipeline Security Agent with Azure DevOps examples
docs: Add screenshot gallery for Security Reviewer Agent OWASP scan
```

---

## Reference Standards

When documenting security findings and recommendations, reference these standards:

| Standard | Use Case | Link |
| -------- | -------- | ---- |
| OWASP Top 10 | Web application vulnerabilities | [owasp.org/Top10](https://owasp.org/Top10/) |
| CIS Azure Benchmark | Azure resource configuration | [cisecurity.org/benchmark/azure](https://www.cisecurity.org/benchmark/azure) |
| CIS Kubernetes Benchmark | Kubernetes security | [cisecurity.org/benchmark/kubernetes](https://www.cisecurity.org/benchmark/kubernetes) |
| NIST 800-53 | Federal security controls | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| Azure Security Benchmark | Azure security best practices | [Microsoft Docs](https://docs.microsoft.com/azure/security/benchmarks/) |
| SLSA Framework | Supply chain security | [slsa.dev](https://slsa.dev/) |
| OpenSSF Scorecard | OSS security posture | [securityscorecards.dev](https://securityscorecards.dev/) |

---

## Visual Studio Code Integration

All agents are designed for use in VS Code with GitHub Copilot. Document the following workflow:

### Activating Custom Agents

1. Open VS Code with the target repository
2. Open Copilot Chat (`Ctrl+Shift+I` or click Copilot icon)
3. Click the agent picker (dropdown next to input field)
4. Select the desired agent from the list
5. Enter your prompt and review the response

### Keyboard Shortcuts

| Action | Windows/Linux | macOS |
| ------ | ------------- | ----- |
| Open Copilot Chat | `Ctrl+Shift+I` | `Cmd+Shift+I` |
| Inline suggestions | `Ctrl+Space` | `Cmd+Space` |
| Accept suggestion | `Tab` | `Tab` |

---

## Maintaining Consistency

This wiki must remain consistent with:

1. **Repository agent definitions** - The `.github/agents/*.md` files are the source of truth
2. **GitHub documentation** - Reference official Copilot and GHAS documentation
3. **Security standards** - Use consistent severity terminology and control mappings
4. **Visual style** - Screenshots should use consistent VS Code theming and layout

When the repository agents are updated, the wiki sections must be updated to reflect:

- New capabilities or responsibilities
- Updated sample prompts
- Changed output formats
- New reference standards

---

## Summary

This wiki documents the custom GitHub Copilot agents in the [gh-advsec-devsecops](https://github.com/devopsabcs-engineering/gh-advsec-devsecops) repository for shift-left DevSecOps practices. Each agent section should include:

1. Clear description of capabilities and responsibilities
2. Categorized sample prompts users can immediately try
3. Screenshots demonstrating usage in VS Code
4. Example outputs showing findings and remediation guidance
5. Links to reference security standards

Follow these instructions to maintain documentation consistency and provide maximum value to users adopting these DevSecOps agents.

---
title: DevSecOps Concepts Guide
description: A concise overview of the shift-left security concepts, workflows, and AI agents demonstrated in this repository.
ms.date: 2026-03-30
ms.topic: overview
---

## What This Repo Demonstrates

This repository is a reference implementation for **Agentic AI-driven DevSecOps**. It combines GitHub Advanced Security (GHAS), GitHub Copilot custom agents, and Microsoft Defender for Cloud to show how security integrates into every phase of the software delivery lifecycle.

The core application is an ASP.NET Core Razor Pages web app (.NET 9.0), paired with intentionally vulnerable sample code across multiple languages so you can see each scanner in action.

## Shift-Left Security

Shift-left means catching vulnerabilities as early as possible, ideally before code reaches `main`. This repo implements shift-left through three layers:

1. **Developer environment**: Copilot agents review code and generate security plans inside VS Code, before a commit is ever pushed.
2. **Pull request gates**: Automated workflows run SAST, SCA, container scanning, and IaC checks on every PR.
3. **Continuous monitoring**: Scheduled scans, SBOM generation, and Defender for Cloud integration provide ongoing visibility.

The goal is to reduce the cost and risk of fixing vulnerabilities by finding them where they are cheapest to resolve: at the developer's keyboard.

## Security Workflows

Seventeen GitHub Actions workflows cover the full scanning spectrum. Each workflow runs on pull requests, pushes, or on a schedule, and results surface directly in the GitHub Security tab.

### Static Analysis (SAST)

| Workflow | What It Scans |
|----------|---------------|
| CodeQL | C#, JavaScript, Python, Go across four separate language configs |
| ESLint | JavaScript for code quality and security patterns |
| Microsoft Security DevOps (MSDO) | Multi-tool orchestration feeding Defender for Cloud |

### Software Composition Analysis (SCA)

| Workflow | What It Does |
|----------|--------------|
| Dependency Review | Blocks PRs that introduce known-vulnerable dependencies |
| Anchore Syft SBOM | Generates software bill of materials on every build |
| Microsoft SBOM Tool | Produces SPDX-format SBOMs for compliance |
| OpenSSF Scorecard | Rates supply-chain security posture weekly |

### Container and Image Scanning

| Workflow | What It Does |
|----------|--------------|
| Anchore Grype | Scans container images for OS and language-level CVEs |
| Trivy | Scans images and filesystem for vulnerabilities and misconfigurations |

### Infrastructure as Code (IaC)

| Workflow | What It Scans |
|----------|---------------|
| tfsec | Terraform files for cloud security misconfigurations |
| Checkmarx KICS | Terraform, ARM, Docker, Kubernetes manifests |
| Kubesec | Kubernetes manifests for workload security risks |

### Dynamic Analysis (DAST)

| Workflow | What It Does |
|----------|--------------|
| OWASP ZAP | Runs baseline scans against the deployed web application |

### CI/CD Pipeline

A build-and-deploy workflow provisions Azure infrastructure through Bicep, builds the application, and deploys it, with security checks gating each stage.

## AI Security Agents

Six custom GitHub Copilot agents live in the repository and run inside VS Code. They bring security expertise directly into the developer workflow without context-switching to external tools.

| Agent | Focus Area |
|-------|------------|
| Security Agent | Full-repository assessment: SAST, SCA, IaC, and CI/CD review with prioritized findings |
| Security Reviewer | Code-review lens: checks changes for OWASP Top 10 issues and suggests line-level fixes |
| Pipeline Security | CI/CD hardening: audits workflow permissions, action pinning, secret handling, and triggers |
| IaC Security | Infrastructure guard: scans Terraform, Bicep, ARM, Kubernetes, Helm, and Dockerfiles |
| Supply Chain Security | Dependency hygiene: secrets detection, SBOM verification, provenance, and repo governance |
| Security Plan Creator | Architect role: generates five-phase security plans with threat models and architecture diagrams |

Each agent produces structured, actionable output. The Security Plan Creator, for example, walks through blueprint selection, architecture analysis, threat assessment, plan generation, and validation.

## Blueprints

Two Azure deployment blueprints (Bicep) provide real infrastructure patterns:

* **Containerized web app**: Azure Container Registry, App Service, and managed identity for a single-container deployment.
* **Three-tier application**: App Service, Azure SQL, Key Vault, and Application Insights for a production-grade stack.

These blueprints pair with the Security Plan Creator agent, which uses them as inputs when generating architecture-specific security plans.

## Terraform Landing Zone

A set of Terraform modules under `terraform/azure/` provisions a full Azure landing zone: AKS, App Service, Key Vault, networking, RBAC, policies, Security Center, SQL, and storage. IaC scanning workflows validate these files on every change.

## Sample Vulnerable Code

The `samples/` directory contains intentionally insecure code across JavaScript, Python, Go, Terraform, ARM, and Dockerfiles. These files exist for demonstration purposes: they trigger findings in the scanning workflows so you can see real alerts and remediation flows.

> Do not deploy sample code to production. These files contain deliberate vulnerabilities for educational use.

## How It All Connects

```text
Developer writes code
        │
        ▼
Copilot agents review in VS Code ──► early feedback before commit
        │
        ▼
Push / PR triggers workflows ──► SAST, SCA, IaC, container scans
        │
        ▼
Results appear in Security tab ──► prioritized, actionable findings
        │
        ▼
Copilot Autofix suggests patches ──► one-click remediation
        │
        ▼
Defender for Cloud aggregates ──► org-wide security posture
```

Security is not a gate at the end of the pipeline. It is continuous feedback woven into every step, from the first keystroke to production monitoring.

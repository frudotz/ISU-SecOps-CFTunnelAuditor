# Prompts for copilot

# OUTPUT LANGUAGE REQUIREMENT
All outputs, explanations, tables, examples and recommendations MUST be written in Turkish.
Do not switch languages.

---

# Cloudflare Tunnel Auditor – Technical Research & Audit Prompt
## Microsoft Copilot (Security Architecture & Compliance Focus)

You are acting as a **security architect, cloud security analyst, and audit tool designer**.

Your task is to perform a **deep technical analysis** for a project called **Cloudflare Tunnel Auditor**.
Avoid high-level marketing language. Focus on **practical security risks, misconfigurations, and audit controls**.

---

## 📌 Project Overview

I am designing a tool named **Cloudflare Tunnel Auditor**.

Primary goals:
- Audit Cloudflare Tunnel (`cloudflared`) deployments for **security risks and misconfigurations**
- Identify unsafe or non-compliant configurations
- Provide **clear, actionable remediation steps**
- Output machine-readable and human-readable reports (JSON + Markdown/PDF)

Target environments:
- Linux servers (VM / bare metal)
- Docker-based deployments
- Optional Kubernetes usage
- Edge devices (e.g., OpenWRT)
- Services exposed via Tunnel (HTTP, SSH, admin panels)

If any assumptions are unclear or incorrect, explicitly state them and propose alternatives.

---

## 1️⃣ Cloudflare Tunnel Security Model & Attack Surface

Analyze the Cloudflare Tunnel architecture with focus on:

- Authentication mechanisms (certificates, tokens, named tunnels)
- Credential storage and lifecycle
- Origin-to-Cloudflare trust boundaries
- Control-plane vs data-plane separation

### Identify attack surfaces such as:
- Credential or token leakage
- Insecure ingress rules
- Origin services unintentionally exposed to the public internet
- Improper use of Cloudflare Access / Zero Trust
- SSH exposure via Tunnel
- Container secret handling risks

### Deliverable:
Provide a **Threat Model Table** with the following columns:

```

Threat | Impact | Likelihood | Detection Method | Recommended Mitigation

```

---

## 2️⃣ Common and High-Risk Misconfigurations

Using Cloudflare documentation and real-world security patterns:

- List **at least 15 common or critical misconfigurations**
- For each misconfiguration, include:
  - How to detect it (config, logs, API checks)
  - Why it is dangerous
  - Secure configuration recommendation
  - Risk level (High / Medium / Low)

Emphasize misconfigurations that are **frequently overlooked**.

---

## 3️⃣ Auditor Control Framework Design

Design an **audit control framework** suitable for automation.

### Control categories:
- Tunnel and ingress configuration
- Cloudflare Access / Zero Trust policies
- API token scope and permissions
- Local system hardening
- Network isolation and firewall enforcement
- Logging, monitoring, and incident response readiness

### Deliverables:
1. **Audit Control Catalog Table**:
```

Category | Control Name | Audit Method (Local/API) | Risk Addressed | Recommendation

```

2. Identify **20–25 controls** suitable for a Minimum Viable Product (MVP).

---

## 4️⃣ Cloudflare API & Permission Strategy

Analyze Cloudflare API usage for an auditor tool:

- Required API domains and endpoints
- Recommended **least-privilege API token scopes**
- Rate limiting considerations
- Audit log visibility and limitations
- Actions the auditor should explicitly **never perform**

Clearly mark **gray areas or risky API usage patterns**.

---

## 5️⃣ Risk Scoring Methodology

Propose a **technical risk scoring model**, including:

- Scoring formula
- Weighting factors (impact, exposure, exploitability)
- Example calculation for one identified finding

Avoid qualitative-only scoring; use structured logic.

---

## 6️⃣ Reporting & Output Design

Recommend output formats:

- JSON report schema (key fields and structure)
- Human-readable report sections (Markdown/PDF style)

Goal:
> A system administrator should be able to take immediate remediation action based on the report.

---

## 7️⃣ Related Tools & Gap Analysis

Analyze whether:
- Dedicated Cloudflare Tunnel audit tools already exist
- General security posture or IaC scanning tools partially cover this area

Explain:
- Why existing tools are insufficient
- What security gaps remain

Provide **5 concrete differentiating features** for Cloudflare Tunnel Auditor.

---

## ⚠️ Analysis Rules

- Clearly state uncertainty where applicable
- Do not blindly repeat “best practices” without context
- Explicitly identify gray areas and trade-offs
- Think defensively and adversarially:
  “How would an attacker abuse this configuration?”

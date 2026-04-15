
# 🔍 Threat Hunts

> Threat hunt reports and KQL investigation documentation by **Robert** — Cybersecurity Analyst Intern at [Log(N) Pacific](https://lognpacific.com).

Each report covers a real simulated incident end-to-end: from initial compromise through containment, with KQL queries, evidence screenshots, MITRE ATT&CK mappings, and analyst notes.

---

## 📁 Hunts

| # | Hunt | Scenario | SIEM | Difficulty | Threat Actor |
|---|---|---|---|---|---|
| 02 | [Scattered Invoice](./scattered-invoice/report.md) | Business Email Compromise — £24,500 wire fraud via MFA fatigue | Microsoft Sentinel | Intermediate | Scattered Spider |

---

## 📂 Repo Structure

Each hunt lives in its own self-contained folder:

```
├── README.md
│
├── scattered-invoice/
│   ├── report.md          # Full IR report with KQL queries and findings
│   └── screenshots/       # Evidence screenshots from Microsoft Sentinel

```

---

## 📋 Report Structure

Every report follows this format:

| Section | Description |
|---|---|
| Executive Summary | What happened and what was the business impact |
| Environment | Workspace, log tables, time window, key identifiers |
| Attack Chain | Visual kill chain overview |
| Investigation Phases | KQL queries + findings + evidence per phase |
| Defense Failures | What controls were missing or bypassed |
| Attack Timeline | Chronological event table |
| IOCs | All indicators of compromise |
| Containment Steps | Immediate response actions in priority order |
| Recommendations | Long-term security improvements |
| MITRE ATT&CK Mapping | Technique IDs mapped to each tactic |
| Analyst Notes | Key lessons learned from the investigation |

---

## 🛠️ Skills

![KQL](https://img.shields.io/badge/KQL-Microsoft%20Sentinel-0078D4?style=flat&logo=microsoft)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC%20Analysis-1e90ff?style=flat)

- **SIEM:** Microsoft Sentinel (KQL)
- **Log Sources:** `SignInLogs`, `CloudAppEvents`, `EmailEvents`, `AuditLogs`
- **Techniques:** MFA fatigue detection, inbox rule forensics, BEC investigation, session correlation, impossible travel analysis
- **Frameworks:** MITRE ATT&CK, NIST IR lifecycle

---

## 🔗 Connect

- **LinkedIn:** [https://www.linkedin.com/in/robert14786/](https://www.linkedin.com/in/robert14786/)
- **Internship:** Log(N) Pacific — Remote SOC Operations

---

*Updated: April 2026*

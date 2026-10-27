# Security Automation & Compliance Scripts

A collection of operational PowerShell and Python scripts designed for information security auditing, GRC compliance verification, and system hardening. 

Developed and maintained by **Yoseph Negussie Alula, MSc** (BSI ISO/IEC 27001 Lead Auditor & CEO at OmniStackIT).

---

## Repository Contents

| Directory | Script | Purpose / ISO 27001 Control Alignment |
| :--- | :--- | :--- |
| `compliance-auditing/` | `Audit-UserAccessRights.ps1` | Audits AD & local user accounts for inactive status, password policies, and privileged rights (**ISO/IEC 27001:2022 A.5.15, A.5.18**). |

---

## Quickstart: User Access Audit Script

### Usage
Run PowerShell as Administrator and execute:

```powershell
.\compliance-auditing\Audit-UserAccessRights.ps1 -InactiveDaysThreshold 90 -ReportPath "ISO27001_Audit_Report.html"
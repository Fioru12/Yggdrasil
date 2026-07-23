<div align="center">

# YGGDRASIL

### **Asgard Cybersecurity Suite — Module IV (Active Directory Security Auditor)**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active_Directory-0078D7?style=for-the-badge&logo=windows&logoColor=white)
![Security Audit](https://img.shields.io/badge/Security-Audit-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Yggdrasil** (*"L'albero cosmico che sostiene i mondi"*) is an automated **Active Directory and Windows Security Posture Auditor** designed to evaluate GPO password policies, account lockout thresholds, privileged account hygiene, and identify domain misconfigurations.

---

## Core Features

| Component | Description |
|:---|:---|
| **Password Policy Audit** | Evaluates minimum length, complexity, history, and maximum age GPO settings |
| **Privileged Account Hygiene** | Detects Domain Admins with 'Password Never Expires' or stale activity |
| **Account Lockout Check** | Validates brute-force protection thresholds |
| **Markdown Reporting** | Generates executive audit reports with scoring (0-100) and remediation playbooks |

---

## Quick Start

```bash
# Run AD security audit simulation
python main.py audit --domain corp.asgard.local
```

---

<div align="center">

**Built by [Fioru12](https://github.com/Fioru12)** — Distributed under the MIT License.

</div>

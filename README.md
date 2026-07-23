<div align="center">

# YGGDRASIL

### **Asgard Cybersecurity Suite — Module IV (Active Directory Security Auditor)**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active_Directory-0078D7?style=for-the-badge&logo=windows&logoColor=white)
![Security Audit](https://img.shields.io/badge/Security-Audit-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Perché ho costruito Yggdrasil?**  
> In molte realtà (specialmente PMI e medie imprese), Active Directory è il cuore pulsante dell'infrastruttura ma spesso soffre di configurazioni storiche mai riviste: policy password blande, account di servizio con privilegi eccessivi e password che non scadono dal 2021. Yggdrasil nasce per offrire un audit rapido, chiaro e orientato al rischio delle GPO e della postura di sicurezza AD.

---

## Funzionalità Principali

- **Audit Policy Password**: Verifica lunghezza minima, complessità e scadenze forzate.
- **Igiene Account Privilegiati**: Intercetta account Domain Admin con opzione "Password mai scaduta" o inattivi da mesi.
- **Reporting Esecutivo**: Genera un report Markdown con punteggio di sicurezza (0-100) e playbook di rimedio immediato.

---

## Quick Start

```bash
# Esegui l'audit di simulazione sul dominio
python main.py audit --domain corp.asgard.local
```

---

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>

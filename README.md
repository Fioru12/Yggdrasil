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
# Esegui l'audit di simulazione sul dominio (dati mock, nessuna connessione richiesta)
python main.py audit --domain corp.asgard.local
```

---

## Audit Reale via LDAP

A partire da questa versione Yggdrasil può interrogare davvero un Domain Controller via LDAP/LDAPS (libreria `ldap3`, pura Python — nessuna toolchain nativa richiesta, funziona anche su Windows).

```bash
python main.py audit --no-simulate \
  --domain corp.local \
  --ldap-host dc01.corp.local \
  --bind-dn "CN=svc-audit,OU=Service Accounts,DC=corp,DC=local" \
  --base-dn "DC=corp,DC=local"
```

La password dell'account di bind può essere fornita in tre modi (in ordine di priorità):

1. `--bind-password` (sconsigliato: resta visibile nella history/processi)
2. variabile d'ambiente `YGGDRASIL_BIND_PASSWORD`
3. prompt interattivo (`getpass`) se nessuna delle due precedenti è impostata

Parametri principali:

| Argomento | Descrizione |
|---|---|
| `--ldap-host` | Hostname o IP del Domain Controller (richiesto) |
| `--ldap-port` | Porta LDAP (default `636`, LDAPS) |
| `--bind-dn` | DN dell'account di bind |
| `--bind-password` | Password di bind (preferire env var o prompt) |
| `--base-dn` | Base DN del dominio, es. `DC=corp,DC=local` (richiesto) |
| `--no-ssl` | Disabilita LDAPS e usa LDAP in chiaro (**sconsigliato**, stampa un warning) |

**Sicurezza dell'account di bind**: per interrogare la password policy e i membri di "Domain Admins" è sufficiente un account con permessi di **sola lettura** sul dominio (un utente autenticato standard è già in grado di leggere questi attributi in una configurazione AD di default). Non usare mai un account Domain Admin o con privilegi di scrittura come account di servizio per l'audit — applicare il principio del minimo privilegio: un service account dedicato, membro solo dei gruppi di lettura strettamente necessari, con password gestita a parte (vault/secret manager) invece che in chiaro sulla riga di comando.

Per default la connessione avviene via **LDAPS** (porta 636, cifrata). Se si forza `--no-ssl` il traffico, inclusa la password di bind, viaggia in chiaro: usarlo solo in ambienti di test isolati.

---

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>

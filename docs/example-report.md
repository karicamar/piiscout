## PiiScout: personal data report

**38 values** in **4 of 6 files**. Worst: **Critical**.

| Category | Values | Files |
|---|---:|---:|
| Special category (Art. 9 GDPR) | 5 | 3 |
| Government identifier | 6 | 2 |
| Financial data | 6 | 2 |
| Contact data | 11 | 3 |
| Identity data | 8 | 2 |
| Online identifier | 2 | 1 |

### Data map

| Severity | File | Field | Data | Values | Distinct |
|---|---|---|---|---:|---:|
| 🟣 Critical | `crm-export.csv` | `Konfession` | Special category field | 2 | 2 |
| 🟣 Critical | `hr/payroll-export.xml` | `Kirchensteuer` | Special category field | 1 | 1 |
| 🟣 Critical | `hr/payroll-export.xml` | `Schwerbehindert` | Special category field | 1 | 1 |
| 🟣 Critical | `support-ticket.json` | `body` | Diagnosis code (ICD-10) | 1 | 1 |
| 🔴 High | `crm-export.csv` | `IBAN` | IBAN | 4 | 4 |
| 🔴 High | `hr/payroll-export.xml` | `SteuerID` | German tax ID (Steuer-ID) | 2 | 2 |
| 🔴 High | `hr/payroll-export.xml` | `SVNummer` | German social insurance number | 2 | 2 |
| 🔴 High | `logs/app.log` | `iban` | IBAN | 1 | 1 |
| 🔴 High | `logs/app.log` | `pan` | Payment card number | 1 | 1 |
| 🔴 High | `support-ticket.json` | `ausweisnummer` | German ID card or passport number | 1 | 1 |
| 🔴 High | `support-ticket.json` | `steuer_id` | German tax ID (Steuer-ID) | 1 | 1 |
| 🟠 Medium | `crm-export.csv` | `E-Mail` | Email address | 3 | 3 |
| 🟠 Medium | `crm-export.csv` | `Geburtsdatum` | Date of birth | 3 | 3 |
| 🟠 Medium | `crm-export.csv` | `Name` | Person name (by field) | 4 | 4 |
| 🟠 Medium | `crm-export.csv` | `Telefon` | German phone number | 4 | 4 |
| 🟠 Medium | `logs/app.log` | – | Email address | 1 | 1 |
| 🟠 Medium | `logs/app.log` | – | German phone number | 1 | 1 |
| 🟠 Medium | `logs/app.log` | `debtor` | Person name (by field) | 1 | 1 |
| 🟠 Medium | `logs/app.log` | `user` | Email address | 1 | 1 |
| 🟠 Medium | `support-ticket.json` | `from` | Email address | 1 | 1 |
| 🟡 Low | `logs/app.log` | `client` | Public IP address | 1 | 1 |
| 🟡 Low | `logs/app.log` | `ip` | Public IP address | 1 | 1 |

Accepted in `.piiscout-ignore`: 2 value(s) in 1 file(s).

Test data and role mailboxes (not counted): 7 value(s).

> ⚠️ **Art. 9 GDPR:** special categories (health, religion, union membership, …) may only be processed under one of the exceptions of Art. 9(2). Check the legal basis and who can read these files.

> 🇩🇪 Die Datenkarte ist eine Grundlage für das Verzeichnis von Verarbeitungstätigkeiten (Art. 30 DSGVO) und für Auskunfts- und Löschanfragen (Art. 15, 17 DSGVO). Werte werden nie im Klartext ausgegeben.

- Fingerprints use a random key (set PIISCOUT_KEY to compare them between runs).

# Samples

Synthetic data to try PiiScout on: `dotnet run --project ../src/PiiScout.Cli -- .` (from this folder).
All names, numbers and accounts are made up; they have valid check digits so the detectors accept them, and any match with a real person or account is a coincidence.

| File | What it shows |
|---|---|
| `crm-export.csv` | Semicolon CSV from Excel: column names give context, `Konfession` is an Art. 9 field |
| `logs/app.log` | The classic logging mistakes: a card number, an IBAN, emails and public IP addresses in an application log |
| `support-ticket.json` | A sick note in a helpdesk ticket: diagnosis code, ID card number, tax ID |
| `hr/payroll-export.xml` | Payroll export: tax IDs, social insurance numbers, church tax (reveals religion) and disability status |
| `fixtures/customers.json` | Test data (example.com, published test cards and IBAN, documentation IP): reported as info only |
| `docs/impressum.md` | Accepted in `.piiscout-ignore`: published company contact data |

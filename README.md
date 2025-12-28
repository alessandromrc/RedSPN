# RedSPN

Active Directory security audit tool that finds security risks and generates a red-themed HTML report.

## Quick Start

1. **Run the audit:**
   ```powershell
   .\Get-ADAudit.ps1
   ```

2. **Generate the report:**
   ```powershell
   python generate_report.py
   ```

3. **Open `ad_audit_report.html` in your browser**

## Requirements

- Windows with Active Directory PowerShell module
- Python 3.6+ (no extra packages needed)

## What It Does

- Finds Kerberoast targets (SPNs)
- Checks delegation risks
- Identifies weak encryption
- Lists privileged accounts
- Shows inactive accounts
- Generates a red-themed HTML report

## Files

- `Get-ADAudit.ps1` - PowerShell script that audits AD
- `generate_report.py` - Python script that creates the HTML report
- `ad_audit_data.json` - Audit data (generated)
- `ad_audit_report.html` - HTML report (generated)

## License

Use responsibly. Only audit systems you own or have permission to audit.

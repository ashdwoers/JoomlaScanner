# JoomlaScanner

A modern Python-based vulnerability scanner for Joomla CMS with automated CVE tracking from NVD.

## Features

- **Version Detection** - Automatically detects Joomla version (1.x - 5.x)
- **Component Enumeration** - Finds installed Joomla components
- **Module Detection** - Detects Joomla modules
- **CVE Matching** - Matches detected versions against NVD CVE database with fuzzy name normalization
- **"Check Manually" Section** - Flags components/modules with known CVEs but unknown or unconfirmed version ranges
- **Full Enumeration Listing** - Collapsible reference of all detected components and modules for manual audit
- **Multiple Output Formats** - Console (default), JSON, and HTML reports with collapsible sections and compact CVE cards

## Installation

```bash
# Clone or download the project
cd JoomlaScanner

# Activate virtual environment
source venv/bin/activate  

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Scan a Target

```bash
# Quick scan (core + CVE-affected + VEL-listed + top popular)
python cli.py scan https://example.com

# Full scan (all components + modules in database)
python cli.py scan https://example.com --full

# HTML report
python cli.py scan https://example.com --format html -o report.html

# JSON report (for automation)
python cli.py scan https://example.com --format json -o report.json

# Version detection only (skip enumeration)
python cli.py scan https://example.com --version-only

# Components/modules only (skip version detection)
python cli.py scan https://example.com --components-only

# Custom timeout and thread count
python cli.py scan https://example.com --timeout 5 --threads 20
```

### Update Databases

```bash
# Update everything (CVEs + extensions)
python cli.py update

# CVEs only (last 7 days by default)
python cli.py update --cves

# Extensions only (components + modules)
python cli.py update --ext

# Full refresh (all CVEs from NVD + all extension sources)
python cli.py update --full

# Quick extension update (JED Algolia + GitHub core only)
python cli.py update --ext --quick

# Fetch CVEs for a specific year
python cli.py update --cves --year 2024

# Fetch CVEs for a year range
python cli.py update --cves --year 2018 --range 2024

# Update extensions from a specific source
python cli.py update --ext --source jed      # JED Algolia (~5,500 extensions)
python cli.py update --ext --source github   # Joomla core components from GitHub
python cli.py update --ext --source nvd      # NVD CPE dictionary
python cli.py update --ext --source cve      # Parse com_/mod_ from CVE descriptions
python cli.py update --ext --source vel      # JED Vulnerable Extensions List
```

### Database Statistics

```bash
python cli.py stats
```

## Output

### Console Output
```
JoomlaScanner Report
============================================================

Target: https://example.com
Joomla Version: 3.10.5 (method: xml_file)

Components Found: 12

Vulnerability Summary:
  Total: 5
  Critical: 2
  High: 2
  Medium: 1
  Low: 0

Joomla Core Vulnerabilities (3):
  - CVE-2024-1234: 9.8 - CRITICAL
    Fixed in: 3.10.6

Component Vulnerabilities (1):
  - com_akeeba: 9.0.0
    * CVE-2024-5678: 8.5 - HIGH
      Fixed in: 9.2.2

============================================================
  Check Manually for Potential Vuln/Exploitable
============================================================
  (Version unknown - CVEs reported for these components/modules)

  Modules (1):
    - mod_vvisit_counter (version: unknown)
      * CVE-2025-40636: 9.3 - CRITICAL

============================================================
  Enumerated Components and Modules
============================================================

  Components (5):
    - com_content (version: 3.10.5) [CORE]
    - com_akeeba (version: 9.0.0) [1 CVE]
    ...

  Modules (3):
    - mod_menu (version: 3.0.0)
    - mod_vvisit_counter (version: unknown) [1 CVE]
    ...
```

### HTML Report
Professional HTML report with:
- **Collapsible sections** - All vulnerability sections use `<details>` for easy navigation; sections with findings auto-expand
- **Compact CVE cards** - Two-column grid layout with severity-colored borders, truncated descriptions
- **Check Manually section** - Components/modules with known CVEs but unconfirmed version ranges
- **Enumerated listing** - Collapsed-by-default reference table of all detected components and modules with version and status tags

### JSON Report
Machine-readable output with structured sections:
- `vulnerabilities` - Confirmed core, component, and module CVEs
- `check_manually` - Potential CVEs (unknown version or no NVD range data)
- `enumerated` - Full list of all detected components and modules

## Project Structure

```
JoomlaScanner/
├── cli.py                       # Main CLI entry point
├── scanner/
│   ├── db.py                   # Database operations
│   ├── fetcher.py              # NVD API integration
│   ├── detector.py             # Version detection
│   ├── component.py            # Component & module enumeration
│   ├── component_scraper.py    # Multi-source component scraper
│   ├── matcher.py              # CVE matching logic
│   └── reporter.py             # Report generation
├── db/
│   ├── schema.sql              # SQLite schema
│   └── joomlascan.db           # SQLite database
├── data/
│   ├── components.json         # Component database (rich JSON format)
│   └── modules.json            # Module database
└── requirements.txt            # Python dependencies
```

## Database

The scanner uses SQLite to store:
- Joomla core CVEs
- Component and module CVEs (both `com_` and `mod_` slugs)
- Detected components and modules
- Scan history

## CVE Sources

- NVD (National Vulnerability Database) - Primary source
- Updated via NVD API v2

## Requirements

- Python 3.8+
- See requirements.txt for dependencies

## Component Sources

The scanner pulls component data from 5 sources:

| Source | Coverage | Data |
|--------|----------|------|
| **JED Algolia API** | ~5,500 extensions | Name, vendor, category, Joomla versions, popularity |
| **Joomla GitHub** | ~35 core components | Definitive core component list across J3/J4/J5 |
| **NVD CPE Dictionary** | ~2,867 CPEs | Vulnerability-relevant components |
| **CVE Description Parsing** | Variable | Extracts `com_*` and `mod_*` from CVE text |
| **JED VEL** | All known vulnerable | Vulnerable, resolved, and abandoned extensions |

## Notes

- Default timeout is 3 seconds per request
- Quick scan (default) checks: core components/modules + CVE-affected + VEL-listed + top popular (popularity >= 10,000). Typically ~700 components and ~300 modules
- Full scan (`--full`) checks every component and module in the database (~1,300+ components, ~3,600+ modules)
- CVE matching uses normalized name lookup to handle naming differences between scanner and NVD (e.g. `mod_vvisitcounter` matches `mod_vvisit_counter`)
- CVEs without version range data in NVD (status "Awaiting Analysis") are reported as potential matches in the "Check Manually" section
- Run `python cli.py update` periodically to keep CVE and extension databases current

## License

MIT License

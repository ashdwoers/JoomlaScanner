-- JoomlaScanner Database Schema

-- Core Joomla CVEs (one row per CVE per affected version range)
CREATE TABLE IF NOT EXISTS joomla_core_cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    description TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cvss_severity TEXT,
    published_date DATE,
    version_start TEXT,
    version_end TEXT,
    version_end_type TEXT,       -- 'excluding' or 'including'
    fixed_version TEXT,
    affected_versions TEXT,
    ref_urls TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cve_id, version_start, version_end)
);

-- Component CVEs (one row per CVE per component per affected version range)
CREATE TABLE IF NOT EXISTS joomla_component_cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    component_name TEXT NOT NULL,
    vendor_name TEXT,
    description TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    version_start TEXT,
    version_end TEXT,
    version_end_type TEXT,       -- 'excluding' or 'including'
    affected_versions TEXT,
    fixed_version TEXT,
    introduced_version TEXT,
    published_date DATE,
    ref_urls TEXT,
    exploit_available INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cve_id, component_name, version_start, version_end)
);

-- Scan history
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    joomla_version TEXT,
    joomla_detection_method TEXT,
    components_detected TEXT,
    vulnerabilities_found TEXT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Components list
CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_name TEXT UNIQUE NOT NULL,
    display_name TEXT,
    vendor_name TEXT,
    category TEXT,
    source TEXT,
    is_core INTEGER DEFAULT 0,
    jed_url TEXT,
    vel_status TEXT,
    has_known_cves INTEGER DEFAULT 0,
    popularity_score INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Modules list
CREATE TABLE IF NOT EXISTS modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name TEXT UNIQUE NOT NULL,
    display_name TEXT,
    vendor_name TEXT,
    category TEXT,
    source TEXT,
    is_core INTEGER DEFAULT 0,
    jed_url TEXT,
    vel_status TEXT,
    has_known_cves INTEGER DEFAULT 0,
    popularity_score INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Metadata for tracking updates
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

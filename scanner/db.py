import sqlite3
import os
from pathlib import Path
from datetime import datetime


class Database:
    def __init__(self, db_path=None):
        if db_path is None:
            base_dir = Path(__file__).parent.parent
            db_path = base_dir / "db" / "joomlascan.db"

        self.db_path = str(db_path)
        self._ensure_db_dir()
        self._init_db()

    def _ensure_db_dir(self):
        db_dir = os.path.dirname(self.db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)

    def _init_db(self):
        schema_path = Path(__file__).parent.parent / "db" / "schema.sql"
        with open(schema_path, "r") as f:
            schema = f.read()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.executescript(schema)
        conn.commit()
        conn.close()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def execute(self, query, params=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        conn.commit()
        conn.close()

    def fetch_one(self, query, params=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        return result

    def fetch_all(self, query, params=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results

    def insert_core_cve(self, cve_data):
        query = """
        INSERT OR REPLACE INTO joomla_core_cves 
        (cve_id, description, cvss_score, cvss_vector, cvss_severity, 
         published_date, version_start, version_end, version_end_type,
         fixed_version, affected_versions, ref_urls)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.execute(
            query,
            (
                cve_data.get("cve_id"),
                cve_data.get("description"),
                cve_data.get("cvss_score"),
                cve_data.get("cvss_vector"),
                cve_data.get("cvss_severity"),
                cve_data.get("published_date"),
                cve_data.get("version_start"),
                cve_data.get("version_end"),
                cve_data.get("version_end_type"),
                cve_data.get("fixed_version"),
                cve_data.get("affected_versions"),
                cve_data.get("ref_urls"),
            ),
        )

    def insert_component_cve(self, cve_data):
        query = """
        INSERT OR REPLACE INTO joomla_component_cves 
        (cve_id, component_name, vendor_name, description, cvss_score, 
         cvss_severity, version_start, version_end, version_end_type,
         affected_versions, fixed_version, introduced_version,
         published_date, ref_urls, exploit_available)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.execute(
            query,
            (
                cve_data.get("cve_id"),
                cve_data.get("component_name"),
                cve_data.get("vendor_name"),
                cve_data.get("description"),
                cve_data.get("cvss_score"),
                cve_data.get("cvss_severity"),
                cve_data.get("version_start"),
                cve_data.get("version_end"),
                cve_data.get("version_end_type"),
                cve_data.get("affected_versions"),
                cve_data.get("fixed_version"),
                cve_data.get("introduced_version"),
                cve_data.get("published_date"),
                cve_data.get("ref_urls"),
                cve_data.get("exploit_available", 0),
            ),
        )

    def get_core_cves(self, version=None):
        query = """
        SELECT cve_id, description, cvss_score, cvss_severity, 
               published_date, fixed_version, ref_urls,
               version_start, version_end, version_end_type
        FROM joomla_core_cves
        ORDER BY cvss_score DESC
        """
        return self.fetch_all(query)

    def get_component_cves(self, component_name, version=None):
        query = """
        SELECT cve_id, description, cvss_score, cvss_severity, 
               published_date, fixed_version, ref_urls,
               version_start, version_end, version_end_type
        FROM joomla_component_cves
        WHERE component_name = ?
        ORDER BY cvss_score DESC
        """
        return self.fetch_all(query, (component_name,))

    def get_all_components(self):
        query = "SELECT component_name, display_name, vendor_name FROM components ORDER BY component_name"
        return self.fetch_all(query)

    def add_component(
        self,
        component_name,
        display_name=None,
        vendor_name=None,
        category=None,
        source="cve",
    ):
        query = """
        INSERT OR IGNORE INTO components (component_name, display_name, vendor_name, category, source)
        VALUES (?, ?, ?, ?, ?)
        """
        self.execute(
            query, (component_name, display_name, vendor_name, category, source)
        )

    def save_scan_history(self, scan_data):
        import json

        query = """
        INSERT INTO scan_history 
        (target_url, joomla_version, joomla_detection_method, components_detected, vulnerabilities_found)
        VALUES (?, ?, ?, ?, ?)
        """
        self.execute(
            query,
            (
                scan_data.get("target_url"),
                scan_data.get("joomla_version"),
                scan_data.get("joomla_detection_method"),
                json.dumps(scan_data.get("components_detected", [])),
                json.dumps(scan_data.get("vulnerabilities_found", [])),
            ),
        )

    def get_last_cve_update(self):
        result = self.fetch_one(
            "SELECT value FROM metadata WHERE key = 'last_cve_update'"
        )
        return result[0] if result else None

    def set_last_cve_update(self, timestamp):
        query = """
        INSERT OR REPLACE INTO metadata (key, value, updated_at)
        VALUES ('last_cve_update', ?, ?)
        """
        self.execute(query, (timestamp, datetime.now().isoformat()))

    def get_core_cve_count(self):
        result = self.fetch_one("SELECT COUNT(*) FROM joomla_core_cves")
        return result[0] if result else 0

    def get_component_cve_count(self):
        result = self.fetch_one("SELECT COUNT(*) FROM joomla_component_cves")
        return result[0] if result else 0

    def get_component_count(self):
        result = self.fetch_one("SELECT COUNT(*) FROM components")
        return result[0] if result else 0

    def add_module(
        self,
        module_name,
        display_name=None,
        vendor_name=None,
        category=None,
        source="cve",
    ):
        query = """
        INSERT OR IGNORE INTO modules (module_name, display_name, vendor_name, category, source)
        VALUES (?, ?, ?, ?, ?)
        """
        self.execute(
            query, (module_name, display_name, vendor_name, category, source)
        )

    def get_all_modules(self):
        query = "SELECT module_name, display_name, vendor_name FROM modules ORDER BY module_name"
        return self.fetch_all(query)

    def get_module_count(self):
        result = self.fetch_one("SELECT COUNT(*) FROM modules")
        return result[0] if result else 0

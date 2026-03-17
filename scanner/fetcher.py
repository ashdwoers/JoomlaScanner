import requests
import json
import re
import time
from datetime import datetime, timedelta
from scanner.db import Database


def _nvd_request(session, url, params, timeout=30, max_retries=5, log=print):
    """Make an NVD API request with retry and exponential backoff on 429/503."""
    delay = 6.0  # NVD public rate limit: 5 requests per 30s
    for attempt in range(max_retries):
        resp = session.get(url, params=params, timeout=timeout)
        if resp.status_code == 200:
            return resp
        if resp.status_code in (429, 503):
            wait = delay * (2 ** attempt)
            log(f"[!] NVD rate limit (HTTP {resp.status_code}), waiting {wait:.0f}s (attempt {attempt + 1}/{max_retries})...")
            time.sleep(wait)
            continue
        return resp
    return resp


class CVEFetcher:
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # CPE patterns for identifying Joomla core vs third-party
    JOOMLA_CORE_VENDORS = {"joomla"}
    JOOMLA_CORE_PRODUCTS = {"joomla", "joomla!"}

    def __init__(self, db=None):
        self.db = db or Database()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "JoomlaScanner/1.0"})

    def _extract_cvss(self, cve_data):
        """Extract CVSS score, vector, and severity from CVE metrics."""
        metrics = cve_data.get("metrics", {})
        cvss_data = None

        # Prefer v3.1 > v3.0 > v2
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})

        cvss_score = cvss_data.get("baseScore") if cvss_data else None
        cvss_vector = cvss_data.get("vectorString") if cvss_data else None
        cvss_severity = cvss_data.get("baseSeverity") if cvss_data else None

        # Derive severity from score if not provided
        if cvss_score and not cvss_severity:
            if cvss_score >= 9.0:
                cvss_severity = "CRITICAL"
            elif cvss_score >= 7.0:
                cvss_severity = "HIGH"
            elif cvss_score >= 4.0:
                cvss_severity = "MEDIUM"
            elif cvss_score > 0:
                cvss_severity = "LOW"

        return cvss_score, cvss_vector, cvss_severity

    def _extract_version_ranges(self, cve_data):
        """
        Extract version ranges from CPE configurations.
        Returns list of dicts with: vendor, product, version_start,
        version_end, version_end_type, is_joomla_core
        """
        ranges = []
        configurations = cve_data.get("configurations", [])

        for config in configurations:
            for node in config.get("nodes", []):
                self._extract_from_node(node, ranges)
                # Handle nested children (operator AND/OR)
                for child in node.get("children", []):
                    self._extract_from_node(child, ranges)

        return ranges

    def _extract_from_node(self, node, ranges):
        """Extract version info from a single CPE match node."""
        for match in node.get("cpeMatch", []):
            if not match.get("vulnerable", False):
                continue

            criteria = match.get("criteria", "")
            parts = criteria.split(":")

            if len(parts) < 6:
                continue

            vendor = parts[3].replace("\\!", "").replace("\\", "").lower()
            product = parts[4].replace("\\!", "").replace("\\", "").lower()
            cpe_version = parts[5] if len(parts) > 5 else "*"

            version_start = match.get("versionStartIncluding")
            version_end_excl = match.get("versionEndExcluding")
            version_end_incl = match.get("versionEndIncluding")

            is_core = (
                vendor in self.JOOMLA_CORE_VENDORS
                and product in self.JOOMLA_CORE_PRODUCTS
            )

            # Determine version_end and type
            version_end = None
            version_end_type = None

            if version_end_excl:
                version_end = version_end_excl
                version_end_type = "excluding"
            elif version_end_incl:
                version_end = version_end_incl
                version_end_type = "including"
            elif cpe_version and cpe_version != "*":
                # Exact version match from CPE string itself
                version_end = cpe_version
                version_end_type = "including"
                if not version_start:
                    version_start = cpe_version

            ranges.append({
                "vendor": vendor,
                "product": product,
                "version_start": version_start,
                "version_end": version_end,
                "version_end_type": version_end_type,
                "is_joomla_core": is_core,
            })

        return ranges

    def _cpe_product_to_slug(self, vendor, product, description):
        """
        Map a CPE vendor:product to a com_ or mod_ slug.
        Uses multiple strategies to find the right slug.
        Returns list of (slug, type) tuples where type is 'component' or 'module'.
        """
        # Strategy 1: Check if description mentions mod_ or com_ directly
        mod_pattern = re.compile(r"\b(mod_[a-zA-Z0-9_]+)\b", re.IGNORECASE)
        com_pattern = re.compile(r"\b(com_[a-zA-Z0-9_]+)\b", re.IGNORECASE)

        mod_matches = mod_pattern.findall(description)
        com_matches = com_pattern.findall(description)

        results = []
        for m in com_matches:
            results.append((m.lower(), "component"))
        for m in mod_matches:
            results.append((m.lower(), "module"))
        if results:
            return results

        # Strategy 2: Check if the CPE product itself starts with mod_
        if product.startswith("mod_"):
            return [(product.lower(), "module")]

        # Strategy 3: Product name mapping (default to com_ prefix)
        product_clean = re.sub(r"[^a-z0-9]", "", product)
        if product_clean:
            slugs = [(f"com_{product_clean}", "component")]

            # Also try vendor_product combo if vendor != product
            vendor_clean = re.sub(r"[^a-z0-9]", "", vendor)
            if vendor_clean and vendor_clean != product_clean:
                slugs.append((f"com_{vendor_clean}", "component"))

            return slugs

        return []

    def _process_cve(self, cve_data):
        """Process a single CVE entry, extracting all version ranges and storing properly."""
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        published = cve_data.get("published", "")[:10]

        cvss_score, cvss_vector, cvss_severity = self._extract_cvss(cve_data)

        references = cve_data.get("references", [])
        ref_urls = [ref.get("url") for ref in references[:5]]

        # Extract version ranges from CPE configurations
        version_ranges = self._extract_version_ranges(cve_data)

        # Also try to extract fixed version from description as fallback
        desc_fixed = self._extract_fixed_version_from_text(description, ref_urls)

        if version_ranges:
            for vr in version_ranges:
                # Compute fixed_version: for "excluding" end, that IS the fixed version
                fixed_version = None
                if vr["version_end_type"] == "excluding":
                    fixed_version = vr["version_end"]
                elif vr["version_end_type"] == "including" and vr["version_end"]:
                    # The fix is the next version after the included end
                    # We can't easily compute this, so store the range and let matcher handle it
                    fixed_version = desc_fixed

                base_entry = {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cvss_severity": cvss_severity,
                    "published_date": published,
                    "version_start": vr["version_start"],
                    "version_end": vr["version_end"],
                    "version_end_type": vr["version_end_type"],
                    "fixed_version": fixed_version,
                    "affected_versions": None,
                    "ref_urls": ",".join(ref_urls),
                }

                if vr["is_joomla_core"]:
                    self.db.insert_core_cve(base_entry)
                else:
                    # Third-party component or module
                    slugs = self._cpe_product_to_slug(
                        vr["vendor"], vr["product"], description
                    )
                    for slug, slug_type in slugs:
                        entry = {
                            **base_entry,
                            "component_name": slug,
                            "vendor_name": vr["vendor"],
                            "introduced_version": vr["version_start"],
                            "exploit_available": 0,
                        }
                        self.db.insert_component_cve(entry)
                        if slug_type == "module":
                            self.db.add_module(
                                module_name=slug,
                                vendor_name=vr["vendor"],
                                source="nvd_cve",
                            )
                        else:
                            self.db.add_component(
                                component_name=slug,
                                vendor_name=vr["vendor"],
                                source="nvd_cve",
                            )
        else:
            # No CPE configurations — fallback to description-based extraction
            base_entry = {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cvss_severity": cvss_severity,
                "published_date": published,
                "version_start": None,
                "version_end": None,
                "version_end_type": None,
                "fixed_version": desc_fixed,
                "affected_versions": None,
                "ref_urls": ",".join(ref_urls),
            }

            # Try to extract component/module names from description
            com_pattern = re.compile(r"\b(com_[a-zA-Z0-9_]+)\b", re.IGNORECASE)
            mod_pattern = re.compile(r"\b(mod_[a-zA-Z0-9_]+)\b", re.IGNORECASE)

            com_matches = com_pattern.findall(description)
            mod_matches = mod_pattern.findall(description)

            # Detect third-party extensions by description patterns like
            # "... component for Joomla", "... plugin for Joomla", etc.
            # These are NOT Joomla core vulnerabilities — they describe
            # vulnerabilities in third-party extensions (e.g. "No Boss
            # Calendar component before 5.0.7 for Joomla").
            third_party_pattern = re.compile(
                r"\b(?:component|plugin|module|extension)\b.{0,30}\bfor\s+joomla\b",
                re.IGNORECASE,
            )
            is_third_party = bool(third_party_pattern.search(description))

            # Only insert as core CVE if it's NOT a third-party extension
            if not is_third_party:
                self.db.insert_core_cve(base_entry)

            for match in com_matches:
                slug = match.lower()
                comp_entry = {
                    **base_entry,
                    "component_name": slug,
                    "vendor_name": None,
                    "introduced_version": None,
                    "exploit_available": 0,
                }
                self.db.insert_component_cve(comp_entry)
                self.db.add_component(component_name=slug, source="nvd_cve")

            for match in mod_matches:
                slug = match.lower()
                mod_entry = {
                    **base_entry,
                    "component_name": slug,
                    "vendor_name": None,
                    "introduced_version": None,
                    "exploit_available": 0,
                }
                self.db.insert_component_cve(mod_entry)
                self.db.add_module(module_name=slug, source="nvd_cve")

    def _extract_fixed_version_from_text(self, description, references):
        """Try to extract a fixed version from description text (fallback)."""
        patterns = [
            r"fixed in (?:version )?(\d+\.\d+[\.\d]*)",
            r"resolved in (?:version )?(\d+\.\d+[\.\d]*)",
            r"patched in (?:version )?(\d+\.\d+[\.\d]*)",
            r"before (\d+\.\d+[\.\d]*)",
            r"prior to (\d+\.\d+[\.\d]*)",
            r"(?:versions? )(\d+\.\d+[\.\d]*) and (?:above|later)",
        ]

        text = description + " " + " ".join(references)

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def fetch_all_joomla_cves(self, verbose=True):
        if verbose:
            print("[*] Fetching all Joomla CVEs from NVD...")

        total_cves = 0
        start_index = 0
        results_per_page = 100

        while True:
            params = {
                "keywordSearch": "joomla",
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }

            try:
                response = _nvd_request(
                    self.session, self.NVD_API_BASE, params, timeout=30,
                )

                if response.status_code != 200:
                    print(f"[!] Error fetching CVEs: HTTP {response.status_code}")
                    break

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    self._process_cve(cve_data)
                    total_cves += 1

                start_index += results_per_page

                if verbose:
                    total = data.get("totalResults", "N/A")
                    print(f"    Fetched {total_cves}/{total} CVEs...")

                time.sleep(6)  # NVD public rate limit

            except Exception as e:
                print(f"[!] Error: {e}")
                break

        self.db.set_last_cve_update(datetime.now().strftime("%Y-%m-%d"))

        if verbose:
            print(f"[+] Total Joomla CVEs processed: {total_cves}")

        return total_cves

    def fetch_new_cves(self, days=7, verbose=True):
        if verbose:
            print(f"[*] Fetching new CVEs from last {days} days...")

        last_update = self.db.get_last_cve_update()

        if last_update:
            start_date = last_update
        else:
            start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

        end_date = datetime.now().strftime("%Y-%m-%d")

        total_cves = self._fetch_date_range(start_date, end_date, verbose=verbose)

        self.db.set_last_cve_update(datetime.now().strftime("%Y-%m-%d"))

        if verbose:
            print(f"[+] New CVEs imported: {total_cves}")

        return total_cves

    def _fetch_date_range(self, start_date, end_date, verbose=True):
        """Fetch CVEs within a date range (must be <= 120 days for NVD API)."""
        total_cves = 0
        start_index = 0

        while True:
            params = {
                "keywordSearch": "joomla",
                "pubStartDate": f"{start_date}T00:00:00",
                "pubEndDate": f"{end_date}T23:59:59",
                "startIndex": start_index,
                "resultsPerPage": 100,
            }

            try:
                response = _nvd_request(
                    self.session, self.NVD_API_BASE, params, timeout=30,
                )

                if response.status_code != 200:
                    if verbose:
                        print(f"[!] NVD API returned {response.status_code} for {start_date} to {end_date}")
                    break

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    self._process_cve(cve_data)
                    total_cves += 1

                start_index += 100

                if start_index >= data.get("totalResults", 0):
                    break

                time.sleep(6)  # NVD public rate limit

            except Exception as e:
                if verbose:
                    print(f"[!] Error fetching {start_date} to {end_date}: {e}")
                break

        return total_cves

    def fetch_by_year(self, year=None, verbose=True):
        """Fetch CVEs for a year, chunked into 120-day windows (NVD API limit)."""
        if year is None:
            year = datetime.now().year

        if verbose:
            print(f"[*] Fetching Joomla CVEs for year {year}...")

        total_cves = 0
        chunk_start = datetime(year, 1, 1)
        year_end = datetime(year, 12, 31)

        while chunk_start <= year_end:
            chunk_end = min(chunk_start + timedelta(days=119), year_end)

            count = self._fetch_date_range(
                chunk_start.strftime("%Y-%m-%d"),
                chunk_end.strftime("%Y-%m-%d"),
                verbose=verbose,
            )
            total_cves += count

            if verbose and count > 0:
                print(
                    f"    {chunk_start.strftime('%Y-%m-%d')} to "
                    f"{chunk_end.strftime('%Y-%m-%d')}: {count} CVEs"
                )

            chunk_start = chunk_end + timedelta(days=1)
            time.sleep(6)  # NVD public rate limit

        if verbose:
            print(f"[+] CVEs imported for {year}: {total_cves}")

        return total_cves

    def fetch_year_range(self, start_year, end_year=None, verbose=True):
        if end_year is None:
            end_year = datetime.now().year

        total_imported = 0

        for year in range(start_year, end_year + 1):
            count = self.fetch_by_year(year, verbose=verbose)
            total_imported += count

        return total_imported

    def get_stats(self):
        return {
            "core_cves": self.db.get_core_cve_count(),
            "component_cves": self.db.get_component_cve_count(),
            "tracked_components": self.db.get_component_count(),
        }


def update_cves(verbose=True):
    fetcher = CVEFetcher()
    fetcher.fetch_all_joomla_cves(verbose=verbose)
    return fetcher.get_stats()


if __name__ == "__main__":
    print("JoomlaScanner CVE Fetcher")
    print("=" * 40)
    stats = update_cves(verbose=True)
    print("\nDatabase Statistics:")
    print(f"  Core CVEs: {stats['core_cves']}")
    print(f"  Component CVEs: {stats['component_cves']}")
    print(f"  Tracked Components: {stats['tracked_components']}")

#!/usr/bin/env python3
"""
Component Scraper - Comprehensive Joomla extension discovery from multiple sources.

Sources:
    1. JED Algolia Search API (~5,500 extensions)
    2. Joomla GitHub Repository (core components)
    3. NVD CPE Dictionary (vulnerability-relevant components)
    4. NVD CVE Description Parsing (com_ extraction)
    5. JED Vulnerable Extensions List (VEL)
"""

import json
import re
import time
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

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
        # Other error — return as-is for caller to handle
        return resp
    return resp  # Return last response after all retries exhausted


class ComponentScraper:
    """Scrapes Joomla components from multiple authoritative sources."""

    # JED Algolia credentials (publicly exposed in JED page source)
    ALGOLIA_APP_ID = "BLPSS1JDLM"
    ALGOLIA_API_KEY = "45457336014964a3858de02be398ea70"
    ALGOLIA_INDEX = "jed_live"
    ALGOLIA_URL = f"https://{ALGOLIA_APP_ID}-dsn.algolia.net/1/indexes/{ALGOLIA_INDEX}"

    # GitHub API
    GITHUB_API = "https://api.github.com/repos/joomla/joomla-cms/contents"
    GITHUB_BRANCHES = ["5.4-dev", "6.0-dev"]

    # NVD CPE API
    NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

    # JED VEL pages
    VEL_URLS = {
        "vulnerable": "https://extensions.joomla.org/vulnerable-extensions/vulnerable/",
        "resolved": "https://extensions.joomla.org/vulnerable-extensions/resolved/",
        "abandoned": "https://extensions.joomla.org/vulnerable-extensions/abandoned/",
    }

    def __init__(self, db=None, verbose=True):
        self.db = db or Database()
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "JoomlaScanner/1.0"})
        self.components = {}  # slug -> component data

    def log(self, msg):
        if self.verbose:
            print(msg)

    # =========================================================================
    # Source 1: JED Algolia Search API
    # =========================================================================

    def scrape_jed_algolia(self):
        """Paginate through all JED extensions via Algolia search API.

        Algolia limits page*hitsPerPage to 1000, so we partition queries
        by category facet to ensure we retrieve all ~5,500 extensions.
        """
        self.log("\n[*] Source 1: JED Algolia Search API")
        self.log("[*] Fetching all extensions from Joomla Extensions Directory...")

        headers = {
            "X-Algolia-Application-Id": self.ALGOLIA_APP_ID,
            "X-Algolia-API-Key": self.ALGOLIA_API_KEY,
        }

        # Step 1: Get all category names via faceting
        try:
            resp = self.session.get(
                self.ALGOLIA_URL,
                headers=headers,
                params={
                    "query": "",
                    "hitsPerPage": 0,
                    "facets": "core_catid",
                    "maxValuesPerFacet": 1000,
                },
                timeout=30,
            )
            if resp.status_code != 200:
                self.log(f"[!] Algolia facet query failed: HTTP {resp.status_code}")
                return 0

            facet_data = resp.json()
            categories = facet_data.get("facets", {}).get("core_catid", {})
            total_extensions = facet_data.get("nbHits", 0)
            self.log(f"[*] Total extensions in JED: {total_extensions}")
            self.log(f"[*] Categories to fetch: {len(categories)}")

        except Exception as e:
            self.log(f"[!] Algolia facet error: {e}")
            return 0

        # Step 2: Fetch each category (all under 1000 items each)
        total_fetched = 0
        cat_count = 0

        for category, count in sorted(categories.items(), key=lambda x: -x[1]):
            cat_count += 1
            page = 0

            while True:
                params = {
                    "query": "",
                    "hitsPerPage": 1000,
                    "page": page,
                    "facetFilters": json.dumps([f"core_catid:{category}"]),
                    "attributesToRetrieve": "core_title,core_created_user_id,core_catid,tags_array,includes,versions,url,type,score,num_reviews,id",
                }

                try:
                    resp = self.session.get(
                        self.ALGOLIA_URL, headers=headers, params=params, timeout=30
                    )

                    if resp.status_code != 200:
                        self.log(f"[!] Algolia error for '{category}': HTTP {resp.status_code}")
                        break

                    data = resp.json()
                    hits = data.get("hits", [])

                    if not hits:
                        break

                    for hit in hits:
                        self._process_jed_hit(hit)
                        total_fetched += 1

                    page += 1
                    if page >= data.get("nbPages", 0):
                        break

                    time.sleep(0.3)

                except Exception as e:
                    self.log(f"[!] Algolia error for '{category}' page {page}: {e}")
                    break

            # Progress update every 20 categories
            if cat_count % 20 == 0 or cat_count == len(categories):
                self.log(
                    f"    Categories: {cat_count}/{len(categories)} | Extensions: {total_fetched}"
                )

            time.sleep(0.3)

        self.log(f"[+] JED Algolia: {total_fetched} extensions fetched")
        return total_fetched

    def _process_jed_hit(self, hit):
        """Process a single JED Algolia hit into component data."""
        title = hit.get("core_title", "").strip()
        if not title:
            return

        url = hit.get("url", "")
        includes = hit.get("includes", [])
        vendor = hit.get("core_created_user_id", "")
        category = hit.get("core_catid", "")
        tags = hit.get("tags_array", [])
        versions = hit.get("versions", [])
        ext_type = hit.get("type", "")
        score = hit.get("score", 0)
        num_reviews = hit.get("num_reviews", 0)
        jed_id = hit.get("id", "")

        # Generate slug candidates
        slugs = self._generate_slugs(title, url)

        # Determine extension types present
        has_component = "com" in includes
        has_module = "mod" in includes
        has_plugin = "plugin" in includes

        # Map Joomla version codes to readable versions
        joomla_versions = []
        version_map = {
            "15": "1.5", "16": "1.6", "17": "1.7",
            "25": "2.5",
            "30": "3", "31": "3.1", "32": "3.2", "33": "3.3", "34": "3.4",
            "35": "3.5", "36": "3.6", "37": "3.7", "38": "3.8", "39": "3.9",
            "40": "4", "41": "4.1", "42": "4.2", "43": "4.3", "44": "4.4",
            "50": "5", "51": "5.1", "52": "5.2", "53": "5.3",
            "60": "6",
        }
        for v in versions:
            joomla_versions.append(version_map.get(str(v), str(v)))

        # Only store if it includes a component
        if has_component and slugs:
            primary_slug = slugs[0]
            aliases = slugs[1:] if len(slugs) > 1 else []

            component = {
                "slug": primary_slug,
                "slug_aliases": aliases,
                "display_name": title,
                "vendor": vendor,
                "category": category,
                "tags": tags,
                "is_core": False,
                "joomla_versions": joomla_versions,
                "source": "jed_algolia",
                "jed_url": url,
                "jed_id": jed_id,
                "license_type": ext_type,
                "has_module": has_module,
                "has_plugin": has_plugin,
                "vel_status": None,
                "has_known_cves": False,
                "popularity_score": score,
                "num_reviews": num_reviews,
            }

            # Store by primary slug, don't overwrite if already exists with richer data
            if primary_slug not in self.components:
                self.components[primary_slug] = component
            else:
                # Merge: keep existing but update JED-specific fields
                existing = self.components[primary_slug]
                existing["jed_url"] = url
                existing["jed_id"] = jed_id
                existing["display_name"] = title
                existing["vendor"] = vendor or existing.get("vendor", "")
                existing["popularity_score"] = max(
                    score, existing.get("popularity_score", 0)
                )

            # Also index aliases for lookup
            for alias in aliases:
                if alias not in self.components:
                    self.components[alias] = component

        # Also store modules if present
        if has_module:
            mod_slugs = self._generate_module_slugs(title, url)
            for mod_slug in mod_slugs:
                if mod_slug not in self.components:
                    self.components[mod_slug] = {
                        "slug": mod_slug,
                        "slug_aliases": [],
                        "display_name": title,
                        "vendor": vendor,
                        "category": category,
                        "tags": tags,
                        "is_core": False,
                        "joomla_versions": joomla_versions,
                        "source": "jed_algolia",
                        "jed_url": url,
                        "jed_id": jed_id,
                        "license_type": ext_type,
                        "has_module": True,
                        "has_plugin": has_plugin,
                        "vel_status": None,
                        "has_known_cves": False,
                        "popularity_score": score,
                        "num_reviews": num_reviews,
                    }

    def _generate_slugs(self, title, url=""):
        """Generate com_ slug candidates from extension title and URL."""
        slugs = []

        # Clean title
        clean = re.sub(r"[^a-zA-Z0-9\s]", "", title).strip().lower()
        words = clean.split()

        if not words:
            return slugs

        # Strategy 1: First word only → com_{first}
        first = words[0]
        if len(first) >= 2:
            slugs.append(f"com_{first}")

        # Strategy 2: All words joined → com_{allwords}
        joined = "".join(words)
        if joined != first:
            slugs.append(f"com_{joined}")

        # Strategy 3: First two words joined (common pattern)
        if len(words) >= 2:
            two = words[0] + words[1]
            if two != joined:
                slugs.append(f"com_{two}")

        # Strategy 4: From URL slug
        if url:
            url_match = re.search(r"/extension/([^/]+)/?", url)
            if url_match:
                url_slug = url_match.group(1).replace("-", "").lower()
                candidate = f"com_{url_slug}"
                if candidate not in slugs:
                    slugs.append(candidate)

                # Also try with hyphens replaced by underscores
                url_slug_us = url_match.group(1).replace("-", "_").lower()
                candidate_us = f"com_{url_slug_us}"
                if candidate_us not in slugs:
                    slugs.append(candidate_us)

        # Strategy 5: Common prefixes - if title starts with "J" or "RS" etc.
        # e.g., "JCE Editor" → com_jce (already covered by first word)
        # e.g., "RSForm" → com_rsform (already covered)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for s in slugs:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique

    def _generate_module_slugs(self, title, url=""):
        """Generate mod_ slug candidates from extension title and URL."""
        slugs = []

        clean = re.sub(r"[^a-zA-Z0-9\s]", "", title).strip().lower()
        words = clean.split()

        if not words:
            return slugs

        first = words[0]
        if len(first) >= 2:
            slugs.append(f"mod_{first}")

        joined = "".join(words)
        if joined != first:
            slugs.append(f"mod_{joined}")

        return slugs

    # =========================================================================
    # Source 2: Joomla GitHub Repository (Core Components)
    # =========================================================================

    def scrape_github_core(self):
        """Fetch core Joomla components and modules from GitHub across multiple branches."""
        self.log("\n[*] Source 2: Joomla GitHub Repository")
        self.log("[*] Fetching core components and modules from joomla/joomla-cms...")

        core_components = set()
        core_modules = set()

        component_dirs = ["administrator/components", "components"]
        module_dirs = ["administrator/modules", "modules"]

        for branch in self.GITHUB_BRANCHES:
            for dir_path in component_dirs:
                url = f"{self.GITHUB_API}/{dir_path}"
                params = {"ref": branch}

                try:
                    resp = self.session.get(url, params=params, timeout=15)

                    if resp.status_code == 200:
                        items = resp.json()
                        for item in items:
                            name = item.get("name", "")
                            if name.startswith("com_"):
                                core_components.add(name)
                    elif resp.status_code == 403:
                        self.log(
                            f"[!] GitHub rate limit hit. Try again later or use a token."
                        )
                        break
                    else:
                        self.log(
                            f"    Warning: {dir_path} on {branch} returned {resp.status_code}"
                        )

                    time.sleep(0.5)  # Be nice to GitHub

                except Exception as e:
                    self.log(f"[!] GitHub error ({branch}/{dir_path}): {e}")

            for dir_path in module_dirs:
                url = f"{self.GITHUB_API}/{dir_path}"
                params = {"ref": branch}

                try:
                    resp = self.session.get(url, params=params, timeout=15)

                    if resp.status_code == 200:
                        items = resp.json()
                        for item in items:
                            name = item.get("name", "")
                            if name.startswith("mod_"):
                                core_modules.add(name)
                    elif resp.status_code == 403:
                        self.log(
                            f"[!] GitHub rate limit hit. Try again later or use a token."
                        )
                        break
                    else:
                        self.log(
                            f"    Warning: {dir_path} on {branch} returned {resp.status_code}"
                        )

                    time.sleep(0.5)

                except Exception as e:
                    self.log(f"[!] GitHub error ({branch}/{dir_path}): {e}")

        self.log(f"[+] GitHub: {len(core_components)} core components, {len(core_modules)} core modules found")

        # Store core components
        for comp in sorted(core_components):
            display_name = comp.replace("com_", "").replace("_", " ").title()

            if comp in self.components:
                self.components[comp]["is_core"] = True
                self.components[comp]["source"] = "github_core"
            else:
                self.components[comp] = {
                    "slug": comp,
                    "slug_aliases": [],
                    "display_name": f"Joomla {display_name}",
                    "vendor": "Joomla! Project",
                    "category": "Core",
                    "tags": ["Core"],
                    "is_core": True,
                    "joomla_versions": [],
                    "source": "github_core",
                    "jed_url": None,
                    "jed_id": None,
                    "license_type": "Free",
                    "has_module": False,
                    "has_plugin": False,
                    "vel_status": None,
                    "has_known_cves": False,
                    "popularity_score": 99999,
                    "num_reviews": 0,
                }

        # Store core modules
        for mod in sorted(core_modules):
            display_name = mod.replace("mod_", "").replace("_", " ").title()

            if mod in self.components:
                self.components[mod]["is_core"] = True
                self.components[mod]["source"] = "github_core"
            else:
                self.components[mod] = {
                    "slug": mod,
                    "slug_aliases": [],
                    "display_name": f"Joomla {display_name}",
                    "vendor": "Joomla! Project",
                    "category": "Core",
                    "tags": ["Core"],
                    "is_core": True,
                    "joomla_versions": [],
                    "source": "github_core",
                    "jed_url": None,
                    "jed_id": None,
                    "license_type": "Free",
                    "has_module": True,
                    "has_plugin": False,
                    "vel_status": None,
                    "has_known_cves": False,
                    "popularity_score": 99999,
                    "num_reviews": 0,
                }

        return len(core_components)

    # =========================================================================
    # Source 3: NVD CPE Dictionary
    # =========================================================================

    def scrape_nvd_cpes(self):
        """Fetch Joomla-related CPEs from NVD to find vulnerability-relevant components."""
        self.log("\n[*] Source 3: NVD CPE Dictionary")
        self.log("[*] Fetching Joomla-related CPEs from NVD...")

        total_fetched = 0
        start_index = 0
        results_per_page = 100
        total_results = None
        component_names = set()

        while True:
            params = {
                "keywordSearch": "joomla",
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }

            try:
                resp = _nvd_request(
                    self.session, self.NVD_CPE_API, params,
                    timeout=30, log=self.log,
                )

                if resp.status_code != 200:
                    self.log(f"[!] NVD CPE API error: HTTP {resp.status_code}")
                    break

                data = resp.json()
                products = data.get("products", [])

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    self.log(f"[*] Total Joomla-related CPEs: {total_results}")

                if not products:
                    break

                for product in products:
                    cpe_data = product.get("cpe", {})
                    cpe_name = cpe_data.get("cpeName", "")

                    # Parse CPE: cpe:2.3:a:vendor:product:version:...
                    parts = cpe_name.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].replace("\\!", "").replace("\\", "")
                        product_name = parts[4].replace("\\!", "").replace("\\", "")

                        # Skip the core Joomla entry itself
                        if vendor == "joomla" and product_name == "joomla":
                            continue

                        # Try to form a com_ slug
                        slug = self._cpe_to_slug(vendor, product_name)
                        if slug:
                            component_names.add(slug)
                            total_fetched += 1

                start_index += results_per_page

                if start_index >= total_results:
                    break

                self.log(
                    f"    Processed {min(start_index, total_results)}/{total_results} CPEs..."
                )
                time.sleep(6)  # NVD public rate limit: ~5 req / 30s

            except Exception as e:
                self.log(f"[!] NVD CPE error: {e}")
                break

        # Store components from CPEs
        for slug in sorted(component_names):
            if slug in self.components:
                self.components[slug]["has_known_cves"] = True
                if self.components[slug]["source"] != "github_core":
                    self.components[slug]["source"] = "nvd_cpe"
            else:
                display_name = slug.replace("com_", "").replace("_", " ").title()
                self.components[slug] = {
                    "slug": slug,
                    "slug_aliases": [],
                    "display_name": display_name,
                    "vendor": "",
                    "category": "",
                    "tags": [],
                    "is_core": False,
                    "joomla_versions": [],
                    "source": "nvd_cpe",
                    "jed_url": None,
                    "jed_id": None,
                    "license_type": "",
                    "has_module": False,
                    "has_plugin": False,
                    "vel_status": None,
                    "has_known_cves": True,
                    "popularity_score": 0,
                    "num_reviews": 0,
                }

        self.log(f"[+] NVD CPE: {len(component_names)} component slugs extracted")
        return len(component_names)

    def _cpe_to_slug(self, vendor, product):
        """Convert a CPE vendor:product to a com_ slug."""
        product_clean = re.sub(r"[^a-z0-9]", "", product.lower())

        if not product_clean:
            return None

        # If product already looks like a component name
        if product_clean.startswith("com"):
            return product_clean if product_clean.startswith("com_") else f"com_{product_clean[3:]}"

        # Common patterns
        slug = f"com_{product_clean}"
        return slug

    # =========================================================================
    # Source 4: NVD CVE Description Parsing
    # =========================================================================

    def parse_nvd_descriptions(self):
        """Extract com_ and mod_ names from CVE descriptions already in the database."""
        self.log("\n[*] Source 4: NVD CVE Description Parsing")
        self.log("[*] Scanning CVE descriptions for component and module names...")

        # Query all CVE descriptions from DB
        rows = self.db.fetch_all(
            "SELECT cve_id, description FROM joomla_core_cves WHERE description IS NOT NULL"
        )
        rows += self.db.fetch_all(
            "SELECT cve_id, description FROM joomla_component_cves WHERE description IS NOT NULL"
        )

        if not rows:
            self.log("[!] No CVEs in database. Run 'python cli.py update' first to populate CVE data.")

        component_names = set()
        module_names = set()
        com_pattern = re.compile(r"\bcom_([a-zA-Z0-9_]+)\b")
        mod_pattern = re.compile(r"\bmod_([a-zA-Z0-9_]+)\b")

        for row in rows:
            description = row[1] or ""
            for match in com_pattern.findall(description):
                component_names.add(f"com_{match.lower()}")
            for match in mod_pattern.findall(description):
                module_names.add(f"mod_{match.lower()}")

        # Store components
        for slug in sorted(component_names):
            if slug in self.components:
                self.components[slug]["has_known_cves"] = True
            else:
                display_name = slug.replace("com_", "").replace("_", " ").title()
                self.components[slug] = {
                    "slug": slug,
                    "slug_aliases": [],
                    "display_name": display_name,
                    "vendor": "",
                    "category": "",
                    "tags": [],
                    "is_core": False,
                    "joomla_versions": [],
                    "source": "nvd_cve_description",
                    "jed_url": None,
                    "jed_id": None,
                    "license_type": "",
                    "has_module": False,
                    "has_plugin": False,
                    "vel_status": None,
                    "has_known_cves": True,
                    "popularity_score": 0,
                    "num_reviews": 0,
                }

        # Store modules
        for slug in sorted(module_names):
            if slug in self.components:
                self.components[slug]["has_known_cves"] = True
            else:
                display_name = slug.replace("mod_", "").replace("_", " ").title()
                self.components[slug] = {
                    "slug": slug,
                    "slug_aliases": [],
                    "display_name": display_name,
                    "vendor": "",
                    "category": "",
                    "tags": [],
                    "is_core": False,
                    "joomla_versions": [],
                    "source": "nvd_cve_description",
                    "jed_url": None,
                    "jed_id": None,
                    "license_type": "",
                    "has_module": True,
                    "has_plugin": False,
                    "vel_status": None,
                    "has_known_cves": True,
                    "popularity_score": 0,
                    "num_reviews": 0,
                }

        self.log(f"[+] CVE Descriptions: {len(component_names)} components, {len(module_names)} modules extracted")
        return len(component_names)

    # =========================================================================
    # Source 5: JED Vulnerable Extensions List (VEL)
    # =========================================================================

    def scrape_jed_vel(self):
        """Scrape the JED Vulnerable Extensions List pages."""
        self.log("\n[*] Source 5: JED Vulnerable Extensions List (VEL)")

        total_found = 0

        for status, url in self.VEL_URLS.items():
            self.log(f"[*] Fetching VEL ({status}): {url}")

            try:
                found = self._scrape_vel_page(url, status)
                total_found += found
                self.log(f"    Found {found} {status} extensions")
                time.sleep(2)  # Be respectful
            except Exception as e:
                self.log(f"[!] VEL scrape error ({status}): {e}")

        self.log(f"[+] VEL: {total_found} total extensions tracked")
        return total_found

    def _scrape_vel_page(self, url, vel_status):
        """Scrape a single VEL page for extension names."""
        found = 0
        start = 0

        while True:
            page_url = f"{url}?start={start}" if start > 0 else url

            try:
                resp = self.session.get(page_url, timeout=15)
                if resp.status_code != 200:
                    break

                try:
                    soup = BeautifulSoup(resp.text, "lxml")
                except Exception:
                    soup = BeautifulSoup(resp.text, "html.parser")

                # VEL uses a single table with rows: "Title, version, vuln_type" | "Published Date"
                table = soup.find("table")
                if not table:
                    break

                rows = table.find_all("tr")
                data_rows = 0

                for row in rows:
                    cells = row.find_all("td")
                    if not cells:
                        continue  # skip header (th)

                    data_rows += 1
                    raw_text = cells[0].get_text(strip=True)
                    if not raw_text:
                        continue

                    # Format: "ExtensionName, version, VulnType"
                    # Extract the extension name (first part before first comma)
                    parts = [p.strip() for p in raw_text.split(",")]
                    ext_name = parts[0] if parts else raw_text

                    # Clean up common suffixes
                    ext_name = re.sub(
                        r"\s+(?:by\s+\w+.*|via\s+.*)$", "", ext_name, flags=re.IGNORECASE
                    ).strip()

                    if ext_name and ext_name.lower() not in ("title", "extension", "name", ""):
                        self._add_vel_extension(ext_name, vel_status)
                        found += 1

                if data_rows == 0:
                    break

                # Check for next page: find the last pagination link for max start value
                pagination_links = soup.select(".pagination a")
                max_start = 0
                for link in pagination_links:
                    href = link.get("href", "")
                    match = re.search(r"start=(\d+)", href)
                    if match:
                        val = int(match.group(1))
                        if val > max_start:
                            max_start = val

                start += 10  # VEL pages use 10 items per page
                if start > max_start:
                    break

                time.sleep(2)

            except Exception as e:
                self.log(f"[!] Error at start={start}: {e}")
                break

        return found

    def _add_vel_extension(self, name, vel_status):
        """Add a VEL extension by display name."""
        slugs = self._generate_slugs(name)
        if slugs:
            for slug in slugs:
                if slug in self.components:
                    self.components[slug]["vel_status"] = vel_status
                    self.components[slug]["has_known_cves"] = True
                else:
                    self.components[slug] = {
                        "slug": slug,
                        "slug_aliases": slugs[1:] if slug == slugs[0] else [],
                        "display_name": name,
                        "vendor": "",
                        "category": "",
                        "tags": [],
                        "is_core": False,
                        "joomla_versions": [],
                        "source": "jed_vel",
                        "jed_url": None,
                        "jed_id": None,
                        "license_type": "",
                        "has_module": False,
                        "has_plugin": False,
                        "vel_status": vel_status,
                        "has_known_cves": True,
                        "popularity_score": 0,
                        "num_reviews": 0,
                    }
                    break  # Only store primary slug

    def _add_vel_extension_by_slug(self, slug, vel_status):
        """Add a VEL extension by com_ slug."""
        if slug in self.components:
            self.components[slug]["vel_status"] = vel_status
            self.components[slug]["has_known_cves"] = True
        else:
            display_name = slug.replace("com_", "").replace("_", " ").title()
            self.components[slug] = {
                "slug": slug,
                "slug_aliases": [],
                "display_name": display_name,
                "vendor": "",
                "category": "",
                "tags": [],
                "is_core": False,
                "joomla_versions": [],
                "source": "jed_vel",
                "jed_url": None,
                "jed_id": None,
                "license_type": "",
                "has_module": False,
                "has_plugin": False,
                "vel_status": vel_status,
                "has_known_cves": True,
                "popularity_score": 0,
                "num_reviews": 0,
            }

    # =========================================================================
    # Merge & Export
    # =========================================================================

    def merge_all_sources(self):
        """
        Run all scrapers and merge results.
        Order matters: later sources enrich earlier data.
        """
        self.log("=" * 60)
        self.log("JoomlaScanner - Component Database Update")
        self.log("=" * 60)

        start_time = time.time()

        # Source 1: JED Algolia (largest dataset)
        jed_count = self.scrape_jed_algolia()

        # Source 2: GitHub core components
        github_count = self.scrape_github_core()

        # Source 3: NVD CPEs
        nvd_cpe_count = self.scrape_nvd_cpes()

        # Source 4: CVE description parsing
        cve_desc_count = self.parse_nvd_descriptions()

        # Source 5: VEL
        vel_count = self.scrape_jed_vel()

        elapsed = time.time() - start_time

        # Count components vs modules
        com_count = sum(1 for k in self.components if k.startswith("com_"))
        mod_count = sum(1 for k in self.components if k.startswith("mod_"))

        self.log("\n" + "=" * 60)
        self.log("Summary")
        self.log("=" * 60)
        self.log(f"  JED Algolia:        {jed_count} extensions")
        self.log(f"  GitHub Core:        {github_count} components")
        self.log(f"  NVD CPE:            {nvd_cpe_count} components")
        self.log(f"  CVE Descriptions:   {cve_desc_count} components")
        self.log(f"  VEL:                {vel_count} extensions")
        self.log(f"  ---")
        self.log(f"  Total unique slugs: {len(self.components)}")
        self.log(f"    Components (com_): {com_count}")
        self.log(f"    Modules (mod_):    {mod_count}")
        self.log(f"  Time elapsed:       {elapsed:.1f}s")

        return self.components

    def merge_source(self, source):
        """Run a single source scraper."""
        source_map = {
            "jed": self.scrape_jed_algolia,
            "github": self.scrape_github_core,
            "nvd": self.scrape_nvd_cpes,
            "cve": self.parse_nvd_descriptions,
            "vel": self.scrape_jed_vel,
        }

        if source not in source_map:
            self.log(f"[!] Unknown source: {source}. Available: {', '.join(source_map.keys())}")
            return {}

        source_map[source]()
        return self.components

    def export_components_json(self, output_path=None):
        """Export components to the new rich JSON format."""
        if output_path is None:
            output_path = Path(__file__).parent.parent / "data" / "components.json"

        # Filter: only com_ entries
        com_entries = {
            k: v for k, v in self.components.items() if k.startswith("com_")
        }

        # Sort: core first, then by popularity, then alphabetical
        sorted_components = sorted(
            com_entries.values(),
            key=lambda c: (
                not c.get("is_core", False),
                -c.get("popularity_score", 0),
                c.get("slug", ""),
            ),
        )

        # Deduplicate (some aliases may point to same component)
        seen_slugs = set()
        unique_components = []
        for comp in sorted_components:
            slug = comp["slug"]
            if slug not in seen_slugs:
                seen_slugs.add(slug)
                unique_components.append(comp)

        output = {
            "metadata": {
                "last_updated": datetime.now().isoformat(),
                "total_components": len(unique_components),
                "total_core": sum(1 for c in unique_components if c.get("is_core")),
                "total_with_cves": sum(
                    1 for c in unique_components if c.get("has_known_cves")
                ),
                "total_vel_vulnerable": sum(
                    1 for c in unique_components if c.get("vel_status") == "vulnerable"
                ),
                "sources": [
                    "jed_algolia",
                    "github_core",
                    "nvd_cpe",
                    "nvd_cve_description",
                    "jed_vel",
                ],
            },
            "components": unique_components,
        }

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2, default=str)

        self.log(f"\n[+] Exported {len(unique_components)} components to {output_path}")

        return len(unique_components)

    def export_to_database(self):
        """Also store components in the SQLite database."""
        count = 0

        for slug, comp in self.components.items():
            if not slug.startswith("com_"):
                continue

            self.db.add_component(
                component_name=slug,
                display_name=comp.get("display_name"),
                vendor_name=comp.get("vendor"),
                category=comp.get("category"),
                source=comp.get("source"),
            )
            count += 1

        self.db.set_last_cve_update(datetime.now().strftime("%Y-%m-%d"))
        self.log(f"[+] Stored {count} components in database")
        return count

    def export_modules_json(self, output_path=None):
        """Export modules to a rich JSON format (mirrors export_components_json)."""
        if output_path is None:
            output_path = Path(__file__).parent.parent / "data" / "modules.json"

        # Filter: only mod_ entries
        mod_entries = {
            k: v for k, v in self.components.items() if k.startswith("mod_")
        }

        # Sort: core first, then by popularity, then alphabetical
        sorted_modules = sorted(
            mod_entries.values(),
            key=lambda m: (
                not m.get("is_core", False),
                -m.get("popularity_score", 0),
                m.get("slug", ""),
            ),
        )

        # Deduplicate
        seen_slugs = set()
        unique_modules = []
        for mod in sorted_modules:
            slug = mod["slug"]
            if slug not in seen_slugs:
                seen_slugs.add(slug)
                unique_modules.append(mod)

        output = {
            "metadata": {
                "last_updated": datetime.now().isoformat(),
                "total_modules": len(unique_modules),
                "total_core": sum(1 for m in unique_modules if m.get("is_core")),
                "total_with_cves": sum(
                    1 for m in unique_modules if m.get("has_known_cves")
                ),
                "sources": [
                    "jed_algolia",
                    "github_core",
                    "nvd_cve_description",
                ],
            },
            "modules": unique_modules,
        }

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2, default=str)

        self.log(f"[+] Exported {len(unique_modules)} modules to {output_path}")

        return len(unique_modules)

    def export_modules_to_database(self):
        """Store modules in the SQLite database."""
        count = 0

        for slug, mod in self.components.items():
            if not slug.startswith("mod_"):
                continue

            self.db.add_module(
                module_name=slug,
                display_name=mod.get("display_name"),
                vendor_name=mod.get("vendor"),
                category=mod.get("category"),
                source=mod.get("source"),
            )
            count += 1

        self.log(f"[+] Stored {count} modules in database")
        return count

    # =========================================================================
    # Quick update (JED Algolia only + existing data merge)
    # =========================================================================

    def quick_update(self):
        """Quick update: JED Algolia + GitHub core only."""
        self.log("=" * 60)
        self.log("JoomlaScanner - Quick Component Update")
        self.log("=" * 60)

        start_time = time.time()

        self.scrape_jed_algolia()
        self.scrape_github_core()

        elapsed = time.time() - start_time

        self.log(f"\n[+] Quick update complete: {len(self.components)} components in {elapsed:.1f}s")

        return self.components


def update_all_components(verbose=True):
    """Convenience function: full update from all sources."""
    scraper = ComponentScraper(verbose=verbose)
    scraper.merge_all_sources()
    scraper.export_components_json()
    scraper.export_to_database()
    scraper.export_modules_json()
    scraper.export_modules_to_database()
    return len(scraper.components)


def update_components_from_source(source, verbose=True):
    """Update from a specific source only."""
    scraper = ComponentScraper(verbose=verbose)
    scraper.merge_source(source)
    scraper.export_components_json()
    scraper.export_to_database()
    scraper.export_modules_json()
    scraper.export_modules_to_database()
    return len(scraper.components)


if __name__ == "__main__":
    print("JoomlaScanner Component Scraper")
    print("=" * 40)

    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        scraper = ComponentScraper()
        scraper.quick_update()
        scraper.export_components_json()
        scraper.export_to_database()
        scraper.export_modules_json()
        scraper.export_modules_to_database()
    else:
        update_all_components()

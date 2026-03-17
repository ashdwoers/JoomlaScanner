import warnings

warnings.filterwarnings("ignore")
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass

import requests
import re
import json
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from pathlib import Path
from scanner.db import Database


class ProgressIndicator:
    def __init__(self, total, prefix="Progress"):
        self.total = total
        self.current = 0
        self.prefix = prefix
        self.start_time = time.time()
        self.spinners = ["|", "/", "-", "\\"]
        self.spin_idx = 0
        self._lock = threading.Lock()

    def update(self, count=1):
        with self._lock:
            self.current += count

    def get_progress(self):
        with self._lock:
            current = self.current

        percent = (current / self.total * 100) if self.total > 0 else 0
        elapsed = time.time() - self.start_time
        rate = current / elapsed if elapsed > 0 else 0
        remaining = (self.total - current) / rate if rate > 0 else 0

        bar_width = 20
        filled = int(bar_width * current / self.total) if self.total > 0 else 0
        bar = "=" * filled + "-" * (bar_width - filled)

        spinner = self.spinners[self.spin_idx % len(self.spinners)]
        self.spin_idx += 1

        return f"\r{self.prefix}: [{bar}] {percent:.1f}% ({current}/{self.total}) {spinner} ETA:{remaining:.0f}s"

    def finish(self):
        elapsed = time.time() - self.start_time
        return f"[*] {self.prefix}: Complete! {self.current} items checked in {elapsed:.1f}s"


class ComponentEnumerator:
    CORE_COMPONENTS = [
        "com_content",
        "com_users",
        "com_media",
        "com_modules",
        "com_plugins",
        "com_templates",
        "com_menus",
        "com_messages",
        "com_categories",
        "com_contact",
        "com_newsfeeds",
        "com_weblinks",
        "com_banners",
        "com_search",
        "com_redirect",
        "com_joomlaupdate",
        "com_installer",
        "com_config",
        "com_login",
        "com_cache",
        "com_cpanel",
        "com_admin",
        "com_frontpage",
        "com_languages",
        "com_checkin",
        "com_ajax",
        "com_privacy",
        "com_actionlogs",
        "com_workflow",
        "com_fields",
        "com_associations",
        "com_guidedtours",
        "com_phonet",
    ]

    POPULAR_COMPONENTS = [
        "com_akeeba",
        "com_k2",
        "com_jce",
        "com_phocagallery",
        "com_phocadownload",
        "com_rsform",
        "com_chronoforms",
        "com_flexicontent",
        "com_sobipro",
        "com_easydiscuss",
        "com_kunena",
        "com_comprofiler",
        "com_community",
        "com_jomsocial",
        "com_jevents",
        "com_virtuemart",
        "com_hikashop",
        "com_osmap",
        "com_fabrik",
        "com_zoo",
        "com_jcomments",
        "com_jomcomment",
        "com_komento",
        "com_t3",
        "com_xtc",
        "com_sppagebuilder",
        "com_jshopping",
        "com_jdownloads",
        "com_docman",
        "com_dropfiles",
        "com_roksprocket",
        "com_mtree",
        "com_sef",
        "com_myblog",
        "com_myjspace",
        "com_eventlist",
        "com_jcalpro",
        "com_youtubegallery",
        "com_yootheme",
        "com_wordpress",
        "com_realestatemanager",
        "com_iproperty",
        "com_osproperty",
        "com_hotproperty",
        "com_djclassifieds",
        "com_djcatalog",
        "com_eventbooking",
        "com_hwdmediashare",
        "com_igallery",
        "com_bt_portfolio",
        "com_bt_slideshow",
        "com_gallery",
    ]

    COMMON_COMPONENTS = [
        "com_content",
        "com_users",
        "com_media",
        "com_modules",
        "com_plugins",
        "com_templates",
        "com_menus",
        "com_messages",
        "com_categories",
        "com_contact",
        "com_newsfeeds",
        "com_weblinks",
        "com_banners",
        "com_search",
        "com_redirect",
        "com_akneo",
        "com_akeeba",
        "com_k2",
        "com_jce",
        "com_jreformed",
        "com_phocagallery",
        "com_phocadownload",
        "com_phocamaps",
        "com_phoca",
        "com_youtubegallery",
        "com_rsform",
        "com_chronoforms",
        "com_flexicontent",
        "com_sobipro",
        "com_easyblog",
        "com_kunena",
        "com_comprofiler",
        "com_community",
        "com_jomsocial",
        "com_jevents",
        "com_eventlist",
        "com_jcalpro",
        "com_ice",
        "com_myjspace",
        "com_jdownloads",
        "com_docman",
        "com_dropfiles",
        "com_spidercalendar",
        "com_socialbacklinks",
        "com_jomcomment",
        "com_komento",
        "com_jcomments",
        "com_ztslideshow",
        "com_roksprocket",
        "com_t3",
        "com_xtc",
        "com_virtuemart",
        "com_hikashop",
        "com_redshop",
        "com_phocacart",
        "com_osmap",
        "com_xmap",
        "com_jmap",
        "com_allies",
        "com_alikonuser",
        "com_apacity",
        "com_bt_portfolio",
        "com_bt_slideshow",
        "com_civicrm",
        "com_cockpit",
        "com_contenido",
        "com_datos",
        "com_easydiscuss",
        "com_fabrik",
        "com_faqbookpro",
        "com_fields",
        "com_flexi",
        "com_google",
        "com_hwdmediashare",
        "com_igallery",
        "com_installer",
        "com_jablogs",
        "com_janalytics",
        "com_jbackup",
        "com_jbusinessdirectory",
        "com_jce",
        "com_jchromestyle",
        "com_jclass",
        "com_jdirectory",
        "com_jfleet",
        "com_jfood",
        "com_jhotelreservation",
        "com_jjobs",
        "com_jmap",
        "com_jms",
        "com_jmulticat",
        "com_jnews",
        "com_joptimise",
        "com_jp",
        "com_jpayplans",
        "com_jphoto",
        "com_jplayer",
        "com_jquery",
        "com_jreviews",
        "com_jsjobs",
        "com_jshopping",
        "com_jsm",
        "com_jtag",
        "com_jticketing",
        "com_jvehiclemanager",
        "com_jwhmcs",
        "com_jwl",
        "com_k2store",
        "com_kunena",
        "com_layer_slider",
        "com_leaguemanager",
        "com_magic",
        "com_mailster",
        "com_mijopolls",
        "com_mijoshop",
        "com_mlm",
        "com_mobilize",
        "com_moo_zoo",
        "com_mtree",
        "com_mv",
        "com_myblog",
        "com_myjspace",
        "com_ninjarss",
        "com_obgrabber",
        "com_osclass",
        "com_osproperty",
        "com_osrs",
        "com_payplans",
        "com_paypal",
        "com_php",
        "com_phpcon",
        "com_pitchpublish",
        "com_playlist",
        "com_plotalot",
        "com_pm",
        "com_polaroid",
        "com_portfolio",
        "com_pricelist",
        "com_profiles",
        "com_projectfork",
        "com_qa",
        "com_quicklogon",
        "com_remository",
        "com_resman",
        "com_sef",
        "com_seminar",
        "com_sendcard",
        "com_shop",
        "com_simplegallery",
        "com_simplelists",
        "com_sitemap",
        "com_slogin",
        "com_smartsection",
        "com_sobipro",
        "com_social",
        "com_socialconnect",
        "com_socialize",
        "com_spambotcheck",
        "com_sppagebuilder",
        "com_stackideas",
        "com_streams",
        "com_super",
        "com_tabber",
        "com_tag",
        "com_taxonomy",
        "com_team",
        "com_templates",
        "com_timeline",
        "com_tmbox",
        "com_uddeim",
        "com_uquick",
        "com_vj",
        "com_vme",
        "com_vm",
        "com_weather",
        "com_webmaster",
        "com_weblinks",
        "com_wizard",
        "com_woothemes",
        "com_wrapper",
        "com_xcloner",
        "com_yendif",
        "com_youtubes",
        "com_zengrid",
        "com_z enf",
        "com_zoo",
        "com_ninja",
    ]

    def __init__(self, target_url, db=None, timeout=10, threads=10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.db = db or Database()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "JoomlaScanner/1.0"})
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads, pool_maxsize=threads,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.detected_components = []
        self._results_lock = threading.Lock()

    def _check_component_worker(self, component, joomla_version):
        """Worker function for threaded enumeration."""
        is_core = component in self.CORE_COMPONENTS

        if is_core and joomla_version:
            version = joomla_version
        else:
            version = self._check_component(component)

        if version:
            return {
                "name": component,
                "version": version,
                "is_core": is_core,
                "is_vulnerable": False,
                "cves": [],
            }
        return None

    def enumerate_components(
        self, component_list=None, verbose=True, quick_scan=True, joomla_version=None
    ):
        if quick_scan and component_list is None:
            component_list = self._load_popular_components()
        elif component_list is None:
            component_list = self._load_components()

        if verbose:
            print(f"[*] Enumerating {len(component_list)} components ({self.threads} threads)...")

        progress = ProgressIndicator(len(component_list), "Components")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_component_worker, comp, joomla_version): comp
                for comp in component_list
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self._results_lock:
                        self.detected_components.append(result)

                progress.update()
                if verbose and sys.stdout.isatty():
                    sys.stdout.write(progress.get_progress())
                    sys.stdout.flush()

        if verbose:
            if sys.stdout.isatty():
                sys.stdout.write("\r" + " " * 80 + "\r")
                sys.stdout.flush()
            print(progress.finish())
            for comp in self.detected_components:
                core_tag = " [CORE]" if comp["is_core"] else ""
                print(f"    [+] Found: {comp['name']} (version: {comp['version']}){core_tag}")
            print(f"[+] Total components found: {len(self.detected_components)}")

        return self.detected_components

    def _load_popular_components(self):
        """Load prioritized components: those with known CVEs + high popularity."""
        json_path = Path(__file__).parent.parent / "data" / "components.json"

        if json_path.exists():
            try:
                with open(json_path, "r") as f:
                    data = json.load(f)

                if isinstance(data, dict) and "components" in data:
                    # Prioritize: core + has_known_cves + VEL + top popular
                    prioritized = []
                    for comp in data["components"]:
                        slug = comp.get("slug", "")
                        if not slug.startswith("com_"):
                            continue
                        is_core = comp.get("is_core", False)
                        has_cves = comp.get("has_known_cves", False)
                        score = comp.get("popularity_score", 0)
                        vel = comp.get("vel_status")

                        # Include in quick scan if: core, has CVEs, VEL listed, or top popular
                        if is_core or has_cves or vel or score >= 10000:
                            prioritized.append(slug)

                    if prioritized:
                        return prioritized
            except:
                pass

        # Fallback to hardcoded popular list
        return self.POPULAR_COMPONENTS

    def _load_components(self):
        json_path = Path(__file__).parent.parent / "data" / "components.json"

        if json_path.exists():
            try:
                with open(json_path, "r") as f:
                    data = json.load(f)

                # Support new rich format
                if isinstance(data, dict) and "components" in data:
                    components = []
                    for comp in data["components"]:
                        slug = comp.get("slug", "")
                        if slug.startswith("com_"):
                            components.append(slug)
                            # Also add aliases for probing
                            for alias in comp.get("slug_aliases", []):
                                if alias.startswith("com_") and alias not in components:
                                    components.append(alias)
                    return components

                # Legacy flat array format
                if isinstance(data, list):
                    return data
            except:
                pass

        db_components = self.db.get_all_components()
        if db_components:
            return [c[0] for c in db_components]

        return self.COMMON_COMPONENTS

    def _check_component(self, component_name):
        xml_paths = [
            f"/administrator/components/{component_name}/{component_name}.xml",
            f"/administrator/components/{component_name}/manifest.xml",
            f"/components/{component_name}/{component_name}.xml",
            f"/components/{component_name}/manifest.xml",
        ]

        for xml_path in xml_paths:
            version = self._get_version_from_xml(xml_path)
            if version:
                return version

        simple_path = f"/components/{component_name}/"
        response = self._make_request(simple_path)
        if response and response.status_code == 200:
            version = self._get_version_from_readme(simple_path)
            if version:
                return version
            return "unknown"

        return None

    def _make_request(self, path):
        url = urljoin(self.target_url + "/", path.lstrip("/"))
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            return response
        except:
            return None

    def _get_version_from_xml(self, path):
        response = self._make_request(path)
        if not response or response.status_code != 200:
            return None

        content = response.text

        version_patterns = [
            r"<version>(\d+\.[\d.]+)</version>",
            r"<version>([^<]+)</version>",
            r'version["\s]*[:=]\s*["\']?(\d+\.[\d.]+)',
            r'<param name="version"[^>]*>([^<]+)</param>',
            r"<releaseVersion>([^<]+)</releaseVersion>",
            r"version['\"]?\s*[:=]\s*['\"]?(\d+\.[\d.]+)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                if version and version != "0":
                    return version

        return None

    def _get_version_from_readme(self, base_path):
        readme_files = [
            "README.txt",
            "readme.txt",
            "CHANGELOG.txt",
            "changelog.txt",
            "HISTORY.txt",
            "history.txt",
            "VERSION.txt",
            "version.txt",
            "manifest.xml",
            "config.xml",
        ]

        for readme in readme_files:
            path = base_path.rstrip("/") + "/" + readme
            response = self._make_request(path)

            if response and response.status_code == 200:
                content = response.text

                version_patterns = [
                    r"(?:Version|v)[:\s]*(\d+\.[\d.]+)",
                    r"(\d+\.\d+\.\d+)",
                    r"v(\d+\.\d+\.\d+)",
                    r"release\s+(\d+\.\d+)",
                ]

                for pattern in version_patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        return match.group(1)

        return None

    def get_result(self):
        return {
            "target": self.target_url,
            "components": self.detected_components,
            "total_found": len(self.detected_components),
        }


def enumerate_joomla_components(target_url, verbose=True):
    enumerator = ComponentEnumerator(target_url)
    return enumerator.enumerate_components(verbose=verbose)


class ModuleEnumerator:
    POPULAR_MODULES = [
        "mod_menu",
        "mod_login",
        "mod_search",
        "mod_breadcrumbs",
        "mod_articles_archive",
        "mod_articles_latest",
        "mod_articles_popular",
        "mod_articles_category",
        "mod_articles_news",
        "mod_articles_slideshow",
        "mod_banners",
        "mod_custom",
        "mod_feed",
        "mod_footer",
        "mod_wrapper",
        "mod_whosonline",
        "mod_stats",
        "mod_syndicate",
        "mod_users_latest",
        "mod_vvisitcounter",
        "mod_roksprocket",
        "mod_jevents_cal",
        "mod_jevents_filter",
        "mod_maximenuck",
        "mod_uber_navigation",
        "mod_youcefslideshow",
        "mod_t3_menu",
        "mod_xt_menu",
        "mod_responsive_menu",
        "mod_mobilemenuck",
        "mod_superfish_menu",
        "mod_megamenu",
        "mod_vertical_mega_menu",
        "mod_ice_slider",
        "mod_ice_carousel",
        "mod_bt_contentslider",
        "mod_bt_googlemaps",
        "mod_djimageslider",
        "mod_djtabsslider",
        "mod_phoca_gallery",
        "mod_phocadownload",
        "mod_phocamaps_marker",
        "mod_k2_content",
        "mod_k2_tools",
        "mod_k2_comments",
        "mod_k2_user",
        "mod_ak_shopping_cart",
        "mod_akproduct",
        "mod_virtuemart_cart",
        "mod_virtuemart_product",
        "mod_hikashop_cart",
        "mod_hikashop_product",
        "mod_yoo_gallery",
        "mod_yoo_slider",
        "mod_yoo_photo_gallery",
        "mod_flexi_contact",
        "mod_flexi_advert",
        "mod_flexi_content",
        "mod_chronoforms",
        "mod_rsform",
        "mod_breezingforms",
        "mod_corporate_calendar",
        "mod_eventlist",
        "mod_jevents",
        "mod_community",
        "mod_kunena",
        "mod_community_activities",
        "mod_social_login",
        "mod_social_stream",
        "mod_social_share",
    ]

    def __init__(self, target_url, db=None, timeout=10, threads=10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.db = db or Database()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "JoomlaScanner/1.0"})
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads, pool_maxsize=threads,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.detected_modules = []
        self._results_lock = threading.Lock()

    def _check_module_worker(self, module):
        """Worker function for threaded enumeration."""
        version = self._check_module(module)
        if version:
            return {
                "name": module,
                "type": "module",
                "version": version,
                "is_vulnerable": False,
                "cves": [],
            }
        return None

    def enumerate_modules(self, module_list=None, verbose=True, quick_scan=True):
        if quick_scan and module_list is None:
            module_list = self._load_popular_modules()
        elif module_list is None:
            module_list = self._load_modules()

        if verbose:
            print(f"[*] Enumerating {len(module_list)} modules ({self.threads} threads)...")

        progress = ProgressIndicator(len(module_list), "Modules")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_module_worker, mod): mod
                for mod in module_list
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self._results_lock:
                        self.detected_modules.append(result)

                progress.update()
                if verbose and sys.stdout.isatty():
                    sys.stdout.write(progress.get_progress())
                    sys.stdout.flush()

        if verbose:
            if sys.stdout.isatty():
                sys.stdout.write("\r" + " " * 80 + "\r")
                sys.stdout.flush()
            print(progress.finish())
            for mod in self.detected_modules:
                print(f"    [+] Found: {mod['name']} (version: {mod['version']})")
            print(f"[+] Total modules found: {len(self.detected_modules)}")

        return self.detected_modules

    def _load_popular_modules(self):
        """Load prioritized modules: those with known CVEs + high popularity."""
        json_path = Path(__file__).parent.parent / "data" / "modules.json"

        if json_path.exists():
            try:
                with open(json_path, "r") as f:
                    data = json.load(f)

                if isinstance(data, dict) and "modules" in data:
                    prioritized = []
                    for mod in data["modules"]:
                        slug = mod.get("slug", "")
                        if not slug.startswith("mod_"):
                            continue
                        is_core = mod.get("is_core", False)
                        has_cves = mod.get("has_known_cves", False)
                        score = mod.get("popularity_score", 0)

                        if is_core or has_cves or score >= 10000:
                            prioritized.append(slug)

                    if prioritized:
                        return prioritized
            except:
                pass

        return self.POPULAR_MODULES

    def _load_modules(self):
        """Load all modules from modules.json, falling back to DB, then hardcoded list."""
        json_path = Path(__file__).parent.parent / "data" / "modules.json"

        if json_path.exists():
            try:
                with open(json_path, "r") as f:
                    data = json.load(f)

                if isinstance(data, dict) and "modules" in data:
                    modules = []
                    for mod in data["modules"]:
                        slug = mod.get("slug", "")
                        if slug.startswith("mod_"):
                            modules.append(slug)
                    if modules:
                        return modules
            except:
                pass

        db_modules = self.db.get_all_modules()
        if db_modules:
            return [m[0] for m in db_modules]

        return self.POPULAR_MODULES

    def _check_module(self, module_name):
        xml_paths = [
            f"/modules/{module_name}/{module_name}.xml",
            f"/modules/{module_name}/mod_{module_name.replace('mod_', '')}.xml",
            f"/administrator/modules/{module_name}/{module_name}.xml",
        ]

        for xml_path in xml_paths:
            version = self._get_version_from_xml(xml_path)
            if version:
                return version

        simple_path = f"/modules/{module_name}/"
        response = self._make_request(simple_path)
        if response and response.status_code == 200:
            return "unknown"

        return None

    def _make_request(self, path):
        url = urljoin(self.target_url + "/", path.lstrip("/"))
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            return response
        except:
            return None

    def _get_version_from_xml(self, path):
        response = self._make_request(path)
        if not response or response.status_code != 200:
            return None

        content = response.text
        version_patterns = [
            r"<version>(\d+[\d.]+)</version>",
            r"<version>([^<]+)</version>",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)

        return None


if __name__ == "__main__":
    import sys
    import time

    if len(sys.argv) < 2:
        print("Usage: python component.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    start = time.time()
    components = enumerate_joomla_components(target)
    elapsed = time.time() - start

    print(f"\nFound {len(components)} components in {elapsed:.2f}s")
    for comp in components[:10]:
        print(f"  - {comp['name']}: {comp['version']}")

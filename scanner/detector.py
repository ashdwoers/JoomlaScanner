import warnings

warnings.filterwarnings("ignore")
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time


class VersionDetector:
    VERSION_PATTERNS = {
        "joomla_xml": [
            "/administrator/manifests/files/joomla.xml",
            "/language/en-GB/en-GB.xml",
            "/administrator/components/com_content/content.xml",
        ],
        "generator_header": None,
        "readme": [
            "/README.txt",
            "/readme.txt",
            "/README.md",
        ],
    }

    FINGERPRINTS = {
        "1.0": [
            "Mambo 4.5",
            "joomla.org",
        ],
        "1.5": [
            "Joomla! 1.5",
        ],
        "1.6": [
            "system.css 20196",
            'MooTools.More={version:"1.3.0.1"',
        ],
        "1.7": [
            'MooTools.More={version:"1.3.2.1"',
        ],
        "2.5": [
            "2005-2012",
        ],
        "3.0": [
            "jQuery",
            "bootstrap.min.css",
            "media/jui",
        ],
        "3.5": [
            'jQuery("',
            "jQuery.cookie",
        ],
        "3.8": [
            " Joomla 3.8",
        ],
        "3.9": [
            "joomla 3.9",
            "3.9.",
        ],
        "3.10": [
            "joomla 3.10",
            "3.10.",
        ],
        "4.0": [
            "Joomla 4",
            "joomla 4",
            "T3 Framework",
            "Bootstrap 5",
            "Tailwind",
            '"joomla": "4.',
        ],
        "4.1": [
            "Joomla 4.1",
            "joomla 4.1",
        ],
        "4.2": [
            "Joomla 4.2",
            "joomla 4.2",
        ],
        "4.3": [
            "Joomla 4.3",
            "joomla 4.3",
        ],
        "4.4": [
            "Joomla 4.4",
            "joomla 4.4",
        ],
        "5.0": [
            "Joomla 5",
            "joomla 5",
            '"joomla": "5.',
        ],
        "5.1": [
            "Joomla 5.1",
            "joomla 5.1",
        ],
    }

    def __init__(self, target_url, timeout=10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "JoomlaScanner/1.0"})
        self.detected_version = None
        self.detection_method = None
        self.confidence = "low"

    def detect(self, verbose=True):
        methods = [
            ("xml_file", self._detect_from_xml),
            ("generator_header", self._detect_from_generator),
            ("readme", self._detect_from_readme),
            ("fingerprint", self._detect_from_fingerprint),
        ]

        for method_name, method_func in methods:
            if verbose:
                print(f"[*] Trying {method_name} detection...")

            version = method_func()
            if version:
                self.detected_version = version
                self.detection_method = method_name
                self.confidence = (
                    "high"
                    if method_name in ["xml_file", "generator_header"]
                    else "medium"
                )

                if verbose:
                    print(
                        f"[+] Joomla version detected: {version} (method: {method_name})"
                    )
                return version

        if verbose:
            print("[!] Could not detect Joomla version")
        return None

    def _make_request(self, path):
        url = urljoin(self.target_url + "/", path.lstrip("/"))
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            return response
        except:
            return None

    def _detect_from_generator(self):
        response = self._make_request("/")
        if not response:
            return None

        generator = response.headers.get("X-Meta-Generator") or response.headers.get(
            "Generator"
        )

        if generator:
            match = re.search(
                r"Joomla!?\s*(\d+\.\d+(?:\.\d+)?)", generator, re.IGNORECASE
            )
            if match:
                return match.group(1)

        soup = BeautifulSoup(response.text, "html.parser")
        meta_generator = soup.find("meta", attrs={"name": "generator"})

        if meta_generator:
            content = meta_generator.get("content", "")
            match = re.search(
                r"Joomla!?\s*(\d+\.\d+(?:\.\d+)?)", content, re.IGNORECASE
            )
            if match:
                return match.group(1)

        return None

    def _detect_from_xml(self):
        xml_paths = [
            "/administrator/manifests/files/joomla.xml",
            "/language/en-GB/en-GB.xml",
            "/administrator/components/com_content/content.xml",
        ]

        for path in xml_paths:
            response = self._make_request(path)
            if not response or response.status_code != 200:
                continue

            content = response.text

            version_match = re.search(
                r"<version>(\d+\.\d+(?:\.\d+)?)</version>", content
            )
            if version_match:
                return version_match.group(1)

            name_match = re.search(
                r"<name>Joomla!?\s*(\d+\.\d+(?:\.\d+)?)</name>", content, re.IGNORECASE
            )
            if name_match:
                return name_match.group(1)

        return None

    def _detect_from_readme(self):
        readme_paths = [
            "/README.txt",
            "/readme.txt",
            "/README.md",
            "/administrator/README.php",
        ]

        for path in readme_paths:
            response = self._make_request(path)
            if not response or response.status_code != 200:
                continue

            content = response.text

            match = re.search(
                r"(?:Joomla!?\s*)?(?:Version|version)[:\s]*(\d+\.\d+(?:\.\d+)?)",
                content,
                re.IGNORECASE,
            )
            if match:
                return match.group(1)

            match = re.search(
                r"Joomla!?\s*(\d+\.\d+(?:\.\d+)?)", content, re.IGNORECASE
            )
            if match:
                return match.group(1)

        return None

    def _detect_from_fingerprint(self):
        fingerprint_paths = [
            "/media/jui/css/bootstrap.min.css",
            "/media/jui/js/jquery.min.js",
            "/templates/system/css/system.css",
            "/media/system/js/core.js",
            "/media/vendor/css/bootstrap.min.css",
            "/media/vendor/css/joomla-fontawesome.min.css",
            "/media/templates/cassiopeia/css/template.css",
            "/administrator/templates/atum/css/template.css",
            "/",
        ]

        for path in fingerprint_paths:
            response = self._make_request(path)
            if not response or response.status_code != 200:
                continue

            content = response.text

            version_patterns = [
                ("5.1", "Joomla 5.1", "joomla 5.1"),
                ("5.0", "Joomla 5", "joomla 5"),
                ("4.4", "Joomla 4.4", "joomla 4.4"),
                ("4.3", "Joomla 4.3", "joomla 4.3"),
                ("4.2", "Joomla 4.2", "joomla 4.2"),
                ("4.1", "Joomla 4.1", "joomla 4.1"),
                ("4.0", "Joomla 4", "joomla 4"),
                ("3.10", "Joomla 3.10", "joomla 3.10"),
                ("3.9", "Joomla 3.9", "joomla 3.9"),
                ("3.8", "Joomla 3.8", "joomla 3.8"),
                ("3.7", "Joomla 3.7", "joomla 3.7"),
                ("3.6", "Joomla 3.6", "joomla 3.6"),
                ("3.5", "Joomla 3.5", "joomla 3.5"),
            ]

            for version_key, pattern1, pattern2 in version_patterns:
                if (
                    pattern1.lower() in content.lower()
                    or pattern2.lower() in content.lower()
                ):
                    return version_key

            for version, patterns in self.FINGERPRINTS.items():
                for pattern in patterns:
                    if pattern in content:
                        if version in ["5.0", "5.1", "4.0", "4.1", "4.2", "4.3", "4.4"]:
                            return version
                        return f"{version}.0"

        return None

    def get_result(self):
        return {
            "version": self.detected_version,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "target": self.target_url,
        }


def detect_joomla_version(target_url, verbose=True):
    detector = VersionDetector(target_url, timeout=10)
    return detector.detect(verbose=verbose)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python detector.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    version = detect_joomla_version(target)
    print(f"Detected version: {version}")

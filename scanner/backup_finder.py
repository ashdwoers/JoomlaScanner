import warnings

warnings.filterwarnings("ignore")
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

import sys
import threading
import time

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from scanner.component import ProgressIndicator


class BackupFinder:
    """Probes common backup filenames against a target URL using HEAD requests.

    Based on the OWASP joomscan backup filename list (~190 entries).
    A file is considered a real backup if the server returns 200 and the
    Content-Type is NOT text/html (same heuristic as joomscan).
    """

    BACKUP_FILENAMES = [
        # ── Archives of the site root ────────────────────────────────
        "backup.zip",
        "backup.tar.gz",
        "backup.tar",
        "backup.tar.bz2",
        "backup.tgz",
        "backup.rar",
        "backup.7z",
        "site-backup.zip",
        "site-backup.tar.gz",
        "site_backup.zip",
        "site_backup.tar.gz",
        "www.zip",
        "www.tar.gz",
        "wwwroot.zip",
        "wwwroot.tar.gz",
        "htdocs.zip",
        "htdocs.tar.gz",
        "public_html.zip",
        "public_html.tar.gz",
        "web.zip",
        "web.tar.gz",
        "website.zip",
        "website.tar.gz",
        "home.zip",
        "home.tar.gz",
        "html.zip",
        "html.tar.gz",
        "archive.zip",
        "archive.tar.gz",
        "archive.rar",
        "old.zip",
        "old.tar.gz",
        "latest.zip",
        "latest.tar.gz",
        "files.zip",
        "files.tar.gz",
        "master.zip",
        "master.tar.gz",
        "release.zip",
        "release.tar.gz",
        "dump.zip",
        "dump.tar.gz",
        "fullbackup.zip",
        "fullbackup.tar.gz",
        "full-backup.zip",
        "full-backup.tar.gz",
        "full_backup.zip",
        "full_backup.tar.gz",
        "complete-backup.zip",
        "complete-backup.tar.gz",
        "sitebackup.zip",
        "sitebackup.tar.gz",
        "websitebackup.zip",
        "websitebackup.tar.gz",
        # ── Database dumps ───────────────────────────────────────────
        "backup.sql",
        "backup.sql.gz",
        "backup.sql.bz2",
        "backup.sql.zip",
        "database.sql",
        "database.sql.gz",
        "database.sql.bz2",
        "database.sql.zip",
        "db.sql",
        "db.sql.gz",
        "db.sql.zip",
        "db-backup.sql",
        "db-backup.sql.gz",
        "db_backup.sql",
        "db_backup.sql.gz",
        "dump.sql",
        "dump.sql.gz",
        "dump.sql.zip",
        "mysql.sql",
        "mysql.sql.gz",
        "mysqldump.sql",
        "mysqldump.sql.gz",
        "data.sql",
        "data.sql.gz",
        "site.sql",
        "site.sql.gz",
        "joomla.sql",
        "joomla.sql.gz",
        "joomla_db.sql",
        "joomla_db.sql.gz",
        "joomladb.sql",
        "joomladb.sql.gz",
        "dbdump.sql",
        "dbdump.sql.gz",
        "export.sql",
        "export.sql.gz",
        # ── Joomla-specific backup patterns ──────────────────────────
        "joomla.zip",
        "joomla.tar.gz",
        "joomla_backup.zip",
        "joomla_backup.tar.gz",
        "joomla-backup.zip",
        "joomla-backup.tar.gz",
        "administrator/backups/backup.zip",
        "administrator/backups/backup.tar.gz",
        "administrator/backups/site-backup.zip",
        "administrator/backups/database.sql",
        "administrator/backups/database.sql.gz",
        "administrator/backups/db-backup.sql",
        "administrator/backups/dump.sql",
        "administrator/backup.zip",
        "administrator/backup.tar.gz",
        "administrator/backup.sql",
        "images/backup.zip",
        "images/backup.tar.gz",
        "images/backup.sql",
        "tmp/backup.zip",
        "tmp/backup.tar.gz",
        "tmp/backup.sql",
        "tmp/backup.sql.gz",
        "media/backup.zip",
        "media/backup.tar.gz",
        "logs/error.log",
        "logs/access.log",
        # ── Akeeba Backup files ──────────────────────────────────────
        "administrator/components/com_akeeba/backup/site-backup.jpa",
        "administrator/components/com_akeeba/backup/backup.jpa",
        "administrator/components/com_akeeba/backup/backup.zip",
        "backups/site-backup.jpa",
        "backups/backup.jpa",
        "backups/backup.zip",
        "backups/backup.tar.gz",
        # ── Configuration files ──────────────────────────────────────
        "configuration.php.bak",
        "configuration.php.old",
        "configuration.php.orig",
        "configuration.php.save",
        "configuration.php.swp",
        "configuration.php.dist",
        "configuration.php.txt",
        "configuration.php~",
        "configuration.bak",
        "configuration.old",
        "configuration.txt",
        "configuration.php-dist",
        "configuration.php.sample",
        ".configuration.php.swp",
        "configuration.php.1",
        "configuration.php.2",
        "configuration_old.php",
        "configuration_bak.php",
        "config.php.bak",
        "config.php.old",
        "config.bak",
        "config.old",
        "config.txt",
        # ── Common .bak / .old patterns ──────────────────────────────
        "index.php.bak",
        "index.php.old",
        "htaccess.bak",
        "htaccess.txt",
        ".htaccess.bak",
        ".htaccess.old",
        ".htpasswd",
        ".htpasswd.bak",
        "robots.txt.bak",
        "web.config.bak",
        "web.config.old",
        "wp-config.php.bak",
        # ── Generic filenames ────────────────────────────────────────
        "1.zip",
        "1.tar.gz",
        "1.sql",
        "2.zip",
        "2.tar.gz",
        "a.zip",
        "b.zip",
        "test.zip",
        "test.tar.gz",
        "test.sql",
        "temp.zip",
        "temp.tar.gz",
        "temp.sql",
        "bak.zip",
        "bak.tar.gz",
        "bak.sql",
        "new.zip",
        "old.zip",
        "old.tar.gz",
        "old.sql",
        "copy.zip",
        "copy.tar.gz",
        "error_log",
        "error.log",
        "access.log",
        "debug.log",
        "php_errors.log",
        # ── Version-control and IDE artifacts ────────────────────────
        ".git/config",
        ".git/HEAD",
        ".gitignore",
        ".svn/entries",
        ".svn/wc.db",
        ".env",
        ".env.bak",
        ".env.local",
        ".env.production",
        ".DS_Store",
        "Thumbs.db",
        ".idea/workspace.xml",
        ".vscode/settings.json",
        "composer.json",
        "composer.lock",
        "package.json",
    ]

    def __init__(self, target_url, timeout=3, threads=10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "JoomlaScanner/1.0"})
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads, pool_maxsize=threads,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self._results = []
        self._results_lock = threading.Lock()

    def _check_backup(self, filename):
        """Send a HEAD request for a single backup filename.

        Returns a result dict if the file likely exists, None otherwise.
        """
        url = urljoin(self.target_url + "/", filename)
        try:
            resp = self.session.head(url, timeout=self.timeout, verify=False, allow_redirects=True)
        except Exception:
            return None

        if resp.status_code != 200:
            return None

        content_type = resp.headers.get("Content-Type", "")
        # If the server returns text/html it is almost certainly a custom 404
        # page or a redirect landing — not an actual backup file.
        if "text/html" in content_type.lower():
            return None

        content_length = resp.headers.get("Content-Length")
        try:
            content_length = int(content_length)
        except (TypeError, ValueError):
            content_length = None

        return {
            "filename": filename,
            "url": url,
            "content_type": content_type.split(";")[0].strip(),
            "content_length": content_length,
            "last_modified": resp.headers.get("Last-Modified", ""),
        }

    def find_backups(self, verbose=True):
        """Probe all backup filenames concurrently.

        Returns a list of dicts for each file that appears to exist.
        """
        filenames = self.BACKUP_FILENAMES

        if verbose:
            print(f"[*] Probing {len(filenames)} backup filenames ({self.threads} threads)...")

        progress = ProgressIndicator(len(filenames), "Backup files")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_backup, fn): fn
                for fn in filenames
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self._results_lock:
                        self._results.append(result)

                progress.update()
                if verbose and sys.stdout.isatty():
                    sys.stdout.write(progress.get_progress())
                    sys.stdout.flush()

        if verbose:
            if sys.stdout.isatty():
                sys.stdout.write("\r" + " " * 80 + "\r")
                sys.stdout.flush()
            print(progress.finish())
            for bf in self._results:
                size = _format_size(bf["content_length"]) if bf["content_length"] else "unknown size"
                print(f"    [+] Found: {bf['filename']} ({size})")

        return self._results


def _format_size(size_bytes):
    """Format a byte count into a human-readable string."""
    if size_bytes is None:
        return "unknown size"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

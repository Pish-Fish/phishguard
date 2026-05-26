"""
Shared OpenPhish / PhishTank feed checks for PhishGuard tools.
"""
import json
import os
import time
from urllib.parse import urlparse

import requests

repo_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Sooty-master")
DB_MAX_AGE_SECONDS = 6 * 60 * 60
PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.json"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
REQUEST_HEADERS = {"User-Agent": "PhishGuard/1.0 (university security research)"}


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def url_match_keys(url):
    """Build normalized URL variants for feed comparison."""
    parsed = urlparse(normalize_url(url))
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    keys = set()
    for scheme in ("http", "https"):
        keys.add(f"{scheme}://{host}{path}")
    if path == "/":
        keys.add(f"http://{host}")
        keys.add(f"https://{host}")
    return keys, host


def urls_match(candidate, target_keys):
    candidate = candidate.strip()
    if not candidate:
        return False
    if candidate in target_keys:
        return True
    cand_keys, _ = url_match_keys(candidate)
    return bool(cand_keys & target_keys)


def hostname_from_url(url):
    parsed = urlparse(normalize_url(url))
    domain = (parsed.hostname or "").lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _db_path(name):
    return os.path.join(repo_dir, "data", name)


def _db_is_stale(db_file):
    if not os.path.isfile(db_file):
        return True
    return (time.time() - os.path.getmtime(db_file)) > DB_MAX_AGE_SECONDS


def _download_file(url, db_file):
    os.makedirs(os.path.dirname(db_file), exist_ok=True)
    tmp_file = db_file + ".download"
    try:
        with requests.get(url, stream=True, timeout=600, headers=REQUEST_HEADERS) as response:
            response.raise_for_status()
            with open(tmp_file, "wb") as out:
                for chunk in response.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        out.write(chunk)
        os.replace(tmp_file, db_file)
        return True
    except Exception:
        if os.path.isfile(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass
        return False


def _ensure_phishtank_db():
    db_file = _db_path("phishtank.json")
    if not _db_is_stale(db_file):
        return db_file
    if _download_file(PHISHTANK_FEED_URL, db_file):
        return db_file
    return db_file if os.path.isfile(db_file) else None


def _ensure_openphish_db():
    db_file = _db_path("openphish.txt")
    if not _db_is_stale(db_file) and os.path.isfile(db_file):
        with open(db_file, encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for line in f if line.strip() and not line.startswith("#"))
        if line_count >= 50:
            return db_file
    if _download_file(OPENPHISH_FEED_URL, db_file):
        return db_file
    return db_file if os.path.isfile(db_file) else None


def check_phishtank(url, domain):
    """Return dict on direct or related hit, else None."""
    db_file = _ensure_phishtank_db()
    if not db_file:
        return None

    try:
        with open(db_file, encoding="utf-8") as f:
            entries = json.load(f)
    except Exception:
        return None

    target_keys, _ = url_match_keys(url)
    direct_hit = None
    related_urls = []

    for entry in entries:
        entry_url = entry.get("url", "")
        if urls_match(entry_url, target_keys):
            direct_hit = {
                "url": entry_url,
                "phish_id": entry.get("phish_id"),
                "phish_detail_page": entry.get("phish_detail_url"),
                "verified": entry.get("verified"),
                "online": entry.get("online"),
            }
            break
        _, entry_host = url_match_keys(entry_url)
        if domain and (domain in entry_url or entry_host == domain):
            related_urls.append({
                "url": entry_url,
                "phish_detail_page": entry.get("phish_detail_url"),
            })

    if direct_hit:
        return {
            "source": "phishtank",
            "listed": True,
            "related": False,
            "matched_url": direct_hit["url"],
            "detail": direct_hit,
            "related_urls": related_urls[:5],
            "related_count": len(related_urls),
            "summary": (
                f"Listed in PhishTank public feed. Phish ID {direct_hit.get('phish_id')}. "
                f"Verified: {direct_hit.get('verified')}, online: {direct_hit.get('online')}."
            ),
        }

    if related_urls:
        return {
            "source": "phishtank",
            "listed": False,
            "related": True,
            "matched_url": None,
            "related_urls": related_urls[:5],
            "related_count": len(related_urls),
            "summary": (
                f"Exact URL not listed, but {len(related_urls)} PhishTank entry(ies) "
                f"mention domain {domain}."
            ),
        }

    return None


def check_openphish(url, domain):
    """Return dict on direct or related hit, else None."""
    db_file = _ensure_openphish_db()
    if not db_file:
        return None

    target_keys, _ = url_match_keys(url)
    direct_hit = None
    related_urls = []

    try:
        with open(db_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                entry_url = line.strip()
                if not entry_url or entry_url.startswith("#"):
                    continue
                if urls_match(entry_url, target_keys):
                    direct_hit = entry_url
                    break
                _, entry_host = url_match_keys(entry_url)
                if domain and (domain in entry_url or entry_host == domain):
                    related_urls.append(entry_url)
    except Exception:
        return None

    if direct_hit:
        return {
            "source": "openphish",
            "listed": True,
            "related": False,
            "matched_url": direct_hit,
            "related_urls": related_urls[:5],
            "related_count": len(related_urls),
            "summary": f"Listed on OpenPhish public feed: {direct_hit}",
        }

    if related_urls:
        return {
            "source": "openphish",
            "listed": False,
            "related": True,
            "matched_url": None,
            "related_urls": related_urls[:5],
            "related_count": len(related_urls),
            "summary": (
                f"Exact URL not listed, but {len(related_urls)} OpenPhish entry(ies) "
                f"mention domain {domain}."
            ),
        }

    return None


def check_threat_feeds(url):
    """
    Check PhishTank then OpenPhish. Returns the first hit dict or None.

    Keys: source, listed, related, matched_url, summary, related_urls, related_count
    """
    url = normalize_url(url)
    domain = hostname_from_url(url)

    phishtank = check_phishtank(url, domain)
    if phishtank:
        return phishtank

    return check_openphish(url, domain)

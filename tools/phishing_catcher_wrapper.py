import importlib
import importlib.util
import json
import os
import re
import sys
from urllib.parse import urlparse

import tldextract
from Levenshtein import distance

repo_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_catcher-master")

# Strong brand keywords from suspicious.yaml — only penalize when the brand is
# impersonated on a different registrable domain, not on the real site.
BRAND_KEYWORDS = {
    "appleid", "icloud", "iforgot", "itunes", "apple",
    "office365", "microsoft", "windows", "protonmail", "tutanota",
    "hotmail", "gmail", "outlook", "yahoo", "google", "yandex",
    "twitter", "facebook", "tumblr", "reddit", "youtube", "linkedin",
    "instagram", "flickr", "whatsapp",
    "localbitcoin", "poloniex", "coinhive", "bithumb", "kraken",
    "bitstamp", "bittrex", "blockchain", "bitpay", "coinbase", "ethereum",
    "uphold", "binance", "crypto", "metamask", "ledger", "trezor",
    "paypal", "amazon", "ebay", "stripe", "visa", "mastercard",
    "netflix", "spotify", "skype", "dropbox", "docusign",
}

# Free hosts commonly abused for credential phishing (brand often in subdomain).
FREE_HOSTING_REGISTERED = {
    "weebly.com", "wixsite.com", "wordpress.com", "blogspot.com", "github.io",
    "netlify.app", "vercel.app", "webflow.io", "square.site", "godaddysites.com",
}

RISKY_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".cam", ".loan",
    ".click", ".work", ".fit", ".rest", ".buzz", ".sbs", ".icu", ".zip",
}

COMMON_LEGIT_SUBDOMAINS = {
    "www", "web", "m", "mobile", "mail", "login", "account", "accounts",
    "secure", "static", "api", "cdn", "support", "help", "blog", "news",
    "drive", "docs", "calendar", "meet", "my", "id", "auth", "sso",
}


def _load_dotenv():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def _dynamic_import(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot import {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    mod_dir = os.path.dirname(path)
    if mod_dir not in sys.path:
        sys.path.insert(0, mod_dir)
    spec.loader.exec_module(module)
    return module


def load_suspicious_config():
    yaml = importlib.import_module("yaml")
    suspicious_path = os.path.join(repo_dir, "suspicious.yaml")
    external_path = os.path.join(repo_dir, "external.yaml")

    with open(suspicious_path, "r", encoding="utf-8") as f:
        suspicious = yaml.safe_load(f)

    if os.path.exists(external_path):
        with open(external_path, "r", encoding="utf-8") as f:
            external = yaml.safe_load(f)
    else:
        external = {}

    if external.get("override_suspicious.yaml") is True:
        suspicious = external
    else:
        if external.get("keywords") is not None:
            suspicious["keywords"].update(external["keywords"])
        if external.get("tlds") is not None:
            suspicious["tlds"].update(external["tlds"])

    return suspicious


def extract_host(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return urlparse(url).hostname or url
    except Exception:
        return url


def _registered_domain(hostname):
    ext = tldextract.extract(hostname.lower())
    if not ext.domain or not ext.suffix:
        return hostname.lower()
    return f"{ext.domain}.{ext.suffix}"


def _is_typosquat(candidate, brand):
    if candidate == brand:
        return False
    if abs(len(candidate) - len(brand)) > 2:
        return False
    return distance(candidate, brand) <= 1


def _hostname_parts(hostname):
    ext = tldextract.extract(hostname.lower())
    labels = [p for p in ext.subdomain.split(".") if p] if ext.subdomain else []
    if ext.domain:
        labels.append(ext.domain)
    return labels, ext


def analyze_domain_context(hostname, suspicious):
    """Adjust raw phishing_catcher score for single-URL checks (not cert stream)."""
    hostname = hostname.lower().strip()
    labels, ext = _hostname_parts(hostname)
    registered = _registered_domain(hostname)
    reasons = []
    adjustments = 0

    brand_keyword_weights = suspicious.get("keywords", {})

    # Real brand site: registrable domain is exactly brand.tld (facebook.com, google.com).
    if ext.domain in BRAND_KEYWORDS and registered == f"{ext.domain}.{ext.suffix}":
        brand_weight = brand_keyword_weights.get(ext.domain, 60)
        adjustments -= brand_weight
        reasons.append(
            f"Legitimate {ext.domain}.{ext.suffix} — brand keyword penalty removed ({brand_weight} pts)."
        )

        sub_labels = [p for p in ext.subdomain.split(".") if p] if ext.subdomain else []
        if sub_labels and all(s in COMMON_LEGIT_SUBDOMAINS for s in sub_labels):
            adjustments -= 15
            reasons.append("Common legitimate subdomain pattern.")

    # Typosquat on registrable label: paypa1.com, g00gle.com
    if ext.domain and ext.domain not in BRAND_KEYWORDS:
        for brand in BRAND_KEYWORDS:
            if _is_typosquat(ext.domain, brand):
                adjustments += 40
                reasons.append(f"Possible typosquat of '{brand}' in domain label.")
                break

    # Brand name only in subdomain while registrable domain is unrelated: evil.com
    if ext.subdomain:
        for brand in BRAND_KEYWORDS:
            if brand in ext.subdomain and ext.domain != brand:
                if re.search(rf"(^|[.\-_]){re.escape(brand)}([.\-_]|$)", ext.subdomain):
                    adjustments += 25
                    reasons.append(f"Brand '{brand}' appears in subdomain on non-{brand} domain.")
                    break

    # Homograph / misleading compound on wrong TLD: secure-facebook.xyz
    tld = f".{ext.suffix}" if ext.suffix else ""
    if tld in RISKY_TLDS:
        for label in labels:
            for brand in BRAND_KEYWORDS:
                if brand in label and ext.domain != brand:
                    adjustments += 20
                    reasons.append(f"Risky TLD ({tld}) with brand-like label '{label}'.")
                    break

    # Brand impersonation on free hosting: auth-uphold-log-com.weebly.com
    if registered in FREE_HOSTING_REGISTERED:
        adjustments += 15
        reasons.append(f"Hosted on free platform ({registered}), often used for phishing.")
        for brand in BRAND_KEYWORDS:
            if brand in hostname and ext.domain != brand:
                if re.search(rf"(^|[.\-_]){re.escape(brand)}([.\-_]|$)", hostname):
                    adjustments += 40
                    reasons.append(f"Brand '{brand}' referenced on free host {registered}.")
                    break

    return adjustments, reasons, registered


def score_domain_adjusted(hostname, score_fn, suspicious):
    raw_score = score_fn(hostname)
    adjustment, reasons, registered = analyze_domain_context(hostname, suspicious)
    adjusted = max(0, raw_score + adjustment)
    return raw_score, adjusted, adjustment, reasons, registered


def map_score_to_label(score: int) -> str:
    try:
        s = int(score)
    except Exception:
        return "Unknown"

    try:
        thr_susp = int(os.environ.get("PHISHING_THRESH_SUSPICIOUS", "90"))
    except Exception:
        thr_susp = 90
    try:
        thr_likely = int(os.environ.get("PHISHING_THRESH_LIKELY", "80"))
    except Exception:
        thr_likely = 80
    try:
        thr_potential = int(os.environ.get("PHISHING_THRESH_POTENTIAL", "65"))
    except Exception:
        thr_potential = 65

    if s >= thr_susp:
        return "Suspicious"
    if s >= thr_likely:
        return "Likely"
    if s >= thr_potential:
        return "Potential"
    return "SAFE"


def build_summary(domain, adjusted, label, raw_score, adjustment, reasons):
    if adjustment < 0 and label == "SAFE":
        return (
            f"{domain} looks like a legitimate site (adjusted score {adjusted}/100, "
            f"raw heuristic {raw_score}). Known-brand domains are not penalized the same way as unknown hosts."
        )
    if adjustment > 0:
        return (
            f"Phishing heuristics scored {domain} as {adjusted}/100 ({label}). "
            f"Extra risk signals applied on top of base score {raw_score}."
        )
    return f"Phishing heuristics scored {domain} as {adjusted}/100 ({label})."


def _feed_override_output(url, domain, feed_hit, raw_score, adjusted, adjustment, reasons, registered):
    """When URL is on a threat feed, heuristics alone are misleading."""
    if feed_hit["listed"]:
        label = "Suspicious"
        display_score = max(adjusted, 100)
        feed_name = "PhishTank" if feed_hit["source"] == "phishtank" else "OpenPhish"
        summary = (
            f"Listed on {feed_name} public feed — treated as confirmed phishing "
            f"(heuristic-only score was {adjusted}/100)."
        )
        reasons = [feed_hit["summary"], *reasons]
    else:
        label = "Likely"
        display_score = max(adjusted, 80)
        feed_name = "PhishTank" if feed_hit["source"] == "phishtank" else "OpenPhish"
        summary = (
            f"Not an exact {feed_name} match, but {feed_hit.get('related_count', 0)} related "
            f"listing(s) on this domain (heuristic score {adjusted}/100)."
        )
        reasons = [feed_hit["summary"], *reasons]

    return {
        "url": url,
        "domain": domain,
        "registered_domain": registered,
        "score": display_score,
        "raw_score": raw_score,
        "heuristic_score": adjusted,
        "score_adjustment": adjustment,
        "category": label,
        "feed_listed": feed_hit["listed"],
        "feed_source": feed_hit["source"],
        "feed_related": feed_hit.get("related", False),
        "matched_feed_url": feed_hit.get("matched_url"),
        "reasons": reasons,
        "summary": summary,
    }


def main():
    _load_dotenv()
    if len(sys.argv) != 2:
        print("Usage: python phishing_catcher_wrapper.py <url>")
        sys.exit(1)

    tools_dir = os.path.dirname(os.path.abspath(__file__))
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)

    from threat_feeds import check_threat_feeds, normalize_url

    url = normalize_url(sys.argv[1])
    domain = extract_host(url)
    suspicious = load_suspicious_config()
    catch_phishing = _dynamic_import("catch_phishing", os.path.join(repo_dir, "catch_phishing.py"))
    catch_phishing.suspicious = suspicious

    try:
        raw_score, adjusted, adjustment, reasons, registered = score_domain_adjusted(
            domain,
            catch_phishing.score_domain,
            suspicious,
        )
    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    feed_hit = None
    try:
        feed_hit = check_threat_feeds(url)
    except Exception:
        pass

    if feed_hit and (feed_hit["listed"] or feed_hit.get("related")):
        output = _feed_override_output(
            url, domain, feed_hit, raw_score, adjusted, adjustment, reasons, registered,
        )
    else:
        label = map_score_to_label(adjusted)
        output = {
            "url": url,
            "domain": domain,
            "registered_domain": registered,
            "score": adjusted,
            "raw_score": raw_score,
            "score_adjustment": adjustment,
            "category": label,
            "reasons": reasons,
            "summary": build_summary(domain, adjusted, label, raw_score, adjustment, reasons),
        }
    print(json.dumps(output))


if __name__ == "__main__":
    main()

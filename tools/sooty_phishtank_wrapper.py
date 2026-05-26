"""

Sooty / PhishTank wrapper for PhishGuard.



When PHISHTANK_API_KEY is set, uses Sooty's online PhishTank API checker.

When no API key is available (e.g. registration disabled), falls back to the

public PhishTank feed (online-valid.json) — no API key required.

"""

import importlib.util

import io

import json

import os

import sys

from contextlib import redirect_stdout

from urllib.parse import urlparse



import tldextract



from threat_feeds import check_openphish, check_phishtank, normalize_url



repo_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Sooty-master")





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





def _api_key_is_usable(api_key):

    if not api_key:

        return False

    lowered = api_key.strip().lower()

    placeholders = (

        "enter phishtank",

        "your_phishtank",

        "your-key",

        "not set",

        "none",

        "placeholder",

    )

    return not any(token in lowered for token in placeholders)





def _score_domain_heuristic(domain):

    tools_dir = os.path.dirname(os.path.abspath(__file__))

    pc_repo = os.path.join(tools_dir, "phishing_catcher-master")

    catch_path = os.path.join(pc_repo, "catch_phishing.py")

    wrapper_path = os.path.join(tools_dir, "phishing_catcher_wrapper.py")

    if not os.path.isfile(catch_path):

        return None



    pc_wrapper = _dynamic_import("phishing_catcher_wrapper", wrapper_path)

    suspicious = pc_wrapper.load_suspicious_config()

    catch_phishing = _dynamic_import("catch_phishing", catch_path)

    catch_phishing.suspicious = suspicious

    _raw, adjusted, _adj, _reasons, _registered = pc_wrapper.score_domain_adjusted(

        domain,

        catch_phishing.score_domain,

        suspicious,

    )

    label = pc_wrapper.map_score_to_label(adjusted)

    return adjusted, label





def _heuristic_verdict(score, domain):

    """Heuristic layer for URLs not in threat feeds (e.g. demo / new phishing sites)."""

    extracted = tldextract.extract(domain)

    tld = f".{extracted.suffix}" if extracted.suffix else ""

    risky_tlds = {

        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".cam", ".loan",

        ".click", ".work", ".fit", ".rest", ".buzz", ".sbs", ".icu",

    }



    if score >= 100:

        return "DANGER", f"Not in threat feeds, but domain heuristics score {score}/100 (very high risk)."

    if score >= 65 and tld in risky_tlds:

        return "WARNING", (

            f"Not in threat feeds, but suspicious TLD ({tld}) and heuristics score {score}/100."

        )

    if score >= int(os.environ.get("PHISHING_THRESH_SUSPICIOUS", "90")) and tld in risky_tlds:

        return "DANGER", (

            f"Not in threat feeds, but suspicious TLD ({tld}) and heuristics score {score}/100."

        )

    return "SAFE", (

        f"Not listed in OpenPhish/PhishTank feeds. Heuristics score {score}/100 (low concern)."

    )





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





def _emit_result(mode, in_database, verdict, summary, **extra):

    payload = {

        "success": True,

        "mode": mode,

        "in_database": in_database,

        "verdict": verdict,

        "summary": summary,

        **extra,

    }

    print(json.dumps(payload))

    return True





def _emit_feed_result(feed_hit):

    mode = "phishtank_local" if feed_hit["source"] == "phishtank" else "openphish_feed"

    if feed_hit["listed"]:

        verdict = "DANGER"

        extra = {"matched_url": feed_hit.get("matched_url")}

        if feed_hit.get("detail"):

            extra["result"] = feed_hit["detail"]

    else:

        verdict = "WARNING"

        extra = {}

    extra["related_urls"] = feed_hit.get("related_urls")

    extra["related_count"] = feed_hit.get("related_count", 0)

    return _emit_result(mode, feed_hit["listed"], verdict, feed_hit["summary"], **extra)





def _check_local_database(url):

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):

        print(

            json.dumps({

                "success": False,

                "error": "Not a valid http or https URL. Please enter the full URL.",

            }),

            file=sys.stdout,

        )

        return False



    domain = (parsed.hostname or "").lower()

    if domain.startswith("www."):

        domain = domain[4:]



    phishtank_hit = check_phishtank(url, domain)

    if phishtank_hit:

        return _emit_feed_result(phishtank_hit)



    openphish_hit = check_openphish(url, domain)

    if openphish_hit:

        return _emit_feed_result(openphish_hit)



    try:

        scored = _score_domain_heuristic(domain)

    except Exception:

        scored = None



    if scored:

        score, category = scored

        verdict, summary = _heuristic_verdict(score, domain)

        return _emit_result(

            "domain_heuristics",

            verdict != "SAFE",

            verdict,

            summary,

            heuristic_score=score,

            heuristic_category=category,

        )



    print(

        json.dumps({

            "success": False,

            "error": (

                "Could not download phishing feeds (PhishTank returned rate-limited or unavailable; "

                "OpenPhish feed also failed). Check your internet connection and try again later. "

                "When PhishTank registration reopens, add PHISHTANK_API_KEY to .env for live API checks."

            ),

        }),

        file=sys.stdout,

    )

    return False





def _check_online_api(url, api_key, app_name):

    phishtank = _dynamic_import("phishtank", os.path.join(repo_dir, "Modules", "phishtank.py"))

    buffer = io.StringIO()

    prev_cwd = os.getcwd()

    try:

        os.chdir(repo_dir)

        with redirect_stdout(buffer):

            phishtank.main("False", app_name, api_key, url)

    finally:

        os.chdir(prev_cwd)



    output = buffer.getvalue().strip()

    in_database = "in database:   true" in output.lower()

    verdict = "DANGER" if in_database else "SAFE"

    print(json.dumps({

        "success": True,

        "mode": "api",

        "in_database": in_database,

        "verdict": verdict,

        "summary": output or "PhishTank API check completed with no output.",

        "raw_output": output,

    }))

    return True





def main():

    if len(sys.argv) != 2:

        print("Usage: python sooty_phishtank_wrapper.py <url>")

        sys.exit(1)



    _load_dotenv()

    url = normalize_url(sys.argv[1])

    api_key = os.environ.get("PHISHTANK_API_KEY") or os.environ.get("SOOTY_PHISHTANK_API_KEY")

    app_name = os.environ.get("PHISHTANK_APP_NAME", "PhishGuard")

    force_local = os.environ.get("PHISHTANK_USE_LOCAL", "").lower() in ("1", "true", "yes")



    has_api_key = _api_key_is_usable(api_key)



    if has_api_key and not force_local:

        try:

            ok = _check_online_api(url, api_key, app_name)

        except Exception as exc:

            print(json.dumps({"success": False, "error": str(exc)}), file=sys.stdout)

            sys.exit(1)

        sys.exit(0 if ok else 1)



    ok = _check_local_database(url)

    sys.exit(0 if ok else 1)





if __name__ == "__main__":

    main()


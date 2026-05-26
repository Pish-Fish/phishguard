from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import whois
import dns.resolver
import nmap
import ssl
import socket
import json
import os
import shlex
import subprocess
import sys
import requests
import tldextract
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # Allow frontend to call backend


# ── Helpers: extract host and registered domain from URL ──────────────────
def extract_host(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return urlparse(url).hostname or url
    except Exception:
        return url


def extract_registered_domain(url):
    host = extract_host(url)
    extracted = tldextract.extract(host)
    if extracted.registered_domain:
        return extracted.registered_domain
    return host


# ── Route: Serve frontend ────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# ── Route: WHOIS ─────────────────────────────────────────────────────────────
@app.route("/api/whois", methods=["POST"])
def whois_lookup():
    data = request.get_json()
    url = data.get("url", "")
    domain = extract_registered_domain(url)

    try:
        w = whois.whois(domain)

        # Creation date handling
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        created_str = created.strftime("%B %d, %Y") if isinstance(created, datetime) else str(created)

        # Expiry date handling
        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        expires_str = expires.strftime("%B %d, %Y") if isinstance(expires, datetime) else str(expires)

        # Domain age
        if isinstance(created, datetime):
            age_days = (datetime.now() - created).days
            age_str = f"{age_days // 365} year(s), {(age_days % 365) // 30} month(s)" if age_days > 365 else f"{age_days} day(s)"
        else:
            age_str = "Unknown"

        return jsonify({
            "success": True,
            "domain": domain,
            "registrar": w.registrar or "Unknown",
            "created": created_str,
            "expires": expires_str,
            "age": age_str,
            "name_servers": list(w.name_servers)[:2] if w.name_servers else [],
            "status": str(w.status[0]) if isinstance(w.status, list) else str(w.status or "Unknown"),
            "country": w.country or "Unknown",
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e), "domain": domain})


# ── Route: NSLookup / DNS ────────────────────────────────────────────────────
@app.route("/api/nslookup", methods=["POST"])
def nslookup():
    data = request.get_json()
    url = data.get("url", "")
    domain = extract_host(url)

    result = {"success": True, "domain": domain, "a_records": [], "mx_records": [], "ns_records": [], "txt_records": []}

    try:
        # A Records (IPv4)
        answers = dns.resolver.resolve(domain, "A")
        result["a_records"] = [str(r) for r in answers]
    except Exception as e:
        result["a_records_error"] = str(e)

    try:
        # MX Records
        answers = dns.resolver.resolve(domain, "MX")
        result["mx_records"] = [str(r.exchange) for r in answers]
    except Exception:
        result["mx_records"] = []

    try:
        # NS Records
        answers = dns.resolver.resolve(domain, "NS")
        result["ns_records"] = [str(r) for r in answers]
    except Exception:
        result["ns_records"] = []

    try:
        # Reverse DNS on first A record
        if result["a_records"]:
            hostname = socket.gethostbyaddr(result["a_records"][0])
            result["reverse_dns"] = hostname[0]
    except Exception:
        result["reverse_dns"] = "Not available"

    return jsonify(result)


# ── Route: Port Scan (Nmap) ──────────────────────────────────────────────────
@app.route("/api/portscan", methods=["POST"])
def port_scan():
    data = request.get_json()
    url = data.get("url", "")
    domain = extract_host(url)

    try:
        nmap_path = _get_nmap_search_path()
        if nmap_path:
            nm = nmap.PortScanner(nmap_search_path=(nmap_path,))
        else:
            nm = nmap.PortScanner()
        # Scan common web-related ports only (fast, safe for demo)
        nm.scan(domain, "21,22,23,25,80,443,3306,8080,8443", arguments="-T4 --open")

        ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                port_list = nm[host][proto].keys()
                for port in sorted(port_list):
                    state = nm[host][proto][port]["state"]
                    service = nm[host][proto][port]["name"]
                    ports.append({
                        "port": port,
                        "state": state,
                        "service": service,
                        "protocol": proto
                    })

        return jsonify({
            "success": True,
            "domain": domain,
            "ports": ports,
            "open_count": len([p for p in ports if p["state"] == "open"])
        })

    except Exception as e:
        error_msg = str(e)
        if "nmap program was not found in path" in error_msg.lower():
            nmap_path = _get_nmap_search_path()
            if nmap_path:
                error_msg = f"Nmap executable not found at NMAP_PATH={nmap_path}. Verify the path is correct."
            else:
                error_msg = "Nmap executable not found in PATH. Install Nmap and make sure it is available to the Flask environment."
        return jsonify({"success": False, "error": error_msg, "domain": domain})


# ── Route: SSL Certificate ───────────────────────────────────────────────────
@app.route("/api/ssl", methods=["POST"])
def ssl_check():
    data = request.get_json()
    url = data.get("url", "")
    domain = extract_host(url)

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.create_connection((domain, 443), timeout=10),
            server_hostname=domain
        )
        cert = conn.getpeercert()
        conn.close()

        # Parse expiry
        expire_str = cert.get("notAfter", "")
        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z") if expire_str else None
        days_remaining = (expire_date - datetime.now()).days if expire_date else 0

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        # SANs
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            sans.append(san_value)

        return jsonify({
            "success": True,
            "domain": domain,
            "issuer": issuer.get("organizationName", "Unknown"),
            "issued_to": subject.get("commonName", domain),
            "valid_from": cert.get("notBefore", "Unknown"),
            "valid_until": expire_str,
            "days_remaining": days_remaining,
            "is_expired": days_remaining < 0,
            "near_expiry": 0 <= days_remaining <= 30,
            "tls_version": conn.version() if hasattr(conn, "version") else "TLS",
            "sans": sans[:5],
            "wildcard": any("*" in s for s in sans),
        })

    except ssl.SSLCertVerificationError as e:
        return jsonify({"success": False, "error": "SSL verification failed: " + str(e), "domain": domain})
    except ConnectionRefusedError:
        return jsonify({"success": False, "error": "Port 443 not open — site may not support HTTPS", "domain": domain})
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "domain": domain})


def _run_external_tool(tool_name, command_template, url, domain, timeout=120):
    if not command_template:
        return {"success": False, "error": f"{tool_name} is not configured. Set {tool_name.upper().replace(' ', '_')}_CMD in .env with a command template containing {url} and/or {domain}.", "domain": domain}

    try:
        if isinstance(command_template, list):
            command_parts = [part.format(url=url, domain=domain) for part in command_template]
        else:
            command = command_template.format(url=url, domain=domain)
            command_parts = shlex.split(command, posix=False)
        completed = subprocess.run(command_parts, capture_output=True, text=True, timeout=timeout)

        if completed.returncode != 0:
            return {
                "success": False,
                "error": f"{tool_name} failed with exit code {completed.returncode}: {completed.stderr.strip() or completed.stdout.strip()}",
                "domain": domain
            }

        return {
            "success": True,
            "tool": tool_name,
            "domain": domain,
            "output": completed.stdout.strip() or completed.stderr.strip()
        }
    except FileNotFoundError:
        return {"success": False, "error": f"{tool_name} command not found. Check your {tool_name.upper().replace(' ', '_')}_CMD setting.", "domain": domain}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"{tool_name} timed out after {timeout} seconds. This tool may require longer to complete for this target.", "domain": domain}
    except Exception as e:
        return {"success": False, "error": str(e), "domain": domain}


@app.route("/api/sooty", methods=["POST"])
def sooty_scan():
    data = request.get_json()
    url = data.get("url", "")
    domain = extract_host(url)
    _load_dotenv()
    default_cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "tools", "sooty_phishtank_wrapper.py"), "{url}"]
    command_template = os.environ.get("SOOTY_CMD") or default_cmd
    # First run may download the public PhishTank database (~large file).
    result = _run_external_tool("Sooty", command_template, url, domain, timeout=900)
    return jsonify(result)


@app.route("/api/phishing_catcher", methods=["POST"])
def phishing_catcher_scan():
    data = request.get_json()
    url = data.get("url", "")
    domain = extract_host(url)
    _load_dotenv()
    default_cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "tools", "phishing_catcher_wrapper.py"), "{url}"]
    command_template = os.environ.get("PHISHING_CATCHER_CMD") or default_cmd
    result = _run_external_tool("phishing_catcher", command_template, url, domain)
    return jsonify(result)


def _load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def _get_nmap_search_path():
    _load_dotenv()
    path = os.environ.get("NMAP_PATH")
    if path:
        path = path.strip().strip('"').strip("'")
        path = path.replace("\\", "/")
        path = path.replace("\n", "").replace("\r", "")
        path = os.path.normpath(path)

        if os.path.isdir(path):
            for name in ("nmap.exe", "nmap"):
                candidate = os.path.join(path, name)
                if os.path.isfile(candidate):
                    return candidate
        if os.path.isfile(path):
            return path

        candidate = os.path.join(path, "nmap.exe")
        if os.path.isfile(candidate):
            return candidate
        candidate = os.path.join(path, "nmap")
        if os.path.isfile(candidate):
            return candidate

        return path

    for candidate in ("/usr/bin/nmap", "/usr/local/bin/nmap"):
        if os.path.isfile(candidate):
            return candidate

    if sys.platform == "win32":
        win_default = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Nmap", "nmap.exe")
        if os.path.isfile(win_default):
            return win_default

    return None


def _call_anthropic(payload):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        _load_dotenv()
        api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("Missing ANTHROPIC_API_KEY environment variable. Create a .env file with ANTHROPIC_API_KEY=your-key or set the variable in your shell.")

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key
    }
    response = requests.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


def _extract_anthropic_text(resp):
    content = resp.get("content")
    if isinstance(content, list):
        return "".join(item.get("text", "") for item in content)
    if isinstance(content, dict):
        return content.get("text", "")
    return ""


@app.route("/api/ai-verdict", methods=["POST"])
def ai_verdict():
    data = request.get_json() or {}
    url = data.get("url", "")

    try:
        payload = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity AI for a university phishing detection system. Analyze the URL for phishing/threat indicators. Respond ONLY in valid JSON with no extra text: {\"verdict\":\"SAFE\"|\"WARNING\"|\"DANGER\",\"score\":<0-100 integer>,\"summary\":\"<2-3 sentences>\",\"tips\":[\"<tip1>\",\"<tip2>\",\"<tip3>\"]}"
                },
                {
                    "role": "user",
                    "content": f"Analyze this URL for phishing risk: {url}"
                }
            ],
            "max_tokens": 1000
        }
        resp = _call_anthropic(payload)
        text = _extract_anthropic_text(resp)
        parsed = json.loads(text.replace("```json", "").replace("```", "").strip())
        return jsonify({
            "success": True,
            "verdict": parsed.get("verdict", "WARNING"),
            "score": parsed.get("score", 50),
            "summary": parsed.get("summary", "AI analysis is currently unavailable. Please review the tool results below manually."),
            "tips": parsed.get("tips", [])
        })
    except EnvironmentError as e:
        return jsonify({"success": False, "error": str(e)}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/ai-summary", methods=["POST"])
def ai_summary():
    data = request.get_json() or {}
    url = data.get("url", "")
    whois_text = data.get("whois", "")
    ns_text = data.get("nslookup", "")
    nmap_text = data.get("nmap", "")
    ssl_text = data.get("ssl", "")
    sooty_text = data.get("sooty", "")
    phishing_text = data.get("phishing", "")

    try:
        payload = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "system",
                    "content": "You are PhishGuard's AI security analyst for a university. Summarize the security scan results for a non-technical university student in 3-4 sentences. Explain what each tool found, what it means for their safety, and give one clear recommendation. Be friendly and clear. No markdown formatting."
                },
                {
                    "role": "user",
                    "content": f"URL: {url}\n\nWHOIS Results:\n{whois_text}\n\nDNS Results:\n{ns_text}\n\nPort Scan Results:\n{nmap_text}\n\nSSL Results:\n{ssl_text}\n\nSooty Results:\n{sooty_text}\n\nPhishing Catcher Results:\n{phishing_text}"
                }
            ],
            "max_tokens": 1000
        }
        resp = _call_anthropic(payload)
        text = _extract_anthropic_text(resp)
        return jsonify({"success": True, "summary": text.strip()})
    except EnvironmentError as e:
        return jsonify({"success": False, "error": str(e)}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug, host="0.0.0.0", port=port)
import os
import sys

# Manually load .env (same as wrappers do)
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
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

# Check what keys are set
keys_to_check = [
    'ANTHROPIC_API_KEY',
    'NMAP_PATH',
    'VIRUSTOTAL_API_KEY',
    'URLSCAN_API_KEY',
    'ABUSEIPDB_API_KEY',
    'PHISHTANK_API_KEY',
    'EMAILREP_API_KEY',
]

print("API Keys Status:")
print("=" * 60)
for key in keys_to_check:
    value = os.environ.get(key, "NOT SET")
    if value and value != "NOT SET":
        # Show only first 10 chars + ...
        display = value[:10] + "..." if len(value) > 10 else value
        status = f"✓ SET ({display})"
    else:
        status = "✗ NOT SET"
    print(f"{key:30s} : {status}")

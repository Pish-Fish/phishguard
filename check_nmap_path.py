import os

env_path = os.path.join(os.path.dirname(__file__), '.env')
with open(env_path, 'r', encoding='utf-8') as f:
    nmap_path = None
    for line in f:
        line = line.strip()
        if line.startswith('NMAP_PATH='):
            nmap_path = line.split('=', 1)[1].strip().strip('"').strip("'")
            break

print('raw:', repr(nmap_path))
print('exists raw:', os.path.exists(nmap_path))
print('isfile raw:', os.path.isfile(nmap_path))
print('isdir raw:', os.path.isdir(nmap_path))
if nmap_path is not None:
    normalized = os.path.normpath(nmap_path)
    print('normalized:', repr(normalized))
    print('exists normalized:', os.path.exists(normalized))
    print('isfile normalized:', os.path.isfile(normalized))
    print('isdir normalized:', os.path.isdir(normalized))
    if os.path.isdir(normalized):
        candidate = os.path.join(normalized, 'nmap.exe')
        print('candidate:', repr(candidate), os.path.exists(candidate), os.path.isfile(candidate))
else:
    print('NMAP_PATH not set in .env')

import urllib.request
import json

pkgs = [
    'Django==5.2.18',
    'asgiref==3.13.0',
    'sqlparse==0.6.0',
    'tzdata==2026.6',
    'argon2-cffi==25.1.0',
    'argon2-cffi-bindings==26.1.0',
    'cffi==2.1.1',
    'pycparser==3.12',
    'cryptography==50.0.2',
    'python-dotenv==1.2.4',
    'python-magic==0.4.27',
    'django-otp==1.7.5',
    'qrcode==8.2',
    'PyOTP==2.10.0',
    'django-axes==8.3.1',
    'django-ratelimit==4.1.0',
    'django-csp==4.0',
    'gunicorn==26.2.0',
    'colorama==0.4.6',
    'packaging==26.3',
    'typing_extensions==4.16.0',
    'psycopg==3.3.6',
    'psycopg-binary==3.3.6',
]

lines = [
    '# CaseVault Cryptographically Pinned Production Dependencies',
    '# Generated per ADR-0005 & ADR-0006 with SHA-256 distribution hashes',
    '',
]

for req in pkgs:
    name, ver = req.split('==')
    url = f'https://pypi.org/pypi/{name}/{ver}/json'
    print(f'Fetching hashes for {req}...')
    with urllib.request.urlopen(url, timeout=15) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        urls = data.get('urls', [])
        hashes = [f"    --hash=sha256:{u['digests']['sha256']}" for u in urls]
        lines.append(f'{name}=={ver} \\')
        lines.append(' \\\n'.join(hashes))
        lines.append('')

with open('requirements.lock', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))

print('Successfully generated requirements.lock')

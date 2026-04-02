import urllib.request, urllib.parse, json

BASE = 'http://localhost:8000/api/auth'

def post(url, data):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

tests = [
    ("Bad domain (gmail)",      {'username': 'test1', 'email': 'test@gmail.com',            'password': 'Test123!',  'role': 'analyst'}),
    ("No number in email",      {'username': 'test2', 'email': 'john.doe@sentinelai.com',   'password': 'Test123!',  'role': 'analyst'}),
    ("Wrong admin invite code", {'username': 'test3', 'email': 'john.doe1@sentinelai.com',  'password': 'Test123!',  'role': 'admin',   'invite_code': 'WRONG'}),
    ("Weak password",           {'username': 'test4', 'email': 'john.doe1@sentinelai.com',  'password': 'weakpass',  'role': 'analyst'}),
    ("Valid analyst",           {'username': 'majeed1', 'email': 'majeed.al1@sentinelai.com','password': 'Majeed123!','role': 'analyst'}),
    ("Valid admin",             {'username': 'sysadmin','email': 'sys.admin1@sentinelai.com','password': 'Admin123!', 'role': 'admin', 'invite_code': 'SENTINEL-ADMIN-2024'}),
]

for label, payload in tests:
    status, resp = post(f'{BASE}/register', payload)
    if status in (200, 201):
        print(f"[OK {status}] {label}: {resp.get('username')} ({resp.get('role')})")
    else:
        print(f"[FAIL {status}] {label}: {resp.get('detail')}")

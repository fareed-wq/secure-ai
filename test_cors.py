import requests

API_URL = 'http://127.0.0.1:8000/api/health'

def check_cors(origin):
    headers = {'Origin': origin, 'Access-Control-Request-Method': 'GET'}
    resp = requests.options(API_URL, headers=headers)
    return resp.headers.get('Access-Control-Allow-Origin')

origins_to_test = [
    'https://www.urlscanonline.com',
    'https://urlscanonline.com',
    'http://localhost:5173',
    'https://secure-ai-xyz.vercel.app',
    'https://random-hacker-site.com',
]

for o in origins_to_test:
    allow = check_cors(o)
    print(f'Origin {o}: {allow}')


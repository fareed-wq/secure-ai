
import sys
import asyncio
from unittest.mock import patch, MagicMock

# mock get_http_session
import api.scanner.transport as transport
import requests

request_count = 0
request_urls = []

original_safe_request = transport.safe_request

def mock_safe_request(method, url, **kwargs):
    global request_count
    request_count += 1
    request_urls.append((method, url))
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '<html></html>'
    mock_resp.headers = {}
    mock_resp.history = []
    mock_resp.content = b'<html></html>'
    return mock_resp

transport.safe_request = mock_safe_request

import api.scanner.orchestrator as orch

def count_requests(mode):
    global request_count
    global request_urls
    request_count = 0
    request_urls = []
    
    try:
        orch.scan_url('https://example.com', probe_subdomains=False, scan_mode=mode)
    except Exception as e:
        print(f'Error: {e}')
    
    print(f'Mode: {mode}, Requests: {request_count}')
    for m, u in request_urls:
        print(f'  {m} {u}')

count_requests('passive')
count_requests('active')


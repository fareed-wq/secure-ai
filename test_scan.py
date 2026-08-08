from api.index import scan_url
import json

result = scan_url("https://google.com")
print(json.dumps(result, indent=2))

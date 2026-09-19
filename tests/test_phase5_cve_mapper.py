import pytest
from unittest.mock import patch, Mock
import requests
from api.scanner.cve_mapper import enrich_with_cves

def test_enrich_with_cves_success():
    identities = [{
        "vendor": "nginx",
        "product": "nginx",
        "version": "1.18.0",
        "version_precision": "EXACT_OBSERVED",
        "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    }]
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-23017",
                    "descriptions": [{"lang": "en", "value": "A security issue in nginx."}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]
                    }
                }
            }
        ]
    }
    
    with patch('requests.get', return_value=mock_response) as mock_get:
        result = enrich_with_cves(identities)
        
        assert len(result) == 1
        assert "cves" in result[0]
        assert len(result[0]["cves"]) == 1
        assert result[0]["cves"][0]["id"] == "CVE-2021-23017"
        assert result[0]["cves"][0]["severity"] == "HIGH"
        
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        assert "cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*" in called_url
        assert mock_get.call_args[1]["timeout"] == 5.0

def test_enrich_with_cves_timeout_handling():
    identities = [{
        "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        "version_precision": "EXACT_OBSERVED"
    }]
    
    with patch('requests.get', side_effect=requests.exceptions.Timeout):
        result = enrich_with_cves(identities)
        assert result[0]["cves"] == []

def test_enrich_with_cves_non_200_handling():
    identities = [{
        "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        "version_precision": "EXACT_OBSERVED"
    }]
    
    mock_response = Mock()
    mock_response.status_code = 403
    
    with patch('requests.get', return_value=mock_response):
        result = enrich_with_cves(identities)
        assert result[0]["cves"] == []

def test_enrich_with_cves_skips_inferred_precision():
    identities = [{
        "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        "version_precision": "INFERRED"
    }]
    
    with patch('requests.get') as mock_get:
        result = enrich_with_cves(identities)
        assert result[0]["cves"] == []
        mock_get.assert_not_called()
        
def test_enrich_with_cves_limits_to_5():
    identities = [{
        "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        "version_precision": "EXACT_OBSERVED"
    }]
    
    vulns = []
    for i in range(10):
        vulns.append({
            "cve": {
                "id": f"CVE-2021-{i:04d}",
                "descriptions": [{"lang": "en", "value": "test"}],
                "metrics": {}
            }
        })
        
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"vulnerabilities": vulns}
    
    with patch('requests.get', return_value=mock_response):
        result = enrich_with_cves(identities)
        assert len(result[0]["cves"]) == 5

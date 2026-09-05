import pytest
from unittest.mock import MagicMock
from api.scanner.modules.discovery import ExposedFilesModule
import requests

@pytest.fixture
def module():
    return ExposedFilesModule()

def mock_response(status_code=200, text="", headers=None, content=b"", url=None, history=None):
    r = MagicMock(spec=requests.Response)
    r.status_code = status_code
    r.text = text
    r.content = content if content else text.encode('utf-8')
    r.headers = headers or {"Content-Type": "text/plain"}
    r.url = url
    r.history = history or []
    return r

def test_real_env_detected(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.env": mock_response(200, "APP_ENV=production\nDB_PASSWORD=secret", {"Content-Type": "text/plain"}, url="http://example.com/.env"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    env_finding = next((f for f in findings if f["name"] == "Exposed .env Configuration File"), None)

    assert env_finding is not None
    assert env_finding["severity"] == "High"

def test_harmless_env_not_high(module, monkeypatch):
    # Only generic keys without sensitive matches
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.env": mock_response(200, "APP_ENV=production\nDEBUG=false\nTHEME=dark", {"Content-Type": "text/plain"}, url="http://example.com/.env"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    env_finding = next((f for f in findings if f["name"] == "Exposed .env Configuration File"), None)

    assert env_finding is None

def test_redirect_protected(module, monkeypatch):
    # A redirect to /login
    hist_mock = [mock_response(301, url="http://example.com/.env")]
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.env": mock_response(200, "APP_ENV=production\nDB_PASSWORD=secret", {"Content-Type": "text/plain"}, url="http://example.com/login", history=hist_mock),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    env_finding = next((f for f in findings if f["name"] == "Exposed .env Configuration File"), None)

    assert env_finding is None

def test_valid_git_head_detected(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.git/HEAD": mock_response(200, "ref: refs/heads/main\n", {"Content-Type": "text/plain"}, url="http://example.com/.git/HEAD"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    git_finding = next((f for f in findings if f["name"] == "Exposed .git Repository"), None)

    assert git_finding is not None
    assert git_finding["severity"] == "Medium"

def test_valid_docker_compose_detected(module, monkeypatch):
    yaml_content = "version: '3'\nservices:\n  web:\n    image: nginx:latest\n"
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/docker-compose.yml": mock_response(200, yaml_content, {"Content-Type": "application/x-yaml"}, url="http://example.com/docker-compose.yml"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    compose_finding = next((f for f in findings if f["name"] == "Exposed Docker Compose Configuration"), None)

    assert compose_finding is not None
    assert compose_finding["severity"] == "Medium"


def test_harmless_env_suffixes_not_high(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.env": mock_response(200, "PASSWORD_POLICY_ENABLED=true\nTOKEN_EXPIRY=3600", {"Content-Type": "text/plain"}, url="http://example.com/.env"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    env_finding = next((f for f in findings if f["name"] == "Exposed .env Configuration File"), None)
    assert env_finding is None

def test_empty_env_value_not_high(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.env": mock_response(200, "DB_PASSWORD=\nAPI_KEY=null", {"Content-Type": "text/plain"}, url="http://example.com/.env"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    env_finding = next((f for f in findings if f["name"] == "Exposed .env Configuration File"), None)
    assert env_finding is None

def test_placeholder_env_value_not_high(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.env": mock_response(200, "API_KEY=changeme\nSECRET=your_secret_here", {"Content-Type": "text/plain"}, url="http://example.com/.env"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    env_finding = next((f for f in findings if f["name"] == "Exposed .env Configuration File"), None)
    assert env_finding is None

def test_aws_secret_detected_high(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.env": mock_response(200, "AWS_SECRET_ACCESS_KEY=plausible-value", {"Content-Type": "text/plain"}, url="http://example.com/.env"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())
    env_finding = next((f for f in findings if f["name"] == "Exposed .env Configuration File"), None)
    assert env_finding is not None
    assert env_finding["severity"] == "High"
    assert "plausible-value" not in env_finding["evidence"]["raw"]

def test_sql_dump_vs_zip_dump(module, monkeypatch):
    # These probes have been removed. We verify they return no findings even if present.
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/db.sql": mock_response(200, "-- MySQL dump\nCREATE TABLE admin;", {"Content-Type": "text/plain"}, url="http://example.com/db.sql"),
        "http://example.com/backup.zip": mock_response(200, "PK\x03\x04...binary...", {"Content-Type": "application/zip"}, content=b"PK\x03\x04...binary...", url="http://example.com/backup.zip"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))

    findings = module.run("http://example.com", "example.com", MagicMock())

    sql_finding = next((f for f in findings if "Exposed Database Backup Dump" in f["name"]), None)
    assert sql_finding is None

    zip_finding = next((f for f in findings if "Exposed Backup / Archive File" in f["name"]), None)
    assert zip_finding is None


def test_git_head_wording_and_evidence(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.git/HEAD": mock_response(200, "ref: refs/heads/main\n", {"Content-Type": "text/plain"}, url="http://example.com/.git/HEAD"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))
    findings = module.run("http://example.com", "example.com", MagicMock())
    git_finding = next((f for f in findings if f["name"] == "Exposed .git Repository"), None)

    assert git_finding is not None
    assert git_finding["severity"] == "Medium"
    assert "entire source code" not in git_finding.get("description", "")
    assert "entire blueprint" not in git_finding.get("description", "")
    assert "Requested:" in git_finding.get("evidence", {}).get("raw", "")
    assert "Validated Git HEAD reference format" in git_finding.get("evidence", {}).get("raw", "")

def test_git_head_arbitrary_ref_rejected(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.git/HEAD": mock_response(200, "ref: refs/heads/main extra junk\n", {"Content-Type": "text/plain"}, url="http://example.com/.git/HEAD"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))
    findings = module.run("http://example.com", "example.com", MagicMock())
    git_finding = next((f for f in findings if f["name"] == "Exposed .git Repository"), None)
    assert git_finding is None

def test_git_head_40_64_ids_accepted(module, monkeypatch):
    # Test 40-char ID
    responses_40 = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.git/HEAD": mock_response(200, "1234567890abcdef1234567890abcdef12345678\n", {"Content-Type": "text/plain"}, url="http://example.com/.git/HEAD"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses_40.get(url, mock_response(404, url=url)))
    findings = module.run("http://example.com", "example.com", MagicMock())
    git_finding_40 = next((f for f in findings if f["name"] == "Exposed .git Repository"), None)
    assert git_finding_40 is not None

    # Test 64-char ID
    responses_64 = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.git/HEAD": mock_response(200, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n", {"Content-Type": "text/plain"}, url="http://example.com/.git/HEAD"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses_64.get(url, mock_response(404, url=url)))
    findings_64 = module.run("http://example.com", "example.com", MagicMock())
    git_finding_64 = next((f for f in findings_64 if f["name"] == "Exposed .git Repository"), None)
    assert git_finding_64 is not None

def test_git_config_separate(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.git/config": mock_response(200, "[core]\n\trepositoryformatversion = 0\n", {"Content-Type": "text/plain"}, url="http://example.com/.git/config"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))
    findings = module.run("http://example.com", "example.com", MagicMock())
    conf_finding = next((f for f in findings if f["name"] == "Exposed .git Configuration File"), None)
    assert conf_finding is not None
    assert conf_finding["severity"] == "Medium"
    assert "Requested:" in conf_finding.get("evidence", {}).get("raw", "")
    assert "Validated Git configuration structure" in conf_finding.get("evidence", {}).get("raw", "")

def test_docker_no_secrets_claim(module, monkeypatch):
    yaml_content = "services:\n  web:\n    image: nginx:latest\n"
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/docker-compose.yml": mock_response(200, yaml_content, {"Content-Type": "application/x-yaml"}, url="http://example.com/docker-compose.yml"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))
    findings = module.run("http://example.com", "example.com", MagicMock())
    compose_finding = next((f for f in findings if f["name"] == "Exposed Docker Compose Configuration"), None)
    assert compose_finding is not None
    assert "deployment secrets" not in compose_finding.get("impact", "")
    assert "Requested:" in compose_finding.get("evidence", {}).get("raw", "")
    assert "Validated Compose services structure" in compose_finding.get("evidence", {}).get("raw", "")

def test_env_evidence_format(module, monkeypatch):
    responses = {
        "http://example.com/": mock_response(200, "<html>home</html>" + "A"*500, {"Content-Type": "text/html"}, url="http://example.com/"),
        "http://example.com/.env": mock_response(200, "APP_ENV=production\nDATABASE_URL=mysql://user:pass@host/db", {"Content-Type": "text/plain"}, url="http://example.com/.env"),
    }
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))
    findings = module.run("http://example.com", "example.com", MagicMock())
    env_finding = next((f for f in findings if f["name"] == "Exposed .env Configuration File"), None)
    assert env_finding is not None
    assert "Requested:" in env_finding.get("evidence", {}).get("raw", "")
    assert "Validated environment-variable syntax with a sensitive credential-style key." in env_finding.get("evidence", {}).get("raw", "")
    assert "Values redacted" in env_finding.get("evidence", {}).get("raw", "")


def test_exact_probe_list_and_max_attempts(module, monkeypatch):
    probes = []
    def mock_safe_request(method, url, **kwargs):
        probes.append((url, kwargs.get('max_attempts')))
        return mock_response(404, url=url)

    monkeypatch.setattr('api.scanner.modules.discovery.safe_request', mock_safe_request)
    module.run('http://example.com', 'example.com', MagicMock())

    paths = [p[0].replace('http://example.com', '') for p in probes]

    # Expected exactly 8 requests: 1 for base_url and 7 paths
    assert len(paths) == 8
    assert paths[0] == '/'

    expected_paths = ['/.env', '/api/.env', '/.git/HEAD', '/.git/config', '/docker-compose.yml', '/phpinfo.php', '/admin']
    for ep in expected_paths:
        assert ep in paths

    # Check max_attempts=1 is set for the guessed paths
    for url, max_attempts in probes[1:]:
        assert max_attempts == 1

def test_removed_paths_never_requested(module, monkeypatch):
    probes = []
    def mock_safe_request(method, url, **kwargs):
        probes.append(url.replace('http://example.com', ''))
        return mock_response(404, url=url)

    monkeypatch.setattr('api.scanner.modules.discovery.safe_request', mock_safe_request)
    module.run('http://example.com', 'example.com', MagicMock())

    removed = ['/backend/.env', '/core/.env', '/docker-compose.yaml', '/.DS_Store', '/uploads/', '/images/', '/assets/', '/static/', '/laravel.log', '/error.log', '/app.log', '/debug.log', '/logs/laravel.log', '/backup.zip', '/site.tar.gz', '/db.sql', '/dump.sql', '/backup.sql']

    for r in removed:
        assert r not in probes

def test_admin_interface_strictness(module, monkeypatch):
    responses = {
        'http://example.com/': mock_response(200, '<html>home</html>' + 'A'*500, {'Content-Type': 'text/html'}, url='http://example.com/'),
        'http://example.com/admin': mock_response(200, '<html>password admin login</html>', {'Content-Type': 'text/html'}, url='http://example.com/admin'),
    }
    monkeypatch.setattr('api.scanner.modules.discovery.safe_request', lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))
    findings = module.run('http://example.com', 'example.com', MagicMock())

    f = next((x for x in findings if x['name'] == 'Administrative Interface Observed'), None)
    assert f is not None
    assert f['severity'] == 'Informational'

def test_admin_interface_ignores_spa(module, monkeypatch):
    # Same content as homepage (SPA fallback)
    responses = {
        'http://example.com/': mock_response(200, '<html>home password admin</html>' + 'A'*500, {'Content-Type': 'text/html'}, url='http://example.com/'),
        'http://example.com/admin': mock_response(200, '<html>home password admin</html>' + 'A'*500, {'Content-Type': 'text/html'}, url='http://example.com/admin'),
    }
    monkeypatch.setattr('api.scanner.modules.discovery.safe_request', lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))
    findings = module.run('http://example.com', 'example.com', MagicMock())

    f = next((x for x in findings if x['name'] == 'Administrative Interface Observed'), None)
    assert f is None

def test_phpinfo_detected(module, monkeypatch):
    responses = {
        'http://example.com/': mock_response(200, '<html>home</html>' + 'A'*500, {'Content-Type': 'text/html'}, url='http://example.com/'),
        'http://example.com/phpinfo.php': mock_response(200, '<html><head><title>phpinfo()</title></head><body>Zend Engine</body></html>', {'Content-Type': 'text/html'}, url='http://example.com/phpinfo.php'),
    }
    monkeypatch.setattr('api.scanner.modules.discovery.safe_request', lambda method, url, **kw: responses.get(url, mock_response(404, url=url)))
    findings = module.run('http://example.com', 'example.com', MagicMock())

    f = next((x for x in findings if x['name'] == 'Exposed phpinfo() File'), None)
    assert f is not None
    assert f['severity'] == 'Medium'

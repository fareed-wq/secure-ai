import pytest
from unittest.mock import patch, MagicMock

from api.scanner.modules.network_services import NetworkServiceExposureModule

class TestNetworkServiceExposureModule:

    @pytest.fixture
    def module(self):
        return NetworkServiceExposureModule()

    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_run_ssh_reachable_informational(self, mock_safe_create_connection, module, mock_session):
        def side_effect(address, timeout):
            if address[1] == 22:
                return MagicMock()
            raise OSError("Connection refused")

        mock_safe_create_connection.side_effect = side_effect

        findings = module.run("http://example.com", "example.com", mock_session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding["name"] == "Port 22 Publicly Reachable (SSH-associated)"
        assert finding["severity"] == "Informational"
        assert "TCP port 22, commonly associated with SSH, is publicly reachable. The service itself was not fingerprinted." in finding["evidence"]["raw"]

    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_run_telnet_reachable_medium(self, mock_safe_create_connection, module, mock_session):
        def side_effect(address, timeout):
            if address[1] == 23:
                return MagicMock()
            raise OSError("Connection refused")

        mock_safe_create_connection.side_effect = side_effect

        findings = module.run("http://example.com", "example.com", mock_session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding["name"] == "Port 23 Publicly Reachable (Telnet-associated)"
        assert finding["severity"] == "Medium"
        assert "TCP port 23, commonly associated with Telnet" in finding["evidence"]["raw"]

    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_run_database_reachable_low(self, mock_safe_create_connection, module, mock_session):
        def side_effect(address, timeout):
            if address[1] == 3306:
                return MagicMock()
            raise OSError("Connection refused")

        mock_safe_create_connection.side_effect = side_effect

        findings = module.run("http://example.com", "example.com", mock_session)

        assert len(findings) == 1
        assert findings[0]["name"] == "Database-Associated Port Publicly Reachable"
        assert findings[0]["severity"] == "Low"
        assert "commonly associated with Database" in findings[0]["evidence"]["raw"]

    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_run_closed_refused(self, mock_safe_create_connection, module, mock_session):
        mock_safe_create_connection.side_effect = OSError("Connection refused")

        findings = module.run("http://example.com", "example.com", mock_session)
        assert len(findings) == 0

    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_run_timeout(self, mock_safe_create_connection, module, mock_session):
        import socket
        mock_safe_create_connection.side_effect = socket.timeout("Timed out")

        findings = module.run("http://example.com", "example.com", mock_session)
        assert len(findings) == 0

    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_run_unexpected_exception(self, mock_safe_create_connection, module, mock_session):
        mock_safe_create_connection.side_effect = ValueError("Something unexpected")

        findings = module.run("http://example.com", "example.com", mock_session)
        assert len(findings) == 0

    def test_port_443_not_in_targets(self, module):
        assert 443 not in module.TARGET_PORTS

    @patch('api.scanner.modules.network_services.ThreadPoolExecutor')
    def test_run_concurrency_capped_at_3(self, mock_executor, module, mock_session):
        # We just need to check the call to ThreadPoolExecutor
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance

        # We need to mock submit to return a mock future to avoid errors in as_completed
        mock_future = MagicMock()
        mock_future.result.return_value = None
        mock_executor_instance.submit.return_value = mock_future

        # also patch as_completed since it requires an iterable of futures
        with patch('api.scanner.modules.network_services.as_completed') as mock_as_completed:
            mock_as_completed.return_value = [mock_future] * len(module.TARGET_PORTS)
            module.run("http://example.com", "example.com", mock_session)

        mock_executor.assert_called_with(max_workers=3)

"""Unit tests for client.py"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from argparse import Namespace
import socket

import client


class TestMeasureTTFB:
    """Tests for measure_ttfb function."""

    @patch('client.socket.socket')
    def test_successful_connection(self, mock_socket_class):
        """Test successful TTFB measurement."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.side_effect = [b'H', b'TTP/1.1 200 OK']

        result = client.measure_ttfb('127.0.0.1', 8080, 'GET / HTTP/1.0\r\n\r\n')

        assert result['success'] is True
        assert result['ttfb_ms'] is not None
        assert result['ttfb_ms'] >= 0
        assert result['response_size'] == 15  # 1 + 14 bytes
        mock_sock.connect.assert_called_once_with(('127.0.0.1', 8080))
        mock_sock.sendall.assert_called_once()
        mock_sock.close.assert_called_once()

    @patch('client.socket.socket')
    def test_connection_timeout(self, mock_socket_class):
        """Test timeout handling."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout("Connection timed out")

        result = client.measure_ttfb('127.0.0.1', 8080, 'test')

        assert result['success'] is False
        assert result['ttfb_ms'] is None
        assert 'error' in result
        mock_sock.close.assert_called_once()

    @patch('client.socket.socket')
    def test_connection_refused(self, mock_socket_class):
        """Test connection refused handling."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")

        result = client.measure_ttfb('127.0.0.1', 8080, 'test')

        assert result['success'] is False
        assert result['ttfb_ms'] is None
        assert 'Connection refused' in result['error']

    @patch('client.socket.socket')
    def test_socket_settings(self, mock_socket_class):
        """Test socket is configured correctly."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.side_effect = [b'X', b'']

        client.measure_ttfb('10.0.0.4', 9000, 'msg')

        mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock.settimeout.assert_called_once_with(5.0)

    @patch('client.socket.socket')
    def test_empty_payload(self, mock_socket_class):
        """Test with empty message."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.side_effect = [b'R', b'esponse']

        result = client.measure_ttfb('127.0.0.1', 8080, '')

        assert result['success'] is True
        mock_sock.sendall.assert_called_once_with(b'')


class TestArgumentParsing:
    """Tests for argument parsing in main()."""

    def test_default_values(self):
        """Test default argument values."""
        with patch('sys.argv', ['client.py']):
            with patch('client.run_single_test') as mock_run:
                client.main()
                args = mock_run.call_args[0][0]
                assert args.host == '10.0.0.4'
                assert args.port == 8080
                assert args.mode == 'single'
                assert args.count == 10
                assert args.concurrency == 5

    def test_custom_host_port(self):
        """Test custom host and port."""
        with patch('sys.argv', ['client.py', '--host', '192.168.1.1', '--port', '9999']):
            with patch('client.run_single_test') as mock_run:
                client.main()
                args = mock_run.call_args[0][0]
                assert args.host == '192.168.1.1'
                assert args.port == 9999

    def test_repeated_mode(self):
        """Test repeated mode selection."""
        with patch('sys.argv', ['client.py', '--mode', 'repeated', '--count', '20']):
            with patch('client.run_repeated_tests') as mock_run:
                client.main()
                args = mock_run.call_args[0][0]
                assert args.mode == 'repeated'
                assert args.count == 20

    def test_concurrent_mode(self):
        """Test concurrent mode selection."""
        with patch('sys.argv', ['client.py', '--mode', 'concurrent', '--concurrency', '10']):
            with patch('client.run_concurrent_tests') as mock_run:
                client.main()
                args = mock_run.call_args[0][0]
                assert args.mode == 'concurrent'
                assert args.concurrency == 10

    def test_payload_size_overrides_message(self):
        """Test --payload-size generates message."""
        with patch('sys.argv', ['client.py', '--payload-size', '100']):
            with patch('client.run_single_test') as mock_run:
                client.main()
                args = mock_run.call_args[0][0]
                assert args.message == 'X' * 100
                assert len(args.message) == 100


class TestRunSingleTest:
    """Tests for run_single_test function."""

    @patch('client.measure_ttfb')
    def test_successful_output(self, mock_measure, capsys):
        """Test output on successful connection."""
        mock_measure.return_value = {
            'success': True,
            'ttfb_ms': 25.5,
            'response_size': 100
        }
        args = Namespace(
            host='127.0.0.1', port=8080,
            message='test', payload_size=0
        )

        client.run_single_test(args)
        captured = capsys.readouterr()

        assert 'TTFB: 25.50 ms' in captured.out
        assert 'Success' in captured.out
        assert 'Response size: 100' in captured.out

    @patch('client.measure_ttfb')
    def test_failed_output(self, mock_measure, capsys):
        """Test output on failed connection."""
        mock_measure.return_value = {
            'success': False,
            'ttfb_ms': None,
            'error': 'Connection refused'
        }
        args = Namespace(
            host='127.0.0.1', port=8080,
            message='test', payload_size=0
        )

        client.run_single_test(args)
        captured = capsys.readouterr()

        assert 'Failed' in captured.out
        assert 'Connection refused' in captured.out


class TestRunRepeatedTests:
    """Tests for run_repeated_tests function."""

    @patch('client.measure_ttfb')
    def test_statistics_calculation(self, mock_measure, capsys):
        """Test TTFB statistics are calculated correctly."""
        mock_measure.side_effect = [
            {'success': True, 'ttfb_ms': 10.0, 'response_size': 50},
            {'success': True, 'ttfb_ms': 20.0, 'response_size': 50},
            {'success': True, 'ttfb_ms': 30.0, 'response_size': 50},
        ]
        args = Namespace(
            host='127.0.0.1', port=8080,
            message='test', payload_size=0,
            count=3, delay=0, verbose=False
        )

        client.run_repeated_tests(args)
        captured = capsys.readouterr()

        assert 'Success: 3/3' in captured.out
        assert 'Min:     10.00 ms' in captured.out
        assert 'Max:     30.00 ms' in captured.out
        assert 'Average: 20.00 ms' in captured.out

    @patch('client.measure_ttfb')
    def test_partial_failure(self, mock_measure, capsys):
        """Test handling of partial failures."""
        mock_measure.side_effect = [
            {'success': True, 'ttfb_ms': 15.0, 'response_size': 50},
            {'success': False, 'ttfb_ms': None, 'error': 'timeout'},
            {'success': True, 'ttfb_ms': 25.0, 'response_size': 50},
        ]
        args = Namespace(
            host='127.0.0.1', port=8080,
            message='test', payload_size=0,
            count=3, delay=0, verbose=False
        )

        client.run_repeated_tests(args)
        captured = capsys.readouterr()

        assert 'Success: 2/3' in captured.out
        assert '67%' in captured.out


class TestRunConcurrentTests:
    """Tests for run_concurrent_tests function."""

    @patch('client.measure_ttfb')
    def test_concurrent_execution(self, mock_measure, capsys):
        """Test concurrent connections are executed."""
        mock_measure.return_value = {
            'success': True,
            'ttfb_ms': 20.0,
            'response_size': 100
        }
        args = Namespace(
            host='127.0.0.1', port=8080,
            message='test', payload_size=0,
            concurrency=3
        )

        client.run_concurrent_tests(args)
        captured = capsys.readouterr()

        assert mock_measure.call_count == 3
        assert 'Success: 3/3' in captured.out

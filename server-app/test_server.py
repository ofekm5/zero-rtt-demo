"""Unit tests for server.py"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from argparse import Namespace
import socket

import server


class TestBuildResponse:
    """Tests for build_response function."""

    def test_simple_body(self):
        """Test response with simple body."""
        response = server.build_response("OK")
        assert response == "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"

    def test_empty_body(self):
        """Test response with empty body."""
        response = server.build_response("")
        assert response == "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"

    def test_content_length_matches(self):
        """Test Content-Length header matches actual body length."""
        body = "Hello World!"
        response = server.build_response(body)
        assert f"Content-Length: {len(body)}" in response
        assert response.endswith(body)

    def test_large_body(self):
        """Test response with large body."""
        body = "X" * 1000
        response = server.build_response(body)
        assert "Content-Length: 1000" in response


class TestHandleClient:
    """Tests for handle_client function."""

    def test_basic_response(self):
        """Test basic request/response cycle."""
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b"GET / HTTP/1.0\r\n\r\n"
        addr = ("127.0.0.1", 12345)
        args = Namespace(verbose=False, delay=0, echo=False, response_size=0)

        server.handle_client(mock_conn, addr, args)

        mock_conn.sendall.assert_called_once()
        sent_data = mock_conn.sendall.call_args[0][0]
        assert b"HTTP/1.0 200 OK" in sent_data
        assert b"OK" in sent_data
        mock_conn.close.assert_called_once()

    def test_echo_mode(self):
        """Test echo mode returns client data."""
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b"Hello Server"
        addr = ("127.0.0.1", 12345)
        args = Namespace(verbose=False, delay=0, echo=True, response_size=0)

        server.handle_client(mock_conn, addr, args)

        sent_data = mock_conn.sendall.call_args[0][0].decode()
        assert "Hello Server" in sent_data
        assert "Content-Length: 12" in sent_data

    def test_custom_response_size(self):
        """Test custom response size generates X-filled body."""
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b"request"
        addr = ("127.0.0.1", 12345)
        args = Namespace(verbose=False, delay=0, echo=False, response_size=100)

        server.handle_client(mock_conn, addr, args)

        sent_data = mock_conn.sendall.call_args[0][0].decode()
        assert "Content-Length: 100" in sent_data
        assert "X" * 100 in sent_data

    def test_empty_request_closes_connection(self):
        """Test empty request closes connection without response."""
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b""
        addr = ("127.0.0.1", 12345)
        args = Namespace(verbose=False, delay=0, echo=False, response_size=0)

        server.handle_client(mock_conn, addr, args)

        mock_conn.sendall.assert_not_called()
        mock_conn.close.assert_called_once()

    @patch('server.time.sleep')
    def test_delay_applied(self, mock_sleep):
        """Test delay is applied before response."""
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b"request"
        addr = ("127.0.0.1", 12345)
        args = Namespace(verbose=False, delay=100, echo=False, response_size=0)

        server.handle_client(mock_conn, addr, args)

        mock_sleep.assert_called_once_with(0.1)  # 100ms = 0.1s

    def test_exception_closes_connection(self):
        """Test exception handling closes connection."""
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = Exception("Network error")
        addr = ("127.0.0.1", 12345)
        args = Namespace(verbose=False, delay=0, echo=False, response_size=0)

        server.handle_client(mock_conn, addr, args)

        mock_conn.close.assert_called_once()

    def test_verbose_logging(self, capsys):
        """Test verbose mode prints connection info."""
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b"test data"
        addr = ("192.168.1.100", 54321)
        args = Namespace(verbose=True, delay=0, echo=False, response_size=0)

        server.handle_client(mock_conn, addr, args)
        captured = capsys.readouterr()

        assert "192.168.1.100:54321" in captured.out
        assert "Received 9 bytes" in captured.out
        assert "Sent" in captured.out


class TestArgumentParsing:
    """Tests for argument parsing in main()."""

    def test_default_values(self):
        """Test default argument values."""
        with patch('sys.argv', ['server.py']):
            with patch('server.run_server') as mock_run:
                server.main()
                args = mock_run.call_args[0][0]
                assert args.host == "0.0.0.0"
                assert args.port == 8080
                assert args.delay == 0
                assert args.response_size == 0
                assert args.echo is False
                assert args.verbose is False

    def test_custom_host_port(self):
        """Test custom host and port."""
        with patch('sys.argv', ['server.py', '--host', '127.0.0.1', '--port', '9999']):
            with patch('server.run_server') as mock_run:
                server.main()
                args = mock_run.call_args[0][0]
                assert args.host == "127.0.0.1"
                assert args.port == 9999

    def test_delay_option(self):
        """Test delay option."""
        with patch('sys.argv', ['server.py', '--delay', '500']):
            with patch('server.run_server') as mock_run:
                server.main()
                args = mock_run.call_args[0][0]
                assert args.delay == 500

    def test_response_size_option(self):
        """Test response-size option."""
        with patch('sys.argv', ['server.py', '--response-size', '1024']):
            with patch('server.run_server') as mock_run:
                server.main()
                args = mock_run.call_args[0][0]
                assert args.response_size == 1024

    def test_echo_flag(self):
        """Test echo flag."""
        with patch('sys.argv', ['server.py', '--echo']):
            with patch('server.run_server') as mock_run:
                server.main()
                args = mock_run.call_args[0][0]
                assert args.echo is True

    def test_verbose_flag(self):
        """Test verbose flag."""
        with patch('sys.argv', ['server.py', '--verbose']):
            with patch('server.run_server') as mock_run:
                server.main()
                args = mock_run.call_args[0][0]
                assert args.verbose is True


class TestRunServer:
    """Tests for run_server function."""

    @patch('server.socket.socket')
    def test_socket_setup(self, mock_socket_class):
        """Test socket is configured correctly."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.accept.side_effect = KeyboardInterrupt()
        args = Namespace(host="0.0.0.0", port=8080, delay=0, echo=False)

        server.run_server(args)

        mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        mock_sock.bind.assert_called_once_with(("0.0.0.0", 8080))
        mock_sock.listen.assert_called_once_with(128)
        mock_sock.close.assert_called_once()

    @patch('server.threading.Thread')
    @patch('server.socket.socket')
    def test_accepts_connections(self, mock_socket_class, mock_thread_class):
        """Test server accepts connections and spawns threads."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_conn = MagicMock()
        mock_sock.accept.side_effect = [
            (mock_conn, ("127.0.0.1", 12345)),
            KeyboardInterrupt()
        ]
        mock_thread = MagicMock()
        mock_thread_class.return_value = mock_thread
        args = Namespace(host="0.0.0.0", port=8080, delay=0, echo=False)

        server.run_server(args)

        mock_thread_class.assert_called_once()
        call_kwargs = mock_thread_class.call_args[1]
        assert call_kwargs['target'] == server.handle_client
        assert call_kwargs['daemon'] is True
        mock_thread.start.assert_called_once()

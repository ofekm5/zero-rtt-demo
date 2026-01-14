#!/usr/bin/env python3
"""
Simple TCP server for testing 0-RTT optimization.
Standard socket implementation - no awareness of 0-RTT.
"""

import socket
import threading
import time
import argparse

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
DEFAULT_BODY = "OK"


def build_response(body):
    """Build HTTP-like response."""
    return f"HTTP/1.0 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}"


def handle_client(conn, addr, args):
    """Handle a single client connection.

    Note: Uses single recv() call - expects small requests (<4KB).
    """
    try:
        data = conn.recv(4096)
        if not data:
            return

        if args.verbose:
            print(f"[{addr[0]}:{addr[1]}] Received {len(data)} bytes")

        # Artificial delay for testing
        if args.delay > 0:
            time.sleep(args.delay / 1000.0)

        # Build response
        if args.echo:
            body = data.decode(errors='replace')
        elif args.response_size > 0:
            body = "X" * args.response_size
        else:
            body = DEFAULT_BODY

        response = build_response(body)
        conn.sendall(response.encode())

        if args.verbose:
            print(f"[{addr[0]}:{addr[1]}] Sent {len(response)} bytes")

    except Exception as e:
        if args.verbose:
            print(f"[{addr[0]}:{addr[1]}] Error: {e}")
    finally:
        conn.close()


def run_server(args):
    """Main server loop."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(128)

    print(f"Server listening on {args.host}:{args.port}")
    if args.delay > 0:
        print(f"Response delay: {args.delay} ms")
    if args.echo:
        print("Echo mode: enabled")

    try:
        while True:
            conn, addr = sock.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, args),
                daemon=True
            )
            thread.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="TCP server for 0-RTT testing")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Listen port")
    parser.add_argument("--delay", type=int, default=0,
                        help="Response delay in ms")
    parser.add_argument("--response-size", type=int, default=0,
                        help="Custom response body size (bytes)")
    parser.add_argument("--echo", action="store_true",
                        help="Echo client data instead of fixed response")
    parser.add_argument("--verbose", action="store_true",
                        help="Log connections")

    args = parser.parse_args()
    run_server(args)


if __name__ == "__main__":
    main()

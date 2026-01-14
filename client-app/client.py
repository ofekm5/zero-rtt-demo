#!/usr/bin/env python3
"""
Simple TCP client for testing 0-RTT optimization.
Measures Time-to-First-Byte for various connection scenarios.
"""

import socket
import time
import argparse
import statistics
from concurrent.futures import ThreadPoolExecutor

DEFAULT_HOST = "10.0.0.4"
DEFAULT_PORT = 8080
DEFAULT_MESSAGE = "GET /test HTTP/1.0\r\n\r\n"


def measure_ttfb(host, port, message):
    """Measure Time-to-First-Byte for a single connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)

    try:
        t_start = time.perf_counter()
        sock.connect((host, port))
        sock.sendall(message.encode())
        first_byte = sock.recv(1)
        t_end = time.perf_counter()

        ttfb_ms = (t_end - t_start) * 1000
        rest = sock.recv(4096)
        response_size = len(first_byte) + len(rest)

        return {'ttfb_ms': ttfb_ms, 'success': True, 'response_size': response_size}
    except Exception as e:
        return {'ttfb_ms': None, 'success': False, 'error': str(e)}
    finally:
        sock.close()


def run_single_test(args):
    """Execute single connection test."""
    print(f"=== Single Connection Test ===")
    print(f"Server: {args.host}:{args.port}")
    print(f"Message: {args.message}")
    print()

    result = measure_ttfb(args.host, args.port, args.message)

    if result['success']:
        print(f"Result:")
        print(f"  TTFB: {result['ttfb_ms']:.2f} ms")
        print(f"  Status: Success")
        print(f"  Response size: {result['response_size']} bytes")
    else:
        print(f"Result:")
        print(f"  Status: Failed")
        print(f"  Error: {result['error']}")


def run_repeated_tests(args):
    """Execute repeated sequential connections."""
    print(f"=== Repeated Connection Test ({args.count} connections) ===")
    print(f"Server: {args.host}:{args.port}")
    print()

    results = []
    for i in range(args.count):
        result = measure_ttfb(args.host, args.port, args.message)
        results.append(result)
        if args.verbose and result['success']:
            print(f"  Connection {i+1}: {result['ttfb_ms']:.2f} ms")

    successful = [r for r in results if r['success']]
    success_count = len(successful)

    print()
    print(f"Results:")
    print(f"  Success: {success_count}/{args.count} ({100*success_count/args.count:.0f}%)")

    if successful:
        ttfbs = [r['ttfb_ms'] for r in successful]
        print(f"  TTFB Statistics:")
        print(f"    Min:     {min(ttfbs):.2f} ms")
        print(f"    Max:     {max(ttfbs):.2f} ms")
        print(f"    Average: {statistics.mean(ttfbs):.2f} ms")
        print(f"    Median:  {statistics.median(ttfbs):.2f} ms")
        if len(ttfbs) > 1:
            print(f"    Std Dev: {statistics.stdev(ttfbs):.2f} ms")


def run_concurrent_tests(args):
    """Execute concurrent connections."""
    print(f"=== Concurrent Connection Test ({args.concurrency} concurrent) ===")
    print(f"Server: {args.host}:{args.port}")
    print()

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(measure_ttfb, args.host, args.port, args.message)
            for _ in range(args.concurrency)
        ]
        results = [f.result() for f in futures]

    successful = [r for r in results if r['success']]
    success_count = len(successful)

    print(f"Results:")
    print(f"  Success: {success_count}/{args.concurrency} ({100*success_count/args.concurrency:.0f}%)")

    if successful:
        ttfbs = [r['ttfb_ms'] for r in successful]
        print(f"  TTFB Statistics:")
        print(f"    Min:     {min(ttfbs):.2f} ms")
        print(f"    Max:     {max(ttfbs):.2f} ms")
        print(f"    Average: {statistics.mean(ttfbs):.2f} ms")


def main():
    parser = argparse.ArgumentParser(description="TCP client for 0-RTT testing")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    parser.add_argument("--mode", choices=["single", "repeated", "concurrent"],
                        default="single", help="Test mode")
    parser.add_argument("--count", type=int, default=10,
                        help="Number of connections for repeated mode")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="Concurrent connections for concurrent mode")
    parser.add_argument("--message", default=DEFAULT_MESSAGE,
                        help="Message to send")
    parser.add_argument("--verbose", action="store_true",
                        help="Show per-connection details")

    args = parser.parse_args()

    if args.mode == "single":
        run_single_test(args)
    elif args.mode == "repeated":
        run_repeated_tests(args)
    elif args.mode == "concurrent":
        run_concurrent_tests(args)


if __name__ == "__main__":
    main()

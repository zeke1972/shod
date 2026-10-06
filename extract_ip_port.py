#!/usr/bin/env python3
"""
Script to extract IP/host and port from JSON files (standard JSON or NDJSON/JSONL)
and write them to a file in 'ip:port' format.
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any, Generator, Optional, Tuple


def is_valid_ip_or_host(val: Any) -> bool:
    """Check if value is a non-empty string that looks like a host or IP."""
    if not isinstance(val, str):
        return False
    val = val.strip()
    return bool(val)


def convert_int_to_ip(val: int) -> Optional[str]:
    """Convert integer IP (e.g. Shodan integer representation) to IPv4 string."""
    try:
        return str(ipaddress.IPv4Address(val))
    except Exception:
        return None


def extract_ip_and_port(data: dict) -> Optional[Tuple[str, int]]:
    """
    Extract IP/host and port from a dictionary.
    Prioritizes explicit 'host', then 'ip_str', 'ip', and nested 'http.host'.
    """
    if not isinstance(data, dict):
        return None

    host = None
    # 1. Direct 'host' field
    if is_valid_ip_or_host(data.get("host")):
        host = data["host"].strip()

    # 2. 'ip_str' field (common in Shodan/Censys)
    elif is_valid_ip_or_host(data.get("ip_str")):
        host = data["ip_str"].strip()

    # 3. 'ip' field (string or integer)
    elif is_valid_ip_or_host(data.get("ip")):
        host = data["ip"].strip()
    elif isinstance(data.get("ip"), int):
        host = convert_int_to_ip(data["ip"])

    # 4. Nested 'http.host'
    elif isinstance(data.get("http"), dict) and is_valid_ip_or_host(data["http"].get("host")):
        host = data["http"]["host"].strip()

    # Extract port
    port = data.get("port")
    if port is None and isinstance(data.get("http"), dict):
        port = data["http"].get("port")

    # Validate port
    if host and port is not None:
        try:
            port_num = int(port)
            if 1 <= port_num <= 65535:
                # Strip protocol if present in host (e.g. http:// or https://)
                if "://" in host:
                    host = host.split("://", 1)[1]
                # Strip trailing slash or paths if any
                host = host.split("/", 1)[0]
                # Strip port if host already contains it
                if ":" in host and not host.startswith("["):  # not raw IPv6
                    # Check if it's ipv6 or host:port
                    parts = host.split(":")
                    if len(parts) == 2 and parts[1].isdigit():
                        host = parts[0]
                return host, port_num
        except (ValueError, TypeError):
            pass

    return None


def walk_objects(node: Any) -> Generator[dict, None, None]:
    """Recursively yields dictionaries from arbitrary JSON structures."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk_objects(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk_objects(item)


def parse_file(file_path: Path) -> Generator[str, None, None]:
    """
    Parses a file either as standard JSON or as NDJSON (newline-delimited JSON).
    Yields 'host:port' strings.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        # First, try to read as entire JSON document
        content = f.read()

    # Try parsing full JSON document
    try:
        data = json.loads(content)
        # Traverse any nested dictionaries or lists
        for obj in walk_objects(data):
            res = extract_ip_and_port(obj)
            if res:
                yield f"{res[0]}:{res[1]}"
        return
    except json.JSONDecodeError:
        pass

    # If full JSON parsing fails, parse line-by-line (NDJSON / JSON Lines)
    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                res = extract_ip_and_port(obj)
                if res:
                    yield f"{res[0]}:{res[1]}"
                else:
                    # Check nested objects in this line
                    for nested in walk_objects(obj):
                        res = extract_ip_and_port(nested)
                        if res:
                            yield f"{res[0]}:{res[1]}"
        except json.JSONDecodeError:
            continue


def main():
    parser = argparse.ArgumentParser(
        description="Extract 'host'/'ip' and 'port' from JSON or NDJSON files and format as 'ip:port'."
    )
    parser.add_argument("input_file", help="Path to input JSON / NDJSON file")
    parser.add_argument(
        "output_file",
        nargs="?",
        default="targets.txt",
        help="Path to output text file (default: targets.txt)",
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Do not deduplicate extracted entries",
    )

    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.is_file():
        print(f"Error: Input file '{args.input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output_file)

    seen = set()
    results = []

    for entry in parse_file(input_path):
        if args.no_dedup:
            results.append(entry)
        else:
            if entry not in seen:
                seen.add(entry)
                results.append(entry)

    with open(output_path, "w", encoding="utf-8") as out:
        for item in results:
            out.write(f"{item}\n")

    print(
        f"Successfully extracted {len(results)} endpoint(s) from '{input_path}' to '{output_path}'."
    )


if __name__ == "__main__":
    main()

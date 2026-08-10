from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def _request(base_url: str, path: str, params: dict[str, object], token: str, timeout: float) -> object:
    query = urlencode({key: value for key, value in params.items() if value not in {None, ""}})
    url = f"{base_url.rstrip('/')}{path}{'?' + query if query else ''}"
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers, method="GET")
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only TCPView agent API client")
    parser.add_argument(
        "--base-url",
        default=os.getenv("TCPV_AGENT_URL", "http://127.0.0.1:18092"),
        help="TCPView base URL (env: TCPV_AGENT_URL)",
    )
    parser.add_argument("--token", default=os.getenv("TCPV_AGENT_TOKEN", ""), help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=float, default=15.0)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("capabilities")

    flows = subparsers.add_parser("flows")
    flows.add_argument("--q", default="")
    flows.add_argument("--status", default="")
    flows.add_argument("--source-port", default="")
    flows.add_argument("--since", default="")
    flows.add_argument("--limit", type=int, default=50)

    query = subparsers.add_parser("query")
    query.add_argument("--flow", default="latest")
    query.add_argument("--flow-q", default="")
    query.add_argument("--q", default="")
    query.add_argument("--summary", default="")
    query.add_argument("--cid", default="")
    query.add_argument("--status", default="")
    query.add_argument("--source-port", default="")
    query.add_argument("--since", default="")
    query.add_argument("--until", default="")
    query.add_argument("--direction", default="all")
    query.add_argument("--min-len", type=int)
    query.add_argument("--max-len", type=int)
    query.add_argument("--cursor", default="")
    query.add_argument("--limit", type=int, default=100)
    query.add_argument("--scan-limit", type=int, default=5000)
    query.add_argument("--view", choices=("compact", "analysis", "payload", "full"), default="compact")
    query.add_argument("--payload-bytes", type=int, default=256)
    query.add_argument("--payload-encoding", choices=("hex", "base64"), default="hex")

    event = subparsers.add_parser("event")
    event.add_argument("--flow", required=True)
    event.add_argument("--id", required=True)
    event.add_argument("--view", choices=("compact", "analysis", "payload", "full"), default="full")
    event.add_argument("--payload-bytes", type=int, default=4096)
    event.add_argument("--payload-encoding", choices=("hex", "base64"), default="hex")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    values = vars(args)
    command = values.pop("command")
    base_url = str(values.pop("base_url"))
    token = str(values.pop("token"))
    timeout = float(values.pop("timeout"))
    paths = {
        "capabilities": "/api/agent/v1/capabilities",
        "flows": "/api/agent/v1/flows",
        "query": "/api/agent/v1/query",
        "event": "/api/agent/v1/event",
    }
    try:
        result = _request(base_url, paths[command], values, token, timeout)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        print(f"HTTP {exc.code}: {detail}", file=sys.stderr)
        return 2
    except (OSError, URLError, ValueError, json.JSONDecodeError) as exc:
        print(f"TCPView agent query failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

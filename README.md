# tcpv-mitm-emitter

A standalone emitter service for TCP packet capture events.

It provides a minimal interface for integration projects:
- `init_emitter(...)`
- `tcp_start(...)`
- `tcp_end(...)`
- `emit_lobby_packet(...)`
- `shutdown_emitter()`

No project-specific imports are required.

## Clone

```bash
git clone git@github.com:xiangjing1324/tcpv-mitm-emitter.git
cd tcpv-mitm-emitter
```

## Install

```bash
# local dev install
pip install -r requirements.txt

# recommended for integration projects
pip install -e .
```

## Server Deploy (Quick)

```bash
git clone git@github.com:xiangjing1324/tcpv-mitm-emitter.git
cd tcpv-mitm-emitter
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

If you use this emitter with mitm project:

```bash
cd /path/to/mitm-project
source venv/bin/activate
pip install -e ~/tcpv-mitm-emitter
mitmweb ... --set tcpv=18091 -s master.py
```

## Quick Start

```python
from tcpv_mitm_emitter import init_emitter, tcp_start, tcp_end, emit_lobby_packet, shutdown_emitter

# Start runtime + web viewer + Redis writer
init_emitter(
    bind_host="0.0.0.0",
    bind_port=18091,
    redis_host="127.0.0.1",
    redis_port=6379,
    redis_db=0,
)

# Compatibility style (flow object)
emit_lobby_packet(flow=flow, packet_data=packet_data, from_client=True, msg_idx=0, chunk_idx=0)

# Decoupled style (no flow dependency)
emit_lobby_packet(
    flow=None,
    account="123456789",
    cid="10.0.0.1:50000->1.2.3.4:65010",
    packet_data=packet_data,
    from_client=True,
)

tcp_start(flow=None, account="123456789", cid="10.0.0.1:50000->1.2.3.4:65010")
# ... emit_lobby_packet(...)
tcp_end(flow=None, account="123456789", cid="10.0.0.1:50000->1.2.3.4:65010")
shutdown_emitter()
```

## API Endpoints

When initialized, FastAPI viewer endpoints are exposed on `bind_host:bind_port`:
- `GET /health`
- `GET /accounts`
- `GET /events?account=...`
- `GET /connections?account=...`
- `GET /stats`
- `GET /`

## Notes

- Redis is required.
- `emit_lobby_packet` is a safe no-op before `init_emitter`.
- Payload accepts `bytes`, `bytearray`, or `list[int]`.
- For flow lifecycle sync, use `tcp_start(...)` and `tcp_end(...)` in caller project.
- `clear_lobby_account(...)` is deprecated for new flow-based integrations.

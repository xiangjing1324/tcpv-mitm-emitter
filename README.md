# tcpv-mitm-emitter

A standalone emitter service for TCP packet capture events.

It provides a minimal interface for integration projects:
- `init_emitter(...)`
- `emit_lobby_packet(...)`
- `clear_lobby_account(account)`
- `shutdown_emitter()`

No project-specific imports are required.

## Install

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from tcpv_mitm_emitter import init_emitter, emit_lobby_packet, clear_lobby_account, shutdown_emitter

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

clear_lobby_account("123456789")
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

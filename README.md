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

# Preview-only mode (store first N bytes but keep real packet length in UI)
full_len = len(packet_data)
emit_lobby_packet(
    flow=None,
    account="123456789",
    cid="10.0.0.1:50000->1.2.3.4:65010",
    packet_data=packet_data[:80],
    packet_len=full_len,
    from_client=True,
)

tcp_start(flow=None, account="123456789", cid="10.0.0.1:50000->1.2.3.4:65010")
# ... emit_lobby_packet(...)
tcp_end(flow=None, account="123456789", cid="10.0.0.1:50000->1.2.3.4:65010")
shutdown_emitter()
```

## Viewer Highlight (Simple Guide)

Open the viewer in browser:

```bash
http://127.0.0.1:18091
```

Then use these 4 steps:

1. Select a flow on the left.
2. In `highlight` input, type hex pattern (spaces optional).
3. Choose mode from `Preview Contains (recommended)` first.
4. Pick a color with color picker.

Pattern basics:

- Use `xx` / `??` / `**` as 1-byte wildcard.
- Example: `19 00 00 00 xx 00 00 00 00 xx`
- You can type without spaces: `19000000xx00000000xx`
- Press `Esc` in highlight input to clear quickly.

Multiple rules + per-rule color:

- Split rules by `;` (or new line).
- Add color using `@#RRGGBB`.
- Example:
  - `0a 92@#ffd166; 33 66 00 0b@#8ec5ff`

Mode explanation:

- `Preview *`: match only current preview bytes (fastest, recommended for live analysis).
- `Full *`: match full payload (for deep check). For performance, scan is limited to first `8KB` per packet.

Display notes:

- Right tail now shows packet sequence: `#seq mX/cY`
- `m/c` is kept for compatibility.

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

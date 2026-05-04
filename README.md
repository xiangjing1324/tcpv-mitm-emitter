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

Then use these 5 steps:

1. Select a flow on the left.
2. In `highlight` input, type hex pattern (spaces optional).
3. Choose mode from `Preview Contains (recommended)` first.
4. Pick a color with color picker.
5. Click `Search` or press `Enter` to apply. Typing alone will not start matching.

Pattern basics:

- Use `xx` / `??` / `**` as 1-byte wildcard.
- Example: `19 00 00 00 xx 00 00 00 00 xx`
- You can type without spaces: `19000000xx00000000xx`
- Press `Esc` in highlight input to clear and remove current search quickly.

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
- Search is now manual:
  - `Search`: apply current pattern/mode/color.
  - `Prev` / `Next`: jump through matched packets.
  - `x/y`: current hit / total hit count.
- Filters can be stacked:
  - `Dir All / Req Only / Resp Only`
  - `Min Len`
  - `Max Len`
  - Click `Filter` to apply, `Clear` to reset.
- `展开 智能/开/关`:
  - `智能` (recommended): if current flow contains truncated packets (`len > stored payload`), body expand is auto disabled for easier preview scanning.
  - `开`: always allow expand.
  - `关`: force collapse all packet bodies.

## API Endpoints

When initialized, FastAPI viewer endpoints are exposed on `bind_host:bind_port`:
- `GET /health`
- `GET /accounts`
- `GET /events?account=...`
- `GET /connections?account=...`
- `GET /stats`
- `GET /config`
- `POST /imports?filename=...` with raw request body (`.txt`, `.tcpvflow.jsonl`, `.tcpvflow.jsonl.gz`)
- `GET /flows/export?account=...`
- `POST /flows/save?account=...`
- `GET /archives`
- `POST /archives/replay?name=...`
- `GET /`

## Import / Replay / Save

TCPV can import existing mitm txt captures and its own archive files.

- Existing txt captures are parsed as label/time + hex packet pairs. Supported labels include `请求原包`, `请求`, `请求透传`, `请求原包未发送`, `响应原包`, and `响应`.
- Standard archive files use `.tcpvflow.jsonl.gz`. They keep flow metadata plus packet events with raw/full/display/before payloads.
- `full_pay` keeps the original encrypted packet. `pay` is the display payload, which becomes decrypted beforedump when `TCPV_TERSAFE_ROOT` is configured and decoding succeeds.
- Saved archives default to `~/.tcpv/flows`, or `TCPV_ARCHIVE_DIR` when set.

Useful environment variables:

```bash
export TCPV_ARCHIVE_DIR=~/.tcpv/flows
export TCPV_TERSAFE_ROOT=/Users/jinger/locaTest   # or /root/Hello on server
export TCPV_QUEUE_MAXSIZE=100000
export TCPV_STREAM_MAXLEN=50000                   # 0 disables Redis stream trimming
export TCPV_TTL_SECONDS=86400                     # 0 disables Redis TTL
export TCPV_MAX_EVENTS_IN_MEMORY=50000
export TCPV_EVENTS_FETCH_LIMIT=2000
```

## Notes

- Redis is required.
- `emit_lobby_packet` is a safe no-op before `init_emitter`.
- Payload accepts `bytes`, `bytearray`, or `list[int]`.
- For flow lifecycle sync, use `tcp_start(...)` and `tcp_end(...)` in caller project.
- `clear_lobby_account(...)` is deprecated for new flow-based integrations.

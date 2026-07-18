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
    analysis={"schema": "tersafe.semantic.v1", "mode": "active", "action": "active_modified"},  # optional
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
- `GET /event?account=...&id=...`（旧事件缺少 `analysis` 时本地补算）
- `GET /connections?account=...`
- `GET /reports/deep?account=...&format=json`
- `GET /reports/deep?account=...&format=markdown`
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
- The optional `analysis` object is stored in Redis field `ana`, returned by `/events` and `/event`, and preserved by import/export. Its current schema is `tersafe.semantic.v1`.
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

## Semantic deep report

Event rows prioritize semantic role, state phase, 8091 source sequence/age, actual upload action, exact/semantic-compatible match kind, plaintext/wire length delta, consistency, and response correlation. There is no CSOB candidate-only shadow state: `active_modified` means a changed packet was uploaded, `active_consistent` means all mirrored fields were already equal and the unchanged packet was uploaded, while `active_blocked`/`validation_failed` means the CSOB request was not uploaded. Hex remains available as a drill-down view. Report-code naming follows evidence boundaries:

- `0x010A001B`: parent container.
- `0x011223xx`: dynamic metadata family; the low byte is displayed only as a subtype.
- `0x0102000A`: typed leaf shell, bucketed by the full shape tuple.
- `0x010A0011`: pairing/protection context (observed), not a fixed whitelist claim.
- response codes such as `0x010A0010/24/27/44/57`: described from direction, fields, preceding request, frequency, and burst behavior; unresolved meaning stays explicit.

Known `ob:` T1/T2/T3 fields are accepted as timestamps. Generic four-byte epoch scans are rejected by default; candidates inside ASCII/hash/string slots or across field boundaries are displayed as rejected with a reason. This includes the historical false positive at child `+0x44`, whose bytes are ASCII `dd3b`.

Offline archives can be summarized as JSON and Markdown:

```bash
python -m tcpv_mitm_emitter.shape_summary capture.tcpvflow.jsonl.gz \
  --json capture.deep.json --markdown capture.deep.md
```

The same command accepts the historical `reportcode_matrix.json`. Matrix rows keep their observation counts and old evidence as provenance, but directions, request/response timing, and unknown meanings are not invented.

## Optional viewer login

Set `TCPV_AUTH_PASSWORD` (or compatibility alias `TCPV_PASSWORD`) to protect the web UI and API with a signed login cookie. `TCPV_AUTH_SECRET`, `TCPV_AUTH_MAX_AGE`, and `TCPV_AUTH_COOKIE_SECURE` customize signing, lifetime, and HTTPS-only cookies. If no environment password is set, the runtime may use mitmweb's configured `web_password` when available.

## Notes

- Redis is required.
- `emit_lobby_packet` is a safe no-op before `init_emitter`.
- Payload accepts `bytes`, `bytearray`, or `list[int]`.
- For flow lifecycle sync, use `tcp_start(...)` and `tcp_end(...)` in caller project.
- `clear_lobby_account(...)` is deprecated for new flow-based integrations.

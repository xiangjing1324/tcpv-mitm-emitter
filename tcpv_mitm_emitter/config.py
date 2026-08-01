from __future__ import annotations

import os
from pathlib import Path


def env_int(name: str, default: int, *, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = str(os.getenv(name, "") or "").strip()
    try:
        value = int(raw) if raw else int(default)
    except ValueError:
        value = int(default)
    if min_value is not None:
        value = max(int(min_value), value)
    if max_value is not None:
        value = min(int(max_value), value)
    return value


def archive_dir() -> Path:
    raw = str(os.getenv("TCPV_ARCHIVE_DIR", "") or "").strip()
    if raw:
        path = Path(raw).expanduser()
    else:
        path = Path.home() / ".tcpv" / "flows"
    path.mkdir(parents=True, exist_ok=True)
    return path


def overflow_dir() -> Path:
    raw = str(os.getenv("TCPV_OVERFLOW_DIR", "") or "").strip()
    if raw:
        path = Path(raw).expanduser()
    else:
        path = archive_dir() / "overflow"
    path.mkdir(parents=True, exist_ok=True)
    return path


def runtime_config() -> dict[str, int | bool | str]:
    return {
        "queue_maxsize": env_int("TCPV_QUEUE_MAXSIZE", 100_000, min_value=1),
        # A flow is the retention unit.  Packet-level MAXLEN trimming would
        # leave a syntactically valid but incomplete flow, which is worse than
        # expiring the whole flow after the observation window.
        "stream_maxlen": env_int("TCPV_STREAM_MAXLEN", 0, min_value=0),
        # Web observation data is operator-controlled.  Zero means Redis must
        # not expire a live or closed flow behind the viewer's back.
        "ttl_seconds": env_int("TCPV_TTL_SECONDS", 0, min_value=0),
        "fetch_limit": env_int("TCPV_EVENTS_FETCH_LIMIT", 2_000, min_value=1, max_value=20_000),
        "api_max_limit": env_int("TCPV_API_MAX_LIMIT", 20_000, min_value=100, max_value=100_000),
        # Zero means no client-side packet eviction. Rendering still uses a
        # bounded DOM window, while search/filter operate on the full flow.
        "max_events_in_memory": env_int("TCPV_MAX_EVENTS_IN_MEMORY", 0, min_value=0),
        "archive_dir": str(archive_dir()),
        "overflow_dir": str(overflow_dir()),
        "tersafe_root": str(os.getenv("TCPV_TERSAFE_ROOT", "") or ""),
    }

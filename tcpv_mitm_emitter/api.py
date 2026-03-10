from __future__ import annotations

import html
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

from .web import INDEX_HTML


def create_app(runtime) -> FastAPI:
    app = FastAPI(title="tcpv-mitm-emitter", version="0.1.0")
    app_js_path = Path(__file__).with_name("app.js")

    def render_index_html() -> str:
        accounts = runtime.get_accounts()
        account_options: list[str] = []
        for item in accounts:
            account = str(item.get("account", ""))
            total = int(item.get("total", 0))
            account_options.append(
                f'<option value="{html.escape(account)}">{html.escape(account)} (total={total})</option>'
            )

        events_html = ""
        event_count = 0
        if accounts:
            first_account = str(accounts[0].get("account", ""))
            events, _last_id, _has_more = runtime.get_events(account=first_account, after_id=None, limit=50)
            event_count = len(events)
            blocks: list[str] = []
            for ev in events:
                ts = int(ev.get("ts", 0))
                direction = "->" if int(ev.get("dir", 0)) == 0 else "<-"
                length = int(ev.get("len", 0))
                prefix = html.escape(str(ev.get("pfx", "")))
                cid = html.escape(str(ev.get("cid", "")))
                seq = int(ev.get("seq", 0))
                blocks.append(
                    "<details>"
                    f"<summary>[{ts}] [{direction}] [len={length}] [{prefix}]</summary>"
                    "<div class=\"body\">"
                    f"<div class=\"meta\">cid={cid} seq={seq} (server preloaded)</div>"
                    "</div>"
                    "</details>"
                )
            events_html = "".join(blocks)

        page = INDEX_HTML
        page = page.replace("__ACCOUNT_OPTIONS__", "".join(account_options))
        page = page.replace("__INITIAL_EVENTS__", events_html)
        page = page.replace("__STATUS_BOOT__", f"preload accounts={len(accounts)} events={event_count}")
        page = page.replace("__APP_JS_VERSION__", runtime.instance_id or "dev")
        return page

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return HTMLResponse(
            content=render_index_html(),
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    @app.get("/health")
    def health() -> dict:
        return {
            "ok": True,
            "enabled": runtime.enabled,
            "instance_id": runtime.instance_id,
        }

    @app.get("/accounts")
    def accounts() -> list[dict]:
        return runtime.get_accounts()

    @app.get("/events")
    def events(
        account: str = Query(..., min_length=1),
        after_id: str | None = Query(None),
        limit: int = Query(200, ge=1, le=1000),
    ) -> dict:
        items, last_id, has_more = runtime.get_events(account=account, after_id=after_id, limit=limit)
        return {
            "events": items,
            "last_id": last_id,
            "has_more": has_more,
        }

    @app.get("/connections")
    def connections(
        account: str = Query(..., min_length=1),
        recent: int = Query(2000, ge=1, le=10000),
    ) -> list[dict]:
        return runtime.get_connections(account=account, recent=recent)

    @app.post("/flows/clear")
    def clear_flow(account: str = Query(..., min_length=1)) -> dict:
        runtime.clear_account(account=account)
        return {"ok": True, "account": account}

    @app.get("/instance")
    def instance() -> dict:
        if not runtime.instance_id:
            raise HTTPException(status_code=404, detail="service not enabled")
        return {"instance_id": runtime.instance_id}

    @app.get("/stats")
    def stats() -> dict:
        return runtime.get_stats()

    @app.get("/app.js")
    def app_js() -> PlainTextResponse:
        content = app_js_path.read_text(encoding="utf-8")
        return PlainTextResponse(
            content=content,
            media_type="application/javascript",
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    return app

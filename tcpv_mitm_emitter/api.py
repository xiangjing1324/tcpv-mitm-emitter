from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import parse_qs, quote, unquote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from .web import INDEX_HTML


AUTH_COOKIE_NAME = "tcpv_auth"
AUTH_COOKIE_MAX_AGE = 30 * 24 * 60 * 60


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "") or "").strip().lower()
    return bool(default) if not raw else raw not in {"0", "false", "off", "no"}


def _env_int(name: str, default: int, *, min_value: int | None = None) -> int:
    raw = str(os.getenv(name, "") or "").strip()
    try:
        value = int(raw) if raw else int(default)
    except ValueError:
        value = int(default)
    return max(int(min_value), value) if min_value is not None else value


def _mitmweb_setting(name: str) -> str:
    prefix = f"{name}="
    argv = list(sys.argv or [])
    for item in argv:
        if item.startswith(prefix):
            return item[len(prefix) :].strip()
    for index, item in enumerate(argv[:-1]):
        if item == "--set" and argv[index + 1].startswith(prefix):
            return argv[index + 1][len(prefix) :].strip()
    return ""


def _auth_password() -> str:
    return (
        str(os.getenv("TCPV_AUTH_PASSWORD", "") or "").strip()
        or str(os.getenv("TCPV_PASSWORD", "") or "").strip()
        or _mitmweb_setting("web_password")
    )


def _auth_secret(password: str) -> bytes:
    explicit = str(os.getenv("TCPV_AUTH_SECRET", "") or "").strip()
    return explicit.encode("utf-8") if explicit else hashlib.sha256(f"tcpv-auth-v1:{password}".encode()).digest()


def _make_auth_token(password: str, now: int | None = None) -> str:
    payload = f"{int(now if now is not None else time.time())}:{secrets.token_hex(8)}".encode()
    body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.new(_auth_secret(password), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def _check_auth_token(token: str, password: str, max_age: int) -> bool:
    if not token or "." not in token:
        return False
    body, signature = token.rsplit(".", 1)
    expected = hmac.new(_auth_secret(password), body.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    try:
        issued_at = int(base64.urlsafe_b64decode((body + "=" * (-len(body) % 4)).encode()).decode().split(":", 1)[0])
    except Exception:
        return False
    now = int(time.time())
    return issued_at <= now + 60 and now - issued_at <= max_age


def _safe_next_url(raw: str) -> str:
    value = unquote(str(raw or "")).strip()
    return value if value.startswith("/") and not value.startswith("//") else "/"


def _login_page(*, error: bool, next_url: str) -> str:
    error_html = '<div class="error">密码不正确</div>' if error else ""
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>TCP 查看器登录</title>
<style>:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:22px}}main{{width:min(420px,100%);border:1px solid #30363d;border-radius:8px;background:#161b22;padding:28px;box-shadow:0 20px 70px #0006}}h1{{margin:0 0 8px}}p,label{{color:#8b949e}}label{{display:block;margin:18px 0 8px;font-size:13px;font-weight:700}}input,button{{width:100%;height:44px;border:1px solid #30363d;border-radius:6px;font:inherit}}input{{background:#0d1117;color:#c9d1d9;padding:0 12px}}button{{margin-top:16px;background:#1f6feb;color:white;font-weight:800;cursor:pointer}}.error{{padding:10px 12px;border:1px solid #f8514966;border-radius:6px;background:#f8514922;color:#ffd7d7}}</style>
</head><body><main><h1>TCP 查看器</h1><p>请输入访问密码。登录状态仅保存在本机浏览器。</p>{error_html}
<form method="post" action="/login"><input type="hidden" name="next" value="{html.escape(_safe_next_url(next_url), quote=True)}"><label for="password">访问密码</label><input id="password" name="password" type="password" autocomplete="current-password" autofocus required><button type="submit">登录</button></form></main></body></html>"""


def create_app(runtime) -> FastAPI:
    app = FastAPI(title="tcpv-mitm-emitter", version="0.1.0")
    app_js_path = Path(__file__).with_name("app.js")
    auth_password = _auth_password()
    auth_max_age = _env_int("TCPV_AUTH_MAX_AGE", AUTH_COOKIE_MAX_AGE, min_value=60)
    auth_cookie_secure = _env_bool("TCPV_AUTH_COOKIE_SECURE", False)

    def is_authenticated(request: Request) -> bool:
        return not auth_password or _check_auth_token(
            str(request.cookies.get(AUTH_COOKIE_NAME, "")), auth_password, auth_max_age
        )

    @app.middleware("http")
    async def require_auth(request: Request, call_next):
        if not auth_password or request.url.path in {"/login", "/logout"} or is_authenticated(request):
            return await call_next(request)
        accept = str(request.headers.get("accept", "") or "").lower()
        if request.method == "GET" and ("text/html" in accept or "*/*" in accept):
            target = quote(str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""), safe="")
            return RedirectResponse(url=f"/login?next={target}", status_code=303)
        return JSONResponse({"detail": "authentication required"}, status_code=401)

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
            events, _last_id, _has_more = runtime.get_events(
                account=first_account,
                after_id=None,
                limit=50,
                include_payload=False,
            )
            event_count = len(events)
            blocks: list[str] = []
            for ev in events:
                ts = int(ev.get("ts", 0))
                direction = "->" if int(ev.get("dir", 0)) == 0 else "<-" 
                length = int(ev.get("len", 0))
                prefix = html.escape(str(ev.get("pfx", "")))
                cid = html.escape(str(ev.get("cid", "")))
                summary = html.escape(str(ev.get("summary", "")))
                seq = int(ev.get("seq", 0))
                meta_text = f"{summary} seq={seq} (server preloaded)" if summary else f"cid={cid} seq={seq} (server preloaded)"
                blocks.append(
                    "<details>"
                    f"<summary>[{ts}] [{direction}] [len={length}] [{prefix}]</summary>"
                    "<div class=\"body\">"
                    f"<div class=\"meta\">{meta_text}</div>"
                    "</div>"
                    "</details>"
                )
            events_html = "".join(blocks)

        page = INDEX_HTML
        page = page.replace("__ACCOUNT_OPTIONS__", "".join(account_options))
        page = page.replace("__INITIAL_EVENTS__", events_html)
        page = page.replace("__STATUS_BOOT__", f"preload accounts={len(accounts)} events={event_count}")
        page = page.replace("__APP_JS_VERSION__", runtime.instance_id or "dev")
        page = page.replace("__APP_CONFIG__", json.dumps(runtime.get_config(), ensure_ascii=False))
        return page

    @app.get("/login", response_class=HTMLResponse)
    def login(request: Request, next: str = Query("/", alias="next"), error: str = Query("")):
        if not auth_password or is_authenticated(request):
            return RedirectResponse(url=_safe_next_url(next), status_code=303)
        return HTMLResponse(_login_page(error=bool(error), next_url=next), headers={"Cache-Control": "no-store"})

    @app.post("/login")
    async def login_post(request: Request):
        if not auth_password:
            return RedirectResponse(url="/", status_code=303)
        form = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
        supplied = str((form.get("password") or [""])[0])
        next_url = _safe_next_url(str((form.get("next") or ["/"])[0]))
        if not secrets.compare_digest(supplied, auth_password):
            return RedirectResponse(url=f"/login?error=1&next={quote(next_url, safe='')}", status_code=303)
        response = RedirectResponse(url=next_url, status_code=303)
        response.set_cookie(
            AUTH_COOKIE_NAME,
            _make_auth_token(auth_password),
            max_age=auth_max_age,
            httponly=True,
            secure=auth_cookie_secure,
            samesite="lax",
        )
        return response

    @app.get("/logout")
    def logout():
        response = RedirectResponse(url="/login", status_code=303)
        response.delete_cookie(AUTH_COOKIE_NAME)
        return response

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
        limit: int = Query(200, ge=1, le=100000),
        include_payload: bool = Query(True),
    ) -> dict:
        items, last_id, has_more = runtime.get_events(
            account=account,
            after_id=after_id,
            limit=limit,
            include_payload=include_payload,
        )
        return {
            "events": items,
            "last_id": last_id,
            "has_more": has_more,
        }

    @app.get("/event")
    def event(
        account: str = Query(..., min_length=1),
        id: str = Query(..., min_length=1),
    ) -> dict:
        item = runtime.get_event(account=account, event_id=id)
        if item is None:
            raise HTTPException(status_code=404, detail="event not found")
        return item

    @app.get("/connections")
    def connections(
        account: str = Query(..., min_length=1),
        recent: int = Query(2000, ge=1, le=10000),
    ) -> list[dict]:
        return runtime.get_connections(account=account, recent=recent)

    @app.get("/reports/deep")
    def deep_report(
        account: str = Query(..., min_length=1),
        format: str = Query("json", pattern="^(json|markdown)$"),
    ):
        try:
            summary, markdown = runtime.get_deep_report(account)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        if format == "markdown":
            return PlainTextResponse(content=markdown, media_type="text/markdown; charset=utf-8")
        return summary

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

    @app.get("/config")
    def config() -> dict:
        return runtime.get_config()

    @app.post("/imports")
    async def imports(
        request: Request,
        filename: str = Query("import.txt", min_length=1),
    ) -> dict:
        data = await request.body()
        if not data:
            raise HTTPException(status_code=400, detail="empty import body")
        try:
            return runtime.import_flow_bytes(data, filename)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/flows/export")
    def export_flow(account: str = Query(..., min_length=1)) -> FileResponse:
        try:
            path, _info = runtime.export_flow(account)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return FileResponse(
            path=str(path),
            filename=path.name,
            media_type="application/gzip",
        )

    @app.post("/flows/save")
    def save_flow(account: str = Query(..., min_length=1)) -> dict:
        try:
            return runtime.save_flow(account)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/archives")
    def archives() -> list[dict]:
        return runtime.list_archives()

    @app.post("/archives/replay")
    def replay_archive(name: str = Query(..., min_length=1)) -> dict:
        try:
            return runtime.replay_archive(name)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

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

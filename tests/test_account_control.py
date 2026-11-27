from __future__ import annotations

import os
from pathlib import Path
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from tcpv_mitm_emitter.api import create_app
from tcpv_mitm_emitter.runtime import TcpvRuntime


APP_JS = Path(__file__).resolve().parents[1] / "tcpv_mitm_emitter" / "app.js"


class _ControlRuntime:
    enabled = True
    instance_id = "account-control-test"

    def __init__(self, *, provider: bool = True) -> None:
        self.provider = provider
        self.submissions: list[dict[str, object]] = []

    def get_accounts(self):
        return []

    def get_config(self):
        return {}

    def has_control_provider(self) -> bool:
        return self.provider

    def control_snapshot(self):
        return {
            "schema": "tcpv.account-control.v1",
            "accounts": [{"identity": "alice", "cs2": {}, "gcloud": {}}],
        }

    def control_submit(self, payload):
        self.submissions.append(dict(payload))
        return {"success": True, "status": "queued", "request_id": "req-1"}

    def control_status(self, channel, identity, request_id):
        return {
            "success": True,
            "status": "delivered",
            "channel": channel,
            "identity": identity,
            "request_id": request_id,
        }


class AccountControlTests(unittest.TestCase):
    def test_runtime_forwards_only_to_injected_provider(self) -> None:
        provider = mock.Mock()
        provider.snapshot.return_value = {"accounts": []}
        provider.submit.return_value = {"success": True}
        provider.status.return_value = {"status": "delivered"}
        runtime = TcpvRuntime()
        runtime._control_provider = provider

        self.assertTrue(runtime.has_control_provider())
        self.assertEqual(runtime.control_snapshot(), {"accounts": []})
        self.assertEqual(runtime.control_submit({"profile": "vv"}), {"success": True})
        self.assertEqual(
            runtime.control_status("cs2", "alice", "req-1"),
            {"status": "delivered"},
        )
        provider.submit.assert_called_once_with({"profile": "vv"})
        provider.status.assert_called_once_with("cs2", "alice", "req-1")

    def test_authenticated_control_routes_and_stale_context_payload(self) -> None:
        runtime = _ControlRuntime()
        with mock.patch.dict(os.environ, {"TCPV_AUTH_PASSWORD": "secret"}, clear=True):
            client = TestClient(create_app(runtime))

        denied = client.get(
            "/api/control/v1/accounts",
            headers={"Accept": "application/json"},
        )
        self.assertEqual(denied.status_code, 401)
        login = client.post(
            "/login",
            content="password=secret&next=%2F",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        self.assertEqual(login.status_code, 303)

        snapshot = client.get("/api/control/v1/accounts")
        self.assertEqual(snapshot.status_code, 200)
        self.assertEqual(snapshot.json()["accounts"][0]["identity"], "alice")
        submitted = client.post(
            "/api/control/v1/commands",
            json={
                "channel": "cs2",
                "identity": "alice",
                "profile": "vv",
                "target_token": "token-a",
                "target_account": "1001",
            },
        )
        self.assertEqual(submitted.status_code, 202)
        self.assertEqual(runtime.submissions[0]["target_token"], "token-a")
        status = client.get(
            "/api/control/v1/status",
            params={"channel": "cs2", "identity": "alice", "request_id": "req-1"},
        )
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["status"], "delivered")

    def test_no_provider_means_no_button_config_and_control_api_is_absent(self) -> None:
        runtime = _ControlRuntime(provider=False)
        with mock.patch.dict(os.environ, {"TCPV_AUTH_PASSWORD": "secret"}, clear=True):
            client = TestClient(create_app(runtime))
        client.post(
            "/login",
            content="password=secret&next=%2F",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn('"account_control_enabled": false', page.text)
        self.assertEqual(client.get("/api/control/v1/accounts").status_code, 404)

    def test_provider_without_auth_is_hidden_and_cannot_execute(self) -> None:
        runtime = _ControlRuntime(provider=True)
        with mock.patch.dict(os.environ, {}, clear=True):
            client = TestClient(create_app(runtime))
        page = client.get("/")
        self.assertIn('"account_control_enabled": false', page.text)
        self.assertEqual(client.get("/api/control/v1/accounts").status_code, 503)

    def test_popup_is_lazy_and_does_not_replace_tcpview_layout(self) -> None:
        source = APP_JS.read_text()
        install_start = source.index("function installAccountControlPanel()")
        install_end = source.index("function setAccountControlMessage(")
        install = source[install_start:install_end]
        self.assertIn("TCPV_CONFIG.account_control_enabled !== true", install)
        self.assertIn('document.createElement("dialog")', install)
        self.assertIn("document.body.appendChild(dialog)", install)
        self.assertIn("dialog.showModal()", install)
        self.assertIn("refreshAccountControlPanel()", install)
        self.assertLess(install.index("dialog.showModal()"), install.index("refreshAccountControlPanel()"))
        self.assertIn("window.clearInterval", install)
        self.assertNotIn("api/control/v1", source[:install_start])
        self.assertIn('apiJson("/api/control/v1/accounts")', source)
        self.assertIn('data-account-control-nav aria-label="在线 KeyProxy 账号"', install)
        self.assertIn("state.accountControl.selectedIdentity", source)


if __name__ == "__main__":
    unittest.main()

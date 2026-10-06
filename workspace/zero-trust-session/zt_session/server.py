"""HTTP 服务: 策略 API / 会话生命周期 API / 状态页 / 审计查询。

路由
====
策略 API
  GET  /api/policies                 列全部版本
  GET  /api/policies/latest          当前生效版本
  GET  /api/policies/{v}             指定历史版本
  POST /api/policies                 发布新版本(版本号必须严格递增)

会话
  POST /api/sessions                 登录建会话(绑定基线)
  GET  /api/sessions                 会话清单
  GET  /api/sessions/{id}            会话状态(JSON)
  GET  /sessions/{id}                会话状态页(HTML)
  POST /api/sessions/{id}/signals    风险信号(风险/位置/设备证明/管理员终止)
  POST /api/sessions/{id}/reauth     再认证
  POST /api/sessions/{id}/terminate  终止
  POST /api/sessions/{id}/authorize  逐请求裁决

审计
  GET  /api/sessions/{id}/audit      逐请求裁决审计(哈希链)
  GET  /api/sessions/{id}/events     会话事件流(哈希链)
  POST /api/sessions/{id}/verify     重放校验报告
"""

from __future__ import annotations

import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .defaults import policy_v1
from .models import PolicyDocument, RiskLevel, RiskSignal, SignalType
from .policy import PolicyError, PolicyStore
from .session import SessionError, SessionManager
from .verifier import ReplayEngine


class App:
    def __init__(self, start_time: int | None = None) -> None:
        self.store = PolicyStore()
        t0 = start_time if start_time is not None else int(time.time())
        self.store.publish(policy_v1(t0))
        self.manager = SessionManager(self.store, clock=lambda: int(time.time() * 1000))
        self.replay = ReplayEngine(self.store)


# ---- HTML 状态页 -----------------------------------------------------------

_PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>零信任会话 {sid}</title><meta http-equiv="refresh" content="3">
<style>
 body{{font-family:ui-monospace,Menlo,Consolas,monospace;margin:24px;background:#0f1420;color:#d7e0ee}}
 h1{{font-size:18px}} h2{{font-size:14px;color:#8fb3ff;margin-top:28px}}
 table{{border-collapse:collapse;font-size:12px}}
 td,th{{border:1px solid #2a3550;padding:4px 10px;text-align:left;vertical-align:top}}
 th{{background:#182034;color:#9db4e6}}
 .ACTIVE{{color:#3ddc84;font-weight:bold}} .TERMINATED{{color:#ff5c7a;font-weight:bold}}
 .deny,.terminated,.reauth_required,.stale_request{{color:#ffb457}}
 .allow{{color:#3ddc84}} .muted{{color:#72809a}}
 .pill{{display:inline-block;padding:1px 8px;border-radius:10px;background:#1d2942}}
 pre{{white-space:pre-wrap;font-size:11px;color:#aebbd4}}
</style></head><body>
<h1>会话 <span class="pill">{sid}</span> 状态水位 <span class="pill">{status}</span> rev={rev}</h1>
<table>
 <tr><th>用户</th><td>{user_id} 角色 {roles}</td><th>设备</th><td>{device_id} 证明健康={attest_healthy}</td></tr>
 <tr><th>登录时刻</th><td>{created_at}</td><th>位置</th><td>{loc_ip} trusted={loc_trusted} @ {loc_at}</td></tr>
 <tr><th>基线策略版本</th><td>{bpv}</td><th>当前策略版本</th><td>{cpv} <span class="muted">(升级只对新请求生效)</span></td></tr>
 <tr><th>基线权限</th><td>{baseline}</td><th>最高风险</th><td>{max_risk}</td></tr>
 <tr><th>已撤销</th><td class="deny">{revoked}</td><th>有效权限上限</th><td class="allow">{ceiling}</td></tr>
 <tr><th>再认证门槛</th><td>level≥{gate_lvl} since {gate_since} 已跨越={gate_ok}</td>
     <th>当前认证</th><td>level={auth_lvl} @ {auth_at}</td></tr>
 <tr><th>终止</th><td colspan=3>{term}</td></tr>
</table>
<h2>逐请求裁决审计 ({naudit} 条)</h2>
<table><tr><th>#</th><th>时刻</th><th>资源</th><th>权限</th><th>裁决</th><th>原因</th><th>策略v</th><th>rev</th><th>request_id</th></tr>
{audit_rows}
</table>
<h2>会话事件流 ({nev} 条)</h2>
<table><tr><th>rev</th><th>#</th><th>时刻</th><th>类型</th><th>策略v</th><th>细节</th></tr>
{event_rows}
</table>
<p class="muted">页面每 3 秒自动刷新 · 哈希链: 事件 {ehash} / 裁决 {dhash}</p>
</body></html>"""


def _esc(x: Any) -> str:
    return html.escape(str(x))


def render_state_page(app: App, sid: str) -> str:
    st = app.manager.state(sid)
    audit = app.manager.audit(sid)
    events = app.manager.events(sid)
    audit_rows = "".join(
        f'<tr><td>{a["seq"]}</td><td>{a["at"]}</td><td>{_esc(a["resource"])}</td>'
        f'<td>{_esc(a["permission"])}</td><td class="{a["decision"]}">{a["decision"]}</td>'
        f'<td>{_esc(a["reason"])}</td><td>{a["policy_version"]}</td>'
        f'<td>{a["session_rev"]}</td><td>{_esc(a["request_id"][:12])}</td></tr>'
        for a in audit[::-1]
    ) or '<tr><td colspan=9 class="muted">暂无裁决</td></tr>'
    event_rows = "".join(
        f'<tr><td>{e["rev"]}</td><td>{e["seq"]}</td><td>{e["at"]}</td>'
        f'<td>{_esc(e["kind"])}</td><td>{e["policy_version"]}</td>'
        f'<td><pre>{_esc(json.dumps(e["detail"], ensure_ascii=False))}</pre></td></tr>'
        for e in events[::-1]
    )
    g = st["gate"]
    return _PAGE.format(
        sid=_esc(sid), status=st["status"], rev=st["rev"],
        user_id=_esc(st["user_id"]), roles=_esc(st["roles"]),
        device_id=_esc(st["device_id"]),
        attest_healthy=st["attestation"]["healthy"],
        created_at=st["created_at"], loc_ip=_esc(st["location"]["ip"]),
        loc_trusted=st["location"]["trusted"], loc_at=st["location"]["observed_at"],
        bpv=st["baseline_policy_version"], cpv=st["current_policy_version"],
        baseline=_esc(st["baseline_permissions"]), max_risk=st["max_risk"],
        revoked=_esc(st["revoked_permissions"]) or "∅",
        ceiling=_esc(st["effective_permission_ceiling"]) or "∅",
        gate_lvl=g["required_level"], gate_since=g["since"], gate_ok=g["satisfied"],
        auth_lvl=st["auth"]["level"], auth_at=st["auth"]["at"],
        term=_esc(f'{st["terminated_at"]} {st["terminate_reason"]}')
             if st["status"] == "TERMINATED" else "—",
        naudit=len(audit), audit_rows=audit_rows, nev=len(events),
        event_rows=event_rows,
        ehash=(events[-1]["hash"][:12] if events else "GENESIS"),
        dhash=(audit[-1]["hash"][:12] if audit else "GENESIS"),
    )


# ---- HTTP 处理器 -----------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    app: App  # 由 server 注入(类属性, 每个 serve 实例独立)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _send_json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body: str) -> None:
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        return json.loads(self.rfile.read(n).decode())

    def _err(self, code: int, msg: str) -> None:
        self._send_json(code, {"error": msg})

    # ---- 路由 ----
    def do_GET(self) -> None:  # noqa: N802
        app = self.app
        p = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if p == "/" or p == "/health":
                return self._send_json(200, {"ok": True,
                                             "latest_policy": app.store.latest_version()})
            if p == "/api/policies":
                return self._send_json(200, [d.to_dict() for d in app.store.all_versions()])
            if p == "/api/policies/latest":
                return self._send_json(200, app.store.latest().to_dict())
            if p.startswith("/api/policies/"):
                return self._send_json(200, app.store.get(int(p.rsplit("/", 1)[1])).to_dict())
            if p == "/api/sessions":
                return self._send_json(200, app.manager.list_sessions())
            if p.startswith("/sessions/"):
                sid = p.rsplit("/", 1)[1]
                return self._send_html(render_state_page(app, sid))

            parts = p.split("/")
            # /api/sessions/{id}[/audit|/events]
            if len(parts) >= 4 and parts[1] == "api" and parts[2] == "sessions":
                sid = parts[3]
                if len(parts) == 4:
                    return self._send_json(200, app.manager.state(sid))
                if parts[4] == "audit":
                    return self._send_json(200, app.manager.audit(sid))
                if parts[4] == "events":
                    return self._send_json(200, app.manager.events(sid))
            return self._err(404, f"not found: {p}")
        except (SessionError, PolicyError) as e:
            return self._err(404, str(e))
        except ValueError as e:
            return self._err(400, f"bad request: {e}")

    def do_POST(self) -> None:  # noqa: N802
        app = self.app
        p = urlparse(self.path).path.rstrip("/")
        try:
            body = self._read_json()
            if p == "/api/policies":
                doc = PolicyDocument.from_dict(body)
                return self._send_json(201, app.store.publish(doc).to_dict())

            parts = p.split("/")
            if len(parts) >= 4 and parts[1] == "api" and parts[2] == "sessions":
                sid = parts[3]
                m = app.manager

                if len(parts) == 4:  # 登录在 /api/sessions, 单会话不支持裸 POST
                    return self._err(404, f"not found: {p}")
                action = parts[4]

                if action == "signals":
                    sig = RiskSignal(
                        signal_id=str(body["signal_id"]),
                        session_id=sid,
                        signal_type=SignalType(body["signal_type"]),
                        severity=RiskLevel(body.get("severity", "low")),
                        observed_at=int(body["observed_at"]),
                        payload=body.get("payload", {}),
                    )
                    return self._send_json(200, m.ingest_signal(sig))
                if action == "reauth":
                    return self._send_json(200, m.reauthenticate(
                        sid, level=int(body.get("level", 1)),
                        at=body.get("at"), method=body.get("method", "mfa")))
                if action == "terminate":
                    return self._send_json(200, m.terminate(
                        sid, reason=body.get("reason", "manual_terminate")))
                if action == "authorize":
                    r = m.authorize(
                        sid, resource=str(body["resource"]),
                        permission=str(body["permission"]),
                        request_id=body.get("request_id"))
                    return self._send_json(200, r.to_dict())
                if action == "verify":
                    return self._send_json(200, self._verify(app, sid))
                return self._err(404, f"not found: {p}")

            if p == "/api/sessions":
                return self._send_json(201, app.manager.login(
                    user_id=str(body["user_id"]),
                    roles=tuple(body.get("roles", [])),
                    device_id=str(body["device_id"]),
                    device_healthy=bool(body.get("device_healthy", True)),
                    ip=str(body.get("ip", "0.0.0.0")),
                    auth_level=int(body.get("auth_level", 1)),
                    session_id=body.get("session_id")))
            return self._err(404, f"not found: {p}")
        except (SessionError, PolicyError) as e:
            return self._err(409, str(e))
        except KeyError as e:
            return self._err(400, f"missing field: {e.args[0]}")
        except ValueError as e:
            return self._err(400, f"bad request: {e}")

    @staticmethod
    def _verify(app: App, sid: str) -> dict[str, Any]:
        s = app.manager._get(sid)
        with s.lock:
            report = app.replay.verify_session(list(s.events), list(s.decisions), sid)
        return {
            "ok": report.ok,
            "event_chain_ok": report.event_chain_ok,
            "decision_chain_ok": report.decision_chain_ok,
            "decisions_checked": report.decisions_checked,
            "mismatches": report.mismatches,
            "invariants_violated": report.invariants_violated,
        }


def build_server(host: str = "0.0.0.0", port: int = 8080) -> ThreadingHTTPServer:
    app = App()
    Handler.app = app
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.app = app  # type: ignore[attr-defined]
    return httpd


def serve(host: str = "0.0.0.0", port: int = 8080) -> None:
    httpd = build_server(host, port)
    print(f"零信任会话连续风险评估服务监听 http://{host}:{port}  (策略 v1 已装载)")
    httpd.serve_forever()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    serve(port=port)

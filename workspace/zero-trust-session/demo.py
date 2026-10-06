#!/usr/bin/env python3
"""端到端剧情演示: 登录基线 → 风险收束 → 乱序信号 → 再认证 → 设备证明更新
→ 策略升级 → 并发终止/再认证 → 审计重放校验。

直接以进程内方式调用服务层(无外部依赖), 逐步打印单一水位 rev 的演化。
"""

from __future__ import annotations

import threading

from zt_session.defaults import policy_v1, policy_v2_tighten
from zt_session.models import Decision, RiskLevel, RiskSignal, SignalType
from zt_session.policy import PolicyStore
from zt_session.session import SessionManager
from zt_session.verifier import ReplayEngine


class Clock:
    def __init__(self) -> None:
        self.t = 1_700_000_000_000

    def __call__(self) -> int:
        self.t += 1
        return self.t


def banner(t: str) -> None:
    print("\n" + "=" * 78)
    print("  " + t)
    print("=" * 78)


def show(mgr: SessionManager, sid: str) -> None:
    s = mgr.state(sid)
    print(f"  rev={s['rev']:<3} {s['status']:<10} 最高风险={s['max_risk']:<9} "
          f"已撤销={s['revoked_permissions'] or '∅'}")
    print(f"  门槛 level≥{s['gate']['required_level']} since={s['gate']['since']} "
          f"已跨越={s['gate']['satisfied']}  认证 level={s['auth']['level']}@"
          f"{s['auth']['at']}")
    print(f"  位置={s['location']['ip']} trusted={s['location']['trusted']} "
          f" 设备健康={s['attestation']['healthy']}@obs={s['attestation']['observed_at']}")
    print(f"  有效权限上限={s['effective_permission_ceiling']}  "
          f"基线策略=v{s['baseline_policy_version']} 当前策略=v{s['current_policy_version']}")


def ask(mgr: SessionManager, sid: str, resource: str, perm: str, rid: str) -> None:
    r = mgr.authorize(sid, resource=resource, permission=perm, request_id=rid)
    mark = {"allow": "✅", "deny": "⛔", "reauth_required": "🔑",
            "terminated": "💀", "stale_request": "♻️"}[r.decision.value]
    print(f"  {mark} {rid}: {perm} on {resource} -> {r.decision.value.upper()} "
          f"({r.reason}) [策略v{r.policy_version}, rev {r.session_rev}]")


def main() -> None:
    clock = Clock()
    store = PolicyStore()
    store.publish(policy_v1(clock()))
    mgr = SessionManager(store, clock=clock)

    banner("1. 登录成功 —— 绑定设备证明/网络位置/角色/策略版本 v1 (基线只减不增)")
    sid = mgr.login(
        user_id="alice@corp", roles=("analyst",), device_id="lap-7788",
        device_healthy=True, ip="10.20.30.40", auth_level=1,
        session_id="sess-demo",
    )["session_id"]
    show(mgr, sid)
    ask(mgr, sid, "docs:q3-plan", "write", "req-0001")
    ask(mgr, sid, "reports:fin", "export", "req-0002")

    banner("2. 中风险信号(异常下载行为) —— 收束 write + 升起再认证门槛")
    mgr.ingest_signal(RiskSignal("sig-1", sid, SignalType.RISK, RiskLevel.MEDIUM,
                                 observed_at=clock.t + 500))
    show(mgr, sid)
    ask(mgr, sid, "docs:q3-plan", "write", "req-0003")

    banner("3. 再认证(强 MFA) —— 门槛解除, 但 write 永久撤销, 不会恢复")
    print("  reauth:", mgr.reauthenticate(sid, level=2))
    ask(mgr, sid, "docs:q3-plan", "write", "req-0004")
    ask(mgr, sid, "docs:q3-plan", "read", "req-0005")

    banner("4. 乱序防护 —— 旧位置信号(声称在受信网)不得回退水位")
    # 先到一个新位置: 离开受信网络
    mgr.ingest_signal(RiskSignal("loc-new", sid, SignalType.LOCATION, RiskLevel.MEDIUM,
                                 observed_at=9000, payload={"ip": "203.0.113.66"}))
    show(mgr, sid)
    # 乱序到达的旧观测
    r = mgr.ingest_signal(RiskSignal("loc-old", sid, SignalType.LOCATION, RiskLevel.LOW,
                                     observed_at=8000, payload={"ip": "10.0.0.9"}))
    print("  旧信号受理结果:", r)
    show(mgr, sid)

    banner("5. 设备证明更新 —— 旧健康证明不能把失陷设备刷回健康")
    mgr.reauthenticate(sid, level=2)  # 位置变更升起了新门槛
    mgr.ingest_signal(RiskSignal("att-bad", sid, SignalType.ATTESTATION,
                                 RiskLevel.HIGH, observed_at=9500,
                                 payload={"healthy": False,
                                          "detail": {"reason": "root_detected"}}))
    show(mgr, sid)
    r = mgr.ingest_signal(RiskSignal("att-old", sid, SignalType.ATTESTATION,
                                     RiskLevel.LOW, observed_at=9100,
                                     payload={"healthy": True}))
    print("  旧证明受理结果:", r)
    ask(mgr, sid, "docs:q3-plan", "read", "req-0006")

    banner("6. 策略升级 v2 —— 对新请求生效; 历史裁决封存; 新权限不反向授予老会话")
    # 干净的新会话(无任何风险信号), 专门展示"策略升级"本身的单向收束效果
    sid2 = mgr.login(
        user_id="bob@corp", roles=("analyst",), device_id="lap-9001",
        device_healthy=True, ip="10.20.30.41", auth_level=1,
        session_id="sess-policy-upgrade",
    )["session_id"]
    store.publish(policy_v2_tighten(clock()))
    print("  -- 老会话 alice(基线 v1, 已被风险收束), 新请求按 v2 裁决 --")
    ask(mgr, sid, "docs:q3-plan", "write", "req-0007")  # 风险已撤销 + v2 也收走
    print("  -- 新会话 bob(基线 v1 授予, 但无风险信号): v2 只能收, 不能扩 --")
    ask(mgr, sid2, "docs:q3-plan", "write", "req-1001")      # v1 有, v2 策略收走
    ask(mgr, sid2, "warehouse:raw", "bulk_export", "req-1002")  # v2 新增, 基线没有
    ask(mgr, sid2, "docs:q3-plan", "read", "req-1003")       # 交集内, 仍允许
    print("  -- alice 的 req-0001 重放(幂等, 封存的 v1 裁决原样返回) --")
    ask(mgr, sid, "docs:q3-plan", "write", "req-0001")

    banner("7. 再认证与终止并发 —— 单一会话水位, 终止吸收态恒成立")
    barrier = threading.Barrier(6)

    def kill():
        barrier.wait()
        mgr.terminate(sid, reason="admin:compromised")

    def reauth(i):
        barrier.wait()
        mgr.reauthenticate(sid, level=2)

    def probe(i):
        barrier.wait()
        for _ in range(20):
            mgr.authorize(sid, resource="docs:x", permission="read",
                          request_id=f"probe-{i}-{threading.get_ident()}-{_}")

    ts = [threading.Thread(target=kill)]
    ts += [threading.Thread(target=reauth, args=(i,)) for i in range(2)]
    ts += [threading.Thread(target=probe, args=(i,)) for i in range(3)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    show(mgr, sid)
    ask(mgr, sid, "docs:q3-plan", "read", "req-0009")
    print("  终止后再认证:", mgr.reauthenticate(sid, level=2))

    banner("8. 逐请求裁决审计 —— 哈希链 + 事件重放独立重算")
    s = mgr._get(sid)
    with s.lock:
        report = ReplayEngine(store).verify_session(list(s.events), list(s.decisions), sid)
    print(f"  事件哈希链完整: {report.event_chain_ok}")
    print(f"  裁决哈希链完整: {report.decision_chain_ok}")
    print(f"  重算裁决条数:   {report.decisions_checked}")
    print(f"  裁决重算不一致: {report.mismatches or '无'}")
    print(f"  单调性违例:     {report.invariants_violated or '无'}")
    print(f"  总体校验:       {'通过 ✅' if report.ok else '失败 ❌'}")

    print("\n  最近 8 条裁决审计(已封存 policy_version, 不随升级重判):")
    for a in mgr.audit(sid)[-8:]:
        print(f"    #{a['seq']:<2} {a['decision']:<15} v{a['policy_version']} "
              f"rev={a['session_rev']:<3} {a['permission']:<12} {a['resource']:<14} "
              f"{a['reason']}")

    print("\n状态页: 启动服务后访问 http://localhost:8080/sessions/sess-demo")


if __name__ == "__main__":
    main()

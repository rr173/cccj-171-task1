"""连续风险评估系统的不变量测试。

覆盖:
  T1 基线绑定 + 初始授权
  T2 风险信号单调收束 / 再认证不恢复权限
  T3 乱序信号: 旧位置、旧设备证明无法回退水位
  T4 设备证明更新: 只能变差, 不能"刷回健康"
  T5 再认证门槛水位(迟到再认证、强度不足)
  T6 再认证与终止并发: 单一水位, 终止吸收态恒成立
  T7 策略升级对新请求生效, 历史裁决封存; 升级不能扩权
  T8 审计哈希链 + 重放重算一致
  T9 信号重复投递幂等
"""

from __future__ import annotations

import threading
import unittest

from zt_session.defaults import policy_v1, policy_v2_tighten
from zt_session.models import (
    Decision,
    RiskLevel,
    RiskSignal,
    SignalType,
)
from zt_session.policy import PolicyStore
from zt_session.session import SessionManager
from zt_session.verifier import ReplayEngine


class FakeClock:
    def __init__(self) -> None:
        self.t = 1_000_000  # 毫秒时钟起点; 信号显式 observed_at(5k/9k)早于此,
                            # 默认再认证时刻晚于所有信号, 仅显式传 at 才触发迟到判定
        self.lock = threading.Lock()

    def __call__(self) -> int:
        with self.lock:
            self.t += 1
            return self.t


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.store = PolicyStore()
        self.store.publish(policy_v1(self.clock()))
        self.mgr = SessionManager(self.store, clock=self.clock)
        self.sid = self.mgr.login(
            user_id="alice", roles=("analyst",), device_id="dev-1",
            device_healthy=True, ip="10.1.2.3", auth_level=1,
            session_id="s1",
        )["session_id"]

    def sig(self, sig_id: str, stype: SignalType, severity: RiskLevel = RiskLevel.LOW,
            observed_at: int = 0, payload=None) -> RiskSignal:
        return RiskSignal(
            signal_id=sig_id, session_id=self.sid, signal_type=stype,
            severity=severity, observed_at=observed_at or self.clock(),
            payload=payload or {},
        )

    def authz(self, resource="docs:q3", perm="write", rid=None):
        return self.mgr.authorize(self.sid, resource=resource, permission=perm,
                                  request_id=rid)


class TestBaseline(Base):
    def test_login_binds_baseline(self):
        st = self.mgr.state(self.sid)
        self.assertEqual(st["status"], "ACTIVE")
        self.assertEqual(st["baseline_policy_version"], 1)
        self.assertEqual(st["current_policy_version"], 1)
        self.assertEqual(st["effective_permission_ceiling"], ["export", "read", "write"])
        # 初始请求放行(受信网络内 docs 写)
        r = self.authz()
        self.assertEqual(r.decision, Decision.ALLOW)

    def test_outside_baseline_never_allowed(self):
        r = self.authz(resource="admin:users", perm="manage")
        self.assertEqual(r.decision, Decision.DENY)
        self.assertEqual(r.reason, "permission_not_in_baseline")


class TestMonotonicShrink(Base):
    def test_signal_only_shrinks_and_reauth_never_restores(self):
        # 中风险: 撤销 write + 要求 level>=1
        self.mgr.ingest_signal(self.sig("x1", SignalType.RISK, RiskLevel.MEDIUM, 5000))
        r = self.authz(rid="r1")
        self.assertEqual(r.decision, Decision.REAUTH_REQUIRED)

        # 再认证跨门槛 —— 但 write 仍被撤销, 不恢复
        self.mgr.reauthenticate(self.sid, level=2)
        r = self.authz(rid="r2")
        self.assertEqual(r.decision, Decision.DENY)
        self.assertEqual(r.reason, "permission_revoked_by_risk")
        st = self.mgr.state(self.sid)
        self.assertEqual(st["revoked_permissions"], ["write"])
        self.assertEqual(st["effective_permission_ceiling"], ["export", "read"])

        # read 仍可用
        self.assertEqual(self.authz(perm="read", rid="r3").decision, Decision.ALLOW)

    def test_low_then_high_watermark_only_rises(self):
        self.mgr.ingest_signal(self.sig("l", SignalType.RISK, RiskLevel.LOW, 5000))
        self.mgr.ingest_signal(self.sig("h", SignalType.RISK, RiskLevel.HIGH, 6000))
        st = self.mgr.state(self.sid)
        self.assertEqual(st["max_risk"], "high")
        self.assertEqual(st["revoked_permissions"], ["export", "write"])

    def test_duplicate_signal_is_idempotent(self):
        s = self.sig("dup", SignalType.RISK, RiskLevel.MEDIUM, 5000)
        first = self.mgr.ingest_signal(s)
        second = self.mgr.ingest_signal(s)
        self.assertTrue(first["accepted"])
        self.assertFalse(second["accepted"])
        self.assertEqual(second["reason"], "duplicate_signal")
        # revoke 集合没有重复膨胀
        self.assertEqual(self.mgr.state(self.sid)["revoked_permissions"], ["write"])


class TestOutOfOrder(Base):
    def test_stale_location_ignored(self):
        # 新观测: 离开受信网络 t=9000 -> 撤销 write
        self.mgr.ingest_signal(self.sig(
            "loc-new", SignalType.LOCATION, RiskLevel.MEDIUM, 9000, {"ip": "203.0.113.7"}))
        self.assertEqual(self.authz(rid="a").decision, Decision.REAUTH_REQUIRED)
        self.mgr.reauthenticate(self.sid, level=2)
        self.assertEqual(self.authz(rid="b").decision, Decision.DENY)  # write 已撤

        # 乱序到达的旧位置 t=8000 声称在受信网络 -> 必须被拒绝
        res = self.mgr.ingest_signal(self.sig(
            "loc-old", SignalType.LOCATION, RiskLevel.LOW, 8000, {"ip": "10.0.0.9"}))
        self.assertFalse(res["accepted"])
        self.assertEqual(res["reason"], "stale_location")
        st = self.mgr.state(self.sid)
        self.assertFalse(st["location"]["trusted"])
        self.assertEqual(st["revoked_permissions"], ["write"])  # 旧信号不恢复权限

        # 即使回到受信网络(新观测), 已撤销的 write 也不恢复(格只有 join)
        self.mgr.ingest_signal(self.sig(
            "loc-back", SignalType.LOCATION, RiskLevel.LOW, 9500, {"ip": "10.0.0.9"}))
        self.mgr.reauthenticate(self.sid, level=2)
        self.assertEqual(self.authz(rid="c").decision, Decision.DENY)

    def test_stale_attestation_cannot_restore_health(self):
        # 新证明 t=9000: 设备不健康(高风险撤销 write/export)
        self.mgr.ingest_signal(self.sig(
            "att-bad", SignalType.ATTESTATION, RiskLevel.HIGH, 9000,
            {"healthy": False, "detail": {"reason": "rooted"}}))
        st = self.mgr.state(self.sid)
        self.assertFalse(st["attestation"]["healthy"])

        # 乱序旧证明 t=8000 声称健康 -> 拒绝, 设备不能"刷回健康"
        res = self.mgr.ingest_signal(self.sig(
            "att-old", SignalType.ATTESTATION, RiskLevel.LOW, 8000, {"healthy": True}))
        self.assertFalse(res["accepted"])
        self.assertEqual(res["reason"], "stale_attestation")
        self.assertFalse(self.mgr.state(self.sid)["attestation"]["healthy"])

        # 更新的健康证明 t=9500 可覆盖健康位(资源规则层面), 但已撤销权限不恢复
        self.mgr.ingest_signal(self.sig(
            "att-good", SignalType.ATTESTATION, RiskLevel.LOW, 9500, {"healthy": True}))
        st = self.mgr.state(self.sid)
        self.assertTrue(st["attestation"]["healthy"])
        self.assertEqual(set(st["revoked_permissions"]), {"write", "export"})


class TestReauthWatermark(Base):
    def test_late_reauth_does_not_clear_gate(self):
        self.mgr.ingest_signal(self.sig("m", SignalType.RISK, RiskLevel.MEDIUM, 5000))
        # 再认证时刻早于信号水位 -> 迟到/重放, 门槛保留
        res = self.mgr.reauthenticate(self.sid, level=2, at=4000)
        self.assertFalse(res["accepted"])
        self.assertEqual(res["reason"], "stale_reauth")
        self.assertEqual(self.authz().decision, Decision.REAUTH_REQUIRED)

        # 时刻足够新(晚于门槛受理时刻)才解除
        self.mgr.reauthenticate(self.sid, level=2)
        # write 被撤销: 拒绝原因是 revoked 而非 reauth
        self.assertEqual(self.authz().decision, Decision.DENY)

    def test_insufficient_level_keeps_gate(self):
        self.mgr.ingest_signal(self.sig("h", SignalType.RISK, RiskLevel.HIGH, 7000))
        res = self.mgr.reauthenticate(self.sid, level=1)
        self.assertFalse(res["accepted"])
        self.assertEqual(res["reason"], "insufficient_level")
        self.assertEqual(self.authz(perm="read").decision, Decision.REAUTH_REQUIRED)

    def test_gate_watermark_across_multiple_signals(self):
        self.mgr.ingest_signal(self.sig("m1", SignalType.RISK, RiskLevel.MEDIUM, 5000))
        self.mgr.reauthenticate(self.sid, level=2)
        # 又一个中风险(门槛同级但 since 推进到新的受理时刻): 旧再认证不再算数
        self.mgr.ingest_signal(self.sig("m2", SignalType.RISK, RiskLevel.MEDIUM, 8000))
        r = self.authz(perm="read", rid="z")
        self.assertEqual(r.decision, Decision.REAUTH_REQUIRED)
        self.mgr.reauthenticate(self.sid, level=2)
        self.assertEqual(self.authz(perm="read", rid="z2").decision, Decision.ALLOW)


class TestTerminateConcurrency(Base):
    def test_terminate_is_absorbing(self):
        self.mgr.terminate(self.sid, reason="test")
        # 终止后信号/再认证/请求全部拒绝
        self.assertFalse(self.mgr.ingest_signal(
            self.sig("late", SignalType.RISK, RiskLevel.LOW, 9000))["accepted"])
        self.assertFalse(self.mgr.reauthenticate(self.sid, level=2)["accepted"])
        self.assertEqual(self.authz().decision, Decision.TERMINATED)
        # 重复终止也不改变状态
        self.assertFalse(self.mgr.terminate(self.sid)["accepted"])
        self.assertEqual(self.mgr.state(self.sid)["status"], "TERMINATED")

    def test_critical_signal_terminates(self):
        self.mgr.ingest_signal(self.sig("c", SignalType.RISK, RiskLevel.CRITICAL, 9000))
        self.assertEqual(self.mgr.state(self.sid)["status"], "TERMINATED")
        self.assertEqual(self.authz().decision, Decision.TERMINATED)

    def test_admin_kill_concurrent_with_reauth_single_watermark(self):
        """再认证与终止在多线程下并发, 任何交织后必须满足:
        终止一旦发生, 之后的所有 authorize 恒为 TERMINATED, 状态不会复活。"""
        outcomes: list[str] = []
        barrier = threading.Barrier(8)

        def kill():
            barrier.wait()
            self.mgr.terminate(self.sid, reason="admin_kill")

        def reauth():
            barrier.wait()
            self.mgr.reauthenticate(self.sid, level=2)

        def probe():
            barrier.wait()
            for _ in range(50):
                outcomes.append(self.authz(perm="read").decision.value)

        threads = [threading.Thread(target=kill)]
        threads += [threading.Thread(target=reauth) for _ in range(3)]
        threads += [threading.Thread(target=probe) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 裁决序列一旦出现 terminated, 其后不得出现任何其它裁决(水位不回退)
        seen_terminated = False
        for o in outcomes:
            if seen_terminated:
                self.assertEqual(o, Decision.TERMINATED.value,
                                 "terminated session resurrected under concurrency")
            if o == Decision.TERMINATED.value:
                seen_terminated = True
        self.assertTrue(seen_terminated, "kill must eventually terminate")

        # 终止后 rev 仍在增长(拒绝事件也入链), 但状态恒为终止
        self.assertEqual(self.mgr.state(self.sid)["status"], "TERMINATED")


class TestPolicyUpgrade(Base):
    def test_upgrade_applies_to_new_requests_only_and_cannot_expand(self):
        # v1 下 write 放行(受信网络)
        r1 = self.authz(rid="req-1")
        self.assertEqual((r1.decision, r1.policy_version), (Decision.ALLOW, 1))

        # 发布 v2: analyst 失去 write, 新增 bulk_export
        self.store.publish(policy_v2_tighten(self.clock()))

        # 历史裁决不重判: request_id 幂等返回原封存结果(原策略版本)
        r1b = self.authz(rid="req-1")
        self.assertTrue(r1b.idempotent)
        self.assertEqual((r1b.decision, r1b.policy_version), (Decision.ALLOW, 1))

        # 新请求按 v2 裁决: write 被新策略收走
        r2 = self.authz(rid="req-2")
        self.assertEqual(r2.decision, Decision.DENY)
        self.assertEqual(r2.reason, "permission_removed_by_current_policy")
        self.assertEqual(r2.policy_version, 2)

        # 升级不能扩权: bulk_export 是 v2 新授予但不在会话基线
        r3 = self.mgr.authorize(self.sid, resource="warehouse:m",
                                permission="bulk_export", request_id="req-3")
        self.assertEqual(r3.decision, Decision.DENY)
        self.assertEqual(r3.reason, "permission_not_in_baseline")

        # 审计中两条记录永久保留各自版本
        audit = {a["request_id"]: a for a in self.mgr.audit(self.sid)}
        self.assertEqual(audit["req-1"]["policy_version"], 1)
        self.assertEqual(audit["req-1"]["decision"], "allow")
        self.assertEqual(audit["req-2"]["policy_version"], 2)
        self.assertEqual(audit["req-2"]["decision"], "deny")

    def test_request_id_reuse_conflict_is_stale(self):
        self.authz(rid="same")
        r = self.mgr.authorize(self.sid, resource="docs:x", permission="read",
                               request_id="same")
        self.assertEqual(r.decision, Decision.STALE_REQUEST)


class TestAuditReplay(Base):
    def test_full_scenario_replay_and_hashchains(self):
        # 构造丰富交织: 信号/乱序/再认证/升级/终止
        self.authz(rid="a1", perm="write")
        self.mgr.ingest_signal(self.sig("m", SignalType.RISK, RiskLevel.MEDIUM, 5000))
        self.authz(rid="a2", perm="write")  # reauth_required
        self.mgr.reauthenticate(self.sid, level=2)
        self.authz(rid="a3", perm="write")  # revoked deny
        self.authz(rid="a4", perm="read")   # allow
        self.mgr.ingest_signal(self.sig(
            "loc", SignalType.LOCATION, RiskLevel.MEDIUM, 7000, {"ip": "203.0.113.9"}))
        self.mgr.ingest_signal(self.sig(
            "loc-stale", SignalType.LOCATION, RiskLevel.LOW, 6500, {"ip": "10.0.0.1"}))
        self.store.publish(policy_v2_tighten(self.clock()))
        # 位置变更在受理时升起新门槛 -> 先要求再认证
        self.assertEqual(self.authz(rid="a5a", perm="read").decision,
                         Decision.REAUTH_REQUIRED)
        self.mgr.reauthenticate(self.sid, level=2)
        self.authz(rid="a5", resource="reports:q", perm="read")  # v2: allow(强认证已满足)
        self.mgr.terminate(self.sid, reason="end")
        self.authz(rid="a6", perm="read")   # terminated

        s = self.mgr._get(self.sid)
        with s.lock:
            report = ReplayEngine(self.store).verify_session(
                list(s.events), list(s.decisions), self.sid)
        self.assertTrue(report.event_chain_ok)
        self.assertTrue(report.decision_chain_ok)
        self.assertEqual(report.mismatches, [])
        self.assertEqual(report.invariants_violated, [])
        self.assertEqual(report.decisions_checked, 7)

    def test_tampering_breaks_chain(self):
        self.authz(rid="q")
        s = self.mgr._get(self.sid)
        # 篡改审计记录中的裁决
        bad = list(s.decisions)
        object.__setattr__(bad[0], "decision", Decision.DENY)
        _, decisions_ok = ReplayEngine(self.store).verify_chains(list(s.events), bad)
        self.assertFalse(decisions_ok)

    def test_concurrent_signal_flood_holds_invariants(self):
        """大量中风险信号并发灌入(非终止路径)后, 水位不变量成立且重放一致。"""
        def flood(i):
            for j in range(100):
                try:
                    self.mgr.ingest_signal(RiskSignal(
                        signal_id=f"f-{i}-{j}", session_id=self.sid,
                        signal_type=SignalType.RISK, severity=RiskLevel.MEDIUM,
                        observed_at=10_000 + i * 100 + j))
                except Exception:
                    pass

        ts = [threading.Thread(target=flood, args=(i,)) for i in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        st = self.mgr.state(self.sid)
        self.assertEqual(st["status"], "ACTIVE")
        self.assertEqual(set(st["revoked_permissions"]), {"write"})
        self.assertEqual(st["max_risk"], "medium")
        # 每一步 rev 严格递增且无空洞
        revs = [e["rev"] for e in self.mgr.events(self.sid)]
        self.assertEqual(revs, list(range(1, len(revs) + 1)))
        s = self.mgr._get(self.sid)
        with s.lock:
            report = ReplayEngine(self.store).verify_session(
                list(s.events), list(s.decisions), self.sid)
        self.assertTrue(report.ok, report)

        # 随后的 critical 终终止后, 无论多少并发信号/再认证, 吸收态保持
        self.mgr.ingest_signal(RiskSignal(
            signal_id="fatal", session_id=self.sid, signal_type=SignalType.RISK,
            severity=RiskLevel.CRITICAL, observed_at=99_999))

        def after_kill(i):
            for j in range(50):
                self.mgr.ingest_signal(RiskSignal(
                    signal_id=f"g-{i}-{j}", session_id=self.sid,
                    signal_type=SignalType.RISK, severity=RiskLevel.MEDIUM,
                    observed_at=20_000 + j))
                self.mgr.reauthenticate(self.sid, level=2)

        ts = [threading.Thread(target=after_kill, args=(i,)) for i in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(self.mgr.state(self.sid)["status"], "TERMINATED")
        self.assertEqual(self.authz(perm="read").decision, Decision.TERMINATED)


if __name__ == "__main__":
    unittest.main(verbosity=2)

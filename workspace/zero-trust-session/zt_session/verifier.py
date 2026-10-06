"""审计重放与不变量校验器。

做两件独立的事:
1. 完整性: 重算事件流 / 裁决流的 SHA-256 哈希链, 任何篡改都会断链。
2. 正确性: 仅依据事件补丁(patch)重放会话状态到每个水位 rev, 再用审计记录中
   *封存的 policy_version* 取出当时策略, 重算逐请求裁决 —— 结果必须与封存裁决
   逐字节一致。这同时验证了"策略升级只对新请求生效、历史裁决不重判":
   旧记录永远用旧版本策略重算。
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Decision
from .policy import PolicyStore
from .session import SessionEvent, AuditDecision, _hash


@dataclass
class VerificationReport:
    session_id: str
    event_chain_ok: bool
    decision_chain_ok: bool
    decisions_checked: int
    mismatches: list[str]
    invariants_violated: list[str]

    @property
    def ok(self) -> bool:
        return (
            self.event_chain_ok
            and self.decision_chain_ok
            and not self.mismatches
            and not self.invariants_violated
        )


class ReplayEngine:
    """从只追加事件重建会话状态(不使用实时会话对象)。"""

    def __init__(self, store: PolicyStore) -> None:
        self.store = store

    @staticmethod
    def verify_chains(events: list[SessionEvent],
                      decisions: list[AuditDecision]) -> tuple[bool, bool]:
        prev = "GENESIS"
        events_ok = True
        for e in events:
            payload = {
                "seq": e.seq, "rev": e.rev, "kind": e.kind, "at": e.at,
                "policy_version": e.policy_version, "detail": e.detail,
                "patch": e.patch,
            }
            if e.prev_hash != prev or e.hash != _hash(payload, prev):
                events_ok = False
                break
            prev = e.hash

        prev = "GENESIS"
        decisions_ok = True
        for d in decisions:
            payload = {
                "seq": d.seq, "at": d.at, "session_id": d.session_id,
                "request_id": d.request_id, "resource": d.resource,
                "permission": d.permission, "decision": d.decision.value,
                "reason": d.reason, "policy_version": d.policy_version,
                "baseline_policy_version": d.baseline_policy_version,
                "session_rev": d.session_rev, "idempotent": d.idempotent,
                "state": d.state,
            }
            if d.prev_hash != prev or d.hash != _hash(payload, prev):
                decisions_ok = False
                break
            prev = d.hash
        return events_ok, decisions_ok

    def verify_session(self, events: list[SessionEvent],
                       decisions: list[AuditDecision],
                       session_id: str | None = None) -> VerificationReport:
        sid = session_id or (decisions[0].session_id if decisions else "?")
        events_ok, decisions_ok = self.verify_chains(events, decisions)

        # --- 事件补丁重放, 建立 rev -> 状态快照 ---
        login = next((e for e in events if e.kind == "LOGIN"), None)
        if login is None:
            return VerificationReport(sid or "?", events_ok, decisions_ok, 0,
                                      ["missing LOGIN event"], [])
        baseline = login.detail["baseline"]
        loc0 = login.detail["location"]
        state = {
            "rev": 0, "status": "ACTIVE", "revoked": set(), "max_risk": "none",
            "gate_level": 0, "gate_since": None,
            "auth_level": baseline["auth_level"], "auth_at": baseline["auth_at"],
            "location_trusted": loc0["trusted"], "location_ip": loc0["ip"],
            "location_observed_at": 0,
            "attestation_healthy": baseline["device_attestation_healthy"],
            "attestation_observed_at": 0,
            "terminated_at": None,
        }
        snapshots: dict[int, dict] = {0: dict(state)}

        invariant_violations: list[str] = []
        for e in events:
            state = dict(state)
            state["revoked"] = set(state["revoked"])
            p = e.patch
            before = snapshots[e.rev - 1]

            if p.get("added_revoked"):
                state["revoked"] |= set(p["added_revoked"])
            # 单调检查: 撤销集只增
            if not set(state["revoked"]).issuperset(before["revoked"]):
                invariant_violations.append(f"rev {e.rev}: revoked set shrank")
            if "gate_after" in p:
                gl, gs = p["gate_after"]
                if gl < before["gate_level"]:
                    invariant_violations.append(f"rev {e.rev}: gate level lowered")
                state["gate_level"], state["gate_since"] = gl, gs
            if p.get("max_risk"):
                state["max_risk"] = p["max_risk"]
            if "location" in p:
                state["location_trusted"] = p["location"]["trusted"]
                state["location_ip"] = p["location"]["ip"]
                state["location_observed_at"] = p["location_observed_at"]
            if "attestation_healthy" in p:
                state["attestation_healthy"] = p["attestation_healthy"]
                state["attestation_observed_at"] = p["attestation_observed_at"]
            if e.kind == "REAUTH_ACCEPTED":
                state["auth_level"] = p["auth_level"]
                state["auth_at"] = p["auth_at"]
            if p.get("terminated"):
                state["status"] = "TERMINATED"
                state["terminated_at"] = p["terminated_at"]
            if before["status"] == "TERMINATED" and state["status"] != "TERMINATED":
                invariant_violations.append(f"rev {e.rev}: left terminated absorbing state")
            state["rev"] = e.rev
            snapshots[e.rev] = state

        # --- 用封存策略版本重算每条裁决 ---
        mismatches: list[str] = []
        checked = 0
        for d in decisions:
            if d.idempotent:
                continue
            snap = snapshots.get(d.session_rev)
            if snap is None:
                mismatches.append(f"decision#{d.seq}: no snapshot for rev {d.session_rev}")
                continue
            got_decision, got_reason = self._recompute(baseline, snap, d)
            if got_decision != d.decision.value or got_reason != d.reason:
                mismatches.append(
                    f"decision#{d.seq} req={d.request_id}: recorded "
                    f"{d.decision.value}/{d.reason} replay {got_decision}/{got_reason}"
                )
            checked += 1

        return VerificationReport(
            session_id=sid or "?", event_chain_ok=events_ok,
            decision_chain_ok=decisions_ok, decisions_checked=checked,
            mismatches=mismatches, invariants_violated=invariant_violations,
        )

    def _recompute(self, baseline: dict, snap: dict, d: AuditDecision) -> tuple[str, str]:
        """与 SessionManager._decide 同语义的独立重算实现(交叉验证)。"""
        from .models import RiskLevel

        if snap["status"] == "TERMINATED":
            return Decision.TERMINATED.value, "session_terminated"

        gl, gs = snap["gate_level"], snap["gate_since"]
        if gl > 0:
            if snap["auth_level"] < gl:
                return Decision.REAUTH_REQUIRED.value, f"reauth_required:level>={gl}"
            if gs is not None and snap["auth_at"] < gs:
                return Decision.REAUTH_REQUIRED.value, f"reauth_required:level>={gl}:since>{gs}"

        if d.permission not in baseline["baseline_permissions"]:
            return Decision.DENY.value, "permission_not_in_baseline"
        if d.permission in snap["revoked"]:
            return Decision.DENY.value, "permission_revoked_by_risk"

        policy = self.store.get(d.policy_version)
        policy_perms: set[str] = set()
        for role in baseline["roles"]:
            policy_perms.update(policy.role_permissions.get(role, ()))
        if d.permission not in policy_perms:
            return Decision.DENY.value, "permission_removed_by_current_policy"

        rule = next((r for r in policy.resource_rules if r.matches(d.resource)), None)
        if rule is None:
            return Decision.DENY.value, "no_matching_resource_rule"
        if d.permission not in rule.permissions:
            return Decision.DENY.value, "permission_denied_by_resource_rule"
        if rule.require_roles and not (set(rule.require_roles) & set(baseline["roles"])):
            return Decision.DENY.value, "role_denied_by_resource_rule"
        if rule.require_trusted_network and not snap["location_trusted"]:
            return Decision.DENY.value, "network_untrusted"
        if rule.require_healthy_device and not snap["attestation_healthy"]:
            return Decision.DENY.value, "device_attestation_unhealthy"
        if snap["auth_level"] < rule.min_auth_level:
            return Decision.DENY.value, "auth_level_below_resource_requirement"
        return Decision.ALLOW.value, "allow"

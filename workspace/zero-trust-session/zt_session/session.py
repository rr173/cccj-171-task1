"""会话引擎: 单会话水位 + 单调收束格 + 哈希链审计。

线程模型
========
每个会话自带一把锁, 登录后的全部写操作(风险信号受理 / 设备证明更新 /
再认证 / 终止)与逐请求裁决都在这 *同一把锁* 内完成, 天然串行化为单一全序,
水位版本号 ``rev`` 每次事件单调 +1。因此:

* 信号乱序到达 —— 按类型做"最新值胜出"(位置/证明)或"并集/上界合并"(风险),
  旧信号无法回退水位;
* 再认证与终止并发 —— 锁内二者之一先发生: 终止先到则再认证被拒; 再认证先到
  也只解除"再认证门槛", 绝不能恢复 revoke 集合;
* 设备证明更新 —— 只接受 observed_at 更新的证明, 旧证明无法把设备姿态刷回健康。

状态空间的偏序(只允许沿箭头方向移动):
    revoked:    A ⊆ A'                      (grow-only set)
    gate:       (lvl, since) 按分量取 max   (只升)
    risk:       max                          (只升)
    terminated: False -> True               (吸收态)
    位置/证明:  仅 observed_at 更新者可覆盖 (latest-wins)
    auth:       level 取 max, at 不允许倒流 (再认证只增强)
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .models import (
    AuthContext,
    Decision,
    Directive,
    NetworkLocation,
    PolicyDocument,
    RiskLevel,
    RiskSignal,
    SignalType,
)
from .policy import PolicyStore

Clock = Callable[[], int]


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash(payload: dict[str, Any], prev_hash: str) -> str:
    return hashlib.sha256(prev_hash.encode() + _canonical(payload)).hexdigest()


# ---- 事件 / 审计条目 -------------------------------------------------------

@dataclass(frozen=True)
class SessionEvent:
    """会话事件流中的一条记录(只追加, 哈希链防篡改)。

    patch 携带该事件对状态的增量, 审计重放时按序应用即可重建任意 rev 的状态,
    从而独立验证每条裁决。
    """

    seq: int
    rev: int
    kind: str                    # 见 Session 文档
    at: int
    policy_version: int
    detail: dict[str, Any]
    patch: dict[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "rev": self.rev,
            "kind": self.kind,
            "at": self.at,
            "policy_version": self.policy_version,
            "detail": self.detail,
            "patch": self.patch,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


@dataclass(frozen=True)
class AuditDecision:
    """逐请求裁决审计 —— 永久封存, 不随策略升级重判。"""

    seq: int
    at: int
    session_id: str
    request_id: str
    resource: str
    permission: str
    decision: Decision
    reason: str
    policy_version: int           # 裁决时刻策略版本(点裁决)
    baseline_policy_version: int  # 登录基线策略版本
    session_rev: int
    idempotent: bool
    state: dict[str, Any]         # 裁决时刻状态快照
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["decision"] = self.decision.value
        return d


@dataclass(frozen=True)
class AuthorizationResult:
    decision: Decision
    reason: str
    session_rev: int
    policy_version: int
    effective_permissions: tuple[str, ...]
    audit_seq: int
    idempotent: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "session_rev": self.session_rev,
            "policy_version": self.policy_version,
            "effective_permissions": list(self.effective_permissions),
            "audit_seq": self.audit_seq,
            "idempotent": self.idempotent,
        }


class SessionError(ValueError):
    pass


class _Session:
    """单个会话的全部可变状态; 任何访问都必须持有 self.lock。"""

    def __init__(self, session_id: str, baseline: AuthContext, location: NetworkLocation,
                 policy: PolicyDocument, now: int) -> None:
        self.session_id = session_id
        self.lock = threading.RLock()
        self.baseline = baseline

        # ---- 单调水位状态 ----
        self.status = "ACTIVE"
        self.rev = 0
        self.revoked: set[str] = set()                 # grow-only
        self.max_risk = RiskLevel.NONE
        self.gate_level = 0                            # 再认证门槛水位
        self.gate_since: Optional[int] = None
        self.terminated_at: Optional[int] = None
        self.terminate_reason: Optional[str] = None

        # ---- latest-wins 上下文(仅接受更新的观测) ----
        # 登录绑定的基线位置/证明来自登录握手本身, 没有"信号观测时刻";
        # 水位初始为 0(无外部观测), 此后只接受 observed_at 严格更新的信号。
        self.location = location
        self.location_observed_at = 0
        self.attestation_healthy = baseline.device_attestation_healthy
        self.attestation_observed_at = 0
        self.attestation_detail: dict[str, Any] = {}

        # ---- 认证状态(再认证只增强) ----
        self.auth_level = baseline.auth_level
        self.auth_at = baseline.auth_at

        # ---- 去重 / 幂等 ----
        self.seen_signal_ids: set[str] = set()
        self.max_signal_observed_at: Optional[int] = None
        self.requests: dict[str, AuditDecision] = {}

        # ---- 只追加日志 ----
        self.events: list[SessionEvent] = []
        self.decisions: list[AuditDecision] = []
        self._event_chain = "GENESIS"
        self._decision_chain = "GENESIS"

        self._append_event(
            "LOGIN", now, policy.version,
            detail={"baseline": baseline.to_dict(), "location": location.to_dict()},
            patch={"login": True},
        )

    # ---- 内部工具(调用方持锁) --------------------------------------------

    def _append_event(self, kind: str, at: int, policy_version: int,
                      detail: dict[str, Any], patch: dict[str, Any]) -> SessionEvent:
        seq = len(self.events)
        self.rev += 1
        payload = {
            "seq": seq, "rev": self.rev, "kind": kind, "at": at,
            "policy_version": policy_version, "detail": detail, "patch": patch,
        }
        h = _hash(payload, self._event_chain)
        evt = SessionEvent(
            seq=seq, rev=self.rev, kind=kind, at=at, policy_version=policy_version,
            detail=detail, patch=patch, prev_hash=self._event_chain, hash=h,
        )
        self.events.append(evt)
        self._event_chain = h
        return evt

    def _append_decision(self, at: int, request_id: str, resource: str, permission: str,
                         decision: Decision, reason: str, policy_version: int,
                         idempotent: bool) -> AuditDecision:
        seq = len(self.decisions)
        state = self._state_snapshot_locked()
        payload = {
            "seq": seq, "at": at, "session_id": self.session_id,
            "request_id": request_id, "resource": resource, "permission": permission,
            "decision": decision.value, "reason": reason,
            "policy_version": policy_version,
            "baseline_policy_version": self.baseline.policy_version,
            "session_rev": self.rev, "idempotent": idempotent, "state": state,
        }
        h = _hash(payload, self._decision_chain)
        rec = AuditDecision(
            seq=seq, at=at, session_id=self.session_id, request_id=request_id,
            resource=resource, permission=permission, decision=decision, reason=reason,
            policy_version=policy_version,
            baseline_policy_version=self.baseline.policy_version,
            session_rev=self.rev, idempotent=idempotent, state=state,
            prev_hash=self._decision_chain, hash=h,
        )
        self.decisions.append(rec)
        self._decision_chain = h
        return rec

    def _state_snapshot_locked(self) -> dict[str, Any]:
        return {
            "rev": self.rev,
            "status": self.status,
            "revoked": sorted(self.revoked),
            "max_risk": self.max_risk.value,
            "gate_level": self.gate_level,
            "gate_since": self.gate_since,
            "auth_level": self.auth_level,
            "auth_at": self.auth_at,
            "location_trusted": self.location.trusted,
            "location_ip": self.location.ip,
            "location_observed_at": self.location_observed_at,
            "attestation_healthy": self.attestation_healthy,
            "attestation_observed_at": self.attestation_observed_at,
        }

    def effective_ceiling(self) -> frozenset[str]:
        """基线权限减去累计撤销 —— 任何时刻授权都不可能超过这个上界。"""
        return self.baseline.baseline_permissions - self.revoked

    def gate_satisfied(self) -> bool:
        if self.gate_level == 0:
            return True
        if self.auth_level < self.gate_level:
            return False
        if self.gate_since is not None and self.auth_at < self.gate_since:
            return False
        return True


class SessionManager:
    def __init__(self, policy_store: PolicyStore, clock: Optional[Clock] = None) -> None:
        self.store = policy_store
        self._clock: Clock = clock or _default_clock
        self._sessions: dict[str, _Session] = {}
        self._registry_lock = threading.Lock()

    def now(self) -> int:
        return self._clock()

    def _get(self, session_id: str) -> _Session:
        try:
            return self._sessions[session_id]
        except KeyError:
            raise SessionError(f"unknown session {session_id}") from None

    # ---- 登录: 绑定基线 ---------------------------------------------------

    def login(self, *, user_id: str, roles: tuple[str, ...], device_id: str,
              device_healthy: bool, ip: str, auth_level: int,
              session_id: Optional[str] = None) -> dict[str, Any]:
        """登录成功后建立会话, 绑定设备证明 / 网络位置 / 用户角色 / 初始策略版本。"""
        now = self.now()
        policy = self.store.latest()
        location = self.store.classify_location(policy, ip)
        baseline_perms = self.store.permissions_for_roles(policy, tuple(roles))
        sid = session_id or uuid.uuid4().hex
        baseline = AuthContext(
            user_id=user_id, roles=tuple(roles), device_id=device_id,
            device_attestation_healthy=device_healthy, location=location,
            auth_level=auth_level, auth_at=now, policy_version=policy.version,
            baseline_permissions=baseline_perms,
        )
        s = _Session(sid, baseline, location, policy, now)
        with self._registry_lock:
            if sid in self._sessions:
                raise SessionError(f"session id {sid} already exists")
            self._sessions[sid] = s
        return self.state(sid)

    # ---- 风险信号受理(含设备证明更新 / 位置变更 / 管理员终止) --------------

    def ingest_signal(self, signal: RiskSignal) -> dict[str, Any]:
        s = self._get(signal.session_id)
        if signal.ingested_at is None:
            object.__setattr__(signal, "ingested_at", self.now())
        with s.lock:
            policy = self.store.latest()  # 信号在受理时刻的最新策略下映射

            if s.status == "TERMINATED":
                s._append_event(
                    "SIGNAL_REJECT_TERMINATED", signal.ingested_at, policy.version,
                    detail={"signal": signal.to_dict()}, patch={},
                )
                return {"accepted": False, "reason": "session_terminated", "rev": s.rev}

            if signal.signal_id in s.seen_signal_ids:
                # 重复投递: 记录但绝不二次作用, 水位不变(patch 为空)
                s._append_event(
                    "SIGNAL_DUPLICATE", signal.ingested_at, policy.version,
                    detail={"signal": signal.to_dict()}, patch={},
                )
                return {"accepted": False, "reason": "duplicate_signal", "rev": s.rev}

            delayed = (
                s.max_signal_observed_at is not None
                and signal.observed_at < s.max_signal_observed_at
            )

            # latest-wins 类型: 旧观测直接拒绝, 不能覆盖更新的上下文
            if signal.signal_type is SignalType.LOCATION:
                if signal.observed_at < s.location_observed_at:
                    s._append_event(
                        "SIGNAL_STALE_LOCATION", signal.ingested_at, policy.version,
                        detail={"signal": signal.to_dict(),
                                "current_observed_at": s.location_observed_at}, patch={},
                    )
                    return {"accepted": False, "reason": "stale_location", "rev": s.rev}

            if signal.signal_type is SignalType.ATTESTATION:
                if signal.observed_at < s.attestation_observed_at:
                    s._append_event(
                        "SIGNAL_STALE_ATTESTATION", signal.ingested_at, policy.version,
                        detail={"signal": signal.to_dict(),
                                "current_observed_at": s.attestation_observed_at}, patch={},
                    )
                    return {"accepted": False, "reason": "stale_attestation", "rev": s.rev}

            directive = self.store.directive_for_signal(policy, signal)

            # latest-wins 上下文更新(信任判定按受理时刻策略, 健康判定来自证明载荷)
            context: dict[str, Any] = {}
            if signal.signal_type is SignalType.LOCATION:
                ip = str(signal.payload.get("ip", ""))
                context["location"] = self.store.classify_location(policy, ip)
            elif signal.signal_type is SignalType.ATTESTATION:
                # 健康位必须由新证明显式携带; 缺省视为不健康(绝不允许"无数据=健康")
                context["attestation_healthy"] = bool(signal.payload.get("healthy", False))
                context["attestation_detail"] = dict(signal.payload.get("detail", {}))

            patch = self._apply_directive(s, signal, directive, context)
            patch["delayed_arrival"] = delayed
            s.seen_signal_ids.add(signal.signal_id)
            s.max_signal_observed_at = (
                signal.observed_at if s.max_signal_observed_at is None
                else max(s.max_signal_observed_at, signal.observed_at)
            )
            s._append_event(
                "SIGNAL_ACCEPTED", signal.ingested_at, policy.version,
                detail={"signal": signal.to_dict(), "directive": directive.to_dict(),
                        "delayed_arrival": delayed},
                patch=patch,
            )
            return {"accepted": True, "reason": "applied", "rev": s.rev,
                    "directive": directive.to_dict(), "delayed_arrival": delayed}

    @staticmethod
    def _apply_directive(s: _Session, signal: RiskSignal, d: Directive,
                         context: dict[str, Any]) -> dict[str, Any]:
        """把指令以 *格连接(join)* 方式并入水位 —— 只收不扩的核心所在。"""
        patch: dict[str, Any] = {
            "added_revoked": sorted(d.revoke - s.revoked),
            "gate_before": [s.gate_level, s.gate_since],
        }
        s.revoked |= d.revoke

        # gate: (level, since) 分量取上界。
        # since 取 *服务器受理时刻* 而非信号观测时刻 —— 门槛是在受理时升起的收束
        # 要求, 会话必须在门槛升起 *之后* 完成再认证; 旧登录/旧再认证都不能算数。
        # 受理时刻在会话锁内单调, 故同级新信号也会把 since 向前推(单一水位)。
        ingested = signal.ingested_at
        if d.require_auth_level > s.gate_level:
            s.gate_level = d.require_auth_level
            s.gate_since = ingested
        elif (d.require_auth_level == s.gate_level and d.require_auth_level > 0
              and (s.gate_since is None or (ingested or 0) > s.gate_since)):
            s.gate_since = ingested
        patch["gate_after"] = [s.gate_level, s.gate_since]

        if signal.severity.rank > s.max_risk.rank:
            s.max_risk = signal.severity
            patch["max_risk"] = signal.severity.value

        # latest-wins 上下文: 只有通过时效检查的新观测才能到达这里
        if "location" in context:
            s.location = context["location"]
            s.location_observed_at = signal.observed_at
            patch["location"] = s.location.to_dict()
            patch["location_observed_at"] = signal.observed_at
        if "attestation_healthy" in context:
            s.attestation_healthy = context["attestation_healthy"]
            s.attestation_observed_at = signal.observed_at
            s.attestation_detail = context["attestation_detail"]
            patch["attestation_healthy"] = s.attestation_healthy
            patch["attestation_observed_at"] = signal.observed_at

        # terminate: 吸收态
        if d.terminate and s.status != "TERMINATED":
            s.status = "TERMINATED"
            s.terminated_at = signal.ingested_at
            s.terminate_reason = f"signal:{signal.signal_type.value}:{signal.severity.value}"
            s.max_risk = RiskLevel.TERMINATE
            patch["terminated"] = True
            patch["terminated_at"] = s.terminated_at
            patch["reason"] = s.terminate_reason
        return patch

    # ---- 再认证 -----------------------------------------------------------

    def reauthenticate(self, session_id: str, *, level: int, at: Optional[int] = None,
                       method: str = "mfa") -> dict[str, Any]:
        s = self._get(session_id)
        at = self.now() if at is None else at
        with s.lock:
            policy = self.store.latest()
            if s.status == "TERMINATED":
                s._append_event("REAUTH_REJECT_TERMINATED", at, policy.version,
                                detail={"level": level, "method": method}, patch={})
                return {"accepted": False, "reason": "session_terminated", "rev": s.rev}

            if s.gate_level > 0 and level < s.gate_level:
                # 认证强度不足以跨越门槛: 水位原样保留
                s._append_event("REAUTH_INSUFFICIENT", at, policy.version,
                                detail={"level": level, "required": s.gate_level}, patch={})
                return {"accepted": False, "reason": "insufficient_level",
                        "required_level": s.gate_level, "rev": s.rev}

            if s.gate_since is not None and at < s.gate_since:
                # 迟到/重放的再认证(观测时刻早于门槛水位): 不得解除门槛
                s._append_event("REAUTH_STALE", at, policy.version,
                                detail={"level": level, "at": at,
                                        "gate_since": s.gate_since}, patch={})
                return {"accepted": False, "reason": "stale_reauth",
                        "gate_since": s.gate_since, "rev": s.rev}

            new_level = max(s.auth_level, level)
            new_at = max(s.auth_at, at)
            patch = {"auth_level": new_level, "auth_at": new_at}
            s.auth_level, s.auth_at = new_level, new_at
            s._append_event("REAUTH_ACCEPTED", at, policy.version,
                            detail={"level": level, "method": method,
                                    "gate_satisfied": s.gate_satisfied()}, patch=patch)
            return {"accepted": True, "reason": "reauthenticated", "rev": s.rev,
                    "gate_satisfied": s.gate_satisfied()}

    # ---- 终止(吸收态) -----------------------------------------------------

    def terminate(self, session_id: str, *, reason: str = "manual_terminate",
                  at: Optional[int] = None) -> dict[str, Any]:
        s = self._get(session_id)
        at = self.now() if at is None else at
        with s.lock:
            policy = self.store.latest()
            if s.status == "TERMINATED":
                s._append_event("TERMINATE_DUPLICATE", at, policy.version,
                                detail={"reason": reason}, patch={})
                return {"accepted": False, "reason": "already_terminated", "rev": s.rev}
            s.status = "TERMINATED"
            s.terminated_at = at
            s.terminate_reason = reason
            if RiskLevel.TERMINATE.rank > s.max_risk.rank:
                s.max_risk = RiskLevel.TERMINATE
            s._append_event("TERMINATED", at, policy.version,
                            detail={"reason": reason},
                            patch={"terminated": True, "terminated_at": at,
                                   "reason": reason})
            return {"accepted": True, "reason": "terminated", "rev": s.rev}

    # ---- 逐请求裁决(点裁决) ----------------------------------------------

    def authorize(self, session_id: str, *, resource: str, permission: str,
                  request_id: Optional[str] = None) -> AuthorizationResult:
        s = self._get(session_id)
        request_id = request_id or uuid.uuid4().hex
        with s.lock:
            now = self.now()
            policy = self.store.latest()  # 策略升级对 *新请求* 立即生效

            # 幂等: 同一 request_id 返回原裁决, 且参数必须一致
            if request_id in s.requests:
                prev = s.requests[request_id]
                if prev.resource == resource and prev.permission == permission:
                    return AuthorizationResult(
                        decision=prev.decision, reason=prev.reason,
                        session_rev=s.rev, policy_version=prev.policy_version,
                        effective_permissions=tuple(sorted(s.effective_ceiling())),
                        audit_seq=prev.seq, idempotent=True,
                    )
                rec = s._append_decision(
                    now, request_id, resource, permission,
                    Decision.STALE_REQUEST, "request_id_reused_with_different_arguments",
                    policy.version, idempotent=False,
                )
                return AuthorizationResult(
                    Decision.STALE_REQUEST, rec.reason, s.rev, policy.version,
                    tuple(sorted(s.effective_ceiling())), rec.seq, False,
                )

            decision, reason = self._decide(s, policy, resource, permission)
            rec = s._append_decision(
                now, request_id, resource, permission, decision, reason,
                policy.version, idempotent=False,
            )
            s.requests[request_id] = rec
            return AuthorizationResult(
                decision=decision, reason=reason, session_rev=s.rev,
                policy_version=policy.version,
                effective_permissions=tuple(sorted(s.effective_ceiling())),
                audit_seq=rec.seq, idempotent=False,
            )

    @staticmethod
    def _decide(s: _Session, policy: PolicyDocument, resource: str,
                permission: str) -> tuple[Decision, str]:
        # 1) 终止是吸收态, 优先于一切
        if s.status == "TERMINATED":
            return Decision.TERMINATED, "session_terminated"

        # 2) 再认证门槛未跨越 -> 会话存活但要求再认证(优先于其余收束判定,
        #    使调用方知道"先再认证"; 门槛解除后才暴露最终的允许/永久拒绝)
        if not s.gate_satisfied():
            return Decision.REAUTH_REQUIRED, (
                f"reauth_required:level>={s.gate_level}"
                + (f":since>{s.gate_since}" if s.gate_since is not None else "")
            )

        # 3) 基线外或已撤销的权限: 再认证也无法恢复, 直接拒绝
        if permission not in s.baseline.baseline_permissions:
            return Decision.DENY, "permission_not_in_baseline"
        if permission in s.revoked:
            return Decision.DENY, "permission_revoked_by_risk"

        # 4) 当前策略可能进一步 *收束* 角色权限(策略升级对新请求生效;
        #    与基线取交集, 因此策略永远不能借升级给会话扩权)
        policy_perms: set[str] = set()
        for role in s.baseline.roles:
            policy_perms.update(policy.role_permissions.get(role, ()))
        if permission not in policy_perms:
            return Decision.DENY, "permission_removed_by_current_policy"

        # 5) 资源规则: 首条命中, 无规则默认拒绝
        rule = next((r for r in policy.resource_rules if r.matches(resource)), None)
        if rule is None:
            return Decision.DENY, "no_matching_resource_rule"
        if permission not in rule.permissions:
            return Decision.DENY, "permission_denied_by_resource_rule"
        if rule.require_roles and not (set(rule.require_roles) & set(s.baseline.roles)):
            return Decision.DENY, "role_denied_by_resource_rule"
        if rule.require_trusted_network and not s.location.trusted:
            return Decision.DENY, "network_untrusted"
        if rule.require_healthy_device and not s.attestation_healthy:
            return Decision.DENY, "device_attestation_unhealthy"
        if s.auth_level < rule.min_auth_level:
            return Decision.DENY, "auth_level_below_resource_requirement"

        return Decision.ALLOW, "allow"

    # ---- 观测: 状态页 / 审计 ----------------------------------------------

    def state(self, session_id: str) -> dict[str, Any]:
        s = self._get(session_id)
        with s.lock:
            b = s.baseline
            return {
                "session_id": s.session_id,
                "status": s.status,
                "rev": s.rev,
                "user_id": b.user_id,
                "roles": list(b.roles),
                "device_id": b.device_id,
                "created_at": b.auth_at,
                "baseline_policy_version": b.policy_version,
                "current_policy_version": self.store.latest_version(),
                "baseline_permissions": sorted(b.baseline_permissions),
                "revoked_permissions": sorted(s.revoked),
                "effective_permission_ceiling": sorted(s.effective_ceiling()),
                "max_risk": s.max_risk.value,
                "gate": {
                    "required_level": s.gate_level,
                    "since": s.gate_since,
                    "satisfied": s.gate_satisfied(),
                },
                "auth": {"level": s.auth_level, "at": s.auth_at},
                "location": {
                    **s.location.to_dict(),
                    "observed_at": s.location_observed_at,
                },
                "attestation": {
                    "healthy": s.attestation_healthy,
                    "observed_at": s.attestation_observed_at,
                    **s.attestation_detail,
                },
                "terminated_at": s.terminated_at,
                "terminate_reason": s.terminate_reason,
            }

    def events(self, session_id: str, limit: Optional[int] = None) -> list[dict[str, Any]]:
        s = self._get(session_id)
        with s.lock:
            evts = s.events if limit is None else s.events[-limit:]
            return [e.to_dict() for e in evts]

    def audit(self, session_id: str, limit: Optional[int] = None) -> list[dict[str, Any]]:
        s = self._get(session_id)
        with s.lock:
            recs = s.decisions if limit is None else s.decisions[-limit:]
            return [r.to_dict() for r in recs]

    def list_sessions(self) -> list[str]:
        with self._registry_lock:
            return sorted(self._sessions)


def _default_clock() -> int:
    import time
    return time.time_ns()

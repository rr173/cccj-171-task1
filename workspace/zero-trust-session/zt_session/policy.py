"""策略库: 版本化、只追加发布; 任意时刻只有一个 *最新生效* 版本。

旧版本永不删除 —— 每条逐请求裁决审计都封存 policy_version, 可精确重算。
"""

from __future__ import annotations

import ipaddress
import threading
from typing import Optional

from .models import Directive, NetworkLocation, PolicyDocument, RiskLevel, RiskSignal


class PolicyError(ValueError):
    pass


class PolicyStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: dict[int, PolicyDocument] = {}
        self._latest_version: int = 0

    # ---- 发布与读取 -------------------------------------------------------

    def publish(self, doc: PolicyDocument) -> PolicyDocument:
        """发布新版本。版本号必须严格递增(防止乱序发布把水位往回拉)。"""
        with self._lock:
            if doc.version in self._versions:
                raise PolicyError(f"policy version {doc.version} already exists")
            if doc.version <= self._latest_version:
                raise PolicyError(
                    f"policy version {doc.version} <= latest {self._latest_version}; "
                    "versions are append-only and strictly increasing"
                )
            self._versions[doc.version] = doc
            self._latest_version = doc.version
            return doc

    def latest(self) -> PolicyDocument:
        with self._lock:
            if not self._versions:
                raise PolicyError("no policy published")
            return self._versions[self._latest_version]

    def get(self, version: int) -> PolicyDocument:
        with self._lock:
            try:
                return self._versions[version]
            except KeyError:
                raise PolicyError(f"unknown policy version {version}") from None

    def latest_version(self) -> int:
        return self._latest_version

    def all_versions(self) -> list[PolicyDocument]:
        with self._lock:
            return [self._versions[v] for v in sorted(self._versions)]

    # ---- 登录基线 ---------------------------------------------------------

    def permissions_for_roles(self, policy: PolicyDocument, roles: tuple[str, ...]) -> frozenset[str]:
        """多角色权限取并集 —— 仅用于建立登录基线, 此后会话不再因策略变化扩权。"""
        perms: set[str] = set()
        for role in roles:
            perms.update(policy.role_permissions.get(role, ()))
        return frozenset(perms)

    # ---- 网络位置判定 -----------------------------------------------------

    def classify_location(self, policy: PolicyDocument, ip: str) -> NetworkLocation:
        addr = ipaddress.ip_address(ip)
        for cidr in policy.trusted_cidrs:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return NetworkLocation(ip=ip, trusted=True, cidr=cidr)
        return NetworkLocation(ip=ip, trusted=False)

    # ---- 信号 -> 指令 映射(按受理时刻的最新策略) ---------------------------

    def directive_for_signal(self, policy: PolicyDocument, signal: RiskSignal) -> Directive:
        """把信号翻译成单调指令。映射只在 *当前策略* 下发生, 即"策略升级对新
        信号/新请求生效"; 指令本身天然只收不扩。"""
        if signal.signal_type.value == "admin_kill":
            return Directive(terminate=True)

        if signal.signal_type.value == "location":
            ip = str(signal.payload.get("ip", ""))
            loc = self.classify_location(policy, ip)
            if loc.trusted:
                # 回到受信网络不产生任何 *收束指令*。
                # 注意: 之前在受信网络外被 revoke 的权限不会因此恢复 ——
                # 引擎只对指令做并集, 不存在"反向授权"指令。
                return Directive()
            return Directive(
                revoke=frozenset(policy.untrusted_network_revoke),
                require_auth_level=policy.untrusted_network_auth_level,
                gate_since=signal.observed_at,
            )

        if signal.signal_type.value == "attestation":
            # 设备证明更新的收束效果来自两部分:
            #  a) 证明携带的风险严重度按 risk_actions 映射(与通用风险一致)
            #  b) 设备健康/新鲜度由资源规则 require_healthy_device 在逐请求
            #     裁决时读取 *最新证明* —— 旧证明(observed_at 更小)会被引擎
            #     拒绝, 无法把设备姿态"刷回健康"。
            return self._risk_action(policy, signal.severity, signal.observed_at)

        return self._risk_action(policy, signal.severity, signal.observed_at)

    @staticmethod
    def _risk_action(
        policy: PolicyDocument, severity: RiskLevel, since: int
    ) -> Directive:
        action = policy.risk_actions.get(severity.value)
        if not action:
            return Directive()
        gate_level = int(action.get("require_auth_level", 0))
        return Directive(
            revoke=frozenset(action.get("revoke", ())),
            require_auth_level=gate_level,
            gate_since=since if gate_level > 0 else None,
            terminate=bool(action.get("terminate", False)),
        )

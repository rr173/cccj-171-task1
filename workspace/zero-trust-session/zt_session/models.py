"""领域模型: 策略 / 风险信号 / 裁决指令。

所有对象均为不可变值对象(frozen dataclass), 状态变更只能通过 session 引擎
产生新的状态快照, 避免旁路修改破坏单调水位。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional


class RiskLevel(str, enum.Enum):
    """风险严重度, 数值越大风险越高(水位比较的基础)。"""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    TERMINATE = "terminate"  # 管理员强制终止, 最高水位

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]

    def __lt__(self, other: "RiskLevel") -> bool:  # 便于直接比较水位
        return self.rank < other.rank

    def __le__(self, other: "RiskLevel") -> bool:
        return self.rank <= other.rank

    def __gt__(self, other: "RiskLevel") -> bool:
        return self.rank > other.rank

    def __ge__(self, other: "RiskLevel") -> bool:
        return self.rank >= other.rank


_RISK_RANK = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
    RiskLevel.TERMINATE: 5,
}


class SignalType(str, enum.Enum):
    """风险信号类型。

    RISK        通用风险信号(按当前策略的 risk_actions 映射为指令)
    LOCATION    网络位置变更(携带新位置; 按当前策略重判受信网络)
    ATTESTATION 设备证明更新(携带新证明; 只可能使设备姿态变差/失新鲜)
    ADMIN_KILL  管理员强制终止(无条件 terminate)
    """

    RISK = "risk"
    LOCATION = "location"
    ATTESTATION = "attestation"
    ADMIN_KILL = "admin_kill"


class Decision(str, enum.Enum):
    """逐请求裁决结果。"""

    ALLOW = "allow"
    DENY = "deny"                  # 策略/权限不足
    REAUTH_REQUIRED = "reauth_required"  # 需先再认证(会话不终止)
    TERMINATED = "terminated"      # 会话已终止
    STALE_REQUEST = "stale_request"  # 幂等键重放但参数不一致


@dataclass(frozen=True)
class Directive:
    """信号在 *当前策略* 下映射出的裁决指令。

    指令本身构成一个单调格:
      revoked: 集合只能并(∪), 不能差
      gate:    (auth_level, since) 按分量取上界(max, max)
      terminate: bool 只能 False -> True
    """

    revoke: frozenset[str] = frozenset()
    require_auth_level: int = 0
    gate_since: Optional[int] = None   # 要求再认证发生在此时刻之后
    terminate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "revoke": sorted(self.revoke),
            "require_auth_level": self.require_auth_level,
            "gate_since": self.gate_since,
            "terminate": self.terminate,
        }


@dataclass(frozen=True)
class AuthContext:
    """登录成功时固化的认证上下文(基线锚点)。"""

    user_id: str
    roles: tuple[str, ...]
    device_id: str
    device_attestation_healthy: bool
    location: "NetworkLocation"
    auth_level: int                       # 登录时的认证强度 0/1/2
    auth_at: int
    policy_version: int                   # 基线策略版本
    baseline_permissions: frozenset[str]  # 登录裁决授予的权限(此后只减不增)

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "roles": list(self.roles),
            "device_id": self.device_id,
            "device_attestation_healthy": self.device_attestation_healthy,
            "location": self.location.to_dict(),
            "auth_level": self.auth_level,
            "auth_at": self.auth_at,
            "policy_version": self.policy_version,
            "baseline_permissions": sorted(self.baseline_permissions),
        }


@dataclass(frozen=True)
class NetworkLocation:
    ip: str
    trusted: bool
    cidr: Optional[str] = None  # 命中的受信网段, 便于审计

    def to_dict(self) -> dict[str, Any]:
        return {"ip": self.ip, "trusted": self.trusted, "cidr": self.cidr}


@dataclass(frozen=True)
class RiskSignal:
    """一个风险信号。observed_at 为信号源观测时刻(乱序判定依据),
    ingested_at 由服务端在受理时加盖。"""

    signal_id: str
    session_id: str
    signal_type: SignalType
    severity: RiskLevel
    observed_at: int
    payload: dict[str, Any] = field(default_factory=dict)
    ingested_at: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "session_id": self.session_id,
            "signal_type": self.signal_type.value,
            "severity": self.severity.value,
            "observed_at": self.observed_at,
            "payload": self.payload,
            "ingested_at": self.ingested_at,
        }


@dataclass(frozen=True)
class ResourceRule:
    """资源规则, 按顺序匹配, 首条命中生效。"""

    resource: str                       # 精确资源名或以 * 结尾的前缀, 如 "doc:*"
    permissions: tuple[str, ...] = ()   # 命中后允许的权限子集; 空表示拒绝全部
    require_roles: tuple[str, ...] = ()
    require_trusted_network: bool = False
    require_healthy_device: bool = False
    min_auth_level: int = 0

    def matches(self, resource: str) -> bool:
        if self.resource.endswith("*"):
            return resource.startswith(self.resource[:-1])
        return resource == self.resource

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ResourceRule":
        return cls(
            resource=d["resource"],
            permissions=tuple(d.get("permissions", ())),
            require_roles=tuple(d.get("require_roles", ())),
            require_trusted_network=bool(d.get("require_trusted_network", False)),
            require_healthy_device=bool(d.get("require_healthy_device", False)),
            min_auth_level=int(d.get("min_auth_level", 0)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "permissions": list(self.permissions),
            "require_roles": list(self.require_roles),
            "require_trusted_network": self.require_trusted_network,
            "require_healthy_device": self.require_healthy_device,
            "min_auth_level": self.min_auth_level,
        }


@dataclass(frozen=True)
class PolicyDocument:
    """不可变策略版本。新版本发布后旧版本永久保留(供历史裁决追溯与重算)。"""

    version: int
    published_at: int
    note: str
    role_permissions: dict[str, tuple[str, ...]]
    resource_rules: tuple[ResourceRule, ...]
    # 风险严重度 -> 动作: {"revoke": [...], "require_auth_level": n, "terminate": bool}
    risk_actions: dict[str, dict[str, Any]]
    trusted_cidrs: tuple[str, ...] = ()
    # 离开受信网络时收束的权限 / 要求的认证强度
    untrusted_network_revoke: tuple[str, ...] = ()
    untrusted_network_auth_level: int = 0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyDocument":
        return cls(
            version=int(d["version"]),
            published_at=int(d["published_at"]),
            note=d.get("note", ""),
            role_permissions={
                k: tuple(v) for k, v in d["role_permissions"].items()
            },
            resource_rules=tuple(ResourceRule.from_dict(r) for r in d.get("resource_rules", ())),
            risk_actions={k: dict(v) for k, v in d.get("risk_actions", {}).items()},
            trusted_cidrs=tuple(d.get("trusted_cidrs", ())),
            untrusted_network_revoke=tuple(d.get("untrusted_network_revoke", ())),
            untrusted_network_auth_level=int(d.get("untrusted_network_auth_level", 0)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "published_at": self.published_at,
            "note": self.note,
            "role_permissions": {k: list(v) for k, v in self.role_permissions.items()},
            "resource_rules": [r.to_dict() for r in self.resource_rules],
            "risk_actions": self.risk_actions,
            "trusted_cidrs": list(self.trusted_cidrs),
            "untrusted_network_revoke": list(self.untrusted_network_revoke),
            "untrusted_network_auth_level": self.untrusted_network_auth_level,
        }

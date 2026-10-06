"""出厂策略 v1 与演示用升级版本。"""

from __future__ import annotations

from .models import PolicyDocument, ResourceRule


def policy_v1(now: int) -> PolicyDocument:
    return PolicyDocument(
        version=1,
        published_at=now,
        note="出厂基线: 风险信号只收不扩; 中风险收写权限, 高风险收导出, 危急终止",
        role_permissions={
            "analyst": ("read", "write", "export"),
            "auditor": ("read", "export"),
            "admin": ("read", "write", "export", "manage"),
        },
        resource_rules=(
            ResourceRule(resource="docs:*", permissions=("read", "write"),
                         require_trusted_network=True),
            ResourceRule(resource="reports:*", permissions=("read", "export"),
                         min_auth_level=1),
            ResourceRule(resource="admin:*", permissions=("manage", "read"),
                         require_roles=("admin",), min_auth_level=2,
                         require_trusted_network=True, require_healthy_device=True),
        ),
        risk_actions={
            "low": {"require_auth_level": 0},
            "medium": {"revoke": ["write"], "require_auth_level": 1},
            "high": {"revoke": ["write", "export"], "require_auth_level": 2},
            "critical": {"terminate": True},
        },
        trusted_cidrs=("10.0.0.0/8", "192.168.0.0/16"),
        untrusted_network_revoke=("write",),
        untrusted_network_auth_level=1,
    )


def policy_v2_tighten(now: int) -> PolicyDocument:
    """升级演示: 收束 analyst 的写权限(新请求立即生效), 同时策略里 *新增* 了
    analyst 的 bulk_export 权限 —— 但会话基线里没有该权限, 逐请求裁决会以
    "基线 ∩ 当前策略" 收口, 证明"策略升级不能静默扩大原授权"。"""
    return PolicyDocument(
        version=2,
        published_at=now,
        note="升级: analyst 移除写权限、新增 bulk_export(老会话拿不到); 导出要求强认证",
        role_permissions={
            "analyst": ("read", "export", "bulk_export"),  # write 收走, bulk_export 新增
            "auditor": ("read", "export"),
            "admin": ("read", "write", "export", "manage"),
        },
        resource_rules=(
            ResourceRule(resource="docs:*", permissions=("read", "write"),
                         require_trusted_network=True),
            ResourceRule(resource="reports:*", permissions=("read", "export"),
                         min_auth_level=2),
            ResourceRule(resource="warehouse:*", permissions=("bulk_export",),
                         require_trusted_network=True, min_auth_level=2),
            ResourceRule(resource="admin:*", permissions=("manage", "read"),
                         require_roles=("admin",), min_auth_level=2,
                         require_trusted_network=True, require_healthy_device=True),
        ),
        risk_actions={
            "low": {"require_auth_level": 0},
            "medium": {"revoke": ["write", "export"], "require_auth_level": 2},
            "high": {"revoke": ["write", "export"], "require_auth_level": 2},
            "critical": {"terminate": True},
        },
        trusted_cidrs=("10.0.0.0/8", "192.168.0.0/16"),
        untrusted_network_revoke=("write", "export"),
        untrusted_network_auth_level=2,
    )

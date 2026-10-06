"""零信任访问会话 —— 连续风险评估系统。

核心不变量（任何代码路径都不得破坏）:
1. 单调收束: 会话建立后, 后续风险信号只能 *收束* 权限(revoke 集合只增)、
   *提高* 再认证门槛(gate 水位只升)或 *终止* 会话; 任何信号都不能把权限恢复到
   基线之上。
2. 单一会话水位: 同一会话的所有事件(信号 / 设备证明更新 / 再认证 / 终止)在同一把
   会话锁内串行裁决, 形成单一水位(rev)。旧信号(observed_at 落后)、重复信号、
   迟到的再认证都不能回退水位。
3. 策略版本点裁决: 每个请求按 *裁决时刻* 已发布的最新策略版本计算, 策略升级只对
   新请求生效; 已执行(裁决)的操作连同当时的 policy_version 永久封存, 不重判。
4. 终止吸收态: TERMINATED 是吸收态, 此后一切请求/信号/再认证均被拒绝,
   包括与终止并发到达的再认证。
"""

from .models import (
    AuthContext,
    Decision,
    Directive,
    NetworkLocation,
    PolicyDocument,
    ResourceRule,
    RiskLevel,
    RiskSignal,
    SignalType,
)
from .policy import PolicyStore
from .session import SessionManager, AuthorizationResult

__all__ = [
    "AuthContext",
    "Decision",
    "Directive",
    "NetworkLocation",
    "PolicyDocument",
    "ResourceRule",
    "RiskLevel",
    "RiskSignal",
    "SignalType",
    "PolicyStore",
    "SessionManager",
    "AuthorizationResult",
]

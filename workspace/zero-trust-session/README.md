# 零信任访问会话 · 连续风险评估系统

登录成功后, 会话与**设备证明、网络位置、用户角色、初始策略版本**绑定形成授权基线;
此后连续到达的风险信号只能**收束权限 / 要求再认证 / 终止会话**, 不能静默扩大原授权。
所有事件(信号乱序、设备证明更新、再认证、终止)在会话锁内串行裁决, 形成**单一水位**;
策略升级只对新请求生效, 已执行操作保留当时裁决; 全部逐请求裁决写入哈希链审计并可独立重放校验。

零第三方依赖, Python 3.10+ 标准库实现。

## 架构

```
zt_session/
  models.py    不可变领域模型: 策略文档/资源规则/风险信号/裁决指令(Directive 单调格)
  policy.py    版本化策略库(只追加发布) + 信号→指令映射 + 受信网络判定
  session.py   会话引擎: 单会话锁 + 水位 rev + 单调收束格 + 哈希链事件/裁决日志
  verifier.py  审计重放器: 哈希链完整性 + 补丁重放状态 + 用封存策略版本重算裁决
  defaults.py  出厂策略 v1 / 收束升级 v2
  server.py    HTTP: 策略 API + 会话 API + 状态页(HTML) + 审计/校验 API
demo.py        端到端剧情演示(乱序/设备/升级/并发终止/审计重放)
tests/         18 项不变量测试(含多线程水位压测)
```

## 核心不变量(被测试与重放器强制)

| 不变量 | 实现机制 |
|---|---|
| 权限只减不增 | `revoked` 为 grow-only set; 有效授权 = `基线权限 − revoked`, 且与当前策略取交集 |
| 再认证门槛只升 | `gate=(level, since)` 分量取上界; 再认证只解除门槛, **永不恢复 revoked** |
| 终止为吸收态 | `TERMINATED` 后一切信号/再认证/请求拒绝, 状态不可复活 |
| 单一会话水位 | 每会话一把锁, 全部写操作串行, `rev` 严格 +1 无空洞 |
| 旧信号不回退水位 | 位置/设备证明按 `observed_at` latest-wins, 旧观测直接拒绝; 风险指令只做格 join; 信号 ID 去重 |
| 旧证明不能刷回健康 | 设备证明 `observed_at` 必须更新; 健康位必须显式携带(缺省=不健康) |
| 迟到再认证无效 | 门槛在**受理时刻**升起, 再认证必须晚于该时刻; 强度不足也被拒 |
| 策略升级不扩权 | 新策略角色权限与**登录基线**取交集; v2 新增权限老会话拿不到 |
| 历史裁决不重判 | 每条裁决封存 `policy_version`; `request_id` 幂等返回原裁决 |
| 审计不可篡改 | 事件流/裁决流双 SHA-256 哈希链; 重放器仅靠补丁重建状态并重算每条裁决 |

裁决优先级: `TERMINATED` → `REAUTH_REQUIRED(门槛)` → `基线外/已撤销 DENY`
→ `当前策略收束 DENY` → `资源规则(网络/设备/角色/强度)` → `ALLOW`。

## 运行

```bash
python3 -m unittest discover -s tests -v   # 18 项不变量测试
python3 demo.py                            # 端到端剧情(含审计重放校验)
python3 -m zt_session.server 8080          # HTTP 服务
# 状态页: http://localhost:8080/sessions/<session_id>
```

## HTTP API

策略 API
- `GET  /api/policies` / `/api/policies/latest` / `/api/policies/{v}`
- `POST /api/policies` — 发布新版本, 版本号必须严格递增(拒绝回退)

会话
- `POST /api/sessions` — 登录建会话
  `{user_id, roles[], device_id, device_healthy, ip, auth_level}`
- `POST /api/sessions/{id}/signals` — 风险信号
  `{signal_id, signal_type: risk|location|attestation|admin_kill, severity, observed_at, payload}`
- `POST /api/sessions/{id}/reauth` — `{level, at?, method?}`
- `POST /api/sessions/{id}/terminate` — `{reason}`
- `POST /api/sessions/{id}/authorize` — `{resource, permission, request_id?}`
- `GET  /api/sessions/{id}` 状态 JSON · `GET /sessions/{id}` 状态页 HTML(3s 自动刷新)

审计
- `GET  /api/sessions/{id}/audit` 逐请求裁决(封存策略版本/状态快照/哈希链)
- `GET  /api/sessions/{id}/events` 会话事件流(含被拒的旧/重复信号)
- `POST /api/sessions/{id}/verify` 重放校验报告(哈希链 + 状态单调性 + 裁决重算一致)

## 设计要点说明

- **信号在受理时刻的最新策略下映射为指令**。策略升级改变新信号与新请求的解释,
  但已经并入水位的撤销/门槛不会被策略变更撤销——格上只有 join 没有 meet。
- **位置回到受信网络不恢复权限**。"回网"只产生上下文更新, 不产生反向授权指令;
  因离网被 revoke 的权限永久保持撤销, 避免"信号抖动导致权限闪烁"。
- **request_id 幂等**: 同键不同参数返回 `STALE_REQUEST` 并记录审计, 防重放混淆。
- **被拒事件也入链并推进 rev**(终止后信号、重复、旧观测), 水位全序可审计。

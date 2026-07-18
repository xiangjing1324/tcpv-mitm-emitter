# TCPView Child 近似语义字典（2026-07-18）

本字典用于 TCPView 实时观察和深度报告。目标是让每个可识别 child 至少落到一个可用大类，同时严格区分“确定含义”和“近似类别”。动态 `0x011223xx` 的低字节只显示 subtype，不能单独决定业务语义。

## 证据等级

| 等级 | UI | 含义 |
|---|---|---|
| `confirmed` | 确定 | 字段结构和连续样本已闭合，可以直接说明承载内容。 |
| `observed` | 观察 | 当前 payload 有可读字段、完整 shape 或历史连续样本直接支持。 |
| `approximate` | 近似 | 只能证明所属大类，精确字段含义目前不能证明。 |
| `unknown` | 未知 | 连 report family 或稳定结构都无法识别。 |

## Report family 与 child 大类

| report / shape | TCPView 类别 | 中文显示 | 等级边界 |
|---|---|---|---|
| `0x010A001B` | `report.container` | 批量上报父容器 | 确定；展开后按 child 分布解释，不把父容器本身当状态。 |
| `0x010A0011` | `control.child_context` | 子请求标签/配对保护上下文 | 观察；历史样本有 `hi_1/hi_2`，不宣称固定高级白名单。 |
| `0x010A0036` | `control.resource_sync` | 配置/规则文件同步标记 | 观察；常见 `mrpcs_*.data`。 |
| `0x010A0056` | `control.resource_sync` | 同步文件保存请求 | 观察。 |
| `0x010A0010/24/27/44/57` | `response.feedback` | 响应反馈/状态字段 | 观察；必须结合字段、方向和前序请求，不能仅凭 reportCode 定义风险。 |
| `0x0112xxxx` + `cs/ob/state/r/p` | `metadata.state.csob` | CSOB 状态快照 | 确定。 |
| `0x0112xxxx` + `model/ver` | `metadata.device_profile` | 设备型号/系统版本画像 | 观察。 |
| `0x0112xxxx` + IDFV/UUID | `metadata.device_identity` | 设备身份标识元数据 | 观察。 |
| `0x0112xxxx` + filename/`dl:` | `metadata.file_reference` | 配置/规则文件引用 | 观察；表示引用/同步上下文，不等于文件内容上传。 |
| `0x0112xxxx` + VPN/语言/录屏 | `metadata.device_environment` | 设备环境/开关标签 | 观察。 |
| `0x0112xxxx` + OpenID/account | `metadata.account` | 账号/OpenID 历史元数据 | 观察。 |
| 其它可解析 `0x0112xxxx` | `metadata.context` | 结构化元数据（具体子项待证） | 近似；不再显示成裸 `unknown`。 |
| 其它 `0x010Axxxx` | `control.protocol` | 控制/反馈记录（具体字段待证） | 近似。 |
| 其它 `0x0102xxxx` | `telemetry.leaf` | 探测遥测叶子（具体字段待证） | 近似。 |

## `0x0102000A` 完整 shape 分类

`0x0102000A` 只是 typed leaf shell。分类键固定使用：

`reportCode + inner_type + selector0 + selector1 + inner_field + record_len`

| shape / payload 证据 | 类别 | 中文显示 | 等级 |
|---|---|---|---|
| `len=68 inner_type=0x100A selector0=0x200D/200E0002 selector1=0x34560001` | `telemetry.time.current` | 当前采样时间 | 确定。 |
| `len=80 inner_type=0x1001 selector0=0x200D/200E0002 selector1=0x34560001` | `telemetry.time.session_baseline` | 会话/缓存基准时间 | 观察；不能当每包当前时间。 |
| `inner_type=0x100B` 或解出 UI token | `environment.ui_hierarchy` | UI 层级/前台窗口探测 | 有 token 为观察；只有 inner_type 为近似。 |
| `inner_type=0x1105/0x2000/0xFFF2` 或解出 dylib/framework | `environment.module_integrity` | 模块/动态库路径探测 | 有文本为观察；只有 shape 为近似。 |
| `inner_type=0x8027/0x8029` 或解出 daemon/调用栈 | `environment.process_stack` | 进程/调用栈探测 | 有文本为观察；只有 shape 为近似。 |
| 同时解出模块与进程 token | `environment.module_process` | 动态库/进程组合探测 | 观察。 |
| 其它完整稳定 shape | `telemetry.binary_probe` | 稳定二进制探测/遥测（字段待证） | 近似；禁止伪造精确字段名。 |

## UI 与报告要求

- 事件行优先显示父包/child 的中文语义分布，例如“设备画像×2 / 配置文件引用×1 / 稳定二进制探测×4”。
- 每个 child 标出“确定/观察/近似/未知”，并在 title/展开区保留证据和完整 shape。
- Hex 只作为下钻证据，不再承担主要解释。
- 深度报告聚合 `semantic_categories`、`semantic_labels_zh` 和 `semantic_tiers`。
- “近似”只说明所属大类；精确字段含义目前不能证明时必须原样写出这一边界。

## 1.14 历史 fixture 回归

对 Packet Engine 的 `tests/fixtures/1_14_device_profile_samples.jsonl` 共 88 条真实 1.14 样本重新解析：

- child/node：289
- `confirmed`：15
- `observed`：235
- `approximate`：39
- 裸 `unknown`：0
- 高频类别：设备画像 198、稳定二进制探测 20、子请求/保护上下文 19、CSOB 状态 15、文件引用 11、结构化 metadata 近似 11。

这里的“unknown=0”只表示每个已识别 report family 都获得了可用大类，不表示 289 个节点的精确字段含义已经全部闭合。

## 历史证据来源

- `dfm_cn_child_reportcode_semantic_latest_8091_20260427.md`
- `dfm_cn_reportcode_专题_20260419.md`
- `0102000a_ios_string_value_report_20260502.md`
- `dfm_cn_0102000a_timestamp_field_report_20260426.md`
- `offline_child_metadata_binary_bridge_all8091.md`

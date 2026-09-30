# UAGame TCPView 显示恢复（2026-10-01）

## 范围

仅更改 `tcpv_mitm_emitter/app.js` 的只读显示，不改变游戏报文、生产端分析、存储字节、资源替换规则。生产端已识别并提取 UAGame 正文时，保留原交接，不再次剥头。

既有 `codex/112-tcpv-uagame-reportcode-probe`、`codex/tcpv-uagame-gcloud-dh-variable-key` 的查看器能力已在基线 `81da0690bd8d5c398222026ad04bf229ad3b3786` 中；不合并其他游戏规则分支。

## 改进

- 兼容结构化生产端身份，不再仅依赖摘要里的 UAGame 字符串。
- 对旧的未识别交接，仅允许目标端口 20001、TGCP 0x4013、已解密的应用视图进入恢复。
- 直接消息与完整 raw-LZ4 压缩块均严格验证：头长 40B、BE32 正文长度与实际长度一致、固定 +38 处 `abab`，正文从 +40 开始。压缩 token 不当作游戏族编号。
- 正文只从验证后的边界解析，不滑动起点或在不透明字段里寻找 CS* 名称。既有编号映射标为“形态参考”，未知名称保持未知，请求/响应名称不能反向套用。
- 前缀只显示已验证头结构，不宣称全正文扫描完成。完整载荷加载后才显示资源与 CRC32 结果。
- 已验证本次资源布局为 `f4.f25={f1:name,f2:uint,f3:ZIP,f4:uint,f5:CRC32(f3)}`；两个整数的正式语义未知。拒绝错误路径、重复资源和仅有 PK 签名的伪归档。
- 校验单条目经典 ZIP 的目录/结束记录边界及整个 ZIP blob 的 CRC32。不在浏览器解压，不声称解压条目的 CRC32 已验证。
- 入站 UAGame 事件也可在原有只读详情路径补载；沿用每次渲染数量预算（自动 96、手动 192），单个自动补载显示长度不超过 1MiB。

## 验证

聚焦命令：

```sh
node --check tcpv_mitm_emitter/app.js
.venv/bin/python -m unittest discover -s tests -p 'test_uagame_display_recovery.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_gcloud_dh_handoff.py' -v
```

9 项恢复正反对照和 7 项既有 GCloud 回归通过；另由独立只读审查复核。

1.12.226.238:18091 的 2026-09-30 22:36:30–22:37:10 保留窗口：71 个事件，66 个未截断应用载荷通过消息头校验（62 直接、4 raw-LZ4），57 个正文完整通过字段解析；2 个 API 截断载荷不解析，3 个其他运输帧不进入恢复。显示回放无异常，所有原生产端分析及显示字节不变。

来源事件 `1790778991333-0`、显示序号 9：恢复入站编号 `0x08000001`，不误称登录请求。资源 `mrpcs-uam-ios-167.data`，ZIP 29924B，blob CRC32 `0xe0d241c1`；目录条目 `unzipmrpcs.data` 声明大小 116711B。

不保存完整登录载荷。安全验证摘要：
`artifacts/uagame-display/2026-10-01/live-view-validation.json`。
资源归档父证据：
`/Users/jinger/Desktop/dfm/artifacts/uagame-ios-mrpcs/2026-09-30/739136f6654fe044/manifest.json`。

## 部署与回滚

当前 `/app.js` 路由每次从磁盘读取，响应禁止缓存；只更新该脚本即可刷新生效，无需重启、清记录或改变其他服务器。

只允许在确认远端基线/干净跟踪文件之后切换至本改动提交，保留全部未跟踪的运行目录。回滚可切回上述基线；同样无需重启。部署验收需比较实际 HTTP 返回脚本的内容哈希、监听进程身份和保留流事件数量。

# TCPView Historical ReportCode Semantic Baseline

- input: `/Users/jinger/Downloads/Payload/tersafe_report_analysis/data/reportcode_matrix.json`
- observations: `88150`
- reportCodes: `90`
- evidence boundary: historical matrix contains aggregate child observations but no request/response direction or flow timing; those fields remain unknown.
- interpretation policy: dynamic subtype and legacy labels are provenance, not fixed protocol semantics.

## Every ReportCode

| reportCode | observed | family/subtype | current safe interpretation | observed payload roles | source evidence | historical note |
|---|---:|---|---|---|---|---|
| `0x0102000a` | 81330 | `0x0102000a` | typed leaf shell；含义由完整 shape 判定 | `typed leaf shell；含义由完整 shape 判定=81330` | `static+history / 高（壳结构）；子语义分型` | typed telemetry 壳；按 inner_type/selector/field/body 再分型 |
| `0x010a0011` | 2203 | `0x010a0011` | 配对/保护上下文（观察） | `配对/保护上下文（观察）=2203` | `static+history / 高` | 短请求标签：CRC32(IEEE) + `hi_%d`（不是检测结论） |
| `0x01122342` | 1067 | `0x011223xx / subtype=0x42` | 动态 metadata event family；低字节仅为 subtype | `device_profile=782` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×782 |
| `0x0112232e` | 886 | `0x011223xx / subtype=0x2e` | 动态 metadata event family；低字节仅为 subtype | `device_profile=527, account_metadata=85, file_reference=16, state_snapshot=2, state_counter=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×527; 账号上下文 + inc/obf 序号×85; 资源文件名引用（非文件内容）×16; 状态快照（cs/ob/state/r/p）×2; 状态计数/序号×1 |
| `0x01122388` | 371 | `0x011223xx / subtype=0x88` | 动态 metadata event family；低字节仅为 subtype | `device_profile=263, state_snapshot=59, account_metadata=4, opaque_token_metadata=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×263; 状态快照（cs/ob/state/r/p）×59; 账号上下文 + inc/obf 序号×4; 不透明 token 元数据×1 |
| `0x0112237a` | 231 | `0x011223xx / subtype=0x7a` | 动态 metadata event family；低字节仅为 subtype | `device_profile=154, account_metadata=16` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×154; 账号上下文 + inc/obf 序号×16 |
| `0x010a0056` | 186 | `0x010a0056` | 目前不能证明含义 | `目前不能证明含义=186` | `static+history / 高（家族）；值枚举中` | `sav_req`/同步控制状态；单字节值至少观察到 1、2 |
| `0x0112236c` | 152 | `0x011223xx / subtype=0x6c` | 动态 metadata event family；低字节仅为 subtype | `device_profile=123` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×123 |
| `0x01020002` | 125 | `0x01020002` | 目前不能证明含义 | `目前不能证明含义=125` | `history / 中` | 固定 28 字节的最小数值/控制 telemetry；具体枚举未命名 |
| `0x010a0036` | 108 | `0x010a0036` | 目前不能证明含义 | `目前不能证明含义=108` | `static+history / 高` | 资源/同步文件 marker：名称、类型/状态及附加数据 |
| `0x0112234d` | 95 | `0x011223xx / subtype=0x4d` | 动态 metadata event family；低字节仅为 subtype | `device_profile=52, account_metadata=6` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×52; 账号上下文 + inc/obf 序号×6 |
| `0x0112234c` | 84 | `0x011223xx / subtype=0x4c` | 动态 metadata event family；低字节仅为 subtype | `device_profile=44` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×44 |
| `0x01122389` | 77 | `0x011223xx / subtype=0x89` | 动态 metadata event family；低字节仅为 subtype | `device_profile=59` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×59 |
| `0x01122338` | 73 | `0x011223xx / subtype=0x38` | 动态 metadata event family；低字节仅为 subtype | `device_profile=33, account_metadata=5` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×33; 账号上下文 + inc/obf 序号×5 |
| `0x01122362` | 59 | `0x011223xx / subtype=0x62` | 动态 metadata event family；低字节仅为 subtype | `device_profile=44, state_snapshot=7` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×44; 状态快照（cs/ob/state/r/p）×7 |
| `0x01122386` | 55 | `0x011223xx / subtype=0x86` | 动态 metadata event family；低字节仅为 subtype | `device_profile=40, state_snapshot=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×40; 状态快照（cs/ob/state/r/p）×1 |
| `0x0112232d` | 53 | `0x011223xx / subtype=0x2d` | 动态 metadata event family；低字节仅为 subtype | `device_profile=29` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×29 |
| `0x01122334` | 50 | `0x011223xx / subtype=0x34` | 动态 metadata event family；低字节仅为 subtype | `device_profile=40, account_metadata=6` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×40; 账号上下文 + inc/obf 序号×6 |
| `0x01122380` | 49 | `0x011223xx / subtype=0x80` | 动态 metadata event family；低字节仅为 subtype | `device_profile=42, state_snapshot=2, opaque_token_metadata=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×42; 状态快照（cs/ob/state/r/p）×2; 不透明 token 元数据×1 |
| `0x01122329` | 47 | `0x011223xx / subtype=0x29` | 动态 metadata event family；低字节仅为 subtype | `device_profile=32` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×32 |
| `0x01122337` | 45 | `0x011223xx / subtype=0x37` | 动态 metadata event family；低字节仅为 subtype | `device_profile=34` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×34 |
| `0x01122358` | 41 | `0x011223xx / subtype=0x58` | 动态 metadata event family；低字节仅为 subtype | `device_profile=14, account_metadata=11` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×14; 账号上下文 + inc/obf 序号×11 |
| `0x01122383` | 34 | `0x011223xx / subtype=0x83` | 动态 metadata event family；低字节仅为 subtype | `device_profile=25` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×25 |
| `0x01122335` | 33 | `0x011223xx / subtype=0x35` | 动态 metadata event family；低字节仅为 subtype | `device_profile=16, account_metadata=1, state_snapshot=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×16; 账号上下文 + inc/obf 序号×1; 状态快照（cs/ob/state/r/p）×1 |
| `0x01122354` | 32 | `0x011223xx / subtype=0x54` | 动态 metadata event family；低字节仅为 subtype | `device_profile=28` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×28 |
| `0x01122361` | 32 | `0x011223xx / subtype=0x61` | 动态 metadata event family；低字节仅为 subtype | `device_profile=15` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×15 |
| `0x0112233a` | 31 | `0x011223xx / subtype=0x3a` | 动态 metadata event family；低字节仅为 subtype | `device_profile=31` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×31 |
| `0x0112233c` | 31 | `0x011223xx / subtype=0x3c` | 动态 metadata event family；低字节仅为 subtype | `device_profile=25` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×25 |
| `0x0112233f` | 31 | `0x011223xx / subtype=0x3f` | 动态 metadata event family；低字节仅为 subtype | `device_profile=28, account_metadata=3` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×28; 账号上下文 + inc/obf 序号×3 |
| `0x0112237d` | 31 | `0x011223xx / subtype=0x7d` | 动态 metadata event family；低字节仅为 subtype | `device_profile=29` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×29 |
| `0x01122348` | 29 | `0x011223xx / subtype=0x48` | 动态 metadata event family；低字节仅为 subtype | `device_profile=29` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×29 |
| `0x01122355` | 28 | `0x011223xx / subtype=0x55` | 动态 metadata event family；低字节仅为 subtype | `device_profile=26` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×26 |
| `0x0112238b` | 26 | `0x011223xx / subtype=0x8b` | 动态 metadata event family；低字节仅为 subtype | `device_profile=25` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×25 |
| `0x0112232f` | 25 | `0x011223xx / subtype=0x2f` | 动态 metadata event family；低字节仅为 subtype | `device_profile=20, state_snapshot=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×20; 状态快照（cs/ob/state/r/p）×2 |
| `0x01122343` | 25 | `0x011223xx / subtype=0x43` | 动态 metadata event family；低字节仅为 subtype | `device_profile=19, state_snapshot=2, account_metadata=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×19; 状态快照（cs/ob/state/r/p）×2; 账号上下文 + inc/obf 序号×1 |
| `0x010a0043` | 24 | `0x010a0043` | 目前不能证明含义 | `目前不能证明含义=24` | `static+history / 中` | 4 字节标量控制记录；字段名/枚举仍未知 |
| `0x01122384` | 24 | `0x011223xx / subtype=0x84` | 动态 metadata event family；低字节仅为 subtype | `device_profile=12` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×12 |
| `0x01122336` | 23 | `0x011223xx / subtype=0x36` | 动态 metadata event family；低字节仅为 subtype | `device_profile=18, account_metadata=3` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×18; 账号上下文 + inc/obf 序号×3 |
| `0x01122339` | 21 | `0x011223xx / subtype=0x39` | 动态 metadata event family；低字节仅为 subtype | `device_profile=21` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×21 |
| `0x01122341` | 19 | `0x011223xx / subtype=0x41` | 动态 metadata event family；低字节仅为 subtype | `device_profile=7, account_metadata=7` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×7; 账号上下文 + inc/obf 序号×7 |
| `0x0112238a` | 18 | `0x011223xx / subtype=0x8a` | 动态 metadata event family；低字节仅为 subtype | `device_profile=5, account_metadata=5, file_reference=4, state_counter=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×5; 账号上下文 + inc/obf 序号×5; 资源文件名引用（非文件内容）×4; 状态计数/序号×1 |
| `0x0112234a` | 15 | `0x011223xx / subtype=0x4a` | 动态 metadata event family；低字节仅为 subtype | `device_profile=14` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×14 |
| `0x01122340` | 14 | `0x011223xx / subtype=0x40` | 动态 metadata event family；低字节仅为 subtype | `device_profile=10, account_metadata=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×10; 账号上下文 + inc/obf 序号×1 |
| `0x01122350` | 14 | `0x011223xx / subtype=0x50` | 动态 metadata event family；低字节仅为 subtype | `device_profile=10, account_metadata=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×10; 账号上下文 + inc/obf 序号×2 |
| `0x01122357` | 14 | `0x011223xx / subtype=0x57` | 动态 metadata event family；低字节仅为 subtype | `device_profile=11` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×11 |
| `0x01122346` | 13 | `0x011223xx / subtype=0x46` | 动态 metadata event family；低字节仅为 subtype | `device_profile=10` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×10 |
| `0x01122371` | 12 | `0x011223xx / subtype=0x71` | 动态 metadata event family；低字节仅为 subtype | `device_profile=11` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×11 |
| `0x01122373` | 11 | `0x011223xx / subtype=0x73` | 动态 metadata event family；低字节仅为 subtype | `device_profile=7, state_snapshot=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×7; 状态快照（cs/ob/state/r/p）×1 |
| `0x0112235d` | 10 | `0x011223xx / subtype=0x5d` | 动态 metadata event family；低字节仅为 subtype | `device_profile=10` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×10 |
| `0x01122360` | 10 | `0x011223xx / subtype=0x60` | 动态 metadata event family；低字节仅为 subtype | `device_profile=7` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×7 |
| `0x01122365` | 10 | `0x011223xx / subtype=0x65` | 动态 metadata event family；低字节仅为 subtype | `device_profile=5` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×5 |
| `0x0112232c` | 9 | `0x011223xx / subtype=0x2c` | 动态 metadata event family；低字节仅为 subtype | `account_metadata=4, device_profile=2, state_snapshot=1, opaque_token_metadata=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：账号上下文 + inc/obf 序号×4; 设备/运行环境画像×2; 状态快照（cs/ob/state/r/p）×1; 不透明 token 元数据×1 |
| `0x0112234e` | 9 | `0x011223xx / subtype=0x4e` | 动态 metadata event family；低字节仅为 subtype | `device_profile=6, state_snapshot=3` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×6; 状态快照（cs/ob/state/r/p）×3 |
| `0x0112232a` | 8 | `0x011223xx / subtype=0x2a` | 动态 metadata event family；低字节仅为 subtype | `device_profile=6` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×6 |
| `0x01122349` | 8 | `0x011223xx / subtype=0x49` | 动态 metadata event family；低字节仅为 subtype | `device_profile=5` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×5 |
| `0x01122366` | 7 | `0x011223xx / subtype=0x66` | 动态 metadata event family；低字节仅为 subtype | `device_profile=4` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×4 |
| `0x01122385` | 7 | `0x011223xx / subtype=0x85` | 动态 metadata event family；低字节仅为 subtype | `device_profile=7` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×7 |
| `0x0112234f` | 6 | `0x011223xx / subtype=0x4f` | 动态 metadata event family；低字节仅为 subtype | `device_profile=5` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×5 |
| `0x01122374` | 6 | `0x011223xx / subtype=0x74` | 动态 metadata event family；低字节仅为 subtype | `device_profile=3` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×3 |
| `0x0112234b` | 5 | `0x011223xx / subtype=0x4b` | 动态 metadata event family；低字节仅为 subtype | `device_profile=5` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×5 |
| `0x0112235f` | 4 | `0x011223xx / subtype=0x5f` | 动态 metadata event family；低字节仅为 subtype | `device_profile=3, state_snapshot=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×3; 状态快照（cs/ob/state/r/p）×1 |
| `0x01122367` | 4 | `0x011223xx / subtype=0x67` | 动态 metadata event family；低字节仅为 subtype | `device_profile=3` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×3 |
| `0x01122369` | 4 | `0x011223xx / subtype=0x69` | 动态 metadata event family；低字节仅为 subtype | `device_profile=4` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×4 |
| `0x0112233e` | 3 | `0x011223xx / subtype=0x3e` | 动态 metadata event family；低字节仅为 subtype | `device_profile=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×2 |
| `0x0112235a` | 3 | `0x011223xx / subtype=0x5a` | 动态 metadata event family；低字节仅为 subtype | `device_profile=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×2 |
| `0x01122377` | 3 | `0x011223xx / subtype=0x77` | 动态 metadata event family；低字节仅为 subtype | `device_profile=3` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×3 |
| `0x01122378` | 3 | `0x011223xx / subtype=0x78` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1, account_metadata=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1; 账号上下文 + inc/obf 序号×1 |
| `0x0112237f` | 3 | `0x011223xx / subtype=0x7f` | 动态 metadata event family；低字节仅为 subtype | `device_profile=3` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×3 |
| `0x0112232b` | 2 | `0x011223xx / subtype=0x2b` | 动态 metadata event family；低字节仅为 subtype | `device_profile=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×2 |
| `0x01122330` | 2 | `0x011223xx / subtype=0x30` | 动态 metadata event family；低字节仅为 subtype | `device_profile=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×2 |
| `0x0112233b` | 2 | `0x011223xx / subtype=0x3b` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x01122347` | 2 | `0x011223xx / subtype=0x47` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x01122353` | 2 | `0x011223xx / subtype=0x53` | 动态 metadata event family；低字节仅为 subtype | `device_profile=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×2 |
| `0x01122364` | 2 | `0x011223xx / subtype=0x64` | 动态 metadata event family；低字节仅为 subtype | `device_profile=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×2 |
| `0x0112236d` | 2 | `0x011223xx / subtype=0x6d` | 动态 metadata event family；低字节仅为 subtype | `device_profile=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×2 |
| `0x01122372` | 2 | `0x011223xx / subtype=0x72` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1, account_metadata=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1; 账号上下文 + inc/obf 序号×1 |
| `0x01122375` | 2 | `0x011223xx / subtype=0x75` | 动态 metadata event family；低字节仅为 subtype | `device_profile=2` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×2 |
| `0x01122328` | 1 | `0x011223xx / subtype=0x28` | 动态 metadata event family；低字节仅为 subtype | `account_metadata=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：账号上下文 + inc/obf 序号×1 |
| `0x01122331` | 1 | `0x011223xx / subtype=0x31` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x01122332` | 1 | `0x011223xx / subtype=0x32` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x0112233d` | 1 | `0x011223xx / subtype=0x3d` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x01122344` | 1 | `0x011223xx / subtype=0x44` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x01122351` | 1 | `0x011223xx / subtype=0x51` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x0112235b` | 1 | `0x011223xx / subtype=0x5b` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x0112235e` | 1 | `0x011223xx / subtype=0x5e` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x01122368` | 1 | `0x011223xx / subtype=0x68` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x0112236b` | 1 | `0x011223xx / subtype=0x6b` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x0112236e` | 1 | `0x011223xx / subtype=0x6e` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x01122381` | 1 | `0x011223xx / subtype=0x81` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |
| `0x01122387` | 1 | `0x011223xx / subtype=0x87` | 动态 metadata event family；低字节仅为 subtype | `device_profile=1` | `static+history / 高（结构）；角色为观察值` | 动态 metadata；本地唯一载荷角色：设备/运行环境画像×1 |

## Dynamic 0x011223xx Subtypes

- subtype counts: `0x42=1067, 0x2e=886, 0x88=371, 0x7a=231, 0x6c=152, 0x4d=95, 0x4c=84, 0x89=77, 0x38=73, 0x62=59, 0x86=55, 0x2d=53, 0x34=50, 0x80=49, 0x29=47, 0x37=45, 0x58=41, 0x83=34, 0x35=33, 0x54=32, 0x61=32, 0x7d=31, 0x3c=31, 0x3a=31, 0x3f=31, 0x48=29, 0x55=28, 0x8b=26, 0x43=25, 0x2f=25, 0x84=24, 0x36=23, 0x39=21, 0x41=19, 0x8a=18, 0x4a=15, 0x57=14, 0x50=14, 0x40=14, 0x46=13, 0x71=12, 0x73=11, 0x60=10, 0x65=10, 0x5d=10, 0x2c=9, 0x4e=9, 0x49=8, 0x2a=8, 0x66=7, 0x85=7, 0x74=6, 0x4f=6, 0x4b=5, 0x67=4, 0x5f=4, 0x69=4, 0x3e=3, 0x78=3, 0x5a=3, 0x7f=3, 0x77=3, 0x75=2, 0x3b=2, 0x2b=2, 0x72=2, 0x6d=2, 0x53=2, 0x47=2, 0x64=2, 0x30=2, 0x31=1, 0x32=1, 0x28=1, 0x87=1, 0x5b=1, 0x3d=1, 0x68=1, 0x6b=1, 0x6e=1, 0x81=1, 0x51=1, 0x5e=1, 0x44=1`
- low byte is only a dynamic subtype. Payload fields and full context decide the observed role.

## Unresolved

- reportCodes: `0x010a0056, 0x01020002, 0x010a0036, 0x010a0043`
- note: 历史矩阵没有方向/时序关联；未知项目前不能证明含义，不把旧标签升级为确定协议语义。

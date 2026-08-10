# TCPView Shape Bucket Summary

- input: `/tmp/replay-18092.tcpvflow.jsonl.gz`
- source: `display`
- account: `replay-18092`
- cid: `127.0.0.1:46529->nj.cschannel.anticheatexpert.com:443 [acc:6708949272549705871]`
- events: `1239`
- shape_buckets: `98`
- policy_note: cleanup only means template bucket / replay sample cleanup; no wire drop; no PE active mutation.

## Report Counts

- reports: `0x010a0024=900, 0x010a001b=226, 0x0102000a=61, 0x010a0010=20, 0x010a0027=17, 0x01122338=2, 0x01122376=1, 0x01122357=1, 0x01122343=1`
- inner_types: `0x100e=171, 0x1005=111, 0x1008=93, 0x8027=60, 0x1001=53, 0x1003=50, 0x8029=38, 0x100a=37, 0x1004=34, 0xfffb=25, 0x1105=20, 0x1002=20, 0x2000=19, 0x100f=16, 0x1006=13, 0x100b=11, ...`
- parent_roster_layouts: `count-u32=217, compact-count-u8=8, count-u32-partial=1`
- parent_child_count_histogram: `2=60, 0=41, 3=37, 4=18, 9=14, 10=14, 1=13, 7=8, 8=6, 5=4, 6=4, 11=3, ...`

## Top Buckets

| count | inner_type | child_len | body_len | tail_len | pe_decision | preview | shape_key |
|---:|---|---|---|---|---|---|---|
| 156 | `0x100e` | `48=156` | `12=156` | `0=156` | `blocked=156` | `opaque=156` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000000:len48:body12:tail0` |
| 109 | `0x1005` | `60=109` | `24=109` | `0=109` | `blocked=109` | `opaque=109` | `0x0102000a:0x1005:0x200f0002:0x34560001:0x00000002:len60:body24:tail0` |
| 93 | `0x1008` | `180=93` | `144=93` | `0=93` | `blocked=93` | `opaque=93` | `0x0102000a:0x1008:0x200f0002:0x34560001:0x0000001a:len180:body144:tail0` |
| 53 | `0x1001` | `80=53` | `44=53` | `0=53` | `blocked=53` | `opaque=53` | `0x0102000a:0x1001:0x200f0002:0x34560001:0x6a5b3355:len80:body44:tail0` |
| 50 | `0x1003` | `88=50` | `52=50` | `0=50` | `blocked=50` | `opaque=50` | `0x0102000a:0x1003:0x200f0002:0x34560001:0x00000000:len88:body52:tail0` |
| 45 | `0x8027` | `132=45` | `96=45` | `8=45` | `blocked=45` | `opaque=45` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001542:len132:body96:tail8` |
| 34 | `0x1004` | `68=34` | `32=34` | `0=34` | `blocked=34` | `opaque=34` | `0x0102000a:0x1004:0x200f0002:0x34560001:0x00000000:len68:body32:tail0` |
| 28 | `0x100a` | `68=28` | `32=28` | `0=28` | `blocked=28` | `opaque=28` | `0x0102000a:0x100a:0x200f0002:0x34560001:0x00000002:len68:body32:tail0` |
| 25 | `0xfffb` | `79=25` | `43=25` | `0=25` | `blocked=25` | `opaque=25` | `0x0102000a:0xfffb:0x200f0002:0x34560001:0x01010000:len79:body43:tail0` |
| 19 | `0x2000` | `44=19` | `8=19` | `0=19` | `python_fallback=19` | `opaque=19` | `0x0102000a:0x2000:0x200f0002:0x34560001:0x00000000:len44:body8:tail0` |
| 16 | `0x100f` | `44=16` | `8=16` | `0=16` | `blocked=16` | `opaque=16` | `0x0102000a:0x100f:0x200f0002:0x34560001:0x00000000:len44:body8:tail0` |
| 16 | `0x1105` | `93=16` | `57=16` | `0=16` | `python_fallback=16` | `opaque=16` | `0x0102000a:0x1105:0x200f0002:0x34560001:0x00000001:len93:body57:tail0` |
| 13 | `0x1006` | `48=13` | `12=13` | `0=13` | `blocked=13` | `opaque=13` | `0x0102000a:0x1006:0x200f0002:0x34560001:0x159400c0:len48:body12:tail0` |
| 10 | `0x100b` | `98=10` | `62=10` | `0=10` | `python_fallback=10` | `opaque=10` | `0x0102000a:0x100b:0x200f0002:0x34560001:0x38e3ffe1:len98:body62:tail0` |
| 5 | `0x1002` | `60=5` | `24=5` | `0=5` | `blocked=5` | `opaque=5` | `0x0102000a:0x1002:0x200f0002:0x34560001:0x31401450:len60:body24:tail0` |
| 4 | `0x100e` | `48=4` | `12=4` | `0=4` | `blocked=4` | `opaque=4` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000001:len48:body12:tail0` |
| 4 | `0x8029` | `93=4` | `57=4` | `8=4` | `blocked=4` | `opaque=4` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000173:len93:body57:tail8` |
| 4 | `0xfffe` | `47=4` | `11=4` | `0=4` | `blocked=4` | `opaque=4` | `0x0102000a:0xfffe:0x200f0002:0x34560001:0x000000fb:len47:body11:tail0` |
| 3 | `0x0100` | `152=3` | `116=3` | `0=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x0100:0x200f0002:0x34560001:0x0000006c:len152:body116:tail0` |
| 3 | `0x1002` | `60=3` | `24=3` | `0=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x1002:0x200f0002:0x34560001:0x24dd57f0:len60:body24:tail0` |
| 3 | `0x1002` | `60=3` | `24=3` | `0=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x1002:0x200f0002:0x34560001:0x3ecfafa0:len60:body24:tail0` |
| 3 | `0x100e` | `49=3` | `13=3` | `0=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000000:len49:body13:tail0` |
| 3 | `0x100e` | `48=3` | `12=3` | `0=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000007:len48:body12:tail0` |
| 3 | `0x1011` | `122=3` | `86=3` | `0=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x1011:0x200f0002:0x34560001:0x00000000:len122:body86:tail0` |
| 3 | `0x8029` | `87=3` | `51=3` | `8=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000003f3:len87:body51:tail8` |
| 3 | `0x8029` | `92=3` | `56=3` | `8=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000003f5:len92:body56:tail8` |
| 2 | `0x1002` | `60=2` | `24=2` | `0=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x1002:0x200f0002:0x34560001:0x2cf2a990:len60:body24:tail0` |
| 2 | `0x1002` | `60=2` | `24=2` | `0=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x1002:0x200f0002:0x34560001:0x2dfc5180:len60:body24:tail0` |
| 2 | `0x1005` | `61=2` | `25=2` | `0=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x1005:0x200f0002:0x34560001:0x00000002:len61:body25:tail0` |
| 2 | `0x100e` | `48=2` | `12=2` | `0=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000002:len48:body12:tail0` |
| 2 | `0x100e` | `48=2` | `12=2` | `0=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000003:len48:body12:tail0` |
| 2 | `0x1105` | `93=2` | `57=2` | `0=2` | `python_fallback=2` | `opaque=2` | `0x0102000a:0x1105:0x200f0002:0x34560001:0x0000000c:len93:body57:tail0` |
| 2 | `0x1105` | `93=2` | `57=2` | `0=2` | `python_fallback=2` | `opaque=2` | `0x0102000a:0x1105:0x200f0002:0x34560001:0x00000028:len93:body57:tail0` |
| 2 | `0x8027` | `132=2` | `96=2` | `8=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000003f7:len132:body96:tail8` |
| 2 | `0x8027` | `132=2` | `96=2` | `8=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000003f9:len132:body96:tail8` |
| 2 | `0x8027` | `121=2` | `85=2` | `8=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000003fe:len121:body85:tail8` |
| 2 | `0x8027` | `118=2` | `82=2` | `8=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00000403:len118:body82:tail8` |
| 2 | `0x8028` | `40=2` | `4=2` | `0=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x8028:0x200f0000:0x010e0001:0x00000007:len40:body4:tail0` |
| 2 | `0x8029` | `102=2` | `66=2` | `8=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len102:body66:tail8` |
| 2 | `0x8029` | `90=2` | `54=2` | `8=2` | `blocked=2` | `opaque=2` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000196:len90:body54:tail8` |

## Blocked Buckets

| count | inner_type | tail | reason | cleanup_hint | samples |
|---:|---|---|---|---|---|
| 156 | `0x100e` | `-=156` | `opaque_body; exact_writer_missing=156` | `template_bucket_only / no_wire_drop=156` | `seq=10/msg=4/child=0, seq=54/msg=15/child=1, seq=96/msg=20/child=1` |
| 109 | `0x1005` | `-=109` | `opaque_body; exact_writer_missing=109` | `template_bucket_only / no_wire_drop=109` | `seq=10/msg=4/child=2, seq=104/msg=23/child=0, seq=104/msg=23/child=4` |
| 93 | `0x1008` | `-=93` | `opaque_body; exact_writer_missing=93` | `template_bucket_only / no_wire_drop=93` | `seq=10/msg=4/child=5, seq=104/msg=23/child=7, seq=115/msg=26/child=2` |
| 53 | `0x1001` | `-=53` | `opaque_body; exact_writer_missing=53` | `template_bucket_only / no_wire_drop=53` | `seq=10/msg=4/child=1, seq=104/msg=23/child=3, seq=155/msg=50/child=6` |
| 50 | `0x1003` | `-=50` | `opaque_body; exact_writer_missing=50` | `template_bucket_only / no_wire_drop=50` | `seq=10/msg=4/child=3, seq=104/msg=23/child=5, seq=155/msg=50/child=8` |
| 45 | `0x8027` | `0201010000000000=29, 0201010000123456=13, 0000000201010000=3` | `tail_policy_unknown_blocked; exact_writer_missing=45` | `template_bucket_only / no_wire_drop=45` | `seq=10/msg=4/child=7, seq=10/msg=4/child=8, seq=96/msg=20/child=2` |
| 34 | `0x1004` | `-=34` | `opaque_body; exact_writer_missing=34` | `template_bucket_only / no_wire_drop=34` | `seq=10/msg=4/child=6, seq=96/msg=20/child=4, seq=104/msg=23/child=8` |
| 28 | `0x100a` | `-=28` | `opaque_body; exact_writer_missing=28` | `template_bucket_only / no_wire_drop=28` | `seq=10/msg=4/child=4, seq=104/msg=23/child=6, seq=155/msg=50/child=9` |
| 25 | `0xfffb` | `-=25` | `opaque_body; exact_writer_missing=25` | `template_bucket_only / no_wire_drop=25` | `seq=155/msg=50/child=0, seq=225/msg=87/child=0, seq=297/msg=131/child=0` |
| 16 | `0x100f` | `-=16` | `opaque_body; exact_writer_missing=16` | `template_bucket_only / no_wire_drop=16` | `seq=212/msg=78/child=3, seq=795/msg=361/child=0, seq=795/msg=361/child=1` |
| 13 | `0x1006` | `-=13` | `opaque_body; exact_writer_missing=13` | `template_bucket_only / no_wire_drop=13` | `seq=321/msg=142/child=1, seq=321/msg=142/child=3, seq=321/msg=142/child=4` |
| 5 | `0x1002` | `-=5` | `opaque_body; exact_writer_missing=5` | `template_bucket_only / no_wire_drop=5` | `seq=96/msg=20/child=5, seq=155/msg=50/child=5, seq=340/msg=151/child=5` |
| 4 | `0x100e` | `-=4` | `opaque_body; exact_writer_missing=4` | `template_bucket_only / no_wire_drop=4` | `seq=876/msg=398/child=1, seq=880/msg=401/child=1, seq=1061/msg=515/child=3` |
| 4 | `0x8029` | `0000000300000002=2, 0100000002123456=1, 0300000002000000=1` | `tail_policy_unknown_blocked; exact_writer_missing=4` | `template_bucket_only / no_wire_drop=4` | `seq=293/msg=128/child=2, seq=314/msg=136/child=None, seq=319/msg=140/child=None` |
| 4 | `0xfffe` | `-=4` | `opaque_body; exact_writer_missing=4` | `template_bucket_only / no_wire_drop=4` | `seq=398/msg=177/child=1, seq=1062/msg=516/child=6, seq=1063/msg=516/child=1` |
| 3 | `0x0100` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=212/msg=78/child=1, seq=804/msg=365/child=2, seq=1103/msg=533/child=2` |
| 3 | `0x1002` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=764/msg=345/child=0, seq=767/msg=348/child=0, seq=771/msg=350/child=4` |
| 3 | `0x1002` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=876/msg=398/child=0, seq=900/msg=410/child=0, seq=900/msg=410/child=4` |
| 3 | `0x100e` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=225/msg=87/child=1, seq=627/msg=277/child=1, seq=962/msg=442/child=2` |
| 3 | `0x100e` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=243/msg=98/child=1, seq=1019/msg=484/child=1, seq=1158/msg=566/child=9` |
| 3 | `0x1011` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=772/msg=351/child=0, seq=1061/msg=515/child=0, seq=1062/msg=516/child=5` |
| 3 | `0x8029` | `000000030000000e=2, 030000000e123456=1` | `tail_policy_unknown_blocked; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=217/msg=81/child=None, seq=999/msg=467/child=0, seq=1004/msg=472/child=None` |
| 3 | `0x8029` | `0300000018000000=3` | `tail_policy_unknown_blocked; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=151/msg=48/child=0, seq=175/msg=56/child=0, seq=985/msg=454/child=0` |
| 2 | `0x1002` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=1117/msg=540/child=0, seq=1118/msg=541/child=1` |
| 2 | `0x1002` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=1061/msg=515/child=1, seq=1061/msg=515/child=4` |
| 2 | `0x1005` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=138/msg=40/child=0, seq=789/msg=355/child=0` |
| 2 | `0x100e` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=1102/msg=532/child=1, seq=1103/msg=533/child=1` |
| 2 | `0x100e` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=1117/msg=540/child=1, seq=1118/msg=541/child=7` |
| 2 | `0x8027` | `020101001e123456=1, 000000020101001e=1` | `tail_policy_unknown_blocked; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=148/msg=45/child=1, seq=983/msg=451/child=None` |
| 2 | `0x8027` | `0000000201010000=2` | `tail_policy_unknown_blocked; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=146/msg=43/child=None, seq=981/msg=449/child=None` |
| 2 | `0x8027` | `0201010000123456=1, 0201010000000000=1` | `tail_policy_unknown_blocked; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=138/msg=40/child=6, seq=962/msg=442/child=0` |
| 2 | `0x8027` | `0201010000000000=1, 0000000201010000=1` | `tail_policy_unknown_blocked; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=115/msg=26/child=1, seq=950/msg=436/child=None` |
| 2 | `0x8028` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=254/msg=107/child=1, seq=259/msg=112/child=10` |
| 2 | `0x8029` | `030000001e000000=2` | `tail_policy_unknown_blocked; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=260/msg=112/child=0, seq=260/msg=112/child=3` |
| 2 | `0x8029` | `030000003a123456=1, 000000030000003a=1` | `tail_policy_unknown_blocked; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=254/msg=107/child=2, seq=280/msg=118/child=None` |
| 2 | `0x8029` | `030000000e000000=1, 000000010000000e=1` | `tail_policy_unknown_blocked; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=212/msg=78/child=2, seq=994/msg=462/child=None` |
| 2 | `0x8029` | `000000030000000e=1, 030000000e123456=1` | `tail_policy_unknown_blocked; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=186/msg=62/child=None, seq=207/msg=73/child=1` |
| 2 | `0xfffe` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=376/msg=171/child=1, seq=1157/msg=565/child=1` |
| 1 | `0x0101` | `-=1` | `opaque_body; exact_writer_missing=1` | `template_bucket_only / no_wire_drop=1` | `seq=1131/msg=545/child=None` |
| 1 | `0x0103` | `-=1` | `opaque_body; exact_writer_missing=1` | `template_bucket_only / no_wire_drop=1` | `seq=243/msg=98/child=2` |

## 0x8027 / 0x8029 Tail Patterns

| inner_type | count | tail_len | tail_hex | tail_u32 | shape_key |
|---|---:|---|---|---|---|
| `0x8027` | 45 | `8=45` | `0201010000000000=29, 0201010000123456=13, 0000000201010000=3` | `0x02010100,0x00000000=29, 0x02010100,0x00123456=13, 0x00000002,0x01010000=3` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001542:len132:body96:tail8` |
| `0x8029` | 4 | `8=4` | `0000000300000002=2, 0100000002123456=1, 0300000002000000=1` | `0x00000003,0x00000002=2, 0x01000000,0x02123456=1, 0x03000000,0x02000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000173:len93:body57:tail8` |
| `0x8029` | 3 | `8=3` | `000000030000000e=2, 030000000e123456=1` | `0x00000003,0x0000000e=2, 0x03000000,0x0e123456=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000003f3:len87:body51:tail8` |
| `0x8029` | 3 | `8=3` | `0300000018000000=3` | `0x03000000,0x18000000=3` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000003f5:len92:body56:tail8` |
| `0x8027` | 2 | `8=2` | `020101001e123456=1, 000000020101001e=1` | `0x02010100,0x1e123456=1, 0x00000002,0x0101001e=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000003f7:len132:body96:tail8` |
| `0x8027` | 2 | `8=2` | `0000000201010000=2` | `0x00000002,0x01010000=2` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000003f9:len132:body96:tail8` |
| `0x8027` | 2 | `8=2` | `0201010000123456=1, 0201010000000000=1` | `0x02010100,0x00123456=1, 0x02010100,0x00000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000003fe:len121:body85:tail8` |
| `0x8027` | 2 | `8=2` | `0201010000000000=1, 0000000201010000=1` | `0x02010100,0x00000000=1, 0x00000002,0x01010000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00000403:len118:body82:tail8` |
| `0x8029` | 2 | `8=2` | `030000001e000000=2` | `0x03000000,0x1e000000=2` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len102:body66:tail8` |
| `0x8029` | 2 | `8=2` | `030000003a123456=1, 000000030000003a=1` | `0x03000000,0x3a123456=1, 0x00000003,0x0000003a=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000196:len90:body54:tail8` |
| `0x8029` | 2 | `8=2` | `030000000e000000=1, 000000010000000e=1` | `0x03000000,0x0e000000=1, 0x00000001,0x0000000e=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000003f3:len88:body52:tail8` |
| `0x8029` | 2 | `8=2` | `000000030000000e=1, 030000000e123456=1` | `0x00000003,0x0000000e=1, 0x03000000,0x0e123456=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000003f3:len91:body55:tail8` |
| `0x8027` | 1 | `8=1` | `0000000201010000=1` | `0x00000002,0x01010000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000001cc:len106:body70:tail8` |
| `0x8027` | 1 | `8=1` | `0201010000123456=1` | `0x02010100,0x00123456=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000001cc:len119:body83:tail8` |
| `0x8027` | 1 | `8=1` | `0201010000000000=1` | `0x02010100,0x00000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000002b7:len132:body96:tail8` |
| `0x8027` | 1 | `8=1` | `0201010018000000=1` | `0x02010100,0x18000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000003f5:len123:body87:tail8` |
| `0x8027` | 1 | `8=1` | `0201010008000000=1` | `0x02010100,0x08000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00000419:len117:body81:tail8` |
| `0x8027` | 1 | `8=1` | `000000020201001e=1` | `0x00000002,0x0201001e=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00000433:len127:body91:tail8` |
| `0x8027` | 1 | `8=1` | `020201001e000000=1` | `0x02020100,0x1e000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00000437:len134:body98:tail8` |
| `0x8029` | 1 | `8=1` | `0000000100000002=1` | `0x00000001,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000030:len75:body39:tail8` |
| `0x8029` | 1 | `8=1` | `0300000006000000=1` | `0x03000000,0x06000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000007d:len105:body69:tail8` |
| `0x8029` | 1 | `8=1` | `0000000100000002=1` | `0x00000001,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000016f:len68:body32:tail8` |
| `0x8029` | 1 | `8=1` | `0000000300000002=1` | `0x00000003,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000173:len125:body89:tail8` |
| `0x8029` | 1 | `8=1` | `0000000100000002=1` | `0x00000001,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000173:len91:body55:tail8` |
| `0x8029` | 1 | `8=1` | `0000000300000002=1` | `0x00000003,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000173:len94:body58:tail8` |
| `0x8029` | 1 | `8=1` | `0000000100000002=1` | `0x00000001,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000017e:len75:body39:tail8` |
| `0x8029` | 1 | `8=1` | `0000000100000002=1` | `0x00000001,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000017e:len87:body51:tail8` |
| `0x8029` | 1 | `8=1` | `0000000300000002=1` | `0x00000003,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000018f:len75:body39:tail8` |
| `0x8029` | 1 | `8=1` | `0100000000123456=1` | `0x01000000,0x00123456=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000190:len101:body65:tail8` |
| `0x8029` | 1 | `8=1` | `0000000100000000=1` | `0x00000001,0x00000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000190:len105:body69:tail8` |
| `0x8029` | 1 | `8=1` | `000000010000000a=1` | `0x00000001,0x0000000a=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000194:len71:body35:tail8` |
| `0x8029` | 1 | `8=1` | `000000030000003a=1` | `0x00000003,0x0000003a=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000196:len85:body49:tail8` |
| `0x8029` | 1 | `8=1` | `0000000300000002=1` | `0x00000003,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000001a1:len101:body65:tail8` |
| `0x8029` | 1 | `8=1` | `0000000300000002=1` | `0x00000003,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000001a1:len95:body59:tail8` |
| `0x8029` | 1 | `8=1` | `0000000300000006=1` | `0x00000003,0x00000006=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000001bc:len101:body65:tail8` |
| `0x8029` | 1 | `8=1` | `0100000002123456=1` | `0x01000000,0x02123456=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000001e1:len101:body65:tail8` |
| `0x8029` | 1 | `8=1` | `0000000300000002=1` | `0x00000003,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000001e6:len101:body65:tail8` |
| `0x8029` | 1 | `8=1` | `000000030000000e=1` | `0x00000003,0x0000000e=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000003f3:len123:body87:tail8` |
| `0x8029` | 1 | `8=1` | `0000000400000008=1` | `0x00000004,0x00000008=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000419:len86:body50:tail8` |

## 0xFFF2 Region/Path Clusters

| count | child_len | body_len | leaf_id/reserved | sibling_0112_context | shape_key |
|---:|---|---|---|---|---|
| 1 | `171=1` | `135=1` | `0x0000007f=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x00550001:0x038999c6:len171:body135:tail0` |
| 1 | `171=1` | `135=1` | `0x000002e3=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x035e0001:0x038999c6:len171:body135:tail0` |
| 1 | `101=1` | `65=1` | `0x0000030b=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x047a0001:0x01000000:len101:body65:tail0` |

## Sample Children

### `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000000:len48:body12:tail0`
- seq=10 msg=4 chunk=4 child=0 parent=0x010a001b len=48 body=12 inner=0x100e tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=54 msg=15 chunk=0 child=1 parent=0x010a001b len=48 body=12 inner=0x100e tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=96 msg=20 chunk=0 child=1 parent=0x010a001b len=48 body=12 inner=0x100e tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=1 parent=0x010a001b len=48 body=12 inner=0x100e tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=9 parent=0x010a001b len=48 body=12 inner=0x100e tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1005:0x200f0002:0x34560001:0x00000002:len60:body24:tail0`
- seq=10 msg=4 chunk=4 child=2 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=0 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=4 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=138 msg=40 chunk=0 child=3 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=151 msg=48 chunk=0 child=1 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1008:0x200f0002:0x34560001:0x0000001a:len180:body144:tail0`
- seq=10 msg=4 chunk=4 child=5 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=7 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=115 msg=26 chunk=0 child=2 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=126 msg=33 chunk=0 child=0 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=138 msg=40 chunk=0 child=1 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1001:0x200f0002:0x34560001:0x6a5b3355:len80:body44:tail0`
- seq=10 msg=4 chunk=4 child=1 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=3 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=155 msg=50 chunk=0 child=6 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=156 msg=51 chunk=0 child=1 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=193 msg=68 chunk=0 child=0 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1003:0x200f0002:0x34560001:0x00000000:len88:body52:tail0`
- seq=10 msg=4 chunk=4 child=3 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=5 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=155 msg=50 chunk=0 child=8 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=184 msg=60 chunk=0 child=None parent=- len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=188 msg=64 chunk=0 child=0 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001542:len132:body96:tail8`
- seq=10 msg=4 chunk=4 child=7 parent=0x010a001b len=132 body=96 inner=0x8027 tail=0201010000000000 u32=0x02010100,0x00000000 pe=blocked preview=opaque reason=tail_policy_unknown_blocked; exact_writer_missing
- seq=10 msg=4 chunk=4 child=8 parent=0x010a001b len=132 body=96 inner=0x8027 tail=0201010000123456 u32=0x02010100,0x00123456 pe=blocked preview=opaque reason=tail_policy_unknown_blocked; exact_writer_missing
- seq=96 msg=20 chunk=0 child=2 parent=0x010a001b len=132 body=96 inner=0x8027 tail=0000000201010000 u32=0x00000002,0x01010000 pe=blocked preview=opaque reason=tail_policy_unknown_blocked; exact_writer_missing
- seq=155 msg=50 chunk=0 child=4 parent=0x010a001b len=132 body=96 inner=0x8027 tail=0201010000000000 u32=0x02010100,0x00000000 pe=blocked preview=opaque reason=tail_policy_unknown_blocked; exact_writer_missing
- seq=156 msg=51 chunk=0 child=3 parent=0x010a001b len=132 body=96 inner=0x8027 tail=0201010000000000 u32=0x02010100,0x00000000 pe=blocked preview=opaque reason=tail_policy_unknown_blocked; exact_writer_missing

### `0x0102000a:0x1004:0x200f0002:0x34560001:0x00000000:len68:body32:tail0`
- seq=10 msg=4 chunk=4 child=6 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=96 msg=20 chunk=0 child=4 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=8 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=156 msg=51 chunk=0 child=2 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=193 msg=68 chunk=0 child=6 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x100a:0x200f0002:0x34560001:0x00000002:len68:body32:tail0`
- seq=10 msg=4 chunk=4 child=4 parent=0x010a001b len=68 body=32 inner=0x100a tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=104 msg=23 chunk=0 child=6 parent=0x010a001b len=68 body=32 inner=0x100a tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=155 msg=50 chunk=0 child=9 parent=0x010a001b len=68 body=32 inner=0x100a tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=193 msg=68 chunk=0 child=3 parent=0x010a001b len=68 body=32 inner=0x100a tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=226 msg=88 chunk=0 child=6 parent=0x010a001b len=68 body=32 inner=0x100a tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0xfffb:0x200f0002:0x34560001:0x01010000:len79:body43:tail0`
- seq=155 msg=50 chunk=0 child=0 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=225 msg=87 chunk=0 child=0 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=297 msg=131 chunk=0 child=0 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=375 msg=171 chunk=0 child=0 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=392 msg=174 chunk=0 child=0 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x2000:0x200f0002:0x34560001:0x00000000:len44:body8:tail0`
- seq=1007 msg=475 chunk=0 child=0 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=1007 msg=475 chunk=0 child=1 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=1010 msg=477 chunk=0 child=0 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=1185 msg=577 chunk=0 child=0 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=1185 msg=577 chunk=0 child=1 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing

### `0x0102000a:0x100f:0x200f0002:0x34560001:0x00000000:len44:body8:tail0`
- seq=212 msg=78 chunk=0 child=3 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=795 msg=361 chunk=0 child=0 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=795 msg=361 chunk=0 child=1 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=795 msg=361 chunk=0 child=2 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=795 msg=361 chunk=0 child=3 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1105:0x200f0002:0x34560001:0x00000001:len93:body57:tail0`
- seq=47 msg=10 chunk=0 child=0 parent=0x010a001b len=93 body=57 inner=0x1105 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=52 msg=13 chunk=0 child=None parent=- len=93 body=57 inner=0x1105 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=104 msg=23 chunk=0 child=2 parent=0x010a001b len=93 body=57 inner=0x1105 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=175 msg=56 chunk=0 child=2 parent=0x010a001b len=93 body=57 inner=0x1105 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=193 msg=68 chunk=0 child=8 parent=0x010a001b len=93 body=57 inner=0x1105 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing

## Semantic Deep Report

本节按方向、完整 shape、字段证据和前序请求解释 reportCode；动态后缀与偶然 hex 不作为固定语义。

- requests: `299`
- responses: `940`
- response/request ratio: `3.1438127090301005`
- state phases: `unknown=1239`
- mirror actions: `none=1239`
- average consistency: `None`
- max source age ms: `None`
- validated shape match rate: `None` (0/0)
- shape match kinds: `-`
- opaque pass-through rate: `None` (0/0)
- response burst max/request/2s: `0x010a0024=32, 0x010a0027=8, 0x010a0010=1`
- burst requests over 3: `0x010a0024=57, 0x010a0027=1`
- accepted timestamps: `15` (`schema:ob-triplet:ob:T1=5, schema:ob-triplet:ob:T2=5, schema:ob-triplet:ob:T3=5`)
- rejected timestamp candidates: `4528` (`ordinary BE32 has no schema-proven timestamp role=3435, candidate falls inside ASCII/hash/string slot=813, candidate crosses a schema/string field boundary=280`)
- 65010 connection: `observed=False status=not_this_flow first=None last=None`

### Every ReportCode

| reportCode | family/subtype | observed | request | response | family role | observed payload roles | confidence | shapes | fields | preceding request |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| `0x010a0024` | `0x010a0024` | 900 | 0 | 900 | 响应反馈（按字段与前序请求解释） | `response_feedback_fields (observed)=900` | `observed` | `-` | `field_a:0x00000000=313, 0x00000337=18, ...; field_b:0x00000001=553, 0x00000000=345, ...; field_c:0x00000194=629, 0x00010194=191, ...` | `0x010a001b <- preceding_request_observed=834, 0x0102000a <- preceding_request_observed=61, 0x01122338 <- preceding_request_observed=2, ...` |
| `0x0102000a` | `0x0102000a` | 797 | 797 | 0 | typed leaf shell；含义由完整 shape 判定 | `typed_leaf_fixed_shape_value (observed)=797` | `confirmed` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000000:len48:body12:tail0=156, 0x0102000a:0x1005:0x200f0002:0x34560001:0x00000002:len60:body24:tail0=109, ...` | `-` | `-` |
| `0x010a001b` | `0x010a001b` | 226 | 226 | 0 | 父容器 | `parent_container (confirmed)=226` | `confirmed` | `-` | `r:0=1, 0/0/0/0/0/0/0=1, ...; cs:b1aee09a/a16d7c85=5, 00000000/00000000=1; ob:6d/d4/6c/0/1/1784361922/1784361932/1784361924/1/0/1=1, 81/d4/ffffffff/0/79/1784362165/1784362175/1784362173/1/0/1=1, ...; state:00b00017=3, 00d00017=2, ...; p:1036/1036,0=1, 1036/1036,1=1, ...` | `-` |
| `0x010a0010` | `0x010a0010` | 20 | 0 | 20 | 响应反馈（按字段与前序请求解释） | `response_feedback_fields (observed)=20` | `observed` | `-` | `field_a:0x0000001e=1, 0x0000005e=1, ...; field_b:0x00000000=20; field_c:0x00000324=20` | `0x010a001b <- preceding_request_observed=20` |
| `0x010a0011` | `0x010a0011` | 20 | 20 | 0 | 配对/保护上下文（观察） | `pairing_or_protection_context_observed (observed)=20` | `observed` | `-` | `-` | `-` |
| `0x01122342` | `0x011223xx / subtype=0x42` | 18 | 18 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=13, device_identity_metadata (observed)=3, application_version_metadata (observed)=1, dynamic_metadata_opaque (unknown)=1` | `confirmed` | `-` | `-` | `-` |
| `0x010a0027` | `0x010a0027` | 17 | 0 | 17 | 响应反馈（按字段与前序请求解释） | `response_feedback_fields (observed)=17` | `observed` | `-` | `field_a:0x00000000=17; field_b:0x00000000=17; field_c:0x00000001=1, 0x00000002=1, ...` | `0x010a001b <- preceding_request_observed=17` |
| `0x0112232e` | `0x011223xx / subtype=0x2e` | 11 | 11 | 0 | 动态 metadata event family；低字节仅为 subtype | `configuration_file_observation (observed)=6, dynamic_metadata_opaque (unknown)=5` | `confirmed` | `-` | `r:0=1` | `-` |
| `0x01122361` | `0x011223xx / subtype=0x61` | 10 | 10 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=9, application_version_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122357` | `0x011223xx / subtype=0x57` | 5 | 5 | 0 | 动态 metadata event family；低字节仅为 subtype | `runtime_api_or_output_route_observation (observed)=5` | `confirmed` | `-` | `-` | `-` |
| `0x01122388` | `0x011223xx / subtype=0x88` | 5 | 5 | 0 | 动态 metadata event family；低字节仅为 subtype | `dynamic_metadata_opaque (unknown)=2, csob_state_snapshot (high)=2, device_profile_metadata (observed)=1` | `confirmed` | `-` | `cs:b1aee09a/a16d7c85=2; ob:95/d4/ffffffff/0/f1/1784362545/1784362555/1784362555/1/0/1=1, a9/d4/ffffffff/0/69/1784362786/1784362796/1784362796/1/0/1=1; state:00b00017=1, 00d00017=1; r:0/3/449/452/382/7/7=1, 0/3/634/637/556/11/11=1; p:1036/1036,2=1, 1036/1036,3=1` | `-` |
| `0x01122338` | `0x011223xx / subtype=0x38` | 4 | 4 | 0 | 动态 metadata event family；低字节仅为 subtype | `runtime_api_or_output_route_observation (observed)=4` | `confirmed` | `-` | `-` | `-` |
| `0x01122343` | `0x011223xx / subtype=0x43` | 4 | 4 | 0 | 动态 metadata event family；低字节仅为 subtype | `csob_state_snapshot (high)=3, device_profile_metadata (observed)=1` | `confirmed` | `-` | `cs:b1aee09a/a16d7c85=3; ob:81/d4/ffffffff/0/79/1784362165/1784362175/1784362173/1/0/1=1, bd/d4/ffffffff/0/e1/1784363026/1784363036/1784363036/1/0/1=1, ...; state:00b00017=2, 00d00017=1; r:0/3/265/268/204/4/4=1, 1/3/817/821/734/14/14=1, ...; p:1036/1036,1=1, 1036/1036,4=1, ...` | `-` |
| `0x0112237a` | `0x011223xx / subtype=0x7a` | 2 | 2 | 0 | 动态 metadata event family；低字节仅为 subtype | `dynamic_metadata_opaque (unknown)=1, device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122389` | `0x011223xx / subtype=0x89` | 2 | 2 | 0 | 动态 metadata event family；低字节仅为 subtype | `certificate_or_trust_observation (observed)=1, device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122329` | `0x011223xx / subtype=0x29` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122334` | `0x011223xx / subtype=0x34` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122335` | `0x011223xx / subtype=0x35` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x0112233c` | `0x011223xx / subtype=0x3c` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `module_or_framework_observation (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122344` | `0x011223xx / subtype=0x44` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x0112234d` | `0x011223xx / subtype=0x4d` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `configuration_file_observation (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122350` | `0x011223xx / subtype=0x50` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122355` | `0x011223xx / subtype=0x55` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122356` | `0x011223xx / subtype=0x56` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122376` | `0x011223xx / subtype=0x76` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122383` | `0x011223xx / subtype=0x83` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122386` | `0x011223xx / subtype=0x86` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `signing_team_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |

### Dynamic 0x011223xx Subtypes

- subtype counts: `0x42=18, 0x2e=11, 0x61=10, 0x88=5, 0x57=5, 0x38=4, 0x43=4, 0x7a=2, 0x89=2, 0x4d=1, 0x83=1, 0x29=1, 0x86=1, 0x56=1, 0x76=1, 0x44=1, 0x3c=1, 0x55=1, 0x34=1, 0x50=1, 0x35=1`
- 低字节只表示动态 subtype；具体含义必须由 payload 字段和上下文判定。

### Timestamp Evidence Boundary

- 只接受 `ob:T1/T2/T3` 和已知 typed-leaf 完整 shape 中的时间字段。
- 普通 BE32、ASCII/hash/string 槽以及跨字段边界候选均拒绝，不再默认高亮。

| seq | reportCode | child | offset | value | rejected reason |
|---:|---|---:|---:|---:|---|
| 1 | `0x00000000` | - | 12 | 3366977536 | ordinary BE32 has no schema-proven timestamp role |
| 2 | `0x00000000` | - | 12 | 3366977536 | ordinary BE32 has no schema-proven timestamp role |
| 2 | `0x00000000` | - | 20 | 1533705442 | candidate crosses a schema/string field boundary |
| 2 | `0x00000000` | - | 36 | 3008826928 | ordinary BE32 has no schema-proven timestamp role |
| 2 | `0x00000000` | - | 44 | 2831045287 | ordinary BE32 has no schema-proven timestamp role |
| 3 | `0x00000000` | - | 12 | 3366977536 | ordinary BE32 has no schema-proven timestamp role |
| 3 | `0x00000000` | - | 36 | 3126001664 | ordinary BE32 has no schema-proven timestamp role |
| 4 | `0x00000000` | - | 12 | 3366977536 | ordinary BE32 has no schema-proven timestamp role |
| 4 | `0x00000000` | - | 20 | 1533705442 | candidate crosses a schema/string field boundary |
| 4 | `0x00000000` | - | 36 | 1863223662 | ordinary BE32 has no schema-proven timestamp role |
| 4 | `0x00000000` | - | 40 | 2436005033 | ordinary BE32 has no schema-proven timestamp role |
| 4 | `0x00000000` | - | 44 | 1232094033 | candidate falls inside ASCII/hash/string slot |

### Unresolved

- reportCodes: `-`
- note: 未知项目前不能证明含义；保留原包与样例，不给出伪确定标签。

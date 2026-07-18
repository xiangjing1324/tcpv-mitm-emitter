# TCPView Shape Bucket Summary

- input: `/tmp/replay-18091.tcpvflow.jsonl.gz`
- source: `display`
- account: `replay-18091`
- cid: `127.0.0.1:54735->nj.cschannel.anticheatexpert.com:443 [acc:6708949272549705871]`
- events: `320`
- shape_buckets: `381`
- policy_note: cleanup only means template bucket / replay sample cleanup; no wire drop; no PE active mutation.

## Report Counts

- reports: `0x010a001b=176, 0x0102000a=91, 0x010a0027=21, 0x010a0010=20, 0x01122388=3, 0x010a0020=2, 0x010a0044=1, 0x010a0057=1, 0x01122389=1, 0x01122350=1`
- inner_types: `0x8029=55, 0x8004=54, 0x1001=50, 0x1002=50, 0x1003=50, 0x1004=50, 0x1008=50, 0x100a=50, 0x1005=49, 0x100e=49, 0x1105=49, 0xfff9=49, 0xfffb=25, 0xfffe=25, 0x8027=25, 0x100f=25, ...`
- parent_roster_layouts: `count-u32=167, compact-count-u8=8, count-u32-partial=1`
- parent_child_count_histogram: `2=57, 3=25, 10=22, 4=16, 11=11, 5=10, 9=10, 7=8, 8=6, 6=6, 16=1, 12=1, ...`

## Top Buckets

| count | inner_type | child_len | body_len | tail_len | pe_decision | preview | shape_key |
|---:|---|---|---|---|---|---|---|
| 50 | `0x1001` | `80=50` | `44=50` | `0=50` | `blocked=50` | `opaque=50` | `0x0102000a:0x1001:0x200f0002:0x34560001:0x6a5b3355:len80:body44:tail0` |
| 50 | `0x1003` | `88=50` | `52=50` | `0=50` | `blocked=50` | `opaque=50` | `0x0102000a:0x1003:0x200f0002:0x34560001:0x00000000:len88:body52:tail0` |
| 50 | `0x1004` | `68=50` | `32=50` | `0=50` | `blocked=50` | `opaque=50` | `0x0102000a:0x1004:0x200f0002:0x34560001:0x00000000:len68:body32:tail0` |
| 50 | `0x1008` | `180=50` | `144=50` | `0=50` | `blocked=50` | `opaque=50` | `0x0102000a:0x1008:0x200f0002:0x34560001:0x0000001a:len180:body144:tail0` |
| 49 | `0x1005` | `60=49` | `24=49` | `0=49` | `blocked=49` | `opaque=49` | `0x0102000a:0x1005:0x200f0002:0x34560001:0x00000002:len60:body24:tail0` |
| 25 | `0x100f` | `44=25` | `8=25` | `0=25` | `blocked=25` | `opaque=25` | `0x0102000a:0x100f:0x200f0002:0x34560001:0x00000000:len44:body8:tail0` |
| 25 | `0xfffb` | `79=25` | `43=25` | `0=25` | `blocked=25` | `opaque=25` | `0x0102000a:0xfffb:0x200f0002:0x34560001:0x01010000:len79:body43:tail0` |
| 24 | `0x2000` | `44=24` | `8=24` | `0=24` | `python_fallback=24` | `opaque=24` | `0x0102000a:0x2000:0x200f0002:0x34560001:0x00000000:len44:body8:tail0` |
| 23 | `0x0100` | `152=23` | `116=23` | `0=23` | `blocked=23` | `opaque=23` | `0x0102000a:0x0100:0x200f0002:0x34560001:0x0000006c:len152:body116:tail0` |
| 18 | `0x100b` | `34=18` | `0=18` | `0=18` | `python_fallback=18` | `opaque=18` | `0x0102000a:0x100b:0x200f0002:0x34560001:0x00000000:len34:body0:tail0` |
| 18 | `0xfffe` | `48=18` | `12=18` | `0=18` | `blocked=18` | `opaque=18` | `0x0102000a:0xfffe:0x200f0002:0x34560001:0x000000fb:len48:body12:tail0` |
| 15 | `0x1009` | `80=15` | `44=15` | `0=15` | `blocked=15` | `opaque=15` | `0x0102000a:0x1009:0x200f0002:0x34560001:0x4a20b82c:len80:body44:tail0` |
| 13 | `0x100d` | `112=13` | `76=13` | `0=13` | `blocked=13` | `opaque=13` | `0x0102000a:0x100d:0x200f0002:0x34560001:0x00000000:len112:body76:tail0` |
| 9 | `0x1006` | `48=9` | `12=9` | `0=9` | `blocked=9` | `opaque=9` | `0x0102000a:0x1006:0x200f0002:0x34560001:0x159400c0:len48:body12:tail0` |
| 8 | `0x1011` | `122=8` | `86=8` | `0=8` | `blocked=8` | `opaque=8` | `0x0102000a:0x1011:0x200f0002:0x34560001:0x00000000:len122:body86:tail0` |
| 7 | `0x100c` | `84=7` | `48=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0x100c:0x200f0002:0x34560001:0xb2704fe8:len84:body48:tail0` |
| 7 | `0x100e` | `48=7` | `12=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000000:len48:body12:tail0` |
| 7 | `0x100e` | `48=7` | `12=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000001:len48:body12:tail0` |
| 7 | `0x100e` | `48=7` | `12=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000002:len48:body12:tail0` |
| 7 | `0xfff9` | `42=7` | `6=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0xfff9:0x00000002:0x34560001:0x00000081:len42:body6:tail0` |
| 7 | `0xfff9` | `42=7` | `6=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0xfff9:0x00000002:0x34560001:0x00000083:len42:body6:tail0` |
| 7 | `0xfff9` | `42=7` | `6=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0xfff9:0x00000002:0x34560001:0x00000084:len42:body6:tail0` |
| 7 | `0xfff9` | `42=7` | `6=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0xfff9:0x00000002:0x34560001:0x00000085:len42:body6:tail0` |
| 7 | `0xfff9` | `42=7` | `6=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0xfff9:0x00000002:0x34560001:0x00000086:len42:body6:tail0` |
| 7 | `0xfff9` | `42=7` | `6=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0xfff9:0x00000002:0x34560001:0x00000089:len42:body6:tail0` |
| 7 | `0xfff9` | `42=7` | `6=7` | `0=7` | `blocked=7` | `opaque=7` | `0x0102000a:0xfff9:0x00000002:0x34560001:0x00000090:len42:body6:tail0` |
| 6 | `0x100b` | `34=6` | `0=6` | `0=6` | `python_fallback=6` | `opaque=6` | `0x0102000a:0x100b:0x200f0002:0x34560001:0x00001234:len34:body0:tail0` |
| 6 | `0x100e` | `48=6` | `12=6` | `0=6` | `blocked=6` | `opaque=6` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000003:len48:body12:tail0` |
| 6 | `0x100e` | `48=6` | `12=6` | `0=6` | `blocked=6` | `opaque=6` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000006:len48:body12:tail0` |
| 6 | `0x100e` | `48=6` | `12=6` | `0=6` | `blocked=6` | `opaque=6` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000007:len48:body12:tail0` |
| 6 | `0x8029` | `87=6` | `51=6` | `8=6` | `blocked=6` | `opaque=6` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len87:body51:tail8` |
| 5 | `0x100e` | `48=5` | `12=5` | `0=5` | `blocked=5` | `opaque=5` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000004:len48:body12:tail0` |
| 5 | `0x100e` | `48=5` | `12=5` | `0=5` | `blocked=5` | `opaque=5` | `0x0102000a:0x100e:0x200f0002:0x34560001:0x00000005:len48:body12:tail0` |
| 4 | `0x0007` | `144=4` | `108=4` | `0=4` | `observe_only=4` | `text_candidate=4` | `0x0102000a:0x0007:0x200f0002:0x34560001:0x00000001:len144:body108:tail0` |
| 4 | `0x8029` | `71=4` | `35=4` | `8=4` | `blocked=4` | `opaque=4` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000003e:len71:body35:tail8` |
| 4 | `0x8029` | `102=4` | `66=4` | `8=4` | `blocked=4` | `opaque=4` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len102:body66:tail8` |
| 4 | `0x8029` | `85=4` | `49=4` | `8=4` | `blocked=4` | `opaque=4` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000004d:len85:body49:tail8` |
| 4 | `0x8029` | `102=4` | `66=4` | `8=4` | `blocked=4` | `opaque=4` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000150e:len102:body66:tail8` |
| 3 | `0x1007` | `64=3` | `28=3` | `0=3` | `blocked=3` | `opaque=3` | `0x0102000a:0x1007:0x200f0002:0x34560001:0x4a20b82c:len64:body28:tail0` |
| 3 | `0xfffe` | `47=3` | `11=3` | `0=3` | `blocked=3` | `opaque=3` | `0x0102000a:0xfffe:0x200f0002:0x34560001:0x000000fb:len47:body11:tail0` |

## Blocked Buckets

| count | inner_type | tail | reason | cleanup_hint | samples |
|---:|---|---|---|---|---|
| 50 | `0x1001` | `-=50` | `opaque_body; exact_writer_missing=50` | `template_bucket_only / no_wire_drop=50` | `seq=29/msg=17/child=4, seq=45/msg=33/child=4, seq=56/msg=43/child=6` |
| 50 | `0x1003` | `-=50` | `opaque_body; exact_writer_missing=50` | `template_bucket_only / no_wire_drop=50` | `seq=29/msg=17/child=6, seq=45/msg=33/child=6, seq=56/msg=43/child=8` |
| 50 | `0x1004` | `-=50` | `opaque_body; exact_writer_missing=50` | `template_bucket_only / no_wire_drop=50` | `seq=29/msg=17/child=7, seq=45/msg=33/child=7, seq=56/msg=43/child=9` |
| 50 | `0x1008` | `-=50` | `opaque_body; exact_writer_missing=50` | `template_bucket_only / no_wire_drop=50` | `seq=30/msg=18/child=0, seq=45/msg=33/child=8, seq=56/msg=43/child=10` |
| 49 | `0x1005` | `-=49` | `opaque_body; exact_writer_missing=49` | `template_bucket_only / no_wire_drop=49` | `seq=45/msg=33/child=1, seq=56/msg=43/child=2, seq=65/msg=52/child=1` |
| 25 | `0x100f` | `-=25` | `opaque_body; exact_writer_missing=25` | `template_bucket_only / no_wire_drop=25` | `seq=46/msg=33/child=0, seq=66/msg=53/child=1, seq=79/msg=9/child=8` |
| 25 | `0xfffb` | `-=25` | `opaque_body; exact_writer_missing=25` | `template_bucket_only / no_wire_drop=25` | `seq=29/msg=17/child=1, seq=56/msg=43/child=0, seq=72/msg=59/child=1` |
| 23 | `0x0100` | `-=23` | `opaque_body; exact_writer_missing=23` | `template_bucket_only / no_wire_drop=23` | `seq=79/msg=9/child=9, seq=100/msg=28/child=8, seq=110/msg=38/child=3` |
| 18 | `0xfffe` | `-=18` | `opaque_body; exact_writer_missing=18` | `template_bucket_only / no_wire_drop=18` | `seq=72/msg=59/child=2, seq=89/msg=19/child=1, seq=105/msg=33/child=1` |
| 15 | `0x1009` | `-=15` | `opaque_body; exact_writer_missing=15` | `template_bucket_only / no_wire_drop=15` | `seq=90/msg=19/child=8, seq=109/msg=37/child=8, seq=121/msg=48/child=8` |
| 13 | `0x100d` | `-=13` | `opaque_body; exact_writer_missing=13` | `template_bucket_only / no_wire_drop=13` | `seq=66/msg=53/child=0, seq=79/msg=9/child=7, seq=110/msg=38/child=1` |
| 9 | `0x1006` | `-=9` | `opaque_body; exact_writer_missing=9` | `template_bucket_only / no_wire_drop=9` | `seq=106/msg=34/child=4, seq=124/msg=50/child=7, seq=150/msg=72/child=4` |
| 8 | `0x1011` | `-=8` | `opaque_body; exact_writer_missing=8` | `template_bucket_only / no_wire_drop=8` | `seq=30/msg=18/child=2, seq=115/msg=43/child=9, seq=139/msg=63/child=9` |
| 7 | `0x100c` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=110/msg=38/child=0, seq=134/msg=59/child=8, seq=161/msg=81/child=9` |
| 7 | `0x100e` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=45/msg=33/child=2, seq=99/msg=27/child=1, seq=133/msg=59/child=1` |
| 7 | `0x100e` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=56/msg=43/child=3, seq=105/msg=33/child=3, seq=139/msg=63/child=1` |
| 7 | `0x100e` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=65/msg=52/child=2, seq=109/msg=37/child=1, seq=142/msg=66/child=1` |
| 7 | `0xfff9` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=112/msg=40/child=0, seq=137/msg=61/child=0, seq=166/msg=85/child=0` |
| 7 | `0xfff9` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=112/msg=40/child=1, seq=137/msg=61/child=1, seq=166/msg=85/child=1` |
| 7 | `0xfff9` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=112/msg=40/child=2, seq=137/msg=61/child=2, seq=166/msg=85/child=2` |
| 7 | `0xfff9` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=112/msg=40/child=3, seq=137/msg=61/child=3, seq=166/msg=85/child=3` |
| 7 | `0xfff9` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=112/msg=40/child=4, seq=137/msg=61/child=4, seq=167/msg=86/child=0` |
| 7 | `0xfff9` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=112/msg=40/child=5, seq=137/msg=61/child=5, seq=167/msg=86/child=1` |
| 7 | `0xfff9` | `-=7` | `opaque_body; exact_writer_missing=7` | `template_bucket_only / no_wire_drop=7` | `seq=112/msg=40/child=6, seq=137/msg=61/child=6, seq=167/msg=86/child=2` |
| 6 | `0x100e` | `-=6` | `opaque_body; exact_writer_missing=6` | `template_bucket_only / no_wire_drop=6` | `seq=72/msg=59/child=4, seq=115/msg=43/child=1, seq=149/msg=72/child=3` |
| 6 | `0x100e` | `-=6` | `opaque_body; exact_writer_missing=6` | `template_bucket_only / no_wire_drop=6` | `seq=77/msg=7/child=1, seq=124/msg=50/child=1, seq=160/msg=81/child=1` |
| 6 | `0x100e` | `-=6` | `opaque_body; exact_writer_missing=6` | `template_bucket_only / no_wire_drop=6` | `seq=90/msg=19/child=1, seq=130/msg=56/child=1, seq=168/msg=87/child=3` |
| 6 | `0x8029` | `030000001e000000=3, 010000001e000000=1, 000000030000001e=1, ...` | `tail_policy_unknown_blocked; exact_writer_missing=6` | `template_bucket_only / no_wire_drop=6` | `seq=84/msg=14/child=0, seq=86/msg=16/child=None, seq=87/msg=17/child=0` |
| 5 | `0x100e` | `-=5` | `opaque_body; exact_writer_missing=5` | `template_bucket_only / no_wire_drop=5` | `seq=116/msg=44/child=1, seq=153/msg=74/child=1, seq=186/msg=104/child=1` |
| 5 | `0x100e` | `-=5` | `opaque_body; exact_writer_missing=5` | `template_bucket_only / no_wire_drop=5` | `seq=121/msg=48/child=1, seq=158/msg=79/child=1, seq=194/msg=110/child=1` |
| 4 | `0x8029` | `0000000100000002=3, 0100000002000000=1` | `tail_policy_unknown_blocked; exact_writer_missing=4` | `template_bucket_only / no_wire_drop=4` | `seq=98/msg=26/child=None, seq=101/msg=29/child=None, seq=255/msg=171/child=None` |
| 4 | `0x8029` | `030000001e000000=3, 000000030000001e=1` | `tail_policy_unknown_blocked; exact_writer_missing=4` | `template_bucket_only / no_wire_drop=4` | `seq=94/msg=22/child=0, seq=95/msg=23/child=0, seq=238/msg=154/child=None` |
| 4 | `0x8029` | `000000030000003a=3, 030000003a000000=1` | `tail_policy_unknown_blocked; exact_writer_missing=4` | `template_bucket_only / no_wire_drop=4` | `seq=76/msg=6/child=None, seq=80/msg=10/child=None, seq=234/msg=150/child=None` |
| 4 | `0x8029` | `0000000300000002=3, 0300000002000000=1` | `tail_policy_unknown_blocked; exact_writer_missing=4` | `template_bucket_only / no_wire_drop=4` | `seq=60/msg=47/child=None, seq=61/msg=48/child=0, seq=198/msg=114/child=None` |
| 3 | `0x1007` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=65/msg=52/child=8, seq=161/msg=81/child=4, seq=288/msg=201/child=4` |
| 3 | `0xfffe` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=56/msg=43/child=1, seq=120/msg=48/child=1, seq=284/msg=197/child=1` |
| 3 | `0xfffe` | `-=3` | `opaque_body; exact_writer_missing=3` | `template_bucket_only / no_wire_drop=3` | `seq=183/msg=101/child=1, seq=276/msg=189/child=1, seq=313/msg=225/child=1` |
| 2 | `0x0100` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=46/msg=33/child=1, seq=66/msg=53/child=3` |
| 2 | `0x1002` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=115/msg=43/child=4, seq=116/msg=44/child=4` |
| 2 | `0x1002` | `-=2` | `opaque_body; exact_writer_missing=2` | `template_bucket_only / no_wire_drop=2` | `seq=139/msg=63/child=4, seq=143/msg=67/child=1` |

## 0x8027 / 0x8029 Tail Patterns

| inner_type | count | tail_len | tail_hex | tail_u32 | shape_key |
|---|---:|---|---|---|---|
| `0x8029` | 6 | `8=6` | `030000001e000000=3, 010000001e000000=1, 000000030000001e=1, 000000010000001e=1` | `0x03000000,0x1e000000=3, 0x01000000,0x1e000000=1, 0x00000003,0x0000001e=1, 0x00000001,0x0000001e=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len87:body51:tail8` |
| `0x8029` | 4 | `8=4` | `0000000100000002=3, 0100000002000000=1` | `0x00000001,0x00000002=3, 0x01000000,0x02000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000003e:len71:body35:tail8` |
| `0x8029` | 4 | `8=4` | `030000001e000000=3, 000000030000001e=1` | `0x03000000,0x1e000000=3, 0x00000003,0x0000001e=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len102:body66:tail8` |
| `0x8029` | 4 | `8=4` | `000000030000003a=3, 030000003a000000=1` | `0x00000003,0x0000003a=3, 0x03000000,0x3a000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000004d:len85:body49:tail8` |
| `0x8029` | 4 | `8=4` | `0000000300000002=3, 0300000002000000=1` | `0x00000003,0x00000002=3, 0x03000000,0x02000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000150e:len102:body66:tail8` |
| `0x8027` | 2 | `8=2` | `0201010000000000=2` | `0x02010100,0x00000000=2` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00000c61:len104:body68:tail8` |
| `0x8027` | 2 | `8=2` | `0000000201010000=2` | `0x00000002,0x01010000=2` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00000f8c:len126:body90:tail8` |
| `0x8027` | 2 | `8=2` | `0000000201010000=1, 0201010000000000=1` | `0x00000002,0x01010000=1, 0x02010100,0x00000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000012ca:len103:body67:tail8` |
| `0x8027` | 2 | `8=2` | `000000020101000e=1, 020101000e123456=1` | `0x00000002,0x0101000e=1, 0x02010100,0x0e123456=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x0000149a:len114:body78:tail8` |
| `0x8027` | 2 | `8=2` | `0000000201010000=2` | `0x00000002,0x01010000=2` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001548:len118:body82:tail8` |
| `0x8029` | 2 | `8=2` | `0100000002000000=1, 0000000100000002=1` | `0x01000000,0x02000000=1, 0x00000001,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000021:len69:body33:tail8` |
| `0x8029` | 2 | `8=2` | `0100000002000000=1, 0000000100000002=1` | `0x01000000,0x02000000=1, 0x00000001,0x00000002=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000030:len75:body39:tail8` |
| `0x8029` | 2 | `8=2` | `0000000300000002=2` | `0x00000003,0x00000002=2` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000042:len101:body65:tail8` |
| `0x8029` | 2 | `8=2` | `000000010000001e=1, 010000001e123456=1` | `0x00000001,0x0000001e=1, 0x01000000,0x1e123456=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len106:body70:tail8` |
| `0x8029` | 2 | `8=2` | `000000030000001e=2` | `0x00000003,0x0000001e=2` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len82:body46:tail8` |
| `0x8029` | 2 | `8=2` | `000000030000001e=2` | `0x00000003,0x0000001e=2` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000046:len88:body52:tail8` |
| `0x8029` | 2 | `8=2` | `010000003a123456=1, 000000010000003a=1` | `0x01000000,0x3a123456=1, 0x00000001,0x0000003a=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000004d:len86:body50:tail8` |
| `0x8029` | 2 | `8=2` | `0000000100000000=2` | `0x00000001,0x00000000=2` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000062:len77:body41:tail8` |
| `0x8029` | 2 | `8=2` | `0300000018000000=1, 0000000300000018=1` | `0x03000000,0x18000000=1, 0x00000003,0x00000018=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000026c:len103:body67:tail8` |
| `0x8029` | 2 | `8=2` | `0000000100000002=1, 0100000002000000=1` | `0x00000001,0x00000002=1, 0x01000000,0x02000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x000012a1:len95:body59:tail8` |
| `0x8029` | 2 | `8=2` | `0000000100000000=1, 0100000000123456=1` | `0x00000001,0x00000000=1, 0x01000000,0x00123456=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00001548:len104:body68:tail8` |
| `0x8029` | 2 | `8=2` | `0300000000000000=2` | `0x03000000,0x00000000=2` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00001548:len108:body72:tail8` |
| `0x8027` | 1 | `8=1` | `0201010018123456=1` | `0x02010100,0x18123456=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x0000026c:len114:body78:tail8` |
| `0x8027` | 1 | `8=1` | `020101001f000000=1` | `0x02010100,0x1f000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00000282:len134:body98:tail8` |
| `0x8027` | 1 | `8=1` | `0000000201010000=1` | `0x00000002,0x01010000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000002a2:len143:body107:tail8` |
| `0x8027` | 1 | `8=1` | `0201010000000000=1` | `0x02010100,0x00000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000002a5:len127:body91:tail8` |
| `0x8027` | 1 | `8=1` | `0000000201010000=1` | `0x00000002,0x01010000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x000002ed:len110:body74:tail8` |
| `0x8027` | 1 | `8=1` | `0000000201010000=1` | `0x00000002,0x01010000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001448:len143:body107:tail8` |
| `0x8027` | 1 | `8=1` | `0000000201010000=1` | `0x00000002,0x01010000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x0000144d:len118:body82:tail8` |
| `0x8027` | 1 | `8=1` | `0000000201010000=1` | `0x00000002,0x01010000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x0000151d:len114:body78:tail8` |
| `0x8027` | 1 | `8=1` | `0201010000123456=1` | `0x02010100,0x00123456=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x0000151f:len166:body130:tail8` |
| `0x8027` | 1 | `8=1` | `0201010000000000=1` | `0x02010100,0x00000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001520:len139:body103:tail8` |
| `0x8027` | 1 | `8=1` | `0000000202020000=1` | `0x00000002,0x02020000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001521:len127:body91:tail8` |
| `0x8027` | 1 | `8=1` | `0000000201010000=1` | `0x00000002,0x01010000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001522:len144:body108:tail8` |
| `0x8027` | 1 | `8=1` | `0201010000123456=1` | `0x02010100,0x00123456=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001523:len148:body112:tail8` |
| `0x8027` | 1 | `8=1` | `0201010000123456=1` | `0x02010100,0x00123456=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001524:len140:body104:tail8` |
| `0x8027` | 1 | `8=1` | `0201010000000000=1` | `0x02010100,0x00000000=1` | `0x0102000a:0x8027:0x200f0002:0x34560001:0x00001542:len132:body96:tail8` |
| `0x8029` | 1 | `8=1` | `0300000002000000=1` | `0x03000000,0x02000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x00000065:len90:body54:tail8` |
| `0x8029` | 1 | `8=1` | `0300000006000000=1` | `0x03000000,0x06000000=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000007d:len105:body69:tail8` |
| `0x8029` | 1 | `8=1` | `0000000100000006=1` | `0x00000001,0x00000006=1` | `0x0102000a:0x8029:0x200f0002:0x34560001:0x0000007d:len92:body56:tail8` |

## 0xFFF2 Region/Path Clusters

| count | child_len | body_len | leaf_id/reserved | sibling_0112_context | shape_key |
|---:|---|---|---|---|---|
| 1 | `101=1` | `65=1` | `0x00000087=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x00570001:0x01000000:len101:body65:tail0` |
| 1 | `171=1` | `135=1` | `0x00000086=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x00570001:0x038999c6:len171:body135:tail0` |
| 1 | `101=1` | `65=1` | `0x0000014b=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x01ba0001:0x01000000:len101:body65:tail0` |
| 1 | `101=1` | `65=1` | `0x0000018f=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x022c0001:0x01000000:len101:body65:tail0` |
| 1 | `101=1` | `65=1` | `0x00000226=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x031a0001:0x01000000:len101:body65:tail0` |
| 1 | `171=1` | `135=1` | `0x0000026a=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x038f0001:0x038999c6:len171:body135:tail0` |
| 1 | `101=1` | `65=1` | `0x0000026b=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x03900001:0x01000000:len101:body65:tail0` |
| 1 | `101=1` | `65=1` | `0x00000327=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x047a0001:0x01000000:len101:body65:tail0` |
| 1 | `101=1` | `65=1` | `0x0000037e=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x04f20001:0x01000000:len101:body65:tail0` |
| 1 | `101=1` | `65=1` | `0x00000400=1` | `-` | `0x0102000a:0xfff2:0x00000000:0x05da0001:0x01000000:len101:body65:tail0` |

## Sample Children

### `0x0102000a:0x1001:0x200f0002:0x34560001:0x6a5b3355:len80:body44:tail0`
- seq=29 msg=17 chunk=0 child=4 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=45 msg=33 chunk=0 child=4 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=56 msg=43 chunk=0 child=6 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=65 msg=52 chunk=0 child=4 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=72 msg=59 chunk=0 child=6 parent=0x010a001b len=80 body=44 inner=0x1001 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1003:0x200f0002:0x34560001:0x00000000:len88:body52:tail0`
- seq=29 msg=17 chunk=0 child=6 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=45 msg=33 chunk=0 child=6 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=56 msg=43 chunk=0 child=8 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=65 msg=52 chunk=0 child=6 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=72 msg=59 chunk=0 child=8 parent=0x010a001b len=88 body=52 inner=0x1003 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1004:0x200f0002:0x34560001:0x00000000:len68:body32:tail0`
- seq=29 msg=17 chunk=0 child=7 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=45 msg=33 chunk=0 child=7 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=56 msg=43 chunk=0 child=9 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=65 msg=52 chunk=0 child=7 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=72 msg=59 chunk=0 child=9 parent=0x010a001b len=68 body=32 inner=0x1004 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1008:0x200f0002:0x34560001:0x0000001a:len180:body144:tail0`
- seq=30 msg=18 chunk=0 child=0 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=45 msg=33 chunk=0 child=8 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=56 msg=43 chunk=0 child=10 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=65 msg=52 chunk=0 child=9 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=73 msg=60 chunk=0 child=0 parent=0x010a001b len=180 body=144 inner=0x1008 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1005:0x200f0002:0x34560001:0x00000002:len60:body24:tail0`
- seq=45 msg=33 chunk=0 child=1 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=56 msg=43 chunk=0 child=2 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=65 msg=52 chunk=0 child=1 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=72 msg=59 chunk=0 child=3 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=77 msg=7 chunk=0 child=0 parent=0x010a001b len=60 body=24 inner=0x1005 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x100f:0x200f0002:0x34560001:0x00000000:len44:body8:tail0`
- seq=46 msg=33 chunk=1 child=0 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=66 msg=53 chunk=0 child=1 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=79 msg=9 chunk=0 child=8 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=100 msg=28 chunk=0 child=7 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=110 msg=38 chunk=0 child=2 parent=0x010a001b len=44 body=8 inner=0x100f tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0xfffb:0x200f0002:0x34560001:0x01010000:len79:body43:tail0`
- seq=29 msg=17 chunk=0 child=1 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=56 msg=43 chunk=0 child=0 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=72 msg=59 chunk=0 child=1 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=89 msg=19 chunk=0 child=0 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=105 msg=33 chunk=0 child=0 parent=0x010a001b len=79 body=43 inner=0xfffb tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x2000:0x200f0002:0x34560001:0x00000000:len44:body8:tail0`
- seq=49 msg=36 chunk=0 child=0 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=65 msg=52 chunk=0 child=0 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=84 msg=14 chunk=0 child=1 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=104 msg=32 chunk=0 child=1 parent=0x010a001b len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=111 msg=39 chunk=0 child=None parent=- len=44 body=8 inner=0x2000 tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing

### `0x0102000a:0x0100:0x200f0002:0x34560001:0x0000006c:len152:body116:tail0`
- seq=79 msg=9 chunk=0 child=9 parent=0x010a001b len=152 body=116 inner=0x0100 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=100 msg=28 chunk=0 child=8 parent=0x010a001b len=152 body=116 inner=0x0100 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=110 msg=38 chunk=0 child=3 parent=0x010a001b len=152 body=116 inner=0x0100 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=117 msg=45 chunk=0 child=None parent=- len=152 body=116 inner=0x0100 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=125 msg=51 chunk=0 child=2 parent=0x010a001b len=152 body=116 inner=0x0100 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x100b:0x200f0002:0x34560001:0x00000000:len34:body0:tail0`
- seq=79 msg=9 chunk=0 child=6 parent=0x010a001b len=34 body=0 inner=0x100b tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=100 msg=28 chunk=0 child=6 parent=0x010a001b len=34 body=0 inner=0x100b tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=116 msg=44 chunk=0 child=9 parent=0x010a001b len=34 body=0 inner=0x100b tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=134 msg=59 chunk=1 child=7 parent=0x010a001b len=34 body=0 inner=0x100b tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing
- seq=143 msg=67 chunk=0 child=6 parent=0x010a001b len=34 body=0 inner=0x100b tail=- u32=- pe=python_fallback preview=opaque reason=string_slot_candidate_same_length_only; exact_writer_missing

### `0x0102000a:0xfffe:0x200f0002:0x34560001:0x000000fb:len48:body12:tail0`
- seq=72 msg=59 chunk=0 child=2 parent=0x010a001b len=48 body=12 inner=0xfffe tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=89 msg=19 chunk=0 child=1 parent=0x010a001b len=48 body=12 inner=0xfffe tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=105 msg=33 chunk=0 child=1 parent=0x010a001b len=48 body=12 inner=0xfffe tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=114 msg=42 chunk=0 child=1 parent=0x010a001b len=48 body=12 inner=0xfffe tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=129 msg=55 chunk=0 child=1 parent=0x010a001b len=48 body=12 inner=0xfffe tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

### `0x0102000a:0x1009:0x200f0002:0x34560001:0x4a20b82c:len80:body44:tail0`
- seq=90 msg=19 chunk=1 child=8 parent=0x010a001b len=80 body=44 inner=0x1009 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=109 msg=37 chunk=0 child=8 parent=0x010a001b len=80 body=44 inner=0x1009 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=121 msg=48 chunk=1 child=8 parent=0x010a001b len=80 body=44 inner=0x1009 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=134 msg=59 chunk=1 child=5 parent=0x010a001b len=80 body=44 inner=0x1009 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing
- seq=150 msg=72 chunk=1 child=6 parent=0x010a001b len=80 body=44 inner=0x1009 tail=- u32=- pe=blocked preview=opaque reason=opaque_body; exact_writer_missing

## Semantic Deep Report

本节按方向、完整 shape、字段证据和前序请求解释 reportCode；动态后缀与偶然 hex 不作为固定语义。

- requests: `275`
- responses: `45`
- response/request ratio: `0.16363636363636364`
- state phases: `unknown=320`
- mirror actions: `none=320`
- average consistency: `None`
- max source age ms: `None`
- validated shape match rate: `None` (0/0)
- shape match kinds: `-`
- opaque pass-through rate: `None` (0/0)
- response burst max/request/2s: `0x010a0027=8, 0x010a0044=1, 0x010a0057=1, 0x010a0010=1, 0x010a0020=1`
- burst requests over 3: `0x010a0027=1`
- accepted timestamps: `18` (`schema:ob-triplet:ob:T1=6, schema:ob-triplet:ob:T2=6, schema:ob-triplet:ob:T3=6`)
- rejected timestamp candidates: `4800` (`ordinary BE32 has no schema-proven timestamp role=3642, candidate falls inside ASCII/hash/string slot=898, candidate crosses a schema/string field boundary=260`)
- 65010 connection: `observed=False status=not_this_flow first=None last=None`

### Every ReportCode

| reportCode | family/subtype | observed | request | response | family role | observed payload roles | confidence | shapes | fields | preceding request |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| `0x0102000a` | `0x0102000a` | 955 | 955 | 0 | typed leaf shell；含义由完整 shape 判定 | `typed_leaf_fixed_shape_value (observed)=955` | `confirmed` | `0x0102000a:0x1001:0x200f0002:0x34560001:0x6a5b3355:len80:body44:tail0=50, 0x0102000a:0x1003:0x200f0002:0x34560001:0x00000000:len88:body52:tail0=50, ...` | `-` | `-` |
| `0x010a001b` | `0x010a001b` | 176 | 176 | 0 | 父容器 | `parent_container (confirmed)=176` | `confirmed` | `-` | `r:0=1, 0/0/0/0/0/0/0=1, ...; cs:b1aee09a/a16d7c85=6, 00000000/00000000=1; ob:35/d4/6c/0/1/1784361814/1784361824/1784361816/1/0/1=1, 49/d4/ffffffff/0/79/1784362054/1784362064/1784362056/1/0/1=1, ...; state:00b00017=6, 00300015=1; p:5448/5448,0=1, 5448/5448,1=1, ...` | `-` |
| `0x010a0027` | `0x010a0027` | 21 | 0 | 21 | 响应反馈（按字段与前序请求解释） | `response_feedback_fields (observed)=21` | `observed` | `-` | `field_a:0x00000000=21; field_b:0x00000000=21; field_c:0x0000000a=2, 0x0000000b=2, ...` | `0x010a001b <- preceding_request_observed=17, 0x0102000a <- weak_time_association=2, 0x010a001b <- weak_time_association=2` |
| `0x010a0010` | `0x010a0010` | 20 | 0 | 20 | 响应反馈（按字段与前序请求解释） | `response_feedback_fields (observed)=20` | `observed` | `-` | `field_a:0x00000013=1, 0x00000074=1, ...; field_b:0x00000000=20; field_c:0x00240324=20` | `0x010a001b <- preceding_request_observed=20` |
| `0x010a0011` | `0x010a0011` | 20 | 20 | 0 | 配对/保护上下文（观察） | `pairing_or_protection_context_observed (observed)=20` | `observed` | `-` | `-` | `-` |
| `0x01122342` | `0x011223xx / subtype=0x42` | 20 | 20 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=16, device_identity_metadata (observed)=2, application_version_metadata (observed)=2` | `confirmed` | `-` | `-` | `-` |
| `0x01122388` | `0x011223xx / subtype=0x88` | 9 | 9 | 0 | 动态 metadata event family；低字节仅为 subtype | `csob_state_snapshot (high)=5, device_profile_metadata (observed)=3, dynamic_metadata_opaque (unknown)=1` | `confirmed` | `-` | `cs:b1aee09a/a16d7c85=5; ob:49/d4/ffffffff/0/79/1784362054/1784362064/1784362056/1/0/1=1, 5d/d4/ffffffff/0/f1/1784362295/1784362305/1784362297/1/0/1=1, ...; state:00b00017=5; r:0/3/193/196/192/0/0=1, 0/3/346/349/339/4/4=1, ...; p:5448/5448,1=1, 5448/5448,2=1, ...` | `-` |
| `0x01122366` | `0x011223xx / subtype=0x66` | 8 | 8 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=6, device_identity_metadata (observed)=1, dynamic_metadata_opaque (unknown)=1` | `confirmed` | `-` | `-` | `-` |
| `0x0112232e` | `0x011223xx / subtype=0x2e` | 5 | 5 | 0 | 动态 metadata event family；低字节仅为 subtype | `dynamic_metadata_opaque (unknown)=3, configuration_file_observation (observed)=2` | `confirmed` | `-` | `-` | `-` |
| `0x0112234d` | `0x011223xx / subtype=0x4d` | 4 | 4 | 0 | 动态 metadata event family；低字节仅为 subtype | `dynamic_metadata_opaque (unknown)=2, configuration_file_observation (observed)=1, device_profile_metadata (observed)=1` | `confirmed` | `-` | `r:0=1` | `-` |
| `0x01122352` | `0x011223xx / subtype=0x52` | 4 | 4 | 0 | 动态 metadata event family；低字节仅为 subtype | `configuration_file_observation (observed)=4` | `confirmed` | `-` | `-` | `-` |
| `0x01122389` | `0x011223xx / subtype=0x89` | 3 | 3 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=2, certificate_or_trust_observation (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x010a0020` | `0x010a0020` | 2 | 0 | 2 | 目前不能证明含义 | `unresolved_payload (unknown)=2` | `unknown` | `-` | `-` | `0x010a001b <- preceding_request_observed=2` |
| `0x0112237a` | `0x011223xx / subtype=0x7a` | 2 | 2 | 0 | 动态 metadata event family；低字节仅为 subtype | `dynamic_metadata_opaque (unknown)=1, device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x010a0044` | `0x010a0044` | 1 | 0 | 1 | 响应反馈（按字段与前序请求解释） | `response_feedback_fields (observed)=1` | `observed` | `-` | `field_a:0x0000000b=1; field_b:0x00000000=1; field_c:0x00006239=1` | `0x010a001b <- preceding_request_observed=1` |
| `0x010a0057` | `0x010a0057` | 1 | 0 | 1 | 响应反馈（按字段与前序请求解释） | `response_feedback_fields (observed)=1` | `observed` | `-` | `field_a:0x00000000=1; field_b:0x00000000=1; field_c:0x00000000=1` | `0x010a001b <- preceding_request_observed=1` |
| `0x01122334` | `0x011223xx / subtype=0x34` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122336` | `0x011223xx / subtype=0x36` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122337` | `0x011223xx / subtype=0x37` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x0112233a` | `0x011223xx / subtype=0x3a` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122343` | `0x011223xx / subtype=0x43` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122348` | `0x011223xx / subtype=0x48` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `csob_state_snapshot (high)=1` | `confirmed` | `-` | `cs:b1aee09a/a16d7c85=1; ob:ac/d4/ffffffff/0/d0/1784363247/1784363257/1784363259/0/0/1=1; state:00b00017=1; r:0/3/970/973/940/16/16=1; p:5448/5448,6=1` | `-` |
| `0x01122350` | `0x011223xx / subtype=0x50` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122357` | `0x011223xx / subtype=0x57` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `device_profile_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122360` | `0x011223xx / subtype=0x60` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `module_or_framework_observation (observed)=1` | `confirmed` | `-` | `-` | `-` |
| `0x01122386` | `0x011223xx / subtype=0x86` | 1 | 1 | 0 | 动态 metadata event family；低字节仅为 subtype | `signing_team_metadata (observed)=1` | `confirmed` | `-` | `-` | `-` |

### Dynamic 0x011223xx Subtypes

- subtype counts: `0x42=20, 0x88=9, 0x66=8, 0x2e=5, 0x4d=4, 0x52=4, 0x89=3, 0x7a=2, 0x43=1, 0x86=1, 0x37=1, 0x57=1, 0x60=1, 0x36=1, 0x50=1, 0x34=1, 0x3a=1, 0x48=1`
- 低字节只表示动态 subtype；具体含义必须由 payload 字段和上下文判定。

### Timestamp Evidence Boundary

- 只接受 `ob:T1/T2/T3` 和已知 typed-leaf 完整 shape 中的时间字段。
- 普通 BE32、ASCII/hash/string 槽以及跨字段边界候选均拒绝，不再默认高亮。

| seq | reportCode | child | offset | value | rejected reason |
|---:|---|---:|---:|---:|---|
| 1 | `0x00000000` | - | 4 | 3439394816 | ordinary BE32 has no schema-proven timestamp role |
| 1 | `0x00000000` | - | 12 | 3366977536 | ordinary BE32 has no schema-proven timestamp role |
| 1 | `0x00000000` | - | 20 | 1533724420 | candidate crosses a schema/string field boundary |
| 1 | `0x00000000` | - | 28 | 2352709792 | ordinary BE32 has no schema-proven timestamp role |
| 1 | `0x00000000` | - | 32 | 2996895744 | ordinary BE32 has no schema-proven timestamp role |
| 1 | `0x00000000` | - | 40 | 3671882234 | ordinary BE32 has no schema-proven timestamp role |
| 1 | `0x00000000` | - | 60 | 2516650496 | ordinary BE32 has no schema-proven timestamp role |
| 1 | `0x00000000` | - | 100 | 1744830464 | ordinary BE32 has no schema-proven timestamp role |
| 2 | `0x0112234d` | 0 | 52 | 1684368442 | candidate falls inside ASCII/hash/string slot |
| 2 | `0x0112234d` | 0 | 56 | 1766877295 | candidate falls inside ASCII/hash/string slot |
| 2 | `0x0112234d` | 0 | 60 | 1852125490 | candidate falls inside ASCII/hash/string slot |
| 2 | `0x0112234d` | 0 | 68 | 1701984818 | candidate falls inside ASCII/hash/string slot |

### Unresolved

- reportCodes: `0x010a0020`
- note: 未知项目前不能证明含义；保留原包与样例，不给出伪确定标签。

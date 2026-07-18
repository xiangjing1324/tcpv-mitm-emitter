# PE/IDA Feedback From TCPView Shape Buckets 2026-06-07

source:
- archive: `/Users/jinger/Desktop/tcpview-115-flow-exports/115_18092_443_b709f068_20260607.tcpv.jsonl`
- bucket_md: `/Users/jinger/Desktop/tcpview-115-flow-exports/115_18092_443_b709f068_20260607.shape-buckets.md`
- bucket_json: `/Users/jinger/Desktop/tcpview-115-flow-exports/115_18092_443_b709f068_20260607.shape-buckets.json`
- flow: `b709f068-1b96-48df-a2d0-8db154ea719e`
- cid: `127.0.0.1:41021->nj.cschannel.anticheatexpert.com:443 [acc:15253589510170603304]`
- parsed source: `display`
- events: `1085`
- parsed `0102000A` shape buckets: `185`

scope:
- This is a read-only PE/IDA feedback report.
- It does not propose PE active mutation.
- cleanup only means `template bucket / replay sample cleanup`. It is not `wire drop` and not `PE active mutation`.
- The counts below are parsed `0102000A` leaf records from `display`, not raw substring hits.

## High-Frequency Bucket Ranking

| rank | count | inner_type | inner_field | child/body/tail | pe_decision | cleanup_hint | worth IDA writer? | shape_key |
|---:|---:|---|---|---|---|---|---|---|
| 1 | 80 | `0x2000` | `0x00000000` | `44/8/0` | `python_fallback` | `template_bucket_only / no_wire_drop` | yes, after exact `0102000A` writer closes; high-volume Python fallback candidate | `0x0102000a:0x2000:0x200e0002:0x34560001:0x00000000:len44:body8:tail0` |
| 2 | 26 | `0xfffb` | `0x01010000` | `79/43/0` | `blocked` | `template_bucket_only / no_wire_drop` | P3; opaque unknown, not before writer/tail work | `0x0102000a:0xfffb:0x200e0002:0x34560001:0x01010000:len79:body43:tail0` |
| 3 | 19 | `0x100f` | `0x00000000` | `44/8/0` | `blocked` | `template_bucket_only / no_wire_drop` | P3; compact opaque shape, maybe descriptor table entry | `0x0102000a:0x100f:0x200e0002:0x34560001:0x00000000:len44:body8:tail0` |
| 4 | 18 | `0xfff2` | `0x01000000` | `101/65/0` | `python_fallback` | `template_bucket_only / no_wire_drop` | P2; region/path producer hypothesis, not active | `0x0102000a:0xfff2:0x00000000:0x01b80001:0x01000000:len101:body65:tail0` |
| 5 | 11 | `0x8021` | `0x0009d52f` | `40/4/0` | `blocked` | `template_bucket_only / no_wire_drop` | P3; small opaque body, likely enum/counter-like | `0x0102000a:0x8021:0x200e0000:0x03e60001:0x0009d52f:len40:body4:tail0` |
| 6 | 10 | `0x8029` | `0x00000185` | `81/45/8` | `blocked` | `template_bucket_only / no_wire_drop` | P1; high-priority tail writer | `0x0102000a:0x8029:0x200e0002:0x34560001:0x00000185:len81:body45:tail8` |
| 7 | 9 | `0x8029` | `0x00000043` | `85/49/8` | `blocked` | `template_bucket_only / no_wire_drop` | P1; high-priority tail writer | `0x0102000a:0x8029:0x200e0002:0x34560001:0x00000043:len85:body49:tail8` |
| 8 | 8 | `0x0100` | `0x0000006b` | `152/116/0` | `blocked` | `template_bucket_only / no_wire_drop` | P3; schema not proven | `0x0102000a:0x0100:0x200e0002:0x34560001:0x0000006b:len152:body116:tail0` |
| 9 | 8 | `0x800a` | `0x00000001` | `164/128/0` | `blocked` | `template_bucket_only / no_wire_drop` | P3; schema not proven | `0x0102000a:0x800a:0x200e0000:0x04560001:0x00000001:len164:body128:tail0` |
| 10 | 8 | `0x8029` | `0x000001e7` | `93/57/8` | `blocked` | `template_bucket_only / no_wire_drop` | P1; high-priority tail writer | `0x0102000a:0x8029:0x200e0002:0x34560001:0x000001e7:len93:body57:tail8` |
| 11 | 8 | `0x8029` | `0x00000405` | `71/35/8` | `blocked` | `template_bucket_only / no_wire_drop` | P1; high-priority tail writer | `0x0102000a:0x8029:0x200e0002:0x34560001:0x00000405:len71:body35:tail8` |
| 12 | 8 | `0xfff3` | `0x00030003` | `202/166/0` | `blocked` | `template_bucket_only / no_wire_drop` | P3; unknown opaque family | `0x0102000a:0xfff3:0x00000000:0x02f80001:0x00030003:len202:body166:tail0` |
| 13 | 7 | `0x8027` | `0x00000177` | `106/70/8` | `blocked` | `template_bucket_only / no_wire_drop` | P1; tail writer | `0x0102000a:0x8027:0x200e0002:0x34560001:0x00000177:len106:body70:tail8` |
| 14 | 7 | `0xfff3` | `0x00040004` | `214/178/0` | `blocked` | `template_bucket_only / no_wire_drop` | P3; unknown opaque family | `0x0102000a:0xfff3:0x00000000:0x05b60001:0x00040004:len214:body178:tail0` |
| 15 | 6 | `0x8029` | `0x000001a2` | `97/61/8` | `blocked` | `template_bucket_only / no_wire_drop` | P1; tail writer | `0x0102000a:0x8029:0x200e0002:0x34560001:0x000001a2:len97:body61:tail8` |

initial prioritization:
- Most valuable IDA payoff: exact `0102000A` writer closure first, because it would unlock interpretation of all buckets.
- Highest bucket volume with non-active PE value: `0x2000`, but it must remain `python_fallback` until exact writer and length policy are proven.
- Highest blocked families by count: `0x8029`, `0xfff3`, `0x8027`, `0xfffb`, `0x100f`, `0x8021`.

## Blocked / Not-Active Bucket Ranking

| family | records | buckets | top shape | current decision | reason class | PE status |
|---|---:|---:|---|---|---|---|
| `0x8029` | 77 | 28 | `inner_field=0x00000185 len81/body45/tail8 count10` | `blocked` | `tail_unknown`, `exact_writer_missing` | no mutation; observe tail metrics only |
| `0xfff3` | 54 | many | `len202/body166 count8`, `len214/body178 count7` | `blocked` | `opaque_body`, `schema_not_proven`, `exact_writer_missing` | no mutation |
| `0x8027` | 31 | 17 | `inner_field=0x00000177 len106/body70/tail8 count7` | `blocked` | `tail_unknown`, `exact_writer_missing` | no mutation; observe tail metrics only |
| `0xfffb` | 27 | 2 | `inner_field=0x01010000 len79/body43 count26` | `blocked` | `opaque_body`, `schema_not_proven`, `exact_writer_missing` | no mutation |
| `0xfff2` | 24 | 7 | `inner_field=0x01000000 len101/body65 count18` | `python_fallback`, not active | `schema_not_proven`, `exact_leaf_writer_missing` | no active_allow; keep Python fallback |
| `0x100f` | 19 | 1 | `inner_field=0x00000000 len44/body8 count19` | `blocked` | `opaque_body`, `exact_writer_missing` | no mutation |
| `0x8021` | 14 | 4 | `inner_field=0x0009d52f len40/body4 count11` | `blocked` | `opaque_body`, `schema_not_proven`, `exact_writer_missing` | no mutation |

notes:
- `0xfff2` is not `pe_decision=blocked` in the current summary; it is `python_fallback`. It is listed here because it is still not eligible for active PE mutation.
- `0x8027` and `0x8029` are structurally parsed enough to show fixed fields and tails, but tail semantics are still unknown.
- `0xfffb`, `0x100f`, and `0x8021` are good P3 candidates only after P0/P1/P2 close; they should not pull effort ahead of exact writer or tail builder work.

## 0x8027 / 0x8029 Tail Pattern Analysis

summary:
- `0x8029`: `77` parsed records across `28` shape buckets.
- `0x8027`: `31` parsed records across `17` shape buckets.
- Both families share selector-heavy shape keys: commonly `selector0=0x200e0002`, `selector1=0x34560001`.
- Current grouping is strongly correlated with `inner_field`, `child_len`, and `body_len`.
- Tail is consistently modeled as last 8 bytes, but content meaning is unclosed.

top `0x8029` tail clusters:

| count | inner_field | child/body | tail_hex patterns | tail_u32 patterns |
|---:|---|---|---|---|
| 10 | `0x00000185` | `81/45` | `010000000a000000=8`, `010000000a123456=2` | `(0x01000000,0x0a000000)=8`, `(0x01000000,0x0a123456)=2` |
| 9 | `0x00000043` | `85/49` | `030000003a000000=8`, `030000003a123456=1` | `(0x03000000,0x3a000000)=8`, `(0x03000000,0x3a123456)=1` |
| 8 | `0x000001e7` | `93/57` | `0100000012000000=6`, `0100000012123456=2` | `(0x01000000,0x12000000)=6`, `(0x01000000,0x12123456)=2` |
| 8 | `0x00000405` | `71/35` | `0400000008000000=6`, `0400000008123456=2` | `(0x04000000,0x08000000)=6`, `(0x04000000,0x08123456)=2` |
| 6 | `0x000001a2` | `97/61` | `0300000002000000=4`, variants with leading endian swap or `123456` suffix | `(0x03000000,0x02000000)=4`, variants |

top `0x8027` tail clusters:

| count | inner_field | child/body | tail_hex patterns | tail_u32 patterns |
|---:|---|---|---|---|
| 7 | `0x00000177` | `106/70` | `0201010000000000=6`, `0000000201010000=1` | `(0x02010100,0x00000000)=6`, `(0x00000002,0x01010000)=1` |
| 3 | `0x00000175` | `114/78` | `0201010000123456=2`, `0201010000000000=1` | `(0x02010100,0x00123456)=2`, `(0x02010100,0x00000000)=1` |
| 3 | `0x000001e5` | `110/74` | `0201010000000000=2`, `0201010000123456=1` | `(0x02010100,0x00000000)=2`, `(0x02010100,0x00123456)=1` |
| 2 | `0x0000047b` | `106/70` | `0000000201010000=2` | `(0x00000002,0x01010000)=2` |
| 2 | `0x00000596` | `122/86` | `0000000201010000=2` | `(0x00000002,0x01010000)=2` |

tail interpretation constraints:
- The `123456` suffix appears in some tail variants. Do not assume it is a valid semantic counter until child boundary and parent trailer interaction are checked in IDA/runtime.
- The first u32 often looks like a small enum or packed flag (`0x01000000`, `0x03000000`, `0x04000000`, `0x02010100`) depending on endian interpretation.
- The second u32 often looks like a small value in high byte position or zero. This may be a counter, length, status, or copied builder argument.

IDA next builder/writer checks:
- Search constants: `0x8027`, `0x8029`, `0x200e0002`, `0x34560001`.
- Search high-frequency `inner_field` values: `0x00000185`, `0x00000043`, `0x000001e7`, `0x00000405`, `0x00000177`, `0x00000175`, `0x000001e5`.
- In candidate writer, confirm where final 8 bytes are appended:
  - direct store to `body_end - 8`
  - memcpy of 8-byte struct
  - two u32 parameters
  - copied tail from source child
- Track function parameters that become:
  - `inner_type`
  - `inner_field`
  - `body_len`
  - last two u32 tail fields
- Only after builder parameter provenance is closed can PE consider counter repair. Current policy remains `tail_policy=unknown_blocked`.

## 0xFFF2 Region/Path Cluster Analysis

summary:
- `0xfff2`: `24` parsed records across `7` shape buckets.
- Current `pe_decision`: `python_fallback`, not `active_allow`.
- All parsed `display` samples are `preview_kind=opaque`; no high-confidence path/text slot was extracted from this summary source.

clusters:

| count | child/body | selector0 | selector1 | inner_field | leaf_id pattern | path/text visibility | shape_key |
|---:|---|---|---|---|---|---|---|
| 18 | `101/65` | `0x00000000` | `0x01b80001` | `0x01000000` | many sequential-ish leaf ids from `0x000000cf` through `0x000000e3` | none in parsed display summary; opaque | `0x0102000a:0xfff2:0x00000000:0x01b80001:0x01000000:len101:body65:tail0` |
| 1 | `171/135` | `0x00000000` | `0x00580001` | `0x038999c6` | `0x00000088` | opaque | `0x0102000a:0xfff2:0x00000000:0x00580001:0x038999c6:len171:body135:tail0` |
| 1 | `171/135` | `0x00000000` | `0x03950001` | `0x038999c6` | `0x00000308` | opaque | `0x0102000a:0xfff2:0x00000000:0x03950001:0x038999c6:len171:body135:tail0` |
| 1 | `101/65` | `0x00000000` | `0x04750001` | `0x01000000` | `0x000002ea` | opaque | `0x0102000a:0xfff2:0x00000000:0x04750001:0x01000000:len101:body65:tail0` |
| 3 | `281/245` | `0x00000000` | `0x04820001`, `0x04f90001`, `0x065b0001` | `0x01000000` | singleton leaf ids | opaque | long region/profile shapes |

mapping hypothesis to IDA functions:
- `sub_2118E4`, `sub_21196C`, `sub_20FCF4`, `sub_2103B8` remain plausible region/path/profile producers.
- The current tcpview summary supports a typed-leaf relationship only as a candidate: `inner_type=0xfff2` appears in real 443 flow and clusters by selector/field/length.
- It does not prove that those functions directly write the exact `0102000A` leaf.
- It does not prove path/string slot boundaries inside the `0xfff2` body from `display` data.

why not `active_allow`:
- Exact `0102000A` writer is still not closed.
- Exact `0xfff2` typed leaf producer is not closed to `sub_2118E4 / sub_21196C / sub_20FCF4 / sub_2103B8`.
- Body is opaque in current parsed summary; no field mask, no length repair policy, no tail/body partition semantics.
- Any replacement would risk corrupting region/path profile or copied runtime state.

## PE Decision Recommendations

active_allow:
- none

observe_only:
- Parent `0x010A001B` roster metrics:
  - report counts
  - child_count histogram
  - child shape index
  - parent layout variants: `count-u32`, `compact-count-u8`, `count-u32-partial`
- All `0102000A` shape bucket metrics:
  - `shape_key`
  - `inner_type`
  - `inner_field`
  - `child_len/body_len/tail_len`
  - `tail_hex/tail_u32`
  - `pe_decision` display tag
- `0x8027 / 0x8029` tail pattern metrics:
  - cluster by `inner_field`
  - track top tail patterns
  - track variants ending with `123456` separately
- `0xfff2` region/path clusters:
  - cluster by `selector1`, `inner_field`, `child_len/body_len`, `leaf_id/reserved`
- Unknown blocked families:
  - `0xfffb`, `0x100f`, `0x8021`, `0xfff3`, `0x800a`, `0x0100`

python_fallback:
- `0x2000`: high-volume same-length/string candidate family, but current parsed preview is opaque and exact writer is missing.
- `0x1105`, `0x100b`, `0x2000` string-like families: only Python fallback until field mask and writer are proven.
- `0xfff2`: region/path candidate remains Python fallback because writer and schema are not proven.

blocked:
- `0x8027`, `0x8029`: blocked due `tail_unknown` and `exact_writer_missing`.
- `0xfffb`, `0x100f`, `0x8021`, `0xfff3`, `0x800a`, `0x0100`: blocked due `opaque_body`, `schema_not_proven`, `exact_writer_missing`.
- Any binary-like runtime child that lacks:
  - exact writer
  - field mask
  - length policy
  - tail repair
  - Python parity

cleanup:
- allowed only as `template bucket / replay sample cleanup`.
- not allowed as `wire drop`.
- not allowed as PE active mutation.
- not a reason to delete or drop binary runtime children from live packet handling.

## IDA Next Priorities

P0: exact `0102000A` writer / `descriptor+4 == 0x0A`
- Continue `sub_3E170` xrefs and wrappers `sub_3E168 / sub_3E32C`.
- Trace vtable caller, descriptor table, and `*(a2+4)` source.
- Confirm whether `descriptor+4 == 0x0A` is constant table data, runtime descriptor field, or caller-provided.
- Expected confirmed evidence:
  - function address of exact writer
  - xref path from leaf producer to writer
  - decompile/asm store of `report_code=0x0102000A`
  - store/copy of `inner_len`, `inner_type`, `selector0`, `selector1`, `inner_field`
  - length calculation/rebuild rule
- PE impact:
  - without P0, all active mutation remains blocked.

P1: `0x8027 / 0x8029` tail writer
- Search xrefs/constants:
  - `0x8027`
  - `0x8029`
  - `0x200e0002`
  - `0x34560001`
  - top `inner_field`: `0x00000185`, `0x00000043`, `0x000001e7`, `0x00000405`, `0x00000177`
- Trace last 8-byte tail construction:
  - two u32 stores
  - 8-byte memcpy
  - copied tail from source child
  - parent trailer interaction
- Expected confirmed evidence:
  - builder parameters for tail u32[0]/u32[1]
  - whether `123456` suffix is legitimate data or boundary artifact
  - whether tail is counter-like and repairable
- PE impact:
  - until confirmed, keep `tail_policy=unknown_blocked`.

P2: `0xfff2` region/path writer close to typed leaf
- Re-check `sub_2118E4`, `sub_21220C`, `sub_21196C`, `sub_20FCF4`, `sub_2103B8`.
- Search for `inner_type=0xfff2`, selector families:
  - `selector0=0x00000000`
  - `selector1=0x01b80001`, `0x00580001`, `0x03950001`, `0x04750001`, `0x04820001`, `0x04f90001`, `0x065b0001`
  - `inner_field=0x01000000`, `0x038999c6`
- Expected confirmed evidence:
  - region/path producer reaches `0102000A` writer
  - field boundary for region/path body
  - whether body contains text/path, encoded path, or opaque profile
- PE impact:
  - remain `python_fallback`; no active allow.

P3: unknown opaque buckets
- Families:
  - `0xfffb`
  - `0x100f`
  - `0x8021`
  - `0xfff3`
  - `0x800a`
  - `0x0100`
- Search by top shape constants:
  - `0xfffb`, `0x01010000`, len `79`, body `43`
  - `0x100f`, len `44`, body `8`
  - `0x8021`, `inner_field=0x0009d52f`, len `40`, body `4`
  - `0xfff3`, body lengths `166/178`
- Expected evidence:
  - producer/writer xrefs
  - whether body is enum, profile, hash, counter, or copied runtime state
- PE impact:
  - observe metrics only; blocked for mutation.

## Final PE Boundary

Current allowed scope:
- P0 documentation/metrics closeout.
- tcpview/offline summary generation.
- IDA/Frida evidence collection.

Not allowed from this evidence:
- PE active mutation.
- wire drop.
- binary runtime child deletion.
- replacing `0x8027 / 0x8029` tails.
- replacing `0xfff2` region/path bodies.
- promoting parent roster confirmation into child replacement authority.

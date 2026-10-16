from __future__ import annotations

import json
import re
import shutil
import subprocess
import zlib
from pathlib import Path


APP_JS = Path(__file__).resolve().parents[1] / "tcpv_mitm_emitter" / "app.js"


def _extract_function(source: str, name: str) -> str:
    match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", source)
    assert match, f"missing function {name}"
    start = match.start()
    brace = source.find("{", match.end())
    assert brace >= 0

    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
        elif block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        elif ch == "/" and nxt == "/":
            line_comment = True
            i += 1
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif ch in {'"', "'", "`"}:
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
        i += 1
    raise AssertionError(f"unterminated function {name}")


def _run_node_harness(tmp_path: Path, name: str, program: str) -> dict[str, object]:
    node = shutil.which("node")
    if not node:
        raise AssertionError("node is required for the focused TCPView MRPCS test")
    harness = tmp_path / name
    harness.write_text(program, encoding="utf-8")
    result = subprocess.run([node, str(harness)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _family0_encrypt(plain: bytes, slot: int = 0) -> bytes:
    labels = [
        "CHAGQX",
        "Q_VA[\\R",
        "SYSZZ",
        "]P@XQA",
        "CE]AQ",
        "[TK",
        "QDF\\",
        "D^GP\\",
        "CA@Z@P",
        "WIX_83qpt",
    ]
    key_xor = (0x8A, 0xE6, 0x9B, 0xF3, 0xC1, 0x7D, 0x40, 0x25)
    raw = labels[slot].encode("latin1")[:8].ljust(8, b"\0")
    key = bytes(value ^ key_xor[index] for index, value in enumerate(raw))
    table = list(range(256))
    seed = (
        ((key[5] << 16) | (key[6] << 8) | key[7])
        ^ ((key[1] << 16) | (key[2] << 8) | key[3])
    ) & 0xFFFFFFFF
    for index in range(256):
        seed = (214013 * seed + 2531011) & 0xFFFFFFFF
        swap_index = (seed >> 16) & 0xFF
        table[index], table[swap_index] = table[swap_index], table[index]
    return bytes(
        key[index & 7] ^ table[value ^ key[index & 7] ^ (index & 0xFF)]
        for index, value in enumerate(plain)
    )


def _strict_0037_family0_envelope(plain: bytes, slot: int = 0) -> bytes:
    cipher = _family0_encrypt(plain, slot)
    total = 28 + len(cipher)
    return b"".join(
        (
            (1).to_bytes(4, "big"),
            total.to_bytes(2, "big"),
            (0x010A0037).to_bytes(4, "big"),
            b"\0" * 10,
            bytes((0, slot)),
            (zlib.crc32(plain) & 0xFFFFFFFF).to_bytes(4, "big"),
            len(cipher).to_bytes(2, "big"),
            cipher,
        )
    )


def _payload_with_crc32(length: int, target: int, prefix: bytes = b"") -> bytes:
    """Build a deterministic equal-length fixture with the requested CRC32."""
    assert length >= len(prefix) + 4
    head = prefix + bytes(length - len(prefix) - 4)
    base = zlib.crc32(head + b"\0\0\0\0") & 0xFFFFFFFF
    vectors: list[int] = []
    for bit_index in range(32):
        suffix = bytearray(4)
        suffix[bit_index // 8] = 1 << (bit_index % 8)
        vectors.append((zlib.crc32(head + suffix) & 0xFFFFFFFF) ^ base)

    basis = [0] * 32
    combinations = [0] * 32
    for bit_index, vector in enumerate(vectors):
        combination = 1 << bit_index
        for pivot in range(31, -1, -1):
            if not (vector & (1 << pivot)):
                continue
            if basis[pivot]:
                vector ^= basis[pivot]
                combination ^= combinations[pivot]
            else:
                basis[pivot] = vector
                combinations[pivot] = combination
                break

    wanted = (target & 0xFFFFFFFF) ^ base
    solution = 0
    for pivot in range(31, -1, -1):
        if not (wanted & (1 << pivot)):
            continue
        assert basis[pivot], "CRC32 suffix transform was not invertible"
        wanted ^= basis[pivot]
        solution ^= combinations[pivot]
    assert wanted == 0
    suffix = bytes(
        sum(((solution >> (byte_index * 8 + bit)) & 1) << bit for bit in range(8))
        for byte_index in range(4)
    )
    payload = head + suffix
    assert zlib.crc32(payload) & 0xFFFFFFFF == target & 0xFFFFFFFF
    return payload


def test_strict_0037_family0_envelope_decrypts_and_rejects_lookalikes(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "isLikelyTssReportCode",
            "detectTssReport",
            "tssSlotRaw",
            "tssFamily0Decrypt",
            "tssCrc32",
            "parseTssEncryptedEnvelope",
            "decryptTssEncryptedEnvelope",
            "decryptDisplayableTssEnvelope",
        )
    )
    plain = b"".join(
        (
            (1).to_bytes(4, "big"),
            (24).to_bytes(2, "big"),
            (0x010A005F).to_bytes(4, "big"),
            b"strict-family0",
        )
    )
    assert len(plain) == 24
    envelope = bytearray(_strict_0037_family0_envelope(plain))
    non_strict_total = bytearray(envelope)
    non_strict_total[5] -= 1
    non_strict_trailer = bytearray(envelope)
    non_strict_trailer.extend(b"\x99")
    non_strict_trailer[4:6] = len(non_strict_trailer).to_bytes(2, "big")
    fake_0037 = bytearray(28)
    fake_0037[6:10] = (0x010A0037).to_bytes(4, "big")
    bad_crc = bytearray(envelope)
    bad_crc[22] ^= 1
    wrong_family = bytearray(envelope)
    wrong_family[20] = 3
    opaque_plain = b"not-a-framed-inner-record"
    opaque_envelope = _strict_0037_family0_envelope(opaque_plain)
    malformed_inner_plain = bytearray(plain)
    malformed_inner_plain[4:6] = (len(malformed_inner_plain) - 1).to_bytes(2, "big")
    malformed_inner_envelope = _strict_0037_family0_envelope(malformed_inner_plain)

    program = f"""
function readBe16(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 1 >= bytes.length) return NaN;
  return ((Number(bytes[offset]) << 8) | Number(bytes[offset + 1])) >>> 0;
}}
function readBe32(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 3 >= bytes.length) return NaN;
  return (((Number(bytes[offset]) * 0x1000000) + (Number(bytes[offset + 1]) << 16) +
    (Number(bytes[offset + 2]) << 8) + Number(bytes[offset + 3])) >>> 0);
}}
function formatHexValue(value, width) {{ return '0x' + (Number(value) >>> 0).toString(16).padStart(Number(width || 0), '0'); }}
const TSS_CRYPTO_KEY_LABELS = ['CHAGQX', 'Q_VA[\\\\R', 'SYSZZ', ']P@XQA', 'CE]AQ', '[TK', 'QDF\\\\', 'D^GP\\\\', 'CA@Z@P', 'WIX_83qpt'];
const TSS_FAMILY0_KEY_XOR = [0x8a, 0xe6, 0x9b, 0xf3, 0xc1, 0x7d, 0x40, 0x25];
const tssFamily0TableCache = new Map();
let tssCrc32TableCache = null;
function tssFamily1Decrypt() {{ throw new Error('unexpected family1'); }}
function tssFamily2Decrypt() {{ throw new Error('unexpected family2'); }}
{functions}
const expectedPlain = {json.dumps(list(plain))};
const strict = {json.dumps(list(envelope))};
const parsed = parseTssEncryptedEnvelope(strict);
if (!parsed || parsed.report !== 0x010a0037 || parsed.family !== 0 || !parsed.valid) throw new Error('strict 0037 was not parsed');
if (parsed.cipherLength !== expectedPlain.length || parsed.trailingLength !== 0) throw new Error('0037 cipher boundary is not strict');
const decrypted = decryptTssEncryptedEnvelope(strict);
if (!decrypted || !decrypted.supported || !decrypted.crcMatch) throw new Error('family0 CRC did not verify');
if (JSON.stringify(decrypted.plain) !== JSON.stringify(expectedPlain)) throw new Error('family0 plaintext mismatch');
if (!decrypted.innerRoot || decrypted.innerRoot.value !== 0x010a005f || decrypted.innerRoot.offset !== 6) throw new Error('inner report was not detected');
if (!decryptDisplayableTssEnvelope(strict)) throw new Error('verified retagged envelope was not displayable');
if (decryptDisplayableTssEnvelope({json.dumps(list(bad_crc))}) !== null) throw new Error('bad CRC 0037 was promoted');
if (decryptDisplayableTssEnvelope({json.dumps(list(opaque_envelope))}) !== null) throw new Error('0037 without trusted inner report was promoted');
if (decryptDisplayableTssEnvelope({json.dumps(list(malformed_inner_envelope))}) !== null) throw new Error('0037 with a non-closing inner record was promoted');
if (parseTssEncryptedEnvelope({json.dumps(list(wrong_family))}) !== null) throw new Error('unsupported 0037 family was accepted');
for (const candidate of [
  {json.dumps(list(non_strict_total))},
  {json.dumps(list(non_strict_trailer))},
  {json.dumps(list(fake_0037))},
]) {{
  if (parseTssEncryptedEnvelope(candidate) !== null) throw new Error('non-strict 0037 was accepted');
  if (decryptTssEncryptedEnvelope(candidate) !== null) throw new Error('non-strict 0037 was decrypted');
}}
console.log(JSON.stringify({{ ok: true, crc: decrypted.actualCrc >>> 0 }}));
"""
    result = _run_node_harness(tmp_path, "strict-0037-family0.js", program)
    assert result == {"ok": True, "crc": zlib.crc32(plain) & 0xFFFFFFFF}


def test_live_retagged_0037_family1_decrypts_third_layer_mrpcs_reference(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    deep_panel = _extract_function(source, "buildGcloudAceCarrierDeepPanel")
    assert "decryptDisplayableTssEnvelope(displayPayload)" in deep_panel
    assert "gcloudSecurityThirdLayerTitle(securityCommand)" in deep_panel
    assert "stack.appendChild(innerPanel)" in deep_panel
    assert "buildTssRecursiveDecodeTree(displayPayload" in deep_panel
    crypto_constants = source[
        source.index("const TSS_CRYPTO_KEY_LABELS"):
        source.index("function tssRol32(")
    ]
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "isLikelyTssReportCode",
            "detectTssReport",
            "tssRol32",
            "tssRor32",
            "tssSlotRaw",
            "tssWriteLe32",
            "tssFamily1Schedule",
            "tssFamily1MarsE",
            "tssFamily1RotWordsLeft",
            "tssFamily1DecryptBlock",
            "tssFamily1TailTransform",
            "tssFamily1Decrypt",
            "tssCrc32",
            "parseTssEncryptedEnvelope",
            "decryptTssEncryptedEnvelope",
            "decryptDisplayableTssEnvelope",
        )
    )
    envelope = bytes.fromhex(
        "000000010055010a0037000000000000000000000108196d32fd0039"
        "f16c4aff1395d71ca64685e9c13a7a5d57b00452007523b70bc3e703"
        "55668025e56f3997e8f7742eb6177251c8d8c870dfb667c26fc75ac64c"
    )
    expected_plain = bytes.fromhex(
        "000000010039010a005b0000000b0000000000000001000000126d7270"
        "63735f695f765f746c2e6461746100eb092f9b00001bba0000064501"
    )
    program = f"""
function readBe16(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 1 >= bytes.length) return NaN;
  return ((Number(bytes[offset]) << 8) | Number(bytes[offset + 1])) >>> 0;
}}
function readBe32(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 3 >= bytes.length) return NaN;
  return (((Number(bytes[offset]) * 0x1000000) + (Number(bytes[offset + 1]) << 16) +
    (Number(bytes[offset + 2]) << 8) + Number(bytes[offset + 3])) >>> 0);
}}
function readLe32(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 3 >= bytes.length) return NaN;
  return ((Number(bytes[offset])) | (Number(bytes[offset + 1]) << 8) |
    (Number(bytes[offset + 2]) << 16) | (Number(bytes[offset + 3]) << 24)) >>> 0;
}}
function formatHexValue(value, width) {{ return '0x' + (Number(value) >>> 0).toString(16).padStart(Number(width || 0), '0'); }}
{crypto_constants}
function tssFamily0Decrypt() {{ throw new Error('unexpected family0'); }}
function tssFamily2Decrypt() {{ throw new Error('unexpected family2'); }}
{functions}
const envelope = {json.dumps(list(envelope))};
const expectedPlain = {json.dumps(list(expected_plain))};
const parsed = parseTssEncryptedEnvelope(envelope);
if (!parsed || !parsed.valid || parsed.family !== 1 || parsed.slot !== 8 || parsed.familyName !== 'family1_mars') throw new Error('live family1 envelope was not parsed');
const decrypted = decryptDisplayableTssEnvelope(envelope);
if (!decrypted || !decrypted.supported || !decrypted.crcMatch) throw new Error('live family1 CRC did not verify');
if (decrypted.actualCrc !== 0x196d32fd) throw new Error('live family1 CRC mismatch');
if (!decrypted.innerRoot || decrypted.innerRoot.value !== 0x010a005b || decrypted.innerRoot.offset !== 6) throw new Error('live inner report was not detected');
if (JSON.stringify(decrypted.plain) !== JSON.stringify(expectedPlain)) throw new Error('live family1 plaintext mismatch');
if (!String.fromCharCode(...decrypted.plain).includes('mrpcs_i_v_tl.data')) throw new Error('MRPCS reference was not decrypted');
const badCrc = envelope.slice();
badCrc[22] ^= 1;
if (decryptDisplayableTssEnvelope(badCrc) !== null) throw new Error('bad CRC family1 envelope was promoted');
console.log(JSON.stringify({{ family: decrypted.familyName, slot: decrypted.slot, report: decrypted.innerRoot.value >>> 0, mrpcs: true }}));
"""
    result = _run_node_harness(tmp_path, "live-0037-family1.js", program)
    assert result == {
        "family": "family1_mars",
        "slot": 8,
        "report": 0x010A005B,
        "mrpcs": True,
    }


def test_mrpcs_transfer_chunk_parses_strict_lengths_indexes_and_crc(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    live_name = b"mrpcs_i_v_tl.data"
    live_wrapper = b"\x00\x01" + (len(live_name) + 1).to_bytes(4, "big") + live_name + b"\x00"
    live_chunks = {
        114: _payload_with_crc32(940, 0xA07020D7),
        116: _payload_with_crc32(588, 0x716E9888),
        119: _payload_with_crc32(940, 0x11F61FEF, live_wrapper),
        120: _payload_with_crc32(940, 0xA31B524A),
    }
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in ("tssCrc32", "parseMrpcsTransferChunk", "findMrpcsTransferChunk")
    )
    program = f"""
function readBe16(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 1 >= bytes.length) return NaN;
  return ((Number(bytes[offset]) << 8) | Number(bytes[offset + 1])) >>> 0;
}}
function readBe32(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 3 >= bytes.length) return NaN;
  return (((Number(bytes[offset]) * 0x1000000) + (Number(bytes[offset + 1]) << 16) +
    (Number(bytes[offset + 2]) << 8) + Number(bytes[offset + 3])) >>> 0);
}}
function formatHexValue(value, width) {{ return '0x' + (Number(value) >>> 0).toString(16).padStart(Number(width || 0), '0'); }}
let tssCrc32TableCache = null;
{functions}
function put16(out, offset, value) {{ out[offset] = (value >>> 8) & 255; out[offset + 1] = value & 255; }}
function put32(out, offset, value) {{ const word = Number(value) >>> 0; out[offset] = word >>> 24; out[offset + 1] = (word >>> 16) & 255; out[offset + 2] = (word >>> 8) & 255; out[offset + 3] = word & 255; }}
function makeRecord(chunk, options = {{}}) {{
  const out = new Array(0x32 + chunk.length).fill(0);
  put32(out, 0x00, 1); put16(out, 0x04, out.length); put32(out, 0x06, 0x010a005f);
  put32(out, 0x14, options.a === undefined ? 0x684ff008 : options.a);
  put32(out, 0x18, options.b === undefined ? 0x3b58a018 : options.b);
  put32(out, 0x1c, options.total === undefined ? chunk.length : options.total);
  put16(out, 0x20, options.count === undefined ? 1 : options.count);
  put16(out, 0x22, options.index === undefined ? 0 : options.index);
  put32(out, 0x24, options.fullCrc === undefined ? tssCrc32(chunk) : options.fullCrc);
  put32(out, 0x28, options.chunkCrc === undefined ? tssCrc32(chunk) : options.chunkCrc);
  put32(out, 0x2c, 0); put16(out, 0x30, chunk.length);
  for (let index = 0; index < chunk.length; index += 1) out[0x32 + index] = chunk[index];
  return out;
}}
function bytesFromHex(hex) {{ return Array.from(Buffer.from(hex, 'hex')); }}
const chunk = Array.from({{ length: 73 }}, (_value, index) => (index * 29 + 7) & 255);
const record = makeRecord(chunk, {{ total: 151, count: 3, index: 1, fullCrc: 0x2ad44bc4 }});
const parsed = parseMrpcsTransferChunk(record);
if (!parsed || !parsed.valid || parsed.reportCode !== 0x010a005f) throw new Error('valid 005f was not parsed');
if (parsed.totalLength !== 151 || parsed.count !== 3 || parsed.index !== 1 || parsed.chunkLength !== chunk.length) throw new Error('005f lengths/indexes mismatch');
if (parsed.fullCrc !== 0x2ad44bc4 || parsed.chunkCrc !== tssCrc32(chunk) || parsed.actualChunkCrc !== parsed.chunkCrc || !parsed.chunkCrcMatch) throw new Error('005f CRC fields mismatch');
if (JSON.stringify(parsed.chunk) !== JSON.stringify(chunk)) throw new Error('005f chunk bytes mismatch');
if (parseMrpcsTransferChunk(record.slice(0, -1)) !== null) throw new Error('truncated chunk accepted');
const trailing = record.concat([0]); put16(trailing, 0x04, trailing.length);
if (parseMrpcsTransferChunk(trailing) !== null) throw new Error('trailing byte accepted');
const badIndex = makeRecord(chunk, {{ count: 3, index: 3 }});
if (parseMrpcsTransferChunk(badIndex) !== null) throw new Error('index >= count accepted');
const badCrc = makeRecord(chunk, {{ chunkCrc: (tssCrc32(chunk) ^ 1) >>> 0 }});
const badParsed = parseMrpcsTransferChunk(badCrc);
if (!badParsed || badParsed.valid !== false || badParsed.chunkCrcMatch !== false || badParsed.actualChunkCrc === badParsed.chunkCrc) throw new Error('bad chunk CRC was not retained as a mismatch');

const liveIdentity = {{ a: 0x6850b6e7, b: 0x0bb2e00b, total: 7171, count: 8, fullCrc: 0xbeedb1ff }};
const liveFixtures = [
  {{ seq: 114, index: 5, gap: 2, lengthOffset: 0x2e, declaredChunk: 940, missing: 0, layout: 'live_005f', storedCrc: 0xa07020d7, actualCrc: 0xa07020d7, header: '0000000103de010a005f000100f0096850b6e70bb2e00b00001c0300080005beedb1ffa07020d72100f0ffffffa203ac', chunk: {json.dumps(list(live_chunks[114]))} }},
  {{ seq: 116, index: 7, gap: 6, lengthOffset: 0x2d, declaredChunk: 591, missing: 3, layout: 'live_005f_truncated_tail', storedCrc: 0x60f6f7ad, actualCrc: 0x716e9888, header: '000000010281010a005f000100f0096850b6e70bb2e00b00001c0300080007beedb1ff60f6f7ad2100f0ffff11024f', chunk: {json.dumps(list(live_chunks[116]))} }},
  {{ seq: 119, index: 0, gap: 5, lengthOffset: 0x2b, declaredChunk: 940, missing: 0, layout: 'live_005f', storedCrc: 0x688c07e7, actualCrc: 0x11f61fef, header: '0000000103de010a005f000100f0096850b6e70bb2e00b00001c0300080000beedb1ff688c07e72100f15f03ac', chunk: {json.dumps(list(live_chunks[119]))} }},
  {{ seq: 120, index: 4, gap: 2, lengthOffset: 0x2e, declaredChunk: 940, missing: 0, layout: 'live_005f', storedCrc: 0xa31b524a, actualCrc: 0xa31b524a, header: '0000000103de010a005f000100f0096850b6e70bb2e00b00001c0300080004beedb1ffa31b524a2100f0ffffffa203ac', chunk: {json.dumps(list(live_chunks[120]))} }},
];
for (const fixture of liveFixtures) {{
  const liveRecord = bytesFromHex(fixture.header).concat(fixture.chunk);
  const prefix = new Array(0x27).fill(0x5a);
  const found = findMrpcsTransferChunk(prefix.concat(liveRecord));
  if (!found || found.layout !== fixture.layout || found.recordOffset !== prefix.length) throw new Error('live fixture was not scanned: seq' + fixture.seq);
  if (found.transferA !== liveIdentity.a || found.transferB !== liveIdentity.b || found.totalLength !== 7171 || found.count !== 8 || found.index !== fixture.index || found.fullCrc !== liveIdentity.fullCrc) throw new Error('live typed fields mismatch: seq' + fixture.seq);
  if (found.declaredGap !== fixture.gap || found.chunkLengthOffset !== fixture.lengthOffset || found.chunkLength !== fixture.declaredChunk || found.actualChunkLength !== fixture.chunk.length || found.missingChunkBytes !== fixture.missing || JSON.stringify(found.chunk) !== JSON.stringify(fixture.chunk)) throw new Error('live header boundary mismatch: seq' + fixture.seq);
  if (found.chunkCrc !== fixture.storedCrc || found.actualChunkCrc !== fixture.actualCrc || found.chunkCrcMatch !== (fixture.missing === 0 && fixture.storedCrc === fixture.actualCrc)) throw new Error('live chunk CRC state mismatch: seq' + fixture.seq);
  if (fixture.missing > 0 && (!found.truncated || found.valid || !found.reason.includes('missing 3B'))) throw new Error('truncated tail was promoted as verified: seq' + fixture.seq);
}}
const wrongLiveLength = bytesFromHex(liveFixtures[0].header).concat(liveFixtures[0].chunk);
put16(wrongLiveLength, 0x04, wrongLiveLength.length + 3);
if (findMrpcsTransferChunk(wrongLiveLength) !== null) throw new Error('live record with unverified declared-length delta was accepted');
const wrongShortIndex = bytesFromHex(liveFixtures[1].header).concat(liveFixtures[1].chunk);
put16(wrongShortIndex, 0x1d, 6);
if (findMrpcsTransferChunk(wrongShortIndex) !== null) throw new Error('gap-6 tail was accepted outside the final index');
const wrongTailRemainder = bytesFromHex(liveFixtures[1].header).concat(liveFixtures[1].chunk);
put32(wrongTailRemainder, 0x17, 7172);
if (findMrpcsTransferChunk(wrongTailRemainder) !== null) throw new Error('gap-6 tail with inconsistent total remainder was accepted');
const wrongTailMissing = bytesFromHex(liveFixtures[1].header).concat(liveFixtures[1].chunk, [0]);
put16(wrongTailMissing, 0x04, wrongTailMissing.length + 6);
if (findMrpcsTransferChunk(wrongTailMissing) !== null) throw new Error('gap-6 tail with missing-byte count other than three was accepted');
const wrongShortIndex0 = bytesFromHex(liveFixtures[2].header).concat(liveFixtures[2].chunk);
put16(wrongShortIndex0, 0x1d, 1);
if (findMrpcsTransferChunk(wrongShortIndex0) !== null) throw new Error('gap-5 short header was accepted outside index 0');
console.log(JSON.stringify({{ ok: true, chunkCrc: parsed.chunkCrc >>> 0, live: liveFixtures.length }}));
"""
    result = _run_node_harness(tmp_path, "parse-005f-transfer-chunk.js", program)
    expected_chunk = bytes((index * 29 + 7) & 0xFF for index in range(73))
    assert result == {
        "ok": True,
        "chunkCrc": zlib.crc32(expected_chunk) & 0xFFFFFFFF,
        "live": 4,
    }


def test_mrpcs_annotations_reassemble_out_of_order_and_correlate_only_within_30s(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "tssCrc32",
            "parseMrpcsTransferChunk",
            "gcloudBytesEqual",
            "isMrpcsResourceFilename",
            "extractMrpcsWrapperName",
            "extractMrpcsResourceNames",
            "normalizeMrpcsNames",
            "mrpcsObservationFileKey",
            "mrpcsObservationAttemptKey",
            "mrpcsChunksMatchCrc",
            "buildMrpcsTransferAnnotations",
            "correlateMrpcsReferenceAnnotations",
        )
    )
    program = f"""
function readBe16(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 1 >= bytes.length) return NaN;
  return ((Number(bytes[offset]) << 8) | Number(bytes[offset + 1])) >>> 0;
}}
function readBe32(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 3 >= bytes.length) return NaN;
  return (((Number(bytes[offset]) * 0x1000000) + (Number(bytes[offset + 1]) << 16) +
    (Number(bytes[offset + 2]) << 8) + Number(bytes[offset + 3])) >>> 0);
}}
function formatHexValue(value, width) {{ return '0x' + (Number(value) >>> 0).toString(16).padStart(Number(width || 0), '0'); }}
function extractPrintableRuns(bytes, minLen) {{
  const out = []; let start = -1;
  for (let index = 0; index <= bytes.length; index += 1) {{
    const printable = index < bytes.length && bytes[index] >= 0x20 && bytes[index] <= 0x7e;
    if (printable && start < 0) start = index;
    if (!printable && start >= 0) {{
      if (index - start >= minLen) out.push({{ off: start, text: String.fromCharCode(...bytes.slice(start, index)) }});
      start = -1;
    }}
  }}
  return out;
}}
let tssCrc32TableCache = null;
const MRPCS_REFERENCE_MAX_GAP_MS = 30 * 1000;
const MRPCS_OBSERVATION_MAX_EVENT_BYTES = 128 * 1024;
{functions}
function put16(out, offset, value) {{ out[offset] = (value >>> 8) & 255; out[offset + 1] = value & 255; }}
function put32(out, offset, value) {{ const word = Number(value) >>> 0; out[offset] = word >>> 24; out[offset + 1] = (word >>> 16) & 255; out[offset + 2] = (word >>> 8) & 255; out[offset + 3] = word & 255; }}
function makeRecord(chunk, options) {{
  const out = new Array(0x32 + chunk.length).fill(0);
  put32(out, 0x00, 1); put16(out, 0x04, out.length); put32(out, 0x06, 0x010a005f);
  put32(out, 0x14, options.a); put32(out, 0x18, options.b);
  put32(out, 0x1c, options.total); put16(out, 0x20, options.count); put16(out, 0x22, options.index);
  put32(out, 0x24, options.fullCrc); put32(out, 0x28, options.chunkCrc === undefined ? tssCrc32(chunk) : options.chunkCrc);
  put32(out, 0x2c, 0); put16(out, 0x30, chunk.length);
  for (let index = 0; index < chunk.length; index += 1) out[0x32 + index] = chunk[index];
  return out;
}}
function makeLiveRecord(chunk, options) {{
  const missing = Number(options.missing || 0);
  const availableLength = chunk.length - missing;
  const out = new Array(options.lengthOffset + 2 + availableLength).fill(0);
  put32(out, 0x00, 1); put16(out, 0x04, out.length + (options.declaredGap === undefined ? 2 : options.declaredGap)); put32(out, 0x06, 0x010a005f);
  put32(out, 0x0f, options.a); put32(out, 0x13, options.b);
  put32(out, 0x17, options.total); put16(out, 0x1b, options.count); put16(out, 0x1d, options.index);
  put32(out, 0x1f, options.fullCrc); put32(out, 0x23, options.chunkCrc === undefined ? tssCrc32(chunk) : options.chunkCrc);
  put16(out, options.lengthOffset, chunk.length);
  for (let index = 0; index < availableLength; index += 1) out[options.lengthOffset + 2 + index] = chunk[index];
  return out;
}}
const filename = 'mrpcs_i_v_ic.data';
const nameBytes = Array.from(Buffer.from(filename, 'ascii'));
const wrapper = [0, 1, 0, 0, 0, nameBytes.length + 1, ...nameBytes, 0];
const chunk0 = wrapper.concat([0x41, 0x42, 0x43, 0x44]);
const chunk1 = Array.from({{ length: 19 }}, (_value, index) => (0x80 + index) & 255);
const whole = chunk0.concat(chunk1);
const fullCrc = tssCrc32(whole);
const parsed0 = parseMrpcsTransferChunk(makeRecord(chunk0, {{ a: 0x11111111, b: 0x22222222, total: whole.length, count: 2, index: 0, fullCrc }}));
const parsed1 = parseMrpcsTransferChunk(makeRecord(chunk1, {{ a: 0xaaaaaaaa, b: 0xbbbbbbbb, total: whole.length, count: 2, index: 1, fullCrc }}));
if (!parsed0 || !parsed1 || !parsed0.chunkCrcMatch || !parsed1.chunkCrcMatch) throw new Error('fixture chunk parse failed');
const base = 1800000000000;
const observations = [
  {{ eventId: 'event-index-1', ts: base + 40000, flowKey: 'flow-A', cid: 'cid-A', dir: 1, chunk: parsed1 }},
  {{ eventId: 'event-index-0', ts: base + 40000, flowKey: 'flow-A', cid: 'cid-A', dir: 1, chunk: parsed0 }},
];
const built = buildMrpcsTransferAnnotations(observations);
if (!(built.annotations instanceof Map) || !Array.isArray(built.files) || !Array.isArray(built.transfers)) throw new Error('annotation build shape mismatch');
if (built.files.length !== 1) throw new Error('out-of-order file did not complete exactly once');
for (const [eventId, expectedIndex] of [['event-index-0', 0], ['event-index-1', 1]]) {{
  const annotation = built.annotations.get(eventId);
  if (!annotation || annotation.type !== 'transfer' || annotation.filename !== filename) throw new Error('missing filename annotation for ' + eventId);
  if (annotation.dir !== 1 || annotation.index !== expectedIndex || annotation.count !== 2 || annotation.totalLength !== whole.length) throw new Error('bad chunk identity annotation for ' + eventId);
  if (!annotation.structuredChunk || annotation.layout !== 'canonical') throw new Error('canonical parser evidence was not retained for ' + eventId);
  if (annotation.attemptSeenCount !== 1 || annotation.fileSeenCount !== 2) throw new Error('attempt/file progress was conflated for ' + eventId);
  if (annotation.attemptVerified || !annotation.fileVerified || !annotation.chunkCrcMatch || annotation.fullCrc !== fullCrc) throw new Error('cross-retry CRC semantics are wrong for ' + eventId);
}}

const lineageBefore = 'mrpcs_i_v_alpha.data';
const lineageCurrent = 'mrpcs_i_v_beta.data';
const lineageNameBytes = Array.from(Buffer.from(lineageCurrent, 'ascii'));
const lineageChunk0 = [0, 1, 0, 0, 0, lineageNameBytes.length + 1, ...lineageNameBytes, 0, 0x55];
const lineageChunk1 = [0x61, 0x62, 0x63];
const lineageWhole = lineageChunk0.concat(lineageChunk1);
const lineageFullCrc = tssCrc32(lineageWhole);
const lineageA = parseMrpcsTransferChunk(makeRecord(lineageChunk0, {{ a: 7, b: 8, total: lineageWhole.length, count: 2, index: 0, fullCrc: lineageFullCrc }}));
const lineageB = parseMrpcsTransferChunk(makeRecord(lineageChunk1, {{ a: 7, b: 8, total: lineageWhole.length, count: 2, index: 1, fullCrc: lineageFullCrc }}));
const localLineageBuilt = buildMrpcsTransferAnnotations([
  {{ eventId: 'local-change', ts: base + 45000, flowKey: 'flow-lineage', cid: 'cid-lineage', dir: 1, chunk: lineageA, beforeNames: [lineageBefore], currentNames: [lineageCurrent] }},
  {{ eventId: 'local-sibling', ts: base + 45001, flowKey: 'flow-lineage', cid: 'cid-lineage', dir: 1, chunk: lineageB, beforeNames: [], currentNames: [] }},
]);
const localChange = localLineageBuilt.annotations.get('local-change');
const localSibling = localLineageBuilt.annotations.get('local-sibling');
if (JSON.stringify(localChange.beforeNames) !== JSON.stringify([lineageBefore]) || JSON.stringify(localChange.currentNames) !== JSON.stringify([lineageCurrent])) throw new Error('event-local alpha/beta lineage was lost');
if (localSibling.filename !== lineageCurrent || localSibling.beforeNames.length || localSibling.currentNames.length) throw new Error('file sibling inherited another event lineage instead of filename-only fallback');

const anonymousCrossAttempt = buildMrpcsTransferAnnotations([
  {{ eventId: 'anonymous-a', ts: base + 46000, flowKey: 'flow-anonymous', cid: '', dir: 1, chunk: parsed0 }},
  {{ eventId: 'anonymous-b', ts: base + 46001, flowKey: 'flow-anonymous', cid: '', dir: 1, chunk: parsed1 }},
]);
if (anonymousCrossAttempt.files.length !== 2 || anonymousCrossAttempt.transfers.length !== 2) throw new Error('missing-CID attempts were merged into one file identity');
for (const eventId of ['anonymous-a', 'anonymous-b']) {{
  const annotation = anonymousCrossAttempt.annotations.get(eventId);
  if (!annotation || annotation.fileVerified || annotation.attemptVerified || annotation.fileSeenCount !== 1 || annotation.attemptSeenCount !== 1) throw new Error('missing CID cross-attempt chunks produced false verification: ' + eventId);
}}
const parsed1SameAttempt = parseMrpcsTransferChunk(makeRecord(chunk1, {{
  a: 0x11111111, b: 0x22222222, total: whole.length, count: 2, index: 1, fullCrc,
}}));
const anonymousSameAttempt = buildMrpcsTransferAnnotations([
  {{ eventId: 'anonymous-same-0', ts: base + 47000, flowKey: 'flow-anonymous', cid: '', dir: 1, chunk: parsed0 }},
  {{ eventId: 'anonymous-same-1', ts: base + 47001, flowKey: 'flow-anonymous', cid: '', dir: 1, chunk: parsed1SameAttempt }},
]);
if (anonymousSameAttempt.files.length !== 1) throw new Error('same anonymous A/B attempt was split');
for (const eventId of ['anonymous-same-0', 'anonymous-same-1']) {{
  const annotation = anonymousSameAttempt.annotations.get(eventId);
  if (!annotation || !annotation.attemptVerified) throw new Error('same anonymous attempt could not complete: ' + eventId);
}}

const liveName = 'mrpcs_i_v_tl.data';
const liveNameBytes = Array.from(Buffer.from(liveName, 'ascii'));
const liveWrapperPrefix = [0, 1, 0, 0, 0, liveNameBytes.length + 1, ...liveNameBytes, 0, 0x31, 0x32];
const liveWrapper = liveWrapperPrefix.concat(new Array(940 - liveWrapperPrefix.length).fill(0x41));
const liveIdentity = {{ a: 0x6850b6e7, b: 0x0bb2e00b, total: 7171, count: 8, fullCrc: 0xbeedb1ff }};
const live5Bytes = Array.from({{ length: 940 }}, (_value, index) => (index * 11 + 5) & 255);
const live7Bytes = Array.from({{ length: 591 }}, (_value, index) => (index * 7 + 0x23) & 255);
const live4Bytes = Array.from({{ length: 940 }}, (_value, index) => (index * 13 + 0xa0) & 255);
const live5 = parseMrpcsTransferChunk(makeLiveRecord(live5Bytes, {{ ...liveIdentity, index: 5, lengthOffset: 0x2e }}));
const live7 = parseMrpcsTransferChunk(makeLiveRecord(live7Bytes, {{
  ...liveIdentity, index: 7, lengthOffset: 0x2d, declaredGap: 6, missing: 3,
}}));
const live0 = parseMrpcsTransferChunk(makeLiveRecord(liveWrapper, {{
  ...liveIdentity, index: 0, lengthOffset: 0x2b, declaredGap: 5, chunkCrc: (tssCrc32(liveWrapper) ^ 1) >>> 0,
}}));
const live4 = parseMrpcsTransferChunk(makeLiveRecord(live4Bytes, {{ ...liveIdentity, index: 4, lengthOffset: 0x2e }}));
if (!live5 || !live7 || !live0 || !live4 || live0.chunkCrcMatch || live7.chunkCrcMatch || !live7.truncated || !live5.chunkCrcMatch || !live4.chunkCrcMatch) throw new Error('live 005f fixtures did not retain CRC/truncation evidence');
const liveBuilt = buildMrpcsTransferAnnotations([
  {{ eventId: 'seq114', ts: base + 50000, flowKey: 'flow-live', cid: 'cid-live', dir: 1, msgIndex: 160, chunkIndex: 0, summaryVerifiedTransfer: true, currentNames: [], beforeNames: [], chunk: live5 }},
  {{ eventId: 'seq116', ts: base + 50002, flowKey: 'flow-live', cid: 'cid-live', dir: 1, msgIndex: 160, chunkIndex: 2, summaryVerifiedTransfer: true, currentNames: [], beforeNames: [], chunk: live7 }},
  {{ eventId: 'seq119', ts: base + 50005, flowKey: 'flow-live', cid: 'cid-live', dir: 1, msgIndex: 160, chunkIndex: 5, summaryVerifiedTransfer: true, currentNames: [liveName], beforeNames: [], chunk: live0 }},
  {{ eventId: 'seq120', ts: base + 50006, flowKey: 'flow-live', cid: 'cid-live', dir: 1, msgIndex: 161, chunkIndex: 0, summaryVerifiedTransfer: true, currentNames: [], beforeNames: [], chunk: live4 }},
  {{ eventId: 'summary-only', ts: base + 50007, flowKey: 'flow-live', cid: 'cid-live', dir: 1, msgIndex: 160, chunkIndex: 6, summaryVerifiedTransfer: true, currentNames: ['mrpcs_i_v_ic.data'], beforeNames: [] }},
]);
if (liveBuilt.files.length !== 1 || liveBuilt.transfers.length !== 1) throw new Error('live file/attempt identity was not aggregated across msg_idx');
if (liveBuilt.files[0].chunks.size !== 2 || liveBuilt.files[0].filename !== liveName) throw new Error('bad-CRC head was not kept for lineage or entered the CRC set');
for (const eventId of ['seq114', 'seq119', 'seq120']) {{
  const annotation = liveBuilt.annotations.get(eventId);
  if (!annotation || !annotation.structuredChunk || annotation.layout !== 'live_005f') throw new Error('live structured annotation missing for ' + eventId);
  const expectedCurrentNames = eventId === 'seq119' ? [liveName] : [];
  if (annotation.filename !== liveName || JSON.stringify(annotation.currentNames) !== JSON.stringify(expectedCurrentNames) || annotation.beforeNames.length !== 0) throw new Error('event-local lineage or file fallback is wrong for ' + eventId);
  if (annotation.fileSeenCount !== 2 || annotation.attemptSeenCount !== 2 || annotation.fileVerified || annotation.attemptVerified) throw new Error('live CRC collection admitted an unverified block for ' + eventId);
}}
const tailAnnotation = liveBuilt.annotations.get('seq116');
if (!tailAnnotation || !tailAnnotation.structuredChunk || tailAnnotation.layout !== 'live_005f_truncated_tail' || tailAnnotation.index !== 7 || tailAnnotation.count !== 8) throw new Error('truncated tail was not retained as structured index 7/8');
if (tailAnnotation.filename !== liveName || tailAnnotation.currentNames.length !== 0 || tailAnnotation.beforeNames.length !== 0) throw new Error('truncated tail lost filename fallback or inherited fake event lineage');
if (tailAnnotation.chunkCrcMatch || tailAnnotation.fileSeenCount !== 2 || tailAnnotation.fileVerified || tailAnnotation.attemptVerified || !tailAnnotation.reason.includes('missing 3B')) throw new Error('truncated tail entered the CRC completion set');
if (liveBuilt.annotations.get('seq119').chunkCrcMatch !== false || liveBuilt.annotations.get('seq114').chunkCrcMatch !== true) throw new Error('per-event live CRC evidence was lost');
const summaryOnly = liveBuilt.annotations.get('summary-only');
if (!summaryOnly || summaryOnly.structuredChunk || summaryOnly.filename || summaryOnly.currentNames.length || summaryOnly.beforeNames.length) throw new Error('summary-only observation inherited an unproven filename');
const references = [
  {{ eventId: 'reference-within', ts: base + 15000, flowKey: 'flow-A', cid: 'cid-A', packetLength: 162, businessRole: 'request_005b', businessNames: [filename], reportCodes: [0x010a005b], currentNames: [filename], beforeNames: ['mrpcs_i_v_old.data'] }},
  {{ eventId: 'reference-after', ts: base + 45000, flowKey: 'flow-A', cid: 'cid-A', packetLength: 220, businessRole: 'request_005b', businessNames: [filename], reportCodes: [0x010a005b], currentNames: [filename], beforeNames: [] }},
  {{ eventId: 'reference-mixed-variants', ts: base + 15000, flowKey: 'flow-A', cid: 'cid-A', packetLength: 162, businessRole: 'alias_request_0061', businessNames: ['mrpcs_i_v_tl.data'], reportCodes: [0x010a0061], beforeReportCodes: [0x010a005b], currentNames: ['mrpcs_i_v_tl.data'], beforeNames: [filename] }},
  {{ eventId: 'reference-timeout', ts: base + 5000, flowKey: 'flow-A', cid: 'cid-A', packetLength: 162, currentNames: [filename], beforeNames: [] }},
  {{ eventId: 'reference-missing-cid', ts: base + 15000, flowKey: 'flow-A', packetLength: 162, currentNames: [filename], beforeNames: [] }},
];
const correlated = correlateMrpcsReferenceAnnotations(references, built, built.annotations);
if (!(correlated instanceof Map)) throw new Error('correlation did not return a Map');
const within = correlated.get('reference-within');
if (!within || within.type !== 'reference' || !within.matched || within.filename !== filename) throw new Error('within-window reference was not matched');
if (within.deltaMs !== 25000 || within.relation !== 'before_transfer' || within.businessRole !== 'request_005b') throw new Error('within-window business/timing metadata mismatch');
if (JSON.stringify(within.reportCodes) !== JSON.stringify([0x010a005b])) throw new Error('request report evidence was lost');
if (JSON.stringify(within.currentNames) !== JSON.stringify([filename]) || JSON.stringify(within.beforeNames) !== JSON.stringify(['mrpcs_i_v_old.data']) || JSON.stringify(within.businessNames) !== JSON.stringify([filename])) throw new Error('reference name lineage was lost');
const after = correlated.get('reference-after');
if (!after || !after.matched || after.relation !== 'after_transfer' || after.deltaMs !== 5000) throw new Error('post-transfer request timing was not retained');
const mixed = correlated.get('reference-mixed-variants');
if (!mixed || mixed.matched || mixed.filename !== 'mrpcs_i_v_tl.data' || JSON.stringify(mixed.beforeReportCodes) !== JSON.stringify([0x010a005b])) throw new Error('before variant name/report was cross-paired with current request');
const timeout = correlated.get('reference-timeout');
if (!timeout || timeout.type !== 'reference' || timeout.matched || timeout.deltaMs !== null || timeout.relation !== '') throw new Error('reference older than 30 seconds was associated');
const missingCid = correlated.get('reference-missing-cid');
if (!missingCid || missingCid.matched || missingCid.deltaMs !== null) throw new Error('missing CID was treated as same connection');

const outboundBuilt = buildMrpcsTransferAnnotations(observations.map((item) => ({{ ...item, dir: 0 }})));
const outboundCorrelation = correlateMrpcsReferenceAnnotations([references[0]], outboundBuilt, outboundBuilt.annotations);
if (outboundCorrelation.get('reference-within').matched) throw new Error('outbound transfer was called a later download');

const cleanNameBytes = Array.from(Buffer.from(' mrpcs_i_v_ic.data ', 'ascii'));
const prefixedNameBytes = Array.from(Buffer.from('notmrpcs_i_v_ic.data', 'ascii'));
if (JSON.stringify(extractMrpcsResourceNames(cleanNameBytes)) !== JSON.stringify([filename])) throw new Error('bounded resource name was not found');
if (extractMrpcsResourceNames(prefixedNameBytes).length !== 0) throw new Error('resource name was cut out of a larger token');
for (const genericName of [
  'mrpcs_i_c.data',
  'mrpcs_a_l.data',
  'mrpcs-uam-ios-167.data',
  'mrpcs.data',
  'MRPCS_I_F.DATA',
]) {{
  if (!isMrpcsResourceFilename(genericName)) throw new Error('generic MRPCS name rejected: ' + genericName);
  const genericBytes = Array.from(Buffer.from(' ' + genericName + ' ', 'ascii'));
  if (JSON.stringify(extractMrpcsResourceNames(genericBytes)) !== JSON.stringify([genericName])) throw new Error('generic MRPCS name not extracted: ' + genericName);
  const rawName = Array.from(Buffer.from(genericName, 'ascii'));
  const genericWrapper = [0, 1, 0, 0, 0, rawName.length + 1, ...rawName, 0, 0x41, 0x42];
  if (extractMrpcsWrapperName(genericWrapper) !== genericName) throw new Error('generic wrapper name not preserved: ' + genericName);
  const genericCrc = tssCrc32(genericWrapper);
  const genericChunk = parseMrpcsTransferChunk(makeRecord(genericWrapper, {{
    a: 0x33333333, b: 0x44444444, total: genericWrapper.length, count: 1, index: 0, fullCrc: genericCrc,
  }}));
  const genericBuilt = buildMrpcsTransferAnnotations([{{
    eventId: 'generic-' + genericName, ts: base + 41000, flowKey: 'flow-A', cid: 'cid-A', dir: 1, chunk: genericChunk,
  }}]);
  const genericAnnotation = genericBuilt.annotations.get('generic-' + genericName);
  if (!genericAnnotation || genericAnnotation.filename !== genericName || !genericAnnotation.fileVerified) throw new Error('generic name did not propagate to transfer marker: ' + genericName);
}}
for (const invalidName of ['mrpfoo.data', 'notmrpcs_i_v_ic.data', 'mrpcs_i_v_ic.bin', 'mrpcs bad.data']) {{
  if (isMrpcsResourceFilename(invalidName)) throw new Error('non-MRPCS name accepted: ' + invalidName);
}}
if (!isMrpcsResourceFilename('mrpcs' + 'x'.repeat(117) + '.data')) throw new Error('maximum wrapper filename rejected');
if (isMrpcsResourceFilename('mrpcs' + 'x'.repeat(118) + '.data')) throw new Error('oversized wrapper filename accepted');

const corrupt1 = {{ ...parsed1, chunkCrc: (parsed1.chunkCrc ^ 1) >>> 0, chunkCrcMatch: false }};
const badBuilt = buildMrpcsTransferAnnotations([
  observations[1],
  {{ ...observations[0], eventId: 'event-bad-index-1', chunk: corrupt1 }},
]);
if (badBuilt.files.some((file) => file.completed || file.fullCrcMatch)) throw new Error('bad chunk CRC completed a file');
for (const annotation of badBuilt.annotations.values()) {{
  if (annotation.attemptVerified || annotation.fileVerified) throw new Error('bad chunk CRC was marked complete');
}}
console.log(JSON.stringify({{ ok: true, fullCrc: fullCrc >>> 0, annotations: built.annotations.size }}));
"""
    result = _run_node_harness(tmp_path, "mrpcs-transfer-annotations.js", program)
    assert result["ok"] is True
    assert result["annotations"] == 2


def test_mrpcs_observer_reads_all_verified_carriers_without_mutating_names(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "isMrpcsResourceFilename",
            "extractMrpcsResourceNames",
            "mrpcsNamedTssReport",
            "collectMrpcsLayerObservation",
            "collectMrpcsInfoObservation",
        )
    )
    program = f"""
function extractPrintableRuns(bytes, minLen) {{
  const out = []; let start = -1;
  for (let index = 0; index <= bytes.length; index += 1) {{
    const printable = index < bytes.length && bytes[index] >= 0x20 && bytes[index] <= 0x7e;
    if (printable && start < 0) start = index;
    if (!printable && start >= 0) {{
      if (index - start >= minLen) out.push({{ off: start, text: String.fromCharCode(...bytes.slice(start, index)) }});
      start = -1;
    }}
  }}
  return out;
}}
function findMrpcsTransferChunk() {{ return null; }}
function readBe16(bytes, offset) {{ return ((Number(bytes[offset]) << 8) | Number(bytes[offset + 1])) >>> 0; }}
function readBe32(bytes, offset) {{ return (((Number(bytes[offset]) * 0x1000000) + (Number(bytes[offset + 1]) << 16) + (Number(bytes[offset + 2]) << 8) + Number(bytes[offset + 3])) >>> 0); }}
function isLikelyTssReportCode(value) {{ return ((Number(value) >>> 16) & 0xffff) === 0x010a; }}
function decryptDisplayableTssEnvelope(bytes) {{
  if (bytes[0] !== 0xfe) return null;
  const name = Array.from(Buffer.from('mrpcs_decrypted.data', 'ascii'));
  const plain = [0, 0, 0, 1, 0, 0, 1, 10, 0, 91, 0, 0, 0, 0, ...name];
  plain[4] = (plain.length >>> 8) & 255; plain[5] = plain.length & 255;
  return {{ supported: true, crcMatch: true, plain }};
}}
function gcloudSecurityCommandFromInfo(info) {{ return info.command || null; }}
const MRPCS_OBSERVATION_MAX_EVENT_BYTES = 128 * 1024;
{functions}
const carrierName = 'mrpcs_i_c.data';
const protoName = 'mrpcs_i_f.data';
const rawName = 'mrpcs-a-l.data';
const hintName = 'mrpcs-uam-ios-167.data';
const info = {{
  command: {{ carrier: {{ payload: Array.from(Buffer.from(carrierName, 'ascii')) }} }},
  protoBytes: [...new Array(9000).fill(0), ...Array.from(Buffer.from(protoName, 'ascii'))],
  bytes: [0xfe, ...Array.from(Buffer.from(rawName, 'ascii'))],
  uagameResource: {{ name: hintName }},
}};
const observed = collectMrpcsInfoObservation(info);
const actual = new Set(observed.names);
for (const expected of [carrierName, protoName, rawName, hintName, 'mrpcs_decrypted.data']) {{
  if (!actual.has(expected)) throw new Error('missing observed name: ' + expected);
}}
if (observed.chunk !== null) throw new Error('non-transfer carrier became a transfer chunk');
if (observed.namedRecords.length !== 1 || observed.namedRecords[0].reportCode !== 0x010a005b || JSON.stringify(observed.namedRecords[0].names) !== JSON.stringify(['mrpcs_decrypted.data'])) throw new Error('complete named 005b request record was not retained');
const aliasName = Array.from(Buffer.from('mrpcs_i_v_tl.data', 'ascii'));
const aliasRecord = [0, 0, 0, 1, 0, 0, 1, 10, 0, 97, 0, 0, 0, 0, ...aliasName];
aliasRecord[4] = (aliasRecord.length >>> 8) & 255; aliasRecord[5] = aliasRecord.length & 255;
const aliasObserved = collectMrpcsLayerObservation([aliasRecord]);
if (aliasObserved.namedRecords.length !== 1 || aliasObserved.namedRecords[0].reportCode !== 0x010a0061 || JSON.stringify(aliasObserved.namedRecords[0].names) !== JSON.stringify(['mrpcs_i_v_tl.data'])) throw new Error('complete named 0061 alias request record was not retained');
if (JSON.stringify(info.command.carrier.payload) !== JSON.stringify(Array.from(Buffer.from(carrierName, 'ascii')))) throw new Error('observer mutated carrier bytes');
console.log(JSON.stringify({{ ok: true, names: observed.names.length }}));
"""
    result = _run_node_harness(tmp_path, "mrpcs-generic-observer.js", program)
    assert result == {"ok": True, "names": 5}


def test_mrpcs_candidate_gate_covers_login_and_security_families(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    function = _extract_function(source, "isMrpcsObservationCandidate")
    program = f"""
const MRPCS_OBSERVATION_MAX_EVENT_BYTES = 128 * 1024;
const MRPCS_REFERENCE_EVENT_CLASSES = new Set([
  'account_login', 'ace_antidata', 'ace_ack', 'ace_light', 'ace_other', 'cstss_all',
]);
function gcloudEventClass(ev) {{ return ev.eventClass; }}
function isMrpcsGcloudResourceCandidate(ev) {{ return ev.mrpcsResourceCandidate === true; }}
{function}
for (const eventClass of ['account_login', 'ace_transfer', 'ace_antidata', 'ace_ack', 'ace_light', 'ace_other', 'cstss_all']) {{
  if (!isMrpcsObservationCandidate({{ eventClass, len: 700 }})) throw new Error('candidate class rejected: ' + eventClass);
}}
for (const eventClass of ['gcloud_heartbeat', 'gcloud_network', 'tgcp_control', 'other']) {{
  if (isMrpcsObservationCandidate({{ eventClass, len: 700 }})) throw new Error('unrelated class accepted: ' + eventClass);
}}
if (!isMrpcsObservationCandidate({{ eventClass: 'gcloud_4013', len: 700, mrpcsResourceCandidate: true }})) throw new Error('verified generic resource candidate rejected');
if (isMrpcsObservationCandidate({{ eventClass: 'gcloud_4013', len: 700, mrpcsResourceCandidate: false }})) throw new Error('unscoped generic 4013 accepted');
if (isMrpcsObservationCandidate({{ eventClass: 'ace_antidata', len: 0 }})) throw new Error('zero-length candidate accepted');
if (isMrpcsObservationCandidate({{ eventClass: 'account_login', len: 128 * 1024 + 1 }})) throw new Error('oversized candidate accepted');
console.log(JSON.stringify({{ ok: true }}));
"""
    result = _run_node_harness(tmp_path, "mrpcs-candidate-gate.js", program)
    assert result == {"ok": True}


def test_mrpcs_business_role_requires_outbound_antidata_and_named_report(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    function = _extract_function(source, "inspectMrpcsEvent")
    program = f"""
function isVerifiedMrpcsTransferSummary() {{ return false; }}
function analyzeGcloudEvent(ev) {{ return {{ report: ev.report, name: ev.currentName }}; }}
function analyzeGcloudBeforeVariant(ev) {{ return ev.beforeReport ? {{ report: ev.beforeReport, name: ev.beforeName }} : null; }}
function collectMrpcsEventPayloadObservation(info) {{
  return info && info.report
    ? {{ names: [info.name], namedRecords: [{{ reportCode: info.report, names: [info.name] }}], chunk: null }}
    : {{ names: [], namedRecords: [], chunk: null }};
}}
function normalizeMrpcsNames(values) {{ return Array.from(new Set((values || []).filter(Boolean))); }}
function gcloudEventClass(ev) {{ return ev.eventClass; }}
function getEventId(ev) {{ return ev.id; }}
const state = {{ flowId: 'flow' }};
{function}
const base = {{ id: 'event', ts: 1, cid: 'cid', len: 62, dir: 0, eventClass: 'ace_antidata', summary: '', currentName: 'mrpcs_i_v_tl.data' }};
if (inspectMrpcsEvent({{ ...base, report: 0x010a005b }}).businessRole !== 'request_005b') throw new Error('005b resource request was not classified');
if (inspectMrpcsEvent({{ ...base, report: 0x010a0061 }}).businessRole !== 'alias_request_0061') throw new Error('0061 alias request was not classified');
if (inspectMrpcsEvent({{ ...base, dir: 1, report: 0x010a005b }}).businessRole !== 'reference') throw new Error('inbound 005b became a client request');
if (inspectMrpcsEvent({{ ...base, eventClass: 'ace_other', report: 0x010a005b }}).businessRole !== 'reference') throw new Error('non-AntiData 005b became a resource request');
if (inspectMrpcsEvent({{ ...base, report: 0x010a0056 }}).businessRole !== 'reference') throw new Error('unknown named report became a resource request');
const mixed = inspectMrpcsEvent({{ ...base, report: 0x010a0061, beforeReport: 0x010a005b, beforeName: 'mrpcs_i_v_ic.data' }});
if (mixed.businessRole !== 'alias_request_0061' || JSON.stringify(mixed.businessNames) !== JSON.stringify(['mrpcs_i_v_tl.data'])) throw new Error('before 005b overrode the current 0061 record');
if (JSON.stringify(mixed.reportCodes) !== JSON.stringify([0x010a0061]) || JSON.stringify(mixed.beforeReportCodes) !== JSON.stringify([0x010a005b])) throw new Error('current/before report evidence was merged');
console.log(JSON.stringify({{ ok: true }}));
"""
    result = _run_node_harness(tmp_path, "mrpcs-business-role.js", program)
    assert result == {"ok": True}


def test_verified_005f_summary_falls_back_without_inventing_a_file(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    function = _extract_function(source, "isVerifiedMrpcsTransferSummary")
    program = f"""
function readSummaryValue(summaryText, key) {{
  const match = String(summaryText || '').match(new RegExp('(?:^|\\\\s)' + key + '=([^\\\\s)]+)'));
  return match ? match[1] : '';
}}
function gcloudEventClass(ev) {{ return ev.eventClass; }}
{function}
const verified = {{
  eventClass: 'ace_transfer',
  summary: 'crypto=decrypted gcloud_observation_ace_header_verified=1 gcloud_observation_ace_reports=0x010a0011,0x010A005F',
}};
if (!isVerifiedMrpcsTransferSummary(verified, verified.summary)) throw new Error('verified 005f transfer summary rejected');
for (const candidate of [
  {{ ...verified, eventClass: 'ace_other' }},
  {{ ...verified, summary: verified.summary.replace('header_verified=1', 'header_verified=0') }},
  {{ ...verified, summary: verified.summary.replace('0x010A005F', '0x010a005e') }},
]) {{
  if (isVerifiedMrpcsTransferSummary(candidate, candidate.summary)) throw new Error('unverified summary promoted');
}}
console.log(JSON.stringify({{ ok: true }}));
"""
    result = _run_node_harness(tmp_path, "mrpcs-verified-summary.js", program)
    assert result == {"ok": True}


def test_visible_old_mrpcs_candidate_is_merged_ahead_of_recent_window(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "syncMrpcsVisibleObservationCandidates",
            "mergeMrpcsObservationCandidateEvents",
        )
    )
    program = f"""
const state = {{ flowId: 'flow-A' }};
const mrpcsObservationIndex = {{ visibleCandidates: new Map(), visibleFlowId: '' }};
function isMrpcsObservationCandidate(ev) {{ return ev && ev.candidate === true; }}
function getEventId(ev) {{ return String(ev && ev.id || ''); }}
{functions}
const oldVisible = {{ id: 'seq114', ts: 114, candidate: true }};
if (!syncMrpcsVisibleObservationCandidates([oldVisible, {{ id: 'noise', ts: 1, candidate: false }}])) throw new Error('visible change was not detected');
if (syncMrpcsVisibleObservationCandidates([oldVisible])) throw new Error('stable visible set triggered a render/schedule loop');
const recent = Array.from({{ length: 224 }}, (_value, index) => ({{ id: 'recent-' + index, ts: 1000 + index, candidate: true }}));
const merged = mergeMrpcsObservationCandidateEvents(mrpcsObservationIndex.visibleCandidates, [recent, [recent[0]], []]);
if (merged.length !== 225 || merged[0].id !== 'seq114' || !merged.some((ev) => ev.id === 'recent-223')) throw new Error('old visible candidate was dropped behind the recent-224 window');
if (!syncMrpcsVisibleObservationCandidates([]) || mrpcsObservationIndex.visibleCandidates.size !== 0) throw new Error('paged-away visible candidates were retained');
console.log(JSON.stringify({{ ok: true, merged: merged.length }}));
"""
    result = _run_node_harness(tmp_path, "mrpcs-visible-priority.js", program)
    assert result == {"ok": True, "merged": 225}


def test_mrpcs_badge_renders_truthful_lineage_colors_and_summary_only_state(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "isMrpcsResourceFilename",
            "normalizeMrpcsNames",
            "mrpcsCompactResourceName",
            "appendMrpcsLineage",
            "syncMrpcsSummaryBadge",
        )
    )
    program = f"""
class FakeNode {{
  constructor(tag = '', text = '') {{
    this.tagName = tag; this.children = []; this.parentNode = null; this._text = String(text || ''); this._classes = new Set(); this.title = '';
    this.classList = {{
      add: (...names) => names.forEach((name) => this._classes.add(name)),
      remove: (...names) => names.forEach((name) => this._classes.delete(name)),
      contains: (name) => this._classes.has(name),
    }};
  }}
  set className(value) {{ this._classes = new Set(String(value || '').split(/\\s+/).filter(Boolean)); }}
  get className() {{ return Array.from(this._classes).join(' '); }}
  set textContent(value) {{ this.children = []; this._text = String(value || ''); }}
  get textContent() {{ return this._text + this.children.map((child) => child.textContent).join(''); }}
  appendChild(child) {{ child.parentNode = this; this.children.push(child); return child; }}
  insertBefore(child, anchor) {{ const index = this.children.indexOf(anchor); child.parentNode = this; if (index < 0) this.children.push(child); else this.children.splice(index, 0, child); return child; }}
  remove() {{ if (!this.parentNode) return; const index = this.parentNode.children.indexOf(this); if (index >= 0) this.parentNode.children.splice(index, 1); this.parentNode = null; }}
  querySelectorAll(selector) {{
    const className = selector.startsWith('.') ? selector.slice(1) : '';
    const out = [];
    const visit = (node) => {{ for (const child of node.children || []) {{ if (className && child.classList && child.classList.contains(className)) out.push(child); visit(child); }} }};
    visit(this); return out;
  }}
  querySelector(selector) {{ return this.querySelectorAll(selector)[0] || null; }}
}}
const document = {{
  createElement: (tag) => new FakeNode(tag),
  createTextNode: (text) => new FakeNode('#text', text),
}};
const MRPCS_TRANSFER_WINDOW = 224;
const MRPCS_REFERENCE_WINDOW = 32;
const MRPCS_LOGIN_WINDOW = 16;
const mrpcsObservationIndex = {{ annotations: new Map(), truncated: false }};
function getEventId(ev) {{ return String(ev && ev.id || ''); }}
function formatHexValue(value, width) {{ return '0x' + (Number(value) >>> 0).toString(16).padStart(Number(width || 0), '0'); }}
{functions}
function makeSummary() {{
  const summary = new FakeNode('summary');
  const preview = new FakeNode('span'); preview.className = 'summary-preview'; summary.appendChild(preview);
  const tail = new FakeNode('span'); tail.className = 'summary-tail'; summary.appendChild(tail);
  return {{ summary, preview }};
}}
function render(annotation) {{
  mrpcsObservationIndex.annotations = new Map([['event', annotation]]);
  const fixture = makeSummary();
  syncMrpcsSummaryBadge(fixture.summary, 'event');
  const badge = fixture.summary.querySelector('.summary-mrpcs-badge');
  if (!badge) throw new Error('badge missing');
  if (fixture.summary.children.indexOf(badge) >= fixture.summary.children.indexOf(fixture.preview)) throw new Error('badge was not kept left of preview');
  return badge;
}}
const base = {{
  type: 'transfer', dir: 1, structuredChunk: true, layout: 'live_005f', filename: 'mrpcs_i_v_tl.data',
  index: 0, count: 8, totalLength: 7171, attemptSeenCount: 2, fileSeenCount: 2,
  attemptVerified: false, fileVerified: false, chunkCrcMatch: true, fullCrc: 0xbeedb1ff,
  beforeNames: [], currentNames: [],
}};
let badge = render(base);
if (badge.querySelector('.summary-mrpcs-lineage-current').textContent !== 'v_tl') throw new Error('filename-only sibling fallback was not compact/green');
if (badge.querySelector('.summary-mrpcs-lineage-before') || badge.querySelector('.summary-mrpcs-lineage-arrow') || badge.textContent.includes('v_ic')) throw new Error('filename-only sibling fallback invented event lineage');
badge = render({{ ...base, beforeNames: ['mrpcs_i_v_alpha.data'], currentNames: ['mrpcs_i_v_beta.data'], filename: 'mrpcs_i_v_beta.data' }});
if (badge.querySelector('.summary-mrpcs-lineage-before').textContent !== 'v_alpha' || badge.querySelector('.summary-mrpcs-lineage-current').textContent !== 'v_beta' || badge.querySelector('.summary-mrpcs-lineage-arrow').textContent !== '→') throw new Error('real before/current lineage was not rendered in stage order');
badge = render({{ ...base, beforeNames: ['mrpcs_i_v_alpha.data'], currentNames: [], filename: 'mrpcs_i_v_beta.data' }});
if (badge.querySelector('.summary-mrpcs-lineage-before') || badge.querySelector('.summary-mrpcs-lineage-arrow') || badge.querySelector('.summary-mrpcs-lineage-current').textContent !== 'v_beta') throw new Error('before-only event was paired with file fallback as fake lineage');
badge = render({{ ...base, beforeNames: ['mrpcs_i_v_tl.data'] }});
if (badge.querySelector('.summary-mrpcs-lineage-before') || badge.querySelector('.summary-mrpcs-lineage-arrow') || badge.querySelector('.summary-mrpcs-lineage-current').textContent !== 'v_tl') throw new Error('identical before/current was rendered as a fake change');
badge = render({{
  type: 'reference', filename: 'mrpcs_i_v_tl.data', currentNames: ['mrpcs_i_v_tl.data'], beforeNames: [],
  businessRole: 'request_005b', businessNames: ['mrpcs_i_v_tl.data'], reportCodes: [0x010a005b], matched: true,
  relation: 'before_transfer', deltaMs: 110, indexComplete: true,
}});
if (!badge.textContent.includes('MRPCS请求↑') || !badge.textContent.includes('005b') || !badge.textContent.includes('110ms后下发') || badge.textContent.includes('前置?')) throw new Error('verified 005b request still used packet-length guesswork');
if (!badge.title.includes('report=0x010a005b') || !badge.title.includes('不再按包长猜测前置')) throw new Error('005b business evidence was not explained');
badge = render({{
  type: 'reference', filename: 'mrpcs_i_v_tl.data', currentNames: ['mrpcs_i_v_tl.data'], beforeNames: [],
  businessRole: 'request_005b', businessNames: ['mrpcs_i_v_tl.data'], reportCodes: [0x010a005b], matched: true,
  relation: 'after_transfer', deltaMs: 4832, indexComplete: true,
}});
if (!badge.textContent.includes('MRPCS请求↑') || !badge.textContent.includes('距上次下发4.83s') || badge.textContent.includes('反馈')) throw new Error('post-transfer 005b request was mislabeled as a response');
badge = render({{
  type: 'reference', filename: 'mrpcs_i_v_tl.data', currentNames: ['mrpcs_i_v_tl.data'], beforeNames: [],
  businessRole: 'alias_request_0061', businessNames: ['mrpcs_i_v_tl.data'], reportCodes: [0x010a0061], matched: false,
  relation: '', deltaMs: null, indexComplete: true,
}});
if (!badge.textContent.includes('MRPCS请求↑') || !badge.textContent.includes('0061') || !badge.textContent.includes('30s未见下发')) throw new Error('verified 0061 alias request was not identified');
if (!badge.title.includes('opaque A/B') || !badge.title.includes('不把它称为上一批反馈或 ACK')) throw new Error('0061 business role boundary was not explained');
badge = render({{
  type: 'reference', filename: 'mrpcs_current.data', currentNames: ['mrpcs_current.data'], beforeNames: ['mrpcs_before.data'],
  businessRole: 'alias_request_0061', businessNames: ['mrpcs_current.data'], reportCodes: [0x010a0061], beforeReportCodes: [0x010a005b],
  matched: false, relation: '', deltaMs: null, indexComplete: true,
}});
if (badge.textContent.includes('before') || badge.querySelector('.summary-mrpcs-lineage-before') || badge.querySelector('.summary-mrpcs-lineage-current').textContent !== 'current') throw new Error('request badge mixed before variant evidence into current role');
badge = render({{ type: 'transfer', dir: 1, structuredChunk: false, summaryVerifiedTransfer: true, chunkIndex: 5, currentNames: [], beforeNames: [] }});
if (!badge.textContent.includes('005f 未完整解析') || badge.textContent.includes('v_ic') || badge.querySelector('.summary-mrpcs-lineage-current') || badge.querySelector('.summary-mrpcs-lineage-before')) throw new Error('summary-only state invented file evidence');
console.log(JSON.stringify({{ ok: true, text: badge.textContent }}));
"""
    result = _run_node_harness(tmp_path, "mrpcs-badge-lineage.js", program)
    assert result["ok"] is True
    assert "005f 未完整解析" in str(result["text"])
    assert re.search(
        r"\.summary-mrpcs-lineage-before\s*\{[^}]*color:\s*#fb7185",
        source,
        re.S,
    )
    assert re.search(
        r"\.summary-mrpcs-lineage-current\s*\{[^}]*color:\s*#34d399",
        source,
        re.S,
    )


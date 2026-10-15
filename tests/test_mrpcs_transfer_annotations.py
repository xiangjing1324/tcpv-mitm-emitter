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
    wrong_family[20] = 1
    opaque_plain = b"not-a-framed-inner-record"
    opaque_envelope = _strict_0037_family0_envelope(opaque_plain)

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
if (parseTssEncryptedEnvelope({json.dumps(list(wrong_family))}) !== null) throw new Error('unverified 0037 family was accepted');
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


def test_mrpcs_transfer_chunk_parses_strict_lengths_indexes_and_crc(
    tmp_path: Path,
) -> None:
    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in ("tssCrc32", "parseMrpcsTransferChunk")
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
console.log(JSON.stringify({{ ok: true, chunkCrc: parsed.chunkCrc >>> 0 }}));
"""
    result = _run_node_harness(tmp_path, "parse-005f-transfer-chunk.js", program)
    expected_chunk = bytes((index * 29 + 7) & 0xFF for index in range(73))
    assert result == {"ok": True, "chunkCrc": zlib.crc32(expected_chunk) & 0xFFFFFFFF}


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
  if (annotation.attemptSeenCount !== 1 || annotation.fileSeenCount !== 2) throw new Error('attempt/file progress was conflated for ' + eventId);
  if (annotation.attemptVerified || !annotation.fileVerified || !annotation.chunkCrcMatch || annotation.fullCrc !== fullCrc) throw new Error('cross-retry CRC semantics are wrong for ' + eventId);
}}
const references = [
  {{ eventId: 'reference-within', ts: base + 15000, packetLength: 162, currentNames: ['mrpcs_i_v_tl.data'], beforeNames: [filename] }},
  {{ eventId: 'reference-timeout', ts: base + 5000, packetLength: 162, currentNames: [filename], beforeNames: [] }},
];
const correlated = correlateMrpcsReferenceAnnotations(references, built, built.annotations);
if (!(correlated instanceof Map)) throw new Error('correlation did not return a Map');
const within = correlated.get('reference-within');
if (!within || within.type !== 'reference' || !within.matched || within.filename !== filename) throw new Error('within-window reference was not matched');
if (within.deltaMs !== 25000 || within.smallPacket !== true) throw new Error('within-window timing/size metadata mismatch');
if (JSON.stringify(within.currentNames) !== JSON.stringify(['mrpcs_i_v_tl.data']) || JSON.stringify(within.beforeNames) !== JSON.stringify([filename])) throw new Error('reference name lineage was lost');
const timeout = correlated.get('reference-timeout');
if (!timeout || timeout.type !== 'reference' || timeout.matched || timeout.deltaMs !== null) throw new Error('reference older than 30 seconds was associated');

const outboundBuilt = buildMrpcsTransferAnnotations(observations.map((item) => ({{ ...item, dir: 0 }})));
const outboundCorrelation = correlateMrpcsReferenceAnnotations([references[0]], outboundBuilt, outboundBuilt.annotations);
if (outboundCorrelation.get('reference-within').matched) throw new Error('outbound transfer was called a later download');

const cleanNameBytes = Array.from(Buffer.from(' mrpcs_i_v_ic.data ', 'ascii'));
const prefixedNameBytes = Array.from(Buffer.from('notmrpcs_i_v_ic.data', 'ascii'));
if (JSON.stringify(extractMrpcsResourceNames(cleanNameBytes)) !== JSON.stringify([filename])) throw new Error('bounded resource name was not found');
if (extractMrpcsResourceNames(prefixedNameBytes).length !== 0) throw new Error('resource name was cut out of a larger token');

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


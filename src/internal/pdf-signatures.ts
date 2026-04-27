export interface ExtractedSignature {
  signatureIndex: number;
  byteRange: [number, number, number, number];
  /** CMS DER bytes (decoded from /Contents hex string). */
  contents: Uint8Array;
  /** Bytes covered by /ByteRange — pdf[a..a+b] ++ pdf[c..c+d]. */
  signedBytes: Uint8Array;
  /** Form field name `/T` from the signature widget annotation, if discoverable. */
  fieldName: string | null;
  /** /SubFilter from the signature value dict, if present. */
  subFilter: string | null;
  /** True iff the byte range covers offset 0 through (effectively) EOF. */
  coversWholeDocument: boolean;
}

const BYTE_RANGE_RE = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/;
const CONTENTS_RE = /\/Contents\s*<([0-9a-fA-F\s]*)>/;
const SUBFILTER_RE = /\/SubFilter\s*\/([A-Za-z0-9_.\-]+)/;
const TYPE_SIG_RE = /\/Type\s*\/Sig\b/g;
const T_RE = /\/T\s*\(((?:\\.|[^\\)])*)\)/;

const WHOLE_DOCUMENT_SLACK = 2;

/**
 * Extract every PAdES signature from a PDF in document order. Returns one
 * entry per `/Type /Sig` value dict, with the `ByteRange`-covered bytes
 * already concatenated for downstream CMS verification.
 */
export function extractSignatures(pdf: Uint8Array): ExtractedSignature[] {
  const text = bytesToLatin1(pdf);
  const sigPositions: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = TYPE_SIG_RE.exec(text)) !== null) {
    sigPositions.push(m.index);
  }

  const out: ExtractedSignature[] = [];
  for (let i = 0; i < sigPositions.length; i++) {
    const start = sigPositions[i] as number;
    const end =
      i + 1 < sigPositions.length
        ? (sigPositions[i + 1] as number)
        : text.length;
    const window = text.slice(start, end);

    const brMatch = BYTE_RANGE_RE.exec(window);
    const cMatch = CONTENTS_RE.exec(window);
    if (!brMatch || !cMatch) continue;

    const a = parseInt(brMatch[1] as string, 10);
    const b = parseInt(brMatch[2] as string, 10);
    const c = parseInt(brMatch[3] as string, 10);
    const d = parseInt(brMatch[4] as string, 10);
    if (
      !Number.isFinite(a) ||
      !Number.isFinite(b) ||
      !Number.isFinite(c) ||
      !Number.isFinite(d) ||
      a < 0 ||
      b < 0 ||
      c < 0 ||
      d < 0 ||
      a + b > pdf.length ||
      c + d > pdf.length
    ) {
      continue;
    }

    const hexClean = (cMatch[1] as string).replace(/\s+/g, "");
    if (hexClean.length % 2 !== 0) continue;
    const contents = hexToBytes(hexClean);

    const sfMatch = SUBFILTER_RE.exec(window);
    const subFilter = sfMatch ? (sfMatch[1] as string) : null;

    // Look for /T (...) inside the sig dict's window first; fall back to a
    // backward scan into the enclosing widget annotation if not present.
    const inWindow = T_RE.exec(window);
    const fieldName = inWindow
      ? decodePdfString(inWindow[1] as string)
      : findFieldNameFor(text, start);

    const signedBytes = concatBytes(pdf.subarray(a, a + b), pdf.subarray(c, c + d));

    const coversWholeDocument =
      a === 0 && c + d >= pdf.length - WHOLE_DOCUMENT_SLACK;

    out.push({
      signatureIndex: out.length,
      byteRange: [a, b, c, d],
      contents,
      signedBytes,
      fieldName,
      subFilter,
      coversWholeDocument,
    });
  }
  return out;
}

/**
 * The `/T` field name lives on the signature widget annotation, not the
 * signature value dict. The widget references the value dict via `/V N R`.
 * We scan backward from the value dict for an annotation whose `/V` points at
 * an object that ultimately contains the value dict. For 0.1.0 we use a
 * simpler heuristic: the closest preceding `/T (...)` within ~4KB is almost
 * always the owning field. Returns `null` if none is found, which is correct
 * behavior — fieldName is documented as best-effort.
 */
function findFieldNameFor(text: string, sigPos: number): string | null {
  const SCAN_BACK = 4096;
  const start = Math.max(0, sigPos - SCAN_BACK);
  const window = text.slice(start, sigPos);
  const re = /\/T\s*\(((?:\\.|[^\\)])*)\)/g;
  let last: RegExpExecArray | null = null;
  let m: RegExpExecArray | null;
  while ((m = re.exec(window)) !== null) last = m;
  if (!last) return null;
  return decodePdfString(last[1] as string);
}

function decodePdfString(raw: string): string {
  return raw
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\b/g, "\b")
    .replace(/\\f/g, "\f")
    .replace(/\\\(/g, "(")
    .replace(/\\\)/g, ")")
    .replace(/\\\\/g, "\\");
}

function bytesToLatin1(bytes: Uint8Array): string {
  // Latin-1 is byte-equivalent — every byte 0..255 maps to U+0000..U+00FF.
  // Avoids multibyte decoding pitfalls for what's a byte-oriented format.
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(
      null,
      bytes.subarray(i, Math.min(i + CHUNK, bytes.length)) as unknown as number[],
    );
  }
  return s;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

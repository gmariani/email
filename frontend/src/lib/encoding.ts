// Byte-level decoding used by headers (RFC 2047) and MIME bodies (RFC 2045).

const decoders = new Map<string, TextDecoder>();

/** A decoder for a MIME charset label; unknown labels fall back to Windows-1252 (a superset of Latin-1). */
export function decoderFor(charset: string | null | undefined): TextDecoder {
    // RFC 2231 allows a language suffix: "utf-8*en".
    const label = (charset ?? '').trim().toLowerCase().replace(/\*.*$/, '') || 'utf-8';
    let decoder = decoders.get(label);
    if (!decoder) {
        try {
            decoder = new TextDecoder(label === 'us-ascii' || label === 'ascii' ? 'utf-8' : label);
        } catch {
            decoder = new TextDecoder('windows-1252');
        }
        decoders.set(label, decoder);
    }
    return decoder;
}

export function decodeBytes(bytes: Uint8Array, charset: string | null | undefined): string {
    return decoderFor(charset).decode(bytes);
}

/** Characters of an already-decoded string back to bytes: ASCII stays as is, anything else becomes UTF-8. */
function toBytes(text: string): number[] {
    const out: number[] = [];
    for (const char of text) {
        const code = char.codePointAt(0) ?? 0;
        if (code < 0x80) out.push(code);
        else out.push(...new TextEncoder().encode(char));
    }
    return out;
}

export function decodeBase64(text: string): Uint8Array {
    const clean = text.replace(/[^A-Za-z0-9+/]/g, '');
    const padded = clean.length % 4 === 1 ? clean.slice(0, -1) : clean;
    try {
        const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
        return Uint8Array.from(binary, (c) => c.charCodeAt(0));
    } catch {
        return new Uint8Array();
    }
}

/** Quoted-printable (RFC 2045). In headers (RFC 2047 "Q"), "_" also means a space. */
export function decodeQuotedPrintable(text: string, header = false): Uint8Array {
    const out: number[] = [];
    const input = header ? text : text.replace(/[ \t]+(\r?\n)/g, '$1');
    for (let i = 0; i < input.length; i++) {
        const char = input[i];
        if (char === '=') {
            const hex = input.slice(i + 1, i + 3);
            if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
                out.push(parseInt(hex, 16));
                i += 2;
                continue;
            }
            // Soft line break: "=" at the end of a line.
            const soft = /^\r?\n/.exec(input.slice(i + 1, i + 3));
            if (soft) {
                i += soft[0].length;
                continue;
            }
            out.push(0x3d);
        } else if (header && char === '_') {
            out.push(0x20);
        } else {
            out.push(...toBytes(char));
        }
    }
    return Uint8Array.from(out);
}

const ENCODED_WORD = /=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g;

/**
 * Decodes RFC 2047 encoded words: "=?UTF-8?B?SGVsbG8=?=" => "Hello".
 * Whitespace between two encoded words is dropped, and adjacent words in the
 * same charset are joined as bytes first so a character split across them survives.
 */
export function decodeEncodedWords(value: string): string {
    if (!value.includes('=?')) return value;

    type Piece = { text: string } | { charset: string; bytes: Uint8Array };
    const pieces: Piece[] = [];
    let last = 0;
    for (const match of value.matchAll(ENCODED_WORD)) {
        const between = value.slice(last, match.index);
        const previous = pieces[pieces.length - 1];
        if (between && !(previous && 'bytes' in previous && /^\s+$/.test(between))) pieces.push({ text: between });
        const [, charset, encoding, payload] = match;
        const bytes = encoding.toUpperCase() === 'B' ? decodeBase64(payload) : decodeQuotedPrintable(payload, true);
        const before = pieces[pieces.length - 1];
        if (before && 'bytes' in before && before.charset.toLowerCase() === charset.toLowerCase()) {
            const joined = new Uint8Array(before.bytes.length + bytes.length);
            joined.set(before.bytes);
            joined.set(bytes, before.bytes.length);
            before.bytes = joined;
        } else {
            pieces.push({ charset, bytes });
        }
        last = (match.index ?? 0) + match[0].length;
    }
    pieces.push({ text: value.slice(last) });
    return pieces.map((p) => ('bytes' in p ? decodeBytes(p.bytes, p.charset) : p.text)).join('');
}

/** RFC 2231 extended value: "utf-8'en'na%C3%AFve.txt" => "naïve.txt" */
export function decodeRfc2231(value: string): string {
    const match = /^([^']*)'[^']*'(.*)$/.exec(value);
    if (!match) return value;
    const bytes: number[] = [];
    const text = match[2];
    for (let i = 0; i < text.length; i++) {
        if (text[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(text.slice(i + 1, i + 3))) {
            bytes.push(parseInt(text.slice(i + 1, i + 3), 16));
            i += 2;
        } else {
            bytes.push(...toBytes(text[i]));
        }
    }
    return decodeBytes(Uint8Array.from(bytes), match[1]);
}

/** Text of a file: UTF-8 when it's valid UTF-8, otherwise Windows-1252 (old 8-bit mail). */
export function decodeFile(bytes: Uint8Array): string {
    try {
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
        return new TextDecoder('windows-1252').decode(bytes);
    }
}

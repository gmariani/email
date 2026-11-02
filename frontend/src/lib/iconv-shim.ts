// Stand-in for iconv-lite, which msgreader uses to decode legacy (ANSI)
// strings in Outlook .msg files. The real package needs Node's Buffer and
// fails in browsers; TextDecoder handles every encoding Outlook writes.
// Wired up as an alias in vite.config.ts.

function label(encoding: string): string {
    const name = encoding.trim().toLowerCase();
    if (name === 'ucs2' || name === 'ucs-2' || name === 'utf16le') return 'utf-16le';
    if (name === 'utf8') return 'utf-8';
    return name;
}

export function decode(bytes: Uint8Array, encoding: string): string {
    try {
        return new TextDecoder(label(encoding)).decode(bytes);
    } catch {
        return new TextDecoder('windows-1252').decode(bytes);
    }
}

/** msgreader only encodes when writing .msg files, which this site never does. */
export function encode(text: string): Uint8Array {
    return new TextEncoder().encode(text);
}

export default { decode, encode };

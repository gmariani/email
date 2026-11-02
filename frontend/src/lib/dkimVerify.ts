import type { DkimSignature } from './auth';
import { decodeBase64 } from './encoding';
import type { HeaderField } from './message';

// DKIM verification (RFC 6376 §3.4, §3.7, §6.1.3; Ed25519 per RFC 8463), done in
// the browser because it needs the message body, which never leaves the page.

export interface DkimVerification {
    /** The body hash we computed matches bh=. null: couldn't compute. */
    bodyHashOk: boolean | null;
    computedBodyHash: string | null;
    /** Set when the body only matched after undoing a known export quirk, or why it couldn't be checked. */
    bodyNote: string | null;
    /** The signature over the headers verifies with the published key. */
    signatureOk: boolean | null;
    /** Why it couldn't be checked, or what went wrong. */
    error: string | null;
}

const WSP = /[ \t]+/g;

/** Body canonicalization: "simple" only trims trailing empty lines; "relaxed" also folds whitespace. */
export function canonicalizeBody(body: string, mode: 'simple' | 'relaxed'): string {
    let lines = body.replace(/\r\n?/g, '\n').split('\n');
    if (mode === 'relaxed') lines = lines.map((line) => line.replace(WSP, ' ').replace(/ $/, ''));
    while (lines.length && lines[lines.length - 1] === '') lines.pop();
    if (!lines.length) return mode === 'simple' ? '\r\n' : '';
    return lines.join('\r\n') + '\r\n';
}

/** Header canonicalization for one field, as raw "Name: value" text (folded with \n). */
export function canonicalizeHeader(raw: string, mode: 'simple' | 'relaxed'): string {
    if (mode === 'simple') return raw.replace(/\r?\n/g, '\r\n');
    const colon = raw.indexOf(':');
    const name = raw.slice(0, colon).trim().toLowerCase();
    const value = raw
        .slice(colon + 1)
        .replace(/\r?\n/g, '')
        .replace(WSP, ' ')
        .trim();
    return `${name}:${value}`;
}

/**
 * The headers listed in h=, picked bottom-up: for a name listed twice, the
 * lower occurrence is used first (RFC 6376 §5.4.2). Names with no (more)
 * occurrences contribute nothing.
 */
export function signedHeaderFields(headers: HeaderField[], names: string[]): HeaderField[] {
    const used = new Set<number>();
    const out: HeaderField[] = [];
    for (const name of names) {
        const field = [...headers].reverse().find((h) => h.key === name && !used.has(h.index));
        if (field) {
            used.add(field.index);
            out.push(field);
        }
    }
    return out;
}

/** The DKIM-Signature header itself, with the b= value emptied, as it was signed. */
export function withoutSignature(raw: string): string {
    return raw.replace(/([;:]\s*b\s*=)[^;]*/i, '$1');
}

function modes(c: string | undefined): ['simple' | 'relaxed', 'simple' | 'relaxed'] {
    const [header = 'simple', body = 'simple'] = (c ?? 'simple/simple').toLowerCase().split('/');
    const pick = (m: string) => (m === 'relaxed' ? 'relaxed' : 'simple');
    return [pick(header), pick(body)];
}

function toBase64(bytes: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

const encoder = new TextEncoder();

/**
 * Wraps a bare PKCS#1 RSAPublicKey in a SubjectPublicKeyInfo, for the few
 * domains that publish keys that way.
 */
function pkcs1ToSpki(pkcs1: Uint8Array): Uint8Array {
    const length = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
    const bitString = [0x03, ...length(pkcs1.length + 1), 0x00, ...pkcs1];
    const algorithm = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    return Uint8Array.from([0x30, ...length(algorithm.length + bitString.length), ...algorithm, ...bitString]);
}

async function importRsa(der: Uint8Array, hash: string): Promise<CryptoKey> {
    const params = { name: 'RSASSA-PKCS1-v1_5', hash };
    try {
        return await crypto.subtle.importKey('spki', der as BufferSource, params, false, ['verify']);
    } catch {
        return await crypto.subtle.importKey('spki', pkcs1ToSpki(der) as BufferSource, params, false, ['verify']);
    }
}

export async function verifyDkim(
    signature: DkimSignature,
    headers: HeaderField[],
    body: string | null,
    key: { publicKey: string | null; keyType: string },
    /** Why there's no body to hash, when body is null. */
    noBody = "Only headers were provided, so the body hash can't be checked.",
): Promise<DkimVerification> {
    const result: DkimVerification = { bodyHashOk: null, computedBodyHash: null, bodyNote: null, signatureOk: null, error: null };
    const tags = signature.tags;
    const algorithm = (tags.a ?? '').toLowerCase();
    const [scheme, hashName] = algorithm.split('-');
    const hash = hashName === 'sha1' ? 'SHA-1' : hashName === 'sha256' ? 'SHA-256' : null;
    if (!hash || (scheme !== 'rsa' && scheme !== 'ed25519')) return { ...result, error: `Unsupported algorithm "${tags.a ?? ''}".` };
    if (!crypto?.subtle) return { ...result, error: 'This browser has no Web Crypto support.' };
    const [headerMode, bodyMode] = modes(tags.c);

    // Body hash.
    if (body === null) {
        result.error = noBody;
        result.bodyNote = noBody;
    } else {
        const want = (tags.bh ?? '').replace(/\s+/g, '');
        const bodyHash = async (text: string) => {
            let canonical = encoder.encode(canonicalizeBody(text, bodyMode));
            if (tags.l && /^\d+$/.test(tags.l)) canonical = canonical.slice(0, parseInt(tags.l, 10));
            return toBase64(await crypto.subtle.digest(hash, canonical as BufferSource));
        };
        result.computedBodyHash = await bodyHash(body);
        result.bodyHashOk = result.computedBodyHash === want;
        // Some mail apps add blank lines between the headers and the body when saving a .eml.
        const blank = /^(?:[ \t]*\r?\n)+/.exec(body)?.[0];
        if (!result.bodyHashOk && blank) {
            const trimmed = await bodyHash(body.slice(blank.length));
            if (trimmed === want) {
                const lines = blank.split('\n').length - 1;
                result.computedBodyHash = trimmed;
                result.bodyHashOk = true;
                result.bodyNote = `Matched after ignoring ${lines} blank line${lines === 1 ? '' : 's'} before the body, which the app that saved this file added.`;
            }
        }
    }

    // Header signature.
    if (!key.publicKey) return { ...result, error: result.error ?? 'No public key to verify with.' };
    if (key.keyType !== scheme) return { ...result, signatureOk: false, error: `The signature uses ${scheme.toUpperCase()} but the published key is ${key.keyType.toUpperCase()}.` };
    const fields = signedHeaderFields(headers, signature.signedHeaders);
    const signed =
        fields.map((f) => canonicalizeHeader(f.raw, headerMode) + '\r\n').join('') + canonicalizeHeader(withoutSignature(signature.header.raw), headerMode);
    const data = encoder.encode(signed);
    const sig = decodeBase64(tags.b ?? '');
    const der = decodeBase64(key.publicKey);
    try {
        if (scheme === 'rsa') {
            const cryptoKey = await importRsa(der, hash);
            result.signatureOk = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, sig as BufferSource, data as BufferSource);
        } else {
            // Ed25519 signs the SHA-256 hash of the headers (RFC 8463 §3). Keys are the raw 32 bytes.
            const raw = der.length === 32 ? der : der.slice(-32);
            const cryptoKey = await crypto.subtle.importKey('raw', raw as BufferSource, { name: 'Ed25519' }, false, ['verify']);
            const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
            result.signatureOk = await crypto.subtle.verify('Ed25519', cryptoKey, sig as BufferSource, digest);
        }
    } catch (error) {
        result.error = `Couldn't use the published key: ${error instanceof Error ? error.message : String(error)}`;
    }
    return result;
}

import { decodeBase64, decodeBytes, decodeEncodedWords, decodeQuotedPrintable, decodeRfc2231 } from './encoding';
import { findHeader, splitMessage, splitTopLevel, stripComments, type HeaderField } from './message';

export interface ContentType {
    type: string;
    params: Record<string, string>;
}

/** 'text/plain; charset="utf-8"; format=flowed' => { type: "text/plain", params: { charset: "utf-8", format: "flowed" } } */
export function parseContentType(value: string | null | undefined, fallback = 'text/plain'): ContentType {
    if (!value) return { type: fallback, params: {} };
    const [type, ...rest] = splitTopLevel(stripComments(value).text, ';');
    return { type: type.trim().toLowerCase() || fallback, params: parseParams(rest) };
}

/** Parameters, including RFC 2231 continuations and charsets: filename*0*=utf-8''a%20b; filename*1=c */
export function parseParams(parts: string[]): Record<string, string> {
    const simple: Record<string, string> = {};
    const continued: Record<string, { index: number; value: string; encoded: boolean }[]> = {};
    for (const part of parts) {
        const eq = part.indexOf('=');
        if (eq < 0) continue;
        const rawKey = part.slice(0, eq).trim().toLowerCase();
        let value = part.slice(eq + 1).trim();
        if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1).replace(/\\(.)/g, '$1');
        const m = /^([^*]+)\*(?:(\d+)\*?)?$/.exec(rawKey);
        if (m && (m[2] !== undefined || rawKey.endsWith('*'))) {
            (continued[m[1]] ??= []).push({ index: m[2] === undefined ? 0 : parseInt(m[2], 10), value, encoded: rawKey.endsWith('*') });
        } else {
            simple[rawKey] = decodeEncodedWords(value);
        }
    }
    for (const [key, pieces] of Object.entries(continued)) {
        pieces.sort((a, b) => a.index - b.index);
        const first = pieces[0];
        if (first.encoded) {
            // Only the first piece carries charset'lang'; percent-decode the whole value with it.
            const charset = /^([^']*)'[^']*'/.exec(first.value);
            const joined = pieces.map((p, i) => (i === 0 && charset ? p.value.slice(charset[0].length) : p.value)).join('');
            simple[key] = decodeRfc2231(`${charset?.[1] ?? 'utf-8'}''${joined}`);
        } else {
            simple[key] = pieces.map((p) => p.value).join('');
        }
    }
    return simple;
}

export interface MimePart {
    /** "1", "1.2", … like IMAP part numbers; "" for the message itself. */
    path: string;
    type: string;
    params: Record<string, string>;
    headers: HeaderField[];
    disposition: string | null;
    filename: string | null;
    encoding: string;
    contentId: string | null;
    /** Size after transfer decoding, in bytes. */
    size: number;
    children: MimePart[];
    /** Decoded text for text/* parts (capped), null otherwise. */
    text: string | null;
    /** For message/rfc822 attachments: the attached email's own source. */
    message: string | null;
    /** The raw (still encoded) body, for downloading attachments. */
    body: string;
}

const MAX_DEPTH = 12;
const MAX_TEXT = 512 * 1024;

export function parseMime(headers: HeaderField[], body: string, path = '', depth = 0): MimePart {
    const contentType = parseContentType(findHeader(headers, 'content-type')?.value);
    const disposition = findHeader(headers, 'content-disposition');
    const dispositionType = disposition ? parseContentType(disposition.value, 'attachment') : null;
    const encoding = (findHeader(headers, 'content-transfer-encoding')?.value ?? '7bit').trim().toLowerCase();
    const filename = dispositionType?.params.filename ?? contentType.params.name ?? null;

    const part: MimePart = {
        path,
        type: contentType.type,
        params: contentType.params,
        headers,
        disposition: dispositionType?.type ?? null,
        filename,
        encoding,
        contentId: findHeader(headers, 'content-id')?.value.replace(/^<|>$/g, '') ?? null,
        size: 0,
        children: [],
        text: null,
        message: null,
        body,
    };

    if (contentType.type.startsWith('multipart/') && contentType.params.boundary && depth < MAX_DEPTH) {
        part.children = splitMultipart(body, contentType.params.boundary).map((chunk, i) => {
            const inner = splitMessage(chunk, { strict: false });
            return parseMime(inner.headers, inner.hasBody || inner.headers.length ? inner.body : chunk, path ? `${path}.${i + 1}` : `${i + 1}`, depth + 1);
        });
        part.size = part.children.reduce((sum, c) => sum + c.size, 0);
        return part;
    }

    const bytes = decodeTransfer(body, encoding);
    part.size = bytes.length;
    if (contentType.type === 'message/rfc822' || contentType.type === 'message/global') {
        part.message = decodeBytes(bytes, 'utf-8');
    } else if (contentType.type.startsWith('text/') && part.disposition !== 'attachment') {
        part.text = decodeBytes(bytes.length > MAX_TEXT ? bytes.slice(0, MAX_TEXT) : bytes, contentType.params.charset);
    }
    return part;
}

export function decodeTransfer(body: string, encoding: string): Uint8Array {
    if (encoding === 'base64') return decodeBase64(body);
    if (encoding === 'quoted-printable') return decodeQuotedPrintable(body);
    return new TextEncoder().encode(body.replace(/\n$/, ''));
}

function splitMultipart(body: string, boundary: string): string[] {
    const lines = body.split('\n');
    const delimiter = `--${boundary}`;
    const parts: string[] = [];
    let current: string[] | null = null;
    for (const line of lines) {
        const trimmed = line.trimEnd();
        if (trimmed === delimiter || trimmed === `${delimiter}--`) {
            if (current) parts.push(current.join('\n'));
            current = trimmed.endsWith('--') && trimmed !== delimiter ? null : [];
            if (current === null) break;
            continue;
        }
        current?.push(line);
    }
    // A message cut off before its closing boundary still has a last part.
    if (current && current.length) parts.push(current.join('\n'));
    return parts;
}

/** Every leaf part, depth first. */
export function leafParts(part: MimePart): MimePart[] {
    return part.children.length ? part.children.flatMap(leafParts) : [part];
}

export function isAttachment(part: MimePart): boolean {
    return part.disposition === 'attachment' || (!!part.filename && part.disposition !== 'inline') || part.message !== null || (!part.type.startsWith('text/') && !part.type.startsWith('multipart/') && part.disposition !== 'inline' && !part.contentId);
}

// ---------------------------------------------------------------- Links

export interface FoundLink {
    url: string;
    host: string | null;
    /** The link's visible text, for HTML links. */
    text: string | null;
    /** Where a known redirector (Barracuda, Safe Links, Proofpoint, Google…) sends the click, when the URL is one. */
    target: string | null;
    targetHost: string | null;
    /** The visible text names a different site than the link goes to. */
    mismatch: boolean;
}

/** Links in the HTML and plain-text parts, deduplicated. Visible text that names another domain is flagged. */
export function findLinks(root: MimePart): FoundLink[] {
    const links = new Map<string, FoundLink>();
    for (const part of leafParts(root)) {
        if (part.text === null) continue;
        if (part.type === 'text/html') {
            const doc = new DOMParser().parseFromString(part.text, 'text/html');
            for (const a of doc.querySelectorAll('a[href]')) {
                const url = a.getAttribute('href')?.trim() ?? '';
                if (!/^https?:\/\//i.test(url)) continue;
                const text = (a.textContent ?? '').replace(/\s+/g, ' ').trim() || null;
                const host = hostOf(url);
                const target = unwrapLink(url);
                const targetHost = target ? hostOf(target) : null;
                const lands = targetHost ?? host;
                const shown = text ? hostOf(text.startsWith('http') ? text : `https://${text}`) : null;
                const looksLikeUrl = !!text && /^(https?:\/\/)?[\w-]+(\.[\w-]+)+(\/\S*)?$/i.test(text);
                const mismatch = looksLikeUrl && !!shown && !!lands && shown !== lands && !lands.endsWith(`.${shown}`);
                const key = `${url}\n${text}`;
                if (!links.has(key)) links.set(key, { url, host, text, target, targetHost, mismatch });
            }
        } else {
            for (const m of part.text.matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/gi)) {
                const url = m[0].replace(/[.,;:!?]+$/, '');
                if ([...links.values()].some((l) => l.url === url)) continue;
                const target = unwrapLink(url);
                links.set(url, { url, host: hostOf(url), text: null, target, targetHost: target ? hostOf(target) : null, mismatch: false });
            }
        }
    }
    return [...links.values()];
}

/** Query parameters redirectors put the real address in, most specific first. */
const TARGET_PARAMS = ['url', 'u', 'a', 'q', 'target', 'dest', 'destination', 'redirect', 'redirect_url', 'redirect_uri', 'link', 'r'];

/**
 * Where a link-protection or tracking redirect really goes, following nested
 * wrappers (Safe Links around Proofpoint, say). Null when the URL isn't one.
 */
export function unwrapLink(url: string): string | null {
    let current = url;
    for (let depth = 0; depth < 5; depth++) {
        const next = unwrapOnce(current);
        if (!next || next === current) break;
        current = next;
    }
    return current === url ? null : current;
}

function unwrapOnce(url: string): string | null {
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        return null;
    }
    // Proofpoint v3: https://urldefense.com/v3/__https://example.com/__;!!…
    const v3 = /^https?:\/\/[^/]*urldefense\.com\/v3\/__(.+?)__;/i.exec(url);
    if (v3) return v3[1];
    // Proofpoint v2: ?u=https-3A__example.com_path (- for %, _ for /)
    if (parsed.hostname.endsWith('urldefense.proofpoint.com')) {
        const u = parsed.searchParams.get('u');
        if (u) {
            try {
                return decodeURIComponent(u.replace(/-/g, '%').replace(/_/g, '/'));
            } catch {
                return null;
            }
        }
    }
    // Amazon SES click tracking: https://…awstrack.me/L0/https:%2F%2Fexample.com%2F/2/<id>/<signature>
    if (parsed.hostname.endsWith('.awstrack.me')) {
        const segment = /^\/C?L0\/([^/]+)/.exec(parsed.pathname)?.[1];
        if (segment) {
            try {
                const target = decodeURIComponent(segment);
                if (/^https?:\/\/[^/\s]/i.test(target)) return target;
            } catch {
                return null;
            }
        }
    }
    for (const name of TARGET_PARAMS) {
        const value = parsed.searchParams.get(name)?.trim();
        if (value && /^https?:\/\/[^/\s]/i.test(value)) return value;
    }
    return null;
}

function hostOf(url: string): string | null {
    try {
        return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    } catch {
        return null;
    }
}

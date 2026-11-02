import { parseAddressList } from './address';
import type { Analysis } from './analyze';
import { findHeader } from './message';
import { findLinks } from './mime';

// Look-alike text: letters from other alphabets that pass for Latin ones
// ("Ѕtоrаgе" with Cyrillic Ѕ, о, а, е), punycode domains (xn--), "styled"
// Unicode letters (𝐒𝐭𝐨𝐫𝐚𝐠𝐞, Ｓｔｏｒａｇｅ) and invisible characters. Phishing uses
// them to get past filters and to fake brand names and domains.

/** Characters from other scripts that are drawn (nearly) like a Latin letter. */
const CONFUSABLE: Record<string, string> = {
    // Cyrillic
    а: 'a', в: 'b', е: 'e', ё: 'ë', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ї: 'ï', ј: 'j', ѕ: 's', ԁ: 'd', һ: 'h', ӏ: 'l', ԛ: 'q', ԝ: 'w', ү: 'y',
    А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', У: 'Y', Х: 'X', І: 'I', Ј: 'J', Ѕ: 'S', Ԛ: 'Q', Ԝ: 'W', Ү: 'Y', Ӏ: 'I',
    // Greek
    α: 'a', ο: 'o', ν: 'v', ρ: 'p', ι: 'i', κ: 'k', υ: 'u', ϲ: 'c', ϳ: 'j',
    Α: 'A', Β: 'B', Ε: 'E', Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P', Τ: 'T', Υ: 'Y', Χ: 'X', Ϲ: 'C',
    // Latin look-alikes outside basic Latin
    ı: 'i', ɑ: 'a', ɡ: 'g', ʟ: 'L', ᴠ: 'v', ᴡ: 'w', ꓲ: 'I', ℓ: 'l',
};

/** Zero-width, joiner, soft hyphen and text-direction characters: unseen, but they change the text. */
const INVISIBLE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/u;

const SCRIPT_NAMES: [RegExp, string][] = [
    [/\p{Script=Cyrillic}/u, 'Cyrillic'],
    [/\p{Script=Greek}/u, 'Greek'],
    [/\p{Script=Armenian}/u, 'Armenian'],
    [/\p{Script=Cherokee}/u, 'Cherokee'],
    [/\p{Script=Latin}/u, 'Latin'],
];

function scriptOf(char: string): string | null {
    return SCRIPT_NAMES.find(([re]) => re.test(char))?.[1] ?? null;
}

export interface OddChar {
    char: string;
    /** "Cyrillic ѕ (U+0455)" */
    name: string;
    /** The Latin letter it passes for; null for invisible characters. */
    looksLike: string | null;
    kind: 'script' | 'styled' | 'invisible';
}

export interface TextCheck {
    /** Characters to point out, in order (each distinct one once). */
    odd: OddChar[];
    /** The text with look-alikes replaced by the letters they imitate, and invisibles removed. */
    reads: string;
    /** Latin words with letters from another alphabet mixed in. */
    mixed: boolean;
    styled: boolean;
    invisible: boolean;
}

const codePoint = (c: string) => `U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`;

/** Styled letters (mathematical bold, fullwidth, circled…) that compatibility-normalise to plain ASCII. */
function styledAs(char: string): string | null {
    if (char.charCodeAt(0) < 0x80) return null;
    const plain = char.normalize('NFKC');
    return plain !== char && /^[A-Za-z0-9]+$/.test(plain) ? plain : null;
}

/**
 * Finds what makes text look like something it isn't. Ordinary non-Latin text
 * (a Russian or Greek name) isn't flagged: only words mixing alphabets, or
 * words made entirely of look-alikes inside otherwise Latin text.
 */
export function checkText(text: string): TextCheck {
    const odd = new Map<string, OddChar>();
    let mixed = false;
    let styled = false;
    let invisible = false;
    const chars = [...text];
    // Real Cyrillic or Greek text has letters with no Latin twin (д, ж, λ…); look-alike text doesn't.
    const genuinelyForeign = chars.some((c) => /\p{L}/u.test(c) && !CONFUSABLE[c] && (scriptOf(c) === 'Cyrillic' || scriptOf(c) === 'Greek'));
    const hasLatin = chars.some((c) => /[A-Za-z]/.test(c));

    for (const word of text.split(/[\s,.;:!?()[\]"'«»<>@/\\|_-]+/u)) {
        const letters = [...word].filter((c) => /\p{L}/u.test(c));
        if (!letters.length) continue;
        const latin = letters.filter((c) => scriptOf(c) === 'Latin' && !CONFUSABLE[c]);
        const lookalikes = letters.filter((c) => CONFUSABLE[c]);
        const flag = lookalikes.length > 0 && (latin.length > 0 || (!genuinelyForeign && hasLatin && lookalikes.length === letters.length));
        if (!flag) continue;
        mixed = true;
        for (const c of lookalikes) {
            if (!odd.has(c)) odd.set(c, { char: c, name: `${scriptOf(c) ?? 'Non-Latin'} ${c} (${codePoint(c)})`, looksLike: CONFUSABLE[c], kind: 'script' });
        }
    }
    for (const c of chars) {
        const plain = styledAs(c);
        if (plain && /[A-Za-z]/.test(plain)) {
            styled = true;
            if (!odd.has(c)) odd.set(c, { char: c, name: `styled ${plain} (${codePoint(c)})`, looksLike: plain, kind: 'styled' });
        }
        if (INVISIBLE.test(c)) {
            invisible = true;
            if (!odd.has(c)) odd.set(c, { char: c, name: `invisible ${codePoint(c)}`, looksLike: null, kind: 'invisible' });
        }
    }
    const reads = chars.map((c) => (INVISIBLE.test(c) ? '' : odd.get(c)?.looksLike ?? c)).join('');
    return { odd: [...odd.values()], reads, mixed, styled, invisible };
}

// ------------------------------------------------------------- Punycode

const BASE = 36;

/** RFC 3492 decoding of one label's part after "xn--". */
export function decodePunycode(input: string): string | null {
    const output: number[] = [];
    const delimiter = input.lastIndexOf('-');
    for (let j = 0; j < Math.max(delimiter, 0); j++) {
        if (input.charCodeAt(j) >= 0x80) return null;
        output.push(input.charCodeAt(j));
    }
    let n = 128;
    let i = 0;
    let bias = 72;
    for (let index = delimiter > 0 ? delimiter + 1 : 0; index < input.length; ) {
        const oldi = i;
        for (let w = 1, k = BASE; ; k += BASE) {
            if (index >= input.length) return null;
            const c = input.charCodeAt(index++);
            const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : BASE;
            if (digit >= BASE) return null;
            i += digit * w;
            const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
            if (digit < t) break;
            w *= BASE - t;
        }
        const length = output.length + 1;
        let delta = i - oldi;
        delta = oldi === 0 ? Math.floor(delta / 700) : delta >> 1;
        delta += Math.floor(delta / length);
        let k = 0;
        for (; delta > ((BASE - 1) * 26) >> 1; k += BASE) delta = Math.floor(delta / (BASE - 1));
        bias = Math.floor(k + ((BASE - 1 + 1) * delta) / (delta + 38));
        n += Math.floor(i / length);
        i %= length;
        output.splice(i++, 0, n);
    }
    try {
        return String.fromCodePoint(...output);
    } catch {
        return null;
    }
}

/** "xn--pypal-4ve.com" => "раypal.com"; null when the domain has no punycode labels. */
export function decodeDomain(domain: string): string | null {
    const labels = domain.split('.');
    if (!labels.some((l) => /^xn--/i.test(l))) return null;
    const decoded = labels.map((l) => (/^xn--/i.test(l) ? decodePunycode(l.slice(4)) : l));
    return decoded.every((l) => l !== null) ? decoded.join('.') : null;
}

// -------------------------------------------------------------- Findings

export interface LookalikeFinding {
    /** Where it was found: "From name", "Reply-To address", "Link"… */
    where: string;
    /** As written in the message (punycode domains decoded, so the trick is visible). */
    shown: string;
    /** The raw punycode form, when there was one. */
    punycode: string | null;
    check: TextCheck;
    /** One sentence saying what's wrong. */
    text: string;
}

function describe(check: TextCheck, punycode: string | null): string {
    const parts: string[] = [];
    if (check.mixed) {
        const scripts = [...new Set(check.odd.filter((o) => o.kind === 'script').map((o) => o.name.split(' ')[0]))].join(' and ');
        parts.push(`uses ${scripts} letters that look like Latin ones`);
    }
    if (check.styled) parts.push('uses styled Unicode letters instead of plain ones');
    if (check.invisible) parts.push('contains invisible characters');
    if (punycode && !parts.length) parts.push('is an internationalised (punycode) domain with non-Latin characters');
    const reads = check.reads.trim();
    return `${parts.join(', ')}${(check.mixed || check.styled) && reads ? `: it reads as "${reads}" but isn't` : ''}.`;
}

function addText(out: LookalikeFinding[], where: string, text: string | null | undefined) {
    if (!text) return;
    const check = checkText(text);
    if (!check.odd.length) return;
    out.push({ where, shown: text, punycode: null, check, text: `The ${where} ${describe(check, null)}` });
}

function addDomain(out: LookalikeFinding[], where: string, domain: string | null | undefined, address?: string) {
    if (!domain) return;
    const unicode = decodeDomain(domain);
    const shown = unicode ?? domain;
    const check = checkText(shown);
    const nonAscii = [...shown].some((c) => c.charCodeAt(0) >= 0x80);
    if (!check.odd.length && !nonAscii) return;
    const label = address ? address.replace(domain, shown) : shown;
    const text = `The ${where} ${label}${unicode ? ` (written ${domain})` : ''} ${describe(check, unicode ? domain : null)}`;
    out.push({ where, shown: label, punycode: unicode ? domain : null, check, text });
}

/** Look-alike tricks in the sender's names, addresses, subject and links. */
export function findLookalikes(analysis: Analysis): LookalikeFinding[] {
    const headers = analysis.message.headers;
    const out: LookalikeFinding[] = [];
    const mailboxes: [string, string][] = [
        ['From', 'from'],
        ['Reply-To', 'reply-to'],
        ['Sender', 'sender'],
    ];
    for (const [label, key] of mailboxes) {
        const box = parseAddressList(findHeader(headers, key)?.decoded ?? '')[0];
        if (!box) continue;
        addText(out, `${label} display name`, box.name);
        const local = box.address.includes('@') ? box.address.slice(0, box.address.lastIndexOf('@')) : null;
        addText(out, `${label} address`, local);
        addDomain(out, `${label} address`, box.domain, box.address);
    }
    const returnPath = findHeader(headers, 'return-path')?.value.replace(/^<|>$/g, '').trim();
    if (returnPath?.includes('@')) addDomain(out, 'envelope sender', returnPath.slice(returnPath.lastIndexOf('@') + 1), returnPath);
    addText(out, 'subject', analysis.subject);

    // Links need the HTML parser, so only in the browser.
    if (analysis.mime && typeof DOMParser !== 'undefined') {
        const seen = new Set<string>();
        for (const link of findLinks(analysis.mime)) {
            if (!link.host || seen.has(link.host)) continue;
            seen.add(link.host);
            addDomain(out, 'link to', link.host);
        }
    }
    // The same text in two places (From and Reply-To names) is one finding.
    const merged: LookalikeFinding[] = [];
    for (const f of out) {
        const same = merged.find((m) => m.shown === f.shown);
        if (same) {
            same.where = `${same.where} and ${f.where}`;
            same.text = `${same.text} The ${f.where} is the same.`;
        } else merged.push({ ...f });
    }
    return merged;
}

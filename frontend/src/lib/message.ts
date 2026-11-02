import { decodeEncodedWords } from './encoding';

export interface HeaderField {
    /** Position in the message, 0 = top (the most recently added). */
    index: number;
    /** As written, e.g. "X-SES-Outgoing". */
    name: string;
    /** Lower case, for lookups. */
    key: string;
    /** As written, including folding (line breaks + indentation). */
    raw: string;
    /** Unfolded onto one line. */
    value: string;
    /** Unfolded, with RFC 2047 encoded words decoded. */
    decoded: string;
}

export interface RawMessage {
    headers: HeaderField[];
    body: string;
    /** Whether a blank line separated headers from a body (false for headers-only pastes). */
    hasBody: boolean;
    warnings: string[];
}

export class NotAnEmailError extends Error {}

const FIELD = /^([!-9;-~]+)[ \t]*:[ \t]?(.*)$/;

/**
 * Splits a message into header fields and body, unfolding continuation lines.
 * Tolerates what people actually paste: CRLF or LF, a leading mbox "From " line,
 * Outlook's headers-only copy (no body), and blank lines before the headers.
 */
export function splitMessage(input: string, { strict = true } = {}): RawMessage {
    const text = input.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
    const lines = text.split('\n');
    const warnings: string[] = [];
    let i = 0;

    // A MIME part (strict = false) that starts with a blank line has no headers.
    if (strict) while (i < lines.length && lines[i].trim() === '') i++;
    if (/^From \S+/.test(lines[i] ?? '') && !FIELD.test(lines[i])) i++;

    type Draft = { name: string; lines: string[] };
    const drafts: Draft[] = [];
    let hasBody = false;
    for (; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') {
            hasBody = true;
            i++;
            break;
        }
        const current = drafts[drafts.length - 1];
        if (/^[ \t]/.test(line) && current) {
            current.lines.push(line);
            continue;
        }
        const match = FIELD.exec(line);
        if (match) {
            drafts.push({ name: match[1], lines: [line] });
        } else if (current) {
            // Usually a folded line whose indentation was lost when copying.
            warnings.push(`Line ${i + 1} isn't a header or an indented continuation; treated it as part of ${current.name}.`);
            current.lines.push(' ' + line);
        } else if (strict) {
            throw new NotAnEmailError(`This doesn't look like an email: line ${i + 1} should be a header such as "Received: …".`);
        } else {
            break;
        }
    }

    if (strict && drafts.length === 0) {
        throw new NotAnEmailError('No headers found. Paste the full message source ("Show original" / "View source"), not just the text.');
    }

    const headers = drafts.map((draft, index): HeaderField => {
        const raw = draft.lines.join('\n');
        const value = unfold(raw.slice(raw.indexOf(':') + 1));
        return { index, name: draft.name, key: draft.name.toLowerCase(), raw, value, decoded: decodeEncodedWords(value) };
    });

    const body = lines.slice(i).join('\n');
    return { headers, body, hasBody: hasBody && body.trim() !== '', warnings };
}

/** Joins folded lines with a single space and trims. */
export function unfold(value: string): string {
    return value.replace(/\n[ \t]+/g, ' ').replace(/\n/g, ' ').trim();
}

export function findHeader(headers: HeaderField[], key: string): HeaderField | undefined {
    return headers.find((h) => h.key === key);
}

export function findHeaders(headers: HeaderField[], key: string): HeaderField[] {
    return headers.filter((h) => h.key === key);
}

/**
 * Splits on a separator outside quotes, comments and angle brackets.
 * Used for address lists (",") and Authentication-Results (";").
 */
export function splitTopLevel(value: string, separator: string): string[] {
    const out: string[] = [];
    let depth = 0;
    let quoted = false;
    let angle = false;
    let start = 0;
    for (let i = 0; i < value.length; i++) {
        const c = value[i];
        if (c === '\\') {
            i++;
        } else if (quoted) {
            if (c === '"') quoted = false;
        } else if (c === '"') {
            quoted = true;
        } else if (c === '(') {
            depth++;
        } else if (c === ')') {
            depth = Math.max(0, depth - 1);
        } else if (depth === 0 && c === '<') {
            angle = true;
        } else if (depth === 0 && c === '>') {
            angle = false;
        } else if (depth === 0 && !angle && c === separator) {
            out.push(value.slice(start, i));
            start = i + 1;
        }
    }
    out.push(value.slice(start));
    return out;
}

/** Removes RFC 5322 comments: "a (note (nested)) b" => "a  b". Returns the comments too. */
export function stripComments(value: string): { text: string; comments: string[] } {
    const comments: string[] = [];
    let text = '';
    let depth = 0;
    let quoted = false;
    let comment = '';
    for (let i = 0; i < value.length; i++) {
        const c = value[i];
        if (depth === 0 && c === '"') quoted = !quoted;
        if (!quoted && c === '(') {
            if (depth > 0) comment += c;
            depth++;
            continue;
        }
        if (!quoted && c === ')' && depth > 0) {
            depth--;
            if (depth === 0) {
                comments.push(comment.trim());
                comment = '';
            } else {
                comment += c;
            }
            continue;
        }
        if (depth > 0) comment += c;
        else text += c;
    }
    if (comment) comments.push(comment.trim());
    return { text, comments };
}

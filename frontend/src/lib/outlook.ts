// Outlook .msg files keep the internet headers as they arrived, but the body
// and attachments in Outlook's own properties. This puts them back together
// as a MIME message the rest of the analyzer can read.
import type { FieldsData } from '@kenjiuno/msgreader';
import { codepageCharset, decodeBytes, encodeBase64 } from './encoding';
import { htmlFromRtf } from './rtf';

/** An opened .msg file. Kept apart from msgreader so this can be tested without one. */
export interface MsgSource {
    fields: FieldsData;
    /** An attachment's bytes; for an attached Outlook item, that item as its own .msg. */
    content(attachment: FieldsData): Uint8Array;
    open(bytes: Uint8Array): MsgSource;
    /** Decompressed RTF, one character per byte. */
    rtf(compressed: Uint8Array): string;
}

export interface RebuiltMessage {
    source: string;
    /** Names of the attachments that were included. */
    attachments: string[];
    /** Names of attachments Outlook keeps in a form that can't be extracted (OLE objects, links). */
    skipped: string[];
}

interface Entity {
    headers: string[];
    body: string;
}

const MAX_DEPTH = 5;

/** Header fields describing the original body, which is being replaced. */
const BODY_HEADERS = new Set(['content-type', 'content-transfer-encoding', 'content-disposition']);

const TYPES: Record<string, string> = {
    pdf: 'application/pdf',
    zip: 'application/zip',
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    gif: 'image/gif',
    webp: 'image/webp',
    svg: 'image/svg+xml',
    bmp: 'image/bmp',
    txt: 'text/plain',
    csv: 'text/csv',
    htm: 'text/html',
    html: 'text/html',
    ics: 'text/calendar',
    eml: 'message/rfc822',
    msg: 'application/vnd.ms-outlook',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

export function msgToEml(msg: MsgSource): RebuiltMessage {
    const result: RebuiltMessage = { source: '', attachments: [], skipped: [] };
    result.source = build(msg, { boundaries: 0, result }, 0);
    return result;
}

interface Context {
    boundaries: number;
    result: RebuiltMessage;
}

function build(msg: MsgSource, context: Context, depth: number): string {
    const { fields } = msg;
    const headers = fields.headers?.trim() ? originalHeaders(fields.headers) : outlookHeaders(fields);
    const entity = bodyOf(msg, context, depth);
    if (!headers.some((h) => /^mime-version:/i.test(h))) headers.push('MIME-Version: 1.0');
    return `${[...headers, ...entity.headers].join('\n')}\n\n${entity.body}`;
}

/** The internet headers as received, minus those describing the body that's being rebuilt. */
function originalHeaders(text: string): string[] {
    const fields: string[] = [];
    let keep = true;
    for (const line of text.replace(/\r\n?/g, '\n').replace(/\n+$/, '').split('\n')) {
        if (/^[ \t]/.test(line)) {
            if (keep && fields.length) fields[fields.length - 1] += `\n${line}`;
            continue;
        }
        keep = !BODY_HEADERS.has(line.slice(0, line.indexOf(':')).trim().toLowerCase());
        if (keep) fields.push(line);
    }
    return fields;
}

/** Headers made up from Outlook's own fields, for items that never had internet headers (drafts, internal mail). */
function outlookHeaders(fields: FieldsData): string[] {
    const address = (name: string | undefined, email: string | undefined) => {
        if (!email) return name?.includes('@') ? `<${name}>` : null;
        return name && name !== email ? `"${name.replace(/["\\]/g, '')}" <${email}>` : `<${email}>`;
    };
    const recipients = (type: 'to' | 'cc') =>
        (fields.recipients ?? [])
            .filter((r) => (r.recipType ?? 'to') === type)
            .map((r) => address(r.name, r.smtpAddress ?? r.email))
            .filter(Boolean)
            .join(', ');
    const headers: string[] = [];
    const from = address(fields.senderName, fields.senderSmtpAddress ?? fields.senderEmail);
    if (from) headers.push(`From: ${from}`);
    const to = recipients('to');
    if (to) headers.push(`To: ${to}`);
    const cc = recipients('cc');
    if (cc) headers.push(`Cc: ${cc}`);
    if (fields.subject) headers.push(`Subject: ${fields.subject}`);
    const date = fields.clientSubmitTime ?? fields.messageDeliveryTime ?? fields.creationTime;
    if (date) headers.push(`Date: ${date}`);
    if (fields.messageId) headers.push(`Message-ID: ${fields.messageId}`);
    return headers;
}

function bodyOf(msg: MsgSource, context: Context, depth: number): Entity {
    const { fields } = msg;
    const text = fields.body ? textPart('text/plain', fields.body) : null;
    const htmlSource = htmlOf(msg);
    const html = htmlSource ? textPart('text/html', htmlSource) : null;
    let body: Entity | null = text && html ? multipart('alternative', [text, html], context) : (html ?? text);

    const inline: Entity[] = [];
    const attached: Entity[] = [];
    for (const attachment of fields.attachments ?? []) {
        const cid = attachment.pidContentId;
        const isInline = !!cid && !!htmlSource?.includes(`cid:${cid}`);
        const part = attachmentPart(msg, attachment, isInline, context, depth);
        if (part) (isInline ? inline : attached).push(part);
    }
    if (inline.length) body = multipart('related', [body ?? textPart('text/plain', ''), ...inline], context);
    if (attached.length) body = multipart('mixed', [body ?? textPart('text/plain', ''), ...attached], context);
    return body ?? textPart('text/plain', '');
}

/** The HTML body: stored as HTML when Outlook kept it, otherwise unwrapped from the RTF body. */
function htmlOf(msg: MsgSource): string | null {
    const { fields } = msg;
    if (fields.html?.length) return decodeBytes(fields.html, codepageCharset(fields.internetCodepage));
    if (fields.bodyHtml) return fields.bodyHtml;
    if (fields.compressedRtf?.length) {
        try {
            return htmlFromRtf(msg.rtf(fields.compressedRtf));
        } catch {
            return null;
        }
    }
    return null;
}

function attachmentPart(msg: MsgSource, attachment: FieldsData, inline: boolean, context: Context, depth: number): Entity | null {
    const name = attachment.fileName ?? attachment.fileNameShort ?? attachment.name ?? 'attachment';
    let bytes: Uint8Array;
    try {
        bytes = msg.content(attachment);
    } catch {
        if (depth === 0) context.result.skipped.push(name);
        return null;
    }
    if (depth === 0) context.result.attachments.push(attachment.innerMsgContent ? `${name}.msg` : name);

    if (attachment.innerMsgContent && depth < MAX_DEPTH) {
        try {
            return {
                headers: ['Content-Type: message/rfc822', 'Content-Transfer-Encoding: 8bit', `Content-Disposition: attachment; ${param('filename', `${name}.eml`)}`],
                body: build(msg.open(bytes), context, depth + 1),
            };
        } catch {
            // An attached item msgreader can't open: offer it as the .msg it is.
        }
    }

    const filename = attachment.innerMsgContent ? `${name}.msg` : name;
    const type = attachment.attachMimeTag?.trim() || TYPES[filename.split('.').pop()?.toLowerCase() ?? ''] || 'application/octet-stream';
    const headers = [`Content-Type: ${type}; ${param('name', filename)}`, 'Content-Transfer-Encoding: base64', `Content-Disposition: ${inline ? 'inline' : 'attachment'}; ${param('filename', filename)}`];
    if (attachment.pidContentId) headers.push(`Content-ID: <${attachment.pidContentId}>`);
    return { headers, body: encodeBase64(bytes) };
}

function textPart(type: string, text: string): Entity {
    return {
        headers: [`Content-Type: ${type}; charset=utf-8`, 'Content-Transfer-Encoding: 8bit'],
        body: text.replace(/\r\n?/g, '\n'),
    };
}

function multipart(subtype: string, parts: Entity[], context: Context): Entity {
    let boundary = `=_outlook_${++context.boundaries}`;
    while (parts.some((p) => p.body.includes(boundary))) boundary += '_';
    const body = parts.map((p) => `--${boundary}\n${p.headers.join('\n')}\n\n${p.body}\n`).join('') + `--${boundary}--`;
    return { headers: [`Content-Type: multipart/${subtype}; boundary="${boundary}"`], body };
}

/** name="value", or RFC 2231's name*=utf-8''value when it isn't plain ASCII. */
function param(key: string, value: string): string {
    if (/^[\x20-\x7e]*$/.test(value) && !/["\\]/.test(value)) return `${key}="${value}"`;
    return `${key}*=utf-8''${encodeURIComponent(value).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)}`;
}

import { decodeFile } from './encoding';
import type { MsgSource } from './outlook';

export interface LoadedEmail {
    source: string;
    /** Something the reader should know about what was loaded. */
    note: string | null;
    /** The body was put back together (from an Outlook .msg), so it isn't byte for byte what the sender signed. */
    bodyRebuilt?: boolean;
}

/** Outlook .msg files are OLE compound documents: they start with D0 CF 11 E0. */
function isOle(bytes: Uint8Array): boolean {
    return bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0;
}

/**
 * Reads a dropped or chosen file: .eml/.txt/.mbox as text, Outlook .msg via
 * msgreader (loaded only when needed). Nothing is uploaded.
 */
export async function readEmailFile(file: File): Promise<LoadedEmail> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (/\.msg$/i.test(file.name) || isOle(bytes)) return readMsg(bytes);
    return { source: decodeFile(bytes), note: null };
}

async function readMsg(bytes: Uint8Array): Promise<LoadedEmail> {
    const [msgreader, { decompressRTF }, { msgToEml }] = await Promise.all([
        import('@kenjiuno/msgreader'),
        import('@kenjiuno/decompressrtf'),
        import('./outlook'),
    ]);
    // msgreader is CommonJS. Vite's dev server and Vitest hand over its class as
    // `default`; the production build hands over the whole exports object, so the
    // class is at `default.default` there.
    const MsgReader = (msgreader.default as unknown as { default?: typeof msgreader.default }).default ?? msgreader.default;
    const open = (data: Uint8Array): MsgSource => {
        const reader = new MsgReader(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer);
        return {
            fields: reader.getFileData(),
            content: (attachment) => reader.getAttachment(attachment).content,
            open,
            rtf: (compressed) => latin1(decompressRTF(Array.from(compressed))),
        };
    };
    const msg = open(bytes);
    if (msg.fields.error) throw new Error(`Couldn't read this Outlook file: ${msg.fields.error}`);
    if (!msg.fields.headers?.trim()) {
        throw new Error(
            "This Outlook file has no internet headers. That happens with drafts, messages that never left Exchange, and some saved copies. In Outlook, open the message and use File › Properties › Internet headers, then paste those here.",
        );
    }
    const rebuilt = msgToEml(msg);
    const skipped = rebuilt.skipped.length ? ` ${rebuilt.skipped.join(', ')} couldn't be extracted.` : '';
    return {
        source: rebuilt.source,
        note: `Outlook .msg file: the headers are as received, but Outlook stores the body in its own format, so the content and attachments were rebuilt from it. DKIM body hashes can't be checked against a rebuilt body.${skipped}`,
        bodyRebuilt: true,
    };
}

/** One character per byte, in chunks small enough to pass as arguments. */
function latin1(bytes: number[]): string {
    let text = '';
    for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.slice(i, i + 0x8000));
    return text;
}

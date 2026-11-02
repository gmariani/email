import { decodeFile } from './encoding';

export interface LoadedEmail {
    source: string;
    /** Something the reader should know about what was loaded. */
    note: string | null;
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
    const { default: MsgReader } = await import('@kenjiuno/msgreader');
    const data = new MsgReader(bytes.buffer as ArrayBuffer).getFileData();
    if (data.error) throw new Error(`Couldn't read this Outlook file: ${data.error}`);
    if (!data.headers?.trim()) {
        throw new Error(
            "This Outlook file has no internet headers. That happens with drafts, messages that never left Exchange, and some saved copies. In Outlook, open the message and use File › Properties › Internet headers, then paste those here.",
        );
    }
    const attachments = (data.attachments ?? []).map((a) => a.fileName ?? a.name).filter(Boolean);
    // Outlook keeps the body and attachments in its own format, so analyse the headers alone.
    const headers = data.headers.replace(/\r\n/g, '\n').replace(/\n+$/, '');
    return {
        source: headers,
        note: `Outlook .msg file: only its internet headers were analysed (Outlook stores the body in its own format).${attachments.length ? ` Attachments: ${attachments.join(', ')}.` : ''}`,
    };
}

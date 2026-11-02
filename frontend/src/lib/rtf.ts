// Outlook keeps an HTML email's body as RTF that wraps the original HTML
// ("encapsulated" HTML, MS-OXRTFEX). This unwraps it again.
import { codepageCharset, decodeBytes } from './encoding';

/** Groups that hold RTF bookkeeping rather than text. */
const SKIPPED = new Set(['fonttbl', 'colortbl', 'stylesheet', 'info', 'pict', 'object', 'header', 'footer', 'listtable', 'listoverridetable', 'rsidtbl', 'generator']);

/** Control words that stand for a character. */
const CHARACTERS: Record<string, string> = {
    par: '\r\n',
    line: '\r\n',
    tab: '\t',
    lquote: '‘',
    rquote: '’',
    ldblquote: '“',
    rdblquote: '”',
    bullet: '•',
    endash: '–',
    emdash: '—',
    emspace: ' ',
    enspace: ' ',
    qmspace: ' ',
};

interface Group {
    /** Nothing in this group is output. */
    skip: boolean;
    /** Inside \htmlrtf … \htmlrtf0: RTF-only formatting, not part of the HTML. */
    htmlrtf: boolean;
    /** Inside {\*\htmltag …}: original HTML markup. */
    tag: boolean;
    /** Characters to drop after \uN (\ucN). */
    uc: number;
}

/**
 * The HTML that an Outlook RTF body was made from, or null when the RTF
 * didn't come from HTML (no \fromhtml1). The input is the decompressed RTF,
 * one character per byte.
 */
export function htmlFromRtf(rtf: string): string | null {
    if (!/^\{\\rtf1[^{]*?\\fromhtml1/.test(rtf.slice(0, 512))) return null;
    const charset = codepageCharset(Number(/\\ansicpg(\d+)/.exec(rtf.slice(0, 512))?.[1]) || 1252);

    let out = '';
    let bytes: number[] = [];
    const flush = () => {
        if (bytes.length) out += decodeBytes(Uint8Array.from(bytes), charset);
        bytes = [];
    };
    const stack: Group[] = [];
    let group: Group = { skip: false, htmlrtf: false, tag: false, uc: 1 };
    /** Characters still to drop after a \uN. */
    let pendingSkip = 0;
    /** The next control word decides whether a just-opened group is skipped. */
    let groupStart = false;
    let ignorable = false;

    const visible = () => !group.skip && (group.tag || !group.htmlrtf);
    const emit = (text: string) => {
        if (pendingSkip > 0) {
            pendingSkip--;
            return;
        }
        if (!visible()) return;
        flush();
        out += text;
    };

    for (let i = 0; i < rtf.length; i++) {
        const c = rtf[i];
        if (c === '{') {
            stack.push(group);
            group = { ...group };
            groupStart = true;
            ignorable = false;
            pendingSkip = 0;
            continue;
        }
        if (c === '}') {
            group = stack.pop() ?? group;
            groupStart = false;
            pendingSkip = 0;
            continue;
        }
        if (c === '\r' || c === '\n') continue;
        if (c !== '\\') {
            groupStart = false;
            emit(c);
            continue;
        }

        const next = rtf[i + 1];
        if (next === '*') {
            ignorable = groupStart;
            i++;
            continue;
        }
        if (next === "'") {
            const hex = rtf.slice(i + 2, i + 4);
            i += 3;
            if (pendingSkip > 0) pendingSkip--;
            else if (visible() && /^[0-9a-f]{2}$/i.test(hex)) bytes.push(parseInt(hex, 16));
            continue;
        }
        if (next === undefined || !/[a-z]/i.test(next)) {
            // Control symbols: \{ \} \\ \~ (no-break space) \_ (non-breaking hyphen) \- (optional hyphen).
            i++;
            groupStart = false;
            if (next === '~') emit(' ');
            else if (next === '_') emit('‑');
            else if (next !== '-' && next !== undefined) emit(next);
            continue;
        }

        const m = /^\\([a-z]+)(-?\d+)? ?/i.exec(rtf.slice(i, i + 64));
        if (!m) continue;
        i += m[0].length - 1;
        const [, word, param] = m;
        const wasStart = groupStart;
        groupStart = false;

        if (wasStart && (ignorable || SKIPPED.has(word))) {
            // {\*\htmltag …} carries HTML; every other ignorable destination is skipped.
            if (word === 'htmltag' && !group.skip) group.tag = true;
            else group.skip = true;
            ignorable = false;
            continue;
        }
        if (word === 'htmlrtf') group.htmlrtf = param !== '0';
        else if (word === 'uc') group.uc = Number(param ?? 1);
        else if (word === 'u') {
            const code = Number(param ?? 0);
            emit(String.fromCharCode(code < 0 ? code + 65536 : code));
            pendingSkip = group.uc;
        } else if (word in CHARACTERS) emit(CHARACTERS[word]);
    }
    flush();
    return out;
}

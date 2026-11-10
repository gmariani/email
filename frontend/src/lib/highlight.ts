/**
 * A small HTML tokenizer for syntax highlighting. It never builds DOM from
 * the input: the caller renders each token as text inside a styled span.
 */
export type HtmlTokenKind = 'text' | 'comment' | 'doctype' | 'punct' | 'tag' | 'attr' | 'value' | 'entity';

export interface HtmlToken {
    kind: HtmlTokenKind;
    text: string;
}

// One piece of the source at a time: comment, <!doctype>/<?xml?>, tag, entity, or plain text.
const PIECE = /<!--[\s\S]*?(?:-->|$)|<[!?][^>]*>?|<\/?[A-Za-z][^\s/>]*(?:[^>"']|"[^"]*"|'[^']*')*>?|&(?:#\d+|#x[0-9a-f]+|[a-z][a-z0-9]*);|[^<&]+|[\s\S]/giy;

// Inside a tag, after its name: whitespace, attribute (with optional value), closing bracket, or anything else.
const ATTR = /(\s+)|([^\s=/>"']+)(?:(\s*=\s*)("[^"]*"|'[^']*'|[^\s>]+))?|(\/?>)|([\s\S])/gy;

export function tokenizeHtml(source: string): HtmlToken[] {
    const tokens: HtmlToken[] = [];
    const push = (kind: HtmlTokenKind, text: string) => {
        const last = tokens[tokens.length - 1];
        if (last && last.kind === kind) last.text += text;
        else tokens.push({ kind, text });
    };
    PIECE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PIECE.exec(source))) {
        const piece = m[0];
        if (piece.startsWith('<!--')) push('comment', piece);
        else if (piece.startsWith('<!') || piece.startsWith('<?')) push('doctype', piece);
        else if (piece.length > 1 && piece[0] === '<') tag(piece, push);
        else if (piece.length > 1 && piece[0] === '&') push('entity', piece);
        else push('text', piece);
    }
    return tokens;
}

function tag(piece: string, push: (kind: HtmlTokenKind, text: string) => void) {
    const open = piece[1] === '/' ? '</' : '<';
    const name = /^[^\s/>]*/.exec(piece.slice(open.length))![0];
    push('punct', open);
    push('tag', name);
    ATTR.lastIndex = open.length + name.length;
    let m: RegExpExecArray | null;
    while (ATTR.lastIndex < piece.length && (m = ATTR.exec(piece))) {
        const [, space, attr, eq, value, close, other] = m;
        if (space) push('text', space);
        else if (attr) {
            push('attr', attr);
            if (eq) push('punct', eq);
            if (value) push('value', value);
        } else if (close) push('punct', close);
        else if (other) push('punct', other);
    }
}

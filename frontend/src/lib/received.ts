import { parseDate, type ParsedDate } from './date';
import { ipScope, isIp, isIPv4, isIPv6, normalizeIp, type IpScope } from './ip';

/**
 * One Received header (RFC 5321 §4.4), which a server adds when it accepts a message:
 *
 *   from <helo> (<rdns> [<ip>]) by <server> via <link> with <protocol> id <queue id> for <recipient>; <date>
 *
 * Every mail server writes it slightly differently (and puts TLS details in
 * comments), so this reads the keyword clauses in any order and then mines
 * the comments for addresses, TLS versions, ciphers and server software.
 */
export interface Received {
    from: {
        /** Name the sending server announced (HELO/EHLO), or the verified name some servers print first. */
        name: string | null;
        /** Name the receiving server found by reverse DNS, when it shows one. */
        rdns: string | null;
        helo: string | null;
        ip: string | null;
        port: number | null;
        /** The receiver noted the reverse DNS didn't match ("may be forged"). */
        mayBeForged: boolean;
        /** The receiver says the IP has no reverse DNS ("unknown"). */
        noRdns: boolean;
    } | null;
    by: { name: string | null; ip: string | null } | null;
    via: string | null;
    protocol: string | null;
    id: string | null;
    for: string | null;
    envelopeFrom: string | null;
    software: string | null;
    tls: TlsInfo | null;
    /** Who logged in to send (SMTP AUTH), or "yes" when only the protocol says so. */
    authenticated: string | null;
    date: ParsedDate | null;
    dateText: string | null;
    comments: string[];
}

export interface TlsInfo {
    version: string | null;
    cipher: string | null;
    bits: string | null;
    /** Sendmail's client-certificate check: OK, NO, NONE, FAIL… */
    verify: string | null;
    note: string | null;
}

export type Security = 'encrypted' | 'unencrypted' | 'local' | 'internal' | 'unknown';

type Token = { kind: 'word'; text: string } | { kind: 'comment'; text: string } | { kind: 'angle'; text: string };

const KEYWORDS = new Set(['from', 'by', 'via', 'with', 'id', 'for']);

export function parseReceived(value: string): Received {
    const { clauses: text, date: dateText } = splitDate(value);
    const tokens = tokenize(text);

    const clauses: Record<string, Token[]> = {};
    const comments: string[] = [];
    let current = 'pre';
    for (const token of tokens) {
        if (token.kind === 'comment') comments.push(token.text);
        if (token.kind === 'word' && KEYWORDS.has(token.text.toLowerCase())) {
            current = token.text.toLowerCase();
            clauses[current] ??= [];
            continue;
        }
        (clauses[current] ??= []).push(token);
    }

    const words = (key: string) => (clauses[key] ?? []).filter((t) => t.kind === 'word').map((t) => t.text);
    const notes = (key: string) => (clauses[key] ?? []).filter((t) => t.kind !== 'word').map((t) => t.text);

    const withWords = words('with');
    let protocol = withWords[0] ?? null;
    let withExtra = withWords.slice(1);
    if (/^microsoft$/i.test(protocol ?? '') && /^smtp$/i.test(withWords[1] ?? '')) {
        protocol = 'Microsoft SMTP Server';
        withExtra = withWords.slice(3);
    } else if (/^microsoft$/i.test(protocol ?? '') && /^smtpsvc/i.test(withWords[1] ?? '')) {
        // IIS: "with Microsoft SMTPSVC(7.5.7601.17514)"
        protocol = 'Microsoft SMTPSVC';
        withExtra = withWords.slice(2);
    }

    const all = comments.join(' ; ');
    const received: Received = {
        from: clauses.from ? parseFrom(words('from'), notes('from')) : fromComments(clauses.pre ?? []),
        by: clauses.by ? parseBy(words('by'), notes('by')) : null,
        via: words('via').join(' ') || null,
        protocol,
        id: words('id')[0] ?? null,
        for: angleOrWord(clauses.for ?? []),
        envelopeFrom: /envelope-from\s*<?([^\s<>)]*)>?/i.exec(all)?.[1] || null,
        software: detectSoftware(comments, protocol, words('by')[0] ?? null, text),
        tls: detectTls(comments, protocol, withExtra),
        authenticated: detectAuth(all, protocol),
        date: parseDate(dateText),
        dateText,
        comments,
    };
    return received;
}

/** The date follows the last ";" outside comments. */
function splitDate(value: string): { clauses: string; date: string | null } {
    let depth = 0;
    let at = -1;
    for (let i = 0; i < value.length; i++) {
        const c = value[i];
        if (c === '(') depth++;
        else if (c === ')') depth = Math.max(0, depth - 1);
        else if (c === ';' && depth === 0) at = i;
    }
    if (at < 0) return { clauses: value, date: null };
    return { clauses: value.slice(0, at), date: value.slice(at + 1).trim() || null };
}

function tokenize(text: string): Token[] {
    const tokens: Token[] = [];
    let i = 0;
    while (i < text.length) {
        const c = text[i];
        if (/\s/.test(c)) {
            i++;
        } else if (c === '(') {
            let depth = 0;
            let j = i;
            for (; j < text.length; j++) {
                if (text[j] === '(') depth++;
                else if (text[j] === ')' && --depth === 0) break;
            }
            tokens.push({ kind: 'comment', text: text.slice(i + 1, j).trim() });
            i = j + 1;
        } else if (c === '<') {
            const end = text.indexOf('>', i);
            const j = end < 0 ? text.length : end;
            tokens.push({ kind: 'angle', text: text.slice(i + 1, j) });
            i = j + 1;
        } else {
            let j = i;
            while (j < text.length && !/[\s(<]/.test(text[j])) j++;
            tokens.push({ kind: 'word', text: text.slice(i, j) });
            i = j;
        }
    }
    return tokens;
}

function angleOrWord(tokens: Token[]): string | null {
    const angle = tokens.find((t) => t.kind === 'angle');
    if (angle) return angle.text || null;
    const word = tokens.find((t) => t.kind === 'word');
    return word ? word.text.replace(/^<|>;?$/g, '') : null;
}

const HOST = /^(?=.{1,253}\.?$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_-]{1,63})*\.?$/;

/** An IP address written as "[1.2.3.4]", "[IPv6:2001:db8::1]", "1.2.3.4" or bare IPv6. */
export function extractIp(text: string): string | null {
    for (const m of text.matchAll(/\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]/gi)) {
        if (isIp(m[1])) return normalizeIp(m[1]);
    }
    for (const raw of text.split(/[\s,;()=]+/)) {
        const word = raw.replace(/^\[|\]$/g, '').replace(/^IPv6:/i, '');
        const v4 = /^(\d+\.\d+\.\d+\.\d+)(?::\d+)?$/.exec(word);
        if (v4 && isIPv4(v4[1])) return v4[1];
        if (isIPv6(word) && word.split(':').length > 2) return normalizeIp(word);
    }
    return null;
}

function parseFrom(words: string[], comments: string[]): NonNullable<Received['from']> {
    // IIS/Exchange: "from mail pickup service by …" (a file dropped in the pickup folder).
    const name = /pickup service/i.test(words.join(' ')) ? words.join(' ') : (words[0] ?? null);
    const joined = comments.join(' ');
    const helo = /\b(?:helo|ehlo)[= ]([^\s)\]]+)/i.exec(joined)?.[1] ?? null;
    const ip = extractIp(joined) ?? (name ? extractIp(name) : null);

    // "(mail.example.com [192.0.2.1])", "(mail.example.com. [192.0.2.1])", "(unknown [192.0.2.1])"
    let rdns: string | null = null;
    let noRdns = false;
    for (const comment of comments) {
        const m = /^([^\s[\]()]+?)\.?\s+\[/.exec(comment);
        if (m) {
            if (m[1].toLowerCase() === 'unknown') noRdns = true;
            else if (HOST.test(m[1]) && !isIp(m[1])) rdns = m[1].toLowerCase();
        }
    }

    const port = /\]:(\d{1,5})\b/.exec(joined) ?? /\bport[= ](\d{1,5})\b/i.exec(joined);
    return {
        name: name ? name.replace(/^\[|\]$/g, '') : null,
        rdns,
        helo,
        ip,
        port: port ? parseInt(port[1], 10) : null,
        mayBeForged: /may be forged/i.test(joined),
        noRdns,
    };
}

/** Sendmail's "(from user@localhost)" and qmail's "(qmail 123 invoked from network)" have no from clause. */
function fromComments(tokens: Token[]): Received['from'] {
    for (const token of tokens) {
        const m = /^from\s+(\S+)/i.exec(token.text);
        if (token.kind === 'comment' && m) {
            return { name: m[1], rdns: null, helo: null, ip: extractIp(token.text), port: null, mayBeForged: false, noRdns: false };
        }
    }
    return null;
}

function parseBy(words: string[], comments: string[]): NonNullable<Received['by']> {
    const name = words[0] ?? null;
    return { name: name ? name.replace(/^\[|\]$/g, '') : null, ip: extractIp(comments.join(' ')) ?? (name ? extractIp(name) : null) };
}

const SOFTWARE: [RegExp, string | ((m: RegExpExecArray) => string)][] = [
    [/\bExim\s+([\d.]+(?:_\d+)?)/i, (m) => `Exim ${m[1]}`],
    [/\bPostfix\b/i, 'Postfix'],
    [/^(\d+\.\d+\.\d+)(?:\/\d+\.\d+\.\d+)?(?:\/[\w-]+)?$/, (m) => `Sendmail ${m[1]}`],
    [/\bSendmail\b/i, 'Sendmail'],
    [/\bqmail\b/i, 'qmail'],
    [/\bOpenSMTPD\b/i, 'OpenSMTPD'],
    [/\bHaraka(?:\/([\d.]+))?/i, (m) => `Haraka${m[1] ? ' ' + m[1] : ''}`],
    [/\bPowerMTA(?:\(TM\))?\s*(v[\w.]+)?/i, (m) => `PowerMTA${m[1] ? ' ' + m[1] : ''}`],
    [/\bMDaemon\b[^;)]*/i, (m) => m[0].trim()],
    [/\bIceWarp\b[^;)]*/i, (m) => m[0].trim()],
    [/\bZimbra\b/i, 'Zimbra'],
    [/\bCommuniGate Pro\b[^;)]*/i, (m) => m[0].trim()],
    [/\bKerio Connect\b[^;)]*/i, (m) => m[0].trim()],
    [/\bhMailServer\b/i, 'hMailServer'],
    [/\bSmarterMail\b[^;)]*/i, (m) => m[0].trim()],
    [/\bAxigen\b/i, 'Axigen'],
    [/\bCourier\b[^;)]*/i, (m) => m[0].trim()],
    [/\bDovecot\b/i, 'Dovecot'],
    [/\bCyrus\b/i, 'Cyrus IMAP'],
    [/\bHalon\b/i, 'Halon'],
    [/\bCoremail\b/i, 'Coremail'],
    [/\bmsmtp\b/i, 'msmtp'],
    [/\bGreenMail\b/i, 'GreenMail'],
    [/\bOpenWave\b/i, 'Openwave'],
    [/\bIBM Domino\b|\bLotus Domino\b/i, 'IBM Domino'],
    [/\bMailEnable\b/i, 'MailEnable'],
    [/\bamavisd?(?:-new)?\b/i, 'amavis (content filter)'],
];

function detectSoftware(comments: string[], protocol: string | null, byName: string | null, text: string): string | null {
    if (protocol === 'Microsoft SMTP Server' || /^mapi$/i.test(protocol ?? '')) return 'Microsoft Exchange';
    if (protocol === 'Microsoft SMTPSVC') return 'Microsoft IIS SMTP';
    for (const comment of comments) {
        for (const [pattern, label] of SOFTWARE) {
            const m = pattern.exec(comment);
            if (m) return typeof label === 'string' ? label : label(m);
        }
    }
    if (/\bqmail\b/i.test(text)) return 'qmail';
    if (byName && /(^|\.)(google\.com|googlemail\.com)$/i.test(byName)) return 'Google';
    if (byName && /^2002:[0-9a-f:]+$/i.test(byName)) return 'Google (internal)';
    return null;
}

/**
 * RFC 3848 protocol names end in "S" when TLS was used (ESMTPS, ESMTPSA, LMTPS…);
 * the version and cipher, when present, are in comments written by each server
 * in its own style:
 *   Exim       with esmtps (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *   Postfix    (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))
 *   Sendmail   (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NO)
 *   Microsoft  with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
 *   Google     (Google Transport Security)
 *   Old Exim   with esmtps (TLSv1.2:ECDHE-RSA-AES256-GCM-SHA384:256)
 */
export function detectTls(comments: string[], protocol: string | null, withExtra: string[] = []): TlsInfo | null {
    const text = [...comments, withExtra.join(' ')].join(' ; ');
    const oldExim = comments.map((c) => /^(?:TLS|SSL)v?[\d.]*:([\w-]+):(\d+)$/i.exec(c)).find(Boolean);
    const version = /\b(?:TLS|SSL)\s?v?(\d)(?:[._](\d))?\b/i.exec(text);
    const cipher =
        oldExim?.[1] ??
        /\bcipher[= ]\s*([A-Z0-9][\w-]+)/i.exec(text)?.[1] ??
        /(?:^|\s)tls\s+([A-Z0-9][\w-]{6,})/i.exec(withExtra.join(' '))?.[1] ??
        /\b(TLS_[A-Z0-9_]+|(?:ECDHE|DHE|AES|CHACHA)[A-Z0-9-]*-(?:SHA\d*|GCM|POLY1305)[A-Z0-9-]*)\b/.exec(text)?.[1] ??
        null;
    const bits = oldExim?.[2] ?? /\bbits=(\d+(?:\/\d+)?)/i.exec(text)?.[1] ?? /\((\d+\/\d+) bits\)/i.exec(text)?.[1] ?? null;
    const verify = /\bverify=(\w+)/i.exec(text)?.[1] ?? null;
    const google = /Google Transport Security/i.test(text);
    const usingTls = /\busing (?:TLS|SSL)\b|\(TLS\)/i.test(text);
    const sProtocol = /^(?:E?SMTPS|ESMTPSA|LMTPSA?|UTF8(?:SMTP|LMTP)SA?|HTTPS)$/i.test(protocol ?? '');

    if (!version && !cipher && !google && !usingTls && !sProtocol) return null;
    const isSsl = version && /ssl/i.test(version[0]);
    return {
        version: version ? `${isSsl ? 'SSL' : 'TLS'} ${version[1]}${isSsl ? '' : '.' + (version[2] ?? '0')}` : null,
        cipher,
        bits,
        verify,
        note: google ? 'Google Transport Security' : null,
    };
}

function detectAuth(comments: string, protocol: string | null): string | null {
    const user =
        /Authenticated sender:\s*([^\s);]+)/i.exec(comments)?.[1] ??
        /\bauthenticated (?:as|user|by)\s+([^\s);]+)/i.exec(comments)?.[1] ??
        /\bauth(?:enticated)?_?id[=:]\s*([^\s);]+)/i.exec(comments)?.[1] ??
        null;
    if (user) return user;
    if (/^(?:E?SMTPS?A|ESMTPSA|LMTPS?A|UTF8(?:SMTP|LMTP)S?A)$/i.test(protocol ?? '')) return 'yes';
    return null;
}

const PROTOCOLS: Record<string, string> = {
    SMTP: 'SMTP',
    ESMTP: 'Extended SMTP',
    ESMTPA: 'Extended SMTP, sender logged in (SMTP AUTH)',
    ESMTPS: 'Extended SMTP over TLS (STARTTLS)',
    ESMTPSA: 'Extended SMTP over TLS, sender logged in',
    SMTPS: 'SMTP over TLS',
    LMTP: 'LMTP: hand-off to the mailbox store',
    LMTPA: 'LMTP, authenticated',
    LMTPS: 'LMTP over TLS',
    LMTPSA: 'LMTP over TLS, authenticated',
    UTF8SMTP: 'SMTP with international addresses (SMTPUTF8)',
    UTF8SMTPA: 'SMTPUTF8, sender logged in',
    UTF8SMTPS: 'SMTPUTF8 over TLS',
    UTF8SMTPSA: 'SMTPUTF8 over TLS, sender logged in',
    HTTP: 'Web or API submission (HTTP)',
    HTTPS: 'Web or API submission (HTTPS)',
    LOCAL: 'Local delivery on the same machine',
    MAPI: 'MAPI: submitted from an Exchange/Outlook mailbox',
    'MICROSOFT SMTP SERVER': 'Exchange SMTP',
    'MICROSOFT SMTPSVC': 'IIS SMTP service (Windows)',
};

export function describeProtocol(protocol: string | null): string | null {
    if (!protocol) return null;
    return PROTOCOLS[protocol.toUpperCase()] ?? (/^local/i.test(protocol) ? 'Local delivery on the same machine' : null);
}

/**
 * Received by the same machine it came from: a content filter handing mail
 * back and forth on one server ("by localhost (spamwall.example.org [192.0.2.1])"),
 * so the receiver is loopback, or reports the sender's own address.
 */
export function receivedBySameBox(received: Received): boolean {
    const byName = (received.by?.name ?? '').toLowerCase();
    if (byName === 'localhost' || byName === 'localhost.localdomain' || byName === '::1' || byName.startsWith('127.')) return true;
    return !!received.by?.ip && !!received.from?.ip && received.by.ip === received.from.ip;
}

/** Was the connection this header records protected in transit? */
export function securityOf(received: Received): Security {
    if (received.tls) return 'encrypted';
    const protocol = (received.protocol ?? '').toUpperCase();
    const fromIp = received.from?.ip;
    const scope: IpScope | null = fromIp ? ipScope(fromIp) : null;
    const fromName = (received.from?.rdns ?? received.from?.name ?? '').toLowerCase();
    const byName = (received.by?.name ?? '').toLowerCase();
    // Handed to itself (content filters, LMTP delivery into the mailbox store) or a loopback connection.
    const sameMachine = (fromName !== '' && fromName === byName) || receivedBySameBox(received);
    if (scope === 'loopback' || fromName === 'localhost' || sameMachine || fromName.includes('pickup service') || protocol.startsWith('LOCAL') || (!fromIp && /^LMTP/.test(protocol))) {
        return 'local';
    }
    // MAPI submissions, "by <server>" with no sender (Gmail's internal hops,
    // filters re-injecting mail) and senders named by a bare queue id
    // ("from 1eYfVN-00004u-44") are hand-offs inside one provider's network.
    if (protocol === 'MAPI' || !received.from || (!fromIp && fromName !== '' && !fromName.includes('.'))) return 'internal';
    if (protocol) return 'unencrypted';
    return 'unknown';
}

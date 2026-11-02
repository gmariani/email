import { domainOf, formatMailbox, parseAddressList } from '../address';
import { aligned, parseAuthResults, parseDkimSignature, parseReceivedSpf, parseTagList, verdictOf, type Verdict } from '../auth';
import { parseDate } from '../date';
import { decodeBase64 } from '../encoding';
import { formatUtc, secondsToTime } from '../format';
import { findHeader } from '../message';
import { parseContentType } from '../mime';
import { describeProtocol, parseReceived, securityOf } from '../received';
import { SERVICES } from '../data/services';
import { sesIdFacts } from './amazon';
import { dkimTagFacts, receivedSpfFacts, resultFacts, resultWord } from './authParts';
import { fact, timeFacts, type Explainer, type Fact, type Tone } from './types';

export function verdictTone(verdict: Verdict): Tone {
    return verdict === 'pass' ? 'good' : verdict === 'fail' ? 'bad' : verdict === 'softfail' || verdict === 'error' ? 'warn' : 'muted';
}

// ------------------------------------------------------------ Addresses

const addresses: Explainer = (field, { headers }) => {
    const list = parseAddressList(field.decoded);
    if (!list.length) return { summary: field.value.includes(':;') ? 'An empty group: the recipients were hidden.' : undefined, facts: [] };
    const facts: Fact[] = list.flatMap((m, i) => [
        ...fact(list.length > 1 ? `#${i + 1}` : 'Address', m.address, { kind: 'email' }),
        ...fact('Display name', m.name),
    ]);

    let summary: string | undefined;
    const from = parseAddressList(findHeader(headers, 'from')?.decoded ?? '')[0];
    if (field.key === 'reply-to' && from?.domain && list[0].domain && !aligned(from.domain, list[0].domain)) {
        facts.push({ label: 'Note', value: `Replies go to ${list[0].domain}, not the sender's domain (${from.domain}).`, tone: 'warn', hint: 'Normal for help desks and newsletters; a classic sign of phishing when the From address is impersonating someone.' });
    }
    if (field.key === 'from' && list[0].name && /@/.test(list[0].name)) {
        const shown = domainOf(list[0].name);
        if (shown && list[0].domain && !aligned(shown, list[0].domain)) {
            facts.push({ label: 'Note', value: `The display name shows an address at ${shown}, but the real address is at ${list[0].domain}.`, tone: 'bad' });
        }
    }
    if (field.key === 'from') summary = `From ${formatMailbox(list[0])}.`;
    if (field.key === 'sender') summary = `Sent by ${list[0].address}${from ? ` on behalf of ${from.address}` : ''}.`;
    if (field.key === 'delivered-to') summary = `Delivered to the mailbox ${list[0].address}.`;
    return { summary, facts };
};

const returnPath: Explainer = (field, { headers }) => {
    const address = field.value.replace(/^<|>$/g, '').trim();
    if (!address) return { summary: 'Empty: this is a bounce or automatic notification, which must not itself bounce.', facts: [] };
    const domain = domainOf(address);
    const from = parseAddressList(findHeader(headers, 'from')?.decoded ?? '')[0];
    const local = address.split('@')[0];
    const facts: Fact[] = [...fact('Address', address, { kind: 'email' }), ...fact('Domain', domain, { kind: 'domain' })];
    if (from?.domain && domain) {
        const ok = aligned(domain, from.domain);
        facts.push({
            label: 'Matches From domain',
            value: ok ? `Yes (${from.domain})` : `No (From is ${from.domain})`,
            tone: ok ? 'good' : 'muted',
            hint: 'For DMARC, SPF only counts when this domain matches the From domain. Sending services often use their own bounce domain, in which case DKIM has to carry DMARC.',
        });
    }
    if (local.length > 30 && /[0-9a-f]{12,}|[=+]/i.test(local)) {
        facts.push({ label: 'Encoding', value: 'Unique per message/recipient (VERP)', tone: 'muted', hint: 'The sending service encodes an id in the address so it knows exactly which message or recipient bounced.' });
    }
    facts.push(...sesIdFacts(local));
    return { summary: `Bounces go to ${address}.`, facts };
};

// --------------------------------------------------------------- Message

const date: Explainer = (field, { route }) => {
    const parsed = parseDate(field.value);
    if (!parsed) return { summary: "The date couldn't be read.", facts: [] };
    const facts: Fact[] = timeFacts("Sender's time", parsed.time, parsed.offset);
    const first = route.hops.find((h) => h.date)?.date?.time;
    if (first !== undefined) {
        const seconds = Math.round((first - parsed.time) / 1000);
        facts.push({
            label: 'To first server',
            value: seconds < 0 ? `${secondsToTime(-seconds)} before it was "written"` : secondsToTime(seconds),
            tone: seconds < -300 ? 'warn' : undefined,
            hint: 'Between the Date header and the first Received timestamp.',
        });
    }
    return { facts };
};

const WORD_ENCODINGS: Record<string, string> = {
    Q: 'Quoted-printable',
    B: 'Base64',
};

const subject: Explainer = (field) => {
    const facts: Fact[] = [...fact('Text', field.decoded)];
    // RFC 2047 encoded words: =?charset?Q|B?text?=
    const words = [...field.value.matchAll(/=\?([^?\s]+)\?([BbQq])\?[^?\s]*\?=/g)];
    if (words.length) {
        const charsets = [...new Set(words.map((w) => w[1].toUpperCase()))];
        const encodings = [...new Set(words.map((w) => w[2].toUpperCase()))];
        facts.push({ label: 'Character set', value: charsets.join(', '), hint: 'The first part of =?charset?encoding?text?=: how the bytes map to letters.' });
        facts.push({ label: 'Encoding', value: encodings.map((e) => WORD_ENCODINGS[e]).join(', '), raw: encodings.join(', '), hint: 'The second part of =?charset?encoding?text?=. Headers may only contain plain ASCII, so other characters are written this way (RFC 2047): Q (quoted-printable) writes them as =XX and spaces as _, B is base64.' });
        facts.push({ label: 'As written', value: field.value, mono: true, tone: 'muted' });
    }
    const prefixes = /^((?:(?:re|fw|fwd|aw|wg|sv|vs|tr|rv|r|antw)\s*(?:\[\d+\])?:\s*)+)/i.exec(field.decoded)?.[1];
    if (prefixes) facts.push({ label: 'Prefix', value: prefixes.trim(), hint: 'RE: = reply, FW:/Fwd: = forward (AW/WG in German, SV/VS in Nordic languages, TR in French…).' });
    return { facts };
};

/** Delivery-Date and the like: a timestamp a server added, shown as written and in the reader's time. */
const timestamp =
    (label: string): Explainer =>
    (field) => {
        const parsed = parseDate(field.value);
        if (!parsed) return null;
        return { facts: timeFacts(label, parsed.time, parsed.offset) };
    };

const messageId: Explainer = (field) => {
    const id = field.value.replace(/^<|>$/g, '').trim();
    const domain = domainOf(`<${id}>`);
    const facts: Fact[] = [...fact('Domain part', domain, { kind: 'domain', hint: 'Usually the server or service that created the message.' })];
    const service = domain ? SERVICES.find((s) => s.messageIds?.some((m) => domain === m || domain.endsWith(`.${m}`) || domain.includes(m))) : undefined;
    if (service) facts.push({ label: 'Generated by', value: service.name, tone: 'info' });
    facts.push(...sesIdFacts(id));
    return { facts };
};

const references: Explainer = (field) => {
    const ids = field.value.match(/<[^>]+>/g) ?? [];
    return {
        summary: field.key === 'references' ? `${ids.length} earlier message${ids.length === 1 ? '' : 's'} in this conversation.` : 'This is a reply.',
        facts: ids.map((id, i) => ({ label: field.key === 'references' ? `#${i + 1}` : 'Replying to', value: id, mono: true })),
    };
};

/**
 * Thread-Index: base64 of a 22-byte header (a timestamp + a 16-byte GUID)
 * followed by one 5-byte block per reply or forward. The timestamp is the top
 * of a Windows FILETIME, written two ways: older Outlook stores its top 6 bytes
 * ("Ad…"), newer versions a reserved 0x01 byte then its top 5 bytes ("AQH…").
 */
export function decodeThreadIndex(value: string): { started: number | null; replies: number; guid: string } | null {
    const bytes = decodeBase64(value);
    if (bytes.length < 22 || (bytes.length - 22) % 5 !== 0) return null;
    const read = (from: number, count: number, shift: bigint) => {
        let filetime = 0n;
        for (let i = from; i < from + count; i++) filetime = (filetime << 8n) | BigInt(bytes[i]);
        return Number((filetime << shift) / 10_000n) - 11_644_473_600_000;
    };
    const plausible = (ms: number) => ms > Date.UTC(1995, 0, 1) && ms < Date.now() + 365 * 86_400_000;
    // Some clients write other layouts; then only the depth and GUID are reliable.
    const started = [read(0, 6, 16n), read(1, 5, 24n)].find(plausible) ?? null;
    const guid = [...bytes.slice(6, 22)].map((b) => b.toString(16).padStart(2, '0')).join('');
    return { started, replies: (bytes.length - 22) / 5, guid };
}

const threadIndex: Explainer = (field) => {
    const decoded = decodeThreadIndex(field.value);
    if (!decoded) return null;
    const started = decoded.started === null ? null : formatUtc(decoded.started);
    return {
        summary: decoded.replies
            ? `Reply/forward #${decoded.replies} in an Outlook conversation${started ? ` started ${started}` : ''}.`
            : `Starts a new Outlook conversation${started ? ` (${started})` : ''}.`,
        facts: [
            ...(decoded.started === null ? [] : timeFacts('Conversation started', decoded.started)),
            ...fact('Depth', decoded.replies ? `${decoded.replies} repl${decoded.replies === 1 ? 'y' : 'ies'}/forwards in` : 'First message'),
            ...fact('Conversation GUID', decoded.guid, { mono: true, tone: 'muted' }),
        ],
    };
};

const PRIORITY: Record<string, [string, Tone | undefined]> = {
    '1': ['1 (Highest)', 'warn'],
    '2': ['2 (High)', undefined],
    '3': ['3 (Normal)', undefined],
    '4': ['4 (Low)', undefined],
    '5': ['5 (Lowest)', undefined],
};

const priority: Explainer = (field) => {
    const n = /^\s*(\d)/.exec(field.value)?.[1];
    const [label, tone] = n && PRIORITY[n] ? PRIORITY[n] : [field.value, undefined];
    return { facts: [{ label: 'Priority', value: label, tone }] };
};

// --------------------------------------------------------------- Content

const MULTIPART: Record<string, string> = {
    'multipart/alternative': 'The same content in several formats (usually plain text and HTML); the app shows the best one it supports.',
    'multipart/mixed': 'A body followed by attachments.',
    'multipart/related': 'HTML with embedded resources such as inline images.',
    'multipart/report': 'A machine-readable delivery or read report (bounce, read receipt).',
    'multipart/signed': 'A signed message (S/MIME or PGP): the signature is a separate part.',
    'multipart/encrypted': 'An encrypted message (PGP/MIME).',
    'text/plain': 'Plain text.',
    'text/html': 'HTML (formatted) only, without a plain-text version.',
    'text/calendar': 'A calendar invitation.',
    'application/pkcs7-mime': 'An S/MIME signed or encrypted message.',
};

const contentType: Explainer = (field) => {
    const ct = parseContentType(field.value);
    return {
        help: MULTIPART[ct.type],
        facts: [
            ...fact('Type', ct.type),
            ...fact('Character set', ct.params.charset),
            ...fact('Boundary', ct.params.boundary, { mono: true, tone: 'muted', hint: 'The line that separates the parts.' }),
            ...fact('Name', ct.params.name),
            ...Object.entries(ct.params)
                .filter(([k]) => !['charset', 'boundary', 'name'].includes(k))
                .map(([k, v]) => ({ label: k, value: v, tone: 'muted' as Tone })),
        ],
    };
};

const ENCODINGS: Record<string, string> = {
    '7bit': 'Plain ASCII text, sent as is.',
    '8bit': 'Text with non-ASCII bytes, sent as is.',
    binary: 'Raw binary, sent as is (rare).',
    'quoted-printable': 'Mostly-readable text: special characters are written as =XX.',
    base64: 'Encoded as base64 (unreadable as is; usual for attachments and non-Latin text).',
};

const transferEncoding: Explainer = (field) => ({ facts: fact('Encoding', field.value.trim()), help: ENCODINGS[field.value.trim().toLowerCase()] });

// ------------------------------------------------------------- Routing

const received: Explainer = (field) => {
    const r = parseReceived(field.value);
    const security = securityOf(r);
    const facts: Fact[] = [];
    const fromName = r.from?.rdns ?? r.from?.name;
    facts.push(...fact('From', fromName, { kind: 'domain' }));
    if (r.from?.helo && r.from.helo !== fromName) facts.push({ label: 'Introduced itself as', value: r.from.helo, kind: 'domain' });
    if (r.from?.name && r.from.rdns && r.from.name.toLowerCase() !== r.from.rdns) facts.push({ label: 'HELO name', value: r.from.name, kind: 'domain' });
    facts.push(...fact('IP address', r.from?.ip, { kind: 'ip' }));
    facts.push(...fact('Source port', r.from?.port));
    if (r.from?.noRdns) facts.push({ label: 'Reverse DNS', value: 'None', tone: 'warn', hint: 'The IP has no reverse DNS name; legitimate mail servers almost always have one.' });
    facts.push(...fact('Received by', r.by?.name, { kind: 'domain' }));
    facts.push(...fact('Receiver IP', r.by?.ip, { kind: 'ip' }));
    facts.push(...fact('Software', r.software));
    if (r.protocol) facts.push({ label: 'Protocol', value: describeProtocol(r.protocol) ?? r.protocol, raw: r.protocol });
    facts.push({
        label: 'Encryption',
        value: security === 'encrypted' ? [r.tls?.version, r.tls?.cipher].filter(Boolean).join(', ') || r.tls?.note || 'Encrypted (TLS)' : SECURITY_TEXT[security],
        tone: security === 'encrypted' ? 'good' : security === 'unencrypted' ? 'bad' : 'muted',
    });
    facts.push(...fact('Key size', r.tls?.bits && `${r.tls.bits} bits`));
    facts.push(...fact('Client certificate', r.tls?.verify, { hint: 'Sendmail: whether the sending server presented a certificate that was verified (OK), not offered (NO/NONE) or failed.' }));
    facts.push(...fact('Logged in as', r.authenticated === 'yes' ? 'Yes (SMTP AUTH)' : r.authenticated, { tone: 'info' }));
    facts.push(...fact('Via', r.via));
    facts.push(...fact('Queue id', r.id, { mono: true }));
    facts.push(...fact('For', r.for, { kind: 'email' }));
    facts.push(...fact('Envelope sender', r.envelopeFrom, { kind: 'email' }));
    if (r.date) facts.push(...timeFacts('Time', r.date.time, r.date.offset));
    const extra = r.comments.filter((c) => !/^\[?[\d.:a-f]+\]?(:\d+)?$/i.test(c));
    facts.push(...fact('Comments', extra.join(' · '), { tone: 'muted' }));

    const summary = `${fromName ?? 'Unknown'}${r.from?.ip && r.from.ip !== fromName ? ` [${r.from.ip}]` : ''} → ${r.by?.name ?? 'unknown'}${r.protocol ? ` with ${r.protocol}` : ''}${security === 'encrypted' ? ` (${r.tls?.version ?? 'TLS'})` : ''}.`;
    return { summary, facts };
};

export const SECURITY_TEXT: Record<string, string> = {
    encrypted: 'Encrypted (TLS)',
    unencrypted: 'Not encrypted',
    local: 'Same machine (never crossed a network)',
    internal: "Inside the provider's own network",
    unknown: 'Not recorded',
};

const originatingIp: Explainer = (field) => ({
    summary: "The sender's own connection, as seen by their mail provider. Often a home or office network.",
    facts: fact('IP address', field.value.replace(/[[\]\s]/g, '').split(',')[0], { kind: 'ip' }),
});

// -------------------------------------------------------- Authentication

const RESULT_HELP: Record<string, Record<string, string>> = {
    spf: {
        pass: 'The sending IP is allowed by the domain\'s SPF record.',
        fail: 'The domain says this IP is NOT allowed to send for it.',
        softfail: 'The domain says this IP probably isn\'t allowed (~all).',
        neutral: 'The domain makes no claim about this IP (?all).',
        none: 'The domain has no SPF record.',
        temperror: 'A temporary DNS error prevented the check.',
        permerror: 'The domain\'s SPF record is broken (syntax error or too many lookups).',
    },
    dkim: {
        pass: 'The signature is valid: the signed parts are unchanged since the signing domain signed them.',
        fail: 'The signature doesn\'t match: the message was modified after signing, or the key is wrong.',
        none: 'The message isn\'t signed.',
        neutral: 'The signature couldn\'t be evaluated.',
        policy: 'The signature is valid but not acceptable under local policy (e.g. weak key).',
        temperror: 'A temporary error (often DNS) prevented the check.',
        permerror: 'The signature or key is malformed.',
    },
    dmarc: {
        pass: 'SPF or DKIM passed for a domain that matches the From address.',
        fail: 'Neither SPF nor DKIM passed for a domain matching From. The domain\'s policy says what to do with it.',
        none: 'The From domain has no DMARC policy.',
        bestguesspass: 'No DMARC record, but it would have passed if there were one.',
        temperror: 'A temporary error prevented the check.',
        permerror: 'The DMARC record is malformed.',
    },
    arc: {
        pass: 'The ARC chain from earlier forwarders is intact.',
        fail: 'The ARC chain is broken.',
        none: 'No ARC headers.',
    },
    compauth: {
        pass: 'Microsoft composite authentication passed (explicitly or implicitly).',
        fail: 'Microsoft composite authentication failed: treated as spoofed.',
        softpass: 'Soft pass: no explicit authentication, but Microsoft\'s heuristics trust it.',
        none: 'Not evaluated.',
    },
};

const authResults: Explainer = (field) => {
    const parsed = parseAuthResults(field);
    const facts: Fact[] = [];
    if (parsed.instance !== null) facts.push({ label: 'ARC Instance (i)', value: `Hop ${parsed.instance}`, raw: String(parsed.instance), hint: 'Which forwarding hop recorded these results.' });
    if (parsed.authservId) facts.push({ label: 'Checked by', value: parsed.authservId, kind: 'domain' });
    for (const r of parsed.results) facts.push(...resultFacts(r));
    const verdicts = parsed.results.filter((r) => ['spf', 'dkim', 'dmarc'].includes(r.method)).map((r) => `${r.method.toUpperCase()} ${r.result}`);
    return { summary: verdicts.length ? `${parsed.authservId || 'The receiver'} found: ${verdicts.join(', ')}.` : undefined, facts };
};

const receivedSpf: Explainer = (field) => {
    const spf = parseReceivedSpf(field.value);
    const facts: Fact[] = [
        { label: 'Sender Policy Framework (SPF)', value: resultWord(spf.result), raw: spf.result, hint: RESULT_HELP.spf[spf.result], tone: verdictTone(verdictOf(spf.result)) },
        ...(spf.comment ? [{ label: 'Explanation', value: spf.comment, sub: true }] : []),
        ...receivedSpfFacts(spf.props),
    ];
    return { summary: RESULT_HELP.spf[spf.result], facts };
};

const dkimSignature: Explainer = (field, { auth }) => {
    const sig = parseDkimSignature(field);
    const t = sig.tags;
    const facts: Fact[] = dkimTagFacts(t);
    if (t.d && t.s) facts.push({ label: 'Key location', value: `${t.s}._domainkey.${t.d}`, mono: true, hint: 'Where the public key that verifies this signature is published.' });
    if (sig.signedHeaders.length && !sig.signedHeaders.includes('from')) facts.push({ label: 'Note', value: "From isn't signed, so this signature can't vouch for the sender.", tone: 'bad' });
    if (field.key === 'dkim-signature' && auth.fromDomain && sig.domain) {
        const ok = aligned(sig.domain, auth.fromDomain);
        facts.push({ label: 'Matches From domain', value: ok ? `Yes (${auth.fromDomain}): counts for DMARC` : `No (From is ${auth.fromDomain}): doesn't count for DMARC`, tone: ok ? 'good' : 'muted' });
    }
    const summary = sig.domain ? `Signed by ${sig.domain}${sig.selector ? ` (selector ${sig.selector})` : ''}.` : undefined;
    return { summary, facts };
};

const arcSeal: Explainer = (field) => {
    const t = parseTagList(field.value);
    const cv = (t.cv ?? '').toLowerCase();
    return {
        summary: `ARC hop ${t.i ?? '?'} sealed by ${t.d ?? 'unknown'}; the chain before it was "${cv || 'unknown'}".`,
        facts: dkimTagFacts(t),
    };
};

// ----------------------------------------------------------- Lists

const listUnsubscribe: Explainer = (field) => {
    const links = field.value.match(/<[^>]+>/g)?.map((l) => l.slice(1, -1)) ?? [];
    return {
        facts: links.map((l) => (/^mailto:/i.test(l) ? { label: 'By email', value: l.replace(/^mailto:/i, ''), kind: 'email' as const } : { label: 'Web link', value: l, kind: 'url' as const, mono: true })),
    };
};

const listUnsubscribePost: Explainer = (field) => ({
    summary: /List-Unsubscribe=One-Click/i.test(field.value) ? 'One-click unsubscribe is supported (required by Gmail and Yahoo for bulk senders).' : undefined,
    facts: [],
});

const PRECEDENCE: Record<string, string> = {
    bulk: 'Bulk mail (newsletters, notifications): auto-responders should stay quiet.',
    list: 'Mailing list traffic.',
    junk: 'Unimportant mail: auto-responders should stay quiet.',
    'first-class': 'Normal priority.',
};

const precedence: Explainer = (field) => ({ summary: PRECEDENCE[field.value.trim().toLowerCase()], facts: [] });

const AUTO_SUBMITTED: Record<string, string> = {
    no: 'Written by a person.',
    'auto-generated': 'Generated automatically (notifications, alerts).',
    'auto-replied': 'An automatic reply (out-of-office, vacation).',
    'auto-notified': 'An automatic notification (e.g. a delivery report).',
};

const autoSubmitted: Explainer = (field) => ({ summary: AUTO_SUBMITTED[field.value.trim().toLowerCase().split(';')[0]], facts: [] });

const listId: Explainer = (field) => {
    const id = /<([^>]+)>/.exec(field.value)?.[1];
    const name = field.decoded.replace(/<[^>]+>/, '').replace(/^"|"$/g, '').trim();
    return { facts: [...fact('List name', name), ...fact('List id', id, { mono: true })] };
};

// ---------------------------------------------------------- Clients

const CLIENTS: [RegExp, string][] = [
    [/Microsoft Outlook\s*([\d.]+)?/i, 'Microsoft Outlook'],
    [/Apple Mail|iPhone Mail|iPad Mail/i, 'Apple Mail'],
    [/Thunderbird/i, 'Mozilla Thunderbird'],
    [/Roundcube/i, 'Roundcube webmail'],
    [/Horde/i, 'Horde webmail'],
    [/SquirrelMail/i, 'SquirrelMail'],
    [/PHPMailer/i, 'PHPMailer (a PHP library: a website or web app sent this)'],
    [/SwiftMailer|Symfony Mailer/i, 'Symfony/Swift Mailer (a PHP website or app)'],
    [/nodemailer/i, 'Nodemailer (a Node.js app)'],
    [/Mailchimp/i, 'Mailchimp'],
    [/Mutt|NeoMutt/i, 'Mutt'],
    [/Evolution/i, 'GNOME Evolution'],
    [/Postbox/i, 'Postbox'],
    [/eM Client/i, 'eM Client'],
    [/Zimbra/i, 'Zimbra'],
    [/WordPress/i, 'WordPress'],
    [/Xerox|Ricoh|Canon|Konica|Kyocera|Sharp MX|Brother|HP Digital Sending|Lexmark|Toshiba e-STUDIO/i, 'a printer/scanner (scan-to-email)'],
];

const mailer: Explainer = (field) => {
    const known = CLIENTS.find(([re]) => re.test(field.value));
    return { summary: known ? `Written with ${known[1]}.` : undefined, facts: [] };
};

const readReceipt: Explainer = (field) => ({ summary: `The sender asked for a read receipt, to ${field.decoded}.`, facts: [] });

const tlsRequired: Explainer = (field) => ({
    summary: /^\s*no\b/i.test(field.value) ? 'The sender allowed delivery without encryption if a secure connection fails.' : undefined,
    facts: [],
});

export const STANDARD: Record<string, Explainer> = {
    from: addresses,
    sender: addresses,
    'reply-to': addresses,
    to: addresses,
    cc: addresses,
    bcc: addresses,
    'delivered-to': addresses,
    'x-original-to': addresses,
    'envelope-to': addresses,
    'x-envelope-to': addresses,
    'resent-from': addresses,
    'resent-to': addresses,
    'return-path': returnPath,
    date,
    'delivery-date': timestamp('Delivered'),
    'resent-date': date,
    subject,
    'message-id': messageId,
    'resent-message-id': messageId,
    'in-reply-to': references,
    references,
    'thread-index': threadIndex,
    'x-priority': priority,
    'content-type': contentType,
    'content-transfer-encoding': transferEncoding,
    received,
    'x-received': received,
    'x-originating-ip': originatingIp,
    'x-sender-ip': originatingIp,
    'authentication-results': authResults,
    'arc-authentication-results': authResults,
    'x-original-authentication-results': authResults,
    'received-spf': receivedSpf,
    'dkim-signature': dkimSignature,
    'arc-message-signature': dkimSignature,
    'x-google-dkim-signature': dkimSignature,
    'arc-seal': arcSeal,
    'domainkey-signature': dkimSignature,
    'list-unsubscribe': listUnsubscribe,
    'list-unsubscribe-post': listUnsubscribePost,
    'list-id': listId,
    precedence,
    'auto-submitted': autoSubmitted,
    'x-mailer': mailer,
    'user-agent': mailer,
    'disposition-notification-to': readReceipt,
    'return-receipt-to': readReceipt,
    'tls-required': tlsRequired,
};


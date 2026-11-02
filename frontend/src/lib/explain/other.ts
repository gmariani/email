import { parseDate } from '../date';
import { formatUtc } from '../format';
import { fact, timeFacts, type Explainer, type Fact } from './types';

// ------------------------------------------------------------- cPanel

/** X-AntiAbuse: one "Key - value" line per header. */
const antiAbuse: Explainer = (field) => {
    const m = /^(.+?)\s+-\s+(.*)$/.exec(field.value);
    if (!m) return { summary: field.value, facts: [] };
    const [, key, value] = m;
    const hints: Record<string, string> = {
        'Primary Hostname': 'The shared hosting server that sent the message.',
        'Original Domain': 'The domain the message was addressed to on that server.',
        'Originator/Caller UID/GID': 'Unix user and group ids of the process that sent it: identifies the hosting account.',
        'Sender Address Domain': 'The envelope sender\'s domain.',
    };
    return { facts: fact(key, value, { hint: hints[key], kind: key.includes('Domain') || key.includes('Hostname') ? 'domain' : undefined }) };
};

/** X-Get-Message-Sender-Via: server.example.com: authenticated_id: user@example.com */
const senderVia: Explainer = (field) => {
    const m = /^([^:]+):\s*(\w+)(?::\s*(.*))?$/.exec(field.value.trim());
    if (!m) return null;
    const [, server, method, detail] = m;
    const how: Record<string, string> = {
        authenticated_id: 'logged in to the mail server as',
        acl_c_relayhosts_text_entry: 'was allowed to relay by the server\'s relay list',
        mailgid: 'was sent by a script running as the hosting account',
    };
    const facts: Fact[] = [...fact('Server', server, { kind: 'domain' }), ...fact('How', how[method] ?? method), ...fact('Account', detail, { kind: /@/.test(detail ?? '') ? 'email' : undefined })];
    return { summary: method === 'authenticated_id' && detail ? `Sent by someone logged in as ${detail} on ${server}.` : undefined, facts };
};

const authenticatedSender: Explainer = (field) => {
    const [server, account] = field.value.split(/:\s*/, 2);
    return { summary: account ? `Sent by the mailbox ${account}, logged in on ${server}.` : undefined, facts: [...fact('Server', server, { kind: 'domain' }), ...fact('Account', account, { kind: 'email' })] };
};

const sourceArgs: Explainer = (field) => ({
    summary: 'The program that sent the message on the web server. A PHP or script path here means a website sent it (contact form, or a hacked site sending spam).',
    facts: fact('Command', field.value, { mono: true }),
});

const sourceDir: Explainer = (field) => ({
    summary: 'The folder of the script that sent the message: which website on the server did it.',
    facts: fact('Directory', field.value, { mono: true }),
});

// -------------------------------------------------------------- Google

/** Encoded or encrypted values: say so in a row, and what it is in the help. */
export const encoded =
    (what: string, who = 'the company that wrote it'): Explainer =>
    (field) => ({
        facts: [{ label: 'Contents', value: `Encoded (${field.value.replace(/\s/g, '').length.toLocaleString()} characters)`, tone: 'muted', hint: `Can't be read outside ${who}. The full text is under Raw header.` }],
        help: what,
    });

const opaque = (what: string) => encoded(what);

const gmFlag =
    (label: string): Explainer =>
    (field) => {
        const yes = field.value.trim() === '1';
        return { facts: [{ label, value: yes ? 'Yes' : 'No', tone: yes ? 'bad' : 'good' }] };
    };

// ------------------------------------------------------------- Mailgun

const mailgunVariables: Explainer = (field) => {
    try {
        const data = JSON.parse(field.decoded) as Record<string, unknown>;
        return { summary: 'Custom data the sender attached for its own tracking.', facts: Object.entries(data).map(([k, v]) => ({ label: k, value: typeof v === 'string' ? v : JSON.stringify(v), mono: true })) };
    } catch {
        return null;
    }
};

// -------------------------------------------------------------- Proton

const protonEncryption: Explainer = (field) => {
    const v = field.value.trim().toLowerCase();
    const text = v === 'end-to-end' ? 'End-to-end encrypted: only the sender and recipient can read it' : v === 'on-delivery' ? 'Encrypted by Proton when it arrived (zero-access storage), not end-to-end' : field.value;
    return { facts: [{ label: 'Encryption', value: text, tone: v === 'end-to-end' ? 'good' : undefined }] };
};

const protonOrigin: Explainer = (field) => ({
    facts: fact('Origin', field.value.trim().toLowerCase() === 'internal' ? 'Internal: between Proton accounts' : field.value.trim().toLowerCase() === 'external' ? 'External: from outside Proton' : field.value),
});

// ----------------------------------------------------------- Microsoft

/** "00:00:02.0270000" => "2.027s" */
const endToEndLatency: Explainer = (field) => {
    const m = /^(?:(\d+)\.)?(\d+):(\d+):(\d+(?:\.\d+)?)$/.exec(field.value.trim());
    if (!m) return null;
    const seconds = (parseInt(m[1] ?? '0', 10) * 86400) + parseInt(m[2], 10) * 3600 + parseInt(m[3], 10) * 60 + parseFloat(m[4]);
    return { summary: `Exchange took ${seconds < 60 ? `${seconds.toFixed(1)} s` : `${Math.round(seconds / 60)} min`} to process and deliver it.`, facts: [] };
};

const ATP: Record<string, string> = { SA: 'Safe Attachments scanned the attachments', SL: 'Safe Links rewrote/checked the links' };

const atpProperties: Explainer = (field) => ({
    facts: field.value.split('|').map((p) => ({ label: p, value: ATP[p.trim()] ?? 'Microsoft Defender processing flag' })),
});

const correlationId: Explainer = (field) => ({
    facts: fact('Correlation id', field.value.trim(), { mono: true, hint: 'Give this id to Microsoft support to trace this message in their logs.' }),
});

const SERVER_ROLES: Record<string, string> = { MB: 'Mailbox server', FT: 'Front-end transport (Exchange Online Protection)', CA: 'Client access (front end)', SP: 'Mailbox server' };

const FORESTS: Record<string, string> = {
    NAM: 'North America', EUR: 'Europe', APC: 'Asia-Pacific', GBR: 'United Kingdom', AUS: 'Australia', CAN: 'Canada', IND: 'India', JPN: 'Japan', KOR: 'Korea',
    BRA: 'Brazil', FRA: 'France', DEU: 'Germany', CHE: 'Switzerland', ZAF: 'South Africa', NOR: 'Norway', ARE: 'United Arab Emirates', LAM: 'Latin America', PR: 'Production',
};

/**
 * "MW4PR04MB7380:EE_|BN7NAM10FT063:EE_": the Exchange Online servers that handled it, each named
 * datacenter (MW4) + forest (PR04, NAM10) + role (MB, FT, CA) + number. The codes after the colon aren't documented.
 */
const trafficDiagnostic: Explainer = (field) => {
    const facts: Fact[] = [];
    for (const part of field.value.split(/[|;]/)) {
        const [server, code] = part.split(':').map((x) => x.trim());
        if (!server) continue;
        facts.push({ label: 'Server', value: server, mono: true });
        const m = /^([A-Z]{2,3}\d)([A-Z]{2,3})(\d{1,2})([A-Z]{2})(\d+)$/i.exec(server);
        if (m) {
            const [, dc, forest, n, role] = m.map((x) => x.toUpperCase());
            facts.push({ label: 'Role', value: SERVER_ROLES[role] ?? role, raw: role, sub: true });
            facts.push({ label: 'Datacenter', value: dc, sub: true, hint: "Microsoft's internal code for the datacenter." });
            facts.push({ label: 'Forest', value: FORESTS[forest] && forest !== 'PR' ? FORESTS[forest] : `${forest}${n}`, raw: `${forest}${n}`, sub: true, hint: 'The group of Exchange Online servers (and region) this one belongs to.' });
        }
        if (code) facts.push({ label: 'Traffic type', value: code, mono: true, tone: 'muted', sub: true, hint: "Microsoft's internal traffic code. It isn't documented." });
    }
    return { facts };
};

/** X-OriginalArrivalTime: 08 Jan 2018 22:02:46.0437 (UTC) FILETIME=[6A70F550:01D388CC] */
const originalArrivalTime: Explainer = (field) => {
    const m = /^(.*?)\s*\(UTC\)/i.exec(field.value);
    const date = m ? parseDate(`${m[1].replace(/\.\d+$/, '')} +0000`) : null;
    return date ? { summary: `First reached a Microsoft mail server at ${formatUtc(date.time)}.`, facts: timeFacts('Arrived', date.time, date.offset) } : null;
};

const emptyMeansNone =
    (label: string, none: string): Explainer =>
    (field) => ({ facts: [{ label, value: field.value.trim() || none, tone: field.value.trim() ? undefined : 'muted' }] });

const kindFact =
    (label: string, kind: 'ip' | 'domain' | 'email'): Explainer =>
    (field) => ({ facts: fact(label, field.value.trim().replace(/^<|>$/g, ''), { kind }) });

/** "OpenDMARC Filter v1.4.2 mail-tester.com A7A4EFC906" */
const filterStamp: Explainer = (field) => {
    const m = /^(.+?)\s+v?([\d.]+)\s+(\S+)\s+(\S+)\s*$/.exec(field.value.trim());
    if (!m) return null;
    return {
        summary: `${m[1]} ${m[2]} on ${m[3]} handled it (queue id ${m[4]}).`,
        facts: [
            ...fact('Software', `${m[1]} ${m[2]}`),
            ...fact('Server', m[3], { kind: 'domain' }),
            ...fact('Queue id', m[4], { mono: true, hint: "The server's id for the message, for searching its logs." }),
        ],
    };
};

/** X-MSYS-API: JSON the sender passed to SparkPost's API. */
const msysApi: Explainer = (field) => {
    try {
        const data = JSON.parse(field.decoded) as Record<string, unknown>;
        const flat: Fact[] = [];
        const walk = (prefix: string, value: unknown) => {
            if (value && typeof value === 'object' && !Array.isArray(value)) {
                for (const [k, v] of Object.entries(value)) walk(prefix ? `${prefix}.${k}` : k, v);
            } else {
                flat.push({ label: prefix, value: typeof value === 'string' ? value : JSON.stringify(value), mono: true, sub: prefix.includes('.') });
            }
        };
        walk('', data);
        const campaign = typeof data.campaign_id === 'string' ? data.campaign_id : null;
        return { summary: campaign ? `Sent through SparkPost as part of the campaign "${campaign}".` : 'Sending options and tracking data passed to SparkPost.', facts: flat.slice(0, 25) };
    } catch {
        return null;
    }
};

const originatorOrg: Explainer = (field) => ({
    summary: `Sent from the Microsoft 365 organisation ${field.value.trim()}.`,
    facts: fact('Organisation', field.value.trim(), { kind: 'domain', hint: "The tenant's default domain. For spam or phishing, this is the Microsoft 365 customer whose account sent it." }),
});

/** "AS4PR10CA0010.EURPRD10.PROD.OUTLOOK.COM (2603:…) To MA0P287MB3370.INDP287.PROD.OUTLOOK.COM (2603:…)" */
const clientProxiedBy: Explainer = (field) => {
    const m = /^(\S+)(?:\s*\(([^)]*)\))?\s+To\s+(\S+)/i.exec(field.value);
    if (!m) return null;
    return {
        facts: [...fact('Front-end server', m[1].toLowerCase()), ...fact('Its address', m[2]), ...fact('Mailbox server', m[3].toLowerCase())],
    };
};

const flag =
    (label: string, meanings: Record<string, string>): Explainer =>
    (field) => {
        const v = field.value.trim();
        return { facts: meanings[v] ? [{ label, value: meanings[v], raw: v }] : fact(label, v) };
    };

/** A header that is just an identifier: one labelled row, like every other header. */
const id =
    (label: string, hint?: string): Explainer =>
    (field) => ({ facts: fact(label, field.value.trim().replace(/^<|>$/g, ''), { mono: true, hint }) });

/** X-Report-Abuse / X-Complaints-To: "<mailto:abuse@example.com>", "Please report abuse here: https://…", or a bare address. */
const reportTo: Explainer = (field) => {
    const facts: Fact[] = [];
    for (const token of field.value.match(/(?:mailto:|https?:\/\/)[^\s<>,]+|[^\s<>,:]+@[^\s<>,]+/gi) ?? []) {
        if (/^https?:/i.test(token)) facts.push({ label: 'Web form', value: token, kind: 'url', mono: true });
        else facts.push({ label: 'Email', value: token.replace(/^mailto:/i, '').replace(/\?.*$/, ''), kind: 'email' });
    }
    return facts.length ? { facts } : null;
};

const opaqueData = encoded('Encoded anti-spam data Microsoft passes between its own servers.', 'Microsoft');

export const OTHER: Record<string, Explainer> = {
    'dmarc-filter': filterStamp,
    'dkim-filter': filterStamp,
    'x-msys-api': msysApi,
    'x-originatororg': originatorOrg,
    'x-clientproxiedby': clientProxiedBy,
    'x-ms-exchange-senderadcheck': flag('Sender directory check', { '0': 'not checked', '1': "checked against the organisation's directory" }),
    'x-ms-exchange-antispam-relay': flag('Relayed by anti-spam service', { '0': 'no', '1': 'yes' }),
    'x-ms-publictraffictype': flag('Traffic type', { Email: 'ordinary email' }),
    'x-ms-exchange-antispam-messagedata-0': opaqueData,
    'x-ms-exchange-antispam-messagedata-1': opaqueData,
    'x-microsoft-antispam-message-info': opaqueData,
    'x-microsoft-antispam-message-info-original': opaqueData,
    'x-ms-exchange-antispam-messagedata-original-0': opaqueData,
    'x-ms-exchange-antispam-messagedata-original-chunkcount': flag('Chunks', {}),
    'mime-version': (field) => ({ facts: fact('Version', field.value.replace(/\(.*\)/, '').trim()) }),
    'x-spam-virus-scanned': (field) => ({ facts: fact('Scanned by', field.value.trim()) }),
    'x-ms-exchange-antispam-messagedata-chunkcount': flag('Chunks', {}),
    'x-ms-exchange-transport-crosstenantheadersstamped': (field) => ({ facts: fact('Stamped by', field.value.trim().toLowerCase()) }),
    'x-zohomailclient': flag('Entered Zoho from', { External: "outside Zoho's own mail apps (an API, SMTP or another service)" }),
    'x-zoho-cm-accountid': (field) => ({ facts: fact('Zoho account id', field.value.trim(), { mono: true, hint: 'Quote this when reporting abuse to Zoho.' }) }),
    'original-envelope-id': (field) => ({ facts: fact('Envelope id', field.value.trim(), { mono: true }) }),
    'x-jid': id('Job id', "Zoho's id for the sending job: quote it when reporting abuse to Zoho."),
    'tm-mail-jid': id('Job id', "ZeptoMail's id for the sending job: quote it when reporting abuse to Zoho."),
    'x-app-message-id': id('Message id', 'The id the sending application gave this message.'),
    'x-mailer-recptid': id('Recipient id'),
    'x-campaign': id('Campaign id'),
    'x-campaignid': id('Campaign id'),
    'x-mc-user': id('Mailchimp account id', 'Quote this when reporting abuse to Mailchimp.'),
    'x-mailer-lid': id('List ids'),
    'x-policysmart': id('Policy id'),
    'content-id': id('Part id', 'HTML in the message refers to this part as cid:<id>.'),
    'x-php-originating-script': (field) => {
        const m = /^(\d+):(.+)$/.exec(field.value.trim());
        return { facts: m ? [...fact('Unix user id', m[1], { hint: 'Identifies the hosting account on the web server.' }), ...fact('Script', m[2], { mono: true })] : fact('Script', field.value.trim(), { mono: true }) };
    },
    'x-report-abuse': reportTo,
    'x-complaints-to': reportTo,
    'x-csa-complaints': reportTo,
    'x-eventbrite': (field) => ({ facts: field.value.split(':').map((part, i) => ({ label: ['Service', 'Id', 'Message'][i] ?? `Part ${i + 1}`, value: part, mono: true })) }),
    'x-eventbritemailer': (field) => ({ facts: fact('Mail service', field.value.trim()) }),
    'x-originalarrivaltime': originalArrivalTime,
    'x-tls': emptyMeansNone('TLS', 'None: the connection to the gateway was not encrypted'),
    'x-authenticated_id': emptyMeansNone('Logged in as', 'Nobody (no SMTP login)'),
    'x-dkim': emptyMeansNone('DKIM', 'Not checked'),
    'x-origin-ip': kindFact('Sending server IP', 'ip'),
    'x-revdns': kindFact('Reverse DNS', 'domain'),
    'x-helo': kindFact('HELO name', 'domain'),
    'x-env-from': kindFact('Envelope sender', 'email'),
    'x-fm-os': (field) => ({ facts: fact('Sending OS (guess)', field.value) }),
    'x-fm-geoip': (field) => ({ facts: fact('Sending country', field.value) }),
    'x-antiabuse': antiAbuse,
    'x-get-message-sender-via': senderVia,
    'x-authenticated-sender': authenticatedSender,
    'x-source-args': sourceArgs,
    'x-source-dir': sourceDir,
    'x-gm-message-state': opaque('A Gmail identifier for the sending account/session.'),
    'x-google-smtp-source': opaque("Google's record of where inside its network the message came from."),
    'x-gm-gg': opaque('A Gmail internal identifier.'),
    'x-gm-features': opaque('Gmail internal features used when composing.'),
    'x-gm-spam': gmFlag('Gmail spam'),
    'x-gm-phishy': gmFlag('Gmail phishing'),
    'x-sg-eid': opaque('SendGrid\'s encrypted message and recipient identifier.'),
    'x-sg-id': opaque('SendGrid\'s encrypted identifier.'),
    'x-entity-id': opaque('SendGrid\'s encoded account identifier.'),
    'x-mailgun-sid': opaque('Mailgun\'s sending-domain identifier.'),
    'x-mailgun-variables': mailgunVariables,
    'x-msfbl': opaque('SparkPost\'s feedback-loop identifier.'),
    'x-pm-content-encryption': protonEncryption,
    'x-pm-origin': protonOrigin,
    'x-ms-exchange-transport-endtoendlatency': endToEndLatency,
    'x-ms-exchange-atpmessageproperties': atpProperties,
    'x-ms-office365-filtering-correlation-id': correlationId,
    'x-ms-traffictypediagnostic': trafficDiagnostic,
};

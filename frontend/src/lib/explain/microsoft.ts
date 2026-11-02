import { parseDate } from '../date';
import { fact, pairs, timeFacts, type Explainer, type Fact, type Tone } from './types';

// Field meanings from Microsoft's "Anti-spam message headers"
// (learn.microsoft.com/defender-office-365/message-headers-eop-mdo).
// Each row is labelled "Full Name (CODE)"; the value is the decoded meaning, the raw value is in its tooltip.

/** A decoded value: what it means, how good or bad, and a longer explanation. */
type Meaning = [value: string, tone: Tone, hint?: string];

/** One code from a header as a row: the decoded meaning when known, else the code itself. */
function coded(label: string, raw: string, meanings: Record<string, Meaning> | ((raw: string) => Meaning | undefined), extra: Partial<Fact> = {}): Fact {
    const known = typeof meanings === 'function' ? meanings(raw) : meanings[raw.toUpperCase()];
    if (!known) return { label, value: raw, mono: true, tone: 'muted', hint: 'Not documented by Microsoft.', ...extra };
    const [value, tone, hint] = known;
    return { label, value, tone, raw, ...extra, hint: [extra.hint, hint].filter(Boolean).join(' ') || undefined };
}

const SCL_HINT = "Microsoft's spam score. In Microsoft 365 it isn't the final decision: Policy Category (CAT) and Directionality (DIR) say how the message was actually filtered.";

export function scl(raw: string): Meaning | undefined {
    const n = parseInt(raw, 10);
    if (Number.isNaN(n)) return undefined;
    if (n === -1) return ['Skipped spam filtering', 'good', 'The message came from a trusted, internal or allow-listed sender.'];
    if (n <= 4) return ['Not spam', 'good'];
    if (n <= 6) return ['Spam', 'warn', 'Delivered to the Junk Email folder.'];
    return ['High-confidence spam', 'bad'];
}

function bcl(raw: string): Meaning | undefined {
    const n = parseInt(raw, 10);
    if (Number.isNaN(n)) return undefined;
    if (n === 0) return ['Not from a bulk sender', 'good'];
    if (n <= 3) return ['Bulk sender, few complaints', 'good'];
    if (n <= 7) return ['Bulk sender, mixed complaints', 'warn'];
    return ['Bulk sender, many complaints', 'bad'];
}

// PCL is no longer in Microsoft's documentation; the ranges are from its earlier versions.
const PCL_HINT = "Microsoft no longer documents PCL; this reading uses the ranges from its earlier documentation (0-3 not likely phishing, 4-8 likely).";

function pcl(raw: string): Meaning | undefined {
    const n = parseInt(raw, 10);
    if (Number.isNaN(n)) return undefined;
    return n <= 3 ? ['Not likely phishing', 'good', PCL_HINT] : ['Likely phishing', 'bad', PCL_HINT];
}

const SFV: Record<string, Meaning> = {
    BLK: ['Blocked', 'bad', "Filtering was skipped and the message blocked: the sender is on the recipient's Blocked Senders list."],
    NSPM: ['Not spam', 'good', 'Spam filtering found it was not spam and delivered it.'],
    SFE: ['Allowed', 'good', "Filtering was skipped: the sender is on the recipient's Safe Senders list."],
    SKA: ['Allowed by policy', 'good', 'Filtering was skipped: the sender is on an allowed senders or domains list in an anti-spam policy.'],
    SKB: ['Blocked by policy', 'bad', 'Marked spam: the sender is on a blocked senders or domains list in an anti-spam policy.'],
    SKI: ['Allowed by IP', 'good', 'Filtering was skipped: the source IP is on the connection filter IP Allow List.'],
    SKN: ['Allowed by mail flow rule', 'good', 'A mail flow (transport) rule bypassed spam filtering.'],
    SKQ: ['Released from quarantine', 'info', 'The message was released from quarantine and sent to the recipients.'],
    SKS: ['Marked spam by rule', 'bad', 'A mail flow rule or on-premises Exchange marked it spam before filtering.'],
    SPM: ['Spam', 'bad', 'Spam filtering marked it as spam.'],
};

const CAT: Record<string, Meaning> = {
    AMP: ['Anti-malware', 'bad'],
    BIMP: ['Brand impersonation', 'bad'],
    BULK: ['Bulk', 'warn'],
    DIMP: ['Domain impersonation', 'bad'],
    FTBP: ['Blocked attachment type', 'bad', 'The anti-malware common attachments filter.'],
    GIMP: ['Mailbox intelligence impersonation', 'bad'],
    HPHSH: ['High-confidence phishing', 'bad'],
    HPHISH: ['High-confidence phishing', 'bad'],
    HSPM: ['High-confidence spam', 'bad'],
    INTOS: ['Intra-organisation phishing', 'bad'],
    MALW: ['Malware', 'bad'],
    OSPM: ['Outbound spam', 'bad'],
    PHSH: ['Phishing', 'bad'],
    SAP: ['Safe Attachments', 'warn'],
    SPM: ['Spam', 'bad'],
    SPOOF: ['Spoofing', 'bad'],
    UIMP: ['User impersonation', 'bad'],
    NONE: ['None', 'good', 'No threat policy applied.'],
};

const DIR: Record<string, Meaning> = {
    INB: ['Inbound', 'info', 'From outside the organisation.'],
    OUT: ['Outbound', 'info', 'Leaving the organisation.'],
    INT: ['Internal', 'info', 'Between users of the same organisation.'],
};

const IPV: Record<string, Meaning> = {
    CAL: ['Allowed', 'good', 'Spam filtering was skipped: the source IP is on the IP Allow List.'],
    NLI: ['Not listed', 'good', "The IP address isn't on any IP reputation list."],
};

const SFTY: Record<string, Meaning> = {
    '9.19': ['Domain impersonation', 'warn', 'The sending domain imitates a protected domain; a safety tip was added.'],
    '9.20': ['User impersonation', 'warn', 'The sender imitates a user in the organisation or a protected user; a safety tip was added.'],
    '9.25': ['First contact', 'warn', 'The "You don\'t often get email from…" safety tip was shown.'],
};

const SRV: Record<string, Meaning> = {
    BULK: ['Bulk', 'warn', "Identified as bulk email by spam filtering and the Bulk Complaint Level (BCL) threshold. With the anti-spam policy's MarkAsSpamBulkMail setting on (the default), bulk mail is treated as spam."],
};

const SFP: Record<string, Meaning> = { '1102': ['High-confidence phishing', 'bad'] };

const RULE_IDS_HINT = "Ids of Microsoft's internal filter rules that matched. Microsoft doesn't publish what they mean; the same ids appear in X-Forefront-Antispam-Report (SFS), X-Microsoft-Antispam (ARA) and the mailbox delivery header (ENG).";

/**
 * Rule ids whose meaning was worked out by trial and error, not published by Microsoft.
 * From decode-spam-headers by Mariusz Banach (github.com/mgeeky/decode-spam-headers, MIT licence).
 */
const KNOWN_RULES: Record<string, string> = {
    '35100500006': 'Embedded image',
    '520007050': 'Moved to Junk by a rule the recipient created for this sender',
    '162623004': 'Suspicious words in the subject',
    '19618925003': 'Suspicious words in the body',
    '28233001': 'Call-to-action words in the subject ("Click here")',
    '30864003': 'Very long body (over about 10,000 characters)',
    '564344004': 'HTML body with little text (under about 150 words)',
    '67856001': 'HTML body uses underline (<u>)',
    '579124003': 'HTML body with no bold, italic or underline',
    '166002': 'HTML body contains a link',
    '21615005': 'A link with a query string (?a=b)',
    '45080400002': 'A link whose query string holds another URL (uncertain)',
    '460985005': 'A link to a dangerous file type, or complex HTML (uncertain)',
    '121216002': 'The first server relayed the message instead of originating it',
    '966005': 'Link text shows a different URL than the link goes to',
    '5002400100002': "The first server's reputation or reverse DNS (uncertain)",
    '58800400005': "The first server's reputation or reverse DNS (uncertain)",
    '19625305002': 'The HTML structure (uncertain)',
    '43540500002': 'The HTML structure (uncertain)',
    '22186003': 'Plain-text body, or domain impersonation (uncertain)',
    '42882007': 'No Reply-To address',
    '78352004': 'No Reply-To address',
};

const KNOWN_RULES_HINT = 'Not official: worked out by testing (decode-spam-headers by Mariusz Banach).';

/** "(13230040)(4022899009)" or "13230040|4022899009": a summary row, then one row per rule with its likely meaning. */
function ruleFacts(label: string, value: string): Fact[] {
    const ids = value.split(/[()|]+/).map((id) => id.trim()).filter(Boolean);
    const known = ids.filter((id) => KNOWN_RULES[id]).length;
    return [
        { label, value: `${ids.length} matched${known ? `, ${known} with a likely meaning` : ''}`, raw: value, hint: RULE_IDS_HINT },
        ...ids.map((id): Fact => (KNOWN_RULES[id] ? { label: 'Rule', value: `Probably: ${KNOWN_RULES[id]}`, raw: id, sub: true, hint: KNOWN_RULES_HINT } : { label: 'Rule', value: 'Unknown', raw: id, sub: true, tone: 'muted', hint: "Microsoft doesn't publish what this rule means." })),
    ];
}

/** X-Forefront-Antispam-Report: CIP:1.2.3.4;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:host;PTR:ptr;CAT:NONE;SFS:(…);DIR:INB; */
export const forefront: Explainer = (field) => {
    const facts: Fact[] = [];
    let verdict: string | null = null;
    for (const [key, value] of pairs(field.value, ';', /:/)) {
        const k = key.toUpperCase();
        if (!value) continue;
        switch (k) {
            case 'CIP':
                facts.push(...fact('Connecting IP (CIP)', value, { kind: 'ip', hint: 'The address that connected to Microsoft 365.' }));
                break;
            case 'CTRY':
                facts.push(...fact('Country/Region (CTRY)', value, { hint: 'Of the connecting IP, which may not be where the message started.' }));
                break;
            case 'LANG':
                facts.push(...fact('Language (LANG)', value, { hint: 'The language the message is written in.' }));
                break;
            case 'SCL':
                facts.push(coded('Spam Confidence Level (SCL)', value, scl, { hint: SCL_HINT }));
                break;
            case 'SRV':
                facts.push(coded('Service (SRV)', value, SRV));
                break;
            case 'IPV':
                facts.push(coded('IP Verdict (IPV)', value, IPV));
                break;
            case 'SFV': {
                const f = coded('Spam Filtering Verdict (SFV)', value, SFV);
                verdict = f.value;
                facts.push(f);
                break;
            }
            case 'H':
                facts.push(...fact('HELO/EHLO Name (H)', value, { kind: 'domain', hint: 'The name the connecting server introduced itself with.' }));
                break;
            case 'PTR':
                facts.push(...fact('PTR Record (PTR)', value, { kind: 'domain', hint: 'The reverse DNS name of the connecting IP.' }));
                break;
            case 'CAT':
                facts.push(coded('Category (CAT)', value, CAT, { hint: 'The threat policy that applied to the message.' }));
                break;
            case 'DIR':
                facts.push(coded('Directionality (DIR)', value, DIR));
                break;
            case 'SFTY':
                facts.push(coded('Safety Tip (SFTY)', value, (v) => SFTY[v]));
                break;
            case 'PCL':
                facts.push(coded('Phishing Confidence Level (PCL)', value, pcl));
                break;
            case 'SFP':
                facts.push(coded('Spoof Filter Policy (SFP)', value, SFP));
                break;
            case 'SFS':
            case 'RULEID':
                facts.push(...ruleFacts(`Spam Filter Rules (${k})`, value));
                break;
            case 'ARC':
                facts.push({ label: 'Authenticated Received Chain (ARC)', value, mono: true, hint: 'AAR: the DMARC authentication results; AMS and AS: signatures of the message and headers, with the chain validation result (cv=).' });
                break;
            default:
                facts.push({ label: key, value, mono: true, tone: 'muted', hint: 'Not documented by Microsoft: used by its anti-spam team for diagnostics.' });
        }
    }
    return { summary: verdict ? `Spam filtering verdict: ${verdict}.` : undefined, facts };
};

/** X-Microsoft-Antispam: BCL:0;ARA:13230040|4022899009; */
export const microsoftAntispam: Explainer = (field) => {
    const facts: Fact[] = [];
    for (const [key, value] of pairs(field.value, ';', /:/)) {
        const k = key.toUpperCase();
        if (!value) continue;
        if (k === 'BCL') facts.push(coded('Bulk Complaint Level (BCL)', value, bcl, { hint: 'How likely a bulk sender is to draw complaints; at or above the policy threshold (usually 7) mail goes to Junk.' }));
        else if (k === 'PCL') facts.push(coded('Phishing Confidence Level (PCL)', value, pcl));
        else if (k === 'ARA') facts.push(...ruleFacts('Anti-spam Rules Applied (ARA)', value));
        else facts.push({ label: key, value, mono: true, tone: 'muted', hint: 'Not documented by Microsoft: used by its anti-spam team for diagnostics.' });
    }
    const bulk = facts.find((f) => f.label.startsWith('Bulk'));
    return { summary: bulk ? `${bulk.value}.` : undefined, facts };
};

const DEST: Record<string, Meaning> = { I: ['Inbox', 'good'], J: ['Junk Email folder', 'warn'], D: ['Deleted Items', 'warn'], Q: ['Quarantine', 'bad'] };
const YES_NO: Record<string, Meaning> = { '0': ['No', 'muted'], '1': ['Yes', 'warn'] };

/** X-Microsoft-Antispam-Mailbox-Delivery: ucf:0;jmr:0;auth:0;dest:I;ENG:(…);OFR:… */
export const mailboxDelivery: Explainer = (field) => {
    const facts: Fact[] = [];
    let summary: string | undefined;
    for (const [key, value] of pairs(field.value, ';', /:/)) {
        const k = key.toLowerCase();
        if (!value) continue;
        if (k === 'dest') {
            const f = coded('Destination (dest)', value, DEST);
            summary = `Delivered to the ${f.value}.`;
            facts.push(f);
        } else if (k === 'ofr') {
            facts.push({ label: 'Override Reason (OFR)', value, hint: 'Why the folder differs from the spam verdict, e.g. a user rule (CustomRules) or Safe/Blocked Senders (TrustedListMatched).' });
        } else if (k === 'jmr') {
            facts.push(coded('Junk Mail Rule (jmr)', value, YES_NO, { hint: "Whether the recipient's own junk rule matched." }));
        } else if (k === 'eng') {
            facts.push(...ruleFacts('Delivery Engine Rules (ENG)', value));
        } else if (k === 'ucf') {
            facts.push(coded('User Custom Flow (ucf)', value, YES_NO, { tone: 'muted' }));
        } else {
            facts.push({ label: key, value, mono: true, tone: 'muted', hint: 'Not documented by Microsoft.' });
        }
    }
    return { summary, facts };
};

const AUTH_AS: Record<string, string> = {
    Anonymous: 'An unauthenticated sender from the internet.',
    Internal: 'A sender inside the same organisation.',
    Partner: 'A sender authenticated through a partner connector.',
    External: 'Authenticated, but from outside the organisation.',
};

export const authAs: Explainer = (field) => ({ facts: fact('Authenticated as', field.value.trim(), { hint: AUTH_AS[field.value.trim()] }) });

export const exchangeScl: Explainer = (field) => {
    const f = coded('Spam Confidence Level (SCL)', field.value.trim(), scl, { hint: SCL_HINT });
    return { facts: [f] };
};

export const exchangeTime: Explainer = (field) => {
    const date = parseDate(field.value);
    return date ? { facts: timeFacts('Arrived', date.time, date.offset) } : null;
};

const FROM_ENTITY: Record<string, string> = { Hosted: 'From a mailbox in Exchange Online.', Internet: 'From outside Microsoft 365.' };

export const fromEntity: Explainer = (field) => ({ facts: fact('Sender', field.value.trim(), { hint: FROM_ENTITY[field.value.trim()] }) });

const MAILBOX_TYPE: Record<string, string> = { HOSTED: 'An Exchange Online mailbox.', ONPREMISES: "A mailbox on the organisation's own Exchange server (hybrid)." };

export const mailboxType: Explainer = (field) => ({ facts: fact('Mailbox type', field.value.trim(), { hint: MAILBOX_TYPE[field.value.trim().toUpperCase()] }) });

/** Older tenants show the address; newer ones an encoded id. */
export const userPrincipalName: Explainer = (field) => {
    const v = field.value.trim();
    return { facts: v.includes('@') ? fact('Mailbox', v, { kind: 'email' }) : fact('Mailbox id', v, { mono: true, hint: "The recipient mailbox's sign-in name, encoded by Microsoft." }) };
};

export const tenantId: Explainer = (field) => ({
    facts: fact('Tenant id', field.value, { mono: true, hint: 'The Microsoft 365 organisation (Entra ID tenant) this copy of the message belongs to.' }),
});

const DIRECTION: Record<string, string> = { Incoming: 'From outside the organisation.', Originating: 'Sent by a user of this organisation.' };

export const directionality: Explainer = (field) => ({ facts: fact('Direction', field.value.trim(), { hint: DIRECTION[field.value.trim()] }) });

/** "ip=[203.0.113.5];domain=mail.example.com" */
function senderFacts(value: string, ipLabel: string, domainLabel: string, hint: string): Fact[] {
    const facts: Fact[] = [];
    for (const [key, raw] of pairs(value, ';', /=/)) {
        const v = raw.replace(/^\[|\]$/g, '').trim();
        if (key.toLowerCase() === 'ip') facts.push({ label: `${ipLabel} (ip)`, value: v, kind: 'ip', hint });
        else if (key.toLowerCase() === 'domain') facts.push({ label: `${domainLabel} (domain)`, value: v, kind: 'domain' });
        else if (v) facts.push({ label: key, value: v });
    }
    return facts;
}

/**
 * Enhanced Filtering for Connectors: when mail reaches Microsoft 365 through another gateway first
 * (Mimecast, Proofpoint…), this records the server that really sent it, before the gateway.
 */
export const externalOriginalSender: Explainer = (field) => {
    const facts = senderFacts(field.value, 'Original Sender IP', 'Original Sender Server', 'The server that handed the message to the first gateway: where it really came from, as recorded by Microsoft 365 Enhanced Filtering.');
    const ip = facts.find((f) => f.kind === 'ip')?.value;
    return { summary: ip ? `Before the gateway, the message came from ${ip}.` : undefined, facts, help: 'Enhanced Filtering for Connectors is on: the message reached Microsoft 365 through another gateway, and Microsoft looked past it to the original sender.' };
};

export const skipListedSender: Explainer = (field) => ({
    facts: senderFacts(field.value, 'Skipped Server IP', 'Skipped Server', 'A server Enhanced Filtering skipped over (a gateway in front of Microsoft 365) to find the original sender.'),
});

const TRUE = /^(true|yes|1)$/i;

export const MICROSOFT_FLAGS: Record<string, Explainer> = {
    'x-ms-exchange-externaloriginalinternetsender': externalOriginalSender,
    'x-ms-exchange-skiplistedinternetsender': skipListedSender,
    'x-ms-exchange-organization-bypassfocusedinbox': (field) => {
        const on = TRUE.test(field.value.trim());
        return { facts: [{ label: 'Bypass Focused Inbox', value: on ? 'Yes' : 'No', raw: field.value.trim(), hint: on ? 'Delivered to the main Inbox, not Other: an admin rule exempts it from Focused Inbox sorting.' : 'Focused Inbox may sort it into Other.' }] };
    },
    'x-ms-exchange-enablefirstcontactsafetytip': (field) => ({
        facts: [{ label: 'First Contact Safety Tip', value: TRUE.test(field.value.trim()) ? 'Enabled' : field.value.trim(), raw: field.value.trim(), hint: 'A custom mail flow rule turns on the "You don\'t often get email from…" tip for this message.' }],
    }),
};

export const hasAttach: Explainer = (field) => ({ facts: fact('Attachments', /^yes$/i.test(field.value.trim()) ? 'Yes' : 'No') });

export const MICROSOFT: Record<string, Explainer> = {
    'x-forefront-antispam-report': forefront,
    'x-forefront-antispam-report-untrusted': forefront,
    'x-microsoft-antispam': microsoftAntispam,
    'x-microsoft-antispam-untrusted': microsoftAntispam,
    'x-microsoft-antispam-mailbox-delivery': mailboxDelivery,
    'x-ms-exchange-organization-authas': authAs,
    'x-ms-exchange-organization-scl': exchangeScl,
    'x-ms-exchange-crosstenant-originalarrivaltime': exchangeTime,
    'x-ms-exchange-crosstenant-fromentityheader': fromEntity,
    'x-ms-exchange-crosstenant-mailboxtype': mailboxType,
    'x-ms-exchange-crosstenant-userprincipalname': userPrincipalName,
    'x-ms-exchange-crosstenant-authas': authAs,
    'x-ms-exchange-crosstenant-authsource': (field) => ({ facts: fact('Authenticated by', field.value.trim().toLowerCase(), { hint: 'The Exchange Online server that authenticated the sender.' }) }),
    'x-ms-exchange-crosstenant-network-message-id': (field) => ({ facts: fact('Network message id', field.value.trim(), { mono: true, hint: "Exchange Online's id for this message: what an admin searches message trace for." }) }),
    'x-ms-exchange-crosstenant-id': tenantId,
    'x-ms-exchange-organization-messagedirectionality': directionality,
    'x-ms-has-attach': hasAttach,
    ...MICROSOFT_FLAGS,
    'x-customspam': (field) => ({
        facts: [{ label: 'Advanced Spam Filter setting', value: field.value.trim(), tone: 'warn', hint: "An Advanced Spam Filter (ASF) option in the recipient organisation's anti-spam policy matched this message." }],
    }),
};

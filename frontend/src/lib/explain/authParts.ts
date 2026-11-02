import type { AuthResult } from '../auth';
import { verdictOf } from '../auth';
import { timeFacts, type Fact, type Tone } from './types';

// One line per part of an authentication header: what each property, comment
// and tag means. (The Authentication tab goes further and re-checks them live.)

export function verdictTone(result: string): Tone {
    const v = verdictOf(result);
    return v === 'pass' ? 'good' : v === 'fail' ? 'bad' : v === 'softfail' || v === 'error' ? 'warn' : 'muted';
}

const RESULTS: Record<string, Record<string, string>> = {
    spf: {
        pass: "the sending server's IP is allowed by the domain's SPF record",
        fail: 'the domain says this IP may NOT send for it',
        softfail: "the domain says this IP probably isn't allowed (~all)",
        neutral: 'the domain makes no claim about this IP',
        none: 'the domain has no SPF record',
        temperror: 'a temporary DNS error stopped the check',
        permerror: "the domain's SPF record is broken",
    },
    dkim: {
        pass: "the signature is valid: the signed content wasn't changed",
        fail: "the signature doesn't verify: content changed after signing, or a fake signature",
        none: 'the message is not signed',
        neutral: "the signature couldn't be evaluated",
        policy: 'valid, but not acceptable under local policy (e.g. weak key)',
        temperror: 'a temporary error (usually DNS) stopped the check',
        permerror: 'the signature or its key is malformed',
    },
    dmarc: {
        pass: 'SPF or DKIM passed for a domain matching the From address',
        fail: 'neither SPF nor DKIM passed for a domain matching From',
        none: 'the From domain publishes no DMARC policy',
        bestguesspass: "no DMARC record, but it would have passed if there were one",
        temperror: 'a temporary error stopped the check',
        permerror: 'the DMARC record is malformed',
    },
    arc: {
        pass: 'the ARC chain from earlier forwarders is intact',
        fail: 'the ARC chain is broken',
        none: 'no ARC headers',
    },
    'dkim-atps': {
        pass: 'the From domain has authorised this third-party signer',
        fail: 'the third-party signer is not authorised by the From domain',
        neutral: "not applicable: usually because the signer is the From domain itself",
        none: 'no third-party authorisation was published',
    },
    compauth: {
        pass: "Microsoft's composite authentication passed",
        fail: 'Microsoft treated the sender as spoofed',
        softpass: "no explicit authentication, but Microsoft's heuristics trust it",
        none: 'not evaluated',
    },
    iprev: {
        pass: "the sending IP's reverse DNS name resolves back to it",
        fail: "the sending IP's reverse DNS doesn't match",
        temperror: 'a temporary DNS error stopped the check',
        permerror: 'the sending IP has no reverse DNS',
    },
    auth: {
        pass: 'the sender logged in to the mail server (SMTP AUTH)',
        fail: 'the login failed',
        none: 'the sender did not log in',
    },
    bimi: {
        pass: "the sender's brand logo was found and is valid",
        none: 'no brand logo (BIMI) record',
        fail: "the brand logo record couldn't be validated",
        skipped: 'not checked (usually because DMARC policy is too weak)',
    },
};

const METHODS: Record<string, string> = {
    spf: 'Sender Policy Framework (SPF)',
    dkim: 'DomainKeys Identified Mail (DKIM)',
    dmarc: 'Domain-based Message Authentication, Reporting & Conformance (DMARC)',
    arc: 'Authenticated Received Chain (ARC)',
    'dkim-atps': 'DKIM Authorized Third-Party Signatures (dkim-atps)',
    compauth: 'Composite Authentication (compauth)',
    iprev: 'IP Reverse DNS (iprev)',
    auth: 'SMTP Authentication (auth)',
    bimi: 'Brand Indicators for Message Identification (BIMI)',
    'x-google-dkim': 'Google Internal DKIM (x-google-dkim)',
};

/** Result keywords as words. */
const RESULT_WORDS: Record<string, string> = {
    pass: 'Pass',
    fail: 'Fail',
    softfail: 'Soft fail',
    softpass: 'Soft pass',
    neutral: 'Neutral',
    none: 'None',
    policy: 'Policy',
    temperror: 'Temporary error',
    permerror: 'Permanent error',
    bestguesspass: 'Best-guess pass',
    skipped: 'Skipped',
};

export const resultWord = (result: string) => RESULT_WORDS[result.toLowerCase()] ?? result;

/** [label, explanation, decode] for each property (ptype.property=value). */
const PROPS: Record<string, [string, string, ((v: string) => string | undefined)?]> = {
    'smtp.mailfrom': ['Envelope Sender', 'The MAIL FROM address or domain that SPF checked; bounces go here.'],
    'smtp.helo': ['HELO Name', 'The name the sending server introduced itself with.'],
    'smtp.remote-ip': ['Sending IP', 'The address of the server that connected.'],
    'smtp.auth': ['Logged-in User', 'The account the sender logged in with.'],
    'header.from': ['From Domain', 'The domain in the From address, which DMARC protects.'],
    'header.d': ['Signing Domain', 'The domain that made the DKIM signature; its public key is looked up in DNS.'],
    'header.i': ['Signing Identity', 'The user or domain the signer says it signed on behalf of.'],
    'header.s': ['Selector', "Which of the domain's keys was used: published at <selector>._domainkey.<domain>."],
    'header.a': ['Algorithm', 'How the signature was made.', (v) => (v.startsWith('ed25519') ? 'Ed25519 with SHA-256' : v.endsWith('sha1') ? 'RSA with SHA-1 (obsolete)' : v.endsWith('sha256') ? 'RSA with SHA-256' : undefined)],
    'header.b': ['Signature Prefix', 'The first characters of the signature, to tell several signatures apart.'],
    'header.reasons': ['Reasons', "The receiver's internal reason codes."],
    'policy.iprev': ['IP Checked', 'The address whose reverse DNS was checked.'],
    'policy.dmarc': ['Policy Applied', 'What the DMARC policy told the receiver to do.'],
    'policy.published-domain-policy': ['Published Policy', "The From domain's DMARC policy (p=)."],
    'policy.applied-disposition': ['Action Taken', 'What the receiver actually did with the message.'],
    'policy.evaluated-disposition': ['Policy Result', 'What the policy would have done.'],
    'policy.authority': ['BIMI Authority', "The brand's verified mark certificate."],
    action: [
        'Action',
        'What the spam filter did based on the DMARC result.',
        (v) =>
            (
                {
                    none: 'Delivered normally',
                    quarantine: 'Quarantined',
                    reject: 'Rejected',
                    oreject: 'Delivered to Junk instead of rejected',
                    'pct.quarantine': 'Delivered anyway (pct below 100%)',
                    'pct.reject': 'Delivered anyway (pct below 100%)',
                    permerror: 'Permanent error in the DMARC check',
                    temperror: 'Temporary error in the DMARC check',
                } as Record<string, string>
            )[v.toLowerCase()],
    ],
};

/** Properties that hold a domain or address, so they link like everywhere else. */
const PROP_KIND: Record<string, Fact['kind']> = { 'header.from': 'domain', 'header.d': 'domain', 'smtp.helo': 'domain', 'policy.iprev': 'ip', 'smtp.remote-ip': 'ip' };

/** compauth reason codes, from Microsoft's "Anti-spam message headers". */
const COMPAUTH_REASONS: Record<string, string> = {
    '000': 'Failed DMARC, and the domain asks for quarantine or reject',
    '001': 'Failed implicit authentication: no authentication records, or only weak ones',
    '002': 'The organisation blocks this sender/domain pair from sending spoofed mail',
    '010': 'Failed DMARC, from one of your own accepted domains',
    '100': 'SPF or DKIM passed, aligned with the From domain',
    '101': 'DKIM-signed by the From domain',
    '102': 'SPF passed and the envelope sender matches the From domain',
    '103': "The From domain matches the sending IP's reverse DNS",
    '104': "The sending IP's reverse DNS matches the From domain",
    '108': 'DKIM failed only because an earlier legitimate hop changed the body',
    '109': 'No DMARC record, but it would have passed',
    '111': 'DMARC errored, but SPF or DKIM is aligned with the From domain',
    '112': 'A DNS timeout prevented fetching the DMARC record',
    '115': 'Sent from a Microsoft 365 organisation that owns the From domain',
    '116': "The From domain's MX matches the sending IP's reverse DNS",
    '130': 'A trusted ARC sealer overrode the DMARC failure',
    '201': "The From domain's PTR matches the sending IP's subnet",
    '202': "The From domain matches the sending IP's reverse DNS domain",
    '501': 'DMARC not enforced: a valid bounce for an established conversation',
    '502': 'DMARC not enforced: a valid bounce for a message this organisation sent',
    '601': 'Spoofs one of your own accepted domains',
    '905': 'DMARC not enforced because of complex routing (e.g. through on-premises Exchange)',
};

function compauthReason(code: string): string | undefined {
    const c = code.trim();
    if (COMPAUTH_REASONS[c]) return COMPAUTH_REASONS[c];
    if (/^70[1-4]$/.test(c)) return 'DMARC not enforced: this organisation has a history of legitimate mail from this sender';
    if (/^1\d\d$/.test(c) || /^7\d\d$/.test(c)) return 'Passed authentication';
    if (/^2\d\d$/.test(c)) return 'Soft-passed implicit authentication';
    if (/^3\d\d$/.test(c)) return 'Not checked';
    if (/^[49]\d\d$/.test(c)) return 'Bypassed composite authentication';
    if (/^6\d\d$/.test(c)) return 'Failed implicit authentication';
    return undefined;
}

const DMARC_POLICY: Record<string, string> = { none: 'None (monitor only)', quarantine: 'Quarantine (spam folder)', reject: 'Reject' };

/** "p=REJECT sp=REJECT dis=NONE" (DMARC), "2048-bit key; unprotected" (DKIM), or free text. */
function commentFacts(method: string, comment: string): Fact[] {
    const facts: Fact[] = [];
    if (method === 'dmarc' && /\b(p|dis|sp|pct)=/i.test(comment)) {
        for (const [, key, raw] of comment.matchAll(/\b(\w+)=(\S+)/g)) {
            const v = raw.toLowerCase();
            const k = key.toLowerCase();
            if (k === 'p') facts.push(sub('Published Policy (p)', DMARC_POLICY[v] ?? raw, raw, 'What the From domain asks receivers to do with mail that fails DMARC.'));
            else if (k === 'sp') facts.push(sub('Subdomain Policy (sp)', DMARC_POLICY[v] ?? raw, raw, 'The same, for subdomains.'));
            else if (k === 'dis') facts.push(sub('Disposition (dis)', v === 'none' ? 'Delivered normally' : DMARC_POLICY[v] ?? raw, raw, 'What this receiver actually did.'));
            else if (k === 'pct') facts.push(sub('Percentage (pct)', `${raw}% of failing mail`, raw, 'The share of failing mail the policy applies to.'));
            else facts.push(sub(k, raw));
        }
        return facts;
    }
    for (const part of comment.split(/;\s*/).map((p) => p.trim()).filter(Boolean)) {
        const bits = /^(\d+)-bit key$/i.exec(part);
        if (bits) facts.push({ ...sub('Key Size', `${bits[1]} bits`, part, 'The size of the public key.'), tone: parseInt(bits[1], 10) < 1024 ? 'bad' : undefined });
        else if (/^unprotected$/i.test(part)) facts.push(sub('Key DNS', 'Not DNSSEC-signed', part, 'Normal for most domains.'));
        else if (/^secure$/i.test(part)) facts.push(sub('Key DNS', 'DNSSEC-signed', part));
        else facts.push(sub('Note', part));
    }
    return facts;
}

/** A part of the result above: indented, the decoded value shown and the raw one in the tooltip. */
function sub(label: string, value: string, raw?: string, hint?: string, extra: Partial<Fact> = {}): Fact {
    return { label, value, sub: true, ...(raw !== undefined ? { raw } : {}), ...(hint ? { hint } : {}), ...extra };
}

/** One result (e.g. "dkim=pass header.d=… header.b=…") as a headline plus one line per part. */
export function resultFacts(r: AuthResult): Fact[] {
    const facts: Fact[] = [
        {
            label: METHODS[r.method] ?? r.method,
            value: resultWord(r.result),
            raw: r.result,
            hint: RESULTS[r.method]?.[r.result],
            tone: r.method === 'compauth' && r.result === 'softpass' ? 'good' : r.method === 'dkim-atps' ? 'muted' : verdictTone(r.result),
        },
    ];
    for (const [key, value] of Object.entries(r.props)) {
        const known = PROPS[key];
        const decoded = known?.[2]?.(value);
        const kind = PROP_KIND[key] ?? (key === 'smtp.mailfrom' ? (value.includes('@') ? 'email' : 'domain') : undefined);
        facts.push(sub(known ? `${known[0]} (${key})` : key, decoded ?? value, decoded ? value : undefined, known?.[1], kind ? { kind } : {}));
    }
    if (r.reason) {
        const decoded = r.method === 'compauth' ? compauthReason(r.reason) : undefined;
        facts.push(sub('Reason (reason)', decoded ?? r.reason, decoded ? r.reason : undefined, r.method === 'compauth' ? 'Why composite authentication passed or failed.' : undefined));
    }
    if (r.comment) facts.push(...commentFacts(r.method, r.comment));
    return facts;
}

/** Received-SPF key=value pairs (RFC 7208 §9.1). */
const RECEIVED_SPF: Record<string, [string, string, Record<string, string>?]> = {
    'client-ip': ['Sending IP', 'The address of the server that connected.'],
    'envelope-from': ['Envelope Sender', 'The MAIL FROM address.'],
    helo: ['HELO Name', 'The name the server introduced itself with.'],
    receiver: ['Receiver', 'The server that did the check.'],
    identity: ['Identity', 'Which name SPF checked.', { mailfrom: 'Envelope sender', helo: 'HELO name' }],
    mechanism: ['Mechanism', 'The part of the SPF record that matched.'],
    problem: ['Problem', 'What went wrong.'],
    'x-sender': ['Sender', 'The sender address.'],
};

const RECEIVED_SPF_KIND: Record<string, Fact['kind']> = { 'client-ip': 'ip', 'envelope-from': 'email', helo: 'domain', receiver: 'domain' };

export function receivedSpfFacts(props: Record<string, string>): Fact[] {
    return Object.entries(props)
        .filter(([key, value]) => !(key === 'receiver' && /^<?unknown>?$/i.test(value)))
        .map(([key, value]) => {
            const known = RECEIVED_SPF[key];
            const decoded = known?.[2]?.[value.toLowerCase()];
            const kind = RECEIVED_SPF_KIND[key];
            return sub(known ? `${known[0]} (${key})` : key, decoded ?? value, decoded ? value : undefined, known?.[1], kind && !(kind === 'email' && !value.includes('@')) ? { kind } : {});
        });
}

/** "relaxed/simple" => "Headers relaxed, body simple". */
function canonicalization(v: string): string {
    const [h = 'simple', b = 'simple'] = v.toLowerCase().split('/');
    return `Headers ${h}, body ${b}`;
}

function algorithm(v: string): string | undefined {
    const a = v.toLowerCase();
    if (a.startsWith('ed25519')) return 'Ed25519 with SHA-256';
    if (a === 'rsa-sha256') return 'RSA with SHA-256';
    if (a === 'rsa-sha1') return 'RSA with SHA-1';
    return undefined;
}

const CHAIN: Record<string, string> = {
    none: 'This is the first hop: there was no earlier chain.',
    pass: 'The ARC chain before this hop was intact.',
    fail: 'The ARC chain before this hop was broken.',
};

/**
 * DKIM-Signature / ARC-Message-Signature / ARC-Seal tags (RFC 6376 §3.5, RFC 8617), one row each in the
 * order written: "Name (tag)", the friendly value, and the tag's raw value in the tooltip.
 */
export function dkimTagFacts(tags: Record<string, string>): Fact[] {
    const facts: Fact[] = [];
    for (const [tag, raw] of Object.entries(tags)) {
        const row = (name: string, value: string, hint: string, extra: Partial<Fact> = {}) => facts.push({ label: `${name} (${tag})`, value, raw, hint, ...extra });
        switch (tag) {
            case 'v':
                row('Version', raw, 'Always 1.');
                break;
            case 'a': {
                const sha1 = raw.toLowerCase().endsWith('sha1');
                row('Algorithm', algorithm(raw) ?? raw, sha1 ? 'How the signature was made. SHA-1 is obsolete and rejected by many receivers.' : 'How the signature was made.', sha1 ? { tone: 'warn' } : {});
                break;
            }
            case 'c':
                row('Canonicalization', canonicalization(raw), 'How strictly the content must match: relaxed tolerates whitespace changes, simple breaks on any change.');
                break;
            case 'd':
                row('Signing Domain', raw, 'The domain that signed, and whose public key verifies it.', { kind: 'domain' });
                break;
            case 's':
                row('Selector', raw, `Which of the domain's keys: published at ${raw}._domainkey.${tags.d ?? '<domain>'}.`);
                break;
            case 'i':
                // ARC uses i= for the hop number; DKIM for the identity signed on behalf of.
                if (/^\d+$/.test(raw)) row('Instance', `Hop ${raw}`, 'Which ARC hop this is.');
                else row('Identity', raw, 'The user or domain the signer signed on behalf of.', raw.includes('@') && !raw.startsWith('@') ? { kind: 'email' } : {});
                break;
            case 'q':
                row('Query Method', raw.toLowerCase() === 'dns/txt' ? 'DNS TXT record' : raw, 'Where the public key is looked up.');
                break;
            case 'l':
                row('Body Length', `First ${raw} bytes of the body`, 'Only this much of the body is signed: anything appended later still passes.', { tone: 'warn' });
                break;
            case 't':
            case 'x': {
                const seconds = parseInt(raw, 10);
                if (!/^\d+$/.test(raw)) row(tag === 't' ? 'Signed At' : 'Expires', raw, '');
                else {
                    const [first, ...rest] = timeFacts(`${tag === 't' ? 'Signed At' : 'Expires'} (${tag})`, seconds * 1000);
                    facts.push({ ...first, raw, hint: tag === 't' ? 'When the signature was made.' : 'After this time the signature should be ignored.' }, ...rest);
                }
                break;
            }
            case 'h':
                row('Signed Headers', raw.split(':').map((h) => h.trim()).filter(Boolean).join(', '), 'The headers the signature covers.');
                break;
            case 'z':
                row('Copied Headers', raw, 'Copies of the original headers, for debugging.', { mono: true });
                break;
            case 'bh':
                facts.push({ label: 'Body Hash (bh)', value: raw, mono: true, hint: 'A fingerprint of the body: any change to the body changes it.' });
                break;
            case 'b':
                facts.push({ label: 'Signature (b)', value: raw.length > 44 ? `${raw.slice(0, 40)}…` : raw, mono: true, hint: 'The signature itself, over the headers and the body hash. The full value is under Raw header.' });
                break;
            case 'cv':
                row('Chain Validation', resultWord(raw), CHAIN[raw.toLowerCase()] ?? '', { tone: raw.toLowerCase() === 'fail' ? 'bad' : raw.toLowerCase() === 'pass' ? 'good' : undefined });
                break;
            default:
                facts.push({ label: tag, value: raw, mono: true, tone: 'muted', hint: 'Not a standard tag.' });
        }
    }
    return facts;
}

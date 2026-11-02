import { domainOf, parseAddressList } from './address';
import { findHeader, findHeaders, splitTopLevel, stripComments, type HeaderField } from './message';
import { extractIp } from './received';

// ------------------------------------------------- Authentication-Results

export interface AuthResult {
    /** spf, dkim, dmarc, arc, compauth, auth, iprev, bimi… */
    method: string;
    result: string;
    reason: string | null;
    comment: string | null;
    /** "smtp.mailfrom" => "example.com", "header.d" => "example.com", "action" => "none" */
    props: Record<string, string>;
    raw: string;
}

export interface AuthResults {
    /** The server that did the checks, e.g. "mx.google.com". */
    authservId: string;
    /** ARC instance (i=) for ARC-Authentication-Results. */
    instance: number | null;
    results: AuthResult[];
    header: HeaderField;
}

/** RFC 8601: "authserv-id; method=result reason=… ptype.prop=value; …" */
export function parseAuthResults(header: HeaderField): AuthResults {
    const segments = splitTopLevel(header.value, ';').map((s) => s.trim()).filter(Boolean);
    let instance: number | null = null;
    const arc = /^i=(\d+)$/i.exec(segments[0] ?? '');
    if (arc) {
        instance = parseInt(arc[1], 10);
        segments.shift();
    }
    // Exchange Online leaves the authserv-id out ("spf=pass (…) smtp.mailfrom=…; dkim=…"),
    // and some servers forget the ";" after it.
    const head = segments.shift() ?? '';
    const [first = '', ...rest] = stripComments(head).text.trim().split(/\s+/);
    let authservId = first;
    if (first.includes('=')) {
        authservId = '';
        segments.unshift(head);
    } else if (rest.some((word) => word.includes('='))) {
        segments.unshift(head.slice(head.indexOf(first) + first.length));
    }

    const results: AuthResult[] = [];
    for (const segment of segments) {
        const result = parseResult(segment);
        if (result) results.push(result);
    }
    return { authservId, instance, results, header };
}

function parseResult(segment: string): AuthResult | null {
    const { text, comments } = stripComments(segment);
    const pairs = [...text.matchAll(/([\w.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;]*)/g)];
    if (!pairs.length) return null;
    const [, methodWithVersion, result] = pairs[0];
    const props: Record<string, string> = {};
    let reason: string | null = null;
    for (const [, key, value] of pairs.slice(1)) {
        const clean = value.replace(/^"|"$/g, '');
        if (key.toLowerCase() === 'reason') reason = clean;
        else props[key.toLowerCase()] = clean;
    }
    return {
        method: methodWithVersion.replace(/\/\d+$/, '').toLowerCase(),
        result: result.replace(/^"|"$/g, '').toLowerCase(),
        reason,
        comment: comments.join('; ') || null,
        props,
        raw: segment,
    };
}

// ------------------------------------------------------- Received-SPF

export interface ReceivedSpf {
    result: string;
    comment: string | null;
    props: Record<string, string>;
}

/** RFC 7208 §9.1: "Pass (mx.example.org: domain of a@b designates 1.2.3.4 as permitted sender) client-ip=1.2.3.4; …" */
export function parseReceivedSpf(value: string): ReceivedSpf {
    const { text, comments } = stripComments(value);
    const result = (/^\s*(\w+)/.exec(text)?.[1] ?? 'none').toLowerCase();
    const props: Record<string, string> = {};
    for (const [, key, val] of text.matchAll(/([\w-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;]*)/g)) {
        props[key.toLowerCase()] = val.replace(/^"|"$/g, '');
    }
    return { result, comment: comments[0] ?? null, props };
}

// ------------------------------------------------- DKIM / ARC tag lists

/** "v=1; a=rsa-sha256; d=example.com; …" => { v: "1", a: "rsa-sha256", d: "example.com" } */
export function parseTagList(value: string): Record<string, string> {
    const tags: Record<string, string> = {};
    for (const part of value.split(';')) {
        const eq = part.indexOf('=');
        if (eq < 0) continue;
        const key = part.slice(0, eq).trim().toLowerCase();
        let tagValue = part.slice(eq + 1).trim();
        // Base64 and header lists may be folded with whitespace anywhere.
        if (['b', 'bh', 'h'].includes(key)) tagValue = tagValue.replace(/\s+/g, '');
        if (key) tags[key] = tagValue;
    }
    return tags;
}

export interface DkimSignature {
    tags: Record<string, string>;
    domain: string | null;
    selector: string | null;
    algorithm: string | null;
    signedHeaders: string[];
    /** Signature timestamp (t=) and expiry (x=), ms since epoch. */
    signedAt: number | null;
    expiresAt: number | null;
    header: HeaderField;
}

export function parseDkimSignature(header: HeaderField): DkimSignature {
    const tags = parseTagList(header.value);
    const seconds = (v: string | undefined) => (v && /^\d+$/.test(v) ? parseInt(v, 10) * 1000 : null);
    return {
        tags,
        domain: tags.d?.toLowerCase() ?? null,
        selector: tags.s ?? null,
        algorithm: tags.a?.toLowerCase() ?? null,
        signedHeaders: (tags.h ?? '').split(':').map((h) => h.trim().toLowerCase()).filter(Boolean),
        signedAt: seconds(tags.t),
        expiresAt: seconds(tags.x),
        header,
    };
}

export interface ArcSet {
    instance: number;
    seal: Record<string, string> | null;
    signature: DkimSignature | null;
    results: AuthResults | null;
}

/** ARC (RFC 8617): each forwarding hop adds a numbered set of three headers. */
export function parseArc(headers: HeaderField[]): ArcSet[] {
    const sets = new Map<number, ArcSet>();
    const set = (i: number) => {
        let s = sets.get(i);
        if (!s) sets.set(i, (s = { instance: i, seal: null, signature: null, results: null }));
        return s;
    };
    for (const h of headers) {
        if (h.key === 'arc-seal') {
            const tags = parseTagList(h.value);
            set(parseInt(tags.i ?? '0', 10)).seal = tags;
        } else if (h.key === 'arc-message-signature') {
            const sig = parseDkimSignature(h);
            set(parseInt(sig.tags.i ?? '0', 10)).signature = sig;
        } else if (h.key === 'arc-authentication-results') {
            const results = parseAuthResults(h);
            set(results.instance ?? 0).results = results;
        }
    }
    return [...sets.values()].sort((a, b) => a.instance - b.instance);
}

// ------------------------------------------------------------ Alignment

/**
 * Second-level registrations that act like top-level domains. Not the full
 * Public Suffix List; enough to get alignment right for common cases.
 */
const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz', 'govt.nz',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
    'com.br', 'net.br', 'org.br', 'gov.br', 'com.mx', 'org.mx', 'gob.mx', 'com.ar', 'com.co', 'com.tr', 'com.cn', 'net.cn', 'org.cn',
    'com.hk', 'com.sg', 'com.my', 'com.ph', 'co.za', 'org.za', 'co.il', 'org.il', 'ac.il', 'co.id', 'or.id', 'com.tw', 'com.ua',
    'co.th', 'in.th', 'com.vn', 'com.pk', 'com.eg', 'com.sa', 'com.pl', 'co.at', 'or.at', 'gv.at',
]);

/** "mail.news.example.co.uk" => "example.co.uk" (approximate organisational domain, RFC 7489 §3.2). */
export function organizationalDomain(domain: string): string {
    const labels = domain.toLowerCase().replace(/\.$/, '').split('.');
    if (labels.length <= 2) return labels.join('.');
    const lastTwo = labels.slice(-2).join('.');
    return labels.slice(MULTI_PART_SUFFIXES.has(lastTwo) ? -3 : -2).join('.');
}

export function aligned(a: string | null, b: string | null, strict = false): boolean {
    if (!a || !b) return false;
    const x = a.toLowerCase().replace(/\.$/, '');
    const y = b.toLowerCase().replace(/\.$/, '');
    return strict ? x === y : organizationalDomain(x) === organizationalDomain(y);
}

// -------------------------------------------------------------- Summary

export type Verdict = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'error' | 'unknown';

/** Where a verdict came from: the receiving server's own check, or one recorded by an earlier server. */
export interface VerdictSource {
    /** The server that did the check (authserv-id), e.g. "mx.google.com". */
    server: string | null;
    /** Set when the result came from an ARC-Authentication-Results header (its instance i=). */
    arc: number | null;
    /** From X-Original-Authentication-Results (kept by a gateway that re-checked). */
    original: boolean;
    /** Not in the headers: this page checked it just now, against today's DNS. */
    live?: boolean;
}

export interface AuthSummary {
    /** The receiving server's own Authentication-Results (topmost), and any others. */
    results: AuthResults[];
    receivedSpf: (ReceivedSpf & { header: HeaderField })[];
    dkim: DkimSignature[];
    arc: ArcSet[];
    fromDomain: string | null;
    envelopeDomain: string | null;
    /**
     * aligned: the check passed for a domain matching From (what DMARC counts).
     * domainMatches: the domain matches From, whether or not the check passed.
     */
    spf: { verdict: Verdict; domain: string | null; ip: string | null; aligned: boolean; domainMatches: boolean; source: VerdictSource | null };
    dkimVerdict: { verdict: Verdict; domains: string[]; failed: string[]; aligned: boolean; domainMatches: boolean; source: VerdictSource | null };
    dmarc: { verdict: Verdict; policy: string | null; source: VerdictSource | null };
}

export function verdictOf(result: string | null | undefined): Verdict {
    switch ((result ?? '').toLowerCase()) {
        case 'pass':
        case 'bestguesspass':
            return 'pass';
        case 'fail':
        case 'hardfail':
            return 'fail';
        case 'softfail':
            return 'softfail';
        case 'neutral':
        case 'policy':
            return 'neutral';
        case 'none':
            return 'none';
        case 'temperror':
        case 'permerror':
        case 'error':
            return 'error';
        default:
            return 'unknown';
    }
}

export function summarizeAuth(headers: HeaderField[]): AuthSummary {
    const results = findHeaders(headers, 'authentication-results').map(parseAuthResults);
    const receivedSpf = findHeaders(headers, 'received-spf').map((h) => ({ ...parseReceivedSpf(h.value), header: h }));
    const dkim = findHeaders(headers, 'dkim-signature').map(parseDkimSignature);
    const arc = parseArc(headers);

    const from = findHeader(headers, 'from');
    const fromDomain = from ? (parseAddressList(from.decoded)[0]?.domain ?? null) : null;
    const returnPath = findHeader(headers, 'return-path');
    const envelopeDomain = domainOf(returnPath?.value);

    // Where to look, most trustworthy first: the receiving server's own results (topmost
    // first), then those recorded in ARC by the servers before it (newest hop first),
    // then results a gateway preserved before re-checking.
    const sources: { results: AuthResult[]; source: VerdictSource }[] = [
        ...results.map((r) => ({ results: r.results, source: { server: r.authservId || null, arc: null, original: false } })),
        ...arc
            .filter((set) => set.results)
            .sort((a, b) => b.instance - a.instance)
            .map((set) => ({ results: set.results!.results, source: { server: set.results!.authservId || set.seal?.d || null, arc: set.instance, original: false } })),
        ...findHeaders(headers, 'x-original-authentication-results')
            .map(parseAuthResults)
            .map((r) => ({ results: r.results, source: { server: r.authservId || null, arc: null, original: true } })),
    ];
    const pick = (method: string) => {
        for (const { results: list, source } of sources) {
            const found = list.filter((x) => x.method === method);
            if (found.length) return { found, source };
        }
        return null;
    };

    // ---- SPF: is the sending server's IP allowed to send for the envelope sender's domain?
    const spfPick = pick('spf');
    const spfResult = spfPick?.found[0] ?? null;
    const spfFallback = receivedSpf[0];
    const mailfrom = spfResult?.props['smtp.mailfrom'];
    const spfDomain = (mailfrom ? (domainOf(mailfrom) ?? mailfrom.toLowerCase()) : null) ?? (spfFallback ? (domainOf(spfFallback.props['envelope-from']) ?? domainOf(`@${spfFallback.props.helo ?? ''}`)) : null) ?? envelopeDomain;
    const spfVerdict = spfResult ? verdictOf(spfResult.result) : spfFallback ? verdictOf(spfFallback.result) : 'unknown';
    const spfIp = spfResult?.props['smtp.remote-ip'] ?? (spfResult?.comment ? extractIp(spfResult.comment) : null) ?? spfFallback?.props['client-ip'] ?? (spfFallback?.comment ? extractIp(spfFallback.comment) : null);
    const spfMatches = aligned(spfDomain, fromDomain);

    // ---- DKIM: which domains signed it, and did their signatures hold up?
    const dkimPick = pick('dkim');
    // header.i is usually "@example.com", but some receivers (Zoho) write a bare "example.com".
    const dkimDomain = (r: AuthResult) => r.props['header.d'] ?? domainOf(r.props['header.i']) ?? (r.props['header.i']?.includes('.') ? r.props['header.i'].toLowerCase() : null);
    const passing = (dkimPick?.found ?? []).filter((r) => verdictOf(r.result) === 'pass');
    const failing = (dkimPick?.found ?? []).filter((r) => verdictOf(r.result) === 'fail');
    const signers = [...new Set((passing.length ? passing.map(dkimDomain) : dkim.map((d) => d.domain)).filter((d): d is string => !!d))];
    const dkimVerdict: Verdict = dkimPick ? (passing.length ? 'pass' : verdictOf(dkimPick.found[0].result)) : dkim.length ? 'unknown' : 'none';
    const dkimMatches = signers.some((d) => aligned(d, fromDomain));

    // ---- DMARC: did SPF or DKIM pass for the From domain?
    const dmarcPick = pick('dmarc');
    const dmarcResult = dmarcPick?.found[0] ?? null;
    const policy = dmarcResult ? (/\bp=(\w+)/i.exec(dmarcResult.comment ?? '')?.[1] ?? dmarcResult.props['policy.published-domain-policy'] ?? null) : null;

    return {
        results,
        receivedSpf,
        dkim,
        arc,
        fromDomain,
        envelopeDomain,
        spf: {
            verdict: spfVerdict,
            domain: spfDomain,
            ip: spfIp ?? null,
            aligned: spfVerdict === 'pass' && spfMatches,
            domainMatches: spfMatches,
            // Received-SPF names its checker in receiver= or at the start of its comment ("mx.example.org: domain of …").
            source: spfPick?.source ?? (spfFallback ? { server: (spfFallback.props.receiver && !/^<?unknown>?$/i.test(spfFallback.props.receiver) ? spfFallback.props.receiver : null) ?? /^([\w.-]+\.[a-z]{2,}):/i.exec(spfFallback.comment ?? '')?.[1] ?? null, arc: null, original: false } : null),
        },
        dkimVerdict: {
            verdict: dkimVerdict,
            domains: signers,
            failed: [...new Set(failing.map(dkimDomain).filter((d): d is string => !!d))],
            aligned: dkimVerdict === 'pass' && dkimMatches,
            domainMatches: dkimMatches,
            source: dkimPick?.source ?? null,
        },
        dmarc: {
            verdict: dmarcResult ? verdictOf(dmarcResult.result) : 'unknown',
            policy: policy?.toLowerCase() ?? null,
            source: dmarcPick?.source ?? null,
        },
    };
}

/** "mx.google.com", "mx.google.com (via ARC, hop 2)", "the receiving server" */
export function sourceLabel(source: VerdictSource | null): string {
    if (!source) return 'nobody';
    if (source.live) return 'this page, just now (no server recorded a result)';
    const server = source.server ?? (source.arc !== null ? 'an earlier server' : 'the receiving server');
    if (source.arc !== null) return `${server} (recorded in ARC, hop ${source.arc})`;
    if (source.original) return `${server} (original results kept by a gateway)`;
    return server;
}

import type { CheckQuery } from '../api';
import type { AuthChecks, DkimKeyCheck } from '../types';
import { domainOf } from './address';
import type { Analysis } from './analyze';
import { aligned, organizationalDomain, sourceLabel, type AuthSummary, type DkimSignature, type Verdict } from './auth';
import { verifyDkim, type DkimVerification } from './dkimVerify';
import { ipScope } from './ip';
import { findHeader } from './message';

/**
 * What to check live: the server that handed the message to the recipient's
 * provider (the IP SPF is evaluated for), the envelope sender, the From
 * domain and each DKIM signature's key. Only these identities are sent.
 */
export function checkQuery(analysis: Analysis): CheckQuery {
    const { auth, route, message } = analysis;
    const handoff = analysis.handoff !== null ? route.hops[analysis.handoff] : null;
    const ip = handoff?.from?.ip && ipScope(handoff.from.ip) === 'public' ? handoff.from.ip : (auth.spf.ip ?? null);
    const spfMailFrom = auth.results.flatMap((r) => r.results).find((r) => r.method === 'spf')?.props['smtp.mailfrom'];
    const mailFrom =
        findHeader(message.headers, 'return-path')?.value.replace(/^<|>$/g, '').trim() ||
        spfMailFrom ||
        auth.receivedSpf[0]?.props['envelope-from'] ||
        handoff?.envelopeFrom ||
        null;
    return {
        ip,
        helo: handoff?.from?.helo ?? (handoff?.from?.name && handoff.from.name.includes('.') ? handoff.from.name : null),
        mailFrom,
        fromDomain: auth.fromDomain,
        orgDomain: auth.fromDomain ? organizationalDomain(auth.fromDomain) : null,
        dkim: auth.dkim.filter((s) => s.domain && s.selector).map((s) => ({ d: s.domain as string, s: s.selector as string })),
    };
}

export interface LiveDkim {
    signature: DkimSignature;
    key: DkimKeyCheck | null;
    verification: DkimVerification | null;
    /** Valid signature and matching body: the domain really signed this content. */
    valid: boolean;
}

export interface LiveAuth {
    checks: AuthChecks;
    query: CheckQuery;
    dkim: LiveDkim[];
    /** Our own DMARC evaluation from the live SPF and DKIM results. */
    dmarc: { result: 'pass' | 'fail' | 'none'; spfAligned: boolean; dkimAligned: boolean; strictSpf: boolean; strictDkim: boolean };
}

export async function evaluate(analysis: Analysis, query: CheckQuery, checks: AuthChecks): Promise<LiveAuth> {
    const body = analysis.message.hasBody && !analysis.bodyRebuilt ? analysis.message.body : null;
    const noBody = analysis.bodyRebuilt ? "This body was rebuilt from an Outlook .msg file, which doesn't keep the original, so the body hash can't be checked." : undefined;
    const dkim = await Promise.all(
        analysis.auth.dkim.map(async (signature): Promise<LiveDkim> => {
            const key = checks.dkim.find((k) => k.domain === signature.domain && k.selector === signature.selector?.toLowerCase()) ?? null;
            const verification =
                key?.found && key.publicKey ? await verifyDkim(signature, analysis.message.headers, body, { publicKey: key.publicKey, keyType: key.keyType ?? 'rsa' }, noBody) : null;
            return { signature, key, verification, valid: !!verification?.signatureOk && verification.bodyHashOk !== false };
        }),
    );

    const tags = checks.dmarc?.tags ?? {};
    const strictSpf = (tags.aspf ?? '').toLowerCase() === 's';
    const strictDkim = (tags.adkim ?? '').toLowerCase() === 's';
    const from = analysis.auth.fromDomain;
    const spfAligned = checks.spf?.result === 'pass' && aligned(checks.spf.domain, from, strictSpf);
    const dkimAligned = dkim.some((d) => d.valid && aligned(d.signature.domain, from, strictDkim));
    return {
        checks,
        query,
        dkim,
        dmarc: {
            result: !checks.dmarc?.found ? 'none' : spfAligned || dkimAligned ? 'pass' : 'fail',
            spfAligned,
            dkimAligned,
            strictSpf,
            strictDkim,
        },
    };
}

/** "postmaster@example.com" => "example.com" */
export function mailFromDomain(query: CheckQuery): string | null {
    return domainOf(query.mailFrom) ?? query.helo;
}

const LIVE = { server: null, arc: null, original: false, live: true };

/** This page's own SPF, DKIM and DMARC verdicts, in the summary's shape (null: couldn't check). */
export function liveVerdicts(auth: AuthSummary, live: LiveAuth): { spf: AuthSummary['spf'] | null; dkimVerdict: AuthSummary['dkimVerdict'] | null; dmarc: AuthSummary['dmarc'] | null } {
    const from = auth.fromDomain;
    const spf = live.checks.spf;
    let spfVerdict: AuthSummary['spf'] | null = null;
    if (spf) {
        const verdict: Verdict = spf.result === 'temperror' || spf.result === 'permerror' ? 'error' : spf.result;
        const matches = aligned(spf.domain, from);
        spfVerdict = { verdict, domain: spf.domain, ip: spf.ip, aligned: verdict === 'pass' && matches, domainMatches: matches, source: LIVE };
    }

    let dkimVerdict: AuthSummary['dkimVerdict'] | null = null;
    if (live.dkim.length) {
        const valid = live.dkim.filter((d) => d.valid);
        const headerOnly = live.dkim.filter((d) => d.verification?.signatureOk && d.verification.bodyHashOk === false);
        // A valid header signature with a different body is usually a modified copy, not a forgery: don't call it a fail.
        const verdict: Verdict = valid.length ? 'pass' : headerOnly.length ? 'neutral' : 'fail';
        const domains = [...new Set((valid.length ? valid : live.dkim).map((d) => d.signature.domain).filter((d): d is string => !!d))];
        const matches = domains.some((d) => aligned(d, from));
        dkimVerdict = { verdict, domains, failed: [], aligned: verdict === 'pass' && matches, domainMatches: matches, source: LIVE };
    } else if (auth.dkim.length === 0) {
        dkimVerdict = { verdict: 'none', domains: [], failed: [], aligned: false, domainMatches: false, source: LIVE };
    }

    const dmarc = live.checks.dmarc && !live.checks.dmarc.lookupFailed ? { verdict: live.dmarc.result as Verdict, policy: live.checks.dmarc.tags.p?.toLowerCase() ?? null, source: LIVE } : null;
    return { spf: spfVerdict, dkimVerdict, dmarc };
}

/**
 * The receiving server's recorded verdicts, with any it didn't record filled
 * in from the live checks (and marked as such). Recorded results always win:
 * they show what happened on arrival.
 */
export function withLive(auth: AuthSummary, live: LiveAuth | null): AuthSummary {
    if (!live) return auth;
    const now = liveVerdicts(auth, live);
    const out: AuthSummary = { ...auth };
    if (auth.spf.verdict === 'unknown' && now.spf) out.spf = now.spf;
    if ((auth.dkimVerdict.verdict === 'unknown' || auth.dkimVerdict.verdict === 'none') && now.dkimVerdict && auth.dkim.length) out.dkimVerdict = now.dkimVerdict;
    if (auth.dmarc.verdict === 'unknown' && now.dmarc) out.dmarc = now.dmarc;
    return out;
}

export interface AuthConflict {
    method: 'SPF' | 'DKIM' | 'DMARC';
    text: string;
    /** Can't be explained by DNS changing since: the claim doesn't match the message itself, or came from a server we can't vouch for. */
    strong: boolean;
}

const PASSED = (v: Verdict) => v === 'pass';
const FAILED = (v: Verdict) => v === 'fail' || v === 'softfail' || v === 'none' || v === 'neutral';

/**
 * Where what the email says disagrees with what's checkable now. Results in ARC
 * or X-Original headers were written by a server we can't vouch for (often on
 * the sender's side), and nothing here verifies the ARC seal, so a pass there
 * that doesn't hold up is a red flag.
 */
export function authConflicts(recorded: AuthSummary, live: LiveAuth): AuthConflict[] {
    const now = liveVerdicts(recorded, live);
    const out: AuthConflict[] = [];
    const secondHand = (source: AuthSummary['spf']['source']) => !!source && (source.arc !== null || source.original);

    // A DKIM pass for a domain whose signature isn't in the message can't be checked by anyone.
    if (PASSED(recorded.dkimVerdict.verdict)) {
        const present = new Set(recorded.dkim.map((s) => s.domain?.toLowerCase()).filter(Boolean));
        for (const d of recorded.dkimVerdict.domains) {
            if (present.has(d.toLowerCase())) continue;
            const others = [...present].join(', ');
            out.push({
                method: 'DKIM',
                text: `${sourceLabel(recorded.dkimVerdict.source)} recorded a valid DKIM signature from ${d}, but this message has no signature from ${d}${others ? ` (only from ${others})` : ''}. Nobody can check that claim.`,
                strong: true,
            });
        }
    }

    const pairs: [AuthConflict['method'], { verdict: Verdict; source: AuthSummary['spf']['source'] }, { verdict: Verdict } | null][] = [
        ['SPF', recorded.spf, now.spf],
        ['DKIM', recorded.dkimVerdict, now.dkimVerdict],
        ['DMARC', recorded.dmarc, now.dmarc],
    ];
    for (const [method, then, current] of pairs) {
        if (!current || then.verdict === 'unknown') continue;
        if (method === 'DKIM' && out.some((c) => c.method === 'DKIM')) continue;
        if (PASSED(then.verdict) && FAILED(current.verdict)) {
            const strong = secondHand(then.source);
            out.push({
                method,
                text:
                    method === 'DKIM' && current.verdict === 'neutral'
                        ? `${sourceLabel(then.source)} recorded DKIM pass; the signature still verifies, but this copy's body differs from what was signed. Usually the copy was changed after delivery (saved, exported or forwarded).`
                        : `${sourceLabel(then.source)} recorded ${method} pass, but checking now gives ${current.verdict}.${strong ? '' : ' DNS records or keys may have changed since the message was sent.'}`,
                strong,
            });
        }
    }
    return out;
}

/**
 * The results to show: what the email recorded, gaps filled from the live
 * checks, and any recorded pass that can't be backed up replaced by what
 * checks out now.
 */
export function checkedAuth(recorded: AuthSummary, live: LiveAuth | null): { auth: AuthSummary; conflicts: AuthConflict[] } {
    const merged = withLive(recorded, live);
    if (!live) return { auth: merged, conflicts: [] };
    const now = liveVerdicts(recorded, live);
    const conflicts = authConflicts(recorded, live);
    const disproved = (method: AuthConflict['method']) => conflicts.some((c) => c.method === method && c.strong);
    return {
        auth: {
            ...merged,
            ...(disproved('SPF') && now.spf ? { spf: now.spf } : {}),
            ...(disproved('DKIM') && now.dkimVerdict ? { dkimVerdict: now.dkimVerdict } : {}),
            ...(disproved('DMARC') && now.dmarc ? { dmarc: now.dmarc } : {}),
        },
        conflicts,
    };
}

import type { NetworkInfo } from '../types';
import { domainOf, parseAddressList } from './address';
import type { Analysis } from './analyze';
import { aligned, organizationalDomain } from './auth';
import type { Tone } from './explain';
import { hostMatches, SERVICES } from './data/services';
import { formatUtc } from './format';
import { ipScope } from './ip';
import { findHeader, type HeaderField } from './message';
import type { Hop } from './route';

/** One thing the headers say about who sent the message. */
export interface Identity {
    label: string;
    value: string;
    kind?: 'email' | 'domain' | 'ip';
    tone?: Tone;
    hint?: string;
    /** Smaller lines under the value: the kind of service, ids to quote… */
    details?: { label: string; value: string }[];
}

export interface ReportTarget {
    who: string;
    role: string;
    why: string;
    email: string | null;
    url: string | null;
    /** Identifiers to quote so they can find the account or server. */
    quote: { name: string; value: string }[];
    /** Where the contact came from: our list of services, or the registry, live. */
    source: 'service' | 'registry' | 'domain' | 'general';
}

export interface SenderReport {
    claimed: Identity[];
    actual: Identity[];
    findings: { text: string; tone: Tone }[];
    /** The hop where the recipient's provider took over; its sender is the last outside server. */
    handoff: Hop | null;
    targets: ReportTarget[];
}

/**
 * Microsoft 365 Enhanced Filtering's record of who really sent it, when the message reached
 * Microsoft through another gateway first: the hand-off hop is then that gateway, not the sender.
 */
export function originalSender(analysis: Analysis): { ip: string | null; domain: string | null } | null {
    return analysis.route.originalSender;
}

/** Addresses whose network owner (and abuse desk) is worth looking up. */
export function networkTargets(analysis: Analysis): string[] {
    const handoff = analysis.handoff !== null ? analysis.route.hops[analysis.handoff] : null;
    const ips = [originalSender(analysis)?.ip, handoff?.from?.ip, analysis.route.clientIp?.ip, analysis.route.originIp].filter((ip): ip is string => !!ip && ipScope(ip) === 'public');
    return [...new Set(ips)].slice(0, 4);
}

/** Accounts the sender logged in with, from wherever servers recorded them. */
function loggedInAccounts(analysis: Analysis): Identity[] {
    const out: Identity[] = [];
    const add = (value: string | null | undefined, source: string) => {
        const v = value?.trim().replace(/^\[|\]$/g, '');
        if (v && v !== 'yes' && !out.some((i) => i.value.toLowerCase() === v.toLowerCase())) {
            out.push({ label: 'Account', value: v, kind: v.includes('@') ? 'email' : undefined, tone: 'info', hint: `The account that logged in to send it (from ${source}).` });
        }
    };
    for (const hop of analysis.route.hops) add(hop.authenticated, `Received (hop ${hop.number})`);
    const h = (key: string) => findHeader(analysis.message.headers, key);
    add(/authenticated_id:\s*(\S+)/i.exec(h('x-get-message-sender-via')?.value ?? '')?.[1], 'X-Get-Message-Sender-Via');
    add(h('x-authenticated-sender')?.value.split(/:\s*/).pop(), 'X-Authenticated-Sender');
    add(h('x-authenticated_id')?.value, 'X-Authenticated_ID');
    add(h('x-originating-email')?.value, 'X-Originating-Email');
    for (const result of analysis.auth.results) for (const r of result.results) add(r.props['smtp.auth'], 'Authentication-Results');
    return out;
}

/**
 * A service's account and campaign ids, labelled as on the Headers tab (Job id, Campaign id…).
 * Identifiers are the monospace facts; opaque headers fall back to their name.
 */
function accountIds(analysis: Analysis, keys: string[]): { label: string; value: string }[] {
    return keys.flatMap((key) => {
        if (key === 'message-id') return [];
        const explained = analysis.headers.find((x) => x.field.key === key);
        if (!explained?.field.value.trim()) return [];
        const ids = explained.facts.filter((f) => f.mono && f.tone !== 'muted');
        return ids.length ? ids.map((f) => ({ label: f.label, value: f.value })) : [{ label: explained.field.name, value: explained.field.value.trim() }];
    });
}

export function senderReport(analysis: Analysis, networks: Record<string, NetworkInfo | null> | null): SenderReport {
    const { auth, route, message } = analysis;
    const headers = message.headers;
    const h = (key: string): HeaderField | undefined => findHeader(headers, key);
    const from = analysis.from;
    const fromDomain = from?.domain ?? null;
    const handoff = analysis.handoff !== null ? route.hops[analysis.handoff] : null;

    // ------------------------------------------------------------- Claimed
    const claimed: Identity[] = [];
    if (from) {
        if (from.name) claimed.push({ label: 'Display name', value: from.name });
        claimed.push({ label: 'From address', value: from.address, kind: 'email' });
    }
    const sender = parseAddressList(h('sender')?.decoded ?? '')[0];
    if (sender && sender.address.toLowerCase() !== from?.address.toLowerCase()) claimed.push({ label: 'On behalf of', value: sender.address, kind: 'email' });
    const replyTo = parseAddressList(h('reply-to')?.decoded ?? '')[0];
    if (replyTo && replyTo.address.toLowerCase() !== from?.address.toLowerCase()) claimed.push({ label: 'Replies go to', value: replyTo.address, kind: 'email' });

    // -------------------------------------------------------------- Actual
    // Plain answers only: is the From genuine, which account, which service or server. The detail tabs have the rest.
    const actual: Identity[] = [];
    const envelope = h('return-path')?.value.replace(/^<|>$/g, '').trim() || route.hops.find((hop) => hop.envelopeFrom)?.envelopeFrom || null;
    if (fromDomain) {
        const verified = auth.dmarc.verdict === 'pass' || auth.spf.aligned || auth.dkimVerdict.aligned;
        actual.push(
            verified
                ? { label: 'Genuine?', value: `Yes: ${fromDomain} sent or approved it`, tone: 'good', hint: 'It passed the checks that tie a message to its From domain (DMARC, SPF, DKIM): see the Authentication tab. A hacked account at that domain would still pass.' }
                : auth.dmarc.verdict === 'fail'
                  ? { label: 'Genuine?', value: `No: it failed ${fromDomain}'s own check`, tone: 'bad', hint: 'The domain publishes a DMARC policy and this message failed it: see the Authentication tab.' }
                  : { label: 'Genuine?', value: `Unproven: nothing ties it to ${fromDomain}`, tone: 'warn', hint: "It isn't signed by, or sent from a server approved by, the From domain: anyone could have written that address. See the Authentication tab." },
        );
    }

    const accounts = loggedInAccounts(analysis);
    actual.push(...accounts);
    if (!accounts.length && route.hops.some((hop) => hop.authenticated === 'yes')) {
        actual.push({ label: 'Account', value: "Logged in, but the name wasn't recorded", tone: 'muted' });
    }

    const sending = analysis.services.filter((s) => s.side === 'sending');
    for (const detected of sending) {
        const s = detected.service;
        actual.push({ label: 'Sent through', value: s.name, details: [{ label: 'Kind', value: s.kind }, ...accountIds(analysis, s.account ?? [])].slice(0, 4) });
    }
    const tenant = h('x-originatororg')?.value.trim();
    if (tenant) actual.push({ label: 'Microsoft 365 organisation', value: tenant, kind: 'domain', hint: 'The Microsoft 365 customer (tenant) whose account sent it.' });

    // No known service: the server and whoever owns its network is what to block or report.
    const original = originalSender(analysis);
    if (!sending.length && original) {
        const net = original.ip ? networks?.[original.ip] : null;
        actual.push({
            label: 'Sending server',
            value: [original.domain, original.ip ? `[${original.ip}]` : ''].filter(Boolean).join(' '),
            tone: 'info',
            hint: 'The message passed through another gateway before Microsoft 365; Microsoft recorded the server that really sent it (Enhanced Filtering).',
            details: net?.organization || net?.name ? [{ label: 'Network owner', value: (net.organization ?? net.name) as string }] : [],
        });
    } else if (!sending.length && handoff?.from) {
        const name = handoff.from.rdns ?? handoff.from.name;
        const net = handoff.from.ip ? networks?.[handoff.from.ip] : null;
        actual.push({
            label: 'Sending server',
            value: [name, handoff.from.ip && handoff.from.ip !== name ? `[${handoff.from.ip}]` : ''].filter(Boolean).join(' '),
            tone: 'info',
            hint: "The last server before the recipient's provider took over, as recorded by that provider: the part of the route that can't be made up.",
            details: net?.organization || net?.name ? [{ label: 'Network owner', value: (net.organization ?? net.name) as string }] : [],
        });
    }

    // ------------------------------------------------------------ Findings
    const findings: SenderReport['findings'] = [];
    for (const account of accounts) {
        const domain = domainOf(account.value);
        if (domain && fromDomain && !aligned(domain, fromDomain)) {
            findings.push({ tone: 'bad', text: `Sent by the account ${account.value}, but the From address claims ${from?.address}.` });
        } else if (domain && fromDomain) {
            findings.push({ tone: 'good', text: `The account that logged in (${account.value}) matches the From domain.` });
        }
    }
    if (from?.name && /@/.test(from.name)) {
        const shown = domainOf(from.name) ?? from.name;
        if (fromDomain && !from.name.toLowerCase().includes(from.address.toLowerCase())) {
            findings.push({ tone: 'bad', text: `The display name shows "${from.name}", but the real address is ${from.address} (${shown} vs ${fromDomain}).` });
        }
    }
    if (replyTo?.domain && fromDomain && !aligned(replyTo.domain, fromDomain)) {
        findings.push({ tone: 'warn', text: `Replies go to ${replyTo.domain}, not ${fromDomain}. Common for help desks and newsletters; a classic trick in phishing.` });
    }

    // ------------------------------------------------------------- Targets
    const targets: ReportTarget[] = [];
    const messageId = h('message-id')?.value.trim();

    for (const detected of analysis.services) {
        const s = detected.service;
        if (detected.side !== 'sending' || s.kind === 'Security gateway' || s.kind === 'Spam filter' || s.kind === 'Hosting control panel') continue;
        const quote = (s.account ?? []).map((key) => h(key)).filter((f): f is HeaderField => !!f?.value.trim()).map((f) => ({ name: f.name, value: f.value.trim() }));
        if (messageId && !quote.some((q) => q.name.toLowerCase() === 'message-id')) quote.push({ name: 'Message-ID', value: messageId });
        targets.push({
            who: s.name,
            role: s.kind,
            why:
                s.kind === 'Mailbox provider'
                    ? `The message was sent from a ${s.name} account. ${s.name} can suspend that account.`
                    : `The message was sent through ${s.name}. They can suspend the customer account that sent it.`,
            email: s.abuse?.email ?? null,
            url: s.abuse?.url ?? null,
            quote,
            source: 'service',
        });
    }

    // Abuse desks match reports against their logs by address and time.
    const timeAt = (ip: string) => {
        const hop = route.hops.find((x) => x.from?.ip === ip && x.date);
        return hop?.date ? formatUtc(hop.date.time) : null;
    };
    const addNetwork = (ip: string | null | undefined, role: string, why: string) => {
        if (!ip || ipScope(ip) !== 'public' || !networks) return;
        const net = networks[ip];
        if (!net) return;
        const who = net.organization ?? net.name ?? ip;
        const existing = targets.find((t) => t.email && net.abuseEmail && t.email.toLowerCase() === net.abuseEmail.toLowerCase());
        if (existing) {
            existing.why += ` (Also the registered abuse contact for ${ip}.)`;
            return;
        }
        if (targets.some((t) => t.source === 'registry' && t.who === who && t.email === net.abuseEmail)) return;
        targets.push({
            who,
            role,
            why,
            email: net.abuseEmail,
            url: null,
            quote: [{ name: 'IP address', value: ip }, ...(timeAt(ip) ? [{ name: 'Time (UTC)', value: timeAt(ip) as string }] : []), ...(net.name ? [{ name: 'Network', value: `${net.name}${net.handle ? ` (${net.handle})` : ''}` }] : [])],
            source: 'registry',
        });
    };
    const handoffName = handoff?.from?.rdns ?? handoff?.from?.name;
    // Behind a gateway, the hand-off is the gateway: report the original sender's network instead.
    if (original?.ip) addNetwork(original.ip, 'Network owner', `Owns the network of ${original.domain ?? original.ip}, the server that really sent the message (recorded by Microsoft 365 before its gateway). If that's a cloud or hosting server, they can shut it down.`);
    else addNetwork(
        handoff?.from?.ip,
        'Network owner',
        `Owns the network of ${handoffName ?? 'the server'} that handed the message to your provider. If that's a cloud or hosting server (EC2, a VPS, a shared host), they can shut it down.`,
    );
    addNetwork(route.clientIp?.ip, "Sender's internet provider", "The sender's own connection, from the header their mail service added.");
    if (route.originIp !== handoff?.from?.ip) addNetwork(route.originIp, 'Earliest network on record', 'Where the first recorded server says the message came from. Less certain: this part of the headers could be forged.');

    // A service's own domain (gmail.com, amazonses.com) isn't worth a registrar report.
    const servicesOwn = (domain: string) => SERVICES.some((s) => hostMatches(domain, s.dkim) || hostMatches(domain, s.hosts));
    const domains = [...new Set([auth.dmarc.verdict === 'pass' ? fromDomain : null, envelope ? domainOf(envelope) : null].filter((d): d is string => !!d).map(organizationalDomain))].filter(
        (d) => !servicesOwn(d),
    );
    for (const domain of domains) {
        targets.push({
            who: `The registrar of ${domain}`,
            role: 'Domain registrar',
            why: `If ${domain} itself was registered to send spam or phishing, its registrar can suspend the domain. Look up the registrar's abuse contact.`,
            email: null,
            url: `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(domain)}`,
            quote: [{ name: 'Domain', value: domain }],
            source: 'domain',
        });
    }

    targets.push({
        who: 'Anti-Phishing Working Group',
        role: 'Phishing only',
        why: 'If this is phishing, forward it (as an attachment) to APWG; their feeds reach browsers and mail providers. Also mark it as spam or phishing in your mail app so your own provider learns from it.',
        email: 'reportphishing@apwg.org',
        url: 'https://apwg.org/reportphishing/',
        quote: [],
        source: 'general',
    });

    return { claimed, actual, findings, handoff, targets };
}

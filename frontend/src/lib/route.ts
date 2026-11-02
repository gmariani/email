import { secondsToTime } from './format';
import { ipScope, type IpScope } from './ip';
import { findHeader, type HeaderField } from './message';
import { parseDate } from './date';
import { parseReceived, securityOf, type Received, type Security } from './received';

export interface Hop extends Received {
    /** 1 = the first server to receive the message. */
    number: number;
    header: HeaderField;
    security: Security;
    /** Where the sending side's address lives. */
    scope: IpScope | null;
    /** Seconds since the previous hop's timestamp (negative = clocks disagree). */
    delay: number | null;
    warnings: string[];
}

export interface Route {
    hops: Hop[];
    /** When the sender's software says it was written (Date header). */
    composed: number | null;
    /** Date header to the last hop. */
    totalSeconds: number | null;
    /** The first public address in the chain: the sending server, or the sender's own connection. */
    originIp: string | null;
    /** X-Originating-IP and similar: the sender's device, as reported by a webmail/submission server. */
    clientIp: { ip: string; header: string } | null;
    /**
     * Microsoft 365 Enhanced Filtering's record (X-MS-Exchange-ExternalOriginalInternetSender) of the server that
     * really sent the message, when it reached Microsoft through another gateway first.
     */
    originalSender: { ip: string | null; domain: string | null } | null;
    counts: Record<Security, number>;
    warnings: string[];
}

const CLIENT_IP_HEADERS = ['x-originating-ip', 'x-sender-ip', 'x-forwarded-for', 'x-real-ip', 'x-client-ip'];

/**
 * Received headers are stacked newest-first (each server adds one on top), so
 * the route is read bottom-up. Only the hops added by servers you trust are
 * reliable: everything below them could have been written by the sender.
 */
export function buildRoute(headers: HeaderField[]): Route {
    const received = headers.filter((h) => h.key === 'received').reverse();
    const hops: Hop[] = [];

    received.forEach((header, i) => {
        const parsed = parseReceived(header.value);
        const previous = hops[i - 1];
        const delay = parsed.date && previous?.date ? Math.round((parsed.date.time - previous.date.time) / 1000) : null;
        const warnings: string[] = [];

        if (!parsed.date) warnings.push('No readable timestamp.');
        if (delay !== null && delay < -60) {
            warnings.push(`Timestamp is ${secondsToTime(-delay)} earlier than the previous hop's: one of the two servers' clocks is wrong, or this header was forged.`);
        } else if (delay !== null && delay > 3600) {
            warnings.push(`Held for ${secondsToTime(delay)} before this server accepted it (queueing, greylisting or retries).`);
        }
        if (parsed.from?.mayBeForged) warnings.push("The receiving server noted the sender's name didn't match its reverse DNS (\"may be forged\").");
        if (parsed.date && parsed.date.time > Date.now() + 86_400_000) {
            warnings.push('Timestamp is in the future.');
        }

        const ip = parsed.from?.ip ?? null;
        const security = securityOf(parsed);
        if (parsed.tls?.version && /^(SSL|TLS 1\.[01])/.test(parsed.tls.version)) {
            warnings.push(`${parsed.tls.version} is obsolete and has known weaknesses; current servers use TLS 1.2 or 1.3.`);
        }
        if (parsed.authenticated && security === 'unencrypted') {
            warnings.push('The sender logged in over an unencrypted connection, so their password may have crossed the network in plain text.');
        }
        hops.push({
            ...parsed,
            number: i + 1,
            header,
            security,
            scope: ip ? ipScope(ip) : null,
            delay,
            warnings,
        });
    });

    const date = parseDate(findHeader(headers, 'date')?.value);
    const lastTime = [...hops].reverse().find((h) => h.date)?.date?.time ?? null;
    const firstTime = hops.find((h) => h.date)?.date?.time ?? null;

    let clientIp: Route['clientIp'] = null;
    for (const key of CLIENT_IP_HEADERS) {
        const header = findHeader(headers, key);
        const ip = header?.value.split(',')[0].replace(/[[\]\s]/g, '');
        if (header && ip) {
            clientIp = { ip, header: header.name };
            break;
        }
    }

    const recorded = findHeader(headers, 'x-ms-exchange-externaloriginalinternetsender')?.value ?? '';
    const originalIp = /\bip=\[?([0-9a-f.:]+)\]?/i.exec(recorded)?.[1] ?? null;
    const originalDomain = /\bdomain=([^;\s]+)/i.exec(recorded)?.[1] ?? null;

    const counts: Record<Security, number> = { encrypted: 0, unencrypted: 0, local: 0, internal: 0, unknown: 0 };
    for (const hop of hops) counts[hop.security]++;

    const warnings: string[] = [];
    if (date && firstTime !== null && firstTime - date.time < -300) {
        warnings.push(`The Date header is ${secondsToTime((date.time - firstTime) / 1000)} after the first server received the message: the sender's clock is wrong or the date was set by hand.`);
    }
    const plain = hops.filter((h) => h.security === 'unencrypted');
    const publicPlain = plain.filter((h) => h.scope !== 'private');
    if (publicPlain.length) {
        warnings.push(`${publicPlain.length} hop${publicPlain.length === 1 ? ' was' : 's were'} not encrypted (hop${publicPlain.length === 1 ? '' : 's'} ${publicPlain.map((h) => h.number).join(', ')}): anyone on the network path between those servers could read the message.`);
    }
    if (plain.length > publicPlain.length) {
        const n = plain.length - publicPlain.length;
        warnings.push(`${n} unencrypted hop${n === 1 ? ' was' : 's were'} inside a private network, visible only to that network.`);
    }

    return {
        hops,
        composed: date?.time ?? null,
        totalSeconds: date && lastTime !== null ? Math.round((lastTime - date.time) / 1000) : firstTime !== null && lastTime !== null ? Math.round((lastTime - firstTime) / 1000) : null,
        originIp: hops.find((h) => h.from?.ip && h.scope === 'public')?.from?.ip ?? null,
        clientIp,
        originalSender: originalIp || originalDomain ? { ip: originalIp, domain: originalDomain } : null,
        counts,
        warnings,
    };
}

/** The name to show for a hop's sending side: verified reverse DNS first, then what it called itself. */
export function senderName(hop: Hop): string | null {
    return hop.from?.rdns ?? hop.from?.name ?? null;
}

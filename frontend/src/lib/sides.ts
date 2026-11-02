import { parseAddressList } from './address';
import { organizationalDomain } from './auth';
import { hostMatches, SERVICES } from './data/services';
import type { HeaderField } from './message';
import { receivedBySameBox } from './received';
import type { Route } from './route';

/** Same organisation, or two names of one known service (outlook.com / office365.com). */
function sameOperator(a: string | null | undefined, b: string | null | undefined): boolean {
    if (!a || !b || !a.includes('.') || !b.includes('.')) return false;
    if (organizationalDomain(a) === organizationalDomain(b)) return true;
    return SERVICES.some((s) => hostMatches(a, s.hosts) && hostMatches(b, s.hosts));
}

/** Domains the message was delivered to: they belong to the receiving side. */
export function recipientDomains(headers: HeaderField[], route: Route): Set<string> {
    const domains = new Set<string>();
    for (const key of ['delivered-to', 'x-original-to', 'envelope-to', 'to', 'cc']) {
        for (const h of headers.filter((x) => x.key === key)) {
            for (const m of parseAddressList(h.decoded)) if (m.domain) domains.add(organizationalDomain(m.domain));
        }
    }
    for (const hop of route.hops) {
        const at = hop.for?.lastIndexOf('@') ?? -1;
        if (hop.for && at > 0) domains.add(organizationalDomain(hop.for.slice(at + 1)));
    }
    return domains;
}

/**
 * Index of the hop where the recipient's side took over. Walking back from the
 * final server, hops stay on the receiving side while they're received by the
 * same operator or by one of the recipient's own domains. The sender recorded
 * in that hop is the last server outside the recipient's control: the most
 * trustworthy origin there is, since every header below it could be forged.
 */
export function handoffIndex(headers: HeaderField[], route: Route): number | null {
    const { hops } = route;
    if (!hops.length) return null;
    const ours = recipientDomains(headers, route);
    const finalServer = [...hops].reverse().find((h) => h.by?.name?.includes('.'))?.by?.name;
    const receiving = (name: string | null | undefined) => !!name && (sameOperator(name, finalServer) || (name.includes('.') && ours.has(organizationalDomain(name))));

    // Steps a server takes through its own content filter ("by localhost") are on whichever side that server is:
    // a receiving gateway's loop is ours, the sender's Exchange relaying to itself (exch01 → exch01) is not.
    const receivingLoop = (hop: Route['hops'][number]) => {
        if (!receivedBySameBox(hop)) return false;
        const names = [hop.by?.name, hop.from?.name, hop.from?.helo].filter((n): n is string => !!n && n.includes('.'));
        return !names.length || names.some(receiving);
    };
    let index = hops.length - 1;
    while (index > 0 && (receiving(hops[index - 1].by?.name) || receivingLoop(hops[index - 1]))) index--;
    // An internal step (no sending server recorded) can't be the hand-off; the one before it is.
    while (index > 0 && !hops[index].from?.ip && (hops[index].security === 'internal' || hops[index].security === 'local')) index--;
    return index;
}

import type { RelayLookup } from '../types';
import { ipScope } from './ip';
import { receivedBySameBox } from './received';
import { senderName, type Hop, type Route } from './route';

/** A server (or the sender's device) on the message's path. */
export interface Stop {
    name: string | null;
    ip: string | null;
    /** Where the IP came from: the header itself, or today's DNS for the host name. */
    ipSource: 'header' | 'dns' | null;
    /** The hop that delivered the message to this stop; null for the origin. */
    hopIn: Hop | null;
    /** Later hand-offs on the same machine (content filters, LMTP into the mailbox). */
    localHops: Hop[];
    /** Server software, from the header this server wrote. */
    software: string | null;
    /** A different name the next server recorded for this one. */
    alsoKnownAs: string | null;
    /** The name and address it has inside its own network, when the public one is shown instead. */
    internal: { name: string | null; ip: string | null } | null;
    /** The last server outside the recipient's provider: the one that handed the message over. */
    sender: boolean;
    /**
     * Microsoft 365 Enhanced Filtering recorded this as the server that really sent the message.
     * 'received': it's also on the Received path; 'record-only': only Microsoft's record shows it.
     */
    original: 'received' | 'record-only' | null;
}

const FQDN = /^(?=.{4,253}$)([a-z0-9_-]+\.)+[a-z]{2,}$/i;

/** Names that only mean something inside one network: "exch01.ELWOOD.local", "Web5", "…prd.sparkpost". */
const INTERNAL_TLD = /\.(local|localdomain|lan|internal|intranet|corp|home|private|priv|prd|prod|sparkpost)$/i;
function internalName(name: string | null): boolean {
    return !!name && (!name.includes('.') || INTERNAL_TLD.test(name));
}

/**
 * Turns the hops into the list of places the message went: the origin (the
 * first hop's sender) followed by each receiving server. The IP of a receiving
 * server is usually only known from the next hop's "from" clause.
 */
export function buildStops(route: Route, handoff: number | null = null): Stop[] {
    const { hops } = route;
    if (!hops.length) return [];
    const stops: Stop[] = [];

    const first = hops[0];
    stops.push({
        name: senderName(first) ?? (first.from ? null : 'Not recorded'),
        ip: first.from?.ip ?? null,
        ipSource: first.from?.ip ? 'header' : null,
        hopIn: null,
        localHops: [],
        software: null,
        alsoKnownAs: first.from?.helo && first.from.helo !== senderName(first) ? first.from.helo : null,
        internal: null,
        sender: false,
        original: null,
    });

    hops.forEach((hop, i) => {
        const previous = stops[stops.length - 1];
        const byName = hop.by?.name ?? null;
        // Same-machine deliveries, and internal steps with no real sender (a gateway passing
        // mail through its own scanner: "by emcmailer", "from 1eYfVN-00004u-44 by …"),
        // belong to the server already on the path rather than being new stops.
        const sameServer = (hop.security === 'local' && byName && previous.name?.toLowerCase() === byName.toLowerCase()) || receivedBySameBox(hop);
        const internalStep = hop.security === 'internal' && (!hop.from || (!hop.from.ip && !hop.from.name?.includes('.')));
        if (i > 0 && (sameServer || internalStep)) {
            previous.localHops.push(hop);
            return;
        }
        stops.push({ name: byName, ip: null, ipSource: null, hopIn: hop, localHops: [], software: hop.software, alsoKnownAs: null, internal: null, sender: false, original: null });
    });

    // A server's address, and the name others know it by, come from the next server's "from" clause:
    // the hop that leaves it, after any steps inside it.
    stops.forEach((stop, i) => {
        if (!stop.hopIn) return;
        const out = stops[i + 1]?.hopIn ?? null;
        const ownIp = stop.hopIn.by?.ip ?? stop.localHops.find((h) => h.by?.ip)?.by?.ip ?? null;
        const ip = out?.from?.ip ?? ownIp;
        const outName = out ? senderName(out) : null;
        const otherName = outName && stop.name && outName.toLowerCase() !== stop.name.toLowerCase() ? outName : null;
        // A server known inside its network by one name and address (exch01.ELWOOD.local, 10.0.3.25) is seen
        // by the next server under its public ones (hybrid.example.com, 66.244.119.124): lead with the public face.
        const goesPublic = !!otherName && FQDN.test(otherName) && !internalName(otherName) && (internalName(stop.name) || (!!ownIp && ipScope(ownIp) !== 'public' && !!out?.from?.ip && ipScope(out.from.ip) === 'public'));
        stop.ip = ip;
        stop.ipSource = ip ? 'header' : null;
        if (!stop.name && outName) {
            stop.name = outName;
        } else if (goesPublic) {
            stop.internal = { name: stop.name, ip: ownIp && ownIp !== ip ? ownIp : null };
            stop.name = otherName;
        } else {
            stop.alsoKnownAs = otherName;
        }
    });
    // The hand-off hop arrives at the recipient's side; the stop it left from is the sending server.
    if (handoff !== null) {
        const at = stops.findIndex((stop) => stop.hopIn === hops[handoff]);
        if (at > 0) stops[at - 1].sender = true;
    }
    return withOriginalSender(stops, route);
}

/**
 * Behind a gateway (Mimecast, Proofpoint…) in front of Microsoft 365, the Received path starts at the
 * gateway. Microsoft's own record names the server that really sent it: mark it on the path, or put
 * it first when the headers don't show it. Either way it, not the gateway, is the sending server.
 */
function withOriginalSender(stops: Stop[], route: Route): Stop[] {
    const original = route.originalSender;
    if (!original) return stops;
    const same = (stop: Stop) => (!!original.ip && stop.ip === original.ip) || (!!original.domain && stop.name?.toLowerCase() === original.domain.toLowerCase());
    const onPath = stops.find(same);
    for (const stop of stops) stop.sender = false;
    if (onPath) {
        onPath.original = 'received';
        onPath.sender = true;
        return stops;
    }
    return [
        { name: original.domain, ip: original.ip, ipSource: original.ip ? 'header' : null, hopIn: null, localHops: [], software: null, alsoKnownAs: null, internal: null, sender: true, original: 'record-only' },
        ...stops,
    ];
}

/** Fill in IPs for servers the headers only name, from the lookup's DNS answers. */
export function withResolvedIps(stops: Stop[], lookup: RelayLookup | null): Stop[] {
    if (!lookup) return stops;
    return stops.map((stop) => {
        if (stop.ip || !stop.name) return stop;
        const resolved = lookup.hosts[stop.name.toLowerCase()]?.[0];
        return resolved ? { ...stop, ip: resolved, ipSource: 'dns' } : stop;
    });
}

/** What to ask the server about: every public IP in the route, and host names without an IP. */
export function lookupTargets(route: Route): { ips: string[]; hosts: string[] } {
    const ips = new Set<string>();
    const hosts = new Set<string>();
    const stops = buildStops(route);
    for (const hop of route.hops) {
        for (const ip of [hop.from?.ip, hop.by?.ip]) if (ip && ipScope(ip) === 'public') ips.add(ip);
    }
    if (route.clientIp && ipScope(route.clientIp.ip) === 'public') ips.add(route.clientIp.ip);
    if (route.originalSender?.ip && ipScope(route.originalSender.ip) === 'public') ips.add(route.originalSender.ip);
    for (const stop of stops) {
        if (!stop.ip && stop.name && FQDN.test(stop.name)) hosts.add(stop.name.toLowerCase());
    }
    return { ips: [...ips].slice(0, 40), hosts: [...hosts].slice(0, 40) };
}

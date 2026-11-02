import { Fragment } from 'react';
import { delayLabel, formatInZone, formatLocal } from '../lib/format';
import { describeProtocol } from '../lib/received';
import type { Hop } from '../lib/route';
import type { Stop } from '../lib/stops';
import { securityIcon } from './facts';
import { DomainLink, IpLabel, useLookup } from './links';
import { Tip } from './ui';

/**
 * The simplified path: origin → each receiving server, with what each link
 * between them used (TLS or not, protocol, delay). Wraps on narrow screens.
 */
export function RouteFlow({ stops, compact = false }: { stops: Stop[]; compact?: boolean }) {
    if (!stops.length) return <p className="text-body-secondary">No Received headers: there's no route to show. (Headers pasted from a sent-items copy often have none.)</p>;
    return (
        <ol className={`route-flow ${compact ? 'route-flow--compact' : ''}`} aria-label="Route the message took">
            {stops.map((stop, i) => (
                <Fragment key={i}>
                    {stop.hopIn ? <Link hop={stop.hopIn} compact={compact} /> : i > 0 && stops[i - 1].original === 'record-only' && <UnrecordedLink />}
                    <StopNode stop={stop} number={i + 1} last={i === stops.length - 1} compact={compact} />
                </Fragment>
            ))}
        </ol>
    );
}

function StopNode({ stop, number, last, compact }: { stop: Stop; number: number; last: boolean; compact: boolean }) {
    const lookup = useLookup();
    const info = stop.ip && lookup.status === 'ready' ? lookup.data.ips[stop.ip] : undefined;
    const location = info?.location;
    const role = stop.original ? 'Original sender' : number === 1 ? 'Origin' : last ? 'Delivered' : stop.sender ? 'Sending server' : 'Relay';
    const roleTip = stop.original
        ? `Microsoft 365 recorded this as the server that really sent the message, before it passed through a gateway on its way in (Enhanced Filtering, X-MS-Exchange-ExternalOriginalInternetSender).${stop.original === 'record-only' ? " It isn't in the Received headers." : ''} It's the one whose network to report.`
        : "The last server outside the recipient's provider: it handed the message over. Its address can't be faked by the sender; it's the one SPF and reverse DNS check, and whose network to report.";
    return (
        <li className={`route-stop ${number === 1 ? 'route-stop--origin' : ''} ${last ? 'route-stop--last' : ''} ${stop.sender ? 'route-stop--sender' : ''}`}>
            <div className="route-stop-head">
                <span className="route-step">{number}</span>
                {stop.sender ? (
                    <Tip label={roleTip}>
                        <span className="route-role dotted">{role}</span>
                    </Tip>
                ) : (
                    <span className="route-role">{role}</span>
                )}
            </div>
            <div className="route-name text-break">{stop.name ? <DomainLink domain={stop.name} /> : <span className="text-body-secondary">Unknown</span>}</div>
            {stop.alsoKnownAs && !compact && <div className="small text-body-secondary text-break">also known as {stop.alsoKnownAs}</div>}
            {stop.ip && (
                <div className="small">
                    <IpLabel ip={stop.ip} />
                    {stop.ipSource === 'dns' && (
                        <Tip label="Not in the headers: this is the host name's address in DNS today.">
                            <span className="text-body-secondary ms-1 dotted">(DNS today)</span>
                        </Tip>
                    )}
                </div>
            )}
            {location && (
                <div className="small text-body-secondary">
                    {[location.city, location.country].filter(Boolean).join(', ')}
                    {location.org && !compact && <div className="text-truncate" title={location.org}>{location.org}</div>}
                </div>
            )}
            {info && !info.public && <div className="small text-body-secondary">Private network</div>}
            {stop.internal && !compact && (
                <Tip label="The name (and address) this server has inside its own network, from the header it wrote. The next server saw it under the public name above.">
                    <div className="small text-body-secondary text-break">
                        inside its network: {stop.internal.name}
                        {stop.internal.ip && ` (${stop.internal.ip})`}
                    </div>
                </Tip>
            )}
            {stop.software && <span className="badge text-bg-secondary mt-1">{stop.software}</span>}
            {stop.localHops.length > 0 && !compact && (
                <div className="small text-body-secondary mt-1">
                    then handed off internally:{' '}
                    {stop.localHops.map((h) => `${h.by?.name && h.by.name.toLowerCase() !== stop.name?.toLowerCase() ? h.by.name : (h.protocol ?? 'local')}${h.delay !== null ? ` (${delayLabel(h.delay)})` : ''}`).join(', ')}
                </div>
            )}
        </li>
    );
}

/** Between Microsoft's recorded original sender and the first Received hop: nothing in the headers says how it got there. */
function UnrecordedLink() {
    const label = "Not in the Received headers: the message went from the original sender to the gateway, but no header records how.";
    return (
        <li className="route-link route-link--unrecorded link-unknown" aria-label={label}>
            <Tip label={label}>
                <div className="route-link-inner">
                    <i className="bi bi-question-circle route-link-icon" />
                    <span className="route-link-label">Not recorded</span>
                    <span className="route-arrow" aria-hidden="true" />
                </div>
            </Tip>
        </li>
    );
}

function Link({ hop, compact }: { hop: Hop; compact: boolean }) {
    const s = securityIcon(hop.security);
    // Only the version fits on the arrow; the cipher goes in the tooltip.
    const tls = hop.tls ? hop.tls.version || hop.tls.note || 'TLS' : null;
    const details = [
        `${s.label}${tls ? `: ${[tls, hop.tls?.cipher].filter(Boolean).join(', ')}` : ''}`,
        hop.protocol && `${hop.protocol}${describeProtocol(hop.protocol) ? ` — ${describeProtocol(hop.protocol)}` : ''}`,
        hop.authenticated && `Sender logged in${hop.authenticated !== 'yes' ? ` as ${hop.authenticated}` : ''}`,
        hop.date && `${formatInZone(hop.date.time, hop.date.offset)}\nYour time: ${formatLocal(hop.date.time)}`,
        ...hop.warnings,
    ]
        .filter(Boolean)
        .join('\n');
    return (
        <li className={`route-link ${s.className}`} aria-label={details}>
            <Tip label={details}>
                <div className="route-link-inner">
                    <i className={`bi ${s.icon} route-link-icon`} />
                    <span className="route-link-label">{tls ?? s.label}</span>
                    {!compact && hop.protocol && <span className="route-link-protocol">{hop.protocol}</span>}
                    {hop.delay !== null && <span className="route-link-delay">{delayLabel(hop.delay)}</span>}
                    {hop.warnings.length > 0 && <i className="bi bi-exclamation-triangle-fill text-warning" />}
                    <span className="route-arrow" aria-hidden="true" />
                </div>
            </Tip>
        </li>
    );
}

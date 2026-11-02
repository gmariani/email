import { useMemo } from 'react';
import { Alert } from 'react-bootstrap';
import { FactList, SecurityBadge } from '../components/facts';
import { GoogleMap, type MapMarker } from '../components/GoogleMap';
import { DomainLink, IpLabel, useLookup } from '../components/links';
import { RouteFlow } from '../components/RouteFlow';
import { Await, CodeBlock, HelpButton, Muted, SectionTitle } from '../components/ui';
import type { Analysis } from '../lib/analyze';
import { delayLabel, locationLabel, secondsToTime } from '../lib/format';
import { timeFacts } from '../lib/explain/types';
import { describeProtocol } from '../lib/received';
import { senderName } from '../lib/route';
import { withResolvedIps, type Stop } from '../lib/stops';
import type { RelayLookup } from '../types';

export function RouteTab({ analysis, stops, onRetry }: { analysis: Analysis; stops: Stop[]; onRetry: () => void }) {
    const { route } = analysis;
    const lookup = useLookup();
    const folded = stops.reduce((n, stop) => n + stop.localHops.length, 0);

    return (
        <>
            <SectionTitle>
                Route <HelpButton>Each server that accepts an email adds a Received header on top. Read bottom-up, they show the path it took. Only trust the part added by servers you know (your own provider); anything below could have been written by the sender.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                <RouteFlow stops={stops} />
                <p className="small text-body-secondary mb-0 mt-2">
                    {route.hops.length} hop{route.hops.length === 1 ? '' : 's'}
                    {folded > 0 && (
                        <>
                            : {route.hops.length - folded} between servers, {folded} inside a server{' '}
                            <HelpButton>Hops inside a server (content filters, a server relaying to itself, delivery to the mailbox) are listed under that server.</HelpButton>
                        </>
                    )}
                    {route.totalSeconds !== null && <> · {secondsToTime(Math.abs(route.totalSeconds))} from the Date header to delivery</>}
                    {route.clientIp && (
                        <>
                            {' '}
                            · sender's device: <IpLabel ip={route.clientIp.ip} showPlace /> <Muted>({route.clientIp.header})</Muted>
                        </>
                    )}
                </p>
            </div>

            {route.warnings.length > 0 && (
                <div className="mt-3">
                    {route.warnings.map((w) => (
                        <Alert key={w} variant="warning" className="py-2">
                            {w}
                        </Alert>
                    ))}
                </div>
            )}

            <SectionTitle className="mt-5">
                Map{' '}
                <HelpButton>
                    Locations are approximate, from IP geolocation{lookup.status === 'ready' && lookup.data.geoSource !== 'none' ? ` (${lookup.data.geoSource})` : ''}. Servers named without an address were looked up in DNS today, which may differ from when the message was sent.
                </HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                <Await state={lookup} label="Locating servers" onRetry={onRetry}>
                    {(data) => <RouteMap stops={stops} data={data} />}
                </Await>
                {lookup.status === 'idle' && <p className="text-body-secondary mb-0">No public addresses to locate.</p>}
            </div>

            <SectionTitle className="mt-5">Hops</SectionTitle>
            <div className="bd-group row">
                {route.hops.map((hop) => (
                    <div key={hop.number} className="hop">
                        <h3 className="h5 d-flex flex-wrap align-items-center gap-2">
                            <span className="route-step">{hop.number}</span>
                            <span className="text-break">
                                {senderName(hop) ? <DomainLink domain={senderName(hop)} /> : <Muted>Unknown sender</Muted>} <i className="bi bi-arrow-right mx-1" />
                                {hop.by?.name ? <DomainLink domain={hop.by.name} /> : <Muted>unknown</Muted>}
                            </span>
                            <SecurityBadge security={hop.security} detail={hop.tls?.version} />
                            {hop.delay !== null && <span className="badge text-bg-dark">{delayLabel(hop.delay)}</span>}
                        </h3>
                        {hop.warnings.map((w) => (
                            <Alert key={w} variant="warning" className="py-1 px-2 small">
                                {w}
                            </Alert>
                        ))}
                        <FactList
                            labelCols={3}
                            facts={[
                                ...(hop.from?.ip ? [{ label: 'From IP', value: hop.from.ip, kind: 'ip' as const }] : []),
                                ...(hop.from?.helo || (hop.from?.name && hop.from.rdns && hop.from.name !== hop.from.rdns)
                                    ? [{ label: 'Introduced itself as', value: (hop.from.helo ?? hop.from.name) as string, kind: 'domain' as const, hint: 'The HELO/EHLO name the sending server gave. It can be anything; the reverse DNS name is what the receiver verified.' }]
                                    : []),
                                ...(hop.from?.noRdns ? [{ label: 'Reverse DNS', value: 'None', tone: 'warn' as const }] : []),
                                ...(hop.from?.mayBeForged ? [{ label: 'Reverse DNS', value: "Doesn't match (\"may be forged\")", tone: 'bad' as const }] : []),
                                ...(hop.protocol ? [{ label: 'Protocol', value: describeProtocol(hop.protocol) ?? hop.protocol, raw: hop.protocol }] : []),
                                ...(hop.tls?.cipher ? [{ label: 'Cipher', value: hop.tls.cipher, mono: true }] : []),
                                ...(hop.tls?.bits ? [{ label: 'Key size', value: `${hop.tls.bits} bits` }] : []),
                                ...(hop.tls?.note ? [{ label: 'TLS', value: hop.tls.note }] : []),
                                ...(hop.authenticated ? [{ label: 'Logged in as', value: hop.authenticated === 'yes' ? 'Yes (SMTP AUTH)' : hop.authenticated, tone: 'info' as const }] : []),
                                ...(hop.software ? [{ label: 'Server software', value: hop.software }] : []),
                                ...(hop.via ? [{ label: 'Via', value: hop.via }] : []),
                                ...(hop.id ? [{ label: 'Queue id', value: hop.id, mono: true, hint: "The receiving server's id for this message: what its admin would search the logs for." }] : []),
                                ...(hop.for ? [{ label: 'For', value: hop.for, kind: 'email' as const }] : []),
                                ...(hop.envelopeFrom ? [{ label: 'Envelope sender', value: hop.envelopeFrom, kind: 'email' as const }] : []),
                                ...(hop.date ? timeFacts('Time', hop.date.time, hop.date.offset) : []),
                            ]}
                        />
                        <details className="mt-1">
                            <summary className="small text-body-secondary">Raw header</summary>
                            <CodeBlock copy>{hop.header.raw}</CodeBlock>
                        </details>
                    </div>
                ))}
                {!route.hops.length && <p className="mb-0">No Received headers.</p>}
            </div>
        </>
    );
}

function RouteMap({ stops, data }: { stops: Stop[]; data: RelayLookup }) {
    const markers = useMemo<MapMarker[]>(() => {
        const out: MapMarker[] = [];
        const ranges: [number, number][] = [];
        withResolvedIps(stops, data).forEach((stop, i) => {
            const location = stop.ip ? data.ips[stop.ip]?.location : null;
            if (location?.lat == null || location.lon == null || (location.lat === 0 && location.lon === 0)) return;
            const previous = out[out.length - 1];
            const lines = [
                { strong: `${i + 1}.`, text: stop.name ?? 'Unknown' },
                { strong: 'IP:', text: `${stop.ip}${stop.ipSource === 'dns' ? ' (from DNS today)' : ''}` },
                { strong: 'Location:', text: locationLabel(location) },
                ...(location.org ? [{ strong: 'Network:', text: location.org }] : []),
            ];
            // Consecutive servers in the same place share a pin.
            if (previous && previous.lat === location.lat && previous.lng === location.lon) {
                const range = ranges[ranges.length - 1];
                range[1] = i + 1;
                previous.label = `${range[0]}–${range[1]}`;
                previous.lines.push({ text: ' ' }, ...lines);
                return;
            }
            out.push({ lat: location.lat, lng: location.lon, title: stop.name ?? stop.ip ?? '', label: String(i + 1), lines });
            ranges.push([i + 1, i + 1]);
        });
        return out;
    }, [stops, data]);

    return <GoogleMap markers={markers} zoom={4} path className="google-map--route" />;
}

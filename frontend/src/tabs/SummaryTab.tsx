import { useMemo, type ReactNode } from 'react';
import { Alert } from 'react-bootstrap';
import { GoogleMap, type MapMarker } from '../components/GoogleMap';
import { EmailLink, useLookup } from '../components/links';
import { RouteFlow } from '../components/RouteFlow';
import { Await, Dl, HelpButton, Muted, SectionTitle } from '../components/ui';
import type { Analysis } from '../lib/analyze';
import { formatInZone, formatLocal, locationLabel, secondsToTime } from '../lib/format';
import { findHeader } from '../lib/message';
import { parseDate } from '../lib/date';
import { parseAddressList } from '../lib/address';
import { withResolvedIps, type Stop } from '../lib/stops';
import { AuthOverview } from './AuthTab';
import { TONE_CLASS } from '../components/facts';
import { SenderReport } from '../components/SenderReport';
import { LookalikeAlert } from '../components/Lookalikes';
import type { LookalikeFinding } from '../lib/lookalike';
import type { AsyncState, NetworkInfo } from '../types';
import type { LiveAuth } from '../lib/liveAuth';

type Row = [ReactNode, ReactNode];

export function SummaryTab({
    analysis,
    stops,
    networks,
    live,
    lookalikes,
    onShowTab,
}: {
    analysis: Analysis;
    stops: Stop[];
    networks: AsyncState<Record<string, NetworkInfo | null>>;
    live: AsyncState<LiveAuth>;
    lookalikes: LookalikeFinding[];
    onShowTab: (tab: string) => void;
}) {
    const { route, services } = analysis;
    const headers = analysis.message.headers;
    const date = parseDate(findHeader(headers, 'date')?.value);
    const replyTo = parseAddressList(findHeader(headers, 'reply-to')?.decoded ?? '')[0];
    const deliveredTo = findHeader(headers, 'delivered-to')?.value ?? findHeader(headers, 'x-original-to')?.value ?? findHeader(headers, 'envelope-to')?.value;
    const returnPath = findHeader(headers, 'return-path')?.value.replace(/^<|>$/g, '');

    const rows: Row[] = [
        ['From', analysis.from ? <Mailbox name={analysis.from.name} address={analysis.from.address} /> : <Muted>Not set</Muted>],
        ['To', analysis.to.length ? analysis.to.map((m, i) => <div key={i}><Mailbox name={m.name} address={m.address} /></div>) : <Muted>Not set (hidden recipients)</Muted>],
    ];
    if (replyTo && replyTo.address.toLowerCase() !== analysis.from?.address.toLowerCase()) rows.push(['Reply-To', <Mailbox name={replyTo.name} address={replyTo.address} />]);
    if (deliveredTo) rows.push(['Delivered to', <EmailLink address={deliveredTo.trim()} />]);
    if (returnPath) rows.push(['Bounces to', <EmailLink address={returnPath} />]);
    rows.push([
        'Date',
        date ? (
            <>
                {formatInZone(date.time, date.offset)}
                <div className="small text-body-secondary">Your time: {formatLocal(date.time)}</div>
            </>
        ) : (
            <Muted>Not set</Muted>
        ),
    ]);
    if (route.totalSeconds !== null) rows.push(['Delivery time', `${secondsToTime(Math.abs(route.totalSeconds))}${route.totalSeconds < 0 ? ' (clocks disagree)' : ''}`]);

    const notes = useMemo(() => collectNotes(analysis), [analysis]);
    const spam = analysis.headers.filter((h) => h.summary && (h.info?.category === 'spam' || /-verdict$/.test(h.field.key)));
    const encrypted = route.counts.encrypted;
    const network = route.hops.length - route.counts.local - route.counts.internal;

    return (
        <>
            <LookalikeAlert findings={lookalikes} />
            <div className="row g-4">
                <div className="col-lg-8">
                    <SectionTitle>Overview</SectionTitle>
                    <div className="bd-group row">
                        <Dl labelCols={3} rows={rows} />
                    </div>
                </div>
                <div className="col-lg-4">
                    <SummaryMap stops={stops} />
                </div>
            </div>

            <SectionTitle className="mt-5">
                Route <HelpButton>The simplified path, from the first server on record to the mailbox. See the Route tab for each hop's details.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                <RouteFlow stops={stops} compact />
                <div className="mt-2">
                    <button type="button" className="btn btn-link p-0" onClick={() => onShowTab('route')}>
                        Hop-by-hop details and map →
                    </button>
                </div>
            </div>

            <SectionTitle className="mt-5">
                Authentication <HelpButton>As checked by the receiving server. DMARC is what ties the From address to the real sender.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                <div>
                    <AuthOverview analysis={analysis} live={live} />
                    <button type="button" className="btn btn-link p-0 mt-1" onClick={() => onShowTab('auth')}>
                        Every result, signature and ARC hop →
                    </button>
                </div>
            </div>

            <SenderReport analysis={analysis} networks={networks} live={live.status === 'ready' ? live.data : null} />

            <div className="row g-4 mt-4">
                <Card title="Services involved" help="Services recognised from their headers, server names, Message-ID and DKIM signatures: senders, gateways, spam filters, mail apps.">
                    {services.length ? (
                        services.slice(0, 5).map((s) => (
                            <div key={s.service.name} className="mb-1">
                                <strong>{s.service.name}</strong> <Muted>· {s.service.kind}{s.side === 'sending' ? ' · sending side' : s.side === 'receiving' ? ' · receiving side' : ''}</Muted>
                                <div className="small text-body-secondary">{s.evidence.slice(0, 2).join('; ')}</div>
                            </div>
                        ))
                    ) : (
                        <Muted>No known service recognised</Muted>
                    )}
                </Card>
                <Card title="Encryption in transit" help="Whether each network hop used TLS. Hops inside one machine or one provider's network are not counted.">
                    {network > 0 ? (
                        <span className={encrypted === network ? 'text-success' : 'text-warning'}>
                            <i className={`bi ${encrypted === network ? 'bi-lock-fill' : 'bi-unlock-fill'} me-1`} />
                            {encrypted === network ? `All ${network} network hop${network === 1 ? '' : 's'} encrypted` : `${encrypted} of ${network} network hops encrypted`}
                        </span>
                    ) : (
                        <Muted>No network hops recorded</Muted>
                    )}
                </Card>
                <Card title="Spam filtering" help="Verdicts recorded by spam filters along the way.">
                    {spam.length ? spam.slice(0, 4).map((h) => <div key={h.field.index} className="small">{h.summary}</div>) : <Muted>No spam-filter verdicts in the headers</Muted>}
                </Card>
            </div>

            {notes.length > 0 && (
                <>
                    <SectionTitle className="mt-5">Delivery notes</SectionTitle>
                    <div className="bd-group row">
                        <ul className="notes mb-0">
                            {notes.map((n, i) => (
                                <li key={i} className={TONE_CLASS[n.tone]}>
                                    {n.text}
                                </li>
                            ))}
                        </ul>
                    </div>
                </>
            )}
            {analysis.message.warnings.length > 0 && (
                <Alert variant="secondary" className="mt-4 small">
                    Some lines couldn't be read cleanly; see the Raw tab.
                </Alert>
            )}
        </>
    );
}

function Mailbox({ name, address }: { name: string | null; address: string }) {
    return (
        <>
            {name && <strong className="me-1">{name}</strong>}
            <span className={name ? 'text-body-secondary' : ''}>
                {name && '<'}
                <EmailLink address={address} />
                {name && '>'}
            </span>
        </>
    );
}

function Card({ title, help, children }: { title: ReactNode; help: string; children: ReactNode }) {
    return (
        <div className="col-md-4">
            <h3 className="h5">
                {title} <HelpButton>{help}</HelpButton>
            </h3>
            <div className="alert alert-light mb-0">{children}</div>
        </div>
    );
}

function SummaryMap({ stops }: { stops: Stop[] }) {
    const lookup = useLookup();
    return (
        <Await state={lookup} label="Locating servers">
            {(data) => {
                const located = withResolvedIps(stops, data)
                    .map((stop, i) => ({ stop, i, location: stop.ip ? data.ips[stop.ip]?.location : null }))
                    .filter((s) => s.location?.lat != null && s.location.lon != null);
                const markers: MapMarker[] = located.map(({ stop, i, location }) => ({
                    lat: location!.lat as number,
                    lng: location!.lon as number,
                    label: String(i + 1),
                    title: stop.name ?? '',
                    lines: [{ strong: `${i + 1}.`, text: stop.name ?? stop.ip ?? '' }, { strong: 'Location:', text: locationLabel(location) }],
                }));
                return <GoogleMap markers={markers} zoom={3} path className="map-single" />;
            }}
        </Await>
    );
}

interface Note {
    text: string;
    tone: 'good' | 'bad' | 'warn' | 'info' | 'muted';
}

/** Delivery problems worth reading: authentication and sender findings have their own sections above. */
function collectNotes(analysis: Analysis): Note[] {
    const notes: Note[] = [];
    for (const warning of analysis.route.warnings) notes.push({ tone: 'warn', text: warning });
    for (const hop of analysis.route.hops) for (const w of hop.warnings) notes.push({ tone: 'warn', text: `Hop ${hop.number}: ${w}` });
    return notes;
}

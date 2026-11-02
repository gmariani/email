import { Alert, Badge, Spinner } from 'react-bootstrap';
import type { Analysis } from '../lib/analyze';
import { checkedAuth, type LiveAuth } from '../lib/liveAuth';
import { senderReport, type Identity, type ReportTarget } from '../lib/sender';
import type { AsyncState, NetworkInfo } from '../types';
import { TONE_CLASS } from './facts';
import { DomainLink, EmailLink, IpLabel } from './links';
import { CopyButton, HelpButton, Muted, SectionTitle, Tip } from './ui';

type Networks = AsyncState<Record<string, NetworkInfo | null>>;

/**
 * Who the message says it's from, who the headers show actually sent it, and
 * who to report it to, in the order most likely to get it stopped.
 */
export function SenderReport({ analysis, networks, live }: { analysis: Analysis; networks: Networks; live: LiveAuth | null }) {
    // The same results as the Authentication summary: live checks fill gaps and overrule claims that don't hold up.
    const report = senderReport({ ...analysis, auth: checkedAuth(analysis.auth, live).auth }, networks.status === 'ready' ? networks.data : null);
    const headers = analysis.message.headers.map((h) => h.raw).join('\n');

    return (
        <>
            <SectionTitle className="mt-5">
                Who sent it <HelpButton>The From line is written by the sender and can say anything. The right-hand side is what the servers along the way recorded: whether the From address holds up, the account that logged in, and the service or server that sent it, which is who to block or report. The Route, Authentication and Headers tabs have the details.</HelpButton>
            </SectionTitle>
            {/* gx-4 only: a vertical gutter (g-4) gives the row a negative top margin, which drags the group's border into the heading. */}
            <div className="bd-group row gx-4">
                <div className="col-lg-5 mb-3">
                    <h3 className="h6 text-body-secondary text-uppercase small">What it says</h3>
                    {report.claimed.length ? <IdentityList items={report.claimed} /> : <Muted>No From address</Muted>}
                </div>
                <div className="col-lg-7 mb-3">
                    <h3 className="h6 text-body-secondary text-uppercase small">Who really sent it</h3>
                    {report.actual.length ? <IdentityList items={report.actual} /> : <Muted>Nothing beyond the From line</Muted>}
                </div>
                {report.findings.length > 0 && (
                    <ul className="notes mb-0 col-12 ps-4">
                        {report.findings.map((f, i) => (
                            <li key={i} className={TONE_CLASS[f.tone]}>
                                {f.text}
                            </li>
                        ))}
                    </ul>
                )}
            </div>

            <SectionTitle className="mt-5">
                Where to report it{' '}
                <HelpButton>
                    In order: the service that sent it can close the account; the owner of the network it came from can shut down the server; the domain's registrar can suspend the domain. Always include the full headers.
                    <br />
                    <br />
                    Network owners and their abuse addresses come live from the regional internet registry (ARIN, RIPE…). Contacts for sending services are from this site's list; if one bounces, check the service's website.
                </HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                <Alert variant="secondary" className="d-flex flex-wrap align-items-center gap-2 py-2">
                    <span className="flex-grow-1">Abuse desks need the full headers, not a screenshot or a forward. Paste them into your report:</span>
                    <span className="d-inline-flex align-items-center">
                        Copy headers <CopyButton text={headers} />
                    </span>
                </Alert>
                <ol className="report-targets">
                    {report.targets.map((target, i) => (
                        <Target key={i} target={target} />
                    ))}
                    {networks.status === 'loading' && (
                        <li className="text-body-secondary">
                            <Spinner animation="border" size="sm" className="me-2" />
                            Asking the internet registries who owns the sending network…
                        </li>
                    )}
                    {networks.status === 'error' && <li className="text-body-secondary">Couldn't look up the network owner: {networks.error}</li>}
                </ol>
            </div>
        </>
    );
}

function IdentityList({ items }: { items: Identity[] }) {
    return (
        <dl className="row facts mb-0">
            {items.map((item, i) => (
                <div key={i} className="contents">
                    <dt className="col-sm-4">{item.label}</dt>
                    <dd className="col-sm-8 text-break">
                        <span className={item.tone ? TONE_CLASS[item.tone] : ''}>
                            {item.kind === 'email' ? <EmailLink address={item.value} /> : item.kind === 'ip' ? <IpLabel ip={item.value} showPlace /> : item.kind === 'domain' ? <DomainLink domain={item.value} /> : <Long value={item.value} />}
                        </span>
                        {item.hint && (
                            <Tip label={item.hint}>
                                <i className="bi bi-info-circle fact-hint" aria-label={item.hint} />
                            </Tip>
                        )}
                        {item.details?.map((d) => (
                            <div key={d.label + d.value} className="small">
                                <span className="text-body-secondary">{d.label}:</span> <Long value={d.value} code={d.label !== 'Kind' && d.label !== 'Network owner'} />
                            </div>
                        ))}
                    </dd>
                </div>
            ))}
        </dl>
    );
}

/** Long ids (Feedback-ID, X-SG-EID…) shortened in the middle; hover to see, click the icon to copy. */
function Long({ value, code = false }: { value: string; code?: boolean }) {
    const short = value.length > 48 ? `${value.slice(0, 22)}…${value.slice(-18)}` : value;
    const text = code ? <code>{short}</code> : <span className="font-monospace small">{short}</span>;
    if (short === value) return code ? <code className="text-break">{value}</code> : <>{value}</>;
    return (
        <>
            <Tip label={value}>{text}</Tip>
            <CopyButton text={value} />
        </>
    );
}

const SOURCE_BADGE: Record<ReportTarget['source'], string | null> = {
    service: null,
    registry: 'from the registry',
    domain: null,
    general: null,
};

function Target({ target }: { target: ReportTarget }) {
    const subject = 'Abuse report: spam/phishing sent through your service';
    return (
        <li className="report-target">
            <div className="d-flex flex-wrap align-items-center gap-2">
                <strong>{target.who}</strong>
                <Badge bg="secondary">{target.role}</Badge>
                {SOURCE_BADGE[target.source] && <span className="small text-body-secondary">{SOURCE_BADGE[target.source]}</span>}
            </div>
            <div className="text-body-secondary small mb-1">{target.why}</div>
            <div className="d-flex flex-wrap gap-3">
                {target.email && (
                    <span>
                        <i className="bi bi-envelope me-1" />
                        <a href={`mailto:${target.email}?subject=${encodeURIComponent(subject)}`}>{target.email}</a>
                        <CopyButton text={target.email} />
                    </span>
                )}
                {target.url && (
                    <a href={target.url} target="_blank" rel="noopener noreferrer">
                        <i className="bi bi-box-arrow-up-right me-1" />
                        {target.source === 'domain' ? 'Look up the registrar (ICANN)' : 'Report form'}
                    </a>
                )}
                {!target.email && !target.url && <Muted>No abuse contact on record: look on their website.</Muted>}
            </div>
            {target.quote.length > 0 && (
                <div className="small mt-1">
                    <span className="text-body-secondary">Quote: </span>
                    {target.quote.map((q, i) => (
                        <span key={i} className="me-3 text-nowrap">
                            {q.name}: <Long value={q.value} code />
                        </span>
                    ))}
                </div>
            )}
        </li>
    );
}

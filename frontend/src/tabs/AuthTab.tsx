import type { ReactNode } from 'react';
import { Alert, Badge } from 'react-bootstrap';
import { FactList } from '../components/facts';
import { DomainLink } from '../components/links';
import { Await, CodeBlock, HelpButton, Muted, SectionTitle } from '../components/ui';
import { DkimSection, DmarcSection, LiveNote, ServerSection, SpfSection } from '../components/AuthChecks';
import { checkedAuth, liveVerdicts, withLive, type AuthConflict, type LiveAuth } from '../lib/liveAuth';
import type { AsyncState } from '../types';
import type { Analysis } from '../lib/analyze';
import { sourceLabel, type Verdict, type VerdictSource } from '../lib/auth';
import type { ExplainedHeader } from '../lib/explain';
import type { HeaderField } from '../lib/message';

export const VERDICT_BADGE: Record<Verdict, { bg: string; text?: 'dark'; label: string }> = {
    pass: { bg: 'success', label: 'Pass' },
    fail: { bg: 'danger', label: 'Fail' },
    softfail: { bg: 'warning', text: 'dark', label: 'Soft fail' },
    neutral: { bg: 'secondary', label: 'Neutral' },
    none: { bg: 'secondary', label: 'None' },
    error: { bg: 'warning', text: 'dark', label: 'Error' },
    unknown: { bg: 'dark', label: 'Not checked' },
};

export function VerdictBadge({ verdict, className = '' }: { verdict: Verdict; className?: string }) {
    const b = VERDICT_BADGE[verdict];
    return (
        <Badge bg={b.bg} text={b.text} className={className}>
            {b.label}
        </Badge>
    );
}

export function AuthTab({ analysis, live, onRetry }: { analysis: Analysis; live: AsyncState<LiveAuth>; onRetry: () => void }) {
    const { auth } = analysis;
    const explained = (field: HeaderField) => analysis.headers.find((h) => h.field === field);

    return (
        <>
            <AuthOverview analysis={analysis} live={live} />

            <div className="mt-5">
                <Await state={live} label="Checking SPF, DKIM keys, DMARC and the sending server" onRetry={onRetry}>
                    {(data) => (
                        <>
                            <LiveNote live={data} />
                            <SpfSection analysis={analysis} live={data} />
                            <DkimSection analysis={analysis} live={data} explained={explained} />
                            <DmarcSection analysis={analysis} live={data} />
                            <ServerSection live={data} />
                        </>
                    )}
                </Await>
            </div>

            <SectionTitle className="mt-5">
                Recorded by servers <HelpButton>The raw results servers wrote into the headers. Each server that checks SPF, DKIM and DMARC can add an Authentication-Results header; the topmost was added last, normally by your own provider: that's the one to trust. Lower ones may have been added (or forged) earlier on the path.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                <details>
                    <summary>
                        {auth.results.length + auth.receivedSpf.length} header{auth.results.length + auth.receivedSpf.length === 1 ? '' : 's'}
                        {auth.arc.length ? ` and ${auth.arc.length} ARC hop${auth.arc.length === 1 ? '' : 's'}` : ''}
                    </summary>
                    {!auth.results.length && <p className="mt-2 mb-0">No Authentication-Results header: the receiving server didn't record its checks.</p>}
                    {auth.results.map((r, i) => (
                        <HeaderBlock key={i} explained={explained(r.header)} title={`${r.authservId || 'Receiving server (no name given)'}${i === 0 ? ' (most recent)' : ''}`} />
                    ))}
                    {auth.receivedSpf.map((spf, i) => (
                        <HeaderBlock key={`spf${i}`} explained={explained(spf.header)} title={`Received-SPF: ${spf.result}`} />
                    ))}
                    {auth.arc.map((set) => (
                        <div key={set.instance} className="mt-3">
                            <h3 className="h6">
                                ARC hop i={set.instance}: sealed by <DomainLink domain={set.seal?.d ?? null} />{' '}
                                <Badge bg={set.seal?.cv === 'fail' ? 'danger' : 'secondary'}>cv={set.seal?.cv ?? '?'}</Badge>{' '}
                                <HelpButton>When a mailing list or forwarder changes a message, DKIM breaks. ARC lets each forwarder record the results it saw and seal them, so the final receiver can choose to trust them.</HelpButton>
                            </h3>
                            {set.results && <HeaderBlock explained={explained(set.results.header)} title="Results this forwarder saw" />}
                        </div>
                    ))}
                </details>
            </div>
            {live.status === 'error' && auth.dkim.length > 0 && (
                <>
                    <SectionTitle className="mt-5">DKIM signatures</SectionTitle>
                    <div className="bd-group row">
                        {auth.dkim.map((sig, i) => (
                            <HeaderBlock key={i} explained={explained(sig.header)} title={`${sig.domain ?? 'Unknown domain'}${sig.selector ? ` · selector ${sig.selector}` : ''}`} />
                        ))}
                    </div>
                </>
            )}
        </>
    );
}

/** Plain-English conclusion first, then SPF / DKIM / DMARC side by side. Shown on the Summary too. */
export function AuthOverview({ analysis: recorded, live }: { analysis: Analysis; live: AsyncState<LiveAuth> }) {
    // Fill in what no server recorded with this page's own live checks.
    const data = live.status === 'ready' ? live.data : null;
    const now = data ? liveVerdicts(recorded.auth, data) : null;
    // A recorded pass that can't be backed up isn't shown as a pass: the cards show what checks out now.
    const { auth, conflicts } = checkedAuth(recorded.auth, data);
    // The headline still says what the headers claimed, and that it doesn't hold up.
    const headline = authHeadline({ ...recorded, auth: withLive(recorded.auth, data) }, conflicts);
    const conflicted = (method: AuthConflict['method']) => conflicts.some((c) => c.method === method);
    const from = auth.fromDomain;
    const viaArc = [auth.spf.source, auth.dkimVerdict.source, auth.dmarc.source].find((s) => s && s.arc !== null);
    const nowState = (v: { verdict: Verdict } | null | undefined, why: string): LiveState =>
        live.status === 'loading' || live.status === 'idle' ? { status: 'pending' } : live.status === 'error' ? { status: 'failed', why: live.error } : v ? { status: 'done', verdict: v.verdict } : { status: 'failed', why };
    return (
        <>
            <Alert variant={headline.variant} className="d-flex gap-2 align-items-start">
                <i className={`bi ${headline.icon} fs-5`} />
                <div>
                    <strong>{headline.title}</strong> {headline.text}
                </div>
            </Alert>
            <div className="row g-4">
                <AuthCard
                    title={<abbr title="Sender Policy Framework">SPF</abbr>}
                    verdict={auth.spf.verdict}
                    recorded={recorded.auth.spf}
                    conflict={conflicted('SPF')}
                    now={nowState(now?.spf, 'no public IP for the sending server')}
                    help="SPF: the domain in the envelope sender (Return-Path) publishes which servers may send for it. The receiver checks the IP of the server that connected against that list."
                >
                    <SpfText auth={auth} />
                    {auth.spf.verdict === 'pass' && <Aligned ok={auth.spf.aligned} domain={auth.spf.domain} from={from} />}
                </AuthCard>
                <AuthCard
                    title={<abbr title="DomainKeys Identified Mail">DKIM</abbr>}
                    verdict={auth.dkimVerdict.verdict}
                    recorded={recorded.auth.dkimVerdict}
                    conflict={conflicted('DKIM')}
                    now={nowState(now?.dkimVerdict, 'no signature to check')}
                    help="DKIM: a signature made with a key the signing domain publishes in DNS. A valid one proves that domain sent (or approved) the message and that the signed parts weren't changed."
                >
                    <DkimText auth={auth} />
                    {auth.dkimVerdict.verdict === 'pass' && <Aligned ok={auth.dkimVerdict.aligned} domain={auth.dkimVerdict.domains.join(', ')} from={from} />}
                </AuthCard>
                <AuthCard
                    title={<abbr title="Domain-based Message Authentication, Reporting & Conformance">DMARC</abbr>}
                    verdict={auth.dmarc.verdict}
                    recorded={recorded.auth.dmarc}
                    conflict={conflicted('DMARC')}
                    now={nowState(now?.dmarc, 'the DNS lookup failed')}
                    help="DMARC passes when SPF or DKIM passed for a domain matching the From address. The From domain's policy says what receivers should do when it fails: none, quarantine (spam folder) or reject."
                >
                    <DmarcText auth={auth} />
                </AuthCard>
            </div>
            {conflicts.length > 0 && (
                <Alert variant={conflicts.some((c) => c.strong) ? 'danger' : 'warning'} className="mt-3 mb-0 py-2">
                    <strong>What the email says doesn't match what can be checked now.</strong>
                    <ul className="mb-0 mt-1 ps-3">
                        {conflicts.map((c) => (
                            <li key={c.text}>{c.text}</li>
                        ))}
                    </ul>
                    {conflicts.some((c) => c.strong) && (
                        <div className="small mt-1">
                            Results in ARC headers are written by a server along the way, often on the sender's side, and this page doesn't verify their seal. A sender can add whatever results it likes, so treat the recorded pass as unproven.
                        </div>
                    )}
                </Alert>
            )}
            {viaArc && (
                <p className="small text-body-secondary mt-2 mb-0">
                    <i className="bi bi-info-circle me-1" />
                    Some results come from the ARC record of <strong>{viaArc.server ?? 'an earlier server'}</strong>: checks it made before passing the message on (forwarding, a gateway or a mailing list). They're as trustworthy as that server.
                </p>
            )}
        </>
    );
}

type Auth = Analysis['auth'];

const Domain = ({ d }: { d: string | null }) => (d ? <DomainLink domain={d} /> : <Muted>unknown</Muted>);

function SpfText({ auth }: { auth: Auth }) {
    const { verdict, domain, ip } = auth.spf;
    const server = ip ? <code>{ip}</code> : 'the sending server';
    switch (verdict) {
        case 'pass':
            return <div>{server} is allowed to send for <Domain d={domain} />.</div>;
        case 'fail':
            return <div className="text-danger"><Domain d={domain} /> says {server} may <strong>not</strong> send for it.</div>;
        case 'softfail':
            return <div className="text-warning"><Domain d={domain} /> says {server} probably isn't allowed to send for it.</div>;
        case 'neutral':
            return <div><Domain d={domain} /> makes no claim about {server}.</div>;
        case 'none':
            return <div><Domain d={domain} /> publishes no SPF record, so nothing says which servers may send for it.</div>;
        case 'error':
            return <div className="text-warning">The check failed with an error (a broken SPF record or a DNS problem) for <Domain d={domain} />.</div>;
        default:
            return <div className="text-body-secondary">Not checked{domain ? <> for <Domain d={domain} /></> : null}: the email has no result and the live check couldn't run.</div>;
    }
}

function DkimText({ auth }: { auth: Auth }) {
    const { verdict, domains, failed } = auth.dkimVerdict;
    const list = (ds: string[]) => ds.map((d, i) => (
        <span key={d}>
            {i > 0 && ', '}
            <DomainLink domain={d} />
        </span>
    ));
    switch (verdict) {
        case 'pass':
            return (
                <div>
                    Signed by {list(domains)}; the signed content arrived unchanged.
                    {failed.length > 0 && <div className="small text-body-secondary">Another signature (by {list(failed)}) didn't verify.</div>}
                </div>
            );
        case 'fail':
            return <div className="text-danger">The signature{failed.length ? <> by {list(failed)}</> : null} didn't verify: the message was changed after signing, or the signature is fake.</div>;
        case 'none':
            return <div>The message isn't signed.</div>;
        case 'neutral':
            return <div className="text-warning">Signed by {list(domains)}: the signature is valid, but this copy's body differs from what was signed (often a modified copy, not a forgery).</div>;
        case 'unknown':
            return <div className="text-body-secondary">Signed by {list(domains)}, but the email has no result and the live check couldn't run.</div>;
        default:
            return <div className="text-warning">The signature couldn't be checked ({verdict}).</div>;
    }
}

function DmarcText({ auth }: { auth: Auth }) {
    const { verdict, policy } = auth.dmarc;
    const from = <Domain d={auth.fromDomain} />;
    const policyText = policy ? <div className="small">Published policy: <strong>{policy}</strong></div> : null;
    switch (verdict) {
        case 'pass':
            return <div>SPF or DKIM passed for {from}, the From domain.{policyText}</div>;
        case 'fail':
            return <div className="text-danger">Neither SPF nor DKIM passed for {from}, the From domain.{policyText}</div>;
        case 'none':
            return <div>{from} publishes no DMARC policy, so receivers don't check that its address is used legitimately.</div>;
        case 'unknown':
            return <div className="text-body-secondary">Not checked for {from}: the email has no result and the live check couldn't run.</div>;
        default:
            return <div className="text-warning">The DMARC check for {from} ended with "{verdict}".{policyText}</div>;
    }
}

function authHeadline({ auth }: Analysis, conflicts: AuthConflict[] = []): { variant: string; icon: string; title: string; text: string } {
    const domain = auth.fromDomain ?? 'the From domain';
    // A recorded pass that doesn't hold up can't be the headline.
    if (auth.dmarc.verdict === 'pass' && conflicts.some((c) => c.strong)) {
        return { variant: 'danger', icon: 'bi-shield-exclamation', title: 'Unproven.', text: `The headers claim this passed DMARC for ${domain}, but the claim doesn't hold up when checked now (see below). Treat the From address as possibly forged.` };
    }
    const policy = auth.dmarc.policy ? ` Its published policy is "${auth.dmarc.policy}".` : '';
    if (auth.dmarc.verdict === 'pass') {
        return { variant: 'success', icon: 'bi-patch-check-fill', title: 'Verified.', text: `This message really comes from ${domain}: it passed DMARC, so the From domain wasn't forged. (A hacked account at ${domain} would still pass.)` };
    }
    if (auth.dmarc.verdict === 'fail') {
        return { variant: 'danger', icon: 'bi-x-octagon-fill', title: 'Failed.', text: `This message could not be verified as coming from ${domain}. Treat the From address as forged.${policy}` };
    }
    if (auth.spf.aligned || auth.dkimVerdict.aligned) {
        const how = [auth.spf.aligned ? 'SPF' : null, auth.dkimVerdict.aligned ? 'DKIM' : null].filter(Boolean).join(' and ');
        return { variant: 'success', icon: 'bi-check-circle-fill', title: 'Probably genuine.', text: `${how} passed for ${domain}, though no DMARC result was recorded.` };
    }
    if (auth.spf.verdict === 'unknown' && auth.dkimVerdict.verdict !== 'pass' && auth.dkimVerdict.verdict !== 'fail' && auth.dmarc.verdict === 'unknown') {
        return { variant: 'secondary', icon: 'bi-question-circle-fill', title: 'Not checked.', text: `No server recorded SPF, DKIM or DMARC results, so nothing proves this came from ${domain}.` };
    }
    return { variant: 'warning', icon: 'bi-exclamation-triangle-fill', title: 'Not verified.', text: `The checks that passed were for other domains, not ${domain}. The From address could be forged.` };
}

type LiveState = { status: 'pending' } | { status: 'failed'; why: string } | { status: 'done'; verdict: Verdict };

/**
 * One check: the verdict that counts (the email's own, else the live one) and
 * its explanation, then both sources side by side so it's clear which is which.
 */
function AuthCard({ title, verdict, recorded, conflict, now, help, children }: { title: ReactNode; verdict: Verdict; recorded: { verdict: Verdict; source: VerdictSource | null }; conflict: boolean; now: LiveState; help: string; children: ReactNode }) {
    const inEmail = recorded.verdict !== 'unknown';
    return (
        <div className="col-md-4">
            <h3>
                {title} <VerdictBadge verdict={verdict} className="ms-1 align-middle fs-6" /> <HelpButton>{help}</HelpButton>
            </h3>
            <div className="alert alert-light mb-0">
                {children}
                <dl className="auth-sources">
                    <dt>In the email</dt>
                    <dd>
                        {inEmail ? (
                            <>
                                <VerdictWord verdict={recorded.verdict} /> <span className="text-body-secondary">by {sourceLabel(recorded.source)}</span>
                                {conflict && (
                                    <div className="text-danger">
                                        <i className="bi bi-exclamation-triangle-fill me-1" />
                                        Doesn't hold up (see below)
                                    </div>
                                )}
                            </>
                        ) : (
                            <Muted>Not recorded</Muted>
                        )}
                    </dd>
                    <dt>Live check</dt>
                    <dd>
                        {now.status === 'pending' ? (
                            <Muted>Checking…</Muted>
                        ) : now.status === 'failed' ? (
                            <Muted>Couldn't run: {now.why}</Muted>
                        ) : (
                            <>
                                <VerdictWord verdict={now.verdict} />
                                {!inEmail && <span className="text-body-secondary"> (shown above)</span>}
                            </>
                        )}
                    </dd>
                </dl>
            </div>
        </div>
    );
}

const VERDICT_TONE: Partial<Record<Verdict, string>> = { pass: 'text-success', fail: 'text-danger', softfail: 'text-warning', error: 'text-warning' };

function VerdictWord({ verdict }: { verdict: Verdict }) {
    return <span className={VERDICT_TONE[verdict] ?? ''}>{VERDICT_BADGE[verdict].label}</span>;
}

/** Only shown once a check passed: does the domain it vouches for match the From address? */
function Aligned({ ok, domain, from }: { ok: boolean; domain: string | null; from: string | null }) {
    if (!from) return null;
    return (
        <div className={`small mt-1 ${ok ? 'text-success' : 'text-warning'}`}>
            <i className={`bi ${ok ? 'bi-check-circle-fill' : 'bi-exclamation-circle'} me-1`} />
            {ok ? `Matches the From domain (${from}).` : `${domain ?? 'That domain'} isn't the From domain (${from}), so this doesn't vouch for the From address.`}
        </div>
    );
}

function HeaderBlock({ explained, title }: { explained: ExplainedHeader | undefined; title: string }) {
    if (!explained) return null;
    return (
        <div className="header-block">
            <h3 className="h6">{title}</h3>
            {explained.summary && <p className="mb-2">{explained.summary}</p>}
            <FactList facts={explained.facts} labelCols={3} />
            <details>
                <summary className="small text-body-secondary">Raw header</summary>
                <CodeBlock copy>{explained.field.raw}</CodeBlock>
            </details>
        </div>
    );
}

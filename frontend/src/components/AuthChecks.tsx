import type { ReactNode } from 'react';
import { Alert } from 'react-bootstrap';
import type { Analysis } from '../lib/analyze';
import { aligned, sourceLabel, verdictOf, type AuthResult } from '../lib/auth';
import type { ExplainedHeader, Fact, Tone } from '../lib/explain';
import { dkimTagFacts } from '../lib/explain/authParts';
import { formatLocal } from '../lib/format';
import { mailFromDomain, type LiveAuth, type LiveDkim } from '../lib/liveAuth';
import type { DmarcCheck, SpfNode, SpfResult } from '../types';
import { FactList, TONE_CLASS } from './facts';
import { DomainLink, IpLabel } from './links';
import { CodeBlock, CopyButton, HelpButton, Muted, SectionTitle } from './ui';

// ------------------------------------------------------------ Shared bits

const ICON: Record<Tone, string> = {
    good: 'bi-check-circle-fill',
    bad: 'bi-x-circle-fill',
    warn: 'bi-exclamation-triangle-fill',
    info: 'bi-info-circle-fill',
    muted: 'bi-dash-circle',
};

/** One finding, mail-tester style: an icon and a sentence. */
function Status({ tone, children }: { tone: Tone; children: ReactNode }) {
    return (
        <div className={`check-status ${TONE_CLASS[tone]}`}>
            <i className={`bi ${ICON[tone]}`} />
            <div className="check-status-text">{children}</div>
        </div>
    );
}

function Recorded({ result, source }: { result: AuthResult | null; source: string | null }) {
    if (!result) return <Muted>Not recorded</Muted>;
    const v = verdictOf(result.result);
    return (
        <span className={v === 'pass' ? 'text-success' : v === 'fail' ? 'text-danger' : 'text-warning'}>
            {result.result}
            {source && <span className="text-body-secondary"> by {source}</span>}
        </span>
    );
}

function Record({ text }: { text: string }) {
    return (
        <span className="d-inline-flex align-items-start">
            <code className="text-break">{text}</code>
            <CopyButton text={text} />
        </span>
    );
}

/** header.i is "@example.com" or "user@example.com", or (Zoho) a bare "example.com". */
function identityIs(identity: string | undefined, domain: string): boolean {
    const i = (identity ?? '').toLowerCase();
    return i === domain || i.endsWith(`@${domain}`);
}

/** The receiving server's own result for a method (and, for DKIM, a domain). */
function recorded(analysis: Analysis, method: string, domain?: string | null): { result: AuthResult | null; source: string | null } {
    const sources = [
        ...analysis.auth.results.map((r) => ({ results: r.results, label: r.authservId || 'the receiving server' })),
        ...analysis.auth.arc.filter((s) => s.results).sort((a, b) => b.instance - a.instance).map((s) => ({ results: s.results!.results, label: sourceLabel({ server: s.results!.authservId || null, arc: s.instance, original: false }) })),
    ];
    for (const { results, label } of sources) {
        const found = results.find((r) => r.method === method && (!domain || (r.props['header.d'] ?? '').toLowerCase() === domain || identityIs(r.props['header.i'], domain)));
        if (found) return { result: found, source: label };
    }
    if (method === 'spf' && analysis.auth.receivedSpf[0]) {
        const spf = analysis.auth.receivedSpf[0];
        const receiver = spf.props.receiver && !/^<?unknown>?$/i.test(spf.props.receiver) ? spf.props.receiver : null;
        return { result: { method: 'spf', result: spf.result, reason: null, comment: spf.comment, props: spf.props, raw: '' }, source: receiver ?? 'the receiving server (Received-SPF)' };
    }
    return { result: null, source: null };
}

export function LiveNote({ live }: { live: LiveAuth }) {
    return (
        <p className="small text-body-secondary mb-3">
            <i className="bi bi-broadcast me-1" />
            Checked live against today's DNS ({formatLocal(Date.parse(live.checks.checkedAt))}){' '}
            <HelpButton>For an older message, records and keys may have changed since it was sent; the receiving server's own results show what it saw on arrival.</HelpButton>
        </p>
    );
}

// ------------------------------------------------------------------- SPF

const SPF_TONE: Record<SpfResult, Tone> = { pass: 'good', fail: 'bad', softfail: 'warn', neutral: 'warn', none: 'warn', temperror: 'warn', permerror: 'bad' };

export function SpfSection({ analysis, live }: { analysis: Analysis; live: LiveAuth }) {
    const spf = live.checks.spf;
    const ip = live.query.ip;
    const domain = mailFromDomain(live.query);
    const server = ip ? <IpLabel ip={ip} showPlace /> : <>the sending server</>;
    const receiver = recorded(analysis, 'spf');

    let headline: ReactNode;
    if (!spf) {
        headline = (
            <Status tone="muted">
                Can't check: {ip ? 'no envelope sender or HELO name to check against.' : "the headers don't show a public IP for the server that handed the message over."}
            </Status>
        );
    } else {
        const d = <DomainLink domain={spf.domain} />;
        const text: Record<SpfResult, ReactNode> = {
            pass: <>{server} is authorised to send for {d}.</>,
            fail: <>{server} is <strong>not</strong> authorised to send for {d}: its SPF record ends by rejecting everything else.</>,
            softfail: <>{server} isn't listed in {d}'s SPF record (soft fail: "probably not authorised").</>,
            neutral: <>{d}'s SPF record makes no claim about {server}.</>,
            none: <>{d} has no SPF record, so nothing says which servers may send for it.</>,
            temperror: <>The SPF check for {d} hit a temporary DNS error.</>,
            permerror: <>{d}'s SPF record is broken, so receivers treat it as an error: {spf.explanation}</>,
        };
        headline = <Status tone={SPF_TONE[spf.result]}>{text[spf.result]}</Status>;
    }

    const changed = spf && receiver.result && verdictOf(receiver.result.result) !== verdictOf(spf.result);
    return (
        <>
            <SectionTitle className="mt-5">
                <abbr title="Sender Policy Framework">SPF</abbr>{' '}
                <HelpButton>The domain in the envelope sender (MAIL FROM, shown as Return-Path) publishes a list of servers allowed to send for it. This checks the IP of the server that handed the message to the recipient's provider against that list.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                {headline}
                <FactList
                    labelCols={3}
                    facts={[
                        ...(live.query.mailFrom ? [{ label: 'Envelope sender', value: live.query.mailFrom, kind: 'email' as const, hint: 'SPF checks the domain of this address, not the From address.' }] : []),
                        ...(domain ? [{ label: 'Domain checked', value: domain, kind: 'domain' as const }] : []),
                        ...(ip ? [{ label: 'Sending server IP', value: ip, kind: 'ip' as const, hint: 'The last server before your provider took over: the one that connected to it.' }] : []),
                        ...(live.query.helo ? [{ label: 'HELO name', value: live.query.helo, kind: 'domain' as const }] : []),
                    ]}
                />
                <dl className="row facts mb-0">
                    {spf?.trace.record && (
                        <>
                            <dt className="col-sm-3">SPF record</dt>
                            <dd className="col-sm-9">
                                <Record text={spf.trace.record} />
                            </dd>
                        </>
                    )}
                    {spf && (
                        <>
                            <dt className="col-sm-3">DNS lookups</dt>
                            <dd className={`col-sm-9 ${spf.lookups >= spf.lookupLimit - 1 ? 'text-warning' : ''}`}>
                                {spf.lookups} of {spf.lookupLimit} allowed
                                {spf.lookups >= spf.lookupLimit - 1 && ': close to the limit; one more include and SPF breaks'}
                            </dd>
                        </>
                    )}
                    <dt className="col-sm-3">In the email</dt>
                    <dd className="col-sm-9">
                        <Recorded {...receiver} />
                    </dd>
                </dl>
                {changed && (
                    <Alert variant="secondary" className="py-2 small mt-2">
                        When the message arrived the result was <strong>{receiver.result?.result}</strong>; checking now gives <strong>{spf?.result}</strong>. The SPF record or the server's address has probably changed since.
                    </Alert>
                )}
                {spf && (
                    <details className="mt-2" open={spf.result !== 'pass'}>
                        <summary>How the record was evaluated</summary>
                        <SpfTrace node={spf.trace} />
                    </details>
                )}
            </div>
        </>
    );
}

function SpfTrace({ node }: { node: SpfNode }) {
    return (
        <div className="spf-trace">
            <div className="small text-body-secondary">
                <DomainLink domain={node.domain} /> {node.record ? <code>{node.record}</code> : <em>no SPF record</em>} → <strong>{node.result}</strong>
            </div>
            <ul>
                {node.terms.map((term, i) => (
                    <li key={i} className={term.matched ? 'spf-term-match' : term.matched === false ? '' : 'text-body-secondary'}>
                        <i className={`bi ${term.matched ? 'bi-check-circle-fill text-success' : term.matched === false ? 'bi-dash-circle' : 'bi-circle'} me-1`} />
                        <code>{term.raw}</code>
                        <span className="small ms-2">
                            {term.matched ? `matched → ${term.qualifier}` : term.matched === false ? 'no match' : term.kind === 'modifier' ? '' : 'not reached'}
                            {term.detail && <span className="text-body-secondary"> — {term.detail}</span>}
                        </span>
                        {term.child && <SpfTrace node={term.child} />}
                    </li>
                ))}
            </ul>
            {node.redirect && <SpfTrace node={node.redirect} />}
            {node.error && node.result !== 'pass' && <div className="small text-warning">{node.error}</div>}
        </div>
    );
}

// ------------------------------------------------------------------ DKIM

export function DkimSection({ analysis, live, explained }: { analysis: Analysis; live: LiveAuth; explained: (field: LiveDkim['signature']['header']) => ExplainedHeader | undefined }) {
    return (
        <>
            <SectionTitle className="mt-5">
                <abbr title="DomainKeys Identified Mail">DKIM</abbr>{' '}
                <HelpButton>The signing domain publishes a public key in DNS. The signature in the email must verify with that key: that proves the domain signed it, and the body hash proves the content wasn't changed. The check is done here in your browser.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                {live.dkim.length ? (
                    live.dkim.map((d, i) => <DkimSignatureCheck key={i} analysis={analysis} item={d} explained={explained(d.signature.header)} />)
                ) : (
                    <Status tone="warn">The message isn't DKIM-signed, so nothing proves which domain sent it or that it wasn't changed.</Status>
                )}
            </div>
        </>
    );
}

function DkimSignatureCheck({ analysis, item, explained }: { analysis: Analysis; item: LiveDkim; explained: ExplainedHeader | undefined }) {
    const { signature, key, verification } = item;
    const domain = signature.domain;
    const receiver = recorded(analysis, 'dkim', domain);
    const receiverPassed = receiver.result && verdictOf(receiver.result.result) === 'pass';
    const from = analysis.auth.fromDomain;

    let headline: ReactNode;
    if (!key?.found) {
        headline = <Status tone="bad">No public key is published at <code>{key?.host ?? `${signature.selector}._domainkey.${domain}`}</code>, so this signature can't be verified. {key?.error}</Status>;
    } else if (key.revoked) {
        headline = <Status tone="bad">The key at <code>{key.host}</code> has been revoked (empty p=), so this signature no longer verifies.</Status>;
    } else if (!verification) {
        headline = <Status tone="muted">Not verified.</Status>;
    } else if (verification.signatureOk && verification.bodyHashOk) {
        headline = <Status tone="good">Valid signature by <DomainLink domain={domain} />: it signed this message and the content is unchanged.</Status>;
    } else if (verification.signatureOk && verification.bodyHashOk === null) {
        headline = <Status tone="good">The signature by <DomainLink domain={domain} /> over the headers is valid. ({verification.bodyNote ?? "No body was provided, so the body hash wasn't checked."})</Status>;
    } else if (verification.signatureOk) {
        headline = (
            <Status tone="warn">
                The signature by <DomainLink domain={domain} /> over the headers is valid, but the body differs from what was signed.{' '}
                {receiverPassed
                    ? 'The receiving server recorded a pass, so the body was most likely altered after delivery: copying from a web page or editor trims spaces, and some mail apps rewrite messages.'
                    : 'It was changed after signing: by a forwarder, a mailing list footer, or tampering.'}
            </Status>
        );
    } else {
        headline = <Status tone="bad">The signature by <DomainLink domain={domain} /> doesn't verify with the published key. {verification.error ?? 'The signed headers were changed, the key was rotated since, or the signature is forged.'}</Status>;
    }

    const t = signature.tags;
    const note = explained?.facts.find((f) => f.label === 'Note');

    return (
        <div className="dkim-check">
            <h3 className="h5">
                <DomainLink domain={domain} /> <Muted>· selector {signature.selector}</Muted>
            </h3>
            {headline}
            <h4 className="h6 text-uppercase small text-body-secondary mt-3">Signature in the email</h4>
            <FactList facts={dkimTagFacts(t)} labelCols={3} />
            {note && <p className="small text-warning mt-2 mb-0">{note.value}</p>}
            <h4 className="h6 text-uppercase small text-body-secondary mt-3">Public key in DNS</h4>
            {key?.found ? (
                <dl className="row facts mb-0">
                    <dt className="col-sm-3">Location</dt>
                    <dd className="col-sm-9 text-break"><code>{key.host}</code></dd>
                    <dt className="col-sm-3">Key</dt>
                    <dd className="col-sm-9">
                        {(key.keyType ?? 'rsa').toUpperCase()} {key.keyBits ? `${key.keyBits}-bit` : ''}
                        {key.weak && <div className="small text-danger">Too short: receivers may reject it. Use 2048 bits.</div>}
                        {key.keyType === 'rsa' && key.keyBits === 1024 && <div className="small text-warning">Works, but 2048 bits is recommended.</div>}
                    </dd>
                    {(key.testing || key.strict) && (
                        <>
                            <dt className="col-sm-3">Flags</dt>
                            <dd className="col-sm-9">
                                {key.testing && <div className="text-warning">t=y: testing mode; receivers may ignore failures</div>}
                                {key.strict && <div>t=s: the i= identity must be exactly the signing domain</div>}
                            </dd>
                        </>
                    )}
                    {key.hashes && (
                        <>
                            <dt className="col-sm-3">Allowed hashes</dt>
                            <dd className="col-sm-9">{key.hashes}</dd>
                        </>
                    )}
                    <dt className="col-sm-3">Record</dt>
                    <dd className="col-sm-9">
                        <details>
                            <summary className="small">Show</summary>
                            <CodeBlock copy>{key.record ?? ''}</CodeBlock>
                        </details>
                    </dd>
                </dl>
            ) : (
                <Muted>{key?.error ?? 'Not looked up.'}</Muted>
            )}
            <h4 className="h6 text-uppercase small text-body-secondary mt-3">Verification</h4>
            <ul className="check-list">
                <li className={verification?.bodyHashOk ? 'text-success' : verification?.bodyHashOk === false ? 'text-warning' : 'text-body-secondary'}>
                    <i className={`bi ${verification?.bodyHashOk ? 'bi-check-circle-fill' : verification?.bodyHashOk === false ? 'bi-x-circle-fill' : 'bi-dash-circle'} me-1`} />
                    Body hash {verification?.bodyHashOk ? 'matches: the body is unchanged' : verification?.bodyHashOk === false ? 'differs: the body was changed after signing' : 'not checked'}
                    {verification?.bodyNote && <div className="small text-body-secondary ms-4">{verification.bodyNote}</div>}
                    {verification?.bodyHashOk === false && (
                        <dl className="row facts small mb-0 ms-3">
                            <dt className="col-sm-3">Signed (bh=)</dt>
                            <dd className="col-sm-9 font-monospace text-break">{t.bh}</dd>
                            <dt className="col-sm-3">This copy</dt>
                            <dd className="col-sm-9 font-monospace text-break">{verification.computedBodyHash}</dd>
                        </dl>
                    )}
                </li>
                <li className={verification?.signatureOk ? 'text-success' : verification?.signatureOk === false ? 'text-danger' : 'text-body-secondary'}>
                    <i className={`bi ${verification?.signatureOk ? 'bi-check-circle-fill' : verification?.signatureOk === false ? 'bi-x-circle-fill' : 'bi-dash-circle'} me-1`} />
                    Signature {verification?.signatureOk ? 'verifies with the published key' : verification?.signatureOk === false ? "doesn't verify with the published key" : 'not checked'}
                </li>
                {from && (
                    <li className={aligned(domain, from) ? 'text-success' : 'text-body-secondary'}>
                        <i className={`bi ${aligned(domain, from) ? 'bi-check-circle-fill' : 'bi-dash-circle'} me-1`} />
                        {aligned(domain, from) ? `Signing domain matches the From domain (${from}), so it counts for DMARC` : `Signed by ${domain}, not the From domain (${from}), so it doesn't count for DMARC`}
                    </li>
                )}
                <li>
                    In the email: <Recorded {...receiver} />
                </li>
            </ul>
            {explained && (
                <details>
                    <summary className="small text-body-secondary">Raw signature header</summary>
                    <CodeBlock copy>{explained.field.raw}</CodeBlock>
                </details>
            )}
        </div>
    );
}

// ----------------------------------------------------------------- DMARC

const DMARC_POLICY: Record<string, string> = { none: 'None (monitor only)', quarantine: 'Quarantine (spam folder)', reject: 'Reject' };
const ALIGNMENT: Record<string, string> = { s: 'Strict', r: 'Relaxed' };

/** [name, friendly value (undefined: show as written), explanation] for each DMARC record tag. */
const DMARC_TAGS: Record<string, [string, (v: string) => string | undefined, string]> = {
    v: ['Version', () => undefined, 'Always DMARC1.'],
    p: ['Policy', (v) => DMARC_POLICY[v.toLowerCase()], 'What receivers should do with mail that fails DMARC.'],
    sp: ['Subdomain Policy', (v) => DMARC_POLICY[v.toLowerCase()], 'The same, for subdomains.'],
    np: ['Non-existent Subdomain Policy', (v) => DMARC_POLICY[v.toLowerCase()], "The same, for subdomains that don't exist."],
    pct: ['Percentage', (v) => `${v}% of failing mail`, 'The share of failing mail the policy applies to.'],
    adkim: ['DKIM Alignment', (v) => ALIGNMENT[v.toLowerCase()], 'Strict: the signing domain must equal the From domain exactly. Relaxed: subdomains of the same organisation count.'],
    aspf: ['SPF Alignment', (v) => ALIGNMENT[v.toLowerCase()], 'Strict: the envelope domain must equal the From domain exactly. Relaxed: subdomains of the same organisation count.'],
    rua: ['Aggregate Reports', () => undefined, 'Where receivers send daily aggregate reports: who sent mail as this domain, and whether it passed.'],
    ruf: ['Failure Reports', () => undefined, 'Where receivers send reports on individual failing messages (few receivers send them).'],
    fo: ['Failure Reporting Options', (v) => ({ '0': 'When SPF and DKIM both fail', '1': 'When either fails', d: 'When DKIM fails', s: 'When SPF fails' } as Record<string, string>)[v], 'When to send failure reports.'],
    rf: ['Report Format', () => undefined, 'The format of failure reports.'],
    ri: ['Report Interval', (v) => (/^\d+$/.test(v) ? `Every ${Math.round(parseInt(v, 10) / 3600)} hours` : undefined), 'The requested interval between aggregate reports.'],
    t: ['Testing', (v) => (v.toLowerCase() === 'y' ? 'Yes' : 'No'), 'In testing mode receivers apply a weaker policy.'],
};

/** The DMARC record's tags, one "Name (tag)" row each, like every other header breakdown. */
function dmarcTagFacts(dmarc: DmarcCheck): Fact[] {
    const facts: Fact[] = [];
    for (const [tag, raw] of Object.entries(dmarc.tags)) {
        const known = DMARC_TAGS[tag];
        if (!known) {
            facts.push({ label: tag, value: raw, mono: true, tone: 'muted', hint: 'Not a standard tag.' });
            continue;
        }
        const [name, decode, hint] = known;
        const value = decode(raw);
        facts.push({ label: `${name} (${tag})`, value: value ?? raw, raw: value ? raw : undefined, hint, tone: tag === 'p' && raw.toLowerCase() === 'none' ? 'warn' : undefined });
        if (tag === 'rua' || tag === 'ruf') {
            for (const r of dmarc.reports.filter((x) => x.tag === tag && x.external)) {
                facts.push({ label: 'Authorised', value: r.authorized ? `Yes, by ${r.domain}` : `No: ${r.domain} hasn't authorised these reports`, tone: r.authorized ? 'good' : 'warn', sub: true, hint: 'A domain receiving reports for another domain must publish a record allowing it.' });
            }
        }
    }
    return facts;
}

export function DmarcSection({ analysis, live }: { analysis: Analysis; live: LiveAuth }) {
    const dmarc = live.checks.dmarc;
    const receiver = recorded(analysis, 'dmarc');
    const from = analysis.auth.fromDomain;
    if (!dmarc) return null;
    const p = (dmarc.tags.p ?? '').toLowerCase();
    const rua = dmarc.reports.filter((r) => r.tag === 'rua');

    return (
        <>
            <SectionTitle className="mt-5">
                <abbr title="Domain-based Message Authentication, Reporting & Conformance">DMARC</abbr>{' '}
                <HelpButton>The From domain's DMARC record says how strictly to check it: a message passes when SPF or DKIM passed for a domain matching the From address. The policy says what receivers should do with mail that fails, and where to send reports.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                {dmarc.lookupFailed ? (
                    <Status tone="muted">{dmarc.errors[0]}</Status>
                ) : !dmarc.found ? (
                    <Status tone="bad">{dmarc.errors[0]}</Status>
                ) : (
                    <>
                        <Status tone={dmarc.valid ? 'good' : 'bad'}>
                            {dmarc.valid ? 'The DMARC record is valid' : 'The DMARC record is invalid, so receivers ignore it'}
                            {dmarc.inherited ? <>: there's none at _dmarc.{dmarc.domain}, so the organisation's record at <code>{dmarc.host}</code> applies.</> : '.'}
                            <div className="mt-1">
                                <Record text={dmarc.record ?? ''} />
                            </div>
                        </Status>
                        {dmarc.errors.map((e) => (
                            <Status key={e} tone="bad">
                                {e}
                            </Status>
                        ))}
                        {p === 'reject' || p === 'quarantine' ? (
                            <Status tone="good">
                                The policy is <strong>{p}</strong>: receivers {p === 'reject' ? 'refuse' : 'send to spam'} mail that fails DMARC, so the domain is protected against spoofing.
                            </Status>
                        ) : null}
                        {rua.length > 0 && (
                            <Status tone="good">
                                Aggregate reports go to {rua.map((r) => r.address).join(', ')}, so the domain owner can see who sends mail as their domain.
                            </Status>
                        )}
                        {dmarc.warnings.map((w) => (
                            <Status key={w} tone="warn">
                                {w}
                            </Status>
                        ))}
                    </>
                )}

                {dmarc.found && (
                    <div className="mt-3">
                        <FactList facts={dmarcTagFacts(dmarc)} labelCols={3} />
                    </div>
                )}

                <h4 className="h6 text-uppercase small text-body-secondary mt-3">
                    Does this message pass? <HelpButton>Worked out live from the SPF and DKIM checks above and this record.</HelpButton>
                </h4>
                <ul className="check-list">
                    <li className={live.dmarc.spfAligned ? 'text-success' : 'text-body-secondary'}>
                        <i className={`bi ${live.dmarc.spfAligned ? 'bi-check-circle-fill' : 'bi-dash-circle'} me-1`} />
                        SPF {live.dmarc.spfAligned ? 'passed for a domain matching From' : live.checks.spf?.result === 'pass' ? `passed, but for ${live.checks.spf.domain}, which doesn't match ${from}${live.dmarc.strictSpf ? ' (strict alignment)' : ''}` : "didn't pass"}
                    </li>
                    <li className={live.dmarc.dkimAligned ? 'text-success' : 'text-body-secondary'}>
                        <i className={`bi ${live.dmarc.dkimAligned ? 'bi-check-circle-fill' : 'bi-dash-circle'} me-1`} />
                        DKIM{' '}
                        {live.dmarc.dkimAligned
                            ? 'has a valid signature from a domain matching From'
                            : live.dkim.some((d) => d.valid)
                              ? `is valid, but signed by ${live.dkim.filter((d) => d.valid).map((d) => d.signature.domain).join(', ')}, not ${from}${live.dmarc.strictDkim ? ' (strict alignment)' : ''}`
                              : live.dkim.some((d) => d.verification?.signatureOk)
                                ? "signature is valid, but this copy's body differs from what was signed, so it can't count here"
                                : 'has no valid signature'}
                    </li>
                    <li className={live.dmarc.result === 'pass' ? 'text-success fw-semibold' : live.dmarc.result === 'fail' ? 'text-danger fw-semibold' : 'text-body-secondary'}>
                        Live check: DMARC {dmarc.lookupFailed ? "couldn't be checked" : live.dmarc.result === 'none' ? 'not applicable (no record)' : live.dmarc.result}
                        {live.dmarc.result === 'fail' && p && <>; the policy says <strong>{p}</strong></>}
                    </li>
                    <li>
                        In the email: <Recorded {...receiver} />
                    </li>
                </ul>
            </div>
        </>
    );
}

// -------------------------------------------------------- Sending server

export function ServerSection({ live }: { live: LiveAuth }) {
    const { reverse, helo, mail } = live.checks;
    const ip = live.query.ip;
    return (
        <>
            <SectionTitle className="mt-5">
                Reverse DNS{' '}
                <HelpButton>Receivers expect a mail server's IP address to have a name (a PTR record) that points back to the same address, and the name it introduced itself with (HELO) to resolve to it. Servers without these are usually junked.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                {ip && (
                    <p className="small text-body-secondary mb-1">
                        Checking <IpLabel ip={ip} showPlace /> <HelpButton>The last server before the recipient's provider took over.</HelpButton>
                    </p>
                )}
                {ip && reverse ? (
                    reverse.confirmed ? (
                        <Status tone="good">
                            <IpLabel ip={ip} /> is associated with <DomainLink domain={reverse.confirmed} />, which points back to the same address (forward-confirmed reverse DNS).
                        </Status>
                    ) : reverse.ptr.length ? (
                        <Status tone="warn">
                            <IpLabel ip={ip} /> has reverse DNS <DomainLink domain={reverse.ptr[0]} />, but that name {reverse.forward[reverse.ptr[0]]?.length ? `points to ${reverse.forward[reverse.ptr[0]].join(', ')}` : "doesn't resolve"}, not back to {ip}. Many receivers treat that as suspicious.
                        </Status>
                    ) : (
                        <Status tone="bad">
                            <IpLabel ip={ip} /> has no reverse DNS. Most large providers reject or junk mail from servers without it.
                        </Status>
                    )
                ) : (
                    <Status tone="muted">No public IP for the sending server in the headers, so reverse DNS wasn't checked.</Status>
                )}

                {helo &&
                    (helo.matchesIp ? (
                        <Status tone="good">
                            The HELO name <DomainLink domain={helo.host} /> is assigned to this server ({ip}).
                        </Status>
                    ) : (
                        <Status tone={helo.addresses.length ? 'warn' : 'bad'}>
                            The HELO name <DomainLink domain={helo.host} /> {helo.addresses.length ? `resolves to ${helo.addresses.join(', ')}, not ${ip}` : "doesn't resolve to any address"}.
                        </Status>
                    ))}

            </div>

            <SectionTitle className="mt-5">
                MX records{' '}
                <HelpButton>The sender's domains (envelope sender and From) should have mail servers (MX records), so replies and bounces can be delivered. Domains that can't receive mail are a common sign of a throwaway sender.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                {!Object.keys(mail).length && <Muted>No sender domain to check.</Muted>}
                {Object.entries(mail).map(([domain, info]) =>
                    info.nullMx ? (
                        <Status key={domain} tone="warn">
                            <DomainLink domain={domain} /> declares that it accepts no mail (null MX): replies and bounces to it will fail.
                        </Status>
                    ) : info.mx.length ? (
                        <Status key={domain} tone="good">
                            <DomainLink domain={domain} /> is assigned to a mail server:{' '}
                            {info.mx.map((m, i) => (
                                <span key={m.target}>
                                    {i > 0 && ', '}
                                    <code>
                                        {m.pri} {m.target}
                                    </code>
                                </span>
                            ))}
                        </Status>
                    ) : (
                        <Status key={domain} tone="warn">
                            <DomainLink domain={domain} /> has no MX record
                            {info.addresses.length ? ', so replies fall back to its web server address, which rarely accepts mail.' : ' or address: replies and bounces to it can\'t be delivered.'}
                        </Status>
                    ),
                )}
            </div>
        </>
    );
}


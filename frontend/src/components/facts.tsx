import type { ReactNode } from 'react';
import type { Fact, Tone } from '../lib/explain';
import type { Security } from '../lib/received';
import { DomainLink, EmailLink, IpLabel } from './links';
import { Marked } from './Lookalikes';
import { Tip } from './ui';

export const TONE_CLASS: Record<Tone, string> = {
    good: 'text-success',
    bad: 'text-danger',
    warn: 'text-warning',
    info: 'text-info',
    muted: 'text-body-secondary',
};

export function FactValue({ fact }: { fact: Fact }) {
    let value: ReactNode = <Marked text={fact.value} />;
    if (fact.kind === 'domain') value = <DomainLink domain={fact.value} />;
    else if (fact.kind === 'email') value = <EmailLink address={fact.value} />;
    else if (fact.kind === 'ip') value = <IpLabel ip={fact.value} showPlace />;
    else if (fact.kind === 'url')
        value = (
            <a href={fact.value} target="_blank" rel="noopener noreferrer nofollow" className="text-break">
                {fact.value}
            </a>
        );
    // The explanation, then the value as written whenever what's shown is its decoded meaning.
    const raw = fact.raw !== undefined && fact.raw !== fact.value ? fact.raw : null;
    const tip = fact.hint || raw !== null ? (
        <>
            {fact.hint}
            {fact.hint && raw !== null && <br />}
            {raw !== null && (
                <>
                    Raw value: <code>{raw}</code>
                </>
            )}
        </>
    ) : null;
    return (
        <span className={`${fact.tone ? TONE_CLASS[fact.tone] : ''} ${fact.mono ? 'font-monospace small text-break' : ''}`}>
            {value}
            {tip && (
                <Tip label={tip}>
                    <i className="bi bi-info-circle fact-hint" aria-label={[fact.hint, raw !== null ? `Raw value: ${raw}` : ''].filter(Boolean).join(' ')} />
                </Tip>
            )}
        </span>
    );
}

/** Label/value rows, in the same two-column layout as Dl. */
export function FactList({ facts, labelCols = 4 }: { facts: Fact[]; labelCols?: number }) {
    if (!facts.length) return null;
    return (
        <dl className="row facts mb-0">
            {facts.map((f, i) => (
                <FactRow key={i} fact={f} labelCols={labelCols} />
            ))}
        </dl>
    );
}

function FactRow({ fact, labelCols }: { fact: Fact; labelCols: number }) {
    return (
        <>
            <dt className={`col-sm-${labelCols} ${fact.sub ? 'fact-sub' : ''}`}>{fact.label}</dt>
            <dd className={`col-sm-${12 - labelCols}`}>
                <FactValue fact={fact} />
            </dd>
        </>
    );
}

const SECURITY: Record<Security, { icon: string; label: string; className: string; help: string }> = {
    encrypted: { icon: 'bi-lock-fill', label: 'Encrypted', className: 'link-encrypted', help: 'This connection used TLS: the message could not be read in transit.' },
    unencrypted: { icon: 'bi-unlock-fill', label: 'Not encrypted', className: 'link-unencrypted', help: 'This connection was plain text: anyone on the network path could read the message.' },
    local: { icon: 'bi-hdd-fill', label: 'Same machine', className: 'link-local', help: 'Handed from one program to another on the same server; it never crossed a network.' },
    internal: { icon: 'bi-building-fill-lock', label: 'Internal', className: 'link-internal', help: "Moved inside the provider's own network; the header doesn't say how." },
    unknown: { icon: 'bi-question-circle-fill', label: 'Unknown', className: 'link-unknown', help: "The server didn't record how the message arrived." },
};

export function SecurityBadge({ security, detail }: { security: Security; detail?: string | null }) {
    const s = SECURITY[security];
    return (
        <Tip label={s.help}>
            <span className={`security-badge ${s.className}`}>
                <i className={`bi ${s.icon}`} /> {detail || s.label}
            </span>
        </Tip>
    );
}

export function securityIcon(security: Security): { icon: string; className: string; label: string } {
    return SECURITY[security];
}

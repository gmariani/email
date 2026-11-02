import { createContext, useContext, type ReactNode } from 'react';
import { inspectorLink } from '../api';
import { flag, locationLabel } from '../lib/format';
import type { LookupState } from '../types';
import { Marked } from './Lookalikes';
import { Tip } from './ui';

/** The relay lookup for the current email, so any IP on the page can show where it is. */
export const LookupContext = createContext<LookupState>({ status: 'idle' });

export function useLookup(): LookupState {
    return useContext(LookupContext);
}

/** A domain, linked to the Domain Inspector when one is configured. */
export function DomainLink({ domain, children }: { domain: string | null | undefined; children?: ReactNode }) {
    const clean = domain?.toLowerCase().replace(/\.$/, '');
    const href = inspectorLink(clean);
    const text = children ?? (domain ? <Marked text={domain} /> : domain);
    if (!href) return <>{text}</>;
    return (
        <a href={href} target="_blank" rel="noopener" className="domain-link" title={`Look up ${clean} in Domain Inspector`}>
            {text}
        </a>
    );
}

/** The domain of an email address is the interesting part; link that. */
export function EmailLink({ address }: { address: string }) {
    const at = address.lastIndexOf('@');
    if (at < 0) return <Marked text={address} />;
    return (
        <>
            <Marked text={address.slice(0, at + 1)} />
            <DomainLink domain={address.slice(at + 1).replace(/>$/, '')} />
        </>
    );
}

/** An IP with its location and owner once the lookup has them. */
export function IpLabel({ ip, showPlace = false }: { ip: string; showPlace?: boolean }) {
    const lookup = useLookup();
    const info = lookup.status === 'ready' ? lookup.data.ips[ip] : undefined;
    const location = info?.location;
    const tip = info
        ? [info.hostname && `Reverse DNS: ${info.hostname}`, location && locationLabel(location), location?.org && `Network: ${location.org}${location.asn ? ` (AS${location.asn})` : ''}`, !info.public && 'Private address: only meaningful inside the sender\'s network']
              .filter(Boolean)
              .join('\n')
        : '';
    return (
        <Tip label={tip}>
            <span className="ip-label">
                <code>{ip}</code>
                {location?.countryCode && <span className="ms-1" aria-label={location.country ?? location.countryCode}>{flag(location.countryCode)}</span>}
                {showPlace && location && <span className="text-body-secondary small ms-1">{[location.city, location.countryCode].filter(Boolean).join(', ')}</span>}
            </span>
        </Tip>
    );
}

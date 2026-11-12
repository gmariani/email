import { createContext, useContext, type ReactNode } from 'react';
import { inspectorLink } from '../api';
import { organizationalDomain } from '../lib/auth';
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

/**
 * A URL with its registered domain picked out, so "paypal.com.evil.example"
 * or "user@host" tricks can't hide the site it really opens.
 */
export function UrlText({ url }: { url: string }) {
    // mailto:someone@host?subject=… — the address's domain is where it goes
    const mail = /^(mailto:[^@?,]*@)([^?,]*)(.*)$/is.exec(url);
    if (mail) {
        const [, before, host, rest] = mail;
        const domain = organizationalDomain(host.toLowerCase());
        const sub = host.slice(0, Math.max(0, host.length - domain.length));
        return (
            <code className="small url-text">
                <span className="url-dim">
                    {before}
                    {sub}
                </span>
                <mark className="url-domain">{host.slice(sub.length)}</mark>
                <span className="url-dim">{rest}</span>
            </code>
        );
    }
    const m = /^([a-z][\w+.-]*:\/\/)([^/?#]*)(.*)$/is.exec(url);
    if (!m) return <code className="small">{url}</code>;
    const [, scheme, authority, rest] = m;
    const at = authority.lastIndexOf('@');
    const userinfo = authority.slice(0, at + 1);
    const hostPort = authority.slice(at + 1);
    const host = hostPort.replace(/:\d+$/, '');
    const port = hostPort.slice(host.length);
    const domain = /^[\d.]+$|^\[/.test(host) ? host : organizationalDomain(host);
    const sub = host.slice(0, host.length - domain.length);
    return (
        <code className="small url-text">
            <span className="url-dim">
                {scheme}
                {userinfo}
                {sub}
            </span>
            <mark className="url-domain">{host.slice(sub.length)}</mark>
            <span className="url-dim">
                {port}
                {rest}
            </span>
        </code>
    );
}

/** Opens VirusTotal's report for a domain or a full URL. */
export function VirusTotalLink({ domain, url }: { domain?: string | null; url?: string }) {
    const href = url ? `https://www.virustotal.com/gui/search/${encodeURIComponent(url)}` : domain ? `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}` : null;
    if (!href) return null;
    return (
        <a href={href} target="_blank" rel="noopener noreferrer" className="vt-link small text-nowrap" title={url ? 'Check this URL on VirusTotal' : `Check ${domain} on VirusTotal`}>
            <i className="bi bi-shield-check me-1" />
            {url ? 'URL' : 'Domain'}
        </a>
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

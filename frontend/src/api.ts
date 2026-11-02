import type { AuthChecks, BootConfig, RelayLookup } from './types';

declare global {
    interface Window {
        __EMAIL_ANALYZER__: BootConfig;
    }
}

export const boot: BootConfig = window.__EMAIL_ANALYZER__ ?? {
    token: null,
    base: '/',
    api: 'api.php',
    mapsKey: '',
    inspectorUrl: '',
};

export class ApiError extends Error {}

async function post<T>(body: unknown, signal: AbortSignal): Promise<T> {
    if (!boot.token) throw new ApiError('Server lookups are unavailable on this page.');

    let response: Response;
    try {
        response = await fetch(boot.api, {
            method: 'POST',
            signal,
            credentials: 'same-origin',
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
                // Both headers are required by the API (see app/Http/ApiGuard.php).
                'X-Requested-With': 'EmailHeaderAnalyzer',
                'X-Lookup-Token': boot.token,
            },
            body: JSON.stringify(body),
        });
    } catch (error) {
        if (signal.aborted) throw error;
        throw new ApiError('Network error — check your connection and try again.');
    }

    let json: { ok: boolean; data?: T; error?: string };
    try {
        json = await response.json();
    } catch {
        throw new ApiError(`Unexpected response from the server (HTTP ${response.status}).`);
    }
    if (!response.ok || !json.ok || json.data === undefined) {
        throw new ApiError(json.error ?? `Request failed (HTTP ${response.status}).`);
    }
    return json.data;
}

/**
 * Locates relay servers (ips, hosts) and/or looks up who owns a network
 * (networks). Only addresses and host names are sent, never the email.
 */
export function locateRelays(query: { ips?: string[]; hosts?: string[]; networks?: string[] }, signal: AbortSignal): Promise<RelayLookup> {
    return post<RelayLookup>(query, signal);
}

export interface CheckQuery {
    ip: string | null;
    helo: string | null;
    mailFrom: string | null;
    fromDomain: string | null;
    orgDomain: string | null;
    dkim: { d: string; s: string }[];
}

/** Live SPF/DKIM/DMARC/DNS checks for the identities in the headers (not the email itself). */
export function runChecks(checks: CheckQuery, signal: AbortSignal): Promise<AuthChecks> {
    return post<AuthChecks>({ checks }, signal);
}

/** Link to the Domain Inspector for a domain, or null when it isn't configured. */
export function inspectorLink(domain: string | null | undefined): string | null {
    if (!boot.inspectorUrl || !domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) return null;
    return `${boot.inspectorUrl.replace(/\/?$/, '/')}${encodeURIComponent(domain.toLowerCase())}/`;
}

import { useCallback, useEffect, useRef, useState } from 'react';
import { locateRelays, runChecks } from './api';
import type { Analysis } from './lib/analyze';
import { checkQuery, evaluate, type LiveAuth } from './lib/liveAuth';
import type { Route } from './lib/route';
import { lookupTargets } from './lib/stops';
import type { AsyncState, LookupState, NetworkInfo } from './types';

/**
 * Asks the server where the relays in this route are. Runs once per analysed
 * email; the page works fine without it (no map, no locations).
 */
export function useRelayLookup(route: Route | null): { lookup: LookupState; retry: () => void } {
    const [lookup, setLookup] = useState<LookupState>({ status: 'idle' });
    const controller = useRef<AbortController | null>(null);

    const run = useCallback((target: Route | null) => {
        controller.current?.abort();
        if (!target) {
            setLookup({ status: 'idle' });
            return;
        }
        const { ips, hosts } = lookupTargets(target);
        if (!ips.length && !hosts.length) {
            setLookup({ status: 'idle' });
            return;
        }
        const abort = new AbortController();
        controller.current = abort;
        setLookup({ status: 'loading' });
        locateRelays({ ips, hosts }, abort.signal).then(
            (data) => setLookup({ status: 'ready', data }),
            (error: unknown) => {
                if (abort.signal.aborted) return;
                setLookup({ status: 'error', error: error instanceof Error ? error.message : 'Something went wrong.' });
            },
        );
    }, []);

    useEffect(() => {
        run(route);
        return () => controller.current?.abort();
    }, [route, run]);

    return { lookup, retry: () => run(route) };
}

/**
 * Asks the registries who owns the networks these addresses belong to, for
 * the abuse contacts. A separate, slower request so the map isn't held up.
 */
export function useNetworkLookup(ips: string[]): AsyncState<Record<string, NetworkInfo | null>> {
    const [state, setState] = useState<AsyncState<Record<string, NetworkInfo | null>>>({ status: 'idle' });
    const key = ips.join(',');

    useEffect(() => {
        if (!key) {
            setState({ status: 'idle' });
            return;
        }
        const abort = new AbortController();
        setState({ status: 'loading' });
        locateRelays({ networks: key.split(',') }, abort.signal).then(
            (data) => setState({ status: 'ready', data: data.networks }),
            (error: unknown) => {
                if (abort.signal.aborted) return;
                setState({ status: 'error', error: error instanceof Error ? error.message : 'Something went wrong.' });
            },
        );
        return () => abort.abort();
    }, [key]);

    return state;
}

/**
 * Live authentication checks: the server looks up SPF, DKIM keys, DMARC and
 * the sending server's DNS; the browser then verifies each DKIM signature,
 * which needs the body (never sent).
 */
export function useLiveAuth(analysis: Analysis, run = 0): AsyncState<LiveAuth> {
    const [state, setState] = useState<AsyncState<LiveAuth>>({ status: 'idle' });

    useEffect(() => {
        const query = checkQuery(analysis);
        if (!query.fromDomain && !query.ip && !query.dkim.length) {
            setState({ status: 'idle' });
            return;
        }
        const abort = new AbortController();
        setState({ status: 'loading' });
        runChecks(query, abort.signal)
            .then((checks) => evaluate(analysis, query, checks))
            .then(
                (data) => !abort.signal.aborted && setState({ status: 'ready', data }),
                (error: unknown) => {
                    if (abort.signal.aborted) return;
                    setState({ status: 'error', error: error instanceof Error ? error.message : 'Something went wrong.' });
                },
            );
        return () => abort.abort();
    }, [analysis, run]);

    return state;
}

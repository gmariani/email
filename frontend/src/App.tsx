import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Alert, Nav, Spinner, Tab } from 'react-bootstrap';
import { InputPanel } from './components/InputPanel';
import { LookupContext } from './components/links';
import { Highlighted } from './components/Lookalikes';
import { TopBar } from './components/TopBar';
import { analyze, type Analysis } from './lib/analyze';
import { handledMessage } from './lib/explain';
import type { LoadedEmail } from './lib/files';
import { findLookalikes } from './lib/lookalike';
import { NotAnEmailError } from './lib/message';
import { buildStops, withResolvedIps } from './lib/stops';
import { AuthTab } from './tabs/AuthTab';
import { ContentTab } from './tabs/ContentTab';
import { HeadersTab } from './tabs/HeadersTab';
import { RawTab } from './tabs/RawTab';
import { RouteTab } from './tabs/RouteTab';
import { SummaryTab } from './tabs/SummaryTab';
import { networkTargets } from './lib/sender';
import { useLiveAuth, useNetworkLookup, useRelayLookup } from './useRelayLookup';

// The pasted source survives a reload of this tab, but never leaves the browser
// and is gone when the tab is closed.
const STORAGE_KEY = 'email-analyzer:source';

function stored(): string {
    try {
        return sessionStorage.getItem(STORAGE_KEY) ?? '';
    } catch {
        return '';
    }
}

function store(source: string | null) {
    try {
        if (source === null) sessionStorage.removeItem(STORAGE_KEY);
        else if (source.length < 2_000_000) sessionStorage.setItem(STORAGE_KEY, source);
    } catch {
        // Private mode or storage full: reloading will just start fresh.
    }
}

export function App() {
    const [state, setState] = useState<{ analysis: Analysis; note: string | null; source: string } | null>(null);
    const [error, setError] = useState<string | null>(null);

    const open = ({ source, note }: LoadedEmail, remember = true) => {
        try {
            const analysis = analyze(source);
            setState({ analysis, note, source });
            setError(null);
            if (remember) store(source);
            window.scrollTo(0, 0);
        } catch (e) {
            setError(e instanceof NotAnEmailError ? e.message : `Couldn't read that email: ${e instanceof Error ? e.message : String(e)}`);
            if (!(e instanceof NotAnEmailError)) console.error(e);
        }
    };

    // Re-open what was being looked at before a reload.
    useEffect(() => {
        const previous = stored();
        if (previous && window.location.hash) open({ source: previous, note: null }, false);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        document.title = state?.analysis.subject ? `${state.analysis.subject} — Email Header Analyzer` : 'Email Header Analyzer';
    }, [state]);

    const reset = () => {
        setState(null);
        setError(null);
        store(null);
        window.history.replaceState(null, '', window.location.pathname);
    };

    return (
        <>
            <TopBar onNew={state ? reset : undefined} />
            {state ? <Results key={state.source} analysis={state.analysis} note={state.note} onOpen={(source) => open({ source, note: 'An email that was attached to the previous one.' })} /> : <InputPanel initial={stored()} error={error} onAnalyze={(email) => open(email)} />}
        </>
    );
}

const TABS = ['summary', 'route', 'auth', 'headers', 'content', 'raw'] as const;
type TabKey = (typeof TABS)[number];

function initialTab(): TabKey {
    const hash = window.location.hash.slice(1);
    return (TABS as readonly string[]).includes(hash) ? (hash as TabKey) : 'summary';
}

function Results({ analysis, note, onOpen }: { analysis: Analysis; note: string | null; onOpen: (source: string) => void }) {
    const [tab, setTab] = useState<TabKey>(initialTab);
    const { lookup, retry } = useRelayLookup(analysis.route);
    const networkIps = useMemo(() => networkTargets(analysis), [analysis]);
    const networks = useNetworkLookup(networkIps);
    const [liveRun, setLiveRun] = useState(0);
    const live = useLiveAuth(analysis, liveRun);
    const lookalikes = useMemo(() => findLookalikes(analysis), [analysis]);
    // Mark disguised letters right in the title, where people read them.
    const marked = (text: string) => {
        const found = lookalikes.find((f) => f.shown === text);
        return found ? <Highlighted text={text} odd={found.check.odd} /> : text;
    };
    const stops = useMemo(() => withResolvedIps(buildStops(analysis.route, analysis.handoff), lookup.status === 'ready' ? lookup.data : null), [analysis, lookup]);

    // Keep the active tab in the URL so it survives reloads.
    useEffect(() => {
        const url = new URL(window.location.href);
        url.hash = tab;
        window.history.replaceState(null, '', url);
    }, [tab]);

    // Name the sending side; failing that, anything that handled the message. A client header
    // (e.g. Outlook's Thread-Index) alone doesn't mean the service relayed it.
    const relay = analysis.services.find((s) => s.side === 'sending' && handledMessage(s)) ?? analysis.services.find((s) => s.side !== 'receiving' && handledMessage(s));
    const tabs: { key: TabKey; title: ReactNode }[] = [
        { key: 'summary', title: 'Summary' },
        {
            key: 'route',
            title: (
                <>
                    Route
                    {lookup.status === 'loading' && <Spinner animation="border" size="sm" className="ms-2 tab-spinner" aria-label="locating servers" />}
                </>
            ),
        },
        { key: 'auth', title: 'Authentication' },
        { key: 'headers', title: 'Headers' },
        { key: 'content', title: 'Content' },
        { key: 'raw', title: 'Raw' },
    ];

    return (
        <LookupContext.Provider value={lookup}>
            <main className="container-xxl bd-gutter mt-3 my-md-4 bd-content">
                <h1 className="display-6 bd-title mb-2 text-center text-break">{analysis.subject ? marked(analysis.subject) : <span className="text-body-secondary">(no subject)</span>}</h1>
                <p className="text-center text-body-secondary mb-4">
                    {analysis.from ? <>From {marked(analysis.from.name ?? analysis.from.address)}</> : 'Unknown sender'}
                    {relay && ` · via ${relay.service.name}`}
                    {lookalikes.length > 0 && (
                        <button type="button" className="btn btn-link btn-sm p-0 ms-2 link-danger align-baseline" onClick={() => setTab('summary')}>
                            <i className="bi bi-incognito me-1" />
                            disguised letters
                        </button>
                    )}
                </p>
                {note && (
                    <Alert variant="secondary" className="py-2">
                        {note}
                    </Alert>
                )}
                {lookup.status === 'error' && tab !== 'route' && (
                    <Alert variant="warning" className="py-2 small">
                        Couldn't locate the servers: {lookup.error}
                    </Alert>
                )}

                <Tab.Container activeKey={tab} onSelect={(key) => key && setTab(key as TabKey)} mountOnEnter>
                    <Nav variant="pills" className="mb-3 justify-content-center" role="tablist">
                        {tabs.map(({ key, title }) => (
                            <Nav.Item key={key}>
                                <Nav.Link eventKey={key}>{title}</Nav.Link>
                            </Nav.Item>
                        ))}
                    </Nav>
                    <Tab.Content>
                        <Tab.Pane eventKey="summary">
                            <SummaryTab analysis={analysis} stops={stops} networks={networks} live={live} lookalikes={lookalikes} onShowTab={(t) => setTab(t as TabKey)} />
                        </Tab.Pane>
                        <Tab.Pane eventKey="route">
                            <RouteTab analysis={analysis} stops={stops} onRetry={retry} />
                        </Tab.Pane>
                        <Tab.Pane eventKey="auth">
                            <AuthTab analysis={analysis} live={live} onRetry={() => setLiveRun((n) => n + 1)} />
                        </Tab.Pane>
                        <Tab.Pane eventKey="headers">
                            <HeadersTab analysis={analysis} />
                        </Tab.Pane>
                        <Tab.Pane eventKey="content">
                            <ContentTab analysis={analysis} onOpenAttached={onOpen} />
                        </Tab.Pane>
                        <Tab.Pane eventKey="raw">
                            <RawTab analysis={analysis} />
                        </Tab.Pane>
                    </Tab.Content>
                </Tab.Container>
            </main>
        </LookupContext.Provider>
    );
}

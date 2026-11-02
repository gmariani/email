import { parseAddressList, type Mailbox } from './address';
import { summarizeAuth, type AuthSummary } from './auth';
import { detectServices, explainHeaders, type DetectedService, type ExplainedHeader } from './explain';
import { findHeader, splitMessage, type RawMessage } from './message';
import { parseMime, type MimePart } from './mime';
import { buildRoute, type Route } from './route';
import { handoffIndex } from './sides';

export interface Analysis {
    message: RawMessage;
    subject: string | null;
    from: Mailbox | null;
    to: Mailbox[];
    route: Route;
    auth: AuthSummary;
    services: DetectedService[];
    headers: ExplainedHeader[];
    /** Null when only headers were pasted. */
    mime: MimePart | null;
    /** Index of the hop where the recipient's side took over (see sides.ts). */
    handoff: number | null;
}

/** Everything the page shows, worked out from the message source alone (no network). */
export function analyze(source: string): Analysis {
    const message = splitMessage(source);
    const { headers } = message;
    const route = buildRoute(headers);
    const auth = summarizeAuth(headers);
    const handoff = handoffIndex(headers, route);
    const context = { headers, route, auth, handoff };
    const services = detectServices(context);

    return {
        message,
        subject: findHeader(headers, 'subject')?.decoded ?? null,
        from: parseAddressList(findHeader(headers, 'from')?.decoded ?? '')[0] ?? null,
        to: parseAddressList(findHeader(headers, 'to')?.decoded ?? ''),
        route,
        auth,
        services,
        headers: explainHeaders(context, services),
        mime: message.hasBody && message.body.trim() ? parseMime(headers, message.body) : null,
        handoff,
    };
}

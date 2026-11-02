import { domainOf } from '../address';
import { CATEGORY_TITLES, headerInfo, type HeaderInfo } from '../data/headers';
import { hostMatches, SENDING_KINDS, SERVICES, type Service } from '../data/services';
import { findHeader, type HeaderField } from '../message';
import { AMAZON } from './amazon';
import { MICROSOFT } from './microsoft';
import { OTHER } from './other';
import { SPAM } from './spam';
import { STANDARD } from './standard';
import type { ExplainContext, Explainer, Fact, SpamRule } from './types';

export type { ExplainContext, Fact, Tone } from './types';

const EXPLAINERS: Record<string, Explainer> = { ...STANDARD, ...MICROSOFT, ...AMAZON, ...SPAM, ...OTHER };

export interface DetectedService {
    service: Service;
    evidence: string[];
    /** Header keys that belong to this service. */
    headers: Set<string>;
    /**
     * sending: it sent, signed or relayed the message before the recipient's side took over;
     * receiving: only the recipient's own provider/filters; neither: only its headers were seen.
     */
    side: 'sending' | 'receiving' | null;
}

export interface ExplainedHeader {
    field: HeaderField;
    info: HeaderInfo | null;
    /** The service group this header is shown under, if any. */
    service: string | null;
    /** Category title, used when there's no service. */
    group: string;
    summary: string | null;
    facts: Fact[];
    rules: SpamRule[];
    help: string | null;
    /** Neither a known header nor one belonging to a recognised service. */
    unrecognized: boolean;
}

/** Which services left traces in the message, with the evidence for each. */
export function detectServices({ headers, route, auth, handoff }: ExplainContext): DetectedService[] {
    const found = new Map<string, DetectedService>();
    const add = (service: Service, evidence: string, side: 'sending' | 'receiving' | null, key?: string) => {
        let entry = found.get(service.name);
        if (!entry) found.set(service.name, (entry = { service, evidence: [], headers: new Set(), side: null }));
        if (!entry.evidence.includes(evidence)) entry.evidence.push(evidence);
        if (key) entry.headers.add(key);
        if (side === 'sending' || (side === 'receiving' && entry.side === null)) entry.side = side;
    };
    // Hops before the hand-off were handled by the sending side; the hand-off's sender too.
    const boundary = handoff ?? route.hops.length;

    const feedbackSender = findHeader(headers, 'feedback-id')?.value.split(':').pop()?.trim() ?? '';
    const messageIdDomain = domainOf(findHeader(headers, 'message-id')?.value);
    for (const service of SERVICES) {
        const names = [...new Set(headers.filter((h) => service.headers?.test(h.key)).map((h) => h.name))];
        if (names.length) {
            add(service, `Headers: ${names.slice(0, 6).join(', ')}${names.length > 6 ? `, +${names.length - 6} more` : ''}`, SENDING_KINDS.has(service.kind) ? 'sending' : null);
            for (const h of headers) if (service.headers?.test(h.key)) found.get(service.name)?.headers.add(h.key);
        }
        if (service.feedbackId?.test(feedbackSender)) add(service, `Feedback-ID names ${feedbackSender}`, 'sending', 'feedback-id');
        route.hops.forEach((hop, i) => {
            const fromName = hop.from?.rdns ?? hop.from?.name;
            if (hostMatches(fromName, service.hosts)) add(service, `Hop ${hop.number} came from ${fromName}`, i <= boundary ? 'sending' : 'receiving');
            if (hostMatches(hop.by?.name, service.hosts)) add(service, `Hop ${hop.number} was received by ${hop.by?.name}`, i < boundary ? 'sending' : 'receiving');
        });
        if (messageIdDomain && service.messageIds?.some((m) => messageIdDomain === m || messageIdDomain.endsWith(`.${m}`))) {
            add(service, `Message-ID domain ${messageIdDomain}`, 'sending');
        }
        for (const sig of auth.dkim) {
            if (hostMatches(sig.domain, service.dkim)) add(service, `DKIM signature by ${sig.domain}`, 'sending');
        }
        const entry = found.get(service.name);
        if (entry && service.relatedHeaders) {
            for (const h of headers) if (service.relatedHeaders.test(h.key)) entry.headers.add(h.key);
        }
    }
    return [...found.values()].sort((a, b) => b.evidence.length - a.evidence.length);
}

/** Evidence beyond a header name: the service actually handled the message (relayed, signed or generated it). */
export function handledMessage(detected: DetectedService): boolean {
    return detected.evidence.some((e) => !e.startsWith('Headers:'));
}

/** Every header gets at least one labelled row, so they all read the same; long values are cut, the raw header has them in full. */
function valueFact(field: HeaderField): Fact {
    const value = field.decoded.trim();
    if (!value) return { label: 'Value', value: '(empty)', tone: 'muted' };
    if (value.length < 160) return { label: 'Value', value };
    return { label: 'Value', value: `${value.slice(0, 80)}… (${value.length.toLocaleString()} characters)`, mono: true, tone: 'muted', hint: 'Shortened: the full text is under Raw header.' };
}

export function explainHeaders(context: ExplainContext, services: DetectedService[]): ExplainedHeader[] {
    return context.headers.map((field) => {
        const info = headerInfo(field.key);
        const service = services.find((s) => s.headers.has(field.key))?.service.name ?? null;
        let explanation = null;
        try {
            explanation = EXPLAINERS[field.key]?.(field, context) ?? null;
        } catch (error) {
            // One odd header shouldn't take the whole analysis down.
            console.warn(`Couldn't explain ${field.name}`, error);
        }
        const generic = info?.title === 'Custom header';
        const facts = explanation?.facts ?? [];
        return {
            field,
            info,
            service,
            group: service ?? CATEGORY_TITLES[info?.category ?? 'other'],
            summary: explanation?.summary ?? null,
            facts: facts.length || explanation?.rules?.length ? facts : [valueFact(field)],
            rules: explanation?.rules ?? [],
            help: explanation?.help ?? null,
            unrecognized: !service && (!info || generic) && !explanation,
        };
    });
}

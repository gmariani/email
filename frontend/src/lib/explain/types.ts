import { formatInZone, formatLocal, formatUtc } from '../format';
import type { AuthSummary } from '../auth';
import type { HeaderField } from '../message';
import type { Route } from '../route';

export type Tone = 'good' | 'bad' | 'warn' | 'info' | 'muted';

/** One labelled piece of information read out of a header. */
export interface Fact {
    label: string;
    value: string;
    /** Longer explanation, shown on hover/under the value. */
    hint?: string;
    /** The value as written in the header, when the value shown is its decoded meaning (SCL 1 => "Not spam"). Shown with the hint. */
    raw?: string;
    tone?: Tone;
    /** Show in a monospace font (identifiers, encoded values). */
    mono?: boolean;
    /** A part of the line above (e.g. one property of a DKIM result), shown indented. */
    sub?: boolean;
    /** Render the value as a link to the Domain Inspector / map. */
    kind?: 'domain' | 'ip' | 'url' | 'email';
}

/** One spam-filter rule that matched: shown as a table row. */
export interface SpamRule {
    name: string;
    /** Points it added (positive: spammier) or took away; null when the header doesn't say. */
    points: number | null;
    /** What it means; null when unknown. */
    meaning: string | null;
    /** Where to read more about it. */
    url: string | null;
}

export interface Explanation {
    /** One sentence saying what this particular header tells us. */
    summary?: string;
    facts: Fact[];
    /** Spam-filter rules that matched, in the header's order. */
    rules?: SpamRule[];
    /** Background on this particular value (what a multipart type means…): shown in the help popover, not inline. */
    help?: string;
}

export interface ExplainContext {
    headers: HeaderField[];
    route: Route;
    auth: AuthSummary;
    /** Index of the hop where the recipient's side took over (see sides.ts). */
    handoff: number | null;
}

export type Explainer = (field: HeaderField, context: ExplainContext) => Explanation | null;

export const fact = (label: string, value: string | number | null | undefined, extra: Omit<Fact, 'label' | 'value'> = {}): Fact[] =>
    value === null || value === undefined || value === '' ? [] : [{ label, value: String(value), ...extra }];

/**
 * Every timestamp reads the same: as written (in the zone it was written in, UTC when it
 * carries none), then UTC and the reader's own time underneath.
 */
export function timeFacts(label: string, time: number, offset: number | null = null): Fact[] {
    return [
        { label, value: formatInZone(time, offset) },
        // Written in UTC already (epoch times, Exchange's stamps): no second UTC row.
        ...(offset === null ? [] : [{ label: 'UTC', value: formatUtc(time), sub: true }]),
        { label: 'Your time', value: formatLocal(time), sub: true },
    ];
}

/** "key1:value1;key2:value2" or "key1=value1; key2=value2" => ordered pairs. */
export function pairs(value: string, separator = ';', assign = /[:=]/): [string, string][] {
    const out: [string, string][] = [];
    for (const part of value.split(separator)) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        const at = trimmed.search(assign);
        if (at < 0) out.push([trimmed, '']);
        else out.push([trimmed.slice(0, at).trim(), trimmed.slice(at + 1).trim()]);
    }
    return out;
}

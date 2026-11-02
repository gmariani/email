import { stripComments } from './message';

export interface ParsedDate {
    /** Milliseconds since the epoch. */
    time: number;
    /** The writer's UTC offset in minutes (east positive); null when it gave none. */
    offset: number | null;
}

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

// Obsolete zone names still seen in old mailers (RFC 5322 §4.3).
const ZONES: Record<string, number> = {
    UT: 0, UTC: 0, GMT: 0, Z: 0,
    EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420,
};

const RFC5322 =
    /^(?:[A-Za-z]{3,9},?\s*)?(\d{1,2})[\s-]+([A-Za-z]{3})[a-z]*[\s-]+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*([+-]\d{2}:?\d{2}|[A-Za-z]{1,5})?/;

/**
 * "Fri, 23 Oct 2026 21:31:12 -0400 (EDT)" and the variants mailers really
 * write (no weekday, two-digit year, missing seconds, fractional seconds,
 * named zones). Falls back to the browser's parser for ISO 8601.
 */
export function parseDate(raw: string | null | undefined): ParsedDate | null {
    if (!raw) return null;
    const text = stripComments(raw).text.replace(/\s+/g, ' ').trim();
    const m = RFC5322.exec(text);
    if (m) {
        const [, day, monthName, yearText, hour, minute, second = '0', fraction = '0', zone] = m;
        const month = MONTHS.indexOf(monthName.toLowerCase());
        if (month < 0) return null;
        let year = parseInt(yearText, 10);
        if (yearText.length === 2) year += year < 50 ? 2000 : 1900;
        else if (yearText.length === 3) year += 1900;

        let offset: number | null = null;
        if (zone && /^[+-]/.test(zone)) {
            const digits = zone.replace(':', '');
            const sign = digits[0] === '-' ? -1 : 1;
            offset = sign * (parseInt(digits.slice(1, 3), 10) * 60 + parseInt(digits.slice(3, 5), 10));
            // "-0000" means "local time unknown" (RFC 5322); the instant is still UTC.
            if (digits === '-0000') offset = null;
        } else if (zone && ZONES[zone.toUpperCase()] !== undefined) {
            offset = ZONES[zone.toUpperCase()];
        }

        const ms = Math.round(parseFloat(`0.${fraction}`) * 1000);
        const utc = Date.UTC(year, month, parseInt(day, 10), parseInt(hour, 10), parseInt(minute, 10), parseInt(second, 10), ms);
        if (Number.isNaN(utc)) return null;
        return { time: utc - (offset ?? 0) * 60_000, offset };
    }

    const fallback = Date.parse(text);
    if (Number.isNaN(fallback)) return null;
    const zone = /(?:([+-])(\d{2}):?(\d{2})|Z)$/.exec(text);
    const offset = zone ? (zone[1] ? (zone[1] === '-' ? -1 : 1) * (parseInt(zone[2], 10) * 60 + parseInt(zone[3], 10)) : 0) : null;
    return { time: fallback, offset };
}

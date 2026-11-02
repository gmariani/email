import type { GeoLocation } from '../types';

/** 90061 => "1d 1h 1m 1s" */
export function secondsToTime(seconds: number): string {
    const units: [string, number][] = [
        ['y', 31_536_000],
        ['d', 86_400],
        ['h', 3_600],
        ['m', 60],
        ['s', 1],
    ];
    const parts: string[] = [];
    let rest = Math.max(0, Math.floor(seconds));
    for (const [label, size] of units) {
        const amount = Math.floor(rest / size);
        if (amount > 0) {
            parts.push(`${amount}${label}`);
            rest -= amount * size;
        }
    }
    return parts.join(' ') || '0s';
}

/** Signed, short: 3 => "+3s", -75 => "−1m 15s", 0 => "<1s" */
export function delayLabel(seconds: number | null): string | null {
    if (seconds === null) return null;
    if (seconds === 0) return '<1s';
    return `${seconds < 0 ? '−' : '+'}${secondsToTime(Math.abs(seconds))}`;
}

const pad = (n: number) => String(n).padStart(2, '0');
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** The time as its writer saw it: "Fri, 23 Oct 2026 21:31:12 -0400". Without an offset, UTC. */
export function formatInZone(time: number, offset: number | null): string {
    const minutes = offset ?? 0;
    const d = new Date(time + minutes * 60_000);
    const sign = minutes < 0 ? '-' : '+';
    const zone = offset === null ? 'UTC' : `${sign}${pad(Math.floor(Math.abs(minutes) / 60))}${pad(Math.abs(minutes) % 60)}`;
    return `${DAYS[d.getUTCDay()]}, ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} ${zone}`;
}

/** "2026-10-24 01:31:12 UTC" */
export function formatUtc(time: number): string {
    return new Date(time).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

/** In the viewer's own time zone. */
export function formatLocal(time: number): string {
    return new Date(time).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
}

export function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KB', 'MB', 'GB'];
    let value = bytes / 1024;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit++;
    }
    return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

export function locationLabel(location: GeoLocation | null | undefined): string {
    if (!location) return 'Unknown';
    const place = [location.city, location.region].filter(Boolean).join(', ');
    const label = [place, location.country].filter(Boolean).join(' ') || 'Unknown';
    return location.anycast ? `${label} (anycast — one of many locations)` : label;
}

/** Regional-indicator emoji for a two-letter country code. */
export function flag(countryCode: string | null | undefined): string {
    if (!countryCode || !/^[A-Za-z]{2}$/.test(countryCode)) return '';
    return String.fromCodePoint(...[...countryCode.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)));
}

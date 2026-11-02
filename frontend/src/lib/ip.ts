// Small IP helpers. The server re-validates everything it's sent.

export function isIPv4(value: string): boolean {
    const parts = value.split('.');
    return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && parseInt(p, 10) <= 255);
}

export function isIPv6(value: string): boolean {
    if (!value.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(value)) return false;
    try {
        // The URL parser validates (and canonicalises) IPv6 literals for us.
        new URL(`http://[${value}]/`);
        return true;
    } catch {
        return false;
    }
}

export function isIp(value: string): boolean {
    return isIPv4(value) || isIPv6(value);
}

/** Canonical form: lower case, compressed IPv6. */
export function normalizeIp(value: string): string {
    const ip = value.replace(/^\[|\]$/g, '').replace(/^ipv6:/i, '');
    if (isIPv6(ip)) return new URL(`http://[${ip}]/`).hostname.slice(1, -1);
    return ip;
}

export type IpScope = 'public' | 'private' | 'loopback';

/** Private and shared ranges only mean something inside one network, so they can't be located. */
export function ipScope(ip: string): IpScope {
    if (isIPv4(ip)) {
        const [a, b] = ip.split('.').map(Number);
        if (a === 127) return 'loopback';
        if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || a === 0) {
            return 'private';
        }
        return 'public';
    }
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
    if (mapped) return ipScope(mapped[1]);
    const v6 = normalizeIp(ip).toLowerCase();
    if (v6 === '::1') return 'loopback';
    if (/^(fc|fd|fe[89ab])/.test(v6) || v6 === '::' || v6.startsWith('::ffff:')) return 'private';
    return 'public';
}

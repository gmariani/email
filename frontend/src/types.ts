// Shapes returned by api.php. Keep in sync with app/Relays/RelayLocator.php.

export interface BootConfig {
    token: string | null;
    /** URL path of the app, e.g. "/projects/email/" */
    base: string;
    api: string;
    mapsKey: string;
    /** Domain Inspector base URL; the domain is appended. Empty: don't link. */
    inspectorUrl: string;
}

export interface GeoLocation {
    city: string | null;
    region: string | null;
    country: string | null;
    countryCode: string | null;
    lat: number | null;
    lon: number | null;
    asn: number | null;
    org: string | null;
    /** true: the address is served from many sites, so the city is only one of them. null: unknown */
    anycast?: boolean | null;
}

export interface IpInfo {
    public: boolean;
    hostname: string | null;
    location: GeoLocation | null;
}

/** Who owns an IP's network and where abuse goes, from the Regional Internet Registry (RDAP). */
export interface NetworkInfo {
    registry: string | null;
    url: string | null;
    handle: string | null;
    name: string | null;
    country: string | null;
    range: string | null;
    cidrs: string[];
    organization: string | null;
    abuseEmail: string | null;
    abusePhone: string | null;
}

export interface RelayLookup {
    ips: Record<string, IpInfo>;
    /** host name => its current IPv4 addresses */
    hosts: Record<string, string[]>;
    geoSource: string;
    /** IP => network owner, only for addresses asked for under "networks" */
    networks: Record<string, NetworkInfo | null>;
}

export type AsyncState<T> =
    | { status: 'idle' }
    | { status: 'loading' }
    | { status: 'ready'; data: T }
    | { status: 'error'; error: string };

export type LookupState = AsyncState<RelayLookup>;

// ------------------------------------------------- Live authentication checks
// Shapes returned for {"checks": …}. Keep in sync with app/Checks/*.php.

export type SpfResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';

export interface SpfTerm {
    raw: string;
    kind: 'mechanism' | 'modifier';
    qualifier?: SpfResult;
    mechanism?: string;
    value?: string | null;
    /** true: matched (evaluation stopped here); false: checked, no match; null: not reached. */
    matched?: boolean | null;
    detail?: string | null;
    child?: SpfNode;
}

export interface SpfNode {
    domain: string;
    record: string | null;
    terms: SpfTerm[];
    redirect: SpfNode | null;
    result: SpfResult;
    error: string | null;
}

export interface SpfCheck {
    result: SpfResult;
    domain: string;
    ip: string;
    lookups: number;
    lookupLimit: number;
    voidLookups: number;
    trace: SpfNode;
    explanation: string | null;
}

export interface DkimKeyCheck {
    domain: string;
    selector: string;
    host: string;
    found: boolean;
    error: string | null;
    record?: string;
    tags?: Record<string, string>;
    keyType?: string;
    keyBits?: number | null;
    publicKey?: string | null;
    revoked?: boolean;
    testing?: boolean;
    strict?: boolean;
    weak?: boolean;
    hashes?: string | null;
}

export interface DmarcCheck {
    domain: string;
    policyDomain: string;
    host: string;
    inherited: boolean;
    found: boolean;
    /** The DNS lookup itself failed: the record may well exist. */
    lookupFailed?: boolean;
    valid: boolean;
    record: string | null;
    tags: Record<string, string>;
    errors: string[];
    warnings: string[];
    reports: { tag: 'rua' | 'ruf'; address: string; domain: string; external: boolean; authorized: boolean | null }[];
}

export interface AuthChecks {
    spf: SpfCheck | null;
    dkim: DkimKeyCheck[];
    dmarc: DmarcCheck | null;
    reverse: { ip: string; ptr: string[]; confirmed: string | null; forward: Record<string, string[]> } | null;
    helo: { host: string; addresses: string[]; matchesIp: boolean } | null;
    mail: Record<string, { mx: { pri: number; target: string; addresses: string[] }[]; nullMx: boolean; addresses: string[] }>;
    checkedAt: string;
    elapsedMs: number;
}

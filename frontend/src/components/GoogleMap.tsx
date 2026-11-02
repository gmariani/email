import { useEffect, useRef, useState } from 'react';
import { boot } from '../api';

export interface MapMarker {
    lat: number;
    lng: number;
    title: string;
    /** Short text drawn on the pin, e.g. the step number. */
    label?: string;
    /** Plain-text lines for the info window (rendered as text, never HTML). */
    lines: { strong?: string; text: string }[];
}

let loader: Promise<void> | null = null;

// Google calls window.gm_authFailure when the key is rejected (wrong domain, billing off…).
// Maps on the page then show a message instead of a broken grey box.
let authFailed = false;
const authListeners = new Set<() => void>();
(window as unknown as { gm_authFailure: () => void }).gm_authFailure = () => {
    authFailed = true;
    authListeners.forEach((listener) => listener());
};
const AUTH_ERROR = "Map unavailable: the Google Maps key isn't authorised for this site's address.";

/** Load the Maps JavaScript API once, on first use. */
function loadMaps(key: string): Promise<void> {
    if (window.google?.maps?.Map) return Promise.resolve();
    loader ??= new Promise<void>((resolve, reject) => {
        const callback = '__emailAnalyzerMapsReady';
        (window as unknown as Record<string, () => void>)[callback] = () => resolve();
        const script = document.createElement('script');
        script.src = `https://maps.googleapis.com/maps/api/js?${new URLSearchParams({ key, callback, loading: 'async' })}`;
        script.async = true;
        script.onerror = () => {
            loader = null;
            reject(new Error('Google Maps failed to load'));
        };
        document.head.appendChild(script);
    });
    return loader;
}

function infoContent(marker: MapMarker): HTMLElement {
    const root = document.createElement('div');
    root.className = 'map-info';
    for (const line of marker.lines) {
        const row = document.createElement('div');
        if (line.strong) {
            const strong = document.createElement('strong');
            strong.textContent = line.strong;
            row.append(strong, ' ');
        }
        row.append(line.text);
        root.append(row);
    }
    return root;
}

/**
 * Markers on a Google map. With `path`, they're joined in order by an arrowed
 * line, to show the route a message took.
 */
export function GoogleMap({ markers, zoom, path = false, className = '' }: { markers: MapMarker[]; zoom: number; path?: boolean; className?: string }) {
    const ref = useRef<HTMLDivElement>(null);
    const [error, setError] = useState<string | null>(!boot.mapsKey ? 'Map unavailable (no Google Maps key configured).' : authFailed ? AUTH_ERROR : null);

    useEffect(() => {
        const listener = () => setError(AUTH_ERROR);
        authListeners.add(listener);
        return () => void authListeners.delete(listener);
    }, []);

    useEffect(() => {
        if (!boot.mapsKey || authFailed || !ref.current || markers.length === 0) return;
        let cancelled = false;
        const placed: google.maps.Marker[] = [];
        let line: google.maps.Polyline | null = null;

        loadMaps(boot.mapsKey).then(
            () => {
                if (cancelled || !ref.current) return;
                const map = new google.maps.Map(ref.current, { center: markers[0], zoom });
                const bounds = new google.maps.LatLngBounds();
                const info = new google.maps.InfoWindow();
                for (const m of markers) {
                    const marker = new google.maps.Marker({
                        position: m,
                        title: m.title,
                        label: m.label ? { text: m.label, color: '#fff', fontWeight: '700' } : undefined,
                        map,
                    });
                    marker.addListener('click', () => {
                        info.setContent(infoContent(m));
                        info.open({ map, anchor: marker });
                    });
                    placed.push(marker);
                    bounds.extend(m);
                }
                if (path && markers.length > 1) {
                    line = new google.maps.Polyline({
                        path: markers.map(({ lat, lng }) => ({ lat, lng })),
                        geodesic: true,
                        strokeColor: '#9461fb',
                        strokeOpacity: 0.9,
                        strokeWeight: 3,
                        icons: [{ icon: { path: google.maps.SymbolPath.FORWARD_CLOSED_ARROW, scale: 3 }, offset: '50%', repeat: '120px' }],
                        map,
                    });
                }
                if (markers.length > 1) map.fitBounds(bounds, 48);
            },
            (e: Error) => !cancelled && setError(e.message),
        );

        return () => {
            cancelled = true;
            placed.forEach((m) => m.setMap(null));
            line?.setMap(null);
        };
    }, [markers, zoom, path]);

    if (error) return <div className={`google-map map-empty ${className}`}>{error}</div>;
    if (markers.length === 0) return <div className={`google-map map-empty ${className}`}>No location available</div>;
    return <div ref={ref} className={`google-map ${className}`} />;
}
